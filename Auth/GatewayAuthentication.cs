using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Auth;

public static class GatewayAuth
{
    public const string Scheme = "GatewayManagement";

    /// <summary>Front scheme that routes each request to the handler matching its credential.</summary>
    public const string ForwardingScheme = "GatewayForwarding";
    public const string PlatformAdminPolicy = "PlatformAdmin";

    /// <summary>Claim carrying the IAM principal ARN the caller resolved to.</summary>
    public const string PrincipalArnClaim = "gateway:principal_arn";

    /// <summary>Claim recording how the caller authenticated, for the audit trail.</summary>
    public const string AuthTypeClaim = "gateway:auth_type";

    /// <summary>Claim carrying the jti of the STS token the caller presented, for the audit trail.</summary>
    public const string TokenIdClaim = "gateway:token_id";

    /// <summary>
    /// Header carrying a SigV4-signed sts:GetCallerIdentity request: how automation proves an
    /// IAM identity in AWS mode. See <see cref="Services.Cloud.Aws.AwsIdentityProvider"/>.
    /// </summary>
    public const string AwsIdentityHeader = "X-Gateway-Aws-Identity";

    /// <summary>
    /// True when the presented bearer token is shaped like a JWT (three base64url segments
    /// beginning with a JSON header). Gateway STS tokens carry a 'ug_sts_' prefix and so are
    /// never mistaken for one.
    /// </summary>
    public static bool LooksLikeJwt(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var token = auth[7..].Trim();
        return token.StartsWith("eyJ", StringComparison.Ordinal) && token.Count(c => c == '.') == 2;
    }
}

/// <summary>
/// Authenticates management-plane callers. Every accepted credential is proven, none is
/// merely asserted:
///
///   1. AWS mode: a signed sts:GetCallerIdentity request in X-Gateway-Aws-Identity, which AWS
///      itself verifies. In AWS mode it is the only thing the identity provider is shown.
///   2. A gateway admin STS token (ug_sts_ with isAdmin) carrying the admin scope.
///   3. The master admin credential from the secret store -- break-glass.
///   4. Simulator modes only: a simulator session key or role name. Neither proves anything,
///      which is why they are accepted only when bound to a local simulator, and
///      StartupValidator allows those bindings in Development alone.
///
/// Break-glass, whether used directly or through an admin token minted from it, acts as the
/// configured BreakGlassPrincipalArn, never as a principal read from the token or the request.
///
/// Authentication only establishes *who* is calling. Whether they may perform the operation
/// is a separate IAM policy decision made by <see cref="IamAuthorizationHandler"/>.
/// </summary>
public class GatewayAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IIdentityProvider _identityProvider;
    private readonly ISecurityService _security;
    private readonly IAdminCredentialService _adminCredentials;
    private readonly CloudOptions _cloudOptions;

    public GatewayAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder,
        IIdentityProvider identityProvider,
        ISecurityService security,
        IAdminCredentialService adminCredentials,
        IOptions<CloudOptions> cloudOptions)
        : base(options, loggerFactory, encoder)
    {
        _identityProvider = identityProvider;
        _security = security;
        _adminCredentials = adminCredentials;
        _cloudOptions = cloudOptions.Value;
    }

    private bool IsSimulatorProvider =>
        _cloudOptions.Provider is CloudProviderMode.Simulator or CloudProviderMode.LocalDotNet;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (_cloudOptions.Provider == CloudProviderMode.Aws)
        {
            // A request carrying a signed identity is judged on that alone.
            var signedIdentity = Request.Headers[GatewayAuth.AwsIdentityHeader].ToString();
            if (!string.IsNullOrWhiteSpace(signedIdentity))
            {
                return await ResolveIdentityAsync(signedIdentity.Trim());
            }

            // Okta JWTs belong to the Okta scheme. Trying one here as a master key would only
            // add a failed-authentication warning to every operator request.
            if (GatewayAuth.LooksLikeJwt(Context))
            {
                return AuthenticateResult.NoResult();
            }
        }

        var presented = ExtractCredential(Request, allowSimulatorRole: IsSimulatorProvider);
        if (string.IsNullOrWhiteSpace(presented))
        {
            return AuthenticateResult.NoResult();
        }

        if (presented.StartsWith("ug_sts_", StringComparison.Ordinal))
        {
            return await AuthenticateAdminTokenAsync(presented);
        }

        if (await _adminCredentials.VerifyAsync(presented))
        {
            var principal = BreakGlassPrincipal();
            if (principal is null)
            {
                return AuthenticateResult.Fail("Break-glass is not configured on this gateway");
            }

            Logger.LogWarning(
                "BREAK-GLASS: master admin credential used on the management plane from {RemoteIp}. This should be rare and alerted on.",
                Context.Connection.RemoteIpAddress);

            return Success(principal, "MasterAdminKey", subject: "break-glass");
        }

        // Simulator conveniences: session keys and role names. Neither is a secret, so they are
        // honoured only when the environment is bound to a local simulator.
        if (IsSimulatorProvider)
        {
            return await ResolveIdentityAsync(presented);
        }

        Logger.LogWarning(
            "Management authentication failed: unrecognised credential from {RemoteIp}.",
            Context.Connection.RemoteIpAddress);
        return AuthenticateResult.Fail("Unrecognised credential");
    }

    private async Task<AuthenticateResult> AuthenticateAdminTokenAsync(string presented)
    {
        var (isValid, payload, failureReason) = await _security.ValidateAppStsTokenAsync(presented);
        if (!isValid || payload is null)
        {
            Logger.LogWarning("Management STS token rejected: {Reason}", failureReason);
            return AuthenticateResult.Fail(failureReason ?? "Invalid STS token");
        }

        if (!payload.IsAdmin)
        {
            return AuthenticateResult.Fail("STS token is not an administrative token");
        }

        // The admin flag records who minted the token; the scope records what it may do. A
        // break-glass token scoped down to 'read' or 'invoke' must not administer anything.
        if (!SecurityService.ScopePermits(payload.Scope, GatewayScopes.Admin))
        {
            Logger.LogWarning(
                "Admin STS token {Jti} carries scope '{Scope}', which does not permit management operations.",
                payload.Jti, payload.Scope);
            return AuthenticateResult.Fail("STS token scope does not permit management operations");
        }

        var principal = BreakGlassPrincipal();
        if (principal is null)
        {
            return AuthenticateResult.Fail("Break-glass is not configured on this gateway");
        }

        Logger.LogWarning(
            "BREAK-GLASS: admin STS token {Jti} used on the management plane from {RemoteIp}.",
            payload.Jti, Context.Connection.RemoteIpAddress);

        return Success(principal, "GatewayAdminStsToken", CallerContext.ActorFor(payload), payload.Jti);
    }

    private async Task<AuthenticateResult> ResolveIdentityAsync(string credential)
    {
        var identity = await _identityProvider.ResolveAsync(credential, Context.RequestAborted);
        if (identity.IsAuthenticated)
        {
            return Success(identity.PrincipalArn, identity.AuthType, identity.PrincipalArn);
        }

        Logger.LogWarning("Management authentication failed: {Reason}", identity.FailureReason);
        return AuthenticateResult.Fail(identity.FailureReason ?? "Unrecognised credential");
    }

    /// <summary>
    /// The principal break-glass acts as. Configured, never derived from the token or the
    /// request, so whoever holds the key cannot choose whose name the audit trail records.
    /// Unset means break-glass is refused, not guessed.
    /// </summary>
    private string? BreakGlassPrincipal()
    {
        var arn = _cloudOptions.AccessControl.BreakGlassPrincipalArn;
        if (!string.IsNullOrWhiteSpace(arn) && arn.StartsWith("arn:", StringComparison.Ordinal))
        {
            return arn;
        }

        Logger.LogError(
            "Break-glass credential presented, but Gateway:Cloud:AccessControl:BreakGlassPrincipalArn is not configured. Refusing.");
        return null;
    }

    private AuthenticateResult Success(string principalArn, string authType, string subject, string? tokenId = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, subject),
            new(GatewayAuth.PrincipalArnClaim, principalArn),
            new(GatewayAuth.AuthTypeClaim, authType)
        };

        if (!string.IsNullOrEmpty(tokenId))
        {
            claims.Add(new Claim(GatewayAuth.TokenIdClaim, tokenId));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, GatewayAuth.Scheme));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, GatewayAuth.Scheme));
    }

    private static string ExtractCredential(HttpRequest request, bool allowSimulatorRole)
    {
        var apiKey = request.Headers["X-API-Key"].ToString();
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            return apiKey.Trim();
        }

        var auth = request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(auth))
        {
            return auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? auth[7..].Trim()
                : auth.Trim();
        }

        if (!allowSimulatorRole)
        {
            return string.Empty;
        }

        // The simulator's convenience header, accepted so the dashboard and the AWS
        // simulator console can drive the gateway with the same role header.
        var simulatorRole = request.Headers["X-Simulator-Role"].ToString();
        return string.IsNullOrWhiteSpace(simulatorRole) ? string.Empty : simulatorRole.Trim();
    }
}

/// <summary>Requires that the caller be allowed the named action by IAM policy.</summary>
public class IamActionRequirement : IAuthorizationRequirement
{
    public IamActionRequirement(string action)
    {
        Action = action;
    }

    /// <summary>Bare action name, e.g. "CreateApplication". Prefixed with the service at evaluation time.</summary>
    public string Action { get; }
}

/// <summary>
/// Turns an authenticated principal plus a requested action into an IAM policy decision,
/// delegating to whichever <see cref="IAccessControlProvider"/> the environment bound.
/// </summary>
public class IamAuthorizationHandler : AuthorizationHandler<IamActionRequirement>
{
    private readonly IAccessControlProvider _accessControl;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly CloudOptions _options;
    private readonly ILogger<IamAuthorizationHandler> _logger;

    public IamAuthorizationHandler(
        IAccessControlProvider accessControl,
        IHttpContextAccessor httpContextAccessor,
        IOptions<CloudOptions> options,
        ILogger<IamAuthorizationHandler> logger)
    {
        _accessControl = accessControl;
        _httpContextAccessor = httpContextAccessor;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        IamActionRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return;
        }

        var principalArn = context.User.FindFirst(GatewayAuth.PrincipalArnClaim)?.Value;
        if (string.IsNullOrWhiteSpace(principalArn))
        {
            return;
        }

        var accessOptions = _options.AccessControl;

        // An explicit admin-role allow-list short-circuits policy evaluation. This is what
        // lets a deployment run without an IAM policy engine reachable.
        if (accessOptions.AdminRoleArns.Length > 0 &&
            accessOptions.AdminRoleArns.Any(arn => string.Equals(arn, principalArn, StringComparison.OrdinalIgnoreCase)))
        {
            context.Succeed(requirement);
            return;
        }

        if (!accessOptions.Enabled)
        {
            // Authentication passed and policy evaluation is off for this environment.
            context.Succeed(requirement);
            return;
        }

        var httpContext = _httpContextAccessor.HttpContext;
        var resourceId = httpContext?.Request.RouteValues.TryGetValue("appId", out var appId) == true
            ? appId?.ToString() ?? "*"
            : "*";

        var action = $"{accessOptions.ServicePrefix}:{requirement.Action}";
        var resource = string.Format(accessOptions.ResourceArnTemplate, resourceId);

        var evaluationContext = new Dictionary<string, string>();
        var sourceIp = httpContext?.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(sourceIp))
        {
            evaluationContext["aws:SourceIp"] = sourceIp;
        }

        var decision = await _accessControl.EvaluateAsync(
            principalArn, action, resource, evaluationContext,
            httpContext?.RequestAborted ?? CancellationToken.None);

        if (decision.IsAllowed)
        {
            context.Succeed(requirement);
            return;
        }

        _logger.LogWarning(
            "IAM denied {Principal} for {Action} on {Resource}: {Reason}",
            principalArn, action, resource, decision.Reason);
    }
}
