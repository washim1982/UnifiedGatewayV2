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
/// Authenticates management-plane callers. Three credential shapes are accepted, in order:
///
///   1. An IAM session credential (simulator STS access key, or an upstream-asserted
///      principal ARN in AWS) — resolved through <see cref="IIdentityProvider"/>.
///   2. A gateway admin STS token (ug_sts_ with isAdmin).
///   3. The master admin credential from the secret store — break-glass.
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

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var presented = ExtractCredential(Request);
        if (string.IsNullOrWhiteSpace(presented))
        {
            return AuthenticateResult.NoResult();
        }

        // 1. Gateway-issued admin STS token.
        if (presented.StartsWith("ug_sts_", StringComparison.Ordinal))
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

            return Success(
                principalArn: BuildPrincipalArn(payload.CallerId ?? payload.AppId),
                authType: "GatewayAdminStsToken",
                subject: payload.CallerId ?? payload.AppId);
        }

        // 2. Master admin credential (break-glass).
        if (await _adminCredentials.VerifyAsync(presented))
        {
            Logger.LogWarning(
                "Master admin credential used from {RemoteIp}. This should be rare and alerted on.",
                Context.Connection.RemoteIpAddress);

            return Success(
                principalArn: BuildPrincipalArn("GatewayBreakGlass"),
                authType: "MasterAdminKey",
                subject: "break-glass");
        }

        // 3. IAM session credential resolved by the environment's identity provider.
        var identity = await _identityProvider.ResolveAsync(presented);
        if (identity.IsAuthenticated)
        {
            return Success(identity.PrincipalArn, identity.AuthType, identity.PrincipalArn);
        }

        Logger.LogWarning("Management authentication failed: {Reason}", identity.FailureReason);
        return AuthenticateResult.Fail(identity.FailureReason ?? "Unrecognised credential");
    }

    private AuthenticateResult Success(string principalArn, string authType, string subject)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, subject),
            new(GatewayAuth.PrincipalArnClaim, principalArn),
            new(GatewayAuth.AuthTypeClaim, authType)
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, GatewayAuth.Scheme));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, GatewayAuth.Scheme));
    }

    private string BuildPrincipalArn(string roleName)
    {
        if (roleName.StartsWith("arn:aws:", StringComparison.OrdinalIgnoreCase))
        {
            return roleName;
        }

        var configured = _cloudOptions.AccessControl.AdminRoleArns.FirstOrDefault();
        return string.IsNullOrWhiteSpace(configured)
            ? $"arn:aws:iam::123456789012:role/{roleName}"
            : configured;
    }

    private static string ExtractCredential(HttpRequest request)
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
