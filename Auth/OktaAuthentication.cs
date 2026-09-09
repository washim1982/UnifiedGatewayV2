using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Okta;

namespace UnifiedGateway.Auth;

public static class OktaClaims
{
    public const string Scheme = "Okta";

    /// <summary>Group membership claim as Okta emits it.</summary>
    public const string Groups = "groups";

    /// <summary>Claim recording which directory group granted the mapped role.</summary>
    public const string GrantingGroup = "gateway:granting_group";
}

/// <summary>
/// Configures JWT bearer validation for Okta-issued tokens and maps group membership onto
/// the IAM principal the authorization layer already understands.
///
/// The same validation runs against simulated and real tokens; only the key source differs —
/// the in-process JWKS when the simulator is on, the tenant's discovery document when it is
/// off. Written as a named-options configurator so the signing key resolves through DI.
/// </summary>
public class ConfigureOktaJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly OktaOptions _okta;
    private readonly IServiceProvider _services;

    public ConfigureOktaJwtBearerOptions(IOptions<OktaOptions> okta, IServiceProvider services)
    {
        _okta = okta.Value;
        _services = services;
    }

    public void Configure(JwtBearerOptions options) => Configure(OktaClaims.Scheme, options);

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name != OktaClaims.Scheme)
        {
            return;
        }

        options.Audience = _okta.Audience;
        options.MapInboundClaims = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _okta.Issuer,
            ValidateAudience = true,
            ValidAudience = _okta.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromSeconds(Math.Max(0, _okta.ClockSkewSeconds)),
            NameClaimType = "email",
            RoleClaimType = _okta.GroupsClaim,

            // RS256 only. Without pinning the algorithm a token could assert "alg":"none",
            // or a symmetric algorithm keyed on the public key, and skip verification.
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
        };

        if (_okta.Enabled)
        {
            // Simulated authorization server: trust only the in-process signing key.
            options.RequireHttpsMetadata = false;
            options.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) =>
            {
                var tokenService = _services.GetRequiredService<IOktaTokenService>();
                return [tokenService.GetPublicSigningKey()];
            };
        }
        else
        {
            // Real Okta tenant: standard OIDC discovery and key rotation.
            options.Authority = _okta.Issuer;
            options.MetadataAddress = _okta.MetadataAddress;
            options.RequireHttpsMetadata = true;
        }

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = OnTokenValidated,
            OnAuthenticationFailed = context =>
            {
                Logger(context.HttpContext).LogWarning(
                    "Okta token validation failed: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            }
        };
    }

    /// <summary>
    /// Turns directory group membership into a gateway role.
    ///
    /// The gateway never asks "is this user an admin?" — it reads the groups Okta asserted and
    /// maps them to an IAM role, which the policy engine then evaluates per action. A user in
    /// no mapped group is authenticated but holds no role, so every check denies.
    /// </summary>
    private Task OnTokenValidated(TokenValidatedContext context)
    {
        var logger = Logger(context.HttpContext);

        if (context.Principal?.Identity is not ClaimsIdentity identity)
        {
            context.Fail("Token produced no identity.");
            return Task.CompletedTask;
        }

        var email = context.Principal.FindFirst("email")?.Value ?? "unknown";
        var groups = context.Principal.FindAll(_okta.GroupsClaim).Select(c => c.Value).ToList();

        var match = groups
            .Select(g => _okta.GroupRoleMappings.TryGetValue(g, out var arn) ? (Group: g, Arn: arn) : default)
            .FirstOrDefault(m => m.Arn is not null);

        if (match.Arn is null)
        {
            logger.LogWarning(
                "{Email} authenticated but is in no group mapped to a gateway role (groups: [{Groups}]).",
                email, string.Join(", ", groups));
            return Task.CompletedTask;
        }

        identity.AddClaim(new Claim(GatewayAuth.PrincipalArnClaim, match.Arn));
        identity.AddClaim(new Claim(GatewayAuth.AuthTypeClaim, "OktaJwt"));
        identity.AddClaim(new Claim(OktaClaims.GrantingGroup, match.Group));

        logger.LogInformation(
            "{Email} authenticated via Okta; group '{Group}' maps to {Role}.",
            email, match.Group, match.Arn);

        return Task.CompletedTask;
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("UnifiedGateway.Auth.Okta");
}
