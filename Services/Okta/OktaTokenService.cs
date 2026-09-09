using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Okta;

public record OktaTokenResult
{
    public string AccessToken { get; init; } = string.Empty;
    public string TokenType { get; init; } = "Bearer";
    public int ExpiresIn { get; init; }
    public string Scope { get; init; } = "openid profile email groups";
    public string Subject { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public IReadOnlyList<string> Groups { get; init; } = [];
}

public interface IOktaTokenService
{
    /// <summary>Authenticates a directory user and issues a signed OIDC access token.</summary>
    OktaTokenResult? IssueToken(string email, string password);

    /// <summary>Public JWKS document, served the way an Okta authorization server serves it.</summary>
    object GetJwks();

    /// <summary>OIDC discovery document for the simulated authorization server.</summary>
    object GetDiscoveryDocument(string baseUrl);

    /// <summary>Signing key the gateway's JWT validation trusts.</summary>
    SecurityKey GetPublicSigningKey();
}

/// <summary>
/// Issues RS256-signed JWTs from an in-process key pair and publishes the matching JWKS.
///
/// RS256 rather than a shared secret is deliberate: the gateway then validates simulated
/// tokens through exactly the same asymmetric path it will use against a real Okta tenant,
/// so switching to real Okta swaps the key source and nothing else.
/// </summary>
public class OktaTokenService : IOktaTokenService
{
    private const string KeyId = "unified-gateway-okta-sim-key-1";

    private readonly OktaOptions _options;
    private readonly ILogger<OktaTokenService> _logger;
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;

    public OktaTokenService(IOptions<OktaOptions> options, ILogger<OktaTokenService> logger)
    {
        _options = options.Value;
        _logger = logger;

        // Generated per process. Restarting the gateway invalidates outstanding simulated
        // tokens, which is the right behaviour for a local identity provider.
        _rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = KeyId };
    }

    public SecurityKey GetPublicSigningKey() => _signingKey;

    public OktaTokenResult? IssueToken(string email, string password)
    {
        var user = OktaDirectory.FindByEmail(email);

        // Always run the comparison, even for an unknown user, so the response time does
        // not distinguish "no such user" from "wrong password".
        var passwordOk = OktaDirectory.VerifyPassword(user, password);

        if (user is null || !passwordOk || !user.IsActive)
        {
            _logger.LogWarning("Okta simulator rejected sign-in for '{Email}'.", email);
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(Math.Max(1, _options.TokenLifetimeMinutes));

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Name, user.DisplayName),
            new(JwtRegisteredClaimNames.GivenName, user.FirstName),
            new(JwtRegisteredClaimNames.FamilyName, user.LastName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("email_verified", "true", ClaimValueTypes.Boolean),
            new("preferred_username", user.Email)
        };

        // Group membership is what the gateway authorizes on.
        foreach (var group in user.GroupNames)
        {
            claims.Add(new Claim(_options.GroupsClaim, group));
        }

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));

        var encoded = new JwtSecurityTokenHandler().WriteToken(token);

        _logger.LogInformation(
            "Okta simulator issued a token for {Email} in groups [{Groups}], valid until {Expiry:u}.",
            user.Email, string.Join(", ", user.GroupNames), expiresAt);

        return new OktaTokenResult
        {
            AccessToken = encoded,
            ExpiresIn = (int)(expiresAt - now).TotalSeconds,
            Subject = user.Id,
            Email = user.Email,
            Groups = user.GroupNames
        };
    }

    public object GetJwks()
    {
        var parameters = _rsa.ExportParameters(includePrivateParameters: false);

        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = KeyId,
                    n = Base64UrlEncoder.Encode(parameters.Modulus),
                    e = Base64UrlEncoder.Encode(parameters.Exponent)
                }
            }
        };
    }

    public object GetDiscoveryDocument(string baseUrl) => new
    {
        issuer = _options.Issuer,
        authorization_endpoint = $"{baseUrl}/okta/oauth2/v1/authorize",
        token_endpoint = $"{baseUrl}/okta/oauth2/v1/token",
        userinfo_endpoint = $"{baseUrl}/okta/oauth2/v1/userinfo",
        jwks_uri = $"{baseUrl}/okta/oauth2/v1/keys",
        response_types_supported = new[] { "token", "id_token" },
        grant_types_supported = new[] { "password" },
        subject_types_supported = new[] { "public" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        scopes_supported = new[] { "openid", "profile", "email", "groups" },
        claims_supported = new[] { "sub", "email", "name", "groups" }
    };
}
