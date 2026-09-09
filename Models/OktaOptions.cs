namespace UnifiedGateway.Models;

/// <summary>
/// Okta configuration.
///
/// The gateway always validates a standard OIDC JWT. What changes between a local
/// simulated Okta and a real Okta tenant is where the signing keys come from:
///   - Simulator: <see cref="Enabled"/> true, keys served from this process at /okta/oauth2/v1/keys
///   - Real Okta: <see cref="Enabled"/> false, <see cref="MetadataAddress"/> set to the tenant's
///     .well-known/openid-configuration
/// The validation and authorization code is identical in both cases.
/// </summary>
public class OktaOptions
{
    public const string SectionName = "Gateway:Okta";

    /// <summary>Run the built-in Okta simulator (issues tokens and serves JWKS locally).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Issuer claim written into simulated tokens and required on validation.</summary>
    public string Issuer { get; set; } = "https://okta-sim.local/oauth2/default";

    /// <summary>Audience claim written into simulated tokens and required on validation.</summary>
    public string Audience { get; set; } = "unified-gateway";

    /// <summary>Lifetime of a simulated access token.</summary>
    public int TokenLifetimeMinutes { get; set; } = 60;

    /// <summary>
    /// OIDC discovery document for a real Okta tenant, e.g.
    /// https://dev-123456.okta.com/oauth2/default/.well-known/openid-configuration
    /// Leave empty when the simulator is enabled.
    /// </summary>
    public string MetadataAddress { get; set; } = string.Empty;

    /// <summary>Claim carrying group membership. Okta uses "groups" by default.</summary>
    public string GroupsClaim { get; set; } = "groups";

    /// <summary>
    /// Maps a directory group to the IAM role the gateway authorizes it as. This is the
    /// bridge between identity (Okta) and authorization (IAM policy evaluation) — the same
    /// shape as an Okta-to-AWS federation mapping.
    /// </summary>
    public Dictionary<string, string> GroupRoleMappings { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Clock skew tolerated on token expiry, in seconds.</summary>
    public int ClockSkewSeconds { get; set; } = 60;
}
