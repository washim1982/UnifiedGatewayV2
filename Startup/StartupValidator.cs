using System.Text.RegularExpressions;
using UnifiedGateway.Models;

namespace UnifiedGateway.Startup;

/// <summary>
/// Refuses to start on a configuration that would be insecure in a reachable environment.
/// A gateway that starts insecure is worse than one that will not start: the first fails
/// silently in production, the second fails loudly in the deploy pipeline.
/// </summary>
public static partial class StartupValidator
{
    private static readonly string[] KnownDefaultAdminKeys =
    [
        "ug-admin-default-change-in-prod",
        "ug-admin-secret-key-change-in-production",
        "ug-dev-admin-key",
        "__PROD_ADMIN_API_KEY_INJECTED_AT_DEPLOY__",
        "changeme",
        "admin"
    ];

    public static void Validate(
        GatewayOptions gateway,
        CloudOptions cloud,
        IHostEnvironment environment,
        OktaOptions? okta = null)
    {
        var failures = new List<string>();

        // Development is the only exemption from the transport and authentication rules below:
        // it is the one environment that runs on a developer's loopback. Test and Staging are
        // network hosts whatever data they hold, and a key sent to them in clear is exposed.
        var isDevelopment = environment.IsDevelopment();

        // --- Admin credential -------------------------------------------------
        var adminKey = gateway.Security.AdminApiKey;
        if (!string.IsNullOrWhiteSpace(adminKey))
        {
            if (KnownDefaultAdminKeys.Contains(adminKey, StringComparer.OrdinalIgnoreCase))
            {
                failures.Add(
                    $"Gateway:Security:AdminApiKey is set to the shipped default '{adminKey}'. " +
                    "Remove it and let the gateway read the credential from the secret store " +
                    $"('{cloud.Secrets.AdminApiKeyName}').");
            }
            else if (!isDevelopment)
            {
                failures.Add(
                    "Gateway:Security:AdminApiKey is set in configuration. Outside Development the " +
                    "admin credential must come from the secret store, not a config file.");
            }
            else if (adminKey.Length < 16)
            {
                failures.Add("Gateway:Security:AdminApiKey is shorter than 16 characters.");
            }
        }

        // --- Authentication kill switch ---------------------------------------
        if (!gateway.Security.EnforceAppApiKey && !isDevelopment)
        {
            failures.Add(
                "Gateway:Security:EnforceAppApiKey is false, which disables application " +
                "authentication entirely. This is only permitted in Development.");
        }

        // --- CORS --------------------------------------------------------------
        if (gateway.Security.AllowedCorsOrigins.Contains("*") && !isDevelopment)
        {
            failures.Add(
                "Gateway:Security:AllowedCorsOrigins contains '*'. Name the permitted origins " +
                "explicitly; a wildcard lets any page script the management API.");
        }

        // --- Transport ---------------------------------------------------------
        if (!gateway.Security.RequireHttps && !isDevelopment)
        {
            failures.Add(
                "Gateway:Security:RequireHttps is false. API keys and STS tokens would travel " +
                "in clear text. This is only permitted in Development.");
        }

        if (gateway.Security.HttpsPort is < 1 or > 65535)
        {
            failures.Add($"Gateway:Security:HttpsPort is {gateway.Security.HttpsPort}; it must be a TCP port.");
        }

        if (gateway.Security.RequireHttps && gateway.Security.HstsMaxAgeDays < 1)
        {
            failures.Add("Gateway:Security:HstsMaxAgeDays must be at least 1 when HTTPS is required.");
        }

        // --- Token lifetimes ---------------------------------------------------
        if (gateway.Security.MaxStsTokenLifetimeSeconds > 86_400)
        {
            failures.Add(
                $"Gateway:Security:MaxStsTokenLifetimeSeconds is {gateway.Security.MaxStsTokenLifetimeSeconds}. " +
                "A 'short temporary secret' longer than 24 hours is a long-lived credential; " +
                "cap it at 3600 unless there is a documented reason.");
        }

        if (gateway.Security.DefaultStsTokenLifetimeSeconds > gateway.Security.MaxStsTokenLifetimeSeconds)
        {
            failures.Add("Gateway:Security:DefaultStsTokenLifetimeSeconds exceeds the configured maximum.");
        }

        if (gateway.Security.MaxAdminStsTokenLifetimeSeconds > 3600)
        {
            failures.Add(
                $"Gateway:Security:MaxAdminStsTokenLifetimeSeconds is {gateway.Security.MaxAdminStsTokenLifetimeSeconds}. " +
                "An admin token is the break-glass credential turned into a bearer token; cap it at an hour.");
        }

        // --- Access control ----------------------------------------------------
        if (!cloud.AccessControl.Enabled && cloud.AccessControl.AdminRoleArns.Length == 0 && !isDevelopment)
        {
            failures.Add(
                "Gateway:Cloud:AccessControl is disabled and no AdminRoleArns are listed, so every " +
                "authenticated caller would be a full administrator.");
        }

        // --- Break-glass -------------------------------------------------------
        // Break-glass acts as a configured principal. Without one it would have to be derived
        // from something the caller supplies, which is how the audit trail gets forged.
        if (!isDevelopment)
        {
            var breakGlass = cloud.AccessControl.BreakGlassPrincipalArn;
            if (string.IsNullOrWhiteSpace(breakGlass))
            {
                failures.Add(
                    "Gateway:Cloud:AccessControl:BreakGlassPrincipalArn is not set. The break-glass " +
                    "credential must act as a named principal so every use of it is attributable.");
            }
            else if (IsPlaceholder(breakGlass))
            {
                failures.Add(
                    $"Gateway:Cloud:AccessControl:BreakGlassPrincipalArn still contains a placeholder ('{breakGlass}'). " +
                    "Substitute the real ARN at deploy time.");
            }
            else if (!breakGlass.StartsWith("arn:", StringComparison.Ordinal))
            {
                failures.Add($"Gateway:Cloud:AccessControl:BreakGlassPrincipalArn is not an ARN ('{breakGlass}').");
            }
        }

        // --- Provider wiring ---------------------------------------------------
        // Both simulators authenticate a caller by role name or session id alone. That proves
        // nothing, so neither may run anywhere a network can reach.
        if (cloud.Provider == CloudProviderMode.Simulator && !isDevelopment)
        {
            failures.Add(
                $"Gateway:Cloud:Provider is 'Simulator' in the '{environment.EnvironmentName}' environment. " +
                "The Python AWS simulator accepts a role name as proof of identity; it is for Development only.");
        }

        // The .NET simulator holds keys in a dev key file and auto-creates any role that is
        // asked for, so a principal is never actually refused. That is fine for a developer
        // loop and unacceptable anywhere else.
        if (cloud.Provider == CloudProviderMode.LocalDotNet && !isDevelopment)
        {
            failures.Add(
                $"Gateway:Cloud:Provider is 'LocalDotNet' in the '{environment.EnvironmentName}' environment. " +
                "The .NET local AWS simulator is for Development only; use 'Aws' elsewhere.");
        }

        ValidateAwsIdentity(cloud, failures);
        ValidateOkta(okta ?? new OktaOptions(), environment, isDevelopment, failures);

        // --- Bedrock ------------------------------------------------------------
        // Bedrock resolves independently of the global provider so that Development can run
        // the control plane on the local simulator while model calls reach the real service.
        var bedrockProvider = cloud.EffectiveBedrockProvider;

        // The .NET simulator has no Bedrock at all. Inheriting it would leave every model
        // call failing at the transport layer with nothing naming the cause, so the choice
        // has to be made explicitly.
        if (bedrockProvider == CloudProviderMode.LocalDotNet)
        {
            failures.Add(
                "Bedrock has no provider: Gateway:Cloud:Provider is 'LocalDotNet', which does not " +
                "implement Bedrock. Set Gateway:Cloud:BedrockProvider to 'Aws' to call the real " +
                "service, or to 'Simulator' to point it at a Bedrock-compatible endpoint.");
        }

        if (bedrockProvider == CloudProviderMode.Aws && !string.IsNullOrWhiteSpace(cloud.BedrockServiceUrl))
        {
            failures.Add(
                "Gateway:Cloud:BedrockServiceUrl overrides the Bedrock endpoint while Bedrock resolves " +
                "to 'Aws'. Clear it so the SDK resolves the real regional endpoint.");
        }

        if (bedrockProvider == CloudProviderMode.Simulator && string.IsNullOrWhiteSpace(cloud.BedrockServiceUrl))
        {
            failures.Add(
                "Bedrock resolves to 'Simulator' but Gateway:Cloud:BedrockServiceUrl is empty, so the " +
                "SDK would call the real regional endpoint with simulated credentials.");
        }

        // --- AWS credential source ----------------------------------------------
        var credentialSource = gateway.Aws.EffectiveCredentialSource;

        // A named profile is a developer's own credential. It is the right thing in a local
        // loop and the wrong thing on a shared host, where the identity must be the host's.
        if (credentialSource == AwsCredentialSource.LocalProfile && !isDevelopment)
        {
            failures.Add(
                $"Gateway:Aws resolves to a local ~/.aws profile in the '{environment.EnvironmentName}' " +
                "environment. That is a developer's own credential; set Gateway:Aws:CredentialSource to " +
                "'RolesAnywhere' so the host authenticates with its own certificate.");
        }

        // The gateway deploys to IIS, so there is no instance or task role to inherit. Every
        // alternative to Roles Anywhere therefore ends at a long-lived access key stored on
        // the host -- exactly the credential this design exists to remove.
        if (credentialSource != AwsCredentialSource.RolesAnywhere && RequiresRolesAnywhere(environment))
        {
            failures.Add(
                $"Gateway:Aws:CredentialSource is '{credentialSource}' in the " +
                $"'{environment.EnvironmentName}' environment. There is no instance or task role to " +
                "inherit under IIS, so anything but 'RolesAnywhere' resolves to a long-lived access key " +
                "on the host. Configure IAM Roles Anywhere.");
        }

        if (credentialSource == AwsCredentialSource.RolesAnywhere)
        {
            ValidateRolesAnywhere(gateway.Aws.RolesAnywhere, environment, isDevelopment, failures);
        }

        if (failures.Count == 0)
        {
            return;
        }

        var message = "Refusing to start. Fix the following configuration problems:" +
                      Environment.NewLine +
                      string.Join(Environment.NewLine, failures.Select(f => "  - " + f));

        throw new InvalidOperationException(message);
    }

    /// <summary>
    /// Environments that reach real AWS and must do so with a host identity rather than a
    /// stored key. Development is exempt because it talks to the local simulator, and its one
    /// real dependency -- Bedrock -- deliberately uses the developer's own profile.
    /// </summary>
    private static bool RequiresRolesAnywhere(IHostEnvironment environment) =>
        !environment.IsDevelopment();

    private static bool IsPlaceholder(string value) => value.Contains('<') || value.Contains('>');

    /// <summary>
    /// Automation proving an IAM identity with a signed GetCallerIdentity request. Off by
    /// default; when on, every setting that scopes whom it admits has to be real.
    /// </summary>
    private static void ValidateAwsIdentity(CloudOptions cloud, List<string> failures)
    {
        var identity = cloud.AwsIdentity;
        if (!identity.Enabled)
        {
            return;
        }

        if (cloud.Provider != CloudProviderMode.Aws)
        {
            failures.Add("Gateway:Cloud:AwsIdentity is enabled, but it only applies when Gateway:Cloud:Provider is 'Aws'.");
        }

        if (string.IsNullOrWhiteSpace(identity.ServerId) || identity.ServerId.Length < 8)
        {
            failures.Add(
                "Gateway:Cloud:AwsIdentity:ServerId must be at least 8 characters. Callers sign it into " +
                "X-Gateway-Server-Id, which binds each signed request to this gateway.");
        }
        else if (IsPlaceholder(identity.ServerId))
        {
            failures.Add($"Gateway:Cloud:AwsIdentity:ServerId still contains a placeholder ('{identity.ServerId}').");
        }

        if (identity.AllowedAccountIds.Length == 0)
        {
            failures.Add(
                "Gateway:Cloud:AwsIdentity:AllowedAccountIds is empty. Name the AWS accounts whose " +
                "principals may manage the gateway.");
        }

        foreach (var account in identity.AllowedAccountIds)
        {
            if (IsPlaceholder(account))
            {
                failures.Add($"Gateway:Cloud:AwsIdentity:AllowedAccountIds still contains a placeholder ('{account}').");
            }
            else if (!AccountIdRegex().IsMatch(account))
            {
                failures.Add($"Gateway:Cloud:AwsIdentity:AllowedAccountIds entry '{account}' is not a 12-digit AWS account id.");
            }
        }

        foreach (var host in identity.AllowedStsHosts)
        {
            if (!StsHostRegex().IsMatch(host))
            {
                failures.Add(
                    $"Gateway:Cloud:AwsIdentity:AllowedStsHosts entry '{host}' is not an AWS STS hostname. " +
                    "The gateway forwards signed requests to STS and nowhere else.");
            }
        }

        if (identity.MaxRequestAgeSeconds is < 30 or > 900)
        {
            failures.Add(
                $"Gateway:Cloud:AwsIdentity:MaxRequestAgeSeconds is {identity.MaxRequestAgeSeconds}. " +
                "Use 30 to 900 seconds; STS itself rejects signatures older than fifteen minutes.");
        }
    }

    /// <summary>
    /// Operator sign-in. The simulator signs admin tokens for users compiled into the binary,
    /// so outside Development it would be a published admin password. Everywhere else the
    /// gateway validates the real tenant, whose URLs and role mappings must be substituted.
    /// </summary>
    private static void ValidateOkta(OktaOptions okta, IHostEnvironment environment, bool isDevelopment, List<string> failures)
    {
        if (isDevelopment)
        {
            return;
        }

        if (okta.Enabled)
        {
            failures.Add(
                $"Gateway:Okta:Enabled is true in the '{environment.EnvironmentName}' environment. The Okta " +
                "simulator issues admin tokens for a directory compiled into the binary; it is for " +
                "Development only. Set it to false and point Gateway:Okta:Issuer at the real tenant.");
            return;
        }

        CheckTenantUrl("Issuer", okta.Issuer, failures);
        CheckTenantUrl("MetadataAddress", okta.MetadataAddress, failures);

        foreach (var (group, arn) in okta.GroupRoleMappings)
        {
            if (IsPlaceholder(arn))
            {
                failures.Add(
                    $"Gateway:Okta:GroupRoleMappings:{group} still contains a placeholder ('{arn}'). " +
                    "Substitute the real role ARN at deploy time.");
            }
            else if (!arn.StartsWith("arn:", StringComparison.Ordinal))
            {
                failures.Add($"Gateway:Okta:GroupRoleMappings:{group} is not a role ARN ('{arn}').");
            }
        }
    }

    private static void CheckTenantUrl(string setting, string value, List<string> failures)
    {
        // Empty means Okta sign-in is not configured, leaving only break-glass and AWS identity
        // on the management plane. That is a valid, if narrow, deployment.
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (IsPlaceholder(value))
        {
            failures.Add(
                $"Gateway:Okta:{setting} still contains a placeholder ('{value}'). " +
                "Substitute the tenant URL at deploy time.");
        }
        else if (!value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            failures.Add(
                $"Gateway:Okta:{setting} must use HTTPS ('{value}'). Signing keys fetched over HTTP " +
                "can be substituted in transit, and a substituted key signs any token it likes.");
        }
    }

    private static void ValidateRolesAnywhere(
        RolesAnywhereOptions rolesAnywhere,
        IHostEnvironment environment,
        bool isDevelopment,
        List<string> failures)
    {
        var required = new (string Name, string Value)[]
        {
            ("TrustAnchorArn", rolesAnywhere.TrustAnchorArn),
            ("ProfileArn", rolesAnywhere.ProfileArn),
            ("RoleArn", rolesAnywhere.RoleArn)
        };

        foreach (var (name, value) in required)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                failures.Add($"Gateway:Aws:RolesAnywhere:{name} is required when CredentialSource is 'RolesAnywhere'.");
            }
            else if (value.Contains('<') || value.Contains('>'))
            {
                // The shipped templates carry <account-id> placeholders, and a deploy that
                // forgets to substitute them fails at the first AWS call rather than at start.
                failures.Add(
                    $"Gateway:Aws:RolesAnywhere:{name} still contains a placeholder ('{value}'). " +
                    "Substitute the real ARN at deploy time.");
            }
        }

        // AWS rejects anything outside this range, and the failure it returns says only
        // "ValidationException", which is a poor place to learn about it.
        if (rolesAnywhere.DurationSeconds is < 900 or > 3600)
        {
            failures.Add(
                $"Gateway:Aws:RolesAnywhere:DurationSeconds is {rolesAnywhere.DurationSeconds}. " +
                "IAM Roles Anywhere accepts 900 to 3600 seconds.");
        }

        // Both of these turn a production deployment into something that is not talking to
        // AWS at all, while still reporting healthy.
        if (!isDevelopment && !string.IsNullOrWhiteSpace(rolesAnywhere.EndpointOverride))
        {
            failures.Add(
                $"Gateway:Aws:RolesAnywhere:EndpointOverride is set in the '{environment.EnvironmentName}' " +
                "environment. Clear it so credentials come from the real Roles Anywhere endpoint.");
        }

        ValidateCertificate(rolesAnywhere.Certificate, failures);
    }

    private static void ValidateCertificate(CertificateOptions certificate, List<string> failures)
    {
        switch (certificate.Source)
        {
            case CertificateSource.WindowsStore when string.IsNullOrWhiteSpace(certificate.Thumbprint):
                failures.Add(
                    "Gateway:Aws:RolesAnywhere:Certificate:Thumbprint is required when Source is 'WindowsStore'.");
                break;

            // Checked only for the source that actually reads it. The base appsettings ships a
            // placeholder thumbprint, and an environment selecting PemFile inherits it without
            // ever using it -- failing on that would be refusing to start over a field the
            // configuration does not consult.
            case CertificateSource.WindowsStore when
                certificate.Thumbprint.Contains('<') || certificate.Thumbprint.Contains('>'):
                failures.Add(
                    "Gateway:Aws:RolesAnywhere:Certificate:Thumbprint still contains a placeholder " +
                    $"('{certificate.Thumbprint}'). Substitute the installed certificate's thumbprint.");
                break;

            case CertificateSource.PemFile when
                string.IsNullOrWhiteSpace(certificate.CertificatePath) ||
                string.IsNullOrWhiteSpace(certificate.PrivateKeyPath):
                failures.Add(
                    "Gateway:Aws:RolesAnywhere:Certificate needs both CertificatePath and PrivateKeyPath " +
                    "when Source is 'PemFile'.");
                break;

            case CertificateSource.PfxFile when string.IsNullOrWhiteSpace(certificate.PfxPath):
                failures.Add("Gateway:Aws:RolesAnywhere:Certificate:PfxPath is required when Source is 'PfxFile'.");
                break;
        }
    }

    [GeneratedRegex(@"^\d{12}$")]
    private static partial Regex AccountIdRegex();

    [GeneratedRegex(@"^sts(-fips)?(\.[a-z0-9-]+)?\.amazonaws\.com(\.cn)?$", RegexOptions.IgnoreCase)]
    private static partial Regex StsHostRegex();
}
