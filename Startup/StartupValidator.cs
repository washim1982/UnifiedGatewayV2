using UnifiedGateway.Models;

namespace UnifiedGateway.Startup;

/// <summary>
/// Refuses to start on a configuration that would be insecure in a reachable environment.
/// A gateway that starts insecure is worse than one that will not start: the first fails
/// silently in production, the second fails loudly in the deploy pipeline.
/// </summary>
public static class StartupValidator
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

    public static void Validate(GatewayOptions gateway, CloudOptions cloud, IHostEnvironment environment)
    {
        var failures = new List<string>();
        var isDevelopment = environment.IsDevelopment();

        // Development and Test run on loopback against the local AWS simulator, so plain
        // HTTP is acceptable there. Staging and Production are network-reachable and are not
        // granted the exemption.
        var isLoopbackEnvironment = isDevelopment || environment.IsEnvironment("Test");

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
        if (!gateway.Security.EnforceAppApiKey && !isLoopbackEnvironment)
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
        if (!gateway.Security.RequireHttps && !isLoopbackEnvironment)
        {
            failures.Add(
                "Gateway:Security:RequireHttps is false. API keys and STS tokens would travel " +
                "in clear text. This is only permitted in Development and Test.");
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

        // --- Access control ----------------------------------------------------
        if (!cloud.AccessControl.Enabled && cloud.AccessControl.AdminRoleArns.Length == 0 && !isDevelopment)
        {
            failures.Add(
                "Gateway:Cloud:AccessControl is disabled and no AdminRoleArns are listed, so every " +
                "authenticated caller would be a full administrator.");
        }

        // --- Provider wiring ---------------------------------------------------
        if (cloud.Provider == CloudProviderMode.Simulator && !isDevelopment && !IsTestLike(environment))
        {
            failures.Add(
                $"Gateway:Cloud:Provider is 'Simulator' in the '{environment.EnvironmentName}' environment. " +
                "The local AWS simulator is for Development and Test only.");
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

    private static bool IsTestLike(IHostEnvironment environment) =>
        environment.IsEnvironment("Test") || environment.IsEnvironment("Staging");

    /// <summary>
    /// Environments that reach real AWS and must do so with a host identity rather than a
    /// stored key. Development is exempt because it talks to the local simulator, and its one
    /// real dependency -- Bedrock -- deliberately uses the developer's own profile.
    /// </summary>
    private static bool RequiresRolesAnywhere(IHostEnvironment environment) =>
        !environment.IsDevelopment();

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
}
