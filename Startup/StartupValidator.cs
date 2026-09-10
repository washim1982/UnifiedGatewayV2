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

        if (cloud.Provider == CloudProviderMode.Aws && !string.IsNullOrWhiteSpace(cloud.BedrockServiceUrl))
        {
            failures.Add(
                "Gateway:Cloud:BedrockServiceUrl overrides the Bedrock endpoint while the provider is " +
                "'Aws'. Clear it so the SDK resolves the real regional endpoint.");
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
}
