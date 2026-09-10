using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud;
using UnifiedGateway.Services.Cloud.LocalDotNet;

namespace UnifiedGateway.Startup;

/// <summary>
/// Prepares the cloud-backed material the gateway needs before it can serve traffic:
/// the KMS-encrypted token signing key and the admin credential. Runs against whichever
/// provider the environment bound, so the same bootstrap works for the simulator and AWS.
/// </summary>
public class CloudBootstrapService : IHostedService
{
    private readonly ISigningKeyProvider _signingKeys;
    private readonly IAdminCredentialService _adminCredentials;
    private readonly ICryptoProvider _crypto;
    private readonly LocalDotNetHealthCheck _localDotNetHealth;
    private readonly CloudOptions _options;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<CloudBootstrapService> _logger;

    public CloudBootstrapService(
        ISigningKeyProvider signingKeys,
        IAdminCredentialService adminCredentials,
        ICryptoProvider crypto,
        LocalDotNetHealthCheck localDotNetHealth,
        IOptions<CloudOptions> options,
        IHostEnvironment environment,
        ILogger<CloudBootstrapService> logger)
    {
        _signingKeys = signingKeys;
        _adminCredentials = adminCredentials;
        _crypto = crypto;
        _localDotNetHealth = localDotNetHealth;
        _options = options.Value;
        _environment = environment;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "Cloud provider mode: {Provider}. Verifying key management availability.", _options.Provider);

        // Before anything else, confirm the configured URLs are the services we think they
        // are. Two local simulators share these ports with different service assignments, so
        // a wrong-stack mix-up otherwise shows up much later as a decrypt failure.
        if (_options.Provider == CloudProviderMode.LocalDotNet)
        {
            var endpoints = await _localDotNetHealth.ProbeAsync(cancellationToken);

            foreach (var endpoint in endpoints.Where(e => !e.IsCorrectService))
            {
                _logger.LogError(
                    "{Expected} is not answering at {Url}: {Problem}. The .NET simulator and the " +
                    "Docker simulator both use ports 5001-5003 with different services on each; " +
                    "stop one before starting the other, or give them distinct ports.",
                    endpoint.Expected, endpoint.Url, endpoint.Problem);
            }

            if (endpoints.All(e => e.IsCorrectService))
            {
                _logger.LogInformation(
                    "Local .NET AWS simulator verified: S3Local, KmsLocal and IamLocal all responding as expected.");
            }
        }

        var available = await _crypto.IsAvailableAsync(cancellationToken);
        if (!available)
        {
            // Do not fail startup: the gateway can still serve local-model traffic, and a
            // transient KMS outage should not take the whole service down. Token issuance
            // fails closed on its own until the key store comes back.
            _logger.LogError(
                "Key management is not reachable for provider {Provider}. STS token issuance and " +
                "validation will fail until it recovers.", _options.Provider);
            return;
        }

        try
        {
            await _signingKeys.EnsureInitializedAsync(cancellationToken);

            var material = await _signingKeys.GetCurrentAsync(cancellationToken);
            _logger.LogInformation(
                "STS signing key ready at generation {Generation}, sourced from '{Secret}'.",
                material.Generation, _options.Secrets.StsSigningKeyName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prepare the STS signing key.");
        }

        try
        {
            var bootstrapped = await _adminCredentials.EnsureInitializedAsync(cancellationToken);
            if (bootstrapped is not null && _environment.IsDevelopment())
            {
                // Printed once, in Development only, so a fresh local environment is usable.
                _logger.LogWarning(
                    "Bootstrapped admin credential (Development only, shown once): {AdminKey}", bootstrapped);
            }
            else if (bootstrapped is not null)
            {
                _logger.LogInformation(
                    "Bootstrapped the admin credential into '{Secret}'. Read it from the secret store.",
                    _options.Secrets.AdminApiKeyName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prepare the admin credential.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
