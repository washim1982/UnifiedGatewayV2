using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud;

/// <summary>
/// Resolves the master admin credential from the environment's secret store, falling back to
/// configuration only in Development. Nothing else in the codebase reads the raw config value.
/// </summary>
public interface IAdminCredentialService
{
    Task<string?> GetAdminApiKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>Constant-time comparison of a presented credential against the stored one.</summary>
    Task<bool> VerifyAsync(string presented, CancellationToken cancellationToken = default);

    /// <summary>Creates the admin credential in the secret store if it is not there yet.</summary>
    Task<string?> EnsureInitializedAsync(CancellationToken cancellationToken = default);
}

public class AdminCredentialService : IAdminCredentialService
{
    private readonly ISecretsProvider _secrets;
    private readonly ISecurityService _security;
    private readonly CloudOptions _cloudOptions;
    private readonly SecurityOptions _securityOptions;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<AdminCredentialService> _logger;

    public AdminCredentialService(
        ISecretsProvider secrets,
        ISecurityService security,
        IOptions<CloudOptions> cloudOptions,
        IOptions<GatewayOptions> gatewayOptions,
        IHostEnvironment environment,
        ILogger<AdminCredentialService> logger)
    {
        _secrets = secrets;
        _security = security;
        _cloudOptions = cloudOptions.Value;
        _securityOptions = gatewayOptions.Value.Security;
        _environment = environment;
        _logger = logger;
    }

    public async Task<string?> GetAdminApiKeyAsync(CancellationToken cancellationToken = default)
    {
        var fromStore = await _secrets.GetSecretAsync(_cloudOptions.Secrets.AdminApiKeyName, cancellationToken);
        if (!string.IsNullOrWhiteSpace(fromStore))
        {
            return fromStore;
        }

        if (_environment.IsDevelopment() && !string.IsNullOrWhiteSpace(_securityOptions.AdminApiKey))
        {
            _logger.LogWarning(
                "Using the configured admin key from appsettings. This fallback exists only in Development.");
            return _securityOptions.AdminApiKey;
        }

        return null;
    }

    public async Task<bool> VerifyAsync(string presented, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(presented))
        {
            return false;
        }

        var expected = await GetAdminApiKeyAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(expected))
        {
            _logger.LogError("No admin credential is available; denying admin authentication.");
            return false;
        }

        return _security.VerifyKey(presented, _security.HashKey(expected));
    }

    public async Task<string?> EnsureInitializedAsync(CancellationToken cancellationToken = default)
    {
        var existing = await _secrets.GetSecretAsync(_cloudOptions.Secrets.AdminApiKeyName, cancellationToken);
        if (!string.IsNullOrWhiteSpace(existing))
        {
            return null;
        }

        var (rawKey, _, _) = _security.GenerateApiKey();
        await _secrets.PutSecretAsync(_cloudOptions.Secrets.AdminApiKeyName, rawKey, cancellationToken);

        _logger.LogInformation(
            "Bootstrapped the admin credential into secret '{Secret}'.",
            _cloudOptions.Secrets.AdminApiKeyName);

        // Returned once so the bootstrapper can surface it to the operator.
        return rawKey;
    }
}
