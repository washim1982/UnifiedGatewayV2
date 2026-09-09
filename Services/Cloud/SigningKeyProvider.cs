using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud;

/// <summary>Signing material for application STS tokens, plus the generation it belongs to.</summary>
public record SigningKeyMaterial
{
    /// <summary>Raw HMAC key bytes.</summary>
    public byte[] Key { get; init; } = [];

    /// <summary>
    /// Monotonic generation number. It is stamped into every issued token and checked on
    /// validation, so rotating the key invalidates outstanding tokens immediately.
    /// </summary>
    public int Generation { get; init; }
}

public interface ISigningKeyProvider
{
    /// <summary>Current signing material, fetched from the secret store and cached.</summary>
    Task<SigningKeyMaterial> GetCurrentAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates fresh signing material at generation+1 and persists it. Every token signed
    /// with a previous generation stops validating.
    /// </summary>
    Task<SigningKeyMaterial> RotateAsync(CancellationToken cancellationToken = default);

    /// <summary>Creates the signing key if the secret store does not have one yet.</summary>
    Task EnsureInitializedAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Holds the gateway's token-signing key in the environment's secret store (KMS-encrypted
/// in the simulator, Secrets Manager + KMS in AWS) rather than in a local DataProtection
/// key ring on the web tier.
/// </summary>
public class SigningKeyProvider : ISigningKeyProvider
{
    private sealed record StoredSigningKey
    {
        public string KeyBase64 { get; init; } = string.Empty;
        public int Generation { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
    }

    private readonly ISecretsProvider _secrets;
    private readonly CloudOptions _options;
    private readonly ILogger<SigningKeyProvider> _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private SigningKeyMaterial? _cached;
    private DateTimeOffset _cachedAt = DateTimeOffset.MinValue;

    public SigningKeyProvider(
        ISecretsProvider secrets,
        IOptions<CloudOptions> options,
        ILogger<SigningKeyProvider> logger)
    {
        _secrets = secrets;
        _options = options.Value;
        _logger = logger;
    }

    private string SecretName => _options.Secrets.StsSigningKeyName;

    public async Task<SigningKeyMaterial> GetCurrentAsync(CancellationToken cancellationToken = default)
    {
        var ttl = TimeSpan.FromSeconds(Math.Max(5, _options.Secrets.CacheSeconds));
        if (_cached is not null && DateTimeOffset.UtcNow - _cachedAt < ttl)
        {
            return _cached;
        }

        await _lock.WaitAsync(cancellationToken);
        try
        {
            if (_cached is not null && DateTimeOffset.UtcNow - _cachedAt < ttl)
            {
                return _cached;
            }

            var raw = await _secrets.GetSecretAsync(SecretName, cancellationToken);
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new InvalidOperationException(
                    $"Token signing key '{SecretName}' is not present in the secret store. " +
                    "The gateway cannot issue or validate STS tokens.");
            }

            var stored = JsonSerializer.Deserialize<StoredSigningKey>(raw)
                ?? throw new InvalidOperationException($"Signing key secret '{SecretName}' is malformed.");

            _cached = new SigningKeyMaterial
            {
                Key = Convert.FromBase64String(stored.KeyBase64),
                Generation = stored.Generation
            };
            _cachedAt = DateTimeOffset.UtcNow;

            return _cached;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<SigningKeyMaterial> RotateAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var currentGeneration = 0;
            var existing = await _secrets.GetSecretAsync(SecretName, cancellationToken);
            if (!string.IsNullOrWhiteSpace(existing))
            {
                try
                {
                    currentGeneration = JsonSerializer.Deserialize<StoredSigningKey>(existing)?.Generation ?? 0;
                }
                catch (JsonException)
                {
                    _logger.LogWarning("Existing signing key secret is malformed; starting a new generation line.");
                }
            }

            var material = await WriteNewKeyAsync(currentGeneration + 1, cancellationToken);

            _logger.LogWarning(
                "STS token signing key rotated to generation {Generation}. All tokens issued under earlier generations are now invalid.",
                material.Generation);

            return material;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task EnsureInitializedAsync(CancellationToken cancellationToken = default)
    {
        var existing = await _secrets.GetSecretAsync(SecretName, cancellationToken);
        if (!string.IsNullOrWhiteSpace(existing))
        {
            return;
        }

        await _lock.WaitAsync(cancellationToken);
        try
        {
            // Re-check inside the lock: another node may have created it while we waited.
            existing = await _secrets.GetSecretAsync(SecretName, cancellationToken);
            if (!string.IsNullOrWhiteSpace(existing))
            {
                return;
            }

            await WriteNewKeyAsync(1, cancellationToken);
            _logger.LogInformation(
                "Bootstrapped STS token signing key '{Secret}' at generation 1.", SecretName);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<SigningKeyMaterial> WriteNewKeyAsync(int generation, CancellationToken cancellationToken)
    {
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var payload = new StoredSigningKey
        {
            KeyBase64 = Convert.ToBase64String(keyBytes),
            Generation = generation,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await _secrets.PutSecretAsync(SecretName, JsonSerializer.Serialize(payload), cancellationToken);

        _cached = new SigningKeyMaterial { Key = keyBytes, Generation = generation };
        _cachedAt = DateTimeOffset.UtcNow;
        return _cached;
    }
}
