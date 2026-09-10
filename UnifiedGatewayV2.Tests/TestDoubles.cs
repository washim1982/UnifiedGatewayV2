using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Cloud;
using UnifiedGateway.Services.Telemetry;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// In-memory stand-ins for the cloud seams, so the security and registry tests exercise the
/// real production code paths without needing the AWS simulator or AWS to be reachable.
/// </summary>
public sealed class InMemorySecretsProvider : ISecretsProvider
{
    private readonly ConcurrentDictionary<string, string> _store = new();

    public Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken = default)
        => Task.FromResult(_store.TryGetValue(name, out var value) ? value : null);

    public Task PutSecretAsync(string name, string value, CancellationToken cancellationToken = default)
    {
        _store[name] = value;
        return Task.CompletedTask;
    }

    public void Invalidate(string name) { }
}

/// <summary>Reversible stand-in for KMS. Not encryption — it only has to round-trip.</summary>
public sealed class InMemoryCryptoProvider : ICryptoProvider
{
    public Task<string> EncryptAsync(string plaintext, CancellationToken cancellationToken = default)
        => Task.FromResult("enc:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext)));

    public Task<string> DecryptAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        if (!ciphertext.StartsWith("enc:", StringComparison.Ordinal))
            throw new InvalidOperationException("Not a ciphertext produced by this provider.");

        return Task.FromResult(Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext[4..])));
    }

    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
}

/// <summary>Signing key held in memory, with the same generation semantics as production.</summary>
public sealed class InMemorySigningKeyProvider : ISigningKeyProvider
{
    private SigningKeyMaterial _current = new()
    {
        Key = RandomNumberGenerator.GetBytes(32),
        Generation = 1
    };

    public Task<SigningKeyMaterial> GetCurrentAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_current);

    public Task<SigningKeyMaterial> RotateAsync(CancellationToken cancellationToken = default)
    {
        _current = new SigningKeyMaterial
        {
            Key = RandomNumberGenerator.GetBytes(32),
            Generation = _current.Generation + 1
        };
        return Task.FromResult(_current);
    }

    public Task EnsureInitializedAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}

/// <summary>Admin credential fixed to a known value for assertions.</summary>
public sealed class StubAdminCredentialService : IAdminCredentialService
{
    private readonly ISecurityService _security;

    public StubAdminCredentialService(ISecurityService security, string adminKey)
    {
        _security = security;
        AdminKey = adminKey;
    }

    public string AdminKey { get; }

    public Task<string?> GetAdminApiKeyAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(AdminKey);

    public Task<bool> VerifyAsync(string presented, CancellationToken cancellationToken = default)
        => Task.FromResult(_security.VerifyKey(presented, _security.HashKey(AdminKey)));

    public Task<string?> EnsureInitializedAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(null);
}


/// <summary>
/// In-memory <see cref="IObjectStore"/>. Tests run the real <see cref="S3AuditStore"/> over
/// this, so batching, date partitioning and read-back are exercised for real rather than
/// stubbed out — only the network is replaced.
/// </summary>
public sealed class InMemoryObjectStore : IObjectStore
{
    private readonly ConcurrentDictionary<string, byte[]> _objects = new(StringComparer.Ordinal);

    public int ObjectCount => _objects.Count;
    public IReadOnlyCollection<string> Keys => _objects.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();

    public Task PutAsync(string key, byte[] content, string contentType, CancellationToken cancellationToken = default)
    {
        _objects[key] = content;
        return Task.CompletedTask;
    }

    public Task<byte[]?> GetAsync(string key, CancellationToken cancellationToken = default)
        => Task.FromResult(_objects.TryGetValue(key, out var body) ? body : null);

    public Task<IReadOnlyList<string>> ListAsync(string prefix, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<string>>(
            _objects.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal))
                         .OrderBy(k => k, StringComparer.Ordinal).ToList());

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        _objects.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task EnsureReadyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
}

/// <summary>An object store whose writes always fail, for testing buffer-retry behaviour.</summary>
public sealed class FailingObjectStore : IObjectStore
{
    public Task PutAsync(string key, byte[] content, string contentType, CancellationToken cancellationToken = default)
        => throw new IOException("object store unavailable");

    public Task<byte[]?> GetAsync(string key, CancellationToken cancellationToken = default)
        => Task.FromResult<byte[]?>(null);

    public Task<IReadOnlyList<string>> ListAsync(string prefix, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<string>>([]);

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task EnsureReadyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
}
/// <summary>Builds a fully wired SecurityService over the in-memory seams.</summary>
public static class TestFactory
{
    public static (ISecurityService Security, InMemorySigningKeyProvider SigningKeys) CreateSecurityService(
        GatewayOptions? options = null)
    {
        var signingKeys = new InMemorySigningKeyProvider();
        var security = new SecurityService(
            signingKeys,
            new InMemoryCryptoProvider(),
            Options.Create(options ?? new GatewayOptions()),
            NullLogger<SecurityService>.Instance);

        return (security, signingKeys);
    }
}
