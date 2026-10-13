using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Services.Providers;

public interface IProviderRegistry
{
    Task<List<ProviderRegistration>> ListAsync(CancellationToken cancellationToken = default);
    Task<ProviderRegistration?> GetAsync(string providerId, CancellationToken cancellationToken = default);
    Task<ProviderRegistration> CreateAsync(CreateProviderRequest request, CancellationToken cancellationToken = default);
    Task<ProviderRegistration?> UpdateAsync(string providerId, UpdateProviderRequest request, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(string providerId, CancellationToken cancellationToken = default);

    /// <summary>The provider's API key, read from the secret store at call time.</summary>
    Task<string?> ApiKeyAsync(ProviderRegistration provider, CancellationToken cancellationToken = default);
}

/// <summary>
/// The model providers an operator has configured: OpenAI, Anthropic, Gemini, an Ollama host,
/// anything speaking the OpenAI shape, and Bedrock.
///
/// Keys never land in this file. A key supplied through the dashboard is written to the secret
/// store under a name derived from the provider id, and the registration keeps the name and the
/// last four characters. That way the registry can be read, copied and backed up without carrying
/// a credential, and rotating a key is a write to one place.
/// </summary>
public partial class ProviderRegistry : IProviderRegistry
{
    private readonly ConcurrentDictionary<string, ProviderRegistration> _providers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ISecretsProvider _secrets;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<ProviderRegistry> _logger;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly string _filePath;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>Endpoints for the kinds that have one well-known home.</summary>
    private static readonly Dictionary<ProviderKind, string> DefaultBaseUrls = new()
    {
        [ProviderKind.Anthropic] = "https://api.anthropic.com",
        [ProviderKind.Gemini] = "https://generativelanguage.googleapis.com",
        [ProviderKind.OpenAiCompatible] = "https://api.openai.com"
    };

    public ProviderRegistry(
        IOptions<GatewayOptions> options,
        ISecretsProvider secrets,
        IHostEnvironment environment,
        ILogger<ProviderRegistry> logger)
    {
        _secrets = secrets;
        _environment = environment;
        _logger = logger;

        var dataDir = Path.GetFullPath(options.Value.Storage.DataDirectory);
        Directory.CreateDirectory(dataDir);
        _filePath = Path.Combine(dataDir, "providers.json");

        Load();
    }

    public Task<List<ProviderRegistration>> ListAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_providers.Values.OrderBy(p => p.ProviderId, StringComparer.OrdinalIgnoreCase).ToList());

    public Task<ProviderRegistration?> GetAsync(string providerId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_providers.TryGetValue(providerId, out var provider) ? provider : null);

    public Task<string?> ApiKeyAsync(ProviderRegistration provider, CancellationToken cancellationToken = default) =>
        string.IsNullOrWhiteSpace(provider.ApiKeySecretName)
            ? Task.FromResult<string?>(null)
            : _secrets.GetSecretAsync(provider.ApiKeySecretName, cancellationToken);

    public async Task<ProviderRegistration> CreateAsync(
        CreateProviderRequest request, CancellationToken cancellationToken = default)
    {
        var providerId = request.ProviderId.Trim().ToLowerInvariant();
        if (!ProviderIdRegex().IsMatch(providerId))
        {
            throw new ProviderRejectedException(
                "providerId must be 2-32 characters of lowercase letters, digits and hyphens. " +
                "Applications name it to route, so it has to be stable.");
        }

        if (_providers.ContainsKey(providerId))
        {
            throw new ProviderRejectedException($"A provider with id '{providerId}' already exists.");
        }

        var baseUrl = Normalize(request.BaseUrl) ?? DefaultBaseUrls.GetValueOrDefault(request.Kind, string.Empty);
        ValidateEndpoint(request.Kind, baseUrl);
        ValidateCredential(request.Kind, baseUrl, request.ApiKey);

        var secretName = string.IsNullOrWhiteSpace(request.ApiKey) ? string.Empty : SecretNameFor(providerId);
        if (secretName.Length > 0)
        {
            await _secrets.PutSecretAsync(secretName, request.ApiKey!.Trim(), cancellationToken);
        }

        var provider = new ProviderRegistration
        {
            ProviderId = providerId,
            Name = string.IsNullOrWhiteSpace(request.Name) ? providerId : request.Name.Trim(),
            Kind = request.Kind,
            BaseUrl = baseUrl,
            ApiKeySecretName = secretName,
            ApiKeyHint = Hint(request.ApiKey),
            Models = request.Models ?? [],
            DefaultModel = request.DefaultModel,
            TimeoutSeconds = Math.Clamp(request.TimeoutSeconds ?? 120, 1, 600)
        };

        _providers[providerId] = provider;
        await PersistAsync();

        _logger.LogInformation(
            "Provider '{ProviderId}' registered: {Kind} at {BaseUrl}.", providerId, provider.Kind, provider.BaseUrl);

        return provider;
    }

    public async Task<ProviderRegistration?> UpdateAsync(
        string providerId, UpdateProviderRequest request, CancellationToken cancellationToken = default)
    {
        if (!_providers.TryGetValue(providerId, out var existing))
        {
            return null;
        }

        var baseUrl = Normalize(request.BaseUrl) ?? existing.BaseUrl;
        if (baseUrl != existing.BaseUrl)
        {
            ValidateEndpoint(existing.Kind, baseUrl);
        }

        var secretName = existing.ApiKeySecretName;
        var hint = existing.ApiKeyHint;

        if (!string.IsNullOrWhiteSpace(request.ApiKey))
        {
            secretName = SecretNameFor(providerId);
            await _secrets.PutSecretAsync(secretName, request.ApiKey.Trim(), cancellationToken);
            hint = Hint(request.ApiKey);

            _logger.LogWarning("API key replaced for provider '{ProviderId}'.", providerId);
        }

        // A provider that needs a key must still have one after the edit.
        ValidateCredential(existing.Kind, baseUrl, secretName.Length > 0 ? "stored" : null);

        var updated = existing with
        {
            Name = request.Name?.Trim() ?? existing.Name,
            BaseUrl = baseUrl,
            ApiKeySecretName = secretName,
            ApiKeyHint = hint,
            Models = request.Models ?? existing.Models,
            DefaultModel = request.DefaultModel ?? existing.DefaultModel,
            TimeoutSeconds = Math.Clamp(request.TimeoutSeconds ?? existing.TimeoutSeconds, 1, 600),
            IsActive = request.IsActive ?? existing.IsActive,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _providers[providerId] = updated;
        await PersistAsync();
        return updated;
    }

    public async Task<bool> DeleteAsync(string providerId, CancellationToken cancellationToken = default)
    {
        if (!_providers.TryRemove(providerId, out _))
        {
            return false;
        }

        await PersistAsync();

        // The secret is left in place deliberately: deleting a provider should not destroy a
        // credential that may still be in use elsewhere, and rotating it is an explicit act.
        _logger.LogWarning(
            "Provider '{ProviderId}' deleted. Applications routed to it will fail until they are repointed.",
            providerId);

        return true;
    }

    /// <summary>
    /// Where the gateway may send prompts. HTTPS everywhere except a loopback host in
    /// Development, which is how local model servers are actually run.
    /// </summary>
    private void ValidateEndpoint(ProviderKind kind, string baseUrl)
    {
        if (kind == ProviderKind.Bedrock)
        {
            return;   // The AWS SDK resolves the regional endpoint; there is nothing to check.
        }

        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ProviderRejectedException($"{kind} needs a baseUrl.");
        }

        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ProviderRejectedException($"baseUrl must be an absolute HTTP or HTTPS URL ('{baseUrl}').");
        }

        // Development may use plain HTTP anywhere, which is how a developer points at an Ollama
        // or LM Studio box on the bench; this matches LocalBackendAuthHandler's rule for the
        // configured local backends. MCP servers are held to a stricter loopback-only rule in
        // Development, because they execute code rather than answer with text.
        if (uri.Scheme != Uri.UriSchemeHttps && !_environment.IsDevelopment())
        {
            throw new ProviderRejectedException(
                $"'{baseUrl}' is plain HTTP. Prompts and completions would cross the network in clear; " +
                "use https://.");
        }
    }

    /// <summary>A remote provider that authenticates with a key must be given one.</summary>
    private static void ValidateCredential(ProviderKind kind, string baseUrl, string? apiKey)
    {
        if (kind is ProviderKind.Bedrock or ProviderKind.Ollama)
        {
            return;   // Bedrock uses the host's AWS identity; Ollama has no authentication.
        }

        var isLoopback = Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) && uri.IsLoopback;
        if (isLoopback)
        {
            return;   // LM Studio and llama.cpp on this machine take no key.
        }

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ProviderRejectedException(
                $"{kind} at '{baseUrl}' needs an apiKey. It is written to the secret store, not to the registry.");
        }
    }

    private static string SecretNameFor(string providerId) => $"/gateway/providers/{providerId}/api-key";

    private static string Hint(string? apiKey) =>
        string.IsNullOrWhiteSpace(apiKey) || apiKey.Length < 4 ? string.Empty : apiKey.Trim()[^4..];

    private static string? Normalize(string? url) =>
        string.IsNullOrWhiteSpace(url) ? null : url.Trim().TrimEnd('/');

    private void Load()
    {
        if (!File.Exists(_filePath))
        {
            return;
        }

        try
        {
            var providers = JsonSerializer.Deserialize<List<ProviderRegistration>>(
                File.ReadAllText(_filePath), JsonOpts) ?? [];

            foreach (var provider in providers)
            {
                _providers[provider.ProviderId] = provider;
            }

            _logger.LogInformation("Loaded {Count} providers from {Path}.", _providers.Count, _filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not read the provider catalogue at {Path}; starting empty.", _filePath);
        }
    }

    private async Task PersistAsync()
    {
        await _fileLock.WaitAsync();
        try
        {
            var json = JsonSerializer.Serialize(_providers.Values.ToList(), JsonOpts);
            var tempPath = _filePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json);

            if (File.Exists(_filePath))
            {
                File.Replace(tempPath, _filePath, _filePath + ".bak", ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _filePath);
            }
        }
        finally
        {
            _fileLock.Release();
        }
    }

    [GeneratedRegex("^[a-z][a-z0-9-]{1,31}$")]
    private static partial Regex ProviderIdRegex();
}
