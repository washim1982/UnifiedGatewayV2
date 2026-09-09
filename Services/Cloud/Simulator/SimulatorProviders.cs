using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud.Simulator;

/// <summary>
/// Named HttpClients used by the simulator providers. Registered in Program.cs so base
/// addresses come from configuration and never from code.
/// </summary>
public static class SimulatorClients
{
    public const string Kms = "SimulatorKmsClient";
    public const string Iam = "SimulatorIamClient";
}

internal static class SimulatorJson
{
    // The simulator uses PascalCase field names throughout (KeyId, CiphertextBlob, SecretValue).
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

#region Secrets — KMS service /secrets

/// <summary>
/// Reads and writes secrets through the simulator's KMS service, which stores them
/// AES-256-GCM encrypted under a KMS key. Mirrors AWS Secrets Manager semantics.
/// </summary>
public class SimulatorSecretsProvider : ISecretsProvider
{
    private sealed record SecretValueResponse
    {
        public string SecretName { get; init; } = string.Empty;
        public string SecretValue { get; init; } = string.Empty;
        public int Version { get; init; }
    }

    private sealed record CreateSecretRequest
    {
        public string SecretName { get; init; } = string.Empty;
        public string SecretValue { get; init; } = string.Empty;
        public string? KeyId { get; init; }
        public string? Description { get; init; }
    }

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly CloudOptions _options;
    private readonly ILogger<SimulatorSecretsProvider> _logger;
    private readonly ConcurrentDictionary<string, (string Value, DateTimeOffset FetchedAt)> _cache = new();

    public SimulatorSecretsProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<CloudOptions> options,
        ILogger<SimulatorSecretsProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken = default)
    {
        var ttl = TimeSpan.FromSeconds(Math.Max(0, _options.Secrets.CacheSeconds));
        if (_cache.TryGetValue(name, out var cached) && DateTimeOffset.UtcNow - cached.FetchedAt < ttl)
        {
            return cached.Value;
        }

        var client = _httpClientFactory.CreateClient(SimulatorClients.Kms);
        var path = "/secrets/" + name.TrimStart('/');

        using var response = await client.GetAsync(path, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            _logger.LogWarning("Secret '{Name}' not found in the simulator secret store.", name);
            return null;
        }

        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<SecretValueResponse>(
            SimulatorJson.Options, cancellationToken);

        if (payload is null || string.IsNullOrEmpty(payload.SecretValue))
        {
            return null;
        }

        _cache[name] = (payload.SecretValue, DateTimeOffset.UtcNow);
        return payload.SecretValue;
    }

    public async Task PutSecretAsync(string name, string value, CancellationToken cancellationToken = default)
    {
        var client = _httpClientFactory.CreateClient(SimulatorClients.Kms);
        var request = new CreateSecretRequest
        {
            SecretName = name.StartsWith('/') ? name : "/" + name,
            SecretValue = value,
            KeyId = string.Equals(_options.Crypto.KeyId, "default", StringComparison.OrdinalIgnoreCase)
                ? null
                : _options.Crypto.KeyId,
            Description = "Managed by Unified LLM Gateway"
        };

        using var response = await client.PostAsJsonAsync("/secrets", request, SimulatorJson.Options, cancellationToken);
        response.EnsureSuccessStatusCode();

        Invalidate(name);
        _logger.LogInformation("Secret '{Name}' written to the simulator secret store.", name);
    }

    public void Invalidate(string name) => _cache.TryRemove(name, out _);
}

#endregion

#region Crypto — KMS service /encrypt and /decrypt

/// <summary>
/// Envelope encryption against the simulator KMS service (AES-256-GCM with encryption
/// context as AAD). The ciphertext blob is opaque and carries its own key id.
/// </summary>
public class SimulatorCryptoProvider : ICryptoProvider
{
    private sealed record EncryptRequest
    {
        public string KeyId { get; init; } = string.Empty;
        public string Plaintext { get; init; } = string.Empty;
        public Dictionary<string, string>? EncryptionContext { get; init; }
    }

    private sealed record EncryptResponse
    {
        public string KeyId { get; init; } = string.Empty;
        public string CiphertextBlob { get; init; } = string.Empty;
    }

    private sealed record DecryptRequest
    {
        public string? KeyId { get; init; }
        public string CiphertextBlob { get; init; } = string.Empty;
        public Dictionary<string, string>? EncryptionContext { get; init; }
    }

    private sealed record DecryptResponse
    {
        public string KeyId { get; init; } = string.Empty;
        public string Plaintext { get; init; } = string.Empty;
    }

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly CloudOptions _options;
    private readonly ILogger<SimulatorCryptoProvider> _logger;

    public SimulatorCryptoProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<CloudOptions> options,
        ILogger<SimulatorCryptoProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string> EncryptAsync(string plaintext, CancellationToken cancellationToken = default)
    {
        var client = _httpClientFactory.CreateClient(SimulatorClients.Kms);
        var request = new EncryptRequest
        {
            KeyId = _options.Crypto.KeyId,
            Plaintext = plaintext,
            EncryptionContext = _options.Crypto.EncryptionContext
        };

        using var response = await client.PostAsJsonAsync("/encrypt", request, SimulatorJson.Options, cancellationToken);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<EncryptResponse>(SimulatorJson.Options, cancellationToken)
            ?? throw new InvalidOperationException("KMS encrypt returned an empty response.");

        return payload.CiphertextBlob;
    }

    public async Task<string> DecryptAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        var client = _httpClientFactory.CreateClient(SimulatorClients.Kms);
        var request = new DecryptRequest
        {
            CiphertextBlob = ciphertext,
            EncryptionContext = _options.Crypto.EncryptionContext
        };

        using var response = await client.PostAsJsonAsync("/decrypt", request, SimulatorJson.Options, cancellationToken);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<DecryptResponse>(SimulatorJson.Options, cancellationToken)
            ?? throw new InvalidOperationException("KMS decrypt returned an empty response.");

        return payload.Plaintext;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _httpClientFactory.CreateClient(SimulatorClients.Kms);
            using var response = await client.GetAsync("/health", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Simulator KMS health probe failed: {Message}", ex.Message);
            return false;
        }
    }
}

#endregion

#region Access control — IAM service /evaluate-policy

/// <summary>
/// Delegates every management-plane authorization decision to the simulator's IAM policy
/// engine, so Allow/Deny, wildcards, explicit-deny override, and conditions behave the way
/// they will in AWS.
/// </summary>
public class SimulatorAccessControlProvider : IAccessControlProvider
{
    private sealed record EvaluatePolicyRequest
    {
        public string RoleArn { get; init; } = string.Empty;
        public string Action { get; init; } = string.Empty;
        public string Resource { get; init; } = string.Empty;
        public Dictionary<string, string> Context { get; init; } = [];
    }

    private sealed record EvaluationResult
    {
        public string Decision { get; init; } = "DENY";
        public string Reason { get; init; } = string.Empty;
    }

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly CloudOptions _options;
    private readonly ILogger<SimulatorAccessControlProvider> _logger;
    private readonly ConcurrentDictionary<string, (AccessDecision Decision, DateTimeOffset At)> _cache = new();

    public SimulatorAccessControlProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<CloudOptions> options,
        ILogger<SimulatorAccessControlProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<AccessDecision> EvaluateAsync(
        string principalArn,
        string action,
        string resource,
        IDictionary<string, string>? context = null,
        CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{principalArn}|{action}|{resource}";
        var ttl = TimeSpan.FromSeconds(Math.Max(0, _options.AccessControl.DecisionCacheSeconds));
        if (_cache.TryGetValue(cacheKey, out var hit) && DateTimeOffset.UtcNow - hit.At < ttl)
        {
            return hit.Decision;
        }

        var request = new EvaluatePolicyRequest
        {
            RoleArn = principalArn,
            Action = action,
            Resource = resource,
            Context = context is null ? [] : new Dictionary<string, string>(context)
        };

        AccessDecision decision;
        try
        {
            var client = _httpClientFactory.CreateClient(SimulatorClients.Iam);
            using var response = await client.PostAsJsonAsync(
                "/evaluate-policy", request, SimulatorJson.Options, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                // Fail closed: an unreachable or erroring policy engine must not grant access.
                _logger.LogError(
                    "IAM policy evaluation returned {Status} for {Principal} on {Action}. Denying.",
                    (int)response.StatusCode, principalArn, action);

                return Deny(principalArn, action, resource,
                    $"Policy engine returned HTTP {(int)response.StatusCode}");
            }

            var result = await response.Content.ReadFromJsonAsync<EvaluationResult>(
                SimulatorJson.Options, cancellationToken);

            var allowed = string.Equals(result?.Decision, "ALLOW", StringComparison.OrdinalIgnoreCase);
            decision = new AccessDecision
            {
                IsAllowed = allowed,
                Reason = result?.Reason ?? "No reason returned",
                Action = action,
                Resource = resource,
                Principal = principalArn
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "IAM policy evaluation failed for {Principal} on {Action}. Denying (fail-closed).",
                principalArn, action);

            return Deny(principalArn, action, resource, "Policy engine unreachable");
        }

        _cache[cacheKey] = (decision, DateTimeOffset.UtcNow);
        return decision;
    }

    private static AccessDecision Deny(string principal, string action, string resource, string reason) => new()
    {
        IsAllowed = false,
        Reason = reason,
        Action = action,
        Resource = resource,
        Principal = principal
    };
}

#endregion

#region Identity — IAM service STS sessions

/// <summary>
/// Resolves a presented STS session credential to a role ARN using the simulator's IAM service.
/// </summary>
public class SimulatorIdentityProvider : IIdentityProvider
{
    private sealed record ActiveSession
    {
        public string AccessKeyId { get; init; } = string.Empty;
        public string RoleArn { get; init; } = string.Empty;
        public string Expiration { get; init; } = string.Empty;
        public bool IsActive { get; init; }
    }

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SimulatorIdentityProvider> _logger;

    public SimulatorIdentityProvider(
        IHttpClientFactory httpClientFactory,
        ILogger<SimulatorIdentityProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<ResolvedIdentity> ResolveAsync(string credential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(credential))
        {
            return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "No credential presented" };
        }

        try
        {
            var client = _httpClientFactory.CreateClient(SimulatorClients.Iam);
            using var response = await client.GetAsync("/sts/sessions", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "IAM service unavailable" };
            }

            var sessions = await response.Content.ReadFromJsonAsync<List<ActiveSession>>(
                SimulatorJson.Options, cancellationToken) ?? [];

            // Exact match only. The simulator gateway does a substring comparison here, which
            // would let a short prefix authenticate as a full session; we do not copy that.
            var match = sessions.FirstOrDefault(s =>
                string.Equals(s.AccessKeyId, credential, StringComparison.Ordinal));

            if (match is null)
            {
                // Fall back to a named IAM role, the simulator's own X-Simulator-Role
                // convention. This is a simulator-only affordance: the AWS provider requires
                // a principal ARN asserted by a verified upstream instead.
                return await ResolveRoleNameAsync(credential, cancellationToken);
            }

            if (!match.IsActive)
            {
                return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Session expired" };
            }

            DateTimeOffset? expiresAt = DateTimeOffset.TryParse(match.Expiration, out var parsed) ? parsed : null;

            return new ResolvedIdentity
            {
                IsAuthenticated = true,
                PrincipalArn = match.RoleArn,
                AuthType = "SimulatorStsSession",
                ExpiresAt = expiresAt
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Identity resolution failed against the simulator IAM service.");
            return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Identity provider unreachable" };
        }
    }

    private sealed record RoleSummary
    {
        public string RoleName { get; init; } = string.Empty;
        public string Arn { get; init; } = string.Empty;
    }

    private async Task<ResolvedIdentity> ResolveRoleNameAsync(string candidate, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(SimulatorClients.Iam);
        using var response = await client.GetAsync("/roles", cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Unknown session credential" };
        }

        var roles = await response.Content.ReadFromJsonAsync<List<RoleSummary>>(
            SimulatorJson.Options, cancellationToken) ?? [];

        var role = roles.FirstOrDefault(r =>
            string.Equals(r.RoleName, candidate, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(r.Arn, candidate, StringComparison.OrdinalIgnoreCase));

        if (role is null)
        {
            return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Unknown role or session credential" };
        }

        return new ResolvedIdentity
        {
            IsAuthenticated = true,
            PrincipalArn = role.Arn,
            AuthType = "SimulatorRole"
        };
    }
}

#endregion
