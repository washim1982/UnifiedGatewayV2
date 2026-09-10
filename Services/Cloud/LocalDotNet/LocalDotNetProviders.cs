using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud.LocalDotNet;

/// <summary>
/// Named HttpClients for the .NET local AWS simulator. Base addresses come from
/// configuration so no URL is compiled into the gateway.
/// </summary>
public static class LocalDotNetClients
{
    public const string Kms = "LocalDotNetKmsClient";
    public const string Iam = "LocalDotNetIamClient";
    public const string S3 = "LocalDotNetS3Client";
}

internal static class LocalDotNetJson
{
    // The simulator serialises with the ASP.NET default (camelCase); its request records
    // are PascalCase. Case-insensitive reads cover both directions.
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true
    };
}

#region Crypto — KmsLocal

/// <summary>
/// Envelope encryption against KmsLocal (AES-GCM under a DPAPI-protected master key).
/// Same contract as <c>AwsKmsCryptoProvider</c>, so nothing above this layer changes.
/// </summary>
public class LocalDotNetCryptoProvider : ICryptoProvider
{
    private sealed record EncryptBody(string KeyId, string PlaintextBase64);
    private sealed record EncryptResult(string CiphertextBlobBase64);
    private sealed record DecryptBody(string KeyId, string CiphertextBlobBase64);
    private sealed record DecryptResult(string PlaintextBase64);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LocalDotNetOptions _options;
    private readonly ILogger<LocalDotNetCryptoProvider> _logger;

    public LocalDotNetCryptoProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<CloudOptions> options,
        ILogger<LocalDotNetCryptoProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value.LocalDotNet;
        _logger = logger;
    }

    public async Task<string> EncryptAsync(string plaintext, CancellationToken cancellationToken = default)
    {
        var client = _httpClientFactory.CreateClient(LocalDotNetClients.Kms);
        var body = new EncryptBody(_options.KeyId, Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext)));

        using var response = await client.PostAsJsonAsync("/encrypt", body, LocalDotNetJson.Options, cancellationToken);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<EncryptResult>(LocalDotNetJson.Options, cancellationToken)
            ?? throw new InvalidOperationException("KmsLocal encrypt returned an empty response.");

        return result.CiphertextBlobBase64;
    }

    public async Task<string> DecryptAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        var client = _httpClientFactory.CreateClient(LocalDotNetClients.Kms);
        var body = new DecryptBody(_options.KeyId, ciphertext);

        using var response = await client.PostAsJsonAsync("/decrypt", body, LocalDotNetJson.Options, cancellationToken);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<DecryptResult>(LocalDotNetJson.Options, cancellationToken)
            ?? throw new InvalidOperationException("KmsLocal decrypt returned an empty response.");

        return Encoding.UTF8.GetString(Convert.FromBase64String(result.PlaintextBase64));
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _httpClientFactory.CreateClient(LocalDotNetClients.Kms);
            using var response = await client.GetAsync("/health", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("KmsLocal health probe failed: {Message}", ex.Message);
            return false;
        }
    }
}

#endregion

#region Secrets — S3Local objects, KMS-encrypted

/// <summary>
/// Stores gateway secrets as KMS-encrypted objects in S3Local.
///
/// The .NET simulator has no Secrets Manager equivalent, so this uses the S3 + KMS envelope
/// pattern instead — the value is encrypted through <see cref="ICryptoProvider"/> before it
/// is written, so the object at rest is ciphertext even in dev. Production keeps
/// <c>AwsSecretsManagerProvider</c>; only the binding differs.
/// </summary>
public class LocalDotNetSecretsProvider : ISecretsProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ICryptoProvider _crypto;
    private readonly LocalDotNetOptions _options;
    private readonly int _cacheSeconds;
    private readonly ILogger<LocalDotNetSecretsProvider> _logger;
    private readonly ConcurrentDictionary<string, (string Value, DateTimeOffset FetchedAt)> _cache = new();

    public LocalDotNetSecretsProvider(
        IHttpClientFactory httpClientFactory,
        ICryptoProvider crypto,
        IOptions<CloudOptions> options,
        ILogger<LocalDotNetSecretsProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _crypto = crypto;
        _options = options.Value.LocalDotNet;
        _cacheSeconds = options.Value.Secrets.CacheSeconds;
        _logger = logger;
    }

    /// <summary>Secret names are paths ("/gateway/dev/admin-api-key"); S3 keys must not lead with a slash.</summary>
    private string KeyFor(string name) => name.TrimStart('/').Replace("//", "/");

    private string PathFor(string name) => $"/{_options.SecretsBucket}/{KeyFor(name)}";

    public async Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken = default)
    {
        var ttl = TimeSpan.FromSeconds(Math.Max(0, _cacheSeconds));
        if (_cache.TryGetValue(name, out var cached) && DateTimeOffset.UtcNow - cached.FetchedAt < ttl)
        {
            return cached.Value;
        }

        var client = _httpClientFactory.CreateClient(LocalDotNetClients.S3);
        using var response = await client.GetAsync(PathFor(name), cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            _logger.LogWarning("Secret '{Name}' not found in bucket '{Bucket}'.", name, _options.SecretsBucket);
            return null;
        }

        response.EnsureSuccessStatusCode();

        var ciphertext = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(ciphertext))
        {
            return null;
        }

        var value = await _crypto.DecryptAsync(ciphertext.Trim(), cancellationToken);
        _cache[name] = (value, DateTimeOffset.UtcNow);
        return value;
    }

    public async Task PutSecretAsync(string name, string value, CancellationToken cancellationToken = default)
    {
        await EnsureBucketAsync(cancellationToken);

        var ciphertext = await _crypto.EncryptAsync(value, cancellationToken);

        var client = _httpClientFactory.CreateClient(LocalDotNetClients.S3);
        using var content = new StringContent(ciphertext, Encoding.UTF8, "text/plain");
        content.Headers.Add("x-kms-key", _options.KeyId);

        using var response = await client.PutAsync(PathFor(name), content, cancellationToken);
        response.EnsureSuccessStatusCode();

        Invalidate(name);
        _logger.LogInformation("Secret '{Name}' written to s3://{Bucket}.", name, _options.SecretsBucket);
    }

    public void Invalidate(string name) => _cache.TryRemove(name, out _);

    /// <summary>
    /// S3Local rejects a PUT into a bucket it does not know about, and the gateway
    /// bootstraps its own secrets on first start, so the bucket is created on demand.
    /// </summary>
    private async Task EnsureBucketAsync(CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(LocalDotNetClients.S3);

        try
        {
            using var response = await client.PostAsJsonAsync(
                "/buckets", new { Name = _options.SecretsBucket, Region = "us-east-1" },
                LocalDotNetJson.Options, cancellationToken);

            // Already-exists is the normal case after the first run.
            if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.Conflict)
            {
                _logger.LogDebug("Bucket create returned {Status}; continuing.", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Bucket create attempt failed ({Message}); continuing.", ex.Message);
        }
    }
}

#endregion

#region Identity — IamLocal

/// <summary>
/// Resolves a presented credential through IamLocal.
///
/// A JWT goes to <c>/get-caller-identity</c>, which verifies the RSA signature server-side —
/// the same shape as handing a session credential to STS. A bare role name is exchanged
/// through <c>/assume-role</c>, which is the simulator's own dev convenience.
/// </summary>
public class LocalDotNetIdentityProvider : IIdentityProvider
{
    private sealed record CallerIdentity(string Arn, string AccountId, string UserId);
    private sealed record AssumeRoleBody(string RoleName, int DurationSeconds);
    private sealed record TokenResult(string Jwt, DateTime ExpiresAt);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LocalDotNetPolicyCache _policyCache;
    private readonly ILogger<LocalDotNetIdentityProvider> _logger;

    public LocalDotNetIdentityProvider(
        IHttpClientFactory httpClientFactory,
        LocalDotNetPolicyCache policyCache,
        ILogger<LocalDotNetIdentityProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _policyCache = policyCache;
        _logger = logger;
    }

    public async Task<ResolvedIdentity> ResolveAsync(string credential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(credential))
        {
            return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "No credential presented" };
        }

        var client = _httpClientFactory.CreateClient(LocalDotNetClients.Iam);

        try
        {
            // A JWT is verified by IamLocal rather than parsed here: signature checking is
            // the identity provider's job, not the caller's.
            if (LooksLikeJwt(credential))
            {
                using var response = await client.PostAsJsonAsync(
                    "/get-caller-identity", new { Jwt = credential }, LocalDotNetJson.Options, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Invalid or expired token" };
                }

                var identity = await response.Content.ReadFromJsonAsync<CallerIdentity>(
                    LocalDotNetJson.Options, cancellationToken);

                if (identity is null || string.IsNullOrWhiteSpace(identity.Arn))
                {
                    return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Identity carried no ARN" };
                }

                CachePoliciesFromToken(identity.Arn, credential);

                return new ResolvedIdentity
                {
                    IsAuthenticated = true,
                    PrincipalArn = identity.Arn,
                    AuthType = "LocalDotNetJwt"
                };
            }

            // Otherwise treat it as a role name and assume it.
            var roleName = credential.StartsWith("arn:aws:", StringComparison.OrdinalIgnoreCase)
                ? credential[(credential.LastIndexOf('/') + 1)..]
                : credential;

            using var assumed = await client.PostAsJsonAsync(
                "/assume-role", new AssumeRoleBody(roleName, 3600), LocalDotNetJson.Options, cancellationToken);

            if (!assumed.IsSuccessStatusCode)
            {
                return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Unknown role" };
            }

            var token = await assumed.Content.ReadFromJsonAsync<TokenResult>(LocalDotNetJson.Options, cancellationToken);
            if (token is null || string.IsNullOrWhiteSpace(token.Jwt))
            {
                return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "AssumeRole returned no token" };
            }

            var arn = ArnFromToken(token.Jwt) ?? $"arn:aws:iam::123456789012:role/{roleName}";
            CachePoliciesFromToken(arn, token.Jwt);

            return new ResolvedIdentity
            {
                IsAuthenticated = true,
                PrincipalArn = arn,
                AuthType = "LocalDotNetAssumedRole",
                ExpiresAt = token.ExpiresAt
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Identity resolution failed against IamLocal.");
            return new ResolvedIdentity { IsAuthenticated = false, FailureReason = "Identity provider unreachable" };
        }
    }

    private static bool LooksLikeJwt(string value) =>
        value.StartsWith("eyJ", StringComparison.Ordinal) && value.Count(c => c == '.') == 2;

    private static string? ArnFromToken(string jwt)
    {
        try
        {
            return new JwtSecurityTokenHandler().ReadJwtToken(jwt)
                .Claims.FirstOrDefault(c => c.Type == "arn")?.Value;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// IamLocal puts the role's policy documents in a claim, so authorization can be decided
    /// without a second round trip. Reading claims here is safe: the signature was already
    /// verified by IamLocal (or produced by it), so this is parsing, not trusting.
    /// </summary>
    private void CachePoliciesFromToken(string arn, string jwt)
    {
        try
        {
            var policies = new JwtSecurityTokenHandler().ReadJwtToken(jwt)
                .Claims.FirstOrDefault(c => c.Type == "policies")?.Value;

            if (!string.IsNullOrWhiteSpace(policies))
            {
                _policyCache.Set(arn, policies);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Could not read policies from token for {Arn}: {Message}", arn, ex.Message);
        }
    }
}

#endregion

#region Access control — policies from IamLocal, evaluated with AWS semantics

/// <summary>Short-lived store of the policy documents IamLocal issued for a principal.</summary>
public class LocalDotNetPolicyCache
{
    private readonly ConcurrentDictionary<string, (string Json, DateTimeOffset At)> _entries = new(StringComparer.OrdinalIgnoreCase);

    public TimeSpan Ttl { get; init; } = TimeSpan.FromMinutes(5);

    public void Set(string arn, string policiesJson) => _entries[arn] = (policiesJson, DateTimeOffset.UtcNow);

    public string? Get(string arn)
    {
        if (!_entries.TryGetValue(arn, out var entry)) return null;
        if (DateTimeOffset.UtcNow - entry.At > Ttl)
        {
            _entries.TryRemove(arn, out _);
            return null;
        }
        return entry.Json;
    }
}

/// <summary>
/// Authorizes management-plane actions against the IAM policies IamLocal holds for the role.
///
/// IamLocal has no "evaluate this for me" endpoint, so the policy documents are fetched (via
/// assume-role, which returns them in a claim) and evaluated here with AWS semantics:
/// explicit Deny wins, then Allow, otherwise implicit Deny. That is the same evaluation
/// <c>AwsAccessControlProvider</c> performs in production, so a policy behaves identically in
/// both places.
/// </summary>
public class LocalDotNetAccessControlProvider : IAccessControlProvider
{
    private sealed record AssumeRoleBody(string RoleName, int DurationSeconds);
    private sealed record TokenResult(string Jwt, DateTime ExpiresAt);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LocalDotNetPolicyCache _policyCache;
    private readonly CloudOptions _options;
    private readonly ILogger<LocalDotNetAccessControlProvider> _logger;

    public LocalDotNetAccessControlProvider(
        IHttpClientFactory httpClientFactory,
        LocalDotNetPolicyCache policyCache,
        IOptions<CloudOptions> options,
        ILogger<LocalDotNetAccessControlProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _policyCache = policyCache;
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
        var policiesJson = _policyCache.Get(principalArn) ?? await FetchPoliciesAsync(principalArn, cancellationToken);

        if (string.IsNullOrWhiteSpace(policiesJson))
        {
            // Fail closed: no policy means no permission.
            return Deny(principalArn, action, resource, "No policy document available for this principal");
        }

        try
        {
            using var document = JsonDocument.Parse(policiesJson);
            var allowed = Evaluate(document.RootElement, action, resource, out var reason);

            return new AccessDecision
            {
                IsAllowed = allowed,
                Reason = reason,
                Action = action,
                Resource = resource,
                Principal = principalArn
            };
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Policy document for {Arn} could not be parsed. Denying.", principalArn);
            return Deny(principalArn, action, resource, "Policy document is malformed");
        }
    }

    private async Task<string?> FetchPoliciesAsync(string principalArn, CancellationToken cancellationToken)
    {
        var roleName = principalArn.Contains('/')
            ? principalArn[(principalArn.LastIndexOf('/') + 1)..]
            : principalArn;

        try
        {
            var client = _httpClientFactory.CreateClient(LocalDotNetClients.Iam);
            using var response = await client.PostAsJsonAsync(
                "/assume-role", new AssumeRoleBody(roleName, 900), LocalDotNetJson.Options, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("IamLocal assume-role returned {Status} for {Role}. Denying.",
                    (int)response.StatusCode, roleName);
                return null;
            }

            var token = await response.Content.ReadFromJsonAsync<TokenResult>(LocalDotNetJson.Options, cancellationToken);
            if (token is null || string.IsNullOrWhiteSpace(token.Jwt)) return null;

            var policies = new JwtSecurityTokenHandler().ReadJwtToken(token.Jwt)
                .Claims.FirstOrDefault(c => c.Type == "policies")?.Value;

            if (!string.IsNullOrWhiteSpace(policies))
            {
                _policyCache.Set(principalArn, policies);
            }

            return policies;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not fetch policies for {Arn} from IamLocal. Denying (fail-closed).", principalArn);
            return null;
        }
    }

    /// <summary>
    /// Evaluates an array of IamPolicy documents. The simulator writes lowercase property
    /// names ("effect", "action"), so matching is case-insensitive on both name and value.
    /// </summary>
    private static bool Evaluate(JsonElement root, string action, string resource, out string reason)
    {
        var allowed = false;
        reason = "No matching Allow (implicit deny)";

        // The claim holds an array of policy documents, but a single document is accepted too.
        var documents = root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray().ToList()
            : [root];

        foreach (var document in documents)
        {
            if (!TryGetProperty(document, "statement", out var statements)) continue;

            var list = statements.ValueKind == JsonValueKind.Array
                ? statements.EnumerateArray().ToList()
                : [statements];

            foreach (var statement in list)
            {
                if (!Matches(statement, "action", action)) continue;
                if (!Matches(statement, "resource", resource)) continue;

                var effect = TryGetProperty(statement, "effect", out var e) ? e.GetString() : null;

                // Explicit Deny short-circuits everything, exactly as in AWS.
                if (string.Equals(effect, "Deny", StringComparison.OrdinalIgnoreCase))
                {
                    reason = "Explicit Deny in policy";
                    return false;
                }

                if (string.Equals(effect, "Allow", StringComparison.OrdinalIgnoreCase))
                {
                    allowed = true;
                    reason = "Allowed by policy statement";
                }
            }
        }

        return allowed;
    }

    private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static bool Matches(JsonElement statement, string property, string candidate)
    {
        if (!TryGetProperty(statement, property, out var element)) return false;

        if (element.ValueKind == JsonValueKind.String)
        {
            return WildcardMatch(element.GetString(), candidate);
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && WildcardMatch(item.GetString(), candidate))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool WildcardMatch(string? pattern, string candidate)
    {
        if (string.IsNullOrEmpty(pattern)) return false;
        if (pattern == "*") return true;

        var regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";

        return System.Text.RegularExpressions.Regex.IsMatch(
            candidate, regex,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase,
            TimeSpan.FromMilliseconds(100));
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
