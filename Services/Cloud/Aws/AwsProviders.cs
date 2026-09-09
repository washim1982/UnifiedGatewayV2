using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud.Aws;

#region Secrets — AWS Secrets Manager

/// <summary>
/// Reads gateway secrets from AWS Secrets Manager using the gateway's assumed role.
/// Same contract as the simulator provider, so nothing above this layer changes.
/// </summary>
public class AwsSecretsManagerProvider : ISecretsProvider
{
    private readonly ISTSService _stsService;
    private readonly GatewayOptions _gatewayOptions;
    private readonly CloudOptions _cloudOptions;
    private readonly ILogger<AwsSecretsManagerProvider> _logger;
    private readonly ConcurrentDictionary<string, (string Value, DateTimeOffset FetchedAt)> _cache = new();

    public AwsSecretsManagerProvider(
        ISTSService stsService,
        IOptions<GatewayOptions> gatewayOptions,
        IOptions<CloudOptions> cloudOptions,
        ILogger<AwsSecretsManagerProvider> logger)
    {
        _stsService = stsService;
        _gatewayOptions = gatewayOptions.Value;
        _cloudOptions = cloudOptions.Value;
        _logger = logger;
    }

    private async Task<AmazonSecretsManagerClient> CreateClientAsync(CancellationToken ct)
    {
        var credentials = await _stsService.GetCredentialsAsync(ct);
        var region = RegionEndpoint.GetBySystemName(_gatewayOptions.Aws.Region);
        return new AmazonSecretsManagerClient(credentials, region);
    }

    public async Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken = default)
    {
        var ttl = TimeSpan.FromSeconds(Math.Max(0, _cloudOptions.Secrets.CacheSeconds));
        if (_cache.TryGetValue(name, out var cached) && DateTimeOffset.UtcNow - cached.FetchedAt < ttl)
        {
            return cached.Value;
        }

        try
        {
            using var client = await CreateClientAsync(cancellationToken);
            var response = await client.GetSecretValueAsync(
                new GetSecretValueRequest { SecretId = name }, cancellationToken);

            var value = response.SecretString;
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            _cache[name] = (value, DateTimeOffset.UtcNow);
            return value;
        }
        catch (ResourceNotFoundException)
        {
            _logger.LogWarning("Secret '{Name}' not found in AWS Secrets Manager.", name);
            return null;
        }
    }

    public async Task PutSecretAsync(string name, string value, CancellationToken cancellationToken = default)
    {
        using var client = await CreateClientAsync(cancellationToken);
        try
        {
            await client.PutSecretValueAsync(
                new PutSecretValueRequest { SecretId = name, SecretString = value }, cancellationToken);
        }
        catch (ResourceNotFoundException)
        {
            await client.CreateSecretAsync(
                new CreateSecretRequest
                {
                    Name = name,
                    SecretString = value,
                    Description = "Managed by Unified LLM Gateway"
                },
                cancellationToken);
        }

        Invalidate(name);
    }

    public void Invalidate(string name) => _cache.TryRemove(name, out _);
}

#endregion

#region Crypto — AWS KMS

/// <summary>Envelope encryption against AWS KMS. Ciphertext is a base64 KMS blob.</summary>
public class AwsKmsCryptoProvider : ICryptoProvider
{
    private readonly ISTSService _stsService;
    private readonly GatewayOptions _gatewayOptions;
    private readonly CloudOptions _cloudOptions;
    private readonly ILogger<AwsKmsCryptoProvider> _logger;

    public AwsKmsCryptoProvider(
        ISTSService stsService,
        IOptions<GatewayOptions> gatewayOptions,
        IOptions<CloudOptions> cloudOptions,
        ILogger<AwsKmsCryptoProvider> logger)
    {
        _stsService = stsService;
        _gatewayOptions = gatewayOptions.Value;
        _cloudOptions = cloudOptions.Value;
        _logger = logger;
    }

    private async Task<AmazonKeyManagementServiceClient> CreateClientAsync(CancellationToken ct)
    {
        var credentials = await _stsService.GetCredentialsAsync(ct);
        var region = RegionEndpoint.GetBySystemName(_gatewayOptions.Aws.Region);
        return new AmazonKeyManagementServiceClient(credentials, region);
    }

    public async Task<string> EncryptAsync(string plaintext, CancellationToken cancellationToken = default)
    {
        using var client = await CreateClientAsync(cancellationToken);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(plaintext));

        var response = await client.EncryptAsync(
            new EncryptRequest
            {
                KeyId = _cloudOptions.Crypto.KeyId,
                Plaintext = stream,
                EncryptionContext = new Dictionary<string, string>(_cloudOptions.Crypto.EncryptionContext)
            },
            cancellationToken);

        return Convert.ToBase64String(response.CiphertextBlob.ToArray());
    }

    public async Task<string> DecryptAsync(string ciphertext, CancellationToken cancellationToken = default)
    {
        using var client = await CreateClientAsync(cancellationToken);
        using var stream = new MemoryStream(Convert.FromBase64String(ciphertext));

        var response = await client.DecryptAsync(
            new DecryptRequest
            {
                CiphertextBlob = stream,
                EncryptionContext = new Dictionary<string, string>(_cloudOptions.Crypto.EncryptionContext)
            },
            cancellationToken);

        return Encoding.UTF8.GetString(response.Plaintext.ToArray());
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var client = await CreateClientAsync(cancellationToken);
            await client.DescribeKeyAsync(
                new DescribeKeyRequest { KeyId = _cloudOptions.Crypto.KeyId }, cancellationToken);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("AWS KMS availability probe failed: {Message}", ex.Message);
            return false;
        }
    }
}

#endregion

#region Access control — local evaluation of IAM policy documents

/// <summary>
/// Evaluates management-plane access against IAM policy documents held in a secret
/// (<c>/gateway/access-policy</c>). AWS has no low-latency "evaluate this for me" runtime
/// call — SimulatePrincipalPolicy is throttled and not built for the request path — so the
/// policy document is fetched, cached, and evaluated locally with AWS semantics:
/// explicit Deny wins, then Allow, otherwise implicit Deny.
/// </summary>
public class AwsAccessControlProvider : IAccessControlProvider
{
    private const string PolicySecretName = "/gateway/access-policy";

    private readonly ISecretsProvider _secrets;
    private readonly CloudOptions _options;
    private readonly ILogger<AwsAccessControlProvider> _logger;

    public AwsAccessControlProvider(
        ISecretsProvider secrets,
        IOptions<CloudOptions> options,
        ILogger<AwsAccessControlProvider> logger)
    {
        _secrets = secrets;
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
        JsonElement policy;
        try
        {
            var raw = await _secrets.GetSecretAsync(PolicySecretName, cancellationToken);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return Deny(principalArn, action, resource,
                    $"No policy document at '{PolicySecretName}'");
            }

            policy = JsonDocument.Parse(raw).RootElement;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load the management access policy. Denying (fail-closed).");
            return Deny(principalArn, action, resource, "Policy document unavailable");
        }

        if (!policy.TryGetProperty("Statement", out var statements) ||
            statements.ValueKind != JsonValueKind.Array)
        {
            return Deny(principalArn, action, resource, "Policy contains no Statement array");
        }

        var allowMatched = false;

        foreach (var statement in statements.EnumerateArray())
        {
            if (!MatchesPrincipal(statement, principalArn)) continue;
            if (!MatchesValue(statement, "Action", action)) continue;
            if (!MatchesValue(statement, "Resource", resource)) continue;

            var effect = statement.TryGetProperty("Effect", out var e) ? e.GetString() : null;

            // Explicit Deny short-circuits everything, exactly as in AWS.
            if (string.Equals(effect, "Deny", StringComparison.OrdinalIgnoreCase))
            {
                return Deny(principalArn, action, resource, "Explicit Deny in access policy");
            }

            if (string.Equals(effect, "Allow", StringComparison.OrdinalIgnoreCase))
            {
                allowMatched = true;
            }
        }

        return new AccessDecision
        {
            IsAllowed = allowMatched,
            Reason = allowMatched ? "Allowed by policy statement" : "No matching Allow (implicit deny)",
            Action = action,
            Resource = resource,
            Principal = principalArn
        };
    }

    private static bool MatchesPrincipal(JsonElement statement, string principalArn)
    {
        // A statement without a Principal applies to every authenticated caller.
        if (!statement.TryGetProperty("Principal", out var principal)) return true;

        if (principal.ValueKind == JsonValueKind.String)
        {
            return WildcardMatch(principal.GetString(), principalArn);
        }

        if (principal.ValueKind == JsonValueKind.Object &&
            principal.TryGetProperty("AWS", out var awsPrincipal))
        {
            return MatchesScalarOrArray(awsPrincipal, principalArn);
        }

        return false;
    }

    private static bool MatchesValue(JsonElement statement, string property, string candidate)
    {
        if (!statement.TryGetProperty(property, out var element)) return false;
        return MatchesScalarOrArray(element, candidate);
    }

    private static bool MatchesScalarOrArray(JsonElement element, string candidate)
    {
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

    /// <summary>IAM-style wildcard matching: '*' spans any run, '?' matches one character.</summary>
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

#region Identity — AWS STS

/// <summary>
/// Resolves the caller identity for a presented AWS session. The gateway trusts the
/// upstream (ALB/API Gateway with SigV4 or OIDC) to have verified the signature, and reads
/// the asserted principal ARN from the configured header.
/// </summary>
public class AwsIdentityProvider : IIdentityProvider
{
    private readonly ILogger<AwsIdentityProvider> _logger;

    public AwsIdentityProvider(ILogger<AwsIdentityProvider> logger)
    {
        _logger = logger;
    }

    public Task<ResolvedIdentity> ResolveAsync(string credential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(credential))
        {
            return Task.FromResult(new ResolvedIdentity
            {
                IsAuthenticated = false,
                FailureReason = "No credential presented"
            });
        }

        // An asserted principal must look like a role ARN; anything else is rejected rather
        // than trusted, so a stray header value cannot become an identity.
        if (!credential.StartsWith("arn:aws:", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Rejected a management credential that is not a principal ARN.");
            return Task.FromResult(new ResolvedIdentity
            {
                IsAuthenticated = false,
                FailureReason = "Credential is not a principal ARN"
            });
        }

        return Task.FromResult(new ResolvedIdentity
        {
            IsAuthenticated = true,
            PrincipalArn = credential,
            AuthType = "AwsAssertedPrincipal"
        });
    }
}

#endregion
