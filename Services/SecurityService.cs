using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Services;

/// <summary>
/// Key generation, hashing, and application STS token issuance.
///
/// Tokens are signed with HMAC-SHA256 using a key held in the environment's secret store
/// (simulator KMS or AWS Secrets Manager + KMS), never with a local key ring on the web
/// tier. Every token carries the signing-key generation, so rotation is an immediate,
/// fleet-wide revocation.
/// </summary>
public class SecurityService : ISecurityService
{
    private const string StsPrefix = "ug_sts_";

    private readonly ISigningKeyProvider _signingKeys;
    private readonly ICryptoProvider _crypto;
    private readonly SecurityOptions _securityOptions;
    private readonly ILogger<SecurityService> _logger;

    /// <summary>Revoked jti values with the instant they stop mattering (their own expiry).</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revoked = new();

    public SecurityService(
        ISigningKeyProvider signingKeys,
        ICryptoProvider crypto,
        IOptions<GatewayOptions> gatewayOptions,
        ILogger<SecurityService> logger)
    {
        _signingKeys = signingKeys;
        _crypto = crypto;
        _securityOptions = gatewayOptions.Value.Security;
        _logger = logger;
    }

    #region API keys

    public (string rawKey, string keyHash, string keyPrefix) GenerateApiKey()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var keySuffix = Convert.ToHexString(randomBytes).ToLowerInvariant();
        var rawKey = $"ug_live_{keySuffix}";
        var keyPrefix = rawKey[..12];
        var keyHash = HashKey(rawKey);

        return (rawKey, keyHash, keyPrefix);
    }

    public string HashKey(string apiKey)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public bool VerifyKey(string apiKey, string hash)
    {
        if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(hash))
        {
            return false;
        }

        var computed = HashKey(apiKey);
        var computedBytes = Encoding.UTF8.GetBytes(computed);
        var expectedBytes = Encoding.UTF8.GetBytes(hash);

        // FixedTimeEquals requires equal lengths; a length mismatch is already a mismatch.
        if (computedBytes.Length != expectedBytes.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(computedBytes, expectedBytes);
    }

    public string MaskSecret(string? secret, int visibleChars = 4)
    {
        if (string.IsNullOrEmpty(secret)) return "******";
        if (secret.Length <= visibleChars * 2) return "******";

        return $"{secret[..visibleChars]}******{secret[^visibleChars..]}";
    }

    #endregion

    #region Envelope encryption

    public async Task<string> EncryptAsync(string plainText, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(plainText)) return string.Empty;
        return await _crypto.EncryptAsync(plainText, cancellationToken);
    }

    public async Task<string> DecryptAsync(string cipherText, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(cipherText)) return string.Empty;
        return await _crypto.DecryptAsync(cipherText, cancellationToken);
    }

    #endregion

    #region Application STS tokens

    public async Task<(string token, DateTimeOffset expiresAt)> IssueAppStsTokenAsync(
        string appId,
        TimeSpan duration,
        string scope = "invoke",
        bool isAdmin = false,
        string? callerId = null,
        CancellationToken cancellationToken = default)
    {
        var issued = await IssueStsTokenAsync(new StsTokenSpec
        {
            AppId = appId,
            Duration = duration,
            Scope = scope,
            IsAdmin = isAdmin,
            CallerId = callerId
        }, cancellationToken);

        return (issued.Token, issued.ExpiresAt);
    }

    public async Task<IssuedStsToken> IssueStsTokenAsync(StsTokenSpec spec, CancellationToken cancellationToken = default)
    {
        var clampedDuration = ClampDuration(spec.Duration, spec.IsAdmin);
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.Add(clampedDuration);

        var signingKey = await _signingKeys.GetCurrentAsync(cancellationToken);

        var payload = new AppStsTokenPayload
        {
            Jti = Guid.NewGuid().ToString("N"),
            AppId = spec.AppId,
            IssuedAtUnix = now.ToUnixTimeSeconds(),
            ExpiresAtUnix = expiresAt.ToUnixTimeSeconds(),
            Scope = GatewayScopes.Normalize(spec.Scope),
            IsAdmin = spec.IsAdmin,
            CallerId = spec.CallerId,
            Generation = signingKey.Generation
        };

        var payloadSegment = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signatureSegment = Base64UrlEncode(ComputeSignature(payloadSegment, signingKey.Key));

        return new IssuedStsToken(
            $"{StsPrefix}{payloadSegment}.{signatureSegment}", now, expiresAt, payload.Jti, payload.Scope);
    }

    public async Task<(bool isValid, AppStsTokenPayload? payload, string? failureReason)> ValidateAppStsTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return (false, null, "Token is empty");

        var cleanToken = token.Trim();
        if (cleanToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            cleanToken = cleanToken[7..].Trim();

        if (!cleanToken.StartsWith(StsPrefix, StringComparison.Ordinal))
            return (false, null, "Token does not have a valid STS prefix (expected 'ug_sts_')");

        var parts = cleanToken[StsPrefix.Length..].Split('.', 2);
        if (parts.Length != 2)
            return (false, null, "Malformed STS token format");

        var payloadSegment = parts[0];
        var signatureSegment = parts[1];

        // 1. Verify the signature before parsing anything out of the payload.
        SigningKeyMaterial signingKey;
        try
        {
            signingKey = await _signingKeys.GetCurrentAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Fail closed: without the signing key nothing can be trusted.
            _logger.LogError(ex, "Signing key unavailable; rejecting STS token.");
            return (false, null, "Signing key unavailable");
        }

        byte[] presentedSignature;
        try
        {
            presentedSignature = Base64UrlDecode(signatureSegment);
        }
        catch
        {
            return (false, null, "Invalid base64 signature encoding");
        }

        var expectedSignature = ComputeSignature(payloadSegment, signingKey.Key);
        if (presentedSignature.Length != expectedSignature.Length ||
            !CryptographicOperations.FixedTimeEquals(presentedSignature, expectedSignature))
        {
            _logger.LogWarning("STS token signature verification failed.");
            return (false, null, "STS token signature verification failed or token has been tampered with");
        }

        // 2. Decode claims.
        AppStsTokenPayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<AppStsTokenPayload>(Base64UrlDecode(payloadSegment));
        }
        catch (Exception ex)
        {
            return (false, null, $"Failed to parse STS claims payload: {ex.Message}");
        }

        if (payload is null)
            return (false, null, "STS claims payload is null");

        // 3. Signing-key generation. A rotated key invalidates every earlier token.
        if (payload.Generation != signingKey.Generation)
        {
            return (false, payload,
                $"Token was issued under signing key generation {payload.Generation}; current generation is {signingKey.Generation}");
        }

        // 4. Expiry.
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > payload.ExpiresAtUnix)
        {
            return (false, payload,
                $"STS token expired at {DateTimeOffset.FromUnixTimeSeconds(payload.ExpiresAtUnix):u}");
        }

        // 5. Targeted revocation.
        if (IsRevoked(payload.Jti))
        {
            return (false, payload, "STS token has been revoked");
        }

        return (true, payload, null);
    }

    public async Task<AppStsInspectResponse> InspectAppStsTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var (isValid, payload, failureReason) = await ValidateAppStsTokenAsync(token, cancellationToken);

        if (payload is null)
        {
            return new AppStsInspectResponse
            {
                IsValid = false,
                Error = failureReason ?? "Invalid token"
            };
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(payload.IssuedAtUnix);
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(payload.ExpiresAtUnix);
        var now = DateTimeOffset.UtcNow;

        return new AppStsInspectResponse
        {
            IsValid = isValid,
            AppId = payload.AppId,
            IsAdmin = payload.IsAdmin,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            ExpiresInSeconds = Math.Round(Math.Max(0, (expiresAt - now).TotalSeconds), 1),
            IsExpired = now > expiresAt,
            Scope = payload.Scope,
            CallerId = payload.CallerId,
            Error = isValid ? null : failureReason
        };
    }


    /// <summary>
    /// True when a token's granted scope permits the required one.
    ///
    /// "*" grants everything and "admin" implies "invoke", since an administrator that could
    /// not call a model would be a strange kind of administrator. Everything else must match
    /// exactly — "read" does not imply "invoke", which is the whole point of the claim.
    /// </summary>
    public static bool ScopePermits(string? granted, string required)
    {
        if (string.IsNullOrWhiteSpace(granted))
        {
            // A token with no scope predates enforcement; treat it as invoke-only rather than
            // as unrestricted, so an old token cannot be more powerful than a new one.
            granted = GatewayScopes.Invoke;
        }

        var parts = granted.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var part in parts)
        {
            if (string.Equals(part, GatewayScopes.All, StringComparison.Ordinal)) return true;
            if (string.Equals(part, required, StringComparison.OrdinalIgnoreCase)) return true;

            if (string.Equals(part, GatewayScopes.Admin, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(required, GatewayScopes.Invoke, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
    public void RevokeToken(string jti, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrWhiteSpace(jti)) return;

        _revoked[jti] = expiresAt;
        PruneRevoked();

        _logger.LogWarning("STS token {Jti} revoked; it will be rejected until it expires at {ExpiresAt:u}.",
            jti, expiresAt);
    }

    private bool IsRevoked(string jti)
    {
        if (!_revoked.TryGetValue(jti, out var expiresAt))
        {
            return false;
        }

        if (DateTimeOffset.UtcNow > expiresAt)
        {
            _revoked.TryRemove(jti, out _);
            return false;
        }

        return true;
    }

    private void PruneRevoked()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var entry in _revoked)
        {
            if (now > entry.Value)
            {
                _revoked.TryRemove(entry.Key, out _);
            }
        }
    }

    /// <summary>
    /// Bounds the requested lifetime. The ceiling is configuration-driven so an environment
    /// can tighten it, and it is what stops a "short temporary secret" being a week long.
    /// Admin tokens get the lower of the two ceilings: each one is break-glass in bearer form.
    /// </summary>
    private TimeSpan ClampDuration(TimeSpan requested, bool isAdmin)
    {
        var min = TimeSpan.FromSeconds(30);
        var maxSeconds = Math.Max(60, _securityOptions.MaxStsTokenLifetimeSeconds);
        if (isAdmin)
        {
            maxSeconds = Math.Min(maxSeconds, Math.Max(60, _securityOptions.MaxAdminStsTokenLifetimeSeconds));
        }

        var max = TimeSpan.FromSeconds(maxSeconds);

        if (requested < min) return min;
        if (requested > max)
        {
            _logger.LogInformation(
                "Requested STS lifetime {Requested} exceeds the ceiling {Max}; clamping.", requested, max);
            return max;
        }

        return requested;
    }

    private static byte[] ComputeSignature(string payloadSegment, byte[] key)
        => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payloadSegment));

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var incoming = input.Replace('-', '+').Replace('_', '/');
        switch (incoming.Length % 4)
        {
            case 2: incoming += "=="; break;
            case 3: incoming += "="; break;
        }
        return Convert.FromBase64String(incoming);
    }

    #endregion
}
