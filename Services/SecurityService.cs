using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public class SecurityService : ISecurityService
{
    private const string StsPrefix = "ug_sts_";
    private readonly IDataProtector _secretProtector;
    private readonly IDataProtector _stsProtector;
    private readonly ILogger<SecurityService> _logger;

    public SecurityService(IDataProtectionProvider dataProtectionProvider, ILogger<SecurityService> logger)
    {
        _secretProtector = dataProtectionProvider.CreateProtector("UnifiedGateway.Security.SecretsProtector.v1");
        _stsProtector = dataProtectionProvider.CreateProtector("UnifiedGateway.Security.StsTokenSigner.v1");
        _logger = logger;
    }

    public (string rawKey, string keyHash, string keyPrefix) GenerateApiKey()
    {
        var randomBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }

        var keySuffix = Convert.ToHexString(randomBytes).ToLowerInvariant();
        var rawKey = $"ug_live_{keySuffix}";
        var keyPrefix = rawKey[..12]; // e.g. "ug_live_a1b2"
        var keyHash = HashKey(rawKey);

        return (rawKey, keyHash, keyPrefix);
    }

    public string HashKey(string apiKey)
    {
        var bytes = Encoding.UTF8.GetBytes(apiKey);
        var hashBytes = SHA256.HashData(bytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public bool VerifyKey(string apiKey, string hash)
    {
        var computed = HashKey(apiKey);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computed),
            Encoding.UTF8.GetBytes(hash)
        );
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        try
        {
            return _secretProtector.Protect(plainText);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to encrypt secret payload");
            throw;
        }
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        try
        {
            return _secretProtector.Unprotect(cipherText);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt secret payload");
            throw;
        }
    }

    public string MaskSecret(string? secret, int visibleChars = 4)
    {
        if (string.IsNullOrEmpty(secret))
            return "******";

        if (secret.Length <= visibleChars)
            return "******";

        var prefix = secret[..visibleChars];
        return $"{prefix}******{secret[^visibleChars..]}";
    }

    #region Application Short Temporary Secrets (STS) Implementation

    public (string token, DateTimeOffset expiresAt) IssueAppStsToken(
        string appId,
        TimeSpan duration,
        string scope = "invoke",
        bool isAdmin = false,
        string? callerId = null)
    {
        // Enforce safety bounds on token TTL (min 30s, max 7 days)
        var clampedDuration = duration < TimeSpan.FromSeconds(30)
            ? TimeSpan.FromSeconds(30)
            : duration > TimeSpan.FromDays(7)
                ? TimeSpan.FromDays(7)
                : duration;

        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.Add(clampedDuration);

        var payload = new AppStsTokenPayload
        {
            Jti = Guid.NewGuid().ToString("N"),
            AppId = appId,
            IssuedAtUnix = now.ToUnixTimeSeconds(),
            ExpiresAtUnix = expiresAt.ToUnixTimeSeconds(),
            Scope = string.IsNullOrWhiteSpace(scope) ? "invoke" : scope.Trim().ToLowerInvariant(),
            IsAdmin = isAdmin,
            CallerId = callerId
        };

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        var payloadSegment = Base64UrlEncode(jsonBytes);

        // Sign payload with DataProtection-backed MAC
        var signatureBytes = _stsProtector.Protect(Encoding.UTF8.GetBytes(payloadSegment));
        var signatureSegment = Base64UrlEncode(signatureBytes);

        var token = $"{StsPrefix}{payloadSegment}.{signatureSegment}";
        return (token, expiresAt);
    }

    public (bool isValid, AppStsTokenPayload? payload, string? failureReason) ValidateAppStsToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return (false, null, "Token is empty");

        var cleanToken = token.Trim();
        if (cleanToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            cleanToken = cleanToken[7..].Trim();

        if (!cleanToken.StartsWith(StsPrefix, StringComparison.OrdinalIgnoreCase))
            return (false, null, "Token does not have a valid STS prefix (expected 'ug_sts_')");

        var tokenBody = cleanToken[StsPrefix.Length..];
        var parts = tokenBody.Split('.', 2);
        if (parts.Length != 2)
            return (false, null, "Malformed STS token format");

        var payloadSegment = parts[0];
        var signatureSegment = parts[1];

        // 1. Verify Signature & Integrity
        byte[] signatureBytes;
        try
        {
            signatureBytes = Base64UrlDecode(signatureSegment);
        }
        catch
        {
            return (false, null, "Invalid base64 signature encoding");
        }

        byte[] verifiedPayloadBytes;
        try
        {
            verifiedPayloadBytes = _stsProtector.Unprotect(signatureBytes);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("STS token signature validation failed: {Message}", ex.Message);
            return (false, null, "STS token signature verification failed or token has been tampered with");
        }

        var verifiedPayloadString = Encoding.UTF8.GetString(verifiedPayloadBytes);
        if (!string.Equals(verifiedPayloadString, payloadSegment, StringComparison.Ordinal))
        {
            return (false, null, "STS token payload integrity mismatch");
        }

        // 2. Decode claims payload
        AppStsTokenPayload? payload;
        try
        {
            var jsonBytes = Base64UrlDecode(payloadSegment);
            payload = JsonSerializer.Deserialize<AppStsTokenPayload>(jsonBytes);
        }
        catch (Exception ex)
        {
            return (false, null, $"Failed to parse STS claims payload: {ex.Message}");
        }

        if (payload == null)
            return (false, null, "STS claims payload is null");

        // 3. Expiration Check
        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (nowUnix > payload.ExpiresAtUnix)
        {
            return (false, payload, $"STS token expired at {DateTimeOffset.FromUnixTimeSeconds(payload.ExpiresAtUnix):u}");
        }

        return (true, payload, null);
    }

    public AppStsInspectResponse InspectAppStsToken(string token)
    {
        var (isValid, payload, failureReason) = ValidateAppStsToken(token);

        if (payload == null)
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
        var isExpired = now > expiresAt;
        var expiresInSeconds = Math.Max(0, (expiresAt - now).TotalSeconds);

        return new AppStsInspectResponse
        {
            IsValid = isValid,
            AppId = payload.AppId,
            IsAdmin = payload.IsAdmin,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            ExpiresInSeconds = Math.Round(expiresInSeconds, 1),
            IsExpired = isExpired,
            Scope = payload.Scope,
            CallerId = payload.CallerId,
            Error = isValid ? null : failureReason
        };
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

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
