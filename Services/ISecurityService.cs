using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface ISecurityService
{
    (string rawKey, string keyHash, string keyPrefix) GenerateApiKey();
    string HashKey(string apiKey);
    bool VerifyKey(string apiKey, string hash);
    string MaskSecret(string? secret, int visibleChars = 4);

    // Application STS (Short Temporary Secret) operations.
    // These are async because the signing key lives in the environment's secret store
    // (KMS-encrypted), not in a local key ring on the web tier.

    Task<(string token, DateTimeOffset expiresAt)> IssueAppStsTokenAsync(
        string appId,
        TimeSpan duration,
        string scope = "invoke",
        bool isAdmin = false,
        string? callerId = null,
        CancellationToken cancellationToken = default);

    Task<(bool isValid, AppStsTokenPayload? payload, string? failureReason)> ValidateAppStsTokenAsync(
        string token,
        CancellationToken cancellationToken = default);

    Task<AppStsInspectResponse> InspectAppStsTokenAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes a single outstanding token by its jti. Bounded by the token's own TTL.</summary>
    void RevokeToken(string jti, DateTimeOffset expiresAt);

    /// <summary>Envelope-encrypts a value with the environment's KMS key.</summary>
    Task<string> EncryptAsync(string plainText, CancellationToken cancellationToken = default);

    /// <summary>Reverses <see cref="EncryptAsync"/>.</summary>
    Task<string> DecryptAsync(string cipherText, CancellationToken cancellationToken = default);
}
