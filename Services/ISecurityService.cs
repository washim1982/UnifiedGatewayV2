using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface ISecurityService
{
    (string rawKey, string keyHash, string keyPrefix) GenerateApiKey();
    string HashKey(string apiKey);
    bool VerifyKey(string apiKey, string hash);
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
    string MaskSecret(string? secret, int visibleChars = 4);

    // Application STS (Short Temporary Secret) Operations
    (string token, DateTimeOffset expiresAt) IssueAppStsToken(
        string appId,
        TimeSpan duration,
        string scope = "invoke",
        bool isAdmin = false,
        string? callerId = null);

    (bool isValid, AppStsTokenPayload? payload, string? failureReason) ValidateAppStsToken(string token);

    AppStsInspectResponse InspectAppStsToken(string token);
}
