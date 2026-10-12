using System.Security.Cryptography;
using System.Text;

namespace S3Local.Services;

public interface IPresignService
{
    string CreatePresignedToken(string bucket, string key, TimeSpan expires);
    bool ValidatePresignedToken(string bucket, string key, string token);
}

public class PresignService : IPresignService
{
    private readonly byte[] _secretKey;

    public PresignService(IConfiguration config)
    {
        var secret = config.GetValue<string>("PresignSecret") ?? "dotnet-aws-simulator-s3-presign-secret-2026";
        _secretKey = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }

    public string CreatePresignedToken(string bucket, string key, TimeSpan expires)
    {
        var expiresUnix = DateTimeOffset.UtcNow.Add(expires).ToUnixTimeSeconds();
        var payload = $"{bucket}:{key}:{expiresUnix}";

        using var hmac = new HMACSHA256(_secretKey);
        var sigBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        var sigHex = Convert.ToHexString(sigBytes).ToLowerInvariant();

        return $"{expiresUnix}.{sigHex}";
    }

    public bool ValidatePresignedToken(string bucket, string key, string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;

        var parts = token.Split('.');
        if (parts.Length != 2) return false;

        if (!long.TryParse(parts[0], out var expiresUnix)) return false;

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresUnix);
        if (expiresAt < DateTimeOffset.UtcNow)
        {
            return false; // Expired
        }

        var payload = $"{bucket}:{key}:{expiresUnix}";
        using var hmac = new HMACSHA256(_secretKey);
        var expectedSig = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expectedSig),
            Encoding.UTF8.GetBytes(parts[1].ToLowerInvariant()));
    }
}
