using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KmsLocal.Services;

public interface IMasterKeyStore
{
    byte[] GetMasterKey(string keyId = "default");
}

public class DevMasterKeyStore : IMasterKeyStore
{
    private readonly string _keysDirectory;
    private readonly ILogger<DevMasterKeyStore> _logger;
    private readonly Dictionary<string, byte[]> _cachedKeys = new();
    private readonly object _lock = new();

    public DevMasterKeyStore(IConfiguration config, ILogger<DevMasterKeyStore> logger)
    {
        _logger = logger;
        _keysDirectory = config.GetValue<string>("KeysDirectory") ?? ".keys";
        Directory.CreateDirectory(_keysDirectory);
        _logger.LogWarning("[DEV ONLY] Dev master key store active. Do not use in production!");
    }

    public byte[] GetMasterKey(string keyId = "default")
    {
        var sanitizedKeyId = SanitizeKeyId(keyId);

        lock (_lock)
        {
            if (_cachedKeys.TryGetValue(sanitizedKeyId, out var cachedKey))
            {
                return cachedKey;
            }

            var key = LoadOrCreateMasterKey(sanitizedKeyId);
            _cachedKeys[sanitizedKeyId] = key;
            return key;
        }
    }

    private byte[] LoadOrCreateMasterKey(string keyId)
    {
        var filePath = Path.Combine(_keysDirectory, $"kms_master_{keyId}.dat");

        if (File.Exists(filePath))
        {
            try
            {
                var encryptedBytes = File.ReadAllBytes(filePath);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var decryptedKey = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.CurrentUser);
                    _logger.LogInformation("Loaded DPAPI-protected master key for '{KeyId}'", keyId);
                    return decryptedKey;
                }
                else
                {
                    // For non-Windows dev fallback: simple XOR with machine-specific dev salt
                    var fallbackKey = UnprotectFallback(encryptedBytes);
                    _logger.LogInformation("Loaded fallback dev master key for '{KeyId}'", keyId);
                    return fallbackKey;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to decrypt master key file {Path}. Generating new key.", filePath);
            }
        }

        // Generate a new 256-bit AES master key
        var rawKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            byte[] protectedBytes;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                protectedBytes = ProtectedData.Protect(rawKey, null, DataProtectionScope.CurrentUser);
            }
            else
            {
                protectedBytes = ProtectFallback(rawKey);
            }

            File.WriteAllBytes(filePath, protectedBytes);
            _logger.LogInformation("Generated and persisted new dev master key for '{KeyId}' to {Path}", keyId, filePath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist master key to file. Storing in-memory only.");
        }

        return rawKey;
    }

    private static string SanitizeKeyId(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId)) return "default";
        var safe = new StringBuilder();
        foreach (char c in keyId)
        {
            if (char.IsLetterOrDigit(c) || c == '_' || c == '-')
                safe.Append(c);
            else
                safe.Append('_');
        }
        return safe.ToString();
    }

    private static byte[] ProtectFallback(byte[] raw)
    {
        byte[] salt = SHA256.HashData(Encoding.UTF8.GetBytes("dotnet-aws-simulator-dev-fallback"));
        byte[] result = new byte[raw.Length];
        for (int i = 0; i < raw.Length; i++)
        {
            result[i] = (byte)(raw[i] ^ salt[i % salt.Length]);
        }
        return result;
    }

    private static byte[] UnprotectFallback(byte[] protectedBytes)
    {
        return ProtectFallback(protectedBytes); // XOR is symmetric
    }
}
