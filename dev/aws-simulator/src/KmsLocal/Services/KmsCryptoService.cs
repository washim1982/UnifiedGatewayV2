using System.Security.Cryptography;
using Shared.Crypto;
using Shared.DTOs;

namespace KmsLocal.Services;

public interface IKmsCryptoService
{
    DataKeyDto GenerateDataKey(string keyId, int keySizeBits = 256);
    byte[] Encrypt(string keyId, byte[] plaintext);
    byte[] Decrypt(string keyId, byte[] ciphertextBlob);
}

public class KmsCryptoService : IKmsCryptoService
{
    private readonly IMasterKeyStore _masterKeyStore;

    public KmsCryptoService(IMasterKeyStore masterKeyStore)
    {
        _masterKeyStore = masterKeyStore;
    }

    public DataKeyDto GenerateDataKey(string keyId, int keySizeBits = 256)
    {
        if (keySizeBits != 128 && keySizeBits != 256)
        {
            throw new ArgumentException("Only 128-bit or 256-bit key sizes are supported.", nameof(keySizeBits));
        }

        int byteCount = keySizeBits / 8;
        var dataKey = RandomNumberGenerator.GetBytes(byteCount);

        var masterKey = _masterKeyStore.GetMasterKey(keyId);
        var ciphertextBlob = AesGcmHelper.Encrypt(masterKey, dataKey);

        return new DataKeyDto(
            PlaintextBase64: Convert.ToBase64String(dataKey),
            CiphertextBlobBase64: Convert.ToBase64String(ciphertextBlob)
        );
    }

    public byte[] Encrypt(string keyId, byte[] plaintext)
    {
        var masterKey = _masterKeyStore.GetMasterKey(keyId);
        return AesGcmHelper.Encrypt(masterKey, plaintext);
    }

    public byte[] Decrypt(string keyId, byte[] ciphertextBlob)
    {
        var masterKey = _masterKeyStore.GetMasterKey(keyId);
        return AesGcmHelper.Decrypt(masterKey, ciphertextBlob);
    }
}
