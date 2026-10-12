using Shared.DTOs;

namespace Shared.Interfaces;

public interface IKmsClient
{
    Task<DataKeyDto> GenerateDataKeyAsync(string keyId, int keySizeBits = 256);
    Task<byte[]> EncryptAsync(string keyId, byte[] plaintext);
    Task<byte[]> DecryptAsync(string keyId, byte[] ciphertext);
}
