using System.Security.Cryptography;

namespace Shared.Crypto;

public static class AesGcmHelper
{
    public const int NonceSize = 12; // 96 bits
    public const int TagSize = 16;   // 128 bits
    public const int DefaultKeySize = 32; // 256 bits

    /// <summary>
    /// Encrypts plaintext using AES-GCM and packages [Nonce(12B)][Tag(16B)][Ciphertext] into a single envelope.
    /// </summary>
    public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] result = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, result, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);

        return result;
    }

    /// <summary>
    /// Decrypts envelope containing [Nonce(12B)][Tag(16B)][Ciphertext] using AES-GCM.
    /// </summary>
    public static byte[] Decrypt(byte[] key, byte[] envelope, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(envelope);

        if (envelope.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Ciphertext envelope is too short to contain valid nonce and tag.");
        }

        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        int ciphertextSize = envelope.Length - NonceSize - TagSize;
        byte[] ciphertext = new byte[ciphertextSize];
        byte[] plaintext = new byte[ciphertextSize];

        Buffer.BlockCopy(envelope, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(envelope, NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(envelope, NonceSize + TagSize, ciphertext, 0, ciphertextSize);

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }
}
