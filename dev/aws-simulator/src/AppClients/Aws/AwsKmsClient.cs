using Amazon.KeyManagementService;
using AwsModel = Amazon.KeyManagementService.Model;
using Shared.DTOs;
using Shared.Interfaces;

namespace AppClients.Aws;

public class AwsKmsClient : IKmsClient
{
    private readonly IAmazonKeyManagementService _kms;

    public AwsKmsClient(IAmazonKeyManagementService kms)
    {
        _kms = kms;
    }

    public async Task<DataKeyDto> GenerateDataKeyAsync(string keyId, int keySizeBits = 256)
    {
        var request = new AwsModel.GenerateDataKeyRequest
        {
            KeyId = keyId,
            KeySpec = keySizeBits == 128 ? DataKeySpec.AES_128 : DataKeySpec.AES_256
        };

        var response = await _kms.GenerateDataKeyAsync(request);
        return new DataKeyDto(
            Convert.ToBase64String(response.Plaintext.ToArray()),
            Convert.ToBase64String(response.CiphertextBlob.ToArray())
        );
    }

    public async Task<byte[]> EncryptAsync(string keyId, byte[] plaintext)
    {
        var request = new AwsModel.EncryptRequest
        {
            KeyId = keyId,
            Plaintext = new MemoryStream(plaintext)
        };

        var response = await _kms.EncryptAsync(request);
        return response.CiphertextBlob.ToArray();
    }

    public async Task<byte[]> DecryptAsync(string keyId, byte[] ciphertext)
    {
        var request = new AwsModel.DecryptRequest
        {
            KeyId = keyId,
            CiphertextBlob = new MemoryStream(ciphertext)
        };

        var response = await _kms.DecryptAsync(request);
        return response.Plaintext.ToArray();
    }
}
