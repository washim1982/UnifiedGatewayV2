using System.Net.Http.Json;
using Shared.DTOs;
using Shared.Interfaces;

namespace AppClients.Local;

public class LocalKmsClient : IKmsClient
{
    private readonly HttpClient _http;

    public LocalKmsClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<DataKeyDto> GenerateDataKeyAsync(string keyId, int keySizeBits = 256)
    {
        var response = await _http.PostAsJsonAsync("/generate-data-key", new GenerateDataKeyRequest(keyId, keySizeBits));
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<DataKeyDto>();
        return result ?? throw new InvalidOperationException("Empty response from KMS service.");
    }

    public async Task<byte[]> EncryptAsync(string keyId, byte[] plaintext)
    {
        var request = new EncryptRequest(keyId, Convert.ToBase64String(plaintext));
        var response = await _http.PostAsJsonAsync("/encrypt", request);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<EncryptResponse>();
        if (result == null || string.IsNullOrEmpty(result.CiphertextBlobBase64))
        {
            throw new InvalidOperationException("Invalid response from KMS encrypt.");
        }

        return Convert.FromBase64String(result.CiphertextBlobBase64);
    }

    public async Task<byte[]> DecryptAsync(string keyId, byte[] ciphertext)
    {
        var request = new DecryptRequest(keyId, Convert.ToBase64String(ciphertext));
        var response = await _http.PostAsJsonAsync("/decrypt", request);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<DecryptResponse>();
        if (result == null || string.IsNullOrEmpty(result.PlaintextBase64))
        {
            throw new InvalidOperationException("Invalid response from KMS decrypt.");
        }

        return Convert.FromBase64String(result.PlaintextBase64);
    }
}
