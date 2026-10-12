using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shared.Crypto;
using Shared.DTOs;
using Shared.Interfaces;

namespace AppClients.Local;

public class LocalRolesAnywhereClient : IRolesAnywhereClient
{
    private readonly HttpClient _http;

    public LocalRolesAnywhereClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<AssumedCredentials> CreateSessionAsync(
        X509Certificate2 clientCert,
        string roleArn,
        string? profileArn = null,
        string? trustAnchorArn = null,
        TimeSpan? duration = null)
    {
        var targetProfile = profileArn ?? "arn:aws:rolesanywhere:us-east-1:123456789012:profile/dev-profile";
        var targetAnchor = trustAnchorArn ?? "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/dev-anchor";
        var durationSec = (int)(duration?.TotalSeconds ?? 3600);

        // Construct challenge payload
        var payload = $"{DateTime.UtcNow:O}:{roleArn}:{targetProfile}";
        var payloadBytes = Encoding.UTF8.GetBytes(payload);

        using var rsa = clientCert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("The provided client certificate does not contain an RSA private key.");

        var signatureBytes = rsa.SignData(payloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signatureBase64 = Convert.ToBase64String(signatureBytes);
        var certPem = X509CertificateGenerator.ExportToPem(clientCert);

        var request = new CreateSessionRequest(
            CertPem: certPem,
            SignatureBase64: signatureBase64,
            PayloadToVerify: payload,
            ProfileArn: targetProfile,
            RoleArn: roleArn,
            TrustAnchorArn: targetAnchor,
            DurationSeconds: durationSec);

        var response = await _http.PostAsJsonAsync("/rolesanywhere/create-session", request);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<CreateSessionResponse>();
        if (body?.Credentials == null)
        {
            throw new InvalidOperationException("Failed to obtain assumed credentials from Roles Anywhere response.");
        }

        return body.Credentials;
    }

    public async Task<GenerateTestCertResponse> GenerateTestCertificateAsync(string subjectName = "CN=LocalWorkloadClient")
    {
        var response = await _http.PostAsync($"/rolesanywhere/generate-test-cert?subject={Uri.EscapeDataString(subjectName)}", null);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<GenerateTestCertResponse>();
        return body!;
    }

    public async Task<List<TrustAnchorSummary>> ListTrustAnchorsAsync()
    {
        var list = await _http.GetFromJsonAsync<List<TrustAnchorSummary>>("/rolesanywhere/trust-anchors");
        return list ?? new List<TrustAnchorSummary>();
    }

    public async Task<List<ProfileSummary>> ListProfilesAsync()
    {
        var list = await _http.GetFromJsonAsync<List<ProfileSummary>>("/rolesanywhere/profiles");
        return list ?? new List<ProfileSummary>();
    }
}
