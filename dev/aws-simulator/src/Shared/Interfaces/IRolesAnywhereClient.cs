using System.Security.Cryptography.X509Certificates;
using Shared.DTOs;

namespace Shared.Interfaces;

public interface IRolesAnywhereClient
{
    Task<AssumedCredentials> CreateSessionAsync(
        X509Certificate2 clientCert,
        string roleArn,
        string? profileArn = null,
        string? trustAnchorArn = null,
        TimeSpan? duration = null);

    Task<GenerateTestCertResponse> GenerateTestCertificateAsync(string subjectName = "CN=LocalWorkloadClient");
    Task<List<TrustAnchorSummary>> ListTrustAnchorsAsync();
    Task<List<ProfileSummary>> ListProfilesAsync();
}
