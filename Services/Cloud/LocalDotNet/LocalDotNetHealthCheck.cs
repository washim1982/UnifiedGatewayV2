using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud.LocalDotNet;

public record LocalDotNetEndpointStatus(string Expected, string Url, bool Reachable, string? Found, string? Problem)
{
    public bool IsCorrectService => Reachable && string.Equals(Found, Expected, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Confirms each configured URL is served by the .NET simulator service the gateway expects.
///
/// This exists because the .NET simulator and the older Python/Docker simulator both listen on
/// 5001-5003 but assign the services differently (Python: IAM/S3/KMS; .NET: S3/KMS/IAM). With
/// the wrong stack running, calls still connect and return plausible HTTP responses, so the
/// failures surface later as confusing 404s and decrypt errors. Checking identity at startup
/// turns that into one clear message.
/// </summary>
public class LocalDotNetHealthCheck
{
    private sealed record HealthResponse(string? Status, string? Service);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LocalDotNetOptions _options;

    public LocalDotNetHealthCheck(IHttpClientFactory httpClientFactory, IOptions<CloudOptions> options)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value.LocalDotNet;
    }

    public async Task<IReadOnlyList<LocalDotNetEndpointStatus>> ProbeAsync(CancellationToken cancellationToken = default)
    {
        return
        [
            await ProbeOneAsync(LocalDotNetClients.S3, "S3Local", _options.S3Url, cancellationToken),
            await ProbeOneAsync(LocalDotNetClients.Kms, "KmsLocal", _options.KmsUrl, cancellationToken),
            await ProbeOneAsync(LocalDotNetClients.Iam, "IamLocal", _options.IamUrl, cancellationToken)
        ];
    }

    private async Task<LocalDotNetEndpointStatus> ProbeOneAsync(
        string clientName, string expected, string url, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient(clientName);
            using var response = await client.GetAsync("/health", cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return new LocalDotNetEndpointStatus(expected, url, false, null,
                    $"/health returned HTTP {(int)response.StatusCode}");
            }

            var health = await response.Content.ReadFromJsonAsync<HealthResponse>(
                LocalDotNetJson.Options, cancellationToken);

            var found = health?.Service;

            if (string.Equals(found, expected, StringComparison.OrdinalIgnoreCase))
            {
                return new LocalDotNetEndpointStatus(expected, url, true, found, null);
            }

            return new LocalDotNetEndpointStatus(expected, url, true, found,
                $"expected '{expected}' but found '{found ?? "an unidentified service"}'");
        }
        catch (Exception ex)
        {
            return new LocalDotNetEndpointStatus(expected, url, false, null, ex.Message);
        }
    }
}
