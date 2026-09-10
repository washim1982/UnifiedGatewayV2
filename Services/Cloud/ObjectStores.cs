using System.Net;
using System.Net.Http.Json;
using System.Text;
using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud.LocalDotNet;

namespace UnifiedGateway.Services.Cloud;

#region S3Local — development

/// <summary>
/// Object store backed by the .NET simulator's S3Local service.
/// </summary>
public class LocalDotNetObjectStore : IObjectStore
{
    private sealed record ObjectSummary(string Bucket, string Key, string? ETag, long Size);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _bucket;
    private readonly ILogger<LocalDotNetObjectStore> _logger;

    public LocalDotNetObjectStore(
        IHttpClientFactory httpClientFactory,
        IOptions<CloudOptions> options,
        ILogger<LocalDotNetObjectStore> logger)
    {
        _httpClientFactory = httpClientFactory;
        _bucket = options.Value.Storage.Bucket;
        _logger = logger;
    }

    private HttpClient Client => _httpClientFactory.CreateClient(LocalDotNetClients.S3);

    public async Task PutAsync(string key, byte[] content, string contentType, CancellationToken cancellationToken = default)
    {
        using var body = new ByteArrayContent(content);
        body.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);

        using var response = await Client.PutAsync($"/{_bucket}/{key}", body, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task<byte[]?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        using var response = await Client.GetAsync($"/{_bucket}/{key}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<string>> ListAsync(string prefix, CancellationToken cancellationToken = default)
    {
        using var response = await Client.GetAsync(
            $"/buckets/{_bucket}/objects?prefix={Uri.EscapeDataString(prefix)}", cancellationToken);

        if (!response.IsSuccessStatusCode) return [];

        var objects = await response.Content.ReadFromJsonAsync<List<ObjectSummary>>(
            LocalDotNetJson.Options, cancellationToken) ?? [];

        return objects
            .Select(o => o.Key)
            .Where(k => !string.IsNullOrEmpty(k))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();
    }

    public async Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        using var response = await Client.DeleteAsync($"/{_bucket}/{key}", cancellationToken);
        if (response.StatusCode != HttpStatusCode.NotFound)
        {
            response.EnsureSuccessStatusCode();
        }
    }

    public async Task EnsureReadyAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var response = await Client.PostAsJsonAsync(
                "/buckets", new { Name = _bucket, Region = "us-east-1" },
                LocalDotNetJson.Options, cancellationToken);

            // Already-exists is the normal case after the first run.
            if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.Conflict)
            {
                _logger.LogDebug("Bucket create returned {Status}; continuing.", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Bucket create attempt failed ({Message}); continuing.", ex.Message);
        }
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var response = await Client.GetAsync("/health", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}

#endregion

#region AWS S3 — test and production

/// <summary>Object store backed by real S3, using the gateway's assumed role.</summary>
public class AwsS3ObjectStore : IObjectStore
{
    private readonly ISTSService _stsService;
    private readonly GatewayOptions _gatewayOptions;
    private readonly string _bucket;
    private readonly ILogger<AwsS3ObjectStore> _logger;

    public AwsS3ObjectStore(
        ISTSService stsService,
        IOptions<GatewayOptions> gatewayOptions,
        IOptions<CloudOptions> cloudOptions,
        ILogger<AwsS3ObjectStore> logger)
    {
        _stsService = stsService;
        _gatewayOptions = gatewayOptions.Value;
        _bucket = cloudOptions.Value.Storage.Bucket;
        _logger = logger;
    }

    private async Task<AmazonS3Client> CreateClientAsync(CancellationToken cancellationToken)
    {
        var credentials = await _stsService.GetCredentialsAsync(cancellationToken);
        var region = RegionEndpoint.GetBySystemName(_gatewayOptions.Aws.Region);
        return new AmazonS3Client(credentials, region);
    }

    public async Task PutAsync(string key, byte[] content, string contentType, CancellationToken cancellationToken = default)
    {
        using var client = await CreateClientAsync(cancellationToken);
        using var stream = new MemoryStream(content);

        await client.PutObjectAsync(new PutObjectRequest
        {
            BucketName = _bucket,
            Key = key,
            InputStream = stream,
            ContentType = contentType
        }, cancellationToken);
    }

    public async Task<byte[]?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            using var client = await CreateClientAsync(cancellationToken);
            using var response = await client.GetObjectAsync(_bucket, key, cancellationToken);
            using var buffer = new MemoryStream();

            await response.ResponseStream.CopyToAsync(buffer, cancellationToken);
            return buffer.ToArray();
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public async Task<IReadOnlyList<string>> ListAsync(string prefix, CancellationToken cancellationToken = default)
    {
        using var client = await CreateClientAsync(cancellationToken);

        var keys = new List<string>();
        var request = new ListObjectsV2Request { BucketName = _bucket, Prefix = prefix };

        // A day of audit data can exceed one page, so follow the continuation token rather
        // than silently billing on the first 1000 objects.
        ListObjectsV2Response response;
        do
        {
            response = await client.ListObjectsV2Async(request, cancellationToken);
            keys.AddRange(response.S3Objects.Select(o => o.Key));
            request.ContinuationToken = response.NextContinuationToken;
        }
        while (response.IsTruncated);

        keys.Sort(StringComparer.Ordinal);
        return keys;
    }

    public async Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        using var client = await CreateClientAsync(cancellationToken);
        await client.DeleteObjectAsync(_bucket, key, cancellationToken);
    }

    public async Task EnsureReadyAsync(CancellationToken cancellationToken = default)
    {
        // The bucket is infrastructure: created by Terraform with versioning, encryption and
        // a lifecycle policy. The gateway only checks it can see it, and never creates it.
        try
        {
            using var client = await CreateClientAsync(cancellationToken);
            await client.GetBucketLocationAsync(_bucket, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Audit bucket '{Bucket}' is not reachable. Billing and telemetry will have nothing to read.",
                _bucket);
        }
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var client = await CreateClientAsync(cancellationToken);
            await client.GetBucketLocationAsync(_bucket, cancellationToken);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("S3 availability probe failed for '{Bucket}': {Message}", _bucket, ex.Message);
            return false;
        }
    }
}

#endregion
