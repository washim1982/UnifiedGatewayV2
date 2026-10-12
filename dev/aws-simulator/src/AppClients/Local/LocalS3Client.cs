using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shared.DTOs;
using Shared.Interfaces;

namespace AppClients.Local;

public class LocalS3Client : IObjectStoreClient
{
    private readonly HttpClient _http;

    public LocalS3Client(HttpClient http)
    {
        _http = http;
    }

    public async Task PutObjectAsync(string bucket, string key, Stream content, string? contentType = null, IDictionary<string, string>? metadata = null)
    {
        var sanitizedKey = key.TrimStart('/');
        var request = new HttpRequestMessage(HttpMethod.Put, $"/{bucket}/{sanitizedKey}")
        {
            Content = new StreamContent(content)
        };

        if (!string.IsNullOrWhiteSpace(contentType))
        {
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        }

        if (metadata != null)
        {
            foreach (var (k, v) in metadata)
            {
                request.Headers.TryAddWithoutValidation($"x-amz-meta-{k}", v);
                request.Headers.TryAddWithoutValidation(k, v);
            }
        }

        var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    public async Task<Stream> GetObjectAsync(string bucket, string key)
    {
        var sanitizedKey = key.TrimStart('/');
        var response = await _http.GetAsync($"/{bucket}/{sanitizedKey}", HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStreamAsync();
    }

    public async Task DeleteObjectAsync(string bucket, string key)
    {
        var sanitizedKey = key.TrimStart('/');
        var response = await _http.DeleteAsync($"/{bucket}/{sanitizedKey}");
        response.EnsureSuccessStatusCode();
    }

    public async Task<string> PresignGetUrlAsync(string bucket, string key, TimeSpan expires)
    {
        var sanitizedKey = key.TrimStart('/');
        var durationSeconds = (int)expires.TotalSeconds;
        var response = await _http.GetFromJsonAsync<PresignResponse>(
            $"/presign?bucket={Uri.EscapeDataString(bucket)}&key={Uri.EscapeDataString(sanitizedKey)}&durationSeconds={durationSeconds}");

        if (response == null)
        {
            throw new InvalidOperationException("Failed to generate presigned URL.");
        }

        return response.Url;
    }
}
