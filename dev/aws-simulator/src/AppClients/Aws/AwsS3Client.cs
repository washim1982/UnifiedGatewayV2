using Amazon.S3;
using Amazon.S3.Model;
using Shared.Interfaces;

namespace AppClients.Aws;

public class AwsS3Client : IObjectStoreClient
{
    private readonly IAmazonS3 _s3;

    public AwsS3Client(IAmazonS3 s3)
    {
        _s3 = s3;
    }

    public async Task PutObjectAsync(string bucket, string key, Stream content, string? contentType = null, IDictionary<string, string>? metadata = null)
    {
        var request = new PutObjectRequest
        {
            BucketName = bucket,
            Key = key,
            InputStream = content,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType
        };

        if (metadata != null)
        {
            foreach (var (k, v) in metadata)
            {
                request.Metadata[k] = v;
            }
        }

        await _s3.PutObjectAsync(request);
    }

    public async Task<Stream> GetObjectAsync(string bucket, string key)
    {
        var request = new GetObjectRequest
        {
            BucketName = bucket,
            Key = key
        };

        var response = await _s3.GetObjectAsync(request);
        return response.ResponseStream;
    }

    public async Task DeleteObjectAsync(string bucket, string key)
    {
        var request = new DeleteObjectRequest
        {
            BucketName = bucket,
            Key = key
        };

        await _s3.DeleteObjectAsync(request);
    }

    public Task<string> PresignGetUrlAsync(string bucket, string key, TimeSpan expires)
    {
        var request = new GetPreSignedUrlRequest
        {
            BucketName = bucket,
            Key = key,
            Expires = DateTime.UtcNow.Add(expires),
            Verb = HttpVerb.GET
        };

        var url = _s3.GetPreSignedURL(request);
        return Task.FromResult(url);
    }
}
