namespace Shared.Interfaces;

public interface IObjectStoreClient
{
    Task PutObjectAsync(string bucket, string key, Stream content, string? contentType = null, IDictionary<string, string>? metadata = null);
    Task<Stream> GetObjectAsync(string bucket, string key);
    Task DeleteObjectAsync(string bucket, string key);
    Task<string> PresignGetUrlAsync(string bucket, string key, TimeSpan expires);
}
