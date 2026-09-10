namespace UnifiedGateway.Services.Cloud;

/// <summary>
/// Object storage for durable gateway data — the audit trail that billing and telemetry are
/// both built from.
///
/// Simulator: S3Local. Test and Production: real S3. The interface is deliberately the small
/// subset the gateway needs, so a new backing store is a short class rather than a port of
/// the S3 API.
/// </summary>
public interface IObjectStore
{
    Task PutAsync(string key, byte[] content, string contentType, CancellationToken cancellationToken = default);

    /// <summary>Returns the object body, or null when the key does not exist.</summary>
    Task<byte[]?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Keys under a prefix, in lexicographic order.</summary>
    Task<IReadOnlyList<string>> ListAsync(string prefix, CancellationToken cancellationToken = default);

    Task DeleteAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Creates the bucket if the backing store needs it to exist first.</summary>
    Task EnsureReadyAsync(CancellationToken cancellationToken = default);

    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);
}
