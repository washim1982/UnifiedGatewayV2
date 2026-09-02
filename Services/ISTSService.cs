using Amazon.Runtime;

namespace UnifiedGateway.Services;

public record AwsCredentialStatus
{
    public bool IsInitialized { get; init; }
    public bool IsAssumedRole { get; init; }
    public string Region { get; init; } = string.Empty;
    public string? RoleArnMasked { get; init; }
    public string? ProfileUsed { get; init; }
    public DateTimeOffset? ExpirationUtc { get; init; }
    public bool IsExpiringSoon { get; init; }
    public string? LastError { get; init; }
}

public interface ISTSService
{
    Task<AWSCredentials> GetCredentialsAsync(CancellationToken cancellationToken = default);
    Task<AwsCredentialStatus> GetStatusAsync(CancellationToken cancellationToken = default);
    Task RefreshCredentialsAsync(CancellationToken cancellationToken = default);
}
