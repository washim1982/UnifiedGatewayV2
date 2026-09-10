using Amazon.Runtime;
using UnifiedGateway.Services.Aws;

namespace UnifiedGateway.Services;

public record AwsCredentialStatus
{
    public bool IsInitialized { get; init; }
    public bool IsAssumedRole { get; init; }
    public string Region { get; init; } = string.Empty;

    /// <summary>Which mechanism produced these credentials: RolesAnywhere, AssumeRole or LocalProfile.</summary>
    public string CredentialSource { get; init; } = string.Empty;

    public string? RoleArnMasked { get; init; }
    public string? ProfileUsed { get; init; }

    /// <summary>The certificate subject Roles Anywhere mapped to a role, masked.</summary>
    public string? SubjectArnMasked { get; init; }

    /// <summary>
    /// The client certificate this host presents. Null unless Roles Anywhere is in use.
    /// Certificate expiry is the failure mode that takes a Roles Anywhere deployment down
    /// everywhere simultaneously, so it is surfaced rather than left to a calendar reminder.
    /// </summary>
    public RolesAnywhereCertificateInfo? Certificate { get; init; }

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
