namespace Shared.DTOs;

public record AssumeRoleRequest(string RoleName, int? DurationSeconds = 3600);
public record GetCallerIdentityRequest(string? Jwt = null);

public record GenerateDataKeyRequest(string KeyId, int? KeySizeBits = 256);
public record EncryptRequest(string KeyId, string PlaintextBase64);
public record EncryptResponse(string CiphertextBlobBase64);
public record DecryptRequest(string KeyId, string CiphertextBlobBase64);
public record DecryptResponse(string PlaintextBase64);

public record PresignRequest(string Bucket, string Key, int DurationSeconds = 3600);
public record PresignResponse(string Url, DateTime ExpiresAt);

public record PutObjectResponse(string ETag);

public record CreateBucketRequest(string Name, string? Region = "us-east-1");
public record BucketSummaryResponse(string Name, string Region, string? Owner, DateTime CreatedAt, int ObjectCount, long TotalBytes);

// IAM Roles Anywhere DTOs
public record CreateSessionRequest(
    string CertPem,
    string SignatureBase64,
    string PayloadToVerify,
    string? ProfileArn = null,
    string? RoleArn = null,
    string? TrustAnchorArn = null,
    int DurationSeconds = 3600);

public record CreateSessionResponse(AssumedCredentials Credentials);

public record AssumedCredentials(
    string AccessKeyId,
    string SecretAccessKey,
    string SessionToken,
    DateTime Expiration);

public record GenerateTestCertResponse(
    string CertPem,
    string PrivateKeyPem,
    string Thumbprint,
    string Subject);

public record TrustAnchorSummary(
    string TrustAnchorArn,
    string Name,
    string CaThumbprint,
    string CaSubject);

public record ProfileSummary(
    string ProfileArn,
    string Name,
    List<string> RoleArns,
    int DurationSeconds);

// --- AWS-compatible IAM Roles Anywhere (POST /sessions) ---------------------
// These mirror the real CreateSession contract so a client needs no change to move
// between this simulator and rolesanywhere.{region}.amazonaws.com.

public record AwsCreateSessionRequest(
    int DurationSeconds = 3600,
    string? ProfileArn = null,
    string? RoleArn = null,
    string? TrustAnchorArn = null,
    string? SessionName = null);

public record AwsSessionCredentials(
    string AccessKeyId,
    string SecretAccessKey,
    string SessionToken,
    string Expiration);

public record AwsAssumedRoleUser(string Arn, string AssumedRoleId);

public record AwsCredentialSetEntry(
    AwsAssumedRoleUser AssumedRoleUser,
    AwsSessionCredentials Credentials,
    int PackedPolicySize,
    string SourceIdentity);

public record AwsCreateSessionResponse(
    List<AwsCredentialSetEntry> CredentialSet,
    string SubjectArn);
