namespace UnifiedGateway.Models;

/// <summary>
/// Selects which backing implementation every cloud-facing seam resolves to.
/// This is the single switch that lets TEST (local AWS simulator) and PROD (real AWS)
/// run the same binary: only configuration changes between environments.
/// </summary>
public enum CloudProviderMode
{
    /// <summary>Local AWS Simulator microservices (IAM/KMS/S3/Bedrock over plain REST).</summary>
    Simulator = 0,

    /// <summary>
    /// The .NET local AWS simulator (DOTNET_AWS_SIMULATOR): S3Local, KmsLocal, IamLocal.
    /// Development only -- see StartupValidator, which refuses it anywhere else.
    /// </summary>
    LocalDotNet = 2,

    /// <summary>Real AWS endpoints via the AWS SDK.</summary>
    Aws = 1
}

public class CloudOptions
{
    public const string SectionName = "Gateway:Cloud";

    /// <summary>Which provider family to bind at startup. See <see cref="CloudProviderMode"/>.</summary>
    public CloudProviderMode Provider { get; set; } = CloudProviderMode.Simulator;

    public SimulatorEndpointOptions Simulator { get; set; } = new();
    public LocalDotNetOptions LocalDotNet { get; set; } = new();
    public SecretsOptions Secrets { get; set; } = new();
    public CryptoOptions Crypto { get; set; } = new();
    public AccessControlOptions AccessControl { get; set; } = new();
    public AuditStorageOptions Storage { get; set; } = new();

    /// <summary>Machine identity for the management plane in AWS mode. See <see cref="AwsIdentityOptions"/>.</summary>
    public AwsIdentityOptions AwsIdentity { get; set; } = new();

    /// <summary>
    /// Overrides <see cref="Provider"/> for Bedrock alone. Null means "follow Provider".
    ///
    /// Bedrock is the one seam where a simulator is a poor substitute: the control plane
    /// (S3, KMS, IAM) is a contract the simulators reproduce faithfully, but model output
    /// is the thing under development, and a stub of it tests nothing. So Development binds
    /// the control plane to the local simulator and Bedrock to the real service, reached
    /// with the developer's own ~/.aws profile.
    ///
    /// Only 'Simulator' and 'Aws' are meaningful here -- the .NET simulator has no Bedrock
    /// at all, which is why leaving this to inherit 'LocalDotNet' is refused at startup.
    /// </summary>
    public CloudProviderMode? BedrockProvider { get; set; }

    /// <summary>The provider actually in force for Bedrock, after the override is applied.</summary>
    public CloudProviderMode EffectiveBedrockProvider => BedrockProvider ?? Provider;

    /// <summary>
    /// Base URL for the Bedrock Runtime API. Empty means "use the real AWS endpoint for the
    /// configured region". The Python simulator is wire-compatible (POST /model/{id}/invoke),
    /// so pointing the AWS SDK at it needs no code change.
    /// </summary>
    public string BedrockServiceUrl { get; set; } = string.Empty;
}

/// <summary>Endpoints of the .NET local AWS simulator.</summary>
public class LocalDotNetOptions
{
    public string S3Url { get; set; } = "http://localhost:5001";
    public string KmsUrl { get; set; } = "http://localhost:5002";
    public string IamUrl { get; set; } = "http://localhost:5003";

    /// <summary>Seconds to wait on any simulator call.</summary>
    public int TimeoutSeconds { get; set; } = 10;

    /// <summary>Bucket the gateway keeps its KMS-encrypted secrets in.</summary>
    public string SecretsBucket { get; set; } = "gateway-secrets";

    /// <summary>
    /// KMS key alias used for envelope encryption. KmsLocal resolves any alias to its
    /// single dev master key, so this exists to mirror the production shape.
    /// </summary>
    public string KeyId { get; set; } = "alias/dev-master-key";
}

public class SimulatorEndpointOptions
{
    public string IamUrl { get; set; } = "http://localhost:5001";
    public string S3Url { get; set; } = "http://localhost:5002";
    public string KmsUrl { get; set; } = "http://localhost:5003";
    public string BedrockUrl { get; set; } = "http://localhost:5004";

    /// <summary>Seconds to wait on any simulator control-plane call.</summary>
    public int TimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// Role presented to the simulator gateway on control-plane calls
    /// (the simulator's X-Simulator-Role convenience header).
    /// </summary>
    public string CallerRoleName { get; set; } = "KmsCryptoRole";
}

/// <summary>
/// Where the durable audit trail lives. Billing and telemetry are both read from it, so
/// this is the store of record for spend and observability data.
/// </summary>
public class AuditStorageOptions
{
    /// <summary>Bucket holding the trail. S3Local in dev, real S3 in test and production.</summary>
    public string Bucket { get; set; } = "gateway-telemetry";

    /// <summary>
    /// Seconds between background flushes. S3 objects are immutable, so records are batched
    /// into whole objects rather than appended; this is the ceiling on how long a record
    /// sits in memory before it is durable.
    /// </summary>
    public int FlushIntervalSeconds { get; set; } = 30;

    /// <summary>Records that force an immediate flush, so a burst does not sit unwritten.</summary>
    public int FlushBatchSize { get; set; } = 100;

    /// <summary>Partitions older than this are deleted. 0 keeps everything.</summary>
    public int RetentionDays { get; set; } = 90;

    /// <summary>
    /// Records held in memory for the metrics view, rehydrated from S3 at startup so the
    /// telemetry page is not blank after a restart.
    /// </summary>
    public int RecentBufferSize { get; set; } = 500;
}

public class SecretsOptions
{
    /// <summary>Secret holding the master admin credential. Replaces the plaintext config value.</summary>
    public string AdminApiKeyName { get; set; } = "/gateway/admin-api-key";

    /// <summary>Secret holding the HMAC key that signs application STS tokens.</summary>
    public string StsSigningKeyName { get; set; } = "/gateway/sts-signing-key";

    /// <summary>How long a fetched secret is cached before it is re-read. Drives rotation pickup.</summary>
    public int CacheSeconds { get; set; } = 300;
}

public class CryptoOptions
{
    /// <summary>KMS key id / alias used to protect gateway material at rest.</summary>
    public string KeyId { get; set; } = "default";

    /// <summary>Encryption context applied to every envelope operation (AAD).</summary>
    public Dictionary<string, string> EncryptionContext { get; set; } = new()
    {
        ["application"] = "UnifiedLLMGateway"
    };
}

public class AccessControlOptions
{
    /// <summary>When false, management-plane IAM evaluation is skipped (authentication still applies).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Service prefix used when building action names, e.g. "gateway:CreateApplication".</summary>
    public string ServicePrefix { get; set; } = "gateway";

    /// <summary>ARN template for management resources. {0} is replaced with the resource id.</summary>
    public string ResourceArnTemplate { get; set; } = "arn:aws:gateway:us-east-1:123456789012:application/{0}";

    /// <summary>Seconds an allow/deny decision is cached per (principal, action, resource).</summary>
    public int DecisionCacheSeconds { get; set; } = 30;

    /// <summary>
    /// Role ARNs permitted to reach the management plane at all. An empty list means
    /// "any authenticated principal, subject to policy evaluation".
    /// </summary>
    public string[] AdminRoleArns { get; set; } = [];

    /// <summary>
    /// Principal the break-glass credential acts as -- directly, and through every admin STS
    /// token minted from it. Fixed server-side so that neither the key holder nor anything
    /// written into a token chooses whose name the audit trail records. Required outside
    /// Development; with it unset, break-glass is refused rather than guessed.
    /// </summary>
    public string BreakGlassPrincipalArn { get; set; } = string.Empty;
}

/// <summary>
/// Lets automation prove an IAM identity to the management plane in AWS mode.
///
/// The caller signs an sts:GetCallerIdentity request with its own AWS credentials and hands
/// the gateway the signed request -- never the credentials. The gateway forwards it to STS
/// and trusts only the ARN STS answers with. Nothing the caller merely asserts, such as an
/// ARN in a header, is accepted as an identity.
/// </summary>
public class AwsIdentityOptions
{
    /// <summary>
    /// Accept signed GetCallerIdentity requests. Off means only Okta sign-in and break-glass
    /// reach the management plane.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Value the caller must sign into the X-Gateway-Server-Id header. Binds a signed request
    /// to this gateway, so one captured by another service using the same pattern cannot be
    /// replayed here. It is not a secret; it is binding only because the header is signed.
    /// </summary>
    public string ServerId { get; set; } = string.Empty;

    /// <summary>AWS accounts whose principals may authenticate. Required when enabled.</summary>
    public string[] AllowedAccountIds { get; set; } = [];

    /// <summary>
    /// STS hostnames a signed request may be sent to. Empty means the global endpoint plus
    /// the configured region's. The gateway forwards nowhere else, which is what keeps it
    /// from being an open relay.
    /// </summary>
    public string[] AllowedStsHosts { get; set; } = [];

    /// <summary>Oldest X-Amz-Date accepted, in seconds. STS itself allows fifteen minutes.</summary>
    public int MaxRequestAgeSeconds { get; set; } = 300;

    /// <summary>How long a verified identity is reused for the same signed request.</summary>
    public int CacheSeconds { get; set; } = 60;

    /// <summary>Seconds to wait on STS.</summary>
    public int TimeoutSeconds { get; set; } = 10;
}
