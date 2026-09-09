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

    /// <summary>Real AWS endpoints via the AWS SDK.</summary>
    Aws = 1
}

public class CloudOptions
{
    public const string SectionName = "Gateway:Cloud";

    /// <summary>Which provider family to bind at startup. See <see cref="CloudProviderMode"/>.</summary>
    public CloudProviderMode Provider { get; set; } = CloudProviderMode.Simulator;

    public SimulatorEndpointOptions Simulator { get; set; } = new();
    public SecretsOptions Secrets { get; set; } = new();
    public CryptoOptions Crypto { get; set; } = new();
    public AccessControlOptions AccessControl { get; set; } = new();

    /// <summary>
    /// Base URL for the Bedrock Runtime API. Empty means "use the real AWS endpoint for the
    /// configured region". The simulator is wire-compatible (POST /model/{id}/invoke), so
    /// pointing the AWS SDK at it needs no code change.
    /// </summary>
    public string BedrockServiceUrl { get; set; } = string.Empty;
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
}
