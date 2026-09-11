namespace UnifiedGateway.Models;

/// <summary>
/// Strongly typed root gateway configuration.
/// </summary>
public class GatewayOptions
{
    public const string SectionName = "Gateway";

    public AwsOptions Aws { get; set; } = new();
    public LocalProvidersOptions LocalProviders { get; set; } = new();
    public SecurityOptions Security { get; set; } = new();
    public StorageOptions Storage { get; set; } = new();
    public GuardrailOptions Guardrails { get; set; } = new();
}

public class AwsOptions
{
    public string Region { get; set; } = "us-east-1";
    public string AssumeRoleArn { get; set; } = string.Empty;
    public string RoleSessionName { get; set; } = "UnifiedGatewaySession";
    public int SessionDurationSeconds { get; set; } = 3600;
    public string LocalProfileName { get; set; } = "default";
    public bool UseLocalProfile { get; set; } = false;
    public string? ExternalId { get; set; }
    public int RefreshBufferMinutes { get; set; } = 5;

    /// <summary>
    /// How this host obtains AWS credentials. <see cref="AwsCredentialSource.Auto"/> keeps the
    /// behaviour of configuration written before this setting existed; Test and Production
    /// must name <see cref="AwsCredentialSource.RolesAnywhere"/> explicitly.
    /// </summary>
    public AwsCredentialSource CredentialSource { get; set; } = AwsCredentialSource.Auto;

    /// <summary>IAM Roles Anywhere settings, used when <see cref="CredentialSource"/> selects it.</summary>
    public RolesAnywhereOptions RolesAnywhere { get; set; } = new();

    /// <summary>
    /// The source actually in force, after <see cref="AwsCredentialSource.Auto"/> is resolved
    /// against the older fields.
    /// </summary>
    public AwsCredentialSource EffectiveCredentialSource => CredentialSource switch
    {
        AwsCredentialSource.Auto when UseLocalProfile => AwsCredentialSource.LocalProfile,
        AwsCredentialSource.Auto => AwsCredentialSource.AssumeRole,
        _ => CredentialSource
    };
}

public class LocalProvidersOptions
{
    public OllamaOptions Ollama { get; set; } = new();
    public LmStudioOptions LmStudio { get; set; } = new();
    public LlamaCppOptions LlamaCpp { get; set; } = new();
}

public class OllamaOptions
{
    public string BaseUrl { get; set; } = "http://localhost:11434";
    public int TimeoutSeconds { get; set; } = 120;
    public bool Enabled { get; set; } = true;
}

public class LmStudioOptions
{
    public string BaseUrl { get; set; } = "http://localhost:1234";
    public int TimeoutSeconds { get; set; } = 120;
    public bool Enabled { get; set; } = true;
}

public class LlamaCppOptions
{
    public string BaseUrl { get; set; } = "http://localhost:8080";
    public int TimeoutSeconds { get; set; } = 120;
    public bool Enabled { get; set; } = true;
}

public class SecurityOptions
{
    /// <summary>
    /// Development-only fallback for the master admin credential. In every other environment
    /// the key is read from the secret store (Gateway:Cloud:Secrets:AdminApiKeyName) and
    /// startup fails if this value is set to a default or left empty.
    /// </summary>
    public string AdminApiKey { get; set; } = string.Empty;

    public bool EnforceAppApiKey { get; set; } = true;
    public int RateLimitPerMinute { get; set; } = 120;

    /// <summary>Requests per minute allowed against credential-issuing endpoints.</summary>
    public int TokenRateLimitPerMinute { get; set; } = 10;

    /// <summary>Requests per minute allowed against the management plane.</summary>
    public int ManagementRateLimitPerMinute { get; set; } = 60;

    /// <summary>
    /// Cross-origin origins permitted to call the gateway. An empty list means no
    /// cross-origin access. "*" is rejected at startup outside Development.
    /// </summary>
    public string[] AllowedCorsOrigins { get; set; } = [];

    /// <summary>Default lifetime applied when a caller does not request one.</summary>
    public int DefaultStsTokenLifetimeSeconds { get; set; } = 900; // 15 minutes

    /// <summary>Hard ceiling on any requested STS lifetime.</summary>
    public int MaxStsTokenLifetimeSeconds { get; set; } = 3600; // 1 hour

    /// <summary>
    /// Ceiling on an admin STS token, which can only be minted from the break-glass credential.
    /// Shorter than an application token's: it is the highest privilege the gateway issues.
    /// </summary>
    public int MaxAdminStsTokenLifetimeSeconds { get; set; } = 900; // 15 minutes

    /// <summary>
    /// Emit HSTS, redirect browsers to HTTPS, and refuse API calls made over plain HTTP.
    /// Disable only for local development; StartupValidator refuses it anywhere else.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// Port browsers are redirected to. Null lets ASP.NET Core discover it from the server's
    /// bindings, which under IIS is the site's HTTPS binding.
    /// </summary>
    public int? HttpsPort { get; set; }

    /// <summary>Strict-Transport-Security max-age, in days.</summary>
    public int HstsMaxAgeDays { get; set; } = 365;

    /// <summary>Milliseconds any single guardrail pattern may run before it is treated as a violation.</summary>
    public int RegexTimeoutMs { get; set; } = 250;

    /// <summary>Abuse control: reject prompts longer than this many characters (0 = unlimited).</summary>
    public int MaxInputCharacters { get; set; } = 100_000;

    /// <summary>Abuse control: hard ceiling applied to any requested MaxTokens (0 = unlimited).</summary>
    public int MaxTokensCeiling { get; set; } = 8192;

    /// <summary>Abuse control: maximum accepted HTTP request body size in bytes (0 = server default).</summary>
    public long MaxRequestBodyBytes { get; set; } = 1_048_576; // 1 MB
}

public class StorageOptions
{
    public string DataDirectory { get; set; } = "./data";
    public string RegistryFileName { get; set; } = "app_registry.json";

    /// <summary>Append-only audit trail that survives restarts (JSON Lines, one file per UTC day).</summary>
    public bool AuditLogEnabled { get; set; } = true;

    /// <summary>Directory for audit files, relative to DataDirectory unless rooted.</summary>
    public string AuditDirectory { get; set; } = "audit";

    /// <summary>Audit files older than this many days are pruned at startup (0 = keep forever).</summary>
    public int AuditRetentionDays { get; set; } = 90;
}
