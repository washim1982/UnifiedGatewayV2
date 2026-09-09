namespace UnifiedGateway.Services.Cloud;

/// <summary>
/// Reads secret material (admin credential, token signing key) from the environment's secret store.
/// Simulator: KMS service /secrets. AWS: Secrets Manager.
/// </summary>
public interface ISecretsProvider
{
    /// <summary>Returns the secret value, or null when the secret does not exist.</summary>
    Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Writes (or overwrites) a secret. Used by bootstrap and rotation.</summary>
    Task PutSecretAsync(string name, string value, CancellationToken cancellationToken = default);

    /// <summary>Drops any cached copy so the next read goes to the store.</summary>
    void Invalidate(string name);
}

/// <summary>
/// Envelope encryption for gateway material at rest.
/// Simulator: KMS service /encrypt and /decrypt. AWS: KMS Encrypt/Decrypt.
/// </summary>
public interface ICryptoProvider
{
    Task<string> EncryptAsync(string plaintext, CancellationToken cancellationToken = default);
    Task<string> DecryptAsync(string ciphertext, CancellationToken cancellationToken = default);

    /// <summary>Liveness probe used by the health endpoint and startup validation.</summary>
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);
}

/// <summary>The outcome of an IAM policy evaluation for one management-plane operation.</summary>
public record AccessDecision
{
    public bool IsAllowed { get; init; }
    public string Reason { get; init; } = string.Empty;
    public string Action { get; init; } = string.Empty;
    public string Resource { get; init; } = string.Empty;
    public string Principal { get; init; } = string.Empty;
}

/// <summary>
/// Authorizes a principal for an action on a resource.
/// Simulator: IAM service /evaluate-policy. AWS: IAM policy evaluation.
/// </summary>
public interface IAccessControlProvider
{
    Task<AccessDecision> EvaluateAsync(
        string principalArn,
        string action,
        string resource,
        IDictionary<string, string>? context = null,
        CancellationToken cancellationToken = default);
}

/// <summary>Identity resolved from a presented credential on the management plane.</summary>
public record ResolvedIdentity
{
    public bool IsAuthenticated { get; init; }
    public string PrincipalArn { get; init; } = string.Empty;
    public string AuthType { get; init; } = string.Empty;
    public string? FailureReason { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
}

/// <summary>
/// Validates a session credential presented to the management plane.
/// Simulator: IAM service STS sessions. AWS: STS GetCallerIdentity on the presented session.
/// </summary>
public interface IIdentityProvider
{
    Task<ResolvedIdentity> ResolveAsync(string credential, CancellationToken cancellationToken = default);
}
