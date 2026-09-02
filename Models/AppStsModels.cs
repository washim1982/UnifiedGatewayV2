using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// Request payload to exchange a long-term Application API Key or Master Admin Key for a short-term STS token.
/// </summary>
public record AppStsTokenRequest
{
    [JsonPropertyName("appId")]
    public string? AppId { get; init; }

    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; init; }

    [JsonPropertyName("durationSeconds")]
    public int DurationSeconds { get; init; } = 3600; // Default: 1 hour (min 60s, max 86400s)

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = "invoke"; // "invoke", "admin", etc.

    [JsonPropertyName("callerId")]
    public string? CallerId { get; init; }
}

/// <summary>
/// Response payload returning the newly minted Short Temporary Secret (STS) token.
/// </summary>
public record AppStsTokenResponse
{
    [JsonPropertyName("token")]
    public string Token { get; init; } = string.Empty;

    [JsonPropertyName("tokenType")]
    public string TokenType { get; init; } = "Bearer";

    [JsonPropertyName("appId")]
    public string AppId { get; init; } = string.Empty;

    [JsonPropertyName("durationSeconds")]
    public int DurationSeconds { get; init; }

    [JsonPropertyName("issuedAt")]
    public DateTimeOffset IssuedAt { get; init; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; init; }

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = "invoke";

    [JsonPropertyName("isAdmin")]
    public bool IsAdmin { get; init; }
}

/// <summary>
/// Decoded claims payload encapsulated inside the cryptographically signed STS token.
/// </summary>
public record AppStsTokenPayload
{
    [JsonPropertyName("jti")]
    public string Jti { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("appId")]
    public string AppId { get; init; } = string.Empty;

    [JsonPropertyName("issuedAt")]
    public long IssuedAtUnix { get; init; }

    [JsonPropertyName("expiresAt")]
    public long ExpiresAtUnix { get; init; }

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = "invoke";

    [JsonPropertyName("isAdmin")]
    public bool IsAdmin { get; init; }

    [JsonPropertyName("callerId")]
    public string? CallerId { get; init; }
}

/// <summary>
/// Detailed inspection response for an STS token.
/// </summary>
public record AppStsInspectResponse
{
    [JsonPropertyName("isValid")]
    public bool IsValid { get; init; }

    [JsonPropertyName("appId")]
    public string? AppId { get; init; }

    [JsonPropertyName("isAdmin")]
    public bool IsAdmin { get; init; }

    [JsonPropertyName("issuedAt")]
    public DateTimeOffset? IssuedAt { get; init; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; init; }

    [JsonPropertyName("expiresInSeconds")]
    public double? ExpiresInSeconds { get; init; }

    [JsonPropertyName("isExpired")]
    public bool IsExpired { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("callerId")]
    public string? CallerId { get; init; }

    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
