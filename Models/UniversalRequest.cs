using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// Universal normalized request schema accepted by the Unified LLM Gateway.
/// </summary>
public record UniversalRequest
{
    [JsonPropertyName("model")]
    public string Model { get; init; } = string.Empty;

    [JsonPropertyName("input")]
    public string Input { get; init; } = string.Empty;

    [JsonPropertyName("system")]
    public string? System { get; init; }

    [JsonPropertyName("temperature")]
    public double Temperature { get; init; } = 0.7;

    [JsonPropertyName("max_tokens")]
    public int MaxTokens { get; init; } = 2048;

    [JsonPropertyName("provider")]
    public string? Provider { get; init; } // "bedrock", "local", or auto

    [JsonPropertyName("metadata")]
    public RequestMetadata? Metadata { get; init; }
}

public record RequestMetadata
{
    [JsonPropertyName("appId")]
    public string? AppId { get; init; }

    [JsonPropertyName("userId")]
    public string? UserId { get; init; }

    [JsonPropertyName("sessionId")]
    public string? SessionId { get; init; }

    [JsonPropertyName("clientIp")]
    public string? ClientIp { get; init; }

    [JsonPropertyName("traceId")]
    public string? TraceId { get; init; }

    [JsonExtensionData]
    public Dictionary<string, object>? Extra { get; init; }
}
