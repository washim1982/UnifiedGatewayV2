using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// Per-application invocation request payload (POST /gateway/{appId}/invoke)
/// </summary>
public record InvokeAppRequest
{
    [JsonPropertyName("input")]
    public string Input { get; init; } = string.Empty;

    [JsonPropertyName("sessionId")]
    public string? SessionId { get; init; }

    [JsonPropertyName("userId")]
    public string? UserId { get; init; }

    [JsonPropertyName("temperature")]
    public double? Temperature { get; init; }

    [JsonPropertyName("max_tokens")]
    public int? MaxTokens { get; init; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; init; }
}
