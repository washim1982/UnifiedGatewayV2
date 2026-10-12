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

    /// <summary>
    /// Skills whose full instructions should be loaded for this call, by skill id. Skills attached
    /// to the application are always announced to the model by name and description; naming one
    /// here adds its body. A skill that is not attached is ignored -- asking cannot grant.
    /// </summary>
    [JsonPropertyName("skills")]
    public List<string>? Skills { get; init; }
}
