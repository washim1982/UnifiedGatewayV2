using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// Universal normalized response schema returned by the Unified LLM Gateway.
/// </summary>
public record UniversalResponse
{
    [JsonPropertyName("output")]
    public string Output { get; init; } = string.Empty;

    [JsonPropertyName("model")]
    public string Model { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty; // "bedrock" | "local"

    [JsonPropertyName("latency_ms")]
    public long LatencyMs { get; init; }

    [JsonPropertyName("tokens")]
    public TokenUsage Tokens { get; init; } = new();

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("fallback_used")]
    public bool FallbackUsed { get; init; }

    [JsonPropertyName("app_id")]
    public string? AppId { get; init; }

    [JsonPropertyName("session_id")]
    public string? SessionId { get; init; }

    [JsonPropertyName("error")]
    public GatewayError? Error { get; init; }

    /// <summary>Tools the model asked to call. Empty when it answered instead.</summary>
    [JsonPropertyName("tool_calls")]
    public List<ToolInvocation> ToolCalls { get; init; } = [];

    /// <summary>Provider stop reason, where one is reported ("tool_use", "end_turn", ...).</summary>
    [JsonPropertyName("stop_reason")]
    public string? StopReason { get; init; }

    /// <summary>How many tool rounds the gateway ran before this answer.</summary>
    [JsonPropertyName("tool_steps")]
    public int ToolSteps { get; init; }
}

public record TokenUsage
{
    [JsonPropertyName("input")]
    public int Input { get; init; }

    [JsonPropertyName("output")]
    public int Output { get; init; }

    [JsonPropertyName("total")]
    public int Total => Input + Output;
}

public record GatewayError
{
    [JsonPropertyName("code")]
    public string Code { get; init; } = "UNKNOWN_ERROR";

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("details")]
    public string? Details { get; init; }
}
