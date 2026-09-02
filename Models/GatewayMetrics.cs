using System.Collections.Concurrent;
using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

public record RequestLogEntry
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("appId")]
    public string? AppId { get; init; }

    [JsonPropertyName("model")]
    public string Model { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty;

    [JsonPropertyName("latencyMs")]
    public long LatencyMs { get; init; }

    [JsonPropertyName("inputTokens")]
    public int InputTokens { get; init; }

    [JsonPropertyName("outputTokens")]
    public int OutputTokens { get; init; }

    [JsonPropertyName("totalTokens")]
    public int TotalTokens => InputTokens + OutputTokens;

    [JsonPropertyName("success")]
    public bool Success { get; init; }

    [JsonPropertyName("fallbackUsed")]
    public bool FallbackUsed { get; init; }

    [JsonPropertyName("guardrailAction")]
    public string GuardrailAction { get; init; } = "None"; // "Passed", "Redacted", "Blocked", "Audited"

    [JsonPropertyName("guardrailViolations")]
    public List<string> GuardrailViolations { get; init; } = [];

    /// <summary>Egress guardrail outcome for the model response: "None", "Passed", "Redacted", "Blocked", "Audited".</summary>
    [JsonPropertyName("outputGuardrailAction")]
    public string OutputGuardrailAction { get; init; } = "None";

    [JsonPropertyName("outputGuardrailViolations")]
    public List<string> OutputGuardrailViolations { get; init; } = [];

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; init; }
}

public class GatewayMetricsSummary
{
    [JsonPropertyName("totalRequests")]
    public long TotalRequests { get; set; }

    [JsonPropertyName("successfulRequests")]
    public long SuccessfulRequests { get; set; }

    [JsonPropertyName("failedRequests")]
    public long FailedRequests { get; set; }

    [JsonPropertyName("fallbackCount")]
    public long FallbackCount { get; set; }

    [JsonPropertyName("guardrailEvaluatedCount")]
    public long GuardrailEvaluatedCount { get; set; }

    [JsonPropertyName("guardrailRedactedCount")]
    public long GuardrailRedactedCount { get; set; }

    [JsonPropertyName("guardrailBlockedCount")]
    public long GuardrailBlockedCount { get; set; }

    [JsonPropertyName("outputGuardrailRedactedCount")]
    public long OutputGuardrailRedactedCount { get; set; }

    [JsonPropertyName("outputGuardrailBlockedCount")]
    public long OutputGuardrailBlockedCount { get; set; }

    [JsonPropertyName("totalTokens")]
    public long TotalTokens { get; set; }

    [JsonPropertyName("avgLatencyMs")]
    public double AvgLatencyMs { get; set; }

    [JsonPropertyName("bedrockRequests")]
    public long BedrockRequests { get; set; }

    [JsonPropertyName("localRequests")]
    public long LocalRequests { get; set; }

    [JsonPropertyName("recentLogs")]
    public List<RequestLogEntry> RecentLogs { get; set; } = [];

    [JsonPropertyName("appStats")]
    public Dictionary<string, AppMetricStats> AppStats { get; set; } = [];
}

public class AppMetricStats
{
    [JsonPropertyName("appId")]
    public string AppId { get; set; } = string.Empty;

    [JsonPropertyName("requestCount")]
    public long RequestCount { get; set; }

    [JsonPropertyName("tokenCount")]
    public long TokenCount { get; set; }

    [JsonPropertyName("avgLatencyMs")]
    public double AvgLatencyMs { get; set; }

    [JsonPropertyName("errorCount")]
    public long ErrorCount { get; set; }

    [JsonPropertyName("guardrailBlockedCount")]
    public long GuardrailBlockedCount { get; set; }
}
