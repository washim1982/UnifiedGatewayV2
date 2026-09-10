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

    // --- Actor attribution -------------------------------------------------
    // Without these the trail answers "what was invoked" but not "by whom",
    // which is what a repudiation control actually needs.

    /// <summary>Key prefix or principal ARN the caller authenticated as.</summary>
    [JsonPropertyName("actor")]
    public string? Actor { get; init; }

    /// <summary>How the caller authenticated (AppApiKey, AppStsToken, GatewayAdminStsToken, ...).</summary>
    [JsonPropertyName("authType")]
    public string? AuthType { get; init; }

    /// <summary>jti of the STS token used, when one was presented.</summary>
    [JsonPropertyName("tokenId")]
    public string? TokenId { get; init; }

    /// <summary>Source IP as seen by the gateway.</summary>
    [JsonPropertyName("sourceIp")]
    public string? SourceIp { get; init; }

    /// <summary>Correlation id carried through the request.</summary>
    [JsonPropertyName("traceId")]
    public string? TraceId { get; init; }

    // --- Billing -----------------------------------------------------------
    // Cost is computed once, when the entry is written, and frozen here with the rates
    // that applied at that moment. Re-pricing an application therefore changes future
    // invoices only; it never rewrites a bill that has already been issued.

    /// <summary>Charge for the input tokens of this request.</summary>
    [JsonPropertyName("inputCost")]
    public decimal InputCost { get; init; }

    /// <summary>Charge for the output tokens of this request.</summary>
    [JsonPropertyName("outputCost")]
    public decimal OutputCost { get; init; }

    [JsonPropertyName("totalCost")]
    public decimal TotalCost => InputCost + OutputCost;

    /// <summary>Input rate applied, per million tokens.</summary>
    [JsonPropertyName("inputRatePerMillion")]
    public decimal InputRatePerMillion { get; init; }

    /// <summary>Output rate applied, per million tokens.</summary>
    [JsonPropertyName("outputRatePerMillion")]
    public decimal OutputRatePerMillion { get; init; }

    /// <summary>
    /// True when a fallback rate was used because the application had no rate card, or the
    /// request carried no application at all.
    /// </summary>
    [JsonPropertyName("isEstimatedCost")]
    public bool IsEstimatedCost { get; init; }
}

/// <summary>
/// A privileged management-plane action. Recorded to the same append-only trail as
/// invocations so create/update/delete/rotate/policy changes are not invisible to forensics.
/// </summary>
public record ManagementAuditEntry
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = "management";

    [JsonPropertyName("action")]
    public string Action { get; init; } = string.Empty;

    [JsonPropertyName("resource")]
    public string? Resource { get; init; }

    [JsonPropertyName("actor")]
    public string? Actor { get; init; }

    [JsonPropertyName("authType")]
    public string? AuthType { get; init; }

    [JsonPropertyName("sourceIp")]
    public string? SourceIp { get; init; }

    [JsonPropertyName("success")]
    public bool Success { get; init; }

    [JsonPropertyName("detail")]
    public string? Detail { get; init; }

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
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
