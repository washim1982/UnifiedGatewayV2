using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

public record GuardrailResult
{
    [JsonPropertyName("isSafe")]
    public bool IsSafe => Violations.Count == 0;

    [JsonPropertyName("isBlocked")]
    public bool IsBlocked { get; init; }

    [JsonPropertyName("actionTaken")]
    public string ActionTaken { get; init; } = "Passed"; // "Passed", "Redacted", "Blocked", "Audited"

    [JsonPropertyName("originalInput")]
    public string OriginalInput { get; init; } = string.Empty;

    [JsonPropertyName("sanitizedInput")]
    public string SanitizedInput { get; init; } = string.Empty;

    [JsonPropertyName("violations")]
    public List<GuardrailViolationDetail> Violations { get; init; } = [];

    [JsonPropertyName("riskScore")]
    public double RiskScore { get; init; }

    [JsonPropertyName("latencyMs")]
    public long LatencyMs { get; init; }
}

public record GuardrailViolationDetail
{
    [JsonPropertyName("category")]
    public string Category { get; init; } = string.Empty; // "PCI", "PII", "Secrets", "PromptInjection", "BedrockContentSafety"

    [JsonPropertyName("ruleName")]
    public string RuleName { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "Medium"; // "Low", "Medium", "High", "Critical"

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("detectedSnippet")]
    public string? DetectedSnippet { get; init; }

    [JsonPropertyName("startIndex")]
    public int StartIndex { get; init; }

    [JsonPropertyName("length")]
    public int Length { get; init; }
}

public record GuardrailTestRequest
{
    [JsonPropertyName("input")]
    public string Input { get; init; } = string.Empty;

    [JsonPropertyName("mode")]
    public GuardrailActionMode? Mode { get; init; }
}
