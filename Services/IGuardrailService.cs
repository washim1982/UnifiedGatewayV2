using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface IGuardrailService
{
    Task<GuardrailResult> EvaluateAsync(
        string input,
        string? systemPrompt = null,
        GuardrailActionMode? modeOverride = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Egress guardrail: inspects MODEL OUTPUT for leaked PCI / PII / secrets before it is
    /// returned to the caller. Prompt-injection detectors are not applied to output.
    /// On the returned result, OriginalInput/SanitizedInput carry the original/sanitized output.
    /// </summary>
    Task<GuardrailResult> EvaluateOutputAsync(
        string output,
        GuardrailActionMode? modeOverride = null,
        CancellationToken cancellationToken = default);

    GuardrailOptions GetCurrentOptions();
    void UpdateOptions(GuardrailOptions options);
}
