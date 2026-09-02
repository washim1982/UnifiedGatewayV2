using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

public enum GuardrailActionMode
{
    Redact = 0,    // Anonymize sensitive data inline before passing to LLM
    Block = 1,     // Reject request immediately with 422/400 policy violation
    AuditOnly = 2  // Log violation in telemetry without altering the prompt
}

public class GuardrailOptions
{
    public const string SectionName = "Guardrails";

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("mode")]
    public GuardrailActionMode Mode { get; set; } = GuardrailActionMode.Redact;

    [JsonPropertyName("pci")]
    public PciGuardrailOptions Pci { get; set; } = new();

    [JsonPropertyName("pii")]
    public PiiGuardrailOptions Pii { get; set; } = new();

    [JsonPropertyName("secrets")]
    public SecretsGuardrailOptions Secrets { get; set; } = new();

    [JsonPropertyName("promptInjection")]
    public PromptInjectionOptions PromptInjection { get; set; } = new();

    [JsonPropertyName("bedrockGuardrails")]
    public BedrockNativeGuardrailOptions BedrockGuardrails { get; set; } = new();

    [JsonPropertyName("outputScanning")]
    public OutputScanningOptions OutputScanning { get; set; } = new();
}

/// <summary>
/// Egress (response) guardrails. Model output is inspected for leaked PCI / PII / secrets
/// before it is returned to the caller. Prompt-injection detectors are not applied to output.
/// </summary>
public class OutputScanningOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>Redact (default) sanitizes the response; Block suppresses it; AuditOnly records only.</summary>
    [JsonPropertyName("mode")]
    public GuardrailActionMode Mode { get; set; } = GuardrailActionMode.Redact;

    [JsonPropertyName("scanPci")]
    public bool ScanPci { get; set; } = true;

    [JsonPropertyName("scanPii")]
    public bool ScanPii { get; set; } = true;

    [JsonPropertyName("scanSecrets")]
    public bool ScanSecrets { get; set; } = true;
}

public class PciGuardrailOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("maskCreditCards")]
    public bool MaskCreditCards { get; set; } = true;

    [JsonPropertyName("maskIban")]
    public bool MaskIban { get; set; } = true;

    [JsonPropertyName("maskCvv")]
    public bool MaskCvv { get; set; } = true;
}

public class PiiGuardrailOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("maskSsn")]
    public bool MaskSsn { get; set; } = true;

    [JsonPropertyName("maskEmails")]
    public bool MaskEmails { get; set; } = true;

    [JsonPropertyName("maskPhoneNumbers")]
    public bool MaskPhoneNumbers { get; set; } = true;

    [JsonPropertyName("maskPassports")]
    public bool MaskPassports { get; set; } = true;
}

public class SecretsGuardrailOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("maskAwsKeys")]
    public bool MaskAwsKeys { get; set; } = true;

    [JsonPropertyName("maskPrivateKeys")]
    public bool MaskPrivateKeys { get; set; } = true;

    [JsonPropertyName("maskJwtTokens")]
    public bool MaskJwtTokens { get; set; } = true;

    [JsonPropertyName("maskGenericApiKeys")]
    public bool MaskGenericApiKeys { get; set; } = true;
}

public class PromptInjectionOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("blockJailbreaks")]
    public bool BlockJailbreaks { get; set; } = true;

    [JsonPropertyName("blockSystemOverrides")]
    public bool BlockSystemOverrides { get; set; } = true;
}

public class BedrockNativeGuardrailOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = false;

    [JsonPropertyName("guardrailIdentifier")]
    public string GuardrailIdentifier { get; set; } = string.Empty;

    [JsonPropertyName("guardrailVersion")]
    public string GuardrailVersion { get; set; } = "DRAFT";
}
