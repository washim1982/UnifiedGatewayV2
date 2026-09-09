using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public partial class GuardrailService : IGuardrailService
{
    private GuardrailOptions _options;
    private readonly ILogger<GuardrailService> _logger;
    private readonly object _optionsLock = new();

    public GuardrailService(
        IOptions<GatewayOptions> gatewayOptions,
        ILogger<GuardrailService> logger)
    {
        _options = gatewayOptions.Value.Guardrails ?? new GuardrailOptions();
        _logger = logger;
    }

    public GuardrailOptions GetCurrentOptions()
    {
        lock (_optionsLock)
        {
            return _options;
        }
    }

    public void UpdateOptions(GuardrailOptions options)
    {
        lock (_optionsLock)
        {
            _options = options;
            _logger.LogInformation("Guardrail configuration updated at runtime. Mode={Mode}, Enabled={Enabled}",
                options.Mode, options.Enabled);
        }
    }

    public Task<GuardrailResult> EvaluateAsync(
        string input,
        string? systemPrompt = null,
        GuardrailActionMode? modeOverride = null,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        GuardrailOptions current;
        lock (_optionsLock)
        {
            current = _options;
        }

        if (!current.Enabled || string.IsNullOrWhiteSpace(input))
        {
            sw.Stop();
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Passed",
                IsBlocked = false,
                OriginalInput = input,
                SanitizedInput = input,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        var activeMode = modeOverride ?? current.Mode;
        var violations = RunDetectors(input, current, scanPci: current.Pci.Enabled, scanPii: current.Pii.Enabled,
            scanSecrets: current.Secrets.Enabled, scanInjection: current.PromptInjection.Enabled);

        // Calculate risk score
        var riskScore = CalculateRiskScore(violations);
        sw.Stop();

        if (violations.Count == 0)
        {
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Passed",
                IsBlocked = false,
                OriginalInput = input,
                SanitizedInput = input,
                RiskScore = 0.0,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        _logger.LogWarning("Guardrails detected {Count} policy violations. ActiveMode={ActiveMode}, MaxSeverity={MaxSeverity}",
            violations.Count, activeMode, violations.Max(v => v.Severity));

        if (activeMode == GuardrailActionMode.Block)
        {
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Blocked",
                IsBlocked = true,
                OriginalInput = input,
                SanitizedInput = input,
                Violations = violations,
                RiskScore = riskScore,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        if (activeMode == GuardrailActionMode.AuditOnly)
        {
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Audited",
                IsBlocked = false,
                OriginalInput = input,
                SanitizedInput = input,
                Violations = violations,
                RiskScore = riskScore,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        // Default: Redact / Mask
        var sanitized = RedactSensitiveData(input, violations);

        return Task.FromResult(new GuardrailResult
        {
            ActionTaken = "Redacted",
            IsBlocked = false,
            OriginalInput = input,
            SanitizedInput = sanitized,
            Violations = violations,
            RiskScore = riskScore,
            LatencyMs = sw.ElapsedMilliseconds
        });
    }

    /// <summary>
    /// Egress guardrail. Scans model OUTPUT for leaked PCI / PII / secrets. Prompt-injection
    /// detectors are deliberately not applied here: they describe attacker input, not leakage.
    /// </summary>
    public Task<GuardrailResult> EvaluateOutputAsync(
        string output,
        GuardrailActionMode? modeOverride = null,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        GuardrailOptions current;
        lock (_optionsLock)
        {
            current = _options;
        }

        var outputOptions = current.OutputScanning ?? new OutputScanningOptions();

        if (!current.Enabled || !outputOptions.Enabled || string.IsNullOrWhiteSpace(output))
        {
            sw.Stop();
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Passed",
                IsBlocked = false,
                OriginalInput = output,
                SanitizedInput = output,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        var activeMode = modeOverride ?? outputOptions.Mode;
        var violations = RunDetectors(
            output,
            current,
            scanPci: outputOptions.ScanPci && current.Pci.Enabled,
            scanPii: outputOptions.ScanPii && current.Pii.Enabled,
            scanSecrets: outputOptions.ScanSecrets && current.Secrets.Enabled,
            scanInjection: false);

        var riskScore = CalculateRiskScore(violations);
        sw.Stop();

        if (violations.Count == 0)
        {
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Passed",
                IsBlocked = false,
                OriginalInput = output,
                SanitizedInput = output,
                RiskScore = 0.0,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        _logger.LogWarning("Egress guardrails detected {Count} sensitive-data leaks in model output. ActiveMode={ActiveMode}",
            violations.Count, activeMode);

        if (activeMode == GuardrailActionMode.Block)
        {
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Blocked",
                IsBlocked = true,
                OriginalInput = output,
                SanitizedInput = string.Empty,
                Violations = violations,
                RiskScore = riskScore,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        if (activeMode == GuardrailActionMode.AuditOnly)
        {
            return Task.FromResult(new GuardrailResult
            {
                ActionTaken = "Audited",
                IsBlocked = false,
                OriginalInput = output,
                SanitizedInput = output,
                Violations = violations,
                RiskScore = riskScore,
                LatencyMs = sw.ElapsedMilliseconds
            });
        }

        return Task.FromResult(new GuardrailResult
        {
            ActionTaken = "Redacted",
            IsBlocked = false,
            OriginalInput = output,
            SanitizedInput = RedactSensitiveData(output, violations),
            Violations = violations,
            RiskScore = riskScore,
            LatencyMs = sw.ElapsedMilliseconds
        });
    }

    /// <summary>Shared detector pipeline used by both the ingress and egress guardrails.</summary>
    /// <summary>
    /// Runs the configured detectors.
    ///
    /// Every pattern carries a match timeout so a crafted input cannot pin a CPU core inside
    /// the engine. A timeout is reported as a violation rather than swallowed: an input the
    /// scanner could not finish reading has not been shown to be clean, so the guardrail
    /// fails closed.
    /// </summary>
    private List<GuardrailViolationDetail> RunDetectors(
        string text,
        GuardrailOptions current,
        bool scanPci,
        bool scanPii,
        bool scanSecrets,
        bool scanInjection)
    {
        try
        {
            return RunDetectorsCore(text, current, scanPci, scanPii, scanSecrets, scanInjection);
        }
        catch (RegexMatchTimeoutException ex)
        {
            _logger.LogError(
                "Guardrail pattern '{Pattern}' timed out after {Timeout}. Treating the input as a violation.",
                ex.Pattern, ex.MatchTimeout);

            return
            [
                new GuardrailViolationDetail
                {
                    Category = "Availability",
                    RuleName = "ScanTimeout",
                    Description = "The content could not be scanned within the allotted time and was not cleared.",
                    Severity = "High"
                }
            ];
        }
    }

    private List<GuardrailViolationDetail> RunDetectorsCore(
        string text,
        GuardrailOptions current,
        bool scanPci,
        bool scanPii,
        bool scanSecrets,
        bool scanInjection)
    {
        var violations = new List<GuardrailViolationDetail>();

        // 1. PCI Detectors (Credit Cards, CVV, IBAN)
        if (scanPci)
        {
            if (current.Pci.MaskCreditCards) DetectCreditCards(text, violations);
            if (current.Pci.MaskIban) DetectIban(text, violations);
            if (current.Pci.MaskCvv) DetectCvv(text, violations);
        }

        // 2. PII Detectors (SSN, Emails, Phone, Passports)
        if (scanPii)
        {
            if (current.Pii.MaskSsn) DetectSsn(text, violations);
            if (current.Pii.MaskEmails) DetectEmails(text, violations);
            if (current.Pii.MaskPhoneNumbers) DetectPhoneNumbers(text, violations);
            if (current.Pii.MaskPassports) DetectPassports(text, violations);
        }

        // 3. Secrets & API Keys
        if (scanSecrets)
        {
            if (current.Secrets.MaskAwsKeys) DetectAwsKeys(text, violations);
            if (current.Secrets.MaskPrivateKeys) DetectPrivateKeys(text, violations);
            if (current.Secrets.MaskJwtTokens) DetectJwtTokens(text, violations);
            if (current.Secrets.MaskGenericApiKeys) DetectGenericApiKeys(text, violations);
        }

        // 4. Prompt Injection & Adversarial Jailbreaks (ingress only)
        if (scanInjection)
        {
            DetectPromptInjection(text, violations, current.PromptInjection);
        }

        return violations;
    }

    #region PCI Detection (with Luhn Algorithm Check)

    // Regex for potential credit card sequences (13 to 19 digits, with optional hyphens/spaces)
    [GeneratedRegex(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex CandidateCreditCardRegex();

    [GeneratedRegex(@"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex IbanRegex();

    [GeneratedRegex(@"(?i)\b(?:cvv|cvc|cvv2|cvc2|security code)[:\s]*([0-9]{3,4})\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex CvvRegex();

    private void DetectCreditCards(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = CandidateCreditCardRegex().Matches(input);
        foreach (Match match in matches)
        {
            var rawDigits = Regex.Replace(match.Value, @"[\s-]", "", RegexOptions.None, TimeSpan.FromMilliseconds(250));
            if (rawDigits.Length >= 13 && rawDigits.Length <= 19 && IsValidLuhn(rawDigits))
            {
                var cardType = IdentifyCardIssuer(rawDigits);
                violations.Add(new GuardrailViolationDetail
                {
                    Category = "PCI",
                    RuleName = $"CreditCard_{cardType}",
                    Severity = "Critical",
                    Description = $"Valid {cardType} payment card number detected and verified via Luhn checksum.",
                    DetectedSnippet = MaskDisplay(match.Value),
                    StartIndex = match.Index,
                    Length = match.Length
                });
            }
        }
    }

    private static bool IsValidLuhn(string digits)
    {
        if (string.IsNullOrWhiteSpace(digits) || !digits.All(char.IsDigit))
            return false;

        int sum = 0;
        bool alternate = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int n = digits[i] - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    private static string IdentifyCardIssuer(string digits)
    {
        if (digits.StartsWith('4')) return "Visa";
        if (digits.StartsWith("34") || digits.StartsWith("37")) return "Amex";
        if (digits.StartsWith("6011") || digits.StartsWith("65")) return "Discover";
        if (digits.StartsWith("35")) return "JCB";
        if (digits.StartsWith("51") || digits.StartsWith("52") || digits.StartsWith("53") || digits.StartsWith("54") || digits.StartsWith("55"))
            return "MasterCard";
        return "PaymentCard";
    }

    private void DetectIban(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = IbanRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "PCI",
                RuleName = "IBAN_BankAccount",
                Severity = "High",
                Description = "International Bank Account Number (IBAN) detected.",
                DetectedSnippet = MaskDisplay(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    private void DetectCvv(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = CvvRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "PCI",
                RuleName = "CVV_SecurityCode",
                Severity = "Critical",
                Description = "Card Verification Value (CVV/CVC) detected.",
                DetectedSnippet = "***",
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    #endregion

    #region PII Detection

    [GeneratedRegex(@"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex SsnRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex PhoneRegex();

    [GeneratedRegex(@"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex PassportRegex();

    private void DetectSsn(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = SsnRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "PII",
                RuleName = "US_SSN",
                Severity = "Critical",
                Description = "US Social Security Number detected.",
                DetectedSnippet = MaskDisplay(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    private void DetectEmails(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = EmailRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "PII",
                RuleName = "EmailAddress",
                Severity = "Medium",
                Description = "Personal or corporate email address detected.",
                DetectedSnippet = MaskEmail(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    private void DetectPhoneNumbers(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = PhoneRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "PII",
                RuleName = "PhoneNumber",
                Severity = "Medium",
                Description = "Phone number detected.",
                DetectedSnippet = MaskDisplay(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    private void DetectPassports(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = PassportRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "PII",
                RuleName = "PassportNumber",
                Severity = "High",
                Description = "Passport document number detected.",
                DetectedSnippet = MaskDisplay(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    #endregion

    #region Secrets & API Keys Detection

    [GeneratedRegex(@"\b(AKIA[0-9A-Z]{16})\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex AwsAccessKeyRegex();

    [GeneratedRegex(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex PrivateKeyRegex();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex JwtTokenRegex();

    [GeneratedRegex(@"\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-_]{20,}|ug_live_[a-f0-9]{64}|sk-[a-zA-Z0-9]{32,})\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex GenericApiKeyRegex();

    private void DetectAwsKeys(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = AwsAccessKeyRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "Secrets",
                RuleName = "AWS_AccessKeyId",
                Severity = "Critical",
                Description = "AWS IAM Access Key ID detected.",
                DetectedSnippet = MaskDisplay(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    private void DetectPrivateKeys(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = PrivateKeyRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "Secrets",
                RuleName = "AsymmetricPrivateKey",
                Severity = "Critical",
                Description = "RSA/EC/OpenSSH Asymmetric Private Key block detected.",
                DetectedSnippet = "-----BEGIN PRIVATE KEY...-----",
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    private void DetectJwtTokens(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = JwtTokenRegex().Matches(input);
        foreach (Match match in matches)
        {
            // Only flag if token looks like a real multi-segment JWT
            if (match.Value.Count(c => c == '.') >= 2)
            {
                violations.Add(new GuardrailViolationDetail
                {
                    Category = "Secrets",
                    RuleName = "JsonWebToken_JWT",
                    Severity = "High",
                    Description = "JSON Web Token (JWT) credentials detected.",
                    DetectedSnippet = MaskDisplay(match.Value),
                    StartIndex = match.Index,
                    Length = match.Length
                });
            }
        }
    }

    private void DetectGenericApiKeys(string input, List<GuardrailViolationDetail> violations)
    {
        var matches = GenericApiKeyRegex().Matches(input);
        foreach (Match match in matches)
        {
            violations.Add(new GuardrailViolationDetail
            {
                Category = "Secrets",
                RuleName = "ApiKeyToken",
                Severity = "Critical",
                Description = "High-entropy API Key / Personal Access Token detected.",
                DetectedSnippet = MaskDisplay(match.Value),
                StartIndex = match.Index,
                Length = match.Length
            });
        }
    }

    #endregion

    #region Prompt Injection & Jailbreak Detection

    [GeneratedRegex(@"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules|commands)\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex SystemOverrideRegex();

    [GeneratedRegex(@"(?i)\b(?:you\s+are\s+now|switch\s+to|act\s+as)\s+(?:DAN|jailbroken|unrestricted|god\s+mode|developer\s+mode|an\s+unfiltered\s+ai)\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex JailbreakDanRegex();

    [GeneratedRegex(@"(?i)\b(?:bypass|disable|turn\s+off)\s+(?:all\s+)?(?:safety|content\s+filter|guardrails?|policy)\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 250)]
    private static partial Regex BypassSafetyRegex();

    private void DetectPromptInjection(string input, List<GuardrailViolationDetail> violations, PromptInjectionOptions options)
    {
        if (options.BlockSystemOverrides)
        {
            var match1 = SystemOverrideRegex().Match(input);
            if (match1.Success)
            {
                violations.Add(new GuardrailViolationDetail
                {
                    Category = "PromptInjection",
                    RuleName = "SystemPromptOverride",
                    Severity = "High",
                    Description = "Attempt to override or ignore system instructions detected.",
                    DetectedSnippet = match1.Value,
                    StartIndex = match1.Index,
                    Length = match1.Length
                });
            }

            var matchBypass = BypassSafetyRegex().Match(input);
            if (matchBypass.Success)
            {
                violations.Add(new GuardrailViolationDetail
                {
                    Category = "PromptInjection",
                    RuleName = "SafetyBypassAttempt",
                    Severity = "High",
                    Description = "Attempt to disable safety policies or guardrails detected.",
                    DetectedSnippet = matchBypass.Value,
                    StartIndex = matchBypass.Index,
                    Length = matchBypass.Length
                });
            }
        }

        if (options.BlockJailbreaks)
        {
            var match2 = JailbreakDanRegex().Match(input);
            if (match2.Success)
            {
                violations.Add(new GuardrailViolationDetail
                {
                    Category = "PromptInjection",
                    RuleName = "Jailbreak_DAN",
                    Severity = "Critical",
                    Description = "Adversarial jailbreak pattern (DAN / Developer Mode) detected.",
                    DetectedSnippet = match2.Value,
                    StartIndex = match2.Index,
                    Length = match2.Length
                });
            }
        }
    }

    #endregion

    #region Sanitization / Redaction Helpers

    private static string RedactSensitiveData(string original, List<GuardrailViolationDetail> violations)
    {
        if (violations.Count == 0) return original;

        // Sort violations in reverse order of StartIndex to replace cleanly without offsetting indices
        var sorted = violations
            .Where(v => v.StartIndex >= 0 && v.Length > 0 && v.StartIndex + v.Length <= original.Length)
            .OrderByDescending(v => v.StartIndex)
            .ToList();

        var sb = new System.Text.StringBuilder(original);

        foreach (var v in sorted)
        {
            var replacement = v.Category switch
            {
                "PCI" => v.RuleName.Contains("CreditCard") ? "[REDACTED_CREDIT_CARD]" :
                         v.RuleName.Contains("IBAN") ? "[REDACTED_IBAN]" : "[REDACTED_CVV]",
                "PII" => v.RuleName.Contains("SSN") ? "[REDACTED_SSN]" :
                         v.RuleName.Contains("Email") ? "[REDACTED_EMAIL]" :
                         v.RuleName.Contains("Phone") ? "[REDACTED_PHONE]" : "[REDACTED_PASSPORT]",
                "Secrets" => v.RuleName.Contains("AWS") ? "[REDACTED_AWS_KEY]" :
                             v.RuleName.Contains("Private") ? "[REDACTED_PRIVATE_KEY]" :
                             v.RuleName.Contains("JWT") ? "[REDACTED_JWT]" : "[REDACTED_API_KEY]",
                "PromptInjection" => "[REDACTED_INJECTION_ATTEMPT]",
                _ => "[REDACTED_SENSITIVE_DATA]"
            };

            sb.Remove(v.StartIndex, v.Length);
            sb.Insert(v.StartIndex, replacement);
        }

        return sb.ToString();
    }

    private static double CalculateRiskScore(List<GuardrailViolationDetail> violations)
    {
        if (violations.Count == 0) return 0.0;
        double score = 0.0;
        foreach (var v in violations)
        {
            score += v.Severity switch
            {
                "Critical" => 0.4,
                "High" => 0.25,
                "Medium" => 0.15,
                _ => 0.05
            };
        }
        return Math.Min(1.0, Math.Round(score, 2));
    }

    private static string MaskDisplay(string value)
    {
        if (value.Length <= 6) return "******";
        return $"{value[..2]}******{value[^2..]}";
    }

    private static string MaskEmail(string email)
    {
        var parts = email.Split('@');
        if (parts.Length != 2) return "******@***.com";
        var name = parts[0];
        var domain = parts[1];
        var maskedName = name.Length > 2 ? $"{name[..1]}***{name[^1..]}" : "***";
        return $"{maskedName}@{domain}";
    }

    #endregion
}
