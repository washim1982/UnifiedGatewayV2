using System.Diagnostics;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public class ModelRouter : IModelRouter
{
    private readonly IBedrockService _bedrockService;
    private readonly ILocalModelService _localModelService;
    private readonly IApplicationRegistryService _registryService;
    private readonly IGuardrailService _guardrailService;
    private readonly GatewayOptions _options;
    private readonly ILogger<ModelRouter> _logger;

    public ModelRouter(
        IBedrockService bedrockService,
        ILocalModelService localModelService,
        IApplicationRegistryService registryService,
        IGuardrailService guardrailService,
        IOptions<GatewayOptions> options,
        ILogger<ModelRouter> logger)
    {
        _bedrockService = bedrockService;
        _localModelService = localModelService;
        _registryService = registryService;
        _guardrailService = guardrailService;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<UniversalResponse> RouteAppRequestAsync(
        string appId,
        InvokeAppRequest request,
        CallerContext? caller = null,
        CancellationToken cancellationToken = default)
    {
        var app = await _registryService.GetAppAsync(appId, cancellationToken);
        if (app == null)
        {
            return new UniversalResponse
            {
                Output = string.Empty,
                AppId = appId,
                Error = new GatewayError
                {
                    Code = "APP_NOT_FOUND",
                    Message = $"Application '{appId}' is not registered."
                }
            };
        }

        if (!app.IsActive)
        {
            return new UniversalResponse
            {
                Output = string.Empty,
                AppId = appId,
                Error = new GatewayError
                {
                    Code = "APP_INACTIVE",
                    Message = $"Application '{appId}' is currently deactivated."
                }
            };
        }

        var universalReq = new UniversalRequest
        {
            Model = app.Model,
            Provider = app.Provider,
            Input = request.Input,
            System = app.SystemPrompt,
            Temperature = request.Temperature ?? app.Temperature,
            MaxTokens = request.MaxTokens ?? app.MaxTokens,
            Metadata = new RequestMetadata
            {
                AppId = app.AppId,
                UserId = request.UserId,
                SessionId = request.SessionId,
                Extra = request.Metadata
            }
        };

        return await RouteWithFallbackAsync(
            universalReq, app.FallbackProvider, app.FallbackModel, caller, cancellationToken);
    }

    public async Task<UniversalResponse> RouteAsync(
        UniversalRequest request,
        CallerContext? caller = null,
        CancellationToken cancellationToken = default)
    {
        return await RouteWithFallbackAsync(request, null, null, caller, cancellationToken);
    }

    private async Task<UniversalResponse> RouteWithFallbackAsync(
        UniversalRequest request,
        string? fallbackProvider,
        string? fallbackModel,
        CallerContext? caller,
        CancellationToken cancellationToken)
    {
        var overallStopwatch = Stopwatch.StartNew();

        // 0. Abuse controls: reject oversized prompts and clamp runaway token requests.
        var maxChars = _options.Security.MaxInputCharacters;
        if (maxChars > 0 && request.Input.Length > maxChars)
        {
            overallStopwatch.Stop();
            _logger.LogWarning("Rejected oversized prompt for AppId {AppId}: {Length} chars exceeds limit {Limit}.",
                request.Metadata?.AppId ?? "direct", request.Input.Length, maxChars);

            var tooLarge = new UniversalResponse
            {
                Output = string.Empty,
                Model = request.Model,
                Provider = request.Provider ?? "gateway",
                LatencyMs = overallStopwatch.ElapsedMilliseconds,
                AppId = request.Metadata?.AppId,
                SessionId = request.Metadata?.SessionId,
                Error = new GatewayError
                {
                    Code = "INPUT_TOO_LARGE",
                    Message = $"Prompt exceeds the maximum allowed size of {maxChars} characters.",
                    Details = $"Received {request.Input.Length} characters."
                }
            };

            await RecordTelemetryAsync(request, tooLarge, false, PassthroughGuardrail(request.Input), caller);
            return tooLarge;
        }

        var tokenCeiling = _options.Security.MaxTokensCeiling;
        if (tokenCeiling > 0 && request.MaxTokens > tokenCeiling)
        {
            _logger.LogInformation("Clamping requested MaxTokens {Requested} to ceiling {Ceiling} for AppId {AppId}.",
                request.MaxTokens, tokenCeiling, request.Metadata?.AppId ?? "direct");
            request = request with { MaxTokens = tokenCeiling };
        }

        // 1. Enterprise Guardrail Inspection before hitting any backend
        var guardrailResult = await _guardrailService.EvaluateAsync(
            request.Input,
            request.System,
            cancellationToken: cancellationToken);

        if (guardrailResult.IsBlocked)
        {
            overallStopwatch.Stop();
            _logger.LogWarning("Request blocked by enterprise guardrails for AppId: {AppId}. Violations: {Violations}",
                request.Metadata?.AppId ?? "direct",
                string.Join("; ", guardrailResult.Violations.Select(v => v.RuleName)));

            var blockedRes = new UniversalResponse
            {
                Output = string.Empty,
                Model = request.Model,
                Provider = request.Provider ?? "guardrail",
                LatencyMs = overallStopwatch.ElapsedMilliseconds,
                AppId = request.Metadata?.AppId,
                SessionId = request.Metadata?.SessionId,
                Error = new GatewayError
                {
                    Code = "GUARDRAIL_BLOCKED",
                    Message = "Request blocked by enterprise security guardrail policy.",
                    Details = string.Join("; ", guardrailResult.Violations.Select(v => $"{v.Category} ({v.RuleName}): {v.Description}"))
                }
            };

            await RecordTelemetryAsync(request, blockedRes, false, guardrailResult, caller);
            return blockedRes;
        }

        // Apply sanitized/redacted input if redaction occurred
        var sanitizedReq = request;
        if (guardrailResult.ActionTaken == "Redacted")
        {
            _logger.LogInformation("Guardrails redacted sensitive data in input before routing to {Model}", request.Model);
            sanitizedReq = request with { Input = guardrailResult.SanitizedInput };
        }

        var primaryProvider = ResolveProvider(sanitizedReq);
        var primaryModel = sanitizedReq.Model;

        _logger.LogInformation("Routing request. Primary Provider: {Provider}, Primary Model: {Model}, AppId: {AppId}",
            primaryProvider, primaryModel, sanitizedReq.Metadata?.AppId ?? "direct");

        UniversalResponse response;

        try
        {
            response = await DispatchToProviderAsync(primaryProvider, sanitizedReq, cancellationToken);
        }
        catch (Exception ex)
        {
            // The exception text can name internal hosts, ARNs and provider internals, so
            // it is logged against the correlation id and the caller is given the id only.
            var reference = caller?.TraceId ?? Guid.NewGuid().ToString("N");
            _logger.LogWarning(ex,
                "Primary provider '{Provider}' failed for model '{Model}'. Reference {Reference}.",
                primaryProvider, primaryModel, reference);

            response = new UniversalResponse
            {
                Output = string.Empty,
                Model = primaryModel,
                Provider = primaryProvider,
                Error = new GatewayError
                {
                    Code = "PRIMARY_PROVIDER_FAILED",
                    Message = "The model provider could not be reached.",
                    Details = $"Reference: {reference}"
                }
            };
        }

        // If primary succeeded, apply egress guardrails, record and return
        if (response.Error == null && !string.IsNullOrEmpty(response.Output))
        {
            overallStopwatch.Stop();
            var (finalRes, outputScan) = await ApplyOutputGuardrailsAsync(
                response with { LatencyMs = overallStopwatch.ElapsedMilliseconds }, cancellationToken);
            await RecordTelemetryAsync(sanitizedReq, finalRes, false, guardrailResult, caller, outputScan);
            return finalRes;
        }

        // Check if fallback is configured
        if (!string.IsNullOrWhiteSpace(fallbackProvider) || !string.IsNullOrWhiteSpace(fallbackModel))
        {
            var targetFallbackProvider = !string.IsNullOrWhiteSpace(fallbackProvider)
                ? fallbackProvider.ToLowerInvariant()
                : (primaryProvider == "bedrock" ? "local" : "bedrock");

            var targetFallbackModel = !string.IsNullOrWhiteSpace(fallbackModel)
                ? fallbackModel
                : (targetFallbackProvider == "local" ? "ollama/llama3" : "anthropic.claude-3-haiku-20240307-v1:0");

            _logger.LogWarning("Triggering automatic fallback. Primary failed ({ErrorCode}). Attempting Fallback Provider: {FallbackProvider}, Fallback Model: {FallbackModel}",
                response.Error?.Code ?? "NO_OUTPUT", targetFallbackProvider, targetFallbackModel);

            var fallbackReq = sanitizedReq with
            {
                Provider = targetFallbackProvider,
                Model = targetFallbackModel
            };

            try
            {
                var fallbackResponse = await DispatchToProviderAsync(targetFallbackProvider, fallbackReq, cancellationToken);
                overallStopwatch.Stop();

                if (fallbackResponse.Error == null)
                {
                    var (finalFallback, fallbackScan) = await ApplyOutputGuardrailsAsync(
                        fallbackResponse with
                        {
                            FallbackUsed = true,
                            LatencyMs = overallStopwatch.ElapsedMilliseconds
                        },
                        cancellationToken);

                    await RecordTelemetryAsync(sanitizedReq, finalFallback, true, guardrailResult, caller, fallbackScan);
                    return finalFallback;
                }

                _logger.LogError(
                    "Both providers failed. Primary: {Primary}. Fallback: {Fallback}. Reference {Reference}.",
                    response.Error?.Message, fallbackResponse.Error?.Message,
                    caller?.TraceId ?? "unavailable");
                overallStopwatch.Stop();
                var dualFailure = response with
                {
                    LatencyMs = overallStopwatch.ElapsedMilliseconds,
                    Error = new GatewayError
                    {
                        Code = "ALL_PROVIDERS_FAILED",
                        Message = "Both the primary and fallback model providers failed.",
                        Details = $"Reference: {caller?.TraceId ?? "unavailable"}"
                    }
                };
                await RecordTelemetryAsync(sanitizedReq, dualFailure, false, guardrailResult, caller);
                return dualFailure;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Fallback provider execution failed with unexpected exception.");
            }
        }

        overallStopwatch.Stop();
        var failureRes = response with { LatencyMs = overallStopwatch.ElapsedMilliseconds };
        await RecordTelemetryAsync(sanitizedReq, failureRes, false, guardrailResult, caller);
        return failureRes;
    }

    private async Task<UniversalResponse> DispatchToProviderAsync(
        string provider,
        UniversalRequest request,
        CancellationToken cancellationToken)
    {
        return provider.ToLowerInvariant() switch
        {
            "bedrock" or "aws" => await _bedrockService.InvokeModelAsync(request, cancellationToken),
            "local" or "ollama" or "lmstudio" or "llamacpp" => await _localModelService.InvokeLocalModelAsync(request, cancellationToken),
            _ => await _bedrockService.InvokeModelAsync(request, cancellationToken)
        };
    }

    private static string ResolveProvider(UniversalRequest req)
    {
        if (!string.IsNullOrWhiteSpace(req.Provider))
        {
            return req.Provider.ToLowerInvariant();
        }

        var model = req.Model.ToLowerInvariant();
        if (model.StartsWith("ollama/") || model.StartsWith("lmstudio/") || model.StartsWith("llamacpp/") || model.StartsWith("llama.cpp/"))
        {
            return "local";
        }

        if (model.Contains("claude") || model.Contains("titan") || model.Contains("meta.llama") || model.Contains("anthropic."))
        {
            return "bedrock";
        }

        return "bedrock";
    }

    /// <summary>
    /// Egress guardrail: scans model output for leaked PCI / PII / secrets before returning it.
    /// Fails closed — if the guardrail engine throws, the response is suppressed rather than leaked.
    /// </summary>
    private async Task<(UniversalResponse Response, GuardrailResult? Scan)> ApplyOutputGuardrailsAsync(
        UniversalResponse response,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(response.Output))
        {
            return (response, null);
        }

        GuardrailResult scan;
        try
        {
            scan = await _guardrailService.EvaluateOutputAsync(response.Output, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Egress guardrail evaluation failed; suppressing model output (fail-closed).");
            return (response with
            {
                Output = string.Empty,
                Error = new GatewayError
                {
                    Code = "OUTPUT_GUARDRAIL_ERROR",
                    Message = "Response withheld: the egress guardrail could not verify the model output."
                }
            }, null);
        }

        if (scan is null)
        {
            return (response, null);
        }

        if (scan.IsBlocked)
        {
            _logger.LogWarning("Model output blocked by egress guardrails for AppId {AppId}. Violations: {Violations}",
                response.AppId ?? "direct",
                string.Join("; ", scan.Violations.Select(v => v.RuleName)));

            return (response with
            {
                Output = string.Empty,
                Error = new GatewayError
                {
                    Code = "OUTPUT_GUARDRAIL_BLOCKED",
                    Message = "Response blocked: the model output contained sensitive data.",
                    Details = string.Join("; ", scan.Violations.Select(v => $"{v.Category} ({v.RuleName})"))
                }
            }, scan);
        }

        if (scan.ActionTaken == "Redacted")
        {
            _logger.LogInformation("Egress guardrails redacted {Count} sensitive item(s) from model output for AppId {AppId}.",
                scan.Violations.Count, response.AppId ?? "direct");

            return (response with { Output = scan.SanitizedInput }, scan);
        }

        return (response, scan);
    }

    /// <summary>A no-op guardrail result used when telemetry is recorded before inspection runs.</summary>
    private static GuardrailResult PassthroughGuardrail(string input) => new()
    {
        ActionTaken = "None",
        IsBlocked = false,
        OriginalInput = input,
        SanitizedInput = input
    };

    private async Task RecordTelemetryAsync(
        UniversalRequest req,
        UniversalResponse res,
        bool fallbackUsed,
        GuardrailResult guardrailResult,
        CallerContext? caller = null,
        GuardrailResult? outputScan = null)
    {
        try
        {
            var log = new RequestLogEntry
            {
                OutputGuardrailAction = outputScan?.ActionTaken ?? "None",
                OutputGuardrailViolations = outputScan?.Violations.Select(v => $"{v.Category}:{v.RuleName}").ToList() ?? [],
                AppId = req.Metadata?.AppId,
                Model = res.Model,
                Provider = res.Provider,
                LatencyMs = res.LatencyMs,
                InputTokens = res.Tokens.Input,
                OutputTokens = res.Tokens.Output,
                Success = res.Error == null,
                FallbackUsed = fallbackUsed,
                GuardrailAction = guardrailResult.ActionTaken,
                GuardrailViolations = guardrailResult.Violations.Select(v => $"{v.Category}:{v.RuleName}").ToList(),
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = res.Error?.Message,

                // Attribution: without these the trail says what ran but not who ran it.
                Actor = caller?.Actor,
                AuthType = caller?.AuthType,
                TokenId = caller?.TokenId,
                SourceIp = caller?.SourceIp,
                TraceId = caller?.TraceId ?? req.Metadata?.TraceId
            };

            await _registryService.RecordMetricAsync(log);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to record telemetry log");
        }
    }
}
