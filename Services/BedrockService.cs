using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Amazon;
using Amazon.BedrockRuntime;
using Amazon.BedrockRuntime.Model;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using GatewayTokenUsage = UnifiedGateway.Models.TokenUsage;

namespace UnifiedGateway.Services;

public class BedrockService : IBedrockService
{
    private readonly ISTSService _stsService;
    private readonly GatewayOptions _options;
    private readonly ILogger<BedrockService> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public BedrockService(
        ISTSService stsService,
        IOptions<GatewayOptions> options,
        ILogger<BedrockService> logger)
    {
        _stsService = stsService;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<UniversalResponse> InvokeModelAsync(UniversalRequest request, CancellationToken cancellationToken = default)
    {
        var modelId = ResolveBedrockModelId(request.Model);
        var stopwatch = Stopwatch.StartNew();

        _logger.LogInformation("Invoking AWS Bedrock Model: {ModelId} for AppId: {AppId}",
            modelId, request.Metadata?.AppId ?? "direct");

        try
        {
            var credentials = await _stsService.GetCredentialsAsync(cancellationToken);
            var region = RegionEndpoint.GetBySystemName(_options.Aws.Region);
            using var client = new AmazonBedrockRuntimeClient(credentials, region);

            var (payloadBytes, contentType) = BuildRequestBody(modelId, request);

            using var requestStream = new MemoryStream(payloadBytes);
            var invokeRequest = new InvokeModelRequest
            {
                ModelId = modelId,
                ContentType = contentType,
                Accept = contentType,
                Body = requestStream
            };

            var response = await client.InvokeModelAsync(invokeRequest, cancellationToken);
            stopwatch.Stop();

            using var reader = new StreamReader(response.Body);
            var responseString = await reader.ReadToEndAsync(cancellationToken);

            var result = ParseResponseBody(modelId, responseString, stopwatch.ElapsedMilliseconds);
            return result with
            {
                AppId = request.Metadata?.AppId,
                SessionId = request.Metadata?.SessionId
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Bedrock invocation failed for model {ModelId}", modelId);

            return new UniversalResponse
            {
                Output = string.Empty,
                Model = modelId,
                Provider = "bedrock",
                LatencyMs = stopwatch.ElapsedMilliseconds,
                AppId = request.Metadata?.AppId,
                SessionId = request.Metadata?.SessionId,
                Error = new GatewayError
                {
                    Code = "BEDROCK_INVOCATION_FAILED",
                    Message = ex.Message,
                    Details = ex.GetType().Name
                }
            };
        }
    }

    public async Task<bool> HealthCheckAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var status = await _stsService.GetStatusAsync(cancellationToken);
            return status.IsInitialized && string.IsNullOrEmpty(status.LastError);
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveBedrockModelId(string model)
    {
        var lower = model.ToLowerInvariant().Trim();
        return lower switch
        {
            "claude-3-5-sonnet" or "claude-3.5-sonnet" => "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "claude-3-sonnet" or "claude-3.0-sonnet" => "anthropic.claude-3-sonnet-20240229-v1:0",
            "claude-3-haiku" or "claude-3.0-haiku" => "anthropic.claude-3-haiku-20240307-v1:0",
            "claude-3-opus" or "claude-3.0-opus" => "anthropic.claude-3-opus-20240229-v1:0",
            "llama3" or "llama-3-8b" => "meta.llama3-8b-instruct-v1:0",
            "llama3-70b" or "llama-3-70b" => "meta.llama3-70b-instruct-v1:0",
            "llama3.1-8b" or "llama3-1-8b" => "meta.llama3-1-8b-instruct-v1:0",
            "llama3.1-70b" or "llama3-1-70b" => "meta.llama3-1-70b-instruct-v1:0",
            "mistral-7b" or "mistral" => "mistral.mistral-7b-instruct-v0:2",
            "mixtral-8x7b" => "mistral.mixtral-8x7b-instruct-v0:1",
            "titan-text" or "titan" => "amazon.titan-text-express-v1",
            _ => model // return verbatim if exact ARN or full Bedrock ID
        };
    }

    private static (byte[] bytes, string contentType) BuildRequestBody(string modelId, UniversalRequest req)
    {
        var lower = modelId.ToLowerInvariant();

        if (lower.Contains("anthropic.claude"))
        {
            var claudeReq = new ClaudeBedrockRequest
            {
                AnthropicVersion = "bedrock-2023-05-31",
                MaxTokens = req.MaxTokens > 0 ? req.MaxTokens : 2048,
                Temperature = req.Temperature,
                System = string.IsNullOrWhiteSpace(req.System) ? null : req.System,
                Messages =
                [
                    new ClaudeMessage { Role = "user", Content = req.Input }
                ]
            };
            return (JsonSerializer.SerializeToUtf8Bytes(claudeReq, JsonOpts), "application/json");
        }

        if (lower.Contains("meta.llama"))
        {
            var systemPart = !string.IsNullOrWhiteSpace(req.System)
                ? $"<|start_header_id|>system<|end_header_id|>\n\n{req.System}<|eot_id|>"
                : string.Empty;

            var fullPrompt = $"<|begin_of_text|>{systemPart}<|start_header_id|>user<|end_header_id|>\n\n{req.Input}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n";

            var llamaReq = new LlamaBedrockRequest
            {
                Prompt = fullPrompt,
                MaxGenLen = req.MaxTokens > 0 ? req.MaxTokens : 2048,
                Temperature = req.Temperature
            };
            return (JsonSerializer.SerializeToUtf8Bytes(llamaReq, JsonOpts), "application/json");
        }

        if (lower.Contains("mistral"))
        {
            var sysPrefix = !string.IsNullOrWhiteSpace(req.System)
                ? $"<<SYS>>\n{req.System}\n<</SYS>>\n\n"
                : string.Empty;

            var fullPrompt = $"<s>[INST] {sysPrefix}{req.Input} [/INST]";
            var mistralReq = new MistralBedrockRequest
            {
                Prompt = fullPrompt,
                MaxTokens = req.MaxTokens > 0 ? req.MaxTokens : 2048,
                Temperature = req.Temperature
            };
            return (JsonSerializer.SerializeToUtf8Bytes(mistralReq, JsonOpts), "application/json");
        }

        if (lower.Contains("amazon.titan"))
        {
            var prompt = !string.IsNullOrWhiteSpace(req.System)
                ? $"{req.System}\n\nUser: {req.Input}\n\nBot:"
                : req.Input;

            var titanReq = new TitanBedrockRequest
            {
                InputText = prompt,
                TextGenerationConfig = new TitanGenerationConfig
                {
                    MaxTokenCount = req.MaxTokens > 0 ? req.MaxTokens : 2048,
                    Temperature = req.Temperature
                }
            };
            return (JsonSerializer.SerializeToUtf8Bytes(titanReq, JsonOpts), "application/json");
        }

        // Default: treat as Claude-compatible schema
        var defaultReq = new ClaudeBedrockRequest
        {
            AnthropicVersion = "bedrock-2023-05-31",
            MaxTokens = req.MaxTokens > 0 ? req.MaxTokens : 2048,
            Temperature = req.Temperature,
            System = req.System,
            Messages = [new ClaudeMessage { Role = "user", Content = req.Input }]
        };
        return (JsonSerializer.SerializeToUtf8Bytes(defaultReq, JsonOpts), "application/json");
    }

    private static UniversalResponse ParseResponseBody(string modelId, string json, long latencyMs)
    {
        var lower = modelId.ToLowerInvariant();

        if (lower.Contains("anthropic.claude"))
        {
            var claudeRes = JsonSerializer.Deserialize<ClaudeBedrockResponse>(json, JsonOpts);
            var text = claudeRes?.Content?.FirstOrDefault()?.Text ?? string.Empty;
            return new UniversalResponse
            {
                Output = text,
                Model = modelId,
                Provider = "bedrock",
                LatencyMs = latencyMs,
                Tokens = new GatewayTokenUsage
                {
                    Input = claudeRes?.Usage?.InputTokens ?? ApproximateTokens(json.Length / 4),
                    Output = claudeRes?.Usage?.OutputTokens ?? ApproximateTokens(text.Length / 4)
                }
            };
        }

        if (lower.Contains("meta.llama"))
        {
            var llamaRes = JsonSerializer.Deserialize<LlamaBedrockResponse>(json, JsonOpts);
            var text = llamaRes?.Generation ?? string.Empty;
            return new UniversalResponse
            {
                Output = text,
                Model = modelId,
                Provider = "bedrock",
                LatencyMs = latencyMs,
                Tokens = new GatewayTokenUsage
                {
                    Input = llamaRes?.PromptTokenCount ?? 0,
                    Output = llamaRes?.GenerationTokenCount ?? ApproximateTokens(text.Length / 4)
                }
            };
        }

        if (lower.Contains("mistral"))
        {
            var mistralRes = JsonSerializer.Deserialize<MistralBedrockResponse>(json, JsonOpts);
            var text = mistralRes?.Outputs?.FirstOrDefault()?.Text ?? string.Empty;
            return new UniversalResponse
            {
                Output = text,
                Model = modelId,
                Provider = "bedrock",
                LatencyMs = latencyMs,
                Tokens = new GatewayTokenUsage
                {
                    Input = ApproximateTokens(json.Length / 6),
                    Output = ApproximateTokens(text.Length / 4)
                }
            };
        }

        if (lower.Contains("amazon.titan"))
        {
            var titanRes = JsonSerializer.Deserialize<TitanBedrockResponse>(json, JsonOpts);
            var result = titanRes?.Results?.FirstOrDefault();
            var text = result?.OutputText ?? string.Empty;
            return new UniversalResponse
            {
                Output = text,
                Model = modelId,
                Provider = "bedrock",
                LatencyMs = latencyMs,
                Tokens = new GatewayTokenUsage
                {
                    Input = titanRes?.InputTextTokenCount ?? 0,
                    Output = result?.TokenCount ?? ApproximateTokens(text.Length / 4)
                }
            };
        }

        // Generic JSON parse fallback
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var outputText = root.TryGetProperty("output", out var outProp) ? outProp.GetString() ?? json : json;

        return new UniversalResponse
        {
            Output = outputText,
            Model = modelId,
            Provider = "bedrock",
            LatencyMs = latencyMs,
            Tokens = new GatewayTokenUsage
            {
                Input = ApproximateTokens(json.Length / 6),
                Output = ApproximateTokens(outputText.Length / 4)
            }
        };
    }

    private static int ApproximateTokens(int chars) => Math.Max(1, chars);
}
