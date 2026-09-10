using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Amazon;
using Amazon.BedrockRuntime;
using Amazon.BedrockRuntime.Model;
using Amazon.Runtime;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using GatewayTokenUsage = UnifiedGateway.Models.TokenUsage;

namespace UnifiedGateway.Services;

public class BedrockService : IBedrockService
{
    private readonly ISTSService _stsService;
    private readonly GatewayOptions _options;
    private readonly CloudOptions _cloudOptions;
    private readonly AmazonBedrockRuntimeConfig _bedrockConfig;
    private readonly ILogger<BedrockService> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public BedrockService(
        ISTSService stsService,
        IOptions<GatewayOptions> options,
        IOptions<CloudOptions> cloudOptions,
        AmazonBedrockRuntimeConfig bedrockConfig,
        ILogger<BedrockService> logger)
    {
        _stsService = stsService;
        _options = options.Value;
        _cloudOptions = cloudOptions.Value;
        _bedrockConfig = bedrockConfig;
        _logger = logger;
    }

    /// <summary>
    /// Builds the Bedrock client for the bound environment.
    ///
    /// The Python simulator implements the real Bedrock Runtime contract
    /// (POST /model/{modelId}/invoke), so TEST differs from PROD only by the ServiceURL on
    /// the injected config: no branch in the invocation path, no second code path to keep
    /// in step. Credentials differ because the simulator does not verify SigV4 on this route.
    ///
    /// The decision reads <see cref="CloudOptions.EffectiveBedrockProvider"/> rather than
    /// <see cref="CloudOptions.Provider"/>, so Development can reach real Bedrock through the
    /// developer's own profile while every other AWS seam stays on the local simulator.
    /// </summary>
    private async Task<AmazonBedrockRuntimeClient> CreateClientAsync(CancellationToken cancellationToken)
    {
        if (_cloudOptions.EffectiveBedrockProvider == CloudProviderMode.Simulator)
        {
            var placeholder = new BasicAWSCredentials("SIMULATED_KEY", "SIMULATED_SECRET");
            return new AmazonBedrockRuntimeClient(placeholder, _bedrockConfig);
        }

        AWSCredentials credentials;
        try
        {
            credentials = await _stsService.GetCredentialsAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Distinguished from an invocation failure on purpose. Everything else Bedrock
            // can throw is infrastructure the caller cannot act on; this one is local
            // configuration a developer fixes in a minute, and burying it behind a
            // correlation id would cost far more than it protects.
            throw new BedrockCredentialsUnavailableException(DescribeCredentialSource(), ex);
        }

        return new AmazonBedrockRuntimeClient(credentials, _bedrockConfig);
    }

    /// <summary>
    /// Names where credentials were meant to come from — the configured intent, not a claim
    /// about what was actually used. When a named profile is missing the SDK silently falls
    /// back to environment variables and then instance metadata, so saying the credentials
    /// "came from" the profile would be wrong in exactly the case this message exists for.
    ///
    /// Config keys and a profile name only: the role ARN and account id stay out, since this
    /// text reaches the caller.
    /// </summary>
    private string DescribeCredentialSource()
    {
        if (_options.Aws.UseLocalProfile)
        {
            var profile = string.IsNullOrWhiteSpace(_options.Aws.LocalProfileName)
                ? "default"
                : _options.Aws.LocalProfileName;

            return $"the local AWS profile '{profile}' (Gateway:Aws:LocalProfileName), falling back " +
                   $"to environment variables and instance metadata if that profile is absent. " +
                   $"Check that ~/.aws/credentials or ~/.aws/config defines it, that any SSO session " +
                   $"for it is still signed in, and that it grants bedrock:InvokeModel in " +
                   $"{_options.Aws.Region}";
        }

        return "the ambient AWS credential chain (environment variables, ECS/EC2 role). " +
               "Set Gateway:Aws:UseLocalProfile to true to use a named ~/.aws profile instead";
    }

    public async Task<UniversalResponse> InvokeModelAsync(UniversalRequest request, CancellationToken cancellationToken = default)
    {
        var modelId = ResolveBedrockModelId(request.Model);
        var stopwatch = Stopwatch.StartNew();

        _logger.LogInformation("Invoking AWS Bedrock Model: {ModelId} for AppId: {AppId}",
            modelId, request.Metadata?.AppId ?? "direct");

        try
        {
            using var client = await CreateClientAsync(cancellationToken);

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
        // Credential resolution mostly succeeds lazily: with no profile and no environment
        // variables the SDK still hands back an instance-metadata credential object, which
        // only fails when it is first used to sign. So the same classification has to run
        // here, or the common local case (no ~/.aws profile yet) reports as an infrastructure
        // fault rather than the setup step it actually is.
        catch (Exception ex) when (IsCredentialProblem(ex))
        {
            stopwatch.Stop();

            _logger.LogError(ex,
                "Bedrock rejected the gateway's credentials for model {ModelId}.", modelId);

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
                    Code = "BEDROCK_CREDENTIALS_UNAVAILABLE",
                    Message = "Bedrock is configured to use the real AWS service, but the credentials were missing or rejected.",
                    Details = $"Configured credential source: {DescribeCredentialSource()}."
                }
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();

            // An AWS exception message routinely carries the account id, the role ARN and the
            // request id. That belongs in the log, not in a response to the caller — they get
            // the correlation id and support looks the rest up against it.
            var reference = request.Metadata?.TraceId ?? Guid.NewGuid().ToString("N");
            _logger.LogError(ex,
                "Bedrock invocation failed for model {ModelId}. Reference {Reference}.", modelId, reference);

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
                    Message = "The Bedrock invocation failed.",
                    Details = $"Reference: {reference}"
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

    /// <summary>
    /// True when a failure is the gateway's own credentials rather than the model call.
    ///
    /// Deliberately narrow. A guess that is too broad would relabel a genuine service fault
    /// as a configuration problem and send an operator looking in the wrong place, so this
    /// matches only the codes AWS returns for an identity that is absent, unrecognised,
    /// expired, or not permitted.
    /// </summary>
    public static bool IsCredentialProblem(Exception ex)
    {
        if (ex is BedrockCredentialsUnavailableException)
        {
            return true;
        }

        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is AmazonServiceException svc &&
                CredentialErrorCodes.Contains(svc.ErrorCode ?? string.Empty))
            {
                return true;
            }

            // Credential resolution failures carry no error code at all, so they have to be
            // matched on the message. Note that AmazonServiceException does NOT derive from
            // AmazonClientException -- both descend directly from Exception -- so testing one
            // type here would miss the case this exists for: the metadata-service probe a
            // machine makes when it has no profile and no environment variables.
            if (current is AmazonClientException or AmazonServiceException &&
                CredentialPhrases.Any(phrase =>
                    current.Message.Contains(phrase, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Phrases the SDK uses when it cannot produce an identity. Kept specific: a bare match
    /// on "credentials" would also catch messages about the *caller's* credentials, which is
    /// a different problem with a different fix.
    /// </summary>
    private static readonly string[] CredentialPhrases =
    [
        "Instance Metadata",
        "security credentials",
        "Unable to find credentials",
        "Unable to get credentials",
        "no credentials",
        "credentials not found",
        "Failed to resolve AWS credentials",
        "SSO session",
        "token has expired"
    ];

    private static readonly HashSet<string> CredentialErrorCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthFailure",
        "ExpiredToken",
        "ExpiredTokenException",
        "IncompleteSignature",
        "InvalidAccessKeyId",
        "InvalidClientTokenId",
        "InvalidSignatureException",
        "MissingAuthenticationToken",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
        "UnauthorizedOperation"
    };

    private static int ApproximateTokens(int chars) => Math.Max(1, chars);
}

/// <summary>
/// Raised when Bedrock is bound to the real AWS service but no credentials could be resolved.
/// Separate from an invocation failure so the caller gets an actionable message instead of a
/// correlation id pointing at a log they cannot read.
/// </summary>
public sealed class BedrockCredentialsUnavailableException : Exception
{
    public string CredentialSource { get; }

    public BedrockCredentialsUnavailableException(string credentialSource, Exception inner)
        : base($"No usable AWS credentials for Bedrock. Source: {credentialSource}.", inner)
    {
        CredentialSource = credentialSource;
    }
}
