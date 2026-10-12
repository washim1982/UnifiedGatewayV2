using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public class LocalModelService : ILocalModelService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly GatewayOptions _options;
    private readonly ILogger<LocalModelService> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public LocalModelService(
        IHttpClientFactory httpClientFactory,
        IOptions<GatewayOptions> options,
        ILogger<LocalModelService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<UniversalResponse> InvokeLocalModelAsync(UniversalRequest request, CancellationToken cancellationToken = default)
    {
        var model = request.Model.Trim();
        var lowerModel = model.ToLowerInvariant();
        var stopwatch = Stopwatch.StartNew();

        _logger.LogInformation("Invoking Local Model: {Model} for AppId: {AppId}",
            model, request.Metadata?.AppId ?? "direct");

        // Enabled is a dispatch restriction, not merely a validation exemption: a disabled backend
        // is never contacted, by invocation or by the discovery and probe paths below (SEC-14).
        var backend = BackendFor(lowerModel);
        if (!backend.Enabled)
        {
            stopwatch.Stop();
            _logger.LogWarning(
                "Refused invocation of '{Model}': the {Backend} backend is disabled in this environment.",
                model, backend.Name);

            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_BACKEND_DISABLED",
                $"The {backend.Name} backend is disabled for this gateway.");
        }

        try
        {
            // Determine the target local engine: LM Studio, llama.cpp, or Ollama
            if (lowerModel.StartsWith("lmstudio/") || lowerModel.StartsWith("openai/"))
            {
                return await InvokeLmStudioAsync(request, stopwatch, cancellationToken);
            }
            if (lowerModel.StartsWith("llamacpp/") || lowerModel.StartsWith("llama.cpp/"))
            {
                return await InvokeLlamaCppAsync(request, stopwatch, cancellationToken);
            }

            // Default local backend is Ollama
            return await InvokeOllamaAsync(request, stopwatch, cancellationToken);
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            // The transport error can carry an internal hostname and port; keep it in the log.
            var reference = request.Metadata?.TraceId ?? Guid.NewGuid().ToString("N");
            _logger.LogError(ex,
                "Local model endpoint unreachable for model {Model}. Reference {Reference}.", model, reference);

            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_ENDPOINT_UNAVAILABLE",
                $"The local model backend could not be reached. Reference: {reference}");
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();

            // Name the numbers that actually caused this. A local model generates at a
            // roughly fixed rate, so the usual cause is a max-tokens budget the configured
            // timeout cannot cover -- not an overloaded engine. Telling the operator which
            // knob to turn is the difference between a dead end and a one-line fix.
            var timeoutSeconds = ResolveTimeoutSeconds(lowerModel);
            var requestedTokens = request.MaxTokens > 0 ? request.MaxTokens : 2048;

            _logger.LogError(ex,
                "Local model {Model} timed out after {Timeout}s with MaxTokens={MaxTokens}.",
                model, timeoutSeconds, requestedTokens);

            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_ENDPOINT_TIMEOUT",
                $"Local model '{model}' did not finish within the configured {timeoutSeconds}s timeout " +
                $"while generating up to {requestedTokens} tokens. Either raise the provider timeout " +
                $"(Gateway:LocalProviders:*:TimeoutSeconds), lower the application's MaxTokens, or use a smaller model.");
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            var reference = request.Metadata?.TraceId ?? Guid.NewGuid().ToString("N");
            _logger.LogError(ex,
                "Local model invocation failed for model {Model}. Reference {Reference}.", model, reference);

            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_INVOCATION_FAILED",
                $"The local model invocation failed. Reference: {reference}");
        }
    }

    /// <summary>
    /// The configured timeout for whichever local engine this model routes to, so an error
    /// can quote the limit that actually fired rather than a generic one.
    /// </summary>
    private int ResolveTimeoutSeconds(string lowerModel)
    {
        if (lowerModel.StartsWith("lmstudio/") || lowerModel.StartsWith("openai/"))
            return _options.LocalProviders.LmStudio.TimeoutSeconds;

        if (lowerModel.StartsWith("llamacpp/") || lowerModel.StartsWith("llama.cpp/"))
            return _options.LocalProviders.LlamaCpp.TimeoutSeconds;

        return _options.LocalProviders.Ollama.TimeoutSeconds;
    }
    private async Task<UniversalResponse> InvokeOllamaAsync(
        UniversalRequest request,
        Stopwatch stopwatch,
        CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("OllamaClient");
        var cleanModel = request.Model.Replace("ollama/", "", StringComparison.OrdinalIgnoreCase);

        var payload = new OllamaGenerateRequest
        {
            Model = cleanModel,
            Prompt = request.Input,
            System = request.System,
            Stream = false,
            Options = new OllamaOptionsPayload
            {
                Temperature = request.Temperature,
                NumPredict = request.MaxTokens > 0 ? request.MaxTokens : 2048
            }
        };

        var httpResponse = await client.PostAsJsonAsync("/api/generate", payload, JsonOpts, ct);
        httpResponse.EnsureSuccessStatusCode();

        var ollamaResult = await httpResponse.Content.ReadFromJsonAsync<OllamaGenerateResponse>(JsonOpts, ct);
        stopwatch.Stop();

        var outputText = ollamaResult?.Response ?? string.Empty;
        var inputTokens = ollamaResult?.PromptEvalCount ?? (request.Input.Length / 4);
        var outputTokens = ollamaResult?.EvalCount ?? (outputText.Length / 4);

        return new UniversalResponse
        {
            Output = outputText,
            Model = cleanModel,
            Provider = "local",
            LatencyMs = stopwatch.ElapsedMilliseconds,
            Tokens = new TokenUsage
            {
                Input = inputTokens,
                Output = outputTokens
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }

    private async Task<UniversalResponse> InvokeLmStudioAsync(
        UniversalRequest request,
        Stopwatch stopwatch,
        CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("LmStudioClient");
        var cleanModel = request.Model.Replace("lmstudio/", "", StringComparison.OrdinalIgnoreCase);

        var payload = new OpenAiChatRequest
        {
            Model = cleanModel,
            Messages = BuildOpenAiMessages(request),
            Temperature = request.Temperature,
            MaxTokens = request.MaxTokens > 0 ? request.MaxTokens : 2048,
            Stream = false,
            Tools = OpenAiTools(request.Tools)
        };

        var httpResponse = await client.PostAsJsonAsync("/v1/chat/completions", payload, JsonOpts, ct);
        httpResponse.EnsureSuccessStatusCode();

        var chatResult = await httpResponse.Content.ReadFromJsonAsync<OpenAiChatResponse>(JsonOpts, ct);
        stopwatch.Stop();

        var choice = chatResult?.Choices?.FirstOrDefault();
        var outputText = choice?.Message?.Content ?? string.Empty;
        var inputTokens = chatResult?.Usage?.PromptTokens ?? (request.Input.Length / 4);
        var outputTokens = chatResult?.Usage?.CompletionTokens ?? (outputText.Length / 4);

        var calls = (choice?.Message?.ToolCalls ?? [])
            .Select(call => new ToolInvocation
            {
                Id = string.IsNullOrWhiteSpace(call.Id) ? Guid.NewGuid().ToString("N") : call.Id,
                Name = ResolveToolName(call.Function.Name, request.Tools),
                Arguments = string.IsNullOrWhiteSpace(call.Function.Arguments) ? "{}" : call.Function.Arguments
            })
            .ToList();

        return new UniversalResponse
        {
            Output = outputText,
            Model = cleanModel,
            Provider = "local",
            LatencyMs = stopwatch.ElapsedMilliseconds,
            StopReason = choice?.FinishReason,
            ToolCalls = calls,
            Tokens = new TokenUsage
            {
                Input = inputTokens,
                Output = outputTokens
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }

    /// <summary>
    /// OpenAI-compatible servers expect [a-zA-Z0-9_-] in a function name, while gateway tools are
    /// namespaced <c>server.tool</c>. The dot is encoded on the way out and matched against the
    /// offered list on the way back.
    /// </summary>
    private static string WireToolName(string toolName) => toolName.Replace(".", "__");

    private static string ResolveToolName(string wireName, List<ToolSpec>? offered) =>
        offered?.FirstOrDefault(t => WireToolName(t.Name) == wireName)?.Name ?? wireName.Replace("__", ".");

    private static List<OpenAiTool>? OpenAiTools(List<ToolSpec>? tools) =>
        tools is not { Count: > 0 }
            ? null
            : tools.Select(t => new OpenAiTool
            {
                Function = new OpenAiFunction
                {
                    Name = WireToolName(t.Name),
                    Description = t.Description,
                    Parameters = ParseSchema(t.InputSchema)
                }
            }).ToList();

    private static JsonElement ParseSchema(string schema)
    {
        try
        {
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(schema) ? "{}" : schema);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            using var fallback = JsonDocument.Parse("""{"type":"object"}""");
            return fallback.RootElement.Clone();
        }
    }

    /// <summary>
    /// The conversation so far: system, the caller's input, then one assistant turn per completed
    /// tool round with a tool message per result. The gateway owns this history, so a refused
    /// round is still represented honestly to the model.
    /// </summary>
    private static List<OpenAiChatMessage> BuildOpenAiMessages(UniversalRequest request)
    {
        var messages = new List<OpenAiChatMessage>();

        if (!string.IsNullOrWhiteSpace(request.System))
        {
            messages.Add(new OpenAiChatMessage { Role = "system", Content = request.System });
        }

        messages.Add(new OpenAiChatMessage { Role = "user", Content = request.Input });

        foreach (var turn in request.ToolTurns ?? [])
        {
            messages.Add(new OpenAiChatMessage
            {
                Role = "assistant",
                Content = turn.AssistantText,
                ToolCalls = turn.Calls.Select(call => new OpenAiToolCall
                {
                    Id = call.Id,
                    Function = new OpenAiFunctionCall
                    {
                        Name = WireToolName(call.Name),
                        Arguments = call.Arguments
                    }
                }).ToList()
            });

            foreach (var result in turn.Results)
            {
                messages.Add(new OpenAiChatMessage
                {
                    Role = "tool",
                    ToolCallId = result.Id,
                    Content = result.Result
                });
            }
        }

        return messages;
    }

    private async Task<UniversalResponse> InvokeLlamaCppAsync(
        UniversalRequest request,
        Stopwatch stopwatch,
        CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("LlamaCppClient");
        var cleanModel = request.Model
            .Replace("llamacpp/", "", StringComparison.OrdinalIgnoreCase)
            .Replace("llama.cpp/", "", StringComparison.OrdinalIgnoreCase);

        var prompt = !string.IsNullOrWhiteSpace(request.System)
            ? $"{request.System}\n\nUser: {request.Input}\nAssistant:"
            : request.Input;

        var payload = new LlamaCppCompletionRequest
        {
            Prompt = prompt,
            Temperature = request.Temperature,
            NPredict = request.MaxTokens > 0 ? request.MaxTokens : 2048,
            Stream = false
        };

        var httpResponse = await client.PostAsJsonAsync("/completion", payload, JsonOpts, ct);
        httpResponse.EnsureSuccessStatusCode();

        var cppResult = await httpResponse.Content.ReadFromJsonAsync<LlamaCppCompletionResponse>(JsonOpts, ct);
        stopwatch.Stop();

        var outputText = cppResult?.Content ?? string.Empty;
        var inputTokens = cppResult?.TokensEvaluated ?? (prompt.Length / 4);
        var outputTokens = cppResult?.TokensPredicted ?? (outputText.Length / 4);

        return new UniversalResponse
        {
            Output = outputText,
            Model = cleanModel,
            Provider = "local",
            LatencyMs = stopwatch.ElapsedMilliseconds,
            Tokens = new TokenUsage
            {
                Input = inputTokens,
                Output = outputTokens
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }

    /// <summary>Which configured backend a model name routes to, and whether it may be called.</summary>
    private (string Name, bool Enabled) BackendFor(string lowerModel)
    {
        if (lowerModel.StartsWith("lmstudio/") || lowerModel.StartsWith("openai/"))
            return ("LmStudio", _options.LocalProviders.LmStudio.Enabled);

        if (lowerModel.StartsWith("llamacpp/") || lowerModel.StartsWith("llama.cpp/"))
            return ("LlamaCpp", _options.LocalProviders.LlamaCpp.Enabled);

        return ("Ollama", _options.LocalProviders.Ollama.Enabled);
    }

    public async Task<Dictionary<string, bool>> ProbeStatusAsync(CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, bool>();

        foreach (var (key, clientName, path, enabled) in new[]
        {
            ("ollama", "OllamaClient", "/api/tags", _options.LocalProviders.Ollama.Enabled),
            ("lmstudio", "LmStudioClient", "/v1/models", _options.LocalProviders.LmStudio.Enabled),
            ("llamacpp", "LlamaCppClient", "/health", _options.LocalProviders.LlamaCpp.Enabled)
        })
        {
            // A disabled backend is reported unavailable without being contacted (SEC-14).
            if (!enabled)
            {
                results[key] = false;
                continue;
            }

            try
            {
                var client = _httpClientFactory.CreateClient(clientName);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(2));
                var resp = await client.GetAsync(path, cts.Token);
                results[key] = resp.IsSuccessStatusCode;
            }
            catch
            {
                results[key] = false;
            }
        }

        return results;
    }

    public async Task<List<string>> ListAvailableLocalModelsAsync(CancellationToken cancellationToken = default)
    {
        var models = new List<string>();

        // Query Ollama models. A disabled backend is not contacted, even for discovery (SEC-14).
        if (_options.LocalProviders.Ollama.Enabled)
        {
            try
            {
                var ollama = _httpClientFactory.CreateClient("OllamaClient");
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(3));
                var resp = await ollama.GetAsync("/api/tags", cts.Token);
                if (resp.IsSuccessStatusCode)
                {
                    var content = await resp.Content.ReadAsStringAsync(cts.Token);
                    using var doc = JsonDocument.Parse(content);
                    if (doc.RootElement.TryGetProperty("models", out var modelsArr))
                    {
                        foreach (var m in modelsArr.EnumerateArray())
                        {
                            if (m.TryGetProperty("name", out var nameProp))
                            {
                                var modelName = nameProp.GetString();
                                if (!string.IsNullOrEmpty(modelName))
                                    models.Add($"ollama/{modelName}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not fetch models from Ollama");
            }
        }

        // Query LM Studio models
        if (_options.LocalProviders.LmStudio.Enabled)
        {
            try
            {
                var lmStudio = _httpClientFactory.CreateClient("LmStudioClient");
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(3));
                var resp = await lmStudio.GetAsync("/v1/models", cts.Token);
                if (resp.IsSuccessStatusCode)
                {
                    var content = await resp.Content.ReadAsStringAsync(cts.Token);
                    using var doc = JsonDocument.Parse(content);
                    if (doc.RootElement.TryGetProperty("data", out var dataArr))
                    {
                        foreach (var m in dataArr.EnumerateArray())
                        {
                            if (m.TryGetProperty("id", out var idProp))
                            {
                                var modelId = idProp.GetString();
                                if (!string.IsNullOrEmpty(modelId))
                                    models.Add($"lmstudio/{modelId}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not fetch models from LM Studio");
            }
        }

        // Defaults stand in for a backend that is up but answered nothing. With every local
        // backend disabled the honest answer is an empty list, not a menu of uncallable models.
        var anyEnabled = _options.LocalProviders.Ollama.Enabled
                         || _options.LocalProviders.LmStudio.Enabled
                         || _options.LocalProviders.LlamaCpp.Enabled;

        if (models.Count == 0 && anyEnabled)
        {
            models.AddRange(["ollama/llama3", "ollama/mistral", "ollama/phi3", "lmstudio/local-model"]);
        }

        return models;
    }

    private static UniversalResponse CreateErrorResponse(UniversalRequest req, string model, long latencyMs, string code, string message)
    {
        return new UniversalResponse
        {
            Output = string.Empty,
            Model = model,
            Provider = "local",
            LatencyMs = latencyMs,
            AppId = req.Metadata?.AppId,
            SessionId = req.Metadata?.SessionId,
            Error = new GatewayError
            {
                Code = code,
                Message = message
            }
        };
    }
}
