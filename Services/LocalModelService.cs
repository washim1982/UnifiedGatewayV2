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
            _logger.LogError(ex, "Local model endpoint unreachable for model {Model}", model);
            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_ENDPOINT_UNAVAILABLE",
                $"Could not connect to local model backend: {ex.Message}");
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Local model invocation timed out for model {Model}", model);
            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_ENDPOINT_TIMEOUT",
                "Local model execution timed out. The local engine may be overloaded or initializing.");
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Local model invocation failed unexpectedly for model {Model}", model);
            return CreateErrorResponse(request, model, stopwatch.ElapsedMilliseconds, "LOCAL_INVOCATION_FAILED", ex.Message);
        }
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

        var messages = new List<OpenAiChatMessage>();
        if (!string.IsNullOrWhiteSpace(request.System))
        {
            messages.Add(new OpenAiChatMessage { Role = "system", Content = request.System });
        }
        messages.Add(new OpenAiChatMessage { Role = "user", Content = request.Input });

        var payload = new OpenAiChatRequest
        {
            Model = cleanModel,
            Messages = messages,
            Temperature = request.Temperature,
            MaxTokens = request.MaxTokens > 0 ? request.MaxTokens : 2048,
            Stream = false
        };

        var httpResponse = await client.PostAsJsonAsync("/v1/chat/completions", payload, JsonOpts, ct);
        httpResponse.EnsureSuccessStatusCode();

        var chatResult = await httpResponse.Content.ReadFromJsonAsync<OpenAiChatResponse>(JsonOpts, ct);
        stopwatch.Stop();

        var outputText = chatResult?.Choices?.FirstOrDefault()?.Message?.Content ?? string.Empty;
        var inputTokens = chatResult?.Usage?.PromptTokens ?? (request.Input.Length / 4);
        var outputTokens = chatResult?.Usage?.CompletionTokens ?? (outputText.Length / 4);

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

    public async Task<Dictionary<string, bool>> ProbeStatusAsync(CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, bool>();

        // Check Ollama
        try
        {
            var ollama = _httpClientFactory.CreateClient("OllamaClient");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var resp = await ollama.GetAsync("/api/tags", cts.Token);
            results["ollama"] = resp.IsSuccessStatusCode;
        }
        catch
        {
            results["ollama"] = false;
        }

        // Check LM Studio
        try
        {
            var lmStudio = _httpClientFactory.CreateClient("LmStudioClient");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var resp = await lmStudio.GetAsync("/v1/models", cts.Token);
            results["lmstudio"] = resp.IsSuccessStatusCode;
        }
        catch
        {
            results["lmstudio"] = false;
        }

        // Check LlamaCpp
        try
        {
            var llamaCpp = _httpClientFactory.CreateClient("LlamaCppClient");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var resp = await llamaCpp.GetAsync("/health", cts.Token);
            results["llamacpp"] = resp.IsSuccessStatusCode;
        }
        catch
        {
            results["llamacpp"] = false;
        }

        return results;
    }

    public async Task<List<string>> ListAvailableLocalModelsAsync(CancellationToken cancellationToken = default)
    {
        var models = new List<string>();

        // Query Ollama models
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

        // Query LM Studio models
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

        // Add common local defaults if list is empty
        if (models.Count == 0)
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
