using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Providers;

/// <summary>Calls one family of provider API on behalf of the gateway.</summary>
public interface IProviderAdapter
{
    ProviderKind Kind { get; }

    Task<UniversalResponse> InvokeAsync(
        ProviderRegistration provider, string? apiKey, UniversalRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Routes a request to the adapter for a registered provider's kind.
///
/// An unknown provider is an error here, not a silent redirect to Bedrock: an application
/// configured for a local model must not reach a cloud one because of a typo (SEC-09).
/// </summary>
public interface IProviderDispatcher
{
    Task<UniversalResponse?> TryInvokeAsync(
        string providerId, UniversalRequest request, CancellationToken cancellationToken);
}

public class ProviderDispatcher(
    IProviderRegistry registry,
    IEnumerable<IProviderAdapter> adapters,
    IBedrockService bedrock,
    ILogger<ProviderDispatcher> logger) : IProviderDispatcher
{
    public async Task<UniversalResponse?> TryInvokeAsync(
        string providerId, UniversalRequest request, CancellationToken cancellationToken)
    {
        var provider = await registry.GetAsync(providerId, cancellationToken);
        if (provider is null)
        {
            return null;   // Not a registered provider; the caller falls back to the built-ins.
        }

        if (!provider.IsActive)
        {
            return Failure(request, providerId, "PROVIDER_DISABLED",
                $"Provider '{providerId}' is disabled.");
        }

        // Bedrock authenticates with the host's own AWS identity, so it keeps its own service.
        if (provider.Kind == ProviderKind.Bedrock)
        {
            return await bedrock.InvokeModelAsync(request, cancellationToken);
        }

        var adapter = adapters.FirstOrDefault(a => a.Kind == provider.Kind);
        if (adapter is null)
        {
            return Failure(request, providerId, "PROVIDER_KIND_UNSUPPORTED",
                $"No adapter is registered for {provider.Kind}.");
        }

        var apiKey = await registry.ApiKeyAsync(provider, cancellationToken);
        if (string.IsNullOrWhiteSpace(apiKey) && provider.ApiKeySecretName.Length > 0)
        {
            logger.LogError(
                "Provider '{ProviderId}' names secret '{Secret}', which is missing or empty.",
                providerId, provider.ApiKeySecretName);

            return Failure(request, providerId, "PROVIDER_CREDENTIAL_MISSING",
                $"The API key for provider '{providerId}' could not be read from the secret store.");
        }

        try
        {
            return await adapter.InvokeAsync(provider, apiKey, request, cancellationToken);
        }
        catch (Exception ex)
        {
            // A provider's error text routinely quotes the request, so it is logged against the
            // correlation id and the caller gets the id.
            var reference = request.Metadata?.TraceId ?? Guid.NewGuid().ToString("N");
            logger.LogError(ex, "Provider '{ProviderId}' failed. Reference {Reference}.", providerId, reference);

            return Failure(request, providerId, "PROVIDER_CALL_FAILED",
                $"The provider could not be reached. Reference: {reference}");
        }
    }

    private static UniversalResponse Failure(UniversalRequest request, string providerId, string code, string message) =>
        new()
        {
            Output = string.Empty,
            Model = request.Model,
            Provider = providerId,
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId,
            Error = new GatewayError { Code = code, Message = message }
        };
}

/// <summary>Shared plumbing: one named client, the provider's timeout, and a JSON policy.</summary>
public abstract class HttpProviderAdapter(IHttpClientFactory httpClientFactory)
{
    public const string HttpClientName = "ModelProviderClient";

    protected static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    protected HttpClient Client(ProviderRegistration provider)
    {
        var client = httpClientFactory.CreateClient(HttpClientName);
        client.BaseAddress = new Uri(provider.BaseUrl);
        client.Timeout = TimeSpan.FromSeconds(Math.Clamp(provider.TimeoutSeconds, 1, 600));
        return client;
    }
}

/// <summary>OpenAI and everything that speaks its chat-completions shape.</summary>
public class OpenAiCompatibleAdapter(IHttpClientFactory httpClientFactory)
    : HttpProviderAdapter(httpClientFactory), IProviderAdapter
{
    public ProviderKind Kind => ProviderKind.OpenAiCompatible;

    public async Task<UniversalResponse> InvokeAsync(
        ProviderRegistration provider, string? apiKey, UniversalRequest request, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var client = Client(provider);

        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        }

        var payload = new OpenAiChatRequest
        {
            Model = ModelName(provider, request.Model),
            Messages = OpenAiWire.Messages(request),
            Temperature = request.Temperature,
            MaxTokens = request.MaxTokens > 0 ? request.MaxTokens : 2048,
            Stream = false,
            Tools = OpenAiWire.Tools(request.Tools)
        };

        using var response = await client.PostAsJsonAsync("/v1/chat/completions", payload, JsonOpts, cancellationToken);
        response.EnsureSuccessStatusCode();

        var completion = await response.Content.ReadFromJsonAsync<OpenAiChatResponse>(JsonOpts, cancellationToken);
        stopwatch.Stop();

        return OpenAiWire.ToResponse(
            completion, request, payload.Model, provider.ProviderId, stopwatch.ElapsedMilliseconds);
    }

    public static string ModelName(ProviderRegistration provider, string requested)
    {
        // "openai/gpt-4o" and "gpt-4o" both mean the same model on a provider called openai.
        var prefix = provider.ProviderId + "/";
        var name = requested.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? requested[prefix.Length..]
            : requested;

        return string.IsNullOrWhiteSpace(name) ? provider.DefaultModel ?? string.Empty : name;
    }
}

/// <summary>Anthropic's Messages API, called directly rather than through Bedrock.</summary>
public class AnthropicAdapter(IHttpClientFactory httpClientFactory)
    : HttpProviderAdapter(httpClientFactory), IProviderAdapter
{
    private const string AnthropicVersion = "2023-06-01";

    public ProviderKind Kind => ProviderKind.Anthropic;

    public async Task<UniversalResponse> InvokeAsync(
        ProviderRegistration provider, string? apiKey, UniversalRequest request, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var client = Client(provider);

        client.DefaultRequestHeaders.Add("x-api-key", apiKey);
        client.DefaultRequestHeaders.Add("anthropic-version", AnthropicVersion);

        var model = OpenAiCompatibleAdapter.ModelName(provider, request.Model);

        var payload = new
        {
            model,
            max_tokens = request.MaxTokens > 0 ? request.MaxTokens : 2048,
            temperature = request.Temperature,
            system = string.IsNullOrWhiteSpace(request.System) ? null : request.System,
            messages = Messages(request),
            tools = Tools(request.Tools)
        };

        using var response = await client.PostAsJsonAsync("/v1/messages", payload, JsonOpts, cancellationToken);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<ClaudeBedrockResponse>(JsonOpts, cancellationToken);
        stopwatch.Stop();

        var blocks = body?.Content ?? [];
        var text = string.Join("\n", blocks.Where(b => b.Type == "text" && !string.IsNullOrEmpty(b.Text)).Select(b => b.Text));

        var calls = blocks
            .Where(b => b.Type == "tool_use" && b.Name is not null)
            .Select(b => new ToolInvocation
            {
                Id = b.Id ?? Guid.NewGuid().ToString("N"),
                Name = OpenAiWire.ResolveToolName(b.Name!, request.Tools),
                Arguments = b.Input?.GetRawText() ?? "{}"
            })
            .ToList();

        return new UniversalResponse
        {
            Output = text,
            Model = model,
            Provider = provider.ProviderId,
            LatencyMs = stopwatch.ElapsedMilliseconds,
            StopReason = body?.StopReason,
            ToolCalls = calls,
            Tokens = new TokenUsage
            {
                Input = body?.Usage?.InputTokens ?? request.Input.Length / 4,
                Output = body?.Usage?.OutputTokens ?? text.Length / 4
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }

    private static List<object> Messages(UniversalRequest request)
    {
        var messages = new List<object> { new { role = "user", content = request.Input } };

        foreach (var turn in request.ToolTurns ?? [])
        {
            var assistant = new List<object>();
            if (!string.IsNullOrWhiteSpace(turn.AssistantText))
            {
                assistant.Add(new { type = "text", text = turn.AssistantText });
            }

            assistant.AddRange(turn.Calls.Select(call => new
            {
                type = "tool_use",
                id = call.Id,
                name = OpenAiWire.WireToolName(call.Name),
                input = OpenAiWire.ParseJson(call.Arguments)
            }));

            messages.Add(new { role = "assistant", content = assistant });
            messages.Add(new
            {
                role = "user",
                content = turn.Results.Select(r => new
                {
                    type = "tool_result",
                    tool_use_id = r.Id,
                    content = r.Result,
                    is_error = r.IsError
                }).ToList()
            });
        }

        return messages;
    }

    private static List<object>? Tools(List<ToolSpec>? tools) =>
        tools is not { Count: > 0 }
            ? null
            : tools.Select(t => (object)new
            {
                name = OpenAiWire.WireToolName(t.Name),
                description = t.Description,
                input_schema = OpenAiWire.ParseJson(t.InputSchema)
            }).ToList();
}

/// <summary>
/// Google Gemini generateContent. Text only for now: Gemini declares tools as
/// functionDeclarations, which is a third tool dialect and is left until it is needed.
/// </summary>
public class GeminiAdapter(IHttpClientFactory httpClientFactory)
    : HttpProviderAdapter(httpClientFactory), IProviderAdapter
{
    public ProviderKind Kind => ProviderKind.Gemini;

    public async Task<UniversalResponse> InvokeAsync(
        ProviderRegistration provider, string? apiKey, UniversalRequest request, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var client = Client(provider);

        // The key goes in a header rather than the query string, so it stays out of URLs, proxy
        // logs and anything that records a request line.
        client.DefaultRequestHeaders.Add("x-goog-api-key", apiKey);

        var model = OpenAiCompatibleAdapter.ModelName(provider, request.Model);

        var payload = new
        {
            contents = new[]
            {
                new { role = "user", parts = new[] { new { text = request.Input } } }
            },
            systemInstruction = string.IsNullOrWhiteSpace(request.System)
                ? null
                : new { parts = new[] { new { text = request.System } } },
            generationConfig = new
            {
                temperature = request.Temperature,
                maxOutputTokens = request.MaxTokens > 0 ? request.MaxTokens : 2048
            }
        };

        using var response = await client.PostAsJsonAsync(
            $"/v1beta/models/{model}:generateContent", payload, JsonOpts, cancellationToken);

        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(JsonOpts, cancellationToken);
        stopwatch.Stop();

        var text = string.Empty;
        string? finishReason = null;

        if (body.TryGetProperty("candidates", out var candidates) && candidates.GetArrayLength() > 0)
        {
            var candidate = candidates[0];
            finishReason = candidate.TryGetProperty("finishReason", out var reason) ? reason.GetString() : null;

            if (candidate.TryGetProperty("content", out var content) &&
                content.TryGetProperty("parts", out var parts))
            {
                text = string.Join("\n", parts.EnumerateArray()
                    .Where(p => p.TryGetProperty("text", out _))
                    .Select(p => p.GetProperty("text").GetString()));
            }
        }

        var usage = body.TryGetProperty("usageMetadata", out var meta) ? meta : default;

        return new UniversalResponse
        {
            Output = text,
            Model = model,
            Provider = provider.ProviderId,
            LatencyMs = stopwatch.ElapsedMilliseconds,
            StopReason = finishReason,
            Tokens = new TokenUsage
            {
                Input = usage.ValueKind == JsonValueKind.Object && usage.TryGetProperty("promptTokenCount", out var p)
                    ? p.GetInt32() : request.Input.Length / 4,
                Output = usage.ValueKind == JsonValueKind.Object && usage.TryGetProperty("candidatesTokenCount", out var c)
                    ? c.GetInt32() : text.Length / 4
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }
}

/// <summary>
/// An Ollama host registered as its own provider. Uses /api/chat rather than /api/generate,
/// because that is the endpoint that carries tools.
/// </summary>
public class OllamaAdapter(IHttpClientFactory httpClientFactory)
    : HttpProviderAdapter(httpClientFactory), IProviderAdapter
{
    public ProviderKind Kind => ProviderKind.Ollama;

    public async Task<UniversalResponse> InvokeAsync(
        ProviderRegistration provider, string? apiKey, UniversalRequest request, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var client = Client(provider);

        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        }

        var model = OpenAiCompatibleAdapter.ModelName(provider, request.Model);

        var payload = new
        {
            model,
            messages = OpenAiWire.Messages(request),
            tools = OpenAiWire.Tools(request.Tools),
            stream = false,
            options = new { temperature = request.Temperature, num_predict = request.MaxTokens > 0 ? request.MaxTokens : 2048 }
        };

        using var response = await client.PostAsJsonAsync("/api/chat", payload, JsonOpts, cancellationToken);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(JsonOpts, cancellationToken);
        stopwatch.Stop();

        var text = string.Empty;
        var calls = new List<ToolInvocation>();

        if (body.TryGetProperty("message", out var message))
        {
            text = message.TryGetProperty("content", out var content) ? content.GetString() ?? string.Empty : string.Empty;

            if (message.TryGetProperty("tool_calls", out var toolCalls) && toolCalls.ValueKind == JsonValueKind.Array)
            {
                calls.AddRange(toolCalls.EnumerateArray()
                    .Where(c => c.TryGetProperty("function", out _))
                    .Select(c =>
                    {
                        var function = c.GetProperty("function");
                        var name = function.TryGetProperty("name", out var n) ? n.GetString() ?? string.Empty : string.Empty;

                        // Ollama sends arguments as an object, not as a JSON string.
                        var arguments = function.TryGetProperty("arguments", out var a) ? a.GetRawText() : "{}";

                        return new ToolInvocation
                        {
                            Id = Guid.NewGuid().ToString("N"),
                            Name = OpenAiWire.ResolveToolName(name, request.Tools),
                            Arguments = arguments
                        };
                    }));
            }
        }

        return new UniversalResponse
        {
            Output = text,
            Model = model,
            Provider = provider.ProviderId,
            LatencyMs = stopwatch.ElapsedMilliseconds,
            ToolCalls = calls,
            Tokens = new TokenUsage
            {
                Input = body.TryGetProperty("prompt_eval_count", out var pe) ? pe.GetInt32() : request.Input.Length / 4,
                Output = body.TryGetProperty("eval_count", out var ec) ? ec.GetInt32() : text.Length / 4
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }
}
