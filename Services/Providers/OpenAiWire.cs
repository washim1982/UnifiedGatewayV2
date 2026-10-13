using System.Text.Json;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Providers;

/// <summary>
/// The OpenAI chat-completions wire format, shared by every server that speaks it: OpenAI itself,
/// Groq, vLLM, LM Studio and llama.cpp.
///
/// It lives here rather than in one caller because the gateway now speaks this shape from two
/// places -- the configured local providers and the registered cloud ones -- and two copies of a
/// message-history builder drift apart quietly.
/// </summary>
public static class OpenAiWire
{
    /// <summary>
    /// Function names allow [a-zA-Z0-9_-], while gateway tools are namespaced <c>server.tool</c>.
    /// The dot is encoded on the way out and matched against the offered list on the way back, so
    /// nothing is parsed in reverse.
    /// </summary>
    public static string WireToolName(string toolName) => toolName.Replace(".", "__");

    public static string ResolveToolName(string wireName, List<ToolSpec>? offered) =>
        offered?.FirstOrDefault(t => WireToolName(t.Name) == wireName)?.Name ?? wireName.Replace("__", ".");

    public static List<OpenAiTool>? Tools(List<ToolSpec>? tools) =>
        tools is not { Count: > 0 }
            ? null
            : tools.Select(t => new OpenAiTool
            {
                Function = new OpenAiFunction
                {
                    Name = WireToolName(t.Name),
                    Description = t.Description,
                    Parameters = ParseJson(t.InputSchema)
                }
            }).ToList();

    /// <summary>A schema a provider published, or an empty object when it is unusable.</summary>
    public static JsonElement ParseJson(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            using var fallback = JsonDocument.Parse("""{"type":"object"}""");
            return fallback.RootElement.Clone();
        }
    }

    /// <summary>
    /// The conversation: system, the caller's input, then one assistant turn per completed tool
    /// round with a tool message per result. The gateway owns this history, so a refused round is
    /// still represented honestly.
    /// </summary>
    public static List<OpenAiChatMessage> Messages(UniversalRequest request)
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

    /// <summary>Turns one chat completion into the gateway's own response shape.</summary>
    public static UniversalResponse ToResponse(
        OpenAiChatResponse? completion, UniversalRequest request, string model, string provider, long latencyMs)
    {
        var choice = completion?.Choices?.FirstOrDefault();
        var text = choice?.Message?.Content ?? string.Empty;

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
            Output = text,
            Model = model,
            Provider = provider,
            LatencyMs = latencyMs,
            StopReason = choice?.FinishReason,
            ToolCalls = calls,
            Tokens = new TokenUsage
            {
                Input = completion?.Usage?.PromptTokens ?? request.Input.Length / 4,
                Output = completion?.Usage?.CompletionTokens ?? text.Length / 4
            },
            AppId = request.Metadata?.AppId,
            SessionId = request.Metadata?.SessionId
        };
    }
}
