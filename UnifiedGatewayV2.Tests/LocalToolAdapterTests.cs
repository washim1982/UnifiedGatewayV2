using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// The OpenAI-compatible wire format for tools, as LM Studio speaks it.
///
/// Two things have to survive the round trip: a namespaced gateway tool name, which the format
/// does not allow verbatim, and a completed tool round replayed as message history.
/// </summary>
public class LocalToolAdapterTests
{
    private sealed class CannedBackend(string responseJson) : HttpMessageHandler
    {
        public string? RequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("http://localhost:1234") };
    }

    private static LocalModelService Service(CannedBackend backend) =>
        new(new SingleClientFactory(backend), Options.Create(new GatewayOptions()), NullLogger<LocalModelService>.Instance);

    private static readonly ToolSpec Search = new()
    {
        Name = "jira.search",
        Description = "Search issues",
        InputSchema = """{"type":"object","properties":{"q":{"type":"string"}}}"""
    };

    private const string ToolCallResponse = """
    {
      "id": "chatcmpl-1",
      "model": "qwen",
      "choices": [{
        "index": 0,
        "finish_reason": "tool_calls",
        "message": {
          "role": "assistant",
          "content": "",
          "tool_calls": [{
            "id": "call_7",
            "type": "function",
            "function": { "name": "jira__search", "arguments": "{\"q\":\"login\"}" }
          }]
        }
      }],
      "usage": { "prompt_tokens": 11, "completion_tokens": 7 }
    }
    """;

    [Fact]
    public async Task ToolsAreOfferedWithADotFreeNameAndTheCallComesBackNamespaced()
    {
        var backend = new CannedBackend(ToolCallResponse);

        var response = await Service(backend).InvokeLocalModelAsync(new UniversalRequest
        {
            Model = "lmstudio/qwen",
            Input = "why is login failing?",
            Tools = [Search]
        });

        // Offered: the format allows no dots, so the namespace is encoded.
        Assert.Contains("\"tools\"", backend.RequestBody);
        Assert.Contains("jira__search", backend.RequestBody);
        Assert.DoesNotContain("\"jira.search\"", backend.RequestBody);

        // Returned: matched back to the gateway's own name, so the tool plane recognises it.
        var call = Assert.Single(response.ToolCalls);
        Assert.Equal("jira.search", call.Name);
        Assert.Equal("call_7", call.Id);
        Assert.Contains("login", call.Arguments);
        Assert.Equal("tool_calls", response.StopReason);
    }

    [Fact]
    public async Task ACompletedRoundIsReplayedAsAssistantAndToolMessages()
    {
        var backend = new CannedBackend("""
        {"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ISSUE-1 is the cause."}}]}
        """);

        var response = await Service(backend).InvokeLocalModelAsync(new UniversalRequest
        {
            Model = "lmstudio/qwen",
            Input = "why is login failing?",
            Tools = [Search],
            ToolTurns =
            [
                new ToolTurn
                {
                    AssistantText = "Looking that up.",
                    Calls = [new ToolInvocation { Id = "call_7", Name = "jira.search", Arguments = """{"q":"login"}""" }],
                    Results = [new ToolExchange { Id = "call_7", Name = "jira.search", Result = "ISSUE-1" }]
                }
            ]
        });

        Assert.Contains("\"role\":\"assistant\"", backend.RequestBody);
        Assert.Contains("\"tool_call_id\":\"call_7\"", backend.RequestBody);
        Assert.Contains("\"role\":\"tool\"", backend.RequestBody);
        Assert.Contains("ISSUE-1", backend.RequestBody);

        Assert.Equal("ISSUE-1 is the cause.", response.Output);
        Assert.Empty(response.ToolCalls);
    }

    [Fact]
    public async Task AnApplicationWithNoToolsSendsNoToolsField()
    {
        var backend = new CannedBackend("""
        {"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello"}}]}
        """);

        await Service(backend).InvokeLocalModelAsync(new UniversalRequest { Model = "lmstudio/qwen", Input = "hi" });

        Assert.DoesNotContain("\"tools\"", backend.RequestBody);
    }
}
