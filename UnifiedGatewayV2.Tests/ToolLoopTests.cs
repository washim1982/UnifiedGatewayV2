using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Mcp;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// The model-driven tool loop: the model asks for a tool, the gateway runs it under the
/// application's bindings and quota, and feeds the result back.
///
/// The loop is where a model's suggestion meets the gateway's authority, so the tests are about
/// what the model cannot cause: it cannot be offered a tool the application lacks, cannot make a
/// refusal fail the request, cannot spend quota it does not have, and cannot loop forever.
/// </summary>
public class ToolLoopTests
{
    private readonly Mock<IBedrockService> _bedrock = new();
    private readonly Mock<IApplicationRegistryService> _registry = new();
    private readonly Mock<IGuardrailService> _guardrails = new();
    private readonly FakeToolCatalog _tools = new();
    private readonly List<UniversalRequest> _seen = [];
    private readonly GatewayOptions _options = new();

    public ToolLoopTests()
    {
        _guardrails
            .Setup(g => g.EvaluateAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<GuardrailActionMode?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string input, string? _, GuardrailActionMode? _, CancellationToken _) =>
                new GuardrailResult { ActionTaken = "Passed", OriginalInput = input, SanitizedInput = input });

        _guardrails
            .Setup(g => g.EvaluateOutputAsync(It.IsAny<string>(), It.IsAny<GuardrailActionMode?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string output, GuardrailActionMode? _, CancellationToken _) =>
                new GuardrailResult { ActionTaken = "Passed", OriginalInput = output, SanitizedInput = output });

        _registry
            .Setup(r => r.RecordMetricAsync(It.IsAny<RequestLogEntry>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
    }

    /// <summary>A tool plane with one read tool, which records what was asked of it.</summary>
    private sealed class FakeToolCatalog : IToolCatalog
    {
        public int Calls { get; private set; }
        public string Output { get; set; } = "ISSUE-1";
        public Exception? Throws { get; set; }

        private static readonly ToolDescriptor Search = new()
        {
            Name = "jira.search",
            ServerId = "jira",
            RemoteName = "search",
            Description = "Search issues",
            SideEffect = ToolSideEffect.Read,
            InputSchema = """{"type":"object","properties":{"q":{"type":"string"}}}"""
        };

        public Task<List<ToolDescriptor>> ListAsync(string serverId, bool refresh = false, CancellationToken cancellationToken = default) =>
            Task.FromResult(serverId == "jira" ? new List<ToolDescriptor> { Search } : []);

        public Task<List<ToolDescriptor>> ListAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new List<ToolDescriptor> { Search });

        public Task<ToolDescriptor?> FindAsync(string toolName, CancellationToken cancellationToken = default) =>
            Task.FromResult(toolName == Search.Name ? Search : null);

        public Task<ToolCallResult> ExecuteAsync(
            AppConfig app, string toolName, JsonElement arguments, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (Throws is not null)
            {
                throw Throws;
            }

            return Task.FromResult(new ToolCallResult
            {
                Tool = toolName,
                Output = Output,
                SideEffect = ToolSideEffect.Read,
                GuardrailAction = "Passed"
            });
        }
    }

    private sealed class DenyingQuota : ICallerQuota
    {
        public bool TryAcquireInvocation(string identity) => false;
        public bool TryAcquireIssuance(string identity) => false;
    }

    private ModelRouter Router(ICallerQuota? quota = null) => new(
        _bedrock.Object,
        Mock.Of<ILocalModelService>(),
        _registry.Object,
        _guardrails.Object,
        Options.Create(_options),
        NullLogger<ModelRouter>.Instance,
        capabilityService: null,
        toolCatalog: _tools,
        quota: quota);

    private void ApplicationHas(params CapabilityBinding[] bindings) =>
        _registry
            .Setup(r => r.GetAppAsync("support-bot", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig
            {
                AppId = "support-bot",
                Provider = "bedrock",
                Model = "anthropic.claude-3-haiku-20240307-v1:0",
                SystemPrompt = "You are a support assistant.",
                IsActive = true,
                Capabilities = [.. bindings]
            });

    /// <summary>Scripts the provider: each response in turn, then the last one repeatedly.</summary>
    private void ProviderReturns(params UniversalResponse[] responses)
    {
        var queue = new Queue<UniversalResponse>(responses);

        _bedrock
            .Setup(b => b.InvokeModelAsync(It.IsAny<UniversalRequest>(), It.IsAny<CancellationToken>()))
            .Callback<UniversalRequest, CancellationToken>((request, _) => _seen.Add(request))
            .ReturnsAsync(() => queue.Count > 1 ? queue.Dequeue() : queue.Peek());
    }

    private static UniversalResponse AsksForSearch(string query = "login") => new()
    {
        Output = "Let me look that up.",
        Model = "claude",
        Provider = "bedrock",
        StopReason = "tool_use",
        ToolCalls =
        [
            new ToolInvocation { Id = "call_1", Name = "jira.search", Arguments = $$"""{"q":"{{query}}"}""" }
        ]
    };

    private static UniversalResponse Answers(string text = "Issue ISSUE-1 is the cause.") => new()
    {
        Output = text,
        Model = "claude",
        Provider = "bedrock",
        StopReason = "end_turn"
    };

    private static CapabilityBinding ToolBinding(string reference = "jira.search") =>
        new() { Kind = CapabilityKind.Tool, Ref = reference, Enabled = true, MaxSideEffect = ToolSideEffect.Read };

    private static InvokeAppRequest Ask(string input = "why is login failing?") => new() { Input = input };

    // --- The happy path ----------------------------------------------------------------

    [Fact]
    public async Task AToolTheModelAsksForIsRunAndItsResultFeedsTheNextTurn()
    {
        ApplicationHas(ToolBinding());
        ProviderReturns(AsksForSearch(), Answers());

        var response = await Router().RouteAppRequestAsync("support-bot", Ask());

        Assert.Equal("Issue ISSUE-1 is the cause.", response.Output);
        Assert.Equal(1, response.ToolSteps);
        Assert.Equal(1, _tools.Calls);

        // The second call carries the completed round, so the provider sees what the tool said.
        var replay = Assert.Single(_seen[1].ToolTurns!);
        Assert.Equal("jira.search", replay.Calls.Single().Name);
        Assert.Equal("ISSUE-1", replay.Results.Single().Result);
        Assert.False(replay.Results.Single().IsError);
    }

    [Fact]
    public async Task OnlyBoundToolsAreOfferedToTheModel()
    {
        ApplicationHas(ToolBinding());
        ProviderReturns(Answers());

        await Router().RouteAppRequestAsync("support-bot", Ask());

        var offered = Assert.Single(_seen[0].Tools!);
        Assert.Equal("jira.search", offered.Name);
        Assert.Contains("\"q\"", offered.InputSchema);
    }

    [Fact]
    public async Task AnApplicationWithNoToolsIsOfferedNoneAndTheProviderIsCalledOnce()
    {
        ApplicationHas();
        ProviderReturns(Answers());

        var response = await Router().RouteAppRequestAsync("support-bot", Ask());

        Assert.Null(_seen.Single().Tools);
        Assert.Equal(0, response.ToolSteps);
        Assert.Equal(0, _tools.Calls);
    }

    [Fact]
    public async Task AToolAboveTheBindingsCeilingIsNeverOffered()
    {
        // The binding permits reads; the catalogue's tool is a read, so it is offered. Lower the
        // ceiling below the tool and it must disappear from what the model can see.
        ApplicationHas(ToolBinding() with { MaxSideEffect = (ToolSideEffect)(-1) });
        ProviderReturns(Answers());

        await Router().RouteAppRequestAsync("support-bot", Ask());

        Assert.Null(_seen.Single().Tools);
    }

    // --- What the model cannot cause ----------------------------------------------------

    [Fact]
    public async Task TheLoopStopsAtTheConfiguredLimitRatherThanRunningOn()
    {
        _options.Mcp.MaxToolSteps = 2;
        ApplicationHas(ToolBinding());
        ProviderReturns(AsksForSearch());   // never stops asking

        var response = await Router().RouteAppRequestAsync("support-bot", Ask());

        Assert.Equal("TOOL_LOOP_EXHAUSTED", response.Error?.Code);
        Assert.Equal(2, response.ToolSteps);
        Assert.Equal(2, _tools.Calls);
    }

    [Fact]
    public async Task ARefusedToolIsReportedToTheModelRatherThanFailingTheRequest()
    {
        ApplicationHas(ToolBinding());
        _tools.Throws = new ToolRefusedException("Tool 'jira.search' is not attached to application 'support-bot'.");
        ProviderReturns(AsksForSearch(), Answers("I could not look that up, but here is what I know."));

        var response = await Router().RouteAppRequestAsync("support-bot", Ask());

        Assert.Null(response.Error);
        Assert.StartsWith("I could not look that up", response.Output);

        var result = _seen[1].ToolTurns!.Single().Results.Single();
        Assert.True(result.IsError);
        Assert.Contains("Refused", result.Result);
    }

    [Fact]
    public async Task AToolCallIsRefusedWhenTheApplicationHasSpentItsQuota()
    {
        ApplicationHas(ToolBinding());
        ProviderReturns(AsksForSearch(), Answers());

        var response = await Router(new DenyingQuota()).RouteAppRequestAsync("support-bot", Ask());

        Assert.Equal(0, _tools.Calls);

        var result = _seen[1].ToolTurns!.Single().Results.Single();
        Assert.True(result.IsError);
        Assert.Contains("quota", result.Result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ArgumentsThatAreNotJsonAreRefusedWithoutCallingTheTool()
    {
        ApplicationHas(ToolBinding());
        ProviderReturns(
            AsksForSearch() with
            {
                ToolCalls = [new ToolInvocation { Id = "call_1", Name = "jira.search", Arguments = "not json" }]
            },
            Answers());

        await Router().RouteAppRequestAsync("support-bot", Ask());

        Assert.Equal(0, _tools.Calls);
        Assert.Contains("valid JSON", _seen[1].ToolTurns!.Single().Results.Single().Result);
    }
}
