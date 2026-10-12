using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Mcp;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// The tool plane: which MCP servers may be registered at all, which tools an application may
/// call, and what comes back.
///
/// This is the first subsystem where the gateway runs something it does not control on an
/// application's behalf, so the tests are mostly about refusals: wrong transport, wrong
/// destination, tool not attached, side effect above the binding's ceiling, result unfit to
/// return.
/// </summary>
public class ToolPlaneTests : IDisposable
{
    private readonly List<string> _directories = [];

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "UnifiedGatewayV2";
        public string ContentRootPath { get; set; } = ".";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    /// <summary>Stands in for a real MCP server: a fixed tool list and a scripted result.</summary>
    private sealed class FakeMcpClient : IMcpClient
    {
        public List<ToolDescriptor> Tools { get; set; } = [];
        public string Output { get; set; } = "ok";
        public bool IsError { get; set; }
        public int Calls { get; private set; }
        public string? LastRemoteName { get; private set; }

        public Task<List<ToolDescriptor>> ListToolsAsync(McpServerRegistration server, CancellationToken cancellationToken = default) =>
            Task.FromResult(Tools.Select(t => t with { ServerId = server.ServerId, Name = $"{server.ServerId}.{t.RemoteName}" }).ToList());

        public Task<(string Output, bool IsError, long LatencyMs)> CallToolAsync(
            McpServerRegistration server, string remoteName, JsonElement arguments, CancellationToken cancellationToken = default)
        {
            Calls++;
            LastRemoteName = remoteName;
            return Task.FromResult((Output, IsError, 12L));
        }
    }

    private (GatewayOptions Options, McpServerRegistry Registry) NewRegistry(
        string environment = "Production", Action<GatewayOptions>? configure = null)
    {
        var directory = Path.Combine(Path.GetTempPath(), "ugw-tools-" + Guid.NewGuid().ToString("N")[..10]);
        _directories.Add(directory);

        var options = new GatewayOptions();
        options.Storage.DataDirectory = directory;
        configure?.Invoke(options);

        return (options, new McpServerRegistry(
            Options.Create(options), new FakeEnvironment(environment), NullLogger<McpServerRegistry>.Instance));
    }

    private static CreateMcpServerRequest Server(string url, McpTransport transport = McpTransport.Http) => new()
    {
        ServerId = "jira",
        Name = "Jira",
        Description = "Issue tracker",
        Transport = transport,
        Url = url
    };

    private static ToolDescriptor Tool(string remoteName, ToolSideEffect sideEffect) => new()
    {
        RemoteName = remoteName,
        Name = $"jira.{remoteName}",
        ServerId = "jira",
        Description = $"{remoteName} tool",
        SideEffect = sideEffect
    };

    private static AppConfig AppWith(params CapabilityBinding[] bindings) => new()
    {
        AppId = "support-bot",
        SystemPrompt = "You are a support assistant.",
        Capabilities = [.. bindings]
    };

    private static CapabilityBinding Binding(CapabilityKind kind, string reference, ToolSideEffect ceiling = ToolSideEffect.Read) =>
        new() { Kind = kind, Ref = reference, Version = 1, Enabled = true, MaxSideEffect = ceiling };

    private static JsonElement Args(string json = "{}") => JsonDocument.Parse(json).RootElement.Clone();

    public void Dispose()
    {
        foreach (var directory in _directories.Where(Directory.Exists))
        {
            try { Directory.Delete(directory, recursive: true); } catch { /* best effort */ }
        }

        GC.SuppressFinalize(this);
    }

    // --- What may be registered -------------------------------------------------------

    [Fact]
    public async Task AStdioServerIsRefusedBecauseItWouldRunUnderTheGatewaysIdentity()
    {
        var (_, registry) = NewRegistry();

        var ex = await Assert.ThrowsAsync<McpServerRejectedException>(
            () => registry.CreateAsync(Server("http://localhost:9000", McpTransport.Stdio)));

        Assert.Contains("stdio", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PlainHttpToARemoteServerIsRefusedOutsideDevelopment()
    {
        var (_, registry) = NewRegistry();

        var ex = await Assert.ThrowsAsync<McpServerRejectedException>(
            () => registry.CreateAsync(Server("http://mcp.corp.internal/mcp")));

        Assert.Contains("plain HTTP", ex.Message);
    }

    [Fact]
    public async Task DevelopmentMayRegisterALoopbackServerOverPlainHttp()
    {
        var (_, registry) = NewRegistry("Development");

        var server = await registry.CreateAsync(Server("http://localhost:9000/mcp"));

        Assert.Equal("jira", server.ServerId);
        Assert.True(server.IsActive);
    }

    [Theory]
    [InlineData("https://169.254.169.254/mcp")]
    [InlineData("https://169.254.1.5/mcp")]
    public async Task ALinkLocalOrMetadataDestinationIsAlwaysRefused(string url)
    {
        var (_, registry) = NewRegistry("Development");

        var ex = await Assert.ThrowsAsync<McpServerRejectedException>(() => registry.CreateAsync(Server(url)));

        Assert.Contains("link-local", ex.Message);
    }

    [Fact]
    public async Task AHostOutsideTheOperatorsAllowlistIsRefused()
    {
        var (_, registry) = NewRegistry(configure: o => o.Mcp.AllowedHosts = ["*.corp.internal"]);

        await Assert.ThrowsAsync<McpServerRejectedException>(
            () => registry.CreateAsync(Server("https://mcp.example.com/mcp")));

        var allowed = await registry.CreateAsync(Server("https://mcp.corp.internal/mcp"));
        Assert.Equal("mcp.corp.internal", new Uri(allowed.Url).Host);
    }

    [Fact]
    public async Task ServerIdsAreNamespacesSoTheyMustBeSlugsAndUnique()
    {
        var (_, registry) = NewRegistry();

        await Assert.ThrowsAsync<McpServerRejectedException>(
            () => registry.CreateAsync(Server("https://mcp.corp.internal") with { ServerId = "Jira Cloud!" }));

        await registry.CreateAsync(Server("https://mcp.corp.internal"));
        await Assert.ThrowsAsync<McpServerRejectedException>(() => registry.CreateAsync(Server("https://mcp.corp.internal")));
    }

    // --- What an application may call -------------------------------------------------

    private async Task<(ToolCatalog Catalog, FakeMcpClient Client)> CatalogWithAsync(
        Action<GatewayOptions>? configure = null, params ToolDescriptor[] tools)
    {
        var (options, registry) = NewRegistry("Development", configure);
        await registry.CreateAsync(Server("https://mcp.corp.internal/mcp"));

        var client = new FakeMcpClient { Tools = [.. tools] };
        var guardrails = new GuardrailService(Options.Create(options), NullLogger<GuardrailService>.Instance);

        return (new ToolCatalog(registry, client, guardrails, Options.Create(options), NullLogger<ToolCatalog>.Instance), client);
    }

    [Fact]
    public async Task AToolTheApplicationDoesNotHaveIsRefusedWithoutCallingTheServer()
    {
        var (catalog, client) = await CatalogWithAsync(null, Tool("search", ToolSideEffect.Read));

        var ex = await Assert.ThrowsAsync<ToolRefusedException>(
            () => catalog.ExecuteAsync(AppWith(), "jira.search", Args()));

        Assert.Contains("not attached", ex.Message);
        Assert.Equal(0, client.Calls);
    }

    [Fact]
    public async Task AnAttachedToolIsCalledAndItsOutputReturned()
    {
        var (catalog, client) = await CatalogWithAsync(null, Tool("search", ToolSideEffect.Read));
        client.Output = "ISSUE-1: login fails";

        var result = await catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.Tool, "jira.search")), "jira.search", Args());

        Assert.Equal("ISSUE-1: login fails", result.Output);
        Assert.False(result.IsError);
        Assert.Equal("search", client.LastRemoteName);
    }

    [Fact]
    public async Task AWriteToolIsRefusedThroughAReadOnlyBinding()
    {
        var (catalog, client) = await CatalogWithAsync(null, Tool("create_issue", ToolSideEffect.Write));

        var ex = await Assert.ThrowsAsync<ToolRefusedException>(() => catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.Tool, "jira.create_issue")), "jira.create_issue", Args()));

        Assert.Contains("Write", ex.Message);
        Assert.Equal(0, client.Calls);
    }

    [Fact]
    public async Task AWriteToolRunsWhenTheBindingWasGivenThatCeiling()
    {
        var (catalog, client) = await CatalogWithAsync(null, Tool("create_issue", ToolSideEffect.Write));

        var result = await catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.Tool, "jira.create_issue", ToolSideEffect.Write)),
            "jira.create_issue", Args());

        Assert.Equal(ToolSideEffect.Write, result.SideEffect);
        Assert.Equal(1, client.Calls);
    }

    [Fact]
    public async Task AServerBindingCoversTheToolsThatServerPublishes()
    {
        var (catalog, client) = await CatalogWithAsync(null, Tool("search", ToolSideEffect.Read));

        var result = await catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.McpServer, "jira")), "jira.search", Args());

        Assert.False(result.IsError);
        Assert.Equal(1, client.Calls);
    }

    [Fact]
    public async Task OversizedArgumentsAreRefusedBeforeTheCall()
    {
        var (catalog, client) = await CatalogWithAsync(o => o.Mcp.MaxArgumentBytes = 64, Tool("search", ToolSideEffect.Read));

        var big = Args($$"""{"q":"{{new string('x', 200)}}"}""");

        await Assert.ThrowsAsync<ToolRefusedException>(() => catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.Tool, "jira.search")), "jira.search", big));

        Assert.Equal(0, client.Calls);
    }

    // --- What comes back ---------------------------------------------------------------

    [Fact]
    public async Task ASecretInAToolResultIsRedactedBeforeTheCallerSeesIt()
    {
        var (catalog, client) = await CatalogWithAsync(null, Tool("search", ToolSideEffect.Read));
        client.Output = "the key is AKIAIOSFODNN7EXAMPLE";

        var result = await catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.Tool, "jira.search")), "jira.search", Args());

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", result.Output);
        Assert.Contains("[REDACTED_AWS_KEY]", result.Output);
        Assert.Equal("Redacted", result.GuardrailAction);
    }

    [Fact]
    public async Task AToolResultTheGuardrailsBlockIsNotReturnedAtAll()
    {
        var (catalog, client) = await CatalogWithAsync(
            o => o.Guardrails.OutputScanning.Mode = GuardrailActionMode.Block,
            Tool("search", ToolSideEffect.Read));

        client.Output = "card 4012888888881881";

        var result = await catalog.ExecuteAsync(
            AppWith(Binding(CapabilityKind.Tool, "jira.search")), "jira.search", Args());

        Assert.Empty(result.Output);
        Assert.True(result.IsError);
        Assert.Equal("Blocked", result.GuardrailAction);
    }

    // --- Attaching tools ----------------------------------------------------------------

    private async Task<(CapabilityService Capabilities, ToolCatalog Catalog)> CapabilitiesWithAsync(params ToolDescriptor[] tools)
    {
        var directory = Path.Combine(Path.GetTempPath(), "ugw-cap-" + Guid.NewGuid().ToString("N")[..10]);
        _directories.Add(directory);

        var options = new GatewayOptions();
        options.Storage.DataDirectory = directory;

        var registry = new McpServerRegistry(
            Options.Create(options), new FakeEnvironment("Development"), NullLogger<McpServerRegistry>.Instance);
        await registry.CreateAsync(Server("https://mcp.corp.internal/mcp"));

        var guardrails = new GuardrailService(Options.Create(options), NullLogger<GuardrailService>.Instance);
        var catalog = new ToolCatalog(
            registry, new FakeMcpClient { Tools = [.. tools] }, guardrails,
            Options.Create(options), NullLogger<ToolCatalog>.Instance);

        var skills = new SkillRegistryService(Options.Create(options), guardrails, NullLogger<SkillRegistryService>.Instance);

        return (new CapabilityService(skills, NullLogger<CapabilityService>.Instance, registry, catalog), catalog);
    }

    [Fact]
    public async Task AttachingAWriteToolNeedsTheCeilingStatedExplicitly()
    {
        var (capabilities, _) = await CapabilitiesWithAsync(Tool("create_issue", ToolSideEffect.Write));

        var ex = await Assert.ThrowsAsync<CapabilityRejectedException>(() => capabilities.ResolveAttachmentAsync(
            AppWith(), new AttachCapabilityRequest { Kind = CapabilityKind.Tool, Ref = "jira.create_issue" }, "operator"));

        Assert.Contains("maxSideEffect", ex.Message);

        var binding = await capabilities.ResolveAttachmentAsync(
            AppWith(),
            new AttachCapabilityRequest
            {
                Kind = CapabilityKind.Tool,
                Ref = "jira.create_issue",
                MaxSideEffect = ToolSideEffect.Write
            },
            "operator");

        Assert.Equal(ToolSideEffect.Write, binding.MaxSideEffect);
    }

    [Fact]
    public async Task AToolNoServerPublishesCannotBeAttached()
    {
        var (capabilities, _) = await CapabilitiesWithAsync(Tool("search", ToolSideEffect.Read));

        await Assert.ThrowsAsync<CapabilityRejectedException>(() => capabilities.ResolveAttachmentAsync(
            AppWith(), new AttachCapabilityRequest { Kind = CapabilityKind.Tool, Ref = "jira.delete_everything" }, null));
    }

    [Fact]
    public async Task AnMcpServerCanBeAttachedAndResolvesAsUsable()
    {
        var (capabilities, _) = await CapabilitiesWithAsync(Tool("search", ToolSideEffect.Read));

        var binding = await capabilities.ResolveAttachmentAsync(
            AppWith(), new AttachCapabilityRequest { Kind = CapabilityKind.McpServer, Ref = "jira" }, "operator");

        var effective = await capabilities.EffectiveAsync(AppWith(binding));

        Assert.True(effective.Single().Usable);
        Assert.Equal("Jira", effective.Single().Name);
    }
}
