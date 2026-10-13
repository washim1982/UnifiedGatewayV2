using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Providers;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// Model providers configured at runtime: OpenAI, Anthropic, Gemini, Ollama hosts and Bedrock.
///
/// The property that matters most is that a key entered once never comes back out: it goes to the
/// secret store, and the registry keeps a name and four characters. The rest is about refusing a
/// destination the gateway should not send prompts to.
/// </summary>
public class ProviderTests : IDisposable
{
    private readonly List<string> _directories = [];

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "UnifiedGatewayV2";
        public string ContentRootPath { get; set; } = ".";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    private (ProviderRegistry Registry, InMemorySecretsProvider Secrets, string Directory) NewRegistry(
        string environment = "Production")
    {
        var directory = Path.Combine(Path.GetTempPath(), "ugw-prov-" + Guid.NewGuid().ToString("N")[..10]);
        _directories.Add(directory);

        var options = new GatewayOptions();
        options.Storage.DataDirectory = directory;

        var secrets = new InMemorySecretsProvider();
        return (new ProviderRegistry(
            Options.Create(options), secrets, new FakeEnvironment(environment), NullLogger<ProviderRegistry>.Instance),
            secrets, directory);
    }

    private static CreateProviderRequest OpenAi(string? apiKey = "sk-test-abcd1234") => new()
    {
        ProviderId = "openai",
        Name = "OpenAI",
        Kind = ProviderKind.OpenAiCompatible,
        BaseUrl = "https://api.openai.com",
        ApiKey = apiKey,
        Models = ["gpt-4o", "gpt-4o-mini"],
        DefaultModel = "gpt-4o"
    };

    public void Dispose()
    {
        foreach (var directory in _directories.Where(Directory.Exists))
        {
            try { Directory.Delete(directory, recursive: true); } catch { /* best effort */ }
        }

        GC.SuppressFinalize(this);
    }

    // --- The credential ----------------------------------------------------------------

    [Fact]
    public async Task AnApiKeyGoesToTheSecretStoreAndOnlyAHintIsKept()
    {
        var (registry, secrets, _) = NewRegistry();

        var provider = await registry.CreateAsync(OpenAi());

        Assert.Equal("/gateway/providers/openai/api-key", provider.ApiKeySecretName);
        Assert.Equal("1234", provider.ApiKeyHint);
        Assert.Equal("sk-test-abcd1234", await secrets.GetSecretAsync(provider.ApiKeySecretName));

        // The registration itself carries nothing usable.
        Assert.DoesNotContain("sk-test", System.Text.Json.JsonSerializer.Serialize(provider));
    }

    [Fact]
    public async Task TheKeyIsNeverWrittenToTheRegistryFile()
    {
        var (registry, _, directory) = NewRegistry();
        await registry.CreateAsync(OpenAi());

        var onDisk = await File.ReadAllTextAsync(Path.Combine(directory, "providers.json"));

        Assert.DoesNotContain("sk-test-abcd1234", onDisk);
        Assert.Contains("/gateway/providers/openai/api-key", onDisk);
    }

    [Fact]
    public async Task SupplyingANewKeyRotatesTheStoredSecret()
    {
        var (registry, secrets, _) = NewRegistry();
        await registry.CreateAsync(OpenAi());

        var updated = await registry.UpdateAsync("openai", new UpdateProviderRequest { ApiKey = "sk-live-wxyz9876" });

        Assert.Equal("9876", updated!.ApiKeyHint);
        Assert.Equal("sk-live-wxyz9876", await secrets.GetSecretAsync(updated.ApiKeySecretName));
    }

    [Fact]
    public async Task AnUpdateWithoutAKeyLeavesTheStoredOneAlone()
    {
        var (registry, secrets, _) = NewRegistry();
        await registry.CreateAsync(OpenAi());

        var updated = await registry.UpdateAsync("openai", new UpdateProviderRequest { Name = "OpenAI (prod)" });

        Assert.Equal("1234", updated!.ApiKeyHint);
        Assert.Equal("sk-test-abcd1234", await secrets.GetSecretAsync(updated.ApiKeySecretName));
    }

    // --- Where prompts may be sent -------------------------------------------------------

    [Fact]
    public async Task PlainHttpToARemoteProviderIsRefused()
    {
        var (registry, _, _) = NewRegistry();

        var ex = await Assert.ThrowsAsync<ProviderRejectedException>(() => registry.CreateAsync(
            OpenAi() with { ProviderId = "selfhosted", BaseUrl = "http://llm.corp.internal" }));

        Assert.Contains("plain HTTP", ex.Message);
    }

    [Fact]
    public async Task DevelopmentMayRegisterALoopbackServerWithNoKey()
    {
        var (registry, _, _) = NewRegistry("Development");

        var provider = await registry.CreateAsync(new CreateProviderRequest
        {
            ProviderId = "lmstudio",
            Kind = ProviderKind.OpenAiCompatible,
            BaseUrl = "http://localhost:1234",
            Models = ["qwen/qwen3.8-27b"]
        });

        Assert.True(provider.IsActive);
        Assert.Empty(provider.ApiKeySecretName);
    }

    [Fact]
    public async Task ARemoteProviderThatAuthenticatesWithAKeyMustBeGivenOne()
    {
        var (registry, _, _) = NewRegistry();

        var ex = await Assert.ThrowsAsync<ProviderRejectedException>(
            () => registry.CreateAsync(OpenAi(apiKey: null)));

        Assert.Contains("apiKey", ex.Message);
    }

    [Theory]
    [InlineData(ProviderKind.Ollama, "http://ollama.lab:11434")]
    [InlineData(ProviderKind.Bedrock, "")]
    public async Task ProvidersThatDoNotUseAKeyNeedNone(ProviderKind kind, string baseUrl)
    {
        // Development, because an Ollama host on plain HTTP is a development arrangement.
        var (registry, _, _) = NewRegistry("Development");

        var provider = await registry.CreateAsync(new CreateProviderRequest
        {
            ProviderId = kind.ToString().ToLowerInvariant(),
            Kind = kind,
            BaseUrl = baseUrl,
            DefaultModel = "any"
        });

        Assert.Empty(provider.ApiKeySecretName);
    }

    [Fact]
    public async Task AnthropicAndGeminiGetTheirWellKnownEndpointsWithoutBeingTold()
    {
        var (registry, _, _) = NewRegistry();

        var claude = await registry.CreateAsync(new CreateProviderRequest
        {
            ProviderId = "claude", Kind = ProviderKind.Anthropic, ApiKey = "sk-ant-0001", DefaultModel = "claude-sonnet-4"
        });

        var gemini = await registry.CreateAsync(new CreateProviderRequest
        {
            ProviderId = "gemini", Kind = ProviderKind.Gemini, ApiKey = "AIza-0002", DefaultModel = "gemini-2.5-pro"
        });

        Assert.Equal("https://api.anthropic.com", claude.BaseUrl);
        Assert.Equal("https://generativelanguage.googleapis.com", gemini.BaseUrl);
    }

    [Theory]
    [InlineData("Open AI")]
    [InlineData("o")]
    public async Task AProviderIdMustBeASlugBecauseApplicationsRouteOnIt(string providerId)
    {
        var (registry, _, _) = NewRegistry();

        await Assert.ThrowsAsync<ProviderRejectedException>(
            () => registry.CreateAsync(OpenAi() with { ProviderId = providerId }));
    }

    [Fact]
    public async Task ADuplicateProviderIdIsRefused()
    {
        var (registry, _, _) = NewRegistry();
        await registry.CreateAsync(OpenAi());

        await Assert.ThrowsAsync<ProviderRejectedException>(() => registry.CreateAsync(OpenAi()));
    }

    // --- Routing --------------------------------------------------------------------------

    [Theory]
    [InlineData("openai/gpt-4o", "gpt-4o")]
    [InlineData("gpt-4o", "gpt-4o")]
    [InlineData("", "gpt-4o")]
    public void AModelMayBeNamedWithOrWithoutItsProviderPrefix(string requested, string expected)
    {
        var provider = new ProviderRegistration { ProviderId = "openai", DefaultModel = "gpt-4o" };

        Assert.Equal(expected, OpenAiCompatibleAdapter.ModelName(provider, requested));
    }

    [Fact]
    public async Task AnUnregisteredProviderIsRefusedRatherThanSentToBedrock()
    {
        // SEC-09: a typo in an application's provider used to reach Bedrock, crossing a
        // data-residency boundary and spending money.
        var registry = new Mock<IApplicationRegistryService>();
        registry
            .Setup(r => r.GetAppAsync("app", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { AppId = "app", Provider = "opanai", Model = "gpt-4o", IsActive = true });
        registry
            .Setup(r => r.RecordMetricAsync(It.IsAny<RequestLogEntry>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var guardrails = new Mock<IGuardrailService>();
        guardrails
            .Setup(g => g.EvaluateAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<GuardrailActionMode?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string input, string? _, GuardrailActionMode? _, CancellationToken _) =>
                new GuardrailResult { ActionTaken = "Passed", OriginalInput = input, SanitizedInput = input });

        var bedrock = new Mock<IBedrockService>();
        var dispatcher = new Mock<IProviderDispatcher>();
        dispatcher
            .Setup(d => d.TryInvokeAsync(It.IsAny<string>(), It.IsAny<UniversalRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UniversalResponse?)null);

        var router = new ModelRouter(
            bedrock.Object, Mock.Of<ILocalModelService>(), registry.Object, guardrails.Object,
            Options.Create(new GatewayOptions()), NullLogger<ModelRouter>.Instance,
            providerDispatcher: dispatcher.Object);

        var response = await router.RouteAppRequestAsync("app", new InvokeAppRequest { Input = "hello" });

        Assert.Equal("UNKNOWN_PROVIDER", response.Error?.Code);
        bedrock.Verify(b => b.InvokeModelAsync(It.IsAny<UniversalRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
