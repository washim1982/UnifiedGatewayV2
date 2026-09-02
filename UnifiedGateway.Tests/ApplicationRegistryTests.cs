using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using Xunit;

namespace UnifiedGateway.Tests;

public class ApplicationRegistryTests
{
    private readonly ApplicationRegistryService _registryService;
    private readonly ISecurityService _securityService;
    private readonly GatewayOptions _options;

    public ApplicationRegistryTests()
    {
        var dataProtectionProvider = new EphemeralDataProtectionProvider();
        _securityService = new SecurityService(dataProtectionProvider, NullLogger<SecurityService>.Instance);

        var tempDir = Path.Combine(Path.GetTempPath(), "ug-tests-" + Guid.NewGuid().ToString("N"));
        _options = new GatewayOptions
        {
            Security = new SecurityOptions
            {
                AdminApiKey = "ug-test-admin-secret-key",
                EnforceAppApiKey = true
            },
            Storage = new StorageOptions
            {
                DataDirectory = tempDir,
                RegistryFileName = "test_registry.json"
            }
        };

        _registryService = new ApplicationRegistryService(
            _securityService,
            Options.Create(_options),
            NullLogger<ApplicationRegistryService>.Instance);
    }

    [Fact]
    public async Task CreateApp_GeneratesKeyAndPersistsApp()
    {
        var createReq = new CreateAppRequest
        {
            AppId = "unit-test-app",
            Name = "Unit Test App",
            Provider = "bedrock",
            Model = "anthropic.claude-3-5-sonnet-20240620-v1:0",
            SystemPrompt = "Test prompt",
            Temperature = 0.4,
            MaxTokens = 1000
        };

        var response = await _registryService.CreateAppAsync(createReq);

        Assert.NotNull(response);
        Assert.Equal("unit-test-app", response.App.AppId);
        Assert.StartsWith("ug_live_", response.ApiKey);
        Assert.Equal("/gateway/unit-test-app/invoke", response.EndpointUrl);
        Assert.StartsWith("ug_sts_", response.StsToken);
        Assert.True(response.StsExpiresAt > DateTimeOffset.UtcNow);

        var retrieved = await _registryService.GetAppAsync("unit-test-app");
        Assert.NotNull(retrieved);
        Assert.Equal("Unit Test App", retrieved.Name);
    }

    [Fact]
    public async Task AuthenticateApp_ValidatesCorrectKey()
    {
        var createReq = new CreateAppRequest
        {
            AppId = "auth-test-app",
            Name = "Auth Test App",
            Provider = "local",
            Model = "ollama/llama3"
        };

        var created = await _registryService.CreateAppAsync(createReq);

        var (isValidCorrect, app) = await _registryService.AuthenticateAppAsync("auth-test-app", created.ApiKey);
        Assert.True(isValidCorrect);
        Assert.NotNull(app);

        var (isValidWrong, _) = await _registryService.AuthenticateAppAsync("auth-test-app", "invalid-key");
        Assert.False(isValidWrong);
    }

    [Fact]
    public async Task AuthenticateApp_WithAppStsToken_Succeeds()
    {
        var createReq = new CreateAppRequest
        {
            AppId = "sts-auth-app",
            Name = "STS Auth App",
            Provider = "bedrock",
            Model = "anthropic.claude-3-5-sonnet-20240620-v1:0"
        };

        var created = await _registryService.CreateAppAsync(createReq);

        // Authenticate using the generated initial STS token
        var (isValidSts, app) = await _registryService.AuthenticateAppAsync("sts-auth-app", created.StsToken);
        Assert.True(isValidSts);
        Assert.NotNull(app);
        Assert.Equal("sts-auth-app", app.AppId);
    }

    [Fact]
    public async Task AuthenticateApp_WithWrongAppStsToken_RejectsCrossAppUsage()
    {
        var app1 = await _registryService.CreateAppAsync(new CreateAppRequest { AppId = "app-one", Name = "App One" });
        var app2 = await _registryService.CreateAppAsync(new CreateAppRequest { AppId = "app-two", Name = "App Two" });

        // Attempt to invoke app-two using app-one's STS token
        var (isValid, _) = await _registryService.AuthenticateAppAsync("app-two", app1.StsToken);
        Assert.False(isValid);
    }

    [Fact]
    public async Task AuthenticateApp_WithAdminStsToken_AuthenticatesAnyApp()
    {
        await _registryService.CreateAppAsync(new CreateAppRequest { AppId = "target-app", Name = "Target App" });

        var (adminToken, _) = _securityService.IssueAppStsToken("*", TimeSpan.FromMinutes(30), "invoke", isAdmin: true);

        var (isValid, app) = await _registryService.AuthenticateAppAsync("target-app", adminToken);
        Assert.True(isValid);
        Assert.NotNull(app);
    }

    [Fact]
    public async Task IssueStsTokenForAppAsync_WithValidApiKey_ReturnsValidStsToken()
    {
        var created = await _registryService.CreateAppAsync(new CreateAppRequest
        {
            AppId = "exchange-app",
            Name = "Exchange Test App"
        });

        var tokenResp = await _registryService.IssueStsTokenForAppAsync(
            appId: "exchange-app",
            apiKey: created.ApiKey,
            durationSeconds: 1800,
            scope: "invoke",
            callerId: "service-worker-42");

        Assert.NotNull(tokenResp);
        Assert.StartsWith("ug_sts_", tokenResp.Token);
        Assert.Equal("exchange-app", tokenResp.AppId);
        Assert.Equal(1800, tokenResp.DurationSeconds);
        Assert.False(tokenResp.IsAdmin);

        // Verify the newly exchanged STS token works for authentication
        var (isValid, _) = await _registryService.AuthenticateAppAsync("exchange-app", tokenResp.Token);
        Assert.True(isValid);
    }

    [Fact]
    public async Task IssueStsTokenForAppAsync_WithAdminKey_ReturnsAdminStsToken()
    {
        var tokenResp = await _registryService.IssueStsTokenForAppAsync(
            appId: "*",
            apiKey: "ug-test-admin-secret-key",
            durationSeconds: 3600);

        Assert.NotNull(tokenResp);
        Assert.StartsWith("ug_sts_", tokenResp.Token);
        Assert.True(tokenResp.IsAdmin);
        Assert.Equal("*", tokenResp.AppId);
    }

    [Fact]
    public async Task IssueStsTokenForAppAsync_WithInvalidKey_ReturnsNull()
    {
        var tokenResp = await _registryService.IssueStsTokenForAppAsync(
            appId: "any-app",
            apiKey: "wrong-secret-key",
            durationSeconds: 3600);

        Assert.Null(tokenResp);
    }

    [Fact]
    public async Task RotateApiKey_IssuesNewKeyAndInvalidatesPrevious()
    {
        var created = await _registryService.CreateAppAsync(new CreateAppRequest
        {
            AppId = "rotate-app",
            Name = "Rotate App"
        });

        var oldKey = created.ApiKey;
        var (oldWorksBefore, _) = await _registryService.AuthenticateAppAsync("rotate-app", oldKey);
        Assert.True(oldWorksBefore);

        var newKey = await _registryService.RotateApiKeyAsync("rotate-app");

        Assert.NotNull(newKey);
        Assert.StartsWith("ug_live_", newKey);
        Assert.NotEqual(oldKey, newKey);

        // The rotated key authenticates; the previous one no longer does.
        var (newWorks, app) = await _registryService.AuthenticateAppAsync("rotate-app", newKey);
        Assert.True(newWorks);
        Assert.NotNull(app);

        var (oldWorksAfter, _) = await _registryService.AuthenticateAppAsync("rotate-app", oldKey);
        Assert.False(oldWorksAfter);
    }

    [Fact]
    public async Task RotateApiKey_ForUnknownApp_ReturnsNull()
    {
        var result = await _registryService.RotateApiKeyAsync("no-such-app");
        Assert.Null(result);
    }

    [Fact]
    public async Task AuditTrail_PersistsAcrossRestart()
    {
        await _registryService.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "audit-app",
            Model = "anthropic.claude-3-haiku-20240307-v1:0",
            Provider = "bedrock",
            LatencyMs = 42,
            InputTokens = 7,
            OutputTokens = 11,
            Success = true,
            GuardrailAction = "Passed",
            OutputGuardrailAction = "Redacted"
        });

        // Simulate a process restart: a fresh service over the same data directory.
        var restarted = new ApplicationRegistryService(
            _securityService,
            Options.Create(_options),
            NullLogger<ApplicationRegistryService>.Instance);

        var summary = await restarted.GetMetricsSummaryAsync();

        var entry = Assert.Single(summary.RecentLogs, l => l.AppId == "audit-app");
        Assert.Equal(42, entry.LatencyMs);
        Assert.Equal(18, entry.TotalTokens);
        Assert.Equal("Redacted", entry.OutputGuardrailAction);
        Assert.Equal(1, summary.OutputGuardrailRedactedCount);
    }

    [Fact]
    public async Task UpdateApp_IncrementsVersionAndAppendsHistory()
    {
        var createReq = new CreateAppRequest
        {
            AppId = "version-test-app",
            Name = "Version Test App",
            SystemPrompt = "Version 1 prompt"
        };

        var created = await _registryService.CreateAppAsync(createReq);
        Assert.Equal(1, created.App.Version);

        var updated = await _registryService.UpdateAppAsync("version-test-app", new UpdateAppRequest
        {
            SystemPrompt = "Version 2 prompt with refinements"
        });

        Assert.NotNull(updated);
        Assert.Equal(2, updated.Version);
        Assert.Equal("Version 2 prompt with refinements", updated.SystemPrompt);
        Assert.Single(updated.VersionHistory);
        Assert.Equal("Version 1 prompt", updated.VersionHistory[0].SystemPrompt);
    }
}
