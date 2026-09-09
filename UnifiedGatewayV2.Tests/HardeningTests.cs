using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Startup;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// One test per hardening control, so a regression shows up as a named failure rather than
/// as a quietly reopened hole.
/// </summary>
public class HardeningTests
{
    private static GatewayOptions GatewayOptionsWith(Action<SecurityOptions>? configure = null)
    {
        var options = new GatewayOptions();
        configure?.Invoke(options.Security);
        return options;
    }

    // --- H4: rotation revokes outstanding tokens ---------------------------------

    [Fact]
    public async Task RotatingTheSigningKey_InvalidatesTokensIssuedBeforeIt()
    {
        var (security, signingKeys) = TestFactory.CreateSecurityService();

        var (token, _) = await security.IssueAppStsTokenAsync("app-a", TimeSpan.FromMinutes(30));
        var (validBefore, _, _) = await security.ValidateAppStsTokenAsync(token);
        Assert.True(validBefore);

        await signingKeys.RotateAsync();

        var (validAfter, _, reason) = await security.ValidateAppStsTokenAsync(token);
        Assert.False(validAfter);
        Assert.NotNull(reason);
    }

    [Fact]
    public async Task TokensIssuedAfterRotation_CarryTheNewGeneration()
    {
        var (security, signingKeys) = TestFactory.CreateSecurityService();

        await signingKeys.RotateAsync();
        var (token, _) = await security.IssueAppStsTokenAsync("app-a", TimeSpan.FromMinutes(30));

        var (isValid, payload, _) = await security.ValidateAppStsTokenAsync(token);
        Assert.True(isValid);
        Assert.Equal(2, payload!.Generation);
    }

    // --- H4: targeted revocation --------------------------------------------------

    [Fact]
    public async Task RevokedToken_IsRejectedWhileItWouldOtherwiseStillBeValid()
    {
        var (security, _) = TestFactory.CreateSecurityService();

        var (token, expiresAt) = await security.IssueAppStsTokenAsync("app-a", TimeSpan.FromMinutes(30));
        var (_, payload, _) = await security.ValidateAppStsTokenAsync(token);

        security.RevokeToken(payload!.Jti, expiresAt);

        var (isValid, _, reason) = await security.ValidateAppStsTokenAsync(token);
        Assert.False(isValid);
        Assert.Contains("revoked", reason, StringComparison.OrdinalIgnoreCase);
    }

    // --- Token lifetime ceiling ---------------------------------------------------

    [Fact]
    public async Task RequestedLifetime_IsClampedToTheConfiguredCeiling()
    {
        var options = GatewayOptionsWith(s => s.MaxStsTokenLifetimeSeconds = 3600);
        var (security, _) = TestFactory.CreateSecurityService(options);

        var (_, expiresAt) = await security.IssueAppStsTokenAsync("app-a", TimeSpan.FromDays(7));

        var lifetime = expiresAt - DateTimeOffset.UtcNow;
        Assert.True(lifetime <= TimeSpan.FromSeconds(3601), $"Lifetime was {lifetime}, expected <= 1 hour.");
    }

    // --- Tamper resistance ---------------------------------------------------------

    [Fact]
    public async Task TamperedPayload_FailsSignatureVerification()
    {
        var (security, _) = TestFactory.CreateSecurityService();
        var (token, _) = await security.IssueAppStsTokenAsync("app-a", TimeSpan.FromMinutes(30), isAdmin: false);

        // Flip a character inside the payload segment.
        var body = token["ug_sts_".Length..];
        var parts = body.Split('.', 2);
        var tampered = "ug_sts_" + parts[0][..^1] + (parts[0][^1] == 'A' ? 'B' : 'A') + "." + parts[1];

        var (isValid, _, _) = await security.ValidateAppStsTokenAsync(tampered);
        Assert.False(isValid);
    }

    // --- H6: guardrail ReDoS resistance --------------------------------------------

    [Fact]
    public async Task PathologicalInput_IsScannedWithinABoundedTime()
    {
        var guardrails = new GuardrailService(
            Options.Create(new GatewayOptions()),
            NullLogger<GuardrailService>.Instance);

        // A long run of digits and separators is the shape that makes the credit-card
        // candidate pattern backtrack. It must return, not hang.
        var hostile = string.Concat(Enumerable.Repeat("4 ", 20_000)) + "!";

        var stopwatch = Stopwatch.StartNew();
        var result = await guardrails.EvaluateAsync(hostile);
        stopwatch.Stop();

        Assert.NotNull(result);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(15),
            $"Guardrail scan took {stopwatch.Elapsed}, which suggests unbounded backtracking.");
    }

    [Fact]
    public async Task ScanTimeout_IsTreatedAsAViolationRatherThanAPass()
    {
        var guardrails = new GuardrailService(
            Options.Create(new GatewayOptions()),
            NullLogger<GuardrailService>.Instance);

        var hostile = string.Concat(Enumerable.Repeat("4 ", 20_000)) + "!";
        var result = await guardrails.EvaluateAsync(hostile);

        // Either the detectors completed (and may or may not have found anything), or they
        // timed out — in which case the input must NOT have been reported as clean.
        if (result.Violations.Any(v => v.RuleName == "ScanTimeout"))
        {
            Assert.NotEqual("Passed", result.ActionTaken);
        }
    }

    // --- H1: startup refuses insecure configuration ---------------------------------

    private sealed class FakeEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "UnifiedGatewayV2";
        public string ContentRootPath { get; set; } = ".";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    [Theory]
    [InlineData("ug-admin-secret-key-change-in-production")]
    [InlineData("ug-admin-default-change-in-prod")]
    [InlineData("ug-dev-admin-key")]
    public void Startup_RefusesAKnownDefaultAdminKey(string defaultKey)
    {
        var gateway = new GatewayOptions();
        gateway.Security.AdminApiKey = defaultKey;

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, new CloudOptions(), new FakeEnvironment()));

        Assert.Contains("AdminApiKey", ex.Message);
    }

    [Fact]
    public void Startup_RefusesWildcardCorsOutsideDevelopment()
    {
        var gateway = new GatewayOptions();
        gateway.Security.AllowedCorsOrigins = ["*"];

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, new CloudOptions(), new FakeEnvironment()));

        Assert.Contains("AllowedCorsOrigins", ex.Message);
    }

    [Fact]
    public void Startup_RefusesDisabledAppAuthenticationInProduction()
    {
        var gateway = new GatewayOptions();
        gateway.Security.EnforceAppApiKey = false;

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, new CloudOptions(), new FakeEnvironment()));

        Assert.Contains("EnforceAppApiKey", ex.Message);
    }

    [Fact]
    public void Startup_RefusesTheSimulatorProviderInProduction()
    {
        var gateway = new GatewayOptions();
        var cloud = new CloudOptions { Provider = CloudProviderMode.Simulator };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment()));

        Assert.Contains("Simulator", ex.Message);
    }

    [Fact]
    public void Startup_AcceptsAValidProductionConfiguration()
    {
        var gateway = new GatewayOptions();
        gateway.Security.AdminApiKey = string.Empty;
        gateway.Security.AllowedCorsOrigins = ["https://gateway.enterprise.internal"];
        gateway.Security.RequireHttps = true;

        var cloud = new CloudOptions { Provider = CloudProviderMode.Aws };

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment());
    }

    [Fact]
    public void Startup_AcceptsTheSimulatorInTest()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];

        var cloud = new CloudOptions { Provider = CloudProviderMode.Simulator };

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = "Test" });
    }

    // --- L2: appId charset ------------------------------------------------------------

    [Theory]
    [InlineData("ok-app-1")]
    [InlineData("Fresh Tenant App")]
    public async Task ValidAppIds_AreAccepted(string appId)
    {
        var registry = CreateRegistry();
        var created = await registry.CreateAppAsync(new CreateAppRequest { AppId = appId, Name = "n" });
        Assert.Matches("^[a-z0-9-]+$", created.App.AppId);
    }

    [Theory]
    [InlineData("bad'); alert(1);//")]
    [InlineData("../../etc/passwd")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("a")]
    public async Task AppIdsOutsideTheAllowedCharset_AreRejected(string appId)
    {
        var registry = CreateRegistry();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            registry.CreateAppAsync(new CreateAppRequest { AppId = appId, Name = "n" }));
    }

    // --- M4: the admin key does not authenticate as an application ---------------------

    [Fact]
    public async Task MasterAdminKey_DoesNotAuthenticateAsAnApplication()
    {
        var registry = CreateRegistry(out var adminKey);
        var created = await registry.CreateAppAsync(new CreateAppRequest { AppId = "tenant-app", Name = "n" });

        var (withAdminKey, _) = await registry.AuthenticateAppAsync(created.App.AppId, adminKey);
        Assert.False(withAdminKey);

        var (withOwnKey, _) = await registry.AuthenticateAppAsync(created.App.AppId, created.ApiKey);
        Assert.True(withOwnKey);
    }

    private static ApplicationRegistryService CreateRegistry() => CreateRegistry(out _);

    private static ApplicationRegistryService CreateRegistry(out string adminKey)
    {
        var (security, _) = TestFactory.CreateSecurityService();
        adminKey = "ug-test-admin-secret-key-value";

        var options = new GatewayOptions
        {
            Storage = new StorageOptions
            {
                DataDirectory = Path.Combine(Path.GetTempPath(), "ug-hardening-" + Guid.NewGuid().ToString("N")),
                RegistryFileName = "registry.json",
                AuditLogEnabled = false
            }
        };

        return new ApplicationRegistryService(
            security,
            new StubAdminCredentialService(security, adminKey),
            Options.Create(options),
            NullLogger<ApplicationRegistryService>.Instance);
    }
}
