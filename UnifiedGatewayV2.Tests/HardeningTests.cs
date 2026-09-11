using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Telemetry;
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
        WithRolesAnywhere(gateway);

        var cloud = new CloudOptions { Provider = CloudProviderMode.Aws };
        cloud.AccessControl.BreakGlassPrincipalArn = "arn:aws:iam::111122223333:role/GatewayBreakGlassRole";

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment());
    }

    [Fact]
    public void Startup_AcceptsTheSimulatorInDevelopment()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];

        var cloud = new CloudOptions
        {
            Provider = CloudProviderMode.Simulator,
            BedrockServiceUrl = "http://localhost:5004"
        };

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = "Development" });
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Staging")]
    public void Startup_RefusesTheSimulatorOutsideDevelopment(string environmentName)
    {
        // The simulator accepts a role name as proof of identity. That proves nothing, so it
        // cannot run anywhere a network can reach -- Test included.
        var gateway = new GatewayOptions();
        gateway.Security.AllowedCorsOrigins = ["https://gateway.test.internal"];
        WithRolesAnywhere(gateway);

        var cloud = new CloudOptions
        {
            Provider = CloudProviderMode.Simulator,
            BedrockServiceUrl = "http://localhost:5004"
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = environmentName }));

        Assert.Contains("Simulator", ex.Message);
    }

    // --- M6: the scope claim is enforced, not decorative -----------------------------

    [Theory]
    [InlineData("invoke", "invoke", true)]
    [InlineData("admin", "invoke", true)]      // an admin that cannot invoke would be odd
    [InlineData("*", "admin", true)]
    [InlineData("read", "invoke", false)]      // the whole point of the claim
    [InlineData("invoke", "admin", false)]
    [InlineData("read", "admin", false)]
    [InlineData(null, "invoke", true)]         // pre-enforcement tokens are invoke-only
    [InlineData(null, "admin", false)]
    public void ScopePermits_FollowsTheDocumentedRules(string? granted, string required, bool expected)
    {
        Assert.Equal(expected, SecurityService.ScopePermits(granted, required));
    }

    [Fact]
    public async Task AReadScopedTokenCannotInvoke()
    {
        var registry = CreateRegistry(out _, out var security);
        var created = await registry.CreateAppAsync(new CreateAppRequest { AppId = "scoped-app", Name = "Scoped" });

        // Same application, same signing key — only the scope differs.
        var (readToken, _) = await security.IssueAppStsTokenAsync(
            created.App.AppId, TimeSpan.FromMinutes(30), GatewayScopes.Read);
        var (invokeToken, _) = await security.IssueAppStsTokenAsync(
            created.App.AppId, TimeSpan.FromMinutes(30), GatewayScopes.Invoke);

        var (readAllowed, _, _) = await registry.AuthenticateAppAsync(created.App.AppId, readToken);
        var (invokeAllowed, _, _) = await registry.AuthenticateAppAsync(created.App.AppId, invokeToken);

        Assert.False(readAllowed);
        Assert.True(invokeAllowed);
    }

    [Fact]
    public void AnUnknownScopeIsRejectedRatherThanSilentlyDowngraded()
    {
        // Quietly granting less than was asked for would let a caller believe they hold a
        // permission they do not.
        Assert.Throws<ArgumentException>(() => GatewayScopes.Normalize("superuser"));
    }

    // --- M1: invocation records carry the caller -------------------------------------

    [Fact]
    public async Task AnAppApiKeyAuthenticationReportsTheKeyPrefixAsTheActor()
    {
        var registry = CreateRegistry();
        var created = await registry.CreateAppAsync(new CreateAppRequest { AppId = "attributed-app", Name = "A" });

        var (isValid, _, caller) = await registry.AuthenticateAppAsync(created.App.AppId, created.ApiKey);

        Assert.True(isValid);
        Assert.NotNull(caller);
        Assert.Equal("AppApiKey", caller!.AuthType);

        // The prefix identifies which key was used without recording the key itself.
        Assert.Equal(created.App.ApiKeyPrefix, caller.Actor);
        Assert.DoesNotContain(created.ApiKey, caller.Actor);
    }

    [Fact]
    public async Task AnStsAuthenticationReportsTheTokenId()
    {
        var registry = CreateRegistry(out _, out var security);
        var created = await registry.CreateAppAsync(new CreateAppRequest { AppId = "token-app", Name = "T" });
        var (token, _) = await security.IssueAppStsTokenAsync(created.App.AppId, TimeSpan.FromMinutes(30));
        var (_, payload, _) = await security.ValidateAppStsTokenAsync(token);

        var (isValid, _, caller) = await registry.AuthenticateAppAsync(created.App.AppId, token);

        Assert.True(isValid);
        Assert.NotNull(caller);
        Assert.Equal("AppStsToken", caller!.AuthType);
        Assert.Equal(payload!.Jti, caller.TokenId);
    }
    /// <summary>
    /// A Roles Anywhere configuration that satisfies the validator. Outside Development
    /// there is no other accepted credential source, so every non-dev validator test needs
    /// one of these before it can exercise whatever it is actually about.
    /// </summary>
    private static void WithRolesAnywhere(GatewayOptions gateway)
    {
        gateway.Aws.CredentialSource = AwsCredentialSource.RolesAnywhere;
        gateway.Aws.RolesAnywhere.TrustAnchorArn = "arn:aws:rolesanywhere:us-east-1:1:trust-anchor/a";
        gateway.Aws.RolesAnywhere.ProfileArn = "arn:aws:rolesanywhere:us-east-1:1:profile/b";
        gateway.Aws.RolesAnywhere.RoleArn = "arn:aws:iam::1:role/GatewayRole";
        gateway.Aws.RolesAnywhere.Certificate.Source = CertificateSource.WindowsStore;
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    }

    // --- Provider binding guards ---------------------------------------------------

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Test")]
    public void Startup_RefusesTheDotNetSimulatorOutsideDevelopment(string environmentName)
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["https://gateway.enterprise.internal"];

        var cloud = new CloudOptions { Provider = CloudProviderMode.LocalDotNet };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = environmentName }));

        Assert.Contains("LocalDotNet", ex.Message);
    }

    [Fact]
    public void Startup_AcceptsTheDotNetSimulatorInDevelopment()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];

        // Bedrock has to be given a provider of its own: the .NET simulator does not
        // implement it, so inheriting LocalDotNet is refused (see the Bedrock tests below).
        var cloud = new CloudOptions
        {
            Provider = CloudProviderMode.LocalDotNet,
            BedrockProvider = CloudProviderMode.Aws
        };
        gateway.Aws.UseLocalProfile = true;

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = "Development" });
    }

    // --- Bedrock resolves independently of the global provider -------------------------

    [Fact]
    public void BedrockFollowsTheGlobalProviderWhenNoOverrideIsSet()
    {
        Assert.Equal(
            CloudProviderMode.Aws,
            new CloudOptions { Provider = CloudProviderMode.Aws }.EffectiveBedrockProvider);
    }

    [Fact]
    public void BedrockOverrideLeavesEveryOtherSeamOnTheSimulator()
    {
        // The whole point of the seam: real model calls, simulated control plane.
        var cloud = new CloudOptions
        {
            Provider = CloudProviderMode.LocalDotNet,
            BedrockProvider = CloudProviderMode.Aws
        };

        Assert.Equal(CloudProviderMode.Aws, cloud.EffectiveBedrockProvider);
        Assert.Equal(CloudProviderMode.LocalDotNet, cloud.Provider);
    }

    [Fact]
    public void Startup_RefusesDevelopmentThatLeavesBedrockOnTheDotNetSimulator()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];

        // No BedrockProvider, so Bedrock would inherit LocalDotNet — which has no Bedrock.
        var cloud = new CloudOptions { Provider = CloudProviderMode.LocalDotNet };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = "Development" }));

        Assert.Contains("Bedrock has no provider", ex.Message);
    }

    [Fact]
    public void Startup_RefusesAServiceUrlWhenBedrockIsReal()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];
        gateway.Aws.UseLocalProfile = true;

        // A leftover simulator URL would silently send "real" Bedrock traffic to localhost.
        var cloud = new CloudOptions
        {
            Provider = CloudProviderMode.LocalDotNet,
            BedrockProvider = CloudProviderMode.Aws,
            BedrockServiceUrl = "http://localhost:5004"
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = "Development" }));

        Assert.Contains("BedrockServiceUrl", ex.Message);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Test")]
    public void Startup_RefusesALocalAwsProfileOutsideDevelopment(string environmentName)
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = true;
        gateway.Security.AllowedCorsOrigins = ["https://gateway.enterprise.internal"];

        // A developer's own credential is not an identity a shared host may run as.
        gateway.Aws.UseLocalProfile = true;

        var cloud = new CloudOptions { Provider = CloudProviderMode.Aws };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment { EnvironmentName = environmentName }));

        Assert.Contains("~/.aws profile", ex.Message);
    }

    [Theory]
    [InlineData("UnrecognizedClientException")]
    [InlineData("InvalidSignatureException")]
    [InlineData("ExpiredToken")]
    [InlineData("AccessDeniedException")]
    public void ACredentialRejectionIsReportedAsConfiguration(string errorCode)
    {
        var ex = new Amazon.Runtime.AmazonServiceException("rejected") { ErrorCode = errorCode };

        Assert.True(BedrockService.IsCredentialProblem(ex));
    }

    [Fact]
    public void AMissingProfileSurfacesThroughTheMetadataProbe()
    {
        // Verbatim from a live run on a machine with no ~/.aws profile and no AWS_ variables:
        // the SDK falls through to instance metadata, which is not there either.
        //
        // The type matters. AmazonServiceException does not derive from AmazonClientException
        // -- both descend directly from Exception -- and an earlier version of the classifier
        // tested only the latter, so this exact case reached the caller as an opaque
        // BEDROCK_INVOCATION_FAILED. Both types are asserted here for that reason.
        const string message = "Unable to get IAM security credentials from EC2 Instance Metadata Service.";

        Assert.True(BedrockService.IsCredentialProblem(
            new Amazon.Runtime.AmazonServiceException(message)));
        Assert.True(BedrockService.IsCredentialProblem(
            new Amazon.Runtime.AmazonClientException(message)));
    }

    [Fact]
    public void AmazonServiceExceptionDoesNotDeriveFromAmazonClientException()
    {
        // Pins the SDK detail the classifier depends on. If a future SDK version changes the
        // hierarchy this fails here rather than silently widening what gets matched.
        Assert.False(typeof(Amazon.Runtime.AmazonClientException)
            .IsAssignableFrom(typeof(Amazon.Runtime.AmazonServiceException)));
    }

    [Fact]
    public void AGenuineServiceFaultIsNotRelabelledAsConfiguration()
    {
        // Too broad a guess would send an operator to the credential chain while the real
        // problem is the model or the service.
        var throttled = new Amazon.Runtime.AmazonServiceException("slow down")
        {
            ErrorCode = "ThrottlingException"
        };
        var missingModel = new Amazon.Runtime.AmazonServiceException("no such model")
        {
            ErrorCode = "ResourceNotFoundException"
        };

        Assert.False(BedrockService.IsCredentialProblem(throttled));
        Assert.False(BedrockService.IsCredentialProblem(missingModel));
        Assert.False(BedrockService.IsCredentialProblem(new TimeoutException()));
    }

    [Fact]
    public void ACredentialFailureIsFoundThroughTheInnerException()
    {
        // The SDK routinely wraps the real cause.
        var inner = new Amazon.Runtime.AmazonServiceException("rejected")
        {
            ErrorCode = "UnrecognizedClientException"
        };

        Assert.True(BedrockService.IsCredentialProblem(
            new InvalidOperationException("invocation failed", inner)));
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

        var (withAdminKey, _, _) = await registry.AuthenticateAppAsync(created.App.AppId, adminKey);
        Assert.False(withAdminKey);

        var (withOwnKey, _, _) = await registry.AuthenticateAppAsync(created.App.AppId, created.ApiKey);
        Assert.True(withOwnKey);
    }

    private static ApplicationRegistryService CreateRegistry() => CreateRegistry(out _, out _);

    private static ApplicationRegistryService CreateRegistry(out string adminKey)
        => CreateRegistry(out adminKey, out _);

    /// <summary>
    /// Also yields the security service the registry validates with. A test that mints a
    /// token must use the same signing key, or it is testing key mismatch rather than scope.
    /// </summary>
    private static ApplicationRegistryService CreateRegistry(out string adminKey, out ISecurityService security)
    {
        (security, _) = TestFactory.CreateSecurityService();
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
            Options.Create(new BillingOptions()),
            new S3AuditStore(new InMemoryObjectStore(), Options.Create(new CloudOptions()), NullLogger<S3AuditStore>.Instance),
            NullLogger<ApplicationRegistryService>.Instance);
    }
}
