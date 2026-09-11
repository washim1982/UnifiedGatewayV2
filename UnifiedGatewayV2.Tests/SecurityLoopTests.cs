using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Auth;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Cloud.Aws;
using UnifiedGateway.Services.Telemetry;
using UnifiedGateway.Startup;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// One group per closed security loop (SL-01 to SL-04 in docs/security-architecture-flow.md),
/// so a regression reopens a named hole rather than a quiet one.
/// </summary>
public class SecurityLoopTests
{
    private const string Account = "111122223333";
    private const string ServerId = "gateway-test-server";
    private const string BreakGlassArn = "arn:aws:iam::111122223333:role/GatewayBreakGlassRole";
    private const string AdminRoleArn = "arn:aws:iam::111122223333:role/GatewayPlatformAdminRole";
    private const string AdminKey = "ug-test-master-key-for-security-loop-tests";
    private const string GetCallerIdentityBody = "Action=GetCallerIdentity&Version=2011-06-15";
    private const string DefaultSignedHeaders = "content-type;host;x-amz-date;x-amz-security-token;x-gateway-server-id";

    #region Test doubles

    private sealed record CapturedRequest(
        string Method, Uri Uri, Dictionary<string, string> Headers, string? ContentType, string Body);

    /// <summary>Stands in for AWS STS and records exactly what the gateway relayed to it.</summary>
    private sealed class StubSts : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public StubSts(HttpStatusCode status = HttpStatusCode.OK, string? body = null)
        {
            _status = status;
            _body = body ?? CallerIdentityXml($"arn:aws:sts::{Account}:assumed-role/GatewayAutomationRole/ci-run-42", Account);
        }

        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);

            Requests.Add(new CapturedRequest(
                request.Method.Method,
                request.RequestUri!,
                request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase),
                request.Content?.Headers.ContentType?.ToString(),
                body));

            return new HttpResponseMessage(_status) { Content = new StringContent(_body, Encoding.UTF8, "text/xml") };
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class SchemeOptions : IOptionsMonitor<AuthenticationSchemeOptions>
    {
        public AuthenticationSchemeOptions CurrentValue { get; } = new();
        public AuthenticationSchemeOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<AuthenticationSchemeOptions, string?> listener) => null;
    }

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "UnifiedGatewayV2";
        public string ContentRootPath { get; set; } = ".";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    #endregion

    #region Builders

    private static string CallerIdentityXml(string arn, string account) =>
        $"""
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <GetCallerIdentityResult>
            <Arn>{arn}</Arn>
            <UserId>AROAEXAMPLE:ci-run-42</UserId>
            <Account>{account}</Account>
          </GetCallerIdentityResult>
          <ResponseMetadata><RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId></ResponseMetadata>
        </GetCallerIdentityResponse>
        """;

    /// <summary>
    /// The envelope a client builds after signing GetCallerIdentity with its own credentials.
    /// The signature itself is opaque to the gateway -- STS checks it -- so a placeholder does.
    /// </summary>
    private static string SignedIdentity(
        string url = "https://sts.amazonaws.com/",
        string body = GetCallerIdentityBody,
        string method = "POST",
        string? serverId = ServerId,
        string signedHeaders = DefaultSignedHeaders,
        DateTime? signedAt = null,
        IDictionary<string, string>? extraHeaders = null)
    {
        var headers = new Dictionary<string, string>
        {
            ["Authorization"] =
                $"AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/20260910/us-east-1/sts/aws4_request, SignedHeaders={signedHeaders}, Signature=0123abcd",
            ["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8",
            ["X-Amz-Date"] = (signedAt ?? DateTime.UtcNow).ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture),
            ["X-Amz-Security-Token"] = "session-token"
        };

        if (serverId is not null)
        {
            headers["X-Gateway-Server-Id"] = serverId;
        }

        foreach (var (name, value) in extraHeaders ?? new Dictionary<string, string>())
        {
            headers[name] = value;
        }

        var json = JsonSerializer.Serialize(new { method, url, headers, body });
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    private static CloudOptions AwsCloud(Action<AwsIdentityOptions>? configure = null)
    {
        var cloud = new CloudOptions { Provider = CloudProviderMode.Aws };
        cloud.AccessControl.BreakGlassPrincipalArn = BreakGlassArn;
        cloud.AwsIdentity.Enabled = true;
        cloud.AwsIdentity.ServerId = ServerId;
        cloud.AwsIdentity.AllowedAccountIds = [Account];
        configure?.Invoke(cloud.AwsIdentity);
        return cloud;
    }

    private static AwsIdentityProvider IdentityProvider(HttpMessageHandler sts, CloudOptions? cloud = null) =>
        new(new StubHttpClientFactory(sts),
            Options.Create(cloud ?? AwsCloud()),
            Options.Create(new GatewayOptions()),
            NullLogger<AwsIdentityProvider>.Instance);

    private static async Task<AuthenticateResult> AuthenticateManagementAsync(
        Action<HttpRequest> arrange,
        CloudOptions? cloud = null,
        ISecurityService? security = null,
        HttpMessageHandler? sts = null)
    {
        cloud ??= AwsCloud();
        security ??= TestFactory.CreateSecurityService().Security;

        var handler = new GatewayAuthenticationHandler(
            new SchemeOptions(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            IdentityProvider(sts ?? new StubSts(), cloud),
            security,
            new StubAdminCredentialService(security, AdminKey),
            Options.Create(cloud));

        var context = new DefaultHttpContext();
        arrange(context.Request);

        await handler.InitializeAsync(
            new AuthenticationScheme(GatewayAuth.Scheme, null, typeof(GatewayAuthenticationHandler)), context);
        return await handler.AuthenticateAsync();
    }

    private static string? ClaimOf(AuthenticateResult result, string type) => result.Principal?.FindFirst(type)?.Value;

    /// <summary>A production configuration the validator accepts; each test breaks one thing.</summary>
    private static (GatewayOptions Gateway, CloudOptions Cloud, OktaOptions Okta) ValidProduction()
    {
        var gateway = new GatewayOptions();
        gateway.Security.AllowedCorsOrigins = ["https://gateway.enterprise.internal"];
        gateway.Aws.CredentialSource = AwsCredentialSource.RolesAnywhere;
        gateway.Aws.RolesAnywhere.TrustAnchorArn = $"arn:aws:rolesanywhere:us-east-1:{Account}:trust-anchor/a";
        gateway.Aws.RolesAnywhere.ProfileArn = $"arn:aws:rolesanywhere:us-east-1:{Account}:profile/b";
        gateway.Aws.RolesAnywhere.RoleArn = $"arn:aws:iam::{Account}:role/GatewayRole";
        gateway.Aws.RolesAnywhere.Certificate.Source = CertificateSource.WindowsStore;
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";

        var okta = new OktaOptions
        {
            Issuer = "https://example.okta.com/oauth2/default",
            MetadataAddress = "https://example.okta.com/oauth2/default/.well-known/openid-configuration",
            GroupRoleMappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["UnifiedGateway-Admins"] = AdminRoleArn
            }
        };

        return (gateway, AwsCloud(), okta);
    }

    private static InvalidOperationException RefusedAtStartup(
        GatewayOptions gateway, CloudOptions cloud, OktaOptions okta, string environment) =>
        Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment(environment), okta));

    #endregion

    [Fact]
    public void TheBaselineProductionConfigurationIsAccepted()
    {
        var (gateway, cloud, okta) = ValidProduction();
        StartupValidator.Validate(gateway, cloud, new FakeEnvironment("Production"), okta);
    }

    // --- SL-01: identity is proven by AWS, never asserted by the caller ----------------------

    [Theory]
    [InlineData("X-API-Key")]
    [InlineData("X-Simulator-Role")]
    public async Task SL01_AnAssertedAdminRoleArnDoesNotAuthenticateInAwsMode(string header)
    {
        var sts = new StubSts();

        var result = await AuthenticateManagementAsync(r => r.Headers[header] = AdminRoleArn, sts: sts);

        Assert.False(result.Succeeded);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_AnArnSentAsABearerTokenDoesNotAuthenticateEither()
    {
        var result = await AuthenticateManagementAsync(r => r.Headers.Authorization = "Bearer " + AdminRoleArn);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task SL01_TheIdentityProviderRefusesABareArnWithoutContactingAws()
    {
        var sts = new StubSts();

        var identity = await IdentityProvider(sts).ResolveAsync(AdminRoleArn);

        Assert.False(identity.IsAuthenticated);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_AwsIdentityIsClosedUnlessEnabled()
    {
        var sts = new StubSts();

        var identity = await IdentityProvider(sts, AwsCloud(o => o.Enabled = false)).ResolveAsync(SignedIdentity());

        Assert.False(identity.IsAuthenticated);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_AnStsVerifiedAssumedRoleAuthenticatesAsItsRole()
    {
        var sts = new StubSts();
        var envelope = SignedIdentity(extraHeaders: new Dictionary<string, string> { ["X-Smuggled"] = "value" });

        var result = await AuthenticateManagementAsync(r => r.Headers[GatewayAuth.AwsIdentityHeader] = envelope, sts: sts);

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Equal($"arn:aws:iam::{Account}:role/GatewayAutomationRole", ClaimOf(result, GatewayAuth.PrincipalArnClaim));
        Assert.Equal("AwsSigV4Verified", ClaimOf(result, GatewayAuth.AuthTypeClaim));

        // What reached STS is exactly the signed call, and nothing the signature does not cover.
        var sent = Assert.Single(sts.Requests);
        Assert.Equal("POST", sent.Method);
        Assert.Equal("https://sts.amazonaws.com/", sent.Uri.ToString());
        Assert.Equal(GetCallerIdentityBody, sent.Body);
        Assert.StartsWith("AWS4-HMAC-SHA256", sent.Headers["Authorization"]);
        Assert.Equal(ServerId, sent.Headers["X-Gateway-Server-Id"]);
        Assert.False(sent.Headers.ContainsKey("X-Smuggled"));
    }

    [Theory]
    [InlineData("https://attacker.example/", GetCallerIdentityBody, "POST")]                    // not STS
    [InlineData("https://sts.amazonaws.com.attacker.example/", GetCallerIdentityBody, "POST")] // lookalike host
    [InlineData("http://sts.amazonaws.com/", GetCallerIdentityBody, "POST")]                    // plaintext
    [InlineData("https://sts.amazonaws.com:8443/", GetCallerIdentityBody, "POST")]              // odd port
    [InlineData("https://sts.amazonaws.com/other", GetCallerIdentityBody, "POST")]              // path
    [InlineData("https://sts.amazonaws.com/?Action=GetCallerIdentity", GetCallerIdentityBody, "POST")]
    [InlineData("https://sts.amazonaws.com/", "Action=AssumeRole&Version=2011-06-15", "POST")]
    [InlineData("https://sts.amazonaws.com/", GetCallerIdentityBody + "&RoleArn=x", "POST")]
    [InlineData("https://sts.amazonaws.com/", GetCallerIdentityBody, "GET")]
    public async Task SL01_AnythingButAGetCallerIdentityPostToStsIsRefusedWithoutContactingAws(
        string url, string body, string method)
    {
        var sts = new StubSts();

        var identity = await IdentityProvider(sts).ResolveAsync(SignedIdentity(url: url, body: body, method: method));

        Assert.False(identity.IsAuthenticated);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_ARequestBoundToAnotherServiceIsRefused()
    {
        var sts = new StubSts();

        var identity = await IdentityProvider(sts).ResolveAsync(SignedIdentity(serverId: "some-other-service"));

        Assert.False(identity.IsAuthenticated);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_AServerIdTheSignatureDoesNotCoverIsRefused()
    {
        // Without the header in SignedHeaders it could be added after signing, and would bind nothing.
        var sts = new StubSts();

        var identity = await IdentityProvider(sts).ResolveAsync(
            SignedIdentity(signedHeaders: "content-type;host;x-amz-date;x-amz-security-token"));

        Assert.False(identity.IsAuthenticated);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_AStaleSignedRequestIsRefused()
    {
        var sts = new StubSts();

        var identity = await IdentityProvider(sts).ResolveAsync(SignedIdentity(signedAt: DateTime.UtcNow.AddMinutes(-20)));

        Assert.False(identity.IsAuthenticated);
        Assert.Empty(sts.Requests);
    }

    [Fact]
    public async Task SL01_AnAccountOutsideTheAllowListIsRefused()
    {
        var sts = new StubSts(body: CallerIdentityXml("arn:aws:sts::999988887777:assumed-role/Admin/x", "999988887777"));

        var identity = await IdentityProvider(sts).ResolveAsync(SignedIdentity());

        Assert.False(identity.IsAuthenticated);
    }

    [Fact]
    public async Task SL01_AnStsRejectionIsARefusal()
    {
        var sts = new StubSts(
            HttpStatusCode.Forbidden,
            "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>");

        var identity = await IdentityProvider(sts).ResolveAsync(SignedIdentity());

        Assert.False(identity.IsAuthenticated);
        Assert.Single(sts.Requests);
    }

    [Theory]
    [InlineData("arn:aws:iam::111122223333:root")]
    [InlineData("arn:aws:sts::111122223333:federated-user/bob")]
    public async Task SL01_RootAndFederatedIdentitiesAreRefused(string arn)
    {
        var identity = await IdentityProvider(new StubSts(body: CallerIdentityXml(arn, Account))).ResolveAsync(SignedIdentity());

        Assert.False(identity.IsAuthenticated);
    }

    [Fact]
    public async Task SL01_AnStsResponseCarryingADtdIsRefused()
    {
        const string withEntity =
            """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "arn:aws:iam::111122223333:user/evil">]><GetCallerIdentityResponse><GetCallerIdentityResult><Arn>&x;</Arn><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>""";

        var identity = await IdentityProvider(new StubSts(body: withEntity)).ResolveAsync(SignedIdentity());

        Assert.False(identity.IsAuthenticated);
    }

    [Fact]
    public void SL01_AnAssumedRoleMapsToTheRoleItsPolicyNames()
    {
        Assert.Equal(
            "arn:aws:iam::111122223333:role/Automation",
            AwsIdentityProvider.ToPrincipalArn("arn:aws:sts::111122223333:assumed-role/Automation/session-1", Account));

        // The ARN's account has to agree with the account STS reported.
        Assert.Null(AwsIdentityProvider.ToPrincipalArn("arn:aws:sts::999988887777:assumed-role/Automation/s", Account));
    }

    [Fact]
    public void SL01_EnablingAwsIdentityRequiresRealScoping()
    {
        var (gateway, cloud, okta) = ValidProduction();
        cloud.AwsIdentity.ServerId = "";
        cloud.AwsIdentity.AllowedAccountIds = ["<account-id>"];

        var ex = RefusedAtStartup(gateway, cloud, okta, "Production");

        Assert.Contains("ServerId", ex.Message);
        Assert.Contains("AllowedAccountIds", ex.Message);
    }

    // --- SL-02: the Okta simulator is Development-only ---------------------------------------

    [Fact]
    public void SL02_TheOktaSimulatorIsOffByDefault()
    {
        Assert.False(new OktaOptions().Enabled);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public void SL02_StartupRefusesTheOktaSimulatorOutsideDevelopment(string environment)
    {
        var (gateway, cloud, okta) = ValidProduction();
        okta.Enabled = true;

        var ex = RefusedAtStartup(gateway, cloud, okta, environment);

        Assert.Contains("Okta simulator", ex.Message);
    }

    [Fact]
    public void SL02_TheOktaSimulatorStillRunsInDevelopment()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];
        gateway.Aws.UseLocalProfile = true;

        var cloud = new CloudOptions { Provider = CloudProviderMode.LocalDotNet, BedrockProvider = CloudProviderMode.Aws };
        var okta = new OktaOptions { Enabled = true, Issuer = "https://okta-sim.local/oauth2/default" };

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment("Development"), okta);
    }

    [Theory]
    [InlineData("http://example.okta.com/oauth2/default")]
    [InlineData("https://<your-tenant>.okta.com/oauth2/default")]
    public void SL02_TheRealTenantMustBeHttpsAndSubstituted(string issuer)
    {
        var (gateway, cloud, okta) = ValidProduction();
        okta.Issuer = issuer;

        var ex = RefusedAtStartup(gateway, cloud, okta, "Production");

        Assert.Contains("Gateway:Okta:Issuer", ex.Message);
    }

    [Fact]
    public void SL02_GroupRoleMappingsMustBeSubstituted()
    {
        var (gateway, cloud, okta) = ValidProduction();
        okta.GroupRoleMappings["UnifiedGateway-Admins"] = "arn:aws:iam::<account-id>:role/GatewayPlatformAdminRole";

        var ex = RefusedAtStartup(gateway, cloud, okta, "Production");

        Assert.Contains("GroupRoleMappings", ex.Message);
    }

    // --- SL-03: TLS everywhere but a developer's loopback --------------------------------------

    [Theory]
    [InlineData("Test")]
    [InlineData("Staging")]
    public void SL03_PlainHttpIsRefusedEverywhereButDevelopment(string environment)
    {
        var (gateway, cloud, okta) = ValidProduction();
        gateway.Security.RequireHttps = false;

        var ex = RefusedAtStartup(gateway, cloud, okta, environment);

        Assert.Contains("RequireHttps", ex.Message);
    }

    [Fact]
    public void SL03_TestCannotSwitchOffApplicationAuthentication()
    {
        var (gateway, cloud, okta) = ValidProduction();
        gateway.Security.EnforceAppApiKey = false;

        var ex = RefusedAtStartup(gateway, cloud, okta, "Test");

        Assert.Contains("EnforceAppApiKey", ex.Message);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Staging")]
    public void SL03_TheRoleNameSimulatorIsDevelopmentOnly(string environment)
    {
        var (gateway, cloud, okta) = ValidProduction();
        cloud.Provider = CloudProviderMode.Simulator;
        cloud.BedrockServiceUrl = "http://localhost:5004";

        var ex = RefusedAtStartup(gateway, cloud, okta, environment);

        Assert.Contains("'Simulator'", ex.Message);
    }

    private static async Task<(int Status, bool Continued, string Body)> SendThroughHttpsEnforcementAsync(string scheme, string path)
    {
        var continued = false;
        var middleware = new HttpsEnforcementMiddleware(
            _ =>
            {
                continued = true;
                return Task.CompletedTask;
            },
            NullLogger<HttpsEnforcementMiddleware>.Instance);

        var context = new DefaultHttpContext();
        context.Request.Scheme = scheme;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        context.Response.Body.Position = 0;
        var body = await new StreamReader(context.Response.Body).ReadToEndAsync();
        return (context.Response.StatusCode, continued, body);
    }

    [Theory]
    [InlineData("/gateway/customer-support-agent/invoke")]
    [InlineData("/gateway/sts/token")]
    [InlineData("/api/apps")]
    [InlineData("/okta/oauth2/v1/token")]
    public async Task SL03_ApiCallsOverPlainHttpAreRefusedNotRedirected(string path)
    {
        var (status, continued, body) = await SendThroughHttpsEnforcementAsync("http", path);

        Assert.Equal(StatusCodes.Status403Forbidden, status);
        Assert.False(continued);
        Assert.Contains("HTTPS_REQUIRED", body);
    }

    [Theory]
    [InlineData("https", "/gateway/sts/token")]
    [InlineData("http", "/index.html")]
    [InlineData("http", "/gatewayish")]
    public async Task SL03_HttpsAndNonApiPathsPassThrough(string scheme, string path)
    {
        var (_, continued, _) = await SendThroughHttpsEnforcementAsync(scheme, path);

        Assert.True(continued);
    }

    // --- SL-04: break-glass is scoped, named by the server, and audited -------------------------

    [Theory]
    [InlineData(GatewayScopes.Read)]
    [InlineData(GatewayScopes.Invoke)]
    public async Task SL04_AnAdminTokenScopedBelowAdminCannotManage(string scope)
    {
        var (security, _) = TestFactory.CreateSecurityService();
        var (token, _) = await security.IssueAppStsTokenAsync("*", TimeSpan.FromMinutes(10), scope, isAdmin: true);

        var result = await AuthenticateManagementAsync(r => r.Headers["X-API-Key"] = token, security: security);

        Assert.False(result.Succeeded);
        Assert.Contains("scope", result.Failure?.Message);
    }

    [Fact]
    public async Task SL04_AnAdminTokenActsAsTheConfiguredBreakGlassPrincipalWhateverItsCallerId()
    {
        var (security, _) = TestFactory.CreateSecurityService();
        var issued = await security.IssueStsTokenAsync(new StsTokenSpec
        {
            AppId = "*",
            Duration = TimeSpan.FromMinutes(10),
            Scope = GatewayScopes.Admin,
            IsAdmin = true,
            CallerId = "arn:aws:iam::111122223333:role/SomeoneElse"
        });

        var result = await AuthenticateManagementAsync(r => r.Headers["X-API-Key"] = issued.Token, security: security);

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Equal(BreakGlassArn, ClaimOf(result, GatewayAuth.PrincipalArnClaim));
        Assert.Equal(issued.TokenId, ClaimOf(result, GatewayAuth.TokenIdClaim));
    }

    [Fact]
    public async Task SL04_TheMasterKeyActsAsTheConfiguredBreakGlassPrincipal()
    {
        var result = await AuthenticateManagementAsync(r => r.Headers["X-API-Key"] = AdminKey);

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Equal(BreakGlassArn, ClaimOf(result, GatewayAuth.PrincipalArnClaim));
        Assert.Equal("MasterAdminKey", ClaimOf(result, GatewayAuth.AuthTypeClaim));
    }

    [Fact]
    public async Task SL04_BreakGlassFailsClosedWithoutAConfiguredPrincipal()
    {
        var cloud = AwsCloud();
        cloud.AccessControl.BreakGlassPrincipalArn = string.Empty;

        var result = await AuthenticateManagementAsync(r => r.Headers["X-API-Key"] = AdminKey, cloud: cloud);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public void SL04_StartupRequiresABreakGlassPrincipalOutsideDevelopment()
    {
        var (gateway, cloud, okta) = ValidProduction();
        cloud.AccessControl.BreakGlassPrincipalArn = string.Empty;

        var ex = RefusedAtStartup(gateway, cloud, okta, "Production");

        Assert.Contains("BreakGlassPrincipalArn", ex.Message);
    }

    private static (ApplicationRegistryService Registry, ISecurityService Security, InMemoryObjectStore Store) CreateRegistry()
    {
        var (security, _) = TestFactory.CreateSecurityService();
        var store = new InMemoryObjectStore();

        var options = new GatewayOptions
        {
            Storage = new StorageOptions
            {
                DataDirectory = Path.Combine(Path.GetTempPath(), "ug-sl-" + Guid.NewGuid().ToString("N")),
                RegistryFileName = "registry.json",
                AuditLogEnabled = true
            }
        };

        var cloud = new CloudOptions { Storage = new AuditStorageOptions { FlushBatchSize = 1 } };

        var registry = new ApplicationRegistryService(
            security,
            new StubAdminCredentialService(security, AdminKey),
            Options.Create(options),
            Options.Create(new BillingOptions()),
            new S3AuditStore(store, Options.Create(cloud), NullLogger<S3AuditStore>.Instance),
            NullLogger<ApplicationRegistryService>.Instance);

        return (registry, security, store);
    }

    private static async Task<string> AuditTrailAsync(InMemoryObjectStore store)
    {
        var trail = new StringBuilder();
        foreach (var key in store.Keys)
        {
            trail.Append(Encoding.UTF8.GetString((await store.GetAsync(key))!));
        }

        return trail.ToString();
    }

    [Fact]
    public async Task SL04_MintingAnAdminTokenIsAuditedWithItsTokenIdAndSource()
    {
        var (registry, _, store) = CreateRegistry();

        var minted = await registry.IssueStsTokenForAppAsync("*", AdminKey, scope: GatewayScopes.Admin, sourceIp: "10.1.2.3");

        Assert.NotNull(minted);
        var trail = await AuditTrailAsync(store);
        Assert.Contains("\"action\":\"MintAdminStsToken\"", trail);
        Assert.Contains(minted!.TokenId, trail);
        Assert.Contains("10.1.2.3", trail);
    }

    [Fact]
    public async Task SL04_AdminTokensAreCappedAtTheAdminLifetime()
    {
        var (registry, _, _) = CreateRegistry();

        var minted = await registry.IssueStsTokenForAppAsync("*", AdminKey, durationSeconds: 3600, scope: GatewayScopes.Admin);

        Assert.NotNull(minted);
        Assert.True(minted!.DurationSeconds <= 900, $"Admin token lived {minted.DurationSeconds}s; the ceiling is 900s.");
    }

    [Theory]
    [InlineData("ops\r\n2026-09-10 INFO forged audit line")]
    [InlineData("<img src=x onerror=alert(1)>")]
    public async Task SL04_ACallerIdCannotCarryControlCharactersOrMarkup(string callerId)
    {
        var (registry, _, _) = CreateRegistry();

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            registry.IssueStsTokenForAppAsync("*", AdminKey, callerId: callerId));

        Assert.Equal("callerId", ex.ParamName);
    }

    [Fact]
    public async Task SL04_AnAdminTokenOnTheDataPlaneIsAttributedToBreakGlassNotItsCallerId()
    {
        var (registry, security, _) = CreateRegistry();
        var created = await registry.CreateAppAsync(new CreateAppRequest { AppId = "victim-app", Name = "Victim" });
        var (token, _) = await security.IssueAppStsTokenAsync(
            "*", TimeSpan.FromMinutes(10), GatewayScopes.Admin, isAdmin: true, callerId: "operator-7");

        var (isValid, _, caller) = await registry.AuthenticateAppAsync(created.App.AppId, token);

        Assert.True(isValid);
        Assert.Equal("break-glass [operator-7]", caller!.Actor);
    }
}
