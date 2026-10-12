using System.Threading.RateLimiting;
using Amazon.BedrockRuntime;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.OpenApi.Models;
using Polly;
using UnifiedGateway.Auth;
using UnifiedGateway.Endpoints;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Aws;
using UnifiedGateway.Services.Cloud;
using UnifiedGateway.Services.Cloud.Aws;
using UnifiedGateway.Services.Cloud.LocalDotNet;
using UnifiedGateway.Services.Cloud.Simulator;
using UnifiedGateway.Services.Mcp;
using UnifiedGateway.Services.Okta;
using UnifiedGateway.Services.Telemetry;
using UnifiedGateway.Startup;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// 1. Configuration
// ---------------------------------------------------------------------------
builder.Services.Configure<GatewayOptions>(
    builder.Configuration.GetSection(GatewayOptions.SectionName));
builder.Services.Configure<CloudOptions>(
    builder.Configuration.GetSection(CloudOptions.SectionName));
builder.Services.Configure<OktaOptions>(
    builder.Configuration.GetSection(OktaOptions.SectionName));
builder.Services.Configure<BillingOptions>(
    builder.Configuration.GetSection(BillingOptions.SectionName));

var gatewayOptions = builder.Configuration
    .GetSection(GatewayOptions.SectionName)
    .Get<GatewayOptions>() ?? new GatewayOptions();

var cloudOptions = builder.Configuration
    .GetSection(CloudOptions.SectionName)
    .Get<CloudOptions>() ?? new CloudOptions();

var oktaOptions = builder.Configuration
    .GetSection(OktaOptions.SectionName)
    .Get<OktaOptions>() ?? new OktaOptions();

// Refuse to start on an insecure configuration rather than starting insecure.
// The validator sees every listen address configuration can give this process: urls
// (ASPNETCORE_URLS, --urls, launchSettings), HTTP_PORTS / HTTPS_PORTS and Kestrel:Endpoints.
StartupValidator.Validate(
    gatewayOptions,
    cloudOptions,
    builder.Environment,
    oktaOptions,
    StartupValidator.CollectListenUrls(builder.Configuration));

// ---------------------------------------------------------------------------
// 2. Cloud provider binding — the single switch between TEST and PROD
//
// Every cloud-facing dependency resolves through an interface. Which implementation
// is bound is decided here from Gateway:Cloud:Provider, so moving an environment from
// the local AWS simulator to real AWS is a configuration change, not a code change.
// ---------------------------------------------------------------------------
var simulatorTimeout = TimeSpan.FromSeconds(Math.Max(1, cloudOptions.Simulator.TimeoutSeconds));

builder.Services.AddHttpClient(SimulatorClients.Kms, client =>
{
    client.BaseAddress = new Uri(cloudOptions.Simulator.KmsUrl);
    client.Timeout = simulatorTimeout;
    client.DefaultRequestHeaders.Add("X-Simulator-Role", cloudOptions.Simulator.CallerRoleName);
});

builder.Services.AddHttpClient(SimulatorClients.Iam, client =>
{
    client.BaseAddress = new Uri(cloudOptions.Simulator.IamUrl);
    client.Timeout = simulatorTimeout;
    client.DefaultRequestHeaders.Add("X-Simulator-Role", cloudOptions.Simulator.CallerRoleName);
});

// The .NET local AWS simulator (DOTNET_AWS_SIMULATOR). Registered unconditionally so the
// clients exist; only the Provider switch decides whether anything resolves to them.
var localDotNetTimeout = TimeSpan.FromSeconds(Math.Max(1, cloudOptions.LocalDotNet.TimeoutSeconds));

builder.Services.AddHttpClient(LocalDotNetClients.Kms, c =>
{
    c.BaseAddress = new Uri(cloudOptions.LocalDotNet.KmsUrl);
    c.Timeout = localDotNetTimeout;
});

builder.Services.AddHttpClient(LocalDotNetClients.Iam, c =>
{
    c.BaseAddress = new Uri(cloudOptions.LocalDotNet.IamUrl);
    c.Timeout = localDotNetTimeout;
});

builder.Services.AddHttpClient(LocalDotNetClients.S3, c =>
{
    c.BaseAddress = new Uri(cloudOptions.LocalDotNet.S3Url);
    c.Timeout = localDotNetTimeout;
});

builder.Services.AddSingleton<LocalDotNetPolicyCache>();
builder.Services.AddSingleton<LocalDotNetHealthCheck>();

switch (cloudOptions.Provider)
{
    case CloudProviderMode.LocalDotNet:
        builder.Services.AddSingleton<IObjectStore, LocalDotNetObjectStore>();
        builder.Services.AddSingleton<ICryptoProvider, LocalDotNetCryptoProvider>();
        builder.Services.AddSingleton<ISecretsProvider, LocalDotNetSecretsProvider>();
        builder.Services.AddSingleton<IAccessControlProvider, LocalDotNetAccessControlProvider>();
        builder.Services.AddSingleton<IIdentityProvider, LocalDotNetIdentityProvider>();
        break;

    case CloudProviderMode.Simulator:
        // The Python simulator has no S3 the gateway can use for telemetry; the audit
        // trail falls back to the .NET simulator's S3Local, which is the dev store anyway.
        builder.Services.AddSingleton<IObjectStore, LocalDotNetObjectStore>();
        builder.Services.AddSingleton<ISecretsProvider, SimulatorSecretsProvider>();
        builder.Services.AddSingleton<ICryptoProvider, SimulatorCryptoProvider>();
        builder.Services.AddSingleton<IAccessControlProvider, SimulatorAccessControlProvider>();
        builder.Services.AddSingleton<IIdentityProvider, SimulatorIdentityProvider>();
        break;

    default:
        builder.Services.AddSingleton<IObjectStore, AwsS3ObjectStore>();
        builder.Services.AddSingleton<ISecretsProvider, AwsSecretsManagerProvider>();
        builder.Services.AddSingleton<ICryptoProvider, AwsKmsCryptoProvider>();
        builder.Services.AddSingleton<IAccessControlProvider, AwsAccessControlProvider>();
        builder.Services.AddSingleton<IIdentityProvider, AwsIdentityProvider>();
        break;
}

builder.Services.AddSingleton<ISigningKeyProvider, SigningKeyProvider>();
builder.Services.AddSingleton<IAdminCredentialService, AdminCredentialService>();

// Machine identity for the management plane in AWS mode: a caller's signed
// sts:GetCallerIdentity request is relayed to STS. Redirects are off, so the request reaches
// the allow-listed STS host or nothing.
builder.Services.AddHttpClient(AwsIdentityProvider.HttpClientName, c =>
    {
        c.Timeout = TimeSpan.FromSeconds(Math.Clamp(cloudOptions.AwsIdentity.TimeoutSeconds, 1, 30));
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false
    });

// Bedrock Runtime. Resolved from EffectiveBedrockProvider, not Provider: Development binds
// the control plane above to the local simulator but sends model calls to real AWS, because
// no simulator produces the model output that is actually being developed against.
// The Python simulator implements the real wire contract (POST /model/{modelId}/invoke),
// so pointing the AWS SDK at it stays pure configuration.
builder.Services.AddSingleton(_ =>
{
    var config = new AmazonBedrockRuntimeConfig
    {
        RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(gatewayOptions.Aws.Region)
    };

    if (!string.IsNullOrWhiteSpace(cloudOptions.BedrockServiceUrl))
    {
        config.ServiceURL = cloudOptions.BedrockServiceUrl;
        config.AuthenticationRegion = gatewayOptions.Aws.Region;
    }

    return config;
});

// ---------------------------------------------------------------------------
// 3. Resilient HttpClientFactory for local model providers
// ---------------------------------------------------------------------------
// Retry and breaker policy lives in LocalProviderResilience so the two rules it encodes --
// a breaker per backend, and no retry of a generation POST -- are unit-testable (SL-17).
var retryPolicy = LocalProviderResilience.BuildRetryPolicy();
var noRetryPolicy = Policy.NoOpAsync<HttpResponseMessage>();

void AddLocalProviderClient(
    string name, string backend, string baseUrl, int timeoutSeconds, bool enabled, string apiKeySecretName)
{
    var circuitBreaker = LocalProviderResilience.BuildCircuitBreaker();

    builder.Services.AddHttpClient(name, client =>
    {
        client.BaseAddress = new Uri(baseUrl);
        client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
    })
    .AddPolicyHandler(request =>
        LocalProviderResilience.IsRetryable(request) ? retryPolicy : noRetryPolicy)
    .AddPolicyHandler(circuitBreaker)
    // Innermost, so a retried request carries the backend credential too, and so a disabled
    // backend is refused on every path that reaches it (SEC-14).
    .AddHttpMessageHandler(services =>
        new LocalBackendAuthHandler(
            services.GetRequiredService<ISecretsProvider>(),
            backend,
            enabled,
            apiKeySecretName,
            enforceRemotePolicy: !builder.Environment.IsDevelopment()));
}

var localProviders = gatewayOptions.LocalProviders;
AddLocalProviderClient("OllamaClient", "Ollama", localProviders.Ollama.BaseUrl,
    localProviders.Ollama.TimeoutSeconds, localProviders.Ollama.Enabled, localProviders.Ollama.ApiKeySecretName);
AddLocalProviderClient("LmStudioClient", "LmStudio", localProviders.LmStudio.BaseUrl,
    localProviders.LmStudio.TimeoutSeconds, localProviders.LmStudio.Enabled, localProviders.LmStudio.ApiKeySecretName);
AddLocalProviderClient("LlamaCppClient", "LlamaCpp", localProviders.LlamaCpp.BaseUrl,
    localProviders.LlamaCpp.TimeoutSeconds, localProviders.LlamaCpp.Enabled, localProviders.LlamaCpp.ApiKeySecretName);

// ---------------------------------------------------------------------------
// 4. Core gateway services
// ---------------------------------------------------------------------------
// Enum values cross the API as their names ("Redact", "Block", "AuditOnly"), matching how
// they are written in appsettings. A numeric-only contract silently rejects the very value
// an operator copies out of the config file.
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(
        new System.Text.Json.Serialization.JsonStringEnumConverter()));

builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<ISecurityService, SecurityService>();
builder.Services.AddSingleton<IGuardrailService, GuardrailService>();
// IAM Roles Anywhere. The gateway runs under IIS, so there is no instance or task role to
// inherit; Test and Production exchange an X.509 certificate for short-lived credentials
// instead of holding a long-lived access key. Registered only when selected, so a
// Development host never tries to open a certificate store it has nothing in.
if (gatewayOptions.Aws.EffectiveCredentialSource == AwsCredentialSource.RolesAnywhere)
{
    builder.Services.AddHttpClient(RolesAnywhereCredentialProvider.HttpClientName, c =>
    {
        c.Timeout = TimeSpan.FromSeconds(15);
    });

    builder.Services.AddSingleton<IRolesAnywhereCredentialProvider, RolesAnywhereCredentialProvider>();
}

builder.Services.AddSingleton<ISTSService, STSService>();
builder.Services.AddSingleton<IBedrockService, BedrockService>();
builder.Services.AddSingleton<ILocalModelService, LocalModelService>();
builder.Services.AddSingleton<IAuditStore, S3AuditStore>();
builder.Services.AddSingleton<IApplicationRegistryService, ApplicationRegistryService>();
// Capabilities an application can be given. Skills today; tools, MCP servers, agents and plugins
// bind through the same catalogue as they arrive.
builder.Services.AddSingleton<ISkillRegistryService, SkillRegistryService>();
builder.Services.AddSingleton<ICapabilityService, CapabilityService>();

// The tool plane. MCP servers execute somewhere this gateway does not control, so their client
// follows no redirects and keeps no cookies: the destination an operator registered is the only
// one it talks to.
builder.Services.AddSingleton<IMcpServerRegistry, McpServerRegistry>();
builder.Services.AddSingleton<IMcpClient, McpClient>();
builder.Services.AddSingleton<IToolCatalog, ToolCatalog>();
builder.Services.AddHttpClient(McpClient.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false
    });
builder.Services.AddSingleton<IModelRouter, ModelRouter>();
builder.Services.AddSingleton<IBillingService, BillingService>();

// Development only: bring the local AWS simulator up with the gateway. Registered before the
// services that call it, because hosted services start in registration order.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddHostedService<LocalAwsSimulatorHost>();
}

builder.Services.AddHostedService<AwsCredentialBackgroundService>();
builder.Services.AddHostedService<CloudBootstrapService>();
builder.Services.AddHostedService<AuditFlushService>();

// ---------------------------------------------------------------------------
// 5. Authentication and authorization for the management plane
// ---------------------------------------------------------------------------
// Two credential shapes reach the management plane: an Okta JWT (people, signed in through
// the identity provider) and a gateway credential or STS token (automation, break-glass).
// A forwarding scheme picks the right handler by inspecting the presented token, so neither
// handler has to know about the other.
builder.Services.AddSingleton<IOktaTokenService, OktaTokenService>();
builder.Services.AddSingleton<
    Microsoft.Extensions.Options.IConfigureOptions<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>,
    ConfigureOktaJwtBearerOptions>();

builder.Services.AddAuthentication(GatewayAuth.ForwardingScheme)
    .AddPolicyScheme(GatewayAuth.ForwardingScheme, GatewayAuth.ForwardingScheme, options =>
    {
        options.ForwardDefaultSelector = context =>
            GatewayAuth.LooksLikeJwt(context) ? OktaClaims.Scheme : GatewayAuth.Scheme;
    })
    .AddScheme<AuthenticationSchemeOptions, GatewayAuthenticationHandler>(GatewayAuth.Scheme, _ => { })
    .AddJwtBearer(OktaClaims.Scheme, _ => { });

builder.Services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, IamAuthorizationHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(GatewayAuth.PlatformAdminPolicy, policy =>
    {
        policy.AddAuthenticationSchemes(GatewayAuth.ForwardingScheme);
        policy.RequireAuthenticatedUser();
    });
});

// ---------------------------------------------------------------------------
// 6. CORS
// ---------------------------------------------------------------------------
builder.Services.AddCors(options =>
{
    options.AddPolicy("GatewayCorsPolicy", policy =>
    {
        var allowedOrigins = gatewayOptions.Security.AllowedCorsOrigins
            .Where(o => !string.IsNullOrWhiteSpace(o) && o != "*")
            .ToArray();

        // No wildcard branch. An empty allow-list means no cross-origin access, which is
        // the safe reading of "nothing configured" for a service that fronts cloud credentials.
        if (allowedOrigins.Length > 0)
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        }
    });
});

// ---------------------------------------------------------------------------
// 7. Abuse controls
// ---------------------------------------------------------------------------
var maxBodyBytes = gatewayOptions.Security.MaxRequestBodyBytes;
if (maxBodyBytes > 0)
{
    builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = maxBodyBytes);
    builder.Services.Configure<IISServerOptions>(o => o.MaxRequestBodySize = maxBodyBytes);
}

var invokeLimit = gatewayOptions.Security.RateLimitPerMinute <= 0 ? 120 : gatewayOptions.Security.RateLimitPerMinute;
var tokenLimit = gatewayOptions.Security.TokenRateLimitPerMinute <= 0 ? 10 : gatewayOptions.Security.TokenRateLimitPerMinute;
var managementLimit = gatewayOptions.Security.ManagementRateLimitPerMinute <= 0 ? 60 : gatewayOptions.Security.ManagementRateLimitPerMinute;

// Per-application quotas, applied by the endpoints once a credential validates (SEC-03).
builder.Services.AddSingleton<ICallerQuota, CallerQuota>();

builder.Services.AddRateLimiter(rl =>
{
    rl.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // These limiters run before authentication, so every partition is the client address: a key,
    // token or appId the caller writes cannot pick a fresh bucket (SEC-03).
    var perAddressFloor = Math.Max(invokeLimit, managementLimit) * 2;

    // A global floor, so an endpoint that forgets to name a policy is still bounded.
    rl.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: RateLimitPartitions.ForClient(httpContext),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = perAddressFloor,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    void AddFixedWindowPolicy(string name, int permitLimit) =>
        rl.AddPolicy(name, httpContext =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: RateLimitPartitions.ForClient(httpContext),
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                }));

    // One address may front several applications, so invocation is bounded per address at the
    // floor, and per application at RateLimitPerMinute by ICallerQuota.
    AddFixedWindowPolicy("per-app", perAddressFloor);
    // Issuance stays tight per address: it is where a key would be guessed.
    AddFixedWindowPolicy("token-issuance", tokenLimit);
    AddFixedWindowPolicy("management", managementLimit);

    rl.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsync(
            "{\"error\":{\"code\":\"RATE_LIMITED\",\"message\":\"Rate limit exceeded. Please retry after the window resets.\"}}",
            token);
    };
});

// ---------------------------------------------------------------------------
// 8. OpenAPI
// ---------------------------------------------------------------------------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Universal AI LLM Gateway API",
        Version = "v1",
        Description = "Unified LLM Gateway (.NET 8) with enterprise guardrails, KMS-backed token signing, IAM-evaluated management plane, and local model failover."
    });

    c.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Description = "Application API key or STS token. Format: X-API-Key: ug_live_... | ug_sts_...",
        Type = SecuritySchemeType.ApiKey,
        Name = "X-API-Key",
        In = ParameterLocation.Header
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "ApiKey" }
            },
            Array.Empty<string>()
        }
    });
});

// Transport security, applied in the pipeline below. Browsers are redirected with a
// permanent, method-preserving 308; API paths never get as far as a redirect.
builder.Services.AddHsts(o =>
{
    o.MaxAge = TimeSpan.FromDays(Math.Max(1, gatewayOptions.Security.HstsMaxAgeDays));
    o.IncludeSubDomains = false;
});

builder.Services.AddHttpsRedirection(o =>
{
    o.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
    if (gatewayOptions.Security.HttpsPort is int httpsPort)
    {
        o.HttpsPort = httpsPort;
    }
});

var app = builder.Build();

// ---------------------------------------------------------------------------
// 9. Middleware pipeline
// ---------------------------------------------------------------------------
// Development drops the transport and authentication checks and auto-grants IAM roles, so it
// answers this machine only, however the host was bound (SEC-13).
if (app.Environment.IsDevelopment())
{
    app.UseMiddleware<DevelopmentLoopbackMiddleware>();
}

if (gatewayOptions.Security.RequireHttps)
{
    // API calls over plain HTTP are refused before anything else sees them; only what is
    // left -- a browser opening the dashboard -- is redirected.
    app.UseMiddleware<HttpsEnforcementMiddleware>();
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Security response headers.
//
// script-src stays 'self' with no 'unsafe-inline' — that is the directive that contains an
// injected script, and it is the one worth being strict about. The dashboard pulls its
// typefaces from Google Fonts, so the stylesheet and font hosts are named explicitly rather
// than the whole policy being loosened. Self-hosting those two files would let font-src and
// style-src drop back to 'self'.
const string ContentSecurityPolicy =
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data:; " +
    "connect-src 'self'; " +
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";
    headers["Content-Security-Policy"] = ContentSecurityPolicy;

    await next();
});

app.UseCors("GatewayCorsPolicy");
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

// Swagger is a complete map of the management surface: Development only.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Unified LLM Gateway v1");
        c.RoutePrefix = "swagger";
    });
}

app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        ctx.Context.Response.Headers.CacheControl = "no-cache, must-revalidate";
    }
});

// ---------------------------------------------------------------------------
// 10. Endpoints
// ---------------------------------------------------------------------------
app.MapGatewayEndpoints();
app.MapDashboardEndpoints();
app.MapCapabilityEndpoints();

// The simulator signs admin tokens for a directory compiled into the binary, so it is
// Development-only twice over: StartupValidator refuses it elsewhere, and it is not mapped.
if (oktaOptions.Enabled && app.Environment.IsDevelopment())
{
    app.MapOktaSimulatorEndpoints();
}

// Unauthenticated liveness probe. It says the process is up and nothing else: a version
// and framework string tells an attacker which advisories to read against this host (SL-13).
app.MapGet("/status", () => Results.Ok(new
{
    name = "Universal AI LLM Gateway",
    status = "Online"
}));

app.Run();

public partial class Program { }
