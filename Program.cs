using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.OpenApi.Models;
using Polly;
using Polly.Extensions.Http;
using UnifiedGateway.Endpoints;
using UnifiedGateway.Models;
using UnifiedGateway.Services;

var builder = WebApplication.CreateBuilder(args);

// 1. Strongly Typed Configuration
builder.Services.Configure<GatewayOptions>(
    builder.Configuration.GetSection(GatewayOptions.SectionName));

var gatewayOptions = builder.Configuration
    .GetSection(GatewayOptions.SectionName)
    .Get<GatewayOptions>() ?? new GatewayOptions();

// 2. Data Protection API for secure token & key encryption
var dataProtectionKeysPath = Path.Combine(AppContext.BaseDirectory, "dataprotection-keys");
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("UnifiedLLMGateway")
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath));

// On Windows / IIS, encrypt the key ring at rest with machine-level DPAPI so it works
// under an app-pool identity that has no loaded user profile.
if (OperatingSystem.IsWindows())
{
    dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);
}

// 3. Resilient HttpClientFactory for Local Providers
var retryPolicy = HttpPolicyExtensions
    .HandleTransientHttpError()
    .Or<TimeoutException>()
    .WaitAndRetryAsync(2, retryAttempt =>
        TimeSpan.FromMilliseconds(200 * Math.Pow(2, retryAttempt)));

builder.Services.AddHttpClient("OllamaClient", client =>
{
    client.BaseAddress = new Uri(gatewayOptions.LocalProviders.Ollama.BaseUrl);
    client.Timeout = TimeSpan.FromSeconds(gatewayOptions.LocalProviders.Ollama.TimeoutSeconds);
}).AddPolicyHandler(retryPolicy);

builder.Services.AddHttpClient("LmStudioClient", client =>
{
    client.BaseAddress = new Uri(gatewayOptions.LocalProviders.LmStudio.BaseUrl);
    client.Timeout = TimeSpan.FromSeconds(gatewayOptions.LocalProviders.LmStudio.TimeoutSeconds);
}).AddPolicyHandler(retryPolicy);

builder.Services.AddHttpClient("LlamaCppClient", client =>
{
    client.BaseAddress = new Uri(gatewayOptions.LocalProviders.LlamaCpp.BaseUrl);
    client.Timeout = TimeSpan.FromSeconds(gatewayOptions.LocalProviders.LlamaCpp.TimeoutSeconds);
}).AddPolicyHandler(retryPolicy);

// 4. Core Gateway Services Registration
builder.Services.AddSingleton<ISecurityService, SecurityService>();
builder.Services.AddSingleton<IGuardrailService, GuardrailService>();
builder.Services.AddSingleton<ISTSService, STSService>();
builder.Services.AddSingleton<IBedrockService, BedrockService>();
builder.Services.AddSingleton<ILocalModelService, LocalModelService>();
builder.Services.AddSingleton<IApplicationRegistryService, ApplicationRegistryService>();
builder.Services.AddSingleton<IModelRouter, ModelRouter>();

// 5. Credential Auto-Refresh Background Service
builder.Services.AddHostedService<AwsCredentialBackgroundService>();

// 6. CORS Policy
builder.Services.AddCors(options =>
{
    options.AddPolicy("GatewayCorsPolicy", policy =>
    {
        var allowedOrigins = gatewayOptions.Security.AllowedCorsOrigins;
        if (allowedOrigins.Contains("*"))
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        }
        else
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        }
    });
});

// 6a. Abuse control: cap the accepted HTTP request body size (Kestrel and IIS in-process)
var maxBodyBytes = gatewayOptions.Security.MaxRequestBodyBytes;
if (maxBodyBytes > 0)
{
    builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = maxBodyBytes);
    builder.Services.Configure<IISServerOptions>(o => o.MaxRequestBodySize = maxBodyBytes);
}

// 6b. Rate Limiting (enforces Gateway:Security:RateLimitPerMinute, partitioned per caller)
var rateLimitPerMinute = gatewayOptions.Security.RateLimitPerMinute <= 0
    ? 120
    : gatewayOptions.Security.RateLimitPerMinute;

builder.Services.AddRateLimiter(rl =>
{
    rl.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    rl.AddPolicy("per-app", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ResolveRatePartition(httpContext),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateLimitPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    rl.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsync(
            "{\"error\":{\"code\":\"RATE_LIMITED\",\"message\":\"Rate limit exceeded. Please retry after the window resets.\"}}",
            token);
    };
});

// 7. OpenAPI / Swagger Documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Universal AI LLM Gateway API",
        Version = "v1",
        Description = "Enterprise-grade Unified LLM Gateway (.NET 8) with Enterprise Guardrails (PII/PCI/Secrets), dynamic Bedrock STS assume-role, local model failover, and automated application routing."
    });

    c.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Description = "Application API Key header. Format: X-API-Key: ug_live_...",
        Type = SecuritySchemeType.ApiKey,
        Name = "X-API-Key",
        In = ParameterLocation.Header
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// 8. Middleware Pipeline
app.UseCors("GatewayCorsPolicy");
app.UseRateLimiter();

if (app.Environment.IsDevelopment() || app.Environment.IsStaging() || app.Environment.IsEnvironment("Test"))
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Unified LLM Gateway v1");
        c.RoutePrefix = "swagger";
    });
}

// Serve embedded dashboard
app.UseDefaultFiles();
app.UseStaticFiles();

// 9. Map Minimal API Endpoints
app.MapGatewayEndpoints();
app.MapDashboardEndpoints();

// Root redirect to Dashboard
app.MapGet("/status", () => Results.Ok(new
{
    name = "Universal AI LLM Gateway",
    version = "1.0.0",
    framework = ".NET 8 Minimal API",
    guardrails = "Enabled (PII, PCI, Secrets, Prompt Injection)",
    status = "Online",
    dashboard = "/",
    swagger = "/swagger"
}));

app.Run();

// Partition rate limiting by caller: presented API key / STS token (hashed), else appId, else IP.
static string ResolveRatePartition(HttpContext ctx)
{
    var key = ctx.Request.Headers["X-API-Key"].ToString();
    if (string.IsNullOrWhiteSpace(key))
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        key = auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? auth[7..] : auth;
    }

    if (!string.IsNullOrWhiteSpace(key))
    {
        var hash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(key.Trim())));
        return "k:" + hash[..16];
    }

    if (ctx.Request.RouteValues.TryGetValue("appId", out var appId) && appId is string s && !string.IsNullOrWhiteSpace(s))
        return "a:" + s;

    return "ip:" + (ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown");
}
