using System.Text.Json;
using IamLocal.Data;
using IamLocal.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Shared.DTOs;
using Shared.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<IamDbContext>((sp, options) =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var dbPath = config.GetValue<string>("DatabasePath") ?? "data/iam.db";
    var dbDir = Path.GetDirectoryName(dbPath);
    if (!string.IsNullOrEmpty(dbDir)) Directory.CreateDirectory(dbDir);
    options.UseSqlite($"Data Source={dbPath}");
});

builder.Services.AddScoped<IRoleStore, SqliteRoleStore>();
builder.Services.AddSingleton<IRsaKeyProvider, RsaKeyProvider>();
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
// The trust anchor CA is process-wide state: loading it per request meant disk and crypto
// work on every call, and let two cold-start requests race to generate different CAs.
builder.Services.AddSingleton<ITrustAnchorProvider, TrustAnchorProvider>();
builder.Services.AddScoped<IRolesAnywhereService, RolesAnywhereService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddCors();

var app = builder.Build();

app.UseCors(policy => policy
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader()
    .WithExposedHeaders("ETag", "x-amz-meta-*", "x-kms-key"));

// Ensure DB created and seeded
using (var scope = app.Services.CreateScope())
{
    var roleStore = scope.ServiceProvider.GetRequiredService<IRoleStore>();
    await roleStore.SeedDefaultRolesAsync();
}

// Endpoints

app.MapPost("/assume-role", async (
    [FromBody] AssumeRoleRequest req,
    IRoleStore roleStore,
    IJwtTokenService tokenService) =>
{
    var role = await roleStore.GetRoleByNameAsync(req.RoleName);
    if (role == null)
    {
        // Auto-create dev role if it doesn't exist for dev convenience
        role = new IamRole
        {
            Name = req.RoleName,
            Arn = $"arn:aws:iam::123456789012:role/{req.RoleName}",
            Description = $"Auto-generated dev role {req.RoleName}",
            Policies = new List<IamPolicy>
            {
                new IamPolicy
                {
                    Version = "2012-10-17",
                    Statement = new List<PolicyStatement>
                    {
                        new PolicyStatement
                        {
                            Effect = "Allow",
                            Action = new List<string> { "*" },
                            Resource = new List<string> { "*" }
                        }
                    }
                }
            }
        };
        await roleStore.AddOrUpdateRoleAsync(role);
    }

    var token = tokenService.GenerateToken(role, req.DurationSeconds ?? 3600);
    return Results.Ok(token);
});

app.MapPost("/get-caller-identity", (
    [FromBody(EmptyBodyBehavior = Microsoft.AspNetCore.Mvc.ModelBinding.EmptyBodyBehavior.Allow)] GetCallerIdentityRequest? req,
    HttpContext httpContext,
    IJwtTokenService tokenService) =>
{
    // Extract token from request body or Authorization header
    string? jwt = req?.Jwt;
    if (string.IsNullOrWhiteSpace(jwt))
    {
        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            jwt = authHeader["Bearer ".Length..].Trim();
        }
    }

    if (string.IsNullOrWhiteSpace(jwt))
    {
        return Results.BadRequest(new { error = "No JWT token provided in body or Authorization header." });
    }

    try
    {
        var identity = tokenService.ValidateAndGetIdentity(jwt);
        return Results.Ok(identity);
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = "Invalid or expired token", message = ex.Message }, statusCode: 401);
    }
});

app.MapGet("/.well-known/jwks.json", (IRsaKeyProvider keyProvider) =>
{
    var jwk = keyProvider.GetJsonWebKey();
    return Results.Ok(new { keys = new[] { jwk } });
});

app.MapGet("/public-key", (IRsaKeyProvider keyProvider) =>
{
    var jwk = keyProvider.GetJsonWebKey();
    return Results.Ok(jwk);
});

// Roles Anywhere Endpoints
app.MapGet("/rolesanywhere/trust-anchors", (IRolesAnywhereService rolesAnywhereService) =>
{
    return Results.Ok(rolesAnywhereService.ListTrustAnchors());
});

app.MapGet("/rolesanywhere/profiles", (IRolesAnywhereService rolesAnywhereService) =>
{
    return Results.Ok(rolesAnywhereService.ListProfiles());
});

app.MapPost("/rolesanywhere/generate-test-cert", (
    [FromQuery] string? subject,
    [FromQuery] int? validityDays,
    IRolesAnywhereService rolesAnywhereService) =>
{
    // validityDays may be negative, which issues an already-expired certificate so that
    // certificate expiry can be rehearsed rather than only discovered.
    var result = rolesAnywhereService.GenerateTestCertificate(
        subject ?? "CN=LocalWorkloadClient", validityDays ?? 730);
    return Results.Ok(result);
});

// AWS-compatible CreateSession.
//
// Mirrors https://rolesanywhere.{region}.amazonaws.com/sessions exactly -- AWS4-X509 signing,
// the X-Amz-X509 header, and the credentialSet response shape -- so a client moves between
// this simulator and real AWS by changing a URL and nothing else. The older
// /rolesanywhere/create-session below speaks a simplified contract of our own and is kept for
// the dashboard demo; it is not what a production client should be written against.
app.MapPost("/sessions", async (HttpContext ctx, IRolesAnywhereService rolesAnywhereService) =>
{
    // The signature covers the raw body, so it has to be read as text and used verbatim.
    // Re-serialising a deserialised object would not reproduce the same bytes.
    ctx.Request.EnableBuffering();
    string body;
    using (var reader = new StreamReader(ctx.Request.Body, leaveOpen: true))
    {
        body = await reader.ReadToEndAsync();
    }
    ctx.Request.Body.Position = 0;

    var region = ctx.RequestServices.GetRequiredService<IConfiguration>()
        .GetValue<string>("Region") ?? "us-east-1";

    var (verified, verifyError, caller) = AwsSigV4X509Verifier.Verify(ctx.Request, body, region);
    if (!verified)
    {
        // AWS answers 403 for every authentication failure here, with no detail. We return the
        // reason, because the entire point of running this locally is to find out which of the
        // dozen possible causes it actually was.
        return Results.Json(new { message = verifyError }, statusCode: 403);
    }

    AwsCreateSessionRequest? request;
    try
    {
        request = JsonSerializer.Deserialize<AwsCreateSessionRequest>(body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = $"Request body is not valid JSON: {ex.Message}" });
    }

    if (request is null)
    {
        return Results.BadRequest(new { message = "Request body is required." });
    }

    var (issued, failure, credentials, subjectArn) =
        await rolesAnywhereService.CreateAwsSessionAsync(caller!, request);

    if (!issued)
    {
        return Results.Json(new { message = failure }, statusCode: 403);
    }

    var roleName = request.RoleArn!.Split('/').Last();
    var sessionName = string.IsNullOrWhiteSpace(request.SessionName) ? "session" : request.SessionName;

    return Results.Ok(new AwsCreateSessionResponse(
        CredentialSet:
        [
            new AwsCredentialSetEntry(
                AssumedRoleUser: new AwsAssumedRoleUser(
                    Arn: $"arn:aws:sts::123456789012:assumed-role/{roleName}/{sessionName}",
                    AssumedRoleId: $"AROA{roleName.ToUpperInvariant()}:{sessionName}"),
                Credentials: new AwsSessionCredentials(
                    AccessKeyId: credentials!.AccessKeyId,
                    SecretAccessKey: credentials.SecretAccessKey,
                    SessionToken: credentials.SessionToken,
                    Expiration: credentials.Expiration.ToUniversalTime().ToString("o")),
                PackedPolicySize: 0,
                SourceIdentity: caller!.Certificate.Subject),
        ],
        SubjectArn: subjectArn ?? string.Empty));
});

app.MapPost("/rolesanywhere/create-session", async ([FromBody] CreateSessionRequest req, IRolesAnywhereService rolesAnywhereService) =>
{
    var (success, errorMessage, credentials) = await rolesAnywhereService.CreateSessionAsync(req);
    if (!success)
    {
        if (errorMessage != null && errorMessage.Contains("Signature verification failed"))
        {
            return Results.Json(new { error = "Unauthorized", message = errorMessage }, statusCode: 401);
        }
        if (errorMessage != null && errorMessage.Contains("not found"))
        {
            return Results.Json(new { error = "NotFound", message = errorMessage }, statusCode: 404);
        }
        return Results.BadRequest(new { error = "BadRequest", message = errorMessage });
    }

    return Results.Ok(new CreateSessionResponse(credentials!));
});

// The console probes all three services from the browser, so it is told where they are rather
// than assuming the default ports.
string DashboardPage() => Shared.Dashboard.DashboardHtml.GetHtml(
    app.Configuration["S3Url"], app.Configuration["KmsUrl"], app.Configuration["IamUrl"]);

app.MapGet("/dashboard", () => Results.Content(DashboardPage(), "text/html"));

app.MapGet("/", (HttpRequest request) =>
{
    if (request.Headers.Accept.ToString().Contains("text/html"))
    {
        return Results.Content(DashboardPage(), "text/html");
    }

    return Results.Ok(new
    {
        service = "IamLocal",
        version = "1.0",
        status = "Healthy",
        endpoints = new[]
        {
            "POST /assume-role",
            "POST /get-caller-identity",
            "GET /.well-known/jwks.json",
            "GET /public-key",
            "GET /dashboard",
            "GET /health"
        }
    });
});

app.MapGet("/health", () => Results.Ok(new { status = "Healthy", service = "IamLocal" }));

app.Run();

namespace IamLocal
{
    public partial class Program { }
}
