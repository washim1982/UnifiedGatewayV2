using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using S3Local.Data;
using S3Local.Services;
using Shared.DTOs;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<S3DbContext>((sp, options) =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var dbPath = config.GetValue<string>("DatabasePath") ?? "data/s3.db";
    var dbDir = Path.GetDirectoryName(dbPath);
    if (!string.IsNullOrEmpty(dbDir)) Directory.CreateDirectory(dbDir);
    options.UseSqlite($"Data Source={dbPath}");
});

builder.Services.AddScoped<IMetadataStore, SqliteMetadataStore>();
builder.Services.AddSingleton<IPresignService, PresignService>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddCors();

var app = builder.Build();

app.UseCors(policy => policy
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader()
    .WithExposedHeaders("ETag", "x-amz-meta-*", "x-kms-key"));

// Ensure DB created and tables exist
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<S3DbContext>();
    await db.Database.EnsureCreatedAsync();

    // EnsureCreatedAsync does not create newly added tables if the database file already exists.
    // Explicitly ensure both Buckets and Objects tables and indexes exist.
    await db.Database.ExecuteSqlRawAsync("""
        CREATE TABLE IF NOT EXISTS "Buckets" (
            "Id" INTEGER NOT NULL CONSTRAINT "PK_Buckets" PRIMARY KEY AUTOINCREMENT,
            "Name" TEXT NOT NULL,
            "Region" TEXT NOT NULL,
            "Owner" TEXT NULL,
            "CreatedAt" TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS "IX_Buckets_Name" ON "Buckets" ("Name");

        CREATE TABLE IF NOT EXISTS "Objects" (
            "Id" INTEGER NOT NULL CONSTRAINT "PK_Objects" PRIMARY KEY AUTOINCREMENT,
            "Bucket" TEXT NOT NULL,
            "Key" TEXT NOT NULL,
            "ETag" TEXT NOT NULL,
            "Size" INTEGER NOT NULL,
            "ContentType" TEXT NOT NULL,
            "MetadataJson" TEXT NULL,
            "Owner" TEXT NULL,
            "CreatedAt" TEXT NOT NULL,
            "UpdatedAt" TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS "IX_Objects_Bucket_Key" ON "Objects" ("Bucket", "Key");
    """);
}

// Helper MD5 computation
string ComputeMd5Hex(string filePath)
{
    using var fs = File.OpenRead(filePath);
    var hash = MD5.HashData(fs);
    return Convert.ToHexString(hash).ToLowerInvariant();
}

string GetDataRoot()
{
    var root = app.Configuration.GetValue<string>("DataRoot") ?? "data/buckets";
    Directory.CreateDirectory(root);
    return root;
}

// 1. PUT /{bucket}/{*key} - Stream upload
app.MapPut("/{bucket}/{*key}", async (
    string bucket,
    string key,
    HttpRequest request,
    HttpResponse response,
    IMetadataStore metaStore) =>
{
    if (string.IsNullOrWhiteSpace(bucket) || string.IsNullOrWhiteSpace(key))
    {
        return Results.BadRequest(new { error = "Bucket and key must be specified." });
    }

    // Sanitize path to prevent directory traversal
    var safeKey = key.TrimStart('/', '\\').Replace('\\', '/');
    var bucketDir = Path.Combine(GetDataRoot(), bucket);
    var fullPath = Path.GetFullPath(Path.Combine(bucketDir, safeKey));

    if (!fullPath.StartsWith(Path.GetFullPath(bucketDir), StringComparison.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { error = "Invalid key path." });
    }

    var parentDir = Path.GetDirectoryName(fullPath);
    if (!string.IsNullOrEmpty(parentDir))
    {
        Directory.CreateDirectory(parentDir);
    }

    await using (var fs = File.Create(fullPath))
    {
        await request.Body.CopyToAsync(fs);
    }

    var fileInfo = new FileInfo(fullPath);
    var etag = ComputeMd5Hex(fullPath);

    // Extract metadata from headers
    var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var header in request.Headers)
    {
        if (header.Key.StartsWith("x-amz-meta-", StringComparison.OrdinalIgnoreCase))
        {
            var metaKey = header.Key["x-amz-meta-".Length..];
            metadata[metaKey] = header.Value.ToString();
        }
        else if (header.Key.Equals("x-kms-key", StringComparison.OrdinalIgnoreCase))
        {
            metadata["x-kms-key"] = header.Value.ToString();
        }
    }

    var owner = request.HttpContext.User.Identity?.Name ?? "dev-user";
    await metaStore.UpsertAsync(bucket, safeKey, etag, fileInfo.Length, request.ContentType, metadata, owner);

    response.Headers.ETag = $"\"{etag}\"";
    return Results.Ok(new PutObjectResponse(etag));
}).Accepts<Stream>("*/*");

// 2. GET /{bucket}/{*key} - Stream download with range processing
app.MapGet("/{bucket}/{*key}", async (
    string bucket,
    string key,
    [FromQuery] string? token,
    HttpRequest request,
    HttpResponse response,
    IMetadataStore metaStore,
    IPresignService presignService) =>
{
    var safeKey = key.TrimStart('/', '\\').Replace('\\', '/');
    var bucketDir = Path.Combine(GetDataRoot(), bucket);
    var fullPath = Path.GetFullPath(Path.Combine(bucketDir, safeKey));

    if (!fullPath.StartsWith(Path.GetFullPath(bucketDir), StringComparison.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { error = "Invalid key path." });
    }

    // Validate presign token if present
    if (!string.IsNullOrWhiteSpace(token))
    {
        if (!presignService.ValidatePresignedToken(bucket, safeKey, token))
        {
            return Results.Json(new { error = "Invalid or expired presigned token." }, statusCode: 403);
        }
    }

    if (!File.Exists(fullPath))
    {
        return Results.NotFound(new { error = $"Object '{safeKey}' not found in bucket '{bucket}'." });
    }

    var meta = await metaStore.GetAsync(bucket, safeKey);
    var contentType = meta?.ContentType ?? "application/octet-stream";
    var etag = meta?.ETag ?? ComputeMd5Hex(fullPath);

    response.Headers.ETag = $"\"{etag}\"";

    // Set custom metadata headers
    if (!string.IsNullOrWhiteSpace(meta?.MetadataJson))
    {
        try
        {
            var customMeta = JsonSerializer.Deserialize<Dictionary<string, string>>(meta.MetadataJson);
            if (customMeta != null)
            {
                foreach (var (k, v) in customMeta)
                {
                    response.Headers[$"x-amz-meta-{k}"] = v;
                    response.Headers[k] = v; // Also expose directly
                }
            }
        }
        catch
        {
            // Ignore corrupted metadata JSON
        }
    }

    return Results.File(fullPath, contentType: contentType, enableRangeProcessing: true);
});

// 3. DELETE /{bucket}/{*key} - Delete object and metadata
app.MapDelete("/{bucket}/{*key}", async (
    string bucket,
    string key,
    IMetadataStore metaStore) =>
{
    var safeKey = key.TrimStart('/', '\\').Replace('\\', '/');
    var bucketDir = Path.Combine(GetDataRoot(), bucket);
    var fullPath = Path.GetFullPath(Path.Combine(bucketDir, safeKey));

    if (File.Exists(fullPath))
    {
        File.Delete(fullPath);
    }

    await metaStore.DeleteAsync(bucket, safeKey);
    return Results.NoContent();
});

// 4. GET /presign - Return presigned token and URL
app.MapGet("/presign", (
    [FromQuery] string bucket,
    [FromQuery] string key,
    [FromQuery] int? durationSeconds,
    HttpRequest request,
    IPresignService presignService) =>
{
    if (string.IsNullOrWhiteSpace(bucket) || string.IsNullOrWhiteSpace(key))
    {
        return Results.BadRequest(new { error = "Bucket and key are required query parameters." });
    }

    var duration = TimeSpan.FromSeconds(durationSeconds ?? 3600);
    var token = presignService.CreatePresignedToken(bucket, key, duration);
    var baseUrl = $"{request.Scheme}://{request.Host}";
    var url = $"{baseUrl}/{bucket}/{key}?token={Uri.EscapeDataString(token)}";

    return Results.Ok(new PresignResponse(url, DateTime.UtcNow.Add(duration)));
});

// Bucket Management Endpoints
app.MapGet("/buckets", async (IMetadataStore metaStore) =>
{
    var list = await metaStore.ListBucketsAsync();
    return Results.Ok(list);
});

app.MapPost("/buckets", async ([FromBody] CreateBucketRequest req, IMetadataStore metaStore) =>
{
    if (string.IsNullOrWhiteSpace(req.Name))
    {
        return Results.BadRequest(new { error = "Bucket name is required." });
    }
    var safeName = req.Name.Trim().ToLowerInvariant();
    var bucketDir = Path.Combine(GetDataRoot(), safeName);
    Directory.CreateDirectory(bucketDir);
    var created = await metaStore.CreateBucketAsync(safeName, req.Region ?? "us-east-1");
    return Results.Ok(new { message = "Bucket created successfully.", name = safeName, created });
});

app.MapDelete("/buckets/{bucket}", async (string bucket, IMetadataStore metaStore) =>
{
    var safeName = bucket.Trim().ToLowerInvariant();
    var bucketDir = Path.Combine(GetDataRoot(), safeName);
    if (Directory.Exists(bucketDir))
    {
        try { Directory.Delete(bucketDir, recursive: true); } catch { }
    }
    await metaStore.DeleteBucketAsync(safeName);
    return Results.Ok(new { message = $"Bucket '{safeName}' deleted." });
});

app.MapGet("/buckets/{bucket}/objects", async (string bucket, [FromQuery] string? prefix, IMetadataStore metaStore) =>
{
    var objects = await metaStore.ListObjectsAsync(bucket, prefix);
    return Results.Ok(objects);
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
        service = "S3Local",
        version = "1.0",
        status = "Healthy",
        endpoints = new[]
        {
            "GET /buckets",
            "POST /buckets",
            "DELETE /buckets/{bucket}",
            "GET /buckets/{bucket}/objects",
            "PUT /{bucket}/{*key}",
            "GET /{bucket}/{*key}",
            "DELETE /{bucket}/{*key}",
            "GET /presign",
            "GET /dashboard",
            "GET /health"
        }
    });
});

app.MapGet("/health", () => Results.Ok(new { status = "Healthy", service = "S3Local" }));

app.Run();

public record CreateBucketRequest(string Name, string? Region = "us-east-1");

namespace S3Local
{
    public partial class Program { }
}
