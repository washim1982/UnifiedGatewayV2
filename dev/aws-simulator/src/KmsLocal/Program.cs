using System.Security.Cryptography;
using KmsLocal.Services;
using Microsoft.AspNetCore.Mvc;
using Shared.DTOs;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IMasterKeyStore, DevMasterKeyStore>();
builder.Services.AddSingleton<IKmsCryptoService, KmsCryptoService>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddCors();

var app = builder.Build();

app.UseCors(policy => policy
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader()
    .WithExposedHeaders("ETag", "x-amz-meta-*", "x-kms-key"));

app.MapPost("/generate-data-key", (
    [FromBody] GenerateDataKeyRequest req,
    IKmsCryptoService cryptoService) =>
{
    var keyId = string.IsNullOrWhiteSpace(req.KeyId) ? "default" : req.KeyId;
    var keySizeBits = req.KeySizeBits ?? 256;

    try
    {
        var result = cryptoService.GenerateDataKey(keyId, keySizeBits);
        return Results.Ok(result);
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/encrypt", (
    [FromBody] EncryptRequest req,
    IKmsCryptoService cryptoService) =>
{
    var keyId = string.IsNullOrWhiteSpace(req.KeyId) ? "default" : req.KeyId;
    if (string.IsNullOrEmpty(req.PlaintextBase64))
    {
        return Results.BadRequest(new { error = "PlaintextBase64 is required." });
    }

    try
    {
        var plaintext = Convert.FromBase64String(req.PlaintextBase64);
        var ciphertextBlob = cryptoService.Encrypt(keyId, plaintext);
        return Results.Ok(new EncryptResponse(Convert.ToBase64String(ciphertextBlob)));
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = "Invalid Base64 in PlaintextBase64." });
    }
    catch (Exception ex)
    {
        return Results.Problem(detail: ex.Message, statusCode: 500);
    }
});

app.MapPost("/decrypt", (
    [FromBody] DecryptRequest req,
    IKmsCryptoService cryptoService) =>
{
    var keyId = string.IsNullOrWhiteSpace(req.KeyId) ? "default" : req.KeyId;
    if (string.IsNullOrEmpty(req.CiphertextBlobBase64))
    {
        return Results.BadRequest(new { error = "CiphertextBlobBase64 is required." });
    }

    try
    {
        var ciphertextBlob = Convert.FromBase64String(req.CiphertextBlobBase64);
        var plaintext = cryptoService.Decrypt(keyId, ciphertextBlob);
        return Results.Ok(new DecryptResponse(Convert.ToBase64String(plaintext)));
    }
    catch (CryptographicException)
    {
        return Results.Json(new { error = "Decryption failed. The ciphertext may have been tampered with or encrypted with a different key." }, statusCode: 400);
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = "Invalid Base64 in CiphertextBlobBase64." });
    }
    catch (Exception ex)
    {
        return Results.Problem(detail: ex.Message, statusCode: 500);
    }
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
        service = "KmsLocal",
        version = "1.0",
        status = "Healthy",
        endpoints = new[]
        {
            "POST /generate-data-key",
            "POST /encrypt",
            "POST /decrypt",
            "GET /dashboard",
            "GET /health"
        }
    });
});

app.MapGet("/health", () => Results.Ok(new { status = "Healthy", service = "KmsLocal" }));

app.Run();

namespace KmsLocal
{
    public partial class Program { }
}
