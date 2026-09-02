using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using UnifiedGateway.Services;
using Xunit;

namespace UnifiedGateway.Tests;

public class SecurityServiceTests
{
    private readonly ISecurityService _securityService;

    public SecurityServiceTests()
    {
        var dataProtectionProvider = new EphemeralDataProtectionProvider();
        _securityService = new SecurityService(dataProtectionProvider, NullLogger<SecurityService>.Instance);
    }

    [Fact]
    public void GenerateApiKey_ShouldReturnValidFormatAndMatchingHash()
    {
        var (rawKey, keyHash, keyPrefix) = _securityService.GenerateApiKey();

        Assert.StartsWith("ug_live_", rawKey);
        Assert.Equal(12, keyPrefix.Length);
        Assert.NotEmpty(keyHash);
        Assert.True(_securityService.VerifyKey(rawKey, keyHash));
    }

    [Fact]
    public void VerifyKey_WithInvalidKey_ShouldReturnFalse()
    {
        var (rawKey, keyHash, _) = _securityService.GenerateApiKey();
        var invalidKey = rawKey + "invalid";

        Assert.False(_securityService.VerifyKey(invalidKey, keyHash));
    }

    [Fact]
    public void EncryptAndDecrypt_ShouldPreserveOriginalText()
    {
        var secret = "arn:aws:iam::123456789012:role/BedrockExecutionRole";

        var encrypted = _securityService.Encrypt(secret);
        Assert.NotEqual(secret, encrypted);

        var decrypted = _securityService.Decrypt(encrypted);
        Assert.Equal(secret, decrypted);
    }

    [Fact]
    public void MaskSecret_ShouldMaskMiddleCharacters()
    {
        var secret = "arn:aws:iam::123456789012:role/BedrockExecutionRole";
        var masked = _securityService.MaskSecret(secret, 4);

        Assert.StartsWith("arn:", masked);
        Assert.EndsWith("Role", masked);
        Assert.Contains("******", masked);
    }

    #region Application STS Token Tests

    [Fact]
    public void IssueAppStsToken_ReturnsValidTokenFormatAndExpiry()
    {
        var (token, expiresAt) = _securityService.IssueAppStsToken(
            appId: "invoice-analyzer",
            duration: TimeSpan.FromMinutes(30),
            scope: "invoke",
            isAdmin: false,
            callerId: "client-worker-1");

        Assert.StartsWith("ug_sts_", token);
        Assert.True(expiresAt > DateTimeOffset.UtcNow);
        Assert.True(expiresAt <= DateTimeOffset.UtcNow.AddMinutes(31));
    }

    [Fact]
    public void ValidateAppStsToken_WithValidToken_ReturnsValidClaims()
    {
        var (token, _) = _securityService.IssueAppStsToken(
            appId: "invoice-analyzer",
            duration: TimeSpan.FromHours(1),
            scope: "invoke",
            isAdmin: false,
            callerId: "client-worker-1");

        var (isValid, payload, failureReason) = _securityService.ValidateAppStsToken(token);

        Assert.True(isValid);
        Assert.Null(failureReason);
        Assert.NotNull(payload);
        Assert.Equal("invoice-analyzer", payload.AppId);
        Assert.Equal("invoke", payload.Scope);
        Assert.False(payload.IsAdmin);
        Assert.Equal("client-worker-1", payload.CallerId);
    }

    [Fact]
    public void ValidateAppStsToken_WithBearerPrefix_TrimsAndValidates()
    {
        var (token, _) = _securityService.IssueAppStsToken(
            appId: "finance-bot",
            duration: TimeSpan.FromMinutes(15));

        var bearerToken = $"Bearer {token}";
        var (isValid, payload, _) = _securityService.ValidateAppStsToken(bearerToken);

        Assert.True(isValid);
        Assert.NotNull(payload);
        Assert.Equal("finance-bot", payload.AppId);
    }

    [Fact]
    public void ValidateAppStsToken_WithTamperedPayload_FailsSignature()
    {
        var (token, _) = _securityService.IssueAppStsToken(
            appId: "app-original",
            duration: TimeSpan.FromHours(1));

        // Tamper with payload
        var parts = token.Split('.');
        var tamperedToken = parts[0] + "tamper." + parts[1];

        var (isValid, payload, failureReason) = _securityService.ValidateAppStsToken(tamperedToken);

        Assert.False(isValid);
        Assert.Null(payload);
        Assert.NotNull(failureReason);
        Assert.NotEmpty(failureReason);
    }

    [Fact]
    public void InspectAppStsToken_ReturnsAccurateTTLAndClaims()
    {
        var (token, _) = _securityService.IssueAppStsToken(
            appId: "test-app",
            duration: TimeSpan.FromSeconds(120),
            scope: "invoke",
            isAdmin: true);

        var inspect = _securityService.InspectAppStsToken(token);

        Assert.True(inspect.IsValid);
        Assert.False(inspect.IsExpired);
        Assert.Equal("test-app", inspect.AppId);
        Assert.True(inspect.IsAdmin);
        Assert.NotNull(inspect.ExpiresInSeconds);
        Assert.True(inspect.ExpiresInSeconds > 0 && inspect.ExpiresInSeconds <= 120);
    }

    #endregion
}
