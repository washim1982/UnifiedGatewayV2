using UnifiedGateway.Models;
using UnifiedGateway.Services;
using Xunit;

namespace UnifiedGatewayV2.Tests;

public class SecurityServiceTests
{
    private readonly ISecurityService _securityService;
    private readonly InMemorySigningKeyProvider _signingKeys;

    public SecurityServiceTests()
    {
        (_securityService, _signingKeys) = TestFactory.CreateSecurityService();
    }

    [Fact]
    public async Task GenerateApiKey_ShouldReturnValidFormatAndMatchingHash()
    {
        var (rawKey, keyHash, keyPrefix) = _securityService.GenerateApiKey();

        Assert.StartsWith("ug_live_", rawKey);
        Assert.Equal(12, keyPrefix.Length);
        Assert.NotEmpty(keyHash);
        Assert.True(_securityService.VerifyKey(rawKey, keyHash));
    }

    [Fact]
    public async Task VerifyKey_WithInvalidKey_ShouldReturnFalse()
    {
        var (rawKey, keyHash, _) = _securityService.GenerateApiKey();
        var invalidKey = rawKey + "invalid";

        Assert.False(_securityService.VerifyKey(invalidKey, keyHash));
    }

    [Fact]
    public async Task EncryptAndDecrypt_ShouldPreserveOriginalText()
    {
        var secret = "arn:aws:iam::123456789012:role/BedrockExecutionRole";

        var encrypted = await _securityService.EncryptAsync(secret);
        Assert.NotEqual(secret, encrypted);

        var decrypted = await _securityService.DecryptAsync(encrypted);
        Assert.Equal(secret, decrypted);
    }

    [Fact]
    public async Task MaskSecret_ShouldMaskMiddleCharacters()
    {
        var secret = "arn:aws:iam::123456789012:role/BedrockExecutionRole";
        var masked = _securityService.MaskSecret(secret, 4);

        Assert.StartsWith("arn:", masked);
        Assert.EndsWith("Role", masked);
        Assert.Contains("******", masked);
    }

    #region Application STS Token Tests

    [Fact]
    public async Task IssueAppStsToken_ReturnsValidTokenFormatAndExpiry()
    {
        var (token, expiresAt) = await _securityService.IssueAppStsTokenAsync(
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
    public async Task ValidateAppStsToken_WithValidToken_ReturnsValidClaims()
    {
        var (token, _) = await _securityService.IssueAppStsTokenAsync(
            appId: "invoice-analyzer",
            duration: TimeSpan.FromHours(1),
            scope: "invoke",
            isAdmin: false,
            callerId: "client-worker-1");

        var (isValid, payload, failureReason) = await _securityService.ValidateAppStsTokenAsync(token);

        Assert.True(isValid);
        Assert.Null(failureReason);
        Assert.NotNull(payload);
        Assert.Equal("invoice-analyzer", payload.AppId);
        Assert.Equal("invoke", payload.Scope);
        Assert.False(payload.IsAdmin);
        Assert.Equal("client-worker-1", payload.CallerId);
    }

    [Fact]
    public async Task ValidateAppStsToken_WithBearerPrefix_TrimsAndValidates()
    {
        var (token, _) = await _securityService.IssueAppStsTokenAsync(
            appId: "finance-bot",
            duration: TimeSpan.FromMinutes(15));

        var bearerToken = $"Bearer {token}";
        var (isValid, payload, _) = await _securityService.ValidateAppStsTokenAsync(bearerToken);

        Assert.True(isValid);
        Assert.NotNull(payload);
        Assert.Equal("finance-bot", payload.AppId);
    }

    [Fact]
    public async Task ValidateAppStsToken_WithTamperedPayload_FailsSignature()
    {
        var (token, _) = await _securityService.IssueAppStsTokenAsync(
            appId: "app-original",
            duration: TimeSpan.FromHours(1));

        // Tamper with payload
        var parts = token.Split('.');
        var tamperedToken = parts[0] + "tamper." + parts[1];

        var (isValid, payload, failureReason) = await _securityService.ValidateAppStsTokenAsync(tamperedToken);

        Assert.False(isValid);
        Assert.Null(payload);
        Assert.NotNull(failureReason);
        Assert.NotEmpty(failureReason);
    }

    [Fact]
    public async Task InspectAppStsToken_ReturnsAccurateTTLAndClaims()
    {
        var (token, _) = await _securityService.IssueAppStsTokenAsync(
            appId: "test-app",
            duration: TimeSpan.FromSeconds(120),
            scope: "invoke",
            isAdmin: true);

        var inspect = await _securityService.InspectAppStsTokenAsync(token);

        Assert.True(inspect.IsValid);
        Assert.False(inspect.IsExpired);
        Assert.Equal("test-app", inspect.AppId);
        Assert.True(inspect.IsAdmin);
        Assert.NotNull(inspect.ExpiresInSeconds);
        Assert.True(inspect.ExpiresInSeconds > 0 && inspect.ExpiresInSeconds <= 120);
    }

    #endregion
}
