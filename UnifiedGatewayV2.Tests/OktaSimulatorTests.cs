using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Okta;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// Covers the simulated identity provider: the hard-coded directory, token issuance, and
/// the group-to-role mapping that authorization is built on.
/// </summary>
public class OktaSimulatorTests
{
    private const string AdminEmail = "wasim.khan@gmail.com";
    private const string AdminPassword = "Admin@12345";
    private const string DevEmail = "dev-user@gmail.com";
    private const string DevPassword = "Dev@12345";

    private static OktaOptions DefaultOptions() => new()
    {
        Enabled = true,
        Issuer = "https://okta-sim.local/oauth2/default",
        Audience = "unified-gateway",
        TokenLifetimeMinutes = 60,
        GroupRoleMappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [OktaDirectory.AdminGroup] = "arn:aws:iam::123456789012:role/GatewayPlatformAdminRole",
            [OktaDirectory.DeveloperGroup] = "arn:aws:iam::123456789012:role/GatewayDeveloperRole"
        }
    };

    private static OktaTokenService CreateService(OktaOptions? options = null) =>
        new(Options.Create(options ?? DefaultOptions()), NullLogger<OktaTokenService>.Instance);

    // --- Directory -----------------------------------------------------------------

    [Fact]
    public void Directory_ContainsBothUsersInTheirGroups()
    {
        var admin = OktaDirectory.FindByEmail(AdminEmail);
        var dev = OktaDirectory.FindByEmail(DevEmail);

        Assert.NotNull(admin);
        Assert.NotNull(dev);
        Assert.Contains(OktaDirectory.AdminGroup, admin!.GroupNames);
        Assert.Contains(OktaDirectory.DeveloperGroup, dev!.GroupNames);

        // The separation the brief asks for: the developer is not an admin.
        Assert.DoesNotContain(OktaDirectory.AdminGroup, dev.GroupNames);
    }

    [Fact]
    public void Directory_StoresNoPlaintextPasswords()
    {
        foreach (var user in OktaDirectory.Users)
        {
            Assert.Matches("^[a-f0-9]{64}$", user.PasswordHash);
            Assert.DoesNotContain(AdminPassword, user.PasswordHash);
            Assert.DoesNotContain(DevPassword, user.PasswordHash);
        }
    }

    [Fact]
    public void Directory_LookupIsCaseInsensitive()
    {
        Assert.NotNull(OktaDirectory.FindByEmail("WASIM.KHAN@GMAIL.COM"));
    }

    // --- Sign-in --------------------------------------------------------------------

    [Theory]
    [InlineData(AdminEmail, AdminPassword)]
    [InlineData(DevEmail, DevPassword)]
    public void ValidCredentials_IssueAToken(string email, string password)
    {
        var result = CreateService().IssueToken(email, password);

        Assert.NotNull(result);
        Assert.Equal(email, result!.Email);
        Assert.NotEmpty(result.AccessToken);
    }

    [Theory]
    [InlineData(AdminEmail, "wrong-password")]
    [InlineData("nobody@gmail.com", AdminPassword)]
    [InlineData("", "")]
    public void InvalidCredentials_IssueNothing(string email, string password)
    {
        Assert.Null(CreateService().IssueToken(email, password));
    }

    [Fact]
    public void DeveloperPassword_DoesNotWorkForTheAdminAccount()
    {
        Assert.Null(CreateService().IssueToken(AdminEmail, DevPassword));
    }

    // --- Token contents ---------------------------------------------------------------

    [Fact]
    public void AdminToken_CarriesTheAdminGroup()
    {
        var result = CreateService().IssueToken(AdminEmail, AdminPassword);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result!.AccessToken);

        var groups = jwt.Claims.Where(c => c.Type == "groups").Select(c => c.Value).ToList();

        Assert.Contains(OktaDirectory.AdminGroup, groups);
        Assert.DoesNotContain(OktaDirectory.DeveloperGroup, groups);
        Assert.Equal(AdminEmail, jwt.Claims.First(c => c.Type == "email").Value);
    }

    [Fact]
    public void DeveloperToken_CarriesOnlyTheDeveloperGroup()
    {
        var result = CreateService().IssueToken(DevEmail, DevPassword);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result!.AccessToken);

        var groups = jwt.Claims.Where(c => c.Type == "groups").Select(c => c.Value).ToList();

        Assert.Equal([OktaDirectory.DeveloperGroup], groups);
    }

    [Fact]
    public void Token_IsSignedWithRs256AndCarriesIssuerAndAudience()
    {
        var options = DefaultOptions();
        var result = CreateService(options).IssueToken(AdminEmail, AdminPassword);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result!.AccessToken);

        Assert.Equal(SecurityAlgorithms.RsaSha256, jwt.Header.Alg);
        Assert.Equal(options.Issuer, jwt.Issuer);
        Assert.Contains(options.Audience, jwt.Audiences);
        Assert.True(jwt.ValidTo > DateTime.UtcNow);
    }

    [Fact]
    public void Token_ValidatesAgainstThePublishedSigningKey()
    {
        var options = DefaultOptions();
        var service = CreateService(options);
        var result = service.IssueToken(AdminEmail, AdminPassword);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = options.Issuer,
            ValidateAudience = true,
            ValidAudience = options.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = service.GetPublicSigningKey(),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
        };

        var principal = new JwtSecurityTokenHandler()
            .ValidateToken(result!.AccessToken, parameters, out _);

        Assert.NotNull(principal);
    }

    [Fact]
    public void TokenFromOneIssuer_DoesNotValidateAgainstAnother()
    {
        // Each service generates its own key pair, so a token from one must be rejected
        // by the other. This is what stops a forged key being accepted.
        var issuing = CreateService();
        var other = CreateService();

        var result = issuing.IssueToken(AdminEmail, AdminPassword);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = other.GetPublicSigningKey(),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
        };

        Assert.ThrowsAny<SecurityTokenException>(() =>
            new JwtSecurityTokenHandler().ValidateToken(result!.AccessToken, parameters, out _));
    }

    [Fact]
    public void Jwks_PublishesTheSigningKeyWithoutPrivateMaterial()
    {
        var jwks = System.Text.Json.JsonSerializer.Serialize(CreateService().GetJwks());

        Assert.Contains("\"kty\":\"RSA\"", jwks);
        Assert.Contains("\"alg\":\"RS256\"", jwks);
        Assert.Contains("\"n\":", jwks);
        Assert.Contains("\"e\":", jwks);

        // Private RSA parameters must never appear in a public JWKS.
        foreach (var privateField in new[] { "\"d\":", "\"p\":", "\"q\":", "\"dp\":", "\"dq\":", "\"qi\":" })
        {
            Assert.DoesNotContain(privateField, jwks);
        }
    }

    // --- Group to role mapping ----------------------------------------------------------

    [Theory]
    [InlineData(AdminEmail, AdminPassword, "GatewayPlatformAdminRole")]
    [InlineData(DevEmail, DevPassword, "GatewayDeveloperRole")]
    public void GroupMembership_MapsToTheExpectedGatewayRole(string email, string password, string expectedRole)
    {
        var options = DefaultOptions();
        var result = CreateService(options).IssueToken(email, password);

        var mapped = result!.Groups
            .Select(g => options.GroupRoleMappings.TryGetValue(g, out var arn) ? arn : null)
            .FirstOrDefault(arn => arn is not null);

        Assert.NotNull(mapped);
        Assert.EndsWith(expectedRole, mapped);
    }

    [Fact]
    public void GroupWithNoMapping_YieldsNoRole()
    {
        var options = DefaultOptions();
        options.GroupRoleMappings.Clear();

        var result = CreateService(options).IssueToken(DevEmail, DevPassword);

        var mapped = result!.Groups
            .Select(g => options.GroupRoleMappings.TryGetValue(g, out var arn) ? arn : null)
            .FirstOrDefault(arn => arn is not null);

        // Authenticated, but holding no gateway role: every IAM check will deny.
        Assert.Null(mapped);
    }
}
