using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Shared.DTOs;
using Shared.Models;

namespace IamLocal.Services;

public interface IJwtTokenService
{
    TokenDto GenerateToken(IamRole role, int durationSeconds = 3600);
    CallerIdentityDto ValidateAndGetIdentity(string jwt);
}

public class JwtTokenService : IJwtTokenService
{
    private readonly IRsaKeyProvider _keyProvider;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    public const string Issuer = "http://localhost:5003";
    public const string Audience = "local-aws-services";

    public JwtTokenService(IRsaKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

    public TokenDto GenerateToken(IamRole role, int durationSeconds = 3600)
    {
        var expiresAt = DateTime.UtcNow.AddSeconds(durationSeconds);
        var credentials = new SigningCredentials(_keyProvider.GetPrivateKey(), SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, role.Name),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("role", role.Name),
            new("arn", role.Arn),
            new("account_id", "123456789012"),
            new("user_id", $"AROA{role.Name.ToUpperInvariant()}:session"),
            new("policies", JsonSerializer.Serialize(role.Policies))
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiresAt,
            Issuer = Issuer,
            Audience = Audience,
            SigningCredentials = credentials
        };

        var token = _tokenHandler.CreateToken(tokenDescriptor);
        var jwtString = _tokenHandler.WriteToken(token);

        return new TokenDto(jwtString, expiresAt);
    }

    public CallerIdentityDto ValidateAndGetIdentity(string jwt)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _keyProvider.GetPublicKey(),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };

        var principal = _tokenHandler.ValidateToken(jwt, validationParameters, out _);

        var arn = principal.FindFirst("arn")?.Value ?? "arn:aws:iam::123456789012:role/anonymous";
        var accountId = principal.FindFirst("account_id")?.Value ?? "123456789012";
        var userId = principal.FindFirst("user_id")?.Value ?? $"AROAANONYMOUS:{Guid.NewGuid():N}";

        return new CallerIdentityDto(arn, accountId, userId);
    }
}
