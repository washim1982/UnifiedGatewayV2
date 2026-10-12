namespace Shared.DTOs;

public record DataKeyDto(string PlaintextBase64, string CiphertextBlobBase64);
public record TokenDto(string Jwt, DateTime ExpiresAt);
public record CallerIdentityDto(string Arn, string AccountId, string UserId);
