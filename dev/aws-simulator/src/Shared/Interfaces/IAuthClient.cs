using Shared.DTOs;

namespace Shared.Interfaces;

public interface IAuthClient
{
    Task<TokenDto> AssumeRoleAsync(string roleName, int durationSeconds = 3600);
    Task<CallerIdentityDto> GetCallerIdentityAsync(string jwt);
}
