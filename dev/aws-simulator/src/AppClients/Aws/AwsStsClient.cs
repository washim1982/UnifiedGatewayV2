using Amazon.SecurityToken;
using AwsModel = Amazon.SecurityToken.Model;
using Shared.DTOs;
using Shared.Interfaces;

namespace AppClients.Aws;

public class AwsStsClient : IAuthClient
{
    private readonly IAmazonSecurityTokenService _sts;

    public AwsStsClient(IAmazonSecurityTokenService sts)
    {
        _sts = sts;
    }

    public async Task<TokenDto> AssumeRoleAsync(string roleName, int durationSeconds = 3600)
    {
        var roleArn = roleName.StartsWith("arn:", StringComparison.OrdinalIgnoreCase)
            ? roleName
            : $"arn:aws:iam::123456789012:role/{roleName}";

        var request = new AwsModel.AssumeRoleRequest
        {
            RoleArn = roleArn,
            RoleSessionName = "local-aws-session",
            DurationSeconds = durationSeconds
        };

        var response = await _sts.AssumeRoleAsync(request);
        var expiration = response.Credentials.Expiration ?? DateTime.UtcNow.AddSeconds(durationSeconds);
        return new TokenDto(response.Credentials.SessionToken, expiration);
    }

    public async Task<CallerIdentityDto> GetCallerIdentityAsync(string jwt)
    {
        var request = new AwsModel.GetCallerIdentityRequest();
        var response = await _sts.GetCallerIdentityAsync(request);

        return new CallerIdentityDto(response.Arn, response.Account, response.UserId);
    }
}
