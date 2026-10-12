using System.Net.Http.Json;
using Shared.DTOs;
using Shared.Interfaces;

namespace AppClients.Local;

public class LocalIamClient : IAuthClient
{
    private readonly HttpClient _http;

    public LocalIamClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<TokenDto> AssumeRoleAsync(string roleName, int durationSeconds = 3600)
    {
        var response = await _http.PostAsJsonAsync("/assume-role", new AssumeRoleRequest(roleName, durationSeconds));
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<TokenDto>();
        return result ?? throw new InvalidOperationException("Empty response from IAM AssumeRole.");
    }

    public async Task<CallerIdentityDto> GetCallerIdentityAsync(string jwt)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/get-caller-identity");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<CallerIdentityDto>();
        return result ?? throw new InvalidOperationException("Empty response from IAM GetCallerIdentity.");
    }
}
