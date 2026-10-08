using System.Net.Http.Headers;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Startup;

/// <summary>
/// Authenticates the gateway to an on-prem model backend (SEC-14).
///
/// Ollama, LM Studio and llama.cpp have no authentication of their own, so a remote backend is
/// expected behind a TLS reverse proxy that checks a bearer credential. The credential is read
/// from the secret store named by Gateway:LocalProviders:*:ApiKeySecretName. With no secret
/// configured the request passes unchanged, which StartupValidator permits only for a backend on
/// this machine or in Development.
/// </summary>
public sealed class LocalBackendAuthHandler : DelegatingHandler
{
    private readonly ISecretsProvider _secrets;
    private readonly string _secretName;

    public LocalBackendAuthHandler(ISecretsProvider secrets, string secretName)
    {
        _secrets = secrets;
        _secretName = secretName;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_secretName))
        {
            return await base.SendAsync(request, cancellationToken);
        }

        // A bearer credential sent in clear is a credential handed to everyone on the path.
        if (request.RequestUri is not { } uri || (uri.Scheme != Uri.UriSchemeHttps && !uri.IsLoopback))
        {
            throw new HttpRequestException(
                "Refusing to send the backend credential over plain HTTP to a remote host.");
        }

        // Fail closed: a backend that expects a credential is not called without one.
        var credential = await _secrets.GetSecretAsync(_secretName, cancellationToken);
        if (string.IsNullOrWhiteSpace(credential))
        {
            throw new HttpRequestException(
                $"The backend credential secret '{_secretName}' is missing or empty.");
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential.Trim());
        return await base.SendAsync(request, cancellationToken);
    }
}
