using System.Net.Http.Headers;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Startup;

/// <summary>
/// Dispatch gate and authentication for an on-prem model backend (SEC-14).
///
/// Ollama, LM Studio and llama.cpp have no authentication of their own, so a remote backend is
/// expected behind a TLS reverse proxy that checks a bearer credential, read from the secret store
/// named by Gateway:LocalProviders:*:ApiKeySecretName.
///
/// `Enabled` is enforced here rather than only in configuration validation. Every caller reaches a
/// backend through its named HttpClient -- invocation, health probes and model discovery alike --
/// so refusing here refuses all of them. Treating `Enabled` as a validation exemption alone left a
/// disabled remote backend reachable in clear text with no credential.
/// </summary>
public sealed class LocalBackendAuthHandler : DelegatingHandler
{
    private readonly ISecretsProvider _secrets;
    private readonly string _backend;
    private readonly bool _enabled;
    private readonly string _secretName;
    private readonly bool _enforceRemotePolicy;

    /// <param name="backend">Configuration name of the backend ("Ollama", "LmStudio", "LlamaCpp").</param>
    /// <param name="enabled">Gateway:LocalProviders:*:Enabled. False refuses every request.</param>
    /// <param name="enforceRemotePolicy">
    /// True outside Development: a backend that is not on this host must use HTTPS and name a
    /// credential. Development may point at a plain-HTTP box on the bench.
    /// </param>
    public LocalBackendAuthHandler(
        ISecretsProvider secrets,
        string backend,
        bool enabled,
        string secretName,
        bool enforceRemotePolicy)
    {
        _secrets = secrets;
        _backend = backend;
        _enabled = enabled;
        _secretName = secretName;
        _enforceRemotePolicy = enforceRemotePolicy;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!_enabled)
        {
            throw new HttpRequestException(
                $"The '{_backend}' backend is disabled (Gateway:LocalProviders:{_backend}:Enabled is false); no request was sent.");
        }

        var uri = request.RequestUri;
        var isRemote = uri is null || !uri.IsLoopback;
        var isHttps = uri?.Scheme == Uri.UriSchemeHttps;
        var hasSecret = !string.IsNullOrWhiteSpace(_secretName);

        // A credential sent in clear is a credential handed to everyone on the path, in every
        // environment.
        if (isRemote && hasSecret && !isHttps)
        {
            throw new HttpRequestException(
                "Refusing to send the backend credential over plain HTTP to a remote host.");
        }

        // Outside Development a remote backend must be encrypted and authenticated: otherwise the
        // prompts cross the network in clear, or anything that can reach the backend calls it
        // around this gateway's authentication, guardrails and metering.
        if (isRemote && _enforceRemotePolicy)
        {
            if (!isHttps)
            {
                throw new HttpRequestException(
                    $"Refusing to send prompts to the remote '{_backend}' backend over plain HTTP.");
            }

            if (!hasSecret)
            {
                throw new HttpRequestException(
                    $"Refusing to call the remote '{_backend}' backend with no configured credential " +
                    $"(Gateway:LocalProviders:{_backend}:ApiKeySecretName).");
            }
        }

        if (!hasSecret)
        {
            return await base.SendAsync(request, cancellationToken);
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
