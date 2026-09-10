using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Amazon.Runtime;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Aws;

public interface IRolesAnywhereCredentialProvider
{
    /// <summary>Exchanges the client certificate for temporary credentials.</summary>
    Task<(AWSCredentials Credentials, DateTimeOffset Expiration, string SubjectArn)> CreateSessionAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Describes the certificate in use, for the credential status view. Subject, thumbprint
    /// and expiry only -- enough to answer "which certificate is this host presenting", with
    /// no key material and no account identifiers.
    /// </summary>
    RolesAnywhereCertificateInfo DescribeCertificate();
}

public sealed record RolesAnywhereCertificateInfo(
    string Subject,
    string Thumbprint,
    DateTimeOffset NotAfter,
    bool ChainPresented);

/// <summary>
/// Obtains AWS credentials through IAM Roles Anywhere.
///
/// This is the credential path for every AWS service the gateway touches in Test and
/// Production -- S3, KMS, Secrets Manager, IAM and Bedrock all resolve through
/// <see cref="ISTSService"/>, which delegates here. There is no stored access key anywhere in
/// the deployment: the host's identity is a certificate, and the credentials it yields expire.
/// </summary>
public sealed class RolesAnywhereCredentialProvider : IRolesAnywhereCredentialProvider, IDisposable
{
    public const string HttpClientName = "RolesAnywhere";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly GatewayOptions _options;
    private readonly ILogger<RolesAnywhereCredentialProvider> _logger;

    private readonly Lazy<ClientCertificateLoader.LoadedCertificate> _certificate;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public RolesAnywhereCredentialProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<GatewayOptions> options,
        ILogger<RolesAnywhereCredentialProvider> logger)
    {
        // A factory rather than a held HttpClient: this provider is consumed by a singleton,
        // and a typed client captured there would pin one HttpMessageHandler -- and its DNS
        // resolution -- for the life of the process.
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;

        // Loaded once and held: under IIS this touches the machine key store, and doing that
        // on every refresh would be both slow and noisy in the security event log.
        _certificate = new Lazy<ClientCertificateLoader.LoadedCertificate>(
            () => ClientCertificateLoader.Load(_options.Aws.RolesAnywhere.Certificate),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public RolesAnywhereCertificateInfo DescribeCertificate()
    {
        var loaded = _certificate.Value;

        return new RolesAnywhereCertificateInfo(
            loaded.Leaf.Subject,
            loaded.Leaf.Thumbprint,
            new DateTimeOffset(loaded.Leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero),
            loaded.Chain.Count > 0);
    }

    public async Task<(AWSCredentials Credentials, DateTimeOffset Expiration, string SubjectArn)>
        CreateSessionAsync(CancellationToken cancellationToken = default)
    {
        var settings = _options.Aws.RolesAnywhere;
        var loaded = _certificate.Value;

        return settings.UseSimulatorProtocol
            ? await CreateSimulatorSessionAsync(settings, loaded, cancellationToken)
            : await CreateAwsSessionAsync(settings, loaded, cancellationToken);
    }

    // --- Real AWS -------------------------------------------------------------------

    private async Task<(AWSCredentials, DateTimeOffset, string)> CreateAwsSessionAsync(
        RolesAnywhereOptions settings,
        ClientCertificateLoader.LoadedCertificate loaded,
        CancellationToken cancellationToken)
    {
        var endpoint = ResolveEndpoint(settings, _options.Aws.Region);
        var host = endpoint.Host;

        // AWS caps a Roles Anywhere session at one hour regardless of what the role's own
        // maximum allows, so clamping here turns a rejected request into a shorter session.
        var duration = Math.Clamp(settings.DurationSeconds, 900, 3600);

        var body = JsonSerializer.Serialize(new CreateSessionBody
        {
            DurationSeconds = duration,
            ProfileArn = settings.ProfileArn,
            RoleArn = settings.RoleArn,
            TrustAnchorArn = settings.TrustAnchorArn,
            SessionName = string.IsNullOrWhiteSpace(settings.SessionName) ? null : settings.SessionName
        }, JsonOpts);

        var signed = RolesAnywhereSigner.Sign(
            loaded.Leaf, loaded.Chain, host, _options.Aws.Region, body, DateTimeOffset.UtcNow);

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(endpoint, "/sessions"))
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        // Set explicitly rather than relying on StringContent, whose header carries a charset
        // parameter that would not match the value that was signed.
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("Authorization", signed.Authorization);
        request.Headers.TryAddWithoutValidation("X-Amz-Date", signed.AmzDate);
        request.Headers.TryAddWithoutValidation("X-Amz-X509", signed.X509);

        if (signed.X509Chain is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Amz-X509-Chain", signed.X509Chain);
        }

        using var http = _httpClientFactory.CreateClient(HttpClientName);
        using var response = await http.SendAsync(request, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new RolesAnywhereException(
                DescribeFailure(response.StatusCode, payload, settings, loaded));
        }

        var session = JsonSerializer.Deserialize<CreateSessionResult>(payload, JsonOpts);
        var credentialSet = session?.CredentialSet?.FirstOrDefault()
            ?? throw new RolesAnywhereException(
                "Roles Anywhere returned no credential set. The profile may list no role this " +
                "certificate is permitted to assume.");

        var credentials = credentialSet.Credentials
            ?? throw new RolesAnywhereException("Roles Anywhere returned a credential set with no credentials.");

        var expiration = credentials.Expiration ?? DateTimeOffset.UtcNow.AddSeconds(duration);

        _logger.LogInformation(
            "Roles Anywhere session established. Subject {SubjectArn}, expires {Expiration:O}.",
            session!.SubjectArn ?? "(unreported)", expiration);

        return (
            new SessionAWSCredentials(credentials.AccessKeyId, credentials.SecretAccessKey, credentials.SessionToken),
            expiration,
            session.SubjectArn ?? string.Empty);
    }

    /// <summary>
    /// Turns an HTTP failure into something an operator can act on. Roles Anywhere failures
    /// are nearly always one of a handful of setup mistakes, and the status code identifies
    /// which one, so naming the likely cause saves a long detour through CloudTrail.
    /// </summary>
    private static string DescribeFailure(
        System.Net.HttpStatusCode status,
        string payload,
        RolesAnywhereOptions settings,
        ClientCertificateLoader.LoadedCertificate loaded)
    {
        var likely = (int)status switch
        {
            403 =>
                "The certificate was not accepted. Check that the trust anchor holds the CA that issued " +
                $"'{loaded.Leaf.Subject}', that the profile lists the role, and that the role's trust " +
                "policy permits rolesanywhere.amazonaws.com with the matching condition keys.",
            404 =>
                "The trust anchor or profile ARN does not resolve. Check both exist in " +
                "this region and account.",
            400 =>
                "The request was rejected as malformed. A duration outside 900-3600 seconds, or a " +
                "chain that does not reach the trust anchor, both report this way.",
            _ => "See the response detail below."
        };

        var chainNote = loaded.Chain.Count == 0
            ? " No intermediate chain was presented; set Certificate:IncludeChain if the trust anchor " +
              "holds a root rather than the issuing intermediate."
            : string.Empty;

        return $"Roles Anywhere CreateSession failed with {(int)status}. {likely}{chainNote} " +
               $"Response: {Truncate(payload, 500)}";
    }

    // --- .NET simulator -------------------------------------------------------------

    /// <summary>
    /// The simulator's simplified contract: an RSA signature over a client-chosen string,
    /// with no SigV4 canonicalisation. Exercising this confirms the wiring and the
    /// certificate load; it does not confirm the production signing is correct.
    /// </summary>
    private async Task<(AWSCredentials, DateTimeOffset, string)> CreateSimulatorSessionAsync(
        RolesAnywhereOptions settings,
        ClientCertificateLoader.LoadedCertificate loaded,
        CancellationToken cancellationToken)
    {
        var endpoint = ResolveEndpoint(settings, _options.Aws.Region);

        var challenge = $"{settings.SessionName}:{DateTimeOffset.UtcNow:O}:{Guid.NewGuid():N}";

        using var rsa = loaded.Leaf.GetRSAPrivateKey()
            ?? throw new RolesAnywhereException(
                "The simulator protocol requires an RSA certificate; this one has no RSA private key.");

        var signature = Convert.ToBase64String(rsa.SignData(
            Encoding.UTF8.GetBytes(challenge), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var body = JsonSerializer.Serialize(new
        {
            CertPem = ToPem(loaded.Leaf),
            SignatureBase64 = signature,
            PayloadToVerify = challenge,
            ProfileArn = settings.ProfileArn,
            RoleArn = settings.RoleArn,
            TrustAnchorArn = settings.TrustAnchorArn,
            DurationSeconds = Math.Clamp(settings.DurationSeconds, 900, 43200)
        });

        using var http = _httpClientFactory.CreateClient(HttpClientName);
        using var response = await http.PostAsync(
            new Uri(endpoint, "/rolesanywhere/create-session"),
            new StringContent(body, Encoding.UTF8, "application/json"),
            cancellationToken);

        var payload = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new RolesAnywhereException(
                $"Simulator CreateSession failed with {(int)response.StatusCode}. Response: {Truncate(payload, 500)}");
        }

        var result = JsonSerializer.Deserialize<SimulatorSessionResult>(payload, JsonOpts);
        var credentials = result?.Credentials
            ?? throw new RolesAnywhereException("The simulator returned no credentials.");

        var expiration = credentials.Expiration ?? DateTimeOffset.UtcNow.AddSeconds(settings.DurationSeconds);

        _logger.LogInformation(
            "Roles Anywhere session established against the simulator. Expires {Expiration:O}. " +
            "Note this exercises the wiring only -- the simulator does not verify AWS4-X509 signatures.",
            expiration);

        return (
            new SessionAWSCredentials(credentials.AccessKeyId, credentials.SecretAccessKey, credentials.SessionToken),
            expiration,
            loaded.Leaf.Subject);
    }

    private static string ToPem(X509Certificate2 certificate) =>
        new string(PemEncoding.Write("CERTIFICATE", certificate.RawData));

    private static Uri ResolveEndpoint(RolesAnywhereOptions settings, string region) =>
        string.IsNullOrWhiteSpace(settings.EndpointOverride)
            ? new Uri($"https://rolesanywhere.{region}.amazonaws.com")
            : new Uri(settings.EndpointOverride);

    private static string Truncate(string value, int max) =>
        string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max] + "...";

    public void Dispose()
    {
        if (!_certificate.IsValueCreated)
        {
            return;
        }

        _certificate.Value.Leaf.Dispose();
        foreach (var certificate in _certificate.Value.Chain)
        {
            certificate.Dispose();
        }
    }

    // --- Wire contracts -------------------------------------------------------------

    private sealed class CreateSessionBody
    {
        public int DurationSeconds { get; set; }
        public string? ProfileArn { get; set; }
        public string? RoleArn { get; set; }
        public string? TrustAnchorArn { get; set; }
        public string? SessionName { get; set; }
    }

    private sealed class CreateSessionResult
    {
        public List<CredentialSetEntry>? CredentialSet { get; set; }
        public string? SubjectArn { get; set; }
    }

    private sealed class CredentialSetEntry
    {
        public SessionCredentials? Credentials { get; set; }
    }

    private sealed class SessionCredentials
    {
        public string AccessKeyId { get; set; } = string.Empty;
        public string SecretAccessKey { get; set; } = string.Empty;
        public string SessionToken { get; set; } = string.Empty;
        public DateTimeOffset? Expiration { get; set; }
    }

    private sealed class SimulatorSessionResult
    {
        public SessionCredentials? Credentials { get; set; }
    }
}

/// <summary>
/// A Roles Anywhere session could not be established. Distinct from a generic AWS failure
/// because the fix is always configuration or certificate lifecycle, never a retry.
/// </summary>
public sealed class RolesAnywhereException : Exception
{
    public RolesAnywhereException(string message) : base(message) { }
    public RolesAnywhereException(string message, Exception inner) : base(message, inner) { }
}
