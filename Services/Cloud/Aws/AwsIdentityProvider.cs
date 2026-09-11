using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Cloud.Aws;

/// <summary>
/// Resolves a management-plane caller to an IAM principal by having AWS vouch for it.
///
/// The caller signs an sts:GetCallerIdentity request with its own credentials and hands the
/// signed request -- not the credentials -- to the gateway in the X-Gateway-Aws-Identity
/// header, as base64 JSON: <c>{ "method", "url", "headers", "body" }</c>. The gateway checks it
/// is exactly that call, aimed at an allow-listed STS host, bound to this gateway and fresh,
/// then sends it to STS. The ARN in STS's answer is the identity. This is the scheme Vault's
/// AWS auth method uses.
///
/// Every failure is a refusal: the provider never returns an identity it did not get from STS.
/// </summary>
public sealed class AwsIdentityProvider : IIdentityProvider
{
    public const string HttpClientName = "AwsStsIdentity";

    /// <summary>Header the caller signs to bind the request to this gateway.</summary>
    public const string ServerIdHeader = "X-Gateway-Server-Id";

    private const int MaxEnvelopeLength = 16 * 1024;
    private const int MaxResponseBytes = 64 * 1024;
    private const int MaxCacheEntries = 1024;
    private const string AmzDateFormat = "yyyyMMdd'T'HHmmss'Z'";

    private static readonly string[] RequiredSignedHeaders = ["host", "x-amz-date", "x-gateway-server-id"];
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions EnvelopeJson = new() { PropertyNameCaseInsensitive = true };

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AwsIdentityOptions _options;
    private readonly string[] _allowedHosts;
    private readonly ILogger<AwsIdentityProvider> _logger;
    private readonly ConcurrentDictionary<string, (ResolvedIdentity Identity, DateTimeOffset Until)> _verified =
        new(StringComparer.Ordinal);

    public AwsIdentityProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<CloudOptions> cloudOptions,
        IOptions<GatewayOptions> gatewayOptions,
        ILogger<AwsIdentityProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = cloudOptions.Value.AwsIdentity;
        _allowedHosts = EffectiveStsHosts(_options, gatewayOptions.Value.Aws.Region);
        _logger = logger;
    }

    /// <summary>The STS hosts a signed request may target: the configured list, else global plus regional.</summary>
    public static string[] EffectiveStsHosts(AwsIdentityOptions options, string region) =>
        options.AllowedStsHosts.Length > 0
            ? options.AllowedStsHosts
            : ["sts.amazonaws.com", $"sts.{region}.amazonaws.com"];

    private TimeSpan MaxRequestAge => TimeSpan.FromSeconds(Math.Clamp(_options.MaxRequestAgeSeconds, 30, 900));

    public async Task<ResolvedIdentity> ResolveAsync(string credential, CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return Refuse("AWS IAM authentication is not enabled on this gateway");
        }

        if (string.IsNullOrWhiteSpace(credential))
        {
            return Refuse("No credential presented");
        }

        if (credential.Length > MaxEnvelopeLength)
        {
            return Refuse("The signed identity request is too large");
        }

        // A client typically presents the same signed request for a burst of calls. STS is asked
        // once, and the answer is kept no longer than the signed request itself stays fresh.
        var cacheKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
        if (_verified.TryGetValue(cacheKey, out var hit) && hit.Until > DateTimeOffset.UtcNow)
        {
            return hit.Identity;
        }

        if (!TryParseEnvelope(credential, out var envelope))
        {
            return Refuse("The credential is not a signed GetCallerIdentity request");
        }

        var inspection = Inspect(envelope);
        if (inspection.Problem is not null)
        {
            _logger.LogWarning("Refused a signed identity request before contacting AWS: {Problem}.", inspection.Problem);
            return Refuse(inspection.Problem);
        }

        string responseBody;
        try
        {
            using var request = BuildStsRequest(envelope, inspection);
            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            responseBody = await ReadBoundedAsync(response.Content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "AWS STS rejected a signed identity request with HTTP {Status} ({Code}).",
                    (int)response.StatusCode, ReadErrorCode(responseBody));
                return Refuse("AWS STS rejected the signed request");
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            _logger.LogWarning(ex, "AWS STS could not be reached to verify a management caller.");
            return Refuse("AWS STS could not be reached");
        }

        if (!TryReadCallerIdentity(responseBody, out var arn, out var account))
        {
            return Refuse("AWS STS returned no caller identity");
        }

        if (!_options.AllowedAccountIds.Contains(account, StringComparer.Ordinal))
        {
            _logger.LogWarning("Management caller {Arn} belongs to account {Account}, which is not allowed.", arn, account);
            return Refuse($"Account {account} is not allowed to manage this gateway");
        }

        var principal = ToPrincipalArn(arn, account);
        if (principal is null)
        {
            _logger.LogWarning("Management caller {Arn} is not an IAM role or user; refusing.", arn);
            return Refuse("Only IAM roles and users may manage this gateway");
        }

        var expiresAt = inspection.SignedAt + MaxRequestAge;
        var identity = new ResolvedIdentity
        {
            IsAuthenticated = true,
            PrincipalArn = principal,
            AuthType = "AwsSigV4Verified",
            ExpiresAt = expiresAt
        };

        Remember(cacheKey, identity, expiresAt);
        _logger.LogInformation("Management caller verified by AWS STS as {Principal}.", principal);

        return identity;
    }

    /// <summary>
    /// The principal a policy is written against. STS reports an assumed role as
    /// <c>arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION</c>; policies name the role,
    /// <c>arn:aws:iam::ACCOUNT:role/ROLE</c>. IAM users pass through. Root, federated users and
    /// anything unrecognised yield null and are refused.
    /// </summary>
    public static string? ToPrincipalArn(string arn, string account)
    {
        var parts = arn.Split(':', 6);
        if (parts.Length != 6 || parts[0] != "arn" || parts[4] != account)
        {
            return null;
        }

        var partition = parts[1];
        var service = parts[2];
        var resource = parts[5];

        if (service == "sts" && resource.StartsWith("assumed-role/", StringComparison.Ordinal))
        {
            var segments = resource.Split('/');
            return segments.Length >= 3 && segments[1].Length > 0
                ? $"arn:{partition}:iam::{account}:role/{segments[1]}"
                : null;
        }

        if (service == "iam" && resource.StartsWith("user/", StringComparison.Ordinal))
        {
            return arn;
        }

        return null;
    }

    #region Envelope inspection

    private sealed record SignedRequestEnvelope
    {
        public string? Method { get; init; }
        public string? Url { get; init; }
        public Dictionary<string, string?>? Headers { get; init; }
        public string? Body { get; init; }
    }

    private sealed record Inspection(
        string? Problem,
        Uri? Target = null,
        DateTimeOffset SignedAt = default,
        IReadOnlyList<string>? SignedHeaders = null,
        IReadOnlyDictionary<string, string>? Headers = null)
    {
        public static Inspection Fail(string problem) => new(problem);
    }

    private static bool TryParseEnvelope(string credential, out SignedRequestEnvelope envelope)
    {
        envelope = new SignedRequestEnvelope();

        // Standard or URL-safe base64, padded or not.
        var text = credential.Trim().Replace('-', '+').Replace('_', '/');
        switch (text.Length % 4)
        {
            case 2: text += "=="; break;
            case 3: text += "="; break;
        }

        var bytes = new byte[text.Length];
        if (!Convert.TryFromBase64String(text, bytes, out var written))
        {
            return false;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<SignedRequestEnvelope>(bytes.AsSpan(0, written), EnvelopeJson);
            if (parsed is null)
            {
                return false;
            }

            envelope = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Everything that can be decided without asking AWS. A request that fails here never
    /// leaves the gateway, so the gateway cannot be used to send arbitrary signed requests.
    /// </summary>
    private Inspection Inspect(SignedRequestEnvelope envelope)
    {
        if (!string.Equals(envelope.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return Inspection.Fail("only a POST to STS is accepted");
        }

        if (!Uri.TryCreate(envelope.Url, UriKind.Absolute, out var url) ||
            url.Scheme != Uri.UriSchemeHttps ||
            !url.IsDefaultPort ||
            url.UserInfo.Length > 0 ||
            url.AbsolutePath != "/" ||
            url.Query.Length > 0 ||
            url.Fragment.Length > 0)
        {
            return Inspection.Fail("the URL must be https://<sts-host>/ with no port, path or query");
        }

        // The allow-list is what keeps this from being an open relay: whatever the caller
        // signed, the gateway only ever sends it to STS.
        if (!_allowedHosts.Contains(url.Host, StringComparer.OrdinalIgnoreCase))
        {
            return Inspection.Fail($"'{url.Host}' is not an allowed STS endpoint");
        }

        if (!IsGetCallerIdentityBody(envelope.Body))
        {
            return Inspection.Fail("the body must be exactly Action=GetCallerIdentity&Version=2011-06-15");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in envelope.Headers ?? new Dictionary<string, string?>())
        {
            if (value is null || name.Any(char.IsWhiteSpace) || value.Contains('\r') || value.Contains('\n'))
            {
                return Inspection.Fail($"header '{name}' is malformed");
            }

            if (!headers.TryAdd(name, value))
            {
                return Inspection.Fail($"header '{name}' appears more than once");
            }
        }

        if (!headers.TryGetValue("Authorization", out var authorization) ||
            !authorization.StartsWith("AWS4-HMAC-SHA256 ", StringComparison.Ordinal))
        {
            return Inspection.Fail("Authorization must be an AWS4-HMAC-SHA256 signature");
        }

        var signedHeaders = ParseSignedHeaders(authorization);
        foreach (var required in RequiredSignedHeaders)
        {
            if (!signedHeaders.Contains(required))
            {
                return Inspection.Fail($"'{required}' must be covered by the signature");
            }
        }

        // The binding. Without it, a request signed for another service that trusts the same
        // pattern could be replayed here; it binds only because the header is signed.
        if (string.IsNullOrEmpty(_options.ServerId) ||
            !headers.TryGetValue(ServerIdHeader, out var serverId) ||
            !string.Equals(serverId, _options.ServerId, StringComparison.Ordinal))
        {
            return Inspection.Fail("the request is not bound to this gateway");
        }

        if (headers.TryGetValue("Host", out var hostHeader) &&
            !string.Equals(hostHeader, url.Host, StringComparison.OrdinalIgnoreCase))
        {
            return Inspection.Fail("the Host header does not match the URL");
        }

        if (!headers.TryGetValue("X-Amz-Date", out var amzDate) ||
            !DateTimeOffset.TryParseExact(
                amzDate, AmzDateFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var signedAt))
        {
            return Inspection.Fail("X-Amz-Date is missing or malformed");
        }

        var age = DateTimeOffset.UtcNow - signedAt;
        if (age > MaxRequestAge || age < -ClockSkew)
        {
            return Inspection.Fail("the signed request has expired or is dated in the future");
        }

        foreach (var name in signedHeaders)
        {
            if (name is not ("host" or "content-length") && !headers.ContainsKey(name))
            {
                return Inspection.Fail($"signed header '{name}' has no value");
            }
        }

        return new Inspection(null, url, signedAt, signedHeaders, headers);
    }

    private static IReadOnlyList<string> ParseSignedHeaders(string authorization)
    {
        const string marker = "SignedHeaders=";

        var start = authorization.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return [];
        }

        start += marker.Length;
        var end = authorization.IndexOf(',', start);
        var list = end < 0 ? authorization[start..] : authorization[start..end];

        return list
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(h => h.ToLowerInvariant())
            .ToList();
    }

    private static bool IsGetCallerIdentityBody(string? body)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 256)
        {
            return false;
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in body.Split('&'))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length != 2)
            {
                return false;
            }

            var key = Uri.UnescapeDataString(parts[0].Replace('+', ' '));
            var value = Uri.UnescapeDataString(parts[1].Replace('+', ' '));
            if (!fields.TryAdd(key, value))
            {
                return false;
            }
        }

        return fields.Count == 2 &&
               fields.TryGetValue("Action", out var action) && action == "GetCallerIdentity" &&
               fields.TryGetValue("Version", out var version) && version == "2011-06-15";
    }

    #endregion

    #region STS exchange

    private static HttpRequestMessage BuildStsRequest(SignedRequestEnvelope envelope, Inspection inspection)
    {
        var headers = inspection.Headers!;
        var signedHeaders = inspection.SignedHeaders!;

        // Rebuilt from the validated host rather than the caller's string, so what is sent is
        // exactly what was checked.
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"https://{inspection.Target!.Host}/"));

        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(envelope.Body!));
        content.Headers.TryAddWithoutValidation(
            "Content-Type",
            headers.TryGetValue("Content-Type", out var contentType)
                ? contentType
                : "application/x-www-form-urlencoded; charset=utf-8");
        request.Content = content;

        // Only what the signature covers is relayed, plus the signature itself and the session
        // token. Anything else in the envelope is dropped, so it cannot smuggle headers to STS.
        request.Headers.TryAddWithoutValidation("Authorization", headers["Authorization"]);

        foreach (var name in signedHeaders)
        {
            if (name is "host" or "content-type" or "content-length")
            {
                continue;
            }

            request.Headers.TryAddWithoutValidation(name, headers[name]);
        }

        if (!signedHeaders.Contains("x-amz-security-token") &&
            headers.TryGetValue("X-Amz-Security-Token", out var sessionToken))
        {
            request.Headers.TryAddWithoutValidation("X-Amz-Security-Token", sessionToken);
        }

        return request;
    }

    private static async Task<string> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);

        var buffer = new byte[MaxResponseBytes + 1];
        var total = 0;
        int read;

        while ((read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)) > 0)
        {
            total += read;
            if (total > MaxResponseBytes)
            {
                throw new InvalidDataException("The STS response exceeded the size limit.");
            }
        }

        return Encoding.UTF8.GetString(buffer, 0, total);
    }

    /// <summary>Parses the GetCallerIdentity result. DTDs are prohibited, so no entity tricks.</summary>
    private static bool TryReadCallerIdentity(string xml, out string arn, out string account)
    {
        arn = string.Empty;
        account = string.Empty;

        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxResponseBytes
            };

            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var result = XDocument.Load(reader)
                .Descendants()
                .FirstOrDefault(e => e.Name.LocalName == "GetCallerIdentityResult");

            arn = result?.Elements().FirstOrDefault(e => e.Name.LocalName == "Arn")?.Value.Trim() ?? string.Empty;
            account = result?.Elements().FirstOrDefault(e => e.Name.LocalName == "Account")?.Value.Trim() ?? string.Empty;

            return arn.Length > 0 && account.Length > 0;
        }
        catch (XmlException)
        {
            return false;
        }
    }

    private static string ReadErrorCode(string body)
    {
        var match = Regex.Match(body, "<Code>([A-Za-z.]{1,64})</Code>", RegexOptions.None, TimeSpan.FromMilliseconds(100));
        return match.Success ? match.Groups[1].Value : "no error code";
    }

    private void Remember(string key, ResolvedIdentity identity, DateTimeOffset requestExpiry)
    {
        var until = DateTimeOffset.UtcNow.AddSeconds(Math.Max(0, _options.CacheSeconds));
        if (requestExpiry < until)
        {
            until = requestExpiry;
        }

        if (_verified.Count >= MaxCacheEntries)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var entry in _verified)
            {
                if (entry.Value.Until <= now)
                {
                    _verified.TryRemove(entry.Key, out _);
                }
            }

            // Still full of live entries: skip caching rather than grow without bound.
            if (_verified.Count >= MaxCacheEntries)
            {
                return;
            }
        }

        _verified[key] = (identity, until);
    }

    #endregion

    private static ResolvedIdentity Refuse(string reason) => new()
    {
        IsAuthenticated = false,
        FailureReason = reason
    };
}
