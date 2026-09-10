using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UnifiedGateway.Services.Aws;

/// <summary>
/// Signs an IAM Roles Anywhere CreateSession request with an X.509 client certificate.
///
/// This is SigV4 with one substantial difference, and getting that difference wrong is the
/// usual reason an implementation fails against the real service: ordinary SigV4 derives an
/// HMAC signing key from the secret access key through four chained HMACs, whereas AWS4-X509
/// has no secret access key at all. The string to sign is signed <em>directly</em> with the
/// certificate's private key, and the credential scope carries the certificate serial number
/// in place of an access key id.
///
/// Kept free of HTTP and configuration so it can be tested against the worked example in the
/// AWS documentation rather than only against a live endpoint.
/// </summary>
public static class RolesAnywhereSigner
{
    public const string ServiceName = "rolesanywhere";
    public const string RsaAlgorithm = "AWS4-X509-RSA-SHA256";
    public const string EcdsaAlgorithm = "AWS4-X509-ECDSA-SHA256";

    /// <summary>The headers a signed CreateSession request must carry, Authorization included.</summary>
    public sealed record SignedRequest(
        string Authorization,
        string AmzDate,
        string X509,
        string? X509Chain,
        string CanonicalRequest,
        string StringToSign);

    /// <summary>
    /// Builds the signature and headers for <c>POST {host}/sessions</c>.
    /// </summary>
    /// <param name="certificate">The client certificate, with an accessible private key.</param>
    /// <param name="chain">Intermediates to present, leaf excluded. May be empty.</param>
    /// <param name="host">Host header value, e.g. <c>rolesanywhere.us-east-1.amazonaws.com</c>.</param>
    /// <param name="region">Region used in the credential scope.</param>
    /// <param name="body">The exact JSON body that will be sent.</param>
    /// <param name="timestampUtc">Signing time. Passed in so the result is reproducible in tests.</param>
    public static SignedRequest Sign(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        string host,
        string region,
        string body,
        DateTimeOffset timestampUtc)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var amzDate = timestampUtc.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var dateStamp = timestampUtc.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

        var x509 = Convert.ToBase64String(certificate.RawData);
        var x509Chain = chain.Count > 0
            ? string.Join(",", chain.Select(c => Convert.ToBase64String(c.RawData)))
            : null;

        // --- Canonical request -------------------------------------------------------
        // Header values are trimmed and the names lowercased, and the names must appear in
        // ascending order in both the canonical headers and the SignedHeaders list.
        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["content-type"] = "application/json",
            ["host"] = host,
            ["x-amz-date"] = amzDate,
            ["x-amz-x509"] = x509
        };

        if (x509Chain is not null)
        {
            headers["x-amz-x509-chain"] = x509Chain;
        }

        var canonicalHeaders = new StringBuilder();
        foreach (var (name, value) in headers)
        {
            canonicalHeaders.Append(name).Append(':').Append(value.Trim()).Append('\n');
        }

        var signedHeaders = string.Join(";", headers.Keys);

        var canonicalRequest = string.Join("\n",
            "POST",
            "/sessions",
            string.Empty,                 // no query string
            canonicalHeaders.ToString(),  // already newline-terminated per header
            signedHeaders,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(body))));

        // --- String to sign ----------------------------------------------------------
        var algorithm = certificate.GetRSAPrivateKey() is not null ? RsaAlgorithm : EcdsaAlgorithm;
        var credentialScope = $"{SerialNumberDecimal(certificate)}/{dateStamp}/{region}/{ServiceName}/aws4_request";

        var stringToSign = string.Join("\n",
            algorithm,
            amzDate,
            credentialScope,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));

        // --- Signature ---------------------------------------------------------------
        var signature = Hex(SignStringToSign(certificate, stringToSign));

        var authorization =
            $"{algorithm} Credential={credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";

        return new SignedRequest(authorization, amzDate, x509, x509Chain, canonicalRequest, stringToSign);
    }

    /// <summary>
    /// Signs the string to sign with the certificate's private key. Unlike ordinary SigV4
    /// there is no derived key and no HMAC: this is an asymmetric signature over the payload.
    /// </summary>
    private static byte[] SignStringToSign(X509Certificate2 certificate, string stringToSign)
    {
        var payload = Encoding.UTF8.GetBytes(stringToSign);

        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            // AWS expects the DER SEQUENCE form, not the fixed-width r||s concatenation that
            // .NET produces by default.
            return ecdsa.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }

        throw new InvalidOperationException(
            "The Roles Anywhere client certificate has no accessible RSA or ECDSA private key. " +
            "Under IIS this is normally the app pool identity lacking read access to the key, " +
            "rather than a missing certificate.");
    }

    /// <summary>
    /// The certificate serial number in decimal, which is what the credential scope carries.
    /// <see cref="X509Certificate2.SerialNumber"/> is big-endian hex; the leading zero keeps
    /// BigInteger from reading a high bit as a sign bit and producing a negative serial.
    /// </summary>
    public static string SerialNumberDecimal(X509Certificate2 certificate)
    {
        var value = BigInteger.Parse("0" + certificate.SerialNumber, NumberStyles.HexNumber,
            CultureInfo.InvariantCulture);

        return value.ToString(CultureInfo.InvariantCulture);
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
