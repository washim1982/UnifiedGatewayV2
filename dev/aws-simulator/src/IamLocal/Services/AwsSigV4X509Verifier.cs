using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IamLocal.Services;

/// <summary>The certificate a caller presented, once its signature has been verified.</summary>
public sealed record VerifiedCaller(X509Certificate2 Certificate, List<X509Certificate2> Chain);

/// <summary>
/// Verifies an AWS IAM Roles Anywhere CreateSession request signed with AWS4-X509.
///
/// This is the real AWS wire contract, not a simplification, so that a client which works
/// against this simulator works unchanged against rolesanywhere.{region}.amazonaws.com. That
/// is the entire point: signing mistakes return an opaque 403 from AWS, which is a miserable
/// thing to debug for the first time in a production deployment.
///
/// It is SigV4 with one substantial difference. Ordinary SigV4 derives an HMAC signing key
/// from the secret access key through four chained HMACs. AWS4-X509 has no secret access key:
/// the string to sign is signed directly with the certificate's private key, and the credential
/// scope carries the certificate serial number where an access key id would normally sit.
/// </summary>
public static class AwsSigV4X509Verifier
{
    public const string RsaAlgorithm = "AWS4-X509-RSA-SHA256";
    public const string EcdsaAlgorithm = "AWS4-X509-ECDSA-SHA256";

    /// <summary>OID for Client Authentication extended key usage.</summary>
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// AWS rejects requests signed outside a five-minute window. Without it a captured
    /// signature replays indefinitely, which is the weakness of the simulator's original
    /// free-form challenge scheme.
    /// </summary>
    private static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(5);

    public static (bool Ok, string? Error, VerifiedCaller? Caller) Verify(
        HttpRequest request, string body, string region)
    {
        // --- Authorization header ----------------------------------------------------
        var authorization = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization))
        {
            return (false, "Missing Authorization header.", null);
        }

        var algorithm = authorization.Split(' ')[0];
        if (algorithm is not (RsaAlgorithm or EcdsaAlgorithm))
        {
            return (false,
                $"Unsupported signing algorithm '{algorithm}'. Expected {RsaAlgorithm} or {EcdsaAlgorithm}.",
                null);
        }

        var credentialScope = Extract(authorization, "Credential=");
        var signedHeaders = Extract(authorization, "SignedHeaders=");
        var signatureHex = Extract(authorization, "Signature=");

        if (credentialScope is null || signedHeaders is null || signatureHex is null)
        {
            return (false,
                "Malformed Authorization header: expected Credential, SignedHeaders and Signature.",
                null);
        }

        // --- Presented certificate ---------------------------------------------------
        var x509Header = request.Headers["X-Amz-X509"].ToString();
        if (string.IsNullOrWhiteSpace(x509Header))
        {
            return (false, "Missing X-Amz-X509 header.", null);
        }

        X509Certificate2 certificate;
        try
        {
            certificate = new X509Certificate2(Convert.FromBase64String(x509Header.Trim()));
        }
        catch (Exception ex)
        {
            return (false, $"X-Amz-X509 is not a base64 DER certificate: {ex.Message}", null);
        }

        var chain = new List<X509Certificate2>();
        var chainHeader = request.Headers["X-Amz-X509-Chain"].ToString();
        if (!string.IsNullOrWhiteSpace(chainHeader))
        {
            foreach (var entry in chainHeader.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    chain.Add(new X509Certificate2(Convert.FromBase64String(entry.Trim())));
                }
                catch (Exception ex)
                {
                    return (false, $"X-Amz-X509-Chain contains an unreadable certificate: {ex.Message}", null);
                }
            }
        }

        // --- Credential scope --------------------------------------------------------
        var scopeParts = credentialScope.Split('/');
        if (scopeParts.Length != 5)
        {
            return (false,
                "Credential scope must be <serial>/<date>/<region>/rolesanywhere/aws4_request.",
                null);
        }

        // Decimal, not hex. A hex serial here is a common and silent mistake.
        var expectedSerial = BigInteger.Parse("0" + certificate.SerialNumber,
            NumberStyles.HexNumber, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);

        if (!string.Equals(scopeParts[0], expectedSerial, StringComparison.Ordinal))
        {
            return (false,
                "Credential scope serial number does not match the presented certificate. " +
                "It must be the serial in decimal.",
                null);
        }

        if (!string.Equals(scopeParts[2], region, StringComparison.OrdinalIgnoreCase))
        {
            return (false, $"Credential scope region '{scopeParts[2]}' does not match '{region}'.", null);
        }

        if (scopeParts[3] != "rolesanywhere" || scopeParts[4] != "aws4_request")
        {
            return (false, "Credential scope service must be 'rolesanywhere' and terminator 'aws4_request'.", null);
        }

        // --- Timestamp ---------------------------------------------------------------
        var amzDate = request.Headers["X-Amz-Date"].ToString();
        if (!DateTimeOffset.TryParseExact(amzDate, "yyyyMMdd'T'HHmmss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var signedAt))
        {
            return (false, "X-Amz-Date is missing or not in yyyyMMddTHHmmssZ form.", null);
        }

        if ((DateTimeOffset.UtcNow - signedAt).Duration() > MaxSkew)
        {
            return (false,
                $"X-Amz-Date {amzDate} is outside the permitted {MaxSkew.TotalMinutes:0}-minute window.",
                null);
        }

        var expectedDate = signedAt.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        if (!string.Equals(scopeParts[1], expectedDate, StringComparison.Ordinal))
        {
            return (false, "Credential scope date does not match X-Amz-Date.", null);
        }

        // --- Canonical request -------------------------------------------------------
        // Rebuilt from the request that actually arrived, so the signature covers the body,
        // the timestamp and the target role rather than a string the client chose.
        var canonicalHeaders = new StringBuilder();
        foreach (var name in signedHeaders.Split(';'))
        {
            var value = name switch
            {
                // Host carries the port when it is not the scheme default, and the client
                // signs what it will actually send.
                "host" => request.Host.Value ?? string.Empty,
                _ => request.Headers[name].ToString()
            };

            canonicalHeaders.Append(name).Append(':').Append(value.Trim()).Append('\n');
        }

        var canonicalRequest = string.Join("\n",
            request.Method,
            request.Path.Value ?? "/",
            request.QueryString.HasValue ? request.QueryString.Value!.TrimStart('?') : string.Empty,
            canonicalHeaders.ToString(),
            signedHeaders,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(body))));

        var stringToSign = string.Join("\n",
            algorithm,
            amzDate,
            credentialScope,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));

        // --- Signature ---------------------------------------------------------------
        byte[] signature;
        try
        {
            signature = Convert.FromHexString(signatureHex);
        }
        catch
        {
            return (false, "Signature is not valid lowercase hex.", null);
        }

        var payload = Encoding.UTF8.GetBytes(stringToSign);
        bool verified;

        if (algorithm == RsaAlgorithm)
        {
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa is null)
            {
                return (false, "Certificate carries no RSA public key but AWS4-X509-RSA-SHA256 was used.", null);
            }

            verified = rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            using var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is null)
            {
                return (false, "Certificate carries no ECDSA public key but AWS4-X509-ECDSA-SHA256 was used.", null);
            }

            // AWS expects the DER SEQUENCE form, not the fixed-width r||s concatenation.
            verified = ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }

        if (!verified)
        {
            return (false,
                "Signature verification failed. The signature must be over the string to sign, " +
                "not the canonical request.",
                null);
        }

        // --- Extended key usage ------------------------------------------------------
        // AWS requires the Client Authentication EKU. The simulator issues certificates with
        // it but never used to check it on the way back in.
        var ekus = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .ToList();

        if (ekus.Count > 0 && ekus.All(oid => oid.Value != ClientAuthOid))
        {
            return (false,
                $"Certificate lacks the Client Authentication extended key usage ({ClientAuthOid}).",
                null);
        }

        return (true, null, new VerifiedCaller(certificate, chain));
    }

    private static string? Extract(string authorization, string key)
    {
        var start = authorization.IndexOf(key, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += key.Length;
        var end = authorization.IndexOf(',', start);
        var value = (end < 0 ? authorization[start..] : authorization[start..end]).Trim();

        return value.Length == 0 ? null : value;
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
