using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Shared.Crypto;

public static class X509CertificateGenerator
{
    /// <summary>
    /// Generates a self-signed Root Certificate Authority (Trust Anchor).
    /// </summary>
    public static X509Certificate2 CreateRootCa(string subjectName = "CN=LocalRolesAnywhereRootCA")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true));

        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
            critical: true));

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-10);
        var notAfter = DateTimeOffset.UtcNow.AddYears(10);

        return req.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>
    /// Issues a client certificate signed by the specified Root CA.
    /// </summary>
    /// <param name="validityDays">
    /// How long the certificate is valid for, from ten minutes ago. A negative value issues an
    /// already-expired certificate, which is how certificate expiry -- the failure that takes a
    /// Roles Anywhere deployment down everywhere at once -- can be rehearsed locally.
    /// </param>
    public static X509Certificate2 CreateClientCertificate(
        X509Certificate2 caCert,
        string subjectName = "CN=LocalWorkloadClient",
        int validityDays = 730)
    {
        var clientRsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, clientRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Client Authentication EKU (1.3.6.1.5.5.7.3.2)
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },
            critical: false));

        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));

        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);

        DateTimeOffset notBefore;
        DateTimeOffset notAfter;

        if (validityDays < 0)
        {
            // An already-expired certificate still has to sit inside the issuer's own validity
            // window -- .NET refuses to issue one whose notBefore precedes the CA's. So start
            // at the CA's notBefore and expire as early as that allows, which is in the past
            // whenever the CA is older than a moment.
            var caNotBefore = new DateTimeOffset(caCert.NotBefore.ToUniversalTime());
            notBefore = caNotBefore;

            var requested = DateTimeOffset.UtcNow.AddDays(validityDays);
            notAfter = requested > caNotBefore ? requested : caNotBefore.AddSeconds(1);

            // Guarantee it really is expired even for a CA created seconds ago.
            var justNow = DateTimeOffset.UtcNow.AddSeconds(-1);
            if (notAfter > justNow)
            {
                notAfter = justNow;
            }
        }
        else
        {
            notBefore = DateTimeOffset.UtcNow.AddMinutes(-10);
            notAfter = DateTimeOffset.UtcNow.AddDays(validityDays);
        }

        using var signedCert = req.Create(
            caCert,
            notBefore,
            notAfter,
            serialNumber);

        return signedCert.CopyWithPrivateKey(clientRsa);
    }

    /// <summary>
    /// Exports certificate as PEM encoded string.
    /// </summary>
    public static string ExportToPem(X509Certificate2 cert)
    {
        return cert.ExportCertificatePem();
    }

    /// <summary>
    /// Exports private key as PEM encoded string (PKCS#8).
    /// </summary>
    public static string ExportPrivateKeyToPem(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPrivateKey();
        if (rsa == null) throw new InvalidOperationException("Certificate does not contain an RSA private key.");
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Imports a certificate and private key from PEM strings.
    /// </summary>
    public static X509Certificate2 ImportFromPem(string certPem, string? privateKeyPem = null)
    {
        var cert = X509Certificate2.CreateFromPem(certPem);
        if (!string.IsNullOrWhiteSpace(privateKeyPem))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            return cert.CopyWithPrivateKey(rsa);
        }
        return cert;
    }
}
