using System.Security.Cryptography.X509Certificates;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Aws;

/// <summary>
/// Loads the Roles Anywhere client certificate and its private key.
///
/// This runs before any AWS call succeeds, so the material it needs cannot come from the
/// secret store -- reaching the secret store is what the resulting credentials are for.
/// That leaves the OS as the root of trust, which is why the Windows certificate store is
/// the default: the private key stays non-exportable, the app pool identity is granted read
/// access to it, and nothing sensitive appears in configuration or in the deployment
/// artefact.
/// </summary>
public sealed class ClientCertificateLoader
{
    public sealed record LoadedCertificate(X509Certificate2 Leaf, IReadOnlyList<X509Certificate2> Chain);

    public static LoadedCertificate Load(CertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var leaf = options.Source switch
        {
            CertificateSource.WindowsStore => FromStore(options),
            CertificateSource.PemFile => FromPem(options),
            CertificateSource.PfxFile => FromPfx(options),
            _ => throw new InvalidOperationException(
                $"Unknown certificate source '{options.Source}'.")
        };

        if (!leaf.HasPrivateKey)
        {
            leaf.Dispose();
            throw new InvalidOperationException(
                "The Roles Anywhere client certificate was found but carries no private key. " +
                "A certificate imported without its key cannot sign a CreateSession request.");
        }

        var chain = options.IncludeChain ? BuildChain(leaf) : [];
        return new LoadedCertificate(leaf, chain);
    }

    private static X509Certificate2 FromStore(CertificateOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Thumbprint))
        {
            throw new InvalidOperationException(
                "Certificate:Thumbprint is required when Certificate:Source is 'WindowsStore'.");
        }

        // Thumbprints are routinely pasted from the Windows certificate dialog, which
        // interleaves spaces and can prepend an invisible left-to-right mark.
        var thumbprint = new string(options.Thumbprint
            .Where(char.IsLetterOrDigit)
            .ToArray())
            .ToUpperInvariant();

        var location = Enum.TryParse<StoreLocation>(options.StoreLocation, ignoreCase: true, out var loc)
            ? loc
            : throw new InvalidOperationException(
                $"Certificate:StoreLocation '{options.StoreLocation}' is not a valid store location " +
                "(expected 'LocalMachine' or 'CurrentUser').");

        var name = Enum.TryParse<StoreName>(options.StoreName, ignoreCase: true, out var storeName)
            ? storeName
            : throw new InvalidOperationException(
                $"Certificate:StoreName '{options.StoreName}' is not a valid store name (normally 'My').");

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        // validOnly: false so an expired certificate reports as expired below rather than as
        // "not found", which sends an operator looking for a deployment problem instead.
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

        if (matches.Count == 0)
        {
            throw new InvalidOperationException(
                $"No certificate with thumbprint {thumbprint} in {location}/{name}. " +
                "Check the certificate is installed for the machine rather than for a user account.");
        }

        var certificate = matches[0];

        if (certificate.NotAfter < DateTime.Now)
        {
            throw new InvalidOperationException(
                $"The Roles Anywhere client certificate {thumbprint} expired on " +
                $"{certificate.NotAfter:yyyy-MM-dd}. Roles Anywhere will reject it.");
        }

        return certificate;
    }

    private static X509Certificate2 FromPem(CertificateOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.CertificatePath) ||
            string.IsNullOrWhiteSpace(options.PrivateKeyPath))
        {
            throw new InvalidOperationException(
                "Certificate:CertificatePath and Certificate:PrivateKeyPath are both required " +
                "when Certificate:Source is 'PemFile'.");
        }

        RequireFile(options.CertificatePath, "Certificate:CertificatePath");
        RequireFile(options.PrivateKeyPath, "Certificate:PrivateKeyPath");

        var loaded = X509Certificate2.CreateFromPemFile(options.CertificatePath, options.PrivateKeyPath);

        // On Windows a certificate built from PEM holds an ephemeral key that cannot be used
        // for signing until it has been round-tripped through a PKCS#12 export.
        if (OperatingSystem.IsWindows())
        {
            using (loaded)
            {
                return new X509Certificate2(
                    loaded.Export(X509ContentType.Pkcs12),
                    (string?)null,
                    X509KeyStorageFlags.EphemeralKeySet);
            }
        }

        return loaded;
    }

    private static X509Certificate2 FromPfx(CertificateOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.PfxPath))
        {
            throw new InvalidOperationException(
                "Certificate:PfxPath is required when Certificate:Source is 'PfxFile'.");
        }

        RequireFile(options.PfxPath, "Certificate:PfxPath");

        string? password = null;
        if (!string.IsNullOrWhiteSpace(options.PfxPasswordEnvironmentVariable))
        {
            password = Environment.GetEnvironmentVariable(options.PfxPasswordEnvironmentVariable);

            if (string.IsNullOrEmpty(password))
            {
                throw new InvalidOperationException(
                    $"Environment variable '{options.PfxPasswordEnvironmentVariable}' is not set on this " +
                    "host, so the Roles Anywhere certificate bundle cannot be opened.");
            }
        }

        return new X509Certificate2(
            File.ReadAllBytes(options.PfxPath),
            password,
            X509KeyStorageFlags.EphemeralKeySet);
    }

    /// <summary>
    /// Collects the intermediates between the leaf and the root. The leaf is sent in
    /// X-Amz-X509 and the root is already held by the trust anchor, so neither belongs here.
    /// </summary>
    private static IReadOnlyList<X509Certificate2> BuildChain(X509Certificate2 leaf)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        // A chain that does not terminate in a locally trusted root is still usable: what
        // matters is that Roles Anywhere can build a path to the trust anchor, which this
        // host has no way to check.
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.Build(leaf);

        return chain.ChainElements
            .Select(element => element.Certificate)
            .Skip(1)                                              // the leaf
            .Where(certificate => certificate.Subject != certificate.Issuer)  // the root
            .ToList();
    }

    private static void RequireFile(string path, string settingName)
    {
        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"{settingName} points at '{path}', which does not exist.");
        }
    }
}
