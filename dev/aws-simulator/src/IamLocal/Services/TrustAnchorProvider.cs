using System.Security.Cryptography.X509Certificates;
using Shared.Crypto;

namespace IamLocal.Services;

public interface ITrustAnchorProvider
{
    /// <summary>The root CA backing the trust anchor. Stable for the life of the process.</summary>
    X509Certificate2 Ca { get; }
}

/// <summary>
/// Holds the Roles Anywhere trust anchor CA.
///
/// Registered as a singleton on purpose. This was previously constructed inside the scoped
/// <see cref="RolesAnywhereService"/>, which meant reading -- and on first run generating and
/// writing -- the CA on every HTTP request. Beyond the cost, two concurrent first requests
/// could each decide the CA was missing, generate different ones and race on the write, after
/// which certificates issued moments earlier no longer chained to the anchor on disk.
/// </summary>
public sealed class TrustAnchorProvider : ITrustAnchorProvider, IDisposable
{
    private const string CaPassword = "dev-ca-password";

    private readonly ILogger<TrustAnchorProvider> _logger;

    public X509Certificate2 Ca { get; }

    public TrustAnchorProvider(ILogger<TrustAnchorProvider> logger)
    {
        _logger = logger;

        var keysDir = Path.Combine(AppContext.BaseDirectory, ".keys");
        Directory.CreateDirectory(keysDir);
        var caPath = Path.Combine(keysDir, "roles_anywhere_ca.pfx");

        if (File.Exists(caPath))
        {
            try
            {
                Ca = new X509Certificate2(caPath, CaPassword, X509KeyStorageFlags.Exportable);
                _logger.LogInformation(
                    "Roles Anywhere trust anchor loaded. Subject {Subject}, thumbprint {Thumbprint}.",
                    Ca.Subject, Ca.Thumbprint);
                return;
            }
            catch (Exception ex)
            {
                // A corrupt or unreadable CA file is replaced, but say so: every certificate
                // issued from the previous CA stops chaining at this moment.
                _logger.LogWarning(ex,
                    "The existing trust anchor at {Path} could not be opened and is being replaced. " +
                    "Client certificates issued from the previous CA will no longer be accepted.", caPath);
            }
        }

        Ca = X509CertificateGenerator.CreateRootCa("CN=LocalRolesAnywhereRootCA");
        File.WriteAllBytes(caPath, Ca.Export(X509ContentType.Pfx, CaPassword));

        _logger.LogInformation(
            "Roles Anywhere trust anchor created. Subject {Subject}, thumbprint {Thumbprint}.",
            Ca.Subject, Ca.Thumbprint);
    }

    public void Dispose() => Ca.Dispose();
}
