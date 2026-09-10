namespace UnifiedGateway.Models;

/// <summary>
/// Where the gateway's AWS credentials come from.
///
/// The gateway deploys to IIS, not to EC2, ECS or Lambda, so there is no instance or task
/// role to inherit. That leaves two honest options for a shared host: a long-lived access
/// key sitting in a file, or IAM Roles Anywhere exchanging an X.509 certificate for
/// short-lived credentials. Test and Production use the second; StartupValidator refuses
/// the alternatives there.
/// </summary>
public enum AwsCredentialSource
{
    /// <summary>
    /// Derive the source from the legacy fields: <c>UseLocalProfile</c> first, then
    /// <c>AssumeRoleArn</c>, then the ambient chain. Preserves the behaviour of any
    /// configuration written before this setting existed.
    /// </summary>
    Auto = 0,

    /// <summary>A named profile in ~/.aws. Development only.</summary>
    LocalProfile = 1,

    /// <summary>Base credentials from the ambient chain, then STS AssumeRole.</summary>
    AssumeRole = 2,

    /// <summary>
    /// IAM Roles Anywhere: sign a CreateSession request with an X.509 client certificate
    /// and receive temporary credentials for the target role. No stored access key.
    /// </summary>
    RolesAnywhere = 3
}

/// <summary>How the client certificate and its private key are obtained.</summary>
public enum CertificateSource
{
    /// <summary>
    /// The Windows certificate store, located by thumbprint. The natural choice under IIS:
    /// the private key is held by the OS, the app pool identity is granted read access to
    /// it, and no key material or passphrase ever appears in configuration or on disk in a
    /// form the application can export.
    /// </summary>
    WindowsStore = 0,

    /// <summary>A PEM certificate and a separate PEM private key, protected by file ACLs.</summary>
    PemFile = 1,

    /// <summary>A PKCS#12 bundle. The passphrase comes from an environment variable, never config.</summary>
    PfxFile = 2
}

/// <summary>
/// IAM Roles Anywhere settings. Every value here is an identifier or a path -- there is no
/// secret in this block, which is the point of the mechanism.
/// </summary>
public class RolesAnywhereOptions
{
    /// <summary>ARN of the trust anchor holding the CA that issued the client certificate.</summary>
    public string TrustAnchorArn { get; set; } = string.Empty;

    /// <summary>ARN of the Roles Anywhere profile listing the roles this workload may assume.</summary>
    public string ProfileArn { get; set; } = string.Empty;

    /// <summary>ARN of the role to assume. Must be listed by the profile above.</summary>
    public string RoleArn { get; set; } = string.Empty;

    /// <summary>Session name recorded in CloudTrail against every call this workload makes.</summary>
    public string SessionName { get; set; } = "unified-gateway";

    /// <summary>Session lifetime. AWS accepts 900-3600 seconds for Roles Anywhere.</summary>
    public int DurationSeconds { get; set; } = 3600;

    /// <summary>The client certificate and key.</summary>
    public CertificateOptions Certificate { get; set; } = new();

    /// <summary>
    /// Overrides the CreateSession endpoint. Empty means the real regional endpoint,
    /// <c>https://rolesanywhere.{region}.amazonaws.com</c>. Only a local simulator has any
    /// business setting this, and StartupValidator refuses it outside Development.
    /// </summary>
    public string EndpointOverride { get; set; } = string.Empty;

    /// <summary>
    /// Speaks the .NET simulator's simplified CreateSession contract instead of the AWS one.
    ///
    /// The simulator verifies a bare RSA signature over a client-chosen string; AWS verifies
    /// a full SigV4 AWS4-X509 signature. Exercising this path therefore tells you the wiring
    /// and the certificate load work -- it does NOT validate the production signing.
    /// Development only.
    /// </summary>
    public bool UseSimulatorProtocol { get; set; } = false;
}

public class CertificateOptions
{
    public CertificateSource Source { get; set; } = CertificateSource.WindowsStore;

    /// <summary>"LocalMachine" or "CurrentUser". LocalMachine is correct for an IIS app pool.</summary>
    public string StoreLocation { get; set; } = "LocalMachine";

    /// <summary>Store name, normally "My" (Personal).</summary>
    public string StoreName { get; set; } = "My";

    /// <summary>Thumbprint of the client certificate. Case and spaces are ignored.</summary>
    public string Thumbprint { get; set; } = string.Empty;

    /// <summary>PEM certificate path, for <see cref="CertificateSource.PemFile"/>.</summary>
    public string CertificatePath { get; set; } = string.Empty;

    /// <summary>PEM private key path, for <see cref="CertificateSource.PemFile"/>.</summary>
    public string PrivateKeyPath { get; set; } = string.Empty;

    /// <summary>PKCS#12 path, for <see cref="CertificateSource.PfxFile"/>.</summary>
    public string PfxPath { get; set; } = string.Empty;

    /// <summary>
    /// Name of the environment variable holding the PKCS#12 passphrase.
    ///
    /// The variable's name, not its value. A passphrase in appsettings would be a secret in
    /// configuration, which is the thing the rest of this codebase spent its effort removing;
    /// and it cannot come from the secret store either, because reaching the secret store is
    /// what these credentials are for.
    /// </summary>
    public string PfxPasswordEnvironmentVariable { get; set; } = string.Empty;

    /// <summary>
    /// Send the intermediate certificates alongside the leaf. Required whenever the trust
    /// anchor holds a root rather than the issuing intermediate.
    /// </summary>
    public bool IncludeChain { get; set; } = true;
}
