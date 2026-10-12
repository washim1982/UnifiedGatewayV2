using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IamLocal.Data;
using Shared.Crypto;
using Shared.DTOs;
using Shared.Models;

namespace IamLocal.Services;

public interface IRolesAnywhereService
{
    TrustAnchorSummary GetTrustAnchor();
    List<TrustAnchorSummary> ListTrustAnchors();
    List<ProfileSummary> ListProfiles();
    GenerateTestCertResponse GenerateTestCertificate(string subjectName = "CN=LocalWorkloadClient", int validityDays = 730);
    Task<(bool Success, string? ErrorMessage, AssumedCredentials? Credentials)> CreateSessionAsync(CreateSessionRequest request);

    /// <summary>
    /// The AWS-compatible CreateSession. The caller's signature has already been verified by
    /// <see cref="AwsSigV4X509Verifier"/>; this applies the authorization AWS applies -- chain
    /// validity, trust anchor, profile membership and the role's own trust policy.
    /// </summary>
    Task<(bool Success, string? ErrorMessage, AssumedCredentials? Credentials, string? SubjectArn)>
        CreateAwsSessionAsync(VerifiedCaller caller, AwsCreateSessionRequest request);
}

public class RolesAnywhereService : IRolesAnywhereService
{
    private readonly IRoleStore _roleStore;
    private readonly IJwtTokenService _tokenService;
    private readonly ILogger<RolesAnywhereService> _logger;
    private readonly X509Certificate2 _trustAnchorCa;

    public const string DefaultTrustAnchorArn = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/dev-anchor";
    public const string DefaultProfileArn = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/dev-profile";
    public const string DefaultTrustAnchorName = "dev-trust-anchor";
    public const string DefaultProfileName = "dev-profile";

    public RolesAnywhereService(
        IRoleStore roleStore,
        IJwtTokenService tokenService,
        ITrustAnchorProvider trustAnchor,
        ILogger<RolesAnywhereService> logger)
    {
        _roleStore = roleStore;
        _tokenService = tokenService;
        _logger = logger;

        // Supplied by a singleton rather than loaded here: this service is scoped, so opening
        // (and on first run generating) the CA in the constructor did that work on every
        // request, and let two concurrent cold-start requests race to create different CAs.
        _trustAnchorCa = trustAnchor.Ca;
    }

    public TrustAnchorSummary GetTrustAnchor()
    {
        return new TrustAnchorSummary(
            DefaultTrustAnchorArn,
            DefaultTrustAnchorName,
            _trustAnchorCa.Thumbprint,
            _trustAnchorCa.Subject);
    }

    public List<TrustAnchorSummary> ListTrustAnchors()
    {
        return new List<TrustAnchorSummary> { GetTrustAnchor() };
    }

    public List<ProfileSummary> ListProfiles()
    {
        return new List<ProfileSummary>
        {
            new(
                DefaultProfileArn,
                DefaultProfileName,
                new List<string>
                {
                    "arn:aws:iam::123456789012:role/dev-role",
                    "arn:aws:iam::123456789012:role/admin-role",
                    // Listed deliberately. Its trust policy is incomplete, so asking for it
                    // gets past the profile check and fails on the role's own trust policy --
                    // reproducing the most common Roles Anywhere misconfiguration in
                    // production, which AWS reports as a bare 403.
                    "arn:aws:iam::123456789012:role/read-only-role"
                },
                3600)
        };
    }

    public GenerateTestCertResponse GenerateTestCertificate(string subjectName = "CN=LocalWorkloadClient", int validityDays = 730)
    {
        using var clientCert = X509CertificateGenerator.CreateClientCertificate(_trustAnchorCa, subjectName, validityDays);
        var certPem = X509CertificateGenerator.ExportToPem(clientCert);
        var keyPem = X509CertificateGenerator.ExportPrivateKeyToPem(clientCert);

        return new GenerateTestCertResponse(
            CertPem: certPem,
            PrivateKeyPem: keyPem,
            Thumbprint: clientCert.Thumbprint,
            Subject: clientCert.Subject);
    }

    public async Task<(bool Success, string? ErrorMessage, AssumedCredentials? Credentials)> CreateSessionAsync(CreateSessionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CertPem))
        {
            return (false, "Missing required certificate in PEM format.", null);
        }

        if (string.IsNullOrWhiteSpace(request.SignatureBase64) || string.IsNullOrWhiteSpace(request.PayloadToVerify))
        {
            return (false, "Missing required cryptographic signature or challenge payload.", null);
        }

        X509Certificate2 clientCert;
        try
        {
            clientCert = X509Certificate2.CreateFromPem(request.CertPem);
        }
        catch (Exception ex)
        {
            return (false, $"Failed to parse client certificate: {ex.Message}", null);
        }

        // 1. Verify digital signature over challenge payload using client certificate public key
        using var rsa = clientCert.GetRSAPublicKey();
        if (rsa == null)
        {
            return (false, "Client certificate does not contain an RSA public key.", null);
        }

        byte[] payloadBytes;
        byte[] signatureBytes;
        try
        {
            payloadBytes = Encoding.UTF8.GetBytes(request.PayloadToVerify);
            signatureBytes = Convert.FromBase64String(request.SignatureBase64);
        }
        catch (Exception ex)
        {
            return (false, $"Invalid signature encoding: {ex.Message}", null);
        }

        bool signatureValid = rsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!signatureValid)
        {
            return (false, "Signature verification failed. The provided signature does not match the certificate.", null);
        }

        // 2. Validate certificate trust chain against Trust Anchor Root CA
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_trustAnchorCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        // chain.Build() returns false for an expired or not-yet-valid certificate but still
        // populates ChainElements with the path it built -- anchor included. Checking only
        // that the anchor appears therefore accepts expired certificates, which is the one
        // failure a local environment most needs to be able to rehearse.
        bool chainValid = chain.Build(clientCert);
        bool isAnchorTrusted = chain.ChainElements.Cast<X509ChainElement>()
            .Any(e => e.Certificate.Thumbprint.Equals(_trustAnchorCa.Thumbprint, StringComparison.OrdinalIgnoreCase));

        if (!isAnchorTrusted)
        {
            return (false, "Certificate validation failed: client certificate is not issued by the trusted anchor CA.", null);
        }

        if (!chainValid)
        {
            var reasons = string.Join(", ", chain.ChainStatus.Select(status => status.Status.ToString()));
            return (false, $"Certificate validation failed: {reasons}.", null);
        }

        // 3. Resolve IAM Role
        var rawRole = request.RoleArn ?? "dev-role";
        var roleName = rawRole.Contains('/') ? rawRole.Split('/').Last() : rawRole;

        var role = await _roleStore.GetRoleByNameAsync(roleName);
        if (role == null)
        {
            return (false, $"IAM Role '{roleName}' not found in role store.", null);
        }

        // 4. Issue temporary STS credentials with JWT session token
        var duration = Math.Clamp(request.DurationSeconds, 900, 43200); // 15m to 12h
        var token = _tokenService.GenerateToken(role, duration);

        var credentials = new AssumedCredentials(
            AccessKeyId: $"ASIA{RandomNumberGenerator.GetHexString(16).ToUpperInvariant()}",
            SecretAccessKey: RandomNumberGenerator.GetHexString(32),
            SessionToken: token.Jwt,
            Expiration: token.ExpiresAt);

        return (true, null, credentials);
    }

    public async Task<(bool Success, string? ErrorMessage, AssumedCredentials? Credentials, string? SubjectArn)>
        CreateAwsSessionAsync(VerifiedCaller caller, AwsCreateSessionRequest request)
    {
        // --- 1. Certificate chain, including validity period ---------------------
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.CustomTrustStore.Add(_trustAnchorCa);

        foreach (var intermediate in caller.Chain)
        {
            chain.ChainPolicy.ExtraStore.Add(intermediate);
        }

        var built = chain.Build(caller.Certificate);

        var anchorPresent = chain.ChainElements.Cast<X509ChainElement>()
            .Any(element => element.Certificate.Thumbprint.Equals(
                _trustAnchorCa.Thumbprint, StringComparison.OrdinalIgnoreCase));

        if (!anchorPresent)
        {
            return (false,
                "The client certificate was not issued by the CA behind this trust anchor.",
                null, null);
        }

        if (!built)
        {
            var reasons = string.Join(", ", chain.ChainStatus.Select(status => status.Status.ToString()));
            return (false, $"Certificate chain validation failed: {reasons}.", null, null);
        }

        // --- 2. Trust anchor -----------------------------------------------------
        if (!string.IsNullOrWhiteSpace(request.TrustAnchorArn) &&
            !string.Equals(request.TrustAnchorArn, DefaultTrustAnchorArn, StringComparison.OrdinalIgnoreCase))
        {
            return (false,
                $"Trust anchor '{request.TrustAnchorArn}' does not resolve in this region and account.",
                null, null);
        }

        // --- 3. Profile ----------------------------------------------------------
        var profile = ListProfiles()
            .FirstOrDefault(p => string.Equals(p.ProfileArn, request.ProfileArn, StringComparison.OrdinalIgnoreCase));

        if (profile is null)
        {
            return (false,
                $"Profile '{request.ProfileArn}' does not resolve in this region and account.",
                null, null);
        }

        if (string.IsNullOrWhiteSpace(request.RoleArn))
        {
            return (false, "roleArn is required.", null, null);
        }

        // The profile is what constrains which roles a certificate holder may ask for.
        if (!profile.RoleArns.Contains(request.RoleArn, StringComparer.OrdinalIgnoreCase))
        {
            return (false,
                $"Profile '{profile.Name}' does not list role '{request.RoleArn}'. " +
                $"It allows: {string.Join(", ", profile.RoleArns)}.",
                null, null);
        }

        // --- 4. Role -------------------------------------------------------------
        var roleName = request.RoleArn.Contains('/') ? request.RoleArn.Split('/').Last() : request.RoleArn;
        var role = await _roleStore.GetRoleByNameAsync(roleName);

        if (role is null)
        {
            return (false, $"IAM Role '{roleName}' not found in the role store.", null, null);
        }

        // --- 5. The role's own trust policy --------------------------------------
        if (!RoleTrustEvaluator.Allows(role.TrustPolicy, DefaultTrustAnchorArn, out var trustFailure))
        {
            _logger.LogWarning(
                "Refused a Roles Anywhere session for {Role}: {Reason}", roleName, trustFailure);

            return (false, trustFailure, null, null);
        }

        // --- 6. Issue ------------------------------------------------------------
        // AWS caps a Roles Anywhere session at one hour whatever the role's own maximum says.
        var duration = Math.Clamp(request.DurationSeconds, 900, 3600);
        var token = _tokenService.GenerateToken(role, duration);

        var credentials = new AssumedCredentials(
            AccessKeyId: $"ASIA{RandomNumberGenerator.GetHexString(16).ToUpperInvariant()}",
            SecretAccessKey: RandomNumberGenerator.GetHexString(32),
            SessionToken: token.Jwt,
            Expiration: token.ExpiresAt);

        var subjectArn =
            $"arn:aws:rolesanywhere:us-east-1:123456789012:subject/{caller.Certificate.Thumbprint.ToLowerInvariant()}";

        _logger.LogInformation(
            "Roles Anywhere session issued to {Subject} for {Role}, valid {Duration}s.",
            caller.Certificate.Subject, roleName, duration);

        return (true, null, credentials, subjectArn);
    }
}
