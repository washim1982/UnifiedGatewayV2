using System.Globalization;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Aws;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// IAM Roles Anywhere is the credential path for every AWS service in Test and Production.
/// The signing is the part that cannot be checked by running it -- a wrong signature returns
/// the same 403 as a misconfigured trust anchor -- so it is verified here against the
/// structure AWS specifies, and the signature is verified with the certificate's public key.
/// </summary>
public class RolesAnywhereTests
{
    private static X509Certificate2 CreateRsaCertificate(string subject = "CN=unified-gateway-test")
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateEcdsaCertificate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=unified-gateway-ecdsa", ecdsa, HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
    }

    private static readonly DateTimeOffset FixedTime =
        new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    private const string Host = "rolesanywhere.us-east-1.amazonaws.com";
    private const string Region = "us-east-1";
    private const string Body = """{"durationSeconds":3600,"profileArn":"p","roleArn":"r","trustAnchorArn":"t"}""";

    // --- The signature itself ---------------------------------------------------------

    [Fact]
    public void TheSignatureVerifiesWithTheCertificatePublicKey()
    {
        // The property that matters: AWS holds only the public key, so whatever is signed
        // must verify against it. This is what a wrong hash, a wrong padding, or a signature
        // over the canonical request instead of the string to sign would all break.
        using var certificate = CreateRsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);

        var signatureHex = signed.Authorization.Split("Signature=")[1];
        var signature = Convert.FromHexString(signatureHex);

        using var publicKey = certificate.GetRSAPublicKey()!;

        Assert.True(publicKey.VerifyData(
            Encoding.UTF8.GetBytes(signed.StringToSign),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void TheSignatureIsOverTheStringToSignNotTheCanonicalRequest()
    {
        // A plausible and completely silent mistake: both are strings, both hash, and the
        // service answers 403 either way.
        using var certificate = CreateRsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);
        var signature = Convert.FromHexString(signed.Authorization.Split("Signature=")[1]);

        using var publicKey = certificate.GetRSAPublicKey()!;

        Assert.False(publicKey.VerifyData(
            Encoding.UTF8.GetBytes(signed.CanonicalRequest),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void EcdsaCertificatesAreSignedWithTheEcdsaAlgorithmAndDerEncoding()
    {
        using var certificate = CreateEcdsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);

        Assert.StartsWith(RolesAnywhereSigner.EcdsaAlgorithm, signed.Authorization, StringComparison.Ordinal);

        var signature = Convert.FromHexString(signed.Authorization.Split("Signature=")[1]);
        using var publicKey = certificate.GetECDsaPublicKey()!;

        // AWS requires the DER SEQUENCE form, not .NET's default fixed-width r||s.
        Assert.True(publicKey.VerifyData(
            Encoding.UTF8.GetBytes(signed.StringToSign),
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    // --- Structure AWS requires -------------------------------------------------------

    [Fact]
    public void TheCredentialScopeCarriesTheSerialNumberInDecimal()
    {
        // Ordinary SigV4 puts an access key id here. AWS4-X509 puts the certificate serial
        // number, in decimal -- hex would be silently rejected.
        using var certificate = CreateRsaCertificate();

        var expected = BigInteger.Parse("0" + certificate.SerialNumber,
            NumberStyles.HexNumber, CultureInfo.InvariantCulture).ToString();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);

        Assert.Contains($"Credential={expected}/20260910/us-east-1/rolesanywhere/aws4_request", signed.Authorization);
    }

    [Fact]
    public void ASerialNumberWithAHighBitStaysPositive()
    {
        // Without the leading zero, BigInteger reads a leading bit of 1 as a sign bit and the
        // scope carries a negative serial number. Most certificates never expose this.
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=high-bit", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var serial = new byte[] { 0xF0, 0x01, 0x02, 0x03 };
        using var certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30),
            serial);

        var decimalSerial = RolesAnywhereSigner.SerialNumberDecimal(certificate);

        Assert.DoesNotContain("-", decimalSerial);
        Assert.Equal("4026597891", decimalSerial);   // 0xF0010203
    }

    [Fact]
    public void TheStringToSignHasTheFourLinesSigV4Requires()
    {
        using var certificate = CreateRsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);
        var lines = signed.StringToSign.Split('\n');

        Assert.Equal(4, lines.Length);
        Assert.Equal(RolesAnywhereSigner.RsaAlgorithm, lines[0]);
        Assert.Equal("20260910T120000Z", lines[1]);
        Assert.EndsWith("/20260910/us-east-1/rolesanywhere/aws4_request", lines[2]);

        // Line 4 is the hash of the canonical request, lowercase hex.
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signed.CanonicalRequest))).ToLowerInvariant(),
            lines[3]);
    }

    [Fact]
    public void TheCanonicalRequestHashesTheExactBodyThatWillBeSent()
    {
        using var certificate = CreateRsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);
        var expectedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Body))).ToLowerInvariant();

        Assert.EndsWith(expectedHash, signed.CanonicalRequest);
        Assert.StartsWith("POST\n/sessions\n\n", signed.CanonicalRequest);
    }

    [Fact]
    public void SignedHeadersAreSortedAndMatchTheCanonicalHeaders()
    {
        using var certificate = CreateRsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);
        var signedHeaders = signed.Authorization.Split("SignedHeaders=")[1].Split(",")[0].Trim();

        Assert.Equal("content-type;host;x-amz-date;x-amz-x509", signedHeaders);

        foreach (var header in signedHeaders.Split(';'))
        {
            Assert.Contains($"{header}:", signed.CanonicalRequest);
        }
    }

    [Fact]
    public void ThePresentedCertificateIsTheBase64DerOfTheLeaf()
    {
        using var certificate = CreateRsaCertificate();

        var signed = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);

        // Base64 DER, not PEM: no header line, no newlines.
        Assert.Equal(Convert.ToBase64String(certificate.RawData), signed.X509);
        Assert.DoesNotContain("BEGIN CERTIFICATE", signed.X509);
    }

    [Fact]
    public void AnIntermediateChainIsSignedAsWellAsSent()
    {
        // A chain sent but not signed produces a signature mismatch rather than a trust
        // failure, which is a confusing way to discover the omission.
        using var certificate = CreateRsaCertificate();
        using var intermediate = CreateRsaCertificate("CN=unified-gateway-intermediate");

        var signed = RolesAnywhereSigner.Sign(certificate, [intermediate], Host, Region, Body, FixedTime);

        Assert.Equal(Convert.ToBase64String(intermediate.RawData), signed.X509Chain);
        Assert.Contains("x-amz-x509-chain", signed.Authorization);
        Assert.Contains("x-amz-x509-chain:", signed.CanonicalRequest);
    }

    [Fact]
    public void SigningIsDeterministicForAGivenTimestamp()
    {
        // RSA PKCS#1 v1.5 is deterministic, so a differing signature would mean something in
        // the canonicalisation is picking up ambient state.
        using var certificate = CreateRsaCertificate();

        var first = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);
        var second = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);

        Assert.Equal(first.Authorization, second.Authorization);
    }

    [Fact]
    public void ADifferentBodyProducesADifferentSignature()
    {
        using var certificate = CreateRsaCertificate();

        var first = RolesAnywhereSigner.Sign(certificate, [], Host, Region, Body, FixedTime);
        var second = RolesAnywhereSigner.Sign(certificate, [], Host, Region,
            Body.Replace("3600", "900"), FixedTime);

        Assert.NotEqual(first.Authorization, second.Authorization);
    }

    // --- The session exchange ---------------------------------------------------------

    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static (RolesAnywhereCredentialProvider Provider, StubHandler Handler) CreateProvider(
        HttpStatusCode status, string responseBody, Action<RolesAnywhereOptions>? configure = null)
    {
        // A PFX on disk, because the Windows store is not something a test may write to.
        using var certificate = CreateRsaCertificate();
        var pfxPath = Path.Combine(Path.GetTempPath(), $"ra-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(pfxPath, certificate.Export(X509ContentType.Pkcs12));

        var options = new GatewayOptions();
        options.Aws.Region = Region;
        options.Aws.CredentialSource = AwsCredentialSource.RolesAnywhere;
        options.Aws.RolesAnywhere.TrustAnchorArn = "arn:aws:rolesanywhere:us-east-1:1:trust-anchor/a";
        options.Aws.RolesAnywhere.ProfileArn = "arn:aws:rolesanywhere:us-east-1:1:profile/b";
        options.Aws.RolesAnywhere.RoleArn = "arn:aws:iam::1:role/GatewayRole";
        options.Aws.RolesAnywhere.Certificate.Source = CertificateSource.PfxFile;
        options.Aws.RolesAnywhere.Certificate.PfxPath = pfxPath;
        options.Aws.RolesAnywhere.Certificate.IncludeChain = false;
        configure?.Invoke(options.Aws.RolesAnywhere);

        var handler = new StubHandler(status, responseBody);

        return (new RolesAnywhereCredentialProvider(
            new StubFactory(handler),
            Options.Create(options),
            NullLogger<RolesAnywhereCredentialProvider>.Instance), handler);
    }

    private const string AwsSessionResponse = """
    {
      "credentialSet": [
        {
          "assumedRoleUser": { "arn": "arn:aws:sts::1:assumed-role/GatewayRole/unified-gateway" },
          "credentials": {
            "accessKeyId": "ASIAEXAMPLE",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": "2026-09-10T13:00:00Z"
          }
        }
      ],
      "subjectArn": "arn:aws:rolesanywhere:us-east-1:1:subject/abc"
    }
    """;

    [Fact]
    public async Task ASuccessfulSessionYieldsTemporaryCredentialsAndAnExpiry()
    {
        var (provider, _) = CreateProvider(HttpStatusCode.Created, AwsSessionResponse);
        using var _p = provider;

        var (credentials, expiration, subjectArn) = await provider.CreateSessionAsync();

        var immutable = await credentials.GetCredentialsAsync();
        Assert.Equal("ASIAEXAMPLE", immutable.AccessKey);
        Assert.Equal("token", immutable.Token);
        Assert.Equal(new DateTimeOffset(2026, 9, 10, 13, 0, 0, TimeSpan.Zero), expiration);
        Assert.Equal("arn:aws:rolesanywhere:us-east-1:1:subject/abc", subjectArn);
    }

    [Fact]
    public async Task TheRequestIsSentToTheRegionalSessionsEndpointWithTheSignedHeaders()
    {
        var (provider, handler) = CreateProvider(HttpStatusCode.OK, AwsSessionResponse);
        using var _p = provider;

        await provider.CreateSessionAsync();

        Assert.Equal($"https://{Host}/sessions", handler.LastRequest!.RequestUri!.ToString());
        Assert.True(handler.LastRequest.Headers.Contains("X-Amz-X509"));
        Assert.True(handler.LastRequest.Headers.Contains("X-Amz-Date"));

        var authorization = handler.LastRequest.Headers.GetValues("Authorization").Single();
        Assert.StartsWith(RolesAnywhereSigner.RsaAlgorithm, authorization, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSignedContentTypeMatchesTheOneActuallySent()
    {
        // StringContent appends "; charset=utf-8", which would not match the signed value and
        // would fail as a signature mismatch with no hint at the cause.
        var (provider, handler) = CreateProvider(HttpStatusCode.OK, AwsSessionResponse);
        using var _p = provider;

        await provider.CreateSessionAsync();

        Assert.Equal("application/json", handler.LastRequest!.Content!.Headers.ContentType!.ToString());
    }

    [Fact]
    public async Task ADurationBeyondTheAwsCeilingIsClampedRatherThanRejected()
    {
        var (provider, handler) = CreateProvider(HttpStatusCode.OK, AwsSessionResponse,
            settings => settings.DurationSeconds = 43200);
        using var _p = provider;

        await provider.CreateSessionAsync();

        Assert.Contains("\"durationSeconds\":3600", handler.LastBody);
    }

    [Fact]
    public async Task AForbiddenResponseNamesTheLikelyCause()
    {
        // 403 is what both a wrong trust anchor and a role trust policy that omits
        // rolesanywhere.amazonaws.com return, so the message has to list the candidates.
        var (provider, _) = CreateProvider(HttpStatusCode.Forbidden, """{"message":"denied"}""");
        using var _p = provider;

        var ex = await Assert.ThrowsAsync<RolesAnywhereException>(() => provider.CreateSessionAsync());

        Assert.Contains("trust anchor", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("403", ex.Message);
    }

    [Fact]
    public async Task AnEmptyCredentialSetIsAnErrorRatherThanANullReference()
    {
        var (provider, _) = CreateProvider(HttpStatusCode.OK, """{"credentialSet":[],"subjectArn":"x"}""");
        using var _p = provider;

        var ex = await Assert.ThrowsAsync<RolesAnywhereException>(() => provider.CreateSessionAsync());

        Assert.Contains("no credential set", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheCertificateDescriptionCarriesNoKeyMaterial()
    {
        var (provider, _) = CreateProvider(HttpStatusCode.OK, AwsSessionResponse);
        using var _p = provider;

        var info = provider.DescribeCertificate();

        Assert.Equal("CN=unified-gateway-test", info.Subject);
        Assert.NotEmpty(info.Thumbprint);
        Assert.True(info.NotAfter > DateTimeOffset.UtcNow);
    }
    // --- Startup guards ---------------------------------------------------------------

    private sealed class FakeEnvironment : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "UnifiedGatewayV2";
        public string ContentRootPath { get; set; } = ".";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    private static GatewayOptions ValidGateway()
    {
        var gateway = new GatewayOptions();
        gateway.Security.AdminApiKey = string.Empty;
        gateway.Security.AllowedCorsOrigins = ["https://gateway.enterprise.internal"];
        gateway.Security.RequireHttps = true;
        gateway.Aws.CredentialSource = AwsCredentialSource.RolesAnywhere;
        gateway.Aws.RolesAnywhere.TrustAnchorArn = "arn:aws:rolesanywhere:us-east-1:1:trust-anchor/a";
        gateway.Aws.RolesAnywhere.ProfileArn = "arn:aws:rolesanywhere:us-east-1:1:profile/b";
        gateway.Aws.RolesAnywhere.RoleArn = "arn:aws:iam::1:role/GatewayRole";
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";
        return gateway;
    }

    private static void Validate(GatewayOptions gateway, string environment = "Production") =>
        UnifiedGateway.Startup.StartupValidator.Validate(
            gateway,
            new CloudOptions { Provider = CloudProviderMode.Aws },
            new FakeEnvironment { EnvironmentName = environment });

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Test")]
    public void AnythingButRolesAnywhereIsRefusedOutsideDevelopment(string environment)
    {
        // Under IIS there is no instance or task role, so every alternative ends at a
        // long-lived access key stored on the host.
        var gateway = ValidGateway();
        gateway.Aws.CredentialSource = AwsCredentialSource.AssumeRole;
        gateway.Aws.AssumeRoleArn = "arn:aws:iam::1:role/GatewayRole";

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway, environment));

        Assert.Contains("RolesAnywhere", ex.Message);
    }

    [Fact]
    public void DevelopmentIsExemptBecauseItTalksToTheSimulator()
    {
        var gateway = new GatewayOptions();
        gateway.Security.RequireHttps = false;
        gateway.Security.AllowedCorsOrigins = ["http://localhost:3000"];
        gateway.Aws.UseLocalProfile = true;

        UnifiedGateway.Startup.StartupValidator.Validate(
            gateway,
            new CloudOptions
            {
                Provider = CloudProviderMode.LocalDotNet,
                BedrockProvider = CloudProviderMode.Aws
            },
            new FakeEnvironment { EnvironmentName = "Development" });
    }

    [Theory]
    [InlineData("TrustAnchorArn")]
    [InlineData("ProfileArn")]
    [InlineData("RoleArn")]
    public void EachRequiredArnIsChecked(string setting)
    {
        var gateway = ValidGateway();

        switch (setting)
        {
            case "TrustAnchorArn": gateway.Aws.RolesAnywhere.TrustAnchorArn = ""; break;
            case "ProfileArn": gateway.Aws.RolesAnywhere.ProfileArn = ""; break;
            case "RoleArn": gateway.Aws.RolesAnywhere.RoleArn = ""; break;
        }

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains(setting, ex.Message);
    }

    [Fact]
    public void AnUnsubstitutedTemplatePlaceholderIsRefusedAtStartup()
    {
        // The shipped appsettings carry an <account-id> placeholder. Catching it here beats
        // discovering it at the first AWS call, minutes after a deploy reports success.
        var gateway = ValidGateway();
        gateway.Aws.RolesAnywhere.RoleArn = "arn:aws:iam::<account-id>:role/GatewayRole";

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains("placeholder", ex.Message);
    }

    [Fact]
    public void AnUnsubstitutedThumbprintPlaceholderIsRefused()
    {
        // The certificate is installed by a separate step, often by a different person, so
        // substituting the ARNs and forgetting the thumbprint is the likely mistake.
        var gateway = ValidGateway();
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "<client-certificate-thumbprint>";

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains("placeholder", ex.Message);
    }

    [Theory]
    [InlineData(300)]
    [InlineData(43200)]
    public void ADurationOutsideTheAwsRangeIsRefused(int duration)
    {
        var gateway = ValidGateway();
        gateway.Aws.RolesAnywhere.DurationSeconds = duration;

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains("900 to 3600", ex.Message);
    }

    [Fact]
    public void TheSimulatorProtocolIsRefusedOutsideDevelopment()
    {
        // It does not verify AWS4-X509 signatures, so a production host using it would be
        // authenticating against something that checks almost nothing.
        var gateway = ValidGateway();
        gateway.Aws.RolesAnywhere.UseSimulatorProtocol = true;

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains("UseSimulatorProtocol", ex.Message);
    }

    [Fact]
    public void AnEndpointOverrideIsRefusedOutsideDevelopment()
    {
        var gateway = ValidGateway();
        gateway.Aws.RolesAnywhere.EndpointOverride = "http://localhost:5003";

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains("EndpointOverride", ex.Message);
    }

    [Fact]
    public void AMissingThumbprintIsRefusedWhenTheStoreIsTheSource()
    {
        var gateway = ValidGateway();
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "";

        var ex = Assert.Throws<InvalidOperationException>(() => Validate(gateway));

        Assert.Contains("Thumbprint", ex.Message);
    }

    [Fact]
    public void AValidRolesAnywhereProductionConfigurationIsAccepted()
    {
        Validate(ValidGateway());
    }

    // --- Certificate loading ----------------------------------------------------------

    [Fact]
    public void AThumbprintPastedFromTheWindowsDialogIsNormalised()
    {
        // That dialog interleaves spaces and prepends a left-to-right mark, and a verbatim
        // paste then matches nothing, reporting as "certificate not found" -- which looks
        // like a deployment failure rather than a formatting one.
        var options = new CertificateOptions
        {
            Source = CertificateSource.WindowsStore,
            Thumbprint = "‎aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd",
            StoreLocation = "CurrentUser",
            StoreName = "My"
        };

        var ex = Assert.Throws<InvalidOperationException>(() => ClientCertificateLoader.Load(options));

        // Not being found is fine here; what matters is that it searched for the normalised
        // value rather than the pasted one.
        Assert.Contains("AABBCCDDEEFF00112233445566778899AABBCCDD", ex.Message);
    }

    [Fact]
    public void APfxWhoseEnvironmentVariableIsUnsetSaysSo()
    {
        using var certificate = CreateRsaCertificate();
        var pfxPath = Path.Combine(Path.GetTempPath(), $"ra-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(pfxPath, certificate.Export(X509ContentType.Pkcs12, "pw"));

        var options = new CertificateOptions
        {
            Source = CertificateSource.PfxFile,
            PfxPath = pfxPath,
            PfxPasswordEnvironmentVariable = "GATEWAY_RA_PFX_PASSWORD_NOT_SET"
        };

        var ex = Assert.Throws<InvalidOperationException>(() => ClientCertificateLoader.Load(options));

        Assert.Contains("GATEWAY_RA_PFX_PASSWORD_NOT_SET", ex.Message);
        File.Delete(pfxPath);
    }
}
