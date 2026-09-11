using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using UnifiedGateway.Models;
using UnifiedGateway.Startup;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// Validates the appsettings files that actually ship, rather than options objects built in a
/// test.
///
/// These exist because of a real regression: adding <c>CredentialSource: "RolesAnywhere"</c> to
/// the base appsettings.json silently applied it to Development too, which has no client
/// certificate, and Development stopped starting. Every unit test still passed, because none
/// of them read the files. Layering is the thing being checked here.
/// </summary>
public class ShippedConfigurationTests
{
    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "UnifiedGatewayV2";
        public string ContentRootPath { get; set; } = ".";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    private sealed record Shipped(GatewayOptions Gateway, CloudOptions Cloud, OktaOptions Okta);

    /// <summary>Walks up from the test binaries to the project root that holds appsettings.json.</summary>
    private static string ProjectRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "appsettings.json")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }

    private static Shipped Load(string environmentName)
    {
        var root = ProjectRoot();

        // The same layering the host performs: base file, then the environment overlay.
        var configuration = new ConfigurationBuilder()
            .SetBasePath(root)
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{environmentName}.json", optional: true)
            .Build();

        var gateway = configuration.GetSection(GatewayOptions.SectionName).Get<GatewayOptions>()
            ?? new GatewayOptions();
        var cloud = configuration.GetSection(CloudOptions.SectionName).Get<CloudOptions>()
            ?? new CloudOptions();
        var okta = configuration.GetSection(OktaOptions.SectionName).Get<OktaOptions>()
            ?? new OktaOptions();

        return new Shipped(gateway, cloud, okta);
    }

    private static void Validate(Shipped shipped, string environmentName) =>
        StartupValidator.Validate(shipped.Gateway, shipped.Cloud, new FakeEnvironment(environmentName), shipped.Okta);

    [Fact]
    public void DevelopmentStartsOnTheShippedConfiguration()
    {
        // The regression this file exists for: Development inherited RolesAnywhere from the
        // base file and refused to start on the placeholder ARNs.
        Validate(Load("Development"), "Development");
    }

    [Fact]
    public void DevelopmentUsesTheSameCredentialMechanismAsProduction()
    {
        var (gateway, cloud, _) = Load("Development");

        // The .NET simulator implements the real AWS4-X509 CreateSession contract, so
        // Development exercises the production credential path rather than a second one.
        Assert.Equal(AwsCredentialSource.RolesAnywhere, gateway.Aws.EffectiveCredentialSource);
        Assert.Equal(CloudProviderMode.LocalDotNet, cloud.Provider);

        // Bedrock alone leaves the simulator.
        Assert.Equal(CloudProviderMode.Aws, cloud.EffectiveBedrockProvider);
    }

    [Fact]
    public void TheEndpointIsTheOnlyThingDevelopmentChangesAboutRolesAnywhere()
    {
        // If anything else diverges, a passing dev run stops being evidence about production.
        var dev = Load("Development").Gateway;
        var prod = Load("Production").Gateway;

        Assert.NotEmpty(dev.Aws.RolesAnywhere.EndpointOverride);
        Assert.Empty(prod.Aws.RolesAnywhere.EndpointOverride);

        Assert.Equal(prod.Aws.CredentialSource, dev.Aws.CredentialSource);
        Assert.Equal(prod.Aws.RolesAnywhere.DurationSeconds, dev.Aws.RolesAnywhere.DurationSeconds);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void TestAndProductionUseRolesAnywhereForEveryAwsService(string environmentName)
    {
        var (gateway, cloud, _) = Load(environmentName);

        Assert.Equal(AwsCredentialSource.RolesAnywhere, gateway.Aws.EffectiveCredentialSource);

        // Bedrock inherits the global provider there, so it uses the same credentials as
        // S3, KMS, Secrets Manager and IAM rather than a path of its own.
        Assert.Equal(CloudProviderMode.Aws, cloud.EffectiveBedrockProvider);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void TestAndProductionShipAsTemplatesThatRefuseToStartUnsubstituted(string environmentName)
    {
        // Deliberate: the ARNs, the thumbprint and the Okta tenant are per-deployment, so the
        // files carry placeholders. Deploying without substituting them must fail at startup
        // rather than at the first AWS call or the first sign-in, minutes later.
        var ex = Assert.Throws<InvalidOperationException>(() => Validate(Load(environmentName), environmentName));

        Assert.Contains("placeholder", ex.Message);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void TestAndProductionAreValidOnceTheTemplateIsSubstituted(string environmentName)
    {
        // The other half of the test above: the placeholders are the only thing wrong with
        // the shipped files, so a deploy that substitutes them has nothing left to fix.
        var (gateway, cloud, okta) = Load(environmentName);

        gateway.Aws.RolesAnywhere.TrustAnchorArn = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/a";
        gateway.Aws.RolesAnywhere.ProfileArn = "arn:aws:rolesanywhere:us-east-1:111122223333:profile/b";
        gateway.Aws.RolesAnywhere.RoleArn = $"arn:aws:iam::111122223333:role/GatewayRole-{environmentName}";
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";

        cloud.AccessControl.BreakGlassPrincipalArn = "arn:aws:iam::111122223333:role/GatewayBreakGlassRole";

        okta.Issuer = "https://example.okta.com/oauth2/default";
        okta.MetadataAddress = "https://example.okta.com/oauth2/default/.well-known/openid-configuration";
        foreach (var group in okta.GroupRoleMappings.Keys.ToList())
        {
            okta.GroupRoleMappings[group] = $"arn:aws:iam::111122223333:role/{group}";
        }

        Validate(new Shipped(gateway, cloud, okta), environmentName);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void NoShippedEnvironmentCarriesACredentialInConfiguration(string environmentName)
    {
        var gateway = Load(environmentName).Gateway;

        // The point of Roles Anywhere: identity is a certificate the OS holds, so there is
        // nothing secret left in the file.
        Assert.Empty(gateway.Security.AdminApiKey);
        Assert.False(gateway.Aws.UseLocalProfile);
        Assert.Empty(gateway.Aws.RolesAnywhere.Certificate.PfxPath);
    }

    // --- SL-02: the simulator cannot be inherited ------------------------------------------

    [Theory]
    [InlineData("Test")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public void OnlyDevelopmentRunsTheOktaSimulator(string environmentName)
    {
        // Staging has no file of its own, so it sees the base file alone -- the case where a
        // forgotten override used to leave the simulator, and its hard-coded admin, switched on.
        Assert.False(Load(environmentName).Okta.Enabled);
    }

    [Fact]
    public void DevelopmentRunsTheOktaSimulator()
    {
        Assert.True(Load("Development").Okta.Enabled);
    }

    [Fact]
    public void AnEnvironmentWithoutItsOwnFileRefusesToStart()
    {
        // The base file is a template, and an environment nobody configured must not boot on it.
        var ex = Assert.Throws<InvalidOperationException>(() => Validate(Load("Staging"), "Staging"));

        Assert.Contains("placeholder", ex.Message);
    }

    // --- SL-03 / SL-04 ---------------------------------------------------------------------

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void EveryNetworkedEnvironmentRequiresHttpsAndAuthentication(string environmentName)
    {
        var gateway = Load(environmentName).Gateway;

        Assert.True(gateway.Security.RequireHttps);
        Assert.True(gateway.Security.EnforceAppApiKey);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void ShippedTemplatesNameABreakGlassPrincipal(string environmentName)
    {
        Assert.NotEmpty(Load(environmentName).Cloud.AccessControl.BreakGlassPrincipalArn);
    }
}
