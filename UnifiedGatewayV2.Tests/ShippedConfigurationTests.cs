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

    private static (GatewayOptions Gateway, CloudOptions Cloud) Load(string environmentName)
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

        return (gateway, cloud);
    }

    [Fact]
    public void DevelopmentStartsOnTheShippedConfiguration()
    {
        // The regression this file exists for: Development inherited RolesAnywhere from the
        // base file and refused to start on the placeholder ARNs.
        var (gateway, cloud) = Load("Development");

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment("Development"));
    }

    [Fact]
    public void DevelopmentUsesTheSameCredentialMechanismAsProduction()
    {
        var (gateway, cloud) = Load("Development");

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
        var (dev, _) = Load("Development");
        var (prod, _) = Load("Production");

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
        var (gateway, _) = Load(environmentName);

        Assert.Equal(AwsCredentialSource.RolesAnywhere, gateway.Aws.EffectiveCredentialSource);

        // Bedrock inherits the global provider there, so it uses the same credentials as
        // S3, KMS, Secrets Manager and IAM rather than a path of its own.
        var (_, cloud) = Load(environmentName);
        Assert.Equal(CloudProviderMode.Aws, cloud.EffectiveBedrockProvider);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void TestAndProductionShipAsTemplatesThatRefuseToStartUnsubstituted(string environmentName)
    {
        // Deliberate: the ARNs and the thumbprint are per-account, so the files carry
        // placeholders. Deploying without substituting them must fail at startup rather than
        // at the first AWS call, minutes later.
        var (gateway, cloud) = Load(environmentName);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, cloud, new FakeEnvironment(environmentName)));

        Assert.Contains("placeholder", ex.Message);
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void TestAndProductionAreValidOnceTheTemplateIsSubstituted(string environmentName)
    {
        // The other half of the test above: the placeholders are the only thing wrong with
        // the shipped files, so a deploy that substitutes them has nothing left to fix.
        var (gateway, cloud) = Load(environmentName);

        gateway.Aws.RolesAnywhere.TrustAnchorArn = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/a";
        gateway.Aws.RolesAnywhere.ProfileArn = "arn:aws:rolesanywhere:us-east-1:111122223333:profile/b";
        gateway.Aws.RolesAnywhere.RoleArn = $"arn:aws:iam::111122223333:role/GatewayRole-{environmentName}";
        gateway.Aws.RolesAnywhere.Certificate.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";

        StartupValidator.Validate(gateway, cloud, new FakeEnvironment(environmentName));
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Production")]
    public void NoShippedEnvironmentCarriesACredentialInConfiguration(string environmentName)
    {
        var (gateway, _) = Load(environmentName);

        // The point of Roles Anywhere: identity is a certificate the OS holds, so there is
        // nothing secret left in the file.
        Assert.Empty(gateway.Security.AdminApiKey);
        Assert.False(gateway.Aws.UseLocalProfile);
        Assert.Empty(gateway.Aws.RolesAnywhere.Certificate.PfxPath);
    }
}
