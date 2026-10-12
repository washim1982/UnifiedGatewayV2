using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using UnifiedGateway.Models;
using UnifiedGateway.Startup;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// The bundled local AWS simulator (dev/aws-simulator), which Development starts with the
/// gateway. Two things have to hold: no other environment may start it, and the ports it is
/// started on must be the ports the gateway then calls. A mismatch there is silent -- the
/// gateway reaches a service of the wrong kind, policy evaluation fails closed, and every
/// management call answers 403.
/// </summary>
public class DevSimulatorTests
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

    /// <summary>
    /// The repository root, found by the project file rather than by appsettings.json: the test
    /// output directory carries a copy of the configuration, so <see cref="ProjectRoot"/> can
    /// resolve there.
    /// </summary>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "UnifiedGatewayV2.csproj")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }

    private static (GatewayOptions Gateway, CloudOptions Cloud) Load(string environmentName)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(ProjectRoot())
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{environmentName}.json", optional: true)
            .Build();

        return (configuration.GetSection(GatewayOptions.SectionName).Get<GatewayOptions>() ?? new GatewayOptions(),
                configuration.GetSection(CloudOptions.SectionName).Get<CloudOptions>() ?? new CloudOptions());
    }

    [Fact]
    public void DevelopmentShipsWithTheSimulatorEnabled()
    {
        var (gateway, _) = Load("Development");

        Assert.True(gateway.DevSimulator.Enabled);
        Assert.Equal("dev/aws-simulator", gateway.DevSimulator.ProjectDirectory);
        // The simulator sources travel with this repository, so a clone can start the whole
        // development environment without fetching a second project.
        var sources = Path.Combine(RepositoryRoot(), gateway.DevSimulator.ProjectDirectory, "src");
        Assert.True(Directory.Exists(sources), $"simulator sources not found at {sources}");
        Assert.All(
            new[] { "S3Local", "KmsLocal", "IamLocal" },
            service => Assert.True(File.Exists(Path.Combine(sources, service, $"{service}.csproj"))));
    }

    [Theory]
    [InlineData("Test")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public void NoOtherEnvironmentEnablesTheSimulator(string environmentName)
    {
        Assert.False(Load(environmentName).Gateway.DevSimulator.Enabled);
    }

    [Fact]
    public void TheSimulatorIsStartedOnThePortsTheGatewayCalls()
    {
        var (_, cloud) = Load("Development");

        // The host derives each port from these same settings, so they cannot drift; this asserts
        // the shipped values are the distinct 5101-5103 range rather than the Docker stack's
        // 5001-5003, which serves a different service on each of those ports.
        Assert.Equal(5101, LocalAwsSimulatorHost.PortOf(cloud.LocalDotNet.S3Url, 0));
        Assert.Equal(5102, LocalAwsSimulatorHost.PortOf(cloud.LocalDotNet.KmsUrl, 0));
        Assert.Equal(5103, LocalAwsSimulatorHost.PortOf(cloud.LocalDotNet.IamUrl, 0));
    }

    [Fact]
    public void RolesAnywhereDevelopmentCredentialsPointAtIamLocal()
    {
        var (gateway, cloud) = Load("Development");

        // Development exchanges its client certificate at IamLocal's Roles Anywhere endpoint. If
        // the override and IamUrl disagree, credentials fail while policy evaluation still works.
        Assert.Equal(
            LocalAwsSimulatorHost.PortOf(cloud.LocalDotNet.IamUrl, 0),
            LocalAwsSimulatorHost.PortOf(gateway.Aws.RolesAnywhere.EndpointOverride, -1));
    }

    [Fact]
    public void StartupRefusesTheSimulatorOutsideDevelopment()
    {
        var gateway = new GatewayOptions();
        gateway.DevSimulator.Enabled = true;

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StartupValidator.Validate(gateway, new CloudOptions(), new FakeEnvironment("Production")));

        Assert.Contains("DevSimulator", ex.Message);
    }

    [Fact]
    public void TheDisabledDefaultIsNotReportedAtStartup()
    {
        var ex = Record.Exception(() =>
            StartupValidator.Validate(new GatewayOptions(), new CloudOptions(), new FakeEnvironment("Production")));

        // Production fails for other reasons; the simulator must not be one of them.
        Assert.DoesNotContain("DevSimulator", ex?.Message ?? string.Empty);
    }

    [Theory]
    [InlineData("http://localhost:5101", 5101)]
    [InlineData("http://127.0.0.1:5103/", 5103)]
    [InlineData("", 42)]
    [InlineData("not-a-url", 42)]
    [InlineData(null, 42)]
    public void APortIsReadFromTheConfiguredUrlOrFallsBack(string? url, int expected)
    {
        Assert.Equal(expected, LocalAwsSimulatorHost.PortOf(url, 42));
    }
}
