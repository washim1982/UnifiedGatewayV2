using System.Diagnostics;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Startup;

/// <summary>
/// Runs the local .NET AWS simulator (S3Local, KmsLocal, IamLocal) for the lifetime of a
/// Development run, so starting the gateway starts its whole control plane.
///
/// The ports come from Gateway:Cloud:LocalDotNet, the same settings the gateway's own clients
/// use, so the services it launches cannot drift from the addresses it then calls. A service
/// already answering on its port is reused rather than duplicated, which keeps the standalone
/// launcher (dev/aws-simulator/run-simulator.ps1) working.
///
/// Development only. The simulator accepts a bare role name as proof of identity and grants every
/// role it is asked for; <see cref="StartupValidator"/> refuses the setting elsewhere, this class
/// refuses it again at runtime, and a Release build never compiles the simulator at all.
/// </summary>
public sealed class LocalAwsSimulatorHost : IHostedService, IDisposable
{
#if DEBUG
    private const string BuildConfiguration = "Debug";
#else
    private const string BuildConfiguration = "Release";
#endif

    private sealed record SimulatorService(string Name, int Port, Dictionary<string, string> Settings);

    private readonly GatewayOptions _gateway;
    private readonly CloudOptions _cloud;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<LocalAwsSimulatorHost> _logger;
    private readonly List<Process> _started = [];
    private readonly ChildProcessJob? _job = ChildProcessJob.TryCreate();
    private readonly HttpClient _probe = new() { Timeout = TimeSpan.FromSeconds(2) };

    public LocalAwsSimulatorHost(
        IOptions<GatewayOptions> gateway,
        IOptions<CloudOptions> cloud,
        IHostEnvironment environment,
        ILogger<LocalAwsSimulatorHost> logger)
    {
        _gateway = gateway.Value;
        _cloud = cloud.Value;
        _environment = environment;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var options = _gateway.DevSimulator;
        if (!options.Enabled)
        {
            return;
        }

        if (!_environment.IsDevelopment())
        {
            _logger.LogError(
                "Gateway:DevSimulator:Enabled is true in the '{Environment}' environment. The simulator " +
                "grants every role it is asked for; refusing to start it.", _environment.EnvironmentName);
            return;
        }

        var projectRoot = Rooted(options.ProjectDirectory);
        var dataDirectory = Rooted(options.DataDirectory);
        Directory.CreateDirectory(dataDirectory);

        // Launch first, then wait: three services starting in parallel cost one startup delay
        // rather than three.
        var waiting = new List<SimulatorService>();
        foreach (var service in Services(dataDirectory))
        {
            if (await LaunchAsync(options, projectRoot, service, cancellationToken))
            {
                waiting.Add(service);
            }
        }

        if (waiting.Count == 0)
        {
            return;
        }

        var deadline = TimeSpan.FromSeconds(Math.Max(1, options.StartupTimeoutSeconds));
        await Task.WhenAll(waiting.Select(service => WaitForHealthAsync(service, deadline, cancellationToken)));
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var process in _started)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync(cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not stop simulator process {Pid}.", process.Id);
            }
        }

        _started.Clear();
    }

    public void Dispose()
    {
        _probe.Dispose();
        // Closing the job kills anything still assigned to it, which covers a host that never
        // reached StopAsync.
        _job?.Dispose();

        foreach (var process in _started)
        {
            process.Dispose();
        }
    }

    /// <summary>The three services, with the configuration each one reads from its environment.</summary>
    private List<SimulatorService> Services(string dataDirectory)
    {
        var s3Port = PortOf(_cloud.LocalDotNet.S3Url, 5001);
        var kmsPort = PortOf(_cloud.LocalDotNet.KmsUrl, 5002);
        var iamPort = PortOf(_cloud.LocalDotNet.IamUrl, 5003);

        // Each service also hosts the simulator console, and that page probes all three from the
        // browser. Every service is told the whole set, so the console works whichever one serves
        // it and whatever ports they were given.
        var endpoints = new Dictionary<string, string>
        {
            ["S3Url"] = $"http://localhost:{s3Port}",
            ["KmsUrl"] = $"http://localhost:{kmsPort}",
            ["IamUrl"] = $"http://localhost:{iamPort}"
        };

        return
        [
            new("S3Local", s3Port, new Dictionary<string, string>(endpoints)
            {
                ["DatabasePath"] = Path.Combine(dataDirectory, "s3.db"),
                ["DataRoot"] = Path.Combine(dataDirectory, "buckets")
            }),
            new("KmsLocal", kmsPort, new Dictionary<string, string>(endpoints)
            {
                ["KeysDirectory"] = Path.Combine(dataDirectory, "keys")
            }),
            new("IamLocal", iamPort, new Dictionary<string, string>(endpoints)
            {
                ["DatabasePath"] = Path.Combine(dataDirectory, "iam.db"),
                ["KeysDirectory"] = Path.Combine(dataDirectory, "keys")
            })
        ];
    }

    /// <summary>Starts one service. True when it was started and still has to become healthy.</summary>
    private async Task<bool> LaunchAsync(
        DevSimulatorOptions options, string projectRoot, SimulatorService service, CancellationToken cancellationToken)
    {
        if (await IsHealthyAsync(service, cancellationToken))
        {
            if (options.ReuseRunning)
            {
                _logger.LogInformation(
                    "{Service} is already answering on port {Port}; reusing it.", service.Name, service.Port);
                return false;
            }

            _logger.LogError(
                "Port {Port} is already in use, so {Service} was not started. Stop whatever holds it, or set " +
                "Gateway:DevSimulator:ReuseRunning.", service.Port, service.Name);
            return false;
        }

        var assembly = Path.Combine(
            projectRoot, "src", service.Name, "bin", BuildConfiguration, "net8.0", service.Name + ".dll");

        if (!File.Exists(assembly))
        {
            _logger.LogError(
                "{Service} was not found at {Path}. A Debug build of the gateway builds the simulator; " +
                "otherwise start it yourself with dev/aws-simulator/run-simulator.ps1.", service.Name, assembly);
            return false;
        }

        var startInfo = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(assembly)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add(assembly);
        startInfo.ArgumentList.Add("--urls");
        startInfo.ArgumentList.Add($"http://localhost:{service.Port}");
        startInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";

        // Paths are passed absolute so the simulator's data never lands beside its binaries.
        foreach (var (key, value) in service.Settings)
        {
            startInfo.Environment[key] = value;
        }

        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not start {Service}.", service.Name);
            return false;
        }

        if (process is null)
        {
            _logger.LogError("Could not start {Service}: no process was created.", service.Name);
            return false;
        }

        _started.Add(process);
        _job?.Attach(process);
        PumpOutput(process, service.Name);
        return true;
    }

    private void PumpOutput(Process process, string serviceName)
    {
        process.OutputDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data)) _logger.LogDebug("[{Service}] {Line}", serviceName, e.Data);
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data)) _logger.LogWarning("[{Service}] {Line}", serviceName, e.Data);
        };

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    private async Task WaitForHealthAsync(SimulatorService service, TimeSpan deadline, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;

        while (DateTimeOffset.UtcNow - started < deadline)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (await IsHealthyAsync(service, cancellationToken))
            {
                _logger.LogInformation(
                    "{Service} is listening on http://localhost:{Port}.", service.Name, service.Port);
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
        }

        _logger.LogError(
            "{Service} did not answer /health on port {Port} within {Seconds}s. The gateway will start, but " +
            "its control plane calls will fail until it does.",
            service.Name, service.Port, (int)deadline.TotalSeconds);
    }

    private async Task<bool> IsHealthyAsync(SimulatorService service, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _probe.GetAsync(
                $"http://localhost:{service.Port}/health", cancellationToken);

            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>The port the gateway's own client will call, so the two cannot disagree.</summary>
    public static int PortOf(string? url, int fallback) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Port : fallback;

    private string Rooted(string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(_environment.ContentRootPath, path);
}
