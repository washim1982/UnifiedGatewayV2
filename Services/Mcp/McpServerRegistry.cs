using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Mcp;

public interface IMcpServerRegistry
{
    Task<List<McpServerRegistration>> ListAsync(CancellationToken cancellationToken = default);
    Task<McpServerRegistration?> GetAsync(string serverId, CancellationToken cancellationToken = default);
    Task<McpServerRegistration> CreateAsync(CreateMcpServerRequest request, CancellationToken cancellationToken = default);
    Task<McpServerRegistration?> UpdateAsync(string serverId, UpdateMcpServerRequest request, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(string serverId, CancellationToken cancellationToken = default);
}

/// <summary>
/// The catalogue of MCP servers, stored as JSON beside the application registry.
///
/// Registering a server is the privileged half of the tool story: its tools execute somewhere the
/// gateway does not control, with whatever rights that server holds, and the gateway calls them on
/// an application's behalf. Everything that can be checked before that happens is checked here --
/// transport, destination, and credential-by-reference -- because afterwards the only control left
/// is the per-application binding.
/// </summary>
public partial class McpServerRegistry : IMcpServerRegistry
{
    private readonly ConcurrentDictionary<string, McpServerRegistration> _servers = new(StringComparer.OrdinalIgnoreCase);
    private readonly GatewayOptions _options;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<McpServerRegistry> _logger;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly string _filePath;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public McpServerRegistry(
        IOptions<GatewayOptions> options,
        IHostEnvironment environment,
        ILogger<McpServerRegistry> logger)
    {
        _options = options.Value;
        _environment = environment;
        _logger = logger;

        var dataDir = Path.GetFullPath(_options.Storage.DataDirectory);
        Directory.CreateDirectory(dataDir);
        _filePath = Path.Combine(dataDir, "mcp-servers.json");

        Load();
    }

    public Task<List<McpServerRegistration>> ListAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_servers.Values.OrderBy(s => s.ServerId, StringComparer.OrdinalIgnoreCase).ToList());

    public Task<McpServerRegistration?> GetAsync(string serverId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_servers.TryGetValue(serverId, out var server) ? server : null);

    public async Task<McpServerRegistration> CreateAsync(
        CreateMcpServerRequest request, CancellationToken cancellationToken = default)
    {
        var serverId = request.ServerId.Trim().ToLowerInvariant();
        if (!ServerIdRegex().IsMatch(serverId))
        {
            throw new McpServerRejectedException(
                "serverId must be 2-32 characters of lowercase letters, digits and underscores. " +
                "It becomes the namespace of every tool the server publishes.");
        }

        if (_servers.ContainsKey(serverId))
        {
            throw new McpServerRejectedException($"An MCP server with id '{serverId}' already exists.");
        }

        ValidateTransport(request.Transport, request.Url);

        var server = new McpServerRegistration
        {
            ServerId = serverId,
            Name = string.IsNullOrWhiteSpace(request.Name) ? serverId : request.Name.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Transport = request.Transport,
            Url = request.Url.Trim(),
            ApiKeySecretName = request.ApiKeySecretName?.Trim() ?? string.Empty,
            DefaultSideEffect = request.DefaultSideEffect,
            TimeoutSeconds = Math.Clamp(request.TimeoutSeconds ?? 30, 1, 300)
        };

        _servers[serverId] = server;
        await PersistAsync();

        _logger.LogWarning(
            "MCP server '{ServerId}' registered at {Url}. Its tools execute outside this gateway.",
            serverId, server.Url);

        return server;
    }

    public async Task<McpServerRegistration?> UpdateAsync(
        string serverId, UpdateMcpServerRequest request, CancellationToken cancellationToken = default)
    {
        if (!_servers.TryGetValue(serverId, out var existing))
        {
            return null;
        }

        var url = request.Url?.Trim() ?? existing.Url;
        if (url != existing.Url)
        {
            ValidateTransport(existing.Transport, url);
        }

        var updated = existing with
        {
            Name = request.Name?.Trim() ?? existing.Name,
            Description = request.Description?.Trim() ?? existing.Description,
            Url = url,
            ApiKeySecretName = request.ApiKeySecretName?.Trim() ?? existing.ApiKeySecretName,
            DefaultSideEffect = request.DefaultSideEffect ?? existing.DefaultSideEffect,
            TimeoutSeconds = Math.Clamp(request.TimeoutSeconds ?? existing.TimeoutSeconds, 1, 300),
            IsActive = request.IsActive ?? existing.IsActive,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _servers[serverId] = updated;
        await PersistAsync();
        return updated;
    }

    public async Task<bool> DeleteAsync(string serverId, CancellationToken cancellationToken = default)
    {
        if (!_servers.TryRemove(serverId, out _))
        {
            return false;
        }

        await PersistAsync();
        _logger.LogWarning("MCP server '{ServerId}' deleted. Bindings to its tools stop resolving.", serverId);
        return true;
    }

    /// <summary>
    /// Where the gateway is willing to send an application's data, and over what.
    ///
    /// Development may point at a plain-HTTP server on this machine, because that is where MCP
    /// servers are developed. Everywhere else the destination must be HTTPS, must not be a
    /// link-local or metadata address, and must match the operator's host allowlist if one is set.
    /// </summary>
    public void ValidateTransport(McpTransport transport, string url)
    {
        if (transport == McpTransport.Stdio)
        {
            throw new McpServerRejectedException(
                "stdio MCP servers are not supported yet: they would run as child processes under the " +
                "gateway's own identity. Register an HTTP server, or front the stdio server with one.");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new McpServerRejectedException($"url must be an absolute HTTP or HTTPS URL ('{url}').");
        }

        if (IsBlockedDestination(uri))
        {
            throw new McpServerRejectedException(
                $"'{uri.Host}' is a link-local or metadata address. The gateway will not call it.");
        }

        var isDevelopment = _environment.IsDevelopment();

        if (uri.Scheme != Uri.UriSchemeHttps && !(isDevelopment && uri.IsLoopback))
        {
            throw new McpServerRejectedException(
                $"'{url}' is plain HTTP. Prompts and tool arguments would cross the network in clear; " +
                "use https:// (Development may use http on this machine).");
        }

        var allowed = _options.Mcp.AllowedHosts;
        if (allowed.Length > 0 && !allowed.Any(pattern => HostMatches(pattern, uri.Host)))
        {
            throw new McpServerRejectedException(
                $"'{uri.Host}' is not in Gateway:Mcp:AllowedHosts. An operator decides which hosts the " +
                "gateway may call on an application's behalf.");
        }
    }

    /// <summary>Link-local, including the cloud metadata address every SSRF aims at.</summary>
    private static bool IsBlockedDestination(Uri uri)
    {
        if (!IPAddress.TryParse(uri.Host, out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? bytes[0] == 169 && bytes[1] == 254
            : address.IsIPv6LinkLocal;
    }

    private static bool HostMatches(string pattern, string host)
    {
        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
    }

    private void Load()
    {
        if (!File.Exists(_filePath))
        {
            return;
        }

        try
        {
            var servers = JsonSerializer.Deserialize<List<McpServerRegistration>>(
                File.ReadAllText(_filePath), JsonOpts) ?? [];

            foreach (var server in servers)
            {
                _servers[server.ServerId] = server;
            }

            _logger.LogInformation("Loaded {Count} MCP servers from {Path}.", _servers.Count, _filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not read the MCP server catalogue at {Path}; starting empty.", _filePath);
        }
    }

    private async Task PersistAsync()
    {
        await _fileLock.WaitAsync();
        try
        {
            var json = JsonSerializer.Serialize(_servers.Values.ToList(), JsonOpts);
            var tempPath = _filePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json);

            if (File.Exists(_filePath))
            {
                File.Replace(tempPath, _filePath, _filePath + ".bak", ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _filePath);
            }
        }
        finally
        {
            _fileLock.Release();
        }
    }

    [GeneratedRegex("^[a-z][a-z0-9_]{1,31}$")]
    private static partial Regex ServerIdRegex();
}
