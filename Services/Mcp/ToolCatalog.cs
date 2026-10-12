using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Mcp;

public interface IToolCatalog
{
    /// <summary>Tools published by one server, from cache unless a refresh is asked for.</summary>
    Task<List<ToolDescriptor>> ListAsync(string serverId, bool refresh = false, CancellationToken cancellationToken = default);

    /// <summary>Every tool every active server publishes.</summary>
    Task<List<ToolDescriptor>> ListAllAsync(CancellationToken cancellationToken = default);

    /// <summary>One tool by its namespaced name, or null.</summary>
    Task<ToolDescriptor?> FindAsync(string toolName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs a tool on behalf of an application, after checking that the application may call it
    /// and that the result is fit to return.
    /// </summary>
    Task<ToolCallResult> ExecuteAsync(
        AppConfig app, string toolName, JsonElement arguments, CancellationToken cancellationToken = default);
}

/// <summary>
/// The tool plane: what exists, what an application may call, and what comes back.
///
/// Three checks stand between an application and a tool, and they are deliberately separate. The
/// catalogue says the tool exists and what it does to the world. The binding says this application
/// was given it, and how far it may go. The guardrails say the result is fit to return -- a tool
/// result is content from somewhere else, as untrusted as anything a model produces.
/// </summary>
public class ToolCatalog(
    IMcpServerRegistry registry,
    IMcpClient client,
    IGuardrailService guardrails,
    IOptions<GatewayOptions> options,
    ILogger<ToolCatalog> logger) : IToolCatalog
{
    private readonly ConcurrentDictionary<string, (List<ToolDescriptor> Tools, DateTimeOffset FetchedAt)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly McpOptions _mcp = options.Value.Mcp;

    public async Task<List<ToolDescriptor>> ListAsync(
        string serverId, bool refresh = false, CancellationToken cancellationToken = default)
    {
        var server = await registry.GetAsync(serverId, cancellationToken);
        if (server is null || !server.IsActive)
        {
            return [];
        }

        var ttl = TimeSpan.FromSeconds(Math.Max(0, _mcp.ToolCacheSeconds));
        if (!refresh && _cache.TryGetValue(serverId, out var cached) && DateTimeOffset.UtcNow - cached.FetchedAt < ttl)
        {
            return cached.Tools;
        }

        var tools = await client.ListToolsAsync(server, cancellationToken);
        _cache[serverId] = (tools, DateTimeOffset.UtcNow);
        return tools;
    }

    public async Task<List<ToolDescriptor>> ListAllAsync(CancellationToken cancellationToken = default)
    {
        var all = new List<ToolDescriptor>();

        foreach (var server in (await registry.ListAsync(cancellationToken)).Where(s => s.IsActive))
        {
            try
            {
                all.AddRange(await ListAsync(server.ServerId, refresh: false, cancellationToken));
            }
            catch (Exception ex)
            {
                // One unreachable server must not hide the rest of the catalogue.
                logger.LogWarning(ex, "Could not list tools from MCP server '{ServerId}'.", server.ServerId);
            }
        }

        return all;
    }

    public async Task<ToolDescriptor?> FindAsync(string toolName, CancellationToken cancellationToken = default)
    {
        var serverId = ServerIdOf(toolName);
        if (serverId is null)
        {
            return null;
        }

        var tools = await ListAsync(serverId, refresh: false, cancellationToken);
        return tools.FirstOrDefault(t => t.Name.Equals(toolName, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<ToolCallResult> ExecuteAsync(
        AppConfig app, string toolName, JsonElement arguments, CancellationToken cancellationToken = default)
    {
        var serverId = ServerIdOf(toolName)
            ?? throw new ToolRefusedException($"'{toolName}' is not a tool name. Tools are named server.tool.");

        var binding = BindingFor(app, serverId, toolName)
            ?? throw new ToolRefusedException(
                $"Tool '{toolName}' is not attached to application '{app.AppId}'. Attach it first; asking cannot grant.");

        var server = await registry.GetAsync(serverId, cancellationToken)
            ?? throw new ToolRefusedException($"MCP server '{serverId}' is no longer registered.");

        if (!server.IsActive)
        {
            throw new ToolRefusedException($"MCP server '{serverId}' is disabled.");
        }

        var tool = await FindAsync(toolName, cancellationToken)
            ?? throw new ToolRefusedException($"MCP server '{serverId}' no longer publishes '{toolName}'.");

        var ceiling = binding.MaxSideEffect;
        if (tool.SideEffect > ceiling)
        {
            throw new ToolRefusedException(
                $"Tool '{toolName}' is {tool.SideEffect}, and application '{app.AppId}' is attached for " +
                $"{ceiling} only. Re-attach it deliberately if that is intended.");
        }

        var payload = arguments.ValueKind == JsonValueKind.Undefined ? "{}" : arguments.GetRawText();
        if (payload.Length > _mcp.MaxArgumentBytes)
        {
            throw new ToolRefusedException(
                $"Tool arguments are {payload.Length} bytes; the limit is {_mcp.MaxArgumentBytes}.");
        }

        var (output, isError, latencyMs) = await client.CallToolAsync(
            server, tool.RemoteName, arguments, cancellationToken);

        // A tool result is content from somewhere the gateway does not control, on its way to a
        // model and a caller. It goes through the egress guardrails like any other content.
        var scan = await guardrails.EvaluateOutputAsync(output, cancellationToken: cancellationToken);

        if (scan.IsBlocked)
        {
            logger.LogWarning(
                "Tool '{Tool}' result for application '{AppId}' was blocked by the guardrails: {Findings}.",
                toolName, app.AppId, string.Join("; ", scan.Violations.Select(v => v.RuleName)));

            return new ToolCallResult
            {
                Tool = toolName,
                Output = string.Empty,
                IsError = true,
                SideEffect = tool.SideEffect,
                LatencyMs = latencyMs,
                GuardrailAction = "Blocked"
            };
        }

        return new ToolCallResult
        {
            Tool = toolName,
            Output = scan.ActionTaken == "Redacted" ? scan.SanitizedInput : output,
            IsError = isError,
            SideEffect = tool.SideEffect,
            LatencyMs = latencyMs,
            GuardrailAction = scan.ActionTaken
        };
    }

    /// <summary>
    /// The binding that permits this call: the tool itself, or the whole server. A server binding
    /// is the coarse grant -- useful for a first-party server, careless for a third-party one.
    /// </summary>
    private static CapabilityBinding? BindingFor(AppConfig app, string serverId, string toolName) =>
        app.Capabilities.FirstOrDefault(b =>
            b.Enabled && b.Kind == CapabilityKind.Tool && b.Ref.Equals(toolName, StringComparison.OrdinalIgnoreCase))
        ?? app.Capabilities.FirstOrDefault(b =>
            b.Enabled && b.Kind == CapabilityKind.McpServer && b.Ref.Equals(serverId, StringComparison.OrdinalIgnoreCase));

    private static string? ServerIdOf(string toolName)
    {
        var separator = toolName.IndexOf('.');
        return separator <= 0 || separator == toolName.Length - 1 ? null : toolName[..separator];
    }
}
