using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Services.Mcp;

public interface IMcpClient
{
    /// <summary>The tools a server publishes right now.</summary>
    Task<List<ToolDescriptor>> ListToolsAsync(McpServerRegistration server, CancellationToken cancellationToken = default);

    /// <summary>Calls one tool and returns its text content.</summary>
    Task<(string Output, bool IsError, long LatencyMs)> CallToolAsync(
        McpServerRegistration server, string remoteName, JsonElement arguments, CancellationToken cancellationToken = default);
}

/// <summary>
/// A minimal MCP client over Streamable HTTP: JSON-RPC 2.0, with the initialize handshake each
/// exchange so the gateway holds no session state between requests.
///
/// Everything a server returns is untrusted: tool names, descriptions and results are data that
/// reach a model and a caller, never instructions to this gateway. Responses are read under a byte
/// cap and a timeout, and the credential is fetched by reference from the secret store.
/// </summary>
public class McpClient(
    IHttpClientFactory httpClientFactory,
    ISecretsProvider secrets,
    IOptions<GatewayOptions> options,
    ILogger<McpClient> logger) : IMcpClient
{
    public const string HttpClientName = "McpClient";
    private const string ProtocolVersion = "2025-06-18";

    private readonly McpOptions _mcp = options.Value.Mcp;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<List<ToolDescriptor>> ListToolsAsync(
        McpServerRegistration server, CancellationToken cancellationToken = default)
    {
        using var session = await OpenAsync(server, cancellationToken);
        var result = await session.CallAsync("tools/list", new { }, cancellationToken);

        var tools = new List<ToolDescriptor>();
        if (!result.TryGetProperty("tools", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return tools;
        }

        foreach (var tool in list.EnumerateArray())
        {
            var remoteName = tool.TryGetProperty("name", out var n) ? n.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(remoteName))
            {
                continue;
            }

            tools.Add(new ToolDescriptor
            {
                Name = $"{server.ServerId}.{remoteName}",
                ServerId = server.ServerId,
                RemoteName = remoteName,
                Description = tool.TryGetProperty("description", out var d) ? d.GetString() ?? string.Empty : string.Empty,
                SideEffect = SideEffectOf(tool, server.DefaultSideEffect),
                InputSchema = tool.TryGetProperty("inputSchema", out var schema) ? schema.GetRawText() : "{}"
            });
        }

        return tools;
    }

    public async Task<(string Output, bool IsError, long LatencyMs)> CallToolAsync(
        McpServerRegistration server, string remoteName, JsonElement arguments, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        using var session = await OpenAsync(server, cancellationToken);
        var result = await session.CallAsync(
            "tools/call", new { name = remoteName, arguments }, cancellationToken);

        stopwatch.Stop();

        var isError = result.TryGetProperty("isError", out var flag) && flag.ValueKind == JsonValueKind.True;
        return (TextOf(result), isError, stopwatch.ElapsedMilliseconds);
    }

    /// <summary>
    /// A server's own hint, when it gives one. MCP's readOnlyHint is advisory, so it can only
    /// narrow the operator's declared default, never widen it.
    /// </summary>
    private static ToolSideEffect SideEffectOf(JsonElement tool, ToolSideEffect serverDefault)
    {
        if (tool.TryGetProperty("annotations", out var annotations) &&
            annotations.TryGetProperty("readOnlyHint", out var readOnly) &&
            readOnly.ValueKind == JsonValueKind.True)
        {
            return ToolSideEffect.Read;
        }

        return serverDefault;
    }

    /// <summary>Concatenates the text blocks of a tool result; other content types are named, not inlined.</summary>
    private static string TextOf(JsonElement result)
    {
        if (!result.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array)
        {
            return result.GetRawText();
        }

        var parts = new List<string>();
        foreach (var block in content.EnumerateArray())
        {
            var type = block.TryGetProperty("type", out var t) ? t.GetString() : null;

            if (type == "text" && block.TryGetProperty("text", out var text))
            {
                parts.Add(text.GetString() ?? string.Empty);
            }
            else if (type is not null)
            {
                parts.Add($"[{type} content omitted]");
            }
        }

        return string.Join("\n", parts);
    }

    private async Task<Session> OpenAsync(McpServerRegistration server, CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient(HttpClientName);
        client.Timeout = TimeSpan.FromSeconds(Math.Clamp(server.TimeoutSeconds, 1, 300));

        string? credential = null;
        if (!string.IsNullOrWhiteSpace(server.ApiKeySecretName))
        {
            credential = await secrets.GetSecretAsync(server.ApiKeySecretName, cancellationToken);
            if (string.IsNullOrWhiteSpace(credential))
            {
                throw new ToolRefusedException(
                    $"The credential secret '{server.ApiKeySecretName}' for MCP server '{server.ServerId}' is " +
                    "missing. The server is not called without it.");
            }
        }

        var session = new Session(client, server, credential, _mcp.MaxOutputBytes, logger);
        await session.InitializeAsync(cancellationToken);
        return session;
    }

    /// <summary>One JSON-RPC exchange with a server: initialize, then the operation.</summary>
    private sealed class Session(
        HttpClient client,
        McpServerRegistration server,
        string? credential,
        int maxOutputBytes,
        ILogger logger) : IDisposable
    {
        private int _id;
        private string? _sessionId;

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            await CallAsync("initialize", new
            {
                protocolVersion = ProtocolVersion,
                capabilities = new { },
                clientInfo = new { name = "unified-gateway", version = "1.0" }
            }, cancellationToken);

            // Notification: no id, no response expected.
            await SendAsync(new { jsonrpc = "2.0", method = "notifications/initialized" }, cancellationToken);
        }

        public async Task<JsonElement> CallAsync(string method, object parameters, CancellationToken cancellationToken)
        {
            var body = new { jsonrpc = "2.0", id = ++_id, method, @params = parameters };
            var payload = await SendAsync(body, cancellationToken)
                ?? throw new ToolRefusedException($"MCP server '{server.ServerId}' returned no response to {method}.");

            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;

            if (root.TryGetProperty("error", out var error))
            {
                var message = error.TryGetProperty("message", out var m) ? m.GetString() : "unknown error";
                throw new ToolRefusedException($"MCP server '{server.ServerId}' refused {method}: {message}");
            }

            return root.TryGetProperty("result", out var result)
                ? result.Clone()
                : throw new ToolRefusedException($"MCP server '{server.ServerId}' returned no result for {method}.");
        }

        private async Task<string?> SendAsync(object body, CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, server.Url)
            {
                Content = new StringContent(JsonSerializer.Serialize(body, JsonOpts), Encoding.UTF8, "application/json")
            };

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

            if (credential is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential.Trim());
            }

            if (_sessionId is not null)
            {
                request.Headers.TryAddWithoutValidation("Mcp-Session-Id", _sessionId);
            }

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            if (response.Headers.TryGetValues("Mcp-Session-Id", out var ids))
            {
                _sessionId = ids.FirstOrDefault();
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new ToolRefusedException(
                    $"MCP server '{server.ServerId}' answered HTTP {(int)response.StatusCode}.");
            }

            // 202 for a notification, and no body to read.
            if (response.Content.Headers.ContentLength == 0)
            {
                return null;
            }

            var text = await ReadCappedAsync(response, cancellationToken);
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            // Streamable HTTP may answer as SSE; the JSON-RPC message is the data of one event.
            var mediaType = response.Content.Headers.ContentType?.MediaType;
            return mediaType == "text/event-stream" ? FirstDataEvent(text) : text;
        }

        /// <summary>
        /// Reads at most the configured cap. A server that answers with more is refused rather
        /// than silently truncated: half a tool result is not a tool result.
        /// </summary>
        private async Task<string> ReadCappedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var buffer = new byte[8192];
            var builder = new MemoryStream();

            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                if (builder.Length + read > maxOutputBytes)
                {
                    throw new ToolRefusedException(
                        $"MCP server '{server.ServerId}' returned more than the {maxOutputBytes} byte limit.");
                }

                builder.Write(buffer, 0, read);
            }

            return Encoding.UTF8.GetString(builder.ToArray());
        }

        private static string? FirstDataEvent(string text)
        {
            foreach (var line in text.Split('\n'))
            {
                if (line.StartsWith("data:", StringComparison.Ordinal))
                {
                    return line[5..].Trim();
                }
            }

            return null;
        }

        public void Dispose()
        {
            if (_sessionId is not null)
            {
                logger.LogDebug("Closing MCP session {SessionId} with {ServerId}.", _sessionId, server.ServerId);
            }
        }
    }
}
