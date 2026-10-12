using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// What a tool does to the world. A read can be retried and logged without consequence; a write
/// changes something; an external call leaves the organisation. A binding carries a ceiling, so an
/// application attached for reads cannot call a tool the server later reclassifies.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ToolSideEffect
{
    Read,
    Write,
    External
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum McpTransport
{
    /// <summary>MCP over HTTP (Streamable HTTP). The only transport this gateway speaks today.</summary>
    Http,

    /// <summary>A child process speaking MCP over stdio. Not implemented; refused at registration.</summary>
    Stdio
}

/// <summary>
/// An MCP server the platform offers. Registering one is an operator action: its tools run with
/// whatever rights the server itself has, and the gateway calls it on an application's behalf.
/// </summary>
public record McpServerRegistration
{
    [JsonPropertyName("serverId")]
    public string ServerId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("transport")]
    public McpTransport Transport { get; init; } = McpTransport.Http;

    [JsonPropertyName("url")]
    public string Url { get; init; } = string.Empty;

    /// <summary>Secret holding the bearer credential for this server. Never the credential itself.</summary>
    [JsonPropertyName("apiKeySecretName")]
    public string ApiKeySecretName { get; init; } = string.Empty;

    /// <summary>Side effect assumed for a tool that does not declare one.</summary>
    [JsonPropertyName("defaultSideEffect")]
    public ToolSideEffect DefaultSideEffect { get; init; } = ToolSideEffect.Read;

    [JsonPropertyName("timeoutSeconds")]
    public int TimeoutSeconds { get; init; } = 30;

    [JsonPropertyName("isActive")]
    public bool IsActive { get; init; } = true;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public record CreateMcpServerRequest
{
    [JsonPropertyName("serverId")]
    public string ServerId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("transport")]
    public McpTransport Transport { get; init; } = McpTransport.Http;

    [JsonPropertyName("url")]
    public string Url { get; init; } = string.Empty;

    [JsonPropertyName("apiKeySecretName")]
    public string ApiKeySecretName { get; init; } = string.Empty;

    [JsonPropertyName("defaultSideEffect")]
    public ToolSideEffect DefaultSideEffect { get; init; } = ToolSideEffect.Read;

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; init; }
}

public record UpdateMcpServerRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("apiKeySecretName")]
    public string? ApiKeySecretName { get; init; }

    [JsonPropertyName("defaultSideEffect")]
    public ToolSideEffect? DefaultSideEffect { get; init; }

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; init; }

    [JsonPropertyName("isActive")]
    public bool? IsActive { get; init; }
}

/// <summary>One tool published by a server, named <c>server.tool</c> across the gateway.</summary>
public record ToolDescriptor
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("serverId")]
    public string ServerId { get; init; } = string.Empty;

    /// <summary>The name the server itself knows it by, without the namespace.</summary>
    [JsonPropertyName("remoteName")]
    public string RemoteName { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("sideEffect")]
    public ToolSideEffect SideEffect { get; init; } = ToolSideEffect.Read;

    /// <summary>The tool's JSON Schema, as the server published it.</summary>
    [JsonPropertyName("inputSchema")]
    public string InputSchema { get; init; } = "{}";
}

/// <summary>The result of one tool call, after the guardrails have seen it.</summary>
public record ToolCallResult
{
    [JsonPropertyName("tool")]
    public string Tool { get; init; } = string.Empty;

    [JsonPropertyName("output")]
    public string Output { get; init; } = string.Empty;

    [JsonPropertyName("isError")]
    public bool IsError { get; init; }

    [JsonPropertyName("sideEffect")]
    public ToolSideEffect SideEffect { get; init; }

    [JsonPropertyName("latencyMs")]
    public long LatencyMs { get; init; }

    /// <summary>What the guardrails did to the result: Passed, Redacted, Blocked or None.</summary>
    [JsonPropertyName("guardrailAction")]
    public string GuardrailAction { get; init; } = "None";
}

/// <summary>Why a tool call was refused before it reached a server.</summary>
public class ToolRefusedException(string message) : Exception(message);

/// <summary>Why an MCP server registration was refused.</summary>
public class McpServerRejectedException(string message) : Exception(message);
