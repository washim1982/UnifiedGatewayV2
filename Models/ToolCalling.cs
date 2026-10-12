using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// A tool as it is offered to a model: the name it calls, what it is for, and the JSON Schema of
/// its arguments. Built from the application's bindings, never from the model's suggestions.
/// </summary>
public record ToolSpec
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    /// <summary>The schema the publishing server declared, as raw JSON.</summary>
    [JsonPropertyName("inputSchema")]
    public string InputSchema { get; init; } = "{}";
}

/// <summary>One call a model asked for.</summary>
public record ToolInvocation
{
    /// <summary>The provider's id for this call, echoed back with the result so they pair up.</summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    /// <summary>Arguments as raw JSON, exactly as the model produced them.</summary>
    [JsonPropertyName("arguments")]
    public string Arguments { get; init; } = "{}";
}

/// <summary>What the gateway sends back for one call.</summary>
public record ToolExchange
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("result")]
    public string Result { get; init; } = string.Empty;

    [JsonPropertyName("isError")]
    public bool IsError { get; init; }
}

/// <summary>
/// One round of the loop: what the model asked for, and what it got. The adapters rebuild a
/// provider's message history from these, so the gateway keeps the conversation rather than the
/// provider keeping state for it.
/// </summary>
public record ToolTurn
{
    [JsonPropertyName("calls")]
    public List<ToolInvocation> Calls { get; init; } = [];

    [JsonPropertyName("results")]
    public List<ToolExchange> Results { get; init; } = [];

    /// <summary>Any text the model produced alongside its tool calls.</summary>
    [JsonPropertyName("assistantText")]
    public string AssistantText { get; init; } = string.Empty;
}
