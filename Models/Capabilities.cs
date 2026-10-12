using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// What a binding points at.
///
/// <see cref="Tool"/> is a binding kind but never a catalogue kind: a tool is published by an MCP
/// server or a plugin, and an application is granted access to it rather than defining it. Keeping
/// one authorization path for tools is the reason the two ideas are separated.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CapabilityKind
{
    Skill,
    Tool,
    McpServer,
    Agent,
    Plugin
}

/// <summary>
/// One capability attached to one application.
///
/// A binding pins a version. The catalogue entry can move on -- a skill is rewritten, an agent
/// gains a node -- without changing what an application sends to a model until someone attaches
/// the new version deliberately.
/// </summary>
public record CapabilityBinding
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];

    [JsonPropertyName("kind")]
    public CapabilityKind Kind { get; init; }

    /// <summary>Catalogue id: a skill id, an agent id, or a namespaced tool name.</summary>
    [JsonPropertyName("ref")]
    public string Ref { get; init; } = string.Empty;

    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Tool bindings only: the strongest side effect this application may trigger through the
    /// tool. A server that later reclassifies a read as a write stops being callable here rather
    /// than quietly gaining the right to change things.
    /// </summary>
    [JsonPropertyName("maxSideEffect")]
    public ToolSideEffect MaxSideEffect { get; init; } = ToolSideEffect.Read;

    /// <summary>Principal that attached it, for the audit trail.</summary>
    [JsonPropertyName("attachedBy")]
    public string? AttachedBy { get; init; }

    [JsonPropertyName("attachedAt")]
    public DateTimeOffset AttachedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>Attach request. The version is pinned; "latest" is deliberately not accepted.</summary>
public record AttachCapabilityRequest
{
    [JsonPropertyName("kind")]
    public CapabilityKind Kind { get; init; }

    [JsonPropertyName("ref")]
    public string Ref { get; init; } = string.Empty;

    /// <summary>Omitted means the catalogue entry's current version, resolved and then pinned.</summary>
    [JsonPropertyName("version")]
    public int? Version { get; init; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    /// <summary>Tool bindings only. Defaults to Read: granting writes is a deliberate act.</summary>
    [JsonPropertyName("maxSideEffect")]
    public ToolSideEffect? MaxSideEffect { get; init; }
}

/// <summary>
/// A binding resolved against the catalogue: what the application may actually use right now, and
/// why not, when a binding no longer resolves.
/// </summary>
public record CapabilityView
{
    [JsonPropertyName("binding")]
    public CapabilityBinding Binding { get; init; } = null!;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    /// <summary>The catalogue's current version, which may be ahead of the pinned one.</summary>
    [JsonPropertyName("catalogVersion")]
    public int CatalogVersion { get; init; }

    /// <summary>False when the catalogue entry is gone, disabled, or the pinned version is absent.</summary>
    [JsonPropertyName("usable")]
    public bool Usable { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }
}
