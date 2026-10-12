using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// A packaged instruction set an application can be given.
///
/// A skill is text the model reads, and nothing else. It carries no execution rights: a skill that
/// says "use the db.query tool" changes nothing unless that tool is separately attached to the
/// same application. Skill bodies are therefore treated as content, not configuration -- they pass
/// the guardrails before they are stored or served.
///
/// The description is cheap and always offered to the model; the body is loaded only when the
/// caller asks for that skill, so attaching ten skills costs ten lines of prompt, not ten bodies.
/// </summary>
public record SkillDefinition
{
    [JsonPropertyName("skillId")]
    public string SkillId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    /// <summary>One line, always present in the prompt index so the model knows the skill exists.</summary>
    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    /// <summary>The instructions themselves, loaded on demand.</summary>
    [JsonPropertyName("body")]
    public string Body { get; init; } = string.Empty;

    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("isActive")]
    public bool IsActive { get; init; } = true;

    /// <summary>SHA-256 of the body: what an audit record names, and what a binding resolves against.</summary>
    [JsonPropertyName("checksum")]
    public string Checksum { get; init; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("versionHistory")]
    public List<SkillSnapshot> VersionHistory { get; init; } = [];
}

/// <summary>A previous version, kept so a binding pinned to it still resolves.</summary>
public record SkillSnapshot
{
    [JsonPropertyName("version")]
    public int Version { get; init; }

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("body")]
    public string Body { get; init; } = string.Empty;

    [JsonPropertyName("checksum")]
    public string Checksum { get; init; } = string.Empty;

    [JsonPropertyName("savedAt")]
    public DateTimeOffset SavedAt { get; init; }
}

public record CreateSkillRequest
{
    [JsonPropertyName("skillId")]
    public string SkillId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("body")]
    public string Body { get; init; } = string.Empty;
}

public record UpdateSkillRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("body")]
    public string? Body { get; init; }

    [JsonPropertyName("isActive")]
    public bool? IsActive { get; init; }
}

/// <summary>Why a skill was refused, so the caller is told rather than quietly given less.</summary>
public class SkillRejectedException(string message) : Exception(message);
