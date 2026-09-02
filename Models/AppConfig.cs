using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// Application registration configuration and routing metadata.
/// </summary>
public record AppConfig
{
    [JsonPropertyName("appId")]
    public string AppId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("apiKeyHash")]
    public string ApiKeyHash { get; set; } = string.Empty;

    [JsonPropertyName("apiKeyPrefix")]
    public string ApiKeyPrefix { get; set; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = "bedrock"; // "bedrock" or "local"

    [JsonPropertyName("model")]
    public string Model { get; init; } = "anthropic.claude-3-5-sonnet-20240620-v1:0";

    [JsonPropertyName("systemPrompt")]
    public string SystemPrompt { get; init; } = "You are a helpful AI assistant.";

    [JsonPropertyName("temperature")]
    public double Temperature { get; init; } = 0.7;

    [JsonPropertyName("maxTokens")]
    public int MaxTokens { get; init; } = 2048;

    [JsonPropertyName("fallbackProvider")]
    public string? FallbackProvider { get; init; } // e.g. "local"

    [JsonPropertyName("fallbackModel")]
    public string? FallbackModel { get; init; } // e.g. "llama3"

    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("isActive")]
    public bool IsActive { get; init; } = true;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("versionHistory")]
    public List<AppConfigSnapshot> VersionHistory { get; init; } = [];
}

public record AppConfigSnapshot
{
    [JsonPropertyName("version")]
    public int Version { get; init; }

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty;

    [JsonPropertyName("model")]
    public string Model { get; init; } = string.Empty;

    [JsonPropertyName("systemPrompt")]
    public string SystemPrompt { get; init; } = string.Empty;

    [JsonPropertyName("temperature")]
    public double Temperature { get; init; }

    [JsonPropertyName("maxTokens")]
    public int MaxTokens { get; init; }

    [JsonPropertyName("savedAt")]
    public DateTimeOffset SavedAt { get; init; }
}

public record CreateAppRequest
{
    [JsonPropertyName("appId")]
    public string AppId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = "bedrock";

    [JsonPropertyName("model")]
    public string Model { get; init; } = "anthropic.claude-3-5-sonnet-20240620-v1:0";

    [JsonPropertyName("systemPrompt")]
    public string SystemPrompt { get; init; } = "You are a helpful AI assistant.";

    [JsonPropertyName("temperature")]
    public double Temperature { get; init; } = 0.7;

    [JsonPropertyName("maxTokens")]
    public int MaxTokens { get; init; } = 2048;

    [JsonPropertyName("fallbackProvider")]
    public string? FallbackProvider { get; init; }

    [JsonPropertyName("fallbackModel")]
    public string? FallbackModel { get; init; }
}

public record CreateAppResponse
{
    [JsonPropertyName("app")]
    public AppConfig App { get; init; } = null!;

    [JsonPropertyName("apiKey")]
    public string ApiKey { get; init; } = string.Empty;

    [JsonPropertyName("endpointUrl")]
    public string EndpointUrl { get; init; } = string.Empty;

    [JsonPropertyName("stsToken")]
    public string StsToken { get; init; } = string.Empty;

    [JsonPropertyName("stsExpiresAt")]
    public DateTimeOffset StsExpiresAt { get; init; }

    [JsonPropertyName("stsDurationSeconds")]
    public int StsDurationSeconds { get; init; } = 3600;
}

public record UpdateAppRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("provider")]
    public string? Provider { get; init; }

    [JsonPropertyName("model")]
    public string? Model { get; init; }

    [JsonPropertyName("systemPrompt")]
    public string? SystemPrompt { get; init; }

    [JsonPropertyName("temperature")]
    public double? Temperature { get; init; }

    [JsonPropertyName("maxTokens")]
    public int? MaxTokens { get; init; }

    [JsonPropertyName("fallbackProvider")]
    public string? FallbackProvider { get; init; }

    [JsonPropertyName("fallbackModel")]
    public string? FallbackModel { get; init; }

    [JsonPropertyName("isActive")]
    public bool? IsActive { get; init; }
}
