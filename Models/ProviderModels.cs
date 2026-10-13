using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

/// <summary>
/// The wire shape a provider speaks. Four API families cover the field, so a new vendor is a
/// registration rather than a code change as long as it speaks one of them.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ProviderKind
{
    /// <summary>OpenAI's chat completions shape: OpenAI itself, Groq, vLLM, LM Studio, llama.cpp.</summary>
    OpenAiCompatible,

    /// <summary>Anthropic's Messages API, called directly rather than through Bedrock.</summary>
    Anthropic,

    /// <summary>Google Gemini generateContent.</summary>
    Gemini,

    /// <summary>Ollama's native API on a host of its own.</summary>
    Ollama,

    /// <summary>AWS Bedrock, which authenticates with the host's own AWS identity, not an API key.</summary>
    Bedrock
}

/// <summary>
/// A model provider an operator has configured.
///
/// The credential is never here. An API key entered in the dashboard is written to the secret
/// store and only its name is kept, so the registry file can be read, copied or backed up without
/// carrying anything worth stealing.
/// </summary>
public record ProviderRegistration
{
    [JsonPropertyName("providerId")]
    public string ProviderId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("kind")]
    public ProviderKind Kind { get; init; } = ProviderKind.OpenAiCompatible;

    [JsonPropertyName("baseUrl")]
    public string BaseUrl { get; init; } = string.Empty;

    /// <summary>Name of the secret holding this provider's API key. Never the key.</summary>
    [JsonPropertyName("apiKeySecretName")]
    public string ApiKeySecretName { get; init; } = string.Empty;

    /// <summary>Last four characters of the key, so an operator can tell which one is in place.</summary>
    [JsonPropertyName("apiKeyHint")]
    public string ApiKeyHint { get; init; } = string.Empty;

    /// <summary>Models offered in the dashboard. Empty means whatever the caller names is passed through.</summary>
    [JsonPropertyName("models")]
    public List<string> Models { get; init; } = [];

    [JsonPropertyName("defaultModel")]
    public string? DefaultModel { get; init; }

    [JsonPropertyName("timeoutSeconds")]
    public int TimeoutSeconds { get; init; } = 120;

    [JsonPropertyName("isActive")]
    public bool IsActive { get; init; } = true;

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public record CreateProviderRequest
{
    [JsonPropertyName("providerId")]
    public string ProviderId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("kind")]
    public ProviderKind Kind { get; init; } = ProviderKind.OpenAiCompatible;

    /// <summary>Omitted for the kinds that have a well-known endpoint.</summary>
    [JsonPropertyName("baseUrl")]
    public string? BaseUrl { get; init; }

    /// <summary>
    /// The API key. Write-only: it goes to the secret store and is never stored in the registry
    /// or returned by any endpoint.
    /// </summary>
    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; init; }

    [JsonPropertyName("models")]
    public List<string>? Models { get; init; }

    [JsonPropertyName("defaultModel")]
    public string? DefaultModel { get; init; }

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; init; }
}

public record UpdateProviderRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("baseUrl")]
    public string? BaseUrl { get; init; }

    /// <summary>A new key replaces the stored one. Omitted leaves the existing key alone.</summary>
    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; init; }

    [JsonPropertyName("models")]
    public List<string>? Models { get; init; }

    [JsonPropertyName("defaultModel")]
    public string? DefaultModel { get; init; }

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; init; }

    [JsonPropertyName("isActive")]
    public bool? IsActive { get; init; }
}

public class ProviderRejectedException(string message) : Exception(message);
