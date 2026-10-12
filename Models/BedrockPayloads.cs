using System.Text.Json;
using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

#region Anthropic Claude Payloads

public class ClaudeBedrockRequest
{
    [JsonPropertyName("anthropic_version")]
    public string AnthropicVersion { get; set; } = "bedrock-2023-05-31";

    [JsonPropertyName("max_tokens")]
    public int MaxTokens { get; set; } = 2048;

    [JsonPropertyName("temperature")]
    public double Temperature { get; set; } = 0.7;

    [JsonPropertyName("system")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? System { get; set; }

    [JsonPropertyName("messages")]
    public List<ClaudeMessage> Messages { get; set; } = [];

    /// <summary>Tools offered for this turn. Omitted entirely when the application has none.</summary>
    [JsonPropertyName("tools")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ClaudeTool>? Tools { get; set; }
}

public class ClaudeMessage
{
    [JsonPropertyName("role")]
    public string Role { get; set; } = "user";

    /// <summary>
    /// A plain string for an ordinary turn, or a list of content blocks once tools are in play
    /// (tool_use from the model, tool_result from the gateway). Anthropic accepts both shapes.
    /// </summary>
    [JsonPropertyName("content")]
    public object Content { get; set; } = string.Empty;
}

/// <summary>A tool as Anthropic expects it: name, description and the JSON Schema of its input.</summary>
public class ClaudeTool
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("input_schema")]
    public JsonElement InputSchema { get; set; }
}

public class ClaudeBedrockResponse
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("content")]
    public List<ClaudeContentBlock> Content { get; set; } = [];

    [JsonPropertyName("stop_reason")]
    public string? StopReason { get; set; }

    [JsonPropertyName("usage")]
    public ClaudeUsage? Usage { get; set; }
}

public class ClaudeContentBlock
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "text";

    [JsonPropertyName("text")]
    public string Text { get; set; } = string.Empty;

    /// <summary>tool_use blocks only: the call id to echo back with the result.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>tool_use blocks only: the tool the model is asking for.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>tool_use blocks only: the arguments the model produced.</summary>
    [JsonPropertyName("input")]
    public JsonElement? Input { get; set; }
}

public class ClaudeUsage
{
    [JsonPropertyName("input_tokens")]
    public int InputTokens { get; set; }

    [JsonPropertyName("output_tokens")]
    public int OutputTokens { get; set; }
}

#endregion

#region Meta Llama Payloads

public class LlamaBedrockRequest
{
    [JsonPropertyName("prompt")]
    public string Prompt { get; set; } = string.Empty;

    [JsonPropertyName("max_gen_len")]
    public int MaxGenLen { get; set; } = 2048;

    [JsonPropertyName("temperature")]
    public double Temperature { get; set; } = 0.7;
}

public class LlamaBedrockResponse
{
    [JsonPropertyName("generation")]
    public string Generation { get; set; } = string.Empty;

    [JsonPropertyName("prompt_token_count")]
    public int PromptTokenCount { get; set; }

    [JsonPropertyName("generation_token_count")]
    public int GenerationTokenCount { get; set; }

    [JsonPropertyName("stop_reason")]
    public string? StopReason { get; set; }
}

#endregion

#region Mistral Payloads

public class MistralBedrockRequest
{
    [JsonPropertyName("prompt")]
    public string Prompt { get; set; } = string.Empty;

    [JsonPropertyName("max_tokens")]
    public int MaxTokens { get; set; } = 2048;

    [JsonPropertyName("temperature")]
    public double Temperature { get; set; } = 0.7;
}

public class MistralBedrockResponse
{
    [JsonPropertyName("outputs")]
    public List<MistralOutput> Outputs { get; set; } = [];
}

public class MistralOutput
{
    [JsonPropertyName("text")]
    public string Text { get; set; } = string.Empty;

    [JsonPropertyName("stop_reason")]
    public string? StopReason { get; set; }
}

#endregion

#region Titan Payloads

public class TitanBedrockRequest
{
    [JsonPropertyName("inputText")]
    public string InputText { get; set; } = string.Empty;

    [JsonPropertyName("textGenerationConfig")]
    public TitanGenerationConfig TextGenerationConfig { get; set; } = new();
}

public class TitanGenerationConfig
{
    [JsonPropertyName("maxTokenCount")]
    public int MaxTokenCount { get; set; } = 2048;

    [JsonPropertyName("temperature")]
    public double Temperature { get; set; } = 0.7;
}

public class TitanBedrockResponse
{
    [JsonPropertyName("inputTextTokenCount")]
    public int InputTextTokenCount { get; set; }

    [JsonPropertyName("results")]
    public List<TitanResult> Results { get; set; } = [];
}

public class TitanResult
{
    [JsonPropertyName("tokenCount")]
    public int TokenCount { get; set; }

    [JsonPropertyName("outputText")]
    public string OutputText { get; set; } = string.Empty;
}

#endregion
