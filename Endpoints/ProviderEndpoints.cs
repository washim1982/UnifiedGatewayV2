using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;
using UnifiedGateway.Auth;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Providers;

namespace UnifiedGateway.Endpoints;

/// <summary>
/// Model providers: OpenAI, Anthropic, Gemini, an Ollama host, anything speaking the OpenAI shape,
/// and Bedrock.
///
/// Configuring a provider is an operator action because it decides where prompts go and what the
/// organisation is billed for. An API key supplied here is written to the secret store and never
/// returned by any endpoint, so this surface can create and rotate a credential without ever
/// being able to read one back.
/// </summary>
public static class ProviderEndpoints
{
    public static void MapProviderEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api")
            .WithTags("Model providers")
            .RequireAuthorization(GatewayAuth.PlatformAdminPolicy)
            .RequireRateLimiting("management");

        group.MapGet("/providers", async (IProviderRegistry registry, CancellationToken ct) =>
            Results.Ok(await registry.ListAsync(ct)))
        .WithName("ListProviders")
        .WithSummary("Configured model providers. Keys are never included.")
        .RequireIamAction("ReadProviders");

        // Presets, not just kinds: four of these are the same OpenAI-compatible adapter, and an
        // operator adding LM Studio should not have to know that. Each preset names the family
        // that speaks for it and the endpoint it normally listens on.
        group.MapGet("/providers/kinds", () => Results.Ok(new[]
        {
            new { id = "openai", kind = ProviderKind.OpenAiCompatible.ToString(), label = "OpenAI", needsKey = true, defaultBaseUrl = "https://api.openai.com", suggestedId = "openai", note = "GPT models through the chat completions API" },
            new { id = "anthropic", kind = ProviderKind.Anthropic.ToString(), label = "Anthropic (Claude)", needsKey = true, defaultBaseUrl = "https://api.anthropic.com", suggestedId = "claude", note = "Messages API, called directly" },
            new { id = "gemini", kind = ProviderKind.Gemini.ToString(), label = "Google Gemini", needsKey = true, defaultBaseUrl = "https://generativelanguage.googleapis.com", suggestedId = "gemini", note = "generateContent; no tool calling yet" },
            new { id = "bedrock", kind = ProviderKind.Bedrock.ToString(), label = "AWS Bedrock", needsKey = false, defaultBaseUrl = "", suggestedId = "bedrock", note = "Authenticates with this host's AWS identity" },
            new { id = "ollama", kind = ProviderKind.Ollama.ToString(), label = "Ollama (local)", needsKey = false, defaultBaseUrl = "http://localhost:11434", suggestedId = "ollama-local", note = "Native API, with tool calling" },
            new { id = "lmstudio", kind = ProviderKind.OpenAiCompatible.ToString(), label = "LM Studio (local)", needsKey = false, defaultBaseUrl = "http://localhost:1234", suggestedId = "lmstudio", note = "OpenAI-compatible server; models are whatever is loaded" },
            new { id = "llamacpp", kind = ProviderKind.OpenAiCompatible.ToString(), label = "llama.cpp (local)", needsKey = false, defaultBaseUrl = "http://localhost:8080", suggestedId = "llamacpp", note = "llama-server's OpenAI-compatible endpoint" },
            new { id = "vllm", kind = ProviderKind.OpenAiCompatible.ToString(), label = "vLLM / self-hosted", needsKey = true, defaultBaseUrl = "", suggestedId = "vllm", note = "Any server speaking the OpenAI chat shape" },
            new { id = "groq", kind = ProviderKind.OpenAiCompatible.ToString(), label = "Groq", needsKey = true, defaultBaseUrl = "https://api.groq.com/openai", suggestedId = "groq", note = "OpenAI-compatible, hosted" }
        }))
        .WithName("ListProviderKinds")
        .WithSummary("Provider presets for the registration form, each naming the family that speaks for it")
        .RequireIamAction("ReadProviders");

        group.MapGet("/providers/{providerId}/models", async (
            string providerId,
            IProviderRegistry registry,
            IHttpClientFactory httpClientFactory,
            CancellationToken ct) =>
        {
            var provider = await registry.GetAsync(providerId, ct);
            if (provider is null)
            {
                return Results.NotFound(new { error = "Provider not found" });
            }

            // Only the OpenAI shape publishes a catalogue the gateway can read; the rest keep
            // whatever the operator listed.
            if (provider.Kind != ProviderKind.OpenAiCompatible)
            {
                return Results.Ok(new { discovered = false, models = provider.Models });
            }

            try
            {
                var client = httpClientFactory.CreateClient(HttpProviderAdapter.HttpClientName);
                client.BaseAddress = new Uri(provider.BaseUrl);
                client.Timeout = TimeSpan.FromSeconds(10);

                var apiKey = await registry.ApiKeyAsync(provider, ct);
                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    client.DefaultRequestHeaders.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);
                }

                using var response = await client.GetAsync("/v1/models", ct);
                response.EnsureSuccessStatusCode();

                var body = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: ct);
                var models = body.TryGetProperty("data", out var data) && data.ValueKind == System.Text.Json.JsonValueKind.Array
                    ? data.EnumerateArray()
                        .Where(m => m.TryGetProperty("id", out _))
                        .Select(m => m.GetProperty("id").GetString())
                        .Where(id => !string.IsNullOrWhiteSpace(id))
                        .ToList()
                    : [];

                return Results.Ok(new { discovered = true, models });
            }
            catch (Exception ex)
            {
                return Results.Ok(new { discovered = false, models = provider.Models, error = ex.Message });
            }
        })
        .WithName("DiscoverProviderModels")
        .WithSummary("Ask an OpenAI-compatible provider which models it is serving")
        .RequireIamAction("ReadProviders");

        group.MapPost("/providers", async (
            [FromBody] CreateProviderRequest request,
            HttpContext ctx,
            IProviderRegistry registry,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            try
            {
                var provider = await registry.CreateAsync(request, ct);

                await apps.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "RegisterProvider", provider.ProviderId, success: true,
                        $"{provider.Kind} at {provider.BaseUrl}; key={(provider.ApiKeySecretName.Length > 0 ? "stored" : "none")}"), ct);

                return Results.Created($"/api/providers/{provider.ProviderId}", provider);
            }
            catch (ProviderRejectedException ex)
            {
                await apps.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "RegisterProvider", request.ProviderId, success: false, ex.Message), ct);

                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("RegisterProvider")
        .WithSummary("Configure a model provider. Any API key goes to the secret store.")
        .RequireIamAction("ManageProviders");

        group.MapPut("/providers/{providerId}", async (
            string providerId,
            [FromBody] UpdateProviderRequest request,
            HttpContext ctx,
            IProviderRegistry registry,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            try
            {
                var provider = await registry.UpdateAsync(providerId, request, ct);
                if (provider is null)
                {
                    return Results.NotFound(new { error = "Provider not found" });
                }

                await apps.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "UpdateProvider", providerId, success: true,
                        $"active={provider.IsActive}; keyRotated={!string.IsNullOrWhiteSpace(request.ApiKey)}"), ct);

                return Results.Ok(provider);
            }
            catch (ProviderRejectedException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("UpdateProvider")
        .WithSummary("Change a provider, or rotate its key by supplying a new one")
        .RequireIamAction("ManageProviders");

        group.MapDelete("/providers/{providerId}", async (
            string providerId,
            HttpContext ctx,
            IProviderRegistry registry,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            if (!await registry.DeleteAsync(providerId, ct))
            {
                return Results.NotFound(new { error = "Provider not found" });
            }

            await apps.RecordManagementActionAsync(
                DashboardEndpoints.Audit(ctx, "DeleteProvider", providerId, success: true), ct);

            return Results.Ok(new
            {
                message = $"Provider '{providerId}' deleted.",
                warning = "Applications routed to it now fail with UNKNOWN_PROVIDER until they are repointed. " +
                          "Its stored API key is left in the secret store."
            });
        })
        .WithName("DeleteProvider")
        .RequireIamAction("ManageProviders");

        group.MapPost("/providers/{providerId}/test", async (
            string providerId,
            HttpContext ctx,
            IProviderRegistry registry,
            IProviderDispatcher dispatcher,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            var provider = await registry.GetAsync(providerId, ct);
            if (provider is null)
            {
                return Results.NotFound(new { error = "Provider not found" });
            }

            var model = provider.DefaultModel ?? provider.Models.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(model))
            {
                return Results.BadRequest(new
                {
                    error = "This provider has no default model, so there is nothing to test against. " +
                            "Set one, or list its models."
                });
            }

            // The smallest real call that proves the endpoint, the credential and the model name
            // all work together. Anything less tests only that a URL parses.
            var response = await dispatcher.TryInvokeAsync(providerId, new UniversalRequest
            {
                Model = model,
                Input = "Reply with the single word: ready.",
                // Generous for a one-word answer, because a reasoning model spends tokens
                // thinking before it writes anything: too small a ceiling returns an empty
                // completion and looks like a broken provider.
                MaxTokens = 256,
                Temperature = 0
            }, ct);

            var ok = response is { Error: null };
            await apps.RecordManagementActionAsync(
                DashboardEndpoints.Audit(ctx, "TestProvider", providerId, ok, response?.Error?.Code), ct);

            return Results.Ok(new
            {
                ok,
                model,
                latencyMs = response?.LatencyMs ?? 0,
                output = response?.Output,
                error = response?.Error
            });
        })
        .WithName("TestProvider")
        .WithSummary("Send one small request to prove the endpoint, credential and model work")
        .RequireIamAction("ManageProviders");
    }
}
