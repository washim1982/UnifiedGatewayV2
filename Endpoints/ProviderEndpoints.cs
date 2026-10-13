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

        group.MapGet("/providers/kinds", () => Results.Ok(new[]
        {
            new { kind = ProviderKind.OpenAiCompatible.ToString(), label = "OpenAI-compatible", needsKey = true, defaultBaseUrl = "https://api.openai.com", note = "OpenAI, Groq, vLLM, LM Studio, llama.cpp" },
            new { kind = ProviderKind.Anthropic.ToString(), label = "Anthropic (Claude)", needsKey = true, defaultBaseUrl = "https://api.anthropic.com", note = "Messages API, called directly" },
            new { kind = ProviderKind.Gemini.ToString(), label = "Google Gemini", needsKey = true, defaultBaseUrl = "https://generativelanguage.googleapis.com", note = "generateContent; no tool calling yet" },
            new { kind = ProviderKind.Ollama.ToString(), label = "Ollama host", needsKey = false, defaultBaseUrl = "http://localhost:11434", note = "Native API with tool calling" },
            new { kind = ProviderKind.Bedrock.ToString(), label = "AWS Bedrock", needsKey = false, defaultBaseUrl = "", note = "Authenticates with this host's AWS identity" }
        }))
        .WithName("ListProviderKinds")
        .WithSummary("Provider families this gateway can speak, for the registration form")
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
