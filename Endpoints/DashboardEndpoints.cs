using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;

namespace UnifiedGateway.Endpoints;

public static class DashboardEndpoints
{
    /// <summary>
    /// Verifies the caller presented the Master Admin API key or a valid Admin STS token.
    /// Used to protect credential-issuing management operations.
    /// </summary>
    private static bool IsAdminRequest(HttpContext ctx, GatewayOptions options, ISecurityService security)
    {
        var presented = ctx.Request.Headers["X-API-Key"].ToString();
        if (string.IsNullOrWhiteSpace(presented))
        {
            var auth = ctx.Request.Headers.Authorization.ToString();
            presented = auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? auth[7..].Trim() : auth.Trim();
        }

        if (string.IsNullOrWhiteSpace(presented)) return false;

        if (presented.StartsWith("ug_sts_", StringComparison.OrdinalIgnoreCase))
        {
            var (isValid, payload, _) = security.ValidateAppStsToken(presented);
            return isValid && payload is { IsAdmin: true };
        }

        return security.VerifyKey(presented, security.HashKey(options.Security.AdminApiKey));
    }

    public static void MapDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api")
            .WithTags("Dashboard & Management");

        // List applications
        group.MapGet("/apps", async (IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var apps = await registry.GetAllAppsAsync(ct);
            return Results.Ok(apps);
        })
        .WithName("ListApplications");

        // Get single application
        group.MapGet("/apps/{appId}", async (string appId, IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var appConfig = await registry.GetAppAsync(appId, ct);
            return appConfig is not null ? Results.Ok(appConfig) : Results.NotFound(new { error = "Application not found" });
        })
        .WithName("GetApplication");

        // Create new application (generates endpoint and API key)
        group.MapPost("/apps", async ([FromBody] CreateAppRequest request, IApplicationRegistryService registry, CancellationToken ct) =>
        {
            try
            {
                var created = await registry.CreateAppAsync(request, ct);
                return Results.Created($"/api/apps/{created.App.AppId}", created);
            }
            catch (InvalidOperationException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("CreateApplication");

        // Update application (increments version and updates prompt/config)
        group.MapPut("/apps/{appId}", async (string appId, [FromBody] UpdateAppRequest request, IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var updated = await registry.UpdateAppAsync(appId, request, ct);
            return updated is not null ? Results.Ok(updated) : Results.NotFound(new { error = "Application not found" });
        })
        .WithName("UpdateApplication");

        // Delete application
        group.MapDelete("/apps/{appId}", async (string appId, IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var deleted = await registry.DeleteAppAsync(appId, ct);
            return deleted ? Results.NoContent() : Results.NotFound(new { error = "Application not found" });
        })
        .WithName("DeleteApplication");

        // Rotate an application's long-term API key (invalidates the previous key immediately).
        // Requires the Master Admin key or an Admin STS token: this mints a credential.
        group.MapPost("/apps/{appId}/rotate-key", async (
            string appId,
            HttpContext ctx,
            IOptions<GatewayOptions> options,
            ISecurityService security,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            if (!IsAdminRequest(ctx, options.Value, security))
            {
                return Results.Json(new
                {
                    error = "ADMIN_UNAUTHORIZED",
                    message = "Key rotation requires the Master Admin API key or an Admin STS token."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var newKey = await registry.RotateApiKeyAsync(appId, ct);
            if (newKey is null)
            {
                return Results.NotFound(new { error = "Application not found" });
            }

            // The plaintext key is returned exactly once; only its hash is stored.
            return Results.Ok(new
            {
                appId,
                apiKey = newKey,
                rotatedAt = DateTimeOffset.UtcNow,
                warning = "Copy this key now. The previous key is no longer valid and this value cannot be retrieved again."
            });
        })
        .WithName("RotateApplicationApiKey")
        .WithSummary("Rotate an application's long-term API key and return the new key once");

        // Mint short temporary secret (STS token) for an application from dashboard
        group.MapPost("/apps/{appId}/sts-token", async (
            string appId,
            [FromQuery] int? durationSeconds,
            [FromQuery] string? scope,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var app = await registry.GetAppAsync(appId, ct);
            if (app == null)
            {
                return Results.NotFound(new { error = "Application not found" });
            }

            var tokenResp = await registry.MintStsTokenDirectAsync(
                appId,
                durationSeconds ?? 3600,
                scope ?? "invoke",
                isAdmin: false,
                callerId: "DashboardUser",
                cancellationToken: ct);

            return Results.Ok(tokenResp);
        })
        .WithName("MintAppStsToken");

        // Test application invocation from dashboard
        group.MapPost("/apps/{appId}/test", async (
            string appId,
            [FromBody] InvokeAppRequest request,
            IModelRouter router,
            CancellationToken ct) =>
        {
            var result = await router.RouteAppRequestAsync(appId, request, ct);
            return Results.Ok(result);
        })
        .WithName("TestApplication");

        // Real-time metrics and analytics
        group.MapGet("/metrics", async (IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var summary = await registry.GetMetricsSummaryAsync(ct);
            return Results.Ok(summary);
        })
        .WithName("GetMetrics");

        // List supported and available models across Bedrock and Local
        group.MapGet("/models", async (ILocalModelService localService, CancellationToken ct) =>
        {
            var bedrockModels = new[]
            {
                new { id = "anthropic.claude-3-5-sonnet-20240620-v1:0", name = "Claude 3.5 Sonnet", provider = "bedrock", contextWindow = 200000 },
                new { id = "anthropic.claude-3-haiku-20240307-v1:0", name = "Claude 3 Haiku", provider = "bedrock", contextWindow = 200000 },
                new { id = "anthropic.claude-3-opus-20240229-v1:0", name = "Claude 3 Opus", provider = "bedrock", contextWindow = 200000 },
                new { id = "meta.llama3-70b-instruct-v1:0", name = "Meta Llama 3 70B", provider = "bedrock", contextWindow = 8192 },
                new { id = "meta.llama3-8b-instruct-v1:0", name = "Meta Llama 3 8B", provider = "bedrock", contextWindow = 8192 },
                new { id = "mistral.mistral-7b-instruct-v0:2", name = "Mistral 7B Instruct", provider = "bedrock", contextWindow = 32000 },
                new { id = "mistral.mixtral-8x7b-instruct-v0:1", name = "Mixtral 8x7B", provider = "bedrock", contextWindow = 32000 },
                new { id = "amazon.titan-text-express-v1", name = "Amazon Titan Text Express", provider = "bedrock", contextWindow = 8000 }
            };

            var localModels = await localService.ListAvailableLocalModelsAsync(ct);

            return Results.Ok(new
            {
                bedrock = bedrockModels,
                local = localModels
            });
        })
        .WithName("GetModels");

        // Get STS Credential status
        group.MapGet("/credentials/status", async (ISTSService stsService, CancellationToken ct) =>
        {
            var status = await stsService.GetStatusAsync(ct);
            return Results.Ok(status);
        })
        .WithName("GetCredentialStatus");

        #region Guardrails Management Endpoints

        // Get Guardrail Configuration
        group.MapGet("/guardrails/config", (IGuardrailService guardrailService) =>
        {
            var config = guardrailService.GetCurrentOptions();
            return Results.Ok(config);
        })
        .WithName("GetGuardrailConfig")
        .WithSummary("Retrieve current enterprise safety guardrail rules and active mode");

        // Update Guardrail Configuration
        group.MapPut("/guardrails/config", ([FromBody] GuardrailOptions options, IGuardrailService guardrailService) =>
        {
            guardrailService.UpdateOptions(options);
            return Results.Ok(new { message = "Guardrail configuration updated successfully", config = options });
        })
        .WithName("UpdateGuardrailConfig")
        .WithSummary("Update enterprise guardrail rules, PCI/PII detectors, and enforcement mode (Block/Redact/Audit)");

        // Test text against Guardrail inspection sandbox
        group.MapPost("/guardrails/test", async (
            [FromBody] GuardrailTestRequest request,
            IGuardrailService guardrailService,
            CancellationToken ct) =>
        {
            var result = await guardrailService.EvaluateAsync(
                request.Input,
                modeOverride: request.Mode,
                cancellationToken: ct);

            return Results.Ok(result);
        })
        .WithName("TestGuardrails")
        .WithSummary("Interactive sandbox to test text against PCI, PII, Secrets, and Injection guardrails");

        #endregion
    }
}
