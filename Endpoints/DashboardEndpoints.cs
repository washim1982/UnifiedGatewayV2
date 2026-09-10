using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using UnifiedGateway.Auth;
using UnifiedGateway.Models;
using UnifiedGateway.Services;

namespace UnifiedGateway.Endpoints;

public static class DashboardEndpoints
{
    /// <summary>
    /// Builds an audit record for a privileged action from the authenticated caller.
    /// </summary>
    private static ManagementAuditEntry Audit(
        HttpContext ctx, string action, string? resource, bool success, string? detail = null) => new()
        {
            Action = action,
            Resource = resource,
            Actor = ctx.User.FindFirst(GatewayAuth.PrincipalArnClaim)?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            AuthType = ctx.User.FindFirst(GatewayAuth.AuthTypeClaim)?.Value,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString(),
            Success = success,
            Detail = detail
        };


    /// <summary>
    /// Maps the grain query parameter onto the enum, defaulting to daily. An unrecognised
    /// value falls back rather than 400-ing: a mistyped grain should still render a page.
    /// </summary>
    private static BillingGrain ParseGrain(string? grain) =>
        Enum.TryParse<BillingGrain>(grain, ignoreCase: true, out var parsed)
            ? parsed
            : BillingGrain.Daily;


    /// <summary>
    /// Maps the range shortcut the dashboard sends (24h / 7d / 30d) onto a window and the
    /// grain that reads sensibly at that length -- hourly detail over a month is unreadable,
    /// and monthly buckets over a day say nothing. An explicit from/to always wins.
    /// </summary>
    private static (DateTimeOffset? From, DateTimeOffset? To, BillingGrain Grain) ResolveRange(
        string? range, DateTimeOffset? from, DateTimeOffset? to)
    {
        if (from.HasValue || to.HasValue)
        {
            return (from, to, BillingGrain.Daily);
        }

        var now = DateTimeOffset.UtcNow;

        return (range ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "24h" or "1d" => (now.AddHours(-24), now, BillingGrain.Daily),
            "7d" => (now.AddDays(-6), now, BillingGrain.Daily),
            "30d" => (now.AddDays(-29), now, BillingGrain.Daily),
            "90d" => (now.AddDays(-89), now, BillingGrain.Weekly),
            "12m" or "1y" => (now.AddMonths(-11), now, BillingGrain.Monthly),
            _ => (null, null, BillingGrain.Daily)
        };
    }
    public static void MapDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        // Deny by default for the whole management plane.
        //
        // Authorization is applied at the group so a new endpoint added below inherits it
        // rather than being publicly reachable until somebody remembers to guard it. Every
        // handler additionally names the IAM action it needs, which is what the environment's
        // policy engine evaluates.
        var group = app.MapGroup("/api")
            .WithTags("Dashboard & Management")
            .RequireAuthorization(GatewayAuth.PlatformAdminPolicy)
            .RequireRateLimiting("management");

        #region Applications

        group.MapGet("/apps", async (IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var apps = await registry.GetAllAppsAsync(ct);
            return Results.Ok(apps);
        })
        .WithName("ListApplications")
        .RequireIamAction("ListApplications");

        group.MapGet("/apps/{appId}", async (string appId, IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var appConfig = await registry.GetAppAsync(appId, ct);
            return appConfig is not null
                ? Results.Ok(appConfig)
                : Results.NotFound(new { error = "Application not found" });
        })
        .WithName("GetApplication")
        .RequireIamAction("GetApplication");

        group.MapPost("/apps", async (
            [FromBody] CreateAppRequest request,
            HttpContext ctx,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            try
            {
                var created = await registry.CreateAppAsync(request, ct);
                await registry.RecordManagementActionAsync(
                    Audit(ctx, "CreateApplication", created.App.AppId, success: true), ct);

                return Results.Created($"/api/apps/{created.App.AppId}", created);
            }
            catch (InvalidOperationException ex)
            {
                await registry.RecordManagementActionAsync(
                    Audit(ctx, "CreateApplication", request.AppId, success: false, ex.Message), ct);

                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("CreateApplication")
        .RequireIamAction("CreateApplication");

        group.MapPut("/apps/{appId}", async (
            string appId,
            [FromBody] UpdateAppRequest request,
            HttpContext ctx,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var updated = await registry.UpdateAppAsync(appId, request, ct);
            await registry.RecordManagementActionAsync(
                Audit(ctx, "UpdateApplication", appId, updated is not null), ct);

            return updated is not null
                ? Results.Ok(updated)
                : Results.NotFound(new { error = "Application not found" });
        })
        .WithName("UpdateApplication")
        .RequireIamAction("UpdateApplication");

        group.MapDelete("/apps/{appId}", async (
            string appId,
            HttpContext ctx,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var deleted = await registry.DeleteAppAsync(appId, ct);
            await registry.RecordManagementActionAsync(
                Audit(ctx, "DeleteApplication", appId, deleted), ct);

            return deleted
                ? Results.NoContent()
                : Results.NotFound(new { error = "Application not found" });
        })
        .WithName("DeleteApplication")
        .RequireIamAction("DeleteApplication");

        #endregion

        #region Credentials

        group.MapPost("/apps/{appId}/rotate-key", async (
            string appId,
            HttpContext ctx,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var newKey = await registry.RotateApiKeyAsync(appId, ct);
            await registry.RecordManagementActionAsync(
                Audit(ctx, "RotateApiKey", appId, newKey is not null), ct);

            if (newKey is null)
            {
                return Results.NotFound(new { error = "Application not found" });
            }

            return Results.Ok(new
            {
                appId,
                apiKey = newKey,
                rotatedAt = DateTimeOffset.UtcNow,
                warning = "Copy this key now. The previous key is no longer valid and this value cannot be retrieved again."
            });
        })
        .WithName("RotateApplicationApiKey")
        .WithSummary("Rotate an application's long-term API key and return the new key once")
        .RequireIamAction("RotateApiKey");

        group.MapPost("/apps/{appId}/sts-token", async (
            string appId,
            [FromQuery] int? durationSeconds,
            [FromQuery] string? scope,
            HttpContext ctx,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var app = await registry.GetAppAsync(appId, ct);
            if (app == null)
            {
                return Results.NotFound(new { error = "Application not found" });
            }

            var callerId = ctx.User.FindFirst(GatewayAuth.PrincipalArnClaim)?.Value ?? "dashboard";

            var tokenResp = await registry.MintStsTokenDirectAsync(
                appId,
                durationSeconds ?? 0,
                scope ?? "invoke",
                isAdmin: false,
                callerId: callerId,
                cancellationToken: ct);

            await registry.RecordManagementActionAsync(
                Audit(ctx, "MintStsToken", appId, success: true,
                      $"scope={tokenResp.Scope}; ttl={tokenResp.DurationSeconds}s"), ct);

            return Results.Ok(tokenResp);
        })
        .WithName("MintAppStsToken")
        .RequireIamAction("MintStsToken");

        /// Rotates the signing key itself, invalidating every outstanding STS token at once.
        group.MapPost("/credentials/rotate-signing-key", async (
            HttpContext ctx,
            Services.Cloud.ISigningKeyProvider signingKeys,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var material = await signingKeys.RotateAsync(ct);
            await registry.RecordManagementActionAsync(
                Audit(ctx, "RotateSigningKey", "gateway", success: true,
                      $"generation={material.Generation}"), ct);

            return Results.Ok(new
            {
                generation = material.Generation,
                rotatedAt = DateTimeOffset.UtcNow,
                warning = "Every STS token issued under an earlier generation is now rejected."
            });
        })
        .WithName("RotateSigningKey")
        .WithSummary("Rotate the STS signing key, revoking all outstanding tokens")
        .RequireIamAction("RotateSigningKey");

        #endregion

        #region Testing and telemetry

        group.MapPost("/apps/{appId}/test", async (
            string appId,
            [FromBody] InvokeAppRequest request,
            HttpContext ctx,
            IModelRouter router,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            // The dashboard tester runs as the signed-in operator, so the invocation is
            // attributed to them rather than to the application it exercises.
            var caller = new CallerContext
            {
                Actor = ctx.User.FindFirst(GatewayAuth.PrincipalArnClaim)?.Value
                        ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
                AuthType = ctx.User.FindFirst(GatewayAuth.AuthTypeClaim)?.Value,
                SourceIp = ctx.Connection.RemoteIpAddress?.ToString(),
                TraceId = ctx.TraceIdentifier
            };

            var result = await router.RouteAppRequestAsync(appId, request, caller, ct);
            await registry.RecordManagementActionAsync(
                Audit(ctx, "TestApplication", appId, result.Error is null), ct);

            // Same status mapping as the public invoke path, so the dashboard sees exactly
            // what a real client would rather than a 200 with an error object inside.
            return GatewayEndpoints.ToHttpResult(result);
        })
        .WithName("TestApplication")
        .RequireIamAction("InvokeApplication");

        group.MapGet("/metrics", async (IApplicationRegistryService registry, CancellationToken ct) =>
        {
            var summary = await registry.GetMetricsSummaryAsync(ct);
            return Results.Ok(summary);
        })
        .WithName("GetMetrics")
        .RequireIamAction("ReadMetrics");

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
            return Results.Ok(new { bedrock = bedrockModels, local = localModels });
        })
        .WithName("GetModels")
        .RequireIamAction("ListModels");

        group.MapGet("/credentials/status", async (ISTSService stsService, CancellationToken ct) =>
        {
            var status = await stsService.GetStatusAsync(ct);
            return Results.Ok(status);
        })
        .WithName("GetCredentialStatus")
        .RequireIamAction("ReadCredentialStatus");

        #endregion


        #region Billing

        // Billing is admin-only: it exposes account-wide spend across every tenant.
        group.MapGet("/billing/summary", async (
            [FromQuery] string? grain,
            [FromQuery] string? range,
            [FromQuery] DateTimeOffset? from,
            [FromQuery] DateTimeOffset? to,
            IBillingService billing,
            CancellationToken ct) =>
        {
            var (windowFrom, windowTo, defaultGrain) = ResolveRange(range, from, to);
            var resolvedGrain = grain is null ? defaultGrain : ParseGrain(grain);

            var summary = await billing.GetSummaryAsync(resolvedGrain, windowFrom, windowTo, ct);
            return Results.Ok(summary);
        })
        .WithName("GetBillingSummary")
        .WithSummary("Account billing summary and per-application breakdown (grain: daily, weekly, monthly)")
        .RequireIamAction("ReadBilling");

        group.MapGet("/billing/applications/{appId}", async (
            string appId,
            [FromQuery] string? grain,
            [FromQuery] DateTimeOffset? from,
            [FromQuery] DateTimeOffset? to,
            IBillingService billing,
            CancellationToken ct) =>
        {
            var result = await billing.GetApplicationBillingAsync(appId, ParseGrain(grain), from, to, ct);
            return result is not null
                ? Results.Ok(result)
                : Results.NotFound(new { error = "No billing history for that application." });
        })
        .WithName("GetApplicationBilling")
        .WithSummary("Billing detail for one application, bucketed at the requested grain")
        .RequireIamAction("ReadBilling");

        group.MapGet("/billing/export", async (
            [FromQuery] string? grain,
            [FromQuery] string? range,
            [FromQuery] string? format,
            [FromQuery] DateTimeOffset? from,
            [FromQuery] DateTimeOffset? to,
            HttpContext ctx,
            IBillingService billing,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var (windowFrom, windowTo, defaultGrain) = ResolveRange(range, from, to);
            var resolvedGrain = grain is null ? defaultGrain : ParseGrain(grain);
            var resolvedFormat = (format ?? "csv").Trim().ToLowerInvariant();

            // Exporting the whole account's spend is privileged; record it either way.
            await registry.RecordManagementActionAsync(
                Audit(ctx, "ExportBilling", "account", success: true,
                      $"grain={resolvedGrain}; format={resolvedFormat}"), ct);

            var stamp = DateTime.UtcNow.ToString("yyyyMMdd");
            var baseName = $"gateway-billing-{resolvedGrain.ToString().ToLowerInvariant()}-{stamp}";

            switch (resolvedFormat)
            {
                case "json":
                {
                    var summary = await billing.GetSummaryAsync(resolvedGrain, windowFrom, windowTo, ct);
                    return Results.Json(summary, contentType: "application/json",
                        statusCode: StatusCodes.Status200OK);
                }

                case "xlsx":
                case "excel":
                {
                    var workbook = await billing.ExportXlsxAsync(resolvedGrain, windowFrom, windowTo, ct);
                    return Results.File(workbook,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        baseName + ".xlsx");
                }

                default:
                {
                    var csv = await billing.ExportCsvAsync(resolvedGrain, windowFrom, windowTo, ct);
                    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", baseName + ".csv");
                }
            }
        })
        .WithName("ExportBilling")
        .WithSummary("Download billing rows as CSV, JSON, or a real .xlsx workbook")
        .RequireIamAction("ReadBilling");

        #endregion

        #region Guardrails

        group.MapGet("/guardrails/config", (IGuardrailService guardrailService) =>
        {
            return Results.Ok(guardrailService.GetCurrentOptions());
        })
        .WithName("GetGuardrailConfig")
        .WithSummary("Retrieve current enterprise safety guardrail rules and active mode")
        .RequireIamAction("ReadGuardrailConfig");

        group.MapPut("/guardrails/config", async (
            [FromBody] GuardrailOptions options,
            HttpContext ctx,
            IGuardrailService guardrailService,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var previous = guardrailService.GetCurrentOptions();

            // Record the policy change before applying it. A guardrail switched off silently
            // and reverted by a restart is precisely the case the audit trail has to survive.
            await registry.RecordManagementActionAsync(
                Audit(ctx, "UpdateGuardrailConfig", "gateway", success: true,
                      $"enabled {previous.Enabled} -> {options.Enabled}; mode {previous.Mode} -> {options.Mode}"), ct);

            guardrailService.UpdateOptions(options);

            return Results.Ok(new { message = "Guardrail configuration updated successfully", config = options });
        })
        .WithName("UpdateGuardrailConfig")
        .WithSummary("Update enterprise guardrail rules, PCI/PII detectors, and enforcement mode")
        .RequireIamAction("UpdateGuardrailConfig");

        group.MapPost("/guardrails/test", async (
            [FromBody] GuardrailTestRequest request,
            IGuardrailService guardrailService,
            CancellationToken ct) =>
        {
            var result = await guardrailService.EvaluateAsync(
                request.Input, modeOverride: request.Mode, cancellationToken: ct);

            return Results.Ok(result);
        })
        .WithName("TestGuardrails")
        .WithSummary("Interactive sandbox to test text against PCI, PII, Secrets, and Injection guardrails")
        .RequireIamAction("TestGuardrails");

        #endregion
    }
}

public static class IamActionEndpointExtensions
{
    /// <summary>
    /// Names the IAM action this endpoint requires. The configured access-control provider
    /// evaluates it — the simulator's IAM policy engine in TEST, IAM policy documents in PROD.
    /// </summary>
    public static RouteHandlerBuilder RequireIamAction(this RouteHandlerBuilder builder, string action)
        => builder.RequireAuthorization(policy =>
        {
            policy.AddAuthenticationSchemes(GatewayAuth.Scheme);
            policy.RequireAuthenticatedUser();
            policy.AddRequirements(new IamActionRequirement(action));
        });
}
