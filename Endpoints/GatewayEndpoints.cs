using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;

namespace UnifiedGateway.Endpoints;

public static class GatewayEndpoints
{
    public static void MapGatewayEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/gateway")
            .WithTags("Gateway Invocation & STS Tokens");

        #region Application STS Token Endpoints

        // Exchange long-term Application API Key or Master Admin Key for Short Temporary Secret (STS Token)
        group.MapPost("/sts/token", async (
            [FromBody] AppStsTokenRequest? request,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            IApplicationRegistryService registryService,
            CancellationToken ct) =>
        {
            var body = request ?? new AppStsTokenRequest();
            var apiKey = !string.IsNullOrWhiteSpace(body.ApiKey)
                ? body.ApiKey.Trim()
                : ExtractApiKey(xApiKey, authHeader);

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                return Results.Json(new
                {
                    error = "UNAUTHORIZED",
                    message = "Missing API key. Provide long-term key in 'apiKey' body property, 'X-API-Key' header, or 'Authorization: Bearer <key>'."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var tokenResponse = await registryService.IssueStsTokenForAppAsync(
                body.AppId,
                apiKey,
                body.DurationSeconds,
                body.Scope,
                body.CallerId,
                ct);

            if (tokenResponse == null)
            {
                return Results.Json(new
                {
                    error = "UNAUTHORIZED",
                    message = "Invalid Application API Key or Master Admin Key provided for STS token generation."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(tokenResponse);
        })
        .WithName("GenerateStsToken")
        .WithSummary("Exchange a long-term API key for a short temporary secret (STS token) with custom TTL")
        .Produces<AppStsTokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized);

        // Inspect and decode an STS token claims & remaining TTL
        group.MapPost("/sts/inspect", (
            [FromBody] TokenInspectRequest? request,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            ISecurityService securityService) =>
        {
            var token = !string.IsNullOrWhiteSpace(request?.Token)
                ? request.Token.Trim()
                : ExtractApiKey(xApiKey, authHeader);

            if (string.IsNullOrWhiteSpace(token))
            {
                return Results.BadRequest(new { error = "Missing token to inspect." });
            }

            var inspection = securityService.InspectAppStsToken(token);
            return Results.Ok(inspection);
        })
        .WithName("InspectStsToken")
        .WithSummary("Inspect decoded claims, expiration, and validity of an Application STS token")
        .Produces<AppStsInspectResponse>(StatusCodes.Status200OK);

        #endregion

        #region Application Invocation Endpoints

        // Per-application generated endpoint (Accepts long-term API key OR short-term STS token)
        group.MapPost("/{appId}/invoke", async (
            string appId,
            [FromBody] InvokeAppRequest request,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            IApplicationRegistryService registryService,
            IModelRouter router,
            CancellationToken ct) =>
        {
            var apiKey = ExtractApiKey(xApiKey, authHeader);
            var (isValid, appConfig) = await registryService.AuthenticateAppAsync(appId, apiKey, ct);

            if (!isValid || appConfig == null)
            {
                return Results.Json(new UniversalResponse
                {
                    Output = string.Empty,
                    AppId = appId,
                    Error = new GatewayError
                    {
                        Code = "UNAUTHORIZED",
                        Message = "Invalid, expired, or missing API key / STS token for this application. Pass via 'X-API-Key' or 'Authorization: Bearer <token>'."
                    }
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var response = await router.RouteAppRequestAsync(appId, request, ct);
            return Results.Ok(response);
        })
        .WithName("InvokeApplication")
        .WithSummary("Invoke a registered AI application with auto-applied system prompt and model routing")
        .Produces<UniversalResponse>(StatusCodes.Status200OK)
        .Produces<UniversalResponse>(StatusCodes.Status401Unauthorized)
        .Produces<UniversalResponse>(StatusCodes.Status404NotFound)
        .RequireRateLimiting("per-app");

        // Universal direct endpoint for admin/orchestrators (Accepts Admin Master API Key OR Admin STS Token)
        group.MapPost("/universal/invoke", async (
            [FromBody] UniversalRequest request,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            IOptions<GatewayOptions> options,
            ISecurityService securityService,
            IModelRouter router,
            CancellationToken ct) =>
        {
            var apiKey = ExtractApiKey(xApiKey, authHeader);
            var expectedKey = options.Value.Security.AdminApiKey;

            if (options.Value.Security.EnforceAppApiKey)
            {
                var isAuthorized = false;

                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    if (apiKey.StartsWith("ug_sts_", StringComparison.OrdinalIgnoreCase))
                    {
                        var (isStsValid, payload, _) = securityService.ValidateAppStsToken(apiKey);
                        if (isStsValid && payload != null && payload.IsAdmin)
                        {
                            isAuthorized = true;
                        }
                    }
                    else
                    {
                        isAuthorized = securityService.VerifyKey(apiKey, securityService.HashKey(expectedKey));
                    }
                }

                if (!isAuthorized)
                {
                    return Results.Json(new UniversalResponse
                    {
                        Output = string.Empty,
                        Error = new GatewayError
                        {
                            Code = "ADMIN_UNAUTHORIZED",
                            Message = "Universal endpoint requires a valid Master Admin API Key or Admin STS Token."
                        }
                    }, statusCode: StatusCodes.Status401Unauthorized);
                }
            }

            var response = await router.RouteAsync(request, ct);
            return Results.Ok(response);
        })
        .WithName("InvokeUniversal")
        .WithSummary("Direct universal schema invocation with specified model and provider")
        .Produces<UniversalResponse>(StatusCodes.Status200OK)
        .Produces<UniversalResponse>(StatusCodes.Status401Unauthorized)
        .RequireRateLimiting("per-app");

        // Gateway health & backend status check
        group.MapGet("/health", async (
            ISTSService stsService,
            ILocalModelService localModelService,
            CancellationToken ct) =>
        {
            var awsStatus = await stsService.GetStatusAsync(ct);
            var localStatus = await localModelService.ProbeStatusAsync(ct);

            var isHealthy = awsStatus.IsInitialized || localStatus.Values.Any(v => v);

            return Results.Ok(new
            {
                status = isHealthy ? "Healthy" : "Degraded",
                timestamp = DateTimeOffset.UtcNow,
                aws = awsStatus,
                localBackends = localStatus
            });
        })
        .WithName("GatewayHealth")
        .WithSummary("Probe STS credentials and local backend health");

        #endregion
    }

    private static string ExtractApiKey(string? xApiKey, string? authHeader)
    {
        if (!string.IsNullOrWhiteSpace(xApiKey))
            return xApiKey.Trim();

        if (!string.IsNullOrWhiteSpace(authHeader))
        {
            if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return authHeader[7..].Trim();
            return authHeader.Trim();
        }

        return string.Empty;
    }
}

public record TokenInspectRequest
{
    public string? Token { get; init; }
}
