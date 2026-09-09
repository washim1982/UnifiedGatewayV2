using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Endpoints;

public static class GatewayEndpoints
{
    public static void MapGatewayEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/gateway")
            .WithTags("Gateway Invocation & STS Tokens");

        #region Application STS token endpoints

        // Exchange a long-term key for a short temporary secret.
        //
        // Rate-limited far more tightly than invocation: this endpoint searches every
        // registered application for a matching key hash, which makes it the natural
        // brute-force oracle if left open.
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
                    message = "Missing API key. Provide it in the 'apiKey' body property, the 'X-API-Key' header, or 'Authorization: Bearer <key>'."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var tokenResponse = await registryService.IssueStsTokenForAppAsync(
                body.AppId, apiKey, body.DurationSeconds, body.Scope, body.CallerId, ct);

            if (tokenResponse == null)
            {
                return Results.Json(new
                {
                    error = "UNAUTHORIZED",
                    message = "Invalid application API key or master admin key."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(tokenResponse);
        })
        .WithName("GenerateStsToken")
        .WithSummary("Exchange a long-term API key for a short temporary secret (STS token)")
        .Produces<AppStsTokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized)
        .RequireRateLimiting("token-issuance");

        group.MapPost("/sts/inspect", async (
            [FromBody] TokenInspectRequest? request,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            ISecurityService securityService,
            CancellationToken ct) =>
        {
            var token = !string.IsNullOrWhiteSpace(request?.Token)
                ? request.Token.Trim()
                : ExtractApiKey(xApiKey, authHeader);

            if (string.IsNullOrWhiteSpace(token))
            {
                return Results.BadRequest(new { error = "Missing token to inspect." });
            }

            var inspection = await securityService.InspectAppStsTokenAsync(token, ct);
            return Results.Ok(inspection);
        })
        .WithName("InspectStsToken")
        .WithSummary("Inspect claims, expiration, and validity of an application STS token")
        .Produces<AppStsInspectResponse>(StatusCodes.Status200OK)
        .RequireRateLimiting("token-issuance");

        #endregion

        #region Application invocation

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
                        Message = "Invalid, expired, or missing API key / STS token for this application."
                    }
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var response = await router.RouteAppRequestAsync(appId, request, ct);
            return ToHttpResult(response);
        })
        .WithName("InvokeApplication")
        .WithSummary("Invoke a registered AI application with auto-applied system prompt and model routing")
        .Produces<UniversalResponse>(StatusCodes.Status200OK)
        .Produces<UniversalResponse>(StatusCodes.Status401Unauthorized)
        .Produces<UniversalResponse>(StatusCodes.Status422UnprocessableEntity)
        .RequireRateLimiting("per-app");

        group.MapPost("/universal/invoke", async (
            [FromBody] UniversalRequest request,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            IOptions<GatewayOptions> options,
            ISecurityService securityService,
            IAdminCredentialService adminCredentials,
            IModelRouter router,
            CancellationToken ct) =>
        {
            if (options.Value.Security.EnforceAppApiKey)
            {
                var apiKey = ExtractApiKey(xApiKey, authHeader);
                var isAuthorized = false;

                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    if (apiKey.StartsWith("ug_sts_", StringComparison.Ordinal))
                    {
                        var (isStsValid, payload, _) = await securityService.ValidateAppStsTokenAsync(apiKey, ct);
                        isAuthorized = isStsValid && payload is { IsAdmin: true };
                    }
                    else
                    {
                        isAuthorized = await adminCredentials.VerifyAsync(apiKey, ct);
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
                            Message = "The universal endpoint requires a valid master admin key or admin STS token."
                        }
                    }, statusCode: StatusCodes.Status401Unauthorized);
                }
            }

            var response = await router.RouteAsync(request, ct);
            return ToHttpResult(response);
        })
        .WithName("InvokeUniversal")
        .WithSummary("Direct universal schema invocation with specified model and provider")
        .Produces<UniversalResponse>(StatusCodes.Status200OK)
        .Produces<UniversalResponse>(StatusCodes.Status401Unauthorized)
        .RequireRateLimiting("per-app");

        // Unauthenticated liveness only. Anything that reveals backend topology, role ARNs
        // or failure detail lives behind the authenticated management plane instead.
        group.MapGet("/health", () => Results.Ok(new
        {
            status = "Healthy",
            timestamp = DateTimeOffset.UtcNow
        }))
        .WithName("GatewayHealth")
        .WithSummary("Liveness probe");

        #endregion
    }

    /// <summary>
    /// Maps a gateway error code onto the HTTP status a client should actually see.
    /// Returning 200 for a blocked or failed request makes SDKs, load balancers and
    /// monitoring read enforcement and outages as success.
    /// </summary>
    internal static IResult ToHttpResult(UniversalResponse response)
    {
        if (response.Error is null)
        {
            return Results.Ok(response);
        }

        var status = response.Error.Code switch
        {
            "GUARDRAIL_BLOCKED" => StatusCodes.Status422UnprocessableEntity,
            "OUTPUT_GUARDRAIL_BLOCKED" => StatusCodes.Status422UnprocessableEntity,
            "OUTPUT_GUARDRAIL_ERROR" => StatusCodes.Status502BadGateway,
            "INPUT_TOO_LARGE" => StatusCodes.Status413PayloadTooLarge,
            "APP_NOT_FOUND" => StatusCodes.Status404NotFound,
            "APP_INACTIVE" => StatusCodes.Status409Conflict,
            "PRIMARY_PROVIDER_FAILED" => StatusCodes.Status502BadGateway,
            "ALL_PROVIDERS_FAILED" => StatusCodes.Status502BadGateway,
            "LOCAL_ENDPOINT_TIMEOUT" => StatusCodes.Status504GatewayTimeout,
            "LOCAL_ENDPOINT_UNAVAILABLE" => StatusCodes.Status502BadGateway,
            _ => StatusCodes.Status500InternalServerError
        };

        return Results.Json(response, statusCode: status);
    }

    private static string ExtractApiKey(string? xApiKey, string? authHeader)
    {
        if (!string.IsNullOrWhiteSpace(xApiKey))
            return xApiKey.Trim();

        if (!string.IsNullOrWhiteSpace(authHeader))
        {
            return authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? authHeader[7..].Trim()
                : authHeader.Trim();
        }

        return string.Empty;
    }
}

public record TokenInspectRequest
{
    public string? Token { get; init; }
}
