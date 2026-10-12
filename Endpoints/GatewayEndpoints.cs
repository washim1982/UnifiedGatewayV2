using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Cloud;
using UnifiedGateway.Services.Mcp;

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
            HttpContext ctx,
            IApplicationRegistryService registryService,
            ICallerQuota quota,
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

            AppStsTokenResponse? tokenResponse;
            try
            {
                // The source address goes into the audit record of the issuance, so a token --
                // above all a break-glass one -- can be traced to where it was requested from.
                tokenResponse = await registryService.IssueStsTokenForAppAsync(
                    body.AppId, apiKey, body.DurationSeconds, body.Scope, body.CallerId,
                    ctx.Connection.RemoteIpAddress?.ToString(), ct);
            }
            catch (ArgumentException ex)
            {
                // A bad scope or callerId is the caller asking for something the gateway will
                // not issue, not a server fault. Say which, plainly.
                var code = ex.ParamName == "callerId" ? "INVALID_CALLER_ID" : "INVALID_SCOPE";
                return Results.BadRequest(new { error = code, message = ex.Message });
            }

            if (tokenResponse == null)
            {
                return Results.Json(new
                {
                    error = "UNAUTHORIZED",
                    message = "Invalid application API key or master admin key."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            // Which application a key belongs to is only known once it verifies, so the quota is
            // checked after minting: an application over its issuance quota gets 429 from any
            // address, and the token it would have received is never released (SEC-03).
            if (!quota.TryAcquireIssuance(tokenResponse.IsAdmin ? "break-glass" : tokenResponse.AppId))
            {
                return QuotaExceeded(ctx);
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
            HttpContext ctx,
            IApplicationRegistryService registryService,
            IModelRouter router,
            ICallerQuota quota,
            CancellationToken ct) =>
        {
            var apiKey = ExtractApiKey(xApiKey, authHeader);
            var (isValid, appConfig, caller) = await registryService.AuthenticateAppAsync(appId, apiKey, ct);

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

            // Every key and STS token of this application draws on one quota (SEC-03).
            if (!quota.TryAcquireInvocation(appConfig.AppId))
            {
                return QuotaExceeded(ctx);
            }

            var response = await router.RouteAppRequestAsync(
                appId, request, WithRequestDetail(caller, ctx), ct);
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
            HttpContext ctx,
            IOptions<GatewayOptions> options,
            IOptions<CloudOptions> cloudOptions,
            ISecurityService securityService,
            IAdminCredentialService adminCredentials,
            IModelRouter router,
            ICallerQuota quota,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            CallerContext? caller = null;
            var breakGlassLog = loggerFactory.CreateLogger("UnifiedGateway.BreakGlass");

            if (options.Value.Security.EnforceAppApiKey)
            {
                var apiKey = ExtractApiKey(xApiKey, authHeader);
                var isAuthorized = false;

                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    if (apiKey.StartsWith("ug_sts_", StringComparison.Ordinal))
                    {
                        var (isStsValid, payload, _) = await securityService.ValidateAppStsTokenAsync(apiKey, ct);

                        // Admin flag AND admin scope. A token can be minted by an admin and
                        // still be scoped down; the narrower of the two has to win.
                        isAuthorized = isStsValid
                            && payload is { IsAdmin: true }
                            && SecurityService.ScopePermits(payload.Scope, GatewayScopes.Admin);

                        if (isAuthorized)
                        {
                            breakGlassLog.LogWarning(
                                "BREAK-GLASS: admin STS token {Jti} used on the universal endpoint from {RemoteIp}.",
                                payload!.Jti, ctx.Connection.RemoteIpAddress);

                            caller = new CallerContext
                            {
                                Actor = CallerContext.ActorFor(payload!),
                                AuthType = "AdminStsToken",
                                TokenId = payload!.Jti
                            };
                        }
                    }
                    else
                    {
                        isAuthorized = await adminCredentials.VerifyAsync(apiKey, ct);
                        if (isAuthorized)
                        {
                            breakGlassLog.LogWarning(
                                "BREAK-GLASS: master admin credential used on the universal endpoint from {RemoteIp}.",
                                ctx.Connection.RemoteIpAddress);

                            caller = new CallerContext { Actor = "break-glass", AuthType = "MasterAdminKey" };
                        }
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

            if (!quota.TryAcquireInvocation(
                    UniversalQuotaIdentity(cloudOptions.Value.AccessControl.BreakGlassPrincipalArn)))
            {
                return QuotaExceeded(ctx);
            }

            var response = await router.RouteAsync(request, WithRequestDetail(caller, ctx), ct);
            return ToHttpResult(response);
        })
        .WithName("InvokeUniversal")
        .WithSummary("Direct universal schema invocation with specified model and provider")
        .Produces<UniversalResponse>(StatusCodes.Status200OK)
        .Produces<UniversalResponse>(StatusCodes.Status401Unauthorized)
        .RequireRateLimiting("per-app");

        // Tool execution.
        //
        // Deliberately not folded into invoke: calling a tool is not answering a question, and a
        // credential minted for one should not be able to do the other. The application must have
        // the tool attached, the credential must carry tools:execute, and the result goes through
        // the egress guardrails before the caller sees it.
        group.MapPost("/{appId}/tools/{tool}", async (
            string appId,
            string tool,
            [FromBody] JsonElement arguments,
            [FromHeader(Name = "X-API-Key")] string? xApiKey,
            [FromHeader(Name = "Authorization")] string? authHeader,
            HttpContext ctx,
            IApplicationRegistryService registryService,
            IToolCatalog toolCatalog,
            ICallerQuota quota,
            CancellationToken ct) =>
        {
            var apiKey = ExtractApiKey(xApiKey, authHeader);
            var (isValid, appConfig, caller) = await registryService.AuthenticateAppAsync(appId, apiKey, ct);

            if (!isValid || appConfig == null)
            {
                return Results.Json(new
                {
                    error = "UNAUTHORIZED",
                    message = "Invalid, expired, or missing API key / STS token for this application."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!SecurityService.ScopePermits(caller?.Scope, GatewayScopes.ToolsExecute))
            {
                return Results.Json(new
                {
                    error = "SCOPE_INSUFFICIENT",
                    message = $"This credential does not carry the '{GatewayScopes.ToolsExecute}' scope. " +
                              "Mint a token with it to call tools."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (!quota.TryAcquireInvocation(appConfig.AppId))
            {
                return QuotaExceeded(ctx);
            }

            try
            {
                var result = await toolCatalog.ExecuteAsync(appConfig, tool, arguments, ct);

                await registryService.RecordManagementActionAsync(
                    ToolAudit(caller, ctx, appId, tool, arguments, success: !result.IsError,
                        $"sideEffect={result.SideEffect}; guardrail={result.GuardrailAction}; {result.LatencyMs}ms"), ct);

                return Results.Ok(result);
            }
            catch (ToolRefusedException ex)
            {
                await registryService.RecordManagementActionAsync(
                    ToolAudit(caller, ctx, appId, tool, arguments, success: false, ex.Message), ct);

                return Results.Json(new { error = "TOOL_REFUSED", message = ex.Message },
                    statusCode: StatusCodes.Status403Forbidden);
            }
        })
        .WithName("ExecuteTool")
        .WithSummary("Call a tool attached to this application")
        .Produces<ToolCallResult>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status403Forbidden)
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
    /// Quota identity for the universal endpoint (SEC-03).
    ///
    /// <see cref="CallerContext.Actor"/> carries the minter's chosen callerId as a label, so keying
    /// a quota on it lets one principal split its own quota by relabelling its tokens. Both
    /// credentials this endpoint accepts -- an admin STS token and the master key -- act as the
    /// configured break-glass principal, so that is the identity the quota follows.
    /// </summary>
    public static string UniversalQuotaIdentity(string? breakGlassPrincipalArn) =>
        "universal:" + (string.IsNullOrWhiteSpace(breakGlassPrincipalArn)
            ? "break-glass"
            : breakGlassPrincipalArn.Trim());

    /// <summary>
    /// An audit record for one tool call. The arguments are hashed rather than recorded: they are
    /// caller content and can carry anything, but a hash still ties an approval, a result and a
    /// complaint to the same call.
    /// </summary>
    private static ManagementAuditEntry ToolAudit(
        CallerContext? caller, HttpContext ctx, string appId, string tool, JsonElement arguments,
        bool success, string? detail)
    {
        var raw = arguments.ValueKind == JsonValueKind.Undefined ? "{}" : arguments.GetRawText();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)))[..16].ToLowerInvariant();

        return new ManagementAuditEntry
        {
            Action = "ExecuteTool",
            Resource = $"{appId}/{tool}",
            Actor = caller?.Actor,
            AuthType = caller?.AuthType,
            TokenId = caller?.TokenId,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString(),
            Success = success,
            Detail = $"args={hash}; {detail}"
        };
    }

    /// <summary>The same 429 the pre-authentication limiters return, for a spent per-application quota.</summary>
    internal static IResult QuotaExceeded(HttpContext ctx)
    {
        ctx.Response.Headers.RetryAfter = "60";
        return Results.Json(new
        {
            error = new
            {
                code = "RATE_LIMITED",
                message = "Rate limit exceeded for this application. Please retry after the window resets."
            }
        }, statusCode: StatusCodes.Status429TooManyRequests);
    }

    /// <summary>
    /// Completes an authenticated caller with the details only the request knows: source
    /// address and correlation id. The id is echoed to the caller on failure, so a support
    /// conversation and the audit record start from the same reference.
    /// </summary>
    private static CallerContext WithRequestDetail(CallerContext? caller, HttpContext ctx)
    {
        var trace = ctx.TraceIdentifier is { Length: > 0 } id ? id : Guid.NewGuid().ToString("N");

        return (caller ?? CallerContext.Anonymous()) with
        {
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString(),
            TraceId = trace
        };
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
            "LOCAL_BACKEND_DISABLED" => StatusCodes.Status502BadGateway,
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
