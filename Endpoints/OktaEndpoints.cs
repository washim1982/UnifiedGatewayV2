using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Auth;
using UnifiedGateway.Services.Okta;

namespace UnifiedGateway.Endpoints;

public record OktaSignInRequest
{
    public string? Username { get; init; }
    public string? Password { get; init; }
}

public static class OktaEndpoints
{
    /// <summary>
    /// Endpoints of the simulated Okta authorization server. Paths mirror a real Okta org so
    /// a client library, or the dashboard, needs only a base-URL change to point at the real
    /// thing. Mapped only when the simulator is enabled.
    /// </summary>
    public static void MapOktaSimulatorEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/okta/oauth2/v1")
            .WithTags("Okta Simulator (local identity provider)");

        // Sign-in. Real Okta would use the authorization-code flow; a password grant is
        // enough here and keeps the local developer loop to a single call.
        group.MapPost("/token", (
            [FromBody] OktaSignInRequest request,
            IOptions<OktaOptions> options,
            IOktaTokenService tokens) =>
        {
            if (!options.Value.Enabled)
            {
                return Results.NotFound(new { error = "The Okta simulator is disabled in this environment." });
            }

            var result = tokens.IssueToken(request.Username ?? string.Empty, request.Password ?? string.Empty);
            if (result is null)
            {
                // One message for both failure modes: never reveal which half was wrong.
                return Results.Json(new
                {
                    error = "invalid_grant",
                    error_description = "Authentication failed. Check the username and password."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new
            {
                access_token = result.AccessToken,
                token_type = result.TokenType,
                expires_in = result.ExpiresIn,
                scope = result.Scope,
                email = result.Email,
                groups = result.Groups
            });
        })
        .WithName("OktaSimulatorToken")
        .WithSummary("Exchange directory credentials for a signed OIDC access token")
        .RequireRateLimiting("token-issuance");

        // Public keys, so the gateway (or anything else) can verify the signature.
        group.MapGet("/keys", (IOktaTokenService tokens) => Results.Ok(tokens.GetJwks()))
            .WithName("OktaSimulatorJwks")
            .WithSummary("JWKS document for the simulated authorization server");

        group.MapGet("/userinfo", (HttpContext ctx) =>
        {
            if (ctx.User.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }

            return Results.Ok(new
            {
                sub = ctx.User.FindFirst("sub")?.Value,
                email = ctx.User.FindFirst("email")?.Value,
                name = ctx.User.FindFirst("name")?.Value,
                groups = ctx.User.FindAll(OktaClaims.Groups).Select(c => c.Value).ToArray()
            });
        })
        .WithName("OktaSimulatorUserInfo")
        .WithSummary("Claims of the currently authenticated user")
        .RequireAuthorization();

        // Directory listing. Useful locally to see who exists and which groups they are in;
        // it deliberately exposes no password material.
        group.MapGet("/directory", (IOptions<OktaOptions> options) => Results.Ok(new
        {
            groups = OktaDirectory.Groups.Select(g => new
            {
                g.Id,
                g.Name,
                g.Description,
                mappedRole = options.Value.GroupRoleMappings.TryGetValue(g.Name, out var arn) ? arn : null,
                members = OktaDirectory.Users
                    .Where(u => u.GroupNames.Contains(g.Name, StringComparer.OrdinalIgnoreCase))
                    .Select(u => u.Email)
                    .ToArray()
            }),
            users = OktaDirectory.Users.Select(u => new
            {
                u.Id,
                u.Email,
                u.DisplayName,
                u.IsActive,
                groups = u.GroupNames
            })
        }))
        .WithName("OktaSimulatorDirectory")
        .WithSummary("Hard-coded users, groups, and group membership");

        app.MapGet("/okta/.well-known/openid-configuration", (
            HttpContext ctx,
            IOktaTokenService tokens) =>
        {
            var baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
            return Results.Ok(tokens.GetDiscoveryDocument(baseUrl));
        })
        .WithName("OktaSimulatorDiscovery")
        .WithTags("Okta Simulator (local identity provider)");
    }
}
