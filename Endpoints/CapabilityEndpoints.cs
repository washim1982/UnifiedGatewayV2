using Microsoft.AspNetCore.Mvc;
using UnifiedGateway.Auth;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Mcp;

namespace UnifiedGateway.Endpoints;

/// <summary>
/// The capability catalogue, and the per-application bindings that draw on it.
///
/// Two privileges, deliberately separate. Registering a capability decides what the platform
/// offers (<c>ManageSkills</c> here; <c>ManageMcpServers</c> and <c>ManagePlugins</c> when those
/// arrive, since they run code). Attaching one to an application only uses what someone already
/// vetted (<c>ManageAppCapabilities</c>). That split is what stops an application owner from
/// introducing executable surface of their own.
/// </summary>
public static class CapabilityEndpoints
{
    public static void MapCapabilityEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api")
            .WithTags("Capabilities (skills, tools, agents, plugins)")
            .RequireAuthorization(GatewayAuth.PlatformAdminPolicy)
            .RequireRateLimiting("management");

        #region Skill catalogue

        group.MapGet("/skills", async (ISkillRegistryService skills, CancellationToken ct) =>
        {
            // The list is a catalogue view: descriptions and versions, not bodies.
            var all = await skills.ListAsync(ct);
            return Results.Ok(all.Select(s => new
            {
                s.SkillId, s.Name, s.Description, s.Version, s.IsActive, s.Checksum, s.UpdatedAt,
                bodyCharacters = s.Body.Length
            }));
        })
        .WithName("ListSkills")
        .WithSummary("Registered skills: instruction sets an application can be given")
        .RequireIamAction("ListCapabilities");

        group.MapGet("/skills/{skillId}", async (string skillId, ISkillRegistryService skills, CancellationToken ct) =>
        {
            var skill = await skills.GetAsync(skillId, ct);
            return skill is null ? Results.NotFound(new { error = "Skill not found" }) : Results.Ok(skill);
        })
        .WithName("GetSkill")
        .WithSummary("One skill, with its body and version history")
        .RequireIamAction("ListCapabilities");

        group.MapPost("/skills", async (
            [FromBody] CreateSkillRequest request,
            HttpContext ctx,
            ISkillRegistryService skills,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            try
            {
                var skill = await skills.CreateAsync(request, ct);
                await registry.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "RegisterSkill", skill.SkillId, success: true,
                        $"version={skill.Version}; checksum={skill.Checksum[..12]}"), ct);

                return Results.Created($"/api/skills/{skill.SkillId}", skill);
            }
            catch (SkillRejectedException ex)
            {
                await registry.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "RegisterSkill", request.SkillId, success: false, ex.Message), ct);

                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("RegisterSkill")
        .WithSummary("Register a skill. Its content is guardrail-checked before it is stored.")
        .RequireIamAction("ManageSkills");

        group.MapPut("/skills/{skillId}", async (
            string skillId,
            [FromBody] UpdateSkillRequest request,
            HttpContext ctx,
            ISkillRegistryService skills,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            try
            {
                var skill = await skills.UpdateAsync(skillId, request, ct);
                if (skill is null)
                {
                    return Results.NotFound(new { error = "Skill not found" });
                }

                await registry.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "UpdateSkill", skillId, success: true,
                        $"version={skill.Version}; active={skill.IsActive}"), ct);

                return Results.Ok(skill);
            }
            catch (SkillRejectedException ex)
            {
                await registry.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "UpdateSkill", skillId, success: false, ex.Message), ct);

                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("UpdateSkill")
        .WithSummary("Change a skill. A content change is a new version; pinned bindings keep the old one.")
        .RequireIamAction("ManageSkills");

        group.MapDelete("/skills/{skillId}", async (
            string skillId,
            HttpContext ctx,
            ISkillRegistryService skills,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var removed = await skills.DeleteAsync(skillId, ct);
            if (!removed)
            {
                return Results.NotFound(new { error = "Skill not found" });
            }

            await registry.RecordManagementActionAsync(
                DashboardEndpoints.Audit(ctx, "DeleteSkill", skillId, success: true), ct);

            return Results.Ok(new
            {
                message = $"Skill '{skillId}' deleted.",
                warning = "Applications that pinned it keep the binding, which now resolves to nothing."
            });
        })
        .WithName("DeleteSkill")
        .RequireIamAction("ManageSkills");

        #endregion

        #region MCP servers

        group.MapGet("/mcp-servers", async (IMcpServerRegistry registry, CancellationToken ct) =>
            Results.Ok(await registry.ListAsync(ct)))
        .WithName("ListMcpServers")
        .WithSummary("Registered MCP servers")
        .RequireIamAction("ReadMcpServers");

        group.MapGet("/mcp-servers/{serverId}/tools", async (
            string serverId,
            [FromQuery] bool refresh,
            IMcpServerRegistry registry,
            IToolCatalog catalog,
            CancellationToken ct) =>
        {
            if (await registry.GetAsync(serverId, ct) is null)
            {
                return Results.NotFound(new { error = "MCP server not found" });
            }

            try
            {
                return Results.Ok(await catalog.ListAsync(serverId, refresh, ct));
            }
            catch (Exception ex)
            {
                // Probing is how an operator finds out a server is misconfigured, so the reason
                // is the useful part of the answer.
                return Results.Json(new { error = $"The server could not be reached: {ex.Message}" },
                    statusCode: StatusCodes.Status502BadGateway);
            }
        })
        .WithName("ListMcpServerTools")
        .WithSummary("Tools a server publishes, fetched live with ?refresh=true")
        .RequireIamAction("ReadMcpServers");

        group.MapPost("/mcp-servers", async (
            [FromBody] CreateMcpServerRequest request,
            HttpContext ctx,
            IMcpServerRegistry registry,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            try
            {
                var server = await registry.CreateAsync(request, ct);
                await apps.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "RegisterMcpServer", server.ServerId, success: true,
                        $"{server.Transport} {server.Url}; defaultSideEffect={server.DefaultSideEffect}"), ct);

                return Results.Created($"/api/mcp-servers/{server.ServerId}", server);
            }
            catch (McpServerRejectedException ex)
            {
                await apps.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "RegisterMcpServer", request.ServerId, success: false, ex.Message), ct);

                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("RegisterMcpServer")
        .WithSummary("Register an MCP server. Its tools execute outside this gateway.")
        .RequireIamAction("ManageMcpServers");

        group.MapPut("/mcp-servers/{serverId}", async (
            string serverId,
            [FromBody] UpdateMcpServerRequest request,
            HttpContext ctx,
            IMcpServerRegistry registry,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            try
            {
                var server = await registry.UpdateAsync(serverId, request, ct);
                if (server is null)
                {
                    return Results.NotFound(new { error = "MCP server not found" });
                }

                await apps.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "UpdateMcpServer", serverId, success: true,
                        $"active={server.IsActive}; url={server.Url}"), ct);

                return Results.Ok(server);
            }
            catch (McpServerRejectedException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        })
        .WithName("UpdateMcpServer")
        .RequireIamAction("ManageMcpServers");

        group.MapDelete("/mcp-servers/{serverId}", async (
            string serverId,
            HttpContext ctx,
            IMcpServerRegistry registry,
            IApplicationRegistryService apps,
            CancellationToken ct) =>
        {
            if (!await registry.DeleteAsync(serverId, ct))
            {
                return Results.NotFound(new { error = "MCP server not found" });
            }

            await apps.RecordManagementActionAsync(
                DashboardEndpoints.Audit(ctx, "DeleteMcpServer", serverId, success: true), ct);

            return Results.Ok(new
            {
                message = $"MCP server '{serverId}' deleted.",
                warning = "Applications bound to its tools keep bindings that no longer resolve."
            });
        })
        .WithName("DeleteMcpServer")
        .RequireIamAction("ManageMcpServers");

        group.MapGet("/tools", async (IToolCatalog catalog, CancellationToken ct) =>
            Results.Ok(await catalog.ListAllAsync(ct)))
        .WithName("ListTools")
        .WithSummary("Every tool published by every active MCP server")
        .RequireIamAction("ListCapabilities");

        #endregion

        #region Catalogue

        group.MapGet("/capabilities", async (
            ISkillRegistryService skills,
            IMcpServerRegistry servers,
            IToolCatalog catalog,
            CancellationToken ct) =>
        {
            var all = await skills.ListAsync(ct);
            var registered = (await servers.ListAsync(ct)).Where(s => s.IsActive).ToList();
            var tools = await catalog.ListAllAsync(ct);

            // One shape for every kind, so the dashboard picker does not change as catalogues
            // arrive. Kinds with no catalogue yet are reported rather than omitted silently.
            return Results.Ok(new
            {
                skills = all.Where(s => s.IsActive).Select(s => new
                {
                    kind = CapabilityKind.Skill.ToString(),
                    @ref = s.SkillId,
                    s.Name,
                    s.Description,
                    s.Version
                }),
                tools = tools.Select(t => new
                {
                    kind = CapabilityKind.Tool.ToString(),
                    @ref = t.Name,
                    name = t.Name,
                    t.Description,
                    t.SideEffect,
                    version = 1
                }),
                mcpServers = registered.Select(s => new
                {
                    kind = CapabilityKind.McpServer.ToString(),
                    @ref = s.ServerId,
                    s.Name,
                    s.Description,
                    s.DefaultSideEffect,
                    version = 1
                }),
                agents = Array.Empty<object>(),
                plugins = Array.Empty<object>(),
                unavailable = new[] { "Agent", "Plugin" }
            });
        })
        .WithName("ListCapabilityCatalog")
        .WithSummary("Everything an application may be given, by kind")
        .RequireIamAction("ListCapabilities");

        #endregion

        #region Application bindings

        group.MapGet("/apps/{appId}/capabilities", async (
            string appId,
            IApplicationRegistryService registry,
            ICapabilityService capabilities,
            CancellationToken ct) =>
        {
            var application = await registry.GetAppAsync(appId, ct);
            if (application is null)
            {
                return Results.NotFound(new { error = "Application not found" });
            }

            return Results.Ok(await capabilities.EffectiveAsync(application, ct));
        })
        .WithName("ListApplicationCapabilities")
        .WithSummary("What this application may use, each binding resolved against the catalogue")
        .RequireIamAction("GetApplication");

        group.MapPost("/apps/{appId}/capabilities", async (
            string appId,
            [FromBody] AttachCapabilityRequest request,
            HttpContext ctx,
            IApplicationRegistryService registry,
            ICapabilityService capabilities,
            CancellationToken ct) =>
        {
            var application = await registry.GetAppAsync(appId, ct);
            if (application is null)
            {
                return Results.NotFound(new { error = "Application not found" });
            }

            CapabilityBinding binding;
            try
            {
                binding = await capabilities.ResolveAttachmentAsync(
                    application, request, ctx.User.FindFirst(GatewayAuth.PrincipalArnClaim)?.Value, ct);
            }
            catch (CapabilityRejectedException ex)
            {
                await registry.RecordManagementActionAsync(
                    DashboardEndpoints.Audit(ctx, "AttachCapability", appId, success: false,
                        $"{request.Kind}:{request.Ref}; {ex.Message}"), ct);

                return Results.BadRequest(new { error = ex.Message });
            }

            var updated = await registry.AttachCapabilityAsync(appId, binding, ct);

            await registry.RecordManagementActionAsync(
                DashboardEndpoints.Audit(ctx, "AttachCapability", appId, success: true,
                    $"{binding.Kind}:{binding.Ref} v{binding.Version}; binding={binding.Id}"), ct);

            return Results.Created($"/api/apps/{appId}/capabilities", new
            {
                binding,
                capabilities = updated?.Capabilities.Count ?? 0
            });
        })
        .WithName("AttachApplicationCapability")
        .WithSummary("Attach a catalogue capability to an application at a pinned version")
        .RequireIamAction("ManageAppCapabilities");

        group.MapDelete("/apps/{appId}/capabilities/{bindingId}", async (
            string appId,
            string bindingId,
            HttpContext ctx,
            IApplicationRegistryService registry,
            CancellationToken ct) =>
        {
            var detached = await registry.DetachCapabilityAsync(appId, bindingId, ct);
            if (!detached)
            {
                return Results.NotFound(new { error = "No such application or binding" });
            }

            await registry.RecordManagementActionAsync(
                DashboardEndpoints.Audit(ctx, "DetachCapability", appId, success: true, $"binding={bindingId}"), ct);

            return Results.Ok(new { message = "Capability detached." });
        })
        .WithName("DetachApplicationCapability")
        .RequireIamAction("ManageAppCapabilities");

        #endregion
    }
}
