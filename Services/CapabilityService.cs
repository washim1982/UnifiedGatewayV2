using System.Text;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Mcp;

namespace UnifiedGateway.Services;

public interface ICapabilityService
{
    /// <summary>Each binding resolved against the catalogue, including ones that no longer resolve.</summary>
    Task<List<CapabilityView>> EffectiveAsync(AppConfig app, CancellationToken cancellationToken = default);

    /// <summary>
    /// The application's system prompt with its attached skills composed in: every usable skill as
    /// a one-line index entry, and the full body of each skill the request asked for.
    /// </summary>
    Task<string> ComposeSystemPromptAsync(
        AppConfig app, IReadOnlyCollection<string>? requestedSkills, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates an attach request against the catalogue and returns the binding to store.
    /// Throws <see cref="CapabilityRejectedException"/> rather than storing something unusable.
    /// </summary>
    Task<CapabilityBinding> ResolveAttachmentAsync(
        AppConfig app, AttachCapabilityRequest request, string? attachedBy, CancellationToken cancellationToken = default);
}

public class CapabilityRejectedException(string message) : Exception(message);

/// <summary>
/// Resolves what an application may actually use.
///
/// A binding is a pin, not a guarantee: the catalogue entry behind it can be disabled or deleted
/// after the fact. Resolution happens per request, and anything that no longer resolves is left
/// out of the prompt and reported as unusable rather than failing the call -- an application does
/// not stop answering because a skill was retired.
/// </summary>
/// <param name="servers">MCP catalogue. Absent in tests that exercise skills alone.</param>
/// <param name="tools">Tool catalogue, read from the servers above.</param>
public class CapabilityService(
    ISkillRegistryService skills,
    ILogger<CapabilityService> logger,
    IMcpServerRegistry? servers = null,
    IToolCatalog? tools = null) : ICapabilityService
{
    public async Task<List<CapabilityView>> EffectiveAsync(AppConfig app, CancellationToken cancellationToken = default)
    {
        var views = new List<CapabilityView>();

        foreach (var binding in app.Capabilities)
        {
            views.Add(binding.Kind switch
            {
                CapabilityKind.Skill => await ResolveSkillAsync(binding, cancellationToken),
                CapabilityKind.McpServer => await ResolveServerAsync(binding, cancellationToken),
                CapabilityKind.Tool => await ResolveToolAsync(binding, cancellationToken),
                _ => Unusable(binding, $"{binding.Kind} capabilities are not supported by this gateway yet.")
            });
        }

        return views;
    }

    public async Task<string> ComposeSystemPromptAsync(
        AppConfig app, IReadOnlyCollection<string>? requestedSkills, CancellationToken cancellationToken = default)
    {
        var bound = app.Capabilities
            .Where(b => b.Kind == CapabilityKind.Skill && b.Enabled)
            .ToList();

        if (bound.Count == 0)
        {
            return app.SystemPrompt;
        }

        var requested = new HashSet<string>(
            requestedSkills ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

        var index = new List<string>();
        var bodies = new List<string>();

        foreach (var binding in bound)
        {
            var snapshot = await ResolveSnapshotAsync(binding, cancellationToken);
            if (snapshot is null)
            {
                continue;
            }

            index.Add($"- {binding.Ref} (v{snapshot.Version}): {snapshot.Description}");

            // Progressive disclosure: the description always, the body only when asked for. Ten
            // attached skills cost ten lines until one of them is actually used.
            if (requested.Contains(binding.Ref) && !string.IsNullOrWhiteSpace(snapshot.Body))
            {
                bodies.Add($"## Skill: {snapshot.Name} ({binding.Ref} v{snapshot.Version})\n{snapshot.Body.Trim()}");
            }
        }

        if (index.Count == 0)
        {
            return app.SystemPrompt;
        }

        var composed = new StringBuilder(app.SystemPrompt.TrimEnd());
        composed.AppendLine().AppendLine();
        composed.AppendLine("## Available skills");
        composed.AppendLine("Instruction sets attached to this application. They describe how to answer; they grant no tools or other access.");
        composed.AppendLine(string.Join(Environment.NewLine, index));

        foreach (var body in bodies)
        {
            composed.AppendLine().AppendLine(body);
        }

        foreach (var missing in requested.Where(r => !bound.Any(b => b.Ref.Equals(r, StringComparison.OrdinalIgnoreCase))))
        {
            logger.LogInformation(
                "Application '{AppId}' asked for skill '{Skill}', which is not attached to it; ignored.",
                app.AppId, missing);
        }

        return composed.ToString().TrimEnd();
    }

    public async Task<CapabilityBinding> ResolveAttachmentAsync(
        AppConfig app, AttachCapabilityRequest request, string? attachedBy, CancellationToken cancellationToken = default)
    {
        var reference = request.Ref?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(reference))
        {
            throw new CapabilityRejectedException("ref is required.");
        }

        if (app.Capabilities.Any(b => b.Kind == request.Kind && b.Ref.Equals(reference, StringComparison.OrdinalIgnoreCase)))
        {
            throw new CapabilityRejectedException(
                $"{request.Kind} '{reference}' is already attached. Detach it first to change its pinned version.");
        }

        return request.Kind switch
        {
            CapabilityKind.Skill => await AttachSkillAsync(request, reference, attachedBy, cancellationToken),
            CapabilityKind.McpServer => await AttachServerAsync(request, reference, attachedBy, cancellationToken),
            CapabilityKind.Tool => await AttachToolAsync(request, reference, attachedBy, cancellationToken),
            _ => throw new CapabilityRejectedException(
                $"{request.Kind} capabilities have no catalogue in this gateway yet. Skills, MCP servers and " +
                "tools are available now; agents and plugins follow in later phases.")
        };
    }

    private async Task<CapabilityBinding> AttachSkillAsync(
        AttachCapabilityRequest request, string reference, string? attachedBy, CancellationToken cancellationToken)
    {
        var skill = await skills.GetAsync(reference, cancellationToken)
            ?? throw new CapabilityRejectedException($"No skill '{reference}' is registered.");

        if (!skill.IsActive)
        {
            throw new CapabilityRejectedException($"Skill '{reference}' is disabled and cannot be attached.");
        }

        var version = request.Version ?? skill.Version;
        if (await skills.GetVersionAsync(reference, version, cancellationToken) is null)
        {
            throw new CapabilityRejectedException(
                $"Skill '{reference}' has no version {version}. Its current version is {skill.Version}.");
        }

        return Bind(request, reference, version, attachedBy);
    }

    private async Task<CapabilityBinding> AttachServerAsync(
        AttachCapabilityRequest request, string reference, string? attachedBy, CancellationToken cancellationToken)
    {
        if (servers is null)
        {
            throw new CapabilityRejectedException("The MCP catalogue is not available in this configuration.");
        }

        var server = await servers.GetAsync(reference, cancellationToken)
            ?? throw new CapabilityRejectedException($"No MCP server '{reference}' is registered.");

        if (!server.IsActive)
        {
            throw new CapabilityRejectedException($"MCP server '{reference}' is disabled and cannot be attached.");
        }

        // Attaching a whole server grants every tool it publishes, now and later. The side-effect
        // ceiling is the only thing bounding that, so it is stated rather than inferred.
        var ceiling = request.MaxSideEffect ?? ToolSideEffect.Read;

        return Bind(request, reference, 1, attachedBy, ceiling);
    }

    private async Task<CapabilityBinding> AttachToolAsync(
        AttachCapabilityRequest request, string reference, string? attachedBy, CancellationToken cancellationToken)
    {
        if (tools is null)
        {
            throw new CapabilityRejectedException("The tool catalogue is not available in this configuration.");
        }

        var tool = await tools.FindAsync(reference, cancellationToken)
            ?? throw new CapabilityRejectedException(
                $"No tool '{reference}' is published by a registered server. Tools are named server.tool.");

        var ceiling = request.MaxSideEffect ?? ToolSideEffect.Read;

        // Granting a write is a deliberate act, so a write tool cannot be attached by accepting
        // the default. The caller has to say so.
        if (tool.SideEffect > ceiling)
        {
            throw new CapabilityRejectedException(
                $"Tool '{reference}' is {tool.SideEffect}, above the {ceiling} ceiling this binding would have. " +
                $"Attach it with maxSideEffect \"{tool.SideEffect}\" if that is intended.");
        }

        return Bind(request, reference, 1, attachedBy, ceiling);
    }

    private static CapabilityBinding Bind(
        AttachCapabilityRequest request,
        string reference,
        int version,
        string? attachedBy,
        ToolSideEffect ceiling = ToolSideEffect.Read) => new()
        {
            Kind = request.Kind,
            Ref = reference,
            Version = version,
            Enabled = request.Enabled,
            MaxSideEffect = ceiling,
            AttachedBy = attachedBy,
            AttachedAt = DateTimeOffset.UtcNow
        };

    private async Task<CapabilityView> ResolveServerAsync(CapabilityBinding binding, CancellationToken cancellationToken)
    {
        if (servers is null)
        {
            return Unusable(binding, "The MCP catalogue is not available in this configuration.");
        }

        var server = await servers.GetAsync(binding.Ref, cancellationToken);
        if (server is null)
        {
            return Unusable(binding, "The MCP server is no longer registered.");
        }

        return new CapabilityView
        {
            Binding = binding,
            Name = server.Name,
            Description = server.Description,
            CatalogVersion = 1,
            Usable = binding.Enabled && server.IsActive,
            Reason = !server.IsActive ? "The MCP server is disabled." :
                     !binding.Enabled ? "Disabled on this application." : null
        };
    }

    private async Task<CapabilityView> ResolveToolAsync(CapabilityBinding binding, CancellationToken cancellationToken)
    {
        if (tools is null)
        {
            return Unusable(binding, "The tool catalogue is not available in this configuration.");
        }

        ToolDescriptor? tool;
        try
        {
            tool = await tools.FindAsync(binding.Ref, cancellationToken);
        }
        catch (Exception ex)
        {
            // An unreachable server is an operational fact, not a broken binding.
            logger.LogWarning(ex, "Could not resolve tool '{Tool}' while listing capabilities.", binding.Ref);
            return Unusable(binding, "The tool's server could not be reached.");
        }

        if (tool is null)
        {
            return Unusable(binding, "No registered server publishes this tool any more.");
        }

        var withinCeiling = tool.SideEffect <= binding.MaxSideEffect;

        return new CapabilityView
        {
            Binding = binding,
            Name = tool.Name,
            Description = tool.Description,
            CatalogVersion = 1,
            Usable = binding.Enabled && withinCeiling,
            Reason = !withinCeiling
                ? $"The tool is now {tool.SideEffect}, above this binding's {binding.MaxSideEffect} ceiling."
                : binding.Enabled ? null : "Disabled on this application."
        };
    }

    private async Task<CapabilityView> ResolveSkillAsync(CapabilityBinding binding, CancellationToken cancellationToken)
    {
        var skill = await skills.GetAsync(binding.Ref, cancellationToken);
        if (skill is null)
        {
            return Unusable(binding, "The skill is no longer registered.");
        }

        if (!skill.IsActive)
        {
            return Unusable(binding, "The skill is disabled in the catalogue.", skill.Version, skill.Name, skill.Description);
        }

        var snapshot = await skills.GetVersionAsync(binding.Ref, binding.Version, cancellationToken);
        if (snapshot is null)
        {
            return Unusable(binding, $"Pinned version {binding.Version} is no longer available.", skill.Version, skill.Name, skill.Description);
        }

        return new CapabilityView
        {
            Binding = binding,
            Name = snapshot.Name,
            Description = snapshot.Description,
            CatalogVersion = skill.Version,
            Usable = binding.Enabled,
            Reason = binding.Enabled ? null : "Disabled on this application."
        };
    }

    private async Task<SkillSnapshot?> ResolveSnapshotAsync(CapabilityBinding binding, CancellationToken cancellationToken)
    {
        var skill = await skills.GetAsync(binding.Ref, cancellationToken);
        if (skill is null || !skill.IsActive)
        {
            return null;
        }

        return await skills.GetVersionAsync(binding.Ref, binding.Version, cancellationToken);
    }

    private static CapabilityView Unusable(
        CapabilityBinding binding, string reason, int catalogVersion = 0, string name = "", string description = "") =>
        new()
        {
            Binding = binding,
            Name = name,
            Description = description,
            CatalogVersion = catalogVersion,
            Usable = false,
            Reason = reason
        };
}
