using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface ISkillRegistryService
{
    Task<List<SkillDefinition>> ListAsync(CancellationToken cancellationToken = default);
    Task<SkillDefinition?> GetAsync(string skillId, CancellationToken cancellationToken = default);

    /// <summary>The body of one version, from the current record or its history.</summary>
    Task<SkillSnapshot?> GetVersionAsync(string skillId, int version, CancellationToken cancellationToken = default);

    Task<SkillDefinition> CreateAsync(CreateSkillRequest request, CancellationToken cancellationToken = default);
    Task<SkillDefinition?> UpdateAsync(string skillId, UpdateSkillRequest request, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(string skillId, CancellationToken cancellationToken = default);
}

/// <summary>
/// The skill catalogue, stored as JSON beside the application registry.
///
/// Skill bodies are untrusted content: they are written by people, imported from elsewhere, and
/// then placed into a system prompt. Every body is run through the guardrails in Block mode before
/// it is stored, and again when the file is loaded at startup -- the file is on disk and can be
/// edited there, so trusting the write-time check alone would be trusting the wrong thing. A body
/// that fails is refused on write, and a stored one that fails on load is deactivated rather than
/// served.
/// </summary>
public partial class SkillRegistryService : ISkillRegistryService
{
    private readonly ConcurrentDictionary<string, SkillDefinition> _skills = new(StringComparer.OrdinalIgnoreCase);
    private readonly IGuardrailService _guardrails;
    private readonly ILogger<SkillRegistryService> _logger;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly string _filePath;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private const int MaxBodyCharacters = 100_000;

    public SkillRegistryService(
        IOptions<GatewayOptions> options,
        IGuardrailService guardrails,
        ILogger<SkillRegistryService> logger)
    {
        _guardrails = guardrails;
        _logger = logger;

        var dataDir = Path.GetFullPath(options.Value.Storage.DataDirectory);
        Directory.CreateDirectory(dataDir);
        _filePath = Path.Combine(dataDir, "skills.json");

        Load();
    }

    public Task<List<SkillDefinition>> ListAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_skills.Values.OrderBy(s => s.SkillId, StringComparer.OrdinalIgnoreCase).ToList());

    public Task<SkillDefinition?> GetAsync(string skillId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_skills.TryGetValue(skillId, out var skill) ? skill : null);

    public Task<SkillSnapshot?> GetVersionAsync(string skillId, int version, CancellationToken cancellationToken = default)
    {
        if (!_skills.TryGetValue(skillId, out var skill))
        {
            return Task.FromResult<SkillSnapshot?>(null);
        }

        if (skill.Version == version)
        {
            return Task.FromResult<SkillSnapshot?>(new SkillSnapshot
            {
                Version = skill.Version,
                Name = skill.Name,
                Description = skill.Description,
                Body = skill.Body,
                Checksum = skill.Checksum,
                SavedAt = skill.UpdatedAt
            });
        }

        return Task.FromResult(skill.VersionHistory.FirstOrDefault(v => v.Version == version));
    }

    public async Task<SkillDefinition> CreateAsync(CreateSkillRequest request, CancellationToken cancellationToken = default)
    {
        var skillId = Normalize(request.SkillId);
        if (!SkillIdRegex().IsMatch(skillId))
        {
            throw new SkillRejectedException(
                "skillId must be 2-64 characters of lowercase letters, digits and hyphens.");
        }

        if (_skills.ContainsKey(skillId))
        {
            throw new SkillRejectedException($"A skill with id '{skillId}' already exists.");
        }

        if (string.IsNullOrWhiteSpace(request.Description))
        {
            throw new SkillRejectedException(
                "description is required: it is the only part of a skill the model always sees.");
        }

        await InspectAsync(skillId, request.Description, request.Body, cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var skill = new SkillDefinition
        {
            SkillId = skillId,
            Name = string.IsNullOrWhiteSpace(request.Name) ? skillId : request.Name.Trim(),
            Description = request.Description.Trim(),
            Body = request.Body ?? string.Empty,
            Version = 1,
            Checksum = Checksum(request.Body ?? string.Empty),
            CreatedAt = now,
            UpdatedAt = now
        };

        _skills[skillId] = skill;
        await PersistAsync();

        _logger.LogInformation("Skill '{SkillId}' registered at version 1.", skillId);
        return skill;
    }

    public async Task<SkillDefinition?> UpdateAsync(
        string skillId, UpdateSkillRequest request, CancellationToken cancellationToken = default)
    {
        if (!_skills.TryGetValue(skillId, out var existing))
        {
            return null;
        }

        var body = request.Body ?? existing.Body;
        var description = request.Description?.Trim() ?? existing.Description;
        var contentChanged = body != existing.Body || description != existing.Description;

        if (contentChanged)
        {
            await InspectAsync(skillId, description, body, cancellationToken);
        }

        // A content change is a new version, so a binding pinned to the old one keeps working.
        var version = contentChanged ? existing.Version + 1 : existing.Version;
        var history = existing.VersionHistory.ToList();

        if (contentChanged)
        {
            history.Add(new SkillSnapshot
            {
                Version = existing.Version,
                Name = existing.Name,
                Description = existing.Description,
                Body = existing.Body,
                Checksum = existing.Checksum,
                SavedAt = existing.UpdatedAt
            });
        }

        var updated = existing with
        {
            Name = request.Name?.Trim() ?? existing.Name,
            Description = description,
            Body = body,
            IsActive = request.IsActive ?? existing.IsActive,
            Version = version,
            Checksum = Checksum(body),
            UpdatedAt = DateTimeOffset.UtcNow,
            VersionHistory = history
        };

        _skills[skillId] = updated;
        await PersistAsync();
        return updated;
    }

    public async Task<bool> DeleteAsync(string skillId, CancellationToken cancellationToken = default)
    {
        if (!_skills.TryRemove(skillId, out _))
        {
            return false;
        }

        await PersistAsync();
        _logger.LogWarning("Skill '{SkillId}' deleted. Bindings that pin it stop resolving.", skillId);
        return true;
    }

    /// <summary>
    /// Guardrails in Block mode over what will end up in a system prompt. Block rather than the
    /// configured mode: redacting a skill would store instructions nobody wrote, and a gateway
    /// running in Redact or AuditOnly should still refuse to keep an injection payload on disk.
    /// </summary>
    private async Task InspectAsync(string skillId, string description, string? body, CancellationToken cancellationToken)
    {
        var text = $"{description}\n\n{body}";

        if (text.Length > MaxBodyCharacters)
        {
            throw new SkillRejectedException(
                $"Skill '{skillId}' is {text.Length} characters; the limit is {MaxBodyCharacters}.");
        }

        var result = await _guardrails.EvaluateAsync(
            text, modeOverride: GuardrailActionMode.Block, cancellationToken: cancellationToken);

        if (result.IsBlocked)
        {
            var findings = string.Join("; ", result.Violations.Select(v => $"{v.Category}:{v.RuleName}"));
            _logger.LogWarning("Skill '{SkillId}' refused by guardrails: {Findings}.", skillId, findings);

            throw new SkillRejectedException(
                $"The skill content was refused by the guardrails ({findings}). A skill becomes part of a " +
                "system prompt, so it is held to the same rules as any other content.");
        }
    }

    private void Load()
    {
        if (!File.Exists(_filePath))
        {
            return;
        }

        try
        {
            var skills = JsonSerializer.Deserialize<List<SkillDefinition>>(
                File.ReadAllText(_filePath), JsonOpts) ?? [];

            foreach (var skill in skills)
            {
                _skills[skill.SkillId] = skill;
            }

            _logger.LogInformation("Loaded {Count} skills from {Path}.", _skills.Count, _filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not read the skill catalogue at {Path}; starting empty.", _filePath);
        }
    }

    private async Task PersistAsync()
    {
        await _fileLock.WaitAsync();
        try
        {
            var json = JsonSerializer.Serialize(_skills.Values.ToList(), JsonOpts);
            var tempPath = _filePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json);

            if (File.Exists(_filePath))
            {
                File.Replace(tempPath, _filePath, _filePath + ".bak", ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _filePath);
            }
        }
        finally
        {
            _fileLock.Release();
        }
    }

    private static string Normalize(string value) => value.Trim().ToLowerInvariant().Replace(' ', '-');

    private static string Checksum(string body) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,63}$")]
    private static partial Regex SkillIdRegex();
}
