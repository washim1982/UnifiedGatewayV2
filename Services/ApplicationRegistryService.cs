using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud;
using UnifiedGateway.Services.Telemetry;

namespace UnifiedGateway.Services;

public partial class ApplicationRegistryService : IApplicationRegistryService
{
    private readonly ConcurrentDictionary<string, AppConfig> _apps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<RequestLogEntry> _recentLogs = new();
    private const int MaxLogHistory = 500;

    private readonly ISecurityService _securityService;
    private readonly IAdminCredentialService _adminCredentials;
    private readonly GatewayOptions _options;
    private readonly BillingOptions _billing;
    private readonly ILogger<ApplicationRegistryService> _logger;
    private readonly IAuditStore _auditStore;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly string _registryFilePath;

    private static readonly JsonSerializerOptions AuditJsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public ApplicationRegistryService(
        ISecurityService securityService,
        IAdminCredentialService adminCredentials,
        IOptions<GatewayOptions> options,
        IOptions<BillingOptions> billingOptions,
        IAuditStore auditStore,
        ILogger<ApplicationRegistryService> logger)
    {
        _securityService = securityService;
        _adminCredentials = adminCredentials;
        _billing = billingOptions.Value;
        _auditStore = auditStore;
        _options = options.Value;
        _logger = logger;

        var dataDir = Path.GetFullPath(_options.Storage.DataDirectory);
        Directory.CreateDirectory(dataDir);
        _registryFilePath = Path.Combine(dataDir, _options.Storage.RegistryFileName);

        InitializeRegistry();
    }

    #region Durable Audit Trail

    // The trail lives in object storage (S3Local in dev, S3 in test and production), not on
    // the local disk: billing and telemetry are both built from it, so it has to outlive any
    // single host and be readable by anything else that needs the same numbers.

    /// <summary>
    /// Reloads the recent-metrics buffer from the trail so the telemetry view is not blank
    /// after a restart. Best effort: a slow or unavailable store must not block startup.
    /// </summary>
    public async Task RehydrateRecentLogsAsync(CancellationToken cancellationToken = default)
    {
        if (!_options.Storage.AuditLogEnabled) return;

        try
        {
            var to = DateTimeOffset.UtcNow;
            var entries = await _auditStore.ReadInvocationsAsync(to.AddDays(-2), to, cancellationToken);

            foreach (var entry in entries.OrderBy(e => e.Timestamp).TakeLast(MaxLogHistory))
            {
                _recentLogs.Enqueue(entry);
            }

            if (entries.Count > 0)
            {
                _logger.LogInformation("Rehydrated {Count} audit entries from object storage.",
                    Math.Min(entries.Count, MaxLogHistory));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not rehydrate recent telemetry from object storage.");
        }
    }

    #endregion

    private void InitializeRegistry()
    {
        try
        {
            if (File.Exists(_registryFilePath))
            {
                var json = File.ReadAllText(_registryFilePath);
                var loaded = JsonSerializer.Deserialize<List<AppConfig>>(json, JsonOpts);
                if (loaded != null)
                {
                    foreach (var app in loaded)
                    {
                        _apps[app.AppId] = app;
                    }
                    _logger.LogInformation("Loaded {Count} registered applications from {Path}", _apps.Count, _registryFilePath);
                    return;
                }
            }

            SeedDefaultApps();
            PersistRegistryToFile();
        }
        catch (Exception ex)
        {
            // Do not reseed over a registry that exists but failed to parse: that would
            // replace every real application and key hash with fresh defaults nobody holds.
            // Fail startup instead, so a corrupt file is investigated rather than overwritten.
            _logger.LogCritical(ex, "Registry at {Path} exists but could not be read.", _registryFilePath);
            throw new InvalidOperationException(
                $"Application registry '{_registryFilePath}' could not be read. " +
                "Restore it from backup or move it aside to start with a fresh registry.", ex);
        }
    }

    private void SeedDefaultApps()
    {
        var (key1, hash1, prefix1) = _securityService.GenerateApiKey();
        var app1 = new AppConfig
        {
            AppId = "customer-support-agent",
            Name = "Customer Support Assistant",
            Description = "Automated customer support routing and FAQ handling.",
            ApiKeyHash = hash1,
            ApiKeyPrefix = prefix1,
            Provider = "bedrock",
            Model = "anthropic.claude-3-5-sonnet-20240620-v1:0",
            SystemPrompt = "You are a professional customer support agent for Acme Corp. Be concise, polite, and accurate.",
            Temperature = 0.5,
            MaxTokens = 1500,
            FallbackProvider = "local",
            FallbackModel = "ollama/llama3",
            Version = 1,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        var (key2, hash2, prefix2) = _securityService.GenerateApiKey();
        var app2 = new AppConfig
        {
            AppId = "code-reviewer-pro",
            Name = "Code Reviewer Pro",
            Description = "Senior engineer automated code review and security analysis.",
            ApiKeyHash = hash2,
            ApiKeyPrefix = prefix2,
            Provider = "bedrock",
            Model = "anthropic.claude-3-5-sonnet-20240620-v1:0",
            SystemPrompt = "You are a principal staff software engineer conducting a strict, helpful code review.",
            Temperature = 0.3,
            MaxTokens = 3000,
            FallbackProvider = "local",
            FallbackModel = "ollama/llama3",
            Version = 1,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        var (key3, hash3, prefix3) = _securityService.GenerateApiKey();
        var app3 = new AppConfig
        {
            AppId = "local-privacy-chat",
            Name = "Local Privacy Chat",
            Description = "Internal offline LLM for processing sensitive and confidential notes.",
            ApiKeyHash = hash3,
            ApiKeyPrefix = prefix3,
            Provider = "local",
            Model = "ollama/llama3",
            SystemPrompt = "You are a private offline assistant. No data leaves this server.",
            Temperature = 0.7,
            MaxTokens = 2048,
            FallbackProvider = "local",
            FallbackModel = "lmstudio/local-model",
            Version = 1,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _apps[app1.AppId] = app1;
        _apps[app2.AppId] = app2;
        _apps[app3.AppId] = app3;

        _logger.LogInformation("Seeded 3 default applications with generated keys.");
    }

    public Task<AppConfig?> GetAppAsync(string appId, CancellationToken cancellationToken = default)
    {
        _apps.TryGetValue(appId, out var app);
        return Task.FromResult(app);
    }

    public Task<List<AppConfig>> GetAllAppsAsync(CancellationToken cancellationToken = default)
    {
        var list = _apps.Values.OrderByDescending(a => a.UpdatedAt).ToList();
        return Task.FromResult(list);
    }

    public async Task<CreateAppResponse> CreateAppAsync(CreateAppRequest request, CancellationToken cancellationToken = default)
    {
        var cleanAppId = string.IsNullOrWhiteSpace(request.AppId)
            ? Guid.NewGuid().ToString("N")[..8]
            : Slugify(request.AppId);

        if (_apps.ContainsKey(cleanAppId))
        {
            throw new InvalidOperationException($"An application with AppId '{cleanAppId}' already exists.");
        }

        var (rawKey, keyHash, keyPrefix) = _securityService.GenerateApiKey();

        var app = new AppConfig
        {
            AppId = cleanAppId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ApiKeyHash = keyHash,
            ApiKeyPrefix = keyPrefix,
            Provider = request.Provider,
            Model = request.Model,
            SystemPrompt = request.SystemPrompt,
            Temperature = request.Temperature,
            MaxTokens = request.MaxTokens,
            FallbackProvider = request.FallbackProvider,
            FallbackModel = request.FallbackModel,
            InputCostPerMillion = request.InputCostPerMillion,
            OutputCostPerMillion = request.OutputCostPerMillion,
            Version = 1,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
            VersionHistory = []
        };

        _apps[cleanAppId] = app;
        await PersistRegistryToFileAsync();

        // Mint initial ready-to-use 1-hour STS temporary token
        var (stsToken, stsExpiresAt) = await _securityService.IssueAppStsTokenAsync(
            cleanAppId,
            TimeSpan.FromSeconds(_options.Security.DefaultStsTokenLifetimeSeconds),
            "invoke",
            isAdmin: false,
            cancellationToken: cancellationToken);

        return new CreateAppResponse
        {
            App = app,
            ApiKey = rawKey,
            EndpointUrl = $"/gateway/{cleanAppId}/invoke",
            StsToken = stsToken,
            StsExpiresAt = stsExpiresAt,
            StsDurationSeconds = _options.Security.DefaultStsTokenLifetimeSeconds
        };
    }

    public async Task<AppConfig?> UpdateAppAsync(string appId, UpdateAppRequest request, CancellationToken cancellationToken = default)
    {
        if (!_apps.TryGetValue(appId, out var existing))
        {
            return null;
        }

        var snapshot = new AppConfigSnapshot
        {
            Version = existing.Version,
            Provider = existing.Provider,
            Model = existing.Model,
            SystemPrompt = existing.SystemPrompt,
            Temperature = existing.Temperature,
            MaxTokens = existing.MaxTokens,
            InputCostPerMillion = existing.InputCostPerMillion,
            OutputCostPerMillion = existing.OutputCostPerMillion,
            SavedAt = existing.UpdatedAt
        };

        var history = new List<AppConfigSnapshot>(existing.VersionHistory) { snapshot };

        var updated = existing with
        {
            Name = request.Name ?? existing.Name,
            Description = request.Description ?? existing.Description,
            Provider = request.Provider ?? existing.Provider,
            Model = request.Model ?? existing.Model,
            SystemPrompt = request.SystemPrompt ?? existing.SystemPrompt,
            Temperature = request.Temperature ?? existing.Temperature,
            MaxTokens = request.MaxTokens ?? existing.MaxTokens,
            FallbackProvider = request.FallbackProvider ?? existing.FallbackProvider,
            FallbackModel = request.FallbackModel ?? existing.FallbackModel,
            IsActive = request.IsActive ?? existing.IsActive,
            InputCostPerMillion = request.InputCostPerMillion ?? existing.InputCostPerMillion,
            OutputCostPerMillion = request.OutputCostPerMillion ?? existing.OutputCostPerMillion,
            Version = existing.Version + 1,
            UpdatedAt = DateTimeOffset.UtcNow,
            VersionHistory = history
        };

        _apps[appId] = updated;
        await PersistRegistryToFileAsync();
        return updated;
    }

    public async Task<bool> DeleteAppAsync(string appId, CancellationToken cancellationToken = default)
    {
        var removed = _apps.TryRemove(appId, out _);
        if (removed)
        {
            await PersistRegistryToFileAsync();
        }
        return removed;
    }

    public async Task<string?> RotateApiKeyAsync(string appId, CancellationToken cancellationToken = default)
    {
        if (!_apps.TryGetValue(appId, out var existing))
        {
            return null;
        }

        var (rawKey, keyHash, keyPrefix) = _securityService.GenerateApiKey();

        var rotated = existing with { UpdatedAt = DateTimeOffset.UtcNow };
        rotated.ApiKeyHash = keyHash;
        rotated.ApiKeyPrefix = keyPrefix;

        _apps[appId] = rotated;
        await PersistRegistryToFileAsync();

        // The old key's hash is overwritten, so it stops authenticating immediately.
        _logger.LogWarning("API key rotated for application '{AppId}'. The previous key is now invalid.", appId);

        return rawKey;
    }

    public async Task<(bool isValid, AppConfig? app, CallerContext? caller)> AuthenticateAppAsync(
        string appId, string apiKey, CancellationToken cancellationToken = default)
    {
        if (!_apps.TryGetValue(appId, out var app) || !app.IsActive)
        {
            return (false, null, null);
        }

        if (!_options.Security.EnforceAppApiKey)
        {
            return (true, app, new CallerContext { Actor = appId, AuthType = "AuthenticationDisabled" });
        }

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return (false, null, null);
        }

        var cleanKey = apiKey.Trim();
        if (cleanKey.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            cleanKey = cleanKey[7..].Trim();
        }

        // 1. Application STS token.
        if (cleanKey.StartsWith("ug_sts_", StringComparison.Ordinal))
        {
            var (isStsValid, payload, failureReason) = await _securityService.ValidateAppStsTokenAsync(cleanKey, cancellationToken);
            if (!isStsValid || payload == null)
            {
                _logger.LogWarning("STS token rejection for appId '{AppId}': {Reason}", appId, failureReason);
                return (false, null, null);
            }

            // Admin tokens may invoke any app; an app token must match this exact appId.
            if (!payload.IsAdmin && !string.Equals(payload.AppId, appId, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("STS token appId mismatch. Token appId: '{TokenAppId}', Request appId: '{ReqAppId}'", payload.AppId, appId);
                return (false, null, null);
            }

            // The scope claim is a restriction the API advertises, so it has to bite. A token
            // minted for reading must not be usable to spend money on inference.
            if (!SecurityService.ScopePermits(payload.Scope, GatewayScopes.Invoke))
            {
                _logger.LogWarning(
                    "STS token for '{AppId}' carries scope '{Scope}', which does not permit {Required}.",
                    appId, payload.Scope, GatewayScopes.Invoke);
                return (false, null, null);
            }

            return (true, app, new CallerContext
            {
                // The callerId was chosen by whoever minted the token, so it rides along as a
                // label; the identity recorded is the app, or break-glass for an admin token.
                Actor = CallerContext.ActorFor(payload),
                AuthType = payload.IsAdmin ? "AdminStsToken" : "AppStsToken",
                TokenId = payload.Jti
            });
        }

        // 2. The application's own long-term key.
        //
        // The master admin key is deliberately NOT accepted here. One credential that
        // authenticates as every tenant leaves no separation of duty and no partial
        // containment after a leak; admins reach applications through an admin STS token
        // instead, which is attributable and revocable.
        var isValid = _securityService.VerifyKey(cleanKey, app.ApiKeyHash);
        if (!isValid)
        {
            return (false, null, null);
        }

        return (true, app, new CallerContext
        {
            // The prefix identifies which key was used without recording the key itself.
            Actor = app.ApiKeyPrefix,
            AuthType = "AppApiKey"
        });
    }
    public async Task<AppStsTokenResponse?> IssueStsTokenForAppAsync(
        string? appId,
        string apiKey,
        int durationSeconds = 3600,
        string scope = "invoke",
        string? callerId = null,
        string? sourceIp = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        // callerId is written into the token and from there into audit records, so it is held
        // to a charset that cannot forge a log line or carry markup into the dashboard.
        if (callerId is not null && !CallerIdRegex().IsMatch(callerId))
        {
            throw new ArgumentException(
                "callerId may use letters, digits and . _ @ : / + = - only, up to 128 characters.",
                nameof(callerId));
        }

        var cleanKey = apiKey.Trim();
        if (cleanKey.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            cleanKey = cleanKey[7..].Trim();

        var duration = TimeSpan.FromSeconds(
            durationSeconds <= 0 ? _options.Security.DefaultStsTokenLifetimeSeconds : durationSeconds);

        // A. Master admin credential, read from the secret store.
        if (await _adminCredentials.VerifyAsync(cleanKey, cancellationToken))
        {
            var targetAppId = string.IsNullOrWhiteSpace(appId) ? "*" : appId.Trim();
            var issued = await _securityService.IssueStsTokenAsync(new StsTokenSpec
            {
                AppId = targetAppId,
                Duration = duration,
                Scope = scope,
                IsAdmin = true,
                CallerId = callerId
            }, cancellationToken);

            // Break-glass turned into a bearer token is the most sensitive thing this service
            // does. It is logged at Warning for alerting and written to the audit trail before
            // the token is handed back.
            _logger.LogWarning(
                "BREAK-GLASS: admin STS token {Jti} minted for '{AppId}' with scope '{Scope}', valid until {ExpiresAt:u}, from {SourceIp}.",
                issued.TokenId, targetAppId, issued.Scope, issued.ExpiresAt, sourceIp ?? "unknown");

            await RecordManagementActionAsync(new ManagementAuditEntry
            {
                Action = "MintAdminStsToken",
                Resource = targetAppId,
                Actor = "break-glass",
                AuthType = "MasterAdminKey",
                SourceIp = sourceIp,
                TokenId = issued.TokenId,
                Success = true,
                Detail = MintDetail(issued, callerId)
            }, cancellationToken);

            return ToResponse(issued, targetAppId, isAdmin: true);
        }

        // B. An application's own long-term key.
        AppConfig? matchedApp = null;
        if (!string.IsNullOrWhiteSpace(appId) && _apps.TryGetValue(appId, out var specificApp))
        {
            if (specificApp.IsActive && _securityService.VerifyKey(cleanKey, specificApp.ApiKeyHash))
            {
                matchedApp = specificApp;
            }
        }
        else
        {
            // Search all registered apps for matching key hash
            foreach (var app in _apps.Values)
            {
                if (app.IsActive && _securityService.VerifyKey(cleanKey, app.ApiKeyHash))
                {
                    matchedApp = app;
                    break;
                }
            }
        }

        if (matchedApp == null)
        {
            return null;
        }

        var issuedToApp = await _securityService.IssueStsTokenAsync(new StsTokenSpec
        {
            AppId = matchedApp.AppId,
            Duration = duration,
            Scope = scope,
            IsAdmin = false,
            CallerId = callerId
        }, cancellationToken);

        await RecordManagementActionAsync(new ManagementAuditEntry
        {
            Action = "ExchangeApiKeyForStsToken",
            Resource = matchedApp.AppId,
            Actor = matchedApp.ApiKeyPrefix,
            AuthType = "AppApiKey",
            SourceIp = sourceIp,
            TokenId = issuedToApp.TokenId,
            Success = true,
            Detail = MintDetail(issuedToApp, callerId)
        }, cancellationToken);

        return ToResponse(issuedToApp, matchedApp.AppId, isAdmin: false);
    }

    public async Task<AppStsTokenResponse> MintStsTokenDirectAsync(
        string appId,
        int durationSeconds = 3600,
        string scope = "invoke",
        bool isAdmin = false,
        string? callerId = null,
        CancellationToken cancellationToken = default)
    {
        var duration = TimeSpan.FromSeconds(
            durationSeconds <= 0 ? _options.Security.DefaultStsTokenLifetimeSeconds : durationSeconds);

        var issued = await _securityService.IssueStsTokenAsync(new StsTokenSpec
        {
            AppId = appId,
            Duration = duration,
            Scope = scope,
            IsAdmin = isAdmin,
            CallerId = callerId
        }, cancellationToken);

        return ToResponse(issued, appId, isAdmin);
    }

    private static string MintDetail(IssuedStsToken issued, string? callerId) =>
        $"scope={issued.Scope}; ttl={(int)(issued.ExpiresAt - issued.IssuedAt).TotalSeconds}s; callerId={callerId ?? "-"}";

    /// <summary>
    /// The response reports the lifetime the token actually got, not the one requested: the
    /// ceiling may have shortened it, and a client planning its refresh needs the real figure.
    /// </summary>
    private static AppStsTokenResponse ToResponse(IssuedStsToken issued, string appId, bool isAdmin) => new()
    {
        Token = issued.Token,
        TokenType = "Bearer",
        AppId = appId,
        DurationSeconds = (int)Math.Round((issued.ExpiresAt - issued.IssuedAt).TotalSeconds),
        IssuedAt = issued.IssuedAt,
        ExpiresAt = issued.ExpiresAt,
        Scope = issued.Scope,
        IsAdmin = isAdmin,
        TokenId = issued.TokenId
    };

    [System.Text.RegularExpressions.GeneratedRegex(@"^[A-Za-z0-9._@:/+=-]{1,128}$")]
    private static partial System.Text.RegularExpressions.Regex CallerIdRegex();

    public async Task RecordManagementActionAsync(ManagementAuditEntry entry, CancellationToken cancellationToken = default)
    {
        if (_options.Storage.AuditLogEnabled)
        {
            await _auditStore.AppendManagementAsync(entry, cancellationToken);
        }

        _logger.LogInformation("Management action {Action} on {Resource} by {Actor} (success={Success})",
            entry.Action, entry.Resource ?? "-", entry.Actor ?? "unknown", entry.Success);
    }
    /// <summary>
    /// Stamps the charge for a request onto its audit entry using the rate card in force
    /// right now. Freezing both the cost and the rates that produced it means a later price
    /// change cannot silently restate past invoices, and an auditor can see how any line
    /// was arrived at.
    /// </summary>
    private RequestLogEntry PriceEntry(RequestLogEntry log)
    {
        decimal inputRate = 0m;
        decimal outputRate = 0m;
        var isEstimated = true;

        if (!string.IsNullOrWhiteSpace(log.AppId) && _apps.TryGetValue(log.AppId, out var app))
        {
            if (app.InputCostPerMillion > 0m || app.OutputCostPerMillion > 0m)
            {
                inputRate = app.InputCostPerMillion;
                outputRate = app.OutputCostPerMillion;
                isEstimated = false;
            }
        }

        if (isEstimated)
        {
            // No rate card: fall back to the configured default and mark the line so the
            // bill never presents a guess as a contracted rate.
            inputRate = _billing.DefaultInputCostPerMillion;
            outputRate = _billing.DefaultOutputCostPerMillion;
        }

        return log with
        {
            InputCost = CostFor(log.InputTokens, inputRate),
            OutputCost = CostFor(log.OutputTokens, outputRate),
            InputRatePerMillion = inputRate,
            OutputRatePerMillion = outputRate,
            IsEstimatedCost = isEstimated
        };
    }

    /// <summary>
    /// Cost of a token count at a per-million rate, rounded to six decimal places.
    /// Individual calls are fractions of a cent, so rounding to currency precision here
    /// would floor almost every line to zero; the rounding to cents happens on the total.
    /// </summary>
    private static decimal CostFor(int tokens, decimal ratePerMillion)
    {
        if (tokens <= 0 || ratePerMillion <= 0m) return 0m;
        return Math.Round(tokens / 1_000_000m * ratePerMillion, 6, MidpointRounding.AwayFromZero);
    }
    public async Task RecordMetricAsync(RequestLogEntry log, CancellationToken cancellationToken = default)
    {
        log = PriceEntry(log);

        _recentLogs.Enqueue(log);
        while (_recentLogs.Count > MaxLogHistory)
        {
            _recentLogs.TryDequeue(out _);
        }

        // Durable trail in object storage; billing and telemetry both read it back.
        if (_options.Storage.AuditLogEnabled)
        {
            await _auditStore.AppendAsync(log, cancellationToken);
        }
    }

    public Task<GatewayMetricsSummary> GetMetricsSummaryAsync(CancellationToken cancellationToken = default)
    {
        var logs = _recentLogs.ToArray();
        var total = logs.Length;
        var successful = logs.Count(l => l.Success);
        var failed = logs.Count(l => !l.Success);
        var fallbacks = logs.Count(l => l.FallbackUsed);
        var totalTokens = logs.Sum(l => (long)l.TotalTokens);
        var avgLatency = total > 0 ? logs.Average(l => l.LatencyMs) : 0.0;
        var bedrock = logs.Count(l => l.Provider.Equals("bedrock", StringComparison.OrdinalIgnoreCase));
        var local = logs.Count(l => l.Provider.Equals("local", StringComparison.OrdinalIgnoreCase));

        var evaluated = logs.Count(l => l.GuardrailAction != "None");
        var redacted = logs.Count(l => l.GuardrailAction == "Redacted");
        var blocked = logs.Count(l => l.GuardrailAction == "Blocked");
        var outputRedacted = logs.Count(l => l.OutputGuardrailAction == "Redacted");
        var outputBlocked = logs.Count(l => l.OutputGuardrailAction == "Blocked");

        var appStats = new Dictionary<string, AppMetricStats>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in logs.Where(l => !string.IsNullOrEmpty(l.AppId)).GroupBy(l => l.AppId!))
        {
            appStats[group.Key] = new AppMetricStats
            {
                AppId = group.Key,
                RequestCount = group.Count(),
                TokenCount = group.Sum(l => (long)l.TotalTokens),
                AvgLatencyMs = group.Average(l => l.LatencyMs),
                ErrorCount = group.Count(l => !l.Success),
                GuardrailBlockedCount = group.Count(l => l.GuardrailAction == "Blocked")
            };
        }

        var summary = new GatewayMetricsSummary
        {
            TotalRequests = total,
            SuccessfulRequests = successful,
            FailedRequests = failed,
            FallbackCount = fallbacks,
            GuardrailEvaluatedCount = evaluated,
            GuardrailRedactedCount = redacted,
            GuardrailBlockedCount = blocked,
            OutputGuardrailRedactedCount = outputRedacted,
            OutputGuardrailBlockedCount = outputBlocked,
            TotalTokens = totalTokens,
            AvgLatencyMs = Math.Round(avgLatency, 2),
            BedrockRequests = bedrock,
            LocalRequests = local,
            RecentLogs = logs.OrderByDescending(l => l.Timestamp).Take(50).ToList(),
            AppStats = appStats
        };

        return Task.FromResult(summary);
    }

    private void PersistRegistryToFile()
    {
        _fileLock.Wait();
        try
        {
            var json = JsonSerializer.Serialize(_apps.Values.ToList(), JsonOpts);
            WriteAtomic(json);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    private async Task PersistRegistryToFileAsync()
    {
        await _fileLock.WaitAsync();
        try
        {
            var json = JsonSerializer.Serialize(_apps.Values.ToList(), JsonOpts);
            var tempPath = _registryFilePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json);
            ReplaceRegistryFile(tempPath);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    /// <summary>
    /// Writes through a temp file and swaps it in, so a crash or a full disk mid-write
    /// leaves the previous registry intact instead of truncating every application.
    /// </summary>
    private void WriteAtomic(string json)
    {
        var tempPath = _registryFilePath + ".tmp";
        File.WriteAllText(tempPath, json);
        ReplaceRegistryFile(tempPath);
    }

    private void ReplaceRegistryFile(string tempPath)
    {
        if (File.Exists(_registryFilePath))
        {
            // File.Replace keeps a backup and is atomic on NTFS.
            File.Replace(tempPath, _registryFilePath, _registryFilePath + ".bak", ignoreMetadataErrors: true);
        }
        else
        {
            File.Move(tempPath, _registryFilePath);
        }
    }

    /// <summary>
    /// Normalises an application id to [a-z0-9-]. The id ends up in URLs, HTML attributes and
    /// log lines, so anything outside that set is rejected rather than silently transformed.
    /// </summary>
    private static string Slugify(string text)
    {
        var normalized = text.Trim().ToLowerInvariant()
            .Replace(' ', '-')
            .Replace('_', '-');

        if (!AppIdRegex().IsMatch(normalized))
        {
            throw new InvalidOperationException(
                $"Application id '{text}' is not valid. Use 3-64 characters of a-z, 0-9 and hyphen.");
        }

        return normalized.Trim('-');
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")]
    private static partial System.Text.RegularExpressions.Regex AppIdRegex();
}
