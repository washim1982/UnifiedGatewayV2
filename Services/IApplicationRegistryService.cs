using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface IApplicationRegistryService
{
    Task<AppConfig?> GetAppAsync(string appId, CancellationToken cancellationToken = default);
    Task<List<AppConfig>> GetAllAppsAsync(CancellationToken cancellationToken = default);
    Task<CreateAppResponse> CreateAppAsync(CreateAppRequest request, CancellationToken cancellationToken = default);
    Task<AppConfig?> UpdateAppAsync(string appId, UpdateAppRequest request, CancellationToken cancellationToken = default);
    Task<bool> DeleteAppAsync(string appId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rotates an application's long-term API key. The previous key is invalidated immediately.
    /// Returns the new plaintext key exactly once, or null if the application does not exist.
    /// </summary>
    Task<string?> RotateApiKeyAsync(string appId, CancellationToken cancellationToken = default);
    /// <summary>
    /// Authenticates a caller for one application. The returned <see cref="CallerContext"/>
    /// carries how they authenticated, so the audit record can be attributed without the
    /// endpoint re-validating the credential.
    /// </summary>
    Task<(bool isValid, AppConfig? app, CallerContext? caller)> AuthenticateAppAsync(
        string appId, string apiKey, CancellationToken cancellationToken = default);
    /// <summary>
    /// Exchanges an application key, or the break-glass credential, for an STS token. Every
    /// issuance is written to the audit trail with the token's jti and the caller's address;
    /// a break-glass issuance is also logged at Warning for alerting.
    /// </summary>
    Task<AppStsTokenResponse?> IssueStsTokenForAppAsync(string? appId, string apiKey, int durationSeconds = 3600, string scope = "invoke", string? callerId = null, string? sourceIp = null, CancellationToken cancellationToken = default);
    Task<AppStsTokenResponse> MintStsTokenDirectAsync(string appId, int durationSeconds = 3600, string scope = "invoke", bool isAdmin = false, string? callerId = null, CancellationToken cancellationToken = default);
    Task RecordMetricAsync(RequestLogEntry log, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reloads the recent-metrics buffer from the durable trail. Called once object
    /// storage is confirmed reachable, so the telemetry view is not blank after a restart.
    /// </summary>
    Task RehydrateRecentLogsAsync(CancellationToken cancellationToken = default);

    /// <summary>Appends a privileged management action to the durable audit trail.</summary>
    Task RecordManagementActionAsync(ManagementAuditEntry entry, CancellationToken cancellationToken = default);
    Task<GatewayMetricsSummary> GetMetricsSummaryAsync(CancellationToken cancellationToken = default);
}
