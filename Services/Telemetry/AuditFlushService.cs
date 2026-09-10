using UnifiedGateway.Services.Cloud;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services.Telemetry;

/// <summary>
/// Flushes buffered audit records to object storage on an interval, and prunes expired
/// partitions once a day.
///
/// Without this a low-traffic gateway would hold records in memory until the batch-size
/// threshold happened to be crossed — which on a quiet day might be never.
/// </summary>
public class AuditFlushService : BackgroundService
{
    private readonly IAuditStore _auditStore;
    private readonly IObjectStore _objectStore;
    private readonly IServiceProvider _services;
    private readonly AuditStorageOptions _options;
    private readonly StorageOptions _legacyStorage;
    private readonly ILogger<AuditFlushService> _logger;

    public AuditFlushService(
        IAuditStore auditStore,
        IObjectStore objectStore,
        IServiceProvider services,
        IOptions<CloudOptions> cloudOptions,
        IOptions<GatewayOptions> gatewayOptions,
        ILogger<AuditFlushService> logger)
    {
        _auditStore = auditStore;
        _objectStore = objectStore;
        _services = services;
        _options = cloudOptions.Value.Storage;
        _legacyStorage = gatewayOptions.Value.Storage;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _objectStore.EnsureReadyAsync(stoppingToken);

            if (await _objectStore.IsAvailableAsync(stoppingToken))
            {
                _logger.LogInformation(
                    "Audit trail ready in bucket '{Bucket}'. Flushing every {Interval}s or every {Batch} records.",
                    _options.Bucket, _options.FlushIntervalSeconds, _options.FlushBatchSize);

                // Now that the trail is readable, refill the recent-metrics buffer so the
                // telemetry view survives a restart.
                var registry = _services.GetRequiredService<IApplicationRegistryService>();
                await registry.RehydrateRecentLogsAsync(stoppingToken);
            }
            else
            {
                _logger.LogError(
                    "Audit bucket '{Bucket}' is not reachable. Billing and telemetry will have no data " +
                    "until it is, and records will stay buffered in memory.", _options.Bucket);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Audit storage preparation failed.");
        }

        var interval = TimeSpan.FromSeconds(Math.Max(1, _options.FlushIntervalSeconds));
        var lastPrune = DateTimeOffset.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, stoppingToken);
                await _auditStore.FlushAsync(stoppingToken);

                // Retention is a housekeeping job, not a per-cycle one.
                if (_legacyStorage.AuditRetentionDays > 0 &&
                    DateTimeOffset.UtcNow - lastPrune > TimeSpan.FromHours(24))
                {
                    await _auditStore.PruneAsync(_legacyStorage.AuditRetentionDays, stoppingToken);
                    lastPrune = DateTimeOffset.UtcNow;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Audit flush cycle failed; records remain buffered.");
            }
        }

        // Shutdown: write what is left rather than dropping it.
        try
        {
            await _auditStore.FlushAsync(CancellationToken.None);
            _logger.LogInformation("Final audit flush complete.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Final audit flush failed; buffered records were lost.");
        }
    }
}
