using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Cloud;

namespace UnifiedGateway.Services.Telemetry;

/// <summary>
/// The durable trail that billing and telemetry are both built from.
/// </summary>
public interface IAuditStore
{
    /// <summary>Queues one invocation record. Returns as soon as it is buffered.</summary>
    Task AppendAsync(RequestLogEntry entry, CancellationToken cancellationToken = default);

    /// <summary>Queues one privileged management action.</summary>
    Task AppendManagementAsync(ManagementAuditEntry entry, CancellationToken cancellationToken = default);

    /// <summary>Invocation records whose timestamp falls inside the window.</summary>
    Task<IReadOnlyList<RequestLogEntry>> ReadInvocationsAsync(
        DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken = default);

    /// <summary>Writes anything buffered. Called on a timer, before reads, and at shutdown.</summary>
    Task FlushAsync(CancellationToken cancellationToken = default);

    /// <summary>Removes partitions older than the retention window.</summary>
    Task PruneAsync(int retentionDays, CancellationToken cancellationToken = default);
}

/// <summary>
/// Audit trail stored as objects in S3.
///
/// S3 objects are immutable, so this cannot append a line per request the way a local file
/// did. Records are buffered and flushed as whole objects — the same shape CloudTrail and
/// ALB access logs use — under a Hive-style date partition:
///
///     audit/dt=2026-09-10/20260910T142233123Z-3f9a2b71.jsonl
///
/// The partition prefix means reading a date range lists only the days it needs, and the
/// layout is directly queryable by Athena or Glue later without a migration.
///
/// The cost of buffering is visibility lag: a record is not readable until its batch lands.
/// Reads therefore flush first, so the dashboard never shows a figure that excludes a request
/// the operator just made.
/// </summary>
public class S3AuditStore : IAuditStore, IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private const string Root = "audit";

    /// <summary>
    /// Record separator. Explicitly LF, not Environment.NewLine: these objects are NDJSON,
    /// read back by this gateway and potentially by Athena or Glue, and a CRLF file written
    /// on Windows would carry a stray carriage return into every parsed record.
    /// </summary>
    private static readonly string LineFeed = ((char)10).ToString();

    private readonly IObjectStore _objectStore;
    private readonly AuditStorageOptions _options;
    private readonly ILogger<S3AuditStore> _logger;

    private readonly ConcurrentQueue<(DateTimeOffset When, string Line)> _buffer = new();
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private DateTimeOffset _lastFlush = DateTimeOffset.UtcNow;

    public S3AuditStore(
        IObjectStore objectStore,
        IOptions<CloudOptions> options,
        ILogger<S3AuditStore> logger)
    {
        _objectStore = objectStore;
        _options = options.Value.Storage;
        _logger = logger;
    }

    #region Write

    public Task AppendAsync(RequestLogEntry entry, CancellationToken cancellationToken = default)
        => EnqueueAsync(entry.Timestamp, JsonSerializer.Serialize(entry, JsonOpts), cancellationToken);

    public Task AppendManagementAsync(ManagementAuditEntry entry, CancellationToken cancellationToken = default)
        => EnqueueAsync(entry.Timestamp, JsonSerializer.Serialize(entry, JsonOpts), cancellationToken);

    private async Task EnqueueAsync(DateTimeOffset when, string line, CancellationToken cancellationToken)
    {
        _buffer.Enqueue((when, line));

        // Flush on size so a burst does not sit unwritten, and so a crash loses at most one
        // batch rather than a whole interval's worth.
        if (_buffer.Count >= Math.Max(1, _options.FlushBatchSize))
        {
            await FlushAsync(cancellationToken);
        }
    }

    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        if (_buffer.IsEmpty) return;

        await _flushLock.WaitAsync(cancellationToken);
        try
        {
            if (_buffer.IsEmpty) return;

            var pending = new List<(DateTimeOffset When, string Line)>();
            while (_buffer.TryDequeue(out var item))
            {
                pending.Add(item);
            }

            if (pending.Count == 0) return;

            // Partition by the record's own timestamp, not by when the flush happens. A batch
            // written just after midnight still contains yesterday's requests, and filing those
            // under today would hide them from any query for yesterday.
            var failed = new List<(DateTimeOffset When, string Line)>();

            foreach (var day in pending.GroupBy(p => p.When.UtcDateTime.Date))
            {
                var now = DateTimeOffset.UtcNow;

                // Timestamp first so keys sort chronologically within a partition; a short random
                // suffix keeps two instances flushing in the same millisecond from colliding.
                var suffix = Guid.NewGuid().ToString("N")[..8];
                var key = $"{Root}/dt={day.Key:yyyy-MM-dd}/{now:yyyyMMdd'T'HHmmssfff}Z-{suffix}.jsonl";
                var body = string.Join(LineFeed, day.Select(d => d.Line)) + LineFeed;
                var payload = Encoding.UTF8.GetBytes(body);

                try
                {
                    await _objectStore.PutAsync(key, payload, "application/x-ndjson", cancellationToken);
                    _lastFlush = now;

                    _logger.LogDebug("Flushed {Count} audit record(s) to {Key}.", day.Count(), key);
                }
                catch (Exception ex)
                {
                    // Keep the records so the next flush retries them. Losing billing data to a
                    // transient S3 error would silently understate an invoice.
                    failed.AddRange(day);
                    _logger.LogError(ex, "Failed to flush {Count} audit record(s) to {Key}.", day.Count(), key);
                }
            }

            foreach (var item in failed)
            {
                _buffer.Enqueue(item);
            }
        }
        finally
        {
            _flushLock.Release();
        }
    }

    /// <summary>True when the interval has elapsed and there is something to write.</summary>
    public bool IsFlushDue() =>
        !_buffer.IsEmpty &&
        DateTimeOffset.UtcNow - _lastFlush >= TimeSpan.FromSeconds(Math.Max(1, _options.FlushIntervalSeconds));

    #endregion

    #region Read

    public async Task<IReadOnlyList<RequestLogEntry>> ReadInvocationsAsync(
        DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken = default)
    {
        // Anything still buffered belongs in this answer.
        await FlushAsync(cancellationToken);

        var entries = new List<RequestLogEntry>();

        foreach (var day in DaysBetween(from, to))
        {
            var prefix = $"{Root}/dt={day:yyyy-MM-dd}/";

            IReadOnlyList<string> keys;
            try
            {
                keys = await _objectStore.ListAsync(prefix, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not list audit partition {Prefix}.", prefix);
                continue;
            }

            foreach (var key in keys)
            {
                cancellationToken.ThrowIfCancellationRequested();

                byte[]? body;
                try
                {
                    body = await _objectStore.GetAsync(key, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not read audit object {Key}.", key);
                    continue;
                }

                if (body is null || body.Length == 0) continue;

                foreach (var line in Encoding.UTF8.GetString(body).Split('\n'))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    // Management actions share the trail and are not billable invocations.
                    if (line.Contains("\"kind\":\"management\"", StringComparison.Ordinal)) continue;

                    try
                    {
                        var entry = JsonSerializer.Deserialize<RequestLogEntry>(line, JsonOpts);
                        if (entry is null) continue;
                        if (entry.Timestamp < from || entry.Timestamp > to) continue;

                        entries.Add(entry);
                    }
                    catch (JsonException)
                    {
                        // A truncated trailing line must not fail the whole invoice.
                    }
                }
            }
        }

        return entries;
    }

    /// <summary>UTC days the window touches, so only those partitions are listed.</summary>
    private static IEnumerable<DateTime> DaysBetween(DateTimeOffset from, DateTimeOffset to)
    {
        var day = from.UtcDateTime.Date;
        var last = to.UtcDateTime.Date;

        while (day <= last)
        {
            yield return day;
            day = day.AddDays(1);
        }
    }

    #endregion

    #region Retention

    public async Task PruneAsync(int retentionDays, CancellationToken cancellationToken = default)
    {
        if (retentionDays <= 0) return;

        var cutoff = DateTime.UtcNow.Date.AddDays(-retentionDays);

        IReadOnlyList<string> keys;
        try
        {
            keys = await _objectStore.ListAsync($"{Root}/", cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not list the audit trail for pruning.");
            return;
        }

        var removed = 0;

        foreach (var key in keys)
        {
            if (!TryPartitionDate(key, out var day) || day >= cutoff) continue;

            try
            {
                await _objectStore.DeleteAsync(key, cancellationToken);
                removed++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not prune audit object {Key}.", key);
            }
        }

        if (removed > 0)
        {
            _logger.LogInformation("Pruned {Count} audit object(s) older than {Days} days.", removed, retentionDays);
        }
    }

    /// <summary>Reads the date out of an "audit/dt=YYYY-MM-DD/..." key.</summary>
    private static bool TryPartitionDate(string key, out DateTime day)
    {
        day = default;

        var marker = key.IndexOf("dt=", StringComparison.Ordinal);
        if (marker < 0 || key.Length < marker + 13) return false;

        return DateTime.TryParseExact(
            key.Substring(marker + 3, 10), "yyyy-MM-dd",
            CultureInfo.InvariantCulture, DateTimeStyles.None, out day);
    }

    #endregion

    public async ValueTask DisposeAsync()
    {
        // Anything still buffered at shutdown is written rather than dropped.
        try
        {
            await FlushAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Final audit flush failed; buffered records were lost.");
        }

        _flushLock.Dispose();
        GC.SuppressFinalize(this);
    }
}
