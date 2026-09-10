using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Telemetry;

namespace UnifiedGateway.Services;

public interface IBillingService
{
    /// <summary>Account-wide summary plus a per-application breakdown at the requested grain.</summary>
    Task<BillingSummary> GetSummaryAsync(
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default);

    /// <summary>Billing detail for a single application, or null when it has no billable history.</summary>
    Task<ApplicationBilling?> GetApplicationBillingAsync(
        string appId,
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default);

    /// <summary>The same rows the summary is built from, as CSV, for finance to reconcile against.</summary>
    Task<string> ExportCsvAsync(
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default);

    /// <summary>The same rows as a real .xlsx workbook, so Excel opens it without an import step.</summary>
    Task<byte[]> ExportXlsxAsync(
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Builds billing figures from the durable audit trail rather than the in-memory metrics
/// buffer, so totals survive a restart and cover the full retention window instead of the
/// last few hundred requests.
///
/// Every line was priced when it was written (see ApplicationRegistryService.PriceEntry),
/// so this class only ever sums; it never re-prices. That is what makes a re-run of a past
/// period reproduce the same invoice.
/// </summary>
public class BillingService : IBillingService
{
    private static readonly JsonSerializerOptions AuditJsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private readonly IApplicationRegistryService _registry;
    private readonly IAuditStore _auditStore;
    private readonly BillingOptions _billing;
    private readonly ILogger<BillingService> _logger;
    private readonly string _auditDirectory;

    public BillingService(
        IApplicationRegistryService registry,
        IAuditStore auditStore,
        IOptions<BillingOptions> billingOptions,
        ILogger<BillingService> logger)
    {
        _registry = registry;
        _auditStore = auditStore;
        _billing = billingOptions.Value;
        _logger = logger;
    }

    #region Public API

    public async Task<BillingSummary> GetSummaryAsync(
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default)
    {
        var (windowStart, windowEnd) = ResolveWindow(grain, from, to);
        var entries = await LoadEntriesAsync(windowStart, windowEnd, cancellationToken);

        // The preceding window of the same length. Comparing a 7-day total against a
        // calendar month would make the headline percentage meaningless.
        var windowLength = windowEnd - windowStart;
        var priorEntries = await LoadEntriesAsync(
            windowStart - windowLength, windowStart.AddTicks(-1), cancellationToken);
        var priorCost = priorEntries.Sum(e => e.TotalCost);

        var apps = await _registry.GetAllAppsAsync(cancellationToken);
        var appsById = apps.ToDictionary(a => a.AppId, StringComparer.OrdinalIgnoreCase);

        var now = DateTimeOffset.UtcNow;
        var monthStart = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var previousMonthStart = monthStart.AddMonths(-1);
        var last24h = now.AddHours(-24);
        var last7d = now.AddDays(-7);

        var totalCost = entries.Sum(e => e.TotalCost);
        var monthToDate = entries.Where(e => e.Timestamp >= monthStart).Sum(e => e.TotalCost);
        var previousMonth = entries
            .Where(e => e.Timestamp >= previousMonthStart && e.Timestamp < monthStart)
            .Sum(e => e.TotalCost);

        var applications = BuildApplicationBilling(entries, appsById, grain, totalCost, now, windowStart, windowEnd);

        // Applications that ran in this window but are no longer registered still owe money;
        // dropping them would understate the bill.
        var unregistered = applications.Count(a => !a.IsRegistered);

        var missingRates = apps
            .Where(a => a.InputCostPerMillion <= 0m && a.OutputCostPerMillion <= 0m)
            .Select(a => a.AppId)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new BillingSummary
        {
            Currency = _billing.Currency,
            GeneratedAt = now,
            WindowStart = windowStart,
            WindowEnd = windowEnd,

            TotalCost = totalCost,
            MonthToDateCost = monthToDate,
            PreviousMonthCost = previousMonth,
            Last24HoursCost = entries.Where(e => e.Timestamp >= last24h).Sum(e => e.TotalCost),
            Last7DaysCost = entries.Where(e => e.Timestamp >= last7d).Sum(e => e.TotalCost),
            ProjectedMonthCost = Money(ProjectMonth(monthToDate, now)),

            MonthlyBudget = _billing.MonthlyBudget,
            BudgetUsedPercent = _billing.MonthlyBudget > 0m
                ? Math.Round((double)(monthToDate / _billing.MonthlyBudget) * 100.0, 1)
                : null,

            TotalRequests = entries.Count,
            TotalInputTokens = entries.Sum(e => (long)e.InputTokens),
            TotalOutputTokens = entries.Sum(e => (long)e.OutputTokens),
            EstimatedRequests = entries.Count(e => e.IsEstimatedCost),
            UnregisteredApplicationCount = unregistered,
            ApplicationsMissingRates = missingRates,

            PreviousPeriodCost = priorCost,
            ChangeVsPreviousPercent = priorCost > 0m
                ? Math.Round((double)((totalCost - priorCost) / priorCost) * 100.0, 1)
                : null,

            CloudCost = CostForProviders(entries, cloud: true),
            LocalCost = CostForProviders(entries, cloud: false),
            TokenEfficiency = Efficiency(
                entries.Sum(e => (long)e.InputTokens),
                entries.Sum(e => (long)e.OutputTokens)),

            Models = entries
                .Select(e => e.Model)
                .Where(m => !string.IsNullOrWhiteSpace(m))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(m => m, StringComparer.OrdinalIgnoreCase)
                .ToList(),

            Grain = grain,
            Buckets = BuildBuckets(entries, grain, windowStart, windowEnd),
            Applications = applications
        };
    }

    public async Task<ApplicationBilling?> GetApplicationBillingAsync(
        string appId,
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default)
    {
        var (windowStart, windowEnd) = ResolveWindow(grain, from, to);
        var entries = (await LoadEntriesAsync(windowStart, windowEnd, cancellationToken))
            .Where(e => string.Equals(e.AppId, appId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var app = await _registry.GetAppAsync(appId, cancellationToken);
        if (entries.Count == 0 && app is null)
        {
            return null;
        }

        var appsById = app is null
            ? new Dictionary<string, AppConfig>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, AppConfig>(StringComparer.OrdinalIgnoreCase) { [app.AppId] = app };

        var totalCost = entries.Sum(e => e.TotalCost);
        var result = BuildApplicationBilling(
                entries, appsById, grain, totalCost, DateTimeOffset.UtcNow, windowStart, windowEnd)
            .FirstOrDefault();

        if (result is null)
        {
            // Registered but never invoked: report a zero line rather than a 404, so the
            // page can show the rate card of an application that has not billed yet.
            return new ApplicationBilling
            {
                AppId = app!.AppId,
                Name = app.Name,
                Provider = app.Provider,
                Model = app.Model,
                IsActive = app.IsActive,
                IsRegistered = true,
                InputCostPerMillion = app.InputCostPerMillion,
                OutputCostPerMillion = app.OutputCostPerMillion,
                Grain = grain,
                Buckets = BuildBuckets([], grain, windowStart, windowEnd)
            };
        }

        return result with { Buckets = BuildBuckets(entries, grain, windowStart, windowEnd) };
    }

    public async Task<string> ExportCsvAsync(
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default)
    {
        var summary = await GetSummaryAsync(grain, from, to, cancellationToken);

        var csv = new System.Text.StringBuilder();
        csv.AppendLine("period,appId,appName,requests,inputTokens,outputTokens,totalTokens," +
                       "inputRatePerMillion,outputRatePerMillion,cost,currency,estimated");

        var (windowStart, windowEnd) = ResolveWindow(grain, from, to);
        var entries = await LoadEntriesAsync(windowStart, windowEnd, cancellationToken);

        var rows = entries
            .GroupBy(e => (Period: PeriodKey(e.Timestamp, grain), AppId: e.AppId ?? "(unattributed)"))
            .OrderBy(g => g.Key.Period, StringComparer.Ordinal)
            .ThenBy(g => g.Key.AppId, StringComparer.OrdinalIgnoreCase);

        var nameById = summary.Applications.ToDictionary(a => a.AppId, a => a.Name, StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows)
        {
            var name = nameById.TryGetValue(row.Key.AppId, out var n) ? n : row.Key.AppId;
            var inputRate = row.Select(e => e.InputRatePerMillion).DefaultIfEmpty(0m).Max();
            var outputRate = row.Select(e => e.OutputRatePerMillion).DefaultIfEmpty(0m).Max();

            csv.Append(Csv(row.Key.Period)).Append(',')
               .Append(Csv(row.Key.AppId)).Append(',')
               .Append(Csv(name)).Append(',')
               .Append(row.Count()).Append(',')
               .Append(row.Sum(e => (long)e.InputTokens)).Append(',')
               .Append(row.Sum(e => (long)e.OutputTokens)).Append(',')
               .Append(row.Sum(e => (long)e.InputTokens + e.OutputTokens)).Append(',')
               .Append(inputRate.ToString(CultureInfo.InvariantCulture)).Append(',')
               .Append(outputRate.ToString(CultureInfo.InvariantCulture)).Append(',')
               .Append(Money(row.Sum(e => e.TotalCost)).ToString(CultureInfo.InvariantCulture)).Append(',')
               .Append(Csv(summary.Currency)).Append(',')
               .Append(row.Any(e => e.IsEstimatedCost) ? "true" : "false")
               .AppendLine();
        }

        return csv.ToString();
    }

    public async Task<byte[]> ExportXlsxAsync(
        BillingGrain grain,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken cancellationToken = default)
    {
        var summary = await GetSummaryAsync(grain, from, to, cancellationToken);

        string[] headers =
        [
            "Application", "App ID", "Provider", "Model",
            "Requests", "Input tokens", "Output tokens", "Total tokens",
            "Input rate / 1M", "Output rate / 1M",
            $"Cost ({summary.Currency})", "Share of spend %", "Cost per request", "Token efficiency",
            "Registered"
        ];

        // Numbers go in as numbers, not text: the point of a workbook over a CSV is that
        // finance can sum a column without re-typing it first.
        var rows = summary.Applications.Select(a => new[]
        {
            XlsxCell.Str(a.Name),
            XlsxCell.Str(a.AppId),
            XlsxCell.Str(a.Provider),
            XlsxCell.Str(a.Model),
            XlsxCell.Num(a.Requests),
            XlsxCell.Num(a.InputTokens),
            XlsxCell.Num(a.OutputTokens),
            XlsxCell.Num(a.TotalTokens),
            XlsxCell.Num(a.InputCostPerMillion),
            XlsxCell.Num(a.OutputCostPerMillion),
            XlsxCell.Num(a.TotalCost),
            XlsxCell.Num((decimal)a.ShareOfTotalPercent),
            XlsxCell.Num(a.AverageCostPerRequest),
            XlsxCell.Num((decimal)a.TokenEfficiency),
            XlsxCell.Str(a.IsRegistered ? "yes" : "deleted")
        }).ToList();

        var sheet = $"Spend {summary.WindowStart:yyyy-MM-dd} to {summary.WindowEnd:yyyy-MM-dd}";
        return XlsxWriter.Write(sheet, headers, rows);
    }
    #endregion

    #region Aggregation

    private List<ApplicationBilling> BuildApplicationBilling(
        List<RequestLogEntry> entries,
        Dictionary<string, AppConfig> appsById,
        BillingGrain grain,
        decimal accountTotal,
        DateTimeOffset now,
        DateTimeOffset windowStart,
        DateTimeOffset windowEnd)
    {
        var monthStart = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero);
        var last24h = now.AddHours(-24);

        return entries
            .GroupBy(e => string.IsNullOrWhiteSpace(e.AppId) ? "(unattributed)" : e.AppId,
                     StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var appId = group.Key;
                appsById.TryGetValue(appId, out var app);

                var cost = group.Sum(e => e.TotalCost);
                var requests = group.LongCount();

                return new ApplicationBilling
                {
                    AppId = appId,
                    Name = app?.Name ?? (appId == "(unattributed)" ? "Direct / universal invocations" : appId),
                    Provider = app?.Provider ?? group.Select(e => e.Provider).FirstOrDefault(p => !string.IsNullOrEmpty(p)) ?? "-",
                    Model = app?.Model ?? group.Select(e => e.Model).FirstOrDefault(m => !string.IsNullOrEmpty(m)) ?? "-",
                    IsActive = app?.IsActive ?? false,
                    IsRegistered = app is not null,

                    // The rate card as it stands now. Historical lines keep the rate they
                    // were billed at, which is why the CSV export reports rates per row.
                    InputCostPerMillion = app?.InputCostPerMillion
                        ?? group.Select(e => e.InputRatePerMillion).DefaultIfEmpty(0m).Max(),
                    OutputCostPerMillion = app?.OutputCostPerMillion
                        ?? group.Select(e => e.OutputRatePerMillion).DefaultIfEmpty(0m).Max(),

                    Requests = requests,
                    InputTokens = group.Sum(e => (long)e.InputTokens),
                    OutputTokens = group.Sum(e => (long)e.OutputTokens),
                    TotalCost = cost,
                    MonthToDateCost = group.Where(e => e.Timestamp >= monthStart).Sum(e => e.TotalCost),
                    Last24HoursCost = group.Where(e => e.Timestamp >= last24h).Sum(e => e.TotalCost),
                    AverageCostPerRequest = requests > 0
                        ? Math.Round(cost / requests, 6, MidpointRounding.AwayFromZero)
                        : 0m,
                    ShareOfTotalPercent = accountTotal > 0m
                        ? Math.Round((double)(cost / accountTotal) * 100.0, 1)
                        : 0.0,

                    CloudCost = CostForProviders(group, cloud: true),
                    LocalCost = CostForProviders(group, cloud: false),
                    TokenEfficiency = Efficiency(
                        group.Sum(e => (long)e.InputTokens),
                        group.Sum(e => (long)e.OutputTokens)),

                    // Cost per bucket, so each row can draw a sparkline without a
                    // follow-up request per application.
                    Trend = BuildBuckets(group.ToList(), grain, windowStart, windowEnd)
                        .Select(b => b.TotalCost)
                        .ToList(),

                    Grain = grain
                };
            })
            .OrderByDescending(a => a.TotalCost)
            .ThenBy(a => a.AppId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }


    /// <summary>
    /// Splits cost by where the work ran. "bedrock"/"aws" is billed by a cloud provider;
    /// anything else is a locally hosted model, where the marginal cost is electricity
    /// rather than an invoice. Keeping the two apart is the point of a hybrid gateway.
    /// </summary>
    private static decimal CostForProviders(IEnumerable<RequestLogEntry> entries, bool cloud)
    {
        return entries
            .Where(e => IsCloudProvider(e.Provider) == cloud)
            .Sum(e => e.TotalCost);
    }

    private static bool IsCloudProvider(string? provider) =>
        provider is not null &&
        (provider.Equals("bedrock", StringComparison.OrdinalIgnoreCase) ||
         provider.Equals("aws", StringComparison.OrdinalIgnoreCase));

    /// <summary>Output tokens produced per input token.</summary>
    private static double Efficiency(long inputTokens, long outputTokens) =>
        inputTokens > 0 ? Math.Round((double)outputTokens / inputTokens, 3) : 0.0;
    /// <summary>
    /// Buckets the window at the requested grain, emitting empty periods too. A gap in a
    /// spend chart should read as "nothing was spent", not as a missing data point.
    /// </summary>
    private static List<BillingBucket> BuildBuckets(
        List<RequestLogEntry> entries,
        BillingGrain grain,
        DateTimeOffset windowStart,
        DateTimeOffset windowEnd)
    {
        var byPeriod = entries
            .GroupBy(e => PeriodKey(e.Timestamp, grain))
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);

        var buckets = new List<BillingBucket>();

        foreach (var (start, end) in EnumeratePeriods(grain, windowStart, windowEnd))
        {
            var key = PeriodKey(start, grain);
            byPeriod.TryGetValue(key, out var rows);
            rows ??= [];

            buckets.Add(new BillingBucket
            {
                Period = key,
                PeriodStart = start,
                PeriodEnd = end,
                Requests = rows.Count,
                InputTokens = rows.Sum(e => (long)e.InputTokens),
                OutputTokens = rows.Sum(e => (long)e.OutputTokens),
                InputCost = rows.Sum(e => e.InputCost),
                OutputCost = rows.Sum(e => e.OutputCost),
                EstimatedRequests = rows.Count(e => e.IsEstimatedCost)
            });
        }

        return buckets;
    }

    private static IEnumerable<(DateTimeOffset Start, DateTimeOffset End)> EnumeratePeriods(
        BillingGrain grain, DateTimeOffset windowStart, DateTimeOffset windowEnd)
    {
        var cursor = TruncateTo(windowStart, grain);

        while (cursor <= windowEnd)
        {
            var next = grain switch
            {
                BillingGrain.Daily => cursor.AddDays(1),
                BillingGrain.Weekly => cursor.AddDays(7),
                BillingGrain.Monthly => cursor.AddMonths(1),
                _ => cursor.AddDays(1)
            };

            yield return (cursor, next.AddTicks(-1));
            cursor = next;
        }
    }

    private static DateTimeOffset TruncateTo(DateTimeOffset value, BillingGrain grain)
    {
        var utc = value.ToUniversalTime();

        return grain switch
        {
            BillingGrain.Daily => new DateTimeOffset(utc.Year, utc.Month, utc.Day, 0, 0, 0, TimeSpan.Zero),
            BillingGrain.Weekly => StartOfIsoWeek(utc),
            BillingGrain.Monthly => new DateTimeOffset(utc.Year, utc.Month, 1, 0, 0, 0, TimeSpan.Zero),
            _ => new DateTimeOffset(utc.Year, utc.Month, utc.Day, 0, 0, 0, TimeSpan.Zero)
        };
    }

    /// <summary>ISO-8601 weeks start on Monday, which is what finance reporting expects.</summary>
    private static DateTimeOffset StartOfIsoWeek(DateTimeOffset value)
    {
        var day = new DateTimeOffset(value.Year, value.Month, value.Day, 0, 0, 0, TimeSpan.Zero);
        var offset = ((int)day.DayOfWeek + 6) % 7; // Monday = 0
        return day.AddDays(-offset);
    }

    private static string PeriodKey(DateTimeOffset value, BillingGrain grain)
    {
        var utc = value.ToUniversalTime();

        return grain switch
        {
            BillingGrain.Daily => utc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            BillingGrain.Weekly => IsoWeekKey(utc),
            BillingGrain.Monthly => utc.ToString("yyyy-MM", CultureInfo.InvariantCulture),
            _ => utc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
        };
    }

    private static string IsoWeekKey(DateTimeOffset value)
    {
        var date = value.UtcDateTime.Date;
        var week = ISOWeek.GetWeekOfYear(date);
        var year = ISOWeek.GetYear(date);
        return $"{year}-W{week:D2}";
    }

    private (DateTimeOffset Start, DateTimeOffset End) ResolveWindow(
        BillingGrain grain, DateTimeOffset? from, DateTimeOffset? to)
    {
        var end = (to ?? DateTimeOffset.UtcNow).ToUniversalTime();

        if (from.HasValue)
        {
            return (from.Value.ToUniversalTime(), end);
        }

        var start = grain switch
        {
            BillingGrain.Daily => end.AddDays(-Math.Max(1, _billing.DailyWindowDays) + 1),
            BillingGrain.Weekly => end.AddDays(-7 * Math.Max(1, _billing.WeeklyWindowWeeks) + 1),
            BillingGrain.Monthly => end.AddMonths(-Math.Max(1, _billing.MonthlyWindowMonths) + 1),
            _ => end.AddDays(-29)
        };

        return (TruncateTo(start, grain), end);
    }

    /// <summary>
    /// Straight-line projection of the current month from spend so far. Deliberately naive:
    /// it says "at today's rate", and is labelled that way rather than sold as a forecast.
    /// </summary>
    private static decimal ProjectMonth(decimal monthToDate, DateTimeOffset now)
    {
        var daysElapsed = now.Day - 1 + (now.TimeOfDay.TotalHours / 24.0);
        if (daysElapsed <= 0.01) return monthToDate;

        var daysInMonth = DateTime.DaysInMonth(now.Year, now.Month);
        return monthToDate / (decimal)daysElapsed * daysInMonth;
    }

    #endregion

    #region Audit trail reading

    /// <summary>
    /// Invocation records for the window, from object storage. The store flushes anything
    /// still buffered before it answers, so a figure never excludes a request the operator
    /// just made.
    /// </summary>
    private async Task<List<RequestLogEntry>> LoadEntriesAsync(
        DateTimeOffset windowStart, DateTimeOffset windowEnd, CancellationToken cancellationToken)
    {
        try
        {
            var entries = await _auditStore.ReadInvocationsAsync(windowStart, windowEnd, cancellationToken);
            return entries.ToList();
        }
        catch (Exception ex)
        {
            // An empty invoice is a visible problem; a wrong one is not. Log loudly and
            // return nothing rather than a partial total presented as complete.
            _logger.LogError(ex, "Could not read the audit trail for {From:u} to {To:u}.", windowStart, windowEnd);
            return [];
        }
    }

    #endregion

    /// <summary>
    /// Escapes a CSV field.
    ///
    /// Application names are operator-supplied and this file is opened in a spreadsheet, so
    /// a leading =, +, - or @ is prefixed with an apostrophe: otherwise a name like
    /// "=HYPERLINK(...)" becomes a live formula in the finance team's Excel.
    /// </summary>
    private static string Csv(string? value)
    {
        const char Quote = '"';
        var text = value ?? string.Empty;

        // Formula injection: a cell starting with =, +, - or @ is evaluated by Excel,
        // and these names are operator-supplied. Prefix it so it stays inert text.
        if (text.Length > 0 && (text[0] is '=' or '+' or '-' or '@' || char.IsControl(text[0])))
        {
            text = "'" + text;
        }

        if (text.Any(c => c == ',' || c == Quote || char.IsControl(c)))
        {
            text = Quote + text.Replace(Quote.ToString(), new string(Quote, 2)) + Quote;
        }

        return text;
    }

    /// <summary>
    /// Rounds a DERIVED value (one produced by division) to six places.
    ///
    /// Plain sums are never routed through this. Line items are already six-place, so
    /// adding them is exact in decimal; rounding each aggregate again -- and rounding
    /// input and output separately before adding -- is what makes the parts stop summing
    /// to the whole. Presentation rounds to currency; the API reconciles exactly.
    /// </summary>
    private static decimal Money(decimal value) => Math.Round(value, 6, MidpointRounding.AwayFromZero);
}
