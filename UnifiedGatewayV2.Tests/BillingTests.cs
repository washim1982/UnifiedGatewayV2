using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services;
using UnifiedGateway.Services.Cloud;
using UnifiedGateway.Services.Telemetry;
using Xunit;

namespace UnifiedGatewayV2.Tests;

/// <summary>
/// Covers pricing at write time and aggregation out of the audit trail. The fixture writes
/// real audit files, so these exercise the same path production billing reads.
/// </summary>
public class BillingTests
{
    private static readonly JsonSerializerOptions AuditJsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private readonly InMemoryObjectStore _objectStore = new();

    // The audit trail lives in the object store, but the application registry is still a
    // file. Each test gets its own directory so registrations do not leak between them.
    private readonly string _dataDir =
        Path.Combine(Path.GetTempPath(), "ug-billing-" + Guid.NewGuid().ToString("N"));

    private readonly GatewayOptions _gatewayOptions;
    private readonly CloudOptions _cloudOptions = new()
    {
        // Flush on every record so a test never has to wait on the interval.
        Storage = new AuditStorageOptions { Bucket = "test-telemetry", FlushBatchSize = 1 }
    };

    public BillingTests()
    {
        _gatewayOptions = new GatewayOptions
        {
            Storage = new StorageOptions
            {
                DataDirectory = _dataDir,
                RegistryFileName = "registry.json"
            }
        };
    }

    private S3AuditStore CreateAuditStore() =>
        new(_objectStore, Options.Create(_cloudOptions), NullLogger<S3AuditStore>.Instance);

    // --- Pricing at write time -------------------------------------------------------

    private ApplicationRegistryService CreateRegistry(
        GatewayOptions gatewayOptions, BillingOptions? billing = null, IAuditStore? auditStore = null)
    {
        var (security, _) = TestFactory.CreateSecurityService();
        return new ApplicationRegistryService(
            security,
            new StubAdminCredentialService(security, "ug-test-admin-secret-key-value"),
            Options.Create(gatewayOptions),
            Options.Create(billing ?? new BillingOptions()),
            auditStore ?? CreateAuditStore(),
            NullLogger<ApplicationRegistryService>.Instance);
    }

    [Fact]
    public async Task RequestCost_UsesTheApplicationsRateCard()
    {
        var registry = CreateRegistry(_gatewayOptions);

        await registry.CreateAppAsync(new CreateAppRequest
        {
            AppId = "priced-app",
            Name = "Priced",
            InputCostPerMillion = 3.00m,
            OutputCostPerMillion = 15.00m
        });

        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "priced-app",
            InputTokens = 1_000_000,
            OutputTokens = 1_000_000,
            Success = true,
            Provider = "bedrock"
        });

        var billing = new BillingService(
            registry, CreateAuditStore(), Options.Create(new BillingOptions()),
            NullLogger<BillingService>.Instance);

        var summary = await billing.GetSummaryAsync(BillingGrain.Daily);

        // 1M input at $3 + 1M output at $15.
        Assert.Equal(18.00m, summary.TotalCost);
        Assert.Equal(0, summary.EstimatedRequests);
    }

    [Fact]
    public async Task PartialMillionTokens_ArePricedProRata()
    {
        var registry = CreateRegistry(_gatewayOptions);
        await registry.CreateAppAsync(new CreateAppRequest
        {
            AppId = "prorata-app",
            Name = "Pro rata",
            InputCostPerMillion = 10.00m,
            OutputCostPerMillion = 30.00m
        });

        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "prorata-app",
            InputTokens = 250_000,   // 0.25M at $10 = $2.50
            OutputTokens = 100_000,  // 0.10M at $30 = $3.00
            Success = true
        });

        var billing = new BillingService(
            registry, CreateAuditStore(), Options.Create(new BillingOptions()),
            NullLogger<BillingService>.Instance);

        Assert.Equal(5.50m, (await billing.GetSummaryAsync(BillingGrain.Daily)).TotalCost);
    }

    [Fact]
    public async Task ApplicationWithoutRates_FallsBackToTheDefaultAndIsFlaggedEstimated()
    {
        var billingOptions = new BillingOptions
        {
            DefaultInputCostPerMillion = 1.00m,
            DefaultOutputCostPerMillion = 2.00m
        };

        var registry = CreateRegistry(_gatewayOptions, billingOptions);
        await registry.CreateAppAsync(new CreateAppRequest { AppId = "unpriced-app", Name = "Unpriced" });

        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "unpriced-app",
            InputTokens = 1_000_000,
            OutputTokens = 1_000_000,
            Success = true
        });

        var billing = new BillingService(
            registry, CreateAuditStore(), Options.Create(billingOptions),
            NullLogger<BillingService>.Instance);

        var summary = await billing.GetSummaryAsync(BillingGrain.Daily);

        Assert.Equal(3.00m, summary.TotalCost);
        Assert.Equal(1, summary.EstimatedRequests);
        Assert.Contains("unpriced-app", summary.ApplicationsMissingRates);
    }

    [Fact]
    public async Task RepricingAnApplication_DoesNotRestatePastCharges()
    {
        var registry = CreateRegistry(_gatewayOptions);
        await registry.CreateAppAsync(new CreateAppRequest
        {
            AppId = "reprice-app",
            Name = "Reprice",
            InputCostPerMillion = 2.00m,
            OutputCostPerMillion = 2.00m
        });

        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "reprice-app", InputTokens = 1_000_000, OutputTokens = 0, Success = true
        });

        // Ten times the price, applied after the fact.
        await registry.UpdateAppAsync("reprice-app", new UpdateAppRequest
        {
            InputCostPerMillion = 20.00m,
            OutputCostPerMillion = 20.00m
        });

        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "reprice-app", InputTokens = 1_000_000, OutputTokens = 0, Success = true
        });

        var billing = new BillingService(
            registry, CreateAuditStore(), Options.Create(new BillingOptions()),
            NullLogger<BillingService>.Instance);

        // $2 at the old rate + $20 at the new one. A re-price must not turn the first
        // request into $20 retroactively.
        Assert.Equal(22.00m, (await billing.GetSummaryAsync(BillingGrain.Daily)).TotalCost);
    }

    // --- Aggregation over a written audit trail ----------------------------------------

    /// <summary>Writes records through the real audit store, so they land as S3 objects.</summary>
    private async Task WriteAuditAsync(params RequestLogEntry[] entries)
    {
        var store = CreateAuditStore();
        foreach (var entry in entries)
        {
            await store.AppendAsync(entry);
        }
        await store.FlushAsync();
    }
    private static RequestLogEntry Entry(string appId, DateTimeOffset when, int inTok, int outTok, decimal cost) => new()
    {
        AppId = appId,
        Timestamp = when,
        InputTokens = inTok,
        OutputTokens = outTok,
        InputCost = cost / 2m,
        OutputCost = cost / 2m,
        InputRatePerMillion = 1m,
        OutputRatePerMillion = 1m,
        Success = true,
        Provider = "bedrock",
        Model = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    };

    private BillingService CreateBilling(BillingOptions? options = null)
    {
        var registry = CreateRegistry(_gatewayOptions);
        return new BillingService(
            registry, CreateAuditStore(),
            Options.Create(options ?? new BillingOptions()),
            NullLogger<BillingService>.Instance);
    }

    [Theory]
    [InlineData(BillingGrain.Daily)]
    [InlineData(BillingGrain.Weekly)]
    [InlineData(BillingGrain.Monthly)]
    public async Task EveryGrain_TotalsToTheSameAmount(BillingGrain grain)
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("app-a", now.AddDays(-1), 1000, 500, 10m),
            Entry("app-a", now.AddDays(-3), 1000, 500, 20m),
            Entry("app-b", now.AddDays(-5), 2000, 800, 30m));

        var summary = await CreateBilling().GetSummaryAsync(grain);

        // Grain changes the bucketing, never the total.
        Assert.Equal(60m, summary.TotalCost);
        Assert.Equal(60m, summary.Buckets.Sum(b => b.TotalCost));
        Assert.Equal(60m, summary.Applications.Sum(a => a.TotalCost));
        Assert.Equal(grain, summary.Grain);
    }

    [Fact]
    public async Task DailyBuckets_CoverEveryDayIncludingOnesWithNoSpend()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("app-a", now.AddDays(-2), 1000, 0, 5m));

        var summary = await CreateBilling(new BillingOptions { DailyWindowDays = 7 })
            .GetSummaryAsync(BillingGrain.Daily);

        // A gap must read as "nothing was spent", not as a missing point on the chart.
        Assert.Equal(7, summary.Buckets.Count);
        Assert.Contains(summary.Buckets, b => b.TotalCost == 0m);
        Assert.Equal(5m, summary.Buckets.Sum(b => b.TotalCost));
    }

    [Fact]
    public async Task PerApplicationBreakdown_IsOrderedByCostAndSharesSumTo100()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("cheap-app", now.AddHours(-1), 100, 100, 10m),
            Entry("pricey-app", now.AddHours(-2), 100, 100, 90m));

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);

        Assert.Equal("pricey-app", summary.Applications[0].AppId);
        Assert.Equal(90.0, summary.Applications[0].ShareOfTotalPercent);
        Assert.Equal(10.0, summary.Applications[1].ShareOfTotalPercent);
        Assert.Equal(100.0, summary.Applications.Sum(a => a.ShareOfTotalPercent));
    }

    [Fact]
    public async Task ApplicationsBilledButNoLongerRegistered_StillAppear()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("deleted-app", now.AddHours(-3), 1000, 1000, 42m));

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);

        // Dropping a deleted tenant's history would silently understate the bill.
        var line = Assert.Single(summary.Applications, a => a.AppId == "deleted-app");
        Assert.False(line.IsRegistered);
        Assert.Equal(42m, line.TotalCost);
        Assert.Equal(1, summary.UnregisteredApplicationCount);
    }

    [Fact]
    public async Task ManagementAuditLines_AreNotBilled()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("app-a", now.AddHours(-1), 1000, 1000, 7m));

        // Management actions share the same trail and must be skipped when billing.
        var store = CreateAuditStore();
        await store.AppendManagementAsync(new ManagementAuditEntry
        {
            Action = "RotateApiKey", Resource = "app-a", Actor = "admin", Success = true
        });
        await store.FlushAsync();

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);

        Assert.Equal(7m, summary.TotalCost);
        Assert.Equal(1, summary.TotalRequests);
    }

    [Fact]
    public async Task EntriesOutsideTheWindow_AreExcluded()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("app-a", now.AddHours(-1), 100, 100, 5m),
            Entry("app-a", now.AddDays(-60), 100, 100, 500m));

        var summary = await CreateBilling(new BillingOptions { DailyWindowDays = 7 })
            .GetSummaryAsync(BillingGrain.Daily);

        Assert.Equal(5m, summary.TotalCost);
    }

    [Fact]
    public async Task TornAuditLine_DoesNotFailTheInvoice()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("app-a", now.AddHours(-1), 100, 100, 9m));

        // Append a truncated record to the object that was just written, which is what a
        // partial multipart upload or an interrupted writer leaves behind.
        var key = _objectStore.Keys.Single();
        var existing = await _objectStore.GetAsync(key);
        var corrupted = System.Text.Encoding.UTF8.GetString(existing!) + "{\"appId\":\"app-a\",\"inputTok";
        await _objectStore.PutAsync(key, System.Text.Encoding.UTF8.GetBytes(corrupted), "application/x-ndjson");

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);

        Assert.Equal(9m, summary.TotalCost);
    }

    [Fact]
    public async Task SingleApplicationView_MatchesItsLineInTheSummary()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("app-a", now.AddHours(-1), 1000, 500, 12m),
            Entry("app-b", now.AddHours(-2), 1000, 500, 30m));

        var billing = CreateBilling();
        var summary = await billing.GetSummaryAsync(BillingGrain.Daily);
        var detail = await billing.GetApplicationBillingAsync("app-a", BillingGrain.Daily);

        Assert.NotNull(detail);
        Assert.Equal(summary.Applications.Single(a => a.AppId == "app-a").TotalCost, detail!.TotalCost);
        Assert.Equal(12m, detail.TotalCost);
    }

    [Fact]
    public async Task UnknownApplication_ReturnsNull()
    {
        Assert.Null(await CreateBilling().GetApplicationBillingAsync("no-such-app", BillingGrain.Daily));
    }

    [Fact]
    public async Task BudgetUsage_IsReportedWhenABudgetIsConfigured()
    {
        var now = DateTimeOffset.UtcNow;
        // Place the charge inside the current calendar month so it counts toward MTD.
        await WriteAuditAsync(Entry("app-a", now.AddMinutes(-5), 1000, 1000, 250m));

        var summary = await CreateBilling(new BillingOptions { MonthlyBudget = 1000m })
            .GetSummaryAsync(BillingGrain.Monthly);

        Assert.Equal(1000m, summary.MonthlyBudget);
        Assert.Equal(25.0, summary.BudgetUsedPercent);
    }

    [Fact]
    public async Task NoBudgetConfigured_ReportsNoBudgetUsage()
    {
        await WriteAuditAsync(Entry("app-a", DateTimeOffset.UtcNow.AddMinutes(-5), 100, 100, 5m));

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);
        Assert.Null(summary.BudgetUsedPercent);
    }

    [Theory]
    [InlineData(BillingGrain.Daily)]
    [InlineData(BillingGrain.Weekly)]
    [InlineData(BillingGrain.Monthly)]
    public async Task PartsReconcileExactlyWithTheHeadlineTotal(BillingGrain grain)
    {
        // Sub-cent amounts across several applications and days: the case where rounding
        // each aggregate to currency precision separately makes the chart stop matching
        // the headline figure.
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("app-a", now.AddHours(-1), 212, 319, 0.014405m),
            Entry("app-b", now.AddHours(-2), 205, 307, 0.001392m),
            Entry("app-c", now.AddHours(-3), 238, 358, 0.030420m),
            Entry("app-a", now.AddDays(-2), 100, 100, 0.007777m));

        var summary = await CreateBilling().GetSummaryAsync(grain);

        var bucketSum = summary.Buckets.Sum(b => b.TotalCost);
        var appSum = summary.Applications.Sum(a => a.TotalCost);

        Assert.Equal(summary.TotalCost, bucketSum);
        Assert.Equal(summary.TotalCost, appSum);
    }
    // --- Prior period, provider split, workbook ------------------------------------------

    [Fact]
    public async Task PriorPeriod_ComparesAgainstAWindowOfTheSameLength()
    {
        var now = DateTimeOffset.UtcNow;

        // 7-day window: this period 10, the 7 days before it 5.
        await WriteAuditAsync(
            Entry("app-a", now.AddDays(-1), 100, 100, 10m),
            Entry("app-a", now.AddDays(-9), 100, 100, 5m));

        var summary = await CreateBilling().GetSummaryAsync(
            BillingGrain.Daily, now.AddDays(-6), now);

        Assert.Equal(10m, summary.TotalCost);
        Assert.Equal(5m, summary.PreviousPeriodCost);
        Assert.Equal(100.0, summary.ChangeVsPreviousPercent);
    }

    [Fact]
    public async Task NoPriorSpend_ReportsNoComparison()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("app-a", now.AddHours(-2), 100, 100, 4m));

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily, now.AddDays(-6), now);

        // A percentage against zero is not a number worth showing.
        Assert.Equal(0m, summary.PreviousPeriodCost);
        Assert.Null(summary.ChangeVsPreviousPercent);
    }

    [Fact]
    public async Task CostIsSplitBetweenCloudAndLocalProviders()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("cloud-app", now.AddHours(-1), 100, 100, 30m) with { Provider = "bedrock" },
            Entry("local-app", now.AddHours(-2), 100, 100, 10m) with { Provider = "local" });

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);

        Assert.Equal(30m, summary.CloudCost);
        Assert.Equal(10m, summary.LocalCost);
        Assert.Equal(summary.TotalCost, summary.CloudCost + summary.LocalCost);
    }

    [Fact]
    public async Task TokenEfficiency_IsOutputPerInputToken()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("app-a", now.AddHours(-1), 200, 500, 1m));

        var summary = await CreateBilling().GetSummaryAsync(BillingGrain.Daily);
        Assert.Equal(2.5, summary.TokenEfficiency);
    }

    [Fact]
    public async Task EachApplicationCarriesATrendOfOneValuePerBucket()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(Entry("app-a", now.AddDays(-1), 100, 100, 6m));

        var summary = await CreateBilling(new BillingOptions { DailyWindowDays = 7 })
            .GetSummaryAsync(BillingGrain.Daily);

        var app = Assert.Single(summary.Applications);
        Assert.Equal(summary.Buckets.Count, app.Trend.Count);
        Assert.Equal(app.TotalCost, app.Trend.Sum());
    }

    [Fact]
    public async Task XlsxExport_IsAValidWorkbookWithARowPerApplication()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("app-a", now.AddHours(-1), 100, 200, 12m),
            Entry("app-b", now.AddHours(-2), 100, 200, 30m));

        var bytes = await CreateBilling().ExportXlsxAsync(BillingGrain.Daily);

        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(bytes));

        // The parts Excel refuses to open a workbook without.
        foreach (var part in new[] { "[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/worksheets/sheet1.xml" })
        {
            Assert.NotNull(archive.GetEntry(part));
        }

        var entry = archive.GetEntry("xl/worksheets/sheet1.xml")!;
        using var reader = new StreamReader(entry.Open());
        var sheet = await reader.ReadToEndAsync();

        // Header plus one row per application.
        Assert.Equal(3, System.Text.RegularExpressions.Regex.Matches(sheet, "<row ").Count);
        Assert.Contains("app-a", sheet);
        Assert.Contains("app-b", sheet);
    }

    [Fact]
    public async Task XlsxExport_EscapesMarkupInApplicationNames()
    {
        var registry = CreateRegistry(_gatewayOptions);
        await registry.CreateAppAsync(new CreateAppRequest
        {
            AppId = "xml-app",
            Name = "Ops & <Analytics>",
            InputCostPerMillion = 1m,
            OutputCostPerMillion = 1m
        });
        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "xml-app", InputTokens = 1_000_000, OutputTokens = 0, Success = true
        });

        var billing = new BillingService(
            registry, CreateAuditStore(), Options.Create(new BillingOptions()),
            NullLogger<BillingService>.Instance);

        var bytes = await billing.ExportXlsxAsync(BillingGrain.Daily);
        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(bytes));
        using var reader = new StreamReader(archive.GetEntry("xl/worksheets/sheet1.xml")!.Open());
        var sheet = await reader.ReadToEndAsync();

        // Raw markup would make the workbook unopenable.
        Assert.Contains("Ops &amp; &lt;Analytics&gt;", sheet);
        Assert.DoesNotContain("<Analytics>", sheet);
    }
    // --- Object storage layout ---------------------------------------------------------

    [Fact]
    public async Task RecordsArePartitionedByTheirOwnDate_NotByFlushTime()
    {
        var now = DateTimeOffset.UtcNow;

        // Both written in the same flush, but they belong to different days. Filing them by
        // flush time would hide the older one from any query for its own date.
        var store = CreateAuditStore();
        await store.AppendAsync(Entry("app-a", now, 100, 100, 1m));
        await store.AppendAsync(Entry("app-a", now.AddDays(-3), 100, 100, 2m));
        await store.FlushAsync();

        var today = $"audit/dt={now.UtcDateTime:yyyy-MM-dd}/";
        var earlier = $"audit/dt={now.AddDays(-3).UtcDateTime:yyyy-MM-dd}/";

        Assert.Contains(_objectStore.Keys, k => k.StartsWith(today, StringComparison.Ordinal));
        Assert.Contains(_objectStore.Keys, k => k.StartsWith(earlier, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ObjectsAreNewlineDelimitedJson()
    {
        var now = DateTimeOffset.UtcNow;
        var store = CreateAuditStore();
        await store.AppendAsync(Entry("app-a", now, 100, 100, 1m));
        await store.AppendAsync(Entry("app-b", now, 100, 100, 2m));
        await store.FlushAsync();

        var key = _objectStore.Keys.First();
        var body = System.Text.Encoding.UTF8.GetString((await _objectStore.GetAsync(key))!);

        // LF only: these objects are read back here and are meant to stay Athena-readable.
        Assert.DoesNotContain((char)13, body);
        Assert.EndsWith(".jsonl", key);

        var records = body.Split((char)10, StringSplitOptions.RemoveEmptyEntries);
        foreach (var record in records)
        {
            Assert.NotNull(JsonSerializer.Deserialize<RequestLogEntry>(record, AuditJsonOpts));
        }
    }

    [Fact]
    public async Task ReadFlushesBufferedRecordsFirst()
    {
        // A record appended but not yet flushed must still appear in a bill, or the page
        // would omit the request the operator just made.
        var cloud = new CloudOptions
        {
            Storage = new AuditStorageOptions { Bucket = "test-telemetry", FlushBatchSize = 1000 }
        };
        var store = new S3AuditStore(_objectStore, Options.Create(cloud), NullLogger<S3AuditStore>.Instance);

        await store.AppendAsync(Entry("app-a", DateTimeOffset.UtcNow, 100, 100, 11m));
        Assert.Equal(0, _objectStore.ObjectCount);

        var entries = await store.ReadInvocationsAsync(
            DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));

        Assert.Single(entries);
        Assert.Equal(1, _objectStore.ObjectCount);
    }

    [Fact]
    public async Task AFailedFlushKeepsRecordsBufferedForRetry()
    {
        var failing = new FailingObjectStore();
        var cloud = new CloudOptions
        {
            Storage = new AuditStorageOptions { Bucket = "test-telemetry", FlushBatchSize = 1 }
        };
        var store = new S3AuditStore(failing, Options.Create(cloud), NullLogger<S3AuditStore>.Instance);

        // Losing billing records to a transient storage error would silently understate an
        // invoice, so a failed flush must not drop them.
        await store.AppendAsync(Entry("app-a", DateTimeOffset.UtcNow, 100, 100, 5m));
        await store.FlushAsync();

        var working = new InMemoryObjectStore();
        var recovered = new S3AuditStore(working, Options.Create(cloud), NullLogger<S3AuditStore>.Instance);
        await recovered.AppendAsync(Entry("app-a", DateTimeOffset.UtcNow, 100, 100, 5m));
        await recovered.FlushAsync();

        Assert.Equal(1, working.ObjectCount);
    }

    [Fact]
    public async Task PruneRemovesPartitionsOlderThanRetention()
    {
        var now = DateTimeOffset.UtcNow;
        var store = CreateAuditStore();

        await store.AppendAsync(Entry("app-a", now, 100, 100, 1m));
        await store.AppendAsync(Entry("app-a", now.AddDays(-40), 100, 100, 1m));
        await store.FlushAsync();

        Assert.Equal(2, _objectStore.ObjectCount);

        await store.PruneAsync(retentionDays: 30);

        Assert.Equal(1, _objectStore.ObjectCount);
        Assert.All(_objectStore.Keys, k =>
            Assert.Contains($"dt={now.UtcDateTime:yyyy-MM-dd}", k));
    }
    // --- CSV export ---------------------------------------------------------------------

    [Fact]
    public async Task CsvExport_HasAHeaderAndOneRowPerPeriodAndApplication()
    {
        var now = DateTimeOffset.UtcNow;
        await WriteAuditAsync(
            Entry("app-a", now.AddHours(-1), 1000, 500, 12m),
            Entry("app-b", now.AddHours(-2), 1000, 500, 30m));

        var csv = await CreateBilling().ExportCsvAsync(BillingGrain.Daily);
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.StartsWith("period,appId,appName", lines[0]);
        Assert.Equal(3, lines.Length);
        Assert.Contains(lines, l => l.Contains("app-a") && l.Contains("12"));
    }

    [Fact]
    public async Task CsvExport_NeutralisesSpreadsheetFormulaInjection()
    {
        var registry = CreateRegistry(_gatewayOptions);

        // An operator-supplied name that Excel would otherwise evaluate.
        await registry.CreateAppAsync(new CreateAppRequest
        {
            AppId = "formula-app",
            Name = "=HYPERLINK(\"http://evil\",\"click\")",
            InputCostPerMillion = 1m,
            OutputCostPerMillion = 1m
        });

        await registry.RecordMetricAsync(new RequestLogEntry
        {
            AppId = "formula-app", InputTokens = 1_000_000, OutputTokens = 0, Success = true
        });

        var billing = new BillingService(
            registry, CreateAuditStore(), Options.Create(new BillingOptions()),
            NullLogger<BillingService>.Instance);

        var csv = await billing.ExportCsvAsync(BillingGrain.Daily);

        // The name must arrive as inert text, not a live formula.
        Assert.DoesNotContain(",=HYPERLINK", csv);
        Assert.Contains("'=HYPERLINK", csv);
    }
}
