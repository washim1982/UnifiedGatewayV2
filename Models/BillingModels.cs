using System.Text.Json.Serialization;

namespace UnifiedGateway.Models;

public class BillingOptions
{
    public const string SectionName = "Gateway:Billing";

    /// <summary>ISO currency code the rates are expressed in. Display only; no conversion happens.</summary>
    public string Currency { get; set; } = "USD";

    /// <summary>
    /// Rate applied when an application has no input rate of its own, or when a request
    /// carries no application (a direct universal invocation). Charges priced this way are
    /// flagged as estimated so they are not mistaken for contracted rates.
    /// </summary>
    public decimal DefaultInputCostPerMillion { get; set; }

    /// <summary>Output-token equivalent of <see cref="DefaultInputCostPerMillion"/>.</summary>
    public decimal DefaultOutputCostPerMillion { get; set; }

    /// <summary>Days of daily detail returned by the billing endpoints.</summary>
    public int DailyWindowDays { get; set; } = 30;

    /// <summary>Weeks of weekly rollup returned by the billing endpoints.</summary>
    public int WeeklyWindowWeeks { get; set; } = 12;

    /// <summary>Months of monthly rollup returned by the billing endpoints.</summary>
    public int MonthlyWindowMonths { get; set; } = 12;

    /// <summary>
    /// Optional monthly spend ceiling for the whole account, used to render a budget bar.
    /// Zero means no budget is tracked. This is a monitoring aid, not an enforcement control.
    /// </summary>
    public decimal MonthlyBudget { get; set; }
}

/// <summary>Which grain a set of billing buckets is aggregated at.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum BillingGrain
{
    Daily,
    Weekly,
    Monthly
}

/// <summary>Usage and cost for one time bucket.</summary>
public record BillingBucket
{
    /// <summary>Bucket label: "2026-09-08", "2026-W37", or "2026-09".</summary>
    [JsonPropertyName("period")]
    public string Period { get; init; } = string.Empty;

    [JsonPropertyName("periodStart")]
    public DateTimeOffset PeriodStart { get; init; }

    [JsonPropertyName("periodEnd")]
    public DateTimeOffset PeriodEnd { get; init; }

    [JsonPropertyName("requests")]
    public long Requests { get; init; }

    [JsonPropertyName("inputTokens")]
    public long InputTokens { get; init; }

    [JsonPropertyName("outputTokens")]
    public long OutputTokens { get; init; }

    [JsonPropertyName("totalTokens")]
    public long TotalTokens => InputTokens + OutputTokens;

    [JsonPropertyName("inputCost")]
    public decimal InputCost { get; init; }

    [JsonPropertyName("outputCost")]
    public decimal OutputCost { get; init; }

    [JsonPropertyName("totalCost")]
    public decimal TotalCost => InputCost + OutputCost;

    /// <summary>Requests in this bucket priced with a fallback rate rather than a set rate.</summary>
    [JsonPropertyName("estimatedRequests")]
    public long EstimatedRequests { get; init; }
}

/// <summary>Per-application billing, with its rate card and its buckets at one grain.</summary>
public record ApplicationBilling
{
    [JsonPropertyName("appId")]
    public string AppId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty;

    [JsonPropertyName("model")]
    public string Model { get; init; } = string.Empty;

    [JsonPropertyName("isActive")]
    public bool IsActive { get; init; } = true;

    /// <summary>False when the application has been deleted but still has billable history.</summary>
    [JsonPropertyName("isRegistered")]
    public bool IsRegistered { get; init; } = true;

    [JsonPropertyName("inputCostPerMillion")]
    public decimal InputCostPerMillion { get; init; }

    [JsonPropertyName("outputCostPerMillion")]
    public decimal OutputCostPerMillion { get; init; }

    [JsonPropertyName("requests")]
    public long Requests { get; init; }

    [JsonPropertyName("inputTokens")]
    public long InputTokens { get; init; }

    [JsonPropertyName("outputTokens")]
    public long OutputTokens { get; init; }

    [JsonPropertyName("totalTokens")]
    public long TotalTokens => InputTokens + OutputTokens;

    [JsonPropertyName("totalCost")]
    public decimal TotalCost { get; init; }

    /// <summary>Cost inside the current calendar month, for the account summary.</summary>
    [JsonPropertyName("monthToDateCost")]
    public decimal MonthToDateCost { get; init; }

    /// <summary>Cost over the trailing 24 hours.</summary>
    [JsonPropertyName("last24HoursCost")]
    public decimal Last24HoursCost { get; init; }

    /// <summary>Mean cost per request over the window, useful for spotting an expensive app.</summary>
    [JsonPropertyName("averageCostPerRequest")]
    public decimal AverageCostPerRequest { get; init; }

    /// <summary>Share of total account cost over the window, 0-100.</summary>
    [JsonPropertyName("shareOfTotalPercent")]
    public double ShareOfTotalPercent { get; init; }

    [JsonPropertyName("grain")]
    public BillingGrain Grain { get; init; }

    [JsonPropertyName("buckets")]
    public List<BillingBucket> Buckets { get; init; } = [];

    /// <summary>Cost per bucket, in window order. Just the numbers a sparkline needs.</summary>
    [JsonPropertyName("trend")]
    public List<decimal> Trend { get; init; } = [];

    /// <summary>Cost incurred on cloud providers (Bedrock).</summary>
    [JsonPropertyName("cloudCost")]
    public decimal CloudCost { get; init; }

    /// <summary>Cost incurred on locally hosted models.</summary>
    [JsonPropertyName("localCost")]
    public decimal LocalCost { get; init; }

    /// <summary>Output tokens produced per input token. Below 1 means a retrieval-shaped workload.</summary>
    [JsonPropertyName("tokenEfficiency")]
    public double TokenEfficiency { get; init; }
}

/// <summary>Account-wide billing summary plus a per-application breakdown.</summary>
public record BillingSummary
{
    [JsonPropertyName("currency")]
    public string Currency { get; init; } = "USD";

    [JsonPropertyName("generatedAt")]
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("windowStart")]
    public DateTimeOffset WindowStart { get; init; }

    [JsonPropertyName("windowEnd")]
    public DateTimeOffset WindowEnd { get; init; }

    // --- Account totals -----------------------------------------------------

    [JsonPropertyName("totalCost")]
    public decimal TotalCost { get; init; }

    [JsonPropertyName("monthToDateCost")]
    public decimal MonthToDateCost { get; init; }

    [JsonPropertyName("previousMonthCost")]
    public decimal PreviousMonthCost { get; init; }

    /// <summary>
    /// Spend over the window immediately before this one, of the same length. This is what
    /// the headline delta compares against -- comparing a 7-day window to a calendar month
    /// would make the percentage meaningless.
    /// </summary>
    [JsonPropertyName("previousPeriodCost")]
    public decimal PreviousPeriodCost { get; init; }

    /// <summary>Change against the preceding window, or null when there is nothing to compare to.</summary>
    [JsonPropertyName("changeVsPreviousPercent")]
    public double? ChangeVsPreviousPercent { get; init; }

    /// <summary>Cost incurred on cloud providers across the window.</summary>
    [JsonPropertyName("cloudCost")]
    public decimal CloudCost { get; init; }

    /// <summary>Cost incurred on locally hosted models across the window.</summary>
    [JsonPropertyName("localCost")]
    public decimal LocalCost { get; init; }

    /// <summary>Account-wide output tokens per input token.</summary>
    [JsonPropertyName("tokenEfficiency")]
    public double TokenEfficiency { get; init; }

    /// <summary>Distinct models seen in the window, for the model filter.</summary>
    [JsonPropertyName("models")]
    public List<string> Models { get; init; } = [];

    [JsonPropertyName("last24HoursCost")]
    public decimal Last24HoursCost { get; init; }

    [JsonPropertyName("last7DaysCost")]
    public decimal Last7DaysCost { get; init; }

    /// <summary>
    /// Month-to-date spend extrapolated across the whole calendar month at the current
    /// daily rate. A straight-line projection, not a forecast.
    /// </summary>
    [JsonPropertyName("projectedMonthCost")]
    public decimal ProjectedMonthCost { get; init; }

    [JsonPropertyName("monthlyBudget")]
    public decimal MonthlyBudget { get; init; }

    /// <summary>Month-to-date spend as a percentage of the budget, or null when none is set.</summary>
    [JsonPropertyName("budgetUsedPercent")]
    public double? BudgetUsedPercent { get; init; }

    [JsonPropertyName("totalRequests")]
    public long TotalRequests { get; init; }

    [JsonPropertyName("totalInputTokens")]
    public long TotalInputTokens { get; init; }

    [JsonPropertyName("totalOutputTokens")]
    public long TotalOutputTokens { get; init; }

    [JsonPropertyName("totalTokens")]
    public long TotalTokens => TotalInputTokens + TotalOutputTokens;

    /// <summary>Requests priced with a fallback rate because no rate card applied.</summary>
    [JsonPropertyName("estimatedRequests")]
    public long EstimatedRequests { get; init; }

    /// <summary>Applications billed in this window that are no longer registered.</summary>
    [JsonPropertyName("unregisteredApplicationCount")]
    public int UnregisteredApplicationCount { get; init; }

    /// <summary>Registered applications that have no rate card set.</summary>
    [JsonPropertyName("applicationsMissingRates")]
    public List<string> ApplicationsMissingRates { get; init; } = [];

    // --- Breakdown ----------------------------------------------------------

    [JsonPropertyName("grain")]
    public BillingGrain Grain { get; init; }

    /// <summary>Account-wide buckets at the requested grain.</summary>
    [JsonPropertyName("buckets")]
    public List<BillingBucket> Buckets { get; init; } = [];

    /// <summary>Per-application totals, most expensive first.</summary>
    [JsonPropertyName("applications")]
    public List<ApplicationBilling> Applications { get; init; } = [];
}
