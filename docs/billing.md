# Billing & Cost Monitoring

Per-application token cost with an account summary, at daily, weekly and monthly grain. Rates are entered by the operator when an application is registered.

| | |
| :--- | :--- |
| **Tests** | 109 passing (29 new) |
| **Access** | `gateway:ReadBilling` — admins and auditors only |
| **Verified** | Live, against the AWS simulator with real token counts |

---

## 1. Rate card

Two fields on the registration form, in the **Billing rate card** section:

- **Input cost / 1M tokens**
- **Output cost / 1M tokens**

Both are also on `PUT /api/apps/{appId}`, and are carried into the application's version history so a version diff shows a price change.

```
cost = tokens / 1,000,000 × ratePerMillion
```

Per-request charges are held to six decimal places. Individual calls are fractions of a cent, so rounding to currency precision at that level would floor almost every line to zero.

---

## 2. Cost is frozen at write time

The charge is computed **once, when the audit entry is written**, using the rate card in force at that moment. The entry stores the cost *and* the rates that produced it.

This is the design decision the rest of the feature rests on:

- Re-pricing an application changes future invoices only. It never restates a bill already issued.
- An auditor can see how any line was arrived at, because the rate travels with it.
- Re-running a past period reproduces the same invoice. The billing service only ever sums; it never re-prices.

A dedicated test (`RepricingAnApplication_DoesNotRestatePastCharges`) pins this.

---

## 3. Where the numbers come from

Billing reads the **durable audit trail in object storage**, not the in-memory metrics buffer. The trail is `s3://<bucket>/audit/dt=YYYY-MM-DD/*.jsonl` — S3Local in Development, S3 in Test and Production (see [telemetry-storage.md](telemetry-storage.md)). So totals survive a restart and cover the full retention window rather than the last few hundred requests. Only the `dt=` partitions inside the requested window are listed, and anything still buffered is flushed before the read.

Management-action lines, including every STS token issuance, share those objects and are skipped by their `kind` marker. A torn trailing line is skipped rather than failing the invoice.

---

## 4. What the page shows

The page is **Usage & Spend**, laid out for triage: the headline figure first, then what
drove it, then the per-application detail.

**Header** — a 24h / 7d / 30d range switch, a "Copy API endpoint" button that puts the
equivalent API URL on the clipboard, and Refresh. The page supplies its own header, so the
shared topbar is hidden on this tab.

**Headline row**

- *Organization spend* — total for the window, with the change against **the preceding window
  of the same length** (not the previous calendar month, which would make a 7-day percentage
  meaningless), and a marker on a $0 / $1 / $10 / $25+ scale placed logarithmically so both a
  four-cent day and a thirty-dollar day land somewhere readable.
- *Input cost* and *Output cost* with their token counts.
- *Top spending app* — name, cost, share, and a sparkline of its trend.

**Second row**

- *Token efficiency* — output tokens per input token, with a note on how to read it.
  Retrieval and embedding workloads pull it below 1; chat and agent loops push it above.
- *Spend over time* — a bar per period with its value, switchable between daily, weekly and
  monthly. Empty periods are drawn, so a gap reads as "nothing was spent" rather than a
  missing point, and the chart opens on the most recent period.

**Token & cost analytics** — two panels of proportional bars plus derived figures: token
efficiency, cost per 1K tokens, tokens per request, largest consumer; cost per request, cost
per app, output share of cost, and cloud share.

**Applications** — a filterable, sortable table: search, model, local/cloud, minimum spend
and minimum efficiency, with CSV / JSON / Excel export. Each row shows the rate card (on a
hover chip), tokens, cost, spend share, and a per-app sparkline.

**Honesty notices** sit above everything, because a confident total resting on guessed rates
is worse than an annotated one:

- how many requests were priced with the fallback rate
- which registered applications have no rate card
- how many billed applications are no longer registered (their history is still charged)

---

## 5. API

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/billing/summary?range=24h\|7d\|30d&grain=daily\|weekly\|monthly` | Account summary + per-application breakdown |
| `GET /api/billing/applications/{appId}?grain=…` | One application, bucketed |
| `GET /api/billing/export?format=csv\|json\|xlsx&range=…` | CSV, JSON, or a real `.xlsx` workbook |

All three require `gateway:ReadBilling`. `from` and `to` override the default window.

Every export writes an audit line of its own — exporting the whole account's spend is a
privileged act worth recording.

`range` is a shortcut that also picks a sensible default grain; an explicit `from`/`to`
always wins. The `.xlsx` is generated in-process (an xlsx is a zip of XML), so finance gets
real numeric cells rather than a CSV Excel re-guesses on every import — and it costs no
third-party dependency.

---

## 6. Bugs found while verifying

Both were caught by checking the running page rather than the unit tests, and both are the kind that would have reached a finance review.

**The parts did not sum to the whole.** The headline read $0.04 while the chart summed to $0.03. Each bucket and each application total was being rounded to cents independently, and input and output were rounded separately before being added. Since line items are already six-place, their sums are exact in `decimal` and need no rounding at all — `Money()` now guards only values produced by division. `PartsReconcileExactlyWithTheHeadlineTotal` asserts `buckets == applications == total` at every grain.

**No bar ever showed its real height.** `.bill-bar-fill` sized itself as a percentage, but `.bill-bar` had no definite height inside an `align-items: flex-end` container, so every fill collapsed to its 2px minimum. The chart looked empty regardless of spend. The bar now has a definite-height plot area; the measured fill went from 2px to 174px.

**The applications table had no styling at all.** `.data-table` was referenced in the markup but never defined in the stylesheet, so the table fell back to user-agent defaults — centred headers, no padding, no row separators. It is now styled explicitly.

---

## 7. Configuration

```jsonc
"Gateway": {
  "Billing": {
    "Currency": "USD",
    "DefaultInputCostPerMillion": 0.0,   // fallback when no rate card applies
    "DefaultOutputCostPerMillion": 0.0,  // such charges are flagged as estimated
    "DailyWindowDays": 30,
    "WeeklyWindowWeeks": 12,
    "MonthlyWindowMonths": 12,
    "MonthlyBudget": 0.0                 // 0 = no budget bar
  }
}
```

`MonthlyBudget` is currently **not rendered**. The redesign replaced the budget bar with the
$0 / $1 / $10 / $25+ spend scale, which shows magnitude rather than progress against a
commitment. The setting and the `monthlyBudget` / `budgetUsedPercent` fields on the API are
still populated, so wiring a budget indicator back into the header is a UI change only.

---

## 8. Limits worth knowing

- **No budget is enforced, and none is displayed.** The API still reports budget usage but the page no longer draws it (see Configuration). Per-app token budgets that actually refuse requests remain Phase 4 of the [hardening review](gateway-hardening-review.md).
- **The projection is naive.** Month-to-date extrapolated at the current daily rate, labelled "at the current daily rate". It is not a forecast and does not model weekday patterns or growth.
- **Billing is per-invocation, not per-provider-invoice.** These figures are what the gateway's own rate cards say you owe. They will not match an AWS bill unless the rate cards match AWS pricing, and they exclude anything AWS charges that the gateway cannot see.
- **Failed requests are billed at zero** because they return no tokens. A provider that charges for failed calls would not be reflected.
- **Aggregation is in-process over the S3 objects.** Fine at current volumes, and the date partitioning keeps a long retention from meaning a full scan. A high-volume deployment wants precomputed daily rollups rather than re-reading raw records on every page load.
- **Rates are per application, not per model.** An application that falls back to a different model is billed at the application's rate either way, which understates a cheap fallback and overstates an expensive one.
