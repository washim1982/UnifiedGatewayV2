# Billing & Telemetry Storage

Both are read from one durable trail in **object storage**. Development uses S3Local in the .NET simulator; Test and Production use real S3.

| | |
| :--- | :--- |
| **Tests** | 118 passing (5 new) |
| **Verified** | Live — records written to and read back from S3Local |

---

## 1. Where it lives

There is one trail, and billing and telemetry are both views over it:

```
s3://<bucket>/audit/dt=2026-09-10/20260910T122827806Z-0c22966c.jsonl
```

| Environment | Provider | Bucket |
| :--- | :--- | :--- |
| Development | `LocalDotNet` | `gateway-telemetry` (S3Local, created on demand) |
| Test | `Aws` | `unified-gateway-telemetry-test` |
| Production | `Aws` | `unified-gateway-telemetry-prod` |

Objects are newline-delimited JSON, LF only. Invocation records and management-action records share the trail and are distinguished by a `kind` field — billing skips the management lines.

**Hive-style `dt=` partitioning** means reading a date range lists only the days it needs, and the layout is queryable by Athena or Glue later without a migration.

---

## 2. The constraint that shapes this

**S3 objects are immutable.** The previous implementation appended a line per request to a local file; that is not possible against S3. Read-modify-write per request would be racy, slow and expensive.

So records are **buffered and flushed as whole objects** — the same shape CloudTrail and ALB access logs use. Flushes happen:

- when the buffer reaches `FlushBatchSize` (default 100)
- every `FlushIntervalSeconds` (default 30)
- **before every read**, so a bill never omits a request the operator just made
- at shutdown

A failed flush **puts the records back on the buffer** rather than dropping them. Losing billing data to a transient S3 error would silently understate an invoice, which is worse than retrying.

### Records are partitioned by their own timestamp

Not by flush time. A batch written just after midnight still contains yesterday's requests, and filing those under today would hide them from any query for yesterday. A single flush therefore writes one object per date it touches.

This was a real bug in the first cut of this work — caught by a test asserting the prior-period comparison, which reads a window that ended before the flush.

---

## 3. The seam

```
IObjectStore ── LocalDotNetObjectStore  → S3Local        (Development)
             └─ AwsS3ObjectStore        → S3             (Test, Production)

IAuditStore  ── S3AuditStore over whichever IObjectStore is bound
```

`S3AuditStore` is one implementation for all environments — batching, partitioning and retention are identical everywhere. Only the transport differs, and it binds from the same `Gateway:Cloud:Provider` switch as every other seam.

`AwsS3ObjectStore` follows the `ListObjectsV2` continuation token, so a day with more than 1000 objects is billed in full rather than truncated at the first page.

---

## 4. Configuration

```jsonc
"Gateway": {
  "Cloud": {
    "Storage": {
      "Bucket": "unified-gateway-telemetry-prod",
      "FlushIntervalSeconds": 30,
      "FlushBatchSize": 100,
      "RetentionDays": 365,
      "RecentBufferSize": 500
    }
  }
}
```

### The bucket is infrastructure, not application state

In Development the gateway creates the bucket on demand. In Test and Production **it never does** — it only checks it can see it, and logs an error if it cannot. Create it with Terraform, with:

- **Versioning** — an audit trail that can be silently overwritten is not an audit trail
- **SSE-KMS** — these records carry token counts, model names and caller identities
- **A lifecycle rule** matching `RetentionDays`, so expiry is enforced by S3 rather than by the gateway walking the bucket
- **A bucket policy** denying `s3:DeleteObject` to everything except the lifecycle rule, if you need the trail to be tamper-evident

The gateway's own `PruneAsync` exists for Development, where there is no lifecycle rule. In Production, prefer the lifecycle rule and set `RetentionDays: 0` to leave deletion to S3.

---

## 5. What did not move

**The application registry** (`app_registry_*.json`) is still a local file. It is configuration rather than telemetry, it is small, and it is read on every request — putting it in S3 would add a network hop to the hot path for no benefit. Moving it to a database remains Phase 3 of the [hardening review](gateway-hardening-review.md).

**The recent-metrics buffer** is still in memory, and is now refilled from S3 at startup so the telemetry page is not blank after a restart. Rehydration happens once object storage is confirmed reachable, not in the constructor — a constructor cannot await.

---

## 6. Cost and latency, honestly

- **Visibility lag.** A record is not durable until its batch lands: up to `FlushIntervalSeconds`, or immediately if the batch fills. Reads flush first, so the dashboard is never stale, but a crash can lose up to one interval of buffered records. Lower `FlushIntervalSeconds` to narrow that window at the cost of more PUTs.
- **PUT volume.** One PUT per flush, not per request. At the defaults a busy gateway writes at most 2 objects a minute per instance; a quiet one writes 1 every 30 seconds only when there is something to write.
- **Read cost scales with the window.** A 30-day billing view lists and fetches 30 partitions. That is fine at current volumes, but a high-traffic deployment should precompute daily rollups rather than re-reading raw records for every page load.
- **Many small objects.** Each flush is its own object. Over a year at 30-second intervals that is a lot of keys. An S3 lifecycle rule that transitions old partitions to Glacier, or a periodic compaction job, is worth adding before that becomes a bill of its own.

---

## 7. Leftovers

`data/dev/audit/` and `data/test/audit/` still hold the old local JSONL files. Nothing reads them any more. They can be deleted, or kept until you have confirmed the S3 trail has the history you care about — the two formats are line-compatible, so an old file's contents can be uploaded into the right `dt=` partition if you want continuity.
