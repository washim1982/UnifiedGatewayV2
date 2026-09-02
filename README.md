# Universal AI LLM Gateway

An on-prem **.NET 8** minimal-API gateway that gives every application one endpoint and routes
requests to **AWS Bedrock** (via STS AssumeRole) or **local model runtimes** (Ollama, LM Studio,
llama.cpp) — with a mandatory, admin-level **guardrails** layer (PCI / PII / secrets / prompt
injection) inspected before any backend is called.

> Security design & threat model: [`architecture.md`](architecture.md).

## Features

- **Unified API** — `POST /gateway/{appId}/invoke` (per-app system prompt, model, fallback) and a
  direct `POST /gateway/universal/invoke` for admins.
- **Guardrails** — Luhn-validated cards, IBAN, CVV, SSN, email, phone, passports, AWS keys, PEM
  private keys, JWTs, API tokens, and prompt-injection/jailbreak detection. Modes: Redact / Block / AuditOnly.
- **Auth** — per-app `ug_live_*` keys (stored as SHA-256 hashes, constant-time verify), short-lived
  signed **STS tokens** (`ug_sts_*`), and a master admin key.
- **Bedrock** — per-family payload shaping (Claude / Llama / Mistral / Titan) over STS AssumeRole
  with in-memory caching + background refresh.
- **Local models** — Ollama, LM Studio, llama.cpp with health probes and model listing; Polly retry.
- **Ops** — telemetry + per-app metrics, config version history, Swagger (non-prod), static dashboard.

## Prerequisites

- .NET 8 SDK to build/publish (build tested with the .NET 10 SDK targeting `net8.0`)
- Windows Server with IIS + the **.NET 8 Hosting Bundle** (ASP.NET Core Module V2) and the
  **Application Initialization** role service
- Ollama / LM Studio / llama.cpp installed natively on-prem for local models (optional)

## Run locally (evaluation)

```bash
dotnet run --project UnifiedGatewayV2.csproj
```

Then open the dashboard at `/`, Swagger at `/swagger`, and `/status`. The registry seeds three demo
apps on first run and persists to `./data`.

## Deploy to IIS (on-prem)

On the server install IIS, the **.NET 8 Hosting Bundle**, and the **Application Initialization**
role service, then:

```powershell
# 1. Publish and overlay the IIS web.config
./deploy/iis/publish.ps1 -OutputRoot C:\inetpub\unified-gateway
```
```powershell
# 2. Create the app pool + site and grant folder permissions (run as Administrator)
./deploy/iis/install.ps1 -SiteRoot C:\inetpub\unified-gateway -Port 8080
```

- The app pool runs **No Managed Code**, **AlwaysRunning** + preload, and never idle-times-out or
  recycles, so the AWS credential-refresh background service keeps running.
- Set production values in `C:\inetpub\unified-gateway\appsettings.Production.json` (AWS role ARN,
  admin key, local model URLs). Add an HTTPS binding with your internal certificate.
- The Data Protection key ring is DPAPI-encrypted at rest (machine-level) on Windows.
- `deploy/iis/uninstall.ps1` removes the site and app pool.

## Provision an application

```bash
curl -s http://localhost:8080/gateway/sts/token \
  -H "X-API-Key: <admin-or-app-key>" -H "Content-Type: application/json" \
  -d '{ "appId": "customer-support-agent", "durationSeconds": 3600 }'
```

Create/manage apps from the dashboard, or with the admin key against the app-management endpoints.

## Invoke

```bash
curl -s http://localhost:8080/gateway/customer-support-agent/invoke \
  -H "X-API-Key: ug_live_..." -H "Content-Type: application/json" \
  -d '{ "input": "Summarize our refund policy.", "maxTokens": 512 }'
```

## Tests

```bash
dotnet test
```

## Security controls

| Control | Behavior |
|---|---|
| **Ingress guardrails** | PCI / PII / secrets / prompt-injection scanned before any backend call (Redact / Block / AuditOnly). |
| **Egress guardrails** | Model **output** scanned for leaked PCI / PII / secrets before it reaches the caller. Redact sanitizes, Block returns `OUTPUT_GUARDRAIL_BLOCKED`. **Fails closed** — if the engine throws, the response is withheld (`OUTPUT_GUARDRAIL_ERROR`). Configure under `Gateway:Guardrails:OutputScanning`. |
| **Rate limiting** | Fixed 1-minute window from `Security:RateLimitPerMinute`, partitioned per caller (API key / STS token → hashed, else appId, else IP). Returns 429 + `Retry-After`. |
| **Abuse clamps** | `MaxInputCharacters` rejects oversized prompts (`INPUT_TOO_LARGE`); `MaxTokensCeiling` clamps runaway `maxTokens`; `MaxRequestBodyBytes` caps the HTTP body (413) on both Kestrel and IIS. |
| **Persistent audit log** | Append-only JSON Lines under `data/audit/audit-YYYYMMDD.jsonl`, rehydrated into metrics on startup so telemetry survives restarts. Pruned per `AuditRetentionDays`. |
| **Key rotation** | `POST /api/apps/{appId}/rotate-key` issues a new `ug_live_*` key and invalidates the previous one immediately. Requires the Master Admin key or an Admin STS token. |
| **Key storage** | Keys stored only as SHA-256 hashes, verified in constant time. Data Protection key ring is DPAPI-encrypted (machine-level) on Windows. |

## Notes

Deployment is native IIS (no Docker/Kubernetes).

**Known gap:** the `/api/*` dashboard management endpoints (list/create/update/delete apps, metrics,
guardrail config) are currently **unauthenticated** — only `rotate-key` requires the admin key. Put
the dashboard behind network restrictions, or ask for admin auth to be applied to the whole `/api`
group before exposing it.

Not yet implemented: streaming (SSE), a durable SQLite/Postgres registry, security response headers
(HSTS/CSP), and an IAM Roles Anywhere credential source.
