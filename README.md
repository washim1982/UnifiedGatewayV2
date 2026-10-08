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
- **Auth** — *data plane:* per-app `ug_live_*` keys (stored as SHA-256 hashes, constant-time verify)
  and short-lived signed **STS tokens** (`ug_sts_*`). *Management plane:* Okta OIDC for people,
  a SigV4-signed `sts:GetCallerIdentity` proof for automation
  ([`docs/aws-iam-authentication.md`](docs/aws-iam-authentication.md)), and a break-glass master key
  that acts as a configured IAM principal and is audited on every use.
- **Bedrock** — per-family payload shaping (Claude / Llama / Mistral / Titan) over STS AssumeRole
  with in-memory caching + background refresh.
- **Local models** — Ollama, LM Studio, llama.cpp with health probes and model listing; a Polly
  circuit breaker per backend, with retries limited to idempotent requests.
- **Ops** — telemetry + per-app metrics, an S3-backed audit trail, config version history,
  Swagger (Development only), static dashboard.

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

Development runs against the local AWS simulator, auto-grants every IAM role, and is the one
environment exempt from the HTTPS and app-key rules — so it **must bind loopback**. Startup refuses
a Development host listening on `0.0.0.0`, `*`, `+` or a LAN address. Run a networked host under a
different environment name.

## Deploy to IIS (on-prem)

On the server install IIS, the **.NET 8 Hosting Bundle**, and the **Application Initialization**
role service, then:

```powershell
# 1. Publish and overlay the IIS web.config
./deploy/iis/publish.ps1 -OutputRoot C:\inetpub\unified-gateway
```
```powershell
# 2. Create the app pool + HTTPS site and grant folder permissions (run as Administrator)
./deploy/iis/install.ps1 -CertificateThumbprint <thumbprint> -HostName gateway.your.internal
```

The certificate must already be in `Cert:\LocalMachine\My` with its private key; the installer
checks that it is unexpired, carries the server-authentication EKU and covers `-HostName`, then
creates a single HTTPS binding and **removes every plain-HTTP binding**. `-AllowHttpRedirect` adds
an HTTP binding back for browsers only — API calls on it are refused, not redirected.
`-DisableLegacyTls` disables SSL 3.0 and TLS 1.0/1.1 machine-wide (needs a reboot).

- The app pool runs **No Managed Code**, **AlwaysRunning** + preload, and never idle-times-out or
  recycles, so the AWS credential-refresh background service keeps running.
- Substitute the `<placeholders>` in `C:\inetpub\unified-gateway\appsettings.Production.json`
  (Roles Anywhere ARNs and certificate thumbprint, `BreakGlassPrincipalArn`, Okta issuer and group
  mappings, local model URLs). Startup refuses to run on the template.
- The admin credential and the token signing key are **not** in config — the gateway reads them
  from Secrets Manager, KMS-encrypted. ASP.NET Data Protection was removed: a key ring on the web
  tier can forge admin tokens.
- `deploy/iis/uninstall.ps1` removes the site and app pool.

## Provision an application

```bash
curl -s https://gateway.your.internal/gateway/sts/token \
  -H "X-API-Key: <admin-or-app-key>" -H "Content-Type: application/json" \
  -d '{ "appId": "customer-support-agent", "durationSeconds": 3600 }'
```

Create/manage apps from the dashboard after signing in through Okta, or from automation with a
signed AWS identity. Plain HTTP is refused with `403 HTTPS_REQUIRED` before authentication runs.

## Invoke

```bash
curl -s https://gateway.your.internal/gateway/customer-support-agent/invoke \
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
| **Management-plane auth** | The whole `/api` group is deny-by-default (`RequireAuthorization`), and each handler names an IAM action evaluated against a policy document — explicit Deny, then Allow, else implicit deny. Access control cannot be switched off outside Development. |
| **Rate limiting** | Fixed 1-minute windows. Before authentication every limiter partitions by client address, so no key, token or appId the caller writes selects a bucket. After a credential validates, a per-application quota applies `Security:RateLimitPerMinute` to invocation and `Security:TokenRateLimitPerMinute` to issuance across all of that application's keys and tokens. Returns 429 + `Retry-After`. Behind a load balancer, configure forwarded headers first — see SEC-03 in [`docs/security-loop-holes.md`](docs/security-loop-holes.md). |
| **Abuse clamps** | `MaxInputCharacters` rejects oversized prompts (`INPUT_TOO_LARGE`); `MaxTokensCeiling` clamps runaway `maxTokens`; `MaxRequestBodyBytes` caps the HTTP body (413) on both Kestrel and IIS. |
| **Persistent audit log** | Append-only JSON Lines, rehydrated into metrics on startup so telemetry survives restarts, and batched to S3 under `audit/dt=YYYY-MM-DD/` so the trail survives loss of the host. Every record carries actor, auth type, token id, source IP and trace id. Pruned per `AuditRetentionDays`. |
| **Key rotation** | `POST /api/apps/{appId}/rotate-key` issues a new `ug_live_*` key and invalidates the previous one immediately; `POST /api/credentials/rotate-signing-key` invalidates every outstanding STS token fleet-wide. Both require the `gateway:RotateApiKey` / `gateway:RotateSigningKey` action. STS tokens already issued from a rotated **app** key stay valid until they expire — see SL-06. |
| **Key storage** | Keys stored only as SHA-256 hashes, verified in constant time. The token signing key and break-glass credential live in Secrets Manager, KMS-encrypted. The application registry itself is still plaintext JSON on the host — see SL-14. |
| **Token inspection** | `/gateway/sts/inspect` reports a valid token's own claims; a token it rejects yields only "not valid", in the same words whether it was expired, revoked or forged, and the attempt is logged. |

## Notes

Deployment is native IIS (no Docker/Kubernetes).

The `/api/*` management endpoints were once unauthenticated. They are not: the group is
deny-by-default and every handler names an IAM action. Operators sign in through Okta, automation
proves an AWS identity, and the break-glass key acts as a configured principal with every use
audited.

Not yet implemented: streaming (SSE) and a durable SQLite/Postgres registry. HSTS, CSP and the
other security headers are in place, and IAM Roles Anywhere is the credential source on IIS.

**Before production traffic:** the AWS provider path has never run against a real AWS account, and
the IIS installer has never run on a real IIS host. Exercise both in staging first.
[`docs/security-architecture-flow.md`](docs/security-architecture-flow.md) lists nine open security
findings, all medium or low — two of which (SL-10, SL-11) need network and AWS changes rather than
code.
