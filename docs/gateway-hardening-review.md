# Gateway Hardening Review

Security assessment of the Unified LLM Gateway (`UnifiedGatewayV2`).

| | |
| :--- | :--- |
| **Target** | UnifiedGatewayV2 |
| **Branch / commit** | `main` · `133e4f5` |
| **Method** | Static source review — not built, not run, no exploitation attempted |
| **Reviewed** | 2026-09-08 |
| **Findings** | 5 critical · 7 high · 10 medium · 4 low |

> A styled version of this report is at [`gateway-hardening-review.html`](gateway-hardening-review.html).
> Related: [`../README.md`](../README.md), [`../architecture.md`](../architecture.md).

---

## Verdict

**The data plane is well built. The management plane has no front door.**

Everything under `/gateway/*` does what an enterprise gateway should: cryptographically random keys stored as hashes, constant-time verification, ingress and egress guardrails, abuse clamps, a durable audit trail. Everything under `/api/*` — the endpoints that create applications, mint credentials, invoke models, and switch the guardrails off — accepts anonymous requests. Only `rotate-key` checks who is calling.

That single gap collapses the rest. An unauthenticated caller can mint a valid STS token for any registered application, which the data plane then honours — so the per-app key model protects nothing while the port is reachable. The README already flags this as known; this review treats it as the finding that gates every other one.

---

## The exposure chain

These five calls need no credential at any point. They are steps in one sequence, not independent issues — each one is reachable because the previous one succeeded.

1. **`POST /api/apps`** — register an application naming any Bedrock model. Auth required: **none**. Returns a live `ug_live_*` key.
2. **`POST /api/apps/{appId}/sts-token?durationSeconds=604800`** — mint a signed STS token for *any* application, including ones the attacker did not create. Auth required: **none**. TTL is clamped at seven days, not at the request.
3. **`POST /gateway/{appId}/invoke`** with `Authorization: Bearer ug_sts_…` — the data plane validates the signature, sees a matching `appId`, and authorizes. The per-app API key was never involved.
4. **`PUT /api/guardrails/config {"enabled": false}`** — turn off PII, PCI, secrets, and injection screening for every tenant at once. Auth required: **none**. Not persisted, not audited — it reverts on the next restart, leaving no trace of the window.
5. **`POST /api/apps {"provider": "<img src=x onerror=…>"}`** — plant stored HTML in a dashboard field that is rendered unescaped, then wait for an operator to open the dashboard and read the master admin key out of their `localStorage`.

**Net effect:** an anonymous caller reaches AWS Bedrock through the gateway's assumed IAM role, with guardrails disabled and no attributable identity in the audit trail — and can escalate to the master admin key by way of the operator's browser.

---

## Critical

### C1 — The entire management plane is unauthenticated

`Endpoints/DashboardEndpoints.cs:40, 56, 71, 79, 124, 150, 162, 195, 214`

**What.** Nine of the ten `/api/*` endpoints run no identity check. `IsAdminRequest` exists and is correct, but it is called from exactly one handler — `rotate-key` at line 88. The dashboard itself sends no credential on any of its calls, so the omission is by construction rather than oversight.

**Impact.** Anyone who can reach the port can enumerate every registered application, create and delete them, rewrite system prompts and model bindings, mint credentials, invoke models, and read the audit log. **There is no server-side notion of an operator at all** — no authentication scheme is registered, and `UseAuthentication` / `UseAuthorization` appear nowhere in the pipeline.

**Fix.** Apply authorization at the group, not per handler, so new endpoints inherit it by default. This is the one change that must land before any exposure beyond localhost.

```csharp
// Program.cs — register a scheme, then in DashboardEndpoints.cs:
var group = app.MapGroup("/api")
    .WithTags("Dashboard & Management")
    .RequireAuthorization("PlatformAdmin")   // deny-by-default for the whole group
    .RequireRateLimiting("management");
```

### C2 — Anonymous STS minting voids the data-plane auth model

`Endpoints/DashboardEndpoints.cs:124` → `Services/ApplicationRegistryService.cs:427`

**What.** `POST /api/apps/{appId}/sts-token` calls `MintStsTokenDirectAsync`, which signs a token unconditionally — it never verifies a caller and never checks that the requester owns the app. `AuthenticateAppAsync` on the data plane accepts that token as proof of identity.

**Impact.** Every control built on the per-app API key — hashing, constant-time comparison, rotation — is bypassable without touching a key. **The hardened data plane inherits the trust level of the unprotected management plane**, which is the lower of the two.

**Fix.** Covered by C1's group-level authorization, but treat minting as a distinct privilege: a token for app X should require either platform-admin rights or proven ownership of X, and the requested TTL should be validated against a per-app policy rather than silently clamped to the seven-day ceiling in `SecurityService.cs:109`.

### C3 — Unauthenticated callers can spend against the organization's AWS account

`Endpoints/DashboardEndpoints.cs:56, 150` · `Services/STSService.cs:114`

**What.** `POST /api/apps/{appId}/test` routes straight into `IModelRouter` with no credential check and no rate-limit attribute. Paired with anonymous app creation, a caller chooses the model and then invokes it.

**Impact.** A classic confused deputy: the gateway holds the assumed-role credentials and will exercise them for anybody. Exposure is **unbounded Bedrock spend, model-access abuse under the organization's IAM identity, and inference logged to the company's CloudTrail with no attributable caller**. This is likely the highest-dollar risk in the review.

**Fix.** Authorize the endpoint, and add a per-app token budget enforced independently of request-rate limiting — requests-per-minute does not bound cost when a single request can request the token ceiling.

### C4 — Guardrails can be disabled globally, anonymously, without a trace

`Endpoints/DashboardEndpoints.cs:214` → `Services/GuardrailService.cs:29`

**What.** `PUT /api/guardrails/config` replaces the whole options object on a singleton with no authorization, no validation, and no audit entry. Sending `{"enabled": false}` disables PII, PCI, secrets, and injection screening for every tenant.

**Impact.** The compliance control the product is sold on can be switched off by an unauthenticated request. Because the change lives only in memory, **it disappears on restart** — so a regulated organization would see redaction resume and have no record that it ever stopped. That is worse than a persisted change: it defeats after-the-fact investigation.

**Fix.** Require platform-admin rights, write a policy-change record to the audit trail (actor, before/after, timestamp) before applying it, persist the change so restarts don't mask it, and validate the payload — a partial body currently nulls out whole detector groups.

### C5 — Stored XSS in the dashboard leads to the master admin key

`wwwroot/js/app.js:367, 383–385, 490, 741` · key stored at `app.js:69`

**What.** Most fields are escaped, but four sinks are not. `${app.provider.toUpperCase()}` is interpolated raw at lines 367 and 490 — uppercasing does not neutralise markup, since HTML tag and attribute names are case-insensitive. `${app.model}` is raw at 490. And `appId` is interpolated into `onclick="selectAppForTest('…')"` handlers at 383–385, where `Slugify` (`ApplicationRegistryService.cs:670`) strips spaces and underscores but leaves quotes intact.

**Impact.** Anonymous app creation (C1) means an attacker controls those values. The dashboard keeps the master admin key in `localStorage` under `ug_universal_admin_key`, and there is no CSP to contain injected script. **The chain runs from an anonymous HTTP request to the master credential the moment an operator opens the dashboard.**

**Fix.** Escape all four sinks; build the action buttons with `addEventListener` and a `dataset` value rather than inline `onclick` strings; restrict `appId` to `[a-z0-9-]` at the API boundary; move the admin credential out of `localStorage` into a session-scoped store or an httpOnly cookie once real sign-in exists; add a CSP as defence in depth.

---

## High

### H1 — A working admin key ships in source control, and nothing refuses to boot on it

`appsettings.json` · `Models/GatewayOptions.cs:59` · `appsettings.Development.json`

**What.** `ug-admin-secret-key-change-in-production` is committed in `appsettings.json`, with `ug-admin-default-change-in-prod` as the compiled-in default and `ug-dev-admin-key` in the development profile. Only the production file uses a deploy-time placeholder. Separately, `EnforceAppApiKey` is a single flag that disables app authentication entirely (`ApplicationRegistryService.cs:410`).

**Impact.** Any deployment that inherits the base configuration is protected by a published credential. A misconfigured environment variable silently falls back to it rather than failing.

**Fix.** Add a startup guard that throws when the environment is not Development and the admin key is empty, a known default, or under a minimum entropy bar. Do the same for `EnforceAppApiKey == false`. Fail fast and loudly; a gateway that starts insecure is worse than one that refuses to start.

### H2 — CORS defaults to any origin

`Program.cs:76–90` · `appsettings.json`, `appsettings.Development.json`

**What.** `AllowedCorsOrigins` is `["*"]` in both the base and development configuration, taking the `AllowAnyOrigin()` branch. Production correctly names two origins.

**Impact.** Any web page a staff member visits can script the management API. Wildcard CORS blocks credentialed requests, but the management plane needs no credentials (C1) — so the usual mitigation does not apply here.

**Fix.** Remove the wildcard branch entirely and treat an empty allow-list as "no cross-origin access". Wildcard CORS should not be reachable through configuration on a service that fronts cloud credentials.

### H3 — No transport security is enforced

`Program.cs` (pipeline, lines 167–196) · `architecture.md:113`

**What.** The pipeline has no `UseHttpsRedirection` and no `UseHsts`; `launchSettings.json` binds plain HTTP alongside HTTPS, and the IIS `web.config` sets no HTTPS-only binding. The threat model claims "Mandatory TLS for all external and cloud communication."

**Impact.** `ug_live_*` keys, STS bearer tokens, and every prompt — the data the guardrails exist to protect — can traverse the network in clear text. On-premise deployment is not a mitigation; internal networks are where credential harvesting happens.

**Fix.** Add HSTS and HTTPS redirection outside Development, and enforce it at the IIS binding so misconfiguration cannot re-open a plaintext listener.

### H4 — STS tokens cannot be revoked, and rotation does not invalidate them

`Services/SecurityService.cs:101–138` · `Services/ApplicationRegistryService.cs:381`

**What.** Tokens carry a `jti`, but nothing records or checks it. Validation is signature plus expiry only. `RotateApiKeyAsync` overwrites the key hash — correctly invalidating the long-term key — while every STS token already minted from it keeps working. The token does not bind to the key version it was issued against.

**Impact.** **There is no way to respond to a compromise.** The documented incident response — rotate the key — leaves valid credentials in the attacker's hands for up to seven days, and an admin token minted with `appId: "*"` is a master credential for that entire window.

**Fix.** Stamp a key generation number into the payload and reject tokens whose generation is stale, giving rotation immediate effect. Add a `jti` denylist (in-memory plus persisted, bounded by max TTL) for targeted revocation. Cut the default TTL to 15 minutes with a one-hour ceiling; seven days is a long-lived credential wearing a short-lived credential's name.

### H5 — Rate limiting misses token issuance and the whole management plane

`Program.cs:106–128` · `Endpoints/GatewayEndpoints.cs:19, 65`

**What.** The `per-app` policy is well designed — partitioned by hashed credential, falling back to appId then IP — but `RequireRateLimiting` is attached to only two endpoints. `/gateway/sts/token`, `/gateway/sts/inspect`, `/gateway/health`, and every `/api/*` route are unlimited.

**Impact.** `/gateway/sts/token` is the ideal brute-force oracle: it accepts a key with no appId and searches every registered app for a match (`ApplicationRegistryService.cs:510`), returning a token on success. Unlimited attempts against it, plus unlimited `/api/apps/{id}/test` invocations, make both credential guessing and cost exhaustion cheap.

**Fix.** Set a global limiter as the floor and override per route. Give credential-issuing endpoints a much tighter limit than invocation endpoints, and add exponential backoff or lockout on repeated authentication failures from one partition.

### H6 — Guardrail regexes are backtracking-prone with no match timeout

`Services/GuardrailService.cs:281` and all `GeneratedRegex` declarations

**What.** The credit-card candidate pattern `\b(?:\d[ -]*?){13,19}\b` combines a lazy inner quantifier with a bounded outer repetition — the shape that backtracks combinatorially on long digit-and-separator runs. No pattern in the file sets a `matchTimeout` or uses `RegexOptions.NonBacktracking`, and `MaxInputCharacters` admits 100,000 characters.

**Impact.** A crafted prompt within the accepted size can pin a CPU core inside the guardrail engine. Because screening runs synchronously before routing, **a handful of concurrent requests can stall the gateway for every tenant** — and reaching it needs no credential via `/api/guardrails/test`.

**Fix.** Set a match timeout (100–250 ms) on every pattern and treat a timeout as a violation rather than a pass, so the failure mode stays closed. Move patterns without backreferences to `NonBacktracking`. Lower the scanned-input ceiling, or chunk long inputs. Add a regression test that feeds a pathological string and asserts a bounded runtime.

### H7 — The Data Protection key ring is the admin-token forging key

`Program.cs:22–32` · `Services/SecurityService.cs:19, 133`

**What.** STS tokens are signed with an `IDataProtector` whose key ring sits in `dataprotection-keys/` beside the binaries, protected by machine-scoped DPAPI. Machine scope means any account on the host can unprotect it.

**Impact.** Anyone with a foothold on the server — not just the app-pool identity — can forge a token with `isAdmin: true` and `appId: "*"`, which every admin check in the codebase honours. Operationally, DPAPI-bound keys also do not move between hosts: **a rebuild or a second node silently invalidates every issued token**, and the failure surfaces as unexplained 401s rather than a clear error.

**Fix.** Move the key ring off the application directory and restrict its ACL to the app-pool identity alone. For multi-node or DR, protect it with an X.509 certificate from the machine store rather than DPAPI. Longer term, sign tokens asymmetrically with a key held in Key Vault or KMS so the signing key never lands on the web tier at all (Phase 2).

---

## Medium

### M1 — The audit trail records no caller identity, and no management actions at all

`Models/GatewayMetrics.cs:6–57` · `Services/ModelRouter.cs:394`

`RequestLogEntry` captures app, model, latency, tokens, and guardrail outcome — but no client IP, no key prefix, no STS `jti`, no user or session identifier. `UniversalRequest` defines a `traceId` that is never propagated into the log. Create, update, delete, rotate, and guardrail-config changes write nothing to the trail.

The trail answers "what was invoked" but not "by whom", which is what a repudiation control needs. The threat model claims traceId correlation that does not exist. Privileged actions are invisible to forensics.

**Fix.** Add actor fields (key prefix or subject, `jti`, source IP, traceId) to the entry, and emit a distinct management-action record for every state change.

### M2 — Blocked and failed requests return HTTP 200

`Endpoints/GatewayEndpoints.cs:119, 176` · `architecture.md` (enforcement modes table)

Both invoke endpoints wrap every outcome in `Results.Ok`. A guardrail block, a provider failure, an oversized prompt, and a successful completion are all 200s distinguished only by an `error` object in the body. The documentation states that Block returns 422.

Client SDKs, load balancers, and monitoring that key on status codes will read blocked and failed requests as successes. Availability and policy-enforcement metrics are quietly wrong, and integrators who follow the documented contract build a bug.

**Fix.** Map error codes to status: 422 for guardrail blocks, 413 for oversized input, 502/504 for provider failures, 404 for unknown apps. Version the change and tell integrators, since it alters an existing contract.

### M3 — Anonymous information disclosure

`Endpoints/DashboardEndpoints.cs:162, 195` · `Endpoints/GatewayEndpoints.cs:185`

`/api/credentials/status` returns the assumed-role ARN masked to first and last twelve characters — enough to expose the role name tail and account fragment — plus expiry and last error. `/api/metrics` returns recent invocation logs including backend error text. `/gateway/health` reveals which local model backends are reachable.

Free reconnaissance of AWS account structure, internal topology, and failure modes ahead of a targeted attempt.

**Fix.** Authorize all three. Split health into an unauthenticated liveness probe that returns only up/down, and an authenticated detail view.

### M4 — The master key authenticates as every application

`Services/ApplicationRegistryService.cs:447, 475`

`AuthenticateAppAsync` accepts the admin key as a valid credential for any app, and `IssueStsTokenForAppAsync` will mint an admin token scoped to `"*"`. One static string is the highest privilege in the system, used interactively from a browser.

No separation of duty and no least privilege: the credential used for routine dashboard work is the same one that can impersonate any tenant. A single leak is total compromise with no partial containment.

**Fix.** Separate operator identity (people, via SSO) from service identity (applications, via keys). Keep a break-glass admin key offline, and require a named human actor for anything a person does interactively.

### M5 — Registry writes are non-atomic — a crash can erase every application

`Services/ApplicationRegistryService.cs:640–668`

Persistence serialises the full registry and calls `File.WriteAllText` over the live file. A crash, a full disk, or a recycle mid-write truncates it. Startup then deserialises a partial file, hits the catch block, and reseeds three default applications.

**Availability and integrity risk for the whole tenant list**: every registered app and key hash lost, replaced by defaults with freshly generated keys nobody holds. There is no backup and no write-ahead. The in-process `SemaphoreSlim` also does not coordinate across IIS worker processes, so an app-pool recycle overlap can interleave writes.

**Fix.** Write to a temp file and `File.Replace` for atomic swap; never reseed defaults when an existing registry fails to parse — fail startup instead, so a corrupt file is investigated rather than overwritten. Phase 3 moves this to a database.

### M6 — The STS `scope` claim is issued but never enforced

`Services/SecurityService.cs:124` · `Services/ApplicationRegistryService.cs:427–443`

Callers set a scope, it is signed into the payload and echoed back on inspect, but no authorization path reads it. Only `IsAdmin` and `AppId` affect decisions.

A token issued as `"read"` can invoke. Worse than a missing feature: the API presents a restriction the runtime does not apply, so operators will rely on it.

**Fix.** Enforce scope at each endpoint, or drop the claim until it is enforced. A security control that exists only in the response body is a liability.

### M7 — Swagger is exposed in Staging and Test

`Program.cs:171`

The UI is served whenever the environment is Development, Staging, or Test — environments that are frequently network-reachable and often share production-shaped data. It publishes a complete, browsable map of the unauthenticated management surface.

**Fix.** Development only, or authorize the Swagger routes alongside the endpoints they document.

### M8 — No security response headers

`Program.cs` (pipeline) — noted as a known gap in `README.md:105`

No `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, or `Permissions-Policy` is emitted. Nothing constrains injected script (C5), the dashboard can be framed for clickjacking, and responses are open to MIME sniffing.

**Fix.** Add a small header middleware ahead of static files. A strict CSP is achievable here because the dashboard loads no third-party assets.

### M9 — `AllowedHosts` is a wildcard

`appsettings.json`

`"AllowedHosts": "*"` with no production override disables host filtering, exposing host-header manipulation and DNS-rebinding against a service that binds to all interfaces.

**Fix.** Name the expected hostnames per environment.

### M10 — Secrets live in configuration files rather than a secret store

`appsettings*.json` · `deploy/iis/install.ps1`

The admin key is a plain configuration value. Production uses a deploy-time placeholder, which is the right instinct, but there is no integration with a managed secret store and no rotation mechanism for the admin credential itself. The highest-value credential sits in a file readable by anyone with host access or a backup copy, with no rotation path and no access log.

**Fix.** Source it from AWS Secrets Manager or Azure Key Vault through a configuration provider, cache with a TTL, and support rotation without a restart. Store a hash, not the key, so the running process never holds the plaintext.

---

## Low

### L1 — The sign-off document claims controls the code does not implement

`architecture.md` §3, §5

Five specific claims do not hold — see the reconciliation table below. Ranked low for exploitability, but it is the finding most likely to cause real harm in an enterprise setting: **a security review that is trusted and wrong is how gaps get formally accepted.** The README is notably more honest than `architecture.md`.

**Fix.** Reconcile the document with the code and mark unimplemented controls as planned. Each row should cite the code that implements it, not the file that mentions it.

### L2 — `appId` accepts an unrestricted character set

`Services/ApplicationRegistryService.cs:670`

`Slugify` lowercases and swaps spaces and underscores for hyphens. Quotes, slashes, angle brackets, and control characters pass through into an identifier used in URLs, HTML attributes, and log lines. This supplies the injection vector in C5 and makes log entries spoofable.

**Fix.** Allow-list `[a-z0-9-]`, cap the length, and reject rather than silently transform — a caller should know the id it will be addressed by.

### L3 — Backend exception text is returned to callers

`Services/ModelRouter.cs:196, 258` · `Services/LocalModelService.cs:58`

Raw `ex.Message` values from Bedrock and local backends are placed in the client-facing error payload, and both primary and fallback messages are concatenated on dual failure. This leaks internal hostnames, ARNs, and AWS error detail to any caller.

**Fix.** Return a stable error code and a correlation id; log the detail server-side against that id.

### L4 — No supply-chain or secret scanning

`UnifiedGatewayV2.csproj` · repository root

No `NuGetAudit` setting, no lock file, no CI pipeline in the repository. Package versions are pinned to 2024 releases across the AWS SDK, Swashbuckle, and Polly. Vulnerable dependencies age in silently, and a committed credential (H1) has nothing watching for it.

**Fix.** Enable `NuGetAudit` with a build-failing threshold, commit a lock file, and add dependency and secret scanning to CI.

---

## Documented controls versus implemented controls

Rows from the STRIDE analysis and sign-off table in `architecture.md` that a reader would reasonably take as assurance.

| Documented claim | What the code does | Status |
| :--- | :--- | :--- |
| Mandatory TLS for all external communication | No HTTPS redirection or HSTS in the pipeline; plain HTTP binding in launch settings. AWS SDK calls are TLS, so the cloud leg holds. | **Not implemented** |
| Unique `traceId` correlation across requests | `traceId` exists on the request model but is never read, propagated, or logged. | **Not implemented** |
| Polly circuit breaking & retry policies | Retry with exponential backoff is configured (`Program.cs:35`). No circuit breaker anywhere. | **Partial** |
| Non-root container execution (`appuser`, UID 1000) | No Dockerfile in the repository; deployment is IIS in-process. | **Not implemented** |
| Block mode aborts with 422 Unprocessable Entity | Returns HTTP 200 with an error object in the body (M2). | **Not implemented** |
| Strict app isolation on `/gateway/{appId}/invoke` | Correct within the data plane — but any caller can mint a token for any app via the open management plane (C2). | **Bypassable** |
| Configurable rate limiting per minute | Well-built partitioned limiter, attached to two endpoints only (H5). | **Partial** |
| Egress guardrails, fail closed | Accurate. An exception in output scanning suppresses the response (`ModelRouter.cs:329`). | **Confirmed** |
| Keys hashed, constant-time verification | Accurate. SHA-256 over a 256-bit CSPRNG key, compared with `FixedTimeEquals`. | **Confirmed** |
| Persistent append-only audit trail | Present and restart-safe, but records no caller identity and no management actions (M1). | **Partial** |

---

## Remediation roadmap

Ordered by dependency, not just severity. Phase 0 is what has to be true before this service is reachable from anywhere but a developer's machine; later phases are what "enterprise grade" means once the obvious holes are shut.

### Phase 0 — Close the open door *(days)*

- **Authorize the `/api` group** with `RequireAuthorization` so it is deny-by-default and new endpoints inherit it — the existing `IsAdminRequest` logic works as an interim scheme.
- **Refuse to start** on a default, empty, or low-entropy admin key outside Development, and on `EnforceAppApiKey: false`.
- **Remove the wildcard CORS branch** and set real origins in every environment file.
- **Enforce TLS** — HSTS plus HTTPS redirection in the pipeline, HTTPS-only at the IIS binding.
- **Escape the four XSS sinks**, replace inline `onclick` with delegated handlers, and constrain `appId` to `[a-z0-9-]`.
- **Add regex match timeouts** that fail closed, and a global rate-limit floor.

*Closes C1 · C2 · C3 · C4 · C5 · H1 · H2 · H3 · H5 · H6*

### Phase 1 — Real identity for operators *(2–4 weeks)*

- **OIDC sign-in for the management plane** against the corporate IdP (Entra ID or equivalent). People authenticate as people; applications keep API keys for the data plane.
- **Roles as authorization policies** — `PlatformAdmin`, `AppOwner`, `Auditor` — so reading metrics does not require the rights to mint credentials.
- **Per-app ownership** on `AppConfig`, so an `AppOwner` sees and rotates only their own applications. This is what makes the gateway genuinely multi-tenant rather than shared-admin.
- **Break-glass admin key** kept offline, alerting loudly whenever it is used.

*Closes M4 · hardens C1*

### Phase 2 — Credential lifecycle you can actually operate *(2–3 weeks)*

- **Asymmetric token signing** — standard JWT signed by a key in Key Vault or KMS, so the web tier never holds signing material and tokens survive host rebuilds.
- **Revocation** — a `jti` denylist bounded by max TTL, plus a key-generation claim so rotation invalidates outstanding tokens immediately.
- **Sane TTLs** — 15-minute default, one-hour ceiling, with the seven-day path removed.
- **Dual-key rotation** — accept the previous key hash for a short overlap so rotation stops being an outage.
- **Enforce `scope`** at every endpoint, or remove the claim.

*Closes H4 · H7 · M6*

### Phase 3 — Durable state and real observability *(3–4 weeks)*

- **Move the registry to SQL Server or Postgres** with transactional writes, encryption at rest, and backups — removing the whole-registry-loss failure mode and making horizontal scale possible.
- **Attributable, immutable audit** — actor, source IP, token `jti`, traceId on every entry, and a record for every management action, written append-only.
- **Ship to the SIEM** over OpenTelemetry, with alerts on guardrail-policy changes, admin-key use, authentication-failure spikes, and token-budget breaches.
- **Interim**: atomic temp-file-and-replace writes, and never reseed defaults over an unparseable registry.

*Closes M1 · M5 · completes M3*

### Phase 4 — Runtime hardening *(2 weeks)*

- **Security headers** including a strict CSP — straightforward here, since the dashboard loads no third-party assets.
- **Cost controls** — per-app daily token budgets and concurrency caps enforced separately from request-rate limits, since one request can consume the entire token ceiling.
- **Correct status codes** — 422 on guardrail block, 413 on oversized input, 502/504 on provider failure; version and communicate the change.
- **Circuit breakers** on both provider paths, and generic error responses carrying a correlation id instead of backend exception text.

*Closes M2 · M8 · M9 · L3 · completes C3*

### Phase 5 — Assurance *(ongoing)*

- **CI gates** — `NuGetAudit` failing the build on known vulnerabilities, a committed lock file, secret scanning, and SAST on every pull request.
- **A test per control**, not just per detector: assert that `/api` rejects anonymous callers, that rotation invalidates outstanding tokens, that a pathological prompt returns within a bounded time.
- **Reconcile `architecture.md`** with the code and keep it honest, citing implementing code for each row.
- **External penetration test** once Phase 2 lands, and a threat-model refresh covering the management plane, which the current STRIDE analysis does not address.

*Closes L1 · L4*

---

## What already holds up

Worth stating plainly, because the remediation plan should not disturb any of it.

- **Key generation and storage** — 256-bit CSPRNG keys, stored only as SHA-256 hashes, verified with `FixedTimeEquals`. Plaintext is returned exactly once on creation and rotation.
- **Egress guardrails fail closed** — if output scanning throws, the model response is suppressed rather than returned. The right default, and easy to get backwards.
- **Detector quality** — Luhn validation on card candidates and SSA assignment rules on SSNs. Real validation rather than pattern-matching that floods reviewers with false positives.
- **Abuse clamps** — input-character limit, token ceiling, and request-body cap applied at both Kestrel and IIS. Correct layering.
- **Rate-limit partitioning** — hashes the presented credential rather than keying on it, falling back to appId then IP. The design is sound; it just isn't applied widely enough.
- **Credential refresh** — proactive STS refresh ahead of expiry, with a buffer, a lock, and retention of working credentials when a refresh fails.
- **Audit durability** — JSON Lines per UTC day, rehydrated at startup, retention-pruned, and tolerant of a torn trailing line.
- **Repository hygiene** — the key ring, the app registry, and the audit directory are all correctly gitignored. Only the sample admin key slipped through.

---

## Scope and method

Static review of all C# sources, configuration, dashboard assets, and deployment scripts on `main` at commit `133e4f5`. The application was not built, run, or tested dynamically, and no exploitation was attempted — the attack chain is derived from reading the code paths, and each step should be confirmed against a running instance before it is treated as proven or as ruled out.

Line references point at commit `133e4f5` and will drift as the code changes. Findings in `bin/`, `obj/`, and `.vs/` were out of scope. Severity reflects impact in a network-reachable enterprise deployment; a gateway bound only to localhost carries materially less risk from the Critical findings, though none of them become acceptable.
