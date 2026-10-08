# UAR → Unified Gateway: feature port plan

| Item | Detail |
| --- | --- |
| Source project | `C:\Users\wasim\Claude\Projects\Universal-AI-Runtime-v1` (Universal AI Runtime, "UAR"), Python 3.12 / FastAPI / gRPC / PostgreSQL, ~9.4k lines of runtime code plus SDKs, plugin SDKs, contracts and a WPF admin app. Milestones M0–M9 implemented. |
| Target project | This repository (`Unified-Gateway-API`), .NET 8 / ASP.NET Core minimal APIs, ~14.2k lines, IIS-hosted, AWS-backed (Roles Anywhere, Secrets Manager, KMS, S3, Bedrock), 331 tests passing. |
| Goal | Every capability UAR offers becomes available in this gateway, without losing what this gateway already does better: AWS host identity, IAM-evaluated management plane, shipped-template validation, and the SEC-01…SEC-14 hardening. |
| Written | 2026-10-07 |

## 1. Method

UAR is a Python runtime; this gateway is a C# service with its own security model. The plan ports
**capabilities, not code**. Each UAR subsystem is re-implemented as C# services behind interfaces
shaped like the ones already here (`IModelRouter`, `IGuardrailService`, `ISecurityService`,
`IApplicationRegistryService`, `IAuditStore`), so existing endpoints, tests and the dashboard keep
working while the surface grows.

Three things are copied nearly verbatim, because they are data rather than code:

- the SQL schema in `migrations/0001…0006` (runs, run_events, approvals, audit + heads/anchors, usage_ledger, tenant_budget, tool_intents, idempotency, agents, api_keys, app_registrations, app_secrets, sts_signing_keys, mcp_servers, plugin_versions, plugin_active);
- the contract shapes in `proto/uar/v1/runtime.proto` and `contracts/generated/openapi.json`;
- the guardrail detector pattern set and the agent graph JSON Schema (`contracts/schemas/agent.schema.json`).

## 2. Where the two projects stand today

| Capability area | UAR | This gateway today | Gap |
| --- | --- | --- | --- |
| Inference API | `POST /api/v1/inference`, sync + SSE + WebSocket, tool-calling loop | `POST /gateway/{appId}/invoke`, `POST /gateway/universal/invoke`, sync only | streaming, tool calls |
| Providers | Ollama, OpenAI-compatible (LM Studio, llama.cpp, Groq, vLLM), OpenAI Responses, Anthropic SDK, Azure OpenAI, Vertex, fake, plugin | Bedrock (Anthropic/Titan/Llama payloads), Ollama, LM Studio, llama.cpp | six provider families plus a deterministic fake |
| Model naming | `local:` / `cloud:` / `enterprise:` classes, aliases, capability matching | per-app `Provider` + `Model` strings; an unknown provider falls through to Bedrock (SEC-09) | class grammar, aliases, capability matching, validation |
| Router policy | rules v2: tenant / role / data class / region / price cap / prefer cost-or-latency; opt-in fallback; per-provider breaker; concurrency and queue limits; price catalog; budgets | per-app primary plus fallback, per-backend circuit breaker, per-app token ceiling | everything else |
| Guardrails | three stages (input / tool_results / output), PII + PCI + secrets + denied terms + size, injection heuristics including hidden-Unicode tricks and an optional classifier model, block/redact/flag, streaming guard, per-tenant policy, exempt roles, `/guardrails/check` | input and output stages, PCI/PII/secrets/injection, block/redact/audit, runtime config update, `/api/guardrails/test` | tool-result stage, denied terms, hidden-Unicode and classifier injection checks, streaming guard, per-tenant policy, exempt roles |
| Tools / MCP | full MCP client (stdio, container, Streamable HTTP), server registry plus runtime registration with operator allowlists, namespaced catalogue, per-call authorization with argument constraints, side-effect classes, intents, audit, first-party filesystem and read-only SQL servers, and UAR itself served as an MCP server at `/mcp` | none | the whole subsystem |
| Agents | durable graph engine: YAML/JSON graphs, CEL expressions, checkpoints, fencing, leases, recovery, sub-agents, loops, parallel, branch, approval nodes, limits, per-agent permissions, run events, cancel/resolve, watch over SSE/WS | none | the whole subsystem |
| Dry-run | static plan plus fixture simulation, provably non-executing | none | the whole subsystem |
| Approvals | approval nodes and inline tool approvals bound to action + args hash; decided once, used once; TTL fails closed; no self-approval; sub-agent approvals park the parent | none | the whole subsystem |
| Audit | per-tenant SHA-256 hash chain, append-only trigger, payload-free rows, `verify` and `export` APIs, retention anchor | S3 NDJSON trail, attributed records, 30 s flush | hash chain, verify/export, tamper evidence (SL-11 / SEC-15 open) |
| Identity | tenant-bound API keys with hot reload, dev HS256 JWT, multi-issuer OIDC with JWKS and group/subject role mapping, built-in STS with OAuth 2.0 client credentials, ES256 tokens, JWKS and discovery endpoints, secret rotation, instant disable, signing-key rotation with activation delay, `require_tokens` mode | app API keys (SHA-256), HMAC `ug_sts_` tokens, Okta OIDC for people, AWS SigV4 identity for automation, break-glass | OAuth 2.0 grant, ES256 + JWKS, app secrets with rotation, per-app token generation (SEC-10), multi-issuer OIDC |
| RBAC | 28 named permissions, six default roles, custom roles, per-tenant quotas, tenant isolation | IAM policy evaluation per management action, scopes on tokens | permission/role model, tenants, quotas |
| Observability | OTel traces, 13 Prometheus metric families, JSON logs, usage and cost ledger | JSON `/api/metrics`, billing derived from the S3 trail | OTel, Prometheus exposition, usage ledger |
| Redaction / retention | builtin and configured patterns applied to audit, events, approval summaries and egress by model class; retention jobs for runs/usage/audit/idempotency | none | both |
| Plugins | gRPC plugin host (register, integrity, activate, pin, rollback, breaker) plus SDKs for Python/Go/TS/.NET/Java and reference plugins | none | the whole subsystem |
| Contracts / SDKs | protobuf → OpenAPI + JSON Schema + TS types, conformance fixtures, `uar-mock`, SDKs for Python/TS/Go/Rust/.NET/Java, a sample per language | hand-written Swagger | contract pipeline, SDKs, mock, fixtures |
| Admin UI | WPF app: overview, keys, apps, MCP, approvals, audit, usage, guardrails, logs, API reference | web dashboard: apps, models, guardrails, billing, usage | MCP, approvals, audit-verify and logs pages |
| Packaging | Docker, Compose, Helm, CI | IIS installer, CI | container/Helm path (optional here) |

## 3. Decisions required before coding

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | Port to C#, or run the Python runtime as a sidecar and proxy to it? | **Port to C#.** A sidecar splits the security model in two — two identity systems, two audit trails — and this repository's hardening would not cover the Python half. The cost is that this is the long road; see §5. |
| D2 | Durable store for runs, approvals, the audit chain, usage and idempotency | **PostgreSQL** through Npgsql with raw SQL, with UAR's migrations ported as they are. The agent engine needs transactions, `FOR UPDATE SKIP LOCKED` leasing and an append-only audit trigger; the JSON registry and S3 trail cannot provide those. Keep the JSON registry as the application catalogue until P5, then move it into the same database. |
| D3 | Tenancy | Add a tenant concept with a single `default` tenant, so existing single-organisation deployments keep working, and carry `tenant` on every new table. Map the current Okta group → IAM role mapping onto tenant plus roles. |
| D4 | Authorization model | Keep `RequireIamAction` as the outer gate on the management plane and introduce UAR's 28 permissions as the inner model used by agents, tools and approvals, with one mapping table in one place. |
| D5 | Tokens | Keep HMAC `ug_sts_` tokens for the existing data plane and add OAuth 2.0 client credentials with ES256 and JWKS alongside; retire the HMAC path once SDKs have moved. This closes SEC-10 on the way. |
| D6 | gRPC and multi-language SDKs | Lowest value here, highest cost. Ship the protobuf contract and generated OpenAPI first; add gRPC and the Go/Rust/Java SDKs only when a consumer appears. |

## 4. Phased plan

Each phase ends with a gate: suite green, new tests named for the capability, and the capability
matrix updated. Sizes: S ≈ 1–2 days, M ≈ 3–5 days, L ≈ 1–2 weeks, XL ≈ 3–4 weeks.

### P0 — Foundations (L)

The config, identity and storage everything else builds on.

- `Models/RuntimeOptions.cs`: tenants, roles → permissions, quotas, data residency, egress classes, profile (`local-only` / `standard`), limits.
- `Services/Governance/PermissionCatalog.cs`: the 28 permissions, six default roles, custom roles, validated at startup through `StartupValidator`.
- `Services/Store/`: Npgsql connection factory, migration runner, `migrations/*.sql` ported from UAR (0001–0006).
- Request envelope: stable error codes (`contracts/errors.md`), a `request_id` on every response, an idempotency table and `Idempotency-Key` handling.
- Principal plumbing: `CallerContext` gains `Tenant`, `Roles` and `Permissions`.
- Tests: config validation, migration run, permission mapping, idempotent replay.

### P1 — Observability and usage ledger (M)

- OpenTelemetry traces (`OTEL_EXPORTER_OTLP_ENDPOINT`), JSON structured logs, and Prometheus `/metrics` carrying UAR's 13 metric families via `prometheus-net`.
- `Services/Telemetry/UsageLedger.cs`: tokens, cost and latency per request, run and node, written to `usage_ledger`.
- `Models/PricingOptions.cs`: a price catalog (`provider/model` plus glob patterns, decimal per million tokens) and `tenant_budget` reserve/settle.
- Billing reads the ledger instead of re-scanning S3, keeping the current API shape.
- Tests: metric emission, cost arithmetic for known and unknown prices, budget reserve/settle/exhaustion.

### P2 — Router v2 and streaming (XL)

- `Services/Router/`: `ProviderCatalog`, a `ModelName` grammar (`class:provider/model` plus aliases), capability matching, `ResolvePlan`.
- Adapters in `Services/Router/Adapters/`: `OllamaAdapter`, `OpenAiCompatAdapter` (LM Studio, llama.cpp, Groq, vLLM), `OpenAiResponsesAdapter`, `AnthropicMessagesAdapter`, `AzureOpenAiAdapter`, `VertexAdapter`, `FakeAdapter`; the existing `BedrockService` becomes `BedrockAdapter`.
- Rules v2: tenant / role / data class / region / price cap / `prefer order|cost|latency`; opt-in fallback; per-provider breaker, max concurrency and queue timeout; provider model discovery.
- Streaming: SSE on the invoke endpoints and a `/gateway/ws` WebSocket frame protocol; a tool-calling loop bounded by `auto_tool_max_steps`.
- Closes SEC-09: an unknown provider no longer silently reaches Bedrock.
- Tests: name grammar, rule precedence, residency and price-cap exclusion, fallback, breaker, stream assembly, tool loop, and a wire-format fixture per adapter.

### P3 — Guardrail parity (M)

- Three stages (input / tool_results / output) with per-tenant policies and `exempt_roles`.
- Detector superset: PII (email, phone, SSN, IBAN, IPv4), PCI (card with Luhn, CVV, track data), secrets (12 types including this gateway's `ug_live_` and `ug_sts_`), denied terms and regexes, `max_chars`.
- Injection: weighted heuristics, hidden-Unicode tricks (tag characters, zero-width runs, bidi controls, long base64 blobs), and an optional classifier model gated by `classifier_min_score`.
- `StreamGuard` for streamed output; `POST /api/guardrails/check`; findings into audit and metrics.
- Keeps SEC-04 (an incomplete scan fails closed), SEC-07 (`ug_sts_` detector) and SEC-08 (every match redacted).
- Tests: port UAR's 30 guardrail tests alongside the existing SEC cases.

### P4 — Identity and token service (L)

- OAuth 2.0 client credentials at `POST /api/v1/oauth/token`, ES256 access tokens, `/.well-known/jwks.json` and `/.well-known/openid-configuration`, key rotation with an activation delay, and signing keys encrypted at rest with KMS rather than a passphrase.
- `app_registrations` and `app_secrets`: register, add and revoke secrets, instant disable, `require_tokens` mode.
- Multi-issuer OIDC with a JWKS cache and group → role plus subject → role mapping, generalising the current Okta path.
- Per-application token generation / `tokensValidAfter`, closing SEC-10, and a durable shared denylist, closing SEC-11.
- Tests: grant flow, ES256 verification, rotation overlap, revoked secret, disabled app, revocation of outstanding tokens.

### P5 — Governance: audit chain, approvals, redaction, retention (L)

- A hash-chained per-tenant audit in Postgres (append-only trigger, payload-free rows, `GET /api/v1/audit/verify`, `GET /api/v1/audit/export`), with the S3 trail kept as the archive sink. Addresses SL-11 / SEC-15.
- Approvals: an `approvals` table, action + args-hash binding, decided once and used once, TTL failing closed, no self-approval, approver roles, and list/get/decide endpoints.
- Redaction: builtin and configured patterns applied to audit details, run events, approval summaries, and prompts bound for named model classes.
- Retention jobs for runs, usage, audit (preserving the chain anchor) and idempotency.
- Tests: tamper, deletion and truncation detection; approval single-use and expiry; redaction coverage; retention followed by chain verification.

### P6 — MCP tool plane (XL)

- `Services/Mcp/`: an MCP client over stdio, container (`docker run` with mounts, `--network none`, memory and CPU caps) and Streamable HTTP, with protocol negotiation (the 2026-07-28 revision, falling back to the legacy handshake).
- `McpServerRegistry` from config and from runtime registration (`/api/v1/admin/mcp-servers`), operator allowlists for commands and images, `${VAR}` secret expansion, and enable/disable/reconnect/delete.
- A namespaced tool catalogue; per-call authorization (tool policies: allow / deny / require_approval, roles, tenants, argument prefix/pattern/length constraints); side-effect classes (read/write/external); `tool_intents` for ambiguous writes; output caps; URL egress checks.
- First-party servers: a confined filesystem server (roots, symlink and ADS checks, exclusive writes) and a read-only SQL server.
- Serve this gateway as an MCP server at `/mcp`, so Claude Desktop, Claude Code and VS Code can use its governed tools, models and agents.
- Tests: sandbox escapes refused, policy denials, approval-gated calls, container isolation, HTTP transport, and `/mcp` driven by a real MCP client.

### P7 — Durable agent engine (XL)

- Graph: `contracts/schemas/agent.schema.json` ported, a compiler with reference, reachability and cycle checks, per-agent `permissions` and `limits`, and `memory.scope`.
- An expression evaluator for the CEL subset UAR uses (`engine/cel.py` is 125 lines and ports directly).
- Node types: `llm`, `tool`, `agent`, `parallel`, `loop`, `branch`, `approval`, `transform`, `end`, with per-node retries.
- Durability: `runs` and `run_events`, a checkpoint after each node, fencing tokens, leases with heartbeats, crash recovery, cancel, resolve, ambiguous-write parking, and sub-agent runs that park the parent.
- API: register agent, start run (202), get run, event stream (`after_seq`), cancel, resolve, and a WebSocket watch.
- Tests: port UAR's engine suite — checkpoint and resume, lost lease, fence conflict, loop and parallel limits, depth limit, and permission narrowing for sub-agents.

### P8 — Dry-run simulator (M)

- A static plan (nodes, model classes, tools, estimated cost) and fixture simulation, with the non-executing guarantee enforced by construction: no adapter and no MCP session is reachable from the dry-run path.
- Tests: a dry run of a graph whose tools would fail proves nothing executed.

### P9 — Plugin runtime (L)

- A gRPC plugin host: manifest, integrity (hash pin), register, activate, pin, rollback, and a per-plugin breaker, for model, tool and agent plugin kinds.
- The .NET plugin SDK first, since this is a .NET shop, then Python and TypeScript if needed.
- Tests: integrity mismatch refused, activation and rollback, breaker opening on a failing plugin.

### P10 — Contracts, SDKs, admin surface, packaging (L)

- `proto/` plus generated OpenAPI, JSON Schema and TS types checked in, conformance fixtures, and a mock server equivalent to `uar-mock`.
- SDKs: C# first, then Python and TypeScript, each validated against the fixtures.
- Dashboard pages for MCP servers, approvals, audit verify/export, service logs, and usage/cost, matching the WPF admin app's coverage.
- Optional: Dockerfile, Compose and Helm alongside the IIS installer, plus the gRPC endpoint.

## 5. Reality check on effort

Summed across phases this is roughly **14–20 person-weeks** of focused work. UAR needed nine
milestones to reach this point and carries ~9.4k lines of runtime code plus migrations, contracts and
SDKs; the two subsystems with no counterpart here — the MCP plane and the durable agent engine — are
half of that on their own.

Nothing in the plan is speculative: every item exists in UAR and can be read while porting. But it
cannot land in one sitting. The phases are ordered so each is independently useful: P0–P1 improve what
is already here, P2–P5 bring the gateway to parity on the governed-inference story, and P6–P10 add the
tool, agent and plugin platform.

## 6. Non-goals

- Re-implementing UAR's Kubernetes and Helm path. This gateway deploys on IIS.
- Go, Rust and Java SDKs until a consumer asks for them.
- Keeping the Python runtime alive in parallel: one gateway, one security model (D1).
