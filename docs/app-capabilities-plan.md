# Plan: skills, agents, plugins, tools and MCP servers on applications

| | |
| --- | --- |
| Goal | A registered application can be given capabilities — skills, tools, MCP servers, agents and plugins — and the gateway enforces, meters and audits every use of them. |
| Today | An application is a routing record: provider, model, system prompt, temperature, token ceiling, fallback, rate card ([AppConfig.cs](../Models/AppConfig.cs)). It has no capabilities at all. |
| Written | 2026-10-10 |
| Related | [uar-feature-port-plan.md](uar-feature-port-plan.md) — the same subsystems viewed as a port from UAR. This document is the application-facing design: what an app owner registers and attaches. |

## 1. Five things, deliberately separated

These overlap in conversation and must not overlap in the model. The distinction that matters is
**who can execute what**.

| Capability | What it is | Executes? | Registered by | Comes from |
| --- | --- | --- | --- | --- |
| **Skill** | A packaged instruction set: a short description plus a body of guidance, and optionally reference files. Conditions how the model answers. | No | App owner or operator | Authored in the gateway, or imported as a `SKILL.md` folder |
| **Tool** | One callable function with a JSON Schema and a side-effect class (read / write / external). | Yes | Nobody directly | *Published by* an MCP server or a plugin |
| **MCP server** | A process, container or HTTP endpoint speaking MCP that publishes tools (and prompts and resources). | Yes, out of process | Operator only | Config, or runtime registration against an allowlist |
| **Agent** | A named graph the gateway executes: llm, tool, branch, loop, parallel, approval and sub-agent nodes, with checkpoints and durable runs. | Yes, orchestrates | Operator or app owner | A YAML/JSON definition validated at registration |
| **Plugin** | Gateway-side code extension loaded over gRPC that can supply tools, model adapters or agent implementations. | Yes, third-party code | Operator only | A signed, hash-pinned artefact |

Two rules fall out of that table and shape everything below:

1. **Tools are never registered on an application.** An application is granted *access to* tools
   that an MCP server or plugin already publishes. This keeps one authorization path instead of two.
2. **Skills grant no execution rights.** A skill is text the model reads. If a skill says "use the
   `db.query` tool", the call still fails unless that tool is separately attached. Skills are
   untrusted content and are treated as such.

## 2. The model: catalogue, then binding

Two levels, with different privilege.

```
  Platform catalogue  (operator)              Application bindings  (app owner)
  ──────────────────────────────              ─────────────────────────────────
  mcp_servers   filesystem, sql, jira   ──┐
  plugins       pdf-extract@1.4.0       ──┼──►  app "support-bot"
  agents        triage@2.1.0            ──┤       tools:   filesystem.read_file, jira.create_issue
  skills        refund-policy@3         ──┘       skills:  refund-policy@3
                                                  agents:  triage@2.1.0
                                                  plugins: pdf-extract@1.4.0
  tools  (derived, never registered)              every binding: pinned version, enabled flag,
  filesystem.read_file, jira.create_issue …       per-binding limits and approval rules
```

**Catalogue** entries are platform resources. Registering an MCP server or a plugin means running
code with the gateway's rights, so both are operator-only and go through allowlists.

**Bindings** attach a catalogue entry to one application at a pinned version. An app owner can only
attach what the catalogue already offers, so the dangerous step and the everyday step are
different operations with different IAM actions.

**Effective capability set** at invocation = bindings ∩ enabled catalogue entries ∩ tool policy ∩
token scope. It is resolved once per request and recorded in the audit entry, so what an
application *could* do at the time of a call is reconstructable afterwards.

### Storage

Bindings and catalogue entries fit the existing JSON registry (they are small and
change rarely), and that is how phases A1–A2 can ship without new infrastructure. **Agent runs do
not fit**: checkpoints, leases and fencing need transactions. Agents therefore wait for the
PostgreSQL store from decision D2 of the port plan, or arrive with it.

## 3. Data model

New `AppConfig` member, carrying only bindings — never capability bodies:

```csharp
[JsonPropertyName("capabilities")]
public List<CapabilityBinding> Capabilities { get; init; } = [];

public record CapabilityBinding
{
    public string Id { get; init; }                  // binding id, for detach and audit
    public CapabilityKind Kind { get; init; }        // Skill | Tool | McpServer | Agent | Plugin
    public string Ref { get; init; }                 // "filesystem.read_file", "refund-policy", "triage"
    public string Version { get; init; }             // pinned; "latest" is refused
    public bool Enabled { get; init; } = true;
    public ToolBindingOptions? Tool { get; init; }   // side-effect ceiling, arg constraints, approval
    public string AttachedBy { get; init; }          // principal ARN
    public DateTimeOffset AttachedAt { get; init; }
}
```

New catalogue records, each with id, version, description, owner, state (`draft` / `active` /
`disabled`), checksum and audit stamps: `SkillDefinition`, `McpServerRegistration`,
`AgentDefinition`, `PluginRegistration`. Tools are not stored; they are read from a connected MCP
server or plugin and cached as `ToolDescriptor` (name, schema, side effect, source).

Versioning follows the existing application pattern: a new version is a new row, bindings pin one,
and `VersionHistory` keeps the previous bodies for rollback.

## 4. Management API

All under the existing `/api` management plane with `RequireIamAction`, so authorization,
rate limiting and audit come for free.

| Operation | Route | New IAM action | Who |
| --- | --- | --- | --- |
| Register / update / disable an MCP server | `POST,PUT,DELETE /api/mcp-servers[/{id}]` | `ManageMcpServers` | Operator |
| Test a server's connection, list its tools | `POST /api/mcp-servers/{id}/probe`, `GET /api/mcp-servers/{id}/tools` | `ReadMcpServers` | Operator, app owner |
| Register / version / disable a plugin | `POST,PUT,DELETE /api/plugins[/{id}]`, `POST /api/plugins/{id}/activate|rollback` | `ManagePlugins` | Operator |
| Register / version an agent | `POST,PUT,DELETE /api/agents[/{id}]` | `ManageAgents` | Operator, app owner (own apps) |
| Register / version a skill | `POST,PUT,DELETE /api/skills[/{id}]` | `ManageSkills` | Operator, app owner |
| Browse the catalogue | `GET /api/capabilities?kind=` | `ListCapabilities` | Any management caller |
| **Attach / detach on an app** | `POST /api/apps/{appId}/capabilities`, `DELETE …/{bindingId}` | `ManageAppCapabilities` | App owner |
| List an app's effective capabilities | `GET /api/apps/{appId}/capabilities` | `GetApplication` | App owner |

Data-plane additions, authenticated by the app's own credential as invocation already is:

| Operation | Route | Scope |
| --- | --- | --- |
| Invoke with tools (tool-calling loop) | existing `POST /gateway/{appId}/invoke` | `invoke` |
| List what this app may use | `GET /gateway/{appId}/capabilities` | `read` |
| Start an agent run | `POST /gateway/{appId}/agents/{agentId}/runs` | `agents:run` (new) |
| Read run, stream events, cancel, resolve | `GET,POST /gateway/{appId}/runs/{runId}[/events|/cancel|/resolve]` | `agents:run` |
| Call one tool directly | `POST /gateway/{appId}/tools/{tool}` | `tools:execute` (new) |

`GatewayScopes` gains `tools:execute` and `agents:run`. Existing `invoke` tokens keep working and
do **not** imply either: a token minted to answer questions should not gain the ability to write
through a tool because the app was later given one.

## 5. Runtime behaviour

**Invocation with skills.** The router composes the system prompt as: app system prompt, then a
one-line index of each attached skill (name and description only), then the full body of any skill
the request names or the model requests. Progressive disclosure keeps the token cost of ten
attached skills near zero until one is used. Skill bodies pass the guardrail input stage before
they are injected — closing SEC-06's system-prompt gap for this new content rather than repeating it.

**Invocation with tools.** When an app has tool bindings and the provider supports tool calling,
the adapter advertises the effective tool set. The loop runs at most `auto_tool_max_steps` times:
model asks → policy check → approval if required → execute through the MCP client → guardrail
`tool_results` stage → feed back. Each call is metered against the app's quota and written to the
audit trail with the tool name and an argument hash, never the arguments themselves.

**Agent runs** are asynchronous: start returns 202 and a run id; the engine executes nodes with a
checkpoint after each, and the caller watches over SSE or WebSocket. A node may only use the
capabilities bound to the application *and* declared in the agent definition — the narrower of the
two, which is what makes a sub-agent safe to call.

**Plugins** provide tools and model adapters that look identical to the above from the
application's point of view. The difference is operational: integrity pin, activation, rollback and
a per-plugin circuit breaker.

## 6. Governance

This feature turns a text gateway into one that executes code on an application's behalf, so the
controls are the point, not the decoration.

- **Separation of duties.** Registering an MCP server or plugin (runs code) is `ManageMcpServers` /
  `ManagePlugins`. Attaching one to an app (uses code someone already vetted) is
  `ManageAppCapabilities`. An app owner cannot introduce new executable surface.
- **Operator allowlists.** Runtime-registered servers are restricted to allowlisted stdio commands
  and container image patterns, as UAR does. Outside Development, a server must be a container or a
  remote HTTPS endpoint — no bare stdio child processes under the IIS app-pool identity.
- **Side-effect classes.** Every tool is `read`, `write` or `external`. A binding carries a ceiling:
  an app attached at `read` cannot call a tool the server later reclassifies as `write`.
- **Approvals.** `write` and `external` tools can require human approval, bound to tool plus
  argument hash, decided once, used once, expiring closed — the approvals subsystem from the port
  plan's P5.
- **Secrets.** Server credentials are stored by reference (`ApiKeySecretName`), never inline, and
  resolved through `ISecretsProvider`, the pattern SEC-14 established for model backends.
- **Egress.** Remote MCP endpoints are checked against an allowlist before connection, so a
  registered server cannot point the gateway at link-local metadata or an internal host.
- **Quotas and cost.** Tool calls and agent nodes consume the app's `ICallerQuota` budget, and agent
  runs carry `max_steps`, `max_tool_calls`, `max_cost_usd` and a timeout.
- **Audit.** Catalogue changes, bindings, tool calls, approvals and run transitions are all
  management or data-plane audit events with actor, app, capability and outcome.
- **Untrusted content.** Skill bodies, tool results and MCP server descriptions are data. They pass
  the guardrail stages, and nothing in them can widen the effective capability set.

## 7. Dashboard

- **Application detail** gains a Capabilities tab: attached skills, tools, agents and plugins, each
  with version, state and last use; attach opens a catalogue picker filtered to what the operator
  has approved.
- **New pages**: MCP Servers (register, probe, tool list, enable/disable), Skills (author, version,
  preview the composed prompt), Agents (definition editor, validation errors, recent runs), Plugins
  (versions, integrity, activate/rollback), Approvals (pending queue).
- The Register New Application modal gains an optional "Start from a template" step that attaches a
  standard skill and tool set.

## 8. Phases

> **Status, 2026-10-10: A0 and A1 are implemented.** 373 tests pass, 23 of them new in
> `CapabilityTests`. What landed:
>
> - `CapabilityBinding` on `AppConfig` with pinned versions ([Capabilities.cs](../Models/Capabilities.cs)).
> - The skill catalogue ([SkillRegistryService.cs](../Services/SkillRegistryService.cs)): slug ids, versioning with history, enable/disable, atomic JSON persistence beside the application registry, and guardrails in Block mode over every body before it is stored.
> - Resolution and prompt composition ([CapabilityService.cs](../Services/CapabilityService.cs)): bindings resolved per request, an index line per usable skill, bodies only for the skills a request names.
> - Management API ([CapabilityEndpoints.cs](../Endpoints/CapabilityEndpoints.cs)): skill CRUD under `ManageSkills`, catalogue browse under `ListCapabilities`, attach and detach under `ManageAppCapabilities`, each audited.
> - `InvokeAppRequest.Skills` carries the request's chosen skills; the router composes them in.
> - The three new IAM actions are granted to the app-owner role, and `ManageMcpServers` / `ManagePlugins` are pre-denied to it, in the dev provisioning script.
>
> - A Skills & Capabilities page in the dashboard: catalogue with enable/disable/delete, a registration form, and attach/detach per application showing the pinned version against the catalogue's current one.
>
> Verified against a running gateway: a skill registers, an injection payload in a body is refused with the finding named, a binding attaches and detaches, a duplicate is refused, and attaching a kind with no catalogue is refused rather than stored.
>
> **A2 is part-built.** 391 tests pass, 18 of them new in `ToolPlaneTests`. What landed:
>
> - MCP server catalogue ([McpServerRegistry.cs](../Services/Mcp/McpServerRegistry.cs)): operator-only registration, slug namespaces, credential by secret reference, and destination rules — HTTPS outside Development, loopback-only plain HTTP in Development, link-local and metadata addresses always refused, optional `Gateway:Mcp:AllowedHosts`.
> - An MCP client over Streamable HTTP ([McpClient.cs](../Services/Mcp/McpClient.cs)): JSON-RPC with the initialize handshake per exchange, no redirects, no cookies, response byte cap, SSE or JSON replies.
> - Tool catalogue and execution ([ToolCatalog.cs](../Services/Mcp/ToolCatalog.cs)): namespaced `server.tool` names, cached listings, per-application binding checks, side-effect ceilings, argument size cap, and the egress guardrails over every result.
> - Bindings for `Tool` and `McpServer` kinds, with `maxSideEffect`. Attaching a write tool refuses unless the ceiling is stated.
> - `POST /gateway/{appId}/tools/{tool}` on the data plane, gated by the new `tools:execute` scope, metered by the application quota, and audited with an argument hash rather than the arguments.
> - Management API: `/api/mcp-servers` CRUD, `/api/mcp-servers/{id}/tools`, `/api/tools`, under `ManageMcpServers` and `ReadMcpServers`.
>
> **The tool-calling loop now works.** `ModelRouter` offers the application's bound tools to the model, runs each call it asks for under the same bindings, quota and guardrails as a direct call, replays the result, and stops at `Gateway:Mcp:MaxToolSteps`. A refusal is handed back to the model as the tool's result rather than failing the request, so it can answer without the tool. Wire support: Bedrock/Anthropic (`tool_use` content blocks) and OpenAI-compatible servers such as LM Studio (`tools` / `tool_calls`). Namespaced `server.tool` names are encoded for providers that forbid dots and matched back against what was offered.
>
> **Deferred from A2:** Ollama's `/api/generate` has no tool support, so an Ollama-routed application is offered none — moving it to `/api/chat` is the remaining adapter. Also stdio and container transports, first-party filesystem and SQL servers, `/mcp` as a server, and the dashboard pages for MCP. The Bedrock payload shapes are covered by code review rather than tests, since `BedrockService` builds its own AWS client.
>
> Not done: the dashboard page for skills has not been click-tested in a browser, only its API. A3 onward is unstarted.



Ordered so each phase is independently useful, and so the lowest-risk capability ships first.

| Phase | Scope | Size | Gate |
| --- | --- | --- | --- |
| **A0 — Binding spine** | `CapabilityBinding` on `AppConfig`, catalogue records, attach/detach API, new IAM actions, effective-set resolution, audit events, Capabilities tab (read-only). No capability executes yet. | M | Attach and detach are audited; an unknown or disabled ref is refused; version pins are required |
| **A1 — Skills** | Skill registration and versioning, `SKILL.md` import, guardrail scan at registration and injection, prompt composition with progressive disclosure, per-app attachment, dashboard authoring | M | A bound skill changes model behaviour; an unbound one is invisible; a skill naming a tool grants nothing |
| **A2 — MCP servers and tools** | MCP client (stdio in dev, container and Streamable HTTP in general), server registry with allowlists, tool catalogue and cache, tool bindings with side-effect ceilings and argument constraints, the tool-calling loop, `POST /gateway/{appId}/tools/{tool}`, `tools:execute` scope, quotas and audit | XL | A tool outside the app's bindings is refused; a sandbox escape attempt fails; every call is metered and audited |
| **A3 — Approvals** | Approval records, binding to tool plus argument hash, single use, TTL fails closed, approver roles, queue API and dashboard | M | A `write` tool requiring approval cannot run twice on one decision, and an expired approval refuses |
| **A4 — Agents** | Graph schema and compiler, expression evaluator, node types, durable runs on PostgreSQL, run API with events, cancel and resolve, per-agent permission narrowing, `agents:run` scope | XL | A run survives a restart; a node cannot use a capability the app lacks; limits stop a runaway loop |
| **A5 — Plugins** | gRPC plugin host, manifest and hash pinning, activate and rollback, per-plugin breaker, plugin-published tools and model adapters, .NET plugin SDK | L | A tampered artefact is refused; a failing plugin opens its breaker without taking the gateway down |
| **A6 — Finish** | Dry-run (plan an agent or tool chain without executing), capability templates, SDK and docs, capability snapshot in the audit record | M | A dry run provably executes nothing |

A0+A1 are worth doing on their own: skills are useful immediately and carry no execution risk.
A2 is the real commitment — it is where the gateway starts running other people's code.

## 9. Decisions needed

| # | Question | Recommendation |
| --- | --- | --- |
| D1 | May app owners register agents and skills, or only operators? | App owners for skills and agents scoped to their own apps; operators only for MCP servers and plugins. Enforced by the split IAM actions above. |
| D2 | Skill format | `SKILL.md` with YAML frontmatter (name, description, version) plus optional resource files, so skills written for Claude import unchanged. |
| D3 | When to introduce PostgreSQL | At A4. A1–A3 fit the JSON registry; agent runs do not. |
| D4 | MCP transports allowed outside Development | Container and remote HTTPS only; stdio stays a Development convenience. |
| D5 | Scope model | Add `tools:execute` and `agents:run` rather than widening `invoke`, so existing tokens gain nothing when an app gains capabilities. |
| D6 | Per-app tool rate limits | Start with the shared app quota; add per-binding limits only when a real workload needs them. |

## 10. Non-goals

- A public marketplace or auto-discovery of third-party MCP servers. The catalogue is curated by operators.
- Letting a skill or a tool result change an application's bindings at runtime.
- Multi-tenant capability sharing across applications owned by different teams, until the tenant model from the port plan's P0 exists.
