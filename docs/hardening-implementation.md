# Gateway Hardening — Implementation

Implements the Phase 0–2 findings from [`gateway-hardening-review.md`](gateway-hardening-review.md) against the local **AWS Simulator** (`C:\Users\wasim\workspace\Projects\AWS-SIMULATOR`), with a provider seam so TEST and PROD run the **same binary** and differ only in configuration.

> **Later changes.** This page records the Phase 0–2 work as delivered. Four gaps found afterwards have since been fixed — SL-01 to SL-04 in [`security-architecture-flow.md`](security-architecture-flow.md):
> - AWS-mode identity is verified by STS rather than asserted.
> - Both simulators and the Okta simulator are Development-only.
> - TLS is enforced by an HTTPS-only IIS binding, with API calls over HTTP refused.
> - Break-glass tokens are scoped, attributed to a configured principal, and audited.
>
> Where this page described the earlier behaviour it has been updated, and says so.

| | |
| :--- | :--- |
| **Tests** | 62 passing at delivery (was 40); 263 today |
| **Verified against** | Live simulator — IAM `:5001`, KMS `:5003`, Bedrock `:5004` |
| **Environments** | `Development` → simulators · `Test` / `Production` → real AWS (the simulators accept a role name as identity, so they are refused outside Development — see SL-01 and SL-03 in [`security-architecture-flow.md`](security-architecture-flow.md)) |

---

## 1. The environment switch

One setting decides which implementation every cloud-facing dependency resolves to:

```jsonc
"Gateway": { "Cloud": { "Provider": "Simulator" } }   // or "Aws"
```

`Program.cs` binds the family at startup. Nothing above this layer knows which is in use.

| Seam | Interface | Simulator | Real AWS |
| :--- | :--- | :--- | :--- |
| Secrets | `ISecretsProvider` | KMS service `/secrets` | Secrets Manager |
| Crypto | `ICryptoProvider` | KMS service `/encrypt`, `/decrypt` | KMS |
| Authorization | `IAccessControlProvider` | IAM service `/evaluate-policy` | IAM policy documents |
| Identity | `IIdentityProvider` | IAM STS sessions / role names (Development only) | Caller-signed `sts:GetCallerIdentity`, verified by STS (SL-01) |
| Bedrock | `AmazonBedrockRuntimeConfig` | `ServiceURL` → `:5004` | Regional endpoint |

**Bedrock needs no adapter at all.** The simulator implements the real wire contract (`POST /model/{modelId}/invoke`, `x-amzn-bedrock-*` response headers), so the AWS SDK talks to it directly — the only difference is `ServiceURL` and placeholder credentials. That is the ideal case; the other three need adapters because the simulator exposes plain REST rather than the AWS JSON-1.1 `X-Amz-Target` protocol.

### What actually differs between Test and Prod

**No application code.** In configuration, `Gateway:Cloud` carries the provider binding. Other blocks (`Aws` region/role, `LocalProviders` hostnames, `Storage` paths, `Security` rate limits and HTTPS) differ per environment the way any deployment config does.

---

## 2. Findings closed

### Critical

| ID | Finding | How it is closed |
| :--- | :--- | :--- |
| **C1** | Management plane unauthenticated | `RequireAuthorization` on the whole `/api` group in `DashboardEndpoints.cs:35`, so new endpoints inherit it. `GatewayAuthenticationHandler` establishes identity; `IamAuthorizationHandler` asks the policy engine per action. |
| **C2** | Anonymous STS minting | `MintStsToken` now requires the `gateway:MintStsToken` IAM action. |
| **C3** | Anonymous Bedrock spend | `/api/apps` and `/api/apps/{id}/test` require IAM actions and carry the `management` rate-limit policy. |
| **C4** | Anonymous guardrail disable | `gateway:UpdateGuardrailConfig` required; the before/after values are written to the audit trail *before* the change is applied. |
| **C5** | Stored XSS → admin key | Four unescaped sinks fixed (`app.js:367, 490, 741`); inline `onclick` replaced with delegated handlers reading `dataset`; `appId` restricted to `[a-z0-9-]`; admin credential moved from `localStorage` to `sessionStorage`; strict CSP added. |

### High

| ID | Finding | How it is closed |
| :--- | :--- | :--- |
| **H1** | Default admin key, no boot guard | `StartupValidator` refuses to start on a known default key, a config-sourced key outside Development, `EnforceAppApiKey: false`, wildcard CORS, or plaintext HTTP. Key now lives in the secret store. |
| **H2** | Wildcard CORS | The `AllowAnyOrigin` branch is gone. An empty allow-list means no cross-origin access. |
| **H3** | No TLS enforcement | `UseHsts` + `UseHttpsRedirection`, gated on `Security:RequireHttps`. *Tightened since (SL-03):* only Development is exempt, because Test is a network host; the IIS installer creates an HTTPS-only binding; API calls over plain HTTP are refused with `403 HTTPS_REQUIRED` rather than redirected. |
| **H4** | STS tokens unrevocable | Tokens carry a signing-key **generation**; `POST /api/credentials/rotate-signing-key` mints a new generation and every earlier token stops validating. Plus a `jti` denylist for targeted revocation. Default TTL cut from 1 h to 15 min, ceiling from 7 days to 1 h. *Since (SL-04):* admin tokens are capped at 15 minutes and need the `admin` scope on `/api`. |
| **H5** | Rate limiting gaps | A global limiter as the floor, plus named policies: `per-app`, `token-issuance` (tight — it is the brute-force oracle), `management`. |
| **H6** | Guardrail ReDoS | 250 ms `matchTimeoutMilliseconds` on all 14 patterns and the inline `Regex.Replace`. A timeout is reported as a `ScanTimeout` violation, so the guardrail **fails closed**. |
| **H7** | Key ring forges admin tokens | DataProtection removed. Tokens are HMAC-SHA256 signed with a key held in the KMS-encrypted secret store, fetched and cached at runtime. The stale local key ring was deleted. |

### Medium

`M1` actor attribution (`Actor`, `AuthType`, `TokenId`, `SourceIp`, `TraceId` on log entries, plus a `ManagementAuditEntry` for every privileged action) · `M2` correct status codes (422/413/409/502/504 instead of blanket 200) · `M3` info-disclosure endpoints authorized; `/gateway/health` reduced to bare liveness · `M4` master key no longer authenticates as any application · `M5` atomic `File.Replace` writes and no reseeding over an unparseable registry · `M7` Swagger in Development only · `M8` CSP and security headers · `M9` `AllowedHosts` scoped · `L2` `appId` charset.

Also fixed in passing: `GuardrailActionMode` now crosses the API as a string (`"Redact"`), matching how it is written in appsettings — previously the API emitted `0` and rejected the value an operator would copy from the config file.

---

## 3. Verified against the running simulator

```
C1  GET  /api/apps                      -> 401     C1  GET /api/metrics             -> 401
C2  POST /api/apps/{id}/sts-token        -> 401     C3  POST /api/apps               -> 401
C4  PUT  /api/guardrails/config          -> 401     C3  POST /api/apps/{id}/test     -> 401

IAM policy evaluation (simulator :5001)
  GatewayAuditorRole       GET /apps 200 · POST /apps 403 · PUT /guardrails 403
  GatewayAppOwnerRole      POST /apps 201 · PUT /guardrails 403 · rotate-signing-key 403
  GatewayPlatformAdminRole GET /apps 200 · PUT /guardrails 200

H4  token valid -> rotate signing key (gen 1 -> 2) -> same token now invalid
H5  34 requests to /gateway/sts/token: 30 x 401, 4 x 429
M2  injection prompt in Block mode -> 422
M8  CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy all present
H7  /gateway/test/sts-signing-key and /gateway/test/admin-api-key stored KMS-encrypted
```

The H5 run replayed a single key. A caller who presents a different string on every request gets a fresh rate-limit bucket each time, so this limit does not yet bind unauthenticated traffic — SL-05, still open.

---

## 4. Running it

**Development against the Python simulator.** The simulator accepts a bare role name as an identity, which proves nothing, so it is refused outside Development (SL-01 and SL-03 in [`security-architecture-flow.md`](security-architecture-flow.md)). Test now runs against real AWS like Production.

```bash
python deploy/simulator/provision-simulator.py
ASPNETCORE_ENVIRONMENT=Development Gateway__Cloud__Provider=Simulator dotnet run --no-launch-profile
```

`provision-simulator.py` creates the IAM roles and policies the gateway authorizes against, and a KMS key. It is the Development equivalent of the Terraform that creates the same resources in AWS. The gateway bootstraps its own signing key and admin credential into the secret store on first start.

Call the management API as a role (Development only — in AWS mode a role name or ARN is refused, and automation signs a GetCallerIdentity request instead; see [`aws-iam-authentication.md`](aws-iam-authentication.md)):

```bash
curl -H "X-API-Key: GatewayPlatformAdminRole" http://localhost:5080/api/apps
```

**PROD** — flip `Gateway:Cloud:Provider` to `Aws`, clear `BedrockServiceUrl`, point `Crypto:KeyId` at a real KMS alias, and create the AWS-side resources:

| Resource | Purpose |
| :--- | :--- |
| KMS key `alias/unified-gateway-prod` | Encrypts the secrets below |
| Secret `/gateway/prod/sts-signing-key` | Token signing key (gateway bootstraps it) |
| Secret `/gateway/prod/admin-api-key` | Break-glass credential |
| Secret `/gateway/prod/access-policy` | IAM policy document the management plane is evaluated against |
| IAM roles | `GatewayPlatformAdminRole`, `GatewayAppOwnerRole`, `GatewayAuditorRole` |
| IAM role `GatewayBreakGlassRole` | The principal break-glass acts as. Set it as `Gateway:Cloud:AccessControl:BreakGlassPrincipalArn`, grant it in the access policy, and alert on its use |
| Okta tenant | Issuer, metadata URL and group-to-role ARNs substituted into `Gateway:Okta` |
| Server certificate | In `Cert:\LocalMachine\My`, passed to `deploy/iis/install.ps1 -CertificateThumbprint` for the HTTPS-only binding |

The shipped Test and Production files carry `<placeholders>` for the account-specific values above; startup refuses until they are substituted.

The execution role needs `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`, `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:CreateSecret`, and the existing `bedrock:InvokeModel`.

---

## 5. What is not done

Honest gaps, so nothing here reads as more finished than it is.

- **The AWS provider path is written but unverified.** `AwsSecretsManagerProvider`, `AwsKmsCryptoProvider`, `AwsAccessControlProvider` and `AwsIdentityProvider` (now the STS relay from SL-01) compile and follow the same contracts the simulator implementations were tested against, but no real AWS account was available here. Exercise them in a staging account before relying on them.
- ~~**`AwsIdentityProvider` trusts an upstream-asserted principal ARN.**~~ **Resolved (SL-01).** It trusted any `arn:aws:` string a client sent, and the IIS deployment had no upstream to verify it. It now relays a caller's SigV4-signed `sts:GetCallerIdentity` request to STS and trusts only the ARN STS returns — see [`aws-iam-authentication.md`](aws-iam-authentication.md).
- **Generation-based revocation is what actually fires**, not the `jti` check, when the signing key rotates: a new key changes the HMAC, so verification fails before the generation comparison is reached. The generation claim still matters for diagnostics and for a future multi-key overlap window. The `jti` denylist is in-memory only, so it is per-node; the generation lever is the fleet-wide one.
- **Phases 3–5 are partly done since.** Okta OIDC operator sign-in and CI scanning (`NuGetAudit`, CodeQL, gitleaks) have landed. Still open: a durable SQL registry, SIEM export and per-app token budgets.
- **`BedrockGuardrails` is still dead config.** `GuardrailIdentifier` is read by nothing (`Models/GuardrailOptions.cs:35`).

---

## 6. A note on the simulator itself

One issue worth fixing in the simulator, found while integrating:

`gateway-service/app/auth.py:84` matches a presented token with `token in s.get("AccessKeyId")` — a substring test. A short string that happens to be a substring of any active access key authenticates as that session. `SimulatorIdentityProvider` in this gateway deliberately uses an exact `Ordinal` comparison instead and does not copy the behaviour.
