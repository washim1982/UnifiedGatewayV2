# Dev Environment — .NET AWS Simulator

Development runs against [`DOTNET_AWS_SIMULATOR`](../../../workspace/Projects/DOTNET_AWS_SIMULATOR). Test and Production run against real AWS. The binary is identical; only `Gateway:Cloud` differs.

| | |
| :--- | :--- |
| **Tests** | 113 passing (4 new) |
| **Verified** | Live, against S3Local / KmsLocal / IamLocal |

---

## 1. The switch

```jsonc
"Gateway": { "Cloud": { "Provider": "LocalDotNet" } }   // Development
"Gateway": { "Cloud": { "Provider": "Aws" } }           // Test, Production
```

| Environment | Provider | Backing services |
| :--- | :--- | :--- |
| Development | `LocalDotNet` | S3Local `:5001`, KmsLocal `:5002`, IamLocal `:5003` |
| Test | `Aws` | KMS, Secrets Manager, IAM, Bedrock |
| Production | `Aws` | KMS, Secrets Manager, IAM, Bedrock |

Going to real AWS is: flip `Provider` to `Aws`, drop the `LocalDotNet` block, point `Crypto.KeyId` at a real alias. No code changes — `StartupValidator` refuses `LocalDotNet` anywhere but Development, so the switch cannot be forgotten.

---

## 2. How the seams map

Your simulator already had the right idea — `IObjectStoreClient` / `IKmsClient` / `IAuthClient` behind one flag. The gateway has its own equivalent seam, so the two line up:

| Gateway seam | Development | Test / Production |
| :--- | :--- | :--- |
| `ICryptoProvider` | KmsLocal `/encrypt`, `/decrypt` | KMS |
| `ISecretsProvider` | KMS-encrypted objects in S3Local | Secrets Manager |
| `IAccessControlProvider` | `policies` claim from IamLocal, evaluated locally | IAM policy documents |
| `IIdentityProvider` | IamLocal `/get-caller-identity` | Upstream-asserted principal |
| Bedrock | *(not simulated — see §5)* | Bedrock Runtime |

**Secrets** were the one missing piece: the .NET simulator has no Secrets Manager equivalent. Rather than store them in the clear, the gateway uses the S3 + KMS envelope pattern — the value is encrypted through `ICryptoProvider` before it is written, so the object at rest is ciphertext even in dev. Verified: reading `s3://gateway-secrets/gateway/dev/admin-api-key` directly returns base64 ciphertext, not the `ug_live_…` key.

**Authorization** reads the policy documents IamLocal puts in the JWT's `policies` claim and evaluates them with AWS semantics — explicit Deny wins, then Allow, otherwise implicit Deny. That is the same evaluation `AwsAccessControlProvider` performs in production, so a policy behaves identically in both places.

---

## 3. Running it

```bash
# 1. Start the simulator (from DOTNET_AWS_SIMULATOR)
./run-simulator.ps1

# 2. Seed the gateway's IAM roles — see §4 for why this matters
python deploy/dotnet-simulator/provision-dotnet-simulator.py

# 3. Start the gateway
ASPNETCORE_ENVIRONMENT=Development dotnet run --no-launch-profile
```

On start the gateway probes each URL and confirms it is the service it expects:

```
Cloud provider mode: LocalDotNet. Verifying key management availability.
Local .NET AWS simulator verified: S3Local, KmsLocal and IamLocal all responding as expected.
STS signing key ready at generation 1, sourced from '/gateway/dev/sts-signing-key'.
```

---

## 4. Two things found while integrating

### The two simulators collide on ports 5001–5003

| Port | Python/Docker simulator | .NET simulator |
| :--- | :--- | :--- |
| 5001 | IAM | **S3** |
| 5002 | S3 | **KMS** |
| 5003 | KMS | **IAM** |

Same ports, different services on each. Only one stack can run at a time, and with the wrong one up the calls still connect and return plausible HTTP — the failure surfaces much later as a confusing 404 or decrypt error.

The gateway now checks service identity at startup (`/health` reports `{"service":"IamLocal"}` vs `{"service":"iam-service"}`) and names exactly what it found:

> `IamLocal is not answering at http://localhost:5003: expected 'IamLocal' but found 'kms-service'. The .NET simulator and the Docker simulator both use ports 5001-5003 with different services on each; stop one before starting the other, or give them distinct ports.`

**Worth fixing properly**: move the .NET simulator to 5101–5103 in `run-simulator.ps1`, and the two can run side by side. The gateway needs only a config change to follow.

### Every role was a full administrator

`IamLocal`'s `/assume-role` auto-creates any unknown role with `Allow */*`. Convenient for a developer loop, but it meant the gateway's role separation was never exercised in dev — `dev-user@gmail.com` was getting `200` on billing and app creation, where production would deny.

`provision-dotnet-simulator.py` seeds the four gateway roles with real scoped policies, writing directly to `src/IamLocal/Data/iam.db` because IamLocal exposes no role-management endpoint. After seeding:

| Endpoint | `wasim.khan@` (Admins) | `dev-user@` (Developers) |
| :--- | :--- | :--- |
| `GET /api/apps` | 200 | 200 |
| `GET /api/models` | 200 | 200 |
| `POST /api/apps` | 201 | **403** |
| `GET /api/metrics` | 200 | **403** |
| `GET /api/billing/summary` | 200 | **403** |
| `PUT /api/guardrails/config` | 200 | **403** |

Which now matches the production matrix exactly.

**A `POST /roles` endpoint on IamLocal** would remove the need to write SQLite from outside. It is a small addition to your project and would make the provisioner a plain HTTP client, like the Python one.

---

## 5. Gaps to be aware of

- **No Bedrock.** The .NET simulator does not emulate Bedrock, so `BedrockServiceUrl` is empty in Development and applications should route through the `local` provider (Ollama) instead. Cloud-model paths are therefore not exercised in dev. The Python simulator does emulate Bedrock if you need that specific coverage.
- **Dev keys are dev keys.** KmsLocal protects its master key with DPAPI or a dev key file. Fine locally, meaningless as a security control.
- **Test now needs real AWS.** Test was previously pointed at the Python simulator; it is now `Aws`, so running the Test environment locally requires credentials, or flipping `Provider` back for a local run.
- **The Python simulator integration is still in the codebase** (`Provider: "Simulator"`, `Services/Cloud/Simulator/`). No shipped configuration uses it any more. It can be deleted if that project is retired.

---

## 6. Review notes on the simulator itself

Genuinely good: the interface-first design, the single `LocalAws:Enabled` switch, RSA-signed JWTs with a JWKS endpoint, AES-GCM with real tamper detection, and a `PolicyEvaluator` that gets explicit-Deny precedence right.

Two things worth attention:

1. **`run-simulator.ps1` starts services with `Start-Process ... -NoNewWindow` and stops them by process name.** `Stop-Process -Name IamLocal,KmsLocal,S3Local` will not match, because the running process is `dotnet`, not the project name. The `$processes` fallback catches the launcher, but a `dotnet run` host process can outlive it — I saw orphaned listeners holding ports after a stop. Launching the built DLLs, or tracking child PIDs, would make shutdown reliable.

2. **The `IRolesAnywhereService` DI lifetime.** I hit `Cannot consume scoped service 'IRoleStore' from singleton 'IRolesAnywhereService'` on a stale build; the current source already registers it `Scoped`, so this appears fixed. Flagging it only because a stale `bin/` will reproduce it — worth a clean rebuild to confirm.
