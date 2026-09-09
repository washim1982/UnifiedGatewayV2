# Simulated Okta Authentication

Local Okta behaviour without an Okta tenant: hard-coded users, AD groups and membership, a real RS256-signed JWT, JWT validation in the gateway, and authorization driven by group membership.

| | |
| :--- | :--- |
| **Tests** | 80 passing (20 new) |
| **Verified** | Live, against the AWS simulator and both accounts |
| **Switch** | `Gateway:Okta:Enabled` — `true` = simulator, `false` = real tenant via OIDC discovery |

---

## 1. The directory

Hard-coded in [`Services/Okta/OktaDirectory.cs`](../Services/Okta/OktaDirectory.cs).

**Users**

| Email | Password | Group |
| :--- | :--- | :--- |
| `wasim.khan@gmail.com` | `Admin@12345` | `UnifiedGateway-Admins` |
| `dev-user@gmail.com` | `Dev@12345` | `UnifiedGateway-Developers` |

Passwords are stored as salted SHA-256, never plaintext, and verified in constant time — an unknown username is compared against a dummy hash so it takes the same time to reject as a wrong password. These are development credentials for a simulated directory, not secrets.

**Groups**

| Group | Purpose |
| :--- | :--- |
| `UnifiedGateway-Admins` | Full administrative control |
| `UnifiedGateway-Developers` | View registered applications and exercise the test API only |

---

## 2. How identity becomes authorization

The gateway never asks *"is this user an admin?"*. It reads the groups Okta asserted, maps them to an IAM role, and lets the policy engine decide per action — the same shape as a real Okta→AWS federation.

```
sign in  ──▶  JWT with groups[]  ──▶  group→role mapping  ──▶  IAM policy evaluation
                                       (appsettings)           (AWS simulator :5001)
```

`Gateway:Okta:GroupRoleMappings`:

```jsonc
"UnifiedGateway-Admins":     "arn:aws:iam::123456789012:role/GatewayPlatformAdminRole",
"UnifiedGateway-Developers": "arn:aws:iam::123456789012:role/GatewayDeveloperRole"
```

A user in no mapped group authenticates but holds no role, so every check denies. Changing what a group may do is an IAM policy edit in [`provision-simulator.py`](../deploy/simulator/provision-simulator.py) — no gateway code changes.

---

## 3. The token

`POST /okta/oauth2/v1/token` with `{username, password}` returns a standard OIDC access token.

**RS256 with a published JWKS**, not a shared secret — so the gateway validates simulated tokens through exactly the same asymmetric path it will use against a real tenant. Endpoints mirror a real Okta org:

| Endpoint | Purpose |
| :--- | :--- |
| `POST /okta/oauth2/v1/token` | Sign in, returns the access token |
| `GET /okta/oauth2/v1/keys` | JWKS (public key only) |
| `GET /okta/oauth2/v1/userinfo` | Claims of the current user |
| `GET /okta/oauth2/v1/directory` | Users, groups, membership, mapped roles |
| `GET /okta/.well-known/openid-configuration` | Discovery document |

Validation pins issuer, audience, lifetime, signing key, and **`ValidAlgorithms = [RS256]`**. That last one matters: without it a token could assert `"alg":"none"` and skip verification entirely.

The signing key is generated per process, so restarting the gateway invalidates outstanding tokens — correct behaviour for a local identity provider.

---

## 4. Two credential shapes, one management plane

A forwarding scheme inspects each request and routes it to the right handler:

- **Bearer token shaped like a JWT** (`eyJ…` with two dots) → Okta validation
- **Anything else** (API key, `ug_sts_` token, `X-Simulator-Role`) → the existing gateway handler

So humans sign in through Okta while automation and break-glass keep working unchanged, and neither handler needs to know about the other.

---

## 5. Verified behaviour

Both accounts, against the running gateway:

| Endpoint | `wasim.khan@` | `dev-user@` |
| :--- | :--- | :--- |
| `GET /api/apps` | 200 | **200** |
| `GET /api/apps/{id}` | 200 | **200** |
| `GET /api/models` | 200 | **200** |
| `POST /api/apps/{id}/test` | 200 | **200** |
| `POST /api/apps` (create) | 201 | 403 |
| `DELETE /api/apps/{id}` | 404¹ | 403 |
| `POST /rotate-key` | 200 | 403 |
| `POST /sts-token` (mint) | 200 | 403 |
| `GET /api/metrics` | 200 | 403 |
| `GET /credentials/status` | 200 | 403 |
| `PUT /guardrails/config` | 200 | 403 |
| `POST /rotate-signing-key` | 200 | 403 |

¹ Authorization passed; the app did not exist.

**Forgery resistance** — every attempt rejected with 401:

```
tampered signature                  401
alg:none with escalated groups      401
group escalated, signature reused   401
gibberish bearer                    401
no credential                       401
```

---

## 6. The dashboard

Sign-in gates the whole console: nothing is fetched until there is a session, so an unauthenticated visitor sees the form rather than a wall of failed requests.

**dev-user sees** — Applications and API Generator & Test tabs; app cards with only a Test API button.
**admin sees** — all five tabs, New Application, and Mint STS / Delete on every card.

Hiding controls is presentation only. The gateway evaluates every request against IAM regardless of what the page renders, which is why the table above was measured at the API, not in the browser.

The token lives in `sessionStorage` for the tab, not `localStorage` — it does not outlive the browser session.

---

## 7. Moving to a real Okta tenant

Configuration only. In `appsettings.Production.json`:

```jsonc
"Okta": {
  "Enabled": false,
  "Issuer": "https://<your-tenant>.okta.com/oauth2/default",
  "MetadataAddress": "https://<your-tenant>.okta.com/oauth2/default/.well-known/openid-configuration",
  "GroupRoleMappings": { /* same group names, prod role ARNs */ }
}
```

With `Enabled: false` the simulator endpoints are not mapped and keys come from the tenant's JWKS via OIDC discovery, with rotation handled by the middleware. Validation and group-to-role mapping code is untouched.

On the Okta side: create the two groups, add a `groups` claim to the authorization server, and set the audience to `unified-gateway`.

---

## 8. Known gaps

- **Password grant, not authorization code.** Real Okta would redirect through a hosted login page with PKCE. The password grant keeps the local loop to one call; it is not a pattern to carry into production, and the real-tenant path should use the authorization-code flow.
- **First matching group wins.** A user in both groups gets whichever appears first in their token. Fine for two disjoint groups; a real deployment with overlapping membership needs a precedence rule.
- **No refresh tokens.** A session lasts until the token expires (60 minutes) or the gateway restarts.
- **The `alg:none` and escalation tests were run by hand**, not committed as automated tests. The unit tests cover directory, issuance, claims, JWKS hygiene and mapping; the forgery cases would be worth adding as integration tests.

---

## 9. A CSP correction

Adding the Okta layer surfaced a mistake in the earlier hardening work: the CSP in `Program.cs` was written on the claim that "the dashboard loads no third-party assets". It does — Inter and JetBrains Mono from Google Fonts — and the strict policy silently blocked them.

The policy now names `fonts.googleapis.com` and `fonts.gstatic.com` explicitly rather than being loosened wholesale. `script-src` stays `'self'` with no `'unsafe-inline'`, which is the directive that actually contains an injected script. Self-hosting those two font files would let both directives drop back to `'self'`.
