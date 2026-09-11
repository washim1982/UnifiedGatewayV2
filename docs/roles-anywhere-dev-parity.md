# Roles Anywhere: simulator review, and making Development imitate Test/Prod

> **Status: implemented.** Everything proposed in Part 2 has been built and verified. The
> simulator changes are on the `feat/aws-compatible-roles-anywhere` branch of
> `DOTNET_AWS_SIMULATOR`; the gateway side is in this repository. `UseSimulatorProtocol` has
> been deleted — there is now one protocol everywhere. Findings S1–S7 and S11 are closed;
> S8–S10 remain open and are listed at the end.
>
> Verified live: the gateway's production signer is accepted by the simulator's independently
> written verifier, and each authorization failure below was reproduced and reported by name.
> Simulator 50/50 tests, gateway 195/195.

Two parts. **Part 1** reviews the IAM Roles Anywhere implementation in
`DOTNET_AWS_SIMULATOR` as it stood before this work. **Part 2** is the setup that makes
Development exercise the same gateway code path Test and Production use.

The short version: the simulator's Roles Anywhere was a well-built *demonstration* of
certificate-based authentication, but it spoke a protocol of its own invention. A client that
worked against it had proven nothing about whether it would work against AWS. Closing that gap
was the only way to test the production credential path without a real AWS account, and it is
now closed.

---

# Part 1 — Review

## 1.1 What it gets right

These are real, not stubs, and they are the hard parts:

- **Genuine X.509 chain validation** against a custom trust store
  (`X509ChainTrustMode.CustomRootTrust` with the anchor CA in `CustomTrustStore`). Not a
  thumbprint comparison pretending to be a chain check.
- **Genuine RSA signature verification** (`VerifyData`, SHA-256, PKCS#1 v1.5).
- **Properly formed certificates** — `CreateRootCa` sets `BasicConstraints(CA=true, critical)`,
  `KeyUsage(KeyCertSign|CrlSign, critical)` and a SubjectKeyIdentifier; client certs get the
  Client Authentication EKU (`1.3.6.1.5.5.7.3.2`) and a random 16-byte serial.
- **A stable trust anchor.** The CA is persisted to `.keys/roles_anywhere_ca.pfx`, so restarting
  the simulator does not invalidate certificates already issued.
- **Session credentials that actually carry authorization** — an RSA-signed JWT with the role's
  policy documents in a `policies` claim, verifiable through the JWKS endpoint. The downstream
  S3/KMS services can make real allow/deny decisions from it.
- **Sensible failure distinctions** — signature failure → 401, unknown role → 404, malformed →
  400. And unlike the `assume-role` path, `create-session` does *not* auto-create a missing role.
- **Duration clamped** to 900–43200 seconds.

## 1.2 Findings

| # | Severity | Finding |
| :--- | :--- | :--- |
| S1 | **High** | The wire protocol is not AWS's. Working here implies nothing about production. |
| S2 | **High** | Expired and not-yet-valid client certificates are accepted. *(verified)* |
| S3 | **High** | The signed payload is chosen by the client and bound to nothing — signatures replay forever. |
| S4 | Medium | `ProfileArn` and `TrustAnchorArn` are accepted and ignored; any role in the store can be obtained. |
| S5 | Medium | No role trust policy exists, so the most common real-world 403 cannot be reproduced. |
| S6 | Medium | `RolesAnywhereService` is `Scoped` but loads (or creates) the CA from disk in its constructor. |
| S7 | Low | No intermediate chain support. |
| S8 | Low | `AccessKeyId` / `SecretAccessKey` are random and unused; SigV4 is never exercised. |
| S9 | Low | Response shape differs from AWS. |
| S10 | Low | Hard-coded CA passphrase; no way to import an existing enterprise CA. |
| S11 | Low | The Client Authentication EKU is issued but never checked on the way back in. |

---

### S1 — The protocol is not AWS's *(High)*

This is the finding that matters most, because it silently defeats the purpose of having a
simulator for this feature.

| | Simulator | Real AWS |
| :--- | :--- | :--- |
| Endpoint | `POST /rolesanywhere/create-session` | `POST /sessions` |
| Certificate sent as | `CertPem` field, PEM text | `X-Amz-X509` header, base64 DER |
| Signature sent as | `SignatureBase64` field, detached | `Authorization` header, hex, inside a SigV4 credential |
| What is signed | `PayloadToVerify` — a free-form client string | The SigV4 string-to-sign, over the canonical request |
| Signature covers the body? | **No** | **Yes** (payload hash in the canonical request) |
| Signature covers a timestamp? | **No** | **Yes** (`X-Amz-Date`, enforced window) |
| Credential scope | *(none)* | `<cert-serial-decimal>/<date>/<region>/rolesanywhere/aws4_request` |
| Response | `{ credentials: {...} }` | `{ credentialSet: [ { credentials, assumedRoleUser } ], subjectArn }` |

A client written against the left column cannot talk to the right column, and vice versa. The
gateway carried a `UseSimulatorProtocol` flag to bridge this, which meant **the production
signing code was never executed in Development** — precisely the code most worth testing,
because every mistake in it returns the same opaque 403. That flag is now gone.

### S2 — Expired certificates are accepted *(High, verified)*

`RolesAnywhereService.cs` around line 155:

```csharp
bool chainValid = chain.Build(clientCert);          // assigned...
bool isAnchorTrusted = chain.ChainElements.Cast<X509ChainElement>()
    .Any(e => e.Certificate.Thumbprint.Equals(_trustAnchorCa.Thumbprint, ...));

if (!isAnchorTrusted) { return (false, "...", null); }   // ...never read
```

`chainValid` is never used. `chain.Build()` returns `false` for an expired certificate but
still populates `ChainElements` with the path it constructed — including the anchor — so
`isAnchorTrusted` stays `true` and the session is issued.

Verified by replicating the exact check against certificates issued from a matching CA:

```
valid client cert            chain.Build()=True  anchorInChain=True  => simulator ACCEPTS
EXPIRED client cert          chain.Build()=False anchorInChain=True  => simulator ACCEPTS
not-yet-valid client cert    chain.Build()=False anchorInChain=True  => simulator ACCEPTS
```

Certificate expiry is the single most likely way a real Roles Anywhere deployment fails, and it
fails everywhere at once. A local environment that accepts expired certificates cannot rehearse
it — and worse, teaches the opposite lesson.

**Fix:** check `chainValid` as well, and report `chain.ChainStatus` so the reason is legible:

```csharp
if (!chainValid || !isAnchorTrusted)
{
    var reasons = string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()));
    return (false, $"Certificate validation failed: {reasons}", null);
}
```

### S3 — The signature is bound to nothing *(High)*

`PayloadToVerify` is whatever the client sends. The server verifies that the signature matches
*that string*, then ignores the string entirely. Consequences:

- A captured `(PayloadToVerify, SignatureBase64, CertPem)` triple is valid **forever**. There is
  no timestamp, no nonce, no expiry.
- The signature does not cover `RoleArn`. An intercepted request for `read-only-role` can be
  replayed asking for `admin-role`, and it verifies.

AWS avoids both: the string-to-sign includes `X-Amz-Date` (rejected outside a window) and the
SHA-256 of the request body, which is where `roleArn` lives.

### S4 — Profile and trust anchor are decorative *(Medium)*

`CreateSessionAsync` accepts `ProfileArn` and `TrustAnchorArn` and never reads them. The
profile is what constrains which roles a certificate may assume — and the simulator's own
profile lists only `dev-role` and `admin-role`, yet a session for `read-only-role` is issued
without complaint. In AWS that is a 403.

### S5 — No role trust policy *(Medium)*

In AWS the role must itself trust the service:

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "rolesanywhere.amazonaws.com" },
  "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
  "Condition": { "ArnEquals": { "aws:SourceArn": "<trust-anchor-arn>" } }
}
```

Omitting `sts:TagSession` or `sts:SetSourceIdentity` is *the* classic Roles Anywhere failure —
`sts:AssumeRole` alone is not enough, and the resulting 403 says nothing useful. The simulator
has no notion of a trust policy, so the failure mode teams most often hit in production cannot
be reproduced or tested locally.

### S6 — The CA is loaded from disk on every request *(Medium)*

`IRolesAnywhereService` is registered `Scoped`, and the constructor does `File.Exists` →
`new X509Certificate2(...)` → possibly `CreateRootCa()` + `File.WriteAllBytes`. That is file
and crypto work per HTTP request, and on a cold start two concurrent requests can both decide
the CA is missing, generate different CAs, and race on the write — after which certificates
issued seconds earlier no longer chain.

**Fix:** make the trust anchor a singleton (`AddSingleton<ITrustAnchorProvider, …>`) and keep
`IRolesAnywhereService` scoped for its `IRoleStore` dependency.

### S7–S11 — Smaller items

- **S7** Single-level CA only; no `X-Amz-X509-Chain`. Enterprise PKIs are almost always
  root → intermediate → leaf, and the intermediate has to be presented.
- **S8** `AccessKeyId` and `SecretAccessKey` are random hex that nothing verifies; only the JWT
  session token is honoured downstream. Fine for the simulator's own services, but it means no
  part of the SigV4 request-signing path is exercised.
- **S9** The response is `{ credentials }` rather than AWS's `{ credentialSet: [...], subjectArn }`.
- **S10** The CA passphrase `dev-ca-password` is hard-coded, and there is no way to import an
  existing CA — so the simulator cannot be pointed at the organisation's real dev PKI.
- **S11** Client certificates are issued with the Client Authentication EKU, but nothing checks
  it on presentation. AWS requires it.

---

# Part 2 — Making Development imitate Test/Prod

## 2.1 What "imitate" has to mean

Not "something that returns credentials". The useful property is:

> **The gateway executes the same code, byte for byte, in Development as in Production.**
> Only the endpoint URL differs.

That is already how the rest of this system works — one binary, `Gateway:Cloud:Provider`
selects the backing service, and no code path is environment-specific. Roles Anywhere was
the exception, because of the `UseSimulatorProtocol` flag. It no longer is.

Achieving it needs one change on each side:

| Side | Change |
| :--- | :--- |
| Simulator | Add an AWS-wire-compatible `POST /sessions` endpoint. |
| Gateway | Set `EndpointOverride` to the simulator, and **remove** `UseSimulatorProtocol`. |

The existing `/rolesanywhere/create-session` endpoint can stay for the dashboard's demo flow —
this is an addition, not a rewrite.

## 2.2 Target shape

```
Development                                   Test / Production
-----------                                   -----------------
gateway  --AWS4-X509-RSA-SHA256-->  IamLocal   gateway  --AWS4-X509-RSA-SHA256-->  AWS
         POST /sessions             :5003               POST /sessions            rolesanywhere.<region>
                                                                                   .amazonaws.com

same signer, same headers, same request body, same response parsing
only Gateway:Aws:RolesAnywhere:EndpointOverride differs
```

## 2.3 Simulator: the verifier

Add `src/IamLocal/Services/AwsSigV4X509Verifier.cs`. This is the server-side mirror of the
gateway's `RolesAnywhereSigner` — it reconstructs the canonical request from the request that
actually arrived and checks the signature against the presented certificate's public key.

```csharp
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IamLocal.Services;

public sealed record VerifiedCaller(X509Certificate2 Certificate, List<X509Certificate2> Chain);

public static class AwsSigV4X509Verifier
{
    public const string RsaAlgorithm   = "AWS4-X509-RSA-SHA256";
    public const string EcdsaAlgorithm = "AWS4-X509-ECDSA-SHA256";

    // AWS rejects requests outside a five-minute window; without this, a captured signature
    // replays forever (finding S3).
    private static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(5);

    public static (bool Ok, string? Error, VerifiedCaller? Caller) Verify(
        HttpRequest request, string body, string region)
    {
        var authorization = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization))
            return (false, "Missing Authorization header.", null);

        var algorithm = authorization.Split(' ')[0];
        if (algorithm is not (RsaAlgorithm or EcdsaAlgorithm))
            return (false, $"Unsupported signing algorithm '{algorithm}'.", null);

        var credential    = Extract(authorization, "Credential=");
        var signedHeaders = Extract(authorization, "SignedHeaders=");
        var signatureHex  = Extract(authorization, "Signature=");

        if (credential is null || signedHeaders is null || signatureHex is null)
            return (false, "Malformed Authorization header.", null);

        // --- certificate -------------------------------------------------------------
        var x509Header = request.Headers["X-Amz-X509"].ToString();
        if (string.IsNullOrWhiteSpace(x509Header))
            return (false, "Missing X-Amz-X509 header.", null);

        X509Certificate2 certificate;
        try { certificate = new X509Certificate2(Convert.FromBase64String(x509Header)); }
        catch (Exception ex) { return (false, $"X-Amz-X509 is not a valid certificate: {ex.Message}", null); }

        var chain = new List<X509Certificate2>();
        var chainHeader = request.Headers["X-Amz-X509-Chain"].ToString();
        if (!string.IsNullOrWhiteSpace(chainHeader))
        {
            foreach (var entry in chainHeader.Split(',', StringSplitOptions.RemoveEmptyEntries))
                chain.Add(new X509Certificate2(Convert.FromBase64String(entry.Trim())));
        }

        // --- credential scope --------------------------------------------------------
        // Serial number in DECIMAL, not hex. This is where an access key id sits in
        // ordinary SigV4.
        var scopeParts = credential.Split('/');
        if (scopeParts.Length != 5)
            return (false, "Credential scope must have five segments.", null);

        var expectedSerial = BigInteger.Parse("0" + certificate.SerialNumber,
            NumberStyles.HexNumber, CultureInfo.InvariantCulture).ToString();

        if (scopeParts[0] != expectedSerial)
            return (false, "Credential scope serial does not match the presented certificate.", null);
        if (scopeParts[2] != region)
            return (false, $"Credential scope region '{scopeParts[2]}' does not match '{region}'.", null);
        if (scopeParts[3] != "rolesanywhere" || scopeParts[4] != "aws4_request")
            return (false, "Credential scope service or terminator is wrong.", null);

        // --- timestamp ---------------------------------------------------------------
        var amzDate = request.Headers["X-Amz-Date"].ToString();
        if (!DateTimeOffset.TryParseExact(amzDate, "yyyyMMdd'T'HHmmss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var signedAt))
            return (false, "X-Amz-Date is missing or malformed.", null);

        if ((DateTimeOffset.UtcNow - signedAt).Duration() > MaxSkew)
            return (false, "X-Amz-Date is outside the permitted five-minute window.", null);

        if (scopeParts[1] != signedAt.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture))
            return (false, "Credential scope date does not match X-Amz-Date.", null);

        // --- canonical request -------------------------------------------------------
        var canonicalHeaders = new StringBuilder();
        foreach (var name in signedHeaders.Split(';'))
        {
            var value = name == "host"
                ? request.Host.Value                       // includes the port when non-default
                : request.Headers[name].ToString();

            canonicalHeaders.Append(name).Append(':').Append(value.Trim()).Append('\n');
        }

        var canonicalRequest = string.Join("\n",
            request.Method,
            request.Path.Value,
            request.QueryString.HasValue ? request.QueryString.Value!.TrimStart('?') : string.Empty,
            canonicalHeaders.ToString(),
            signedHeaders,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(body))));

        var stringToSign = string.Join("\n",
            algorithm,
            amzDate,
            credential,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));

        // --- signature ---------------------------------------------------------------
        // No derived signing key: the certificate's private key signed this directly.
        var payload = Encoding.UTF8.GetBytes(stringToSign);
        byte[] signature;
        try { signature = Convert.FromHexString(signatureHex); }
        catch { return (false, "Signature is not valid hex.", null); }

        bool verified;
        if (algorithm == RsaAlgorithm)
        {
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa is null) return (false, "Certificate carries no RSA public key.", null);
            verified = rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            using var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is null) return (false, "Certificate carries no ECDSA public key.", null);
            verified = ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }

        if (!verified)
            return (false, "Signature verification failed.", null);

        // --- EKU (finding S11) -------------------------------------------------------
        var hasClientAuth = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>())
            .Any(o => o.Value == "1.3.6.1.5.5.7.3.2");

        if (!hasClientAuth)
            return (false, "Certificate lacks the Client Authentication EKU (1.3.6.1.5.5.7.3.2).", null);

        return (true, null, new VerifiedCaller(certificate, chain));
    }

    private static string? Extract(string authorization, string key)
    {
        var start = authorization.IndexOf(key, StringComparison.Ordinal);
        if (start < 0) return null;

        start += key.Length;
        var end = authorization.IndexOf(',', start);
        return (end < 0 ? authorization[start..] : authorization[start..end]).Trim();
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
```

### Reading the body twice

The signature covers the raw body, so it must be read as text *before* model binding and used
verbatim — re-serialising a deserialised object will not reproduce the same bytes.

```csharp
app.MapPost("/sessions", async (HttpContext ctx, IRolesAnywhereService svc) =>
{
    ctx.Request.EnableBuffering();
    using var reader = new StreamReader(ctx.Request.Body, leaveOpen: true);
    var body = await reader.ReadToEndAsync();
    ctx.Request.Body.Position = 0;

    var (ok, error, caller) = AwsSigV4X509Verifier.Verify(ctx.Request, body, "us-east-1");
    if (!ok)
        return Results.Json(new { message = error }, statusCode: 403);   // AWS answers 403

    var req = JsonSerializer.Deserialize<AwsCreateSessionRequest>(body, JsonOpts)!;
    var (issued, failure, credentials, subjectArn) = await svc.CreateAwsSessionAsync(caller!, req);

    if (!issued)
        return Results.Json(new { message = failure }, statusCode: 403);

    return Results.Ok(new
    {
        credentialSet = new[]
        {
            new
            {
                assumedRoleUser = new { arn = $"arn:aws:sts::123456789012:assumed-role/{req.RoleArn.Split('/')[^1]}/{req.SessionName}" },
                credentials = new
                {
                    accessKeyId     = credentials!.AccessKeyId,
                    secretAccessKey = credentials.SecretAccessKey,
                    sessionToken    = credentials.SessionToken,
                    expiration      = credentials.Expiration.ToUniversalTime().ToString("o")
                },
                packedPolicySize = 0,
                sourceIdentity   = caller!.Certificate.Subject
            }
        },
        subjectArn = subjectArn
    });
});
```

## 2.4 Simulator: model what AWS actually enforces

The verifier above closes S1, S3 and S11. The authorization findings (S2, S4, S5) close in
`CreateAwsSessionAsync`, and this is what makes Development *rehearse* production rather than
merely resemble it:

```csharp
// S2 — an expired or not-yet-valid certificate must be refused.
using var chain = new X509Chain();
chain.ChainPolicy.TrustMode       = X509ChainTrustMode.CustomRootTrust;
chain.ChainPolicy.RevocationMode  = X509RevocationMode.NoCheck;
chain.ChainPolicy.CustomTrustStore.Add(_trustAnchorCa);
foreach (var intermediate in caller.Chain)                    // S7
    chain.ChainPolicy.ExtraStore.Add(intermediate);

if (!chain.Build(caller.Certificate))
{
    var reasons = string.Join(", ", chain.ChainStatus.Select(s => s.Status));
    return (false, $"Certificate chain validation failed: {reasons}", null, null);
}

// S4 — the trust anchor must be the one named, and the profile must list the role.
if (request.TrustAnchorArn != DefaultTrustAnchorArn)
    return (false, "Trust anchor ARN does not resolve.", null, null);

var profile = ListProfiles().FirstOrDefault(p => p.ProfileArn == request.ProfileArn);
if (profile is null)
    return (false, "Profile ARN does not resolve.", null, null);

if (!profile.RoleArns.Contains(request.RoleArn, StringComparer.OrdinalIgnoreCase))
    return (false, $"Profile '{profile.Name}' does not list role '{request.RoleArn}'.", null, null);

// S5 — the role must trust rolesanywhere.amazonaws.com for all three actions.
if (!RoleTrustsRolesAnywhere(role, request.TrustAnchorArn, out var trustFailure))
    return (false, trustFailure, null, null);

// S3 — AWS caps Roles Anywhere at one hour regardless of the role's own maximum.
var duration = Math.Clamp(request.DurationSeconds, 900, 3600);
```

`RoleTrustsRolesAnywhere` needs a `TrustPolicyJson` column on the role table, seeded for
`dev-role` with the policy from §S5 above, and deliberately **left empty for one seeded role**
so the failure is reproducible on demand. Being able to make that 403 happen locally, and read
a message that names the missing action, is worth more than the rest of this change combined.

## 2.5 Gateway: Development configuration

Once the simulator speaks the AWS protocol, Development drops the bridging flag entirely:

```jsonc
// appsettings.Development.json
"Aws": {
  "Region": "us-east-1",
  "CredentialSource": "RolesAnywhere",
  "RolesAnywhere": {
    "TrustAnchorArn": "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/dev-anchor",
    "ProfileArn":     "arn:aws:rolesanywhere:us-east-1:123456789012:profile/dev-profile",
    "RoleArn":        "arn:aws:iam::123456789012:role/dev-role",
    "SessionName":    "unified-gateway-dev",
    "DurationSeconds": 3600,
    "EndpointOverride": "http://localhost:5003",
    "Certificate": {
      "Source": "PemFile",
      "CertificatePath": "./certs/dev-client.crt",
      "PrivateKeyPath":  "./certs/dev-client.key",
      "IncludeChain": false
    }
  }
}
```

`UseSimulatorProtocol` is gone — that is the point. `EndpointOverride` remains the **only**
difference from Production, and `StartupValidator` already refuses it outside Development.

Get the certificate from the simulator:

```bash
curl -s -X POST "http://localhost:5003/rolesanywhere/generate-test-cert?subject=CN=unified-gateway-dev" \
  | python -c "import sys,json;d=json.load(sys.stdin);open('certs/dev-client.crt','w').write(d['certPem']);open('certs/dev-client.key','w').write(d['privateKeyPem'])"
```

Add `certs/` to `.gitignore`. On Windows the gateway round-trips a PEM pair through PKCS#12 so
the key is usable for signing — that is handled in `ClientCertificateLoader`.

> **Port note.** The signature covers the `Host` header, and HttpClient sends
> `Host: localhost:5003` for a non-default port. The gateway signs `Uri.Authority`, which
> includes the port; the verifier above reads `request.Host.Value`, which also includes it.
> Signing the bare hostname instead produces a signature mismatch that presents as a 403 —
> this was a real bug in the gateway's signer, found while writing this document and now fixed
> and covered by a test.

## 2.6 What this then proves, and what it still does not

**Proves — the whole production credential path runs in Development:**

| | |
| :--- | :--- |
| Canonical request construction | Byte-identical to what AWS receives |
| String-to-sign construction | Four-line SigV4 form, verified server-side |
| Credential scope | Serial number in decimal, region, service, terminator |
| Direct asymmetric signing | No derived key — RSA PKCS#1 v1.5 or ECDSA DER |
| Header set and casing | `X-Amz-X509`, `X-Amz-X509-Chain`, `X-Amz-Date`, `Authorization` |
| Content-Type exactness | `application/json` with no charset parameter |
| Response parsing | `credentialSet[0].credentials`, `subjectArn` |
| Certificate loading | PEM/PFX/store, and the Windows PKCS#12 round-trip |
| Expiry, profile and trust-policy refusals | Reproducible on demand |

**Does not prove:**

- **AWS's actual acceptance.** Two implementations agreeing means they agree with each other.
  If both misread the same detail of the specification, the tests stay green and Production
  fails. This is genuinely mitigated but not eliminated.
- **Real trust anchor and Private CA behaviour** — certificate issuance, renewal, revocation
  and CRL distribution are all outside the simulator.
- **Real IAM evaluation.** The simulator evaluates its own policy documents; permission
  boundaries, SCPs and session policies are not modelled.
- **Real network conditions** — TLS to `rolesanywhere.<region>.amazonaws.com`, proxies,
  egress rules, and regional endpoint resolution.

The remaining risk is best retired with a single throwaway AWS account: one Private CA, one
trust anchor, one profile, one role, and one successful `CreateSession`. Everything after that
first success is what the simulator already covers.

## 2.7 Order of work

| Step | Change | Closes | Effort |
| :--- | :--- | :--- | :--- |
| 1 | ~~Fix `chainValid` in the existing endpoint~~ **done** | S2 | Minutes |
| 2 | ~~Make the trust anchor a singleton~~ **done** | S6 | Minutes |
| 3 | ~~Add `AwsSigV4X509Verifier` + `POST /sessions`~~ **done** | S1, S3, S11 | Half a day |
| 4 | ~~Enforce profile and trust anchor~~ **done** | S4, S7 | An hour |
| 5 | ~~Add role trust policies, one deliberately broken~~ **done** | S5 | An hour |
| 6 | ~~Point Development at it; delete `UseSimulatorProtocol`~~ **done** | — | Minutes |
| 7 | One real AWS session, once | The residual risk | **Still outstanding** |

Steps 1 and 2 are worth doing regardless — they are defects in the simulator's existing
behaviour, independent of anything the gateway does.

---

## 2.8 What was actually built

**In `DOTNET_AWS_SIMULATOR`** (branch `feat/aws-compatible-roles-anywhere`):

| File | Change |
| :--- | :--- |
| `Services/AwsSigV4X509Verifier.cs` | New. Server-side AWS4-X509 verification: canonical request, decimal serial, five-minute window, RSA and ECDSA, Client Authentication EKU. |
| `Services/TrustAnchorProvider.cs` | New. The CA as a singleton, ending per-request disk I/O and the cold-start race. |
| `Services/RolesAnywhereService.cs` | `chainValid` now honoured; `CreateAwsSessionAsync` enforces chain validity, trust anchor, profile membership and the role trust policy. |
| `Models/PolicyModels.cs` | `RoleTrustPolicy` and `RoleTrustEvaluator`. |
| `Data/RoleStore.cs` | `TrustPolicyJson` column with an in-place `ALTER TABLE` for existing dev databases; trust policies seeded. |
| `Program.cs` | `POST /sessions`, body buffered so the signature covers the exact bytes. |
| `Crypto/X509CertificateGenerator.cs` | `validityDays`, so expiry can be rehearsed. |
| `tests/IntegrationTests/AwsRolesAnywhereSessionTests.cs` | New. 12 tests, signing written independently of the verifier. |

**In this repository:**

| File | Change |
| :--- | :--- |
| `Models/RolesAnywhereOptions.cs` | `UseSimulatorProtocol` deleted. |
| `Services/Aws/RolesAnywhereCredentialProvider.cs` | Simulator branch deleted; signs `Uri.Authority` so a non-default port is covered; a reported error message now leads instead of the generic guess. |
| `Startup/StartupValidator.cs` | Simulator-protocol rule removed; the thumbprint placeholder check applies only to `WindowsStore`, which is the only source that reads it. |
| `appsettings.Development.json` | `CredentialSource: RolesAnywhere` with `EndpointOverride` to `:5003`. |

## 2.9 Still open

| # | Finding | Why it was left |
| :--- | :--- | :--- |
| S8 | `AccessKeyId` / `SecretAccessKey` are random and unverified downstream | Closing it means implementing SigV4 verification across S3Local and KmsLocal — a much larger change than the credential exchange, and unrelated to it. |
| S9 | `/rolesanywhere/create-session` still returns the old response shape | Kept deliberately for the dashboard's demo flow. The AWS-shaped response is on `POST /sessions`. |
| S10 | Hard-coded CA passphrase; no way to import an existing enterprise CA | Worth doing if you want dev certificates issued by your real internal PKI. |

The one that matters most is not in the table: **no request has yet been accepted by real
AWS.** Until that happens, what has been proven is that two implementations of the same
specification agree with each other.
