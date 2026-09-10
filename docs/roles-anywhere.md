# AWS credentials in Test and Production: IAM Roles Anywhere

The gateway deploys to IIS. It is not on EC2, ECS or Lambda, so there is no instance role, task
role or execution role to inherit. That leaves two honest ways for the process to prove who it
is to AWS:

1. A long-lived access key on the host, in a file or an environment variable.
2. An X.509 certificate exchanged for short-lived credentials — IAM Roles Anywhere.

Test and Production use the second. `StartupValidator` refuses the first, because a stored
access key is exactly the credential the rest of this work removed from the gateway: it does
not expire, it is copied whenever the host is rebuilt, and nothing records where it has been.

Every AWS call the gateway makes resolves through `ISTSService` — S3, KMS, Secrets Manager,
IAM and Bedrock alike — so configuring this once covers all of them.

---

## 1. Configuration

```jsonc
"Gateway": {
  "Aws": {
    "Region": "us-east-1",
    "CredentialSource": "RolesAnywhere",
    "RolesAnywhere": {
      "TrustAnchorArn": "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/abc-123",
      "ProfileArn":     "arn:aws:rolesanywhere:us-east-1:111122223333:profile/def-456",
      "RoleArn":        "arn:aws:iam::111122223333:role/BedrockGatewayExecutionRole-prod",
      "SessionName":    "unified-gateway-prod",
      "DurationSeconds": 3600,
      "Certificate": {
        "Source": "WindowsStore",
        "StoreLocation": "LocalMachine",
        "StoreName": "My",
        "Thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
        "IncludeChain": true
      }
    }
  }
}
```

There is **no secret in this block**. Every value is an identifier, a path or a thumbprint —
that is the property that makes the mechanism worth the setup cost.

`CredentialSource` also accepts `AssumeRole` and `LocalProfile`; both are refused outside
Development. `Auto` (the default when the key is absent) resolves to `LocalProfile` when
`UseLocalProfile` is true and `AssumeRole` otherwise, which is what configuration written
before this setting existed did.

---

## 2. What has to exist in AWS

Four things, in this order. Three of them are easy to create and impossible to guess from an
error message later, so they are worth doing deliberately.

### A private CA

Roles Anywhere needs a CA it can trust. AWS Private CA is the managed option; an existing
internal PKI works too, and is usually what an enterprise already has. What matters is that
you can issue client certificates from it and hand the gateway one.

### A trust anchor

Points at that CA. Either a Private CA ARN, or the CA certificate bundle pasted in for an
external PKI.

```bash
aws rolesanywhere create-trust-anchor \
  --name unified-gateway-prod \
  --source 'sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData="<PEM of the CA cert>"}' \
  --enabled
```

### A role whose trust policy names the service

This is the step that most often gets missed, and it fails as an unexplained 403:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "rolesanywhere.amazonaws.com" },
    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
    "Condition": {
      "ArnEquals": {
        "aws:SourceArn": "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/abc-123"
      }
    }
  }]
}
```

All three actions are required — `sts:AssumeRole` alone is not enough, because Roles Anywhere
sets a source identity and session tags on every session.

The `aws:SourceArn` condition matters: without it, any trust anchor in the account can assume
this role.

The role's own permission policy is whatever the gateway needs — `bedrock:InvokeModel`, the
telemetry and secrets buckets, the KMS key, and IAM policy reads.

### A profile

Lists the roles a certificate holder may ask for:

```bash
aws rolesanywhere create-profile \
  --name unified-gateway-prod \
  --role-arns arn:aws:iam::111122223333:role/BedrockGatewayExecutionRole-prod \
  --duration-seconds 3600 \
  --enabled
```

---

## 3. The certificate on the host

`Source: "WindowsStore"` is the default and the right choice under IIS:

- Import the client certificate into **LocalMachine\My** (not a user store — the app pool is
  not a logged-in user).
- Grant the app pool identity **read access to the private key**: certificate → All Tasks →
  Manage Private Keys → add `IIS AppPool\<pool name>`.
- Set `Thumbprint` to the certificate's thumbprint. Spaces and the invisible left-to-right
  mark that the Windows certificate dialog inserts when you copy are stripped automatically.

The private key never leaves the OS, is not exportable, and appears in no configuration file
or deployment artefact.

`PemFile` and `PfxFile` exist for non-Windows hosts and for containers. A PKCS#12 passphrase
is read from an environment variable named by `PfxPasswordEnvironmentVariable` — the variable's
*name* goes in config, never the passphrase. It cannot come from the secret store, because
reaching the secret store is what these credentials are for.

### IncludeChain

Leave it `true` unless the trust anchor holds the *issuing* CA directly. The leaf goes in
`X-Amz-X509`; intermediates go in `X-Amz-X509-Chain`; the root is already at the trust anchor.
A missing intermediate presents as a 400, not as a trust error.

---

## 4. How the exchange works

`RolesAnywhereSigner` implements SigV4 with one substantial difference, and it is the
difference that makes a hand-rolled implementation fail:

| | Ordinary SigV4 | AWS4-X509 |
| :--- | :--- | :--- |
| Credential scope begins with | Access key id | **Certificate serial number, in decimal** |
| Signing key | Derived from the secret key through four chained HMACs | **None — the private key signs directly** |
| Signature | HMAC-SHA256 | **RSA PKCS#1 v1.5 or ECDSA, over the string to sign** |

Everything else — canonical request, sorted lowercase headers, the payload hash, the four-line
string to sign — is unchanged.

A mistake in any of this returns **403**, the same status as a wrong trust anchor or a role
trust policy that omits the service principal. That is why the signing is covered by unit
tests that verify the signature against the certificate's own public key rather than only by
running it: the service cannot tell you which of the two you got wrong.

Sessions last up to an hour (AWS caps Roles Anywhere at 3600s regardless of the role's own
maximum, and the provider clamps rather than letting AWS reject it).
`AwsCredentialBackgroundService` refreshes `RefreshBufferMinutes` before expiry.

---

## 5. Checking it

`GET /api/credentials/status` reports what the host is actually using:

```json
{
  "isInitialized": true,
  "credentialSource": "RolesAnywhere",
  "roleArnMasked": "arn:aws:iam:******ecutionRole-prod",
  "certificate": {
    "subject": "CN=unified-gateway-prod",
    "thumbprint": "AABBCC...",
    "notAfter": "2027-09-10T00:00:00+00:00",
    "chainPresented": true
  },
  "expirationUtc": "2026-09-10T14:56:43Z",
  "isExpiringSoon": false
}
```

**Watch `certificate.notAfter`.** Client-certificate expiry is the failure mode that takes a
Roles Anywhere deployment down everywhere at once, on a date nobody is looking at. It is
surfaced here so it can be alerted on rather than left to a calendar reminder.

---

## 6. Failures and what they mean

`StartupValidator` refuses these before the process starts:

| Configuration | Refused because |
| :--- | :--- |
| `CredentialSource` is not `RolesAnywhere` outside Development | Everything else ends at a stored access key on the host. |
| A `<placeholder>` left in any ARN or the thumbprint | The shipped templates carry them; a deploy that forgets to substitute fails here rather than at the first AWS call. |
| Missing `TrustAnchorArn`, `ProfileArn` or `RoleArn` | All three are required for CreateSession. |
| `DurationSeconds` outside 900–3600 | AWS returns a bare `ValidationException`. |
| `EndpointOverride` set outside Development | The host would not be talking to AWS while still reporting healthy. |
| `UseSimulatorProtocol` outside Development | The simulator does not verify AWS4-X509 signatures. |

At runtime:

| Symptom | Cause |
| :--- | :--- |
| 403 from CreateSession | Trust anchor does not hold the issuing CA; the profile does not list the role; or the role trust policy omits `rolesanywhere.amazonaws.com`, the `aws:SourceArn` condition, or `sts:TagSession` / `sts:SetSourceIdentity`. |
| 404 | Trust anchor or profile ARN does not resolve in this region and account. |
| 400 | Duration out of range, or the chain does not reach the trust anchor. |
| "no accessible RSA or ECDSA private key" | Under IIS this is nearly always the app pool identity lacking read access to the private key, not a missing certificate. |
| "expired on …" at startup | The certificate expired. Reissue and reimport; nothing about it renews itself. |

---

## 7. Development

Development does not use Roles Anywhere. The control plane is the local .NET simulator, which
needs no AWS credentials at all, and Bedrock deliberately uses the developer's own `~/.aws`
profile (see [dev-environment.md §7](dev-environment.md)).

The wiring can still be exercised locally against the simulator's own Roles Anywhere endpoint:

```bash
curl -X POST "http://localhost:5003/rolesanywhere/generate-test-cert?subject=CN=unified-gateway-dev"
```

then run with `Gateway__Aws__CredentialSource=RolesAnywhere`,
`Gateway__Aws__RolesAnywhere__UseSimulatorProtocol=true` and
`Gateway__Aws__RolesAnywhere__EndpointOverride=http://localhost:5003`.

**This confirms the wiring, not the protocol.** The simulator verifies a bare RSA signature
over a string the client chooses; AWS verifies a full AWS4-X509 SigV4 signature. A run that
succeeds here says the configuration binds, the certificate loads and its key is usable, the
session is exchanged and the credentials are cached with the right expiry. It says nothing
about whether the production signature is correct — that is what the signer's unit tests are
for, and it remains unverified against the real service until a real trust anchor exists.
