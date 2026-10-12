# Local AWS Simulator (.NET 8)

A lightweight, standalone .NET 8 AWS simulator that emulates minimal **S3**, **KMS**, and **STS / IAM** behaviors needed during local development.

It allows you to test cloud-native application flows locally (such as envelope encryption, presigned URLs, and IAM role assumption) with zero AWS infrastructure or Docker overhead, and switch to real AWS in TEST/PROD environments with a **single configuration flag**.

---

## Architecture & Project Structure

```text
local-aws-sim/
├─ src/
│  ├─ Shared/                    # Interfaces (IObjectStoreClient, IKmsClient, IAuthClient), DTOs, PolicyEvaluator, AesGcmHelper
│  ├─ S3Local/                   # ASP.NET Core Web API (S3 streaming, range processing, SQLite metadata, presigning)
│  ├─ KmsLocal/                  # ASP.NET Core Web API (AES-GCM AEAD, DPAPI/dev master key store, envelope encryption)
│  ├─ IamLocal/                  # ASP.NET Core Web API (STS AssumeRole, GetCallerIdentity, RSA-signed JWTs, SQLite roles)
│  └─ AppClients/                # Local HTTP clients + AWS SDK clients + AddAwsClients DI extension
├─ samples/
│  └─ SampleApp/                 # Example .NET 8 console app demonstrating the full end-to-end encryption workflow
├─ tests/
│  ├─ UnitTests/                 # Policy evaluator, AES-GCM helper, and KMS crypto tests
│  └─ IntegrationTests/          # WebApplicationFactory integration tests and end-to-end multi-service test
├─ local-aws-sim.sln
├─ .gitignore
└─ README.md
```

---

## Interactive Dashboard Console

All three services host a unified, interactive **AWS Simulator Console** accessible directly from your browser:
* **IAM Dashboard**: `http://localhost:5003/` or `http://localhost:5003/dashboard`
* **KMS Dashboard**: `http://localhost:5002/` or `http://localhost:5002/dashboard`
* **S3 Dashboard**: `http://localhost:5001/` or `http://localhost:5001/dashboard`

The dashboard features:
- **Real-Time Health Grid**: Live status pings and latency monitoring for S3, KMS, and IAM.
- **🪣 Real S3 Console**: AWS Management Console-style buckets table, "Create bucket" modal, hierarchical breadcrumb navigation (`Amazon S3 / Buckets / [bucket-name]`), object explorer with KMS encryption badges, file and text upload modal, and presign modal.
- **⚡ Live E2E Flow Simulation**: Run the entire cloud-native encryption, upload, presign, download, and decryption pipeline with a single click.
- **🏛️ IAM Roles Anywhere**: Exchange X.509 client certificates issued by the simulator's Trust Anchor for temporary AWS STS credentials (`ASIA...` AccessKeyId, SecretAccessKey, and SessionToken).
- **🛡️ STS / IAM Console**: Assume roles, view and decode RSA-signed JWT tokens, inspect claims, and verify caller identities.
- **🔑 KMS Console**: Generate 256-bit data keys, test AES-GCM envelope encryption/decryption, and test cryptographic tamper detection.

---

## Service Endpoints

### 1. S3Local (`http://localhost:5001`)
* `PUT /{bucket}/{*key}` — Streams file upload directly to disk (`data/buckets/{bucket}/{key}`), computes MD5 hex ETag, extracts metadata headers (`x-amz-meta-*`, `x-kms-key`), and persists metadata in SQLite.
* `GET /{bucket}/{*key}` — Streams file download with `enableRangeProcessing: true` supporting byte-range HTTP 206 partial content requests. Populates custom metadata headers and validates presigned tokens.
* `DELETE /{bucket}/{*key}` — Deletes the object on disk and removes metadata from SQLite.
* `GET /presign?bucket={b}&key={k}&durationSeconds={s}` — Issues HMAC-SHA256 time-limited presigned URLs.

### 2. KmsLocal (`http://localhost:5002`)
* `POST /generate-data-key` — Generates a 256-bit cryptographic data key, encrypts it using AES-GCM with the master key, and returns `DataKeyDto(PlaintextBase64, CiphertextBlobBase64)`.
* `POST /encrypt` — Encrypts arbitrary payload bytes with AES-GCM using the master key.
* `POST /decrypt` — Decrypts ciphertext blob using AES-GCM and verifies authentication tag integrity.
* *Security*: Uses Windows DPAPI (`ProtectedData.Protect`) or dev-only key file store.

### 3. IamLocal (`http://localhost:5003`)
* `POST /assume-role` — Issues RSA-signed JWT tokens containing `role`, `arn`, and `policies` claims. Seeds default roles (`dev-role`, `admin-role`, `read-only-role`) in SQLite.
* `POST /get-caller-identity` — Verifies JWT RSA signature and extracts caller identity (`Arn`, `AccountId`, `UserId`).
* `GET /.well-known/jwks.json` & `GET /public-key` — Exposes the RSA public key for verification.

---

## Single Configuration Switch: Local Simulator vs. Real AWS

Applications depend **only** on the shared interfaces:
- `IObjectStoreClient`
- `IKmsClient`
- `IAuthClient`

Toggle between the simulator and AWS with a single setting:

### Local Development (`appsettings.Development.json`)
```json
{
  "LocalAws": {
    "Enabled": true,
    "S3Url": "http://localhost:5001",
    "KmsUrl": "http://localhost:5002",
    "StsUrl": "http://localhost:5003"
  }
}
```

### Production / Staging (`appsettings.Production.json`)
```json
{
  "LocalAws": {
    "Enabled": false
  },
  "AWS": {
    "Region": "us-east-1"
  }
}
```

### DI Registration (`Program.cs`)
```csharp
using AppClients.Extensions;

// Registers Local clients or AWS SDK clients based on configuration
builder.Services.AddAwsClients(builder.Configuration);
```

---

## Running the Services

You can run each service independently using standard `dotnet run`:

```bash
# Terminal 1: STS / IAM Emulator
dotnet run --project src/IamLocal/IamLocal.csproj --urls "http://localhost:5003"

# Terminal 2: KMS Emulator
dotnet run --project src/KmsLocal/KmsLocal.csproj --urls "http://localhost:5002"

# Terminal 3: S3 Emulator
dotnet run --project src/S3Local/S3Local.csproj --urls "http://localhost:5001"
```

### Run the Sample Application
With the services running, execute the sample client:
```bash
dotnet run --project samples/SampleApp/SampleApp.csproj
```

The sample app demonstrates the complete workflow:
1. Calls `IAuthClient.AssumeRoleAsync("dev-role")` to acquire a JWT token.
2. Calls `IAuthClient.GetCallerIdentityAsync(token)` to inspect identity ARN and user ID.
3. Calls `IKmsClient.GenerateDataKeyAsync("alias/dev-master-key")` to obtain a 256-bit data key.
4. Encrypts payload locally using AES-GCM.
5. Streams the encrypted object to S3 with `x-kms-key` metadata header.
6. Generates an expiring presigned GET URL.
7. Downloads the encrypted object from S3.
8. Calls `IKmsClient.DecryptAsync` to recover the plaintext data key from the metadata blob.
9. Decrypts downloaded bytes locally and asserts 100% integrity.
10. Deletes object from S3.

---

## Running Tests

All unit tests and in-process integration tests (using `WebApplicationFactory`) can be executed via:

```bash
dotnet test local-aws-sim.sln --logger "console;verbosity=normal"
```

* **UnitTests**: Verifies `PolicyEvaluator` (wildcard matching, explicit Deny precedence), `AesGcmHelper` (tamper detection, tag validation), and KMS crypto service.
* **IntegrationTests**: Tests `IamLocal`, `KmsLocal`, and `S3Local` HTTP endpoints and runs an automated multi-service end-to-end workflow test.

---

## Security Notes
* **Dev-Only Usage**: This simulator is strictly for local development and unit/integration testing.
* **Master Keys**: Master keys are protected via DPAPI on Windows and excluded from version control via `.gitignore`.
* **Zero Production Footprint**: Set `LocalAws:Enabled: false` in test/staging/production to ensure all operations route directly to official AWS SDK clients.
