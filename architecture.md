# Security Architecture Review & System Design

**Project:** Universal AI LLM Gateway  
**Runtime:** .NET 8 Minimal API (C#)  
**Target Environments:** Development, Test/Staging, Production — **On-Prem (Windows Server / IIS)**  
**Document Version:** 1.1.0  
**Status:** Security Baseline Approved (with Enterprise Admin Guardrails)  

---

## 1. Executive Summary & Security Objectives

The **Universal AI LLM Gateway** provides a unified, secure abstraction layer between enterprise client applications and heterogeneous Large Language Model (LLM) providers (AWS Bedrock Runtime and Local engines like Ollama, LM Studio, and llama.cpp).

### 1.1 Core Security Objectives
1. **Mandatory Admin-Level Guardrails:** Every inbound request is intercepted and inspected for PCI (Credit Cards with Luhn validation, IBAN, CVV), PII (SSN, Email, Phone, Passports), Secrets (AWS Keys, Private Keys, JWTs, API tokens), and Prompt Injection / Jailbreaks before reaching AWS Bedrock or local inference backends.
2. **Zero Credential Exposure:** Temporary AWS STS session tokens and IAM long-term secrets are isolated in memory and never logged, cached to disk unencrypted, or transmitted to client applications.
3. **Least Privilege & Role Isolation:** AWS Bedrock execution is mediated via short-lived temporary STS sessions (`sts:AssumeRole`) scoped strictly to `bedrock:InvokeModel` with automated background token rotation.
4. **Application Sandboxing & Auth:** Every upstream consumer application is authenticated via distinct cryptographically generated API keys (`ug_live_*`), verified using constant-time SHA-256 hash comparison.
5. **Data Protection & Secret Encryption:** Persistent application metadata, role configurations, and master keys are safeguarded using ASP.NET Core Data Protection API.
6. **Defense in Depth:** Rate limiting, non-root Alpine container sandboxing, CORS lockdown, and automated fallback failover prevent denial of service and data poisoning.

---

## 2. High-Level Security Architecture & Trust Boundaries

```mermaid
flowchart TD
    %% Trust Boundaries
    subgraph TB_EXT["TRUST BOUNDARY 1: External / Client Zone (Untrusted)"]
        ClientAppA["Enterprise App A\n(Customer Support)"]
        ClientAppB["Enterprise App B\n(Code Reviewer)"]
        AdminUser["Platform Admin\n(Dashboard UI)"]
    end

    subgraph TB_DMZ["TRUST BOUNDARY 2: Gateway DMZ / Kubernetes Ingress"]
        Ingress["TLS / Ingress Controller\n(HTTPS Termination - Port 443/8080)"]
        RateLimiter["Rate Limiting & CORS Filter\n(GatewayCorsPolicy)"]
    end

    subgraph TB_GW["TRUST BOUNDARY 3: Gateway Processing Boundary (.NET 8 Core)"]
        subgraph AuthLayer["Authentication & Security Subsystem"]
            ApiKeyFilter["X-API-Key & Bearer Validator"]
            SecService["ISecurityService\n- Fixed-Time SHA256 Verification\n- Data Protection Key Encryption\n- Secret Masking Engine"]
        end

        subgraph GuardrailSubsystem["Enterprise Guardrail Subsystem (Admin Level)"]
            GuardrailSvc["IGuardrailService (Pre-Execution Inspection)\n- PCI: Visa/MC/Amex/Discover (Luhn Check), IBAN, CVV\n- PII: US SSN, Email, Phone, Passports\n- Secrets: AWS Keys, Private Keys, JWTs, API Tokens\n- Safety: Prompt Injection & Adversarial Jailbreak Defense\n- Action Engine: Redact / Block / AuditOnly"]
        end

        subgraph CoreRouter["Orchestration & Routing Engine"]
            Router["IModelRouter\n- Request Normalizer\n- Resilient Fallback Orchestrator"]
            AppReg["IApplicationRegistryService\n- Encrypted Config Store\n- Version History Snapshots\n- Telemetry & Audit Logger"]
        end

        subgraph CredentialVault["Credential & Token Isolation Subsystem"]
            STSSvc["ISTSService\n(In-Memory Token Cache)"]
            STSWorker["AwsCredentialBackgroundService\n(Proactive Token Refresh - 5m TTL Buffer)"]
            DataProtection["ASP.NET Data Protection API\n(Persistent File/KMS Keys)"]
        end
    end

    subgraph TB_AWS["TRUST BOUNDARY 4: AWS Cloud IAM & Bedrock Zone"]
        AWS_STS["AWS Security Token Service (STS)\n(sts:AssumeRole)"]
        AWS_IAM["Target Execution IAM Role\n(arn:aws:iam::*:role/BedrockGatewayExecutionRole)"]
        AWS_Bedrock["AWS Bedrock Runtime\n- Claude 3.5 Sonnet / Haiku\n- Meta Llama 3 70B\n- Mistral / Titan"]
    end

    subgraph TB_LOCAL["TRUST BOUNDARY 5: Private VPC / Local Inference Zone"]
        Local_Ollama["Ollama Engine\n(http://localhost:11434)"]
        Local_LM["LM Studio Engine\n(http://localhost:1234)"]
        Local_LlamaCpp["llama.cpp Engine\n(http://localhost:8080)"]
    end

    %% Data Flow & Interconnections
    ClientAppA -->|"HTTPS POST /gateway/{appId}/invoke\nX-API-Key: ug_live_..."| Ingress
    ClientAppB -->|"HTTPS POST /gateway/{appId}/invoke\nX-API-Key: ug_live_..."| Ingress
    AdminUser -->|"HTTPS GET / & REST /api/*\nX-API-Key: Master Admin Key"| Ingress

    Ingress --> RateLimiter
    RateLimiter --> ApiKeyFilter
    ApiKeyFilter --> SecService
    SecService -->|"Validate Key Hash & Scope"| AppReg
    ApiKeyFilter -->|"Authenticated Request"| Router

    Router -->|"1. Intercept & Evaluate Prompt"| GuardrailSvc
    GuardrailSvc -.->|"If Block Mode & Violations: Abort 422"| Router
    GuardrailSvc -.->|"If Redact Mode: Inline Anonymize"| Router

    Router -->|"2. Fetch System Prompt & Model Config"| AppReg
    AppReg -.->|"Encrypt / Decrypt Sensitive Fields"| DataProtection

    Router -->|"3. Request Temporary Bedrock Session"| STSSvc
    STSWorker -->|"Proactive Background Refresh"| STSSvc
    STSSvc -->|"AssumeRoleAsync (TLS 1.3 / SigV4)"| AWS_STS
    AWS_STS -->|"Issue Ephemeral Credentials\n(AccessKeyId, SecretKey, SessionToken)"| STSSvc
    AWS_STS -.->|"Scope to IAM Role Policy"| AWS_IAM

    Router -->|"4. InvokeModelAsync (Sanitized Payload + SigV4 Signed)"| AWS_Bedrock
    STSSvc -.->|"Provide Ephemeral Memory Credentials"| AWS_Bedrock

    Router -->|"Fallback / Local Route (Sanitized Payload)"| Local_Ollama
    Router -->|"Local Route"| Local_LM
    Router -->|"Local Route"| Local_LlamaCpp
```

---

## 3. Threat Model & STRIDE Analysis

| STRIDE Category | Threat Description | Attack Vector | Security Countermeasures & Implementation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Impersonation of client applications or unauthorized access to per-app endpoints. | Attackers guess or brute-force API keys or spoof client identity. | • Cryptographically random 256-bit API keys (`ug_live_*`).<br>• Keys stored only as SHA-256 hashes.<br>• Fixed-time string comparison (`CryptographicOperations.FixedTimeEquals`) to defeat timing attacks.<br>• Per-app isolation and Master Key partition. |
| **Tampering** | Modification of in-flight prompts, prompt injection attacks, or unauthorized tampering with registry files. | Prompt injection (`ignore previous instructions`), DAN jailbreak exploits, or man-in-the-middle attacks. | • **Guardrails Subsystem** detects and sanitizes/blocks prompt override attempts.<br>• Mandatory TLS for all external and cloud communication.<br>• AWS SigV4 cryptographic request signing on all AWS Bedrock calls.<br>• Data Protection API (`IDataProtector`) encrypts sensitive configuration at rest. |
| **Repudiation** | Malicious users denying sending abusive, sensitive, or high-cost prompts. | Lack of invocation logs or trace correlation. | • Granular audit logging with `RequestLogEntry` tracking timestamp, `appId`, model, guardrail action (`Redacted`/`Blocked`), and token counts.<br>• Unique `traceId` correlation across requests. |
| **Information Disclosure** | Leakage of customer PII (SSN, Email, Phone), PCI (Credit Cards, CVV, IBAN), API tokens, or AWS STS temporary credentials. | Prompts containing sensitive user data being transmitted to cloud LLM or stored in unencrypted logs. | • **Pre-Execution Guardrails** redact sensitive data (`[REDACTED_CREDIT_CARD]`, `[REDACTED_SSN]`, `[REDACTED_AWS_KEY]`) before reaching AWS Bedrock or logs.<br>• Algorithmic **Luhn checksum** verifies valid credit cards to prevent false positives.<br>• AWS STS session tokens never logged or serialized to client responses. |
| **Denial of Service (DoS)** | Backend model exhaustion, prompt flooding, or local LLM server starvation. | Flooding gateway with maximum-token requests or triggering concurrent heavy model loads. | • Configurable rate limiting per minute (`RateLimitPerMinute`).<br>• Explicit `max_tokens` quotas and request timeouts (30–120s).<br>• Resilient Polly circuit breaking & retry policies.<br>• Automated failover routing (Bedrock -> Local or vice-versa). |
| **Elevation of Privilege** | Cross-tenant access to another application's prompt or unauthorized access to AWS infrastructure. | Tenant parameter pollution or IAM role permission creep. | • Strict app isolation: requests to `/gateway/{appId}/invoke` can only execute within the registered `appId` security context.<br>• AWS IAM Role scoped strictly to `bedrock:InvokeModel`.<br>• Non-root container execution (`appuser`, UID 1000). |

---

## 4. Guardrails Subsystem Specification

### 4.1 Supported Detectors & Enforcement Rules

1. **PCI & Financial Data Protection**:
   - **Payment Cards:** Visa, MasterCard, American Express, Discover, Diners Club, JCB with algorithmic **Luhn checksum verification**.
   - **IBAN:** International Bank Account Numbers.
   - **CVV/CVC:** 3-digit and 4-digit security codes.
2. **PII & Personal Identity Protection**:
   - **US SSN:** Formatted (`XXX-XX-XXXX`) and unformatted 9-digit Social Security Numbers validated against SSA assignment rules.
   - **Email Addresses:** RFC 5322 compliant personal and corporate email addresses.
   - **Phone Numbers:** International E.164 and localized North American formats.
   - **Passports:** International passport document identifiers.
3. **Secrets, Keys & Credentials**:
   - **AWS IAM Keys:** `AKIA[0-9A-Z]{16}` access key identifiers.
   - **Asymmetric Private Keys:** RSA, EC, DSA, and OpenSSH private key PEM blocks.
   - **JWT Tokens:** Multi-segment Base64 JSON Web Tokens.
   - **API Tokens:** High-entropy Bearer tokens, GitHub PATs (`ghp_*`), OpenAI (`sk-*`), Gateway keys (`ug_live_*`).
4. **Prompt Injection & Adversarial Jailbreaks**:
   - **System Overrides:** `"ignore all previous instructions"`, `"disregard prior system prompts"`, `"reveal system prompt"`.
   - **Jailbreaks:** DAN (Do Anything Now), Developer Mode, unrestricted persona overrides.
   - **Safety Bypasses:** Direct commands attempting to disable guardrails or content moderation.

### 4.2 Enforcement Action Modes

| Mode | Behavior | Use Case |
| :--- | :--- | :--- |
| **`Redact`** *(Default)* | Inline anonymization with descriptive tokens (`[REDACTED_CREDIT_CARD]`, `[REDACTED_SSN]`, `[REDACTED_AWS_KEY]`). Prompt is sanitized before being dispatched to Bedrock. | Enterprise customer support, RAG pipelines, external user chatbots where data privacy must be preserved without breaking conversational flow. |
| **`Block`** | Aborts execution immediately with `422 Unprocessable Entity` / `GUARDRAIL_BLOCKED` and detailed violation metadata. Downstream LLMs are never invoked. | High-security financial apps, internal code reviewers, strictly regulated compliance workloads. |
| **`AuditOnly`** | Evaluates prompt, records violations in telemetry and security KPIs, but passes original prompt unaltered. | Baseline monitoring, shadow evaluation, policy tuning before active enforcement. |

---

## 5. Security Review Sign-Off & Verification

| Security Control Requirement | Implementation Status | Evidence / Verification Location |
| :--- | :--- | :--- |
| **Admin-Level Pre-Execution Guardrails** | **PASSED** | [`GuardrailService.cs`](Services/GuardrailService.cs), [`ModelRouter.cs`](Services/ModelRouter.cs) |
| **PCI Credit Card Luhn Validation** | **PASSED** | Validated in [`GuardrailServiceTests.cs`](UnifiedGatewayV2.Tests/GuardrailServiceTests.cs). |
| **PII & Secrets Redaction** | **PASSED** | Inline sanitization verified for SSN, Email, Phone, AWS Keys, and JWTs. |
| **Prompt Injection & Jailbreak Defense** | **PASSED** | System override and DAN patterns detected and quarantined. |
| **Zero Plaintext Secrets / STS Isolation** | **PASSED** | [`STSService.cs`](Services/STSService.cs), [`AwsCredentialBackgroundService.cs`](Services/AwsCredentialBackgroundService.cs) |
| **Egress (Response) Guardrails** | **PASSED** | Model output scanned for leaked PCI/PII/secrets; fails closed. [`GuardrailService.cs`](Services/GuardrailService.cs), [`ModelRouter.cs`](Services/ModelRouter.cs) |
| **Rate Limiting & Abuse Clamps** | **PASSED** | Per-caller limiter, input/token/body caps. [`Program.cs`](Program.cs) |
| **Persistent Audit Trail** | **PASSED** | Append-only JSONL, survives restart. [`ApplicationRegistryService.cs`](Services/ApplicationRegistryService.cs) |
| **Automated Unit & Integration Test Suite** | **PASSED** | 40/40 tests passing in [`UnifiedGatewayV2.Tests`](UnifiedGatewayV2.Tests). |
