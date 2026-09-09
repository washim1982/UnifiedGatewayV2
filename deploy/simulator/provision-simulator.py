#!/usr/bin/env python3
"""
Provisions the local AWS Simulator with everything the Unified LLM Gateway needs in TEST.

This is the TEST-environment equivalent of the Terraform/CloudFormation that would create
the same resources in PROD: IAM roles and policies, a KMS key, and the gateway's secrets.
Nothing here is application code -- moving to PROD means running the AWS equivalent of this
script, not changing the gateway.

Usage:
    python deploy/simulator/provision-simulator.py
    python deploy/simulator/provision-simulator.py --iam http://localhost:5001 --kms http://localhost:5003
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

ACCOUNT = "123456789012"


def call(method, url, payload=None, expect=(200, 201, 204)):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, (json.loads(body) if body.strip() else None)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        return e.code, body
    except urllib.error.URLError as e:
        print(f"  ! cannot reach {url}: {e.reason}")
        sys.exit(1)


# --- IAM roles the gateway's management plane is authorized against ---------------
#
# The gateway asks the IAM policy engine "may <principal> perform gateway:<Action> on
# <resource>?" for every management call. These policies are the answer.

ROLES = [
    {
        "name": "GatewayPlatformAdminRole",
        "description": "Full administrative control of the Unified LLM Gateway.",
        "policy_name": "GatewayPlatformAdminPolicy",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FullGatewayAdministration",
                    "Effect": "Allow",
                    "Action": "gateway:*",
                    "Resource": "*",
                }
            ],
        },
    },
    {
        "name": "GatewayAppOwnerRole",
        "description": "Manages applications but cannot change guardrail policy or signing keys.",
        "policy_name": "GatewayAppOwnerPolicy",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ManageApplications",
                    "Effect": "Allow",
                    "Action": [
                        "gateway:ListApplications",
                        "gateway:GetApplication",
                        "gateway:CreateApplication",
                        "gateway:UpdateApplication",
                        "gateway:RotateApiKey",
                        "gateway:MintStsToken",
                        "gateway:InvokeApplication",
                        "gateway:ReadMetrics",
                        "gateway:ListModels",
                        "gateway:TestGuardrails",
                        "gateway:ReadGuardrailConfig",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyPolicyAndKeyControl",
                    "Effect": "Deny",
                    "Action": [
                        "gateway:UpdateGuardrailConfig",
                        "gateway:RotateSigningKey",
                        "gateway:DeleteApplication",
                    ],
                    "Resource": "*",
                },
            ],
        },
    },
    {
        "name": "GatewayDeveloperRole",
        "description": "Okta group UnifiedGateway-Developers: view registered applications and exercise the test API only.",
        "policy_name": "GatewayDeveloperPolicy",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ViewRegisteredApplicationsAndTest",
                    "Effect": "Allow",
                    "Action": [
                        "gateway:ListApplications",
                        "gateway:GetApplication",
                        "gateway:InvokeApplication",
                        "gateway:ListModels",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyEverythingElse",
                    "Effect": "Deny",
                    "Action": [
                        "gateway:CreateApplication",
                        "gateway:UpdateApplication",
                        "gateway:DeleteApplication",
                        "gateway:RotateApiKey",
                        "gateway:MintStsToken",
                        "gateway:RotateSigningKey",
                        "gateway:UpdateGuardrailConfig",
                        "gateway:ReadGuardrailConfig",
                        "gateway:TestGuardrails",
                        "gateway:ReadMetrics",
                        "gateway:ReadCredentialStatus",
                    ],
                    "Resource": "*",
                },
            ],
        },
    },
    {
        "name": "GatewayAuditorRole",
        "description": "Read-only access for audit and compliance review.",
        "policy_name": "GatewayAuditorPolicy",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOnly",
                    "Effect": "Allow",
                    "Action": [
                        "gateway:ListApplications",
                        "gateway:GetApplication",
                        "gateway:ReadMetrics",
                        "gateway:ReadGuardrailConfig",
                        "gateway:ReadCredentialStatus",
                        "gateway:ListModels",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyEverythingThatChangesState",
                    "Effect": "Deny",
                    "Action": [
                        "gateway:CreateApplication",
                        "gateway:UpdateApplication",
                        "gateway:DeleteApplication",
                        "gateway:RotateApiKey",
                        "gateway:MintStsToken",
                        "gateway:RotateSigningKey",
                        "gateway:UpdateGuardrailConfig",
                        "gateway:InvokeApplication",
                    ],
                    "Resource": "*",
                },
            ],
        },
    },
]

ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def provision_iam(iam_url):
    print("\nIAM roles and policies")
    for role in ROLES:
        status, _ = call(
            "POST",
            f"{iam_url}/roles",
            {
                "RoleName": role["name"],
                "AssumeRolePolicyDocument": ASSUME_ROLE_POLICY,
                "Description": role["description"],
            },
        )
        state = "created" if status in (200, 201) else "exists"
        print(f"  - {role['name']}: {state}")

        status, _ = call(
            "POST",
            f"{iam_url}/roles/{role['name']}/policies",
            {"PolicyName": role["policy_name"], "PolicyDocument": role["policy"]},
        )
        print(f"      policy {role['policy_name']}: {'attached' if status in (200, 201) else status}")


def provision_kms(kms_url):
    print("\nKMS key")
    status, keys = call("GET", f"{kms_url}/keys")
    existing = None
    if isinstance(keys, list):
        existing = next((k for k in keys if k.get("Description") == "Unified LLM Gateway master key"), None)

    if existing:
        print(f"  - reusing {existing['KeyId']}")
        return existing["KeyId"]

    status, key = call(
        "POST",
        f"{kms_url}/keys",
        {"Description": "Unified LLM Gateway master key", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    if isinstance(key, dict) and key.get("KeyId"):
        print(f"  - created {key['KeyId']}")
        return key["KeyId"]

    print(f"  ! key creation returned {status}: {key}")
    return None


def verify_secrets(kms_url):
    print("\nGateway secrets")
    print("  The gateway bootstraps these on first start; nothing to pre-create.")
    status, secrets = call("GET", f"{kms_url}/secrets")
    if isinstance(secrets, list):
        names = [s.get("SecretName") for s in secrets if "/gateway/" in (s.get("SecretName") or "")]
        if names:
            for n in sorted(names):
                print(f"  - present: {n}")
        else:
            print("  - none yet (expected before the first gateway start)")


def main():
    parser = argparse.ArgumentParser(description="Provision the AWS Simulator for the Unified LLM Gateway.")
    parser.add_argument("--iam", default="http://localhost:5001")
    parser.add_argument("--kms", default="http://localhost:5003")
    args = parser.parse_args()

    print("Provisioning the local AWS Simulator for the Unified LLM Gateway")
    print(f"  IAM: {args.iam}")
    print(f"  KMS: {args.kms}")

    provision_iam(args.iam)
    provision_kms(args.kms)
    verify_secrets(args.kms)

    print("\nDone. Start the gateway with:")
    print("  ASPNETCORE_ENVIRONMENT=Test dotnet run")
    print("\nThen call the management API as a role, e.g.:")
    print('  curl -H "X-API-Key: GatewayPlatformAdminRole" http://localhost:5000/api/apps')


if __name__ == "__main__":
    main()
