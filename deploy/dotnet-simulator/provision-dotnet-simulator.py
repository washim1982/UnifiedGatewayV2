#!/usr/bin/env python3
"""
Provisions the .NET local AWS simulator (DOTNET_AWS_SIMULATOR) for the Unified LLM Gateway.

This is the DEV-environment equivalent of the Terraform that creates the same IAM roles in
TEST and PROD. Nothing here is application code: moving to real AWS means running the AWS
equivalent of this script and flipping Gateway:Cloud:Provider to "Aws".

Why it writes SQLite directly: IamLocal exposes no role-management endpoint, and its
/assume-role auto-creates any unknown role with Allow */*. Left alone, every gateway role in
dev would be a full administrator and role separation would never be exercised locally.
Seeding real policies makes a dev denial behave the way a production denial will.

The simulator now ships inside this repository at dev/aws-simulator, and the gateway starts it
in Development (Gateway:DevSimulator), keeping its databases, buckets and keys under
data/dev/simulator. Those are the defaults below. Start the gateway once so IamLocal creates
its database, then run this.

Usage:
    python deploy/dotnet-simulator/provision-dotnet-simulator.py
    python deploy/dotnet-simulator/provision-dotnet-simulator.py --db C:/path/to/iam.db
    python deploy/dotnet-simulator/provision-dotnet-simulator.py --sim-root C:/path/to/DOTNET_AWS_SIMULATOR
"""

import argparse
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid

ACCOUNT = "123456789012"

# The repository root, two directories above this script.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Where the bundled simulator keeps its state (Gateway:DevSimulator:DataDirectory).
DEFAULT_DB = os.path.join(REPO_ROOT, "data", "dev", "simulator", "iam.db")

# A separately cloned DOTNET_AWS_SIMULATOR, for anyone still running one.
DEFAULT_SIM_ROOT = r"C:\Users\wasim\workspace\Projects\DOTNET_AWS_SIMULATOR"

# Policies use the simulator's own lowercase property names so its dashboard renders them.
ROLES = [
    {
        "name": "GatewayPlatformAdminRole",
        "description": "Full administrative control of the Unified LLM Gateway.",
        "policies": [
            {
                "version": "2012-10-17",
                "statement": [
                    {"sid": "FullGatewayAdministration", "effect": "Allow",
                     "action": ["gateway:*"], "resource": ["*"]},
                    {"sid": "SimulatorServices", "effect": "Allow",
                     "action": ["s3:*", "kms:*", "sts:*"], "resource": ["*"]},
                ],
            }
        ],
    },
    {
        "name": "GatewayAppOwnerRole",
        "description": "Manages applications; cannot change guardrail policy, keys, or see account billing.",
        "policies": [
            {
                "version": "2012-10-17",
                "statement": [
                    {"sid": "ManageApplications", "effect": "Allow",
                     "action": [
                         "gateway:ListApplications", "gateway:GetApplication",
                         "gateway:CreateApplication", "gateway:UpdateApplication",
                         "gateway:RotateApiKey", "gateway:MintStsToken",
                         "gateway:InvokeApplication", "gateway:ReadMetrics",
                         "gateway:ListModels", "gateway:TestGuardrails",
                         "gateway:ReadGuardrailConfig",
                         # Capabilities: an application owner authors skills and attaches
                         # catalogue entries to their own applications. Registering anything that
                         # executes -- MCP servers, plugins -- stays with the platform admin.
                         "gateway:ListCapabilities", "gateway:ManageSkills",
                         "gateway:ManageAppCapabilities",
                         # Read the MCP catalogue to choose tools to attach; registering a
                         # server stays with the platform admin, since its tools execute.
                         "gateway:ReadMcpServers",
                     ],
                     "resource": ["*"]},
                    {"sid": "DenyPolicyAndKeyControl", "effect": "Deny",
                     "action": [
                         "gateway:UpdateGuardrailConfig", "gateway:RotateSigningKey",
                         "gateway:DeleteApplication", "gateway:ReadBilling",
                         "gateway:ManageMcpServers", "gateway:ManagePlugins",
                     ],
                     "resource": ["*"]},
                    {"sid": "SimulatorServices", "effect": "Allow",
                     "action": ["s3:*", "kms:*", "sts:*"], "resource": ["*"]},
                ],
            }
        ],
    },
    {
        "name": "GatewayDeveloperRole",
        "description": "Okta group UnifiedGateway-Developers: view registered applications and use the test API only.",
        "policies": [
            {
                "version": "2012-10-17",
                "statement": [
                    {"sid": "ViewAndTest", "effect": "Allow",
                     "action": [
                         "gateway:ListApplications", "gateway:GetApplication",
                         "gateway:InvokeApplication", "gateway:ListModels",
                         # Read the catalogue, but neither author nor attach.
                         "gateway:ListCapabilities",
                     ],
                     "resource": ["*"]},
                    {"sid": "DenyEverythingElse", "effect": "Deny",
                     "action": [
                         "gateway:CreateApplication", "gateway:UpdateApplication",
                         "gateway:DeleteApplication", "gateway:RotateApiKey",
                         "gateway:MintStsToken", "gateway:RotateSigningKey",
                         "gateway:UpdateGuardrailConfig", "gateway:ReadGuardrailConfig",
                         "gateway:TestGuardrails", "gateway:ReadMetrics",
                         "gateway:ReadCredentialStatus", "gateway:ReadBilling",
                         "gateway:ManageSkills", "gateway:ManageAppCapabilities",
                         "gateway:ManageMcpServers", "gateway:ManagePlugins",
                     ],
                     "resource": ["*"]},
                ],
            }
        ],
    },
    {
        "name": "GatewayAuditorRole",
        "description": "Read-only access for audit and compliance review, including billing.",
        "policies": [
            {
                "version": "2012-10-17",
                "statement": [
                    {"sid": "ReadOnly", "effect": "Allow",
                     "action": [
                         "gateway:ListApplications", "gateway:GetApplication",
                         "gateway:ReadMetrics", "gateway:ReadGuardrailConfig",
                         "gateway:ReadCredentialStatus", "gateway:ListModels",
                         "gateway:ReadBilling",
                     ],
                     "resource": ["*"]},
                    {"sid": "DenyEverythingThatChangesState", "effect": "Deny",
                     "action": [
                         "gateway:CreateApplication", "gateway:UpdateApplication",
                         "gateway:DeleteApplication", "gateway:RotateApiKey",
                         "gateway:MintStsToken", "gateway:RotateSigningKey",
                         "gateway:UpdateGuardrailConfig", "gateway:InvokeApplication",
                     ],
                     "resource": ["*"]},
                ],
            }
        ],
    },
]


def provision_roles(db_path):
    print(f"\nIAM roles  ({db_path})")

    if not os.path.exists(db_path):
        print("  ! iam.db not found. Start IamLocal once so it creates the database, then re-run.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    try:
        for role in ROLES:
            arn = f"arn:aws:iam::{ACCOUNT}:role/{role['name']}"
            policies = json.dumps(role["policies"], separators=(",", ":"))

            existing = conn.execute(
                "SELECT Id FROM Roles WHERE lower(Name) = lower(?)", (role["name"],)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE Roles SET Arn = ?, Description = ?, PoliciesJson = ? WHERE Id = ?",
                    (arn, role["description"], policies, existing[0]),
                )
                state = "updated"
            else:
                conn.execute(
                    "INSERT INTO Roles (Id, Name, Arn, Description, PoliciesJson) VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), role["name"], arn, role["description"], policies),
                )
                state = "created"

            allows = sum(len(s["action"]) for p in role["policies"]
                         for s in p["statement"] if s["effect"] == "Allow")
            denies = sum(len(s["action"]) for p in role["policies"]
                         for s in p["statement"] if s["effect"] == "Deny")
            print(f"  - {role['name']}: {state}  ({allows} allow, {denies} deny)")

        conn.commit()
    finally:
        conn.close()


def verify(iam_url):
    """Assume each role and confirm the policies come back scoped rather than Allow */*."""
    print("\nVerification (via /assume-role)")

    for role in ROLES:
        body = json.dumps({"RoleName": role["name"], "DurationSeconds": 900}).encode()
        req = urllib.request.Request(
            f"{iam_url}/assume-role", data=body, method="POST",
            headers={"Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                jwt = json.loads(resp.read())["jwt"]
        except urllib.error.URLError as e:
            print(f"  ! {role['name']}: cannot reach IamLocal ({e.reason})")
            continue

        payload = jwt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        import base64
        claims = json.loads(base64.urlsafe_b64decode(payload))
        policies = json.loads(claims.get("policies", "[]"))

        actions = [a for p in policies for s in p.get("statement", []) for a in s.get("action", [])]
        wildcard = "*" in actions
        print(f"  - {role['name']}: {len(actions)} actions"
              f"{'  ! still wildcard' if wildcard else '  scoped'}")


def main():
    parser = argparse.ArgumentParser(description="Provision the .NET AWS simulator for the gateway.")
    parser.add_argument("--db", default=None,
                        help="IamLocal's SQLite database (default: the bundled simulator's).")
    parser.add_argument("--sim-root", default=None,
                        help="A separately cloned DOTNET_AWS_SIMULATOR to provision instead.")
    parser.add_argument("--iam", default="http://localhost:5103")
    args = parser.parse_args()

    if args.db:
        db_path = args.db
    elif args.sim_root:
        db_path = os.path.join(args.sim_root, "src", "IamLocal", "Data", "iam.db")
    else:
        db_path = DEFAULT_DB

    print("Provisioning the .NET local AWS simulator for the Unified LLM Gateway")
    print(f"  IamLocal database: {db_path}")

    provision_roles(db_path)
    verify(args.iam)

    print("\nDone. Start the gateway with:")
    print("  ASPNETCORE_ENVIRONMENT=Development dotnet run --no-launch-profile")


if __name__ == "__main__":
    main()
