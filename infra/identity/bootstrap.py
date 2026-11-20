# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Configure identity the way an operator would in AWS (console/Terraform against
bedrock-agentcore-control). Idempotent, so it runs on every `up`.

- workload identity `gateway`, allowed to send users back to the portal's return URL
- OAuth2 credential provider `jira-dc` (CustomOauth2). Jira DC has no discovery document,
  so the authorization server metadata is given explicitly. The client id/secret are the
  ones from the Jira incoming application link.
"""

import os
import sys
import time

import httpx

IDENTITY = os.environ.get("IDENTITY_URL", "http://identity:8001")
H = {"X-Identity-Admin": os.environ["IDENTITY_ADMIN_TOKEN"]}


def call(op: str, body: dict) -> dict:
    r = httpx.post(f"{IDENTITY}/identities/{op}", json=body, headers=H, timeout=15)
    if r.is_error:
        sys.exit(f"[identity-init] {op} → {r.status_code} {r.text}")
    return r.json()


def main() -> None:
    for _ in range(60):
        try:
            if httpx.get(f"{IDENTITY}/healthz", timeout=2).status_code == 200:
                break
        except httpx.TransportError:
            pass
        time.sleep(1)
    else:
        sys.exit("[identity-init] identity not reachable")

    call("CreateWorkloadIdentity", {
        "name": "gateway",
        "allowedResourceOauth2ReturnUrls": ["https://portal.localtest.me/oauth/return"],
    })
    out = call("CreateOauth2CredentialProvider", {
        "name": "jira-dc",
        "credentialProviderVendor": "CustomOauth2",
        "oauth2ProviderConfigInput": {"customOauth2ProviderConfig": {
            "oauthDiscovery": {"authorizationServerMetadata": {
                "issuer": "https://jira.localtest.me",
                "authorizationEndpoint": "https://jira.localtest.me/rest/oauth2/latest/authorize",
                "tokenEndpoint": "https://jira.localtest.me/rest/oauth2/latest/token",
                "responseTypes": ["code"],
            }},
            "clientId": os.environ["JIRA_OAUTH_CLIENT_ID"],
            "clientSecret": os.environ["JIRA_OAUTH_CLIENT_SECRET"],
        }},
        # Playground extension (not an AgentCore field): Jira scopes are hierarchical.
        "x-playground": {
            "scopeHierarchy": ["READ", "WRITE", "ADMIN", "SYSTEM_ADMIN"],
            # §5.2 verify mode: the Jira account that consented must equal the user's jira_username claim.
            "verifyIdentity": {"url": "https://jira.localtest.me/rest/api/2/myself", "field": "name",
                               "claim": "jira_username"},
        },
    })
    print(f"[identity-init] workload gateway + provider jira-dc ready; callbackUrl={out['callbackUrl']}", flush=True)


if __name__ == "__main__":
    main()
