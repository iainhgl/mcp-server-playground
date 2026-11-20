"""Configuration from the environment (set in docker-compose.yml)."""

import os


def _req(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"missing env {name}")
    return v


SERVICE = "identity"
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://identity.localtest.me")
CALLBACK_URL = f"{PUBLIC_URL}/identities/oauth2/callback"
DATABASE_URL = _req("DATABASE_URL")
BAO_ADDR = os.environ.get("BAO_ADDR", "http://openbao:8200")
BAO_TOKEN_FILE = os.environ.get("BAO_TOKEN_FILE", "/secrets/token")
BAO_TRANSIT_KEY = os.environ.get("BAO_TRANSIT_KEY", "vault-dek")
ADMIN_TOKEN = _req("IDENTITY_ADMIN_TOKEN")  # control plane (≈ IAM admin on bedrock-agentcore-control)
WAT_KEY = _req("IDENTITY_WAT_KEY").encode()  # signs workload access tokens (T3)
WAT_TTL = 300
SESSION_TTL = 600  # T6: a 3LO session must complete within 10 min
REFRESH_SKEW = 30  # treat T4 as expired 30 s early

IDP_DISCOVERY_URL = _req("IDP_DISCOVERY_URL")
# Who may call the data plane (service tokens, aud=identity), and which operations (≈ IAM policy).
CALLER_ACL: dict[str, set[str]] = {
    "GetWorkloadAccessTokenForJWT": {"gateway-svc"},
    "GetWorkloadAccessTokenForUserId": {"portal-svc"},
    "GetResourceOauth2Token": {"gateway-svc", "portal-svc"},
    "CompleteResourceTokenAuth": {"portal-svc"},
    # Playground extensions (no AgentCore equivalent).
    "x-ResourceTokenRejected": {"gateway-svc"},  # C6: downstream returned 401 for a vaulted T4
    "x-GetConsentSessionStatus": {"gateway-svc"},  # so the gateway can send notifications/elicitation/complete
    "x-ListUserConnections": {"portal-svc"},
    "x-DeleteUserConnection": {"portal-svc"},
}
# Which user tokens identity accepts as `userToken`: the gateway token (T1) or the portal token (T2).
USER_TOKEN_AUDIENCES = os.environ.get("USER_TOKEN_AUDIENCES", "https://gateway.localtest.me/mcp,portal").split(",")

# Verify mode (SPEC §5.2): at binding, check the downstream account (/myself) against the user's claim.
VERIFY_DOWNSTREAM = os.environ.get("IDENTITY_VERIFY_DOWNSTREAM", "true").lower() == "true"
