"""mitmweb addon: label every token on a flow with its SPEC §3 name (T1…T7) and fingerprint.

For each flow it looks at the Authorization header, JSON request bodies (identity calls carry
userToken / workloadIdentityToken), and token-endpoint responses. JWTs are labelled from their
claims (aud / azp / iss). Opaque tokens are labelled by context (Jira → T4/T5). The result goes
in the flow comment, and the flow is marked. Nothing is stored. The fingerprints match the ledger,
so you can jump between mitmweb and /ledger.
"""

import base64
import hashlib
import json

from mitmproxy import http

GATEWAY_AUD = "https://gateway.localtest.me/mcp"


def fp(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()[:12]


def claims(tok: str) -> dict | None:
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return None


def label_jwt(c: dict) -> str:
    aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
    azp = c.get("azp") or c.get("client_id")
    if c.get("aud") == "identity:workload-access":
        return "T3"
    if azp in ("gateway-svc", "portal-svc"):
        return "T7"
    if GATEWAY_AUD in aud:
        return "T1"
    if "portal" in aud:
        return "T2"
    if c.get("typ") == "ID":
        return "id_token"
    return "JWT"


def label(tok: str, host: str, field: str = "") -> str:
    c = claims(tok)
    if c is not None:
        return f"{label_jwt(c)}:{fp(tok)}"
    if field == "refresh_token":
        return f"T5:{fp(tok)}" if "jira" in host else f"refresh:{fp(tok)}"
    if "jira" in host:
        return f"T4:{fp(tok)}"
    return f"opaque:{fp(tok)}"


class TokenLabeler:
    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        seen: list[str] = []
        auth = flow.request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            seen.append("→ " + label(auth[7:].strip(), host))
        if "json" in flow.request.headers.get("content-type", ""):
            try:
                body = json.loads(flow.request.get_text() or "{}")
                for k in ("userToken", "workloadIdentityToken"):
                    v = body.get(k) or (body.get("userIdentifier") or {}).get(k)
                    if isinstance(v, str):
                        seen.append(f"→ {k} " + label(v, host))
            except (ValueError, AttributeError):
                pass
        if flow.response and "json" in flow.response.headers.get("content-type", ""):
            try:
                body = json.loads(flow.response.get_text() or "{}")
                for k in ("access_token", "refresh_token", "accessToken", "workloadAccessToken", "id_token"):
                    if isinstance(body.get(k), str):
                        resp_host = host
                        if k == "accessToken":
                            resp_host = "jira"  # identity hands out Jira tokens (T4)
                        seen.append(f"← {k} " + label(body[k], resp_host, k))
            except (ValueError, AttributeError):
                pass
        if seen:
            flow.comment = "  ".join(seen)
            flow.marked = ":key:"


addons = [TokenLabeler()]
