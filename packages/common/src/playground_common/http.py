"""Outbound HTTP client for server-to-server calls (SPEC §2, §6.6).

- Trust comes from explicit CA files (CA_FILES, colon-separated): the Caddy
  internal root, plus the mitmproxy CA when traffic goes through the proxy.
  It does not use the system store or certifi, so trust is visible and deliberate.
- HTTPS_PROXY / NO_PROXY come from the environment, which sends server-to-server
  traffic through mitmproxy so mitmweb shows every hop.
"""

import os
import ssl

import httpx2


def ssl_context() -> ssl.SSLContext:
    files = [f for f in os.environ.get("CA_FILES", "").split(":") if f]
    if not files:
        raise RuntimeError("CA_FILES is not set; refusing to fall back to the system trust store")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies certs + hostname by default
    for f in files:
        ctx.load_verify_locations(cafile=f)
    return ctx


def async_client(**kwargs) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(verify=ssl_context(), trust_env=True, timeout=10, **kwargs)
