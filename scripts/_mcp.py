"""Minimal MCP Streamable-HTTP client for the checks (raw JSON-RPC, so every byte is visible)."""

import json

import httpx
from _oauth import CA, GATEWAY

PROTOCOL = "2025-11-25"


class McpSession:
    def __init__(self, token: str, capabilities: dict | None = None, name: str = "check"):
        self.token, self.sid, self._id = token, None, 0
        r = self._post("initialize", {"protocolVersion": PROTOCOL, "capabilities": capabilities or {},
                                      "clientInfo": {"name": name, "version": "0"}})
        self.init_status = r.status_code
        self.sid = r.headers.get("mcp-session-id")
        if r.status_code == 200:
            self._post("notifications/initialized", notify=True)

    def _post(self, method: str, params: dict | None = None, notify: bool = False) -> httpx.Response:
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "Authorization": f"Bearer {self.token}"}
        if self.sid:
            h |= {"Mcp-Session-Id": self.sid, "Mcp-Protocol-Version": PROTOCOL}
        body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self._id += 1
            body["id"] = self._id
        return httpx.post(GATEWAY, json=body, headers=h, verify=CA, timeout=60)

    @staticmethod
    def _msg(r: httpx.Response) -> dict:
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            return [json.loads(x[5:]) for x in r.text.splitlines() if x.startswith("data:")][-1]
        return r.json()

    def call(self, tool: str, args: dict | None = None) -> dict:
        """Returns {'error': {...}} for a JSON-RPC error, else {'isError', 'text', 'data'}."""
        m = self._msg(self._post("tools/call", {"name": tool, "arguments": args or {}}))
        if "error" in m:
            return {"error": m["error"]}
        res = m["result"]
        text = " ".join(c.get("text", "") for c in res.get("content", []))
        return {"isError": bool(res.get("isError")), "text": text, "data": res.get("structuredContent")}
