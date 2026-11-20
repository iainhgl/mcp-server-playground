"""Minimal MCP Streamable-HTTP client for the checks (raw JSON-RPC, so every byte is visible)."""

import json
import threading

import httpx
from _oauth import CA, GATEWAY

PROTOCOL = "2025-11-25"


class McpSession:
    def __init__(self, token: str, capabilities: dict | None = None, name: str = "check", protocol: str = PROTOCOL):
        self.token, self.sid, self._id, self.protocol = token, None, 0, protocol
        self.capabilities = capabilities or {}
        r = self._post("initialize", {"protocolVersion": protocol, "capabilities": capabilities or {},
                                      "clientInfo": {"name": name, "version": "0"}})
        self.init_status = r.status_code
        self.sid = r.headers.get("mcp-session-id")
        if r.status_code == 200:
            self._post("notifications/initialized", notify=True)

    def _post(self, method: str, params: dict | None = None, notify: bool = False) -> httpx.Response:
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "Authorization": f"Bearer {self.token}"}
        if self.sid:
            h |= {"Mcp-Session-Id": self.sid, "Mcp-Protocol-Version": self.protocol}
        if self.protocol >= "2026-07-28":
            h["Mcp-Method"] = method  # 2026-07-28 HTTP transport: headers mirror the body for routing
            if params and "name" in params:
                h["Mcp-Name"] = params["name"]  # e.g. the tool name on tools/call
        params = dict(params or {})
        if self.protocol >= "2026-07-28" and method != "initialize" and not notify:
            # 2026-07-28: every request carries the protocol version + client capabilities in _meta.
            params["_meta"] = {"io.modelcontextprotocol/protocolVersion": self.protocol,
                               "io.modelcontextprotocol/clientCapabilities": self.capabilities}
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            self._id += 1
            body["id"] = self._id
        return httpx.post(GATEWAY, json=body, headers=h, verify=CA, timeout=60)

    @staticmethod
    def _msg(r: httpx.Response) -> dict:
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            return [json.loads(x[5:]) for x in r.text.splitlines() if x.startswith("data:")][-1]
        return r.json()

    def listen(self) -> list[dict]:
        """Open the standalone GET /mcp SSE stream (server-initiated messages) in a background thread.
        Returns the live list that incoming JSON-RPC messages are appended to."""
        received: list[dict] = []
        h = {"Accept": "text/event-stream", "Authorization": f"Bearer {self.token}",
             "Mcp-Session-Id": self.sid, "Mcp-Protocol-Version": self.protocol}

        def run() -> None:
            try:
                with httpx.stream("GET", GATEWAY, headers=h, verify=CA, timeout=httpx.Timeout(10, read=120)) as r:
                    for line in r.iter_lines():
                        if line.startswith("data:"):
                            received.append(json.loads(line[5:]))
            except httpx.HTTPError:
                pass

        threading.Thread(target=run, daemon=True).start()
        return received

    def call(self, tool: str, args: dict | None = None, input_responses: dict | None = None) -> dict:
        """Returns {'error': {...}} for a JSON-RPC error, {'input_required': {...}} for a 2026-07-28
        InputRequiredResult, else {'isError', 'text', 'data'}. `input_responses` makes this a retry."""
        params: dict = {"name": tool, "arguments": args or {}}
        if input_responses is not None:
            params["inputResponses"] = input_responses
        m = self._msg(self._post("tools/call", params))
        if "error" in m:
            return {"error": m["error"]}
        res = m["result"]
        if res.get("resultType") == "input_required":
            return {"input_required": res}
        text = " ".join(c.get("text", "") for c in res.get("content", []))
        return {"isError": bool(res.get("isError")), "text": text, "data": res.get("structuredContent")}
