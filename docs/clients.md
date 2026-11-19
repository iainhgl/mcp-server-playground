# MCP clients: setup and observed behaviour

SPEC §6.7. Record what each real client actually does here (S2, S4, S20).

## Claude Code (S2)

### Setup
1. The stack is up: `make up`.
2. Start Claude Code from this repo with `make claude`. Claude Code runs on Node, which ignores the macOS keychain, so
   `make claude` sets `NODE_EXTRA_CA_CERTS=certs/caddy-root.crt`. Without it, discovery fails with a TLS error.
   - `make claude ARGS=--continue` resumes your last session with the CA trusted.
   - To make this permanent, add `export NODE_EXTRA_CA_CERTS=<repo>/certs/caddy-root.crt` to your shell profile.
3. The repo's `.mcp.json` declares the server `atlassian-playground` → `https://gateway.localtest.me/mcp`.
   Approve it when Claude Code asks. If you want it outside this repo instead:
   `claude mcp add --transport http atlassian-playground https://gateway.localtest.me/mcp`
4. Run `/mcp`, pick `atlassian-playground`, then **Authenticate**. The browser opens the Keycloak login. Log in as
   `alice` (password `SEED_USER_PASSWORD` in `.env`) and approve the consent screen.
5. Ask: *"call gateway___whoami"*. Expect `preferred_username: alice` and `scope` including `mcp:tools`.

### What to watch while you do it
- `make ledger`: gateway `inbound.rejected` (first, unauthenticated) then `inbound.validated` events.
- Keycloak admin (https://idp.localtest.me/admin, `KC_ADMIN_USER`/`KC_ADMIN_PASSWORD` from `.env`) → realm
  *playground* → Clients: the client Claude Code registered through DCR, with its redirect URI.
- mitmweb (http://localhost:8081, password `MITM_WEB_PASSWORD`): the gateway's discovery/JWKS fetches. To see Claude
  Code's own traffic as well, see `make claude-mitm` (later).

### Observed (fill in)
| Item | Observed |
|---|---|
| Claude Code version | |
| Discovery path used (PRM URL, AS metadata URL) | |
| DCR request (client_name, redirect_uris, scope, auth method) | |
| Scope requested at /authorize | |
| `resource` parameter sent? | |
| Where tokens are stored | |
| Behaviour when T1 expires (5 min) | |
