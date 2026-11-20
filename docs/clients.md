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
   Approve it when Claude Code asks. **Careful:** the answer is saved in `.claude/settings.local.json`. If you pick
   "don't use", the server goes into `disabledMcpjsonServers` and silently disappears from `/mcp`. To fix it, move it to
   `enabledMcpjsonServers` and restart Claude Code. If you want it outside this repo instead:
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

### Observed (S2, 2026-11-19)
| Item | Observed |
|---|---|
| Claude Code version | 2.1.328, **native build** (Mach-O binary, not the npm/Node package). It still honours `NODE_EXTRA_CA_CERTS` |
| Approval | Approving the project server doesn't connect anything visibly. You have to go to `/mcp` → Authenticate. No browser opens on its own |
| Discovery | `GET /.well-known/oauth-protected-resource/mcp` (path-suffixed, from `WWW-Authenticate`) ×8, root form ×1. Several unauthenticated `POST /mcp` → 401 before auth |
| DCR registration | `client_name` "Claude Code (atlassian-playground)", public client (`token_endpoint_auth_method: none`), redirect `http://localhost:<random port>/callback` (here 63889). It got Keycloak's DCR defaults: `consentRequired: true`, optional scopes `mcp:tools` + `offline_access` |
| Scope requested | `mcp:tools offline_access` (token scope: `mcp:tools offline_access profile email`). **`offline_access` gives an offline session in Keycloak, with no normal SSO session** |
| PKCE | Keycloak does **not** enforce PKCE for DCR clients (`pkce.code.challenge.method` unset). Whether Claude Code sent it can't be seen, because client traffic isn't proxied |
| `resource` parameter | Not observed (client traffic isn't proxied, and Keycloak ignores it anyway) |
| Tokens at the gateway | 4 distinct access-token fingerprints in about 22 s for one login + one tool call. Possibly a refresh per reconnect: investigate in phase 5 |
| Where tokens are stored | Client-side (Claude Code credential store), not inspected |
| Behaviour when T1 expires (5 min) | Not yet observed |
| Result | `gateway___whoami` → alice, `azp` = the DCR client id, `scope` includes `mcp:tools` ✅ |

## Claude Code end to end (S4)

### Steps
1. Stack up (`make up`), CA trusted, Claude Code started with `make claude` (second terminal).
2. `/mcp` → `atlassian-playground` should show its tools (`jira___*`). If it says reconnect/needs auth, Authenticate as **alice**.
3. Ask: *"List my Jira issues"*.
   - The gateway can't use a Jira token yet, so it signals consent. Note **which signal** Claude Code shows: a URL-elicitation prompt (`-32042`) or the tool error text with a link.
4. Open the link. Jira login as **alice** (password `SEED_USER_PASSWORD`), then **Allow**. You should land on the portal saying **"Jira connected"**. Note whether you were asked to log in to Keycloak again (H3).
5. Back in Claude Code: *"try again"*. Expect ALPHA-1..3 only.
6. Optional: *"add a comment to ALPHA-2 saying hello"* → a WRITE consent link → Allow → retry → the comment is added as alice.
7. Look at https://portal.localtest.me/ledger (last 15 min) and mitmweb (http://localhost:8081, labels in the comment column).

### Observed (S4, fill in)
| Item | Observed |
|---|---|
| Claude Code version | 2.1.328 |
| Declares `elicitation.url`? (ledger `consent.signalled mode=`) | **Yes**: `mode=url_elicitation` (run 1, 16:52–16:55) |
| How the consent link was presented | URL-elicitation prompt (-32042) showing the long URL. **Enter = decline** (run 3). Declined → Claude Code doesn't pass the error message on, so the link never reaches the chat (run 2). Opening the URL from the prompt (copy/Cmd-click) → Jira consent → binding ✅ (run 3, 10:26) |
| After consent completed | Run 3: prompt stuck on **"Reopen URL"**, because the gateway didn't send `notifications/elicitation/complete`. Fixed. Re-test: does it clear by itself? |
| `consentSignal: tool_error` (link in chat) | not yet tried |
| Did the model retry on its own after consent? | (re-test with the completion notification) |
| H3: Keycloak login prompt at the portal? | |
| Result after consent | Via **portal pre-consent** (Connected apps → Connect → Jira login/Allow → 'Jira connected'): the next call returned alice's issues (ALPHA-1, ALPHA-3 assigned to her) ✅ |
| WRITE step-up (optional) | |
