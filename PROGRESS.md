# Progress

Living status for the build described in [SPEC.md](SPEC.md). The architecture and token-flow view, with per-step verification markers, is in [docs/architecture.md](docs/architecture.md). Update this file in the same commit as the work it describes.

**Current phase:** 4, End-to-end 3LO (🟨 automated checks pass; waiting on the manual S4 run in Claude Code)
**Last updated:** 2026-11-19

---

## Phases

Legend: ⬜ not started · 🟨 in progress · ✅ done · ⏸ blocked

| Phase | Status | Exit criteria (SPEC §10) | Notes |
|---|---|---|---|
| 0. Edge & IdP | ✅ | Trusted-TLS login to `idp.localtest.me`. DCR via curl works | `make check`: 15/15. Browser login as alice automated over the real login + consent pages with the Caddy CA pinned. Survives `make down && make up`. Manual check done 2026-11-19: `make trust`, then a browser login as alice at https://idp.localtest.me/realms/playground/account over trusted TLS |
| 1. Gateway shell | ✅ | S1, S2, S14: Claude Code connects, `whoami` shows claims | `make check1`: 25/25 (S1 + S14 + session binding + ledger + invariant 6). S2 done in Claude Code 2.1.328. Observations in `docs/clients.md` |
| 2. Stub downstream | ✅ | Manual PKCE flow returns T4. `/search` filtered per user | `make check2`: 36/36 and repeatable. Jira persona: OAuth provider (PKCE, rotation, both client auth methods, scope hierarchy), login/consent/profile pages, REST v2 subset with Jira-style hiding, PATs, faults. Fidelity assumptions F1–F27 in `docs/stub-fidelity.md` |
| 3. Identity + vault | ✅ | Scripted Flow B without gateway. S9 | `make check3`: 36/36, repeatable, passes after `make down && make up`. The script plays gateway (gateway-svc) and portal (portal-svc + T2) |
| 4. End-to-end 3LO | 🟨 | S3, S4, S5, S8, S15, S18 | `make check4`: 30/30. All five checks pass together. **S4 (Claude Code) pending.** Runbook: `docs/clients.md` §S4 |
| 5. Lifecycle & attacks | ⬜ | S6, S7, S10–S13, S16, S17, S19 | |
| 6. More clients & sources | ⬜ | S20, Confluence tools | |
| 7. Second IdP | ⬜ | Design record + one §12 option working | |
| 8. AWS port | ⬜ | §11 checklist answered (separate spec) | |

## Acceptance scenarios (SPEC §8)

| # | Status | Result / evidence |
|---|---|---|
| S1 | ✅ | `make check1`: 401 → PRM via `resource_metadata` → RFC 8414 AS metadata → DCR → PKCE with challenge scope → initialize → tools/list → whoami=alice |
| S2 | ✅ | 2026-11-19, Claude Code 2.1.328: DCR as "Claude Code (atlassian-playground)", browser login + consent as alice, `gateway___whoami` → alice (ledger 14:21:16, azp b8bb83e8…). Details: docs/clients.md |
| S3 | ✅ | `check4`: first `jira___search_issues` → isError + link → Jira login/consent → identity → portal (silent SSO) → binding → retry → ALPHA only |
| S4 | 🟨 | First run (16:52–16:55): Claude Code **declares `elicitation.url`** → got -32042. It exposed two gaps, both now fixed: a dead vaulted T4 (left by check4's revoke-all) looped 401 → link and the portal showed Connected; and a declined elicitation lost the link. **Re-run needed** after the fixes |
| S5 | ✅ | `check4`: repeat calls (search, get_issue) with no consent. BETA-1 → 404 tool error, JQL on BETA → 'does not exist' |
| S6 | 🟨 | Identity level ✅ (`check3`): a stale T4 is refreshed transparently and the rotated T5 stored. Through the gateway: phase 4–5 |
| S7 | 🟨 | Identity level ✅ (`check3`): 10 concurrent requests → exactly 1 refresh at Jira (row lock), 9 vault hits, same T4. Through the gateway: phase 5 |
| S8 | ✅ | `check4`: bob consents separately (via -32042 URL elicitation), sees BETA only. alice unaffected. 2 vault rows |
| S9 | ✅ | `check3`: bob's T2 completing alice's session → 403 `binding.mismatch`. Session FAILED, parked T4/T5 wiped, nothing stored, and alice can't reuse the session |
| S10 | ⬜ | |
| S11 | ⬜ | |
| S12 | ✅ | `check4`: dave → link → Jira login fails → no vault row. Later calls still return a clean consent link |
| S13 | 🟨 | Stub ✅, identity purge ✅ (`check3`), gateway C6 ✅ (`check4`: Jira 401 → `downstream.unauthorized` → new consent link). Disable-user/offline-session aspects: phase 5 |
| S14 | ✅ | `make check1`: 5 bad tokens → 401, each with a ledger reason (audience ×3, bad signature, untrusted issuer). Keycloak refuses `mcp:tools` to portal. Bob's token on alice's session → 404 |
| S15 | ✅ | `check4`: no T1 fp in any Jira api event. Gateway downstream fps = Jira api.call fps. mitmweb labels every Jira API call `→ T4` |
| S16 | 🟨 | `check4`: add_comment with READ → WRITE consent link → consent → comment as alice. READ then works without re-consent (scopeHierarchy). Phase 5 for edge cases |
| S17 | ⬜ | |
| S18 | ✅ | `check4`: carol connects in the portal (Jira user carol.w) → first MCP call needs no consent → ALPHA+BETA |
| S19 | ✅ | All 4 service logs + the ledger DB contain no raw tokens (`check4`, plus check1–3 per service). Access logs turned off where callback URLs carry codes |
| S20 | ⬜ | |

## Risks to verify (SPEC §11)

| Risk | Status | Finding |
|---|---|---|
| R1 Network reachability of Jira DC from AgentCore | open | |
| R2 Gateway 3LO surface to MCP clients | open | |
| R3 Gateway PRM discovery / multiple issuers | open | |
| R4 Jira DC OAuth specifics (check by hand on real instance) | open | The stub encodes 27 assumptions as a checklist: `docs/stub-fidelity.md` F1–F27. Fill it in on the real instance |
| R5 Entra + off-the-shelf clients | open | |
| R6 Identity alignment across RH SSO / Entra / Jira | open | |

---

## Discoveries log

Newest first. Record anything learned while building that differs from or adds to the spec. If it changes the design, also edit SPEC.md and add a line to its changelog (SPEC §14).

| Date | Phase | Discovery | Spec impact |
|---|---|---|---|
| 2026-11-19 | 4 | **S4 found a dead-token loop.** After a downstream 401 the gateway forced a new consent, but **the revoked T4 stayed in the vault**. Every later call hit it, got 401 and minted another consent session, and the portal showed "Connected". Fix: `x-ResourceTokenRejected`: identity refreshes once under the row lock, otherwise purges. Fingerprint-matched, so a stale report can't delete a newer token. Question for AWS (R2): what does AgentCore do here? | §6.2, §6.3, §11 R2 |
| 2026-11-19 | 4 | **Claude Code 2.1.328 declares `capabilities.elicitation.url`**, so it gets JSON-RPC -32042, not the isError text. -32042 is one-way: **if the user declines or dismisses the prompt, the server never knows**, and the link was gone. Fix: the link also goes in the error `message`. (Alternative not taken: in-band `elicitation/create` via `ctx.elicit_url()`, which does return accept/decline but blocks the tool call while the user decides.) | §6.2 |
| 2026-11-19 | 4 | `check4`'s C6 step revokes every grant in Jira, which **left dead tokens in the vault for later manual runs**. That's how S4 hit the loop. `check4` now empties the vault at the end. | — |
| 2026-11-19 | 4 | **Uvicorn access logs recorded one-time OAuth `code` + `state`** from callback URLs (portal `/callback`, identity `/identities/oauth2/callback`). Short-lived, but credentials, so access logs are now off for identity and portal. The ledger records the events without secrets. Production: make sure ALB/CloudFront/API Gateway access logs on the return-URL app don't keep query strings. | §6.4 |
| 2026-11-19 | 4 | **H3 is silent end to end through the real portal** (scripted browser, non-offline login): the user saw only Jira's login and consent. The portal re-authenticates on every return, so binding always uses a fresh T2 and **the portal stores no tokens at all**. | §3 T2, §6.4 |
| 2026-11-19 | 4 | MCP SDK 2.3 surfaces `ToolError` as `isError: true` with text prefixed *"Error executing tool <name>: "*. `UrlElicitationRequiredError` becomes a top-level JSON-RPC error (-32042), not a tool result. Which one a client gets depends only on its declared `capabilities.elicitation.url`. | §6.2 |
| 2026-11-19 | 4 | **Disconnect in the portal only forgets vaulted tokens.** Jira DC has no revocation API (F16/F17), so an issued T4 keeps working at Jira until it expires (≈2 h) unless the user revokes in Jira. That's a real gap for "remove access now" requests. | §6.4, stub-fidelity |
| 2026-11-19 | 4 | C6 is implemented as "Jira 401 → force a new consent". It doesn't first try a forced refresh, because with rotation-on-revoke semantics a refresh after a 401 would fail anyway. Revisit in phase 5. | §6.2 |
| 2026-11-19 | 4 | Starlette form parsing needs `python-multipart`: the portal's POSTs returned 500 until it was added. Found by `check4` (S18). | — |
| 2026-11-19 | 3 | **The portal needs two Keycloak identities.** A user-login client (`portal`, T2 `aud=portal`) and a separate service client (`portal-svc`) for calling identity. With one client, a user's T2 would also carry the identity audience and could pass as the portal service. In AWS the portal's IAM role does this job. | §6.1, §6.3 |
| 2026-11-19 | 3 | **Portal login (H3) was silent** after a scripted MCP login (no `offline_access`) in the same browser, because the Keycloak SSO cookie carried over. Still to confirm with Claude Code's `offline_access` login (phase 4). | architecture §2 |
| 2026-11-19 | 3 | Keycloak puts `account` in `aud` on service, portal and user tokens (default roles). It's harmless because every check names its own audience, but tokens are broader than they look. | §6.1 |
| 2026-11-19 | 3 | **AAD matters:** without binding the ciphertext to `workload\|user\|provider`, anyone with DB write access could copy alice's encrypted token into bob's row and identity would hand it to bob. With AAD, the tag check fails and the row is purged (`check3`). AgentCore's vault internals aren't visible, so this is a design principle to ask AWS about, not something we can verify there. | §6.3 |
| 2026-11-19 | 3 | Parked tokens (between callback and binding) are a distinct state, `PENDING_BINDING`. Without it, the callback would have to write to the vault for whoever *started* the flow, before knowing who finished it. That is exactly the consent-hijack hole S9 tests. | §6.3 |
| 2026-11-19 | 3 | Scope comparison needs provider knowledge (Jira WRITE ⊇ READ). Without it, a WRITE grant would force re-consent for READ. Added `x-playground.scopeHierarchy`. How AgentCore keys or compares scopes in its vault is an open question for R2/R4. | §6.3, §11 |
| 2026-11-19 | 3 | Identity reaches OpenBao directly, bypassing mitmproxy, because transit responses contain plaintext data keys. Its traffic to Jira's token endpoint **does** go through mitmproxy, so **mitmweb shows raw T4/T5 in token responses**. That's deliberate: it's the "attacker on the wire" view, kept local. | §6.3, §7 |
| 2026-11-19 | 2 | The stub hides what the user can't see the way Jira does (JQL on a project you can't browse → 400 "does not exist", issue → 404). **The MCP tools will see the same.** Tool errors must not reveal whether a project exists. | §6.5 |
| 2026-11-19 | 2 | Each consent creates a **separate grant** in the stub, so repeated consents pile up as several "Authorized applications" entries. Real DC behaviour is unknown (F15). Identity should reuse its vault entry rather than re-consent needlessly. | §6.5, stub-fidelity F15 |
| 2026-11-19 | 2 | After rotation the **old access token stays valid until it expires** (stub assumption F10). So revoking at the vault doesn't kill an issued T4. Only revoking in Jira does. Relevant to S13/S17. | §6.5, stub-fidelity F10 |
| 2026-11-19 | 2 | Atlassian app link credentials come from `.env` (`JIRA_OAUTH_CLIENT_ID/SECRET`). `make env` now **adds missing keys** to an existing `.env` (`scripts/env_sync.sh`) so later phases can add secrets without a reset. | §6.5 |
| 2026-11-19 | 1 | **Claude Code requests `offline_access`** as well as `mcp:tools`. Keycloak then creates an **offline session only**: the refresh token outlives SSO idle/max limits and logout. This matters for revocation (S13) and user disable (S17). Production RH SSO/Entra policy on offline tokens for MCP clients should be decided deliberately. | §6.1 (open), §8 S17 |
| 2026-11-19 | 1 | **Keycloak doesn't enforce PKCE for DCR-registered clients.** The anonymous DCR policies don't set `pkce.code.challenge.method`. Hardening item: add a realm client policy with the `pkce-enforcer` executor (S256) for all clients. | §6.1 (todo) |
| 2026-11-19 | 1 | Project `.mcp.json` approval is saved in `.claude/settings.local.json`. Choosing "don't use" puts the server in `disabledMcpjsonServers` and **silently hides it from `/mcp`**. Approving it doesn't start auth either: the user has to go to `/mcp` → Authenticate. | docs/clients.md |
| 2026-11-19 | 1 | Claude Code here is a native binary (not Node), but `NODE_EXTRA_CA_CERTS` still works. | §2 |
| 2026-11-19 | 1 | Keycloak leaves out `aud` **entirely** when no audience mapper applies, so PyJWT reports `MissingRequiredClaimError`. The authorizer now logs it as "missing required claim 'aud'". | — |
| 2026-11-19 | 1 | **MCP Python SDK is now 2.x (2.3.0)**: `FastMCP` → `mcp.server.mcpserver.MCPServer`. It depends on **`httpx2`** (a fork) rather than `httpx`, and it adds protocol version 2026-07-28 with multi-round-trip `InputRequiredResult`. Phase 4's consent-elicitation design should be checked against that. | §6, §6.2 |
| 2026-11-19 | 1 | The SDK provides resource-server plumbing (PRM at the **path-suffixed** `/.well-known/oauth-protected-resource/mcp`, 401/403 with `resource_metadata`), but **leaves `scope` out of `WWW-Authenticate`** (the MCP spec says SHOULD include it). We add it with an ASGI wrapper. `AuthSettings.validate_token_resource` will default to True in SDK 3.0, which would break with Keycloak (no RFC 8707 `resource` binding), so it is set explicitly to False and our verifier checks `aud`. | §6.2 |
| 2026-11-19 | 1 | The PRM generated by the SDK lists only **one** authorization server (`AuthSettings.issuer_url`). A second IdP (phase 7) needs our own PRM route. The root PRM route already lists all configured issuers. | §6.2, §12 |
| 2026-11-19 | 1 | Keycloak returns **`invalid_scope`** when a client requests a scope that isn't assigned to it (portal + `mcp:tools`), rather than silently dropping it. That's a stronger guarantee than expected. | §6.1, §8 S14 |
| 2026-11-19 | 1 | The SDK binds an MCP session to its principal. Another user's valid token on that `Mcp-Session-Id` gets **404**, not 403. | §6.2 |
| 2026-11-19 | 1 | Off-the-shelf flow: a client that asks only for `mcp:tools` (no `openid`) gets no ID token. The gateway never needs one. | — |
| 2026-11-19 | 1 | The gateway's outbound discovery/JWKS calls do go through mitmproxy, which intercepts TLS and trusts the Caddy CA. They show up in mitmweb (`/flows` API accepts `Authorization: Bearer <MITM_WEB_PASSWORD>`). JWKS is cached, and an untrusted-issuer token is refused with no network call. | — |
| 2026-11-19 | 0 | **Keycloak 26.8.1 serves RFC 8414 path-inserted AS metadata natively** (`/.well-known/oauth-authorization-server/realms/playground`), but not the path-inserted `openid-configuration`. MCP clients try the former first, so no proxy rewrite is needed. The production RH SSO version must be checked: older builds may need a rewrite. | §6.1 |
| 2026-11-19 | 0 | **Keycloak ignores RFC 8707 `resource`** (accepted, not advertised, no effect). Audience comes only from the `mcp:tools` scope's audience mapper. | §6.1 (gap confirmed) |
| 2026-11-19 | 0 | `mcp:tools` must be a realm **optional** scope, not default. As a default it would put the gateway `aud` on every client's tokens, including the portal's, which breaks audience separation (S14). It is also removed explicitly from portal/gateway-svc/identity. | §6.1 changed |
| 2026-11-19 | 0 | No CIMD advertised by Keycloak. MCP clients will use DCR. DCR trusted-hosts must use `client-uris-must-match` rather than sender-host matching, because registration requests arrive via the proxy. | §6.1 |
| 2026-11-19 | 0 | Keycloak 24+ declarative user profile silently drops unmanaged attributes, so `jira_username` has to be declared in the user profile. | §6.1 |
| 2026-11-19 | 0 | OpenBao 2.x removed `file` storage, so Raft is used instead. After unseal, the node must win Raft leadership before writes succeed (`cannot write to readonly storage`), so the bootstrap waits for `/sys/health`=200. The init response key is `keys_base64`. | §6.6 changed |
| 2026-11-19 | 0 | Realm config is reconciled by a script instead of a JSON import, so it can evolve without volume wipes. Keycloak returns 409 when re-adding an existing realm default scope, so the script checks before adding. | §6.1, §9 |
| 2026-11-19 | 0 | Runtime is **Colima** (4 CPU / 8 GB) with the Homebrew docker CLI + compose plugin (`~/.docker/config.json` `cliPluginsExtraDirs`). Binding host port 443 works without sudo. | — |

## Pinned versions
Caddy 2.11.8 · Postgres 16.16 · psycopg 3.3.9 · cryptography 50.0.2 · Keycloak 26.8.1 · OpenBao 2.7.1 · mitmproxy 12.3.0 · uv 0.13.8 (python 3.12, trixie) · mcp 2.3.0 · httpx2 2.16.2 · PyJWT 2.15.1 · uvicorn 0.54.0

## How to run
After a reboot, run `colima start` first (the Docker runtime). Then `make up` → `make trust` (once) → `make check` (all phases) or `make check0` … `check4`. Portal: https://portal.localtest.me (Connected apps, Token ledger). Identity admin view: `curl -H "X-Identity-Admin: $IDENTITY_ADMIN_TOKEN" https://identity.localtest.me/admin/vault`. Jira stub UI: https://jira.localtest.me/secure/ViewProfile.jspa (Jira users alice / bob / carol.w). `make ledger` follows token events. `make claude` starts Claude Code trusting the local CA. `make claude ARGS=--continue` resumes the previous session with the same trust. `make help` lists all targets. Credentials are in `.env` (generated by `make env`). Seed users: alice/bob/carol/dave with `SEED_USER_PASSWORD`.

## Next up
- **S4 re-run (you), after the fixes:** `make claude` (second terminal) → `/mcp` → reconnect `atlassian-playground` if needed → ask "list my Jira issues" → open the link → Jira login (alice) + Allow → "Jira connected" → ask again. Then fill in the S4 table in `docs/clients.md`. Watch: `make ledger`, https://portal.localtest.me/ledger, mitmweb http://localhost:8081.
- Then phase 5: lifecycle and attacks through the gateway (S6, S7, S10, S11, S13, S16, S17). Backlog: PKCE enforcer, offline_access policy, Claude Code token churn, verify mode (§5.2).
- **You (any time):** go through `docs/stub-fidelity.md` against the real Jira DC and record the answers.
- Backlog (phase 5 hardening): enforce PKCE S256 for all clients through a Keycloak client policy. Decide the `offline_access` policy for MCP clients. Investigate Claude Code's token churn (4 tokens in 22 s).
