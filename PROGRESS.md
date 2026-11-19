# Progress

Living status for the build described in [SPEC.md](SPEC.md). The architecture and token-flow view, with per-step verification markers, is in [docs/architecture.md](docs/architecture.md). Update this file in the same commit as the work it describes.

**Current phase:** 3, Identity + vault (not started). Phases 0–2 done
**Last updated:** 2026-11-19

---

## Phases

Legend: ⬜ not started · 🟨 in progress · ✅ done · ⏸ blocked

| Phase | Status | Exit criteria (SPEC §10) | Notes |
|---|---|---|---|
| 0. Edge & IdP | ✅ | Trusted-TLS login to `idp.localtest.me`. DCR via curl works | `make check`: 15/15. Browser login as alice automated over the real login + consent pages with the Caddy CA pinned. Survives `make down && make up`. Manual check done 2026-11-19: `make trust`, then a browser login as alice at https://idp.localtest.me/realms/playground/account over trusted TLS |
| 1. Gateway shell | ✅ | S1, S2, S14: Claude Code connects, `whoami` shows claims | `make check1`: 25/25 (S1 + S14 + session binding + ledger + invariant 6). S2 done in Claude Code 2.1.328. Observations in `docs/clients.md` |
| 2. Stub downstream | ✅ | Manual PKCE flow returns T4. `/search` filtered per user | `make check2`: 36/36 and repeatable. Jira persona: OAuth provider (PKCE, rotation, both client auth methods, scope hierarchy), login/consent/profile pages, REST v2 subset with Jira-style hiding, PATs, faults. Fidelity assumptions F1–F27 in `docs/stub-fidelity.md` |
| 3. Identity + vault | ⬜ | Scripted Flow B without gateway. S9 | |
| 4. End-to-end 3LO | ⬜ | S3, S4, S5, S8, S15, S18 | |
| 5. Lifecycle & attacks | ⬜ | S6, S7, S10–S13, S16, S17, S19 | |
| 6. More clients & sources | ⬜ | S20, Confluence tools | |
| 7. Second IdP | ⬜ | Design record + one §12 option working | |
| 8. AWS port | ⬜ | §11 checklist answered (separate spec) | |

## Acceptance scenarios (SPEC §8)

| # | Status | Result / evidence |
|---|---|---|
| S1 | ✅ | `make check1`: 401 → PRM via `resource_metadata` → RFC 8414 AS metadata → DCR → PKCE with challenge scope → initialize → tools/list → whoami=alice |
| S2 | ✅ | 2026-11-19, Claude Code 2.1.328: DCR as "Claude Code (atlassian-playground)", browser login + consent as alice, `gateway___whoami` → alice (ledger 14:21:16, azp b8bb83e8…). Details: docs/clients.md |
| S3 | ⬜ | |
| S4 | ⬜ | |
| S5 | ⬜ | |
| S6 | ⬜ | |
| S7 | ⬜ | |
| S8 | ⬜ | |
| S9 | ⬜ | |
| S10 | ⬜ | |
| S11 | ⬜ | |
| S12 | 🟨 | Stub side ✅ (`check2`): dave has no Jira account, so the Jira login fails. End to end (clean tool error, no vault row) waits for phase 4 |
| S13 | 🟨 | Stub side ✅ (`check2`): user revokes on the profile page → T4 401 `revoked`, T5 `invalid_grant`. Gateway/identity reaction waits for phase 5 |
| S14 | ✅ | `make check1`: 5 bad tokens → 401, each with a ledger reason (audience ×3, bad signature, untrusted issuer). Keycloak refuses `mcp:tools` to portal. Bob's token on alice's session → 404 |
| S15 | 🟨 | Stub side ✅ (`check2`): Keycloak T1 sent to Jira → 401. Gateway-path check waits for phase 4 |
| S16 | ⬜ | |
| S17 | ⬜ | |
| S18 | ⬜ | |
| S19 | 🟨 | Gateway part checked in `make check1` (raw T1 absent from gateway logs). Full check comes once all services exist |
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
Caddy 2.11.8 · Postgres 16.16 · Keycloak 26.8.1 · OpenBao 2.7.1 · mitmproxy 12.3.0 · uv 0.13.8 (python 3.12, trixie) · mcp 2.3.0 · httpx2 2.16.2 · PyJWT 2.15.1 · uvicorn 0.54.0

## How to run
After a reboot, run `colima start` first (the Docker runtime). Then `make up` → `make trust` (once) → `make check` (all phases) or `make check0` / `check1` / `check2`. Jira stub UI: https://jira.localtest.me/secure/ViewProfile.jspa (Jira users alice / bob / carol.w). `make ledger` follows token events. `make claude` starts Claude Code trusting the local CA. `make claude ARGS=--continue` resumes the previous session with the same trust. `make help` lists all targets. Credentials are in `.env` (generated by `make env`). Seed users: alice/bob/carol/dave with `SEED_USER_PASSWORD`.

## Next up
- Phase 3: `services/identity`, the AgentCore Identity-shaped API (`CreateWorkloadIdentity`, `CreateOauth2CredentialProvider` with explicit endpoints, `GetWorkloadAccessTokenForJWT/UserId`, `GetResourceOauth2Token`, `/identities/oauth2/callback`, `CompleteResourceTokenAuth`). Postgres schema (vault, sessions, ledger). Envelope encryption via OpenBao transit. Jira client secret moved into OpenBao KV. `gateway-svc` T7 auth. Exit: scripted Flow B without the gateway + S9 (consent hijack blocked).
- **You (any time):** go through `docs/stub-fidelity.md` against the real Jira DC and record the answers.
- Backlog (phase 5 hardening): enforce PKCE S256 for all clients through a Keycloak client policy. Decide the `offline_access` policy for MCP clients. Investigate Claude Code's token churn (4 tokens in 22 s).
