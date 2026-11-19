# Progress

Living status for the build described in [SPEC.md](SPEC.md). Update this file in the same commit as the work it describes.

**Current phase:** 0, Edge & IdP (not started)
**Last updated:** 2026-11-19

---

## Phases

Legend: ⬜ not started · 🟨 in progress · ✅ done · ⏸ blocked

| Phase | Status | Exit criteria (SPEC §10) | Notes |
|---|---|---|---|
| 0. Edge & IdP | ⬜ | Trusted-TLS login to `idp.localtest.me`. DCR via curl works | |
| 1. Gateway shell | ⬜ | S1, S2, S14: Claude Code connects, `whoami` shows claims | |
| 2. Stub downstream | ⬜ | Manual PKCE flow returns T4. `/search` filtered per user | |
| 3. Identity + vault | ⬜ | Scripted Flow B without gateway. S9 | |
| 4. End-to-end 3LO | ⬜ | S3, S4, S5, S8, S15, S18 | |
| 5. Lifecycle & attacks | ⬜ | S6, S7, S10–S13, S16, S17, S19 | |
| 6. More clients & sources | ⬜ | S20, Confluence tools | |
| 7. Second IdP | ⬜ | Design record + one §12 option working | |
| 8. AWS port | ⬜ | §11 checklist answered (separate spec) | |

## Acceptance scenarios (SPEC §8)

| # | Status | Result / evidence |
|---|---|---|
| S1 | ⬜ | |
| S2 | ⬜ | |
| S3 | ⬜ | |
| S4 | ⬜ | |
| S5 | ⬜ | |
| S6 | ⬜ | |
| S7 | ⬜ | |
| S8 | ⬜ | |
| S9 | ⬜ | |
| S10 | ⬜ | |
| S11 | ⬜ | |
| S12 | ⬜ | |
| S13 | ⬜ | |
| S14 | ⬜ | |
| S15 | ⬜ | |
| S16 | ⬜ | |
| S17 | ⬜ | |
| S18 | ⬜ | |
| S19 | ⬜ | |
| S20 | ⬜ | |

## Risks to verify (SPEC §11)

| Risk | Status | Finding |
|---|---|---|
| R1 Network reachability of Jira DC from AgentCore | open | |
| R2 Gateway 3LO surface to MCP clients | open | |
| R3 Gateway PRM discovery / multiple issuers | open | |
| R4 Jira DC OAuth specifics (check by hand on real instance) | open | |
| R5 Entra + off-the-shelf clients | open | |
| R6 Identity alignment across RH SSO / Entra / Jira | open | |

---

## Discoveries log

Newest first. Record anything learned while building that differs from or adds to the spec. If it changes the design, also edit SPEC.md and add a line to its changelog (SPEC §14).

| Date | Phase | Discovery | Spec impact |
|---|---|---|---|
| — | — | (none yet) | — |

## Next up
- Phase 0: `docker-compose.yml` with Caddy, Keycloak, Postgres, OpenBao, mitmproxy. `make trust` / `make hosts`. Keycloak realm import with DCR policies and the `mcp:tools` audience scope.
