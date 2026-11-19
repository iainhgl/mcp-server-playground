# mcp-server-playground

Local Docker model of: off-the-shelf MCP client → MCP gateway (AgentCore-shaped) → Atlassian DC, with per-user downstream OAuth consent. Learning tool for token flow and storage ahead of an AWS AgentCore build.

## Source of truth
- `SPEC.md`: the design. Section numbers (§) are referenced from elsewhere, so don't renumber them.
- `PROGRESS.md`: phase status, scenario results, risk findings and the discoveries log.

## Working rules
- When finishing a piece of work, update `PROGRESS.md` in the same commit: phase/scenario status, evidence, and "Next up".
- If building reveals that the spec is wrong or incomplete (tool behaviour, Keycloak/MCP client quirks, Jira DC facts), do three things:
  1. Log it in the PROGRESS.md discoveries log.
  2. Edit the relevant SPEC.md section.
  3. Add a row to the SPEC §14 changelog.
  Never let the spec silently drift from what was built.
- Never log or commit raw tokens or secrets (SPEC §3 invariant 6). `.env` and `certs/` are gitignored.
