# Jira DC stub: fidelity checklist

The real Jira/Confluence DC can't be connected to this PoC (SPEC D1). This list is every behaviour the stub *assumes*. Check each one by hand on the real instance (as a normal user, plus an admin for the app link), record the answer, and change the stub where it differs (SPEC §11 R4).

How to check: use the real instance's UI and `curl` against its REST API, with an OAuth app link created for the test or a PAT. Never paste real tokens into this repo.

| # | Behaviour the stub implements | Where in stub | Real instance says | Checked |
|---|---|---|---|---|
| F1 | Product + version (the stub targets current DC LTS) | — | | ⬜ |
| F2 | OAuth 2.0 provider through an **incoming application link**. Endpoints `/rest/oauth2/latest/authorize` and `/rest/oauth2/latest/token` | `app.py` | | ⬜ |
| F3 | **No** discovery document (`/.well-known/oauth-authorization-server` → 404) | `no_discovery` | | ⬜ |
| F4 | PKCE S256 supported. Optional unless the link requires it | `authorize_get`, `token` | | ⬜ |
| F5 | Client auth at the token endpoint: `client_secret_post` and `client_secret_basic` | `_client_auth` | | ⬜ |
| F6 | Scopes `READ < WRITE < ADMIN < SYSTEM_ADMIN`, hierarchical (WRITE implies READ). The link's configured scope caps what can be requested | `_scopes_ok`, `_implies` | | ⬜ |
| F7 | Access token lifetime ≈ **7200 s**, set by a system property (which one?) | `DEFAULT_FAULTS.access_ttl` | | ⬜ |
| F8 | Refresh token lifetime ≈ **90 d** | `refresh_ttl` | | ⬜ |
| F9 | Refresh **rotates**: a new refresh token each time, and the old one is dead | `Store.rotate` | | ⬜ |
| F10 | Old **access** token stays valid until it expires after a refresh | `Store.rotate` | | ⬜ |
| F11 | Reusing a rotated refresh token: `invalid_grant` only (no grant-wide revocation) | `refresh_reuse_revokes_grant=false` | | ⬜ |
| F12 | Authorization code: single use, 10 min lifetime | `CODE_TTL`, `consume_code` | | ⬜ |
| F13 | Token response shape: `access_token, refresh_token, token_type: "bearer", expires_in, scope` + `Cache-Control: no-store` | `issue_pair` | | ⬜ |
| F14 | Tokens are opaque (not JWTs) | `issue_pair` | | ⬜ |
| F15 | Each consent creates a **separate grant**, so a user can see the same app listed several times | `new_grant` | | ⬜ |
| F16 | User can revoke an app's access from their profile ("Authorized applications"?) and all its tokens die at once | `profile` | | ⬜ |
| F17 | Admin can revoke app access for all users (deleting/editing the app link?) | `/_stub/revoke-all` | | ⬜ |
| F18 | The link's **redirect URL** must match exactly. Can it be the AgentCore callback `https://bedrock-agentcore.<region>.amazonaws.com/identities/oauth2/callback`? | `authorize_get` | | ⬜ |
| F19 | Bearer header carries both OAuth tokens and PATs | `_bearer` | | ⬜ |
| F20 | API 401 body for an invalid/expired/revoked token (`errorMessages`?), and whether `WWW-Authenticate` is set | `_bearer` | | ⬜ |
| F21 | 403 body when the token lacks the scope (READ token doing a write) | `api()` | | ⬜ |
| F22 | JQL on a project you can't browse → 400 *"The value 'X' does not exist for the field 'project'"* | `jql.py` | | ⬜ |
| F23 | GET an issue you can't see → 404 *"Issue does not exist or you do not have permission to see it."* | `get_issue` | | ⬜ |
| F24 | `/rest/api/2/myself`, `/search` (GET + POST), `/issue/{key}`, `/issue/{key}/comment` response shapes (spot-check field names) | `app.py` | | ⬜ |
| F25 | Consent screen: wording, shown on every authorize or only the first time? | `consent` | | ⬜ |
| F26 | Jira login identity vs SSO identity: same directory (AD)? Same usernames? (affects SPEC §5 verify mode, R6) | `seed.USERS` | | ⬜ |
| F27 | Confluence: same provider endpoints and behaviour, a separate app link, separate consent | `PERSONA=confluence` | | ⬜ |
| F28 | Confluence CQL on a space you can't see returns **no results** (not an error, unlike Jira JQL) | `cql.py` | | ⬜ |
| F29 | Confluence content you can't see → 404 `{"statusCode":404,"message":"No content found with id: ContentId{id=…}"}` | `cf_get_content` | | ⬜ |
| F30 | `/rest/api/user/current` returns `username` = the directory login (used for verify mode) | `cf_current_user` | | ⬜ |
| F31 | Confluence and Jira usernames are the same directory login (one AD), so one `jira_username` claim serves both | `seed.USERS` | | ⬜ |
