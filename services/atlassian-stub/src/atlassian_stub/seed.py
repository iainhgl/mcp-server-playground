"""Seed directory and content (SPEC §5).

Jira users are a *separate* identity store from the IdP. carol is `carol.w` here
(to exercise mapping), and dave has no Jira account at all. In production the
two stores are usually fed by the same AD, which is why passwords match here.
"""

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    name: str  # Jira username (login)
    key: str  # Jira user key (stable internal id)
    display_name: str
    email: str


@dataclass(frozen=True)
class Project:
    key: str
    id: str
    name: str
    members: frozenset[str]  # usernames with BROWSE_PROJECTS


@dataclass
class Issue:
    key: str
    id: str
    project: str
    issuetype: str
    summary: str
    description: str
    status: str
    assignee: str | None
    reporter: str
    created: str
    updated: str
    comments: list[tuple[str, str, str]] = field(default_factory=list)  # (author, body, created)


USERS = {
    u.name: u
    for u in [
        User("alice", "JIRAUSER10100", "Alice Anders", "alice@example.test"),
        User("bob", "JIRAUSER10101", "Bob Brown", "bob@example.test"),
        User("carol.w", "JIRAUSER10102", "Carol White", "carol@example.test"),
    ]
}


def password_ok(username: str, password: str) -> bool:
    return username in USERS and password == os.environ.get("SEED_USER_PASSWORD")


# ---- Jira persona ---------------------------------------------------------

PROJECTS = {
    p.key: p
    for p in [
        Project("ALPHA", "10000", "Alpha Platform", frozenset({"alice", "carol.w"})),
        Project("BETA", "10001", "Beta Operations", frozenset({"bob", "carol.w"})),
    ]
}

_T = "2026-11-0{}T09:{}:00.000+0000"

ISSUES = {
    i.key: i
    for i in [
        Issue("ALPHA-1", "10100", "ALPHA", "Bug", "Login page returns 500 on expired session",
              "Steps: let the session expire, reload /login. Stack trace points at the session filter.",
              "In Progress", "alice", "carol.w", _T.format(2, 10), _T.format(5, 12),
              [("carol.w", "Reproduced on staging.", _T.format(3, 15))]),
        Issue("ALPHA-2", "10101", "ALPHA", "Story", "Add audit logging for token refresh",
              "Every refresh should emit an audit event with the token fingerprint, never the token.",
              "To Do", "carol.w", "alice", _T.format(3, 30), _T.format(3, 30)),
        Issue("ALPHA-3", "10102", "ALPHA", "Task", "Upgrade Postgres to 16",
              "Move the platform database to Postgres 16 and re-run the migration suite.",
              "Done", "alice", "alice", _T.format(1, 45), _T.format(6, 20)),
        Issue("BETA-1", "10200", "BETA", "Task", "Rotate TLS certificates on edge proxies",
              "Certificates on the edge proxies expire at the end of the month.",
              "In Progress", "bob", "bob", _T.format(2, 5), _T.format(7, 40),
              [("bob", "Staging done, production next week.", _T.format(7, 41))]),
        Issue("BETA-2", "10201", "BETA", "Bug", "Pager alert noise from disk checks",
              "Disk checks page at 80% on volumes that autoscale; raise the threshold or make it smarter.",
              "To Do", "bob", "carol.w", _T.format(4, 20), _T.format(4, 20)),
        Issue("BETA-3", "10202", "BETA", "Story", "Runbook for OpenBao unseal",
              "Document the unseal procedure after a node restart, including who holds key shares.",
              "To Do", "carol.w", "bob", _T.format(5, 50), _T.format(5, 50)),
    ]
}


def visible_projects(username: str) -> set[str]:
    return {k for k, p in PROJECTS.items() if username in p.members}


# ---- Confluence persona ---------------------------------------------------

@dataclass(frozen=True)
class Space:
    key: str
    id: str
    name: str
    members: frozenset[str]  # usernames with VIEWSPACE


@dataclass(frozen=True)
class Page:
    id: str
    space: str
    title: str
    body: str  # storage format (XHTML)
    author: str
    created: str
    version: int = 1


SPACES = {
    s.key: s
    for s in [
        Space("ENG", "98305", "Engineering", frozenset({"alice"})),
        Space("OPS", "98306", "Operations", frozenset({"bob"})),
        # carol.w has a Confluence account but no space permissions; dave has no account at all.
    ]
}

PAGES = {
    p.id: p
    for p in [
        Page("65601", "ENG", "Architecture overview",
             "<p>The platform runs behind an MCP gateway. Tokens never reach the assistant.</p>",
             "alice", "2026-10-01T09:00:00.000Z", 3),
        Page("65602", "ENG", "Onboarding checklist",
             "<ul><li>Request Jira access</li><li>Read the architecture overview</li></ul>",
             "alice", "2026-10-05T10:30:00.000Z"),
        Page("65603", "ENG", "Token handling standards",
             "<p>Log fingerprints, never raw tokens. Envelope-encrypt anything at rest.</p>",
             "alice", "2026-10-12T14:00:00.000Z", 2),
        Page("65701", "OPS", "On-call runbook",
             "<p>Pager alerts route to the primary on-call. Escalate after 15 minutes.</p>",
             "bob", "2026-09-20T08:00:00.000Z", 5),
        Page("65702", "OPS", "OpenBao unseal procedure",
             "<p>After a node restart, unseal with the shared key, then wait for raft leadership.</p>",
             "bob", "2026-10-02T16:45:00.000Z"),
    ]
}


def visible_spaces(username: str) -> set[str]:
    return {k for k, s in SPACES.items() if username in s.members}
