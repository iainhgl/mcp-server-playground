"""A deliberately small JQL subset. Enough for realistic tool calls, and it fails
the way Jira does on anything else.

Supported: clauses joined by AND, plus an optional ORDER BY (ignored):
  project = KEY | project in (A, B)
  assignee = currentUser() | assignee = name | assignee is EMPTY
  status = "X" | issuetype = X
  text ~ "x" | summary ~ "x"
"""

import re
from collections.abc import Callable

from atlassian_stub.seed import PROJECTS, Issue


class JqlError(Exception):
    pass


def _val(v: str) -> str:
    return v.strip().strip('"').strip("'")


def _field_is(field: str, value: str | None) -> Callable[[Issue], bool]:
    want = value.lower() if value is not None else None
    return lambda i: ((getattr(i, field) or "").lower() if want is not None else getattr(i, field)) == want


def _in_projects(keys: list[str]) -> Callable[[Issue], bool]:
    ks = frozenset(keys)
    return lambda i: i.project in ks


def _contains(needle: str, include_description: bool) -> Callable[[Issue], bool]:
    n = needle.lower()
    return lambda i: n in i.summary.lower() or (include_description and n in i.description.lower())


def compile_jql(jql: str, username: str, visible: set[str]) -> Callable[[Issue], bool]:
    jql = re.split(r"\border\s+by\b", jql or "", flags=re.IGNORECASE)[0].strip()
    preds: list[Callable[[Issue], bool]] = []
    if not jql:
        return lambda i: True
    for clause in re.split(r"\s+and\s+", jql, flags=re.IGNORECASE):
        c = clause.strip()
        if m := re.fullmatch(r"project\s*=\s*(\S+)", c, re.IGNORECASE):
            keys = [_val(m.group(1)).upper()]
        elif m := re.fullmatch(r"project\s+in\s*\(([^)]*)\)", c, re.IGNORECASE):
            keys = [_val(k).upper() for k in m.group(1).split(",")]
        else:
            keys = None
        if keys is not None:
            for k in keys:
                # Jira doesn't reveal that a project exists if you can't browse it.
                if k not in PROJECTS or k not in visible:
                    raise JqlError(f"The value '{k}' does not exist for the field 'project'.")
            preds.append(_in_projects(keys))
            continue
        if re.fullmatch(r"assignee\s*=\s*currentUser\(\)", c, re.IGNORECASE):
            preds.append(_field_is("assignee", username))
        elif re.fullmatch(r"assignee\s+is\s+empty", c, re.IGNORECASE):
            preds.append(_field_is("assignee", None))
        elif m := re.fullmatch(r"assignee\s*=\s*(.+)", c, re.IGNORECASE):
            preds.append(_field_is("assignee", _val(m.group(1))))
        elif m := re.fullmatch(r"status\s*=\s*(.+)", c, re.IGNORECASE):
            preds.append(_field_is("status", _val(m.group(1))))
        elif m := re.fullmatch(r"(?:issuetype|type)\s*=\s*(.+)", c, re.IGNORECASE):
            preds.append(_field_is("issuetype", _val(m.group(1))))
        elif m := re.fullmatch(r"(text|summary)\s*~\s*(.+)", c, re.IGNORECASE):
            preds.append(_contains(_val(m.group(2)), m.group(1).lower() == "text"))
        else:
            raise JqlError(f"Error in the JQL Query: unsupported clause '{c}' (playground stub subset).")
    return lambda i: all(p(i) for p in preds)
