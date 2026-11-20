"""A deliberately small CQL subset for the Confluence persona.

Supported: clauses joined by AND (ORDER BY ignored):
  space = KEY | space in (A, B) | type = page | text ~ "x" | title ~ "x"
Unlike Jira's JQL, Confluence CQL on a space you can't see simply returns no results (an assumption to
confirm on the real instance: stub-fidelity F28). Permission filtering is applied by the caller.
"""

import re
from collections.abc import Callable

from atlassian_stub.seed import Page


class CqlError(Exception):
    pass


def _val(v: str) -> str:
    return v.strip().strip('"').strip("'")


def _in_spaces(keys: list[str]) -> Callable[[Page], bool]:
    ks = frozenset(keys)
    return lambda p: p.space in ks


def _contains(needle: str, body_too: bool) -> Callable[[Page], bool]:
    n = needle.lower()
    return lambda p: n in p.title.lower() or (body_too and n in p.body.lower())


def compile_cql(cql: str) -> Callable[[Page], bool]:
    cql = re.split(r"\border\s+by\b", cql or "", flags=re.IGNORECASE)[0].strip()
    preds: list[Callable[[Page], bool]] = []
    for clause in re.split(r"\s+and\s+", cql, flags=re.IGNORECASE) if cql else []:
        c = clause.strip()
        if m := re.fullmatch(r"space\s*=\s*(\S+)", c, re.IGNORECASE):
            preds.append(_in_spaces([_val(m.group(1)).upper()]))
        elif m := re.fullmatch(r"space\s+in\s*\(([^)]*)\)", c, re.IGNORECASE):
            preds.append(_in_spaces([_val(k).upper() for k in m.group(1).split(",")]))
        elif re.fullmatch(r"type\s*=\s*\"?page\"?", c, re.IGNORECASE):
            continue
        elif m := re.fullmatch(r"(text|title)\s*~\s*(.+)", c, re.IGNORECASE):
            preds.append(_contains(_val(m.group(2)), m.group(1).lower() == "text"))
        else:
            raise CqlError(f"Could not parse cql : {c} (playground stub subset)")
    return lambda p: all(f(p) for f in preds)
