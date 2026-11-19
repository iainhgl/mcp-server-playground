"""Server-rendered pages for the portal. Tokens never appear in HTML."""

import json
from html import escape
from typing import Any

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--muted:#5b6470;--line:#dde1e6;--brand:#3b5bdb;--ok:#2b8a3e;
--bad:#c92a2a;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#15181c;--card:#1d2127;--ink:#e6e9ee;--muted:#9aa4b1;--line:#2d333b;
--brand:#91a7ff;--ok:#69db7c;--bad:#ff8787;--chip:#262b33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;gap:16px;align-items:center;padding:12px 16px;background:var(--card);border-bottom:1px solid var(--line)}
header b{font-weight:650}header nav{display:flex;gap:14px;flex-wrap:wrap}header a{color:var(--brand);text-decoration:none}
main{max-width:1100px;margin:24px auto;padding:0 16px}.card{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:20px;margin-bottom:16px}h1{font-size:20px;margin:0 0 12px}h2{font-size:16px;margin:0 0 10px}
.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}button{font:inherit;padding:7px 12px;border-radius:6px;
border:1px solid var(--line);background:var(--brand);color:#fff;cursor:pointer}button.ghost{background:transparent;color:var(--ink)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line);
vertical-align:top}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.chip{display:inline-block;background:var(--chip);border-radius:4px;padding:0 6px;font-size:12px}
.scroll{overflow-x:auto}form.inline{display:inline}input[type=text]{font:inherit;padding:6px;border:1px solid var(--line);
border-radius:6px;background:var(--bg);color:var(--ink)}
"""


def page(title: str, body: str, user: dict | None = None, extra_head: str = "") -> str:
    who = (f'<span class="muted">Signed in as <b>{escape(user["name"])}</b> · <a href="/logout">Sign out</a></span>'
           if user else '<a href="/login">Sign in</a>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title>
<style>{CSS}</style>{extra_head}</head><body><header><b>Playground portal</b><nav><a href="/">Home</a>
<a href="/connections">Connected apps</a><a href="/ledger">Token ledger</a></nav><span style="flex:1"></span>{who}</header>
<main>{body}</main></body></html>"""


def home(user: dict | None) -> str:
    if not user:
        return page("Portal", '<div class="card"><h1>Playground portal</h1><p>This is the app users land on after '
                    'approving Jira access (the AgentCore <code>resourceOauth2ReturnUrl</code>). '
                    '<a href="/login">Sign in</a> to manage connected apps or view the token ledger.</p></div>')
    return page("Portal", f"""<div class="card"><h1>Hello {escape(user['name'])}</h1>
<p class="muted">Your vault identity: <code>{escape(user['user_id'])}</code></p>
<p><a href="/connections">Connected apps</a> · <a href="/ledger">Token ledger</a></p></div>""", user)


def result(user: dict | None, ok: bool, title: str, msg: str) -> str:
    cls = "ok" if ok else "bad"
    return page(title, f'<div class="card"><h1 class="{cls}">{escape(title)}</h1><p>{escape(msg)}</p>'
                f'<p><a href="/connections">Connected apps</a></p></div>', user)


def connections(user: dict, conns: list[dict[str, Any]], providers: list[str]) -> str:
    have = {c["provider_name"]: c for c in conns}
    rows = ""
    for p in providers:
        c = have.get(p)
        if c:
            rows += f"""<tr><td><b>{escape(p)}</b></td><td class="ok">Connected</td><td>{escape(' '.join(c['scopes']))}</td>
<td class="mono">{escape(c['updated_at'][:19])}</td><td><form class="inline" method="post" action="/connections/disconnect">
<input type="hidden" name="provider" value="{escape(p)}"><button class="ghost">Disconnect</button></form></td></tr>"""
        else:
            rows += f"""<tr><td><b>{escape(p)}</b></td><td class="muted">Not connected</td><td></td><td></td>
<td><form class="inline" method="post" action="/connections/connect"><input type="hidden" name="provider"
value="{escape(p)}"><button>Connect</button></form></td></tr>"""
    return page("Connected apps", f"""<div class="card"><h1>Connected apps</h1>
<p class="muted">Downstream accounts the MCP gateway may use on your behalf (identity's token vault, metadata only).
Disconnecting forgets the tokens here. To cut off an already-issued token immediately, also revoke the app in Jira.</p>
<div class="scroll"><table><tr><th>Provider</th><th>Status</th><th>Scopes</th><th>Updated (UTC)</th><th></th></tr>
{rows}</table></div></div>""", user)


SERVICES = ["gateway", "identity", "jira-stub", "portal"]


def ledger(user: dict, events: list[dict], minutes: int, q: str) -> str:
    rows = "".join(
        f"""<tr><td class="mono">{escape(e['ts'].strftime('%H:%M:%S.%f')[:-3])}</td><td>{escape(e['service'])}</td>
<td><b>{escape(e['event'])}</b></td><td>{f'<span class="chip">{escape(e["token_label"])}</span>' if e['token_label'] else ''}</td>
<td class="mono">{escape(e['fp'] or '')}</td><td class="mono">{escape(_detail(e['data']))}</td></tr>"""
        for e in events)
    diagram = _mermaid(events[-60:])
    head = ('<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.esm.min.mjs";'
            'mermaid.initialize({startOnLoad:true,theme:matchMedia("(prefers-color-scheme: dark)").matches?"dark":"default",'
            'sequence:{mirrorActors:false,noteMargin:4}});</script>')
    return page("Token ledger", f"""<div class="card"><h1>Token ledger</h1>
<form method="get" action="/ledger"><label>Last <input type="text" name="minutes" value="{minutes}" size="3"> min</label>
<label> filter <input type="text" name="q" value="{escape(q)}" placeholder="event, fp, user…"></label>
<button>Show</button></form><p class="muted">{len(events)} events. Fingerprints are sha256(token)[:12]; raw tokens are
never recorded. Labels follow SPEC §3 (T1 gateway token … T7 service token).</p></div>
<div class="card scroll"><h2>Sequence (last {min(60, len(events))} events)</h2><pre class="mermaid">{escape(diagram)}</pre></div>
<div class="card scroll"><table><tr><th>Time (UTC)</th><th>Service</th><th>Event</th><th>Token</th><th>fp</th><th>Detail</th></tr>
{rows}</table></div>""", user, head)


_SKIP = {"ts", "service", "event", "token", "fp"}


def _detail(d: dict) -> str:
    return " ".join(f"{k}={v if not isinstance(v, (dict, list)) else json.dumps(v)}"
                    for k, v in d.items() if k not in _SKIP)[:240]


def _mermaid(events: list[dict]) -> str:
    lines = ["sequenceDiagram"] + [f"  participant {s}" for s in SERVICES]
    for e in events:
        svc = e["service"] if e["service"] in SERVICES else "portal"
        label = f"{e['event']}" + (f" {e['token_label']} {e['fp'][:6]}" if e["token_label"] and e["fp"] else "")
        lines.append(f"  Note over {svc}: {label.replace(':', ' ').replace(';', ' ')}")
    return "\n".join(lines)
