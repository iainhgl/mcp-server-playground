"""Minimal server-rendered pages: login, OAuth consent, profile (authorized apps + PATs)."""

from html import escape

CSS = """
:root{--bg:#f4f5f7;--card:#fff;--ink:#172b4d;--muted:#5e6c84;--brand:#0052cc;--line:#dfe1e6;--danger:#de350b}
@media (prefers-color-scheme:dark){:root{--bg:#1d2125;--card:#22272b;--ink:#dee4ea;--muted:#9fadbc;
--brand:#579dff;--line:#38414a;--danger:#f87462}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{background:var(--card);border-bottom:1px solid var(--line);padding:12px 16px;display:flex;gap:12px;
align-items:center}header b{color:var(--brand)}header .tag{font-size:12px;color:var(--muted);
border:1px solid var(--line);border-radius:3px;padding:1px 6px}
main{max-width:560px;margin:32px auto;padding:0 16px}.card{background:var(--card);border:1px solid var(--line);
border-radius:6px;padding:24px;margin-bottom:16px}h1{font-size:20px;margin:0 0 16px}h2{font-size:16px;margin:0 0 12px}
label{display:block;font-weight:600;margin:12px 0 4px}input[type=text],input[type=password]{width:100%;
padding:8px;border:2px solid var(--line);border-radius:3px;background:var(--bg);color:var(--ink);font:inherit}
button{font:inherit;padding:8px 14px;border-radius:3px;border:0;cursor:pointer;background:var(--brand);color:#fff}
button.secondary{background:transparent;color:var(--ink);border:1px solid var(--line)}
button.danger{background:var(--danger)}.muted{color:var(--muted);font-size:13px}.err{color:var(--danger)}
ul.scopes{padding-left:20px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 4px;
border-bottom:1px solid var(--line);font-size:14px}code{font-size:13px;word-break:break-all}
.row{display:flex;gap:8px;margin-top:20px}
"""

SCOPE_TEXT = {
    "READ": "View projects, issues and other content you can see",
    "WRITE": "Create and edit issues and comments as you",
    "ADMIN": "Administer projects you administer",
    "SYSTEM_ADMIN": "Administer the whole instance",
}


def page(title: str, body: str, product: str, user: str | None = None) -> str:
    who = f'<span class="muted">Logged in as <b>{escape(user)}</b> · <a href="/secure/ViewProfile.jspa">Profile</a> · ' \
          f'<a href="/logout">Log out</a></span>' if user else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title>
<style>{CSS}</style></head><body><header><b>{escape(product)}</b><span class="tag">Data Center · playground stub</span>
<span style="flex:1"></span>{who}</header><main>{body}</main></body></html>"""


def login(product: str, destination: str, error: str | None = None) -> str:
    err = f'<p class="err">{escape(error)}</p>' if error else ""
    return page(f"Log in - {product}", f"""<div class="card"><h1>Log in to {escape(product)}</h1>{err}
<form id="login-form" method="post" action="/login.jsp">
<input type="hidden" name="os_destination" value="{escape(destination)}">
<label for="u">Username</label><input type="text" id="u" name="os_username" autocomplete="username" autofocus>
<label for="p">Password</label><input type="password" id="p" name="os_password" autocomplete="current-password">
<div class="row"><button type="submit" name="login" value="Log In">Log in</button></div></form>
<p class="muted">This Jira user directory is separate from your SSO account (SPEC §5).</p></div>""", product)


def consent(product: str, user: str, client_name: str, scopes: list[str], hidden: dict[str, str]) -> str:
    fields = "".join(f'<input type="hidden" name="{escape(k)}" value="{escape(v)}">' for k, v in hidden.items())
    items = "".join(f"<li><b>{escape(s)}</b>: {escape(SCOPE_TEXT.get(s, s))}</li>" for s in scopes)
    return page(f"Allow access - {product}", f"""<div class="card"><h1>{escape(client_name)} wants to access your
{escape(product)} account</h1><p>It will act as <b>{escape(user)}</b> and can:</p><ul class="scopes">{items}</ul>
<p class="muted">You can revoke this at any time from your profile under Authorized applications.</p>
<form id="consent-form" method="post" action="/rest/oauth2/latest/authorize">{fields}
<div class="row"><button type="submit" name="decision" value="allow">Allow</button>
<button class="secondary" type="submit" name="decision" value="deny">Deny</button></div></form></div>""",
                product, user)


def error_page(product: str, message: str, user: str | None = None) -> str:
    return page(f"Error - {product}", f'<div class="card"><h1>Something went wrong</h1>'
                f'<p class="err">{escape(message)}</p></div>', product, user)


def profile(product: str, user: str, xsrf: str, grants: list, pats: list, new_pat: str | None = None) -> str:
    g_rows = "".join(
        f"""<tr><td>{escape(g['client_name'])}</td><td>{escape(g['scope'])}</td>
<td><form method="post" action="/secure/ViewProfile.jspa"><input type="hidden" name="atl_token" value="{xsrf}">
<input type="hidden" name="revoke_grant" value="{g['id']}"><button class="danger" type="submit">Revoke</button></form></td></tr>"""
        for g in grants) or '<tr><td colspan="3" class="muted">No applications have access.</td></tr>'
    p_rows = "".join(f"<tr><td>{escape(p['name'])}</td></tr>" for p in pats) or \
        '<tr><td class="muted">None.</td></tr>'
    shown = f'<p>New token (shown once): <code id="new-pat">{escape(new_pat)}</code></p>' if new_pat else ""
    return page(f"Profile - {product}", f"""<div class="card"><h1>{escape(user)}</h1></div>
<div class="card"><h2>Authorized applications</h2><table id="grants"><tr><th>Application</th><th>Scope</th><th></th></tr>
{g_rows}</table></div>
<div class="card"><h2>Personal access tokens</h2><table>{p_rows}</table>{shown}
<form method="post" action="/secure/ViewProfile.jspa"><input type="hidden" name="atl_token" value="{xsrf}">
<label for="n">Token name</label><input type="text" id="n" name="pat_name" value="playground">
<div class="row"><button type="submit">Create token</button></div></form></div>""", product, user)
