"""Generate two draw.io diagrams for the AWS "option 1" design (Cognito federated to IAM Identity Center
in front of AgentCore Gateway, Atlassian DC downstream). Plain shapes, plain-text labels and grey fills only,
so they import cleanly into Gliffy.

    python3 docs/diagrams/aws_option1_diagrams.py

writes docs/diagrams/aws-option1-token-boundaries.drawio and docs/diagrams/aws-option1-sequence.drawio
"""

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).parent

# Greys only
BOX = "fillColor=#E6E6E6;strokeColor=#666666;fontColor=#1A1A1A;"
ZONE = "fillColor=#F7F7F7;strokeColor=#999999;dashed=1;fontColor=#333333;"
NOTE = "fillColor=#EEEEEE;strokeColor=#999999;fontColor=#1A1A1A;"
GROUP = "fillColor=#F2F2F2;strokeColor=#BBBBBB;fontColor=#555555;"
TEXT = "text;strokeColor=none;fillColor=none;fontColor=#1A1A1A;"


class Diagram:
    def __init__(self, name: str):
        self.name, self.cells, self.n = name, [], 2

    def _id(self) -> str:
        self.n += 1
        return f"c{self.n}"

    def box(self, x, y, w, h, label, style=BOX, extra="") -> str:
        cid = self._id()
        self.cells.append(
            f'<mxCell id="{cid}" value="{escape(label, {chr(10): "&#xa;", chr(34): "&quot;"})}" '
            f'style="rounded=0;whiteSpace=wrap;html=0;{style}{extra}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def text(self, x, y, w, h, label, extra="") -> str:
        return self.box(x, y, w, h, label, TEXT, extra)

    def line(self, x1, y1, x2, y2, label="", style="", src=None, tgt=None) -> str:
        cid = self._id()
        ends = (f' source="{src}"' if src else "") + (f' target="{tgt}"' if tgt else "")
        pts = "" if (src and tgt) else (f'<mxPoint x="{x1}" y="{y1}" as="sourcePoint"/>'
                                        f'<mxPoint x="{x2}" y="{y2}" as="targetPoint"/>')
        self.cells.append(
            f'<mxCell id="{cid}" value="{escape(label, {chr(10): "&#xa;", chr(34): "&quot;"})}" '
            f'style="edgeStyle=none;html=0;strokeColor=#333333;fontColor=#1A1A1A;labelBackgroundColor=#FFFFFF;'
            f'fontSize=10;{style}" edge="1" parent="1"{ends}>'
            f'<mxGeometry relative="1" as="geometry">{pts}</mxGeometry></mxCell>')
        return cid

    def save(self, filename: str, w: int, h: int) -> Path:
        xml = (f'<mxfile host="app.diagrams.net"><diagram name="{escape(self.name)}" id="{filename}">'
               f'<mxGraphModel dx="{w}" dy="{h}" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" '
               f'arrows="1" fold="1" page="1" pageScale="1" pageWidth="{w}" pageHeight="{h}" math="0" shadow="0">'
               f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{"".join(self.cells)}</root>'
               f'</mxGraphModel></diagram></mxfile>\n')
        path = OUT / filename
        path.write_text(xml)
        return path


# --------------------------------------------------------------------------- 1. token boundaries

def boundaries() -> Path:
    d = Diagram("Option 1 - token boundaries")
    d.text(20, 10, 1200, 30, "AWS option 1: Cognito (federated to IAM Identity Center) in front of AgentCore Gateway"
           " - which token crosses which boundary", "fontSize=16;fontStyle=1;align=left;")

    # zones
    d.box(20, 60, 270, 470, "User device", ZONE, "verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;")
    d.box(330, 60, 330, 190, "AWS identity (no enterprise IdP)", ZONE,
          "verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;")
    d.box(700, 60, 230, 190, "AWS account - your app", ZONE, "verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;")
    d.box(330, 290, 600, 330, "AWS account - Amazon Bedrock AgentCore", ZONE,
          "verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;")
    d.box(980, 290, 250, 330, "Client / on-prem network", ZONE,
          "verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;")

    # entities
    browser = d.box(60, 110, 190, 70, "Browser\n(H1 sign-in, H2 Atlassian consent,\nH3 return)")
    mc = d.box(60, 380, 190, 70, "MCP client\n(Claude Code)\nholds T1, T1r")
    idc = d.box(350, 110, 130, 90, "IAM Identity Center\n(AWS access portal\nusers)")
    cog = d.box(510, 110, 130, 90, "Amazon Cognito\nuser pool\n(OIDC, no DCR:\npre-registered client)")
    ret = d.box(720, 110, 190, 90, "Return-URL app\n(Lambda / ECS)\nIAM role for SigV4")
    gw = d.box(360, 360, 170, 90, "AgentCore Gateway\nCUSTOM_JWT authorizer\n(Cognito discovery URL)\ntargets: jira, confluence")
    ident = d.box(620, 340, 280, 110, "AgentCore Identity\nworkload identity (gateway)\ntoken vault: T4/T5 per\n(workload, user sub, provider)\ncallback endpoint (regional)")
    kms = d.box(620, 500, 130, 70, "AWS KMS\n(vault encryption)")
    sm = d.box(770, 500, 130, 70, "Secrets Manager\nT8: Atlassian\nclient secrets")
    jira = d.box(1010, 350, 190, 70, "Jira DC\n(OAuth 2.0 provider +\nREST API)")
    conf = d.box(1010, 470, 190, 70, "Confluence DC\n(separate app link,\nseparate consent)")

    # token flows
    d.line(0, 0, 0, 0, "opens browser", "endArrow=block;dashed=1;", mc, browser)
    d.line(0, 0, 0, 0, "H1: OIDC auth code + PKCE", "endArrow=block;startArrow=block;", browser, cog)
    d.line(0, 0, 0, 0, "SAML assertion\n(federation)", "endArrow=block;startArrow=block;", cog, idc)
    d.line(0, 0, 0, 0, "code -> T1 + T1r\n(token endpoint)", "endArrow=block;startArrow=block;", mc, cog)
    d.line(0, 0, 0, 0, "MCP + Bearer T1\n(Cognito access token)", "endArrow=block;", mc, gw)
    d.line(0, 0, 0, 0, "T1 -> T3 (workload token)\nT3 -> T4  (internal)", "endArrow=block;startArrow=block;", gw, ident)
    d.line(0, 0, 0, 0, "wrap / unwrap\ndata keys", "endArrow=block;startArrow=block;", ident, kms)
    d.line(0, 0, 0, 0, "read T8", "endArrow=block;", ident, sm)
    d.line(0, 0, 0, 0, "Bearer T4 only\n(never T1)", "endArrow=block;", gw, jira)
    d.line(0, 0, 0, 0, "code + verifier + T8 -> T4/T5\nrefresh T5\n(R1: reachable from AWS?)",
           "endArrow=block;startArrow=block;", ident, jira)
    d.line(0, 0, 0, 0, "H2: login + consent", "endArrow=block;dashed=1;", browser, jira)
    d.line(0, 0, 0, 0, "callback ?code&state", "endArrow=block;dashed=1;", browser, ident)
    d.line(0, 0, 0, 0, "H3: return ?session_id", "endArrow=block;dashed=1;", browser, ret)
    d.line(0, 0, 0, 0, "silent OIDC -> T2", "endArrow=block;startArrow=block;", ret, cog)
    d.line(0, 0, 0, 0, "CompleteResourceTokenAuth\n(SigV4 + userToken T2)", "endArrow=block;", ret, ident)
    d.line(0, 0, 0, 0, "Bearer T4", "endArrow=block;dashed=1;", gw, conf)

    legend = (
        "Tokens\n"
        "SAML   Identity Center -> Cognito assertion (browser-carried). Proves who the AWS user is.\n"
        "T1     Cognito access token (JWT). Held by the MCP client, sent to the Gateway. Checked: signature, iss, client_id, scope.\n"
        "T1r    Cognito refresh token. MCP client only.\n"
        "T2     Cognito token for the return-URL app (silent SSO). Used once for binding, never stored.\n"
        "T3     AgentCore workload access token: binds workload (gateway) + user (T1 sub). Internal to AgentCore.\n"
        "T4/T5  Atlassian access / refresh tokens. Only in AgentCore Identity's token vault (KMS); T4 lent to the Gateway per call.\n"
        "T8     Atlassian OAuth client id/secret (app link) in Secrets Manager.\n"
        "SigV4  Return-URL app's IAM role signing the CompleteResourceTokenAuth call.\n"
        "\n"
        "To verify with AWS: Cognito <- Identity Center SAML federation; Claude Code with a pre-registered client id; "
        "Gateway allowedClients/allowedScopes for Cognito access tokens (no aud); R1 network path to on-prem Jira."
    )
    d.box(20, 650, 1210, 200, legend, NOTE, "align=left;verticalAlign=top;spacingLeft=10;spacingTop=6;fontFamily=Courier New;fontSize=11;")
    return d.save("aws-option1-token-boundaries.drawio", 1260, 880)


# --------------------------------------------------------------------------- 2. sequence diagram

PARTS = [
    ("user", "User\n(browser)"),
    ("mc", "MCP client\n(Claude Code)"),
    ("idc", "IAM Identity\nCenter"),
    ("cog", "Amazon Cognito\nuser pool"),
    ("gw", "AgentCore\nGateway"),
    ("id", "AgentCore Identity\n(token vault)"),
    ("aws", "KMS +\nSecrets Manager"),
    ("ret", "Return-URL app\n(your app)"),
    ("jira", "Jira / Confluence\nDC"),
]

STEPS = [
    ("group", "A. Connect and sign in (H1)"),
    ("msg", "mc", "gw", "POST /mcp (no token)"),
    ("msg", "gw", "mc", "401 WWW-Authenticate: resource_metadata, scope", True),
    ("msg", "mc", "gw", "GET /.well-known/oauth-protected-resource"),
    ("msg", "gw", "mc", "authorization_servers: [Cognito]", True),
    ("msg", "mc", "cog", "GET OIDC discovery"),
    ("note", "mc", "cog", "No DCR in Cognito: the MCP client uses a pre-registered app client id"),
    ("msg", "mc", "user", "open /oauth2/authorize (code + PKCE S256, scope mcp)"),
    ("msg", "user", "cog", "authorize request"),
    ("msg", "cog", "user", "302 -> Identity Center (SAML request)", True),
    ("msg", "user", "idc", "sign in to the AWS access portal (MFA)"),
    ("msg", "idc", "user", "SAML assertion (POST binding)", True),
    ("msg", "user", "cog", "POST /saml2/idpresponse"),
    ("msg", "cog", "user", "302 http://localhost:<port>/callback?code", True),
    ("msg", "user", "mc", "code"),
    ("msg", "mc", "cog", "POST /oauth2/token (code, code_verifier)"),
    ("msg", "cog", "mc", "T1 (access JWT) + T1r (refresh) + id token", True),
    ("msg", "mc", "gw", "initialize [Bearer T1]"),
    ("self", "gw", "JWT authorizer: Cognito JWKS, iss, client_id, scope"),
    ("msg", "gw", "mc", "session established", True),
    ("end",),
    ("group", "B. First Atlassian call -> consent (H2) -> binding (H3)"),
    ("msg", "mc", "gw", "tools/call jira___search_issues [Bearer T1]"),
    ("msg", "gw", "id", "GetWorkloadAccessTokenForJWT(gateway, T1)"),
    ("msg", "id", "gw", "T3 (workload + user sub)", True),
    ("msg", "gw", "id", "GetResourceOauth2Token(T3, jira-dc, USER_FEDERATION, returnUrl)"),
    ("self", "id", "vault miss -> new 3LO session (state, PKCE)"),
    ("msg", "id", "gw", "authorizationUrl + sessionUri", True),
    ("msg", "gw", "mc", "URL elicitation (InputRequiredResult / -32042)", True),
    ("msg", "mc", "user", "open authorizationUrl"),
    ("msg", "user", "jira", "/rest/oauth2/latest/authorize (state, code_challenge)"),
    ("note", "user", "jira", "H2: Jira login + consent (this is the identity mapping)"),
    ("msg", "jira", "user", "302 -> AgentCore Identity callback ?code&state", True),
    ("msg", "user", "id", "GET /identities/oauth2/callback"),
    ("msg", "id", "aws", "read client secret T8 (Secrets Manager)"),
    ("msg", "id", "jira", "POST /rest/oauth2/latest/token (code, verifier, T8)   [R1 network path]"),
    ("msg", "jira", "id", "T4 + T5", True),
    ("msg", "id", "user", "302 -> returnUrl?session_id=sessionUri", True),
    ("msg", "user", "ret", "GET /oauth/return?session_id"),
    ("msg", "ret", "cog", "OIDC authorize (silent: Cognito session from H1)"),
    ("msg", "cog", "ret", "T2 (same user sub)", True),
    ("msg", "ret", "id", "CompleteResourceTokenAuth(sessionUri, userToken=T2)   [SigV4, app IAM role]"),
    ("self", "id", "binding: T2 sub == session starter sub, else reject"),
    ("msg", "id", "aws", "KMS: encrypt T4/T5 into the vault"),
    ("msg", "ret", "user", "'Jira connected'", True),
    ("msg", "mc", "gw", "retry tools/call [Bearer T1]"),
    ("msg", "gw", "id", "GetWorkloadAccessTokenForJWT + GetResourceOauth2Token"),
    ("msg", "id", "aws", "KMS decrypt"),
    ("msg", "id", "gw", "T4", True),
    ("msg", "gw", "jira", "GET /rest/api/2/search [Bearer T4]"),
    ("msg", "jira", "gw", "the user's issues only", True),
    ("msg", "gw", "mc", "tool result (data, no tokens)", True),
    ("end",),
    ("group", "C. Later calls / refresh"),
    ("msg", "mc", "cog", "refresh T1 with T1r when expired"),
    ("msg", "gw", "id", "GetResourceOauth2Token(T3, jira-dc)"),
    ("self", "id", "T4 expired -> refresh under lock"),
    ("msg", "id", "jira", "POST token (refresh_token = T5)"),
    ("msg", "jira", "id", "new T4 + new T5 (rotation)", True),
    ("msg", "id", "gw", "T4", True),
    ("end",),
]


def sequence() -> Path:
    d = Diagram("Option 1 - sequence")
    left, gap, bw, bh, top = 40, 175, 150, 50, 50
    xs = {k: left + i * gap + bw / 2 for i, (k, _) in enumerate(PARTS)}
    width = left * 2 + gap * (len(PARTS) - 1) + bw
    d.text(left, 10, width, 30, "AWS option 1 - calls and token exchanges (Cognito federated to IAM Identity Center ->"
           " AgentCore Gateway -> Atlassian DC)", "fontSize=15;fontStyle=1;align=left;")

    y = top + bh + 30
    groups_open: list[tuple[str, float]] = []
    later: list[str] = []  # group rectangles are drawn first (behind), collected then prepended
    content_start = len(d.cells)
    for step in STEPS:
        kind = step[0]
        if kind == "group":
            groups_open.append((step[1], y))
            y += 30
        elif kind == "end":
            title, gy = groups_open.pop()
            later.append((title, gy, y + 6))
            y += 26
        elif kind == "msg":
            a, b, label = step[1], step[2], step[3]
            dashed = len(step) > 4 and step[4]
            x1, x2 = xs[a], xs[b]
            lx = min(x1, x2)
            d.text(lx, y - 20, abs(x2 - x1), 18, label, "fontSize=10;align=center;verticalAlign=bottom;")
            d.line(x1, y, x2, y, "", "endArrow=block;endFill=1;" + ("dashed=1;" if dashed else ""))
            y += 36
        elif kind == "note":
            a, b, label = step[1], step[2], step[3]
            x1, x2 = sorted((xs[a], xs[b]))
            d.box(x1 - 40, y - 8, (x2 - x1) + 80, 26, label, NOTE, "fontSize=10;")
            y += 36
        elif kind == "self":
            who, label = step[1], step[2]
            d.box(xs[who] + 6, y - 10, 230, 26, label, NOTE, "fontSize=10;align=left;spacingLeft=4;")
            y += 36
    bottom = y + 10

    content = d.cells[content_start:]
    d.cells = d.cells[:content_start]
    for title, gy, gend in later:  # behind everything else
        d.box(left - 25, gy - 4, width - left + 10, gend - gy, title, GROUP,
              "verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;fontSize=11;")
    # lifelines + head/foot boxes (mermaid style: actors mirrored at the bottom)
    for (k, label), x in zip(PARTS, xs.values()):
        d.line(x, top + bh, x, bottom, "", "endArrow=none;dashed=1;strokeColor=#999999;")
        d.box(x - bw / 2, top, bw, bh, label, BOX, "fontSize=11;")
        d.box(x - bw / 2, bottom, bw, bh, label, BOX, "fontSize=11;")
    d.cells.extend(content)
    return d.save("aws-option1-sequence.drawio", int(width + 40), int(bottom + bh + 40))


if __name__ == "__main__":
    for p in (boundaries(), sequence()):
        print(p)
