"""Approver page for held actions. Local only: binds 127.0.0.1, checks Host and Origin,
accepts JSON-only POSTs, escapes every rendered value, and sends a nonce-based CSP.

    python3 server.py            # mock Policy API + scripted agent + page on http://127.0.0.1:8765
"""
import html
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import mock_policy_api
from held_actions import HeldActions, PolicyClient, PolicyError, Route

HERE = Path(__file__).resolve().parent
MAX_POST = 64 * 1024

# Which Rule a named person can lift, by adding which trusted context fact. ruleIds match the mock's RULES.
ROUTES = {
    "rule_refund_over_250": Route("finance_lead_approval", "Malik Benali", "Finance lead"),
    "rule_suspend_paying_account": Route("account_owner_approval", "Sophie Laurent", "Account owner"),
    "rule_status_page_ic": Route("incident_commander_approval", "Claire Moreau", "Incident commander"),
}

# A scripted support agent proposing five write-actions: (summary, action, params, trusted context).
DEMO = [
    ("Close ticket #4810", "tickets/close",
     {"ticket_id": "4810", "resolution": "Reset link re-sent; customer confirmed login works."},
     {"customer_confirmed": True}),
    ("Refund EUR 480 on order ORD-77213", "payments/issue_refund",
     {"order_id": "ORD-77213", "amount_eur": 480, "reason": "Duplicate annual charge"},
     {"customer_tier": "pro", "refunds_last_90d": 0}),
    ("Suspend account acc_5521 (Business plan)", "accounts/change_status",
     {"account_id": "acc_5521", "status": "suspended"},
     {"plan": "business", "unpaid_invoices": 2, "days_overdue": 45}),
    ("Email j.martin@example.com that the refund is on its way", "email/send_customer",
     {"to": "j.martin@example.com", "subject": "Your refund is on its way", "body": "Hi J., we have issued..."},
     {"customer_opted_out": True}),
    ("Set incident INC-2291 to Resolved on the public status page", "statuspage/set_status",
     {"incident_id": "INC-2291", "status": "resolved", "message": "Payments are processing normally again."},
     {"severity": "Sev-2", "runbook": "matched", "open_incidents": 2, "affected_customers": 14}),
]

DONE = {
    "tickets/close": "Ticket {ticket_id} closed",
    "payments/issue_refund": "Refunded EUR {amount_eur} on {order_id}",
    "accounts/change_status": "Account {account_id} set to {status}",
    "email/send_customer": "Email sent to {to}",
    "statuspage/set_status": "Status page: {incident_id} set to {status}",
}


def demo_execute(action, params):
    return DONE[action].format(**params)  # ponytail: stands in for your real tool handlers


def run_demo_agent(loop):
    run = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    for n, (summary, action, params, ctx) in enumerate(DEMO, 1):
        loop.propose("support-agent", action, params, ctx, f"support-{run}-{n}", summary)


# ---------- rendering ----------

def e(v):
    return html.escape(str(v), quote=True)


CSS = """
:root{--bg:#f6f6f4;--card:#fff;--ink:#1b1b1a;--mut:#6b6b66;--line:#e4e3de;--amber:#b25e00;--amber-bg:#fff4e0;
--green:#1d7a46;--green-bg:#e6f4ec;--red:#b42318;--red-bg:#fdecea;--blue:#1f5fbf;--blue-bg:#e9f0fb;--code:#f1f0ec}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1d1d1b;--ink:#ecebe6;--mut:#a3a29b;--line:#33322e;
--amber:#f0a14a;--amber-bg:#3a2a12;--green:#5cc98b;--green-bg:#15301f;--red:#f2867c;--red-bg:#3a1a17;--blue:#86adf0;
--blue-bg:#18263d;--code:#262622}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
main{max-width:1240px;margin:0 auto;padding:28px 16px 48px}
header{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px;margin-bottom:20px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}.sub{margin:0;color:var(--mut);max-width:640px}
.stats{display:flex;gap:8px;flex-wrap:wrap}.stat{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:13px}
.stat b{font-variant-numeric:tabular-nums}.stat.wait b{color:var(--amber)}.stat.ran b{color:var(--green)}.stat.blk b{color:var(--red)}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 370px;gap:20px;align-items:start}
@media (max-width:920px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 18px 16px;margin-bottom:14px}
.route{display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:13px;color:var(--amber);background:var(--amber-bg);
border-radius:999px;padding:4px 12px;width:fit-content}.route .t{color:var(--mut)}
h2{font-size:18px;margin:10px 0 6px}.why{margin:0 0 12px}.label{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin-right:6px}
dl{display:grid;grid-template-columns:110px 1fr;gap:6px 12px;margin:0 0 12px;font-size:13px}dt{color:var(--mut)}dd{margin:0;min-width:0;overflow-wrap:anywhere}
code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);border-radius:4px;padding:1px 5px}
.chip{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:0 6px;margin:0 4px 4px 0;font-size:12.5px}
textarea{width:100%;resize:vertical;margin-bottom:10px;border:1px solid var(--line);border-radius:8px;padding:10px;background:var(--code);color:var(--ink);
font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
.note{flex:1 1 220px;min-width:0;border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--card);color:var(--ink);font:inherit}
.actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
button{font:inherit;font-size:14px;border-radius:8px;padding:8px 14px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
button:focus-visible,textarea:focus-visible,.note:focus-visible,a:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
button.ok{background:var(--green);border-color:var(--green);color:#fff}button.no{color:var(--red);border-color:var(--red)}
button:disabled{opacity:.4;cursor:default}.msg{flex-basis:100%;font-size:13px;color:var(--red)}.msg:empty{display:none}
aside h3{font-size:14px;margin:0 0 10px;display:flex;justify-content:space-between;gap:8px}aside h3 a{font-weight:400;font-size:13px;color:var(--blue)}
.ev{display:grid;grid-template-columns:40px auto 1fr;align-items:center;gap:3px 8px;padding:8px 0;border-top:1px solid var(--line);font-size:12.5px}
.ev .tm{color:var(--mut);font-variant-numeric:tabular-nums}.ev code{justify-self:start}.ev .who{grid-column:2/4;color:var(--mut)}
.pill{display:inline-block;border-radius:5px;padding:0 6px;font-size:11.5px;font-weight:600;letter-spacing:.02em;height:fit-content;width:fit-content}
.p-HELD{color:var(--amber);background:var(--amber-bg)}.p-APPROVED,.p-EDITED,.p-EXECUTED{color:var(--green);background:var(--green-bg)}
.p-REJECTED,.p-BLOCKED,.p-PREVENTED{color:var(--red);background:var(--red-bg)}.p-POLICY{color:var(--blue);background:var(--blue-bg)}
.empty{padding:28px;text-align:center;color:var(--mut)}.foot{margin-top:10px;font-size:12.5px;color:var(--mut)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-top:1px solid var(--line);vertical-align:top}th{border-top:0;color:var(--mut);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.det{max-width:440px;overflow-wrap:anywhere}td.nw{white-space:nowrap}tr.human td{background:var(--green-bg)}tr.human td.who{font-weight:600}.wrap{overflow-x:auto}a{color:var(--blue)}
"""

JS = """
const show = (card, text) => { card.querySelector('.msg').textContent = text; };
document.querySelectorAll('[data-held] textarea').forEach(t => {
  const original = t.value;
  t.addEventListener('input', () => {
    const card = t.closest('[data-held]'), edited = t.value !== original;
    card.querySelector('[data-decision=edit]').disabled = !edited;
    card.querySelector('[data-decision=approve]').disabled = edited;
  });
});
document.addEventListener('click', async ev => {
  const b = ev.target.closest('button[data-decision]');
  if (!b) return;
  const card = b.closest('[data-held]');
  const body = {heldId: card.dataset.held, decision: b.dataset.decision,
                approver: card.dataset.approver, comment: card.querySelector('.note').value};
  if (body.decision === 'edit') {
    try { body.params = JSON.parse(card.querySelector('textarea').value); }
    catch { return show(card, 'The payload is not valid JSON.'); }
  }
  card.querySelectorAll('button').forEach(x => { x.disabled = true; });
  const r = await fetch('/api/decide', {method: 'POST', headers: {'content-type': 'application/json'},
                                        body: JSON.stringify(body)});
  if (r.ok) return location.reload();
  const j = await r.json().catch(() => ({}));
  card.querySelector('[data-decision=reject]').disabled = false;
  card.querySelector('textarea').dispatchEvent(new Event('input'));
  show(card, j.error || 'Request failed');
});
"""


def page(title, nonce, body, script=""):
    js = f'<script nonce="{nonce}">{script}</script>' if script else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>'
            f'<style nonce="{nonce}">{CSS}</style></head><body><main>{body}</main>{js}</body></html>')


def card(h):
    facts = "".join(f'<span class="chip">{e(k)}: {e(v)}</span>' for k, v in h.context.items()) or "none"
    who = e(h.route.approver)
    return f"""
<article class="card" data-held="{e(h.id)}" data-approver="{who}">
  <div class="route">Waiting on <b>{who}</b> <span>&middot; {e(h.route.role)}</span>
    <span class="t">&middot; held {e(h.held_at[11:16])} UTC</span></div>
  <h2>{e(h.summary)}</h2>
  <p class="why"><span class="label">Held because</span>{e(h.rule.get("reason", h.rule["ruleId"]))}</p>
  <dl>
    <dt>Needs</dt><dd><code>{e(h.route.fact)}</code> from {who}</dd>
    <dt>Facts checked</dt><dd>{facts}</dd>
    <dt>Proposed by</dt><dd>{e(h.agent)} &middot; <code>{e(h.action)}</code> &middot; rule <code>{e(h.rule["ruleId"])}</code>
      &middot; decision <code>{e(h.decision["decisionId"])}</code></dd>
  </dl>
  <label class="label" for="p-{e(h.id)}">Exact payload &middot; this is what runs</label>
  <textarea id="p-{e(h.id)}" rows="{len(h.params) + 2}" spellcheck="false">{e(json.dumps(h.params, indent=2))}</textarea>
  <div class="actions">
    <input class="note" aria-label="Note for the audit log" placeholder="Note for the audit log (optional)" maxlength="500">
    <button class="ok" data-decision="approve">Approve as {who}</button>
    <button data-decision="edit" disabled>Approve with edits</button>
    <button class="no" data-decision="reject">Reject</button>
    <span class="msg" role="status"></span>
  </div>
</article>"""


HUMAN = {"APPROVED", "EDITED", "REJECTED"}
TRAIL = HUMAN | {"HELD", "EXECUTED", "BLOCKED"}  # the full log has everything


def ev_row(r):
    detail = (r.get("routedTo") and f"routed to {r['routedTo']}") or r.get("result") or r.get("error") \
        or (r.get("comment") and f"\u201c{r['comment']}\u201d") or ""
    return (f'<div class="ev"><span class="tm">{e(r["at"][11:16])}</span>'
            f'<span class="pill p-{e(r["event"])}">{e(r["event"])}</span><code>{e(r.get("action", ""))}</code>'
            f'<span class="who">by {e(r["actor"])}{" &middot; " + e(detail) if detail else ""}</span></div>')


def home(loop, nonce):
    recs = loop.audit.records()
    session = [r for r in recs if r["seq"] > loop.audit.start]
    ran = sum(r["event"] == "EXECUTED" for r in session)
    blocked = sum(r["event"] == "BLOCKED" for r in session)
    waiting = loop.waiting()
    cards = "".join(card(h) for h in waiting) or '<div class="card empty">Nothing is waiting. Every held action has a decision.</div>'
    trail = "".join(ev_row(r) for r in [r for r in reversed(recs) if r["event"] in TRAIL][:12])
    body = f"""
<header><div><h1>Held actions</h1>
<p class="sub">Agent actions a policy Rule stopped until a named person signs off. Nothing below runs until they approve.</p></div>
<div class="stats"><span class="stat wait"><b>{len(waiting)}</b> waiting for a person</span>
<span class="stat ran"><b>{ran}</b> ran</span><span class="stat blk"><b>{blocked}</b> blocked</span></div></header>
<div class="grid"><section aria-label="Held actions">{cards}</section>
<aside class="card"><h3>Audit trail <a href="/audit">Full log</a></h3>{trail}
<p class="foot">{len(recs)} records &middot; hash chain {"intact" if loop.audit.verify() else "BROKEN"} &middot;
<a href="/audit.jsonl">Export audit.jsonl</a></p></aside></div>"""
    return page("Held actions", nonce, body, JS)


def audit_row(r, skip):
    human = ' class="human"' if r["event"] in HUMAN else ""
    dec = "<code>%s</code>" % e(r["decisionId"]) if r.get("decisionId") else ""
    details = json.dumps({k: v for k, v in r.items() if k not in skip}, sort_keys=True)
    return (f'<tr{human}><td>{e(r["seq"])}</td><td class="nw">{e(r["at"].replace("T", " ").rstrip("Z"))}</td>'
            f'<td><span class="pill p-{e(r["event"])}">{e(r["event"])}</span></td><td class="who">{e(r["actor"])}</td>'
            f'<td><code>{e(r.get("action", ""))}</code></td><td>{dec}</td><td class="det">{e(details)}</td></tr>')


def audit_page(loop, nonce):
    recs, ok = loop.audit.records(), loop.audit.verify()
    skip = {"seq", "at", "event", "actor", "action", "decisionId", "prev"}
    rows = "".join(audit_row(r, skip) for r in recs)
    body = f"""
<header><div><h1>Audit log</h1><p class="sub">Append-only. Who decided, when, and what the Policy API said before and after.
Each line carries the sha256 of the line before it.</p></div>
<div class="stats"><span class="stat"><b>{len(recs)}</b> records</span>
<span class="stat {"ran" if ok else "blk"}">hash chain <b>{"intact" if ok else "BROKEN"}</b></span>
<a class="stat" href="/audit.jsonl">Export audit.jsonl</a><a class="stat" href="/">Back to held actions</a></div></header>
<div class="wrap"><table><thead><tr><th>#</th><th>When (UTC)</th><th>Event</th><th>Who</th><th>Action</th><th>Decision</th>
<th>Details</th></tr></thead><tbody>{rows}</tbody></table></div>"""
    return page("Audit log", nonce, body)


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    server_version = "held-actions"

    def _send(self, status, data, ctype, nonce=None, extra=()):
        data = data.encode() if isinstance(data, str) else data
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("content-security-policy",
                         "default-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
                         f"frame-ancestors 'none'; script-src 'nonce-{nonce or 'x'}'; style-src 'nonce-{nonce or 'x'}'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), "application/json")

    def _host_ok(self):
        if self.headers.get("Host") in self.server.allowed:  # blocks DNS rebinding
            return True
        self._json(403, {"error": "bad Host header"})
        return False

    def do_GET(self):
        if not self._host_ok():
            return
        loop, nonce = self.server.loop, secrets.token_urlsafe(16)
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, home(loop, nonce), "text/html; charset=utf-8", nonce)
        elif path == "/audit":
            self._send(200, audit_page(loop, nonce), "text/html; charset=utf-8", nonce)
        elif path == "/audit.jsonl":
            data = loop.audit.path.read_bytes() if loop.audit.path.exists() else b""
            self._send(200, data, "application/x-ndjson", extra=[("content-disposition", 'attachment; filename="audit.jsonl"')])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return
        if self.headers.get("Origin") not in {"http://" + h for h in self.server.allowed}:
            return self._json(403, {"error": "bad or missing Origin header"})  # CSRF
        if self.headers.get_content_type() != "application/json":
            return self._json(415, {"error": "send application/json"})
        try:
            n = int(self.headers.get("content-length", ""))
        except ValueError:
            return self._json(411, {"error": "content-length required"})
        if n > MAX_POST:
            return self._json(413, {"error": "body too large"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self._json(400, {"error": "body is not JSON"})
        if self.path != "/api/decide":
            return self._json(404, {"error": "not found"})
        if not isinstance(body, dict):
            return self._json(400, {"error": "body must be a JSON object"})
        try:
            # ponytail: no login locally, each card acts as its routed approver. Behind SSO, take the
            # approver from the session, never from the body. decide() still refuses anyone else.
            out = self.server.loop.decide(str(body.get("heldId", "")), body.get("decision"),
                                          body.get("approver"), body.get("params"), body.get("comment", ""))
        except LookupError as x:
            return self._json(404, {"error": str(x)})
        except PermissionError as x:
            return self._json(403, {"error": str(x)})
        except ValueError as x:
            return self._json(409 if "already" in str(x) else 400, {"error": str(x)})
        except PolicyError as x:
            msg = x.body
            try:
                msg = json.loads(x.body)["error"]["message"]
            except (ValueError, KeyError, TypeError):
                pass
            return self._json(400 if x.status < 500 else 502, {"error": f"Policy API refused it: {msg}"})
        self._json(200, out)

    def log_message(self, *a):
        pass


def make_server(loop, port=8765):
    srv = HTTPServer(("127.0.0.1", port), Handler)  # loopback only
    srv.loop = loop
    srv.allowed = {f"127.0.0.1:{srv.server_port}", f"localhost:{srv.server_port}"}
    return srv


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    if os.environ.get("RIPPLETIDE_BASE_URL"):
        client, where = PolicyClient(), os.environ["RIPPLETIDE_BASE_URL"]
    else:
        state, url, _ = mock_policy_api.serve()
        client, where = PolicyClient(url, state.api_key), f"local mock at {url}"
    loop = HeldActions(client, ROUTES, demo_execute, HERE / "audit.jsonl")
    run_demo_agent(loop)
    srv = make_server(loop, port)
    print(f"Policy API: {where}\nAgent proposed {len(DEMO)} actions, {len(loop.waiting())} held.\n"
          f"Approver page: http://127.0.0.1:{srv.server_port}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
