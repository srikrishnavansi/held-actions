"""Local stand-in for the Rippletide runtime Policy API, so the loop runs with no account.

Shapes follow the public docs (read 2026-10-12):
  Policy API ............ https://docs.rippletide.com/docs/policy-api
  Dispositions/modes .... https://docs.rippletide.com/docs/observe-and-enforce
  Catalogue format ...... https://docs.rippletide.com/docs/policy-api ("catalog.json")
  "approvals ... are not a separate generic Escalate disposition" ... https://docs.rippletide.com

Only the two runtime routes the loop needs are mocked:
  POST /v1/policy/decide                          -> decisionId, invocationId, disposition, rule snapshot
  POST /v1/policy/decisions/:decisionId/receipt   -> EXECUTED | PREVENTED
Not documented, so ASSUMED here: the field name and inner shape of the rule snapshot (`rules`),
the `outcome`/`reason` field names for UNDETERMINED/NO_MATCH, and the error body shape.
"""
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BODY = 256 * 1024  # docs: "Runtime bodies are limited to 256 KB"

# Declared catalogue, in the documented catalog.json format (formatVersion / actions / key / name / paramsSchema).
CATALOG = {
    "formatVersion": 1,
    "actions": [
        {"key": "tickets/close", "name": "close_ticket", "paramsSchema": {
            "type": "object", "required": ["ticket_id"], "additionalProperties": False,
            "properties": {"ticket_id": {"type": "string"}, "resolution": {"type": "string"}}}},
        {"key": "payments/issue_refund", "name": "issue_refund", "paramsSchema": {
            "type": "object", "required": ["order_id", "amount_eur"], "additionalProperties": False,
            "properties": {"order_id": {"type": "string"}, "amount_eur": {"type": "number"},
                           "reason": {"type": "string"}}}},
        {"key": "accounts/change_status", "name": "change_account_status", "paramsSchema": {
            "type": "object", "required": ["account_id", "status"], "additionalProperties": False,
            "properties": {"account_id": {"type": "string"},
                           "status": {"type": "string", "enum": ["active", "suspended", "closed"]}}}},
        {"key": "email/send_customer", "name": "send_customer_email", "paramsSchema": {
            "type": "object", "required": ["to", "subject", "body"], "additionalProperties": False,
            "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}}},
        {"key": "statuspage/set_status", "name": "set_status_page", "paramsSchema": {
            "type": "object", "required": ["incident_id", "status"], "additionalProperties": False,
            "properties": {"incident_id": {"type": "string"},
                           "status": {"type": "string", "enum": ["investigating", "monitoring", "resolved"]},
                           "message": {"type": "string"}}}},
    ],
}

# Rule releases. Real Rules are written and versioned in the app/CLI (docs/write-rules);
# ponytail: a Python predicate stands in for each compiled release.
# An approval is just a trusted context fact the Rule checks for (e.g. finance_lead_approval),
# which is how docs say approvals live: "recorded from your runtime", not a disposition.
RULES = [
    {"ruleId": "rule_close_confirmed", "name": "Close tickets the customer confirmed",
     "action": "tickets/close", "effect": "ALLOW", "mode": "ENFORCE",
     "reason": "Customer confirmed the fix.",
     "when": lambda p, c: c.get("customer_confirmed") is True},
    {"ruleId": "rule_refund_over_250", "name": "Large refunds need the finance lead",
     "action": "payments/issue_refund", "effect": "BLOCK", "mode": "ENFORCE",
     "reason": "Refunds over EUR 250 require finance lead approval.",
     "when": lambda p, c: p["amount_eur"] > 250 and not c.get("finance_lead_approval")},
    {"ruleId": "rule_suspend_paying_account", "name": "Suspending a paying account needs its owner",
     "action": "accounts/change_status", "effect": "BLOCK", "mode": "ENFORCE",
     "reason": "Suspending a paying account requires account owner approval.",
     "when": lambda p, c: p["status"] == "suspended" and c.get("plan") != "free"
     and not c.get("account_owner_approval")},
    {"ruleId": "rule_no_email_opted_out", "name": "Never email a customer who opted out",
     "action": "email/send_customer", "effect": "BLOCK", "mode": "ENFORCE",
     "reason": "Customer opted out of email contact.",
     "when": lambda p, c: c.get("customer_opted_out") is True},
    {"ruleId": "rule_status_page_ic", "name": "Customer-facing status changes need the incident commander",
     "action": "statuspage/set_status", "effect": "BLOCK", "mode": "ENFORCE",
     "reason": "Customer-facing status changes require incident commander approval.",
     "when": lambda p, c: not c.get("incident_commander_approval")},
]

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
}


def schema_errors(schema, value):
    """The subset of JSON Schema the catalogue above uses. Docs: invalid schemas are errors, not Allow."""
    if not isinstance(value, dict):
        return ["params must be an object"]
    props = schema.get("properties", {})
    errs = [f"missing {k}" for k in schema.get("required", []) if k not in value]
    if schema.get("additionalProperties") is False:
        errs += [f"unknown field {k}" for k in value if k not in props]
    for k, v in value.items():
        spec = props.get(k, {})
        if "type" in spec and not _TYPES[spec["type"]](v):
            errs.append(f"{k} must be a {spec['type']}")
        elif "enum" in spec and v not in spec["enum"]:
            errs.append(f"{k} must be one of {spec['enum']}")
    return errs


def disposition(matched):
    """Effective disposition, straight from the observe-and-enforce table."""
    blocks = [r for r in matched if r["effect"] == "BLOCK"]
    if any(r["mode"] == "ENFORCE" for r in blocks):
        return "BLOCK"
    if blocks:
        return "WOULD_BLOCK"  # blocking matches were all Observe-only
    return "ALLOW"  # an Allow match, or no match (UNDETERMINED / NO_MATCH still lets it proceed)


class PolicyState:
    def __init__(self, api_key, rules=RULES, catalog=CATALOG):
        self.api_key = api_key
        self.rules = rules
        self.actions = {a["key"]: a for a in catalog["actions"]}
        self.decisions = {}      # decisionId -> response body
        self.invocations = {}    # invocationId -> (input fingerprint, decisionId)
        self.receipts = {}       # decisionId -> receipt body
        self.lock = threading.Lock()

    def handle(self, method, path, api_key, body):
        """Returns (status, json). Pure enough to read top to bottom."""
        if not api_key or not secrets.compare_digest(api_key, self.api_key):
            return 401, _err("UNAUTHORIZED", "missing or wrong x-api-key (Connection key)")
        if method != "POST":
            return 405, _err("METHOD_NOT_ALLOWED", "POST only")
        if not isinstance(body, dict):
            return 400, _err("INVALID_REQUEST", "body must be a JSON object")
        with self.lock:
            if path == "/v1/policy/decide":
                return self._decide(body)
            parts = path.split("/")  # ['', 'v1', 'policy', 'decisions', id, 'receipt']
            if len(parts) == 6 and parts[1:4] == ["v1", "policy", "decisions"] and parts[5] == "receipt":
                return self._receipt(parts[4], body)
        return 404, _err("NOT_FOUND", path)

    def _decide(self, b):
        inv, action, params, ctx = b.get("invocationId"), b.get("action"), b.get("params"), b.get("context", {})
        if not isinstance(inv, str) or not inv:
            return 400, _err("INVALID_REQUEST", "invocationId is required")
        if action not in self.actions:
            return 400, _err("INVALID_REQUEST", f"action {action!r} is not in the declared catalogue")
        errs = schema_errors(self.actions[action]["paramsSchema"], params)
        if errs or not isinstance(ctx, dict):
            return 400, _err("INVALID_REQUEST", "; ".join(errs or ["context must be an object"]))

        fp = hashlib.sha256(json.dumps([action, params, ctx], sort_keys=True).encode()).hexdigest()
        if inv in self.invocations:  # docs: identical retry replays, different input is a conflict
            seen_fp, dec_id = self.invocations[inv]
            if seen_fp != fp:
                return 409, _err("INVOCATION_CONFLICT", "invocationId reused with different input")
            return 200, self.decisions[dec_id]

        matched = [r for r in self.rules
                   if r["action"] == action and r["mode"] != "DISABLED" and r["when"](params, ctx)]
        dec = {
            "decisionId": "dec_" + secrets.token_hex(8),
            "invocationId": inv,
            "disposition": disposition(matched),
            # ASSUMED shape: docs only say the response includes "the immutable Rule snapshot".
            "rules": [{k: r[k] for k in ("ruleId", "name", "effect", "mode", "reason")} for r in matched],
        }
        if not matched:
            dec.update(outcome="UNDETERMINED", reason="NO_MATCH")
        self.decisions[dec["decisionId"]] = dec
        self.invocations[inv] = (fp, dec["decisionId"])
        return 200, dec

    def _receipt(self, dec_id, b):
        if dec_id not in self.decisions:
            return 404, _err("NOT_FOUND", "unknown decisionId")
        receipt = {"outcome": b.get("outcome"), "occurredAt": b.get("occurredAt")}
        if receipt["outcome"] not in ("EXECUTED", "PREVENTED") or not isinstance(receipt["occurredAt"], str):
            return 400, _err("INVALID_REQUEST", "outcome must be EXECUTED or PREVENTED, with occurredAt")
        if dec_id in self.receipts and self.receipts[dec_id] != receipt:
            return 409, _err("RECEIPT_CONFLICT", "a different receipt was already reported")
        self.receipts[dec_id] = receipt
        return 200, {"decisionId": dec_id, **receipt}


def _err(code, message):
    return {"error": {"code": code, "message": message}}  # ASSUMED error body shape


def serve(port=0, api_key=None):
    """Start the mock on 127.0.0.1 in a background thread. Returns (state, base_url, server)."""
    state = PolicyState(api_key or secrets.token_hex(16))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            if n > MAX_BODY:
                return self._send(413, _err("PAYLOAD_TOO_LARGE", "runtime bodies are limited to 256 KB"))
            try:
                body = json.loads(self.rfile.read(n) or b"null")
            except ValueError:
                return self._send(400, _err("INVALID_REQUEST", "body is not JSON"))
            self._send(*state.handle("POST", self.path, self.headers.get("x-api-key"), body))

        def do_GET(self):
            self._send(*state.handle("GET", self.path, self.headers.get("x-api-key"), None))

        def _send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return state, f"http://127.0.0.1:{server.server_port}", server


if __name__ == "__main__":
    st, url, _ = serve(8787)
    print(f"mock Policy API on {url}  (x-api-key: {st.api_key})")
    threading.Event().wait()
