"""Held actions: the human half of a Rippletide Block.

The Policy API returns ALLOW / WOULD_BLOCK / BLOCK (https://docs.rippletide.com/docs/policy-api).
An approval is not a disposition; the docs say it is "recorded from your runtime" (https://docs.rippletide.com).
So: a Rule blocks the action until a trusted context fact (say `finance_lead_approval`) is present.
When an enforced BLOCK comes only from Rules listed in the routing table, this loop holds the action
for the named approver instead of dropping it. On approval it adds that fact to the context and asks
the Policy API again with a new invocationId; the action runs only if that second decision allows it.
"""
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class PolicyError(Exception):
    def __init__(self, status, body):
        super().__init__(f"Policy API {status}: {body}")
        self.status, self.body = status, body


class PolicyClient:
    """Raw HTTP, exactly the documented calls. Point RIPPLETIDE_BASE_URL / RIPPLETIDE_API_KEY at a
    real Connection to use Rippletide instead of the mock; nothing else changes."""

    def __init__(self, base_url=None, api_key=None):
        self.base_url = (base_url or os.environ["RIPPLETIDE_BASE_URL"]).rstrip("/")
        self.api_key = api_key or os.environ["RIPPLETIDE_API_KEY"]

    def _post(self, path, body):
        req = urllib.request.Request(
            self.base_url + path, data=json.dumps(body).encode(), method="POST",
            headers={"content-type": "application/json", "x-api-key": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            # Docs: auth/schema errors are errors, not Allow. We fail closed: nothing runs.
            with e:
                raise PolicyError(e.code, e.read().decode(errors="replace")) from None

    def decide(self, invocation_id, action, params, context):
        return self._post("/v1/policy/decide",
                          {"invocationId": invocation_id, "action": action, "params": params, "context": context})

    def receipt(self, decision_id, outcome, occurred_at):
        return self._post(f"/v1/policy/decisions/{urllib.parse.quote(decision_id, safe='')}/receipt",
                          {"outcome": outcome, "occurredAt": occurred_at})


class Audit:
    """Append-only JSONL. Each line carries the sha256 of the line before it, so an edited or
    deleted line breaks the chain (verify())."""

    def __init__(self, path):
        self.path = Path(path)
        lines = self.path.read_text().splitlines() if self.path.exists() else []
        # ponytail: reads the whole file once at start; keep the tail hash elsewhere if it grows huge
        self.seq, self.prev = len(lines), _sha(lines[-1]) if lines else "0" * 64
        self.start = self.seq  # records after this were written by this process

    def write(self, event, actor, **detail):
        self.seq += 1
        rec = {"seq": self.seq, "at": now(), "event": event, "actor": actor, **detail, "prev": self.prev}
        line = json.dumps(rec, sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.prev = _sha(line)
        return rec

    def records(self):
        return [json.loads(x) for x in self.path.read_text().splitlines()] if self.path.exists() else []

    def verify(self):
        prev = "0" * 64
        for line in self.path.read_text().splitlines() if self.path.exists() else []:
            if json.loads(line).get("prev") != prev:
                return False
            prev = _sha(line)
        return True


def _sha(line):
    return hashlib.sha256(line.encode()).hexdigest()


@dataclass(frozen=True)
class Route:
    fact: str       # trusted context fact that lifts the Rule, e.g. "finance_lead_approval"
    approver: str   # the named person who decides
    role: str


@dataclass
class Held:
    id: str
    action: str
    params: dict
    context: dict
    agent: str
    summary: str
    invocation_id: str
    decision: dict
    rule: dict
    route: Route
    held_at: str = field(default_factory=now)
    status: str = "waiting"   # waiting | deciding | released | rejected | blocked | passed on (to a next approver)
    result: str = ""


class HeldActions:
    def __init__(self, client, routes, execute, audit_path):
        self.client = client
        self.routes = routes                     # ruleId -> Route
        self.execute = execute                   # execute(action, params) -> str; the protected effect
        self.audit = Audit(audit_path)
        self.items = {}                          # ponytail: in-memory queue; back it with a table to survive restarts
        self.approval_facts = {r.fact for r in routes.values()}

    def propose(self, agent, action, params, context, invocation_id, summary=""):
        # An agent must never approve itself: approval facts only come from decide() below.
        ctx = {k: v for k, v in context.items() if k not in self.approval_facts}
        dec = self.client.decide(invocation_id, action, params, ctx)
        return self._apply(agent, agent, action, params, ctx, invocation_id, summary or action, dec)

    def decide(self, held_id, decision, approver, params=None, comment=""):
        """decision: approve | edit | reject. `approver` comes from your SSO session in production."""
        h = self.items.get(held_id)
        if h is None:
            raise LookupError("no such held action")
        if h.status != "waiting":
            raise ValueError(f"already decided: {h.status}")
        if approver != h.route.approver:
            raise PermissionError(f"routed to {h.route.approver}, not {approver}")
        if decision not in ("approve", "edit", "reject"):
            raise ValueError("decision must be approve, edit or reject")
        comment = str(comment or "")[:500]

        if decision == "reject":
            h.status = "rejected"   # its decision already got a PREVENTED receipt when it was held
            self.audit.write("REJECTED", approver, heldId=h.id, action=h.action, comment=comment)
            return {"status": "rejected"}

        if decision == "edit" and not isinstance(params, dict):
            raise ValueError("edited params must be a JSON object")
        new_params = params if decision == "edit" else h.params
        ctx = {**h.context, h.route.fact: {"by": approver, "at": now(), "heldDecisionId": h.decision["decisionId"]}}
        inv = h.invocation_id + "-approved"  # docs: "Use a new invocation ID for every real attempt"
        h.status = "deciding"  # nobody can decide it twice, even if something below fails
        try:
            dec = self.client.decide(inv, h.action, new_params, ctx)
        except Exception:
            h.status = "waiting"  # e.g. a 400 for a bad edit: nothing recorded, still held
            raise
        self.audit.write("EDITED" if decision == "edit" else "APPROVED", approver, heldId=h.id, action=h.action,
                         comment=comment, fact=h.route.fact,
                         **({"before": h.params, "after": new_params} if decision == "edit" else {}))
        r = self._apply(approver, h.agent, h.action, new_params, ctx, inv, h.summary, dec)
        h.status = {"executed": "released", "held": "passed on", "blocked": "blocked"}[r["status"]]
        h.result = r.get("result", "")
        return r

    def _apply(self, actor, agent, action, params, ctx, invocation_id, summary, dec):
        """Honor one decision: run it, hold it for a named person, or drop it."""
        disp = dec["disposition"]
        self.audit.write("POLICY", actor, action=action, invocationId=invocation_id,
                         decisionId=dec["decisionId"], disposition=disp,
                         rules=[r["ruleId"] for r in dec.get("rules", [])])
        if disp in ("ALLOW", "WOULD_BLOCK"):   # docs: WOULD_BLOCK lets the effect run, evidence kept
            return {"status": "executed", "decisionId": dec["decisionId"],
                    "result": self._run(actor, action, params, dec)}

        self._receipt(dec, "PREVENTED", actor, action)  # this attempt did not run, whatever happens next
        # Hold only if every enforced blocking Rule is one a named person can lift, and that person
        # has not already lifted it (approving again cannot help). Anything else is a hard block.
        blocking = [r for r in dec.get("rules", []) if r["effect"] == "BLOCK" and r["mode"] == "ENFORCE"]
        routable = [r for r in blocking if r["ruleId"] in self.routes and self.routes[r["ruleId"]].fact not in ctx]
        if not blocking or len(routable) != len(blocking):
            self.audit.write("BLOCKED", actor, action=action, decisionId=dec["decisionId"])
            return {"status": "blocked", "decisionId": dec["decisionId"]}

        rule, route = routable[0], self.routes[routable[0]["ruleId"]]  # two approvals needed? one at a time
        h = Held("h_" + secrets.token_hex(4), action, params, ctx, agent, summary, invocation_id, dec, rule, route)
        self.items[h.id] = h
        self.audit.write("HELD", actor, heldId=h.id, action=action, decisionId=dec["decisionId"],
                         ruleId=rule["ruleId"], reason=rule.get("reason", ""), waitingFor=route.fact,
                         routedTo=route.approver, role=route.role, params=params)
        return {"status": "held", "heldId": h.id, "decisionId": dec["decisionId"], "routedTo": route.approver}

    def _run(self, actor, action, params, dec):
        at = now()
        try:
            result, error = str(self.execute(action, params)), ""
        except Exception as e:  # docs: EXECUTED means the handler was invoked, even if it failed
            result, error = "", f"{type(e).__name__}: {e}"
        self._receipt(dec, "EXECUTED", actor, action, at=at, result=result, error=error)
        return result or error

    def _receipt(self, dec, outcome, actor, action, at=None, **extra):
        at = at or now()
        # Local record first: if the receipt call fails, the audit still shows what really happened,
        # and the identical receipt can be retried (docs: "Receipt retries must be identical").
        self.audit.write(outcome, actor, action=action, decisionId=dec["decisionId"], occurredAt=at,
                         **{k: v for k, v in extra.items() if v})
        self.client.receipt(dec["decisionId"], outcome, at)

    def waiting(self):
        return [h for h in self.items.values() if h.status == "waiting"]
