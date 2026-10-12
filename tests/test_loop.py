"""python3 tests/test_loop.py : hold, approve, reject, edit, audit log, and the page guards."""
import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mock_policy_api  # noqa: E402
import server  # noqa: E402
from held_actions import HeldActions, PolicyClient, PolicyError  # noqa: E402

REFUND = ("payments/issue_refund", {"order_id": "ORD-1", "amount_eur": 480, "reason": "dup"}, {"customer_tier": "pro"})


class Loop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.url, cls.mock = mock_policy_api.serve()  # real HTTP, same calls as production

    @classmethod
    def tearDownClass(cls):
        cls.mock.shutdown()
        cls.mock.server_close()

    def setUp(self):
        self.ran = []
        self.audit = Path(tempfile.mkdtemp()) / "audit.jsonl"
        self.loop = HeldActions(PolicyClient(self.url, self.state.api_key), server.ROUTES,
                                lambda a, p: self.ran.append((a, p)) or "done", self.audit)
        self.n = 0

    def propose(self, action, params, ctx):
        self.n += 1
        return self.loop.propose("agent", action, params, ctx, f"{self.id()}-{self.n}")

    def test_allow_runs_and_hard_block_drops(self):
        r = self.propose("tickets/close", {"ticket_id": "1"}, {"customer_confirmed": True})
        self.assertEqual(r["status"], "executed")
        self.assertEqual(self.state.receipts[r["decisionId"]]["outcome"], "EXECUTED")
        r = self.propose("email/send_customer", {"to": "a@b.c", "subject": "s", "body": "b"}, {"customer_opted_out": True})
        self.assertEqual(r["status"], "blocked")           # not routable -> nobody can approve it
        self.assertEqual(self.state.receipts[r["decisionId"]]["outcome"], "PREVENTED")
        self.assertEqual(len(self.ran), 1)

    def test_hold(self):
        # The agent tries to approve itself; the fact is stripped and the action is still held.
        r = self.propose(REFUND[0], REFUND[1], {**REFUND[2], "finance_lead_approval": True})
        self.assertEqual(r["status"], "held")
        self.assertEqual(r["routedTo"], "Malik Benali")
        self.assertEqual(self.ran, [])
        self.assertEqual(self.state.decisions[r["decisionId"]]["disposition"], "BLOCK")
        self.assertEqual(self.state.receipts[r["decisionId"]]["outcome"], "PREVENTED")
        self.assertEqual([h.id for h in self.loop.waiting()], [r["heldId"]])

    def test_approve(self):
        h = self.propose(*REFUND)["heldId"]
        with self.assertRaises(PermissionError):           # only the routed approver can decide
            self.loop.decide(h, "approve", "Claire Moreau")
        r = self.loop.decide(h, "approve", "Malik Benali", comment="duplicate confirmed")
        self.assertEqual(r["status"], "executed")
        self.assertEqual(self.ran, [REFUND[:2]])
        second = self.state.decisions[r["decisionId"]]
        self.assertEqual(second["disposition"], "ALLOW")
        self.assertTrue(second["invocationId"].endswith("-approved"))  # new attempt, new invocationId
        self.assertEqual(self.state.receipts[r["decisionId"]]["outcome"], "EXECUTED")
        with self.assertRaises(ValueError):                # no double decisions
            self.loop.decide(h, "approve", "Malik Benali")

    def test_reject(self):
        h = self.propose(*REFUND)["heldId"]
        decisions_before = len(self.state.decisions)
        self.assertEqual(self.loop.decide(h, "reject", "Malik Benali", comment="not a duplicate")["status"], "rejected")
        self.assertEqual(self.ran, [])
        self.assertEqual(len(self.state.decisions), decisions_before)  # nothing re-checked, nothing ran
        self.assertEqual(self.loop.waiting(), [])

    def test_edit(self):
        h = self.propose(*REFUND)["heldId"]
        with self.assertRaises(PolicyError):               # a bad edit is refused by the catalogue schema
            self.loop.decide(h, "edit", "Malik Benali", params={**REFUND[1], "iban": "x"})
        self.assertEqual(len(self.loop.waiting()), 1)      # ...and the item is still waiting
        edited = {**REFUND[1], "amount_eur": 200}
        r = self.loop.decide(h, "edit", "Malik Benali", params=edited)
        self.assertEqual(r["status"], "executed")
        self.assertEqual(self.ran, [(REFUND[0], edited)])  # the edited payload ran, not the original
        rec = [x for x in self.loop.audit.records() if x["event"] == "EDITED"][0]
        self.assertEqual((rec["before"]["amount_eur"], rec["after"]["amount_eur"]), (480, 200))

    def test_audit_log(self):
        h = self.propose(*REFUND)["heldId"]
        self.loop.decide(h, "approve", "Malik Benali")
        recs = [json.loads(x) for x in self.audit.read_text().splitlines()]
        self.assertEqual([r["event"] for r in recs],
                         ["POLICY", "PREVENTED", "HELD", "APPROVED", "POLICY", "EXECUTED"])
        approved = recs[3]
        self.assertEqual(approved["actor"], "Malik Benali")
        self.assertRegex(approved["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(self.loop.audit.verify())
        lines = self.audit.read_text().splitlines()       # rewrite history -> chain breaks
        lines[3] = lines[3].replace("Malik Benali", "Someone Else")
        self.audit.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.loop.audit.verify())


class Page(unittest.TestCase):
    def setUp(self):
        self.state, url, self.mock = mock_policy_api.serve()
        self.loop = HeldActions(PolicyClient(url, self.state.api_key), server.ROUTES, server.demo_execute,
                                Path(tempfile.mkdtemp()) / "audit.jsonl")
        self.held = self.loop.propose("agent", *REFUND[:2], {}, "page-1",
                                      summary='<script>alert(1)</script><img src=x onerror=alert(2)>')["heldId"]
        self.srv = server.make_server(self.loop, 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_port

    def tearDown(self):
        for s in (self.srv, self.mock):
            s.shutdown()
            s.server_close()

    def req(self, method, path, body=None, **headers):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest(method, path, skip_host=True)
        for k, v in {"Host": f"127.0.0.1:{self.port}", **headers}.items():
            if v is not None:
                c.putheader(k, v)
        data = body.encode() if body else b""
        c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        out = r.status, r.read().decode()
        c.close()
        return out

    def test_guards(self):
        origin = f"http://127.0.0.1:{self.port}"
        ok = json.dumps({"heldId": self.held, "decision": "reject", "approver": "Malik Benali"})
        status, page = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)  # agent text is escaped
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<img src=x", page)
        self.assertEqual(self.req("GET", "/", Host="evil.example")[0], 403)  # DNS rebinding
        self.assertEqual(self.req("POST", "/api/decide", ok, **{"Content-Type": "application/json"})[0], 403)
        self.assertEqual(self.req("POST", "/api/decide", ok, Origin="http://evil.example",
                                  **{"Content-Type": "application/json"})[0], 403)  # CSRF
        self.assertEqual(self.req("POST", "/api/decide", "heldId=x", Origin=origin,
                                  **{"Content-Type": "application/x-www-form-urlencoded"})[0], 415)
        self.assertEqual(self.loop.waiting()[0].status, "waiting")  # none of the above decided anything
        self.assertEqual(self.req("POST", "/api/decide", ok, Origin=origin,
                                  **{"Content-Type": "application/json"})[0], 200)
        self.assertEqual(self.loop.waiting(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
