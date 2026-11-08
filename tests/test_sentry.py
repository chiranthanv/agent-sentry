import copy
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from pathlib import Path

from agent_sentry.policy import validate_policy
from agent_sentry.gate import Gate, ReplayedCall
from agent_sentry.server import make_server, strict_json
from agent_sentry.store import Conflict, Store

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "examples/policy.json").read_text())
WRITE = {"path": "workspace/report.md", "content": "hello"}


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.db"
        self.now = 1000.0
        self.store = Store(self.path, clock=lambda: self.now)
        self.session = self.store.create_session(POLICY)

    def call(self, tool="file.read", args=None, key="first", approval=None):
        return self.store.authorize(
            self.session,
            key,
            tool,
            args if args is not None else {"path": "workspace/a"},
            approval,
        )

    def test_allow_reserves_cost_from_policy(self):
        result = self.call()
        self.assertTrue(result["allowed"])
        self.assertEqual((result["calls"], result["units"]), (1, 1))

    def test_unknown_tool_does_not_reserve(self):
        result = self.call(tool="shell.exec", args={"command": "anything"})
        self.assertEqual((result["reason"], result["units"]), ("unknown_tool", 0))

    def test_path_traversal_variants(self):
        paths = [
            "../private",
            "workspace/../secret",
            "/workspace/a",
            "workspace\\..\\key",
            "C:/workspace/a",
            "workspace/%2e%2e/key",
            "workspace//a",
            "workspace/./a",
            "workspace/a.",
            "workspace/a\x00",
        ]
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                self.assertEqual(
                    self.call(args={"path": path}, key=f"p{index}")["reason"],
                    "invalid_path",
                )

    def test_prefix_collision_is_outside_scope(self):
        self.assertEqual(
            self.call(args={"path": "workspace-evil/a"})["reason"], "path_outside_scope"
        )

    def test_unknown_argument_cannot_set_cost(self):
        self.assertEqual(
            self.call(args={"path": "workspace/a", "units": 0})["reason"],
            "invalid_arguments",
        )

    def test_write_requires_content_and_approval(self):
        self.assertEqual(self.call("file.write", WRITE)["reason"], "approval_required")
        self.assertEqual(
            self.call("file.write", {"path": "workspace/a"}, key="missing")["reason"],
            "invalid_arguments",
        )

    def test_approval_exact_arguments_and_single_use(self):
        token = self.store.approve(self.session, "file.write", WRITE)
        altered = {**WRITE, "content": "changed"}
        self.assertEqual(
            self.call("file.write", altered, "altered", token)["reason"],
            "approval_mismatch",
        )
        self.assertTrue(self.call("file.write", WRITE, "approved", token)["allowed"])
        self.assertEqual(
            self.call("file.write", WRITE, "again", token)["reason"], "approval_used"
        )

    def test_approval_bound_to_session(self):
        token = self.store.approve(self.session, "file.write", WRITE)
        other = self.store.create_session(POLICY)
        result = self.store.authorize(other, "x", "file.write", WRITE, token)
        self.assertEqual(result["reason"], "approval_mismatch")

    def test_expiry_at_boundary(self):
        token = self.store.approve(self.session, "file.write", WRITE, ttl=10)
        self.now += 10
        self.assertEqual(
            self.call("file.write", WRITE, approval=token)["reason"], "approval_expired"
        )

    def test_expired_denial_is_idempotent(self):
        token = self.store.approve(self.session, "file.write", WRITE, ttl=1)
        self.now += 2
        first = self.call("file.write", WRITE, approval=token)
        retry = self.call("file.write", WRITE, approval=token)
        self.assertEqual(first["reason"], retry["reason"])
        self.assertTrue(retry["replayed"])

    def test_retries_do_not_double_charge_or_duplicate_event(self):
        first = self.call()
        event_count = len(self.store.events())
        retry = self.call()
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["units"], first["units"])
        self.assertEqual(len(self.store.events()), event_count)

    def test_idempotency_collision_rejected(self):
        self.call()
        with self.assertRaises(Conflict):
            self.call(args={"path": "workspace/changed"})

    def test_call_budget_exhaustion(self):
        for i in range(5):
            self.assertTrue(self.call(key=f"x{i}")["allowed"])
        self.assertEqual(self.call(key="over")["reason"], "budget_exceeded")

    def test_unit_budget_exhaustion(self):
        for i in range(4):
            self.assertTrue(
                self.call("http.get", {"url": "https://docs.example.org/a"}, f"x{i}")[
                    "allowed"
                ]
            )
        self.assertEqual(self.call(key="over")["reason"], "budget_exceeded")

    def test_concurrent_budget_never_overspends_across_store_instances(self):
        barrier = threading.Barrier(16)

        def worker(index):
            store = Store(self.path)
            barrier.wait(timeout=10)
            return store.authorize(
                self.session, f"parallel-{index}", "file.read", {"path": "workspace/a"}
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(worker, range(16)))
        self.assertEqual(sum(r["allowed"] for r in results), 5)
        self.assertEqual(self.store.sessions()[0]["calls"], 5)
        self.assertTrue(self.store.verify()["valid"])

    def test_concurrent_same_request_reserves_once(self):
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.call(), range(12)))
        self.assertEqual(sum(not r["replayed"] for r in results), 1)
        self.assertEqual(self.store.sessions()[0]["calls"], 1)

    def test_concurrent_approval_consumed_once(self):
        token = self.store.approve(self.session, "file.write", WRITE)
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(
                pool.map(
                    lambda i: self.call("file.write", WRITE, f"x{i}", token), range(10)
                )
            )
        self.assertEqual(sum(r["allowed"] for r in results), 1)

    def test_transaction_rolls_back_if_audit_write_fails(self):
        token = self.store.approve(self.session, "file.write", WRITE)
        original = self.store._event

        def fail(*_):
            raise RuntimeError("simulated disk failure")

        self.store._event = fail
        with self.assertRaises(RuntimeError):
            self.call("file.write", WRITE, approval=token)
        self.store._event = original
        self.assertEqual(self.store.sessions()[0]["calls"], 0)
        self.assertTrue(self.call("file.write", WRITE, approval=token)["allowed"])

    def test_reopen_preserves_budget_and_idempotency(self):
        self.call()
        self.store = Store(self.path)
        self.assertTrue(self.call()["replayed"])
        self.assertEqual(self.store.sessions()[0]["units"], 1)

    def test_allowlist_url_bypasses(self):
        urls = [
            "https://docs.example.org.evil.test/a",
            "https://docs.example.org@evil.test/a",
            "http://docs.example.org/a",
            "https://docs.example.org:444/a",
            "https://docs.example.org/a#x",
            "https://docs.example.org\\@evil.test",
            "https://docs.example.org/\na",
        ]
        for i, url in enumerate(urls):
            with self.subTest(url=url):
                self.assertFalse(
                    self.call("http.get", {"url": url}, f"url{i}")["allowed"]
                )

    def test_exact_mail_recipient(self):
        self.assertEqual(
            self.call(
                "mail.send",
                {"to": "attacker@example.test", "subject": "x", "body": "x"},
            )["reason"],
            "recipient_outside_scope",
        )

    def test_policy_is_immutable_snapshot(self):
        mutable = copy.deepcopy(POLICY)
        session = self.store.create_session(mutable)
        mutable["max_calls"] = 0
        self.assertTrue(
            self.store.authorize(session, "x", "file.read", {"path": "workspace/a"})[
                "allowed"
            ]
        )

    def test_audit_contains_no_plaintext_arguments_or_approval(self):
        args = {
            "path": "workspace/report.md",
            "content": "private-marker-very-specific",
        }
        token = self.store.approve(self.session, "file.write", args)
        self.call("file.write", args, approval=token)
        events = json.dumps(self.store.events())
        self.assertNotIn(args["content"], events)
        self.assertNotIn(token, events)

    def test_audit_detects_modified_event(self):
        self.call()
        with self.store.connection() as db:
            db.execute("UPDATE events SET payload='{}' WHERE seq=2")
        self.assertEqual(self.store.verify()["broken_at"], 2)

    def test_pagination(self):
        self.call()
        first = self.store.events(limit=1)
        self.assertEqual(len(first), 1)
        self.assertEqual(
            self.store.events(after=first[0]["seq"])[0]["kind"], "decision"
        )

    def test_strict_input_types(self):
        for value in [True, -1, 2.5, "5"]:
            policy = copy.deepcopy(POLICY)
            policy["max_calls"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_policy(policy)
        with self.assertRaises(ValueError):
            self.call(args={"path": "workspace/a", "x": float("nan")})

    def test_invalid_policy_fails_closed(self):
        for change in [
            {"extra": 1},
            {"tools": {"shell.exec": {}}},
            {"tools": {}},
            {"name": "has spaces"},
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_policy({**POLICY, **change})

    def test_cannot_approve_outside_policy(self):
        with self.assertRaises(ValueError):
            self.store.approve(
                self.session, "file.write", {**WRITE, "path": "private/key"}
            )

    def test_gate_denied_call_never_reaches_executor(self):
        effects = []
        gate = Gate(
            self.store,
            self.session,
            {"file.write": lambda **args: effects.append(args)},
        )
        with self.assertRaises(PermissionError):
            gate.invoke("denied", "file.write", WRITE)
        self.assertEqual(effects, [])

    def test_gate_executes_once_and_refuses_replay(self):
        effects = []
        gate = Gate(
            self.store,
            self.session,
            {"file.write": lambda **args: effects.append(args)},
        )
        token = self.store.approve(self.session, "file.write", WRITE)
        gate.invoke("write", "file.write", WRITE, token)
        with self.assertRaises(ReplayedCall):
            gate.invoke("write", "file.write", WRITE, token)
        self.assertEqual(effects, [WRITE])

    def test_executor_failure_keeps_reservation(self):
        def fails(**_):
            raise OSError("Synthetic executor failure")

        gate = Gate(self.store, self.session, {"file.read": fails})
        with self.assertRaises(OSError):
            gate.invoke("failure", "file.read", {"path": "workspace/a"})
        self.assertEqual(self.store.sessions()[0]["calls"], 1)
        with self.assertRaises(ReplayedCall):
            gate.invoke("failure", "file.read", {"path": "workspace/a"})


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "http.db")
        self.session = self.store.create_session(POLICY)
        self.token = "test-only-token-" + "x" * 32
        self.server = make_server(self.store, self.token, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        merged = {"Authorization": "Bearer " + self.token, **(headers or {})}
        if isinstance(body, dict):
            body = json.dumps(body)
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body, merged)
        response = connection.getresponse()
        data = response.read()
        status, response_headers = response.status, dict(response.getheaders())
        connection.close()
        return status, data, response_headers

    def payload(self):
        return {
            "session": self.session,
            "request_id": "http-1",
            "tool": "file.read",
            "arguments": {"path": "workspace/a"},
        }

    def test_authorize_round_trip_and_conflict(self):
        status, body, _ = self.request("POST", "/v1/authorize", self.payload())
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["allowed"])
        altered = {**self.payload(), "arguments": {"path": "workspace/b"}}
        self.assertEqual(self.request("POST", "/v1/authorize", altered)[0], 409)

    def test_authentication_required(self):
        self.assertEqual(
            self.request("GET", "/v1/sessions", headers={"Authorization": ""})[0], 401
        )

    def test_cross_origin_and_host_rejected(self):
        self.assertEqual(
            self.request(
                "POST", "/v1/authorize", self.payload(), {"Origin": "https://evil.test"}
            )[0],
            403,
        )
        self.assertEqual(
            self.request("GET", "/v1/sessions", headers={"Host": "evil.test"})[0], 403
        )

    def test_malformed_json_and_duplicates(self):
        for body in ['{"x":', '{"session":"a","session":"b"}', "NaN", "[]"]:
            with self.subTest(body=body):
                self.assertEqual(
                    self.request(
                        "POST",
                        "/v1/authorize",
                        body,
                        {"Content-Type": "application/json"},
                    )[0],
                    400,
                )

    def test_oversized_body_and_wrong_media_type(self):
        self.assertEqual(self.request("POST", "/v1/authorize", "x" * 65_537)[0], 413)
        self.assertEqual(self.request("POST", "/v1/authorize", "{}")[0], 415)

    def test_read_endpoints_and_no_approval_endpoint(self):
        for path, key in [
            ("/v1/sessions", "sessions"),
            ("/v1/events", "events"),
            ("/v1/verify", "valid"),
        ]:
            status, body, _ = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn(key, json.loads(body))
        self.assertEqual(self.request("POST", "/v1/approve", {})[0], 404)

    def test_unknown_session_is_404(self):
        payload = {**self.payload(), "session": "unknown"}
        self.assertEqual(self.request("POST", "/v1/authorize", payload)[0], 404)

    def test_invalid_pagination(self):
        for query in [
            "after=-1",
            "after=no",
            "limit=501",
            "limit=0",
            "x=1",
            "limit=1&limit=2",
        ]:
            self.assertEqual(self.request("GET", "/v1/events?" + query)[0], 400)

    def test_assets_security_headers(self):
        for path in ["/", "/app.js", "/style.css"]:
            status, body, headers = self.request(
                "GET", path, headers={"Authorization": ""}
            )
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("GET", "/../../README.md")[0], 404)

    def test_duplicate_json_parser(self):
        with self.assertRaises(ValueError):
            strict_json('{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main()
