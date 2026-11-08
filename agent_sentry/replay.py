"""Replay authored scenarios. This measures policy behavior, not model robustness."""

import json
import tempfile
from pathlib import Path

from .store import Store


def evaluate(path):
    suite = json.loads(Path(path).read_text(encoding="utf-8"))
    results = []
    for case in suite["cases"]:
        with tempfile.TemporaryDirectory() as folder:
            clock = [1_000_000.0]
            store = Store(Path(folder) / "replay.db", clock=lambda: clock[0])
            session = store.create_session(suite["policy"])
            approvals = {}
            checks = []
            for i, step in enumerate(case["steps"]):
                if "advance" in step:
                    clock[0] += step["advance"]
                    continue
                if "approve" in step:
                    call = step["approve"]
                    approvals[step["as"]] = store.approve(
                        session, call["tool"], call["arguments"], step.get("ttl", 300)
                    )
                    continue
                kwargs = {
                    "session": session,
                    "request_id": step.get("request_id", f"call-{i}"),
                    "tool": step["tool"],
                    "arguments": step["arguments"],
                }
                if "approval" in step:
                    kwargs["approval"] = approvals[step["approval"]]
                result = store.authorize(**kwargs)
                checks.append(
                    {
                        "expected": step["expect"],
                        "actual": result["reason"],
                        "passed": result["reason"] == step["expect"],
                    }
                )
            results.append(
                {
                    "id": case["id"],
                    "category": case["category"],
                    "passed": bool(checks)
                    and all(c["passed"] for c in checks)
                    and store.verify()["valid"],
                    "checks": checks,
                }
            )
    return {
        "suite": suite["name"],
        "kind": "authored deterministic policy scenarios; no LLM calls",
        "cases": len(results),
        "passed": sum(r["passed"] for r in results),
        "results": results,
    }
