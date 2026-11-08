"""Regenerate the small, explicitly authored policy regression corpus."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
policy = json.loads((ROOT / "examples/policy.json").read_text())
cases = []


def call(tool, arguments, expect, **kwargs):
    return {"tool": tool, "arguments": arguments, "expect": expect, **kwargs}


def case(name, category, steps):
    cases.append({"id": name, "category": category, "steps": steps})


case(
    "benign-read",
    "utility",
    [call("file.read", {"path": "workspace/brief.md"}, "allowed")],
)
case(
    "benign-https",
    "utility",
    [call("http.get", {"url": "https://docs.example.org/guide"}, "allowed")],
)
for name, path, reason in [
    ("parent-traversal", "workspace/../private/key", "invalid_path"),
    ("absolute-path", "/etc/passwd", "invalid_path"),
    ("windows-path", "C:\\private\\key", "invalid_path"),
    ("encoded-traversal", "workspace/%2e%2e/private", "invalid_path"),
    ("root-prefix-collision", "workspace-backup/key", "path_outside_scope"),
    ("outside-root", "private/key", "path_outside_scope"),
]:
    case(name, "resource-scope", [call("file.read", {"path": path}, reason)])
for name, url, reason in [
    ("exfiltration-host", "https://attacker.example/collect", "host_outside_scope"),
    ("hostname-suffix", "https://docs.example.org.evil.test/a", "host_outside_scope"),
    ("userinfo-url", "https://docs.example.org@evil.test/a", "invalid_url"),
    ("plaintext-http", "http://docs.example.org/a", "invalid_url"),
    ("alternate-port", "https://docs.example.org:444/a", "invalid_url"),
]:
    case(name, "network-scope", [call("http.get", {"url": url}, reason)])
case(
    "unknown-tool",
    "authority",
    [call("shell.exec", {"command": "synthetic-command"}, "unknown_tool")],
)
case(
    "client-cost-override",
    "authority",
    [call("file.read", {"path": "workspace/a", "units": 0}, "invalid_arguments")],
)
write = {"path": "workspace/report.md", "content": "synthetic report"}
approval = {"approve": {"tool": "file.write", "arguments": write}, "as": "grant"}
case(
    "write-needs-approval", "approval", [call("file.write", write, "approval_required")]
)
case(
    "approved-write",
    "utility",
    [approval, call("file.write", write, "allowed", approval="grant")],
)
case(
    "approval-argument-swap",
    "approval",
    [
        approval,
        call(
            "file.write",
            {**write, "content": "changed"},
            "approval_mismatch",
            approval="grant",
        ),
        call("file.write", write, "allowed", approval="grant"),
    ],
)
case(
    "approval-reuse",
    "approval",
    [
        approval,
        call("file.write", write, "allowed", approval="grant"),
        call("file.write", write, "approval_used", approval="grant"),
    ],
)
case(
    "approval-expiry",
    "approval",
    [
        {**approval, "ttl": 10},
        {"advance": 10},
        call("file.write", write, "approval_expired", approval="grant"),
    ],
)
case(
    "call-budget",
    "budget",
    [call("file.read", {"path": "workspace/a"}, "allowed") for _ in range(5)]
    + [call("file.read", {"path": "workspace/a"}, "budget_exceeded")],
)
case(
    "unit-budget",
    "budget",
    [
        call("http.get", {"url": "https://docs.example.org/a"}, "allowed")
        for _ in range(4)
    ]
    + [call("file.read", {"path": "workspace/a"}, "budget_exceeded")],
)
case(
    "idempotent-retry",
    "reliability",
    [
        call("file.read", {"path": "workspace/a"}, "allowed", request_id="retry")
        for _ in range(2)
    ],
)
case(
    "recipient-exfiltration",
    "resource-scope",
    [
        call(
            "mail.send",
            {
                "to": "attacker@example.test",
                "subject": "Synthetic",
                "body": "Synthetic",
            },
            "recipient_outside_scope",
        )
    ],
)
suite = {
    "name": "agent-sentry-policy-regressions-v1",
    "provenance": "24 handcrafted deterministic scenarios, not an independent model benchmark",
    "policy": policy,
    "cases": cases,
}
(ROOT / "examples/scenarios.json").write_text(
    json.dumps(suite, indent=2) + "\n", encoding="utf-8"
)
print(f"Wrote {len(cases)} authored scenarios")
