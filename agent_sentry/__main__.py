import argparse
import json
import logging
import os
import secrets
from pathlib import Path

from .replay import evaluate
from .server import make_server, strict_json
from .store import Store


def main():
    parser = argparse.ArgumentParser(
        description="Agent Sentry: local tool authorization and policy replay"
    )
    parser.add_argument("--db", default=".state/sentry.db")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("session", help="Create an immutable-policy session")
    create.add_argument("--policy", default="examples/policy.json")
    approve = sub.add_parser(
        "approve", help="Operator-only, one-use approval for exact arguments"
    )
    approve.add_argument("session")
    approve.add_argument("tool")
    approve.add_argument(
        "--arguments", required=True, help="JSON file containing exact arguments"
    )
    approve.add_argument("--ttl", type=int, default=300)
    serve = sub.add_parser("serve", help="Run authenticated loopback API and dashboard")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--token-file", default=".state/api.token")
    replay = sub.add_parser(
        "eval", help="Evaluate authored scenarios without a model or API key"
    )
    replay.add_argument("--suite", default="examples/scenarios.json")
    replay.add_argument("--output")
    sub.add_parser("verify", help="Check the audit hash chain")
    sub.add_parser("demo", help="Record harmless synthetic authorization attempts")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        if args.command == "eval":
            result = evaluate(args.suite)
            if args.output:
                Path(args.output).write_text(
                    json.dumps(result, indent=2) + "\n", encoding="utf-8"
                )
            print(json.dumps(result, indent=2))
            return int(result["passed"] != result["cases"])
        Path(args.db).parent.mkdir(parents=True, exist_ok=True)
        store = Store(args.db)
        if args.command == "session":
            print(
                store.create_session(
                    strict_json(Path(args.policy).read_text(encoding="utf-8"))
                )
            )
        elif args.command == "approve":
            print(
                store.approve(
                    args.session,
                    args.tool,
                    strict_json(Path(args.arguments).read_text(encoding="utf-8")),
                    args.ttl,
                )
            )
        elif args.command == "verify":
            result = store.verify()
            print(json.dumps(result, indent=2))
            return int(not result["valid"])
        elif args.command == "demo":
            policy = strict_json(
                Path("examples/policy.json").read_text(encoding="utf-8")
            )
            session = store.create_session(policy)
            attempts = [
                ("file.read", {"path": "workspace/brief.md"}),
                ("file.read", {"path": "workspace/../private/key"}),
                ("http.get", {"url": "https://attacker.example/collect"}),
                (
                    "file.write",
                    {"path": "workspace/report.md", "content": "Synthetic demo"},
                ),
            ]
            for index, (tool, arguments) in enumerate(attempts):
                print(
                    json.dumps(
                        store.authorize(session, f"demo-{index}", tool, arguments)
                    )
                )
            tool, arguments = attempts[-1]
            token = store.approve(session, tool, arguments)
            print(
                json.dumps(
                    store.authorize(session, "demo-approved", tool, arguments, token)
                )
            )
            print(
                "Demo records authorization decisions only; no files, URLs or emails are executed."
            )
        else:
            token_path = Path(args.token_file)
            token_path.parent.mkdir(parents=True, exist_ok=True)
            if not token_path.exists():
                fd = os.open(token_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w", encoding="ascii") as stream:
                    stream.write(secrets.token_urlsafe(32))
            token = token_path.read_text(encoding="ascii").strip()
            server = make_server(store, token, args.port)
            print(
                f"Dashboard: http://127.0.0.1:{server.server_port}\nAPI token file: {token_path.resolve()}",
                flush=True,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        return 0
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
