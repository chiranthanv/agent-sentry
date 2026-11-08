"""A deterministic tool-use demonstration; no model, network, or real file writes."""

import json
import tempfile
from pathlib import Path

from agent_sentry.gate import Gate
from agent_sentry.store import Store


def main():
    policy = json.loads(Path("examples/policy.json").read_text())
    workspace = {"workspace/brief.md": "Prepare a short report."}
    with tempfile.TemporaryDirectory() as folder:
        store = Store(Path(folder) / "demo.db")
        session = store.create_session(policy)

        def write(path, content):
            workspace[path] = content
            return {"written": path}

        gate = Gate(
            store,
            session,
            {"file.read": lambda path: workspace[path], "file.write": write},
        )
        print(
            "Read:",
            gate.invoke("read-brief", "file.read", {"path": "workspace/brief.md"}),
        )
        unsafe = {"path": "workspace/../private/key"}
        try:
            gate.invoke("injected-path", "file.read", unsafe)
        except PermissionError as exc:
            print("Blocked:", exc)
        output = {
            "path": "workspace/report.md",
            "content": "Report prepared from the approved brief.",
        }
        approval = store.approve(session, "file.write", output)
        print(
            "Approved write:",
            gate.invoke("write-report", "file.write", output, approval),
        )
        assert workspace["workspace/report.md"] == output["content"]
        print("Actual synthetic tool state:", json.dumps(workspace, indent=2))
        print("Audit:", store.verify())


if __name__ == "__main__":
    main()
