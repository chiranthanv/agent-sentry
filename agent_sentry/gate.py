"""An opt-in integration boundary for trusted, registered Python tools."""


class ReplayedCall(RuntimeError):
    """Authorization was already reserved; do not blindly repeat a side effect."""


class Gate:
    def __init__(self, store, session, tools):
        self.store = store
        self.session = session
        self.tools = dict(tools)

    def invoke(self, request_id, tool, arguments, approval=None):
        if tool not in self.tools:
            raise ValueError("No trusted executor registered for this tool")
        decision = self.store.authorize(
            self.session, request_id, tool, arguments, approval
        )
        if not decision["allowed"]:
            raise PermissionError(decision["reason"])
        if decision["replayed"]:
            raise ReplayedCall(
                "Reservation already exists; reconcile the original result before retrying"
            )
        # No automatic retries: authorization and external effects cannot share a SQLite transaction.
        # Tool exceptions propagate and the reservation remains charged.
        return self.tools[tool](**arguments)
