# Interview preparation

## Thirty-second explanation

“Agent Sentry checks whether an agent is authorized to make a structured tool call. Policies restrict resources and budgets; risky calls require one-use approval for the exact arguments. A SQLite transaction reserves the budget, consumes approval, records the decision, and persists an idempotency response together. I can demonstrate races, retries, and rollback behavior without using a paid model.”

Use “I built” only once you can explain the implementation and your AI-assisted workflow honestly.

## Walkthrough

Run `python -m examples.guarded_agent`. Explain how the benign read reaches the in-memory executor, the traversal attempt is rejected before execution, and the approved write changes the actual synthetic workspace. Then run `python -m agent_sentry demo` and `python -m agent_sentry serve` to inspect allowed/denied events in the dashboard. Finally run the tests and show the concurrency and failure-injection cases.

Follow one call through `Gate.invoke`, `Store.authorize`, `scope_reason`, the transaction, and the event append. Explain why a policy verdict and an external side effect have different failure boundaries.

## Five likely questions

1. **Why `BEGIN IMMEDIATE` rather than a Python lock?** A Python lock protects one process only. The database transaction serializes competing writers across independent connections sharing the same file. Demonstrate the 16-connection budget race. SQLite's single writer is also a throughput limit.
2. **Does idempotency guarantee exactly-once tool execution?** No. It prevents duplicate authorization reservations. A tool can succeed and the process can crash before the client observes it. The adapter refuses re-execution of a replayed reservation, and a real integration needs result reconciliation or downstream idempotency.
3. **Why bind approval to arguments rather than a tool name?** Tool-only approval would permit a different destination or body. The token record includes a digest of the full canonical call and the session; changing content, resource, or session invalidates it.
4. **What does the audit hash chain actually prove?** It exposes inconsistent partial changes to event data. A database owner can rewrite the whole chain or truncate it. A separately trusted head checkpoint or append-only remote sink is needed for stronger tamper evidence.
5. **Can this stop prompt injection or SSRF?** It can deny out-of-scope structured calls made through the boundary. It cannot determine whether an in-scope request is semantically harmful. A real network executor must handle redirects, DNS/IP checks, and TLS, while a filesystem executor needs OS isolation and symlink/TOCTOU defenses.

## Technical tradeoffs to defend

- Python standard library: easy reproduction and a small dependency surface; fewer production server facilities.
- SQLite: inspectable ACID behavior without infrastructure; one-writer scaling and single-host scope.
- Fixed units: deterministic quotas that the caller cannot understate; not actual token or money accounting.
- Hashing arguments: avoid retaining raw bodies in events; hashes still permit equality/guessing leakage.
- Conservative retries: prevent blind duplicate effects; retain a reservation even when execution fails.
- Handcrafted scenarios: transparent and repeatable; expected results share author assumptions and are not independent evidence of model robustness.

## Resume wording supported by the implementation

- “Built a Python/SQLite authorization service for agent tool calls with scoped policies, exact-argument approvals, persistent idempotency, and atomic budget reservations.”
- “Added concurrency and failure-injection tests for quota contention, single-use approvals, rollback, and HTTP validation, plus 24 deterministic policy replay scenarios.”
- “Implemented an authenticated local decision dashboard and a trusted-tool adapter with explicit retry and execution-failure semantics.”

Do not claim production adoption, real-world attack prevention rates, latency/throughput improvements, MCP support, or independent security review. Add exact test/CI counts only with the current verification evidence.

## Placement study links to the code

Use composite keys and indexes to discuss DBMS; transactions and locks for concurrency; canonicalization and hashing for security; HTTP status handling for networking; invariant-based tests for software engineering. Practice data structures and algorithm questions separately—this project does not replace those interviews.
