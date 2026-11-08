# Architecture and decisions

## Invariants

1. An allowed reservation cannot exceed either session limit.
2. Every new valid authorization request records exactly one decision event and one idempotency record in the same transaction.
3. Approval consumption and the charge either commit together or roll back together.
4. An approval cannot authorize a different session, tool, or canonical argument object.
5. A retried request does not append an event or consume another unit. Different inputs under the same request ID are a conflict.
6. The trusted Gate calls an executor only for a fresh allowed reservation.

Invalid request schemas and unknown session IDs fail before a decision is recorded. Idempotency conflicts are errors, not new authorization decisions.

## Transaction walkthrough

`Store.authorize` checks basic types and canonicalizes arguments. It starts `BEGIN IMMEDIATE`, obtains the session snapshot, and looks for a prior `(session_id, request_id)` record. A matching fingerprint returns the original response with `replayed=true`. A mismatch raises `Conflict`.

For a new request it evaluates the configured tool and resource, then any approval requirement, then both quotas. The rule's fixed units are trusted policy data; callers cannot supply costs. If allowed, the transaction increments counters and consumes a required approval. It inserts the response and a hash-linked decision event, then commits. Any exception rolls all of these changes back.

SQLite's write reservation serializes competing writers across connections. WAL allows readers while a writer operates. Each operation opens and closes its own connection, with foreign keys enabled and a ten-second busy timeout. This design deliberately favors understandable correctness over high write throughput. One shared database file is required; separate replicas would have separate budgets.

## Schema

| Table | Key | Stored data |
| --- | --- | --- |
| sessions | session ID | Immutable policy JSON, reserved calls and units |
| approvals | SHA-256 of random token | Session, exact-call binding, expiry, consumed flag |
| requests | session ID + request ID | Input fingerprint, original response |
| events | monotonic sequence | Event JSON, previous hash, current hash |

The DB uses integer counters and nonnegative checks. Denied calls do not consume budget. Persisted idempotency avoids a restart charging again. Canonical JSON sorts object keys; array order remains meaningful. Arguments reject non-finite numbers and requests reject duplicate JSON fields at the HTTP boundary.

## Approval workflow

Only the operator CLI/library can mint approval tokens. The agent HTTP API cannot create sessions or approvals. Tokens use `secrets.token_urlsafe(32)` and only their SHA-256 digests are stored. The binding includes the complete tool arguments, including write/email content. Tokens expire at the boundary `expires <= now`; they are consumed only on an allowed call.

Expiry uses wall-clock time so it survives process restarts. A trusted operator and a correctly managed system clock are assumptions. A production service should address clock rollback, cancellation, revocation, and retention explicitly.

## Execution and retries

Authorization reserves capacity, not successful execution. `Gate.invoke` commits authorization and then invokes a registered trusted Python callable. If it crashes between those steps, the budget remains reserved although the tool may not have run. If it crashes after an external effect, the caller may not know the outcome. Replays raise `ReplayedCall`; the operator must reconcile the original result. There is no automatic execution retry and no refund endpoint.

The HTTP API returns the original decision on retry. Direct HTTP clients must honor `replayed`; they must not interpret a replayed `allowed=true` as permission to execute the effect a second time. An uncooperative executor can bypass any library boundary, which is why this is not a sandbox.

## Audit integrity

Each event stores `hash(canonical({previous, payload}))`, linking it to the previous event. Verification recomputes the chain in order. This detects accidental or partial changes to stored event content. It does not authenticate the operator, prevent full-chain rewriting by a database owner, or detect suffix deletion without a separately trusted checkpoint. Sessions and request tables are not independently attested by `verify`.

Raw argument values and tokens are not in audit events. Their digests can still leak equality or support guessing of low-entropy values. Session policies contain allowlists, and the database remains sensitive operational data.

## API and UI

The standard-library HTTP server binds only to IPv4 loopback. API routes require a bearer token; static dashboard assets are public on loopback. Host and Origin checks, no CORS permission, fixed asset routing, limited body size, socket timeouts, and a restrictive CSP reduce common local development mistakes. The web interface constructs cells using `textContent` and keeps credentials in memory.

The HTTP server has no production worker/rate-limit model and shares one operator credential across sessions. Schema upgrades are not implemented. These are intentional scope limits, not properties suitable for an Internet service.
