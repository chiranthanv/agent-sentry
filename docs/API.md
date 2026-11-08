# API and operator commands

Run commands from the repository root. The default database is `.state/sentry.db`; choose another with `python -m agent_sentry --db PATH COMMAND`.

## Trusted operator

```bash
python -m agent_sentry session --policy examples/policy.json
python -m agent_sentry serve --port 8765 --token-file .state/api.token
```

To approve a write, save its exact arguments to a local JSON file:

```json
{"path":"workspace/report.md","content":"Reviewed report"}
```

```bash
python -m agent_sentry approve SESSION_ID file.write --arguments write-arguments.json --ttl 300
```

The command prints a one-use secret token for the caller's `approval` field. Keep real bodies and approval tokens out of Git and logs. Every change to the body needs a new approval. TTL must be an integer from 1 to 3600 seconds.

## Authenticated client example

Use a session ID returned by the operator command. Save this script locally or run it in a Python REPL:

```python
import json
import urllib.request
from pathlib import Path

token = Path('.state/api.token').read_text().strip()
payload = {
    'session': 'SESSION_ID',
    'request_id': 'read-brief-1',
    'tool': 'file.read',
    'arguments': {'path': 'workspace/brief.md'},
}
request = urllib.request.Request(
    'http://127.0.0.1:8765/v1/authorize',
    data=json.dumps(payload).encode(),
    headers={'Authorization': 'Bearer ' + token,
             'Content-Type': 'application/json'},
)
with urllib.request.urlopen(request, timeout=5) as response:
    print(json.load(response))
```

## Endpoints

| Method / route | Response |
| --- | --- |
| POST `/v1/authorize` | Decision for session, request ID, tool, arguments, optional approval |
| GET `/v1/sessions` | Sessions, policy snapshots, reserved calls and units |
| GET `/v1/events?after=0&limit=100` | Sequence-ordered events; limit 1–500 |
| GET `/v1/verify` | Hash-chain validity, count, and head or broken sequence |
| GET `/`, `/app.js`, `/style.css` | Dashboard assets; no bearer token needed |

All `/v1/` routes require the operator-configured bearer token. There are no HTTP session-creation, approval, execution, delete, or policy-update endpoints. The service is intentionally loopback-only.

## Decision contract

```json
{
  "session": "SESSION_ID",
  "request_id": "read-brief-1",
  "allowed": true,
  "reason": "allowed",
  "calls": 1,
  "units": 1,
  "policy_hash": "SHA256_OF_POLICY",
  "replayed": false
}
```

`calls` and `units` describe counters when the original decision was made. An idempotent retry returns that stored response even if later requests have changed current counters. Query sessions for current totals. A prior denial remains a denial on retry; after obtaining approval use a new request ID.

Stable reasons include `unknown_tool`, `invalid_arguments`, `invalid_path`, `path_outside_scope`, `invalid_url`, `host_outside_scope`, `recipient_outside_scope`, `approval_required`, `approval_mismatch`, `approval_used`, `approval_expired`, and `budget_exceeded`.

A denied valid call returns HTTP 200 with `allowed=false`. Request schema errors return 400, authentication failure 401, rejected Host/Origin 403, unknown session/route 404, idempotency conflict 409, oversized body 413, and wrong media type 415. Unexpected server errors return 500. Clients must fail closed on transport/errors and never infer permission from an unsuccessful response.

## Resource semantics

`file.read` takes only `path`. `file.write` takes `path` and `content`. Paths are relative virtual POSIX-style paths; absolute paths, backslashes, colons, percent escapes, nulls, empty segments, dot segments, and trailing dots/spaces are rejected. No OS access occurs during authorization.

`http.get` takes only an HTTPS `url` with an exact allowed hostname, optional port 443, no userinfo, fragment, whitespace, or backslashes. It does not issue the HTTP request. `mail.send` requires exact `to`, `subject`, and `body` strings and does not send mail.

The trusted tool executor must use exactly these interpreted arguments, secure its filesystem/network access separately, and honor `replayed`. See [ARCHITECTURE.md](ARCHITECTURE.md) for delivery semantics.
