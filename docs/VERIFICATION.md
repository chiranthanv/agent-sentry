# Verification record

Observed locally on 9 November 2026. These are local results; consult the PR checks for the separate GitHub Actions results.

| Check | Observed result |
| --- | --- |
| Runtime | Windows, Python 3.12.14; no runtime dependencies installed for the project |
| `python -m unittest discover -s tests -v` | **41 tests passed**; no skipped tests. Includes actual loopback HTTP requests, concurrency races, rollback injection, executor gating, and persistence checks. |
| `python -m agent_sentry eval --output examples/eval-results.json` | **24 of 24 authored scenarios passed**. [Full result artifact](../examples/eval-results.json) |
| `python -m examples.guarded_agent` | Benign read executed; traversal denied before executor; approved write changed the in-memory workspace; audit verification returned valid. |
| `python -m agent_sentry demo` | Recorded five synthetic decisions: two allowed, three denied. No external tool effects were executed. |
| `ruff check .` | Passed with Ruff 0.14.3 |
| `ruff format .` followed by format check | Source formatted; format check is part of CI and final pre-push verification |
| Local wheel install and import from outside the source tree | Version 0.1.0 imported; packaged dashboard asset found through `importlib.resources` |
| `node scripts/check_dashboard.cjs` | Passed using installed Chrome in headless mode. Verified authenticated ledger loading, audit status, decision rows, no page errors, and no document overflow at 390 px. |

## Browser evidence

- [Desktop screenshot, 1440 px viewport](evidence/dashboard-desktop.png)
- [Mobile screenshot, 390 px viewport](evidence/dashboard-mobile.png)

These screenshots show the actual local application using synthetic demo data. The API token field was cleared before capture. They are not mockups or evidence of public deployment.

To reproduce optional browser verification, first start the demo/server as described in the README. Install Playwright in a separate local Node development environment, install its Chromium browser, then run `node scripts/check_dashboard.cjs`. Alternatively set `SENTRY_BROWSER_CHANNEL=chrome` to use an installed Chrome. Node dependencies are optional test tooling, not runtime dependencies of the Python service.

## Test interpretation

The 16-worker test uses independent SQLite connections to one file and asserts exactly five fresh allowed calls. The approval contention test asserts only one fresh call consumes its token. These are correctness tests under the exercised concurrency schedules, not a throughput benchmark or a proof covering all possible executions.

The scenario set is handwritten and implementation-specific. Its 24/24 result is not a model safety score. No real-model trial, independent penetration test, public hosting, or production load measurement has been performed.

The sandbox initially denied local socket connections. The HTTP suite was run with permission to connect to its temporary loopback server. A Windows temporary-file cleanup issue in the test was fixed by explicitly closing the SQLite connection. The final 41-test run completed successfully.
