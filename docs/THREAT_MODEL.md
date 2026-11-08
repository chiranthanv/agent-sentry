# Threat model

## Protected boundary

An untrusted agent can propose tool names, argument objects, request IDs, and any approval token it has received. A trusted operator creates policies and issues approvals. The trusted executor registry integrates `Gate` or correctly handles the HTTP decision. The attacker is assumed unable to modify the Python process, database, policies, local API credential, or executor implementation.

The project constrains the *authority of structured calls*. It does not classify natural-language instructions as malicious. A prompt injection may still cause an in-scope harmful action or produce an incorrect answer.

| Attempt | Implemented response | Boundary / residual risk |
| --- | --- | --- |
| Unknown tool or extra cost field | Deny tool / reject arguments | Cannot police an executor that bypasses the Gate |
| Virtual path traversal or root-prefix collision | Reject ambiguous paths / check segment boundary | No real filesystem resolution, symlink, mount, junction or TOCTOU protection |
| Unapproved destination or hostname suffix | Exact HTTPS hostname allowlist | Does not resolve or pin DNS; executor must block private IPs, recheck redirects, and enforce TLS |
| Email exfiltration to another recipient | Exact recipient allowlist and approval | Approved recipient/body may still be inappropriate; no mail is sent by the service |
| Reused or modified approval | Session/arguments binding, expiry, one-use consumption | Operator compromise defeats this assumption |
| Concurrent quota overspend | One transaction for decision, budget, approval, event | Single database file; no distributed consensus |
| Retry charging twice | Stored idempotency response | External effect delivery needs reconciliation |
| Malformed HTTP input | Strict JSON, body limit, controlled errors | Development server has no public-service DoS guarantee |
| Local browser cross-origin call | Host/Origin validation, bearer auth, no CORS | Local malware or token theft is outside scope |
| Partial audit edit | Hash-chain verification | Full rewrite or truncation requires external anchoring to detect |

## Operational notes

Keep `.state/` private and out of Git. The API token file is created with restrictive POSIX mode; Windows users must manage directory ACLs separately. Anyone who can read the local token can read the ledger and request decisions for existing sessions. Anyone who can invoke the operator library with database access can mint approvals. There is no multi-user isolation.

The demo uses synthetic `.example`/`.test` addresses and virtual paths. Neither scenario replay nor the dashboard executes URLs or emails. The integration demonstration writes only to an in-memory dictionary. No external model endpoint is used.

## Claims deliberately excluded

No production security certification, comprehensive injection resistance, OS sandboxing, MCP conformance, independent audit, real-world attack-success rate, actual token-cost accounting, multi-tenant authorization, or exactly-once external execution is claimed.

Research inspiration is documented in [RESEARCH.md](RESEARCH.md); an OWASP reference is not OWASP certification or endorsement.
