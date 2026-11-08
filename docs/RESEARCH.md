# Research and portfolio direction

Research reviewed on 9 November 2026. These sources informed project selection; they do not establish hiring outcomes or endorse this implementation.

## What the evidence suggests

| Primary source | Useful observation | Engineering response in this project |
| --- | --- | --- |
| [GitHub Octoverse 2026, 28 Oct 2026](https://github.blog/news-insights/octoverse/octoverse-commits-pushes-reach-new-highs-in-2026-as-developers-build-with-agents/) | Agent-assisted workflows and review tooling are a substantial part of activity on GitHub. Activity is not a quality measure. | Build an inspectable control mechanism and verification evidence, rather than treating generated code volume as achievement. |
| [Anthropic: Demystifying evals for AI agents, 9 Jan 2026](https://www.anthropic.com/research/demystifying-evals-for-ai-agents) | Agent evaluation needs traces, state, and explicit outcomes; a plausible final answer does not establish successful execution. | Record decisions, test state transitions and actual synthetic executor outcomes, and retain per-case results. |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Autonomous systems need controls around the authority with which they act. | Scope tools, bind approvals to exact calls, and document the trusted-executor boundary. This is a selective engineering response, not comprehensive framework coverage. |
| [MCP security best practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices) | Tool integrations introduce authentication and delegation boundaries that need explicit security design. | Keep operator approval issuance separate from the agent-facing API. Do not label a generic JSON tool API an MCP implementation. |
| [CNCF + SlashData State of Cloud Native Development Q1 2026, 24 Mar 2026](https://www.cncf.io/reports/state-of-cloud-native-development-q1-2026/) | Standardized platform and DevOps environments are widely used by backend developers in the surveyed population. | Add repeatable setup, automated CI, traceable failures, and a control-plane API. A Kubernetes cluster is unnecessary for this local MVP. |
| [Amazon India SDE internship requirements, job 10524610](https://www.amazon.jobs/en/jobs/10524610/software-dev-engineer-intern) | The posting emphasizes programming, CS fundamentals, algorithms, complexity, relational databases, and explaining technical tradeoffs. It is one employer example, not a complete labor-market survey. | Make SQL isolation, idempotency, data structures, API error semantics, and concurrency testable interview topics. |

**Inference:** a narrowly scoped agent-control service is a useful portfolio bridge between current AI infrastructure work and durable software-engineering skills. This inference is not a guarantee of placement. The portfolio still needs DSA practice, CS fundamentals, and the ability to explain every module.

## Alternatives reviewed before implementation

| Existing tool | Published purpose | Why build this smaller project? |
| --- | --- | --- |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | An environment for evaluating attacks and defenses for LLM agents. | Agent Sentry's authored traces test deterministic authority invariants. It is not a replacement benchmark or a claim to improve AgentDojo results. |
| [Inspect](https://inspect.aisi.org.uk/) | A general evaluation framework with tools, agents, scorers, and sandbox integrations. | This project exposes the authorization state machine and database transaction directly. Use Inspect when a full real-model evaluation environment is needed. |
| [Promptfoo](https://www.promptfoo.dev/docs/intro/) | CLI/library support for evaluating and red-teaming LLM applications. | Scope here is a runtime reservation/approval ledger with offline regression replay. Building another general prompt comparison platform would duplicate established work. |

No implementation code or dataset was copied from these tools. The 24 scenarios are explicitly handcrafted for this policy schema. The area already has strong projects; “new” means new to this portfolio, not novel academic research.

## Ranked new project directions

The ranking is engineering judgment based on scope, verifiability, placement relevance, and the existing portfolio—not a statistical trend score.

1. **Agent Sentry:** authorization, exact-call approvals, concurrent budgets, and evaluation traces. Best first choice because it adds AI infrastructure/security while showcasing DBMS and backend reasoning. The current repository delivers the first bounded MVP.
2. **ReplayStream:** a replayable event pipeline with schema validation, deduplication, event-time windows, dead letters, and transactional offsets. Demonstrates data engineering and distributed-systems failure semantics; begin locally before adding a broker.
3. **EvidenceLens:** versioned technical-document retrieval with citation verification, retrieval baselines, and a held-out answerability dataset. Start with lexical retrieval and measurable evidence quality; add open-model generation only after the baseline works.
4. **DriftLab:** a reproducible tabular ML pipeline with leakage-safe temporal splits, a simple baseline, experiment tracking, and drift-triggered evaluation. Focus on evaluation validity and reproducibility; document a model that fails to beat the baseline honestly.

These are proposals for later work. Only Agent Sentry is implemented here. No new paid services, deployments, or external-model evaluations are required for its MVP.

## Twelve-week sequence

Assumption: about 10–12 focused hours per week. If time is lower, finish two projects well and defer the rest. Dates begin when sustained development starts; the week numbers are milestones rather than promised calendar completion dates.

| Week | Milestone | Evidence required to call it done |
| --- | --- | --- |
| 1 | Agent Sentry authorization MVP | Resource/approval/budget invariants, working API, adversarial fixtures |
| 2 | Integration and failure semantics | Executor adapter, races and rollback tests, retry/reconciliation design |
| 3 | Packaging and review | Linux/Windows CI, demo, honest verification, architecture/interview walkthrough |
| 4 | ReplayStream ingestion | Versioned event schema, deterministic generator, validation and dead-letter tests |
| 5 | Replay and recovery | Restart/replay tests, deduplication, offset transaction, out-of-order cases |
| 6 | Pipeline demonstration | Reproducible throughput/latency measurement with environment and dataset recorded |
| 7 | EvidenceLens retrieval baseline | Licensed/versioned corpus, lexical baseline, independent question set |
| 8 | Citation and answerability checks | Citation correctness tests, abstention behavior, held-out evaluation |
| 9 | Retrieval comparison | Repeatable baseline comparison, failure analysis, local demo |
| 10 | DriftLab baseline | Licensed dataset, temporal split, leakage checks, simple predictor baseline |
| 11 | Experiments and drift | Tracked configurations, data/model versioning, simulated shift tests |
| 12 | Portfolio review | Re-run setup for every featured project, verify claims, refine resume bullets and demo scripts |

For all four, use feature branches and review PRs. Publish measured results only with the exact command, dataset, environment, and limitations. Merge and public deployment remain operator decisions.
