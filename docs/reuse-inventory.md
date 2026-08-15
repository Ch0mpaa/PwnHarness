# Reuse inventory

## Objective

Accelerate PwnHarness without coupling the external-pentest application to Screwhead's CTF runtime or modifying its source repository.

## Extract from Screwhead

| Source | PwnHarness destination | Adaptation |
| --- | --- | --- |
| `agent.py::_compact_for_tier` | `packages/context-builder` | Replace chat-tail retention with engagement/asset/hypothesis retrieval and explicit token budgets. |
| ReAct loop | `packages/agent-loop` | Replace flag objective with bounded methodology tasks and typed decisions. |
| Skill retrieval | `packages/knowledge` | Retrieve service-specific methodology using metadata and hybrid search. |
| Provider clients | `packages/model-provider` | Default to one OpenAI-compatible local endpoint and 4B model. |
| Loop detection | `packages/recovery-loop` | Detect repeated jobs, repeated hypotheses and no-information-gain actions. |
| `judge.py` | `packages/reviewer` | Validate evidence, impact and contradictory facts instead of flag syntax. |
| `fails.py` | `packages/engineering-loop` | Compare agent decisions with analyst decisions and generate regression cases. |
| `teams.py` | `packages/job-runner` | Replace challenge categories with engagement-scoped specialist queues. |
| `tools.py` schemas | `packages/tool-registry` | Keep typed schemas; replace arbitrary shell execution with allowlisted adapters. |

## Reimplement from The Grind

The Grind is proprietary. Reuse its architecture, not source code, until selected components are explicitly relicensed.

- Agents reason and propose; one gate executes.
- Idempotency key before execution.
- Capability policy and operator confirmation.
- Claim-first audit ledger.
- Content-addressed context snapshots.
- One execution path for local workers and future MCP clients.
- Ports-and-adapters boundary around models, tools, persistence and interfaces.

## Do not carry forward

- CTF flag extraction or submission.
- Discord command interface.
- Automatic frontier escalation.
- RunPod-specific routing.
- Challenge-category teams.
- Generic unrestricted shell execution.
- Shared global work directories.
- Full accumulated chat history.
- Automatic acceptance of model conclusions.

## First production extraction

1. Define `ContextPacketV1`, `ToolJobV1`, `EvidenceV1` and `ReviewDecisionV1`.
2. Port context budgeting behind unit tests.
3. Implement the execution gate and allowlisted adapters.
4. Port the judge pattern into an evidence reviewer.
5. Port failure telemetry into the engineering-loop event schema.
6. Add Nmap XML ingestion and login-surface screenshot workflow.
