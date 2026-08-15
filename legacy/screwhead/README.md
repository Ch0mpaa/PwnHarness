# Screwhead reference import

These files were copied unchanged from [Ch0mpaa/Lilc](https://github.com/Ch0mpaa/Lilc) for controlled extraction into PwnHarness.

Source repository files were not modified.

## Imported files

- `agent.py`: ReAct loop, provider routing, context compaction, skill retrieval, escalation and recovery.
- `tools.py`: tool schemas and execution adapters.
- `judge.py`: independent result-validation pattern.
- `prompts.py`: category-specific prompt routing.
- `config.py`: provider, timeout and concurrency configuration.
- `fails.py`: failure telemetry and review.
- `detector.py`: hallucination/loop detection.
- `teams.py`: category queues, concurrency and isolated workspaces.

## Rules

1. Treat these files as read-only reference code.
2. Do not import this package into the production PwnHarness runtime.
3. Extract behavior behind new PwnHarness interfaces with tests.
4. Remove CTF, flag, Discord, frontier-routing and unrestricted-shell assumptions.
5. Preserve source attribution.
6. The source repository contains no LICENSE file at the time of import. Do not publish a PwnHarness release until licensing is explicitly resolved.
