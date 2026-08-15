# Selected Cygor components

This directory contains an intentionally limited, unchanged source snapshot from
[tjnull/cygor](https://github.com/tjnull/cygor).

- Upstream commit: `d7188a73f792eb72457454ef081e8ee260512ed4`
- Snapshot date: 2026-08-15
- Upstream license: Apache License 2.0 (see `LICENSE`)
- Integration status: vendored reference code; not yet wired into the PwnHarness runtime

## Included

| Upstream path | Intended PwnHarness use |
| --- | --- |
| `cygor/parse.py` | Normalize Nmap XML/GNMAP/text into structured host and service records |
| `cygor/workspace.py` | Engagement workspace and persistent-result layout patterns |
| `cygor/module_loader.py` | Enumeration module discovery and loading |
| `cygor/plugin_loader.py` | External plugin discovery and lifecycle patterns |
| `cygor/modules/base.py` | Common module execution contract |
| `cygor/modules/schema.py` | Structured module result schemas |
| `cygor/modules/lockon.py` | Playwright web screenshots and web-service evidence |
| `cygor/modules/webenum.py` | Controlled ffuf/Feroxbuster/Gobuster/Dirsearch orchestration |

## Deliberately excluded

- Cygor's FastAPI/Bootstrap UI
- Masscan/Naabu/Nmap scanner orchestration
- Credential-recon features
- Jumpbox and proxy configuration
- Service-specific active enumeration modules
- Cygor's AI enrichment and MCP implementation
- Database migrations and application models

PwnHarness will wrap useful behavior behind its own scope gate, typed ToolGate,
engagement schema, evidence store, and approval policies. The local model will
request typed actions; it will not invoke these modules or arbitrary shell
commands directly.

## Modification policy

The files listed above were copied unchanged. If a vendored source file is
modified, retain its upstream notices and add a prominent modification notice
as required by Apache-2.0. Prefer adapters in first-party PwnHarness packages
over direct edits to vendored code.
