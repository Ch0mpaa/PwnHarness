# Architecture principles

1. One local model may assume several roles through versioned system prompts.
2. The application owns state; the model receives bounded context packets.
3. Scanner output is parsed into facts before model use.
4. Methodology is executable; RAG supplies supporting tradecraft.
5. Agents propose; the execution gate validates and executes.
6. Scanner observations are candidates, never confirmed findings.
7. Evidence and contradictory evidence are both first-class.
8. Every action is engagement-scoped, policy-checked and audited.
9. Web, CLI and future MCP clients share the same core.
10. Analyst decisions are authoritative learning labels.
