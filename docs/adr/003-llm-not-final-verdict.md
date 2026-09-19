# ADR 003: Architectural Role of LLMs in Security Remediation

## Status
Accepted

## Context
While LLMs must not make security policy decisions, their natural language understanding and contextual reasoning are invaluable for developer experience: explaining complex evidence graphs, parsing compiler/runtime errors, and suggesting semantic replacements for hallucinated or deprecated libraries.

## Decision
The LLM serves exclusively as an advisory subagent:
1. Explain evidence: Converts structured graphs and advisory payloads into plain developer explanations.
2. Candidate ranking: Suggests genuine package replacements based on API usage context.
3. Repair generation: Suggests code patches to replace imports.
All LLM repair outputs must cycle through the full verification gate (RESCAN -> VERIFY -> EVIDENCE -> TRUST -> GATE) before acceptance.

## Consequences
- Clean separation between explanatory intelligence and deterministic security enforcement.
- Safe integration of LLMs without granting them security gate override authority.
