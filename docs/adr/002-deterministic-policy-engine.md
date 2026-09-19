# ADR 002: Deterministic Policy Engine Over LLM Verdicts

## Status
Accepted

## Context
LLMs are probabilistic by nature and susceptible to hallucination, prompt injection, sycophancy, and non-deterministic variations across runs. In a supply-chain firewall, allowing an LLM to cast the final vote on whether an unverified or suspicious package may be installed presents a catastrophic security vulnerability.

## Decision
All final policy outcomes (`ALLOW`, `HOLD`, `BLOCK`, `ALERT`) MUST be calculated by deterministic, rule-based policy engines evaluating concrete evidence artifacts. LLM interaction is strictly constrained to candidate ranking, conversational explanation of findings, and code patch proposals.

## Consequences
- Security verdicts are 100% reproducible and testable via standard unit and regression suites.
- Policy rules can be audited and versioned as code (`policy.yaml` / Python rules).
