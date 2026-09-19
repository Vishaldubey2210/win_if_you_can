# ADR 004: Temporal Phantom Memory for Dependency Hallucination Defense

## Status
Accepted

## Context
AI coding assistants often hallucinate realistic package names. Attackers scrape public LLM prompt datasets, agent logs, or search queries to identify hallucinated packages that do not exist yet on PyPI or npm. The attacker then registers that exact package name with malicious setup scripts.
If a security scanner simply checks "does this package exist?", it will block the package when it doesn't exist, but will dangerously mark it as "FOUND / SAFE" once the attacker registers it!

## Decision
SLOPGUARD implements a temporal memory store called `PhantomWatchlist`. When a package is first observed and verified as `NOT_FOUND`, its identity, ecosystem, first-seen timestamp, and observation count are persisted.
If a subsequent scan discovers that a previously `NOT_FOUND` package is now published on the registry (`NOT_FOUND -> APPEARED`), SLOPGUARD triggers a high-severity `ALERT` and quarantines the package until human review confirms genuine provenance.

## Consequences
- Protects against the primary vector of AI package hallucination exploitation.
- Distinguishes innocent new packages from packages that were previously flagged as missing in AI workflows.
