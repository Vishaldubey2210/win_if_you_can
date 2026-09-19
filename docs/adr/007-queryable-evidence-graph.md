# ADR 007: Queryable Evidence Graph Architecture

## Status
Accepted

## Context
Traditional supply-chain tools store security verdicts as static JSON blobs or flat database rows. This prevents developers and security teams from querying relationships (e.g., "Which packages are hosted on this repository?", "What releases were published by this maintainer?", "What advisories affect this package?").

## Decision
SLOPGUARD introduces a queryable, in-memory and serializable `EvidenceGraph`.
The graph enforces the canonical security hierarchy:
```
IMPORT
  ↓
PACKAGE
  ↓
RELEASE
  ↓
MAINTAINER / PUBLISHER
  ↓
REPOSITORY
  ↓
ADVISORY
  ↓
PROVENANCE
```
Every edge is strictly backed by timestamped, structured evidence. Graph relationships are never inferred or hallucinated.

## Consequences
- Enables deep security audits, graph queries, and interactive visual exploration in the dashboard and CLI.
- All decisions are fully explainable and reconstructable.
