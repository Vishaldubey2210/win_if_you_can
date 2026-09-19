# ADR 008: Release-Level Trust and Package Velocity Analysis

## Status
Accepted

## Context
Verifying only that a package name exists at the registry level leaves developers vulnerable to:
1. Newly registered packages created moments earlier by attackers.
2. Single-release packages with no source repository or issue tracking.
3. Compromised accounts pushing abnormal release spikes.

## Decision
SLOPGUARD evaluates measurable release-level trust signals through `ReleaseSignalAnalyzer`:
- `package_age_days`: Time elapsed since the package's initial version release.
- `latest_release_age_days`: Time elapsed since the current release was uploaded.
- `total_releases`: Complete release history count.
- `is_new_package`: Packages published under 14 days ago with single releases and no linked repository are quarantined under `HOLD`.
- `provenance_available`: Distinguishes packages with transparent repository linkage and build attestations.

Signals are treated as objective evidence rather than sensationalized AI judgments.

## Consequences
- Protects against rapid package injection attacks and ephemeral malicious releases.
- Retains explainability by documenting exact timestamps and release counts.
