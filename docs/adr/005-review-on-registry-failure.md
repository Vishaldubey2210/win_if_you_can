# ADR 005: Distinction of Registry Outages and Fail-Safe Posture

## Status
Accepted

## Context
When an automated dependency checker issues HTTP requests to package registries (e.g. PyPI or npm), errors such as HTTP 429 (Too Many Requests), HTTP 500/502/503 (Server Unavailable), network timeouts, or DNS failures can occur.
If a scanner treats any non-200 response as `NOT_FOUND`, it generates false hallucinations and confuses the developer.
Conversely, if it fails open on errors, attackers can trigger rate limits or denial-of-service against registry endpoints to bypass scanning.

## Decision
SLOPGUARD explicitly separates registry response statuses into typed categories:
- `FOUND`: HTTP 200 with valid metadata payload.
- `NOT_FOUND`: Explicit HTTP 404 confirming absence.
- `RATE_LIMITED`: HTTP 429.
- `SERVER_ERROR`: HTTP 5xx.
- `NETWORK_ERROR`: Connection timeout or DNS failure.
Any non-404 error condition must evaluate to policy verdict `HOLD / REVIEW_REQUIRED`. The system never allows installation when evidence cannot be verified.

## Consequences
- Prevents fail-open vulnerabilities during registry disruptions.
- Preserves accurate evidence logs without corrupting phantom history with transient network errors.
