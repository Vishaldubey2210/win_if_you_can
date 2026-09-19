from __future__ import annotations
import asyncio
import time
from typing import Dict, List, Optional, Tuple
import httpx
from slopguard.core.models import Ecosystem
from slopguard.evidence.models import (
    EvidenceRecord,
    EvidenceStatus,
    EvidenceType,
    SecurityAdvisory,
)


class OSVAdapter:
    """
    Client for querying open-source vulnerability advisories via Google's OSV API (https://api.osv.dev).
    Respects rate limits, timeouts, and distinguishes lack of vulnerabilities from API failure.
    """

    def __init__(
        self,
        base_url: str = "https://api.osv.dev/v1/query",
        timeout_seconds: float = 6.0,
        max_retries: int = 2,
        cache_ttl_seconds: float = 600.0,
    ) -> None:
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.cache_ttl_seconds = cache_ttl_seconds
        # Cache key: "ecosystem:package:version" -> (List[SecurityAdvisory], expire_at, EvidenceStatus, error_msg)
        self._cache: Dict[str, Tuple[List[SecurityAdvisory], float, EvidenceStatus, Optional[str]]] = {}

    def _map_ecosystem(self, ecosystem: Ecosystem) -> Optional[str]:
        if ecosystem == Ecosystem.PYPI:
            return "PyPI"
        elif ecosystem == Ecosystem.NPM:
            return "npm"
        return None

    def _cache_key(self, package_name: str, ecosystem: Ecosystem, version: Optional[str]) -> str:
        v_str = version.strip() if version else ""
        return f"{ecosystem.value}:{package_name.strip().lower()}:{v_str}"

    async def query_advisories(
        self,
        package_name: str,
        ecosystem: Ecosystem,
        version: Optional[str] = None,
    ) -> Tuple[List[SecurityAdvisory], EvidenceRecord]:
        clean_pkg = package_name.strip()
        osv_eco = self._map_ecosystem(ecosystem)

        if not osv_eco:
            record = EvidenceRecord(
                package=clean_pkg,
                ecosystem=ecosystem,
                version=version,
                evidence_type=EvidenceType.ADVISORY,
                source="api.osv.dev",
                status=EvidenceStatus.NOT_APPLICABLE,
                confidence=1.0,
                notes=["Ecosystem not supported by OSV"],
            )
            return [], record

        cache_key = self._cache_key(clean_pkg, ecosystem, version)
        now = time.time()
        if cache_key in self._cache:
            cached_advs, expire_at, cached_status, cached_err = self._cache[cache_key]
            if now < expire_at:
                record = EvidenceRecord(
                    package=clean_pkg,
                    ecosystem=ecosystem,
                    version=version,
                    evidence_type=EvidenceType.ADVISORY,
                    source="api.osv.dev",
                    status=cached_status,
                    confidence=1.0,
                    payload={"advisory_count": len(cached_advs), "cached": True},
                    notes=["Loaded from local OSV cache"] if not cached_err else [f"Cached failure: {cached_err}"],
                )
                return cached_advs, record
            del self._cache[cache_key]

        payload = {
            "package": {
                "name": clean_pkg,
                "ecosystem": osv_eco,
            }
        }
        if version:
            payload["version"] = version.strip()

        client_timeout = httpx.Timeout(self.timeout_seconds, connect=3.0)
        start_time = time.perf_counter()

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=client_timeout) as client:
                    resp = await client.post(
                        self.base_url,
                        json=payload,
                        headers={"User-Agent": "SLOPGUARD-OSV-Client/0.1.0"},
                    )

                latency_ms = (time.perf_counter() - start_time) * 1000.0

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        vulns_data = data.get("vulns", [])
                        advisories: List[SecurityAdvisory] = []

                        for item in vulns_data:
                            adv_id = item.get("id", "UNKNOWN")
                            summary = item.get("summary") or item.get("details", "")[:100] or adv_id
                            details = item.get("details")

                            # Parse severity if present
                            severity = "UNKNOWN"
                            database_specific = item.get("database_specific", {})
                            if isinstance(database_specific, dict) and "severity" in database_specific:
                                severity = str(database_specific["severity"]).upper()

                            # Parse affected versions
                            affected_versions = []
                            fixed_versions = []
                            for aff in item.get("affected", []):
                                for r in aff.get("ranges", []):
                                    for ev in r.get("events", []):
                                        if "fixed" in ev:
                                            fixed_versions.append(ev["fixed"])
                                        if "introduced" in ev:
                                            affected_versions.append(f">={ev['introduced']}")

                            refs = [r.get("url") for r in item.get("references", []) if isinstance(r, dict) and r.get("url")]

                            advisories.append(
                                SecurityAdvisory(
                                    advisory_id=adv_id,
                                    summary=summary,
                                    details=details,
                                    severity=severity,
                                    affected_versions=affected_versions,
                                    fixed_versions=fixed_versions,
                                    references=refs,
                                )
                            )

                        # Cache successful lookup
                        self._cache[cache_key] = (advisories, now + self.cache_ttl_seconds, EvidenceStatus.VERIFIED, None)

                        record = EvidenceRecord(
                            package=clean_pkg,
                            ecosystem=ecosystem,
                            version=version,
                            evidence_type=EvidenceType.ADVISORY,
                            source="api.osv.dev",
                            status=EvidenceStatus.VERIFIED,
                            confidence=1.0,
                            payload={"advisory_count": len(advisories), "latency_ms": latency_ms},
                            notes=[f"OSV returned {len(advisories)} security advisories"],
                        )
                        return advisories, record

                    except Exception as json_err:
                        record = EvidenceRecord(
                            package=clean_pkg,
                            ecosystem=ecosystem,
                            version=version,
                            evidence_type=EvidenceType.ADVISORY,
                            source="api.osv.dev",
                            status=EvidenceStatus.FAILED,
                            confidence=0.5,
                            notes=[f"Failed to parse OSV response: {json_err}"],
                        )
                        return [], record

                elif resp.status_code == 404:
                    # OSV 404 means no vulnerabilities found for package
                    self._cache[cache_key] = ([], now + self.cache_ttl_seconds, EvidenceStatus.VERIFIED, None)
                    record = EvidenceRecord(
                        package=clean_pkg,
                        ecosystem=ecosystem,
                        version=version,
                        evidence_type=EvidenceType.ADVISORY,
                        source="api.osv.dev",
                        status=EvidenceStatus.VERIFIED,
                        confidence=1.0,
                        payload={"advisory_count": 0, "latency_ms": latency_ms},
                        notes=["No active advisories found on OSV (HTTP 404)"],
                    )
                    return [], record

                elif resp.status_code == 429:
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    record = EvidenceRecord(
                        package=clean_pkg,
                        ecosystem=ecosystem,
                        version=version,
                        evidence_type=EvidenceType.ADVISORY,
                        source="api.osv.dev",
                        status=EvidenceStatus.INCONCLUSIVE,
                        confidence=0.5,
                        notes=["OSV API rate limit exceeded (HTTP 429)"],
                    )
                    return [], record

                elif resp.status_code in (500, 502, 503, 504):
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    record = EvidenceRecord(
                        package=clean_pkg,
                        ecosystem=ecosystem,
                        version=version,
                        evidence_type=EvidenceType.ADVISORY,
                        source="api.osv.dev",
                        status=EvidenceStatus.INCONCLUSIVE,
                        confidence=0.5,
                        notes=[f"OSV API server error (HTTP {resp.status_code})"],
                    )
                    return [], record

                else:
                    record = EvidenceRecord(
                        package=clean_pkg,
                        ecosystem=ecosystem,
                        version=version,
                        evidence_type=EvidenceType.ADVISORY,
                        source="api.osv.dev",
                        status=EvidenceStatus.INCONCLUSIVE,
                        confidence=0.5,
                        notes=[f"Unexpected OSV HTTP response status {resp.status_code}"],
                    )
                    return [], record

            except httpx.TimeoutException:
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                record = EvidenceRecord(
                    package=clean_pkg,
                    ecosystem=ecosystem,
                    version=version,
                    evidence_type=EvidenceType.ADVISORY,
                    source="api.osv.dev",
                    status=EvidenceStatus.INCONCLUSIVE,
                    confidence=0.5,
                    notes=[f"OSV query timed out after {self.timeout_seconds}s"],
                )
                return [], record

            except httpx.RequestError as req_err:
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                record = EvidenceRecord(
                    package=clean_pkg,
                    ecosystem=ecosystem,
                    version=version,
                    evidence_type=EvidenceType.ADVISORY,
                    source="api.osv.dev",
                    status=EvidenceStatus.FAILED,
                    confidence=0.5,
                    notes=[f"Network error querying OSV: {req_err}"],
                )
                return [], record

        record = EvidenceRecord(
            package=clean_pkg,
            ecosystem=ecosystem,
            version=version,
            evidence_type=EvidenceType.ADVISORY,
            source="api.osv.dev",
            status=EvidenceStatus.INCONCLUSIVE,
            confidence=0.5,
            notes=["OSV retries exhausted without resolution"],
        )
        return [], record
