from __future__ import annotations
import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple
import httpx
from slopguard.core.models import Ecosystem, RegistryEvidence, RegistryStatus


class BaseRegistryAdapter(ABC):
    """
    Abstract base class for registry adapters.
    Guarantees that network errors, rate limits, and server failures are
    never conflated with 404 NOT_FOUND.
    """

    def __init__(
        self,
        ecosystem: Ecosystem,
        timeout_seconds: float = 8.0,
        max_retries: int = 2,
        cache_ttl_seconds: float = 300.0,
    ) -> None:
        self.ecosystem = ecosystem
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.cache_ttl_seconds = cache_ttl_seconds
        # In-memory LRU-like cache: key -> (RegistryEvidence, expire_timestamp)
        self._cache: Dict[str, Tuple[RegistryEvidence, float]] = {}

    def _get_from_cache(self, key: str) -> Optional[RegistryEvidence]:
        now = time.time()
        if key in self._cache:
            evidence, expire_at = self._cache[key]
            if now < expire_at:
                # Return cached copy with cached=True
                cached_evidence = evidence.model_copy()
                cached_evidence.cached = True
                return cached_evidence
            del self._cache[key]
        return None

    def _store_in_cache(self, key: str, evidence: RegistryEvidence) -> None:
        # Only cache authoritative findings: FOUND or NOT_FOUND
        if evidence.status in (RegistryStatus.FOUND, RegistryStatus.NOT_FOUND):
            expire_at = time.time() + self.cache_ttl_seconds
            self._cache[key] = (evidence, expire_at)

    @abstractmethod
    def get_package_url(self, package_name: str) -> str:
        """Returns the public registry URL for querying package metadata."""
        pass

    @abstractmethod
    def parse_metadata_response(
        self, package_name: str, status_code: int, data: dict, latency_ms: float
    ) -> RegistryEvidence:
        """Parses valid 200 JSON payload into structured RegistryEvidence."""
        pass

    async def verify_package(self, package_name: str) -> RegistryEvidence:
        """
        Verify package existence and metadata on the registry with bounded retries.
        """
        clean_name = package_name.strip()
        cached = self._get_from_cache(clean_name)
        if cached:
            return cached

        url = self.get_package_url(clean_name)
        start_time = time.perf_counter()

        client_timeout = httpx.Timeout(self.timeout_seconds, connect=4.0)

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=client_timeout, follow_redirects=True) as client:
                    resp = await client.get(url, headers={"User-Agent": "SLOPGUARD-Security-Firewall/0.1.0"})

                latency_ms = (time.perf_counter() - start_time) * 1000.0

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        evidence = self.parse_metadata_response(clean_name, 200, data, latency_ms)
                        self._store_in_cache(clean_name, evidence)
                        return evidence
                    except Exception as json_err:
                        return RegistryEvidence(
                            package_name=clean_name,
                            ecosystem=self.ecosystem,
                            status=RegistryStatus.MALFORMED_RESPONSE,
                            http_status=200,
                            latency_ms=latency_ms,
                            error_message=f"Malformed JSON response: {json_err}",
                        )

                elif resp.status_code == 404:
                    evidence = RegistryEvidence(
                        package_name=clean_name,
                        ecosystem=self.ecosystem,
                        status=RegistryStatus.NOT_FOUND,
                        http_status=404,
                        latency_ms=latency_ms,
                        error_message="Package not found on registry",
                    )
                    self._store_in_cache(clean_name, evidence)
                    return evidence

                elif resp.status_code == 429:
                    # Rate limited: retry once if attempts remain, else return RATE_LIMITED
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    return RegistryEvidence(
                        package_name=clean_name,
                        ecosystem=self.ecosystem,
                        status=RegistryStatus.RATE_LIMITED,
                        http_status=429,
                        latency_ms=latency_ms,
                        error_message="Registry rate limit exceeded (HTTP 429)",
                    )

                elif resp.status_code in (500, 502, 503, 504):
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    return RegistryEvidence(
                        package_name=clean_name,
                        ecosystem=self.ecosystem,
                        status=RegistryStatus.SERVER_ERROR,
                        http_status=resp.status_code,
                        latency_ms=latency_ms,
                        error_message=f"Registry server error (HTTP {resp.status_code})",
                    )

                else:
                    return RegistryEvidence(
                        package_name=clean_name,
                        ecosystem=self.ecosystem,
                        status=RegistryStatus.SERVER_ERROR,
                        http_status=resp.status_code,
                        latency_ms=latency_ms,
                        error_message=f"Unexpected HTTP status {resp.status_code}",
                    )

            except httpx.TimeoutException:
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                return RegistryEvidence(
                    package_name=clean_name,
                    ecosystem=self.ecosystem,
                    status=RegistryStatus.TIMEOUT,
                    latency_ms=latency_ms,
                    error_message=f"Connection timed out after {self.timeout_seconds}s",
                )

            except httpx.RequestError as req_err:
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                return RegistryEvidence(
                    package_name=clean_name,
                    ecosystem=self.ecosystem,
                    status=RegistryStatus.NETWORK_ERROR,
                    latency_ms=latency_ms,
                    error_message=f"Network request failure: {req_err}",
                )

        # Fallback if loop finishes
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return RegistryEvidence(
            package_name=clean_name,
            ecosystem=self.ecosystem,
            status=RegistryStatus.NETWORK_ERROR,
            latency_ms=latency_ms,
            error_message="Maximum retries exhausted without resolution",
        )
