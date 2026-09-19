import pytest
import httpx
from slopguard.core.models import Ecosystem
from slopguard.evidence.models import EvidenceStatus
from slopguard.evidence.osv import OSVAdapter

@pytest.mark.asyncio
async def test_osv_no_advisories(monkeypatch):
    adapter = OSVAdapter()

    async def mock_post(*args, **kwargs):
        return httpx.Response(status_code=404, json={})

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    advs, record = await adapter.query_advisories("safe-package", Ecosystem.PYPI)
    assert len(advs) == 0
    assert record.status == EvidenceStatus.VERIFIED
    assert record.payload["advisory_count"] == 0

@pytest.mark.asyncio
async def test_osv_advisory_found(monkeypatch):
    adapter = OSVAdapter()

    mock_body = {
        "vulns": [
            {
                "id": "GHSA-1234-5678",
                "summary": "Remote Code Execution vulnerability",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}]}]}],
                "references": [{"url": "https://github.com/advisories/GHSA-1234-5678"}]
            }
        ]
    }

    async def mock_post(*args, **kwargs):
        return httpx.Response(status_code=200, json=mock_body)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    advs, record = await adapter.query_advisories("vulnerable-pkg", Ecosystem.PYPI)
    assert len(advs) == 1
    assert advs[0].advisory_id == "GHSA-1234-5678"
    assert advs[0].severity == "HIGH"
    assert "1.0.5" in advs[0].fixed_versions
    assert record.status == EvidenceStatus.VERIFIED

@pytest.mark.asyncio
async def test_osv_rate_limited(monkeypatch):
    adapter = OSVAdapter(max_retries=0)

    async def mock_post(*args, **kwargs):
        return httpx.Response(status_code=429)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    advs, record = await adapter.query_advisories("any-pkg", Ecosystem.PYPI)
    assert len(advs) == 0
    assert record.status == EvidenceStatus.INCONCLUSIVE
    assert "429" in record.notes[0]

@pytest.mark.asyncio
async def test_osv_server_error_500(monkeypatch):
    adapter = OSVAdapter(max_retries=0)

    async def mock_post(*args, **kwargs):
        return httpx.Response(status_code=500)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    advs, record = await adapter.query_advisories("any-pkg", Ecosystem.PYPI)
    assert len(advs) == 0
    assert record.status == EvidenceStatus.INCONCLUSIVE
    assert "500" in record.notes[0]

@pytest.mark.asyncio
async def test_osv_timeout(monkeypatch):
    adapter = OSVAdapter(max_retries=0)

    async def mock_post(*args, **kwargs):
        raise httpx.TimeoutException("Connection timed out")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    advs, record = await adapter.query_advisories("any-pkg", Ecosystem.PYPI)
    assert len(advs) == 0
    assert record.status == EvidenceStatus.INCONCLUSIVE
    assert "timed out" in record.notes[0]
