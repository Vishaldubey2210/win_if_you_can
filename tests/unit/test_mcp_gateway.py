import pytest
from unittest.mock import AsyncMock
from slopguard.mcp.gateway import MCPGateway
from slopguard.core.scanner import ScannerService
from slopguard.core.models import Ecosystem, RegistryStatus, RegistryEvidence, PolicyAction, PolicyDecision


@pytest.mark.asyncio
async def test_mcp_tool_definitions():
    gateway = MCPGateway()
    tools = gateway.get_tool_definitions()
    names = [t["name"] for t in tools]
    assert "verify_dependency" in names
    assert "inspect_evidence" in names
    assert "inspect_history" in names
    assert "propose_repair" in names
    assert "rescan_patch" in names
    assert "scan_code" in names
    assert "gate_install" in names
    assert "list_phantoms" in names
    assert "simulate_policy" in names


@pytest.mark.asyncio
async def test_mcp_execute_verify_tool():
    scanner = ScannerService()
    # Mock pypi adapter to avoid external network calls during unit test
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="requests",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.FOUND,
            latest_version="2.31.0",
            release_count=50,
        )
    )
    scanner.osv_adapter.query_advisories = AsyncMock(return_value=([], False))

    gateway = MCPGateway(scanner_service=scanner)
    result = await gateway.execute_tool("verify_dependency", {"package_name": "requests"})
    assert result["package"] == "requests"
    assert result["verdict"] == "ALLOW"
    assert result["risk_level"] == "LOW"


@pytest.mark.asyncio
async def test_mcp_execute_propose_repair():
    gateway = MCPGateway()
    code = "import cv2\nimg = cv2.imread('test.png')"
    result = await gateway.execute_tool("propose_repair", {"package_name": "cv2", "code": code})
    assert result["candidates_found"] > 0
    assert result["best_candidate"]["candidate_package"] == "opencv-python"
    assert "import cv2" in code


@pytest.mark.asyncio
async def test_mcp_execute_scan_code_tool():
    gateway = MCPGateway()
    code = "import os\nimport sys"
    result = await gateway.execute_tool("scan_code", {"code": code, "language": "python"})
    assert result["allowed"] is True
    assert len(result["dependencies"]) == 2
    names = [d["name"] for d in result["dependencies"]]
    assert "os" in names
    assert "sys" in names


@pytest.mark.asyncio
async def test_mcp_execute_list_phantoms_tool():
    gateway = MCPGateway()
    result = await gateway.execute_tool("list_phantoms", {})
    assert "count" in result
    assert "phantoms" in result
    assert isinstance(result["phantoms"], list)
