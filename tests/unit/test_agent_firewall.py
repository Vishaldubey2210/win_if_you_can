import pytest
from slopguard.core.models import Ecosystem, PolicyAction
from slopguard.core.scanner import ScannerService
from slopguard.gate.firewall import AgentActionFirewall, QuarantineViolationError

@pytest.mark.asyncio
async def test_agent_firewall_blocks_phantom_install(tmp_path):
    storage = tmp_path / "firewall_phantoms.json"
    scanner = ScannerService(phantom_storage_path=str(storage))
    firewall = AgentActionFirewall(scanner)

    # Attempting to install a non-existent package
    pkg = "ai-generated-nonexistent-package-xyz"
    permit = await firewall.verify_and_gate_install(pkg, ecosystem=Ecosystem.PYPI)

    assert permit.allowed is False
    assert permit.gate_action == PolicyAction.BLOCK
    assert permit.quarantine_held is True

    # With raise_on_block=True
    with pytest.raises(QuarantineViolationError, match="blocked by quarantine gate"):
        await firewall.verify_and_gate_install(pkg, ecosystem=Ecosystem.PYPI, raise_on_block=True)

@pytest.mark.asyncio
async def test_agent_firewall_permits_genuine_install(tmp_path):
    storage = tmp_path / "firewall_phantoms.json"
    scanner = ScannerService(phantom_storage_path=str(storage))
    firewall = AgentActionFirewall(scanner)

    permit = await firewall.verify_and_gate_install("requests", ecosystem=Ecosystem.PYPI)
    assert permit.allowed is True
    assert permit.gate_action == PolicyAction.ALLOW
    assert permit.quarantine_held is False
