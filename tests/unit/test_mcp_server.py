import json
import pytest
from click.testing import CliRunner
from slopguard.cli.main import cli
from slopguard.mcp.server import create_mcp_server


@pytest.mark.asyncio
async def test_mcp_server_initialization():
    server = create_mcp_server()
    assert server.name == "slopguard"

    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    expected_tools = [
        "verify_dependency",
        "scan_code",
        "inspect_evidence",
        "inspect_history",
        "propose_repair",
        "rescan_patch",
        "gate_install",
        "list_phantoms",
        "simulate_policy",
    ]
    for exp in expected_tools:
        assert exp in tool_names, f"Missing tool: {exp}"


@pytest.mark.asyncio
async def test_mcp_server_resources():
    server = create_mcp_server()
    resources = await server.list_resources()
    uris = [str(r.uri) for r in resources]
    assert "slopguard://health" in uris
    assert "slopguard://policy" in uris
    assert "slopguard://phantoms" in uris


@pytest.mark.asyncio
async def test_mcp_server_prompts():
    server = create_mcp_server()
    prompts = await server.list_prompts()
    prompt_names = [p.name for p in prompts]
    assert "audit_code_dependencies" in prompt_names
    assert "repair_hallucinated_dependency" in prompt_names


@pytest.mark.asyncio
async def test_mcp_server_call_scan_code():
    server = create_mcp_server()
    code = "import json\nimport math"
    result = await server.call_tool("scan_code", {"code": code, "language": "python"})
    assert result is not None
    assert result.is_error is False
    res_data = result.structured_content["result"]
    assert res_data["allowed"] is True
    assert len(res_data["dependencies"]) == 2


@pytest.mark.asyncio
async def test_mcp_server_call_list_phantoms():
    server = create_mcp_server()
    result = await server.call_tool("list_phantoms", {})
    assert result is not None
    assert result.is_error is False
    res_data = result.structured_content["result"]
    assert "count" in res_data
    assert "phantoms" in res_data


def test_cli_mcp_config():
    runner = CliRunner()
    result = runner.invoke(cli, ["mcp", "config", "--client", "cursor"])
    assert result.exit_code == 0
    assert "mcpServers" in result.output
    assert "slopguard" in result.output


def test_cli_mcp_tools():
    runner = CliRunner()
    result = runner.invoke(cli, ["mcp", "tools"])
    assert result.exit_code == 0
    assert "verify_dependency" in result.output
    assert "scan_code" in result.output
    assert "gate_install" in result.output
