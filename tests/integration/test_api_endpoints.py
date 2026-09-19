import pytest
from fastapi.testclient import TestClient
from slopguard.api.app import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "slopguard"

def test_serve_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "SLOPGUARD" in response.text
    assert "CONTROL PLANE" in response.text

def test_scan_endpoint_python():
    payload = {
        "content": "import os\nimport sys\nimport requests",
        "language": "python",
        "source_label": "test_script.py"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert len(data["dependencies"]) == 3
    assert data["summary"]["allowed_count"] == 3
    assert data["summary"]["blocked_count"] == 0

def test_scan_endpoint_block_phantom():
    payload = {
        "content": "import completely_fake_package_999999",
        "language": "python"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["blocked_count"] == 1
    dep = data["dependencies"][0]
    assert dep["decision"]["action"] == "BLOCK"
    assert dep["registry"]["status"] == "NOT_FOUND"

def test_verify_endpoint():
    response = client.get("/api/v1/verify/pypi/requests")
    assert response.status_code == 200
    data = response.json()
    assert data["package_name"] == "requests"
    assert data["status"] == "FOUND"
    assert data["release_count"] > 100

def test_list_phantoms_endpoint():
    response = client.get("/api/v1/phantoms")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_policy_simulate_endpoint():
    payload = {
        "package_name": "requests",
        "ecosystem": "pypi",
        "profile": "STRICT_CI"
    }
    response = client.post("/api/v1/policy/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["simulated_action"] == "ALLOW"
    assert data["policy_profile"] == "STRICT_CI"

def test_gate_verify_install_endpoint():
    # Attempting to install a hallucinated package should be BLOCKED
    payload = {
        "package_name": "langchain-fastapi-agent-optimizer-fake",
        "ecosystem": "pypi",
        "actor": "ai-coding-agent"
    }
    response = client.post("/api/v1/gate/verify-install", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is False
    assert data["gate_action"] == "BLOCK"
    assert data["quarantine_held"] is True

def test_repair_propose_and_rescan_endpoints():
    propose_payload = {
        "dependency_name": "requets",
        "code": "import requets\nprint('hello')",
        "ecosystem": "pypi"
    }
    response = client.post("/api/v1/repair/propose", json=propose_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["candidate_count"] > 0
    prop = data["proposals"][0]
    assert prop["candidate"]["candidate_package"] == "requests"

    # Rescan the patched code
    rescan_payload = {
        "patched_code": prop["patched_code"],
        "language": "python"
    }
    rescan_resp = client.post("/api/v1/repair/rescan", json=rescan_payload)
    assert rescan_resp.status_code == 200
    rescan_data = rescan_resp.json()
    assert rescan_data["success"] is True

def test_audit_list_endpoint():
    response = client.get("/api/v1/audit")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_benchmark_endpoint():
    response = client.get("/api/v1/benchmark")
    assert response.status_code == 200
    data = response.json()
    assert "evaluated_categories" in data
    assert data["evaluated_categories"]["REAL"]["accuracy"] == 100.0
