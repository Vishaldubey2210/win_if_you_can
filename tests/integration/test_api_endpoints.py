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
