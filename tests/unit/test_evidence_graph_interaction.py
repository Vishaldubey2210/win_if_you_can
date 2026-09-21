import html
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from slopguard.api.app import app
from slopguard.core.models import (
    Ecosystem,
    EvaluatedDependency,
    ExtractedDependency,
    IdentityResolution,
    IdentityStatus,
    PolicyAction,
    PolicyDecision,
    RegistryEvidence,
    RegistryStatus,
    TrustAssessment,
    TrustLevel,
)
from slopguard.evidence.graph import EvidenceGraph, NodeType, GraphNode
from slopguard.evidence.models import ProvenanceSignal, SecurityAdvisory

client = TestClient(app)


def build_test_graph(pkg_name="requests", missing_evidence=False, malicious=False):
    graph = EvidenceGraph()
    raw_name = "<script>alert('xss')</script>" if malicious else pkg_name

    dep = ExtractedDependency(
        name=raw_name,
        ecosystem=Ecosystem.PYPI,
        file_path="src/main.py",
        line_number=42,
        raw_statement=f"import {raw_name}",
    )
    identity = IdentityResolution(
        input_name=raw_name,
        normalized_name=pkg_name.lower(),
        resolved_package=pkg_name,
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
        confidence=0.98,
        evidence_notes=[f"Resolved {raw_name} securely"],
    )

    if missing_evidence:
        registry = RegistryEvidence(
            package_name=pkg_name,
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.NOT_FOUND,
            http_status=404,
        )
        prov = ProvenanceSignal(
            has_provenance=False,
            evidence_notes=["No cryptographic provenance attestation or verified repository found"],
        )
        advs = []
    else:
        repo_url = "https://github.com/psf/requests?query=<img src=x onerror=alert(1)>" if malicious else "https://github.com/psf/requests"
        author_name = "Kenneth Reitz <img src=x>" if malicious else "Kenneth Reitz"
        registry = RegistryEvidence(
            package_name=pkg_name,
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.FOUND,
            latest_version="2.34.2",
            release_count=163,
            repository_url=repo_url,
            author=author_name,
            latest_release_time=datetime(2026, 5, 14, 19, 25, tzinfo=timezone.utc),
            first_release_time=datetime(2011, 2, 14, 8, 49, tzinfo=timezone.utc),
            all_versions=["2.34.0", "2.34.1", "2.34.2"],
        )
        prov = ProvenanceSignal(
            has_provenance=True,
            publisher_identity=author_name,
            source_repository=repo_url,
            build_system="GitHub Actions",
            transparency_log_verified=True,
            evidence_notes=["Linked to verified GitHub repository and build workflow"],
        )
        advs = [
            SecurityAdvisory(
                advisory_id="GHSA-j8r2-6x86-q33q",
                summary="<b onmouseover=alert(1)>Leaked credentials in redirects</b>" if malicious else "Leaked credentials in redirects",
                severity="HIGH",
                affected_versions=["<2.31.0"],
                fixed_versions=["2.31.0"],
            )
        ]

    trust = TrustAssessment(
        package_name=pkg_name,
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.VERIFIED if not missing_evidence else TrustLevel.UNRESOLVED,
        identity_verified=True,
        registry_verified=not missing_evidence,
    )
    decision = PolicyDecision(action=PolicyAction.ALLOW if not missing_evidence else PolicyAction.BLOCK)

    eval_dep = EvaluatedDependency(
        extracted=dep,
        identity=identity,
        registry=registry,
        trust=trust,
        decision=decision,
        timestamp=datetime.now(timezone.utc),
    )

    graph.ingest_evaluated_dependency(eval_dep, advisories=advs, provenance=prov)
    return graph, eval_dep, advs, prov


# 1. Test clicking / querying IMPORT node
def test_node_import_evidence():
    graph, eval_dep, _, _ = build_test_graph("requests")
    imports = graph.get_package_imports("requests", Ecosystem.PYPI)
    assert len(imports) >= 1
    imp_node = imports[0]
    assert imp_node.type == NodeType.IMPORT
    assert imp_node.properties["import_specifier"] == "requests"
    assert imp_node.properties["language"] == "python"
    assert imp_node.properties["source_type"] == "SOURCE_CODE"
    assert imp_node.properties["file_path"] == "src/main.py"
    assert imp_node.properties["line_number"] == 42
    assert "timestamp" in imp_node.properties


# 2. Test clicking / querying PACKAGE node
def test_node_package_evidence():
    graph, eval_dep, _, _ = build_test_graph("requests")
    pkg_node = graph.get_package_node("requests", Ecosystem.PYPI)
    assert pkg_node is not None
    assert pkg_node.type == NodeType.PACKAGE
    assert pkg_node.properties["canonical_name"] == "requests"
    assert pkg_node.properties["ecosystem"] == "pypi"
    assert pkg_node.properties["identity_status"] == "RESOLVED"
    assert pkg_node.properties["normalized_name"] == "requests"
    assert pkg_node.properties["confidence"] == 0.98
    assert len(pkg_node.properties["evidence_notes"]) > 0


# 3. Test clicking / querying RELEASE node
def test_node_release_evidence():
    graph, eval_dep, _, _ = build_test_graph("requests")
    releases = graph.get_package_releases("requests", Ecosystem.PYPI)
    assert len(releases) == 1
    rel_node = releases[0]
    assert rel_node.type == NodeType.RELEASE
    assert rel_node.properties["version"] == "2.34.2"
    assert rel_node.properties["release_count"] == 163
    assert "2026-05-14" in rel_node.properties["latest_release_time"]
    assert "2011-02-14" in rel_node.properties["first_release_time"]
    assert "2.34.2" in rel_node.properties["all_versions"]


# 4. Test clicking / querying REPO node
def test_node_repo_evidence():
    graph, eval_dep, _, _ = build_test_graph("requests")
    repo = graph.get_package_repository("requests", Ecosystem.PYPI)
    assert repo is not None
    assert repo.type == NodeType.REPOSITORY
    assert repo.properties["url"] == "https://github.com/psf/requests"
    assert repo.properties["author"] == "Kenneth Reitz"
    assert repo.properties["has_repository"] is True


# 5. Test clicking / querying PROV node
def test_node_prov_evidence():
    graph, eval_dep, _, _ = build_test_graph("requests")
    prov = graph.get_package_provenance("requests", Ecosystem.PYPI)
    assert prov is not None
    assert prov.type == NodeType.PROVENANCE
    assert prov.properties["has_provenance"] is True
    assert prov.properties["build_system"] == "GitHub Actions"
    assert prov.properties["transparency_log_verified"] is True
    assert len(prov.properties["evidence_notes"]) > 0


# 6. Test clicking / querying OSV node
def test_node_osv_evidence():
    graph, eval_dep, advs, _ = build_test_graph("requests")
    advisory_nodes = graph.get_package_advisories("requests", Ecosystem.PYPI)
    assert len(advisory_nodes) == 1
    adv = advisory_nodes[0]
    assert adv.type == NodeType.ADVISORY
    assert adv.properties["advisory_id"] == "GHSA-j8r2-6x86-q33q"
    assert adv.properties["severity"] == "HIGH"
    assert adv.properties["affected_versions"] == ["<2.31.0"]
    assert adv.properties["fixed_versions"] == ["2.31.0"]
    assert adv.properties["source"] == "OSV (Open Source Vulnerabilities)"


# 7. Test missing evidence state (nonexistent/phantom package)
def test_missing_evidence_state():
    graph, eval_dep, _, _ = build_test_graph("requets", missing_evidence=True)
    # Releases must be empty
    releases = graph.get_package_releases("requets", Ecosystem.PYPI)
    assert len(releases) == 0

    # Repository must be None
    repo = graph.get_package_repository("requets", Ecosystem.PYPI)
    assert repo is None

    # Advisories must be empty
    advs = graph.get_package_advisories("requets", Ecosystem.PYPI)
    assert len(advs) == 0

    # Provenance has_provenance must be False
    prov = graph.get_package_provenance("requets", Ecosystem.PYPI)
    assert prov is not None
    assert prov.properties["has_provenance"] is False
    assert "No cryptographic provenance" in prov.properties["evidence_notes"][0]


# 8. Test switching between nodes in graph representation
def test_switching_between_nodes_representation():
    graph, _, _, _ = build_test_graph("requests")
    node_types_visited = []

    # Sequence of clicks: IMPORT -> PACKAGE -> RELEASE -> REPO -> PROV -> OSV
    click_sequence = ["IMPORT", "PACKAGE", "RELEASE", "REPO", "PROV", "OSV"]
    for ntype in click_sequence:
        if ntype == "IMPORT":
            res = graph.get_package_imports("requests", Ecosystem.PYPI)
            assert len(res) > 0
            node_types_visited.append("IMPORT")
        elif ntype == "PACKAGE":
            res = graph.get_package_node("requests", Ecosystem.PYPI)
            assert res is not None
            node_types_visited.append("PACKAGE")
        elif ntype == "RELEASE":
            res = graph.get_package_releases("requests", Ecosystem.PYPI)
            assert len(res) > 0
            node_types_visited.append("RELEASE")
        elif ntype == "REPO":
            res = graph.get_package_repository("requests", Ecosystem.PYPI)
            assert res is not None
            node_types_visited.append("REPO")
        elif ntype == "PROV":
            res = graph.get_package_provenance("requests", Ecosystem.PYPI)
            assert res is not None
            node_types_visited.append("PROV")
        elif ntype == "OSV":
            res = graph.get_package_advisories("requests", Ecosystem.PYPI)
            assert len(res) > 0
            node_types_visited.append("OSV")

    assert node_types_visited == click_sequence


# 9. Test malicious/untrusted metadata escaping
def test_untrusted_metadata_escaping():
    graph, eval_dep, advs, prov = build_test_graph("requests", malicious=True)
    imports = graph.get_package_imports("requests", Ecosystem.PYPI)
    raw_import = imports[0].properties["import_specifier"]
    assert "<script>" in raw_import

    # Verify standard HTML escaping sanitizes raw XSS payloads
    escaped_import = html.escape(raw_import)
    assert "<script>" not in escaped_import
    assert "&lt;script&gt;" in escaped_import

    repo = graph.get_package_repository("requests", Ecosystem.PYPI)
    escaped_repo = html.escape(repo.properties["url"])
    assert "<img" not in escaped_repo
    assert "&lt;img" in escaped_repo

    adv = graph.get_package_advisories("requests", Ecosystem.PYPI)[0]
    escaped_summary = html.escape(adv.properties["summary"])
    assert "<b" not in escaped_summary
    assert "&lt;b" in escaped_summary


# 10. Test API endpoint returns all 6 nodes and real evidence
def test_api_graph_endpoint_requests():
    resp = client.get("/api/v1/graph/pypi/requests")
    assert resp.status_code == 200
    data = resp.json()

    assert data["package"] == "requests"
    assert data["ecosystem"] == "pypi"

    # 1. IMPORT
    assert data["import_node"] is not None
    assert data["import_node"]["type"] == "IMPORT"
    assert data["import_node"]["properties"]["import_specifier"] == "requests"

    # 2. PACKAGE
    assert data["package_node"] is not None
    assert data["package_node"]["type"] == "PACKAGE"
    assert data["package_node"]["properties"]["canonical_name"] == "requests"

    # 3. RELEASE
    assert len(data["releases"]) >= 1
    assert data["releases"][0]["type"] == "RELEASE"
    assert "version" in data["releases"][0]["properties"]

    # 4. REPO
    assert data["repository"] is not None
    assert data["repository"]["type"] == "REPOSITORY"
    assert "github.com" in data["repository"]["properties"]["url"]

    # 5. PROV
    assert data["provenance"] is not None
    assert data["provenance"]["type"] == "PROVENANCE"

    # 6. OSV
    assert "advisories" in data
    assert isinstance(data["advisories"], list)


def test_api_graph_endpoint_nonexistent():
    resp = client.get("/api/v1/graph/pypi/requets")
    assert resp.status_code == 200
    data = resp.json()

    # IMPORT & PACKAGE resolved
    assert data["import_node"] is not None
    assert data["package_node"] is not None

    # Missing evidence states: zero releases, null repository
    assert len(data["releases"]) == 0
    assert data["repository"] is None
    assert data["provenance"]["properties"]["has_provenance"] is False
