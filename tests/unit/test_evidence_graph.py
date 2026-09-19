import pytest
from datetime import datetime, timezone
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
from slopguard.evidence.graph import EvidenceGraph, NodeType
from slopguard.evidence.models import ProvenanceSignal, SecurityAdvisory

def test_evidence_graph_ingestion_and_queries():
    graph = EvidenceGraph()

    dep = ExtractedDependency(
        name="requests",
        ecosystem=Ecosystem.PYPI,
        file_path="app.py",
        line_number=10,
    )
    identity = IdentityResolution(
        input_name="requests",
        normalized_name="requests",
        resolved_package="requests",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    registry = RegistryEvidence(
        package_name="requests",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        latest_version="2.31.0",
        release_count=150,
        repository_url="https://github.com/psf/requests",
        author="Kenneth Reitz",
    )
    trust = TrustAssessment(
        package_name="requests",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.VERIFIED,
        identity_verified=True,
        registry_verified=True,
    )
    decision = PolicyDecision(action=PolicyAction.ALLOW)

    eval_dep = EvaluatedDependency(
        extracted=dep,
        identity=identity,
        registry=registry,
        trust=trust,
        decision=decision,
    )

    advisories = [
        SecurityAdvisory(
            advisory_id="GHSA-j8r2-6x86-q33q",
            summary="Leaked credentials in session redirects",
            severity="MEDIUM",
        )
    ]
    provenance = ProvenanceSignal(
        has_provenance=True,
        publisher_identity="Kenneth Reitz",
        source_repository="https://github.com/psf/requests",
        build_system="GitHub Actions",
    )

    graph.ingest_evaluated_dependency(eval_dep, advisories=advisories, provenance=provenance)

    # Test query methods
    releases = graph.get_package_releases("requests", Ecosystem.PYPI)
    assert len(releases) == 1
    assert releases[0].properties["version"] == "2.31.0"

    repo = graph.get_package_repository("requests", Ecosystem.PYPI)
    assert repo is not None
    assert repo.properties["url"] == "https://github.com/psf/requests"

    adv_nodes = graph.get_package_advisories("requests", Ecosystem.PYPI)
    assert len(adv_nodes) == 1
    assert adv_nodes[0].label == "GHSA-j8r2-6x86-q33q"

    prov_node = graph.get_package_provenance("requests", Ecosystem.PYPI)
    assert prov_node is not None
    assert prov_node.properties["build_system"] == "GitHub Actions"
