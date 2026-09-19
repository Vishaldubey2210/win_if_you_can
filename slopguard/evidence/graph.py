from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field
from slopguard.core.models import Ecosystem, EvaluatedDependency, RegistryStatus
from slopguard.evidence.models import EvidenceRecord, ProvenanceSignal, SecurityAdvisory


class NodeType(str, Enum):
    IMPORT = "IMPORT"
    PACKAGE = "PACKAGE"
    RELEASE = "RELEASE"
    PUBLISHER = "PUBLISHER"
    REPOSITORY = "REPOSITORY"
    ADVISORY = "ADVISORY"
    PROVENANCE = "PROVENANCE"
    TEMPORAL_OBSERVATION = "TEMPORAL_OBSERVATION"


class EdgeRelation(str, Enum):
    RESOLVES_TO = "RESOLVES_TO"
    HAS_RELEASE = "HAS_RELEASE"
    PUBLISHED_BY = "PUBLISHED_BY"
    HOSTED_AT = "HOSTED_AT"
    AFFECTED_BY = "AFFECTED_BY"
    ATTESTED_BY = "ATTESTED_BY"
    OBSERVED_AS = "OBSERVED_AS"


class GraphNode(BaseModel):
    id: str
    type: NodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    evidence_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GraphEdge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    target_id: str
    relation: EdgeRelation
    evidence_id: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceGraph(BaseModel):
    """
    Structured queryable in-memory Evidence Graph.
    Ensures every security connection is backed by an explicit evidence edge.
    """
    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)

    def add_node(self, node: GraphNode) -> GraphNode:
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        self.edges.append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def get_package_node_id(self, package_name: str, ecosystem: Ecosystem) -> str:
        return f"pkg:{ecosystem.value}:{package_name.strip().lower()}"

    def get_package_releases(self, package_name: str, ecosystem: Ecosystem) -> List[GraphNode]:
        pkg_id = self.get_package_node_id(package_name, ecosystem)
        release_node_ids = {
            e.target_id for e in self.edges if e.source_id == pkg_id and e.relation == EdgeRelation.HAS_RELEASE
        }
        return [self.nodes[n_id] for n_id in release_node_ids if n_id in self.nodes]

    def get_package_repository(self, package_name: str, ecosystem: Ecosystem) -> Optional[GraphNode]:
        pkg_id = self.get_package_node_id(package_name, ecosystem)
        for e in self.edges:
            if e.source_id == pkg_id and e.relation == EdgeRelation.HOSTED_AT:
                return self.nodes.get(e.target_id)
        return None

    def get_package_advisories(self, package_name: str, ecosystem: Ecosystem) -> List[GraphNode]:
        pkg_id = self.get_package_node_id(package_name, ecosystem)
        advisory_ids = {
            e.target_id for e in self.edges if e.source_id == pkg_id and e.relation == EdgeRelation.AFFECTED_BY
        }
        return [self.nodes[n_id] for n_id in advisory_ids if n_id in self.nodes]

    def get_package_provenance(self, package_name: str, ecosystem: Ecosystem) -> Optional[GraphNode]:
        pkg_id = self.get_package_node_id(package_name, ecosystem)
        for e in self.edges:
            if e.source_id == pkg_id and e.relation == EdgeRelation.ATTESTED_BY:
                return self.nodes.get(e.target_id)
        return None

    def get_package_history(self, package_name: str, ecosystem: Ecosystem) -> List[GraphNode]:
        pkg_id = self.get_package_node_id(package_name, ecosystem)
        history_ids = {
            e.target_id for e in self.edges if e.source_id == pkg_id and e.relation == EdgeRelation.OBSERVED_AS
        }
        return [self.nodes[n_id] for n_id in history_ids if n_id in self.nodes]

    def ingest_evaluated_dependency(
        self,
        dep: EvaluatedDependency,
        advisories: Optional[List[SecurityAdvisory]] = None,
        provenance: Optional[ProvenanceSignal] = None,
    ) -> None:
        """
        Builds graph nodes and edges from an EvaluatedDependency with full evidence traceability.
        """
        raw_name = dep.extracted.name
        pkg_name = dep.identity.resolved_package
        eco = dep.identity.ecosystem

        # 1. Import Node
        import_id = f"import:{eco.value}:{raw_name}:{dep.extracted.file_path or 'unknown'}:{dep.extracted.line_number or 0}"
        self.add_node(
            GraphNode(
                id=import_id,
                type=NodeType.IMPORT,
                label=raw_name,
                properties={
                    "file_path": dep.extracted.file_path,
                    "line_number": dep.extracted.line_number,
                    "is_stdlib": dep.extracted.is_stdlib,
                },
            )
        )

        # 2. Package Node
        pkg_id = self.get_package_node_id(pkg_name, eco)
        self.add_node(
            GraphNode(
                id=pkg_id,
                type=NodeType.PACKAGE,
                label=pkg_name,
                properties={
                    "ecosystem": eco.value,
                    "identity_status": dep.identity.status.value,
                    "confidence": dep.identity.confidence,
                    "is_stdlib": dep.identity.is_stdlib,
                },
            )
        )

        # Edge: Import -> Package
        self.add_edge(
            GraphEdge(
                source_id=import_id,
                target_id=pkg_id,
                relation=EdgeRelation.RESOLVES_TO,
                properties={"status": dep.identity.status.value},
            )
        )

        # 3. Registry releases & metadata
        if dep.registry and dep.registry.status == RegistryStatus.FOUND:
            # Latest Release Node
            if dep.registry.latest_version:
                rel_id = f"rel:{eco.value}:{pkg_name}@{dep.registry.latest_version}"
                self.add_node(
                    GraphNode(
                        id=rel_id,
                        type=NodeType.RELEASE,
                        label=f"{pkg_name}@{dep.registry.latest_version}",
                        properties={
                            "version": dep.registry.latest_version,
                            "release_count": dep.registry.release_count,
                            "latest_release_time": dep.registry.latest_release_time.isoformat() if dep.registry.latest_release_time else None,
                        },
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=pkg_id,
                        target_id=rel_id,
                        relation=EdgeRelation.HAS_RELEASE,
                    )
                )

                # Publisher / Author Node
                if dep.registry.author:
                    pub_id = f"pub:{dep.registry.author.lower()}"
                    self.add_node(
                        GraphNode(
                            id=pub_id,
                            type=NodeType.PUBLISHER,
                            label=dep.registry.author,
                            properties={"name": dep.registry.author},
                        )
                    )
                    self.add_edge(
                        GraphEdge(
                            source_id=rel_id,
                            target_id=pub_id,
                            relation=EdgeRelation.PUBLISHED_BY,
                        )
                    )

            # Repository Node
            if dep.registry.repository_url:
                repo_id = f"repo:{dep.registry.repository_url}"
                self.add_node(
                    GraphNode(
                        id=repo_id,
                        type=NodeType.REPOSITORY,
                        label=dep.registry.repository_url,
                        properties={"url": dep.registry.repository_url},
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=pkg_id,
                        target_id=repo_id,
                        relation=EdgeRelation.HOSTED_AT,
                    )
                )

        # 4. Security Advisories
        if advisories:
            for adv in advisories:
                adv_id = f"adv:{adv.advisory_id}"
                self.add_node(
                    GraphNode(
                        id=adv_id,
                        type=NodeType.ADVISORY,
                        label=adv.advisory_id,
                        properties={
                            "summary": adv.summary,
                            "severity": adv.severity,
                            "affected_versions": adv.affected_versions,
                            "fixed_versions": adv.fixed_versions,
                        },
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=pkg_id,
                        target_id=adv_id,
                        relation=EdgeRelation.AFFECTED_BY,
                    )
                )

        # 5. Provenance Signal
        if provenance:
            prov_id = f"prov:{eco.value}:{pkg_name}"
            self.add_node(
                GraphNode(
                    id=prov_id,
                    type=NodeType.PROVENANCE,
                    label=f"Provenance ({pkg_name})",
                    properties=provenance.model_dump(),
                )
            )
            self.add_edge(
                GraphEdge(
                    source_id=pkg_id,
                    target_id=prov_id,
                    relation=EdgeRelation.ATTESTED_BY,
                )
            )

        # 6. Temporal Observation
        if dep.phantom_state.value != "NONE":
            obs_id = f"obs:{eco.value}:{pkg_name}:{dep.phantom_state.value}"
            self.add_node(
                GraphNode(
                    id=obs_id,
                    type=NodeType.TEMPORAL_OBSERVATION,
                    label=f"State: {dep.phantom_state.value}",
                    properties={"state": dep.phantom_state.value},
                )
            )
            self.add_edge(
                GraphEdge(
                    source_id=pkg_id,
                    target_id=obs_id,
                    relation=EdgeRelation.OBSERVED_AS,
                )
            )
