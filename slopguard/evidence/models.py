from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from slopguard.core.models import Ecosystem


class EvidenceType(str, Enum):
    REGISTRY_IDENTITY = "REGISTRY_IDENTITY"
    PACKAGE_METADATA = "PACKAGE_METADATA"
    RELEASE_METADATA = "RELEASE_METADATA"
    REPOSITORY = "REPOSITORY"
    PUBLISHER = "PUBLISHER"
    ADVISORY = "ADVISORY"
    PROVENANCE = "PROVENANCE"
    ALIAS_MAPPING = "ALIAS_MAPPING"
    TYPOSQUAT_RELATION = "TYPOSQUAT_RELATION"
    TEMPORAL_OBSERVATION = "TEMPORAL_OBSERVATION"


class EvidenceStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceRecord(BaseModel):
    """
    Normalized security evidence record with provenance, timestamps,
    and structured payloads.
    """
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    package: str
    ecosystem: Ecosystem
    version: Optional[str] = None
    evidence_type: EvidenceType
    source: str = Field(description="Originating source e.g. pypi.org, api.osv.dev, registry.npmjs.org")
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: EvidenceStatus
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    payload: Dict[str, Any] = Field(default_factory=dict)
    reference_url: Optional[str] = None
    notes: List[str] = Field(default_factory=list)


class SecurityAdvisory(BaseModel):
    """Normalized advisory model from OSV or CVE feeds."""
    advisory_id: str  # e.g. GHSA-xxxx-xxxx, PYSEC-2023-xxx, CVE-2023-xxxx
    summary: str
    details: Optional[str] = None
    severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW
    affected_versions: List[str] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    published_at: Optional[datetime] = None
    references: List[str] = Field(default_factory=list)


class ProvenanceSignal(BaseModel):
    """Attestation and provenance evidence from source repos and registries."""
    has_provenance: bool = False
    publisher_identity: Optional[str] = None
    source_repository: Optional[str] = None
    build_system: Optional[str] = None
    attestation_url: Optional[str] = None
    transparency_log_verified: bool = False
    evidence_notes: List[str] = Field(default_factory=list)


class EvidenceSnapshot(BaseModel):
    """
    Cryptographic/temporal snapshot of all security evidence evaluated
    for a specific package at a given point in time (TOCTOU protection).
    """
    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    package: str
    ecosystem: Ecosystem
    version: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy_version: str = "1.0.0"
    records: List[EvidenceRecord] = Field(default_factory=list)
    advisories: List[SecurityAdvisory] = Field(default_factory=list)
    provenance: Optional[ProvenanceSignal] = None
    snapshot_hash: Optional[str] = None
