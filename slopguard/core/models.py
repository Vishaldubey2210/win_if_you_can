from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    UNKNOWN = "unknown"


class RegistryStatus(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    SERVER_ERROR = "SERVER_ERROR"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    SKIPPED = "SKIPPED"


class IdentityStatus(str, Enum):
    RESOLVED = "RESOLVED"
    ALIASED = "ALIASED"
    STDLIB = "STDLIB"
    UNRESOLVED = "UNRESOLVED"
    AMBIGUOUS = "AMBIGUOUS"


class TrustLevel(str, Enum):
    VERIFIED = "VERIFIED"
    REVIEW = "REVIEW"
    SUSPICIOUS = "SUSPICIOUS"
    UNRESOLVED = "UNRESOLVED"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"
    ALERT = "ALERT"


class PhantomState(str, Enum):
    NONE = "NONE"
    NOT_FOUND = "NOT_FOUND"
    WATCH = "WATCH"
    APPEARED = "APPEARED"
    RESOLVED = "RESOLVED"


class DependencySourceType(str, Enum):
    SOURCE_CODE = "SOURCE_CODE"
    MANIFEST = "MANIFEST"
    AGENT_ACTION = "AGENT_ACTION"


class ExtractedDependency(BaseModel):
    name: str = Field(description="Raw import or manifest requirement name")
    version_constraint: Optional[str] = Field(default=None, description="Specified version constraint if any")
    ecosystem: Ecosystem = Field(default=Ecosystem.UNKNOWN)
    source_type: DependencySourceType = Field(default=DependencySourceType.SOURCE_CODE)
    file_path: Optional[str] = Field(default=None)
    line_number: Optional[int] = Field(default=None)
    raw_statement: Optional[str] = Field(default=None)
    is_stdlib: bool = Field(default=False)
    is_relative: bool = Field(default=False)


class IdentityResolution(BaseModel):
    input_name: str
    normalized_name: str
    resolved_package: str
    ecosystem: Ecosystem
    status: IdentityStatus
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    is_stdlib: bool = False
    evidence_notes: List[str] = Field(default_factory=list)


class RegistryEvidence(BaseModel):
    package_name: str
    ecosystem: Ecosystem
    status: RegistryStatus
    http_status: Optional[int] = None
    latest_version: Optional[str] = None
    all_versions: List[str] = Field(default_factory=list)
    release_count: int = 0
    first_release_time: Optional[datetime] = None
    latest_release_time: Optional[datetime] = None
    repository_url: Optional[str] = None
    homepage_url: Optional[str] = None
    author: Optional[str] = None
    maintainers: List[str] = Field(default_factory=list)
    description_summary: Optional[str] = None
    latency_ms: float = 0.0
    error_message: Optional[str] = None
    cached: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TyposquatCandidate(BaseModel):
    target_package: str
    similar_package: str
    distance: int
    similarity_ratio: float
    confidence: float
    reason: str


class TrustAssessment(BaseModel):
    package_name: str
    ecosystem: Ecosystem
    level: TrustLevel
    identity_verified: bool
    registry_verified: bool
    is_stdlib: bool = False
    has_typosquat_risk: bool = False
    typosquat_details: Optional[TyposquatCandidate] = None
    signals: Dict[str, Any] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    action: PolicyAction
    reasons: List[str] = Field(default_factory=list)
    risk_level: str = "LOW"
    confidence: float = 1.0
    requires_human_review: bool = False
    suggested_fix: Optional[str] = None


class EvaluatedDependency(BaseModel):
    extracted: ExtractedDependency
    identity: IdentityResolution
    registry: Optional[RegistryEvidence] = None
    trust: TrustAssessment
    phantom_state: PhantomState = PhantomState.NONE
    decision: PolicyDecision
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanSummary(BaseModel):
    total_extracted: int = 0
    stdlib_count: int = 0
    allowed_count: int = 0
    hold_count: int = 0
    blocked_count: int = 0
    alert_count: int = 0
    duration_ms: float = 0.0


class ScanResult(BaseModel):
    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_label: Optional[str] = None
    ecosystem: Ecosystem
    dependencies: List[EvaluatedDependency] = Field(default_factory=list)
    summary: ScanSummary
    scenario: Optional[str] = Field(default=None, description="Active scenario label associated with the scan")
