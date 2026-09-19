from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    SCAN_STARTED = "scan_started"
    DEPENDENCY_EXTRACTED = "dependency_extracted"
    IDENTITY_RESOLVED = "identity_resolved"
    REGISTRY_CHECKED = "registry_checked"
    EVIDENCE_COLLECTED = "evidence_collected"
    TRUST_EVALUATED = "trust_evaluated"
    PHANTOM_DETECTED = "phantom_detected"
    STATE_CHANGED = "state_changed"
    REPAIR_PROPOSED = "repair_proposed"
    REPAIR_APPLIED = "repair_applied"
    RESCAN_STARTED = "rescan_started"
    POLICY_EVALUATED = "policy_evaluated"
    INSTALLATION_BLOCKED = "installation_blocked"
    INSTALLATION_ALLOWED = "installation_allowed"


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: Optional[str] = None
    event_type: AuditEventType
    actor: str = "slopguard-control-plane"
    package: Optional[str] = None
    action: Optional[str] = None
    policy_version: str = "1.0.0"
    details: Dict[str, Any] = Field(default_factory=dict)


class DecisionReconstruction(BaseModel):
    package: str
    scan_id: Optional[str] = None
    timestamp: datetime
    verdict: str
    risk_level: str
    requires_human_review: bool
    import_specifier: Optional[str] = None
    canonical_identity: Optional[str] = None
    registry_evidence: Dict[str, Any] = Field(default_factory=dict)
    trust_signals: Dict[str, Any] = Field(default_factory=dict)
    advisories: List[Dict[str, Any]] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    temporal_history: Dict[str, Any] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)
    suggested_fix: Optional[str] = None
    audit_events: List[AuditEvent] = Field(default_factory=list)
