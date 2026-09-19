from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from slopguard.core.models import Ecosystem, PolicyAction


class RepairCandidate(BaseModel):
    candidate_package: str
    original_dependency: str
    ecosystem: Ecosystem
    confidence: float = Field(ge=0.0, le=1.0)
    compatibility_score: float = Field(ge=0.0, le=1.0, default=1.0)
    reason: str
    is_stdlib_alternative: bool = False
    evidence_notes: List[str] = Field(default_factory=list)


class PatchProposal(BaseModel):
    original_code: str
    patched_code: str
    original_import: str
    replacement_import: str
    diff: str
    candidate: RepairCandidate


class RescanValidation(BaseModel):
    success: bool
    rescan_verdict: PolicyAction
    reasons: List[str] = Field(default_factory=list)
    remaining_blocked_count: int = 0
