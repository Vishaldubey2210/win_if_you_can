from __future__ import annotations
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from pydantic import BaseModel, Field
from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction
from slopguard.audit.models import AuditEvent, AuditEventType

if TYPE_CHECKING:
    from slopguard.core.scanner import ScannerService


class QuarantineViolationError(Exception):
    """Raised when an installation action is blocked by SLOPGUARD quarantine policy."""
    pass


class InstallationPermit(BaseModel):
    allowed: bool
    package: str
    ecosystem: Ecosystem
    gate_action: PolicyAction
    reasons: List[str] = Field(default_factory=list)
    suggested_fix: Optional[str] = None
    quarantine_held: bool = False
    evidence_snapshot_id: Optional[str] = None


class AgentActionFirewall:
    """
    AI Agent Action Firewall and Pre-Install Quarantine Gate.
    Intercepts proposed package installations (e.g. pip install X, npm install Y),
    evaluates them through the control plane, and prevents execution when policy rejects.
    """

    def __init__(self, scanner_service: ScannerService) -> None:
        self.scanner = scanner_service

    async def verify_and_gate_install(
        self,
        package_name: str,
        ecosystem: Ecosystem = Ecosystem.PYPI,
        actor: str = "ai-agent",
        raise_on_block: bool = False,
    ) -> InstallationPermit:
        """
        Verify package before permitting installation action.
        """
        dep = ExtractedDependency(name=package_name, ecosystem=ecosystem)
        scan_res = await self.scanner.scan_dependencies([dep], source_label=f"agent-install:{actor}")

        eval_dep = scan_res.dependencies[0]
        verdict = eval_dep.decision.action

        # Log audit event
        event_type = AuditEventType.INSTALLATION_ALLOWED if verdict == PolicyAction.ALLOW else AuditEventType.INSTALLATION_BLOCKED
        if hasattr(self.scanner, "audit_logger") and self.scanner.audit_logger:
            self.scanner.audit_logger.log(
                AuditEvent(
                    scan_id=scan_res.scan_id,
                    event_type=event_type,
                    actor=actor,
                    package=package_name,
                    action=verdict.value,
                    details={"reasons": eval_dep.decision.reasons},
                )
            )

        if verdict == PolicyAction.ALLOW:
            return InstallationPermit(
                allowed=True,
                package=package_name,
                ecosystem=ecosystem,
                gate_action=PolicyAction.ALLOW,
                reasons=eval_dep.decision.reasons,
                quarantine_held=False,
            )
        else:
            permit = InstallationPermit(
                allowed=False,
                package=package_name,
                ecosystem=ecosystem,
                gate_action=verdict,
                reasons=eval_dep.decision.reasons,
                suggested_fix=eval_dep.decision.suggested_fix,
                quarantine_held=True,
            )
            if raise_on_block:
                raise QuarantineViolationError(
                    f"Installation of package '{package_name}' blocked by quarantine gate ({verdict.value}): "
                    + "; ".join(eval_dep.decision.reasons)
                )
            return permit
