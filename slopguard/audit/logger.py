from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from slopguard.audit.models import AuditEvent, AuditEventType, DecisionReconstruction
from slopguard.core.models import EvaluatedDependency


class AuditLogger:
    """
    Append-only audit log maintaining complete decision reconstruction trails
    and observability events.
    """

    def __init__(self, log_path: Optional[str] = None) -> None:
        self.log_path = Path(log_path) if log_path else None
        self._events: List[AuditEvent] = []
        if self.log_path and self.log_path.exists():
            self._load()

    def _load(self) -> None:
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._events.append(AuditEvent.model_validate_json(line))
        except Exception:
            pass

    def log(self, event: AuditEvent) -> None:
        self._events.append(event)
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")

    def list_events(
        self,
        scan_id: Optional[str] = None,
        package: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        filtered = self._events
        if scan_id:
            filtered = [e for e in filtered if e.scan_id == scan_id]
        if package:
            pkg_lower = package.lower().strip()
            filtered = [e for e in filtered if e.package and e.package.lower() == pkg_lower]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        return filtered[-limit:]

    def reconstruct(self, package_name: str, evaluated_dep: Optional[EvaluatedDependency] = None) -> Optional[DecisionReconstruction]:
        """
        Deterministic decision reconstruction answering:
        'Why did SLOPGUARD make this decision for package X?'
        """
        pkg_events = self.list_events(package=package_name)

        if not evaluated_dep and not pkg_events:
            return None

        verdict = evaluated_dep.decision.action.value if evaluated_dep else "UNKNOWN"
        risk = evaluated_dep.decision.risk_level if evaluated_dep else "UNKNOWN"
        review = evaluated_dep.decision.requires_human_review if evaluated_dep else False
        ts = evaluated_dep.timestamp if evaluated_dep else pkg_events[-1].timestamp
        reasons = evaluated_dep.decision.reasons if evaluated_dep else []
        fix = evaluated_dep.decision.suggested_fix if evaluated_dep else None

        reg_data = evaluated_dep.registry.model_dump(mode="json") if evaluated_dep and evaluated_dep.registry else {}
        trust_signals = evaluated_dep.trust.signals if evaluated_dep else {}
        temporal_history = {"phantom_state": evaluated_dep.phantom_state.value} if evaluated_dep else {}

        return DecisionReconstruction(
            package=package_name,
            timestamp=ts,
            verdict=verdict,
            risk_level=risk,
            requires_human_review=review,
            import_specifier=evaluated_dep.extracted.name if evaluated_dep else None,
            canonical_identity=evaluated_dep.identity.resolved_package if evaluated_dep else None,
            registry_evidence=reg_data,
            trust_signals=trust_signals,
            reasons=reasons,
            suggested_fix=fix,
            audit_events=pkg_events,
        )
