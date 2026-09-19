from __future__ import annotations
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from slopguard.core.models import Ecosystem, PhantomState, RegistryStatus


class StateTransition(BaseModel):
    from_state: PhantomState
    to_state: PhantomState
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str


class PhantomRecord(BaseModel):
    package_name: str
    ecosystem: Ecosystem
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    occurrence_count: int = 1
    current_state: PhantomState = PhantomState.NOT_FOUND
    previous_state: PhantomState = PhantomState.NONE
    transitions: List[StateTransition] = Field(default_factory=list)
    last_known_registry_status: Optional[RegistryStatus] = None
    notes: List[str] = Field(default_factory=list)


class PhantomMemory:
    """
    Temporal memory tracking packages that were unresolved (phantoms / hallucinations).
    Detects when a previously non-existent package suddenly appears on a registry
    (state change NOT_FOUND -> APPEARED), a critical indicator of dependency hallucination exploitation.
    """

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self.storage_path = Path(storage_path) if storage_path else None
        self._records: Dict[str, PhantomRecord] = {}
        if self.storage_path and self.storage_path.exists():
            self._load()

    def _key(self, package_name: str, ecosystem: Ecosystem) -> str:
        clean = package_name.strip().lower()
        if ecosystem == Ecosystem.PYPI:
            clean = re.sub(r"[-_.]+", "-", clean)
        return f"{ecosystem.value}:{clean}"

    def _load(self) -> None:
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    rec = PhantomRecord.model_validate(item)
                    self._records[self._key(rec.package_name, rec.ecosystem)] = rec
        except Exception:
            self._records = {}

    def save(self) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        serializable = [r.model_dump(mode="json") for r in self._records.values()]
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)

    def record_observation(
        self, package_name: str, ecosystem: Ecosystem, registry_status: RegistryStatus
    ) -> PhantomRecord:
        """
        Record observation of a package, updating temporal phantom states and detecting transitions.
        """
        key = self._key(package_name, ecosystem)
        now = datetime.now(timezone.utc)

        if key in self._records:
            record = self._records[key]
            record.last_seen = now
            record.occurrence_count += 1
            prev_status = record.last_known_registry_status
            record.last_known_registry_status = registry_status

            # Check for phantom state transitions
            if registry_status == RegistryStatus.FOUND:
                if record.current_state in (PhantomState.NOT_FOUND, PhantomState.WATCH):
                    # Package was previously missing, but has now appeared!
                    record.previous_state = record.current_state
                    record.current_state = PhantomState.APPEARED
                    transition = StateTransition(
                        from_state=record.previous_state,
                        to_state=PhantomState.APPEARED,
                        timestamp=now,
                        reason="Previously unresolved phantom package is now published on registry",
                    )
                    record.transitions.append(transition)
                    record.notes.append(
                        f"CRITICAL STATE CHANGE: First seen as NOT_FOUND on {record.first_seen.isoformat()}, now APPEARED"
                    )

            elif registry_status == RegistryStatus.NOT_FOUND:
                if record.current_state == PhantomState.NOT_FOUND and record.occurrence_count >= 3:
                    # Package repeatedly hallucinated, move to active WATCH
                    record.previous_state = record.current_state
                    record.current_state = PhantomState.WATCH
                    record.transitions.append(
                        StateTransition(
                            from_state=PhantomState.NOT_FOUND,
                            to_state=PhantomState.WATCH,
                            timestamp=now,
                            reason=f"Observed missing {record.occurrence_count} times; elevated to WATCH",
                        )
                    )

            self.save()
            return record

        else:
            # First time observation
            initial_state = PhantomState.NOT_FOUND if registry_status == RegistryStatus.NOT_FOUND else PhantomState.NONE
            record = PhantomRecord(
                package_name=package_name.strip(),
                ecosystem=ecosystem,
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
                current_state=initial_state,
                previous_state=PhantomState.NONE,
                last_known_registry_status=registry_status,
                notes=[f"Initial observation with registry status: {registry_status.value}"],
            )
            # Only keep track in memory if it was NOT_FOUND or unusual
            if registry_status == RegistryStatus.NOT_FOUND:
                self._records[key] = record
                self.save()
            return record

    def get_record(self, package_name: str, ecosystem: Ecosystem) -> Optional[PhantomRecord]:
        return self._records.get(self._key(package_name, ecosystem))

    def list_phantoms(self) -> List[PhantomRecord]:
        return list(self._records.values())
