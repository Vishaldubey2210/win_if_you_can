from __future__ import annotations
import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from slopguard.core.models import (
    Ecosystem,
    EvaluatedDependency,
    ExtractedDependency,
    PhantomState,
    PolicyAction,
    RegistryStatus,
    ScanResult,
    ScanSummary,
)
from slopguard.extraction.python_ast import PythonASTExtractor
from slopguard.extraction.javascript import JavaScriptExtractor
from slopguard.extraction.manifest import ManifestExtractor
from slopguard.identity.resolver import IdentityResolver
from slopguard.registry.pypi import PyPIAdapter
from slopguard.registry.npm import NPMAdapter
from slopguard.evidence.osv import OSVAdapter
from slopguard.evidence.provenance import ProvenanceExtractor
from slopguard.evidence.graph import EvidenceGraph
from slopguard.evidence.models import (
    EvidenceRecord,
    EvidenceSnapshot,
    EvidenceStatus,
    EvidenceType,
    ProvenanceSignal,
    SecurityAdvisory,
)
from slopguard.trust.evaluator import TrustEvaluator
from slopguard.memory.phantom import PhantomMemory
from slopguard.policy.engine import DeterministicPolicyEngine


class ScannerService:
    """
    Core SLOPGUARD Firewall Service.
    Coordinates the canonical pipeline:
    EXTRACT -> IDENTITY -> VERIFY -> EVIDENCE -> TRUST -> MEMORY -> GATE
    """

    def __init__(
        self,
        phantom_storage_path: Optional[str] = None,
        pypi_adapter: Optional[PyPIAdapter] = None,
        npm_adapter: Optional[NPMAdapter] = None,
        osv_adapter: Optional[OSVAdapter] = None,
    ) -> None:
        self.py_extractor = PythonASTExtractor()
        self.js_extractor = JavaScriptExtractor()
        self.identity_resolver = IdentityResolver()
        self.pypi_adapter = pypi_adapter or PyPIAdapter()
        self.npm_adapter = npm_adapter or NPMAdapter()
        self.osv_adapter = osv_adapter or OSVAdapter()
        self.provenance_extractor = ProvenanceExtractor()
        self.trust_evaluator = TrustEvaluator()
        self.policy_engine = DeterministicPolicyEngine()
        self.evidence_graph = EvidenceGraph()
        self.snapshots: Dict[str, EvidenceSnapshot] = {}

        default_storage = phantom_storage_path or os.path.expanduser("~/.slopguard/phantoms.json")
        self.memory = PhantomMemory(storage_path=default_storage)

    def extract_from_source(
        self, content: str, language: str = "python", file_path: str = "<input>"
    ) -> List[ExtractedDependency]:
        lang = language.lower()
        if lang in ("python", "py"):
            return self.py_extractor.extract(content, file_path=file_path)
        elif lang in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
            return self.js_extractor.extract(content, file_path=file_path)
        elif lang in ("requirements", "requirements.txt"):
            return ManifestExtractor.parse_requirements_txt(content, file_path=file_path)
        elif lang in ("pyproject", "pyproject.toml"):
            return ManifestExtractor.parse_pyproject_toml(content, file_path=file_path)
        elif lang in ("package_json", "package.json"):
            return ManifestExtractor.parse_package_json(content, file_path=file_path)
        else:
            raise ValueError(f"Unsupported language or manifest format: '{language}'")

    async def scan_dependencies(
        self, extracted: List[ExtractedDependency], source_label: str = "<input>"
    ) -> ScanResult:
        scan_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        evaluated_list: List[EvaluatedDependency] = []
        allowed_count = 0
        hold_count = 0
        blocked_count = 0
        alert_count = 0
        stdlib_count = 0

        # Phase 1: Identity Resolution
        resolved_items = []
        for dep in extracted:
            if dep.is_relative:
                continue
            identity = self.identity_resolver.resolve(dep)
            resolved_items.append((dep, identity))

        # Phase 2: Registry & OSV Verification (Async parallel)
        async def verify_one(dep: ExtractedDependency, identity):
            if identity.is_stdlib:
                return dep, identity, None, [], None

            # 1. Query Registry
            reg_evidence = None
            if identity.ecosystem == Ecosystem.PYPI:
                reg_evidence = await self.pypi_adapter.verify_package(identity.resolved_package)
            elif identity.ecosystem == Ecosystem.NPM:
                reg_evidence = await self.npm_adapter.verify_package(identity.resolved_package)

            # 2. Query OSV Advisories (if package found or suspected)
            advisories: List[SecurityAdvisory] = []
            if reg_evidence and reg_evidence.status == RegistryStatus.FOUND:
                advisories, _ = await self.osv_adapter.query_advisories(
                    package_name=identity.resolved_package,
                    ecosystem=identity.ecosystem,
                    version=dep.version_constraint or reg_evidence.latest_version,
                )

            # 3. Extract Provenance
            provenance = self.provenance_extractor.extract(reg_evidence)

            return dep, identity, reg_evidence, advisories, provenance

        tasks = [verify_one(dep, ident) for dep, ident in resolved_items]
        verified_results = await asyncio.gather(*tasks)

        # Phase 3, 4, 5: Trust, Memory, Evidence Graph, Snapshots, and Policy Gate
        for dep, identity, registry, advisories, provenance in verified_results:
            trust = self.trust_evaluator.evaluate(
                identity=identity,
                registry=registry,
                advisories=advisories,
                provenance=provenance,
            )

            # Update temporal phantom memory if external package
            phantom_record = None
            if not identity.is_stdlib and registry:
                phantom_record = self.memory.record_observation(
                    package_name=identity.resolved_package,
                    ecosystem=identity.ecosystem,
                    registry_status=registry.status,
                )

            decision = self.policy_engine.evaluate(
                identity=identity,
                trust=trust,
                registry=registry,
                phantom_record=phantom_record,
            )

            p_state = phantom_record.current_state if phantom_record else PhantomState.NONE

            # Track counts
            if identity.is_stdlib:
                stdlib_count += 1
            if decision.action == PolicyAction.ALLOW:
                allowed_count += 1
            elif decision.action == PolicyAction.HOLD:
                hold_count += 1
            elif decision.action == PolicyAction.BLOCK:
                blocked_count += 1
            elif decision.action == PolicyAction.ALERT:
                alert_count += 1

            evaluated_dep = EvaluatedDependency(
                extracted=dep,
                identity=identity,
                registry=registry,
                trust=trust,
                phantom_state=p_state,
                decision=decision,
                timestamp=datetime.now(timezone.utc),
            )
            evaluated_list.append(evaluated_dep)

            # Ingest into Evidence Graph
            self.evidence_graph.ingest_evaluated_dependency(
                dep=evaluated_dep,
                advisories=advisories,
                provenance=provenance,
            )

            # Create immutable Evidence Snapshot for TOCTOU auditability
            snap_key = f"{identity.ecosystem.value}:{identity.resolved_package}"
            snap_records = []
            if registry:
                snap_records.append(
                    EvidenceRecord(
                        package=identity.resolved_package,
                        ecosystem=identity.ecosystem,
                        version=registry.latest_version,
                        evidence_type=EvidenceType.REGISTRY_IDENTITY,
                        source=f"{identity.ecosystem.value}.registry",
                        status=EvidenceStatus.VERIFIED if registry.status == RegistryStatus.FOUND else EvidenceStatus.FAILED,
                        payload={"releases": registry.release_count, "author": registry.author},
                    )
                )
            snap = EvidenceSnapshot(
                package=identity.resolved_package,
                ecosystem=identity.ecosystem,
                version=registry.latest_version if registry else None,
                records=snap_records,
                advisories=advisories,
                provenance=provenance,
                snapshot_hash=hashlib.sha256(f"{snap_key}:{decision.action.value}:{time.time()}".encode()).hexdigest(),
            )
            self.snapshots[snap_key] = snap

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        main_eco = evaluated_list[0].identity.ecosystem if evaluated_list else Ecosystem.PYPI

        summary = ScanSummary(
            total_extracted=len(evaluated_list),
            stdlib_count=stdlib_count,
            allowed_count=allowed_count,
            hold_count=hold_count,
            blocked_count=blocked_count,
            alert_count=alert_count,
            duration_ms=round(duration_ms, 2),
        )

        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            source_label=source_label,
            ecosystem=main_eco,
            dependencies=evaluated_list,
            summary=summary,
        )

    async def scan_code(
        self, content: str, language: str = "python", file_path: str = "<input>"
    ) -> ScanResult:
        extracted = self.extract_from_source(content, language=language, file_path=file_path)
        return await self.scan_dependencies(extracted, source_label=file_path)

    async def scan_file(self, file_path: str) -> ScanResult:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = p.read_text(encoding="utf-8")
        ext = p.suffix.lower()
        fname = p.name.lower()

        if fname == "requirements.txt" or ext == ".txt":
            lang = "requirements"
        elif fname == "pyproject.toml" or ext == ".toml":
            lang = "pyproject"
        elif fname == "package.json":
            lang = "package_json"
        elif ext in (".py", ".pyw"):
            lang = "python"
        elif ext in (".js", ".jsx", ".mjs", ".cjs"):
            lang = "javascript"
        elif ext in (".ts", ".tsx"):
            lang = "typescript"
        else:
            lang = "python"

        return await self.scan_code(content, language=lang, file_path=str(p.resolve()))
