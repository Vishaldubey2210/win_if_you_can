from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from slopguard.core.models import (
    Ecosystem,
    ExtractedDependency,
    RegistryEvidence,
    ScanResult,
    TrustAssessment,
)
from slopguard.core.scanner import ScannerService
from slopguard.evidence.models import EvidenceSnapshot, SecurityAdvisory
from slopguard.evidence.graph import GraphNode

app = FastAPI(
    title="SLOPGUARD API",
    version="0.2.0",
    description="AI Dependency Control Plane and Supply-Chain Firewall REST API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner_service = ScannerService()


def parse_ecosystem(eco_str: str) -> Ecosystem:
    clean = eco_str.lower()
    if clean in ("pypi", "python"):
        return Ecosystem.PYPI
    elif clean in ("npm", "node", "javascript", "js"):
        return Ecosystem.NPM
    raise HTTPException(status_code=400, detail=f"Unsupported ecosystem: {eco_str}")


class ScanRequest(BaseModel):
    content: str = Field(description="Source code or manifest file text")
    language: str = Field(
        default="python",
        description="Language or manifest format: python, javascript, typescript, requirements, pyproject, package_json",
    )
    source_label: Optional[str] = Field(default="<api_payload>")


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "slopguard",
        "version": "0.2.0",
        "features": [
            "AST Extraction",
            "Identity Resolution",
            "Failure-Isolated Registry Verification",
            "Live OSV Advisory Verification",
            "Evidence Graph",
            "Provenance & Attestation",
            "Unicode Homoglyph Detection",
            "Temporal Phantom Memory",
            "Deterministic Policy Gate",
        ],
    }


@app.post("/api/v1/scan", response_model=ScanResult)
async def scan_endpoint(req: ScanRequest):
    try:
        result = await scanner_service.scan_code(
            content=req.content,
            language=req.language,
            file_path=req.source_label or "<api_payload>",
        )
        return result
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal scan failure: {exc}")


@app.get("/api/v1/verify/{ecosystem}/{package_name}", response_model=RegistryEvidence)
async def verify_endpoint(ecosystem: str, package_name: str):
    eco = parse_ecosystem(ecosystem)
    adapter = scanner_service.pypi_adapter if eco == Ecosystem.PYPI else scanner_service.npm_adapter
    return await adapter.verify_package(package_name)


@app.get("/api/v1/advisories/{ecosystem}/{package_name}")
async def advisories_endpoint(ecosystem: str, package_name: str, version: Optional[str] = None):
    eco = parse_ecosystem(ecosystem)
    advs, record = await scanner_service.osv_adapter.query_advisories(
        package_name=package_name, ecosystem=eco, version=version
    )
    return {
        "package": package_name,
        "ecosystem": eco.value,
        "advisory_count": len(advs),
        "advisories": [a.model_dump(mode="json") for a in advs],
        "evidence_record": record.model_dump(mode="json"),
    }


@app.get("/api/v1/trust/{ecosystem}/{package_name}", response_model=TrustAssessment)
async def trust_endpoint(ecosystem: str, package_name: str):
    eco = parse_ecosystem(ecosystem)
    adapter = scanner_service.pypi_adapter if eco == Ecosystem.PYPI else scanner_service.npm_adapter

    dep = ExtractedDependency(name=package_name, ecosystem=eco)
    identity = scanner_service.identity_resolver.resolve(dep)

    registry = await adapter.verify_package(identity.resolved_package)
    advisories, _ = await scanner_service.osv_adapter.query_advisories(
        package_name=identity.resolved_package,
        ecosystem=eco,
        version=registry.latest_version,
    )
    provenance = scanner_service.provenance_extractor.extract(registry)

    return scanner_service.trust_evaluator.evaluate(
        identity=identity,
        registry=registry,
        advisories=advisories,
        provenance=provenance,
    )


@app.get("/api/v1/graph/{ecosystem}/{package_name}")
async def graph_endpoint(ecosystem: str, package_name: str):
    eco = parse_ecosystem(ecosystem)
    releases = scanner_service.evidence_graph.get_package_releases(package_name, eco)
    repository = scanner_service.evidence_graph.get_package_repository(package_name, eco)
    advisories = scanner_service.evidence_graph.get_package_advisories(package_name, eco)
    provenance = scanner_service.evidence_graph.get_package_provenance(package_name, eco)
    history = scanner_service.evidence_graph.get_package_history(package_name, eco)

    return {
        "package": package_name,
        "ecosystem": eco.value,
        "releases": [r.model_dump(mode="json") for r in releases],
        "repository": repository.model_dump(mode="json") if repository else None,
        "advisories": [a.model_dump(mode="json") for a in advisories],
        "provenance": provenance.model_dump(mode="json") if provenance else None,
        "history": [h.model_dump(mode="json") for h in history],
    }


@app.get("/api/v1/evidence/{ecosystem}/{package_name}")
async def evidence_endpoint(ecosystem: str, package_name: str):
    eco = parse_ecosystem(ecosystem)
    key = f"{eco.value}:{package_name.lower().strip()}"
    snap = scanner_service.snapshots.get(key)
    if not snap:
        # Generate on-demand if not in memory
        adapter = scanner_service.pypi_adapter if eco == Ecosystem.PYPI else scanner_service.npm_adapter
        registry = await adapter.verify_package(package_name)
        advs, _ = await scanner_service.osv_adapter.query_advisories(
            package_name=package_name, ecosystem=eco, version=registry.latest_version
        )
        prov = scanner_service.provenance_extractor.extract(registry)
        snap = EvidenceSnapshot(
            package=package_name,
            ecosystem=eco,
            version=registry.latest_version,
            advisories=advs,
            provenance=prov,
        )
    return snap.model_dump(mode="json")


@app.get("/api/v1/phantoms")
async def list_phantoms():
    records = scanner_service.memory.list_phantoms()
    return [r.model_dump(mode="json") for r in records]


@app.get("/api/v1/history/{ecosystem}/{package_name}")
async def history_endpoint(ecosystem: str, package_name: str):
    eco = parse_ecosystem(ecosystem)
    record = scanner_service.memory.get_record(package_name, eco)
    if not record:
        return {"package": package_name, "ecosystem": eco.value, "status": "NO_HISTORICAL_OBSERVATIONS"}
    return record.model_dump(mode="json")
