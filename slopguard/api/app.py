from __future__ import annotations
import os
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from slopguard.core.models import Ecosystem, RegistryEvidence, ScanResult
from slopguard.core.scanner import ScannerService

app = FastAPI(
    title="SLOPGUARD API",
    version="0.1.0",
    description="AI Dependency Control Plane and Supply-Chain Firewall REST API",
)

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner_service = ScannerService()


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
        "version": "0.1.0",
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
    eco = ecosystem.lower()
    if eco in ("pypi", "python"):
        evidence = await scanner_service.pypi_adapter.verify_package(package_name)
    elif eco in ("npm", "node", "javascript"):
        evidence = await scanner_service.npm_adapter.verify_package(package_name)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported ecosystem: {ecosystem}")
    return evidence


@app.get("/api/v1/phantoms")
async def list_phantoms():
    records = scanner_service.memory.list_phantoms()
    return [r.model_dump(mode="json") for r in records]
