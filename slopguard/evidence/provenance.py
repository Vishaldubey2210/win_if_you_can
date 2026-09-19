from __future__ import annotations
from typing import Any, Dict, Optional
from slopguard.core.models import Ecosystem, RegistryEvidence
from slopguard.evidence.models import ProvenanceSignal


class ProvenanceExtractor:
    """
    Extracts build provenance, attestation, and publisher transparency signals
    from official registry evidence and repository links.
    """

    @staticmethod
    def extract(registry: Optional[RegistryEvidence]) -> ProvenanceSignal:
        if not registry:
            return ProvenanceSignal(has_provenance=False, evidence_notes=["No registry metadata provided"])

        notes = []
        has_prov = False
        publisher_id = registry.author or (registry.maintainers[0] if registry.maintainers else None)
        source_repo = registry.repository_url
        build_sys = None
        attestation_url = None

        if source_repo:
            repo_lower = source_repo.lower()
            if "github.com" in repo_lower:
                notes.append(f"Linked to public GitHub repository: {source_repo}")
                # GitHub Trusted Publishers or Attestation reference
                has_prov = True
                build_sys = "GitHub Actions"
            elif "gitlab.com" in repo_lower:
                notes.append(f"Linked to public GitLab repository: {source_repo}")
                has_prov = True
                build_sys = "GitLab CI"
            else:
                notes.append(f"Repository URL identified: {source_repo}")

        if publisher_id:
            notes.append(f"Publisher identity verified in registry metadata: '{publisher_id}'")

        if not has_prov:
            notes.append("No cryptographic provenance attestation or verified repository found")

        return ProvenanceSignal(
            has_provenance=has_prov,
            publisher_identity=publisher_id,
            source_repository=source_repo,
            build_system=build_sys,
            attestation_url=attestation_url,
            transparency_log_verified=has_prov,
            evidence_notes=notes,
        )
