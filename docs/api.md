# SLOPGUARD REST API Specification (v0.2.0)

Base URL: `http://localhost:8000/api/v1`

---

## Endpoints

### 1. Health Check
- **GET** `/health`
- **Response**:
```json
{
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
    "Deterministic Policy Gate"
  ]
}
```

---

### 2. Dependency Scan
- **POST** `/scan`
- **Request Body**:
```json
{
  "content": "import cv2\nimport requests",
  "language": "python",
  "source_label": "main.py"
}
```
- **Response**: `ScanResult` schema with summary, extracted dependencies, resolved identities, registry evidence, trust reports, and deterministic policy decisions (`ALLOW`, `HOLD`, `BLOCK`, `ALERT`).

---

### 3. Registry Verification
- **GET** `/verify/{ecosystem}/{package_name}`
- **Parameters**: `ecosystem` (`pypi` or `npm`), `package_name`
- **Response**: `RegistryEvidence` schema with release count, latest version, author, repository URL, and latency.

---

### 4. Vulnerability Advisories
- **GET** `/advisories/{ecosystem}/{package_name}?version=x.y.z`
- **Response**:
```json
{
  "package": "requests",
  "ecosystem": "pypi",
  "advisory_count": 16,
  "advisories": [ ... ]
}
```

---

### 5. Multi-Dimensional Trust Assessment
- **GET** `/trust/{ecosystem}/{package_name}`
- **Response**: `TrustAssessment` with explicit dimensions (`identity`, `registry`, `repository`, `provenance`, `advisory`), release signals, and human-readable evidence reasons.

---

### 6. Evidence Graph Query
- **GET** `/graph/{ecosystem}/{package_name}`
- **Response**: Node and edge relationships (`HOSTED_AT`, `HAS_RELEASE`, `AFFECTED_BY`, `ATTESTED_BY`).

---

### 7. Temporal Phantom Watchlist
- **GET** `/phantoms`
- **Response**: Array of all tracked phantoms with state transitions and observation counts.
