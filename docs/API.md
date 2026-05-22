# Aegis API Reference

Last updated: 2026-04-14

This document describes the live HTTP API exposed by the backend in local Docker mode.

## 1. Base Information

- Base URL: http://localhost:8000
- API prefix: /api/v1
- OpenAPI JSON: http://localhost:8000/api/v1/openapi.json
- Swagger UI: http://localhost:8000/docs
- Health: GET /health
- Content type: application/json

## 2. Auth and Security

Current API behavior:
- No backend JWT/session enforcement.
- Frontend login is currently a local UI gate.
- Treat as local trusted environment, not production-hardened security.

## 3. Core Semantics

### 3.1 Score model

- risk_score: 0-100 (higher is worse)
- q_score: 0-100 (higher is better)
- relation: q_score = 100 - risk_score

### 3.2 Compliance tiers

- FULLY_QUANTUM_SAFE
- PQC_TRANSITIONING
- QUANTUM_VULNERABLE

### 3.3 Scan status

- pending
- running
- completed
- failed

## 4. Endpoints

## 4.1 Health

### GET /health

Returns backend liveness.

Example response:

```json
{
  "status": "ok"
}
```

## 4.2 Scans

### POST /api/v1/scan

Create a scan job and dispatch background pipeline.

Request body:

```json
{
  "target": "example.com",
  "scan_profile": "Standard + Full Port Scan",
  "initiated_by": "frontend_scan_queue"
}
```

Request fields:
- target: required; domain/IP/CIDR accepted.
- scan_profile: optional; free-form string persisted to scan_jobs.scan_profile.
- initiated_by: optional; persisted to scan_jobs.initiated_by.

Response: 202 Accepted

```json
{
  "scan_id": "uuid",
  "target": "example.com",
  "status": "pending",
  "created_at": "2026-04-12T12:00:00Z"
}
```

Behavior notes:
- target is validated before scan creation.
- scan_profile string controls full-port and enumeration behavior in orchestrator.

### GET /api/v1/scan/{scan_id}

Returns live/persisted scan status.

Response includes:
- scan metadata (target, status, created/completed timestamps)
- progress counters
- summary posture counters
- stage and stage_detail
- runtime/persisted events
- degraded_modes list

### GET /api/v1/scan/{scan_id}/results

Returns compiled scan read model.

Top-level fields:
- scan metadata and status
- progress, summary
- stage/stage_detail/elapsed_seconds
- events, degraded_modes
- dns_records[]
- assets[]

AssetResultResponse fields (important):
- asset_id, hostname, ip_address, port, protocol, service_type
- open_ports, asset_metadata, is_shadow_it, discovery_source
- assessment
- certificate and leaf_certificate
- cbom
- remediation and remediation_actions
- compliance_certificate
- asset_fingerprint

## 4.3 Mission Control

### GET /api/v1/mission-control/graph

Query params:
- scan_id (optional UUID)
- limit (default 150, max 500)

Returns node/edge graph payload used in network topology visualizations.

### GET /api/v1/mission-control/overview

Query params:
- recent_limit (default 10, max 25)
- priority_limit (default 5, max 10)

Returns portfolio_summary, recent_scans, priority_findings, and system_health.

### GET /api/v1/mission-control/activity

Query params:
- limit (default 25, max 100)

Returns recent scan activity feed.

### GET /api/v1/scan/history

Query params:
- limit (default 200, max 5000)
- target (optional exact target filter)

Returns lightweight timeline entries with summary/progress and scan metadata.

## 4.4 Asset Artifact Endpoints

### GET /api/v1/assets/{asset_id}/cbom

Returns latest persisted CBOM document for one asset.

### GET /api/v1/assets/{asset_id}/certificate

Returns latest persisted compliance certificate for one asset.

### GET /api/v1/assets/{asset_id}/remediation

Returns latest persisted remediation bundle for one asset.

## 4.5 System Health

### GET /api/v1/system/health

Returns live backend system diagnostics assembled at request time (no hardcoded status payloads).

Top-level fields:
- timestamp
- overall_status
- services[]: backend_api, postgres, qdrant dependency checks
- system_checks[]: runtime/app-state, docs corpus, frontend bundle checks
- api_endpoints[]: discovered API routes with methods/path/status
- infra_endpoints[]: non-API routes (health/docs/spa routes) with methods/path/status
- route_totals: counts for api, infra, total
- runtime: live runtime configuration snapshot

Example response shape:

```json
{
  "timestamp": "2026-04-14T12:00:00Z",
  "overall_status": "healthy",
  "services": [
    {"name": "backend_api", "status": "healthy", "details": {}},
    {"name": "postgres", "status": "healthy", "details": {}},
    {"name": "qdrant", "status": "healthy", "details": {}}
  ],
  "system_checks": [
    {"name": "docs_corpus", "status": "healthy", "details": {}},
    {"name": "frontend_bundle", "status": "healthy", "details": {}},
    {"name": "app_runtime", "status": "healthy", "details": {}}
  ],
  "api_endpoints": [
    {"path": "/api/v1/scan", "methods": ["POST"], "status": "healthy"}
  ],
  "infra_endpoints": [
    {"path": "/health", "methods": ["GET"], "status": "healthy"}
  ],
  "route_totals": {"api": 10, "infra": 3, "total": 13},
  "runtime": {}
}
```

## 5. Key Response Shapes

## 5.1 AssessmentResponse

Important fields:
- tls_version, cipher_suite
- kex_algorithm, auth_algorithm, enc_algorithm, mac_algorithm
- kex_vulnerability, sig_vulnerability, sym_vulnerability, tls_vulnerability
- risk_score
- score_explanation (deterministic derivation payload including `formula`, `inputs`, `weighted_components`, `penalties`, `base_risk_score`, `final_risk_score`, `q_score`, `derivation`, and explicit text explanations)
- compliance_tier

## 5.2 AssetCertificateResponse

Important fields:
- subject_cn, issuer, certificate_authority
- signature_algorithm, key_type, key_size
- valid_from, valid_until, days_remaining
- sha256_fingerprint

## 5.3 AssetFingerprintResponse

Cross-scan continuity payload:
- canonical_key
- appearance_count
- latest_q_score
- latest_compliance_tier
- first_seen/last_seen timestamps
- q_score_history[]

## 6. Error Handling

Validation and request errors are returned with standard FastAPI error responses.

Common scenarios:
- invalid target in POST /scan => 400
- unknown scan_id or asset_id => 404
- unhandled server issues => 500

## 7. Scanner Profile Notes

Profile parsing is string-based and currently supports operational toggles embedded in scan_profile text:
- full port/all ports tokens => enable full TCP sweep mode.
- no enumeration token => disable broad subdomain enumeration.

Scanner UI submits one target per run.

## 8. Local Mode Notes

Default local mode characteristics:
- EMBEDDING_PROVIDER_MODE=local
- LLM_PROVIDER_MODE=local
- cloud keys are not required for normal scanning and deterministic scoring

Deterministic risk/compliance decisions are never delegated to LLM providers.

## 9. Practical API Verification Commands

```bash
curl -s http://localhost:8000/health | jq
curl -s http://localhost:8000/api/v1/scan/history?limit=5 | jq
```

Create a scan:

```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H 'content-type: application/json' \
  -d '{"target":"example.com","scan_profile":"Standard","initiated_by":"manual"}' | jq
```

Fetch results:

```bash
curl -s http://localhost:8000/api/v1/scan/<scan_id>/results | jq
```

## 10. Contract Ownership

Backend contract definitions are in:
- backend/api/v1/schemas.py
- backend/api/v1/endpoints/scans.py
- backend/api/v1/endpoints/mission_control.py
- backend/api/v1/endpoints/assets.py

When runtime behavior changes, update this document and schemas together.
