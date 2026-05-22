# Aegis Operational Context

Last updated: 2026-04-12

This document is the detailed operational context for how Aegis works today.

Use this file as the primary reference for:
- architecture and behavior reality (not aspirational design)
- deterministic scoring and compliance boundaries
- API and data-flow expectations
- scanner UX and execution semantics
- local runtime and setup assumptions
- maintenance rules for future contributors

## 1. Product Boundaries

## 1.1 What Aegis is

Aegis is a scan-centric cryptographic intelligence platform focused on quantum-readiness posture for banking infrastructure.

Core loop:
1. Submit a target.
2. Discover reachable assets and cryptographic surfaces.
3. Perform deterministic cryptographic analysis.
4. Generate artifacts (CBOM, remediation bundle, compliance outputs).
5. Expose posture through dashboard and APIs.

## 1.2 Non-negotiable principles

1. Deterministic engine for risk and compliance.
2. LLM output is advisory and never the scoring authority.
3. API and frontend status/tier vocabulary must remain aligned.
4. Scan history and per-asset history must be reproducible from persisted data.

## 2. Runtime Topology

Local Docker services:
1. backend (FastAPI)
2. frontend (React/Vite)
3. postgres
4. qdrant
5. pgadmin (optional operational UI)

Ports:
- frontend: 3000
- backend: 8000
- postgres: 5432
- qdrant: 6333
- pgadmin: 5050

## 3. Local Mode and Environment Policy

Current default mode is local deterministic mode.

Practical implications:
1. Cloud API keys are not required to run scans and deterministic scoring.
2. Root .env is tracked intentionally for reproducible local setup.
3. .env.example remains the template and optional cloud-extension reference.
4. Embedding/LLM provider mode defaults are local.

Required base env groups for local operation:
- database URL
- qdrant URL/collection/source directory
- app metadata and skip enumeration flag
- certificate issuer defaults

## 4. End-to-End Pipeline (Execution Reality)

## 4.1 Scan submission path

1. Frontend scanner creates scan via POST /api/v1/scan.
2. Backend validates target and persists scan_jobs row.
3. Background orchestrator task starts and updates runtime/persisted events.
4. Frontend polls GET /api/v1/scan/{scan_id}.
5. On completion, frontend consumes GET /api/v1/scan/{scan_id}/results.

## 4.2 Discovery and analysis phases

Typical orchestrator phases:
1. scope normalization
2. enumeration and DNS validation
3. port scanning and service inference
4. TLS probing and certificate extraction
5. cipher decomposition + vulnerability mapping
6. deterministic risk and tier evaluation
7. artifact generation and persistence

## 4.3 Degraded/fallback behavior

Orchestrator may enter degraded modes based on runtime constraints.
Examples:
- enumeration fallback path when broad tooling is unavailable
- direct TLS fallback when bounded port scanning yields no findings

These are surfaced in scan status payload via degraded_modes/events.

## 5. Deterministic Scoring Model

## 5.1 Formula

Base risk fraction:

R_base = 0.45*V_kex + 0.35*V_sig + 0.10*V_sym + 0.10*V_tls

Risk score (0-100):

risk_score = min(100, 100*R_base + certificate_penalty_points)

Penalty points:
- +10 when leaf certificate days_remaining <= 0
- +5 when leaf certificate days_remaining <= 30
- +0 otherwise

q_score relation:
- q_score = 100 - risk_score

## 5.2 Why this matters operationally

1. Unknown/weak KEX and SIG dominate risk by design (45/35 weights).
2. Symmetric and TLS-version effects are lower but still explicit.
3. Certificate freshness is an additive operational penalty layer.
4. Final score is capped to avoid overflow and keep normalized semantics.

## 5.3 Score explanation payload

score_explanation contains deterministic derivation details including:
- formula text
- inputs (weights, vulnerabilities, algorithm strings)
- weighted component breakdown
- penalties and reason (e.g., "expired_certificate")
- base_risk_score and final_risk_score
- q_score and mathematical derivation text
- explicit component sentence explanations (kex, sig, sym, tls)

## 6. Compliance and Status Vocabulary

Backend compliance tiers:
1. FULLY_QUANTUM_SAFE
2. PQC_TRANSITIONING
3. QUANTUM_VULNERABLE

Frontend status classes (normalized):
1. elite-pqc
2. transitioning
3. vulnerable
4. critical
5. standard/unknown compatibility paths for sparse legacy rows

Important: status mapping consistency is critical for KPI correctness.

## 7. Data Model Overview

## 7.1 Persistence principles

1. scan_jobs is the root execution entity.
2. discovered_assets holds scan-scoped host/surface records.
3. crypto_assessments is the deterministic scoring record.
4. certificate_chains stores chain-level certificate metadata.
5. asset_fingerprints captures cross-scan continuity and q-score history.

## 7.2 Read-model composition

Compiled scan results include:
- scan metadata/progress/summary/events/degraded modes
- dns_records
- per-asset payloads with assessment/certificate/cbom/remediation/actions/fingerprint

Dashboard and asset pages rely on this compiled read model.

## 8. Frontend Architecture Context

## 8.1 Key contexts

1. SelectedScanContext: selected scan ownership and result hydration.
2. ScanQueueContext: queue lifecycle and completion transitions.

## 8.2 Adapter contract

frontend/src/lib/adapters.ts maps backend result payloads to UI Asset objects.

Important adapter concerns:
- preserve risk_score/q_score semantics
- avoid misleading defaults for missing assessments
- map compliance tiers and statuses consistently
- keep certificate missing-data behavior explicit

## 8.3 Scanner UX behavior

Scanner is single-target per run.
Profile text encodes options such as full port scan and enumeration behavior.

## 9. API Surface Summary

Active endpoint families:
1. /api/v1/scan (create, status, results)
2. /api/v1/scan/history
3. /api/v1/mission-control/*
4. /api/v1/assets/{asset_id}/*

Detailed contracts are maintained in API.md and schemas.py.

## 10. Operational Workflows

## 10.1 Standard local bootstrap

1. docker compose up -d --build
2. docker compose exec backend alembic upgrade head
3. docker compose exec backend python scripts/ingest_nist_docs.py

## 10.2 Verification workflow

1. Run simulation scan from backend container.
2. Poll scan status endpoint.
3. Inspect results endpoint for risk, tiers, and artifacts.
4. Validate dashboard selection and asset details against API payload.

## 10.3 Historical score backfill workflow

When scoring logic changes:
1. recompute risk_score for existing crypto_assessments using deterministic formula
2. refresh asset_fingerprints.q_score_history and latest_q_score from recomputed values
3. validate representative hosts in database and API read model

## 11. Known Risks and Practical Constraints

1. Backend auth is still local/demo-grade.
2. Incomplete runtime metadata from external hosts can produce sparse assessment/certificate fields.
3. Historical records may predate newer scoring explanation structure and need backfill.
4. Frontend presentation can be misleading if missing-data defaults are not explicit.

## 12. Change Management Rules

When modifying scoring or scan contracts:
1. update backend scoring logic
2. add/adjust unit tests
3. run historical backfill for existing DB rows
4. verify API payload shape
5. update frontend adapter/view mapping
6. update README, SETUP, API, DATABASE, and CONTEXT docs together

## 13. Documentation Governance

This file should be updated whenever one of these changes:
1. scoring formula or penalty policy
2. status/tier mapping contract
3. scanner profile semantics
4. endpoint contracts used by frontend pages
5. persistence model for history/read models

Authoring rules:
1. document what is implemented today
2. separate facts from future ideas
3. include operational consequences, not just code locations
4. keep deterministic-vs-advisory boundaries explicit

## 14. Ownership Pointers

Primary ownership files:
- backend/analysis/risk_scorer.py
- backend/pipeline/orchestrator.py
- backend/api/v1/schemas.py
- backend/api/v1/endpoints/scans.py
- backend/api/v1/endpoints/mission_control.py
- frontend/src/contexts/SelectedScanContext.tsx
- frontend/src/contexts/ScanQueueContext.tsx
- frontend/src/lib/adapters.ts
- frontend/src/pages/AssetDetail.tsx

## 15. Current Reality Snapshot

As of this update:
1. Local deterministic mode is the default setup path.
2. No mandatory cloud keys for local setup.
3. Score policy includes certificate expiry penalty layer.
4. Historical score refresh process is part of operational maintenance when scoring changes.
5. Documentation has been aligned to setup-first local execution.
