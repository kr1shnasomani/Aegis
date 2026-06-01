# Aegis Database Reference

Last updated: 2026-04-12

This document describes persisted storage used by Aegis in local Docker mode.

## 1. Storage Systems

Aegis uses two storage backends:

1. PostgreSQL
- transactional scan records
- deterministic analysis data
- generated artifacts and history read models
- **Apache AGE Graph Extension** for tracking complex network relationships (nodes and edges) inside `aegis_network_graph`

2. Qdrant
- vector corpus used for retrieval-backed remediation context
- default collection: aegis_nist_docs

## 2. Runtime Database Configuration

Primary local values:
- DATABASE_URL=postgresql+asyncpg://aegis:aegis@postgres:5432/aegis
- QDRANT_URL=http://qdrant:6333
- QDRANT_COLLECTION_NAME=aegis_nist_docs

## 3. Schema Source of Truth

Authoritative schema sources:
1. SQLAlchemy models under backend/models
2. Alembic migration history under migrations/versions

If there is a mismatch, treat the runtime models as the current contract and update migrations/docs accordingly.

## 4. Core Entity Graph

Scan-centric relationship model:

scan_jobs
- discovered_assets
  - crypto_assessments
  - certificate_chains
  - cbom_documents
  - remediation_bundles
  - remediation_actions
  - compliance_certificates
- dns_records
- scan_events

Cross-scan continuity:
- asset_fingerprints (linked to first/last scan IDs)

## 5. Table Inventory

## 5.1 scan_jobs

Purpose:
- root record for each submitted scan

Important columns:
- id (UUID PK)
- target
- status
- created_at
- completed_at
- scan_profile
- initiated_by

## 5.2 discovered_assets

Purpose:
- one row per discovered host/ip/port surface within a scan

Important columns:
- id (UUID PK)
- scan_id (FK -> scan_jobs.id)
- hostname, ip_address, port, protocol
- service_type
- server_software
- open_ports (JSONB)
- asset_metadata (JSONB)
- is_shadow_it
- discovery_source

## 5.3 crypto_assessments

Purpose:
- deterministic cryptographic decomposition and scoring

Important columns:
- asset_id (FK -> discovered_assets.id)
- tls_version, cipher_suite
- kex_algorithm, auth_algorithm, enc_algorithm, mac_algorithm
- kex_vulnerability, sig_vulnerability, sym_vulnerability, tls_vulnerability
- risk_score
- score_explanation (JSONB)
- compliance_tier

## 5.4 certificate_chains

Purpose:
- persisted certificate chain rows per asset

Important columns:
- asset_id (FK)
- cert_level (LEAF/INTERMEDIATE/ROOT enum)
- subject, issuer
- public_key_algorithm, key_size_bits
- signature_algorithm
- quantum_safe
- not_before, not_after

## 5.5 cbom_documents

Purpose:
- persisted CycloneDX CBOM payloads per asset and scan

Important columns:
- asset_id, scan_id
- serial_number
- cbom_json
- created_at

## 5.6 remediation_bundles

Purpose:
- per-asset remediation package output

Important columns:
- asset_id
- hndl_timeline (JSONB)
- patch_config
- migration_roadmap
- source_citations (JSONB)
- created_at

## 5.7 remediation_actions

Purpose:
- structured remediation action rows for prioritization and UI tables

Important columns:
- asset_id
- priority (P1-P4)
- finding
- action
- effort
- status
- category
- nist_reference

## 5.8 compliance_certificates

Purpose:
- persisted compliance certificate metadata and optional PEM

Important columns:
- asset_id
- tier
- signing_algorithm
- valid_from, valid_until
- extensions_json
- remediation_bundle_id
- certificate_pem

## 5.9 dns_records

Purpose:
- DNS validation outcomes tied to scan scope

Important columns:
- scan_id
- hostname
- resolved_ips (JSONB array)
- cnames (JSONB array)
- discovery_source
- is_in_scope
- discovered_at

## 5.10 scan_events

Purpose:
- persisted event timeline for scan execution and diagnostics

Important columns:
- scan_id
- timestamp
- kind
- message
- stage

## 5.11 asset_fingerprints

Purpose:
- stable cross-scan identity and q-score history

Important columns:
- canonical_key (unique)
- first_seen_scan_id
- last_seen_scan_id
- first_seen_at, last_seen_at
- appearance_count
- q_score_history (JSONB array)
- latest_q_score
- latest_compliance_tier

## 6. Enum Domains

Current enums include:
- scan_status: pending, running, completed, failed
- service_type: tls, vpn, api
- compliance_tier: FULLY_QUANTUM_SAFE, PQC_TRANSITIONING, QUANTUM_VULNERABLE
- cert_level: LEAF, INTERMEDIATE, ROOT
- remediation_priority: P1, P2, P3, P4
- remediation_status: not_started, in_progress, done, verified
- remediation_effort: low, medium, high

## 7. Scoring Persistence Notes

risk_score persistence model:
- Stored as numeric score (0-100) on crypto_assessments.risk_score.
- Derived by deterministic formula from vulnerability components.
- Includes certificate penalty from LEAF cert expiry window.

q_score usage model:
- Not a primary persisted score on assessments.
- Derived as q_score = 100 - risk_score.
- Persisted historically in asset_fingerprints.q_score_history and latest_q_score.

## 8. Qdrant Collection Notes

Expected collection:
- aegis_nist_docs

Corpus source:
- corpus/nist

Ingestion command:

```bash
docker compose exec backend python scripts/ingest_nist_docs.py
```

## 9. Useful Database Checks

List tables:

```bash
docker compose exec -T postgres psql -U aegis -d aegis -c "\dt"
```

Inspect assessment count:

```bash
docker compose exec -T postgres psql -U aegis -d aegis -c "select count(*) from crypto_assessments;"
```

Inspect scan status counts:

```bash
docker compose exec -T postgres psql -U aegis -d aegis -c "select status, count(*) from scan_jobs group by status;"
```

## 10. Maintenance Guidance

- Keep table names and key column notes in sync with backend/models.
- Update this file whenever new read-model tables or JSON fields are introduced.
- If you add migration scripts that alter scoring schema behavior, also update CONTEXT.md and API.md.
