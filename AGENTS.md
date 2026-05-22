# Aegis Agent Instructions

This file defines repository-specific rules for coding agents working on Aegis.

## 1) Product Context

Aegis is a scan-centric quantum cryptographic intelligence platform.

Core flow:
1. Discover internet-facing cryptographic surfaces.
2. Analyze TLS and certificate posture.
3. Compute deterministic quantum risk and compliance tier.
4. Generate persisted artifacts (CBOM, remediation bundle, compliance certificate).
5. Expose results via API and dashboard.

## 2) Source of Truth Documents

Use these documents in this order:
1. README.md
2. SETUP.md
3. docs/API.md
4. docs/DATABASE.md
5. docs/CONTEXT.md
6. docs/SOLUTION.md

Hard rule:
- Never modify docs/SOLUTION.md unless explicitly asked by the user.

## 3) Runtime and Environment Reality

Current default runtime is local deterministic mode, but EVERYTHING MUST BE RUN VIA DOCKER.

Important facts:
0. STRICT RULE: No local environments (no local `node_modules`, no local `.venv` or `venv`). All execution, building, and testing must be run exclusively via Docker to prevent supply chain attacks. Remove any rogue `node_modules` or `venv` folders encountered.
1. Root .env is intentionally tracked.
2. Cloud API keys are not required for standard local scan operation.
3. Deterministic scoring and compliance logic must remain non-LLM.
4. Backend container startup applies Alembic migration automatically.

## 4) Architectural Constraints

Do not violate these:
1. Risk scoring and compliance tiering are deterministic only.
2. RAG/advisory logic must not write risk scores or tiers.
3. Keep backend and frontend status/tier vocabulary aligned.
4. Prefer minimal targeted changes over broad refactors.

## 5) Codebase Boundaries

Primary code ownership map:
1. backend/analysis: deterministic scoring/parsing logic
2. backend/compliance: tier evaluation rules
3. backend/pipeline: orchestration and read-model assembly
4. backend/api/v1: endpoint and schema contracts
5. backend/models + backend/repositories: persistence model
6. frontend/src/lib/adapters.ts: backend-to-UI mapping
7. frontend/src/contexts: scan selection and queue lifecycle
8. frontend/src/pages: route-level UX surfaces

## 6) Implementation Workflow

For non-trivial work:
1. Read relevant docs and existing module.
2. Implement minimal working change first.
3. Validate with focused tests/build.
4. Only then expand robustness if needed.

## 7) Testing Expectations

Minimum validation before completion:
1. Backend logic changes: targeted pytest for changed module.
2. Frontend changes: production build in frontend.
3. Data/score changes: verify with at least one DB/API sanity query.

Preferred checks:
1. docker compose exec -T backend pytest -q <tests>
2. docker compose exec -T frontend npm run build
3. docker compose exec -T backend python simulation/run.py

## 8) Data and Migration Safety

Rules:
1. Avoid schema-changing migrations unless user asks.
2. If scoring logic changes, ensure historical backfill is addressed.
3. Do not silently alter deterministic formula semantics.
4. Keep score explanation payload aligned with formula behavior.

## 9) File Hygiene

1. Do not add temporary scripts/files to repository unless requested.
2. Remove accidental junk files (.DS_Store, .bak, .orig, .rej) when encountered.
3. Keep scripts directory production-meaningful.

## 10) Agent Skill Usage

Check .agents/skills before implementing complex work.

High-value skills in this repo:
1. docker-oqs
2. fastapi-templates
3. sqlalchemy-alembic-expert-best-practices-code-review
4. pytest-coverage
5. frontend-design

## 11) Completion Criteria

A task is complete only when:
1. Code changes compile/lint/test for touched areas.
2. Docs are updated if behavior/contract changed.
3. User-facing semantics are verified against runtime data where applicable.
