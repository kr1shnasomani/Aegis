# Aegis Setup Guide

This guide provides the exact steps to host and run the Aegis platform locally using Docker. 

## Prerequisites

- **Git**
- **Docker Desktop** (Required for all platforms: Windows, macOS, Linux)

*Note:* No local Node.js or Python installations are required. No cloud API keys are required for the default local deterministic mode. The intelligence corpus (Qdrant) and environment variables (`.env`) are already preconfigured and preloaded for you.

---

## 1. Clone the Repository

```bash
git clone https://github.com/notgautham/Aegis.git
cd Aegis
```

*(Optional)* If you need to reset the environment variables, you can copy the template:
```bash
cp .env.example .env
```

## 2. Deploy the Stack

Build and start all services in detached mode:

```bash
docker compose up -d --build
```

Docker will automatically:
- Build the OQS-enabled Python backend.
- Build the React/Vite frontend.
- Spin up PostgreSQL (with Apache AGE) and Qdrant.
- Apply all database migrations automatically on startup.

## 3. Access the Platform

Once the containers are running, you can access the services here:

- **Web Dashboard:** [http://localhost:3000](http://localhost:3000)
- **Backend API:** [http://localhost:8000](http://localhost:8000)
- **Interactive API Docs (Swagger):** [http://localhost:8000/docs](http://localhost:8000/docs)
- **PgAdmin (DB Management):** [http://localhost:5050](http://localhost:5050)

**Demo Login Credentials:**
- **Email:** `demo@aegis.bank`
- **Password:** `aegis2026`

---

## 4. Generate the Codebase Knowledge Graph (Graphify)

Aegis uses [Graphify](https://github.com/safishamsi/graphify) to maintain an interactive 3D architecture map and codebase knowledge graph. 

To generate the `graphify-out` folder locally:

1. Install the `graphifyy` package:
   ```bash
   pipx install graphifyy
   # or with uv: uv tool install graphifyy
   ```
2. Build the graph for the codebase:
   ```bash
   graphify update .
   ```
This will extract all codebase architecture paths and generate `graphify-out/graph.html` which you can open in any browser.

---

## Common Operational Commands

**View System Logs:**
To monitor the scanning engine and backend events:
```bash
docker compose logs -f backend
```

To monitor the frontend UI logs:
```bash
docker compose logs -f frontend
```

**Run a Terminal Verification Scan:**
To verify the scanning engine is working without using the UI:
```bash
docker compose exec backend python simulation/run.py --target sc.com --skip-enumeration
```

## Scan Modes and When to Use Them

Aegis supports multiple scan variations through `scan_profile`.

### 1. Fast Validation (recommended default)

Use this for quick checks, parity validation, and CI smoke runs.

- Profile example: `Standard + Bounded Port Scan + No Enumeration`
- Behavior: scans bounded ports and only root/www hostnames
- Typical outcome: fast completion with deterministic top-level posture

Terminal/API example:
```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
	-H 'content-type: application/json' \
	-d '{"target":"example.com","scan_profile":"Standard + Bounded Port Scan + No Enumeration"}'
```

### 2. Balanced Discovery

Use this for routine production checks where broader hostname coverage is needed.

- Profile example: `Standard + Bounded Port Scan + Full Enumeration`
- Behavior: bounded ports, broad hostname expansion
- Notes: runtime depends on DNS size and CDN sprawl

### 3. Full-Fledge / Deep Coverage

Use this for investigations and periodic deep assessments.

- Profile example: `Deep + Full Port Scan + Full Enumeration`
- Behavior: full TCP port scan + broad subdomain enumeration
- Notes: this is the most expensive mode; runtime scales with target size

Practical guidance for very large domains:

1. Prefer running deep scans during low-traffic windows.
2. Keep deterministic mode (`LLM_PROVIDER_MODE=local`, `EMBEDDING_PROVIDER_MODE=local`) for stable throughput.
3. Use scan events and ETA range in UI/API to monitor progression by stage.

### 4. PQC-Focused Audit

Use this when cryptographic posture and migration planning are the primary concern.

- Profile example: `PQC Focus + Bounded Port Scan + No Enumeration`
- Behavior: narrower surface with cryptography-heavy analysis output

## Runtime Guardrails for Large Scans

For large targets, Aegis now applies adaptive prioritization and bounded probing to keep scans responsive.

Useful environment variables:

- `AEGIS_MAX_TLS_TARGETS_PER_SCAN` (default `1200`): max TLS handshakes per scan
- `AEGIS_TLS_STAGE_BUDGET_SECONDS` (default `1200`): maximum wall-time budget for TLS probing stage
- `AEGIS_STREAMING_DEEPEN_LIMIT` (default `400`): number of deferred low-priority hostnames to process in progressive deepening
- `AEGIS_STREAMING_DEEPEN_BATCH_SIZE` (default `80`): deepening chunk size

Example override:
```bash
AEGIS_MAX_TLS_TARGETS_PER_SCAN=800 \
AEGIS_TLS_STAGE_BUDGET_SECONDS=900 \
docker compose up -d
```

**Stop the Platform:**
To safely shut down all containers without losing your scanned data:
```bash
docker compose down
```
