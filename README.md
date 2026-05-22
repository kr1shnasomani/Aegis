<p align="center">
  <img src="./frontend/public/logo.jpeg" alt="Aegis Logo" width="120" />
</p>

<h1 align="center">Aegis</h1>

<p align="center">
  <strong>Autonomous Quantum Cryptographic Intelligence Platform for Banking Infrastructure</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python_3.11-14354C?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React_Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/OQS_OpenSSL-FF5722?style=for-the-badge" alt="OQS OpenSSL" />
  <img src="https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Apache_AGE-E22A25?style=for-the-badge&logo=apache&logoColor=white" alt="Apache AGE" />
  <img src="https://img.shields.io/badge/Qdrant-E22A25?style=for-the-badge" alt="Qdrant" />
</p>

---

> **🚀 Want to run Aegis locally?**  
> Everything is fully containerized. Please navigate to **[SETUP.md](./SETUP.md)** for the quick, 2-step installation guide. No API keys or local SDKs are required for the default local deterministic mode.

---

## 🌊 Overview

Aegis is a scan-centric platform engineered to defend internet-facing cryptographic assets against the **Harvest Now, Decrypt Later (HNDL)** threat. By merging low-level Post-Quantum Cryptography (PQC) handshake inspection with deterministic scoring and deterministic remediation, Aegis provides a clear bridge to a quantum-safe future.

---

## ⚙️ How It Works

Aegis continuously discovers assets, evaluates their cryptographic posture, and builds actionable technical roadmaps based on NIST FIPS standards.

1. **Asset Discovery:** Identifies domains, IPs, and open ports (TLS, VPN, API).
2. **OQS Handshake Probing:** Performs deep byte-level inspection using an Open-Quantum-Safe (OQS) patched OpenSSL engine to detect hybrid PQC key exchanges (e.g., `X25519MLKEM768`).
3. **Graph Mapping:** Stores network topologies and relationships in an **Apache AGE** graph database for real-time interactive visualization.
4. **Deterministic Scoring:** Calculates a precise quantum vulnerability risk score and compliance tier.
5. **Artifact Generation:** Produces industry-standard CycloneDX 1.6 Cryptographic Bills of Materials (CBOMs) and technical remediation patches.

---

## 🚦 Scan Variations

Aegis supports scan profiles that trade off speed vs depth.

1. **Fast Validation:** `Standard + Bounded Port Scan + No Enumeration`
2. **Balanced Discovery:** `Standard + Bounded Port Scan + Full Enumeration`
3. **Full-Fledge Deep Scan:** `Deep + Full Port Scan + Full Enumeration`
4. **PQC-Focused Audit:** `PQC Focus + Bounded Port Scan + No Enumeration`

For very large domains, full-fledge scans can still be expensive. Aegis uses adaptive hostname/TLS prioritization, progressive deepening, and TLS-stage budgets to avoid indefinite probing while preserving high-value coverage first.

Detailed run examples and tuning flags are available in [SETUP.md](./SETUP.md).

---

## 🧮 Deterministic Scoring Model

Aegis relies on a strict, deterministic, and weighted formula to evaluate quantum risk, fully independent of probabilistic inference. 

**Risk Formula:**
> **Risk = 100 × (0.45 × V<sub>KEX</sub> + 0.35 × V<sub>SIG</sub> + 0.10 × V<sub>SYM</sub> + 0.10 × V<sub>TLS</sub>) + P<sub>cert</sub>**

*Where:*
- **V<sub>KEX</sub>** (45%): Key Exchange Vulnerability (Highly vulnerable to Shor's Algorithm).
- **V<sub>SIG</sub>** (35%): Signature Vulnerability (Authentication risks).
- **V<sub>SYM</sub>** (10%): Symmetric Cipher Vulnerability (Grover's Algorithm impact).
- **V<sub>TLS</sub>** (10%): Protocol Version Vulnerability (Legacy TLS configurations).

**Certificate Penalty (P<sub>cert</sub>):**
- `+10` points if the certificate is expired (Days remaining ≤ 0).
- `+5` points if the certificate expires within 30 days.
*(Note: Final Risk Score is strictly capped at 100)*

**Score Semantics:**
- **Risk Score** (Backend): `0-100` scale. **Higher is more vulnerable.**
- **Q-Score** (Frontend UI): `0-100` scale. **Higher is more secure.** *(Q-Score = 100 - Risk Score)*

---

## 🏗️ Repository Structure

Aegis is built as a modular monolith. 

```text
Aegis/
├── backend/             # FastAPI engine & Core PQC Scanning Logic
│   ├── analysis/        # Risk scoring & handshake metadata resolution
│   ├── discovery/       # Multi-protocol probing (TLS, VPN, API)
│   ├── intelligence/    # RAG Orchestrator & NIST roadmap generators
│   └── pipeline/        # Deterministic scan orchestration
├── frontend/            # React + Vite UI with Tailwind CSS
│   └── src/components/  # Interactive D3/Force-Graph visualizations
├── docker/              # Infrastructure-as-Code (OQS builds, Graph DB init)
├── corpus/                # Intelligence corpus (NIST Standards, FIPS PDFs)
├── docs/      # Extended architectural & API references
├── migrations/          # Alembic relational database migrations
├── scripts/             # Data ingestion & validation utilities
├── simulation/          # Standalone terminal-based scan testing utilities
└── tests/               # Unit and Integration test suites
```

---

## 📚 Documentation Index

For detailed technical guides and references, please see the specific documentation files mapped below:

| Documentation | Purpose |
| :--- | :--- |
| 🛠️ [**SETUP.md**](./SETUP.md) | Universal installation, environment configuration, and startup guide for running Aegis. |
| 📡 [**docs/API.md**](./docs/API.md) | Comprehensive backend REST endpoint documentation and cURL integration examples. |
| 💾 [**docs/DATABASE.md**](./docs/DATABASE.md) | Detailed schema mapping for PostgreSQL, Apache AGE (Graph), and Qdrant. |
| 🧠 [**docs/CONTEXT.md**](./docs/CONTEXT.md) | Technical context, core principles, and developer rules for the codebase. |
| 🎯 [**docs/SOLUTION.md**](./docs/SOLUTION.md) | Strategic product framing, threat models, and business problem statement. |

---

<p align="center">
  Built for the future of cryptographic security.
</p>
