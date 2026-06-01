import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

# Setup paths so we can import backend
SIM_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SIM_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.config import get_settings
from backend.core.database import async_session_factory
from backend.models.enums import ScanStatus
from backend.repositories.scan_job_repo import ScanJobRepository
from backend.pipeline.orchestrator import PipelineOrchestrator, ScanReadService


def _safe_text(value):
    return "-" if value is None else str(value)


def _print_pretty_summary(output):
    print("\n=== AEGIS LOCAL PIPELINE REPORT ===")
    print(f"Target: {output['target']}")
    print(f"Duration: {output['scan_duration_seconds']}s")
    model = output.get("score_model", {})
    print("Score Model:")
    print(f"  risk_score: {_safe_text(model.get('risk_score'))}")
    print(f"  q_score: {_safe_text(model.get('q_score'))}")
    print(f"  relation: {_safe_text(model.get('relation'))}")
    print(f"Assets: {len(output.get('assets', []))}")

    assets = output.get("assets", [])
    if not assets:
        print("\nNo assets discovered.")
        return

    print("\nAssets:")
    header = (
        f"{'HOSTNAME':35} {'PORT':>5} {'TLS':10} {'KEY EXCHANGE':20} "
        f"{'CERT SIG':18} {'RISK':>6} {'Q':>6} {'TIER':20}"
    )
    print(header)
    print("-" * len(header))
    for asset in assets:
        print(
            f"{_safe_text(asset.get('hostname'))[:35]:35} "
            f"{_safe_text(asset.get('port')):>5} "
            f"{_safe_text(asset.get('tls_version'))[:10]:10} "
            f"{_safe_text(asset.get('kex_algorithm'))[:20]:20} "
            f"{_safe_text(asset.get('sig_algorithm'))[:18]:18} "
            f"{_safe_text(asset.get('risk_score')):>6} "
            f"{_safe_text(asset.get('q_score')):>6} "
            f"{_safe_text(asset.get('compliance_tier'))[:20]:20}"
        )


async def main():
    parser = argparse.ArgumentParser(description="Run Aegis Pipeline locally.")
    parser.add_argument("--target", required=True, help="Target domain (e.g. <url>)")
    parser.add_argument("--skip-enumeration", action="store_true", help="Skip Amass/DNSx")
    parser.add_argument(
        "--full-port-scan", action="store_true", help="Enable full TCP port scanning mode"
    )
    parser.add_argument(
        "--format", choices=["pretty", "json"], default="pretty", help="Terminal output format"
    )
    args = parser.parse_args()

    settings = get_settings()
    if args.skip_enumeration:
        settings.SKIP_ENUMERATION = True

    # Keep logging visible so errors during pipeline execution are not swallowed
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # 1. Create Scan Job exactly as the API does
    async with async_session_factory() as session:
        repo = ScanJobRepository(session)
        scan_profile = "Simulation"
        if args.full_port_scan:
            scan_profile += " + Full Port Scan"
        if args.skip_enumeration:
            scan_profile += " + No Enumeration"
        else:
            scan_profile += " + Full Enumeration"
        scan_job = await repo.create(
            target=args.target,
            status=ScanStatus.PENDING,
            scan_profile=scan_profile,
            initiated_by="simulation_runner",
        )
        await session.commit()
        scan_id = scan_job.id

    # 2. Run Pipeline Orchestrator directly
    start_time = time.time()
    orchestrator = PipelineOrchestrator()
    try:
        await orchestrator.run_scan(scan_id=scan_id, target=args.target)
    except Exception as e:
        print(f"PIPELINE CRASHED: {e}", file=sys.stderr)
        sys.exit(1)

    end_time = time.time()
    scan_duration_seconds = round(end_time - start_time, 2)

    # 3. Retrieve Results exactly as the API does
    read_service = ScanReadService()
    results = await read_service.get_scan_results(scan_id=scan_id)

    # 4. Format JSON Output
    formatted_assets = []
    for asset in results.get("assets", []):
        assessment = asset.get("assessment") or {}
        cbom = asset.get("cbom") or {}
        remediation = asset.get("remediation") or {}

        cbom_json = cbom.get("cbom_json", {})
        cbom_summary = cbom_json.get("quantumRiskSummary") if cbom_json else None

        hndl_timeline = remediation.get("hndl_timeline") or {}
        entries = hndl_timeline.get("entries", [])
        hndl_break_year = min((e["breakYear"] for e in entries), default=None) if entries else None

        tier = assessment.get("compliance_tier")
        tier_val = tier.value if hasattr(tier, "value") else tier

        formatted_assets.append(
            {
                "hostname": asset.get("hostname"),
                "port": asset.get("port"),
                "tls_version": assessment.get("tls_version"),
                "cipher_suite": assessment.get("cipher_suite"),
                "kex_algorithm": assessment.get("kex_algorithm"),
                "sig_algorithm": assessment.get("auth_algorithm"),
                "enc_algorithm": assessment.get("enc_algorithm"),
                "V_kex": assessment.get("kex_vulnerability"),
                "V_sig": assessment.get("sig_vulnerability"),
                "V_sym": assessment.get("sym_vulnerability"),
                "V_tls": assessment.get("tls_vulnerability"),
                "risk_score": assessment.get("risk_score"),
                "q_score": (
                    None
                    if assessment.get("risk_score") is None
                    else round(100 - float(assessment.get("risk_score")), 2)
                ),
                "compliance_tier": tier_val,
                "hndl_break_year": hndl_break_year,
                "cbom_summary": cbom_summary,
                "remediation_patch": remediation.get("patch_config"),
            }
        )

    output = {
        "target": args.target,
        "scan_duration_seconds": scan_duration_seconds,
        "score_model": {
            "risk_score": "0-100, higher is worse",
            "q_score": "0-100, higher is better",
            "relation": "q_score = 100 - risk_score",
        },
        "assets": formatted_assets,
    }

    json_output = json.dumps(output, indent=2)

    # Write to file
    results_dir = SIM_DIR / "results"
    results_dir.mkdir(exist_ok=True, parents=True)
    latest_file = results_dir / "latest.json"
    latest_file.write_text(json_output)

    # Print to terminal
    if args.format == "json":
        print(json_output)
    else:
        _print_pretty_summary(output)
        print(f"\nJSON artifact written to: {latest_file}")


if __name__ == "__main__":
    asyncio.run(main())
