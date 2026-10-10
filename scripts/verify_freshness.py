#!/usr/bin/env python3
"""
verify_freshness.py — verifica se o report.json bate certo com o código atual.
"""
from junit_to_report import compute_source_hashes, aggregate_hash, CONFIG_FILES
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


def classify_reason(match: bool, diff: dict) -> str:
    if match:
        return "match"
    if diff["missing"]:
        return "source_missing"
    if any(any(c.endswith(cfg) for cfg in CONFIG_FILES) for c in diff["changed"]):
        return "config_changed"
    if diff["changed"]:
        return "source_changed"
    if diff["added"]:
        return "source_added"
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", type=Path, default=Path("arkhe/report.json"))
    ap.add_argument("--out", type=Path, default=Path("arkhe/freshness.json"))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--allow-missing-hash", action="store_true")
    args = ap.parse_args()

    if not args.report.exists():
        print(f"ERRO: report não encontrado: {args.report}", file=sys.stderr)
        return 1

    report = json.loads(args.report.read_text())
    code_hash = report.get("code_hash")

    current_hashes = compute_source_hashes()
    current_agg = aggregate_hash(current_hashes)

    if not code_hash:
        if not args.allow_missing_hash:
            diff = {"added": [], "removed": [], "changed": [], "missing": []}
            freshness = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "match": False,
                "reason": "report_without_code_hash",
                "sha_match": False,
                "blake3_match": False,
                "report_hash": None,
                "current_hash": current_agg["sha256"],
                "report_blake3": None,
                "current_blake3": current_agg.get("blake3"),
                "diff": diff
            }
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(freshness, indent=2))
            print("✗ report sem code_hash — freshness falha por omissão", file=sys.stderr)
            return 1
        return 0

    report_sha = code_hash.get("sha256")
    report_b3 = code_hash.get("blake3")

    report_files = report.get("source_hashes", {})
    diff = {"added": [], "missing": [], "changed": []}

    for path, h in report_files.items():
        if path not in current_hashes:
            diff["missing"].append(path)
        elif current_hashes[path] != h:
            diff["changed"].append(path)

    for path in current_hashes:
        if path not in report_files:
            diff["added"].append(path)

    sha_match = report_sha == current_agg["sha256"]
    b3_match = (report_b3 == current_agg.get("blake3")) if report_b3 and current_agg.get("blake3") else True

    if sha_match != b3_match:
        print(f"AVISO: SHA-256 e BLAKE3 discordam entre si. sha_match={sha_match}, blake3_match={b3_match}.", file=sys.stderr)

    match = sha_match and b3_match
    reason = classify_reason(match, diff)

    freshness = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "match": match,
        "reason": reason,
        "sha_match": sha_match,
        "blake3_match": b3_match,
        "report_hash": report_sha,
        "current_hash": current_agg["sha256"],
        "report_blake3": report_b3,
        "current_blake3": current_agg.get("blake3"),
        "diff": diff
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(freshness, indent=2))

    if match:
        print("✓ freshness ok")
        return 0
    else:
        print(f"✗ freshness mismatch ({reason})")
        print(f"  sha_match={sha_match}, blake3_match={b3_match}")
        return 1 if args.strict else 0

if __name__ == "__main__":
    sys.exit(main())
