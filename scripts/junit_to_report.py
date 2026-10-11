#!/usr/bin/env python3
"""
junit_to_report.py — converte JUnit XML do cargo-nextest em report.json.

CORREÇÕES v5 (adaptação arkhe-solana):
  - Glob para .rs em crates/*/src e programs/*/src.
  - CONFIG_FILES = {Cargo.toml, Cargo.lock, Anchor.toml, package.json}.
  - parse_junit() reconhece o formato cargo-nextest (testsuites aninhados).
  - verification_source = "cargo-test" (não "pytest").
  - return 0 explícito.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

CONFIG_FILES = {
    "Cargo.toml",
    "Cargo.lock",
    "Anchor.toml",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
}


def collect_source_files() -> list[Path]:
    """
    Descobre os ficheiros-fonte a hashear.

    Inclui .rs em crates/*/src e programs/*/src, mais config files
    que afectam comportamento sem serem código.
    """
    root = Path.cwd()
    files = set()

    for base in ("crates", "programs"):
        base_path = root / base
        if not base_path.is_dir():
            continue
        for p in base_path.rglob("*.rs"):
            if "target" in p.parts:
                continue
            if "__pycache__" in p.parts:
                continue
            if p.name.startswith("test_"):
                continue
            files.add(p)

    for cfg in CONFIG_FILES:
        p = root / cfg
        if p.exists():
            files.add(p)

    return sorted(files)


def compute_source_hashes() -> dict[str, dict]:
    import hashlib
    try:
        import blake3
        has_b3 = True
    except ImportError:
        has_b3 = False

    out = {}
    for f in collect_source_files():
        rel = f.relative_to(Path.cwd())
        rel_str = str(rel).replace("\\", "/")
        bytes_content = f.read_bytes()
        sha256_hash = hashlib.sha256(bytes_content).hexdigest()

        b3_hash = None
        if has_b3:
            b3_hash = blake3.blake3(bytes_content).hexdigest()

        out[rel_str] = {
            "sha256": sha256_hash,
            "blake3": b3_hash
        }
    return out


def aggregate_hash(hashes: dict[str, dict]) -> dict[str, str | None]:
    import hashlib
    try:
        import blake3
        has_b3 = True
    except ImportError:
        has_b3 = False

    sha = hashlib.sha256()
    b3 = blake3.blake3() if has_b3 else None

    for path in sorted(hashes):
        hash_obj = hashes[path]
        line = f"{path}:{hash_obj['sha256']}\n"
        sha.update(line.encode())
        if b3:
            b3.update(line.encode())

        if hash_obj['blake3']:
            line_b3 = f"{path}:{hash_obj['blake3']}\n"
            sha.update(line_b3.encode())
            if b3:
                b3.update(line_b3.encode())

    return {
        "sha256": sha.hexdigest(),
        "blake3": b3.hexdigest() if b3 else None,
    }


def parse_junit(path: Path) -> dict:
    """
    Parse de JUnit XML do cargo-nextest.

    O cargo-nextest emite:
      <testsuites>
        <testsuite name="..." tests="N" failures="N" ...>
          <testcase name="..." classname="..." time="...">
            <failure .../> | <error .../> | <skipped/>  (opcional)
          </testcase>
        </testsuite>
      </testsuites>

    Também aceita o formato plano do pytest para retrocompatibilidade.
    """
    if not path.exists():
        print(f"[aviso] XML ausente: {path}", file=sys.stderr)
        return {}

    tree = ET.parse(path)
    root = tree.getroot()
    results = {}
    ts = datetime.now(timezone.utc).isoformat()

    # Aceita ambos os formatos: <testsuites> (nextest) e <testsuite> (pytest)
    if root.tag == "testsuites":
        testcases = root.iter("testcase")
    else:
        testcases = root.iter("testcase")

    for tc in testcases:
        name = tc.get("name", "")
        failure = tc.find("failure")
        error = tc.find("error")
        skipped = tc.find("skipped")

        if failure is not None or error is not None:
            status = "falsified"
        elif skipped is not None:
            status = "skipped"
        else:
            status = "verified"

        results[name] = {"status": status, "last_run": ts}

    return results


def build_ledger(junit_files: list[Path]) -> dict:
    """Constrói o ledger.json a partir de múltiplos JUnit XMLs."""
    claims = {}
    for xml in junit_files:
        parsed = parse_junit(xml)
        for name, result in parsed.items():
            claims[name] = {
                "claim_id": name,
                "status": result["status"],
                "verification_source": "cargo-test",
                "last_run": result["last_run"],
                "depends_on": [],
                "source_files": [],
            }
    return {"claims": claims}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--junit-dir", type=Path, default=Path("target/nextest/default"))
    ap.add_argument("--out", type=Path, default=Path("arkhe/ledger.json"))
    ap.add_argument("--report", type=Path, default=Path("arkhe/report.json"))
    args = ap.parse_args()

    junit_files = sorted(args.junit_dir.glob("*.xml")) if args.junit_dir.is_dir() else []
    if not junit_files:
        print(f"[aviso] nenhum XML em {args.junit_dir}", file=sys.stderr)

    ledger = build_ledger(junit_files)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(ledger, indent=2))
    print(f"✓ ledger: {len(ledger['claims'])} claim(s) em {args.out}")

    # Gerar report.json com code_hash
    hashes = compute_source_hashes()
    agg = aggregate_hash(hashes)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "code_hash": agg,
        "source_hashes": hashes,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2))
    print(f"✓ report: {len(hashes)} ficheiro(s), sha256={agg['sha256'][:20]}…")

    return 0


if __name__ == "__main__":
    sys.exit(main())