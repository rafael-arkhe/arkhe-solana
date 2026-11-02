#!/usr/bin/env python3
"""
Arkhe-Test Pipeline Runner
Implementa o pipeline de qualidade contínuo:
- Estágio 1: Feedback rápido (< 5 min)
- Estágio 2: Integração (< 20 min)
- Estágio 3: Adversarial contínuo (falsificadores e ataques de segurança)
Gera relatórios content-addressed em `arkhe-test/reports/`.
"""

import hashlib
import json
import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

def log(msg):
    print(f"[ARKHE-TEST] {msg}", flush=True)

def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def run_command(cmd, cwd=BASE_DIR):
    start = time.time()
    res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    duration = time.time() - start
    return res.returncode == 0, res.stdout, res.stderr, duration

def main():
    log("Iniciando Pipeline de Qualidade arkhe-test...")
    total_start = time.time()
    report = {
        "timestamp": int(time.time()),
        "stages": {},
        "status": "PASS",
        "invariants_covered": [f"I-{i:02d}" for i in range(1, 11)],
        "meta_invariants_covered": [f"I-T{i:02d}" for i in range(1, 9)],
    }

    # Estágio 1: Feedback rápido
    log("Executando Estágio 1: Feedback Rápido (< 5 min)...")
    ok1, out1, err1, dur1 = run_command("cargo test --lib suites::stages::tests::test_stage1_fast_feedback_execution")
    if not ok1:
        log(f"FALHA Estágio 1:\n{err1}\n{out1}")
        sys.exit(1)
    log(f"Estágio 1 CONCLUÍDO em {dur1:.2f}s")
    report["stages"]["stage_1_fast_feedback"] = {
        "status": "PASS",
        "duration_seconds": dur1,
    }

    # Estágio 2: Integração
    log("Executando Estágio 2: Integração (< 20 min)...")
    ok2, out2, err2, dur2 = run_command("cargo test --lib suites::stages::tests::test_stage2_integration_execution")
    if not ok2:
        log(f"FALHA Estágio 2:\n{err2}\n{out2}")
        sys.exit(1)
    log(f"Estágio 2 CONCLUÍDO em {dur2:.2f}s")
    report["stages"]["stage_2_integration"] = {
        "status": "PASS",
        "duration_seconds": dur2,
    }

    # Estágio 3: Adversarial
    log("Executando Estágio 3: Adversarial Contínuo (Falsificadores I-01 a I-10)...")
    ok3, out3, err3, dur3 = run_command("cargo test --lib suites::invariants::tests::test_all_invariants_i01_to_i10")
    if not ok3:
        log(f"FALHA Estágio 3:\n{err3}\n{out3}")
        sys.exit(1)
    log(f"Estágio 3 CONCLUÍDO em {dur3:.2f}s")
    report["stages"]["stage_3_adversarial"] = {
        "status": "PASS",
        "duration_seconds": dur3,
    }

    total_duration = time.time() - total_start
    report["total_duration_seconds"] = total_duration

    # Content-addressing do relatório
    serialized = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    report_hash = compute_sha256(serialized)
    report["content_digest_sha256"] = report_hash

    report_path = os.path.join(REPORTS_DIR, "security", f"run-{int(time.time())}.json")
    with open(report_path, "w") as fp:
        json.dump(report, fp, indent=2)

    log(f"Pipeline arkhe-test aprovado com sucesso em {total_duration:.2f}s!")
    log(f"Relatório de segurança gravado em: {report_path}")
    log(f"Content Digest (SHA-256): {report_hash}")

if __name__ == "__main__":
    main()
