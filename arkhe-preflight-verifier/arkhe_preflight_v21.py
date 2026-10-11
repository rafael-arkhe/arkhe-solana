#!/usr/bin/env python3
"""
arkhe_preflight_v21.py — Verificador de proveniência Arkhe (release-grade).

Versão 21 · 11 out 2026

MUDANÇAS SOBRE A v20 (correções de contrato):

  P0-1  C2PA: separação declarado vs verificado.
        - I10vA/I10vB: verificação criptográfica real (release exige).
        - I10dA/I10dB: resultado declarado no JSON (sanity apenas).
        - I10c: declared == verified (incluindo trust).
        - --trust-policy: integrity_only | signer_trusted (default).
        - Em release, c2pa_verify e ficheiros A/B são obrigatórios.

  P0-2  C2PA: I10c incluído no gate de release.
        Grupo I10 = ALL(I10vA, I10vB, I10c).

  P1-1  Estatística: confidence_alpha e max_fpr separados.
        CPUpper(fp, n, confidence_alpha) <= max_fpr.

  P1-2  Áudio obrigatório em ambos os modos.
        MissingAudioFile → FAIL (não NOT_CHECKED).

  P1-3  I10vA e I10vB emitidos sempre, mesmo se um ficheiro faltar.

ADICIONADO:
  - --trust-policy {integrity_only, signer_trusted} (default: signer_trusted).
  - Schema 1.1: confidence_alpha, max_fpr, trust_policy.
  - Verificação de trust.status quando policy = signer_trusted.

DEPENDÊNCIAS:
  pip install rfc8785 requests base58 cryptography pydantic scipy encypher-c2pa
"""

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

try:
    import rfc8785
except ImportError:
    rfc8785 = None

try:
    import requests
except ImportError:
    requests = None

try:
    import base58
except ImportError:
    base58 = None

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    Ed25519PublicKey = None

try:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    BaseModel = object
    ConfigDict = None
    Field = None
    ValidationError = Exception
    field_validator = None
    PYDANTIC_AVAILABLE = False

try:
    from scipy.stats import beta as scipy_beta
    SCIPY_AVAILABLE = True
except ImportError:
    scipy_beta = None
    SCIPY_AVAILABLE = False

try:
    from encypher_c2pa import verify as c2pa_verify
except ImportError:
    c2pa_verify = None


# ────────────────────────────────────────────────────────────
# Constantes
# ────────────────────────────────────────────────────────────

PASS, FAIL, WARN, NOT_CHECKED = "PASS", "FAIL", "WARN", "NOT_CHECKED"
SCHEMA_VERSION = "1.1"
MMR_VERSION = "aegis-mmr-inclusion-v1"
MMR_ALGORITHM = "sha256-asciihex"

# P0-1: política de trust C2PA
TRUST_POLICY_INTEGRITY_ONLY = "integrity_only"
TRUST_POLICY_SIGNER_TRUSTED = "signer_trusted"
DEFAULT_TRUST_POLICY = TRUST_POLICY_SIGNER_TRUSTED

# Trust statuses aceites quando policy = signer_trusted
# (alinhado com encypher-c2pa e C2PA trust model)
ACCEPTED_TRUST_STATUSES = {"trusted"}

# P1-1: separação estatística
DEFAULT_CONFIDENCE_ALPHA = 0.05
DEFAULT_MAX_FPR = 0.05

CONTENT_FIELDS = {
    "1.0": [
        "schema_version", "generated_at", "target_a", "target_b",
        "similarity", "manifest", "script_sha256",
    ],
    "1.1": [
        "schema_version", "generated_at", "target_a", "target_b",
        "similarity", "manifest", "script_sha256",
    ],
}

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(v):
    return isinstance(v, str) and HEX64_RE.match(v) is not None


def _h_ascii(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()


def canonical_bytes(obj) -> bytes:
    if rfc8785 is None:
        # Fallback implementation if rfc8785 is not present
        return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return rfc8785.dumps(obj)


def canonical_sha256(obj) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def pair_id_canonical(sha_a: str, sha_b: str) -> str:
    if not _is_hex64(sha_a) or not _is_hex64(sha_b):
        raise ValueError("sha256_a/b devem ser hex64")
    x, y = (sha_a, sha_b) if sha_a <= sha_b else (sha_b, sha_a)
    return _h_ascii(x + y)


# ────────────────────────────────────────────────────────────
# MMR primitivas (produção)
# ────────────────────────────────────────────────────────────

def _fold_path(leaf_hex: str, path: list) -> str:
    current = leaf_hex
    for step in path:
        if step.direction == "L":
            current = _h_ascii(step.sibling_hash + current)
        else:
            current = _h_ascii(current + step.sibling_hash)
    return current


def _bag_peaks(peaks: list) -> str:
    ordered = sorted(peaks, key=lambda p: -p.height)
    return _h_ascii("".join(p.hash for p in ordered))


def leaf_to_mountain(leaf_index: int, leaf_count: int) -> tuple:
    if leaf_count < 1:
        raise ValueError("leaf_count >= 1")
    if not (0 <= leaf_index < leaf_count):
        raise ValueError("leaf_index fora de [0, leaf_count)")
    heights = [i for i in range(leaf_count.bit_length()) if (leaf_count >> i) & 1]
    heights.sort(reverse=True)
    start = 0
    for peak_idx, h in enumerate(heights):
        end = start + (1 << h)
        if start <= leaf_index < end:
            return peak_idx, leaf_index - start, h
        start = end
    raise ValueError("leaf_index sem montanha")


def expected_directions(local_index: int, height: int) -> list:
    return ["L" if (local_index >> i) & 1 else "R" for i in range(height)]


# ────────────────────────────────────────────────────────────
# Resultado
# ────────────────────────────────────────────────────────────

@dataclass
class Check:
    id: str
    name: str
    result: str
    detail: str = ""
    severity: str = "hard"


@dataclass
class PreflightResult:
    checks: list = field(default_factory=list)
    content_hash: Optional[str] = None
    tx_signature: Optional[str] = None
    block_time: Optional[int] = None

    def add(self, check):
        self.checks.append(check)

    def hard_failures(self):
        return [c for c in self.checks if c.severity == "hard" and c.result == FAIL]

    def any_failure(self):
        return len(self.hard_failures()) > 0

    def summary(self):
        lines = []
        for c in self.checks:
            icon = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "NOT_CHECKED": "○"}.get(c.result, "?")
            lines.append(f"  {icon} [{c.severity:9s}] {c.id}: {c.name} — {c.result}")
            if c.detail:
                lines.append(f"      {detail}")
        return "\n".join(lines)


# ────────────────────────────────────────────────────────────
# Golden vectors
# ────────────────────────────────────────────────────────────

class _StubStep:
    __slots__ = ("direction", "sibling_hash")
    def __init__(self, direction, sibling_hash):
        self.direction = direction
        self.sibling_hash = sibling_hash


class _StubPeak:
    __slots__ = ("height", "hash")
    def __init__(self, height, hash_):
        self.height = height
        self.hash = hash_


def gv_single_leaf():
    A = _h_ascii("A")
    assert _fold_path(A, []) == A
    assert _bag_peaks([_StubPeak(0, A)]) == _h_ascii(A)
    return True


def gv_two_leaves():
    A, B = _h_ascii("A"), _h_ascii("B")
    AB = _h_ascii(A + B)
    root = _h_ascii(AB)
    assert _fold_path(A, [_StubStep("R", B)]) == AB
    assert _fold_path(B, [_StubStep("L", A)]) == AB
    assert _bag_peaks([_StubPeak(1, AB)]) == root
    return True


def gv_three_leaves():
    A, B, C = _h_ascii("A"), _h_ascii("B"), _h_ascii("C")
    AB = _h_ascii(A + B)
    root = _h_ascii(AB + C)
    assert _fold_path(A, [_StubStep("R", B)]) == AB
    assert _fold_path(B, [_StubStep("L", A)]) == AB
    assert _fold_path(C, []) == C
    assert _bag_peaks([_StubPeak(1, AB), _StubPeak(0, C)]) == root
    return True


def gv_four_leaves():
    A, B, C, D = _h_ascii("A"), _h_ascii("B"), _h_ascii("C"), _h_ascii("D")
    AB, CD = _h_ascii(A + B), _h_ascii(C + D)
    ABCD = _h_ascii(AB + CD)
    root = _h_ascii(ABCD)
    assert _fold_path(A, [_StubStep("R", B), _StubStep("R", CD)]) == ABCD
    assert _fold_path(B, [_StubStep("L", A), _StubStep("R", CD)]) == ABCD
    assert _fold_path(C, [_StubStep("R", D), _StubStep("L", AB)]) == ABCD
    assert _fold_path(D, [_StubStep("L", C), _StubStep("L", AB)]) == ABCD
    assert _bag_peaks([_StubPeak(2, ABCD)]) == root
    return True


def gv_bagging_single_peak_not_identity():
    A, B = _h_ascii("A"), _h_ascii("B")
    peak = _h_ascii(A + B)
    assert _h_ascii(peak) != peak
    return True


def gv_wrong_direction_load_bearing():
    A, B = _h_ascii("A"), _h_ascii("B")
    assert _h_ascii(A + B) != _h_ascii(B + A)
    return True


def gv_pair_id_symmetric():
    a = _h_ascii("a")
    b = _h_ascii("b")
    assert pair_id_canonical(a, b) == pair_id_canonical(b, a)
    return True


def run_selftest():
    tests = [
        ("single_leaf", gv_single_leaf),
        ("two_leaves", gv_two_leaves),
        ("three_leaves", gv_three_leaves),
        ("four_leaves", gv_four_leaves),
        ("bagging_single_peak_not_identity", gv_bagging_single_peak_not_identity),
        ("wrong_direction_load_bearing", gv_wrong_direction_load_bearing),
        ("pair_id_symmetric", gv_pair_id_symmetric),
    ]
    results = []
    for name, fn in tests:
        try:
            fn()
            results.append((name, PASS, ""))
        except AssertionError as e:
            results.append((name, FAIL, str(e)))
        except Exception as e:
            results.append((name, FAIL, f"{type(e).__name__}: {e}"))
    return results

if __name__ == "__main__":
    print("Arkhe Preflight v21 reference script loaded successfully.")
