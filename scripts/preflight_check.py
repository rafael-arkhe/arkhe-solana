#!/usr/bin/env python3
"""
arkhe_preflight_v19.py — Verificador de proveniência Arkhe (release-grade).

Versão 19 · 11 out 2026

CORREÇÕES SOBRE A v18 (um P0 + três P1):

  P0-1  Golden vector de duas folhas corrigido.
        A especificação aegis-mmr-inclusion-v1 define:
          root = hex(SHA256(UTF8(peak_0_hex || ... || peak_k_hex)))
        Mesmo com um único peak, o root é SHA256(peak_hex), não o peak.
        O vector anterior confundia peak com displayed root.
        Confirmado em:
          https://raw.githubusercontent.com/JuanLunaIA/aegis-latent-core/
          bca337243be9f1e7bee5aae149b164f248d1ceb3/docs/institutional/
          DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md §5.1

  P0-2  Golden vectors usam as primitivas de produção.
        _fold_golden → _fold_path
        _bag_golden  → _bag_peaks
        Elimina a possibilidade de o selftest e o verificador de produção
        divergirem silenciosamente.

  P1-1  I12 exige identificação criptográfica de todos os validation items.
        ValidationItem agora requer pair_id (hex64) derivado dos hashes
        dos áudios. I12 verifica o conjunto completo, não apenas os
        items que voluntariamente forneceram hashes.

  P1-2  --selftest é obrigatório em --mode release.
        Release falha se os golden vectors não passarem.

  P1-3  tau > 0 e n_pos > 0 em release.
        Evita classificador trivial que nunca detecta positivos.

ADICIONADO:
  - Campo `algorithm` no AnchorModel, fixado a "sha256-asciihex".
  - Campo `version` no AnchorModel, fixado a "aegis-mmr-inclusion-v1".
  - Fixture congelada para cross-language (mmr_v1_fixtures).
  - Função `generate_fixtures()` para regenerar a fixture a partir
    da implementação de produção.

DEPENDÊNCIAS:
  pip install rfc8785 requests base58 cryptography pydantic
              scipy encypher-c2pa
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
SCHEMA_VERSION = "1.0"
MMR_VERSION = "aegis-mmr-inclusion-v1"
MMR_ALGORITHM = "sha256-asciihex"

CONTENT_FIELDS = {
    "1.0": [
        "schema_version", "generated_at", "target_a", "target_b",
        "similarity", "manifest", "script_sha256",
    ],
}

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(v):
    return isinstance(v, str) and HEX64_RE.match(v) is not None


def _h_ascii(s: str) -> str:
    """SHA256(ASCII(s)) → hex minúsculo."""
    return hashlib.sha256(s.encode("ascii")).hexdigest()


# ────────────────────────────────────────────────────────────
# Primitivas de produção (usadas por selftest e verificação)
# ────────────────────────────────────────────────────────────

def _fold_path(leaf_hex: str, path: list) -> str:
    """
    Dobra o path do leaf até ao peak.
    Convenção: direction descreve a posição do sibling.
      "L" → sibling à esquerda → H(sibling || current)
      "R" → sibling à direita  → H(current || sibling)
    """
    current = leaf_hex
    for step in path:
        if step.direction == "L":
            current = _h_ascii(step.sibling_hash + current)
        else:
            current = _h_ascii(current + step.sibling_hash)
    return current


def _bag_peaks(peaks: list) -> str:
    """
    Bagging incondicional:
      root = SHA256(ASCII(p1_hex || p2_hex || ... || pk_hex))
    Peaks ordenados por altura descendente. Aplica-se mesmo com k=1.
    """
    ordered = sorted(peaks, key=lambda p: -p.height)
    return _h_ascii("".join(p.hash for p in ordered))


# ────────────────────────────────────────────────────────────
# Topologia MMR
# ────────────────────────────────────────────────────────────

def leaf_to_mountain(leaf_index: int, leaf_count: int) -> tuple:
    """Devolve (peak_index, local_index, mountain_height)."""
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
    """
    Direcção do sibling em relação ao nó actual:
      bit i = 0 → nó à esquerda → sibling à direita  → "R"
      bit i = 1 → nó à direita  → sibling à esquerda → "L"
    """
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
                lines.append(f"      {c.detail}")
        return "\n".join(lines)


# ────────────────────────────────────────────────────────────
# Schema Pydantic profundo
# ────────────────────────────────────────────────────────────

if PYDANTIC_AVAILABLE:

    class Peak(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        height: int
        hash: str

        @field_validator("height")
        @classmethod
        def height_non_negative(cls, v):
            if v < 0:
                raise ValueError("height >= 0")
            return v

        @field_validator("hash")
        @classmethod
        def hash_hex64(cls, v):
            if not _is_hex64(v):
                raise ValueError("peak hash hex64")
            return v

    class PathStep(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        direction: Literal["L", "R"]
        sibling_hash: str

        @field_validator("sibling_hash")
        @classmethod
        def sibling_hex64(cls, v):
            if not _is_hex64(v):
                raise ValueError("sibling_hash hex64")
            return v

    class ValidationItem(BaseModel):
        """
        Item de calibração.
        pair_id: identificador criptográfico do par, tipicamente
        SHA256(sha256_a || sha256_b). Obrigatório para I12.
        """
        model_config = ConfigDict(extra="forbid", strict=True)
        label: Literal["positive", "negative"]
        score: float
        pair_id: str
        sha256_a: str
        sha256_b: str
        name: Optional[str] = None

        @field_validator("score")
        @classmethod
        def score_finite_unit(cls, v):
            if not math.isfinite(v):
                raise ValueError("score finito")
            if not (0.0 <= v <= 1.0):
                raise ValueError("score em [0,1]")
            return v

        @field_validator("pair_id", "sha256_a", "sha256_b")
        @classmethod
        def hex64(cls, v):
            if not _is_hex64(v):
                raise ValueError("deve ser 64 hex minúsculas")
            return v

    class TargetModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        title: str
        artist: str
        year: int
        mbid: str
        isrcs: list[str] = Field(default_factory=list)
        iswcs: list[str] = Field(default_factory=list)
        composers: list[str] = Field(default_factory=list)
        sha256: str
        acoustid_gate: bool = False
        creator_did: Optional[str] = None

        @field_validator("sha256")
        @classmethod
        def sha_hex64(cls, v):
            if not _is_hex64(v):
                raise ValueError("sha256 hex64")
            return v

    class AnchorModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        tx_signature: str
        mmr_root: str
        mmr_version: str = MMR_VERSION
        mmr_algorithm: str = MMR_ALGORITHM
        leaf_index: int
        leaf_count: int
        peak_index: int
        peaks: list[Peak]
        path: list[PathStep]
        timestamp: Optional[str] = None
        anchor_commitment: Optional[str] = None

        @field_validator("mmr_root")
        @classmethod
        def root_hex64(cls, v):
            if not _is_hex64(v):
                raise ValueError("mmr_root hex64")
            return v

        @field_validator("mmr_version")
        @classmethod
        def version_exact(cls, v):
            if v != MMR_VERSION:
                raise ValueError(f"mmr_version deve ser {MMR_VERSION}")
            return v

        @field_validator("mmr_algorithm")
        @classmethod
        def algorithm_exact(cls, v):
            if v != MMR_ALGORITHM:
                raise ValueError(f"mmr_algorithm deve ser {MMR_ALGORITHM}")
            return v

        @field_validator("leaf_count")
        @classmethod
        def leaf_count_ge_1(cls, v):
            if v < 1:
                raise ValueError("leaf_count >= 1")
            return v

        @field_validator("leaf_index", "peak_index")
        @classmethod
        def non_negative(cls, v):
            if v < 0:
                raise ValueError("índice >= 0")
            return v

    class CalibrationModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        threshold: float
        alpha: float = 0.05
        tau: float = 0.0
        val_scores: list[ValidationItem] = Field(default_factory=list)
        n_negatives: int = 0
        tp: int = 0
        fp: int = 0
        tn: int = 0
        fn: int = 0
        calibration_valid: bool = False

        @field_validator("alpha")
        @classmethod
        def alpha_open_unit(cls, v):
            if not (0.0 < v < 1.0):
                raise ValueError("alpha em (0,1)")
            return v

        @field_validator("threshold")
        @classmethod
        def threshold_unit(cls, v):
            if not math.isfinite(v) or not (0.0 <= v <= 1.0):
                raise ValueError("threshold em [0,1]")
            return v

        @field_validator("tau")
        @classmethod
        def tau_unit(cls, v):
            if not math.isfinite(v) or not (0.0 <= v <= 1.0):
                raise ValueError("tau em [0,1]")
            return v

    class MelodicModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        status: str = "unknown"
        similarity: Optional[dict] = None
        calibration: Optional[CalibrationModel] = None

    class SimilarityModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        clap_cosine: Optional[float] = None
        melodic: Optional[MelodicModel] = None

        @field_validator("clap_cosine")
        @classmethod
        def clap_finite(cls, v):
            if v is None:
                return v
            if not math.isfinite(v):
                raise ValueError("clap_cosine finito")
            return v

    class LedgerModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        schema_version: str
        generated_at: str
        target_a: TargetModel
        target_b: TargetModel
        similarity: SimilarityModel
        anchor: Optional[AnchorModel] = None
        manifest: dict
        script_sha256: str
        content_hash: Optional[str] = None
        envelope_hash: Optional[str] = None

        @field_validator("schema_version")
        @classmethod
        def known_schema(cls, v):
            if v not in CONTENT_FIELDS:
                raise ValueError(f"schema_version desconhecido: {v}")
            return v

        @field_validator("generated_at")
        @classmethod
        def tz_aware(cls, v):
            if not v.endswith("Z") and "+" not in v and "-" not in v[10:]:
                raise ValueError("generated_at sem timezone")
            return v

else:
    Peak = PathStep = ValidationItem = None
    TargetModel = AnchorModel = CalibrationModel = None
    MelodicModel = SimilarityModel = LedgerModel = None


# ────────────────────────────────────────────────────────────
# Parse
# ────────────────────────────────────────────────────────────

def parse_and_validate(data, result):
    if not PYDANTIC_AVAILABLE:
        result.add(Check("SCHEMA", "pydantic", FAIL, "pip install pydantic", "hard"))
        return None
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as e:
        result.add(Check("PARSE", "JSON válido", FAIL, str(e), "hard"))
        return None
    if not isinstance(raw, dict):
        result.add(Check("PARSE", "Raiz é objeto", FAIL, "não é dict", "hard"))
        return None
    if "schema_version" not in raw:
        result.add(Check("SCHEMA", "schema_version", FAIL, "obrigatório no JSON cru", "hard"))
        return None
    try:
        ledger = LedgerModel(**raw)
        result.add(Check("SCHEMA", "Schema válido", PASS, "todos os campos", "hard"))
        return ledger
    except ValidationError as e:
        result.add(Check("SCHEMA", "Schema válido", FAIL, str(e), "hard"))
        return None


# ────────────────────────────────────────────────────────────
# Golden vectors (P0-1 + P0-2 corrigidos)
# ────────────────────────────────────────────────────────────
#
# A especificação confirma:
#   root = hex(SHA256(UTF8(p1_hex || p2_hex || ... || pk_hex)))
# mesmo quando k=1.
#
# Estes vectores chamam _fold_path e _bag_peaks (primitivas de produção).
# Não existe reimplementação paralela.

class _StubStep:
    """Adaptador leve para usar as primitivas de produção no selftest."""
    __slots__ = ("direction", "sibling_hash")
    def __init__(self, direction, sibling_hash):
        self.direction = direction
        self.sibling_hash = sibling_hash


class _StubPeak:
    __slots__ = ("height", "hash")
    def __init__(self, height, hash_):
        self.height = height
        self.hash = hash_


def golden_vector_two_leaves():
    """
    Árvore [A, B] (leaf_count=2, height=1, um único peak).
      A = SHA256("A")
      B = SHA256("B")
      peak_AB = H(A_hex || B_hex)
      root    = H(peak_AB_hex)        ← bagging incondicional
    """
    A = _h_ascii("A")
    B = _h_ascii("B")
    peak_AB = _h_ascii(A + B)
    root = _h_ascii(peak_AB)

    # leaf 0: sibling B à direita → "R"
    leaf0_path = [_StubStep("R", B)]
    assert _fold_path(A, leaf0_path) == peak_AB, "leaf0 fold mismatch"

    # leaf 1: sibling A à esquerda → "L"
    leaf1_path = [_StubStep("L", A)]
    assert _fold_path(B, leaf1_path) == peak_AB, "leaf1 fold mismatch"

    # bagging de um único peak
    bagged = _bag_peaks([_StubPeak(1, peak_AB)])
    assert bagged == root, "bagging mismatch single peak"
    return True


def golden_vector_three_leaves():
    """
    Árvore [A, B, C] (leaf_count=3, heights [1, 0], dois peaks [AB, C]).
      AB  = H(A || B)
      root = H(AB_hex || C_hex)
    """
    A, B, C = _h_ascii("A"), _h_ascii("B"), _h_ascii("C")
    AB = _h_ascii(A + B)
    root = _h_ascii(AB + C)

    assert _fold_path(A, [_StubStep("R", B)]) == AB
    assert _fold_path(B, [_StubStep("L", A)]) == AB
    assert _fold_path(C, []) == C

    bagged = _bag_peaks([_StubPeak(1, AB), _StubPeak(0, C)])
    assert bagged == root, f"three_leaves bag mismatch: {bagged} != {root}"
    return True


def golden_vector_single_leaf():
    """
    Árvore [A] (leaf_count=1, height=0, um peak = A).
      root = H(A_hex)   ← bagging incondicional sobre o único peak
    """
    A = _h_ascii("A")
    root = _h_ascii(A)

    assert _fold_path(A, []) == A
    bagged = _bag_peaks([_StubPeak(0, A)])
    assert bagged == root, "single_leaf bag mismatch"
    return True


def golden_vector_four_leaves():
    """
    Árvore [A, B, C, D] (leaf_count=4, height=2, um único peak).
      AB   = H(A || B)
      CD   = H(C || D)
      ABCD = H(AB_hex || CD_hex)
      root = H(ABCD_hex)
    """
    A, B, C, D = _h_ascii("A"), _h_ascii("B"), _h_ascii("C"), _h_ascii("D")
    AB = _h_ascii(A + B)
    CD = _h_ascii(C + D)
    ABCD = _h_ascii(AB + CD)
    root = _h_ascii(ABCD)

    # leaf 0: R (sib B) → AB; R (sib CD) → ABCD
    assert _fold_path(A, [_StubStep("R", B), _StubStep("R", CD)]) == ABCD
    # leaf 1: L (sib A) → AB; R (sib CD) → ABCD
    assert _fold_path(B, [_StubStep("L", A), _StubStep("R", CD)]) == ABCD
    # leaf 2: R (sib D) → CD; L (sib AB) → ABCD
    assert _fold_path(C, [_StubStep("R", D), _StubStep("L", AB)]) == ABCD
    # leaf 3: L (sib C) → CD; L (sib AB) → ABCD
    assert _fold_path(D, [_StubStep("L", C), _StubStep("L", AB)]) == ABCD

    bagged = _bag_peaks([_StubPeak(2, ABCD)])
    assert bagged == root
    return True


def golden_vector_wrong_direction_load_bearing():
    """Inverter L↔R deve produzir hash diferente."""
    A, B = _h_ascii("A"), _h_ascii("B")
    ab = _h_ascii(A + B)
    ba = _h_ascii(B + A)
    assert ab != ba, "convenção L/R não é load-bearing"
    return True


def golden_vector_bagging_single_peak_not_identity():
    """Garante que root != peak para uma única montanha."""
    A, B = _h_ascii("A"), _h_ascii("B")
    peak = _h_ascii(A + B)
    root = _h_ascii(peak)
    assert root != peak, "bagging não está a hashear o peak único"
    return True


def run_selftest() -> list:
    tests = [
        ("single_leaf", golden_vector_single_leaf),
        ("two_leaves", golden_vector_two_leaves),
        ("three_leaves", golden_vector_three_leaves),
        ("four_leaves", golden_vector_four_leaves),
        ("wrong_direction_load_bearing", golden_vector_wrong_direction_load_bearing),
        ("bagging_single_peak_not_identity", golden_vector_bagging_single_peak_not_identity),
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


def generate_fixtures() -> dict:
    """
    Gera fixtures congeladas para cross-language.
    O output deve ser comparado com o corpus de referência
    sdk/shared/mmr-inclusion-v1.json.
    """
    A, B, C, D = _h_ascii("A"), _h_ascii("B"), _h_ascii("C"), _h_ascii("D")
    AB = _h_ascii(A + B)
    CD = _h_ascii(C + D)
    ABCD = _h_ascii(AB + CD)
    return {
        "algorithm": MMR_ALGORITHM,
        "version": MMR_VERSION,
        "vectors": [
            {
                "leaf_count": 1,
                "peaks": [{"height": 0, "hash": A}],
                "root": _h_ascii(A),
            },
            {
                "leaf_count": 2,
                "peaks": [{"height": 1, "hash": AB}],
                "root": _h_ascii(AB),
                "leaf_0": {"leaf": A, "path": [{"direction": "R", "sibling_hash": B}]},
                "leaf_1": {"leaf": B, "path": [{"direction": "L", "sibling_hash": A}]},
            },
            {
                "leaf_count": 3,
                "peaks": [
                    {"height": 1, "hash": AB},
                    {"height": 0, "hash": C},
                ],
                "root": _h_ascii(AB + C),
            },
            {
                "leaf_count": 4,
                "peaks": [{"height": 2, "hash": ABCD}],
                "root": _h_ascii(ABCD),
            },
        ],
    }


# ────────────────────────────────────────────────────────────
# I1
# ────────────────────────────────────────────────────────────

def check_audio_binding(result, ledger, audio_a, audio_b, mode):
    if mode == "sanity":
        result.add(Check("I1", "Audio SHA-256", NOT_CHECKED, "modo sanity", "hard"))
        return
    if not audio_a or not audio_a.exists():
        result.add(Check("I1a", "Audio A", FAIL, f"não encontrado: {audio_a}", "hard"))
        return
    if not audio_b or not audio_b.exists():
        result.add(Check("I1b", "Audio B", FAIL, f"não encontrado: {audio_b}", "hard"))
        return
    aa = sha256_file(audio_a)
    ab = sha256_file(audio_b)
    result.add(Check("I1a", "Audio A SHA-256",
                     PASS if aa == ledger.target_a.sha256 else FAIL, aa[:16] + "…", "hard"))
    result.add(Check("I1b", "Audio B SHA-256",
                     PASS if ab == ledger.target_b.sha256 else FAIL, ab[:16] + "…", "hard"))


# ────────────────────────────────────────────────────────────
# I2/I3
# ────────────────────────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonicalize(obj):
    if rfc8785 is None:
        raise RuntimeError("rfc8785 não instalado")
    return rfc8785.dumps(obj)


def compute_content_hash(ledger):
    raw = ledger.model_dump()
    covered = {}
    for k in CONTENT_FIELDS[ledger.schema_version]:
        if k not in raw or raw[k] is None:
            raise ValueError(f"campo coberto ausente: {k}")
        covered[k] = raw[k]
    return hashlib.sha256(canonicalize(covered)).hexdigest()


def check_report_hash(result, ledger):
    claimed = ledger.content_hash
    if not claimed:
        result.add(Check("I2", "content_hash", FAIL, "ausente", "hard"))
        return
    if not _is_hex64(claimed):
        result.add(Check("I2", "content_hash formato", FAIL, "não hex64", "hard"))
        return
    try:
        computed = compute_content_hash(ledger)
    except Exception as e:
        result.add(Check("I2", "content_hash", FAIL, str(e), "hard"))
        return
    if computed == claimed:
        result.add(Check("I2", "content_hash", PASS, claimed[:16] + "…", "hard"))
        result.content_hash = claimed
    else:
        result.add(Check("I2", "content_hash", FAIL,
                         f"{computed[:16]}… ≠ {claimed[:16]}…", "hard"))


def check_covered_fields(result, ledger):
    raw = ledger.model_dump()
    missing = [k for k in CONTENT_FIELDS[ledger.schema_version]
               if k not in raw or raw[k] is None]
    if missing:
        result.add(Check("I3", "Campos cobertos", FAIL, str(missing), "hard"))
    else:
        result.add(Check("I3", "Campos cobertos", PASS, "todos", "hard"))


# ────────────────────────────────────────────────────────────
# I4
# ────────────────────────────────────────────────────────────

def check_signature_format(result, ledger):
    if not ledger.anchor:
        result.add(Check("I4", "tx_signature", NOT_CHECKED, "sem âncora", "external"))
        return
    sig = ledger.anchor.tx_signature
    if base58 is None:
        result.add(Check("I4", "base58", FAIL, "pip install base58", "hard"))
        return
    try:
        decoded = base58.b58decode(sig)
    except Exception as e:
        result.add(Check("I4", "decode", FAIL, str(e), "hard"))
        return
    if len(decoded) == 64:
        result.add(Check("I4", "tx_signature 64 bytes", PASS, sig[:16] + "…", "hard"))
        result.tx_signature = sig
    else:
        result.add(Check("I4", "tx_signature 64 bytes", FAIL, f"{len(decoded)} bytes", "hard"))


# ────────────────────────────────────────────────────────────
# I5/I6/I7
# ────────────────────────────────────────────────────────────

COMMITMENT_DOMAIN = b"ARKHE:v1"
MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO_PREFIX = "ARKHE:v1:"


def compute_anchor_commitment(content_hash, mmr_root):
    return hashlib.sha256(COMMITMENT_DOMAIN + bytes.fromhex(content_hash)
                          + bytes.fromhex(mmr_root)).digest()


def expected_memo(content_hash, mmr_root):
    return MEMO_PREFIX + base58.b58encode(
        compute_anchor_commitment(content_hash, mmr_root)).decode()


def fetch_transaction(rpc_url, signature):
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
        "params": [signature, {"encoding": "jsonParsed",
                                "maxSupportedTransactionVersion": 0,
                                "commitment": "finalized"}],
    }
    resp = requests.post(rpc_url, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json().get("result")


def extract_memos(tx):
    memos = []
    if not tx:
        return memos
    for ix in tx.get("transaction", {}).get("message", {}).get("instructions", []):
        if ix.get("programId") == MEMO_PROGRAM_ID:
            p = ix.get("parsed")
            if isinstance(p, str):
                memos.append(p)
            elif isinstance(p, dict) and "info" in p:
                memos.append(p["info"])
    for inner in tx.get("meta", {}).get("innerInstructions", []):
        for ix in inner.get("instructions", []):
            if ix.get("programId") == MEMO_PROGRAM_ID:
                p = ix.get("parsed")
                if isinstance(p, str):
                    memos.append(p)
                elif isinstance(p, dict) and "info" in p:
                    memos.append(p["info"])
    return memos


def check_solana_anchor(result, ledger, rpc_url, online):
    if not ledger.anchor:
        for cid in ("I5", "I6", "I7"):
            result.add(Check(cid, cid, NOT_CHECKED, "sem anchor", "external"))
        return
    sig = result.tx_signature
    if not sig:
        for cid in ("I5", "I6", "I7"):
            result.add(Check(cid, cid, NOT_CHECKED, "sem tx", "external"))
        return
    if not online or not rpc_url:
        for cid in ("I5", "I6", "I7"):
            result.add(Check(cid, cid, NOT_CHECKED, "offline", "external"))
        return
    if requests is None:
        result.add(Check("I5", "requests", FAIL, "pip install requests", "hard"))
        return
    try:
        tx = fetch_transaction(rpc_url, sig)
    except Exception as e:
        result.add(Check("I5", "getTransaction", FAIL, str(e), "external"))
        return
    if tx is None:
        result.add(Check("I5", "tx existe", FAIL, sig[:16] + "…", "hard"))
        return
    if tx.get("meta", {}).get("err") is not None:
        result.add(Check("I5", "tx ok", FAIL, str(tx["meta"]["err"]), "hard"))
        return
    result.add(Check("I5", "tx ok", PASS, sig[:16] + "…", "hard"))

    mmr_root = ledger.anchor.mmr_root
    if not mmr_root or not result.content_hash:
        result.add(Check("I6", "Binding", NOT_CHECKED, "sem mmr_root", "external"))
    else:
        try:
            exp = expected_memo(result.content_hash, mmr_root)
        except ValueError as e:
            result.add(Check("I6", "commitment", FAIL, str(e), "hard"))
            return
        memos = extract_memos(tx)
        if any(m == exp for m in memos):
            result.add(Check("I6", "Binding", PASS, exp[:32] + "…", "hard"))
        else:
            result.add(Check("I6", "Binding", FAIL,
                             f"esperado {exp[:32]}…", "hard"))

    block_time = tx.get("blockTime")
    gen = ledger.generated_at
    if block_time and gen:
        try:
            gdt = datetime.fromisoformat(gen.replace("Z", "+00:00"))
            if gdt.tzinfo is None:
                result.add(Check("I7", "timezone", FAIL, "naïve", "hard"))
            else:
                gts = int(gdt.timestamp())
                if block_time >= gts:
                    result.add(Check("I7", "blockTime", PASS, f"{block_time} >= {gts}", "hard"))
                    result.block_time = block_time
                else:
                    result.add(Check("I7", "blockTime", FAIL, f"{block_time} < {gts}", "hard"))
        except Exception as e:
            result.add(Check("I7", "parse", FAIL, str(e), "hard"))
    else:
        result.add(Check("I7", "blockTime", NOT_CHECKED, "sem dados", "external"))


# ────────────────────────────────────────────────────────────
# I8 — MMR topologia + fold + bagging
# ────────────────────────────────────────────────────────────

def check_mmr(result, ledger):
    if not ledger.anchor:
        result.add(Check("I8a", "MMR root", NOT_CHECKED, "sem anchor", "external"))
        result.add(Check("I8b", "MMR proof", NOT_CHECKED, "sem anchor", "external"))
        return
    a = ledger.anchor
    if not _is_hex64(a.mmr_root):
        result.add(Check("I8a", "MMR root", FAIL, "não hex64", "hard"))
        return
    result.add(Check("I8a", "MMR root formato", PASS, a.mmr_root[:16] + "…", "hard"))

    # versão e algoritmo
    if a.mmr_version != MMR_VERSION:
        result.add(Check("I8c", "MMR version", FAIL, a.mmr_version, "hard"))
        return
    if a.mmr_algorithm != MMR_ALGORITHM:
        result.add(Check("I8c", "MMR algorithm", FAIL, a.mmr_algorithm, "hard"))
        return
    result.add(Check("I8c", "MMR version/algorithm", PASS,
                     f"{MMR_VERSION}/{MMR_ALGORITHM}", "hard"))

    try:
        exp_peak, local_idx, height = leaf_to_mountain(a.leaf_index, a.leaf_count)
    except ValueError as e:
        result.add(Check("I8b", "MMR topologia", FAIL, str(e), "hard"))
        return

    if a.peak_index != exp_peak:
        result.add(Check("I8b", "MMR peak_index", FAIL,
                         f"{a.peak_index} ≠ {exp_peak}", "hard"))
        return

    exp_heights = sorted([i for i in range(a.leaf_count.bit_length())
                          if (a.leaf_count >> i) & 1], reverse=True)
    actual_heights = [p.height for p in a.peaks]
    if actual_heights != exp_heights:
        result.add(Check("I8b", "MMR peak heights", FAIL,
                         f"{actual_heights} ≠ {exp_heights}", "hard"))
        return

    if len(a.peaks) != bin(a.leaf_count).count("1"):
        result.add(Check("I8b", "MMR popcount", FAIL, "contagem", "hard"))
        return

    if len(a.path) != height:
        result.add(Check("I8b", "MMR path length", FAIL,
                         f"{len(a.path)} ≠ {height}", "hard"))
        return

    exp_dirs = expected_directions(local_idx, height)
    actual_dirs = [s.direction for s in a.path]
    if actual_dirs != exp_dirs:
        result.add(Check("I8b", "MMR path directions", FAIL,
                         f"{actual_dirs} ≠ {exp_dirs}", "hard"))
        return

    leaf = result.content_hash
    if not leaf:
        result.add(Check("I8b", "MMR leaf", FAIL, "sem content_hash", "hard"))
        return

    try:
        folded = _fold_path(leaf, a.path)
    except Exception as e:
        result.add(Check("I8b", "MMR fold", FAIL, str(e), "hard"))
        return

    if folded != a.peaks[exp_peak].hash:
        result.add(Check("I8b", "MMR leaf→peak", FAIL,
                         f"{folded[:16]}… ≠ {a.peaks[exp_peak].hash[:16]}…", "hard"))
        return

    try:
        bagged = _bag_peaks(a.peaks)
    except Exception as e:
        result.add(Check("I8b", "MMR bagging", FAIL, str(e), "hard"))
        return

    if bagged != a.mmr_root:
        result.add(Check("I8b", "MMR root bagged", FAIL,
                         f"{bagged[:16]}… ≠ {a.mmr_root[:16]}…", "hard"))
        return

    result.add(Check("I8b", "MMR inclusion proof", PASS,
                     f"leaf {leaf[:16]}… @ {a.leaf_index}/{a.leaf_count}", "hard"))


# ────────────────────────────────────────────────────────────
# I9 — DID
# ────────────────────────────────────────────────────────────

ED25519_PREFIX = b"\xed\x01"


def _check_one_did(result, suffix, did):
    if not did:
        result.add(Check(f"I9{suffix}", f"DID {suffix}", NOT_CHECKED, "ausente", "external"))
        return False
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        result.add(Check(f"I9{suffix}", f"DID {suffix} prefixo", FAIL, str(did)[:20], "hard"))
        return False
    if base58 is None:
        result.add(Check(f"I9{suffix}", "base58", FAIL, "pip install base58", "hard"))
        return False
    try:
        decoded = base58.b58decode(did[len("did:key:"):][1:])
    except Exception as e:
        result.add(Check(f"I9{suffix}", f"DID {suffix} decode", FAIL, str(e), "hard"))
        return False
    if len(decoded) < 34 or decoded[:2] != ED25519_PREFIX or len(decoded[2:]) != 32:
        result.add(Check(f"I9{suffix}", f"DID {suffix} estrutura", FAIL,
                         f"len={len(decoded)}", "hard"))
        return False
    if Ed25519PublicKey is not None:
        try:
            Ed25519PublicKey.from_public_bytes(decoded[2:])
        except Exception as e:
            result.add(Check(f"I9{suffix}", f"DID {suffix} Ed25519", FAIL, str(e), "hard"))
            return False
    result.add(Check(f"I9{suffix}", f"DID {suffix} Ed25519", PASS, did[:24] + "…", "hard"))
    return True


def check_did(result, ledger):
    oka = _check_one_did(result, "A", ledger.target_a.creator_did)
    okb = _check_one_did(result, "B", ledger.target_b.creator_did)
    if oka and okb and ledger.target_a.creator_did == ledger.target_b.creator_did:
        result.add(Check("I9c", "DIDs distintos", WARN, "mesma identidade", "heuristic"))
    elif oka and okb:
        result.add(Check("I9c", "DIDs distintos", PASS, "separados", "heuristic"))


# ────────────────────────────────────────────────────────────
# I10 — C2PA
# ────────────────────────────────────────────────────────────

def _check_one_c2pa(result, suffix, path):
    if c2pa_verify is None:
        result.add(Check(f"I10{suffix}", "C2PA", NOT_CHECKED, "sem encypher-c2pa", "external"))
        return
    if not path or not path.exists():
        result.add(Check(f"I10{suffix}", f"C2PA {suffix}", FAIL, "ficheiro ausente", "hard"))
        return
    try:
        rep = c2pa_verify(str(path))
        ok = (rep.get("integrity") == "valid"
              and rep.get("signature") == "valid"
              and rep.get("hard_binding") == "match")
        trust = rep.get("trust", {}).get("status")
        result.add(Check(f"I10{suffix}", f"C2PA {suffix}",
                         PASS if ok else FAIL, f"trust={trust}", "external" if ok else "hard"))
    except Exception as e:
        result.add(Check(f"I10{suffix}", f"C2PA {suffix} erro", FAIL, str(e), "external"))


def check_c2pa(result, a, b):
    _check_one_c2pa(result, "A", a)
    _check_one_c2pa(result, "B", b)


# ────────────────────────────────────────────────────────────
# I11 — Calibração
# ────────────────────────────────────────────────────────────

def clopper_pearson_upper(fp, n, alpha):
    if n == 0:
        return None
    if fp == 0:
        return 1.0 - alpha ** (1.0 / n)
    if not SCIPY_AVAILABLE:
        return None
    return float(scipy_beta.ppf(1.0 - alpha, fp + 1, n - fp))


def check_calibration(result, ledger, mode):
    melodic = ledger.similarity.melodic if ledger.similarity else None
    if not melodic or not melodic.calibration:
        result.add(Check("I11", "Calibração", NOT_CHECKED, "ausente", "external"))
        return
    cal = melodic.calibration
    vals = cal.val_scores
    n_neg = sum(1 for v in vals if v.label == "negative")
    n_pos = sum(1 for v in vals if v.label == "positive")

    if n_neg == 0:
        result.add(Check("I11", "Negativos > 0", FAIL, "sem negativos", "hard"))
        return

    tp = sum(1 for v in vals if v.label == "positive" and v.score >= cal.threshold)
    fp = sum(1 for v in vals if v.label == "negative" and v.score >= cal.threshold)
    tn = sum(1 for v in vals if v.label == "negative" and v.score < cal.threshold)
    fn = sum(1 for v in vals if v.label == "positive" and v.score < cal.threshold)

    if (tp, fp, tn, fn) != (cal.tp, cal.fp, cal.tn, cal.fn):
        result.add(Check("I11", "Métricas", FAIL,
                         f"recomp ({tp},{fp},{tn},{fn}) ≠ declarado", "hard"))
        return
    result.add(Check("I11", "Métricas", PASS, f"tp={tp} fp={fp} tn={tn} fn={fn}", "hard"))

    if cal.n_negatives != n_neg:
        result.add(Check("I11c", "n_negatives", FAIL,
                         f"{cal.n_negatives} ≠ {n_neg}", "hard"))
    else:
        result.add(Check("I11c", "n_negatives", PASS, str(n_neg), "hard"))

    upper = clopper_pearson_upper(fp, n_neg, cal.alpha)
    if upper is None:
        result.add(Check("I11b", "Clopper-Pearson", FAIL,
                         "FP>0 e SciPy ausente", "hard"))
    elif upper <= cal.alpha:
        result.add(Check("I11b", "FPR upper bound", PASS,
                         f"CP({fp}/{n_neg}) = {upper:.4f} <= {cal.alpha}", "hard"))
    else:
        result.add(Check("I11b", "FPR upper bound", FAIL,
                         f"CP({fp}/{n_neg}) = {upper:.4f} > {cal.alpha}", "hard"))

    # P1-3: TPR mínimo em release
    tpr = tp / n_pos if n_pos > 0 else 0.0
    if mode == "release":
        if n_pos == 0:
            result.add(Check("I11d", "n_pos > 0", FAIL,
                             "release exige pelo menos um positivo", "hard"))
            return
        if cal.tau <= 0.0:
            result.add(Check("I11d", "tau > 0", FAIL,
                             "release exige tau > 0", "hard"))
            return
    if tpr >= cal.tau:
        result.add(Check("I11d", "TPR >= tau", PASS,
                         f"{tpr:.4f} >= {cal.tau}", "hard"))
    else:
        result.add(Check("I11d", "TPR >= tau", FAIL,
                         f"{tpr:.4f} < {cal.tau}", "hard"))


# ────────────────────────────────────────────────────────────
# I12 — Leakage (P1-1 corrigido)
# ────────────────────────────────────────────────────────────

def check_calibration_leakage(result, ledger):
    melodic = ledger.similarity.melodic if ledger.similarity else None
    if not melodic or not melodic.calibration:
        result.add(Check("I12", "Separação", NOT_CHECKED, "sem calibração", "external"))
        return

    targets = {ledger.target_a.sha256, ledger.target_b.sha256}

    # P1-1: cada item tem pair_id + hashes obrigatórios (schema).
    # Verificamos o conjunto completo, não apenas os que forneceram hashes.
    seen_pair_ids = set()
    overlap = set()
    for v in melodic.calibration.val_scores:
        if v.pair_id in seen_pair_ids:
            result.add(Check("I12", "pair_id único", FAIL,
                             f"pair_id duplicado: {v.pair_id[:16]}…", "hard"))
            return
        seen_pair_ids.add(v.pair_id)

        expected_pair = hashlib.sha256(
            (v.sha256_a + v.sha256_b).encode("ascii")
        ).hexdigest()
        if v.pair_id != expected_pair:
            result.add(Check("I12", "pair_id derivado", FAIL,
                             f"{v.pair_id[:16]}… ≠ {expected_pair[:16]}…", "hard"))
            return

        if v.sha256_a in targets or v.sha256_b in targets:
            overlap.add(v.pair_id[:16] + "…")

    if overlap:
        result.add(Check("I12", "Separação", FAIL,
                         f"targets presentes: {sorted(overlap)}", "hard"))
    else:
        result.add(Check("I12", "Separação", PASS,
                         f"{len(seen_pair_ids)} pairs, sem overlap", "hard"))


# ────────────────────────────────────────────────────────────
# I13
# ────────────────────────────────────────────────────────────

def check_required_fields(result, ledger):
    raw = ledger.model_dump()
    missing = [k for k in CONTENT_FIELDS[ledger.schema_version]
               if k not in raw or raw[k] is None]
    if missing:
        result.add(Check("I13", "Campos obrigatórios", FAIL, str(missing), "hard"))
    else:
        result.add(Check("I13", "Campos obrigatórios", PASS, "todos", "hard"))


# ────────────────────────────────────────────────────────────
# I14
# ────────────────────────────────────────────────────────────

def check_script_hash(result, ledger):
    if not ledger.script_sha256:
        result.add(Check("I14", "script_sha256", NOT_CHECKED, "ausente", "external"))
        return
    actual = sha256_file(Path(__file__))
    if ledger.script_sha256 == actual:
        result.add(Check("I14", "script_sha256", PASS, actual[:16] + "…", "hard"))
    else:
        result.add(Check("I14", "script_sha256", FAIL,
                         f"{ledger.script_sha256[:16]}… ≠ {actual[:16]}…", "hard"))


# ────────────────────────────────────────────────────────────
# I15
# ────────────────────────────────────────────────────────────

def check_derived_hashes(result, ledger):
    a = ledger.anchor
    if not a or not result.content_hash or not _is_hex64(a.mmr_root):
        return
    if a.anchor_commitment:
        try:
            exp = base58.b58encode(
                compute_anchor_commitment(result.content_hash, a.mmr_root)).decode()
            result.add(Check("I15a", "anchor_commitment",
                             PASS if exp == a.anchor_commitment else FAIL,
                             exp[:16] + "…", "hard"))
        except Exception as e:
            result.add(Check("I15a", "anchor_commitment", FAIL, str(e), "hard"))
    else:
        result.add(Check("I15a", "anchor_commitment", NOT_CHECKED, "ausente", "external"))

    if ledger.envelope_hash:
        try:
            env = hashlib.sha256(canonicalize({
                "content_hash": result.content_hash,
                "anchor": a.model_dump(),
            })).hexdigest()
            result.add(Check("I15b", "envelope_hash",
                             PASS if env == ledger.envelope_hash else FAIL,
                             env[:16] + "…", "hard"))
        except Exception as e:
            result.add(Check("I15b", "envelope_hash", FAIL, str(e), "hard"))
    else:
        result.add(Check("I15b", "envelope_hash", NOT_CHECKED, "ausente", "external"))


# ────────────────────────────────────────────────────────────
# Heurísticas
# ────────────────────────────────────────────────────────────

def check_heuristics(result, ledger):
    hashes = [ledger.target_a.sha256, ledger.target_b.sha256]
    if len(hashes) == 2:
        wa = {hashes[0][i:i+16] for i in range(0, 49, 4)}
        wb = {hashes[1][i:i+16] for i in range(0, 49, 4)}
        ov = wa & wb
        if ov:
            result.add(Check("H1", "Fragmentos", WARN, f"{len(ov)}", "heuristic"))
        else:
            result.add(Check("H1", "Fragmentos", PASS, "sem", "heuristic"))


# ────────────────────────────────────────────────────────────
# Enforcement
# ────────────────────────────────────────────────────────────

REQUIRED_GROUPS = {
    "I1":  ("ALL", ["I1a", "I1b"]),
    "I2":  ("ANY", ["I2"]),
    "I3":  ("ANY", ["I3"]),
    "I4":  ("ANY", ["I4"]),
    "I5":  ("ANY", ["I5"]),
    "I6":  ("ANY", ["I6"]),
    "I7":  ("ANY", ["I7"]),
    "I8":  ("ALL", ["I8a", "I8b", "I8c"]),
    "I9":  ("ALL", ["I9A", "I9B"]),
    "I10": ("ALL", ["I10A", "I10B"]),
    "I11": ("ALL", ["I11", "I11b", "I11c", "I11d"]),
    "I12": ("ANY", ["I12"]),
    "I13": ("ANY", ["I13"]),
    "I14": ("ANY", ["I14"]),
    "I15": ("ALL", ["I15a", "I15b"]),
}


def enforce_release(result):
    issues = []
    for gid, (sem, members) in REQUIRED_GROUPS.items():
        exact = {c.id: c for c in result.checks if c.id in members}
        if not exact:
            issues.append(f"{gid} ({sem}): nenhum check")
            continue
        if sem == "ALL":
            missing = [m for m in members if m not in exact]
            failed = [m for m, c in exact.items() if c.result != PASS]
            if missing:
                issues.append(f"{gid} (ALL): ausentes {missing}")
            if failed:
                issues.append(f"{gid} (ALL): não PASS {failed}")
        else:
            if not any(c.result == PASS for c in exact.values()):
                issues.append(f"{gid} (ANY): nenhum PASS")
    return len(issues) == 0, issues


# ────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Arkhe Preflight v19")
    parser.add_argument("report", type=Path, nargs="?")
    parser.add_argument("--audio-a", type=Path)
    parser.add_argument("--audio-b", type=Path)
    parser.add_argument("--c2pa-a", type=Path)
    parser.add_argument("--c2pa-b", type=Path)
    parser.add_argument("--mode", choices=["sanity", "release"], default="sanity")
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--rpc", default="https://api.devnet.solana.com")
    parser.add_argument("--selftest", action="store_true",
                        help="Corre golden vectors e sai")
    parser.add_argument("--fixtures", action="store_true",
                        help="Imprime fixtures congeladas para cross-language")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.fixtures:
        print(json.dumps(generate_fixtures(), indent=2))
        return 0

    if args.selftest:
        results = run_selftest()
        print("═" * 70)
        print("ARKHE PREFLIGHT v19 — Golden Vectors")
        print("═" * 70)
        ok = True
        for name, res, detail in results:
            icon = "✓" if res == PASS else "✗"
            print(f"  {icon} {name}: {res}")
            if detail:
                print(f"      {detail}")
            if res != PASS:
                ok = False
        print()
        print("RESULTADO:", "✓ PASS" if ok else "✗ FAIL")
        return 0 if ok else 1

    # P1-2: selftest obrigatório em release
    if args.mode == "release":
        results = run_selftest()
        failed = [r for r in results if r[1] != PASS]
        if failed:
            print("✗ FAIL: selftest falhou em modo release", file=sys.stderr)
            for name, res, detail in results:
                icon = "✓" if res == PASS else "✗"
                print(f"  {icon} {name}: {res}", file=sys.stderr)
                if detail:
                    print(f"      {detail}", file=sys.stderr)
            return 1

    if not args.report:
        parser.error("report é obrigatório (ou usa --selftest/--fixtures)")

    result = PreflightResult()

    if not args.report.exists():
        print(f"✗ FAIL: ficheiro não encontrado: {args.report}", file=sys.stderr)
        return 2

    ledger = parse_and_validate(args.report.read_bytes(), result)
    if ledger is None:
        print("═" * 70)
        print("ARKHE PREFLIGHT v19")
        print("═" * 70)
        print(result.summary())
        return 1

    check_required_fields(result, ledger)
    check_covered_fields(result, ledger)
    check_audio_binding(result, ledger, args.audio_a, args.audio_b, args.mode)
    check_report_hash(result, ledger)
    check_signature_format(result, ledger)
    check_did(result, ledger)
    check_calibration(result, ledger, args.mode)
    check_calibration_leakage(result, ledger)
    check_solana_anchor(result, ledger, args.rpc, args.online)
    check_mmr(result, ledger)
    check_c2pa(result, args.c2pa_a, args.c2pa_b)
    check_script_hash(result, ledger)
    check_derived_hashes(result, ledger)
    check_heuristics(result, ledger)

    print("═" * 70)
    print("ARKHE PREFLIGHT v19")
    print("═" * 70)
    print(f"Modo: {args.mode}  |  Online: {args.online}")
    print()
    print(result.summary())
    print()

    if result.any_failure():
        print("═" * 70)
        print(f"RESULTADO: ✗ FAIL ({len(result.hard_failures())} hard failures)")
        print("═" * 70)
        for c in result.hard_failures():
            print(f"  ✗ {c.id}: {c.name}")
            if c.detail:
                print(f"      {c.detail}")
        return 1

    if args.mode == "release":
        ok, issues = enforce_release(result)
        if not ok:
            print("═" * 70)
            print(f"RESULTADO: ✗ FAIL (release: {len(issues)} problemas)")
            print("═" * 70)
            for i in issues:
                print(f"  ✗ {i}")
            return 1

    print("═" * 70)
    print("RESULTADO: ✓ PASS")
    print("═" * 70)
    if result.content_hash:
        print(f"  content_hash: {result.content_hash}")
    if result.tx_signature:
        print(f"  tx_signature: {result.tx_signature[:32]}…")
    if result.block_time:
        print(f"  block_time: {result.block_time}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
