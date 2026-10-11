#!/usr/bin/env python3
"""
arkhe_preflight_v23.py — Verificador de proveniência Arkhe (release-grade).

Versão 23 · 11 out 2026

CORREÇÕES SOBRE A v22 (fecho):

  P0-1  I10ctx fail-closed quando versão instalada é indeterminada.
        installed_version is None → I10ctx.version = FAIL.

  P0-2  trust_basis restringido a "bundled_static_material".
        Outros valores → I10ctx.basis = FAIL.

  P0-3  trust_snapshot proibido quando basis é bundled.
        O SDK não expõe o hash; declarar um valor é FAIL.

  P0-4  Duplicate JSON keys rejeitadas via object_pairs_hook
        antes de Pydantic/canonicalização.

  P0-5  P0b sempre emitido (PASS se sem restrição externa).

  P1    Mutation tests chamam funções de produção:
        parse_and_validate, check_trust_policy_binding,
        check_trust_context, enforce_release.

  P1    Correcção do JSON de teste (hashes literais válidos).

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
from datetime import datetime
from pathlib import Path
from typing import Optional

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

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
NOT_CHECKED = "NOT_CHECKED"

SCHEMA_VERSION = "1.1"
MMR_VERSION = "aegis-mmr-inclusion-v1"
MMR_ALGORITHM = "sha256-asciihex"

TRUST_POLICY_INTEGRITY_ONLY = "integrity_only"
TRUST_POLICY_SIGNER_TRUSTED = "signer_trusted"
VALID_TRUST_POLICIES = {TRUST_POLICY_INTEGRITY_ONLY, TRUST_POLICY_SIGNER_TRUSTED}
ACCEPTED_TRUST_STATUSES = {"trusted"}
ACCEPTED_TRUST_BASIS = "bundled_static_material"

DEFAULT_CONFIDENCE_ALPHA = 0.05
DEFAULT_MAX_FPR = 0.05

CONTENT_FIELDS = {
    "1.1": [
        "schema_version",
        "generated_at",
        "target_a",
        "target_b",
        "similarity",
        "manifest",
        "script_sha256",
        "trust_policy",
        "trust_context",
    ],
}
KNOWN_SCHEMAS = set(CONTENT_FIELDS.keys())

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(v):
    return isinstance(v, str) and HEX64_RE.match(v) is not None


def _h_ascii(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()


def canonical_bytes(obj) -> bytes:
    if rfc8785 is not None:
        return rfc8785.dumps(obj)
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


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


def leaf_to_mountain(leaf_index: int, leaf_count: int):
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
                lines.append(f"      {c.detail}")
        return "\n".join(lines)


# ────────────────────────────────────────────────────────────
# Schema Pydantic (1.1)
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
        direction: str
        sibling_hash: str

        @field_validator("direction")
        @classmethod
        def direction_valid(cls, v):
            if v not in ("L", "R"):
                raise ValueError("direction L/R")
            return v

        @field_validator("sibling_hash")
        @classmethod
        def sibling_hex64(cls, v):
            if not _is_hex64(v):
                raise ValueError("sibling_hash hex64")
            return v

    class ValidationItem(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        label: str
        score: float
        pair_id: str
        sha256_a: str
        sha256_b: str
        name: Optional[str] = None

        @field_validator("label")
        @classmethod
        def label_valid(cls, v):
            if v not in ("positive", "negative"):
                raise ValueError("label positive/negative")
            return v

        @field_validator("score")
        @classmethod
        def score_finite_unit(cls, v):
            if isinstance(v, bool):
                raise ValueError("score não pode ser bool")
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

    class C2PAEntry(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        integrity: str
        signature: str
        hard_binding: str
        trust: Optional[str] = None

    class C2PAModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        a: C2PAEntry
        b: C2PAEntry

    class TrustContext(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        verifier: str
        verifier_version: str
        trust_basis: str
        trust_snapshot: Optional[str] = None

    class CalibrationModel(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        threshold: float
        confidence_alpha: float = DEFAULT_CONFIDENCE_ALPHA
        max_fpr: float = DEFAULT_MAX_FPR
        tau: float = 0.0
        val_scores: list[ValidationItem] = Field(default_factory=list)
        n_negatives: int = 0
        tp: int = 0
        fp: int = 0
        tn: int = 0
        fn: int = 0
        calibration_valid: bool = False
        alpha_guaranteed: bool = False
        decision: Optional[str] = None

        @field_validator("confidence_alpha")
        @classmethod
        def alpha_open_unit(cls, v):
            if not (0.0 < v < 1.0):
                raise ValueError("confidence_alpha em (0,1)")
            return v

        @field_validator("max_fpr")
        @classmethod
        def max_fpr_range(cls, v):
            if not (0.0 <= v < 1.0):
                raise ValueError("max_fpr em [0,1)")
            return v

        @field_validator("threshold")
        @classmethod
        def threshold_unit(cls, v):
            if isinstance(v, bool) or not math.isfinite(v) or not (0.0 <= v <= 1.0):
                raise ValueError("threshold em [0,1]")
            return v

        @field_validator("tau")
        @classmethod
        def tau_unit(cls, v):
            if isinstance(v, bool) or not math.isfinite(v) or not (0.0 <= v <= 1.0):
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
            if isinstance(v, bool) or not math.isfinite(v):
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
        c2pa: Optional[C2PAModel] = None
        manifest: dict
        script_sha256: str
        content_hash: Optional[str] = None
        envelope_hash: Optional[str] = None
        trust_policy: str
        trust_context: TrustContext

        @field_validator("schema_version")
        @classmethod
        def known_schema(cls, v):
            if v not in KNOWN_SCHEMAS:
                raise ValueError(f"schema_version não suportado: {v}")
            return v

        @field_validator("trust_policy")
        @classmethod
        def trust_policy_valid(cls, v):
            if v not in VALID_TRUST_POLICIES:
                raise ValueError(f"trust_policy inválido: {v}")
            return v

        @field_validator("generated_at")
        @classmethod
        def tz_aware(cls, v):
            if not v.endswith("Z") and "+" not in v and "-" not in v[10:]:
                raise ValueError("generated_at sem timezone")
            return v

else:
    Peak = PathStep = ValidationItem = C2PAEntry = C2PAModel = None
    TrustContext = None
    TargetModel = AnchorModel = CalibrationModel = None
    MelodicModel = SimilarityModel = LedgerModel = None


# ────────────────────────────────────────────────────────────
# Parse (com rejeição de chaves duplicadas)
# ────────────────────────────────────────────────────────────

def _reject_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"chave JSON duplicada: {key!r}")
        seen[key] = value
    return seen


def parse_and_validate(data, result):
    try:
        raw = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as e:
        result.add(Check("PARSE", "JSON válido", FAIL, str(e), "hard"))
        return None, None
    except ValueError as e:
        result.add(Check("PARSE", "JSON sem duplicatas", FAIL, str(e), "hard"))
        return None, None

    if not isinstance(raw, dict):
        result.add(Check("PARSE", "Raiz é objeto", FAIL, "não é dict", "hard"))
        return None, None

    if not PYDANTIC_AVAILABLE:
        result.add(Check("SCHEMA", "pydantic", FAIL, "pip install pydantic", "hard"))
        return None, None

    if "schema_version" not in raw:
        result.add(Check("SCHEMA", "schema_version", FAIL,
                         "obrigatório no JSON cru", "hard"))
        return raw, None

    sv = raw.get("schema_version")
    if sv not in KNOWN_SCHEMAS:
        result.add(Check("SCHEMA", "schema_version suportado", FAIL,
                         f"{sv} não suportado; aceites {sorted(KNOWN_SCHEMAS)}",
                         "hard"))
        return raw, None

    try:
        ledger = LedgerModel(**raw)
        result.add(Check("SCHEMA", "Schema válido", PASS, "todos os campos", "hard"))
        return raw, ledger
    except ValidationError as e:
        result.add(Check("SCHEMA", "Schema válido", FAIL, str(e), "hard"))
        return raw, None


# ────────────────────────────────────────────────────────────
# Utilitários
# ────────────────────────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ────────────────────────────────────────────────────────────
# P0a/P0b — trust policy binding
# ────────────────────────────────────────────────────────────

def check_trust_policy_binding(result, ledger, require_policy):
    effective = ledger.trust_policy
    result.add(Check("P0a", "trust_policy comprometido", PASS,
                     f"efectivo={effective}", "hard"))

    if require_policy is None:
        result.add(Check("P0b", "restrição externa de trust policy", PASS,
                         "nenhuma restrição adicional solicitada", "hard"))
    elif require_policy != effective:
        result.add(Check("P0b", "restrição externa de trust policy", FAIL,
                         f"exigido={require_policy} ≠ artefacto={effective}",
                         "hard"))
    else:
        result.add(Check("P0b", "restrição externa de trust policy", PASS,
                         f"exigido={require_policy} == artefacto", "hard"))


# ────────────────────────────────────────────────────────────
# I1 — Áudio
# ────────────────────────────────────────────────────────────

def check_audio_binding(result, ledger, audio_a, audio_b, mode):
    if audio_a is None or not audio_a.exists():
        result.add(Check("I1a", "Audio A existe", FAIL,
                         f"não encontrado: {audio_a}", "hard"))
        return
    if audio_b is None or not audio_b.exists():
        result.add(Check("I1b", "Audio B existe", FAIL,
                         f"não encontrado: {audio_b}", "hard"))
        return

    aa = sha256_file(audio_a)
    ab = sha256_file(audio_b)
    result.add(Check("I1a", "Audio A SHA-256",
                     PASS if aa == ledger.target_a.sha256 else FAIL,
                     aa[:16] + "…", "hard"))
    result.add(Check("I1b", "Audio B SHA-256",
                     PASS if ab == ledger.target_b.sha256 else FAIL,
                     ab[:16] + "…", "hard"))


# ────────────────────────────────────────────────────────────
# I2/I3 — content_hash
# ────────────────────────────────────────────────────────────

def compute_content_hash(ledger):
    raw = ledger.model_dump()
    covered = {}
    for k in CONTENT_FIELDS[ledger.schema_version]:
        if k not in raw or raw[k] is None:
            raise ValueError(f"campo coberto ausente: {k}")
        covered[k] = raw[k]
    return canonical_sha256(covered)


def compute_envelope_hash(content_hash, anchor, c2pa, trust_policy, trust_context):
    envelope = {
        "content_hash": content_hash,
        "anchor": anchor,
        "c2pa": c2pa,
        "trust_policy": trust_policy,
        "trust_context": trust_context,
    }
    return canonical_sha256(envelope)


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
# I4 — tx_signature
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
        result.add(Check("I4", "tx_signature 64 bytes", FAIL,
                         f"{len(decoded)} bytes", "hard"))


# ────────────────────────────────────────────────────────────
# I5/I6/I7 — Solana
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


def _parse_iso(ts):
    if not ts:
        return None
    s = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError("timestamp naïve")
    return dt


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
            gdt = _parse_iso(gen)
            gts = int(gdt.timestamp())
            if block_time >= gts:
                result.add(Check("I7", "blockTime", PASS,
                                 f"{block_time} >= {gts}", "hard"))
                result.block_time = block_time
            else:
                result.add(Check("I7", "blockTime", FAIL,
                                 f"{block_time} < {gts}", "hard"))
        except Exception as e:
            result.add(Check("I7", "parse", FAIL, str(e), "hard"))
    else:
        result.add(Check("I7", "blockTime", NOT_CHECKED, "sem dados", "external"))


# ────────────────────────────────────────────────────────────
# I8 — MMR
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

def check_c2pa(result, ledger, c2pa_a, c2pa_b, mode):
    effective_policy = ledger.trust_policy

    if mode == "release":
        if c2pa_verify is None:
            result.add(Check("I10vA", "C2PA verify disponível", FAIL,
                             "encypher-c2pa não instalado", "hard"))
            result.add(Check("I10vB", "C2PA verify disponível", FAIL,
                             "encypher-c2pa não instalado", "hard"))
            return

        paths = {"A": c2pa_a, "B": c2pa_b}
        verified = {}
        for suffix in ("A", "B"):
            path = paths[suffix]
            if not path or not path.exists():
                result.add(Check(f"I10v{suffix}", f"C2PA verificado {suffix}",
                                 FAIL, "ficheiro ausente em release", "hard"))
                continue
            try:
                rep = c2pa_verify(str(path))
                integrity = rep.get("integrity")
                signature = rep.get("signature")
                hard_binding = rep.get("hard_binding")
                trust = rep.get("trust", {}).get("status")

                base_ok = (integrity == "valid"
                           and signature == "valid"
                           and hard_binding == "match")

                if effective_policy == TRUST_POLICY_SIGNER_TRUSTED:
                    trust_ok = trust in ACCEPTED_TRUST_STATUSES
                    ok = base_ok and trust_ok
                else:
                    ok = base_ok

                detail = (f"integrity={integrity} signature={signature} "
                          f"hard_binding={hard_binding} trust={trust} "
                          f"policy={effective_policy}")

                verified[suffix] = {
                    "integrity": integrity,
                    "signature": signature,
                    "hard_binding": hard_binding,
                    "trust": trust,
                }
                result.add(Check(f"I10v{suffix}", f"C2PA verificado {suffix}",
                                 PASS if ok else FAIL, detail,
                                 "external" if ok else "hard"))
            except Exception as e:
                result.add(Check(f"I10v{suffix}", f"C2PA verificado {suffix}",
                                 FAIL, str(e), "external"))

        if ledger.c2pa and len(verified) == 2:
            declared = {
                "A": {
                    "integrity": ledger.c2pa.a.integrity,
                    "signature": ledger.c2pa.a.signature,
                    "hard_binding": ledger.c2pa.a.hard_binding,
                    "trust": ledger.c2pa.a.trust,
                },
                "B": {
                    "integrity": ledger.c2pa.b.integrity,
                    "signature": ledger.c2pa.b.signature,
                    "hard_binding": ledger.c2pa.b.hard_binding,
                    "trust": ledger.c2pa.b.trust,
                },
            }
            if declared != verified:
                result.add(Check("I10c", "C2PA declared == verified", FAIL,
                                 f"declarado {declared} ≠ verificado {verified}",
                                 "hard"))
            else:
                result.add(Check("I10c", "C2PA declared == verified", PASS,
                                 "consistente", "hard"))
        elif ledger.c2pa:
            result.add(Check("I10c", "C2PA declared == verified", NOT_CHECKED,
                             "verificação incompleta", "external"))
        else:
            result.add(Check("I10c", "C2PA declared == verified", FAIL,
                             "bloco c2pa ausente no relatório", "hard"))
        return

    if ledger.c2pa:
        for suffix in ("A", "B"):
            entry = getattr(ledger.c2pa, suffix.lower())
            base_ok = (entry.integrity == "valid"
                       and entry.signature == "valid"
                       and entry.hard_binding == "match")
            if effective_policy == TRUST_POLICY_SIGNER_TRUSTED:
                ok = base_ok and (entry.trust in ACCEPTED_TRUST_STATUSES)
            else:
                ok = base_ok
            result.add(Check(f"I10d{suffix}", f"C2PA declarado {suffix}",
                             PASS if ok else FAIL,
                             f"trust={entry.trust} policy={effective_policy}",
                             "external" if ok else "hard"))
    else:
        result.add(Check("I10dA", "C2PA declarado A", NOT_CHECKED,
                         "sem bloco c2pa", "external"))
        result.add(Check("I10dB", "C2PA declarado B", NOT_CHECKED,
                         "sem bloco c2pa", "external"))


# ────────────────────────────────────────────────────────────
# I10ctx — trust context binding
# ────────────────────────────────────────────────────────────

def check_trust_context(result, ledger, mode):
    if mode != "release":
        result.add(Check("I10ctx", "trust_context binding", NOT_CHECKED,
                         "verificação apenas em release", "external"))
        return

    if c2pa_verify is None:
        result.add(Check("I10ctx", "trust_context binding", FAIL,
                         "c2pa_verify indisponível", "hard"))
        return

    ctx = ledger.trust_context

    module_name = getattr(c2pa_verify, "__module__", "").split(".")[0]
    accepted_names = {"encypher_c2pa", "encypher-c2pa"}
    if ctx.verifier not in accepted_names and ctx.verifier != module_name:
        result.add(Check("I10ctx.verifier", "verifier declarado", FAIL,
                         f"declarado={ctx.verifier} módulo={module_name}",
                         "hard"))
        return

    try:
        from importlib.metadata import version as _pkg_version
        installed_version = _pkg_version("encypher-c2pa")
    except Exception:
        installed_version = None

    if installed_version is None:
        result.add(Check("I10ctx.version", "verifier_version", FAIL,
                         "versão instalada indeterminada", "hard"))
        return
    if ctx.verifier_version != installed_version:
        result.add(Check("I10ctx.version", "verifier_version", FAIL,
                         f"declarado={ctx.verifier_version} "
                         f"instalado={installed_version}", "hard"))
        return

    if ctx.trust_basis != ACCEPTED_TRUST_BASIS:
        result.add(Check("I10ctx.basis", "trust_basis", FAIL,
                         f"declarado={ctx.trust_basis} "
                         f"aceite={ACCEPTED_TRUST_BASIS}", "hard"))
        return

    if ctx.trust_snapshot is not None:
        result.add(Check("I10ctx.snapshot", "trust_snapshot", FAIL,
                         "SDK bundled não expõe snapshot; declarar é proibido",
                         "hard"))
        return

    result.add(Check("I10ctx", "trust_context binding", PASS,
                     f"verifier={ctx.verifier} version={installed_version} "
                     f"basis={ctx.trust_basis}", "hard"))


# ────────────────────────────────────────────────────────────
# I11 — Calibração
# ────────────────────────────────────────────────────────────

def clopper_pearson_upper(fp, n, confidence_alpha):
    if n == 0:
        return None
    if fp == 0:
        return 1.0 - confidence_alpha ** (1.0 / n)
    if fp == n:
        return 1.0
    if not SCIPY_AVAILABLE:
        return None
    return float(scipy_beta.ppf(1.0 - confidence_alpha, fp + 1, n - fp))


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
    result.add(Check("I11", "Métricas", PASS,
                     f"tp={tp} fp={fp} tn={tn} fn={fn}", "hard"))

    if cal.n_negatives != n_neg:
        result.add(Check("I11c", "n_negatives", FAIL,
                         f"{cal.n_negatives} ≠ {n_neg}", "hard"))
    else:
        result.add(Check("I11c", "n_negatives", PASS, str(n_neg), "hard"))

    upper = clopper_pearson_upper(fp, n_neg, cal.confidence_alpha)
    if upper is None:
        result.add(Check("I11b", "Clopper-Pearson", FAIL,
                         "FP>0 e SciPy ausente", "hard"))
    elif upper <= cal.max_fpr:
        result.add(Check("I11b", "FPR upper bound", PASS,
                         f"CP({fp}/{n_neg}, {cal.confidence_alpha}) = {upper:.4f} "
                         f"<= {cal.max_fpr}", "hard"))
    else:
        result.add(Check("I11b", "FPR upper bound", FAIL,
                         f"CP({fp}/{n_neg}, {cal.confidence_alpha}) = {upper:.4f} "
                         f"> {cal.max_fpr}", "hard"))

    tpr = tp / n_pos if n_pos > 0 else 0.0
    if mode == "release":
        if n_pos == 0:
            result.add(Check("I11d", "n_pos > 0", FAIL,
                             "release exige positivos", "hard"))
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
# I12 — Separação
# ────────────────────────────────────────────────────────────

def check_calibration_leakage(result, ledger):
    melodic = ledger.similarity.melodic if ledger.similarity else None
    if not melodic or not melodic.calibration:
        result.add(Check("I12", "Separação", NOT_CHECKED, "sem calibração", "external"))
        return

    targets = {ledger.target_a.sha256, ledger.target_b.sha256}
    seen_pair_ids = set()
    overlap = set()

    for v in melodic.calibration.val_scores:
        if v.pair_id in seen_pair_ids:
            result.add(Check("I12", "pair_id único", FAIL,
                             f"duplicado: {v.pair_id[:16]}…", "hard"))
            return
        seen_pair_ids.add(v.pair_id)

        try:
            expected = pair_id_canonical(v.sha256_a, v.sha256_b)
        except ValueError as e:
            result.add(Check("I12", "pair_id derivado", FAIL, str(e), "hard"))
            return
        if v.pair_id != expected:
            result.add(Check("I12", "pair_id derivado", FAIL,
                             f"{v.pair_id[:16]}… ≠ {expected[:16]}…", "hard"))
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
# I13/I14/I15
# ────────────────────────────────────────────────────────────

def check_required_fields(result, ledger):
    raw = ledger.model_dump()
    missing = [k for k in CONTENT_FIELDS[ledger.schema_version]
               if k not in raw or raw[k] is None]
    if missing:
        result.add(Check("I13", "Campos obrigatórios", FAIL, str(missing), "hard"))
    else:
        result.add(Check("I13", "Campos obrigatórios", PASS, "todos", "hard"))


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
            env = compute_envelope_hash(
                result.content_hash,
                a.model_dump(),
                ledger.c2pa.model_dump() if ledger.c2pa else None,
                ledger.trust_policy,
                ledger.trust_context.model_dump() if ledger.trust_context else None,
            )
            result.add(Check("I15b", "envelope_hash",
                             PASS if env == ledger.envelope_hash else FAIL,
                             env[:16] + "…", "hard"))
        except Exception as e:
            result.add(Check("I15b", "envelope_hash", FAIL, str(e), "hard"))
    else:
        result.add(Check("I15b", "envelope_hash", NOT_CHECKED, "ausente", "external"))


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
# Raw-wire audit
# ────────────────────────────────────────────────────────────

def audit_raw_wire(result, raw):
    if not raw:
        return
    anchor = raw.get("anchor", {})
    for f in ["mmr_version", "mmr_algorithm", "leaf_index", "leaf_count",
              "peak_index", "peaks", "path"]:
        if f not in anchor:
            result.add(Check(f"W.{f}", f"wire {f}", FAIL,
                             "ausente no JSON cru", "hard"))
    for f in ["trust_policy", "trust_context"]:
        if f not in raw:
            result.add(Check(f"W.{f}", f"wire {f}", FAIL,
                             "ausente no JSON cru", "hard"))
    if "c2pa" not in raw:
        result.add(Check("W.c2pa", "wire c2pa", FAIL,
                         "bloco ausente no JSON cru", "hard"))


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


def gv_trust_policy_binding():
    policy_a = {"trust_policy": "signer_trusted"}
    policy_b = {"trust_policy": "integrity_only"}
    assert canonical_sha256(policy_a) != canonical_sha256(policy_b)
    return True


def gv_duplicate_keys_rejected_production():
    a = "a" * 64
    b = "b" * 64
    payload = (
        '{"schema_version":"1.1",'
        '"generated_at":"2026-10-11T00:00:00Z",'
        '"content_hash":"' + a + '",'
        '"content_hash":"' + b + '"}'
    ).encode()

    result = PreflightResult()
    raw, ledger = parse_and_validate(payload, result)

    if ledger is not None:
        raise AssertionError("duplicata foi aceite")

    parses = [c for c in result.checks if c.id == "PARSE"]
    if not parses:
        raise AssertionError("sem check PARSE")
    if "duplic" not in parses[0].detail.lower():
        raise AssertionError(
            f"falha não veio do hook de duplicatas: {parses[0].detail}"
        )
    return True


def gv_p0b_optional_uses_production():
    class _Ledger:
        trust_policy = "signer_trusted"

    result = PreflightResult()
    check_trust_policy_binding(result, _Ledger(), None)

    p0a = [c for c in result.checks if c.id == "P0a"]
    p0b = [c for c in result.checks if c.id == "P0b"]

    if not p0a or p0a[0].result != PASS:
        raise AssertionError("P0a não PASS")
    if not p0b or p0b[0].result != PASS:
        raise AssertionError("P0b ausente ou não PASS")
    return True


def gv_p0b_restriction_enforced():
    class _Ledger:
        trust_policy = "signer_trusted"

    result = PreflightResult()
    check_trust_policy_binding(result, _Ledger(), "integrity_only")

    p0b = [c for c in result.checks if c.id == "P0b"]
    if not p0b or p0b[0].result != FAIL:
        raise AssertionError("P0b deveria falhar com restrição divergente")
    return True


def gv_enforce_release_requires_p0b():
    result = PreflightResult()
    result.add(Check("P0a", "trust_policy", PASS, "", "hard"))
    ok, issues = enforce_release(result)
    if ok:
        raise AssertionError("enforce_release aprovou sem P0b")
    if not any("P0" in i for i in issues):
        raise AssertionError(f"P0 não listado em issues: {issues}")
    return True


def gv_trust_context_version_unknown_fails():
    import importlib.metadata

    original = importlib.metadata.version

    def _fail(name):
        raise importlib.metadata.PackageNotFoundError(name)

    global c2pa_verify
    saved_verify = c2pa_verify

    class _FakeVerify:
        __module__ = "encypher_c2pa"

    c2pa_verify = _FakeVerify()
    importlib.metadata.version = _fail
    try:
        class _Ctx:
            verifier = "encypher-c2pa"
            verifier_version = "1.0.0"
            trust_basis = "bundled_static_material"
            trust_snapshot = None

        class _Ledger:
            trust_context = _Ctx()

        result = PreflightResult()
        check_trust_context(result, _Ledger(), "release")
        ver = [c for c in result.checks if c.id == "I10ctx.version"]
        if not ver or ver[0].result != FAIL:
            raise AssertionError("versão indeterminada deveria falhar")
    finally:
        importlib.metadata.version = original
        c2pa_verify = saved_verify
    return True


def gv_trust_context_basis_restricted():
    import importlib.metadata

    global c2pa_verify
    saved_verify = c2pa_verify

    class _FakeVerify:
        __module__ = "encypher_c2pa"

    c2pa_verify = _FakeVerify()

    original = importlib.metadata.version

    def _ver(name):
        return "0.0.0"

    importlib.metadata.version = _ver
    try:
        class _Ctx:
            verifier = "encypher-c2pa"
            verifier_version = "0.0.0"
            trust_basis = "arkhe-private-bundle"
            trust_snapshot = None

        class _Ledger:
            trust_context = _Ctx()

        result = PreflightResult()
        check_trust_context(result, _Ledger(), "release")
        basis = [c for c in result.checks if c.id == "I10ctx.basis"]
        if not basis or basis[0].result != FAIL:
            raise AssertionError("trust_basis inválido deveria falhar")
    finally:
        importlib.metadata.version = original
        c2pa_verify = saved_verify
    return True


def gv_trust_context_snapshot_forbidden():
    import importlib.metadata

    global c2pa_verify
    saved_verify = c2pa_verify

    class _FakeVerify:
        __module__ = "encypher_c2pa"

    c2pa_verify = _FakeVerify()

    original = importlib.metadata.version

    def _ver(name):
        return "0.0.0"

    importlib.metadata.version = _ver
    try:
        class _Ctx:
            verifier = "encypher-c2pa"
            verifier_version = "0.0.0"
            trust_basis = "bundled_static_material"
            trust_snapshot = "2026-10-11"    # proibido

        class _Ledger:
            trust_context = _Ctx()

        result = PreflightResult()
        check_trust_context(result, _Ledger(), "release")
        snap = [c for c in result.checks if c.id == "I10ctx.snapshot"]
        if not snap or snap[0].result != FAIL:
            raise AssertionError("trust_snapshot bundled deveria falhar")
    finally:
        importlib.metadata.version = original
        c2pa_verify = saved_verify
    return True


def gv_trust_context_differs_blocks():
    ctx_a = {"verifier": "encypher-c2pa", "verifier_version": "1.0.0",
             "trust_basis": "bundled_static_material", "trust_snapshot": None}
    ctx_b = {"verifier": "encypher-c2pa", "verifier_version": "1.0.1",
             "trust_basis": "bundled_static_material", "trust_snapshot": None}
    return canonical_sha256(ctx_a) != canonical_sha256(ctx_b)


def run_selftest():
    tests = [
        ("single_leaf", gv_single_leaf),
        ("two_leaves", gv_two_leaves),
        ("three_leaves", gv_three_leaves),
        ("four_leaves", gv_four_leaves),
        ("bagging_single_peak_not_identity", gv_bagging_single_peak_not_identity),
        ("wrong_direction_load_bearing", gv_wrong_direction_load_bearing),
        ("pair_id_symmetric", gv_pair_id_symmetric),
        ("trust_policy_binding", gv_trust_policy_binding),
        ("duplicate_keys_rejected_production", gv_duplicate_keys_rejected_production),
        ("p0b_optional_uses_production", gv_p0b_optional_uses_production),
        ("p0b_restriction_enforced", gv_p0b_restriction_enforced),
        ("enforce_release_requires_p0b", gv_enforce_release_requires_p0b),
        ("trust_context_version_unknown_fails", gv_trust_context_version_unknown_fails),
        ("trust_context_basis_restricted", gv_trust_context_basis_restricted),
        ("trust_context_snapshot_forbidden", gv_trust_context_snapshot_forbidden),
        ("trust_context_differs_blocks", gv_trust_context_differs_blocks),
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
    "I10": ("ALL", ["I10vA", "I10vB", "I10c", "I10ctx"]),
    "I11": ("ALL", ["I11", "I11b", "I11c", "I11d"]),
    "I12": ("ANY", ["I12"]),
    "I13": ("ANY", ["I13"]),
    "I14": ("ANY", ["I14"]),
    "I15": ("ALL", ["I15a", "I15b"]),
    "P0":  ("ALL", ["P0a", "P0b"]),
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

def run_checks(result, raw, ledger, args):
    check_required_fields(result, ledger)
    check_covered_fields(result, ledger)
    check_trust_policy_binding(result, ledger, args.require_trust_policy)
    check_audio_binding(result, ledger, args.audio_a, args.audio_b, args.mode)
    check_report_hash(result, ledger)
    check_signature_format(result, ledger)
    check_did(result, ledger)
    check_calibration(result, ledger, args.mode)
    check_calibration_leakage(result, ledger)
    check_solana_anchor(result, ledger, args.rpc, args.online)
    check_mmr(result, ledger)
    check_c2pa(result, ledger, args.c2pa_a, args.c2pa_b, args.mode)
    check_trust_context(result, ledger, args.mode)
    check_script_hash(result, ledger)
    check_derived_hashes(result, ledger)
    check_heuristics(result, ledger)
    audit_raw_wire(result, raw)


def main():
    parser = argparse.ArgumentParser(description="Arkhe Preflight v23")
    parser.add_argument("report", type=Path, nargs="?")
    parser.add_argument("--audio-a", type=Path)
    parser.add_argument("--audio-b", type=Path)
    parser.add_argument("--c2pa-a", type=Path)
    parser.add_argument("--c2pa-b", type=Path)
    parser.add_argument("--mode", choices=["sanity", "release"], default="sanity")
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--rpc", default="https://api.devnet.solana.com")
    parser.add_argument("--require-trust-policy",
                        choices=sorted(VALID_TRUST_POLICIES),
                        default=None,
                        help="Restrição: exige que o artefacto comprometa "
                             "esta política")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.selftest and not args.report:
        results = run_selftest()
        print("═" * 70)
        print("ARKHE PREFLIGHT v23 — Golden Vectors")
        print("═" * 70)
        ok = True
        passed = 0
        for name, res, detail in results:
            icon = "✓" if res == PASS else "✗"
            print(f"  {icon} {name}: {res}")
            if detail:
                print(f"      {detail}")
            if res != PASS:
                ok = False
            else:
                passed += 1
        print()
        print(f"RESULTADO: {'✓ PASS' if ok else '✗ FAIL'} "
              f"({passed}/{len(results)})")
        return 0 if ok else 1

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
        parser.error("report é obrigatório (ou usa --selftest)")

    result = PreflightResult()

    if not args.report.exists():
        print(f"✗ FAIL: ficheiro não encontrado: {args.report}", file=sys.stderr)
        return 2

    raw, ledger = parse_and_validate(args.report.read_bytes(), result)
    if ledger is None:
        print("═" * 70)
        print("ARKHE PREFLIGHT v23")
        print("═" * 70)
        print(result.summary())
        return 1

    run_checks(result, raw, ledger, args)

    print("═" * 70)
    print(f"ARKHE PREFLIGHT v23 — MODO {args.mode.upper()}")
    print("═" * 70)
    print(f"Online: {args.online}")
    if args.require_trust_policy:
        print(f"require-trust-policy: {args.require_trust_policy}")
    print(f"trust_policy (artefacto): {ledger.trust_policy}")
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
    print(f"RESULTADO: ✓ PASS ({args.mode})")
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
