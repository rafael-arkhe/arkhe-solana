#!/usr/bin/env python3
"""
arkhe_melodic_pipeline.py — Pipeline de autoria e similaridade melódica.
Caso: Ben Jor × Rod Stewart.

Versão 10 · 10 out 2026
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from typing import Optional

import requests

# ────────────────────────────────────────────────────────────
# Bibliotecas específicas (importadas com tratamento de erro)
# ────────────────────────────────────────────────────────────

try:
    import acoustid
except ImportError:
    acoustid = None

try:
    import musicbrainzngs
    musicbrainzngs.set_useragent(
        "ArkhePipeline", "1.0", "https://arkhe.dev"
    )
except ImportError:
    musicbrainzngs = None

try:
    from clapback_embed import embed_file as clap_embed_file
    from clapback_embed import PIPELINE_VERSION as CLAP_PIPELINE_VERSION
except ImportError:
    clap_embed_file = None
    CLAP_PIPELINE_VERSION = "unavailable"

try:
    from music21 import converter as m21_converter
    from music21 import stream as m21_stream
    from music21 import note as m21_note
    from music21 import chord as m21_chord
    from music21 import interval as m21_interval
except ImportError:
    m21_converter = None

# ────────────────────────────────────────────────────────────
# Configuração
# ────────────────────────────────────────────────────────────

CONFIG = {
    "acoustid_api_key": os.getenv("ACOUSTID_API_KEY", ""),
    "acrcloud_host": os.getenv("ACRCLOUD_HOST", ""),
    "acrcloud_access_key": os.getenv("ACRCLOUD_ACCESS_KEY", ""),
    "acrcloud_access_secret": os.getenv("ACRCLOUD_ACCESS_SECRET", ""),
    "deezer_base": "https://api.deezer.com",
    "cache_db": os.getenv("ARKHE_CACHE_DB", "arkhe_cache.sqlite"),
    "min_acoustid_score": 0.9,
    "min_similarity_score": 0.5,
    "http_timeout": 15,
    "retry_max_attempts": 5,
    "retry_backoff_base": 1.5,
    "demucs_timeout": 600,
    "basic_pitch_timeout": 300,
    "calibration_fraction": 0.5,
}

log = logging.getLogger("arkhe")


# ────────────────────────────────────────────────────────────
# Utilitários
# ────────────────────────────────────────────────────────────

def canonical(obj) -> str:
    """Serialização canónica (RFC 8785 simplificado)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ────────────────────────────────────────────────────────────
# Cache SQLite
# ────────────────────────────────────────────────────────────

class ContentCache:
    """Cache endereçado por hash de conteúdo."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(self.SCHEMA)
        self.conn.commit()

    def get(self, key: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT value FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def set(self, key: str, value: dict):
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (key, value, created_at) VALUES (?, ?, ?)",
            (key, canonical(value), datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    @staticmethod
    def hash_file(path: Path) -> str:
        return sha256_file(path)

    @staticmethod
    def hash_text(text: str) -> str:
        return sha256_text(text)

    def close(self):
        self.conn.close()


# ────────────────────────────────────────────────────────────
# Rate limiter com retry transitório
# ────────────────────────────────────────────────────────────

class RateLimiter:
    """Limitador centralizado por host com retry exponencial."""

    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self._last_call = {}

    def wait(self, host: str):
        now = time.time()
        last = self._last_call.get(host, 0)
        delta = now - last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last_call[host] = time.time()

    def retry(self, fn, host: str, max_attempts: int = None):
        """Executa fn com retry em erros transitórios."""
        max_attempts = max_attempts or CONFIG["retry_max_attempts"]
        last_exc = None

        for attempt in range(max_attempts):
            self.wait(host)
            try:
                return fn()
            except requests.exceptions.RequestException as e:
                # Correção v10: Response 4xx/5xx é falsy
                retry_after = None
                if e.response is not None:
                    retry_after = e.response.headers.get("Retry-After")
                if retry_after:
                    time.sleep(float(retry_after))
                last_exc = e
            except Exception as e:
                # Captura MusicBrainzError, AcoustidError, etc.
                exc_name = type(e).__name__
                if exc_name in ("NetworkError", "MusicBrainzError",
                                "AcoustidError", "AcoustidAPIError"):
                    last_exc = e
                else:
                    raise

            sleep_time = CONFIG["retry_backoff_base"] ** attempt
            log.warning("Retry %d/%d para %s após %.1fs: %s",
                        attempt + 1, max_attempts, host, sleep_time, last_exc)
            time.sleep(sleep_time)

        raise RuntimeError(f"Falha após {max_attempts} tentativas: {last_exc}")


LIMITER = RateLimiter(min_interval=1.0)

def _http_get(url: str, timeout: int = None):
    """GET que levanta HTTPError em 4xx/5xx."""
    resp = requests.get(url, timeout=timeout or CONFIG["http_timeout"])
    resp.raise_for_status()
    return resp

# ────────────────────────────────────────────────────────────
# Estágio 1 — MusicBrainz
# ────────────────────────────────────────────────────────────

@dataclass
class RecordingInfo:
    mbid: str
    title: str
    artist: str
    isrcs: list = field(default_factory=list)
    iswcs: list = field(default_factory=list)
    composers: list = field(default_factory=list)
    release_date: Optional[str] = None


def resolve_musicbrainz(
    title: str,
    artist: str,
    year: Optional[int] = None,
    cache: Optional[ContentCache] = None,
) -> RecordingInfo:
    """Resolve uma gravação no MusicBrainz por título e artista."""
    if musicbrainzngs is None:
        raise RuntimeError("musicbrainzngs não instalado")

    cache_key = f"mb:{title.lower()}:{artist.lower()}:{year or ''}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return RecordingInfo(**cached)

    # Busca com filtro de artista
    base_query = f'recording:"{title}" AND artist:"{artist}"'

    queries_to_try = []
    if year:
        queries_to_try.append(base_query + f" AND date:{year}")
        queries_to_try.append(base_query + f" AND firstreleasedate:{year}")
    queries_to_try.append(base_query)

    recordings = []
    for q in queries_to_try:
        result = LIMITER.retry(
            lambda: musicbrainzngs.search_recordings(query=q, limit=10),
            "musicbrainz",
        )
        recordings = result.get("recording-list", [])
        if recordings:
            break

    if not recordings:
        raise ValueError(f"Nenhuma gravação encontrada: {title} / {artist}")

    # Escolher o melhor resultado (primeiro com score >= 90)
    best = None
    for rec in recordings:
        score = int(rec.get("ext:score", 0))
        if score >= 90:
            best = rec
            break
    if best is None:
        best = recordings[0]

    mbid = best["id"]
    title_found = best.get("title", "")
    artist_found = ""
    for ac in best.get("artist-credit", []):
        if isinstance(ac, dict):
            artist_found = ac.get("artist", {}).get("name", "")
            break

    # Lookup completo com includes corretos
    # Correção v10: work-level-rels em vez de iswcs (iswcs não é válido para work)
    detail = LIMITER.retry(
        lambda: musicbrainzngs.get_recording_by_id(
            mbid, includes=["isrcs", "work-rels", "artist-rels"]
        ),
        "musicbrainz",
    )

    rec_detail = detail.get("recording", {})
    isrcs = []
    for isrc_obj in rec_detail.get("isrc-list", []):
        if isinstance(isrc_obj, dict) and "id" in isrc_obj:
            isrcs.append(isrc_obj["id"])

    # Compositores via work-rels
    composers = []
    works = rec_detail.get("work-relation-list", [])
    for wr in works:
        work = wr.get("work", {})
        # Buscar relações de artista na obra
        for ar in work.get("artist-relation-list", []):
            if ar.get("type") == "composer":
                artist_info = ar.get("artist", {})
                composers.append(artist_info.get("name", ""))

    # ISWC: buscar via work (se disponível)
    iswcs = []
    for wr in works:
        work = wr.get("work", {})
        for iswc_obj in work.get("iswc-list", []):
            if isinstance(iswc_obj, dict):
                iswcs.append(iswc_obj.get("iswc", ""))

    info = RecordingInfo(
        mbid=mbid,
        title=title_found,
        artist=artist_found,
        isrcs=isrcs,
        iswcs=iswcs,
        composers=[c for c in composers if c],
        release_date=best.get("first-release-date"),
    )

    if cache:
        cache.set(cache_key, asdict(info))

    return info


# ────────────────────────────────────────────────────────────
# Estágio 2 — Deezer
# ────────────────────────────────────────────────────────────

def lookup_deezer_isrc(isrc: str, cache: Optional[ContentCache] = None) -> Optional[dict]:
    """Consulta a API do Deezer por ISRC."""
    if not isrc:
        return None

    cache_key = f"deezer:{isrc}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return cached

    url = f"{CONFIG['deezer_base']}/track/isrc:{isrc}"
    try:
        resp = LIMITER.retry(
            lambda: _http_get(url, timeout=CONFIG["http_timeout"]),
            "deezer",
        )
        data = resp.json()
    except Exception as e:
        log.warning("Deezer falhou para %s: %s", isrc, e)
        return None

    if "error" in data:
        log.warning("Deezer erro: %s", data["error"])
        return None

    result = {
        "deezer_id": data.get("id"),
        "title": data.get("title"),
        "artist": data.get("artist", {}).get("name"),
        "album": data.get("album", {}).get("title"),
        "isrc": data.get("isrc"),
    }

    if cache:
        cache.set(cache_key, result)

    return result


# ────────────────────────────────────────────────────────────
# Estágio 3 — AcoustID
# ────────────────────────────────────────────────────────────

@dataclass
class AcoustIDResult:
    fingerprint: str
    duration: float
    recordings: list = field(default_factory=list)


def fingerprint_acoustid(
    audio_path: Path,
    cache: Optional[ContentCache] = None,
) -> AcoustIDResult:
    """Gera fingerprint e faz lookup no AcoustID."""
    if acoustid is None:
        raise RuntimeError("pyacoustid não instalado")

    file_hash = ContentCache.hash_file(audio_path)
    cache_key = f"acoustid:{file_hash}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return AcoustIDResult(**cached)

    # Correção v10: import acoustid (não pyacoustid)
    # fingerprint_file fora do retry (não é rede)
    try:
        duration, fp = acoustid.fingerprint_file(str(audio_path))
    except acoustid.FingerprintGenerationError as e:
        raise RuntimeError(f"Fingerprint falhou: {e}")

    # Correção v10: fp pode ser bytes; decodificar antes de json.dumps
    if isinstance(fp, bytes):
        fp = fp.decode("utf-8", errors="replace")

    # Lookup com retry de rede
    result = LIMITER.retry(
        lambda: acoustid.lookup(
            CONFIG["acoustid_api_key"], fp, duration
        ),
        "acoustid",
    )

    recordings = []
    for rec in result.get("results", []):
        score = rec.get("score", 0)
        for r in rec.get("recordings", []):
            recordings.append({
                "id": r.get("id"),
                "title": r.get("title"),
                "score": score,
                "artists": [
                    a.get("name") for a in r.get("artists", [])
                ],
            })

    out = AcoustIDResult(
        fingerprint=fp,
        duration=duration,
        recordings=recordings,
    )

    if cache:
        cache.set(cache_key, asdict(out))

    return out


def gate_acoustid(
    result: AcoustIDResult,
    expected_mbids: list[str],
    min_score: float = None,
) -> bool:
    """
    Correção v10: retorna False se expected_mbids estiver vazio.
    """
    if not expected_mbids:
        return False

    min_score = min_score or CONFIG["min_acoustid_score"]

    found = {
        rec["id"]
        for rec in result.recordings
        if rec.get("score", 0) >= min_score
    }
    return bool(found & set(expected_mbids))


# ────────────────────────────────────────────────────────────
# Estágio 4 — ACRCloud (apenas Identification)
# ────────────────────────────────────────────────────────────

@dataclass
class ACRCloudResult:
    status: str
    recordings: list = field(default_factory=list)
    error: Optional[str] = None


def acrcloud_identify(
    audio_path: Path,
    cache: Optional[ContentCache] = None,
) -> ACRCloudResult:
    """
    Correção v10: apenas Identification API.
    Parâmetros não enviados removidos do manifesto.
    """
    if not CONFIG["acrcloud_access_key"]:
        return ACRCloudResult(
            status="skipped",
            error="ACRCloud não configurado",
        )

    file_hash = ContentCache.hash_file(audio_path)
    cache_key = f"acrcloud:{file_hash}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return ACRCloudResult(**cached)

    http_method = "POST"
    http_uri = "/v1/identify"
    data_type = "audio"
    signature_version = "1"
    timestamp = str(int(time.time()))

    string_to_sign = (
        http_method + "\n"
        + http_uri + "\n"
        + CONFIG["acrcloud_access_key"] + "\n"
        + data_type + "\n"
        + signature_version + "\n"
        + timestamp
    )

    sign = base64.b64encode(
        hmac.new(
            CONFIG["acrcloud_access_secret"].encode("ascii"),
            string_to_sign.encode("ascii"),
            digestmod=hashlib.sha1,
        ).digest()
    ).decode("ascii")

    with open(audio_path, "rb") as f:
        sample = f.read(1_000_000)  # primeiros 1 MB

    files = [("sample", (audio_path.name, sample, "audio/wav"))]
    data = {
        "access_key": CONFIG["acrcloud_access_key"],
        "sample_bytes": len(sample),
        "timestamp": timestamp,
        "signature": sign,
        "data_type": data_type,
        "signature_version": signature_version,
    }

    def do_acr():
        resp = requests.post(
            f"https://{CONFIG['acrcloud_host']}{http_uri}",
            files=files,
            data=data,
            timeout=CONFIG["http_timeout"],
        )
        resp.raise_for_status()
        return resp

    try:
        resp = LIMITER.retry(
            do_acr,
            "acrcloud",
        )
        result = resp.json()
    except Exception as e:
        return ACRCloudResult(status="error", error=str(e))

    status = result.get("status", {})
    code = status.get("code", -1)

    if code != 0:
        return ACRCloudResult(
            status="error",
            error=status.get("msg", f"code={code}"),
        )

    recordings = []
    for m in result.get("metadata", {}).get("music", []):
        recordings.append({
            "title": m.get("title"),
            "artists": [a.get("name") for a in m.get("artists", [])],
            "score": m.get("score"),
            "acrid": m.get("acrid"),
        })

    out = ACRCloudResult(status="ok", recordings=recordings)
    if cache:
        cache.set(cache_key, asdict(out))

    return out


# ────────────────────────────────────────────────────────────
# Estágio 4b — CLAP
# ────────────────────────────────────────────────────────────

def clap_embed(
    audio_path: Path,
    cache: Optional[ContentCache] = None,
) -> Optional[list]:
    """Gera embedding CLAP de 512 dimensões."""
    if clap_embed_file is None:
        log.warning("clapback-embed não instalado; estágio 4b pulado")
        return None

    # Correção v10: verificar model_dir antes de tentar
    model_dir = os.getenv("CLAPBACK_MODEL_DIR")
    if not model_dir:
        log.warning(
            "CLAPBACK_MODEL_DIR não definida; modelos CLAP não exportados. "
            "Correr: python -m clapback_embed.scripts.export_models"
        )
        return None

    file_hash = ContentCache.hash_file(audio_path)
    cache_key = f"clap:{file_hash}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return cached.get("embedding")

    try:
        vector = clap_embed_file(str(audio_path), model_dir=model_dir)
    except Exception as e:
        log.warning("CLAP falhou: %s", e)
        return None

    if cache:
        cache.set(cache_key, {"embedding": list(vector)})

    return list(vector)


def cosine_similarity(a: list, b: list) -> float:
    """Similaridade de cosseno entre dois vetores L2-normalizados."""
    if not a or not b or len(a) != len(b):
        return 0.0

    # Verificar normalização L2
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    return dot / (norm_a * norm_b)


# ────────────────────────────────────────────────────────────
# Estágio 4b — Similaridade simbólica (Smith-Waterman)
# ────────────────────────────────────────────────────────────

def extract_skyline(score) -> list[int]:
    """
    Correção v10: extrai o contorno monofónico mais agudo (skyline).
    """
    if m21_converter is None:
        return []

    try:
        if isinstance(score, str) or isinstance(score, Path):
            score = m21_converter.parse(str(score))
    except Exception:
        return []

    # Recolher todas as notas por offset
    note_events = []
    for n in score.flatten().notes:
        if isinstance(n, m21_note.Note):
            note_events.append((float(n.offset), int(n.pitch.midi)))
        elif isinstance(n, m21_chord.Chord):
            for p in n.pitches:
                note_events.append((float(n.offset), int(p.midi)))

    if not note_events:
        return []

    note_events.sort(key=lambda x: x[0])

    # Skyline: em cada offset, escolher a nota mais aguda
    skyline = []
    current_offset = None
    current_high = None

    for offset, pitch in note_events:
        if current_offset is None or offset != current_offset:
            if current_high is not None:
                skyline.append(current_high)
            current_offset = offset
            current_high = pitch
        else:
            current_high = max(current_high, pitch)

    if current_high is not None:
        skyline.append(current_high)

    return skyline


def intervals_from_pitches(pitches: list[int]) -> list[int]:
    """Converte pitches em intervalos."""
    return [pitches[i + 1] - pitches[i] for i in range(len(pitches) - 1)]


def smith_waterman(
    a: list[int],
    b: list[int],
    tolerance: int = 1,
) -> tuple[float, int]:
    """
    Correção v10: tolerância ±1 semitom, retorna score e comprimento alinhado.
    """
    if not a or not b:
        return 0.0, 0

    m, n = len(a), len(b)
    # Pontuação: match se |a[i]-b[j]| <= tolerance
    match_score = 2
    mismatch_score = -1
    gap_score = -1

    # Algoritmo Smith-Waterman (O(m*n))
    H = [[0] * (n + 1) for _ in range(m + 1)]
    max_score = 0
    max_len = 0
    len_matrix = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if abs(a[i - 1] - b[j - 1]) <= tolerance:
                diag = H[i - 1][j - 1] + match_score
                diag_len = len_matrix[i - 1][j - 1] + 1
            else:
                diag = H[i - 1][j - 1] + mismatch_score
                diag_len = len_matrix[i - 1][j - 1] + 1

            up = H[i - 1][j] + gap_score
            left = H[i][j - 1] + gap_score

            H[i][j] = max(0, diag, up, left)

            if H[i][j] == 0:
                len_matrix[i][j] = 0
            elif H[i][j] == diag:
                len_matrix[i][j] = diag_len
            elif H[i][j] == up:
                len_matrix[i][j] = len_matrix[i - 1][j]
            else:
                len_matrix[i][j] = len_matrix[i][j - 1]

            if H[i][j] > max_score:
                max_score = H[i][j]
                max_len = len_matrix[i][j]

    # Normalizar pelo score máximo possível
    max_possible_score = min(m, n) * match_score
    normalized = max_score / max_possible_score if max_possible_score > 0 else 0.0
    return normalized, max_len


def melodic_similarity(
    midi_a: Path,
    midi_b: Path,
    cache: Optional[ContentCache] = None,
) -> dict:
    """Compara duas melodias com Smith-Waterman sobre intervalos."""
    key_a = ContentCache.hash_file(midi_a)
    key_b = ContentCache.hash_file(midi_b)
    cache_key = f"sw:{key_a}:{key_b}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return cached

    skyline_a = extract_skyline(midi_a)
    skyline_b = extract_skyline(midi_b)

    intervals_a = intervals_from_pitches(skyline_a)
    intervals_b = intervals_from_pitches(skyline_b)

    score, aligned_len = smith_waterman(intervals_a, intervals_b, tolerance=1)

    result = {
        "score": score,
        "aligned_length": aligned_len,
        "skyline_a_length": len(skyline_a),
        "skyline_b_length": len(skyline_b),
        "intervals_a_length": len(intervals_a),
        "intervals_b_length": len(intervals_b),
    }

    if cache:
        cache.set(cache_key, result)

    return result


# ────────────────────────────────────────────────────────────
# Estágio 3.5 — Calibração
# ────────────────────────────────────────────────────────────

def calibrate_threshold(
    pairs: list[dict],
    cache: Optional[ContentCache] = None,
    fraction: float = None,
) -> dict:
    """
    Correção v10: calibração com pares positivos e negativos,
    validação disjunta.
    """
    fraction = fraction or CONFIG["calibration_fraction"]

    positives = [p for p in pairs if p.get("label") == "positive"]
    negatives = [p for p in pairs if p.get("label") == "negative"]

    if not positives or not negatives:
        return {
            "threshold": CONFIG["min_similarity_score"],
            "calibration_valid": False,
            "reason": "pares insuficientes (positivos ou negativos ausentes)",
            "n_positives": len(positives),
            "n_negatives": len(negatives),
        }

    # Dividir em calibração e validação
    n_pos_cal = max(1, int(len(positives) * fraction))
    n_neg_cal = max(1, int(len(negatives) * fraction))

    cal_pos = positives[:n_pos_cal]
    val_pos = positives[n_pos_cal:]
    cal_neg = negatives[:n_neg_cal]
    val_neg = negatives[n_neg_cal:]

    # Calcular scores dos pares de calibração negativos
    cal_neg_scores = []
    for pair in cal_neg:
        if "score" in pair:
            cal_neg_scores.append(pair["score"])
        else:
            sim = melodic_similarity(Path(pair["audio_a"]), Path(pair["audio_b"]), cache)
            cal_neg_scores.append(sim["score"])

    # Limiar: percentil 95 dos negativos
    if not cal_neg_scores:
        threshold = CONFIG["min_similarity_score"]
        valid = False
    else:
        neg_scores_sorted = sorted(cal_neg_scores)
        idx = int(len(neg_scores_sorted) * 0.95)
        threshold = neg_scores_sorted[min(idx, len(neg_scores_sorted) - 1)]
        valid = True

    # Validação
    val_scores = []
    for pair in val_pos + val_neg:
        if "score" in pair:
            val_scores.append({
                "label": pair.get("label"),
                "score": pair["score"],
            })
        else:
            sim = melodic_similarity(
                Path(pair["audio_a"]), Path(pair["audio_b"]), cache
            )
            val_scores.append({
                "label": pair.get("label"),
                "score": sim["score"],
            })

    tp = sum(1 for v in val_scores if v["label"] == "positive" and v["score"] >= threshold)
    fp = sum(1 for v in val_scores if v["label"] == "negative" and v["score"] >= threshold)
    tn = sum(1 for v in val_scores if v["label"] == "negative" and v["score"] < threshold)
    fn = sum(1 for v in val_scores if v["label"] == "positive" and v["score"] < threshold)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "threshold": threshold,
        "calibration_valid": valid,
        "n_positives": len(positives),
        "n_negatives": len(negatives),
        "n_calibration": len(cal_pos) + len(cal_neg),
        "n_validation": len(val_pos) + len(val_neg),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "val_scores": val_scores,
    }


# ────────────────────────────────────────────────────────────
# Detecção de versões
# ────────────────────────────────────────────────────────────

def detect_versions() -> dict:
    """Detecta versões das bibliotecas instaladas."""
    packages = [
        "musicbrainzngs",
        "pyacoustid",
        "clapback-embed",
        "music21",
        "demucs",
        "basic-pitch",
        "requests",
    ]
    versions = {}
    for pkg in packages:
        try:
            versions[pkg] = version(pkg)
        except PackageNotFoundError:
            versions[pkg] = None
    return versions


# ────────────────────────────────────────────────────────────
# Manifesto
# ────────────────────────────────────────────────────────────

def build_manifest(
    targets: list[dict],
    config: dict,
    versions: dict,
) -> dict:
    """
    Correção v10: sem ciclo (não recebe report).
    Inclui SHA-256 dos áudios.
    """
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "config": {
            k: v for k, v in config.items()
            if k not in ("acoustid_api_key", "acrcloud_access_key",
                         "acrcloud_access_secret")
        },
        "versions": versions,
        "clap_pipeline_version": CLAP_PIPELINE_VERSION,
    }

def run_demucs_and_basic_pitch(audio_path: Path, out_dir: Path) -> Optional[Path]:
    """Wraps demucs and basic-pitch CLI execution to extract vocals into MIDI"""
    out_dir.mkdir(parents=True, exist_ok=True)

    # Run Demucs
    try:
        subprocess.run(
            ["demucs", "-o", str(out_dir), "-n", "htdemucs", str(audio_path)],
            check=True, timeout=CONFIG["demucs_timeout"], capture_output=True
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning("Demucs falhou: %s", e)
        return None

    vocal_path = out_dir / "htdemucs" / audio_path.stem / "vocals.wav"
    if not vocal_path.exists():
        return None

    # Run Basic Pitch
    try:
        subprocess.run(
            ["basic-pitch", str(out_dir), str(vocal_path)],
            check=True, timeout=CONFIG["basic_pitch_timeout"], capture_output=True
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning("Basic Pitch falhou: %s", e)
        return None

    midi_path = out_dir / f"vocals_basic_pitch.mid"
    if not midi_path.exists():
        return None

    return midi_path

# ────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Arkhe Melodic Pipeline v10"
    )
    parser.add_argument("--config", type=Path, help="Ficheiro JSON de configuração")
    parser.add_argument("--audio-a", type=Path, help="Áudio do alvo A")
    parser.add_argument("--audio-b", type=Path, help="Áudio do alvo B")
    parser.add_argument("--title-a", default="Taj Mahal")
    parser.add_argument("--artist-a", default="Jorge Ben")
    parser.add_argument("--year-a", type=int, default=1972)
    parser.add_argument("--title-b", default="Da Ya Think I'm Sexy")
    parser.add_argument("--artist-b", default="Rod Stewart")
    parser.add_argument("--year-b", type=int, default=1978)
    parser.add_argument("--out", type=Path, default=Path("arkhe_report.json"))
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Cache
    cache = ContentCache(CONFIG["cache_db"])

    try:
        # Verificar áudios
        if not args.audio_a or not args.audio_a.exists():
            log.error("Áudio A não encontrado: %s", args.audio_a)
            return 1
        if not args.audio_b or not args.audio_b.exists():
            log.error("Áudio B não encontrado: %s", args.audio_b)
            return 1

        # ──────────────────────────────────────────────
        # Estágio 1: Resolver identidade
        # ──────────────────────────────────────────────
        log.info("Estágio 1: Resolver identidade (MusicBrainz)")
        rec_a = resolve_musicbrainz(
            args.title_a, args.artist_a, args.year_a, cache
        )
        rec_b = resolve_musicbrainz(
            args.title_b, args.artist_b, args.year_b, cache
        )
        log.info("A: %s (%s) — MBID %s", rec_a.title, rec_a.artist, rec_a.mbid)
        log.info("B: %s (%s) — MBID %s", rec_b.title, rec_b.artist, rec_b.mbid)

        # ──────────────────────────────────────────────
        # Estágio 2: Cruzar metadados (Deezer)
        # ──────────────────────────────────────────────
        log.info("Estágio 2: Cruzar metadados (Deezer)")
        deezer_a = lookup_deezer_isrc(rec_a.isrcs[0], cache) if rec_a.isrcs else None
        deezer_b = lookup_deezer_isrc(rec_b.isrcs[0], cache) if rec_b.isrcs else None

        # ──────────────────────────────────────────────
        # Estágio 3: Fingerprint AcoustID
        # ──────────────────────────────────────────────
        log.info("Estágio 3: Fingerprint AcoustID")
        fp_a = fingerprint_acoustid(args.audio_a, cache)
        fp_b = fingerprint_acoustid(args.audio_b, cache)

        gate_a = gate_acoustid(fp_a, [rec_a.mbid])
        gate_b = gate_acoustid(fp_b, [rec_b.mbid])

        if not gate_a:
            log.warning("Gate AcoustID falhou para A")
        if not gate_b:
            log.warning("Gate AcoustID falhou para B")

        # ──────────────────────────────────────────────
        # Estágio 4: ACRCloud
        # ──────────────────────────────────────────────
        log.info("Estágio 4: ACRCloud Identification")
        acr_a = acrcloud_identify(args.audio_a, cache)
        acr_b = acrcloud_identify(args.audio_b, cache)

        # ──────────────────────────────────────────────
        # Estágio 4b: CLAP
        # ──────────────────────────────────────────────
        log.info("Estágio 4b: CLAP embeddings")
        clap_a = clap_embed(args.audio_a, cache)
        clap_b = clap_embed(args.audio_b, cache)
        clap_sim = cosine_similarity(clap_a, clap_b) if clap_a and clap_b else None

        # ──────────────────────────────────────────────
        # Estágio Melódico
        # ──────────────────────────────────────────────
        log.info("Estágio Melódico (Demucs + Basic Pitch + Smith-Waterman)")
        work_dir = Path(tempfile.mkdtemp(prefix="arkhe_"))

        midi_a = run_demucs_and_basic_pitch(args.audio_a, work_dir / "a")
        midi_b = run_demucs_and_basic_pitch(args.audio_b, work_dir / "b")

        smith_waterman_res = None
        if midi_a and midi_b:
            smith_waterman_res = melodic_similarity(midi_a, midi_b, cache)

        shutil.rmtree(work_dir, ignore_errors=True)

        # ──────────────────────────────────────────────
        # Relatório
        # ──────────────────────────────────────────────
        versions = detect_versions()

        # Correção v10: sem ciclo; hashes de custódia
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_a": {
                "title": args.title_a,
                "artist": args.artist_a,
                "year": args.year_a,
                "mbid": rec_a.mbid,
                "isrcs": rec_a.isrcs,
                "iswcs": rec_a.iswcs,
                "composers": rec_a.composers,
                "deezer": deezer_a,
                "acoustid_gate": gate_a,
                "acrcloud": asdict(acr_a),
                "sha256": ContentCache.hash_file(args.audio_a),
            },
            "target_b": {
                "title": args.title_b,
                "artist": args.artist_b,
                "year": args.year_b,
                "mbid": rec_b.mbid,
                "isrcs": rec_b.isrcs,
                "iswcs": rec_b.iswcs,
                "composers": rec_b.composers,
                "deezer": deezer_b,
                "acoustid_gate": gate_b,
                "acrcloud": asdict(acr_b),
                "sha256": ContentCache.hash_file(args.audio_b),
            },
            "similarity": {
                "clap_cosine": clap_sim,
                "clap_available": clap_a is not None and clap_b is not None,
                "smith_waterman": smith_waterman_res,
            },
            "manifest": build_manifest(
                targets=[
                    {"id": "A", "title": args.title_a, "artist": args.artist_a},
                    {"id": "B", "title": args.title_b, "artist": args.artist_b},
                ],
                config=CONFIG,
                versions=versions,
            ),
            "script_sha256": ContentCache.hash_file(Path(__file__)),
        }

        if not smith_waterman_res:
            report["similarity"]["smith_waterman_error"] = "MIDI não gerado"

        # Hash do próprio relatório (antes de gravar)
        report["report_hash"] = ContentCache.hash_text(canonical(report))

        # Gravar
        args.out.write_text(
            json.dumps(report, indent=2, ensure_ascii=False)
        )
        log.info("Relatório gravado: %s", args.out)
        log.info("report_hash: %s", report["report_hash"])

        return 0

    finally:
        cache.close()


if __name__ == "__main__":
    sys.exit(main())
