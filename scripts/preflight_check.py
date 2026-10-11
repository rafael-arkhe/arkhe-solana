#!/usr/bin/env python3
"""
preflight_check.py — verifica mecanicamente um relatório Arkhe antes de gravar a demo.

Uso:
  python preflight_check.py report.json --audio-a a.wav --audio-b b.wav [--online]
         [--hash-excludes report_hash,anchor,c2pa]

Só usa a biblioteca padrão. Código de saída: 0 = tudo passou; 1 = alguma falha.
`--online` consulta api.devnet.solana.com para confirmar que a transação existe.

O que NÃO verifica: se o MMR root bate com a árvore do WormGraph, nem se o
manifesto C2PA é válido (isso exige o próprio verificador do app / c2patool).
"""
import argparse, hashlib, json, re, sys
from datetime import datetime
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EMPTY_SHA = hashlib.sha256(b"").hexdigest()
TEST_SHA = hashlib.sha256(b"test").hexdigest()

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def b58_nbytes(s):
    n = 0
    for c in s:
        if c not in B58:
            return None
        n = n * 58 + B58.index(c)
    return (n.bit_length() + 7) // 8 + (len(s) - len(s.lstrip("1")))


def canonical(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for ch in iter(lambda: f.read(65536), b""):
            h.update(ch)
    return h.hexdigest()


def shared_window(a, b, n=16):
    return {a[i:i + n] for i in range(len(a) - n + 1)} & {b[i:i + n] for i in range(len(b) - n + 1)}


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--audio-a", type=Path)
    ap.add_argument("--audio-b", type=Path)
    ap.add_argument("--online", action="store_true")
    ap.add_argument("--hash-excludes", default="report_hash",
                    help="chaves de topo fora do corpo coberto pelo report_hash")
    a = ap.parse_args()
    r = json.loads(a.report.read_text())

    # 1. hashes de áudio: forma, placeholders conhecidos, igualdade com os arquivos
    hashes = {"audio_a": r["target_a"]["sha256"], "audio_b": r["target_b"]["sha256"]}
    for k, v in hashes.items():
        check(f"{k}.sha256 tem 64 hex", HEX64.match(v), f"len={len(v)}")
        check(f"{k}.sha256 não é placeholder (vazio/'test')", v not in (EMPTY_SHA, TEST_SHA))
    check("audio_a != audio_b", hashes["audio_a"] != hashes["audio_b"])
    for key, path in (("audio_a", a.audio_a), ("audio_b", a.audio_b)):
        if path:
            real = sha256_file(path)
            check(f"{key}.sha256 == sha256sum({path.name})", real == hashes[key], real[:16] + "…")

    # 2. report_hash recomputado sobre o corpo canônico
    ex = {x for x in a.hash_excludes.split(",") if x}
    body = {k: v for k, v in r.items() if k not in ex}
    calc = hashlib.sha256(canonical(body).encode()).hexdigest()
    rh = r.get("report_hash", "")
    check("report_hash tem 64 hex", HEX64.match(rh), f"len={len(rh)}")
    check(f"report_hash == sha256(canonical(corpo sem {sorted(ex)}))", calc == rh, f"calculado {calc[:16]}…")

    # 3. âncora
    anc = r.get("anchor")
    check("existe bloco 'anchor'", anc is not None)
    if anc:
        sig = anc.get("tx_signature", "")
        n = b58_nbytes(sig)
        check("tx_signature = base58 de 64 bytes (87–88 chars)", n == 64 and 86 <= len(sig) <= 88,
              f"{len(sig)} chars → {n} bytes")
        check("mmr_root tem 64 hex", HEX64.match(anc.get("mmr_root", "")))
        try:
            check("anchor.timestamp > generated_at (âncora vem depois do relatório)",
                  parse_ts(anc["timestamp"]) > parse_ts(r["generated_at"]),
                  f'{anc["timestamp"]} vs {r["generated_at"]}')
        except Exception as e:
            check("timestamps legíveis", False, str(e))
        check("explorer_url contém a mesma assinatura", sig in anc.get("explorer_url", ""))
        # nenhum fragmento de 16 hex repetido entre campos que deveriam ser independentes
        fields = {"audio_a": hashes["audio_a"], "audio_b": hashes["audio_b"], "report_hash": rh,
                  "mmr_root": anc.get("mmr_root", ""), "script_sha256": r.get("script_sha256", "")}
        dup = [(x, y) for i, x in enumerate(fields) for y in list(fields)[i + 1:]
               if len(fields[x]) >= 16 and len(fields[y]) >= 16 and shared_window(fields[x], fields[y])]
        check("hashes independentes não compartilham trechos de 16 hex", not dup, str(dup))

    # 4. DID
    c2 = r.get("c2pa")
    if c2:
        did = c2.get("signer_did", "")
        key = did.split("z", 1)[-1] if did.startswith("did:key:z") else ""
        check("signer_did é did:key Ed25519 (34 bytes multicodec+chave)", b58_nbytes(key) == 34,
              f"{b58_nbytes(key)} bytes")
        check("signer_did sem padrão repetitivo", not re.search(r"(.{3,6})\1\1", key), key)

    # 5. similaridade e calibração
    m = r["similarity"]["melodic"]
    s = m["similarity"]
    check("0 <= score <= 1", 0 <= s["score"] <= 1, str(s["score"]))
    check("score == 1.0 exige conferência manual do alinhamento", s["score"] != 1, "melodias comerciais raramente dão 1,0")
    check("intervalos = skyline − 1 (A e B)",
          s["intervals_a_length"] == s["skyline_a_length"] - 1 and s["intervals_b_length"] == s["skyline_b_length"] - 1)
    c = m.get("calibration")
    if c:
        vs = c["val_scores"]
        neg = [v["score"] for v in vs if v["label"] == "negative"]
        pos = [v["score"] for v in vs if v["label"] == "positive"]
        thr = c["threshold"]
        fp, tn = sum(x > thr for x in neg), sum(x <= thr for x in neg)
        tp, fn = sum(x > thr for x in pos), sum(x <= thr for x in pos)
        check("tp/fp/tn/fn recomputados de val_scores", (tp, fp, tn, fn) == (c["tp"], c["fp"], c["tn"], c["fn"]),
              f"calculado {(tp, fp, tn, fn)}")
        check("fpr recomputado", abs(fp / max(1, fp + tn) - c["fpr"]) < 1e-3)
        check("n_validation_negatives == nº de negativos em val_scores", len(neg) == c["n_validation_negatives"])
        min_cal = 19  # ceil(1/α) − 1 para α = 0,05
        check("calibração com garantia: n_calibration >= 19 (α=5%)",
              c["n_calibration"] >= min_cal if c["alpha"] == 0.05 else True, f"n_cal={c['n_calibration']}")
        check("calibration_valid coerente com alpha_guaranteed", c["calibration_valid"] == c["alpha_guaranteed"] or not c["calibration_valid"])
        exp = "above_threshold" if s["score"] > thr else "below_threshold"
        if c["calibration_valid"]:
            check("decision coerente com score vs limiar", m["decision"] == exp, f"{m['decision']} vs {exp}")
        else:
            check("decision = uncalibrated quando calibração inválida", m["decision"] == "uncalibrated")
        pair_names = [v.get("name", "") for v in vs]
        check("par-alvo fora da validação (sem circularidade)",
              not any(("Taj Mahal" in n and "Sexy" in n) for n in pair_names))

    # 6. online
    if a.online and anc:
        import urllib.request
        req = urllib.request.Request(
            "https://api.devnet.solana.com", method="POST", headers={"Content-Type": "application/json"},
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getSignatureStatuses",
                             "params": [[anc["tx_signature"]], {"searchTransactionHistory": True}]}).encode())
        try:
            val = json.load(urllib.request.urlopen(req, timeout=15))["result"]["value"][0]
            check("transação existe na devnet", val is not None and val.get("err") is None, str(val))
        except Exception as e:
            check("transação existe na devnet", False, f"consulta falhou: {e}")

    w = max(len(n) for n, _, _ in results)
    for n, ok, d in results:
        print(f"{'PASS' if ok else 'FAIL'}  {n:<{w}}  {d}")
    fails = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(fails)}/{len(results)} verificações passaram" + (f" — {len(fails)} FALHA(S)" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())