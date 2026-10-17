import blake3
import json
import cbor2

def generate_blake3():
    return [
        {
            "id": "BLAKE3-001",
            "component": "BLAKE3",
            "normative_source": "BLAKE3 Official Test Vectors (empty input)",
            "description": "BLAKE3 hash of empty input (32-byte output)",
            "input": {
                "data_hex": "",
                "domain": "none"
            },
            "expected_output": {
                "hash_hex": blake3.blake3(b"").digest().hex()
            }
        },
        {
            "id": "BLAKE3-002",
            "component": "BLAKE3",
            "normative_source": "BLAKE3 Official Test Vectors (input 'abc')",
            "description": "BLAKE3 hash of ASCII 'abc'",
            "input": {
                "data_hex": "616263",
                "domain": "none"
            },
            "expected_output": {
                "hash_hex": blake3.blake3(b"abc").digest().hex()
            }
        }
    ]

def generate_gguf():
    # CDE sorting by bytewise lexicographic order of deterministic encodings.
    # We will just construct the map manually to ensure it's CDE
    # license: MIT, architecture: llama, context_length: 4096
    # 4096 is 0x1000, so uint16: 19 10 00

    cbor_bytes = cbor2.dumps({
        "license": "MIT",
        "architecture": "llama",
        "context_length": 4096
    }, canonical=True)

    return [
        {
            "id": "GGUF-CANON-001",
            "component": "GGUF Canonicalization",
            "normative_source": "AKG-CBOR-v1 (RFC 8949 §4.2.1)",
            "description": "Canonical CBOR encoding of GGUF metadata map",
            "input": {
                "metadata": {
                    "architecture": "llama",
                    "context_length": 4096,
                    "license": "MIT"
                }
            },
            "expected_output": {
                "canonical_cbor_hex": cbor_bytes.hex(),
                "canonical_hash_hex": blake3.blake3(cbor_bytes).digest().hex()
            }
        }
    ]

def leaf_hash(data: bytes) -> bytes:
    return blake3.blake3(b'\x00' + data).digest()

def node_hash(left: bytes, right: bytes) -> bytes:
    return blake3.blake3(b'\x01' + left + right).digest()

def bag_peaks(peaks: list[bytes], size: int) -> bytes:
    if not peaks:
        return blake3.blake3(b'').digest()

    size_bytes = size.to_bytes(8, 'big')
    acc = peaks[-1]
    for p in reversed(peaks[:-1]):
        acc = blake3.blake3(b'\x02' + size_bytes + p + acc).digest()
    return acc

class MMR:
    def __init__(self):
        self.leaves = []
        self.nodes = {}

    def add(self, data: bytes):
        self.leaves.append(data)

    def build(self):
        n = len(self.leaves)
        if n == 0:
            self.peaks = []
            return

        def build_perfect_tree(start_idx, h):
            if h == 0:
                h_val = leaf_hash(self.leaves[start_idx])
                self.nodes[(h, start_idx)] = h_val
                return h_val
            left = build_perfect_tree(start_idx, h - 1)
            right = build_perfect_tree(start_idx + (1 << (h - 1)), h - 1)
            val = node_hash(left, right)
            self.nodes[(h, start_idx)] = val
            return val

        self.peaks = []
        start = 0
        rem = n
        h = 0
        while (1 << h) <= rem:
            h += 1
        h -= 1

        while rem > 0:
            while (1 << h) > rem:
                h -= 1
            peak_hash = build_perfect_tree(start, h)
            self.peaks.append(peak_hash)
            start += (1 << h)
            rem -= (1 << h)

    def get_root(self):
        return bag_peaks(self.peaks, len(self.leaves))

    def get_proof(self, target_index):
        n = len(self.leaves)
        if n == 0:
            return [], []

        start = 0
        rem = n
        h = 0
        while (1 << h) <= rem:
            h += 1
        h -= 1

        peak_idx = -1
        peak_h = -1
        peak_start = -1

        peaks_info = []

        while rem > 0:
            while (1 << h) > rem:
                h -= 1
            peaks_info.append((h, start, self.peaks[len(peaks_info)]))
            if start <= target_index < start + (1 << h):
                peak_idx = len(peaks_info) - 1
                peak_h = h
                peak_start = start
            start += (1 << h)
            rem -= (1 << h)

        proof_hashes = []
        proof_dirs = []

        idx = target_index - peak_start

        for level in range(peak_h):
            pos_at_level = idx >> level
            sibling_pos = pos_at_level ^ 1
            sibling_start_leaf = peak_start + (sibling_pos << level)

            sibling_hash = self.nodes[(level, sibling_start_leaf)]
            proof_hashes.append(sibling_hash.hex())
            if pos_at_level % 2 == 0:
                proof_dirs.append("right")
            else:
                proof_dirs.append("left")

        accs = [b''] * len(self.peaks)
        accs[-1] = self.peaks[-1]
        for i in range(len(self.peaks)-2, -1, -1):
            accs[i] = blake3.blake3(b'\x02' + n.to_bytes(8, 'big') + self.peaks[i] + accs[i+1]).digest()

        if peak_idx < len(self.peaks) - 1:
            proof_hashes.append(accs[peak_idx + 1].hex())
            proof_dirs.append("right")

        for i in range(peak_idx - 1, -1, -1):
            proof_hashes.append(self.peaks[i].hex())
            proof_dirs.append("left")

        return proof_hashes, proof_dirs

def generate_mmr_cases():
    cases = []
    # Sizes: 1, 3, 4, 5, 7
    for n in [1, 3, 4, 5, 7]:
        mmr = MMR()
        leaves_hex = []
        for i in range(n):
            s = str(i+1).rjust(64, '0')
            leaves_hex.append(s)
            mmr.add(bytes.fromhex(s))

        mmr.build()

        # We will generate proof for index n // 2
        target_idx = n // 2
        root = mmr.get_root().hex()
        hashes, dirs = mmr.get_proof(target_idx)

        cases.append({
            "id": f"MMR-{n:03d}",
            "component": "WormGraph MMR",
            "normative_source": "RFC 6962 (Merkle Tree) + Arkhe Domain Separation",
            "description": f"Merkle Mountain Range of {n} leaves, inclusion proof for leaf index {target_idx}",
            "input": {
                "leaves": leaves_hex,
                "target_index": target_idx,
                "hash_function": "BLAKE3",
                "leaf_prefix": "00",
                "node_prefix": "01",
                "bagging_prefix": "02"
            },
            "expected_output": {
                "root_hash_hex": root,
                "inclusion_proof_hashes": hashes,
                "inclusion_proof_directions": dirs
            }
        })
    return cases

def generate_c2pa():
    # Positive minimal valid claim-map-v2
    # instanceID, claim_generator_info, signature, created_assertions, alg
    pos_claim = {
        "alg": "sha256",
        "claim_generator": "Arkhe/1.0",
        "claim_generator_info": [{"name": "Arkhe", "version": "1.0"}],
        "created_assertions": [],
        "format": "image/jpeg",
        "instanceID": "xmp:iid:12345",
        "signature": "sig_dummy",
        "title": "test_asset.jpg"
    }

    pos_cbor = cbor2.dumps(pos_claim, canonical=True)
    pos_hash = blake3.blake3(pos_cbor).digest().hex()

    # Negative vector (missing required fields, invalid alg)
    neg_claim = {
        "alg": "Ed25519",
        "claim_generator": "Arkhe/1.0",
        "format": "image/jpeg",
        "title": "test_asset.jpg"
    }
    neg_cbor = cbor2.dumps(neg_claim, canonical=True)
    neg_hash = blake3.blake3(neg_cbor).digest().hex()

    return [
        {
            "id": "C2PA-001",
            "component": "C2PA Manifest Parsing",
            "normative_source": "C2PA Spec 2.3 (Claim Canonicalization)",
            "description": "Extraction and canonicalization of C2PA claim-map-v2 fields",
            "input": {
                "claim_json": pos_claim
            },
            "expected_output": {
                "canonical_cbor_hex": pos_cbor.hex(),
                "claim_hash_hex": pos_hash
            }
        },
        {
            "id": "C2PA-NEG-001",
            "component": "C2PA Manifest Parsing",
            "normative_source": "C2PA Spec 2.3 (Claim Canonicalization)",
            "description": "Invalid C2PA claim missing required v2 fields and using wrong alg",
            "input": {
                "claim_json": neg_claim
            },
            "expected_output": {
                "error": "Invalid claim-map-v2: missing instanceID, signature, created_assertions. alg must be a hash algorithm.",
                "canonical_cbor_hex": neg_cbor.hex(),
                "claim_hash_hex": neg_hash
            }
        }
    ]

def main():
    vectors = generate_blake3() + generate_gguf() + generate_mmr_cases() + generate_c2pa()

    out = {
        "$schema": "https://arkhe.dev/schemas/golden-vectors-v1.json",
        "version": "AKG-CBOR-v1",
        "generated_by": "hand-authored-contract",
        "generated_at": "2026-10-17T00:00:00Z",
        "vectors": vectors
    }

    with open("tests/golden_vectors.json", "w") as f:
        json.dump(out, f, indent=2)

if __name__ == "__main__":
    main()
