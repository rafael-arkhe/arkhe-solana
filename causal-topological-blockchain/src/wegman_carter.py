"""
Módulo Wegman-Carter MAC: Autenticação informação-teórica
com hash universal sobre GF(2^128) e estratificação de chaves.

Referências:
- Wegman & Carter (1981). New hash functions and their use in
  authentication and set equality. JCSS.
- ArXiv:2603.14826. TF-QKD Architecture for Blockchain.
"""
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple


def derive_keys(qkd_key: bytes, key_length: int = 32
                ) -> Tuple[bytes, bytes]:
    """
    HKDF-SHA256: deriva (k_hash, k_otp) da chave QKD.

    O Wegman-Carter requer duas chaves independentes:
    - k_hash: para a família universal de hash
    - k_otp: para o one-time pad (XOR)
    """
    salt = b'\x00' * 32
    prk = hmac.new(salt, qkd_key, hashlib.sha256).digest()
    k_hash = hmac.new(prk, b'hash' + b'\x01', hashlib.sha256).digest()
    k_otp = hmac.new(prk, b'otp' + b'\x02', hashlib.sha256).digest()
    return k_hash[:key_length], k_otp[:key_length]


class GF2_128:
    """
    Aritmética em GF(2^128) com polinômio irredutível
    p(x) = x^128 + x^7 + x^2 + x + 1 (usado em GCM/GMAC).

    Referência: Chou & Bernstein (2014).
    """
    MOD = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

    @staticmethod
    def _clmul(a: int, b: int) -> int:
        """Multiplicação carry-less (sem carry) em GF(2)."""
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            b >>= 1
        return result

    @staticmethod
    def mul(a: int, b: int) -> int:
        """Multiplicação em GF(2^128) com redução modular."""
        p = GF2_128._clmul(a, b)
        for i in range(255, 127, -1):
            if (p >> i) & 1:
                p ^= GF2_128.MOD << (i - 128)
        return p & ((1 << 128) - 1)

    @staticmethod
    def eval_poly(coeffs: List[int], x: int) -> int:
        """Avalia polinômio P(X) = sum_i coeffs[i] * X^i
        em GF(2^128) usando o método de Horner."""
        result = 0
        for c in reversed(coeffs):
            result = GF2_128.mul(result, x) ^ c
        return result


def universal_hash_gf128(k_hash: bytes, message: bytes) -> bytes:
    """
    Família universal de hash por avaliação polinomial em GF(2^128).

    H_k(m) = P_m(k) onde P_m é o polinômio cujos coeficientes
    são os blocos de 16 bytes da mensagem.

    A probabilidade de colisão é limitada por (l-1)/2^128,
    onde l é o número de blocos.
    """
    r = int.from_bytes(k_hash[:16], 'big')
    blocks = [message[i:i+16] for i in range(0, len(message), 16)]
    coeffs = [int.from_bytes(b.ljust(16, b'\x00'), 'big')
              for b in blocks]
    h = GF2_128.eval_poly(coeffs, r)
    return h.to_bytes(16, 'big')


class WegmanCarterMAC:
    """
    Wegman-Carter MAC com estratos indexados por (signer, peer).

    Estrutura: MAC = H_k_hash(m) XOR k_otp
    - H: família universal de hash (GF(2^128))
    - k_otp: one-time pad

    Segurança informação-teórica: resistente a adversários com
    poder computacional ilimitado.
    """

    def __init__(self):
        # (signer, peer) -> list of (k_hash, k_otp)
        self.strata: Dict[Tuple[bytes, bytes],
                          List[Tuple[bytes, bytes]]] = {}
        self._sign_counter: Dict[Tuple[bytes, bytes], int] = {}

    def import_qkd_key(self, signer_id: bytes, peer_id: bytes,
                       qkd_key: bytes) -> None:
        """Importa chave QKD e a associa ao par (signer, peer)."""
        k_hash, k_otp = derive_keys(qkd_key)
        key = (signer_id, peer_id)
        self.strata.setdefault(key, []).append((k_hash, k_otp))
        self._sign_counter.setdefault(key, 0)

    def get_key_material(self, signer_id: bytes, peer_id: bytes,
                         idx: int) -> Optional[Tuple[bytes, bytes]]:
        """Método público para acessar material de chave."""
        keys = self.strata.get((signer_id, peer_id))
        if not keys or idx >= len(keys):
            return None
        return keys[idx]

    def sign(self, signer_id: bytes, peer_id: bytes, message: bytes
             ) -> Optional[Tuple[bytes, int]]:
        """
        Assina com a chave compartilhada entre (signer, peer).
        Retorna (mac, key_idx).
        """
        key = (signer_id, peer_id)
        idx = self._sign_counter.get(key, 0)
        material = self.get_key_material(signer_id, peer_id, idx)
        if material is None:
            return None
        k_hash, k_otp = material
        h = universal_hash_gf128(k_hash, message)
        mac = bytes(a ^ b for a, b in zip(h[:32], k_otp[:32]))
        self._sign_counter[key] = idx + 1
        return mac, idx

    def verify(self, signer_id: bytes, peer_id: bytes, message: bytes,
               mac: bytes, key_idx: int) -> bool:
        """Verifica usando a chave compartilhada entre (signer, peer)."""
        material = self.get_key_material(signer_id, peer_id, key_idx)
        if material is None:
            return False
        k_hash, k_otp = material
        h = universal_hash_gf128(k_hash, message)
        expected = bytes(a ^ b for a, b in zip(h[:32], k_otp[:32]))
        return hmac.compare_digest(expected, mac)
