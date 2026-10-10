"""
Módulo de Delayed Key Disclosure: Revelação atrasada de chaves
para auditoria pública.

A chave para o bloco B_N é propagada apenas após o conteúdo
do bloco ter sido hash-locked e registrado pela maioria honesta.

Referência: ArXiv:2603.14826. TF-QKD Architecture for Blockchain.
"""
import hmac
from dataclasses import dataclass
from typing import Dict

from wegman_carter import universal_hash_gf128


@dataclass
class DisclosureRecord:
    """Registro de revelação de chave."""
    block_id: bytes
    k_hash: bytes = b''
    k_otp: bytes = b''
    mac_vector: bytes = b''
    message: bytes = b''
    disclosed: bool = False


class DelayedKeyDisclosure:
    """
    Divulgação atrasada de chaves para auditoria pública.

    A verificação usa EXATAMENTE o mesmo MAC do Wegman-Carter,
    permitindo que qualquer auditor recompute o MAC original.
    """

    def __init__(self):
        self.records: Dict[bytes, DisclosureRecord] = {}

    def register(self, block_id: bytes, k_hash: bytes, k_otp: bytes,
                 message: bytes, mac: bytes) -> None:
        """Registra bloco para revelação futura."""
        self.records[block_id] = DisclosureRecord(
            block_id=block_id, k_hash=k_hash, k_otp=k_otp,
            mac_vector=mac, message=message, disclosed=False
        )

    def disclose(self, block_id: bytes) -> bool:
        """Revela a chave de um bloco já commitado."""
        rec = self.records.get(block_id)
        if not rec:
            return False
        rec.disclosed = True
        return True

    def audit(self, block_id: bytes) -> Dict:
        """
        Auditoria pública: qualquer auditor recomputa o MAC
        usando (k_hash, k_otp) revelados.
        """
        rec = self.records.get(block_id)
        if not rec:
            return {"status": "not_found"}
        if not rec.disclosed:
            return {"status": "key_not_disclosed"}

        h = universal_hash_gf128(rec.k_hash, rec.message)
        expected = bytes(a ^ b for a, b in zip(h[:32],
                                               rec.k_otp[:32]))
        valid = hmac.compare_digest(expected, rec.mac_vector)

        return {
            "status": "audited",
            "block_id": block_id.hex()[:16],
            "mac_valid": valid,
            "key_revealed": True
        }
