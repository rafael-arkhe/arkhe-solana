"""
Protótipo L0+L3: Integração QKD-ICO + DAG Causal.

FLUXO:
1. QKD-ICO → chave bruta K_ij
2. KDF(K_ij) → (k_hash, k_otp)
3. MAC.sign(msg, k_hash, k_otp) → (mac, idx)
4. DAG.propose_block(author, peer, msg, mac, idx)
5. MAC.verify(msg, mac, idx) → bool
6. DAG.commit_blocks()
7. Disclosure.register(block_id, k_hash, k_otp, msg, mac)
8. Disclosure.disclose(block_id)
9. Disclosure.audit(block_id) → MAC recomputado
"""
import time
from typing import Dict, List, Tuple

from ico_qkd import ICOQKDProtocol
from wegman_carter import WegmanCarterMAC
from dag_consensus import MysticetiDAG, Block
from delayed_disclosure import DelayedKeyDisclosure


class PrototypeL0L3:
    """
    Protótipo L0+L3 com camada QKD-ICO OPERACIONAL.

    Integra:
    - L0: QKD-ICO para distribuição de chaves e detecção de Eve
    - L3: DAG causal (Mysticeti/FinWhale) para consenso
    - Wegman-Carter MAC para autenticação incondicional
    - Delayed key disclosure para auditoria pública
    """

    def __init__(self, n_validators: int = 4, f_byzantine: int = 1,
                 n_qubits: int = 500, p_detect_honest: float = 0.001):
        self.n_validators = n_validators
        self.qkd_protocols: Dict[Tuple[int, int], ICOQKDProtocol] = {}
        self.qkd_keys: Dict[Tuple[int, int], bytes] = {}
        self.mac = WegmanCarterMAC()
        self.dag = MysticetiDAG(n_validators, f_byzantine,
                                 max_round_jump=2)
        self.disclosure = DelayedKeyDisclosure()
        self.tx_counter = 0
        self.eve_detected = False

        # Inicializa protocolos QKD para cada par
        for i in range(n_validators):
            for j in range(i + 1, n_validators):
                qkd = ICOQKDProtocol(
                    n_qubits=n_qubits,
                    p_detect_honest=p_detect_honest
                )
                qkd.calibrate_threshold(alpha=0.01)
                self.qkd_protocols[(i, j)] = qkd

    def establish_keys(self, has_eve: bool = False,
                       eve_intercept_prob: float = 0.0) -> bool:
        """
        Fase 1: executa QKD-ICO para cada par e integra ao MAC.

        CORREÇÃO: ICOQKDProtocol.run_session() é CHAMADO.
        """
        print(f"[L0] Estabelecendo chaves QKD-ICO"
              f"{' (com Eve)' if has_eve else ''}...")

        for (i, j), qkd in self.qkd_protocols.items():
            result = qkd.run_session(
                has_eve=has_eve,
                eve_intercept_prob=eve_intercept_prob,
                eve_strength=0.3
            )

            if result.session_aborted:
                print(f"  [ABORT] Sessão ({i},{j}): "
                      f"{result.abort_reason}")
                self.eve_detected = True
                return False

            self.qkd_keys[(i, j)] = result.key

            # Injeta no MAC indexado por (signer, peer)
            node_i = bytes([i])
            node_j = bytes([j])
            self.mac.import_qkd_key(node_i, node_j, result.key)
            self.mac.import_qkd_key(node_j, node_i, result.key)

            print(f"  [OK] Sessão ({i},{j}): "
                  f"detecção={result.detection_probability:.4f}, "
                  f"chave={result.key[:4].hex()}...")

        print("[L0] Todas as chaves integradas ao MAC.")
        return True

    def submit_transaction(self, sender: int, peer: int,
                           payload: bytes) -> Block:
        """
        Fase 2: submissão autenticada.

        CORREÇÃO: especifica o peer explicitamente.
        """
        self.tx_counter += 1
        sender_id = bytes([sender])
        peer_id = bytes([peer])

        result = self.mac.sign(sender_id, peer_id, payload)
        if result is None:
            raise RuntimeError("Chaves esgotadas para este par")
        mac, key_idx = result

        block = self.dag.propose_block(
            author=sender_id,
            peer=peer_id,
            transactions=[payload],
            target_round=self.dag.current_round + 1
        )
        block.mac = mac
        block.mac_key_idx = key_idx

        material = self.mac.get_key_material(sender_id, peer_id,
                                             key_idx)
        if material:
            k_hash, k_otp = material
            self.disclosure.register(block.block_id, k_hash, k_otp,
                                     payload, mac)
        return block

    def verify_transaction(self, block: Block) -> bool:
        """
        Verifica o MAC usando (author, peer) e índice explícito.

        CORREÇÃO: peer é usado na verificação.
        """
        return self.mac.verify(
            signer_id=block.author,
            peer_id=block.peer,
            message=block.transactions[0],
            mac=block.mac,
            key_idx=block.mac_key_idx
        )

    def run_cycle(self, n_tx: int = 6, has_eve: bool = False,
                  eve_intercept_prob: float = 0.0) -> Dict:
        """Executa um ciclo completo com opção de Eve."""
        print("=" * 60)
        print(f"PROTÓTIPO L0 + L3 "
              f"{'(COM EVE)' if has_eve else '(SEM EVE)'}")
        print("=" * 60)

        if not self.establish_keys(has_eve, eve_intercept_prob):
            return {"status": "aborted",
                    "reason": "Eve detectado no QKD-ICO"}

        print(f"\n[L3] Submetendo {n_tx} transações...")
        blocks = []
        for i in range(n_tx):
            sender = i % self.n_validators
            peer = (i + 1) % self.n_validators
            payload = f"TX_{i}_{time.time_ns()}".encode()
            try:
                block = self.submit_transaction(sender, peer,
                                                 payload)
                blocks.append(block)
                print(f"  Bloco {block.block_id.hex()[:8]}... "
                      f"rodada {block.round} ({sender}→{peer})")
            except RuntimeError as e:
                print(f"  [SKIP] {e}")

        print("\n[Verificação] Verificando MACs...")
        verified = sum(1 for b in blocks
                       if self.verify_transaction(b))
        print(f"  {verified}/{len(blocks)} MACs verificados")

        committed = self.dag.commit_blocks()
        print(f"\n[L3] {len(committed)} blocos commitados")

        print("\n[Auditoria] Revelando chaves...")
        audit_results = []
        for bid in committed[:3]:
            self.disclosure.disclose(bid)
            result = self.disclosure.audit(bid)
            audit_results.append(result)
            print(f"  {result['block_id']}: "
                  f"MAC válido={result.get('mac_valid')}")

        ordered = self.dag.topological_order()
        print(f"\n[Ledger] Ordem topológica: {len(ordered)} blocos")

        return {
            "status": "success",
            "has_eve": has_eve,
            "blocks_proposed": len(blocks),
            "macs_verified": verified,
            "blocks_committed": len(committed),
            "audit_passed": sum(1 for r in audit_results
                                if r.get("mac_valid")),
            "topological_order_len": len(ordered),
            "eve_detected": self.eve_detected,
        }


if __name__ == "__main__":
    # Teste 1: Sem Eve
    print("\n" + "=" * 60)
    print("TESTE 1: CICLO SEM EVE")
    print("=" * 60)
    proto1 = PrototypeL0L3(n_validators=4, f_byzantine=1,
                            n_qubits=500)
    result1 = proto1.run_cycle(n_tx=6, has_eve=False)

    # Teste 2: Com Eve (interceptando 30% dos qubits)
    print("\n" + "=" * 60)
    print("TESTE 2: CICLO COM EVE (30% de interceptação)")
    print("=" * 60)
    proto2 = PrototypeL0L3(n_validators=4, f_byzantine=1,
                            n_qubits=500)
    result2 = proto2.run_cycle(n_tx=6, has_eve=True,
                                eve_intercept_prob=0.30)

    print("\n" + "=" * 60)
    print("SUMÁRIO")
    print("=" * 60)
    print(f"Sem Eve: {result1}")
    print(f"Com Eve: {result2}")
