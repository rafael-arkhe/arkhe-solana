"""
Módulo DAG Causal: Consenso DAG com correção de round-jumping
(Qiu et al., 2026) e ordenação topológica real.

Referências:
- Qiu et al. (2026). Mechanized Safety and Liveness Proofs for the
  Mysticeti Consensus Protocol. IEEE S&P 2026.
- Ladelsky & Friedman (2026). FinWhale: An Optimally Resilient
  Two-Round Terminating DAG Protocol. arXiv:2606.26292.
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Block:
    """Bloco do DAG."""
    block_id: bytes
    round: int
    author: bytes
    peer: bytes  # destinatário da autenticação
    parents: List[bytes] = field(default_factory=list)
    transactions: List[bytes] = field(default_factory=list)
    mac: Optional[bytes] = None
    mac_key_idx: Optional[int] = None
    timestamp: float = field(default_factory=time.time)


class MysticetiDAG:
    """
    DAG causal com correção de round-jumping (Qiu et al., 2026).

    A vulnerabilidade: se processos honestos saltam rodadas
    arbitrariamente, existe um contraexemplo de liveness.

    A correção: restrição de salto absoluto — um validador não pode
    propor um bloco em uma rodada que exceda current_round + max_round_jump.
    """

    def __init__(self, n_validators: int = 4, f_byzantine: int = 1,
                 max_round_jump: int = 2):
        self.n_validators = n_validators
        self.f_byzantine = f_byzantine
        self.max_round_jump = max_round_jump
        self.blocks: Dict[bytes, Block] = {}
        self.rounds: Dict[int, List[bytes]] = {}
        self.current_round = 0
        self.committed_blocks: List[bytes] = []

    def _block_id(self, r: int, author: bytes, peer: bytes,
                  parents: List[bytes], txs: List[bytes]) -> bytes:
        data = (f"{r}:{author.hex()}:{peer.hex()}:"
                f"{':'.join(p.hex() for p in parents)}:"
                f"{':'.join(t.hex() for t in txs)}")
        return hashlib.sha256(data.encode()).digest()

    def propose_block(self, author: bytes, peer: bytes,
                      transactions: List[bytes],
                      target_round: Optional[int] = None,
                      parents: Optional[List[bytes]] = None) -> Block:
        """Propõe bloco com restrição de salto absoluto."""
        if target_round is None:
            target_round = self.current_round + 1

        # Correção de Qiu et al. (2026)
        if target_round > self.current_round + self.max_round_jump:
            raise ValueError(
                f"Round-jumping bloqueado: alvo {target_round}, "
                f"atual {self.current_round}, "
                f"máximo {self.current_round + self.max_round_jump}"
            )

        if parents is None:
            parents = list(self.rounds.get(self.current_round, []))

        bid = self._block_id(target_round, author, peer,
                             parents, transactions)
        block = Block(bid, target_round, author, peer,
                      parents, transactions)
        self.blocks[bid] = block
        self.rounds.setdefault(target_round, []).append(bid)
        self.current_round = max(self.current_round, target_round)
        return block

    def commit_blocks(self) -> List[bytes]:
        """
        Commit de blocos com supermaioria de validadores distintos.

        Correção: não depende de líder — qualquer bloco com
        referências de 2f+1 validadores distintos é commitado.
        """
        committed = []
        for bid, block in self.blocks.items():
            if bid in self.committed_blocks:
                continue
            distinct_refs = set()
            for b in self.blocks.values():
                if b.round == block.round + 1 and bid in b.parents:
                    distinct_refs.add(b.author)
            if len(distinct_refs) >= 2 * self.f_byzantine + 1:
                self.committed_blocks.append(bid)
                committed.append(bid)
        return committed

    def topological_order(self) -> List[bytes]:
        """Ordenação topológica real (Kahn's algorithm)."""
        committed_set = set(self.committed_blocks)
        in_degree = {b: 0 for b in committed_set}
        dependents = {b: [] for b in committed_set}

        for b in committed_set:
            for parent in self.blocks[b].parents:
                if parent in committed_set:
                    in_degree[b] += 1
                    dependents[parent].append(b)

        queue = sorted([b for b in committed_set
                        if in_degree[b] == 0])
        order = []
        while queue:
            node = queue.pop(0)
            order.append(node)
            for dep in sorted(dependents[node]):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    queue.append(dep)
        return order
