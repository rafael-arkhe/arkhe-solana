"""
Módulo QKD-ICO: Protocolo de distribuição de chaves quânticas
com ordem causal indefinida (Spencer-Wood, 2025).

A detecção de Eve ocorre via medição do qubit de controle,
sem comparação pública de subconjunto da chave.

Referências:
- Spencer-Wood, H. (2025). Indefinite causal key distribution.
  J. Phys. A: Math. Theor. 58 495303. DOI: 10.1088/1751-8121/ae1e44
- Valibouse et al. (2026). Experimental QKD in an Indefinite Causal Order.
  arXiv:2608.13561
"""
import numpy as np
from dataclasses import dataclass, field
from typing import List, Tuple
from scipy import stats


@dataclass
class ICOQKDResult:
    """Resultado de uma sessão QKD-ICO."""
    key: bytes
    control_measurements: List[int]
    detection_probability: float
    session_aborted: bool = False
    abort_reason: str = ""
    n_qubits_used: int = 0


class ICOQKDProtocol:
    """
    Protocolo QKD-ICO de Spencer-Wood (2025).

    O quantum switch coloca as operações de Alice e Bob em superposição
    de ordens causais:

        |Ψ⟩ = (1/√2)(|A antes de B⟩ + |B antes de A⟩)

    A medição do qubit de controle revela se Eve perturbou a interferência.
    A probabilidade de detecção é proporcional ao termo de interferência
    2·Re(α*β), que é máximo quando as amplitudes são iguais.
    """

    def __init__(self, n_qubits: int = 500,
                 p_detect_honest: float = 0.001,
                 p_detect_eve: float = 0.15):
        self.n_qubits = n_qubits
        self.p_detect_honest = p_detect_honest
        self.p_detect_eve = p_detect_eve
        self.detection_threshold = 1
        self.n_detected_total = 0

    def calibrate_threshold(self, alpha: float = 0.01) -> int:
        """Calibra k tal que P(Bin(n, p_honest) >= k) <= alpha."""
        k = 0
        while stats.binom.sf(k - 1, self.n_qubits,
                             self.p_detect_honest) > alpha:
            k += 1
        self.detection_threshold = max(1, k)
        return self.detection_threshold

    def _quantum_switch_amplitude(self, phase_control: float,
                                   eve_perturbation: float = 0.0
                                   ) -> Tuple[complex, complex]:
        """
        Modela o quantum switch com amplitudes complexas.

        α = amplitude de |A antes de B⟩
        β = amplitude de |B antes de A⟩

        Eve, ao interceptar, introduz uma perturbação de fase
        que reduz a visibilidade da interferência.
        """
        alpha = np.exp(1j * phase_control) / np.sqrt(2)
        beta = np.exp(-1j * phase_control) / np.sqrt(2)

        if eve_perturbation > 0:
            alpha = alpha * np.exp(1j * eve_perturbation)
            beta = beta * np.exp(-1j * eve_perturbation)

        return alpha, beta

    def _detection_probability(self, has_eve: bool,
                                eve_strength: float = 0.3) -> float:
        """
        Probabilidade de detecção baseada na visibilidade.

        Sem Eve: V = 1 → p_det = p_detect_honest (ruído do switch)
        Com Eve: V = 1 - eve_strength → p_det = (1 - V) / 2
        """
        if not has_eve:
            return self.p_detect_honest
        V = max(0.0, 1.0 - eve_strength)
        return (1.0 - V) / 2.0

    def run_session(self, has_eve: bool = False,
                    eve_intercept_prob: float = 0.0,
                    eve_strength: float = 0.3) -> ICOQKDResult:
        """
        Executa uma sessão de QKD-ICO.

        Args:
            has_eve: se True, Eve está presente
            eve_intercept_prob: fração de qubits interceptados
            eve_strength: força da perturbação de fase de Eve
        """
        control_measurements = []
        key_bits = []
        n_detected = 0

        for i in range(self.n_qubits):
            # Eve intercepta?
            if has_eve and np.random.random() < eve_intercept_prob:
                p_det = self._detection_probability(True, eve_strength)
            else:
                p_det = self.p_detect_honest

            # Detecção?
            if np.random.random() < p_det:
                control_measurements.append(1)
                n_detected += 1
            else:
                control_measurements.append(0)

            # Bit de chave (simulado)
            key_bits.append(np.random.randint(0, 2))

        self.n_detected_total = n_detected
        session_aborted = n_detected >= self.detection_threshold

        if session_aborted:
            return ICOQKDResult(
                key=b'',
                control_measurements=control_measurements,
                detection_probability=n_detected / self.n_qubits,
                session_aborted=True,
                abort_reason=(f"Eve detectado: {n_detected} medições "
                              f"de controle (limiar={self.detection_threshold})"),
                n_qubits_used=self.n_qubits
            )

        key = bytes(np.packbits(key_bits).tolist())
        return ICOQKDResult(
            key=key,
            control_measurements=control_measurements,
            detection_probability=n_detected / self.n_qubits,
            session_aborted=False,
            n_qubits_used=self.n_qubits
        )

    def power_against_eve(self, p_eve: float) -> float:
        """Potência do teste contra Eve."""
        return stats.binom.sf(self.detection_threshold - 1,
                              self.n_qubits, p_eve)
