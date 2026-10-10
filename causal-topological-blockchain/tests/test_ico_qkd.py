import pytest
from src.ico_qkd import ICOQKDProtocol


def test_no_eve_no_false_positive():
    """Sem Eve, a taxa de falso positivo deve ser baixa."""
    qkd = ICOQKDProtocol(n_qubits=500, p_detect_honest=0.001)
    qkd.calibrate_threshold(alpha=0.01)
    fp_count = 0
    for _ in range(1000):
        result = qkd.run_session(has_eve=False)
        if result.session_aborted:
            fp_count += 1
    fp_rate = fp_count / 1000
    assert fp_rate < 0.05, f"FP rate = {fp_rate}"


def test_eve_detected():
    """Com Eve interceptando 30% dos qubits, detecção deve ser alta."""
    qkd = ICOQKDProtocol(n_qubits=500, p_detect_honest=0.001)
    qkd.calibrate_threshold(alpha=0.01)
    tp_count = 0
    for _ in range(100):
        result = qkd.run_session(has_eve=True,
                                 eve_intercept_prob=0.30)
        if result.session_aborted:
            tp_count += 1
    tp_rate = tp_count / 100
    assert tp_rate > 0.80, f"TP rate = {tp_rate}"
