from src.prototype_runner import PrototypeL0L3


def test_cycle_without_eve():
    """Ciclo sem Eve deve completar com sucesso."""
    proto = PrototypeL0L3(n_validators=4, n_qubits=200)
    result = proto.run_cycle(n_tx=4, has_eve=False)
    assert result["status"] == "success"
    assert result["macs_verified"] == result["blocks_proposed"]


def test_cycle_with_eve():
    """Ciclo com Eve deve abortar no QKD-ICO."""
    proto = PrototypeL0L3(n_validators=4, n_qubits=200)
    result = proto.run_cycle(n_tx=4, has_eve=True,
                              eve_intercept_prob=0.50)
    assert result["status"] == "aborted"
