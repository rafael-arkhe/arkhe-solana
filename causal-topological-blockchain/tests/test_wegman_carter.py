import pytest
import hmac
from src.wegman_carter import WegmanCarterMAC, derive_keys


def test_derive_keys():
    qkd_key = b"test_key_12345678901234567890123"
    k_hash, k_otp = derive_keys(qkd_key)
    assert len(k_hash) == 32
    assert len(k_otp) == 32
    assert k_hash != k_otp


def test_wegman_carter_sign_verify():
    mac = WegmanCarterMAC()
    signer_id = b"alice"
    peer_id = b"bob"
    qkd_key = b"test_key_12345678901234567890123"

    mac.import_qkd_key(signer_id, peer_id, qkd_key)

    message = b"test message"
    result = mac.sign(signer_id, peer_id, message)
    assert result is not None

    mac_val, key_idx = result

    assert mac.verify(signer_id, peer_id, message, mac_val, key_idx)
    assert not mac.verify(signer_id, peer_id, b"tampered message", mac_val, key_idx)
