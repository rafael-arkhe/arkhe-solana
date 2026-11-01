"""
Petals layer relay fallback server.
Integrity is guaranteed by L2 AFiR receipts, not by this relay.
"""

def forward_layer_tensor(model_id: str, layer_idx: int, input_tensor_b64: str) -> dict:
    return {
        "status": "forwarded",
        "model_id": model_id,
        "layer_idx": layer_idx,
        "input_len": len(input_tensor_b64),
        "note": "Output must be verified via AFiR receipt before MobileWER anchoring."
    }

if __name__ == "__main__":
    print("Petals relay service loaded.")
