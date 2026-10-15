import json
import hashlib
import cbor2

# Hex to bytes helper
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def canonical_cbor(obj):
    # This is a simplified canonical CBOR for python
    # We will sort dict keys
    return cbor2.dumps(obj, canonical=True)

with open("test-vectors/conformance/c01-valid-verification-record.json", "r") as f:
    c01_data = json.load(f)

# Need to properly format normative_inputs as VerificationRecord
vr = c01_data["normative_inputs"]

# We will need to map it accurately to wire projection, but this is a simplified start
print(json.dumps(vr, indent=2))
