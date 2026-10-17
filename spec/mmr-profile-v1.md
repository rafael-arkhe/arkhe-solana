# Arkhe MMR Profile v1

This document defines the standard for Merkle Mountain Range (MMR) generation and verification within the Arkhe ecosystem.

## Profile Parameters

| Parameter | Value | Justification |
| :--- | :--- | :--- |
| **Domain Separation** | `LeafHash = BLAKE3(0x00 \|\| leaf)`<br>`NodeHash = BLAKE3(0x01 \|\| left \|\| right)` | Aligned with RFC 6962; strong and widely used convention. |
| **Bagging Order** | **Right to left** | Common convention (e.g., Grin, `ckb-merkle-mountain-range`). |
| **Size Prefix** | **Include total MMR size in bagging hash:** `H(size \|\| peak_i \|\| acc)` | Prevents cross-size confusion attacks, as seen in the Grin convention. The size is serialized as an 8-byte big-endian unsigned integer, and the domain separator is `0x02`. So the hash is `BLAKE3(0x02 \|\| size_u64_be \|\| peak_i \|\| acc)`. |
| **Index Convention** | **Leaf 0 is leftmost** | Aligns with the append-only intuition (add to the right). |

## ProfileRef

The profile is uniquely identified by the following identifier and digest (which can be derived from the contents or treated as a stable reference):

- **ProfileRef**: `arkhe:mmr-profile:v1`
- **Digest (SHA-256 of parameters)**: 8f63b7e6fcf46e14f041a2498c2c39eb330ce0d04c3c69dd2a14b957b05a3ae2

## Hashing and Bagging Rules

1. **Leaf nodes:** `BLAKE3(0x00 || leaf_data)`
2. **Internal nodes:** `BLAKE3(0x01 || left_hash || right_hash)`
3. **Bagging:** Let `peaks` be the list of peak hashes ordered from left to right (highest to lowest height).
   - If `peaks` is empty, the root is `BLAKE3("")`.
   - Otherwise, `acc = peaks[-1]`.
   - For `i` from `len(peaks) - 2` down to `0`:
     `acc = BLAKE3(0x02 || size_u64_be || peaks[i] || acc)`
   - The final `acc` is the root hash.
