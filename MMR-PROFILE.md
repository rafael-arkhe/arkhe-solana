# Arkhe MMR Profile v1

This document specifies the exact profile configuration for the Merkle Mountain Range (MMR) used within the Arkhe project.

## Profile Configuration

1. **Domain Separation**:
   The hashing algorithm strictly uses **BLAKE3**. Domain separation is enforced using the following byte prefixes before hashing:
   - `0x00`: Leaf node
   - `0x01`: Internal node
   - `0x02`: Root
   - `0x03`: Bagging

2. **Peak Ordering**:
   Peaks are ordered based on their position in the tree structure (standard mountain range logic).

3. **Bagging Direction**:
   **Right-to-Left**. When bagging peaks to compute the final root, the operation processes peaks from the rightmost (smallest) to the leftmost (largest).

4. **Accumulator Initialization (`acc init`)**:
   Unconditional bagging is enforced. The bagging process always includes the total MMR size (number of leaves) serialized as an 8-byte big-endian integer as a prefix, even if there is only a single peak.

5. **Empty Tree Representation**:
   The root of an empty MMR (0 leaves) is explicitly defined, ensuring deterministic validation of empty states.

6. **Inclusion Proof Format**:
   Specifies the portable format for proving a leaf's inclusion within a specific MMR root, verifiable offline in O(log n) time.

7. **Consistency Proof Format**:
   Specifies the format for append-only proofs, demonstrating that a new MMR state is a valid extension of a prior state.