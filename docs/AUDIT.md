# Golden Vectors Audit

The golden vectors have been audited and updated to reflect correct handling of CBOR canonicalization, C2PA standards, and Arkhe's specific MMR conventions.

## GGUF Canonicalization
- `GGUF-CANON-001` is marked as `READY`.
- Updated the GGUF canonicalization to use CBOR canonical mode (CDE), ensuring bytewise lexicographical sorting of keys and minimal integer widths.

## C2PA
- `C2PA-001` is marked as `READY`.
- `C2PA-NEG-001` is marked as `READY`.
- Updated C2PA vectors to use valid `claim-map-v2` fields, including `instanceID`, `signature`, `created_assertions`, and `claim_generator_info`. The `alg` field now correctly specifies a hash algorithm (`sha256`), and a negative test case was added to verify error handling for incorrect claims.

## BLAKE3
- `BLAKE3-001` and `BLAKE3-002` are marked as `READY`.
- Confirmed that the empty string and 'abc' vectors match the official BLAKE3 test vectors.

## MMR
- MMR vectors `MMR-001`, `MMR-003`, `MMR-004`, `MMR-005`, and `MMR-007` are marked as `READY`.
- The `MMRProfile` was frozen to define specific behaviors for node hashes, peak bagging, and index conventions (`spec/mmr-profile-v1.md`). With this standard frozen, we can confidently test various lengths of MMRs without ambiguity.
