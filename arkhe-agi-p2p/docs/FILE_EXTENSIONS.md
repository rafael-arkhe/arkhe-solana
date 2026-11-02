# Arkhe File Extensions & Artifact Formats Specification

Normative specification for file extensions across all layers of Arkhe AGI-P2P.

See full specification at [docs/architecture/file-extensions.md](../../docs/architecture/file-extensions.md).

## Summary by Layer

1. **Identity & Content**: `.cid`, `.multihash`, `.pub`, `.sig`, `.cert`, `.crl`, `.keystore`, `.seed`.
2. **Manifests & Models**: `.arkmanifest`, `.arkmanifest.sig`, `.gguf`, `.gguf.part`, `.gguf.index`, `.quant`, `.lineage`, `.eval`, `.dataset`, `.tokenizer`, `.vocab`.
3. **Receipts & Evidence**: `.afir`, `.afir.json`, `.afirtree`, `.wer`, `.mmr`, `.mmrproof`, `.consistency`, `.checkpoint`, `.attest`, `.arkbundle`, `.wasm`.
4. **Network & Discovery**: `.peers`, `.peerledger`, `.seeds`, `.dhtcache`, `.announce`, `.gossip`, `.netpolicy`, `.pcap`.
5. **Inference & Execution**: `.policy`, `.policy.sig`, `.request`, `.response`, `.session`, `.router`, `.expertmap`, `.kv`, `.gpu`, `.onnx`, `.safetensors`.
6. **Verification & Frauds**: `.fraudproof`, `.reexec`, `.zkproof`, `.teequote`, `.verdict`, `.slash`, `.golden`.
7. **Economy & Governance**: `.constitution`, `.constitution.sig`, `.proposal`, `.vote`, `.canon`, `.emission`, `.reward`, `.stake`, `.epoch`, `.gini`.
8. **Chain Integration (CAL)**: `.anchor`, `.ibc`, `.ccip`, `.layerzero`, `.abi`, `.sol`, `.move`, `.tx`, `.receiptroot`.
9. **Build, Test & Supply Chain**: `.toml`, `.rs`, `.ts`, `.cs`, `.csproj`, `.wasm`, `.wat`, `.json`, `.lock`, `.sbom`, `.provenance`, `.sha256`, `.sigstore`, `.log`, `.trace`.

## Security Rules
- **Prohibited Extensions**: Unencrypted `.pem`, production `.env`, MMR/checkpoint `.bak`, payload `.dump`.
- **Restricted Extensions**: Native binaries `.dll`, `.exe`, `.so`, `.dylib` (must have hash, signature and SLSA provenance), ephemeral receipt `.tmp` (must be atomically renamed or discarded).
- **Fail-Closed Principle**: Any corrupted file, missing signature, or digest mismatch strictly aborts execution.
