# Arkhe

Arkhe is a hybrid blockchain architecture for AI provenance and royalty micropayments. It aligns a complex technical architecture (provenance, AI, and blockchain) with the legal and financial realities of dozens of countries. The project's architecture utilizes a hybrid blockchain model: Solana for execution and settlement (using Pay.sh/x402), and Ethereum (EVM) for liquidity and attestation (EAS).

## Three Pillars of Arkhe

1. **International Standards (C2PA and Berne Convention)**
   Arkhe positions itself as a compliance and settlement layer on top of established frameworks. Using C2PA (ISO 22144), it handles machine-readable provenance. Through the `arkhe-eu-ai-act` crate, it addresses the upcoming requirements of Article 50 of the EU AI Act, generating auditable Compliance Reports anchored on-chain.

2. **Micropayments Infrastructure (Solana)**
   Utilizing Solana for sub-second transactions and fraction-of-a-cent fees, Arkhe integrates with Pay.sh (Google Cloud), x402, and MPP protocols. Royalties are settled atomically only if a valid inclusion proof is verified on-chain via the WormGraph. The main settlement environment uses the `arkhe-verify` (Anchor) contract to validate these proofs.

3. **Interoperability (Chain-Agnostic Provenance)**
   Instead of replacing national registries, Arkhe connects to them. The `arkhe-c2pa-bridge` anchors C2PA manifests on Solana (WormGraph) and Ethereum (EAS), enabling cross-chain liquidity while maintaining efficient settlement.

## Project Structure

The Arkhe repository is structured as a Rust Cargo workspace containing multiple crates, Solana smart contracts built with the Anchor framework, and a frontend web application.

*   **`crates/`**: Contains various Rust crates such as `arkhe-core`, `arkhe-eu-ai-act`, and `arkhe-c2pa-bridge`.
*   **`programs/`**: Contains the Anchor-based Solana smart contracts (e.g., `arkhe-verify`).
*   **`frontend/`**: A Vite + React + TypeScript web application, using `vitest` for testing.
    *   **Architecture**: The frontend utilizes WebGPU for acceleration, with a fallback to WebAssembly (e.g., using `blake3-wasm-rs` or `hash-wasm`) for cryptographic operations like BLAKE3 hashing when WebGPU is unavailable.
    *   **Deployment**: The frontend is deployed to Vercel as a Single Page Application (SPA). It requires a `vercel.json` file in the `frontend/` directory configured with route rewrites to `index.html` for client-side routing, and COOP/COEP headers (`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`) for WASM SharedArrayBuffer support.

## Getting Started

To set up the project workspace locally:

1.  **Prerequisites**: Install Rust, Solana CLI, and Anchor.
2.  **Compile Rust Crates**: Run `cargo build` to compile the Rust crates.
3.  **Compile Smart Contracts**: Run `anchor build` to compile the Solana smart contracts.

### Local Development Environment

To start a local Solana node, use the provided script:

```bash
bash scripts/start-test-validator.sh
```

By default, the `sol_blake3` feature (HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3) is inactive, mirroring mainnet. To explicitly enable it for testing, use the `--blake3` flag:

```bash
bash scripts/start-test-validator.sh --blake3
```
Alternatively, you can run `solana-test-validator -r` with the feature gate explicitly enabled.

See `docs/guides/quickstart.md` and `docs/guides/local-development.md` for more detailed information.

## Testing and Contributing

We welcome contributions! Please follow these guidelines:

1.  **Formatting**: Ensure your code is properly formatted by running `cargo fmt`.
2.  **Testing**: Verify the test suite passes by running `cargo test`.
    *   **Note on `arkhe-c2pa-bridge`**: This crate has known upstream dependency resolution conflicts with `rasn` and `bs58` (via `c2pa` and `anchor-lang`). When running workspace-wide tests, it may require isolation via `default-members` in the root `Cargo.toml` or testing individually via `cargo test -p arkhe-c2pa-bridge`.
3.  **Pull Requests**: Create a branch from `main`, add tests for your code, and submit your pull request. Contributions are made under the GNU Affero General Public License version 3.
