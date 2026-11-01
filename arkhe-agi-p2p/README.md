# Arkhe AGI-P2P: Pilha de Verificação em Profundidade

O framework **arkhe-agi-p2p** integra os principais projetos do ecossistema de inteligência artificial ponto-a-ponto (**Petals**, **Hyperspace**, **OmniNode**, **A.N.N.**, **OpenCLAW-P2P**, **IETF SPICE**, **AFiR**) e fornece a camada fundamental de evidência local e auditabilidade offline: o **ArkheOS Mobile**.

```text
┌─────────────────────────────────────────────────────────────────────┐
│ L4 — GOVERNANÇA E INCENTIVOS                                        │
│ OpenCLAW-P2P (BFT + reputação) · A.N.N. (sem autoridade central)   │
│ Risco residual: Sybil, colusão, escala do BFT                      │
├─────────────────────────────────────────────────────────────────────┤
│ L3 — EVIDÊNCIA LOCAL E CONSISTÊNCIA HISTÓRICA                       │
│ ArkheOS Mobile: MobileWER · MMR selado pelo StrongBox               │
│ Binding: attestation_blob ↔ MobileWER · OfflineVerificationBundle   │
│ Risco residual: comprometimento do Titan M2                         │
├─────────────────────────────────────────────────────────────────────┤
│ L2 — PROVENIÊNCIA DA INFERÊNCIA                                     │
│ IETF SPICE (inference_root) · AFiR (ML-DSA-65, TEE-free)           │
│ ZKML (opcional, verificação forte) · TEE (aceleração)              │
│ Risco residual: AFiR não prova correção; ZKML é caro; TEE é do      │
│ fabricante                                                          │
├─────────────────────────────────────────────────────────────────────┤
│ L1 — DISTRIBUIÇÃO E CONSENSO                                        │
│ Petals (camadas) · Hyperspace (Mysticeti DAG)                       │
│ OmniNode (BLAKE3 → CIDv1, SUM Chain)                                │
│ Risco residual: nó malicioso devolve output adulterado (Petals);    │
│ atestação off-chain conluiável (OmniNode)                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Estrutura do Workspace

- **`crates/l1-distribution/`**:
  - `arkhe-omninode-client`: chunker de modelos por transformer block e BLAKE3 -> CIDv1.
  - `arkhe-hyperspace-sdk`: canais de micropagamentos e leitor de DAG Mysticeti.
  - `arkhe-petals-adapter`: roteador de camadas em swarm.
- **`crates/l2-provenance/`**:
  - `arkhe-spice`: árvore append-only `inference_chain`, verificação ZKML e TEE quote.
  - `arkhe-afir`: recibos pós-quânticos ML-DSA-65 de 384 bytes e verificador offline.
  - `arkhe-inference-router`: roteamento semântico de proveniência.
- **`crates/l3-evidence/`**:
  - `arkhe-mobile-wer`: `MobileWER` e binding criptográfico com o Titan M2 / StrongBox.
  - `arkhe-mobile-mmr`: Merkle Mountain Range local selada e checkpoints assinados híbridos.
  - `arkhe-mobile-verify`: `OfflineVerificationBundle` e verificação completa sem servidor.
- **`crates/l4-governance/`**:
  - `arkhe-openclaw`: consenso BFT tolerante a falhas bizantinas (20%) e reputação.
  - `arkhe-ann-spec`: especificação formal de acumulador quase-periódico sem autoridade central.
- **`services/`**: nós executáveis de OmniNode e Hyperspace.
- **`packages/`**: MCP server em TypeScript com suporte a verificação e SDK.
- **`contracts/`**: contratos Solidity para liquidação e atestação.
- **`mobile/`**: aplicação Android em Kotlin e ponte JNI nativa em Rust.

## Como Executar

```bash
# Compilar e testar todo o workspace
cargo build --workspace
cargo test --workspace
```
