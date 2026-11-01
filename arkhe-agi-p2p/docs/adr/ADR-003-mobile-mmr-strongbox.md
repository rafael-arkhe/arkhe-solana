# ADR-003: MMR Local e Checkpoints Distribuídos no StrongBox

## Contexto
O Android StrongBox (Titan M2) suporta ML-DSA no Android 17, mas não suporta Ed25519 (TEE-only).

## Decisão
Gerar checkpoints híbridos em envelope distribuído: a chave ML-DSA é isolada no StrongBox, enquanto a chave Ed25519 reside no TEE/software.
