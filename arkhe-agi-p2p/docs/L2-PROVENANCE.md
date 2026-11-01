# Camada 2: Proveniência da Inferência

## Perfil AFiR
- Algoritmo: ML-DSA-65 (FIPS 204).
- Tamanho: 384 bytes de envelope de assinatura.
- Desempenho: ~0.785 ms de overhead por fragmento.
- TEE-free: não depende de enclaves fechados de fabricantes para garantia criptográfica primária.

## IETF SPICE
- Estrutura de dados: `inference_chain` (Merkle tree binária append-only).
- Nós intermediários: BLAKE3 com domínio `SPICE:INFERENCE:NODE\0`.
- ZKML opcional para verificação estrita de circuitos.
