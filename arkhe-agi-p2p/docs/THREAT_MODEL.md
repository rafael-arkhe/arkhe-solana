# Modelo de Ameaças e Limites Declarados

| Risco Residual | Mitigação no Framework | Limite Declarado |
| :--- | :--- | :--- |
| **Nó malicioso devolve output adulterado** | AFiR verificado contra o `inference_root` ancorado no MMR | O nó pode errar, mas não forja assinatura válida |
| **Comprometimento do Titan M2** | Checkpoint híbrido (StrongBox ML-DSA + TEE Ed25519) | Se o hardware seguro for quebrado, o binding de hardware falha |
| **Ataque Sybil em governança** | Quórum BFT qualificado e limites de peso por reputação | Governança aberta requer proof-of-personhood para evitar Sybil completo |
| **Atraso térmico / consumo móvel** | Inferência híbrida particionada via OmniNode/Petals | Dispositivos móveis atuam primariamente como nós de evidência (L3) |
