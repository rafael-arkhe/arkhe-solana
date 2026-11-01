# Arquitetura Integrada: Pilha de Verificação em Profundidade

Esta arquitetura estabelece a ancoragem mútua entre camadas P2P distribuídas e a evidência local no dispositivo do utilizador.

## Divisão de Responsabilidades

1. **L1**: Distribuição e transporte dos fragmentos de tensores de pesos (OmniNode) e liquidação económica em streaming (Hyperspace).
2. **L2**: Geração do recibo AFiR pós-quântico de 384 bytes e Merkle root de inferência (IETF SPICE).
3. **L3**: Enlace irrefutável com hardware móvel (Titan M2 / StrongBox) e registro contínuo em MMR append-only selado localmente.
4. **L4**: Governança BFT para propostas de auto-melhoria e reputação de agentes (OpenCLAW-P2P).
