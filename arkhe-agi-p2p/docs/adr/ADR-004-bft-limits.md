# ADR-004: Limites de Escala do BFT e Resistência a Sybil

## Contexto
O BFT finaliza em 60s em redes de 20 nós com até 20% bizantinos, mas não escala para milhares de nós permissionless.

## Decisão
Usar BFT apenas para decisões críticas locais/regionais e governança, enquanto o alto throughput de liquidação é tratado pelo DAG Mysticeti.
