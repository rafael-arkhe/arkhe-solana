# Camada 1: Distribuição e Consenso

## OmniNode
- Pesos são particionados por bloco de atenção e feed-forward de transformadores.
- O hash BLAKE3 gera identificadores determinísticos encapsulados em multihash CIDv1 (`bafk...`).
- O nó valida o digest do chunk antes de disponibilizar para a rede.

## Hyperspace
- Consenso em DAG assíncrono Mysticeti.
- Canais de pagamento bidirecionais de streaming por token ou fragmento computado.

## Petals
- Fallback em topologia em anel ou enxame quando modelos excedem o orçamento de nós locais.
- Toda inferência Petals requer recibo AFiR emitido por cada nó que processou a camada.
