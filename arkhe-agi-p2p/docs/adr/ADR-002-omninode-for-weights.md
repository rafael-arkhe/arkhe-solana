# ADR-002: OmniNode para Endereçamento de Pesos por Conteúdo

## Contexto
Diferentes nós podem tentar servir modelos modificados ou adulterados.

## Decisão
Usar o padrão BLAKE3 -> CIDv1 multihash para todos os chunks de tensores, permitindo validação criptográfica estrita antes do carregamento em memória.
