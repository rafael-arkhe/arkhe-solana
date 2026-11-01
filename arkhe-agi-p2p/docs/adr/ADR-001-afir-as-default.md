# ADR-001: AFiR como Mecanismo Padrão de Proveniência

## Contexto
O ZKML possui overhead de até 1000x para modelos grandes, e TEEs introduzem dependência de fabricantes de silício. O AFiR oferece assinaturas pós-quânticas ML-DSA-65 de 384 bytes com 0.785 ms de latência.

## Decisão
Adotar o AFiR como o mecanismo padrão de proveniência na Camada 2, reservando ZKML apenas para fragmentos de alto risco.
