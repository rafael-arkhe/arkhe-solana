# Blockchain Causal-Topológica

Protótipo funcional L0+L3: QKD-ICO + DAG Causal com autenticação
Wegman-Carter e auditoria pública via delayed key disclosure.

## Componentes

| Módulo | Descrição | Base na Literatura |
|---|---|---|
| **QKD-ICO** | Detecção de eavesdropper sem comparação pública | Spencer-Wood (2025) |
| **Wegman-Carter MAC** | Autenticação informação-teórica | ArXiv:2603.14826 |
| **DAG Causal** | Consenso BFT com correção de round-jumping | Qiu et al. (2026) |
| **Delayed Disclosure** | Auditoria pública via revelação atrasada | ArXiv:2603.14826 |

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
cd src
python prototype_runner.py
```

## Resultados Esperados

**Sem Eve:** Sessões QKD completam, MACs verificam, blocos são
commitados, auditoria passa.

**Com Eve:** Sessão QKD aborta, chaves não são integradas, nenhuma
transação é proposta.

## Limitações

- Redução de segurança formal ausente para a composição L0+L3.
- Pós-seleção no quantum switch limita o QKD-ICO a prova de princípio.
- Ataques coletivos não são cobertos pela prova de segurança.
- Incentivos e Sybil resistance fora do escopo.

## Licença

MIT.
