# Limitações Declaradas

## O que NÃO foi demonstrado

1. **Redução de segurança formal:** A composição QKD-ICO + Wegman-Carter
   + DAG não tem prova formal de que a vantagem de Eve é negligenciável
   sob ataques coletivos. A prova de Spencer-Wood cobre apenas ataques
   individuais no protocolo QKD isolado.

2. **Pós-seleção no quantum switch:** A implementação experimental de
   Valibouse et al. (2026) não constitui ainda um protocolo de QKD seguro
   devido à pós-seleção necessária para medições dentro do SWITCH.

3. **Interface L0-L3 formal:** A integração funcional implementada não
   constitui uma redução de segurança. A interface entre QKD-ICO e DAG
   não existe na literatura.

4. **Ataques coletivos:** Ataques com memória quântica entre rodadas
   não são analisados pela prova de Spencer-Wood.

5. **Incentivos e Sybil resistance:** O protótipo não aborda seleção de
   validadores, proteção contra Sybil ou incentivos econômicos.

## Barreiras técnicas imediatas

- **Pós-seleção:** Sem superá-la, o QKD-ICO permanece uma prova de
  princípio, não um protocolo operacional.
- **Consumo de chaves:** O Wegman-Carter exige uso one-time, impondo
  alta demanda por geração de chaves QKD.
- **Latência:** A pós-seleção pode introduzir latência adicional que
  afeta o consenso DAG.
