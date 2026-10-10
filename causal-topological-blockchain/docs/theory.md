# Fundamentos Teóricos

## 1. QKD com Ordem Causal Indefinida (ICO)

O protocolo de Spencer-Wood (2025) coloca as operações de Alice e Bob
em superposição de ordens causais através de um quantum switch fotônico.
A detecção de eavesdroppers ocorre via medição do qubit de controle,
sem comparação pública de subconjunto da chave.

**Teorema principal:** É impossível para um eavesdropper, realizando
qualquer ataque individual, extrair informação útil sobre a chave sem
induzir probabilidade não-nula de detecção.

**Limitação:** A prova cobre apenas ataques individuais. Ataques
coletivos com memória quântica entre rodadas não são analisados.

## 2. Wegman-Carter MAC

O Wegman-Carter MAC oferece segurança informação-teórica (incondicional)
via hash universal + one-time pad. A segurança não depende de hipóteses
computacionais, sendo resistente inclusive a computadores quânticos.

**Estrutura:** MAC = H_{k_hash}(m) XOR k_otp

**Limitação:** Requer uso estrito one-time das chaves, impondo alta
demanda por geração de chaves QKD.

## 3. DAG Causal (Mysticeti/FinWhale)

O Mysticeti é um protocolo de consenso DAG-based BFT implantado na
Sui blockchain. A liveness é altamente sensível ao comportamento de
round-jumping dos participantes honestos.

**Correção:** Uma restrição simples no round-jumping (salto absoluto)
restaura a liveness do protocolo.

**FinWhale:** Estende Mysticeti com fast-path que atinge terminação
em dois delays de mensagem, tolerando n = 3f + 2p - 1 faltas bizantinas.

## 4. Integração L0 + L3

A integração usa as chaves QKD-ICO para autenticar mensagens de consenso
via Wegman-Carter MAC. A estratificação de chaves (K_evid, K_cons) permite
auditoria pública via delayed key disclosure.
