# Arkhe-Test: Pipeline Contínuo de Invariantes e Falsificadores

O `arkhe-test` é o mecanismo contínuo que transforma as especificações do whitepaper em evidência criptográfica auditável. Nenhuma funcionalidade entra em produção sem um teste que possa reprová-la.

## Estrutura do Módulo

```text
arkhe-test/
  vectors/           # Vetores canônicos e de falsificação (AFiR, MMR, Checkpoint, Fraud)
  suites/            # Testes dos 10 invariantes (I-01 a I-10) e estágios do pipeline
  harness/           # Guards de Feature Flags (I-T06) e Rollback Seguro (I-T05)
  reports/           # Relatórios assinados e content-addressed por execução
  policies/          # Políticas TOML: flags.toml, release.toml, rollback.toml
  pipeline_runner.py # Orquestrador dos Estágios 1, 2 e 3 (< 5s localmente)
```

## Como Executar

```bash
# Executar suíte completa de invariantes
cd arkhe-test && cargo test

# Executar os três estágios do pipeline e emitir relatório auditável
python3 arkhe-test/pipeline_runner.py
```
