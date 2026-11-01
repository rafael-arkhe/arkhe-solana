# RFC-0001: ArkheOS — Distro Linux de Verificação Fail-Closed
Data: 2026-10-31
Status: DRAFT consolidado
Base: 31 iterações de design + pesquisa técnica 2026

## 1. Sumário executivo
ArkheOS é uma distribuição Linux cuja função primária não é executar aplicações, mas provar que as aplicações fizeram o que dizem ter feito. A tese central: evidência > afirmação. Cada componente carrega prova criptográfica da sua origem, autorização e execução; o sistema é verificável offline por qualquer terceiro, sem confiança no produtor.

## 2. Decisões consolidadas (inalteradas)
| Decisão | Conteúdo |
| --- | --- |
| Arquitetura aditiva | Camada de evidência sobre RBB/Besu-QBFT; não substitui consenso nem permissionamento |
| Contrato comum | UnifiedCheckpointEnvelope v2 com source_chain e source_tx_ref |
| Verificação offline | arkhe-verify.wasm + arkhe-verify-host; pipeline multi-gate |
| Fail-closed | Sem evidência verificável, a transição é negada ou declarada inconclusiva |
| Separação de dimensões | Integridade, cobertura, conciliação, autorização e âncora reportadas separadamente |
| Append-only | Evidência não é reescrita; rollback do sistema ≠ rollback da prova |
| Confiança externa | O pacote nunca contém a raiz de confiança; trust.d é fornecido externamente |
| Reprodutibilidade | Replay determinístico + build reproduzível + reprodução independente |

## 3. Camadas (L0–L6) — alterações
| Camada | Alteração face à v2 |
| --- | --- |
| L0 — Hardware | Inalterada (TPM 2.0, TEE, GPU TEE) |
| L1 — Boot | Política PCR[0,4,7,11] com systemd-pcrlock primário; re-selagem pós-actualização |
| L2 — Kernel Arkhe | MMR baseado em tari_mmr com extensão BLAKE3; arkhe-gate como daemon + BPF LSM |
| L3 — Base | bootc + composefs + fs-verity em vez de “ostree A/B”; systemd ≥ 258 e Landlock ABI ≥ 11 |
| L4 — Verificação | Gate 3.5 (Rekor body consistency); bundle auto-contido; arkhe-verify-host alinhado com sigstore-verifier |
| L5 — Interfaces | Inalterada (CLI, TUI, MCP, portal) |
| L6 — Aplicações | arkhe-custody com relatório regulatório Res. 589/2026 (existência, titularidade, cobertura, staking) |

## 4. Pipeline de verificação revisto
Gate 0 — Sanitização: limites, formato, CVEs conhecidos
Gate 1 — Hash SHA-256/BLAKE3: streaming
Gate 2 — Assinatura Sigstore: bundle v0.3, Fulcio, identity policy
Gate 3 — Rekor inclusion: checkpoint, SET, Merkle proof
Gate 3.5 — Rekor body consistency: CVE-2022-36056 guard
Gate 4 — Policy check: ConstitutionGraph / required_evidence

Invariante central: VerifyAndLoad ⇒ SignatureValid ∧ RekorEntryBindsToThisWasm ∧ RekorBodyConsistent ∧ PolicySatisfied ∧ Instantiate(same_bytes)

## 5. Requisitos de versão mínimos
| Componente | Versão mínima | Justificação |
| --- | --- | --- |
| systemd | ≥ 258 | RestrictFileSystemAccess=exec (BPF LSM) |
| Landlock | ABI ≥ 11 | Sandbox não privilegiado estendido |
| TPM 2.0 | Rev. 1.38 (2016+) | policyAuthorizeNV para systemd-pcrlock |
| tari_mmr | 5.x | Base MMR madura |

## 6. Build reprodutível (D6) — meta revista
| Métrica | Meta |
| --- | --- |
| Pacotes reprodutíveis (amd64) | ≥ 96.9% (herdada do Debian Trixie) |
| Pacotes reprodutíveis (arm64) | ≥ 96.8% |
| Allowlist de excepções | Documentada, com prazo de correção por pacote |
| .buildinfo por pacote | Publicado como o Debian faz |
| Gate por pacote | reprotest em CI; falha bloqueia release |

## 7. Invariantes globais (revisão)
| ID | Enunciado | Alteração |
| --- | --- | --- |
| INV-OS-01 | Nenhum pacote executa sem VerifyAndLoad PASS | Inalterado |
| INV-OS-02 | Toda transição protegida produz WorkerExecutionRecord | Inalterado |
| INV-OS-03 | WormGraph é append-only | Inalterado |
| INV-OS-04 | A UI mostra o que o kernel decidiu | Inalterado |
| INV-OS-05 | Estado honesto por componente | Inalterado |
| INV-OS-06 | Trust anchor ausente → recovery | Inalterado |
| INV-OS-07 | Boot determinístico (SOURCE_DATE_EPOCH) | Inalterado |
| INV-OS-08 | Build reproduzível por pacote (≥ 96.9%) | Revisto |
| INV-OS-09 | Rekor body consistency (CVE-2022-36056) | Novo |
| INV-OS-10 | Política TPM PCR[0,4,7,11] com pcrlock | Novo |
