# Camada 3: Evidência Local (ArkheOS Mobile)

## MobileWER (Work Evidence Record)
Cada ação relevante de inferência gera um registro contendo:
- `device_attestation_hash`: `H(attestation_blob || first_wer_nonce || app_measurement)`
- `app_id`: hash do APK/APEX verificado no boot.
- `action`: enum estruturado da inferência.
- `input_digest`, `output_digest`, `policy_digest`.

## MMR Selado pelo StrongBox
- Perfil Arkhe MMR v1: Right-to-Left peak bagging.
- Checkpoint assinado distribuído:
  - StrongBox (Android 17): assinatura ML-DSA-65.
  - TEE / Software: assinatura Ed25519.
- O verificador offline valida tanto o MMR quanto as assinaturas sem qualquer chamada a servidor.
