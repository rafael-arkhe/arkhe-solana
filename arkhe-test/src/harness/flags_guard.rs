//! Invariante I-T06: Feature flags não enfraquecem segurança.
//! Proíbe terminantemente qualquer tentativa de registrar flags que desativem
//! checagem de assinatura, verificação de hash, append-only de MMR ou separação de papéis.

use std::collections::HashSet;

pub const PROHIBITED_KEYWORDS: &[&str] = &[
    "signature_check",
    "hash_check",
    "mmr_append_only",
    "role_separation",
    "bypass_attestation",
    "disable_security",
];

pub fn verify_feature_flags_policy(flags_toml_content: &str) -> Result<(), String> {
    let parsed: toml::Value = toml::from_str(flags_toml_content)
        .map_err(|e| format!("Falha ao parsear flags.toml: {}", e))?;

    let mut declared_flags = HashSet::new();

    if let Some(table) = parsed.get("allowed_flags").and_then(|v| v.as_table()) {
        for (flag_name, _) in table {
            declared_flags.insert(flag_name.to_lowercase());
        }
    }

    // Regra formal: flag not in {signature_check, hash_check, mmr_append_only, role_separation}
    for flag in &declared_flags {
        for prohibited in PROHIBITED_KEYWORDS {
            if flag.contains(prohibited) {
                return Err(format!(
                    "Violação I-T06: Feature flag '{}' tenta enfraquecer invariante crítico de segurança ('{}')",
                    flag, prohibited
                ));
            }
        }
    }

    Ok(())
}
