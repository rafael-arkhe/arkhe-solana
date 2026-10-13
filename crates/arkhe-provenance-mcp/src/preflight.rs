use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AssetRef {
    pub url: String,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyProvenanceArgs {
    /// Metering label. Phase A treats this as caller-supplied/untrusted until OAuth is enabled.
    pub tenant_id: String,
    /// Caller-generated idempotency key. Reuse is rejected in Phase A.
    pub idempotency_key: String,
    /// Full Arkhe report JSON.
    pub report: Value,
    pub audio_a: AssetRef,
    pub audio_b: AssetRef,
    #[serde(default)]
    pub c2pa_a: Option<AssetRef>,
    #[serde(default)]
    pub c2pa_b: Option<AssetRef>,
    /// `sanity` or `release`.
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub online: bool,
}

fn default_mode() -> String {
    "sanity".to_owned()
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightVerifyRequest {
    pub mode: String,
    pub report: Value,
    pub audio_a: AssetRef,
    pub audio_b: AssetRef,
    pub c2pa_a: Option<AssetRef>,
    pub c2pa_b: Option<AssetRef>,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseGate {
    pub applied: bool,
    pub passed: Option<bool>,
    #[serde(default)]
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckEntry {
    pub id: String,
    pub name: String,
    pub result: String,
    pub severity: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightEvidence {
    pub result: String,
    pub mode: String,
    pub verifier_version: String,
    pub verifier_sha256: String,
    pub content_hash: Option<String>,
    pub envelope_hash: Option<String>,
    pub release_gate: ReleaseGate,
    pub hard_failures: u32,
    #[serde(default)]
    pub checks: Vec<CheckEntry>,
}

#[derive(Debug, Clone)]
pub struct VerifiedPreflightResponse {
    pub evidence: PreflightEvidence,
    /// SHA-256 of the exact HTTP response body returned by the private preflight service.
    pub wire_sha256: String,
    pub wire_len: usize,
}

#[derive(Clone)]
pub struct PreflightClient {
    client: Client,
    base_url: String,
}

impl PreflightClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(330))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        })
    }

    pub async fn verify(&self, args: &VerifyProvenanceArgs) -> anyhow::Result<VerifiedPreflightResponse> {
        validate_request(args)?;

        let req = PreflightVerifyRequest {
            mode: args.mode.clone(),
            report: args.report.clone(),
            audio_a: args.audio_a.clone(),
            audio_b: args.audio_b.clone(),
            c2pa_a: args.c2pa_a.clone(),
            c2pa_b: args.c2pa_b.clone(),
            online: args.online,
        };

        let url = format!("{}/internal/verify", self.base_url);
        let response = self.client.post(url).json(&req).send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            anyhow::bail!(
                "preflight returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }

        let wire_sha256 = hex::encode(Sha256::digest(&body));
        let wire_len = body.len();
        let evidence: PreflightEvidence = serde_json::from_slice(&body)?;
        validate_evidence(args, &evidence)?;
        Ok(VerifiedPreflightResponse {
            evidence,
            wire_sha256,
            wire_len,
        })
    }
}

fn validate_request(args: &VerifyProvenanceArgs) -> anyhow::Result<()> {
    if args.mode != "sanity" && args.mode != "release" {
        anyhow::bail!("mode must be 'sanity' or 'release'");
    }
    if args.tenant_id.trim().is_empty() || args.idempotency_key.trim().is_empty() {
        anyhow::bail!("tenant_id and idempotency_key are required");
    }
    if args.mode == "release" && (!args.online || args.c2pa_a.is_none() || args.c2pa_b.is_none()) {
        anyhow::bail!("release requires online=true and c2pa_a/c2pa_b");
    }
    Ok(())
}

fn report_str<'a>(report: &'a Value, key: &str) -> Option<&'a str> {
    report.get(key).and_then(Value::as_str)
}

pub(crate) fn validate_evidence(
    args: &VerifyProvenanceArgs,
    evidence: &PreflightEvidence,
) -> anyhow::Result<()> {
    if evidence.mode != args.mode {
        anyhow::bail!("preflight mode mismatch");
    }
    if evidence.result != "PASS" && evidence.result != "FAIL" {
        anyhow::bail!("invalid preflight result");
    }

    // Evidence check IDs must be unique. A consumer must never collapse conflicting checks.
    let mut ids = HashSet::new();
    for check in &evidence.checks {
        if !ids.insert(check.id.as_str()) {
            anyhow::bail!("duplicate preflight check id: {}", check.id);
        }
    }

    if args.mode == "release" {
        if !evidence.release_gate.applied {
            anyhow::bail!("release evidence did not apply release gate");
        }
        if evidence.result == "PASS" && evidence.release_gate.passed != Some(true) {
            anyhow::bail!("release PASS without release_gate.passed=true");
        }
    } else if evidence.release_gate.applied || evidence.release_gate.passed.is_some() {
        anyhow::bail!("sanity evidence has invalid release gate state");
    }

    if evidence.result == "PASS" {
        if evidence.hard_failures != 0 {
            anyhow::bail!("PASS evidence contains hard failures");
        }
        if evidence.checks.is_empty() {
            anyhow::bail!("PASS evidence contains no checks");
        }

        let report_content = report_str(&args.report, "content_hash")
            .ok_or_else(|| anyhow::anyhow!("report missing content_hash"))?;
        if evidence.content_hash.as_deref() != Some(report_content) {
            anyhow::bail!("content_hash subject mismatch");
        }

        let report_script = report_str(&args.report, "script_sha256")
            .ok_or_else(|| anyhow::anyhow!("report missing script_sha256"))?;
        if evidence.verifier_sha256 != report_script {
            anyhow::bail!("verifier_sha256 subject mismatch");
        }

        if args.mode == "release" {
            let report_envelope = report_str(&args.report, "envelope_hash")
                .ok_or_else(|| anyhow::anyhow!("release report missing envelope_hash"))?;
            if evidence.envelope_hash.as_deref() != Some(report_envelope) {
                anyhow::bail!("envelope_hash subject mismatch");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(mode: &str) -> VerifyProvenanceArgs {
        VerifyProvenanceArgs {
            tenant_id: "tenant-a".into(),
            idempotency_key: "idem-a".into(),
            report: json!({
                "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "envelope_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "script_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }),
            audio_a: AssetRef { url: "https://assets.example/a".into(), expected_sha256: "0".repeat(64) },
            audio_b: AssetRef { url: "https://assets.example/b".into(), expected_sha256: "1".repeat(64) },
            c2pa_a: if mode == "release" { Some(AssetRef { url: "https://assets.example/a".into(), expected_sha256: "0".repeat(64) }) } else { None },
            c2pa_b: if mode == "release" { Some(AssetRef { url: "https://assets.example/b".into(), expected_sha256: "1".repeat(64) }) } else { None },
            mode: mode.into(),
            online: mode == "release",
        }
    }

    fn pass_evidence(mode: &str) -> PreflightEvidence {
        PreflightEvidence {
            result: "PASS".into(),
            mode: mode.into(),
            verifier_version: "23".into(),
            verifier_sha256: "c".repeat(64),
            content_hash: Some("a".repeat(64)),
            envelope_hash: if mode == "release" { Some("b".repeat(64)) } else { None },
            release_gate: ReleaseGate {
                applied: mode == "release",
                passed: if mode == "release" { Some(true) } else { None },
                issues: vec![],
            },
            hard_failures: 0,
            checks: vec![CheckEntry { id: "I1".into(), name: "test".into(), result: "PASS".into(), severity: "hard".into(), detail: String::new() }],
        }
    }

    #[test]
    fn release_pass_requires_some_true() {
        let a = args("release");
        let mut e = pass_evidence("release");
        e.release_gate.passed = None;
        assert!(validate_evidence(&a, &e).is_err());
    }

    #[test]
    fn sanity_rejects_applied_release_gate() {
        let a = args("sanity");
        let mut e = pass_evidence("sanity");
        e.release_gate.applied = true;
        assert!(validate_evidence(&a, &e).is_err());
    }

    #[test]
    fn pass_binds_content_hash() {
        let a = args("sanity");
        let mut e = pass_evidence("sanity");
        e.content_hash = Some("d".repeat(64));
        assert!(validate_evidence(&a, &e).is_err());
    }

    #[test]
    fn pass_binds_verifier_hash() {
        let a = args("sanity");
        let mut e = pass_evidence("sanity");
        e.verifier_sha256 = "d".repeat(64);
        assert!(validate_evidence(&a, &e).is_err());
    }

    #[test]
    fn duplicate_check_ids_are_rejected() {
        let a = args("sanity");
        let mut e = pass_evidence("sanity");
        e.checks.push(e.checks[0].clone());
        assert!(validate_evidence(&a, &e).is_err());
    }
}
