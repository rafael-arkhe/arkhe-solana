use std::sync::{Arc, Mutex};
use uuid::Uuid;
use arkhe_provenance_mcp::metering::{UsageLedgerPort, UsageEvent, MeteringError};
use arkhe_provenance_mcp::preflight::{PreflightPort, VerifyProvenanceArgs, VerifiedPreflightResponse, PreflightEvidence, ReleaseGate};
use arkhe_provenance_mcp::server::ArkheMcpConfig;
use arkhe_provenance_mcp::tools::provenance::ProvenanceService;
use async_trait::async_trait;

#[derive(Debug, Clone)]
struct FakeUsageLedger {
    pub fail_append: bool,
    pub existing_idempotency: Option<Uuid>,
    pub appended_events: Arc<Mutex<Vec<UsageEvent>>>,
}

impl FakeUsageLedger {
    fn new(fail_append: bool, existing_idempotency: Option<Uuid>) -> Self {
        Self {
            fail_append,
            existing_idempotency,
            appended_events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl UsageLedgerPort for FakeUsageLedger {
    async fn append(&self, event: &UsageEvent) -> Result<(), MeteringError> {
        if self.fail_append {
            return Err(MeteringError::Unavailable);
        }
        self.appended_events.lock().unwrap().push(event.clone());
        Ok(())
    }

    async fn seen_idempotency_key(
        &self,
        _tenant_id: &str,
        _idempotency_key: &str,
    ) -> Result<Option<Uuid>, MeteringError> {
        Ok(self.existing_idempotency)
    }

    fn price_book_version(&self) -> &str {
        "v1-fake"
    }
}

#[derive(Clone)]
struct FakePreflight {
    pub response: Result<VerifiedPreflightResponse, String>,
    pub call_count: Arc<Mutex<usize>>,
}

impl FakePreflight {
    fn new(response: Result<VerifiedPreflightResponse, String>) -> Self {
        Self {
            response,
            call_count: Arc::new(Mutex::new(0)),
        }
    }
}

#[async_trait]
impl PreflightPort for FakePreflight {
    async fn verify(&self, _args: &VerifyProvenanceArgs) -> anyhow::Result<VerifiedPreflightResponse> {
        *self.call_count.lock().unwrap() += 1;
        match &self.response {
            Ok(res) => Ok(res.clone()),
            Err(e) => anyhow::bail!("{}", e),
        }
    }
}

fn test_config() -> ArkheMcpConfig {
    ArkheMcpConfig {
        sol_price_usd: Some("150".into()),
        verify_cost_usd: Some("0".into()),
        royalty_lookup_cost_usd: Some("0".into()),
    }
}

fn valid_request() -> VerifyProvenanceArgs {
    serde_json::from_value(serde_json::json!({
        "tenant_id": "test_tenant",
        "idempotency_key": "test_idem",
        "report": { "content_hash": "c_hash", "script_sha256": "v_hash" },
        "audio_a": { "url": "http://a", "expected_sha256": "a_hash" },
        "audio_b": { "url": "http://b", "expected_sha256": "b_hash" },
        "mode": "sanity"
    })).unwrap()
}

fn valid_release_verified_report() -> VerifiedPreflightResponse {
    VerifiedPreflightResponse {
        evidence: PreflightEvidence {
            result: "PASS".to_owned(),
            mode: "sanity".to_owned(),
            verifier_version: "23".to_owned(),
            verifier_sha256: "v_hash".to_owned(),
            content_hash: Some("c_hash".to_owned()),
            envelope_hash: None,
            release_gate: ReleaseGate { applied: false, passed: None, issues: vec![] },
            hard_failures: 0,
            checks: vec![],
        },
        wire_sha256: "w_hash".to_owned(),
        wire_len: 1234,
    }
}

#[tokio::test]
async fn successful_verification_is_withheld_when_metering_fails() {
    let preflight = FakePreflight::new(Ok(valid_release_verified_report()));
    let ledger = FakeUsageLedger::new(true, None);

    let service = ProvenanceService::new(
        Arc::new(ledger.clone()),
        Arc::new(preflight.clone()),
        test_config()
    );

    let result = service.verify(valid_request()).await.unwrap();

    assert!(result.is_error.unwrap_or(false));
    let error_text = serde_json::to_string(&result.content).unwrap();
    assert!(error_text.contains("metering commit failed; response withheld fail-closed"));

    // Verify preflight was called
    assert_eq!(*preflight.call_count.lock().unwrap(), 1);

    // Verify no events were appended due to failure state
    assert!(ledger.appended_events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_execution_rejected() {
    let preflight = FakePreflight::new(Ok(valid_release_verified_report()));
    let ledger = FakeUsageLedger::new(false, Some(uuid::Uuid::new_v4()));

    let service = ProvenanceService::new(
        Arc::new(ledger.clone()),
        Arc::new(preflight.clone()),
        test_config()
    );

    let result = service.verify(valid_request()).await.unwrap();

    assert!(result.is_error.unwrap_or(false));
    let error_text = serde_json::to_string(&result.content).unwrap();
    assert!(error_text.contains("idempotency key already used"));

    // Verify preflight was NEVER called
    assert_eq!(*preflight.call_count.lock().unwrap(), 0);
}

#[tokio::test]
async fn valid_verification_succeeds_and_meters() {
    let preflight = FakePreflight::new(Ok(valid_release_verified_report()));
    let ledger = FakeUsageLedger::new(false, None);

    let service = ProvenanceService::new(
        Arc::new(ledger.clone()),
        Arc::new(preflight.clone()),
        test_config()
    );

    let result = service.verify(valid_request()).await.unwrap();

    assert!(!result.is_error.unwrap_or(false));

    // Verify preflight was called
    assert_eq!(*preflight.call_count.lock().unwrap(), 1);

    // Verify event was appended
    let events = ledger.appended_events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool, "verify_provenance");
    assert_eq!(events[0].result, "PASS");
}
