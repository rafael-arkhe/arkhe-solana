use arkhe_provenance_mcp::metering::{
    ExistingUsage, MeteringError, UsageEvent, UsageLedgerPort,
};
use arkhe_provenance_mcp::preflight::{
    PreflightCheck, PreflightError, PreflightEvidence, PreflightPort, PreflightRequest,
    VerifiedPreflight,
};
use arkhe_provenance_mcp::tools::provenance::{
    ProvenanceError, ProvenanceService, VerifyProvenanceRequest,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Default)]
struct FakeLedgerState {
    existing: Option<ExistingUsage>,
    appended: Vec<UsageEvent>,
    append_error: Option<String>,
    find_calls: usize,
}

#[derive(Clone, Default)]
struct FakeUsageLedger {
    state: Arc<Mutex<FakeLedgerState>>,
}

impl FakeUsageLedger {
    fn with_append_failure(message: &str) -> Self {
        let state = FakeLedgerState {
            append_error: Some(message.to_owned()),
            ..Default::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn with_existing() -> Self {
        let state = FakeLedgerState {
            existing: Some(ExistingUsage {
                request_id: Uuid::new_v4(),
                request_digest: "existing".into(),
            }),
            ..Default::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn appended_count(&self) -> usize {
        self.state.lock().unwrap().appended.len()
    }
}

#[async_trait]
impl UsageLedgerPort for FakeUsageLedger {
    async fn find_idempotency(
        &self,
        _tenant_id: &str,
        _idempotency_key: &str,
    ) -> Result<Option<ExistingUsage>, MeteringError> {
        let mut state = self.state.lock().unwrap();
        state.find_calls += 1;
        Ok(state.existing.clone())
    }

    async fn append(&self, event: UsageEvent) -> Result<(), MeteringError> {
        let mut state = self.state.lock().unwrap();
        if let Some(message) = &state.append_error {
            return Err(MeteringError::Unavailable(message.clone()));
        }
        state.appended.push(event);
        Ok(())
    }
}

#[derive(Default)]
struct FakePreflightState {
    calls: usize,
    error: Option<String>,
}

#[derive(Clone, Default)]
struct FakePreflight {
    state: Arc<Mutex<FakePreflightState>>,
}

impl FakePreflight {
    fn calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }

    fn pass() -> VerifiedPreflight {
        let evidence = PreflightEvidence {
            result: "PASS".into(),
            mode: "release".into(),
            verifier_version: "v23".into(),
            verifier_sha256: "a".repeat(64),
            content_hash: "abc".into(),
            envelope_hash: Some("b".repeat(64)),
            hard_failures: 0,
            checks: vec![PreflightCheck {
                id: "I1".into(),
                passed: true,
            }],
        };
        let raw_response = serde_json::to_vec(&evidence).unwrap();
        VerifiedPreflight {
            evidence,
            raw_response,
        }
    }
}

#[async_trait]
impl PreflightPort for FakePreflight {
    async fn verify(&self, _request: PreflightRequest) -> Result<VerifiedPreflight, PreflightError> {
        let mut state = self.state.lock().unwrap();
        state.calls += 1;
        if let Some(message) = &state.error {
            return Err(PreflightError::Transport(message.clone()));
        }
        Ok(Self::pass())
    }
}

fn request() -> VerifyProvenanceRequest {
    VerifyProvenanceRequest {
        tenant_id: "integration-tenant".into(),
        idempotency_key: "integration-idem".into(),
        report: serde_json::json!({"content_hash": "abc"}),
        mode: "release".into(),
        online: true,
        c2pa_a: Some("a".into()),
        c2pa_b: Some("b".into()),
    }
}

#[tokio::test]
async fn public_behavior_success_commits_usage_event() {
    let ledger = FakeUsageLedger::default();
    let preflight = FakePreflight::default();
    let service = ProvenanceService::new(Arc::new(ledger.clone()), Arc::new(preflight.clone()));

    let response = service.verify(request()).await.unwrap();

    assert_eq!(response.result, "PASS");
    assert_eq!(ledger.appended_count(), 1);
    assert_eq!(preflight.calls(), 1);
}

#[tokio::test]
async fn public_behavior_metering_failure_is_fail_closed() {
    let ledger = FakeUsageLedger::with_append_failure("ledger unavailable");
    let preflight = FakePreflight::default();
    let service = ProvenanceService::new(Arc::new(ledger), Arc::new(preflight));

    let result = service.verify(request()).await;

    assert!(matches!(result, Err(ProvenanceError::Metering(_))));
}

#[tokio::test]
async fn public_behavior_duplicate_idempotency_does_not_execute_preflight() {
    let ledger = FakeUsageLedger::with_existing();
    let preflight = FakePreflight::default();
    let service = ProvenanceService::new(Arc::new(ledger), Arc::new(preflight.clone()));

    let result = service.verify(request()).await;

    assert!(matches!(result, Err(ProvenanceError::DuplicateRequest)));
    assert_eq!(preflight.calls(), 0);
}
