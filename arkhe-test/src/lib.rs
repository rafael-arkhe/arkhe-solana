//! arkhe-test: Suíte contínua de testes e falsificadores para o ecossistema Arkhe.
//! Transforma os critérios do whitepaper Arkhe AGI-P2P em evidência auditável,
//! implementando os testes estritos dos invariantes I-01 a I-10 e I-T01 a I-T08.

pub mod harness;
pub mod suites;

pub use harness::flags_guard::verify_feature_flags_policy;
pub use harness::rollback_guard::simulate_safe_rollback;
