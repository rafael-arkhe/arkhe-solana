use std::sync::Arc;
use crate::{
    metering::UsageLedger,
    preflight::HttpPreflightClient,
    royalty::{RoyaltyStatusArgs, RoyaltyStore},
    tools::provenance::{ProvenanceService, VerifyProvenanceRequest},
};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct ArkheMcpConfig {
    pub sol_price_usd: Option<String>,
    pub verify_cost_usd: Option<String>,
    pub royalty_lookup_cost_usd: Option<String>,
}

impl ArkheMcpConfig {
    pub fn from_env() -> Self {
        Self {
            sol_price_usd: std::env::var("ARKHE_SOL_PRICE_USD").ok(),
            verify_cost_usd: std::env::var("ARKHE_VERIFY_ESTIMATED_COST_USD").ok(),
            royalty_lookup_cost_usd: std::env::var("ARKHE_ROYALTY_LOOKUP_ESTIMATED_COST_USD").ok(),
        }
    }
}

#[derive(Clone)]
pub struct ArkheMcp {
    pub(crate) royalties: RoyaltyStore,
    // pub(crate) usage: UsageLedger,
    // pub(crate) _config: ArkheMcpConfig,
    pub(crate) provenance_service: ProvenanceService,
}

impl ArkheMcp {
    pub fn new(
        pool: PgPool,
        preflight_base_url: impl Into<String>,
        _price_book_version: impl Into<String>,
        _config: ArkheMcpConfig,
    ) -> anyhow::Result<Self> {
        let usage = UsageLedger::new(pool.clone());
        let preflight = HttpPreflightClient::new(preflight_base_url)?;

        let provenance_service = ProvenanceService::new(
            Arc::new(usage.clone()),
            Arc::new(preflight),
        );

        Ok(Self {
            royalties: RoyaltyStore::new(pool),
            // usage,
            // config,
            provenance_service,
        })
    }
}

#[tool_router(server_handler)]
impl ArkheMcp {
    #[tool(description = "Verify an Arkhe provenance report using the hardened internal preflight verifier. This tool verifies only; it does not anchor or settle anything.")]
    async fn verify_provenance(
        &self,
        Parameters(req): Parameters<VerifyProvenanceRequest>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        let response = self.provenance_service.verify(req).await.map_err(|e| rmcp::ErrorData::new(rmcp::model::ErrorCode(0), e.to_string(), None))?;
        Ok(rmcp::model::CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(serde_json::to_string(&response).unwrap())
        ]))
    }

    #[tool(description = "Read the current royalty status for an Arkhe work by UUID or BLAKE3 hash. This is a read-only lookup and does not settle royalties.")]
    async fn get_royalty_status(
        &self,
        Parameters(req): Parameters<RoyaltyStatusArgs>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        let response = self.royalties.get(&req.work_id).await.map_err(|e| rmcp::ErrorData::new(rmcp::model::ErrorCode(0), e.to_string(), None))?;
        Ok(rmcp::model::CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(serde_json::to_string(&response).unwrap())
        ]))
    }
}
