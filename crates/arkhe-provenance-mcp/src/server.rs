use crate::{
    metering::UsageLedger,
    preflight::{PreflightClient, VerifyProvenanceArgs},
    royalty::{RoyaltyStatusArgs, RoyaltyStore},
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
    pub(crate) preflight: PreflightClient,
    pub(crate) royalties: RoyaltyStore,
    pub(crate) usage: UsageLedger,
    pub(crate) config: ArkheMcpConfig,
}

impl ArkheMcp {
    pub fn new(
        pool: PgPool,
        preflight_base_url: impl Into<String>,
        price_book_version: impl Into<String>,
        config: ArkheMcpConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            preflight: PreflightClient::new(preflight_base_url)?,
            royalties: RoyaltyStore::new(pool.clone()),
            usage: UsageLedger::new(pool, price_book_version),
            config,
        })
    }
}

#[tool_router(server_handler)]
impl ArkheMcp {
    #[tool(description = "Verify an Arkhe provenance report using the hardened internal preflight verifier. This tool verifies only; it does not anchor or settle anything.")]
    async fn verify_provenance(
        &self,
        params: Parameters<VerifyProvenanceArgs>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        self.verify_provenance_impl(params).await
    }

    #[tool(description = "Read the current royalty status for an Arkhe work by UUID or BLAKE3 hash. This is a read-only lookup and does not settle royalties.")]
    async fn get_royalty_status(
        &self,
        params: Parameters<RoyaltyStatusArgs>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        self.get_royalty_status_impl(params).await
    }
}
