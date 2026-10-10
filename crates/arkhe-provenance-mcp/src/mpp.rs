use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use mpp::server::{Mpp, StripeChargeMethod, StripeChargeOptions};
use mpp::MppError;
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct ToolResponse {
    pub result: serde_json::Value,
    pub payment_id: Option<String>,
    pub record_hash: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub mpp: Arc<Mpp<StripeChargeMethod>>,
}

pub struct AppError(MppError);

impl From<MppError> for AppError {
    fn from(inner: MppError) -> Self {
        AppError(inner)
    }
}

// Convert AppError to Axum response
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self.0 {
            MppError::PaymentRequired { .. } => {
                // To keep it simple, just return the 402 with the text
                (StatusCode::PAYMENT_REQUIRED, "Payment Required").into_response()
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response(),
        }
    }
}

pub async fn create_mpp_server() -> Router {
    // We instantiate StripeChargeMethod
    let method = StripeChargeMethod::new(
        std::env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| "sk_test_123".to_string()),
        std::env::var("STRIPE_NETWORK_ID").unwrap_or_else(|_| "network_test_123".to_string()),
        vec!["card".to_string()],
    );

    let mpp = Mpp::new(
        method,
        "api.arkhe.dev",
        std::env::var("MPP_SECRET_KEY").unwrap_or_else(|_| "test_secret_key".to_string()),
    );

    let state = AppState { mpp: Arc::new(mpp) };

    Router::new()
        .route("/mcp/v1/tools/:tool_name", post(handle_mcp_tool))
        .with_state(state)
}

pub async fn handle_mcp_tool(
    State(state): State<AppState>,
    Path(tool_name): Path<String>,
    headers: HeaderMap,
    Json(params): Json<serde_json::Value>,
) -> Result<Json<ToolResponse>, AppError> {
    let price = price_for_tool(&tool_name);

    // Instead of doing verification, we simply simulate it for the skeleton
    // (If the auth_header doesn't exist, we send a 402 charge challenge)
    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    if auth_header.is_none() {
        let desc = format!("Arkhe tool: {}", tool_name);
        let options = StripeChargeOptions {
            description: Some(&desc),
            external_id: None,
            expires: None,
            metadata: None,
        };
        let challenge = state
            .mpp
            .stripe_charge_with_options(&price.to_string(), options)?;
        return Err(MppError::PaymentRequired {
            realm: Some(challenge.realm),
            description: challenge.description,
        }
        .into());
    }

    let result = execute_tool(&tool_name, params).await?;

    Ok(Json(ToolResponse {
        record_hash: Some(compute_record_hash(&result)),
        result,
        payment_id: Some("simulated_payment_id".to_string()),
    }))
}

fn price_for_tool(tool_name: &str) -> i64 {
    match tool_name {
        "arkhe_verify_c2pa" => 1,      // $0.01
        "arkhe_check_royalty" => 1,    // $0.01
        "arkhe_detect_watermark" => 1, // $0.01
        "arkhe_settle_royalty" => 50,  // $0.50 (mínimo SPT)
        "arkhe_generate_report" => 10, // $0.10
        _ => 10,
    }
}

async fn execute_tool(
    tool_name: &str,
    _params: serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    Ok(serde_json::json!({
        "status": "success",
        "tool": tool_name
    }))
}

fn compute_record_hash(_result: &serde_json::Value) -> String {
    "dummy_hash".to_string()
}
