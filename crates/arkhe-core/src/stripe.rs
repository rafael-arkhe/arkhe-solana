use async_stripe::{
    Account, AccountLink, AccountLinkType, AccountType, Client, CreateAccount,
    CreateAccountCapabilities, CreateAccountCapabilitiesCardPayments,
    CreateAccountCapabilitiesTransfers, CreateAccountLink, StripeError,
};
use std::str::FromStr;

pub async fn create_connect_account(
    client: &Client,
    email: &str,
    country: &str,
) -> Result<Account, StripeError> {
    let params = CreateAccount {
        type_: Some(AccountType::Express),
        email: Some(email),
        country: Some(country),
        capabilities: Some(CreateAccountCapabilities {
            transfers: Some(CreateAccountCapabilitiesTransfers {
                requested: Some(true),
            }),
            card_payments: Some(CreateAccountCapabilitiesCardPayments {
                requested: Some(true),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    Account::create(client, params).await
}

pub async fn create_onboarding_link<'a>(
    client: &Client,
    account_id: &'a str,
    refresh_url: &'a str,
    return_url: &'a str,
) -> Result<AccountLink, StripeError> {
    let params = CreateAccountLink {
        account: async_stripe::AccountId::from_str(account_id).unwrap(),
        type_: AccountLinkType::AccountOnboarding,
        refresh_url: Some(refresh_url),
        return_url: Some(return_url),
        collect: None,
        expand: &[],
        collection_options: None,
    };

    AccountLink::create(client, params).await
}

pub struct OnboardingStatus {
    pub is_complete: bool,
    pub charges_enabled: bool,
    pub payouts_enabled: bool,
    pub currently_due: Option<Vec<String>>,
    pub eventually_due: Option<Vec<String>>,
    pub disabled_reason: Option<String>,
}

pub async fn check_onboarding_status(
    client: &Client,
    account_id: &async_stripe::AccountId,
) -> Result<OnboardingStatus, StripeError> {
    let account = Account::retrieve(client, account_id, &[]).await?;

    Ok(OnboardingStatus {
        is_complete: account.charges_enabled.unwrap_or(false)
            && account.payouts_enabled.unwrap_or(false),
        charges_enabled: account.charges_enabled.unwrap_or(false),
        payouts_enabled: account.payouts_enabled.unwrap_or(false),
        currently_due: account
            .requirements
            .as_ref()
            .and_then(|r| r.currently_due.clone()),
        eventually_due: account
            .requirements
            .as_ref()
            .and_then(|r| r.eventually_due.clone()),
        disabled_reason: account
            .requirements
            .as_ref()
            .and_then(|r| r.disabled_reason.clone()),
    })
}
