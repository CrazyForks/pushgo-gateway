use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::{
    api::{Error, HttpResult},
    app::AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct ProviderTokenQuery {
    provider: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProviderTokenResponse {
    provider: String,
    token: String,
    expires_in: u64,
}

enum TokenProvider {
    Apns,
    Fcm,
}

impl TokenProvider {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "apns" => Some(TokenProvider::Apns),
            "fcm" => Some(TokenProvider::Fcm),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TokenProvider::Apns => "apns",
            TokenProvider::Fcm => "fcm",
        }
    }
}

pub(crate) async fn provider_token(
    State(state): State<AppState>,
    Query(query): Query<ProviderTokenQuery>,
) -> HttpResult {
    let provider = TokenProvider::parse(&query.provider)
        .ok_or(Error::Validation("provider must be apns or fcm"))?;
    let info = match provider {
        TokenProvider::Apns => state.apns.token_info_fresh().await?,
        TokenProvider::Fcm => state.fcm.token_info_fresh().await?,
    };

    Ok(crate::api::ok(ProviderTokenResponse {
        provider: provider.as_str().to_string(),
        token: info.token.as_ref().to_string(),
        expires_in: info.expires_in,
    }))
}
