use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{
    api::{Error, HttpResult, deserialize_platform},
    app::AppState,
    storage::Platform,
};

#[derive(Debug, Deserialize)]
pub(crate) struct RetireData {
    #[serde(default)]
    device_token: String,
    #[serde(deserialize_with = "deserialize_platform")]
    platform: Platform,
}

#[derive(Debug, Serialize)]
pub(super) struct RetireResponse {
    removed_subscriptions: usize,
}

pub(crate) async fn device_retire(
    State(state): State<AppState>,
    Json(payload): Json<RetireData>,
) -> HttpResult {
    let token = payload.device_token.trim();
    if token.is_empty() {
        return Err(Error::Validation("device token must not be empty"));
    }

    let removed = state.store.retire_device(token, payload.platform)?;

    Ok(crate::api::ok(RetireResponse {
        removed_subscriptions: removed,
    }))
}
