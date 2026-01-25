use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        Error, HttpResult, deserialize_platform, format_channel_id, normalize_channel_alias,
        parse_channel_id, validate_channel_password,
    },
    app::AppState,
    storage::{Platform, StoreError},
};

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelSubscribeData {
    #[serde(default)]
    channel_id: String,
    #[serde(default)]
    channel_name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    device_token: String,
    #[serde(deserialize_with = "deserialize_platform")]
    platform: Platform,
    #[serde(default)]
    device_tokens: Vec<DeviceTokenData>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceTokenData {
    #[serde(default)]
    device_token: String,
    #[serde(deserialize_with = "deserialize_platform")]
    platform: Platform,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelSubscribeResponse {
    channel_id: String,
    channel_name: String,
    created: bool,
    subscribed: bool,
}

pub(crate) async fn channel_subscribe(
    State(state): State<AppState>,
    Json(payload): Json<ChannelSubscribeData>,
) -> HttpResult {
    let devices = resolve_device_tokens(
        payload.device_token,
        payload.platform,
        payload.device_tokens,
    )?;
    let channel_id = if payload.channel_id.trim().is_empty() {
        None
    } else {
        Some(parse_channel_id(&payload.channel_id)?)
    };
    let channel_name = if payload.channel_name.trim().is_empty() {
        None
    } else {
        Some(normalize_channel_alias(&payload.channel_name)?)
    };
    if channel_id.is_some() == channel_name.is_some() {
        return Err(Error::Validation(
            "must provide either channel_id or channel_name",
        ));
    }
    let password = validate_channel_password(&payload.password)?;

    let mut created = false;
    let mut alias = String::new();
    let mut resolved_channel = channel_id;
    for (index, device) in devices.into_iter().enumerate() {
        let (use_channel, use_alias) = if index == 0 {
            (resolved_channel, channel_name.as_deref())
        } else {
            (resolved_channel, None)
        };
        let outcome = state.store.subscribe_channel(
            use_channel,
            use_alias,
            password,
            &device.device_token,
            device.platform,
        )?;
        created |= outcome.created;
        alias = outcome.alias;
        resolved_channel = Some(outcome.channel_id);
    }
    let channel_id = resolved_channel.ok_or(StoreError::ChannelNotFound)?;

    Ok(crate::api::ok(ChannelSubscribeResponse {
        channel_id: format_channel_id(&channel_id),
        channel_name: alias,
        created,
        subscribed: true,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelUnsubscribeData {
    #[serde(default)]
    channel_id: String,
    #[serde(default)]
    device_token: String,
    #[serde(deserialize_with = "deserialize_platform")]
    platform: Platform,
    #[serde(default)]
    device_tokens: Vec<DeviceTokenData>,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelUnsubscribeResponse {
    channel_id: String,
    removed: bool,
}

pub(crate) async fn channel_unsubscribe(
    State(state): State<AppState>,
    Json(payload): Json<ChannelUnsubscribeData>,
) -> HttpResult {
    let devices = resolve_device_tokens(
        payload.device_token,
        payload.platform,
        payload.device_tokens,
    )?;
    let channel_id = parse_channel_id(&payload.channel_id)?;

    let mut removed = false;
    for device in devices {
        let removed_once =
            state
                .store
                .unsubscribe_channel(channel_id, &device.device_token, device.platform)?;
        removed = removed || removed_once;
    }

    Ok(crate::api::ok(ChannelUnsubscribeResponse {
        channel_id: format_channel_id(&channel_id),
        removed,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelExistsQuery {
    channel_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelExistsResponse {
    channel_id: String,
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_name: Option<String>,
}

pub(crate) async fn channel_exists(
    State(state): State<AppState>,
    Query(query): Query<ChannelExistsQuery>,
) -> HttpResult {
    let channel_id = parse_channel_id(&query.channel_id)?;
    let info = state.store.channel_info(channel_id)?;
    Ok(crate::api::ok(ChannelExistsResponse {
        channel_id: format_channel_id(&channel_id),
        exists: info.is_some(),
        channel_name: info.map(|meta| meta.alias),
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelRenameData {
    #[serde(default)]
    channel_id: String,
    #[serde(default)]
    channel_name: String,
    #[serde(default)]
    password: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelRenameResponse {
    channel_id: String,
    channel_name: String,
}

pub(crate) async fn channel_rename(
    State(state): State<AppState>,
    Json(payload): Json<ChannelRenameData>,
) -> HttpResult {
    let channel_id = parse_channel_id(&payload.channel_id)?;
    let channel_name = normalize_channel_alias(&payload.channel_name)?;
    let password = validate_channel_password(&payload.password)?;

    state
        .store
        .rename_channel(channel_id, password, &channel_name)?;

    Ok(crate::api::ok(ChannelRenameResponse {
        channel_id: format_channel_id(&channel_id),
        channel_name,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelSyncData {
    #[serde(default)]
    device_token: String,
    #[serde(deserialize_with = "deserialize_platform")]
    platform: Platform,
    #[serde(default)]
    device_tokens: Vec<DeviceTokenData>,
    #[serde(default)]
    channels: Vec<ChannelSyncItem>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChannelSyncItem {
    #[serde(default)]
    channel_id: String,
    #[serde(default)]
    password: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelSyncResponse {
    success: usize,
    failed: usize,
    channels: Vec<ChannelSyncResult>,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelSyncResult {
    channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_name: Option<String>,
    subscribed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
}

pub(crate) async fn channel_sync(
    State(state): State<AppState>,
    Json(payload): Json<ChannelSyncData>,
) -> HttpResult {
    let devices = resolve_device_tokens(
        payload.device_token,
        payload.platform,
        payload.device_tokens,
    )?;
    if payload.channels.is_empty() {
        return Err(Error::Validation("channels must not be empty"));
    }

    let mut results = Vec::with_capacity(payload.channels.len());
    let mut success = 0usize;
    let mut failed = 0usize;

    for item in payload.channels {
        let channel_id = match parse_channel_id(&item.channel_id) {
            Ok(value) => value,
            Err(Error::Validation(msg)) => {
                results.push(ChannelSyncResult {
                    channel_id: item.channel_id,
                    channel_name: None,
                    subscribed: false,
                    error: Some(msg.to_string()),
                    error_code: Some("invalid_channel_id"),
                });
                failed += 1;
                continue;
            }
            Err(other) => return Err(other),
        };

        let password = match validate_channel_password(&item.password) {
            Ok(value) => value,
            Err(Error::Validation(msg)) => {
                results.push(ChannelSyncResult {
                    channel_id: item.channel_id,
                    channel_name: None,
                    subscribed: false,
                    error: Some(msg.to_string()),
                    error_code: Some("invalid_password"),
                });
                failed += 1;
                continue;
            }
            Err(other) => return Err(other),
        };

        let mut channel_alias = None;
        let mut subscribed = true;
        for device in devices.iter() {
            match state.store.subscribe_channel(
                Some(channel_id),
                None,
                password,
                &device.device_token,
                device.platform,
            ) {
                Ok(outcome) => {
                    channel_alias = Some(outcome.alias);
                }
                Err(StoreError::ChannelNotFound) => {
                    subscribed = false;
                    results.push(ChannelSyncResult {
                        channel_id: format_channel_id(&channel_id),
                        channel_name: None,
                        subscribed: false,
                        error: Some("channel not found".to_string()),
                        error_code: Some("channel_not_found"),
                    });
                }
                Err(StoreError::ChannelPasswordMismatch) => {
                    subscribed = false;
                    results.push(ChannelSyncResult {
                        channel_id: format_channel_id(&channel_id),
                        channel_name: None,
                        subscribed: false,
                        error: Some("invalid channel password".to_string()),
                        error_code: Some("invalid_channel_password"),
                    });
                }
                Err(StoreError::InvalidDeviceToken) => {
                    return Err(StoreError::InvalidDeviceToken.into());
                }
                Err(other) => return Err(other.into()),
            }
            if !subscribed {
                break;
            }
        }

        if subscribed {
            success += 1;
            results.push(ChannelSyncResult {
                channel_id: format_channel_id(&channel_id),
                channel_name: channel_alias,
                subscribed: true,
                error: None,
                error_code: None,
            });
        } else {
            failed += 1;
        }
    }

    Ok(crate::api::ok(ChannelSyncResponse {
        success,
        failed,
        channels: results,
    }))
}

fn resolve_device_tokens(
    device_token: String,
    platform: Platform,
    device_tokens: Vec<DeviceTokenData>,
) -> Result<Vec<DeviceTokenData>, Error> {
    if device_tokens.is_empty() {
        if device_token.trim().is_empty() {
            return Err(Error::Validation("device token must not be empty"));
        }
        return Ok(vec![DeviceTokenData {
            device_token: device_token.trim().to_string(),
            platform,
        }]);
    }

    let mut resolved = Vec::with_capacity(device_tokens.len());
    for item in device_tokens {
        if item.device_token.trim().is_empty() {
            return Err(Error::Validation("device token must not be empty"));
        }
        resolved.push(DeviceTokenData {
            device_token: item.device_token.trim().to_string(),
            platform: item.platform,
        });
    }
    Ok(resolved)
}
