use std::{collections::HashMap, sync::Arc};

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    api::{
        Error, HttpResult, deserialize_empty_as_none, format_channel_id, parse_channel_id,
        validate_channel_password,
    },
    app::AppState,
    dispatch::{ApnsJob, FcmJob, WnsJob},
    providers::{apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload},
    storage::{Platform, StoreError},
};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub(crate) struct PushIntent {
    pub channel_id: String,
    pub password: String,
    pub title: String,
    #[serde(deserialize_with = "deserialize_empty_as_none")]
    pub body: Option<String>,
    #[serde(deserialize_with = "deserialize_empty_as_none")]
    pub sound: Option<String>,
    #[serde(deserialize_with = "deserialize_empty_as_none")]
    pub level: Option<String>,
    pub volume: Option<f32>,
    #[serde(flatten)]
    pub data: HashMap<String, String>,
}

impl PushIntent {
    pub fn validate_payload(&self) -> Result<(), Error> {
        if self.channel_id.trim().is_empty() {
            return Err(Error::Validation("channel id must not be empty"));
        }
        validate_channel_password(&self.password)?;
        if self.title.trim().is_empty() {
            return Err(Error::Validation("title must not be empty"));
        }
        if let Some(volume) = self.volume {
            if !volume.is_finite() || !(0.0..=1.0).contains(&volume) {
                return Err(Error::Validation("volume must be between 0 and 1"));
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct PushSummary {
    channel_id: String,
    channel_name: String,
    message_id: String,
    total: usize,
    accepted: usize,
    rejected: usize,
}

pub(crate) async fn push_to_channel(
    State(state): State<AppState>,
    Json(payload): Json<PushIntent>,
) -> HttpResult {
    payload.validate_payload()?;
    let channel_id = parse_channel_id(&payload.channel_id)?;
    let password = validate_channel_password(&payload.password)?;
    let channel_info = state
        .store
        .channel_info_with_password(channel_id, password)?
        .ok_or(StoreError::ChannelNotFound)?;
    let channel_id_value = format_channel_id(&channel_id);
    let channel_name = channel_info.alias;

    let message_id = Uuid::new_v4().to_string();
    let PushIntent {
        title,
        body,
        sound,
        level,
        volume,
        data,
        ..
    } = payload;
    let sound = normalize_optional_string(sound);
    let level = normalize_optional_string(level);
    let priority = FcmPayload::priority_for_level(level.as_deref());

    let devices = state.store.list_channel_devices(channel_id)?;
    if devices.is_empty() {
        return Ok(crate::api::ok(PushSummary {
            channel_id: channel_id_value.clone(),
            channel_name: channel_name.clone(),
            message_id,
            total: 0,
            accepted: 0,
            rejected: 0,
        }));
    }

    let mut has_android = false;
    let mut has_apns = false;
    let mut has_wns = false;
    for device in &devices {
        match device.platform {
            Platform::ANDROID => {
                has_android = true;
            }
            Platform::WINDOWS => {
                has_wns = true;
            }
            _ => {
                has_apns = true;
            }
        }
    }

    let mut data = data;
    add_standard_fields(
        &mut data,
        StandardFields {
            channel_id: &channel_id_value,
            channel_name: &channel_name,
            title: &title,
            body: body.as_deref(),
            sound: sound.as_deref(),
            level: level.as_deref(),
            volume,
        },
    );
    data.insert("messageId".to_string(), message_id.clone());
    let apns_payload = if has_apns {
        let apns_data = strip_apns_fields(data.clone());
        let payload = Arc::new(ApnsPayload::new(
            title.clone(),
            body.clone(),
            Some(channel_id_value.clone()),
            level.clone(),
            sound.clone(),
            volume,
            apns_data,
        ));
        Some(payload)
    } else {
        None
    };
    let apns_collapse_id = if has_apns {
        Some(Arc::from(message_id.clone().into_boxed_str()))
    } else {
        None
    };
    let fcm_payload = if has_android {
        let payload = Arc::new(FcmPayload::new(data.clone(), priority));
        Some(payload)
    } else {
        None
    };
    let wns_payload = if has_wns {
        let payload = Arc::new(WnsPayload::new(data.clone()));
        Some(payload)
    } else {
        None
    };

    let total = devices.len();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut dispatch_closed = false;
    for (index, device) in devices.into_iter().enumerate() {
        match device.platform {
            Platform::ANDROID => {
                let payload = fcm_payload
                    .clone()
                    .ok_or(Error::Internal("missing FCM payload".to_string()))?;
                match state.dispatch.try_send_fcm(FcmJob {
                    channel_id,
                    device_token: Arc::from(device.token_str()),
                    payload,
                }) {
                    Ok(()) => accepted += 1,
                    Err(crate::dispatch::DispatchError::QueueFull) => rejected += 1,
                    Err(crate::dispatch::DispatchError::ChannelClosed) => {
                        rejected += 1;
                        dispatch_closed = true;
                    }
                }
            }
            Platform::WINDOWS => {
                let payload = wns_payload
                    .clone()
                    .ok_or(Error::Internal("missing WNS payload".to_string()))?;
                match state.dispatch.try_send_wns(WnsJob {
                    channel_id,
                    device_token: Arc::from(device.token_str()),
                    payload,
                }) {
                    Ok(()) => accepted += 1,
                    Err(crate::dispatch::DispatchError::QueueFull) => rejected += 1,
                    Err(crate::dispatch::DispatchError::ChannelClosed) => {
                        rejected += 1;
                        dispatch_closed = true;
                    }
                }
            }
            _ => {
                let payload = apns_payload
                    .clone()
                    .ok_or(Error::Internal("missing APNs payload".to_string()))?;
                match state.dispatch.try_send_apns(ApnsJob {
                    channel_id,
                    device_token: Arc::from(device.token_str()),
                    platform: device.platform,
                    payload,
                    collapse_id: apns_collapse_id.clone(),
                }) {
                    Ok(()) => accepted += 1,
                    Err(crate::dispatch::DispatchError::QueueFull) => rejected += 1,
                    Err(crate::dispatch::DispatchError::ChannelClosed) => {
                        rejected += 1;
                        dispatch_closed = true;
                    }
                }
            }
        }
        if dispatch_closed {
            let remaining = total.saturating_sub(index + 1);
            rejected += remaining;
            break;
        }
    }

    Ok(crate::api::ok(PushSummary {
        channel_id: channel_id_value,
        channel_name,
        message_id,
        total,
        accepted,
        rejected,
    }))
}

fn strip_apns_fields(mut data: HashMap<String, String>) -> HashMap<String, String> {
    for key in ["title", "body", "sound", "level", "volume"] {
        data.remove(key);
    }
    data
}

struct StandardFields<'a> {
    channel_id: &'a str,
    channel_name: &'a str,
    title: &'a str,
    body: Option<&'a str>,
    sound: Option<&'a str>,
    level: Option<&'a str>,
    volume: Option<f32>,
}

fn add_standard_fields(data: &mut HashMap<String, String>, fields: StandardFields<'_>) {
    data.insert("channel_id".to_string(), fields.channel_id.to_string());
    data.insert("channel_name".to_string(), fields.channel_name.to_string());
    data.insert("title".to_string(), fields.title.to_string());
    if let Some(value) = fields.body.map(str::trim).filter(|text| !text.is_empty()) {
        data.insert("body".to_string(), value.to_string());
    }
    if let Some(value) = fields.sound.map(str::trim).filter(|text| !text.is_empty()) {
        data.insert("sound".to_string(), value.to_string());
    }
    if let Some(value) = fields.level.map(str::trim).filter(|text| !text.is_empty()) {
        data.insert("level".to_string(), value.to_string());
    }
    if let Some(value) = fields.volume {
        data.insert("volume".to_string(), value.to_string());
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::PushIntent;
    use crate::api::Error;
    use std::collections::HashMap;

    fn base_intent() -> PushIntent {
        PushIntent {
            channel_id: "0123456789ABCDEFGHJKMNPQRSTVWXYZ".to_string(),
            password: "password123".to_string(),
            title: "hello".to_string(),
            body: None,
            sound: None,
            level: None,
            volume: None,
            data: HashMap::new(),
        }
    }

    #[test]
    fn validate_payload_rejects_invalid_volume() {
        let mut intent = base_intent();
        intent.volume = Some(1.5);
        let err = intent.validate_payload().unwrap_err();
        assert!(matches!(
            err,
            Error::Validation("volume must be between 0 and 1")
        ));
    }

    #[test]
    fn validate_payload_accepts_valid_volume() {
        let mut intent = base_intent();
        intent.volume = Some(0.5);
        intent.validate_payload().expect("volume should be valid");
    }
}
