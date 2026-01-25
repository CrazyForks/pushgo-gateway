mod handlers;
pub mod router;

use std::{borrow::Cow, str::FromStr};

use axum::Json;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    storage::{Platform, StoreError},
    util::{decode_crockford_base32_128, encode_crockford_base32},
};

pub(crate) fn json_response<T: Serialize>(status: axum::http::StatusCode, body: T) -> Response {
    (status, Json(body)).into_response()
}

pub(crate) fn ok<T: Serialize>(data: T) -> Response {
    json_response(axum::http::StatusCode::OK, StatusResponse::ok_with(data))
}

pub(crate) fn err(status: axum::http::StatusCode, msg: impl Into<Cow<'static, str>>) -> Response {
    json_response(status, StatusResponse::err(msg))
}

#[derive(Debug, Error)]
pub enum Error {
    /// Request validation error.
    #[error("validation failed: {0}")]
    Validation(&'static str),

    /// Authentication failed or not authorized.
    #[error("invalid credentials or unauthorized")]
    Unauthorized,

    /// Upstream push provider failure.
    #[error("upstream {provider} error (HTTP {status}): {message}")]
    Upstream {
        provider: &'static str,
        status: u16,
        message: String,
    },

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Server is overloaded and rejecting work.
    #[error("server is too busy")]
    TooBusy,

    #[error(transparent)]
    StoreError(#[from] StoreError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        use axum::http::StatusCode;

        match self {
            Error::Validation(msg) => err(StatusCode::BAD_REQUEST, msg),

            Error::Unauthorized => err(StatusCode::UNAUTHORIZED, "authentication failed"),

            Error::TooBusy => err(
                StatusCode::SERVICE_UNAVAILABLE,
                "server is busy, please try again later",
            ),

            Error::Upstream { message, .. } => err(StatusCode::BAD_GATEWAY, message),

            Error::Internal(msg) => err(StatusCode::INTERNAL_SERVER_ERROR, msg),

            Error::StoreError(StoreError::InvalidDeviceToken) => {
                err(StatusCode::BAD_REQUEST, "invalid device token")
            }

            Error::StoreError(StoreError::ChannelNotFound) => {
                err(StatusCode::NOT_FOUND, "channel not found")
            }

            Error::StoreError(StoreError::ChannelPasswordMismatch) => {
                err(StatusCode::FORBIDDEN, "invalid channel password")
            }

            Error::StoreError(StoreError::ChannelAliasMissing) => {
                err(StatusCode::BAD_REQUEST, "channel name must not be empty")
            }

            Error::StoreError(StoreError::InvalidPlatform) => {
                err(StatusCode::BAD_REQUEST, "invalid platform")
            }

            Error::StoreError(_) => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error, please try again later",
            ),
        }
    }
}

/// Trim string fields and map empty strings to `None`.
pub fn deserialize_empty_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw: Option<Cow<'de, str>> = Option::deserialize(deserializer)?;

    match raw {
        None => Ok(None),
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                T::from_str(t).map(Some).map_err(D::Error::custom)
            }
        }
    }
}

/// Parse and validate the platform field from a string.
pub(crate) fn deserialize_platform<'de, D>(deserializer: D) -> Result<Platform, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<Cow<'de, str>> = Option::deserialize(deserializer)?;
    let value = raw.unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(D::Error::custom(
            "platform must not be empty (expected one of: ios, ipados, macos, watchos, android)",
        ));
    }
    Platform::from_str(trimmed).map_err(D::Error::custom)
}

const MAX_CHANNEL_ALIAS_LEN: usize = 128;

pub fn normalize_channel_alias(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::Validation("channel name must not be empty"));
    }
    let len = trimmed.chars().count();
    if len > MAX_CHANNEL_ALIAS_LEN {
        return Err(Error::Validation("channel name too long (max 128)"));
    }
    if trimmed.chars().any(|ch| ch.is_control()) {
        return Err(Error::Validation(
            "channel name contains invalid characters",
        ));
    }
    Ok(trimmed.to_string())
}

pub fn parse_channel_id(raw: &str) -> Result<[u8; 16], Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::Validation("channel id must not be empty"));
    }
    decode_crockford_base32_128(trimmed).map_err(|_| Error::Validation("invalid channel id"))
}

pub fn format_channel_id(channel_id: &[u8; 16]) -> String {
    encode_crockford_base32(channel_id)
}

pub fn validate_channel_password(raw: &str) -> Result<&str, Error> {
    let trimmed = raw.trim();
    let len = trimmed.len();
    if !(8..=128).contains(&len) {
        return Err(Error::Validation(
            "channel password length must be between 8 and 128",
        ));
    }
    Ok(trimmed)
}

pub type HttpResult = Result<Response, Error>;

#[derive(Serialize)]
pub(super) struct StatusResponse<T = ()> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}
impl<T: Serialize> IntoResponse for StatusResponse<T> {
    fn into_response(self) -> Response {
        (axum::http::StatusCode::OK, Json(self)).into_response()
    }
}

impl<T: Serialize> StatusResponse<T> {
    #[inline]
    pub fn ok_with(data: T) -> Self {
        Self {
            success: true,
            error: None,
            data: Some(data),
        }
    }
}

impl StatusResponse {
    #[inline]
    pub fn err(msg: impl Into<Cow<'static, str>>) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}
