use std::{collections::HashMap, sync::Arc, time::Duration};

use reqwest::Client;
use serde::Serialize;

use crate::{
    Error,
    providers::{
        BoxFuture, DispatchResult, FcmClient, FcmTokenProvider, TokenInfo, fcm::FcmPayload,
    },
};

const FCM_TIMEOUT: Duration = Duration::from_secs(60);

pub struct FcmService {
    client: Client,
    token_provider: Arc<dyn FcmTokenProvider>,
}

impl FcmService {
    pub fn new(token_provider: Arc<dyn FcmTokenProvider>) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent("pushgo-backend/0.1.0")
            .timeout(FCM_TIMEOUT)
            .build()
            .map_err(|err| Error::Internal(err.to_string()))?;

        Ok(Self {
            client,
            token_provider,
        })
    }

    pub async fn send_to_device(
        &self,
        device_token: &str,
        payload: Arc<FcmPayload>,
    ) -> DispatchResult {
        let access = match self.token_provider.token_info().await {
            Ok(access) => access,
            Err(err) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(err),
                    invalid_token: false,
                };
            }
        };

        let request = FcmRequest {
            message: FcmMessage {
                token: device_token,
                data: payload.data(),
                android: FcmAndroidConfig {
                    priority: payload.priority(),
                },
            },
        };

        let body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(err) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::Internal(err.to_string())),
                    invalid_token: false,
                };
            }
        };

        let endpoint = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            access.project_id
        );

        let response = match self
            .client
            .post(&endpoint)
            .bearer_auth(access.token.token.as_ref())
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: Some(Error::Internal(err.to_string())),
                    invalid_token: false,
                };
            }
        };

        let status = response.status();
        let status_code = status.as_u16();
        let body_text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let message = if body_text.is_empty() {
                format!("FCM error, status {status_code}")
            } else {
                body_text.clone()
            };
            return DispatchResult {
                success: false,
                status_code,
                error: Some(Error::Upstream {
                    provider: "FCM",
                    status: status_code,
                    message,
                }),
                invalid_token: is_fcm_token_invalid(status_code, &body_text),
            };
        }

        DispatchResult {
            success: true,
            status_code,
            error: None,
            invalid_token: false,
        }
    }

    pub async fn token_info(&self) -> Result<TokenInfo, Error> {
        let access = self.token_provider.token_info().await?;
        Ok(access.token)
    }

    pub async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        let access = self.token_provider.token_info_fresh().await?;
        Ok(access.token)
    }
}

impl FcmClient for FcmService {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<FcmPayload>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move { self.send_to_device(device_token, payload).await })
    }

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info_fresh().await })
    }
}

fn is_fcm_token_invalid(status_code: u16, body_text: &str) -> bool {
    if status_code == 404 {
        return true;
    }
    let value: serde_json::Value = match serde_json::from_str(body_text) {
        Ok(value) => value,
        Err(_) => {
            let haystack = body_text.to_ascii_lowercase();
            return haystack.contains("unregistered")
                || haystack.contains("not registered")
                || haystack.contains("invalid registration token")
                || (haystack.contains("registration token") && haystack.contains("invalid"));
        }
    };
    let error = match value.get("error") {
        Some(error) => error,
        None => return false,
    };
    if error
        .get("status")
        .and_then(|status| status.as_str())
        .map(|status| status.eq_ignore_ascii_case("NOT_FOUND"))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(details) = error.get("details").and_then(|details| details.as_array()) {
        for detail in details {
            if detail
                .get("errorCode")
                .and_then(|code| code.as_str())
                .map(|code| code.eq_ignore_ascii_case("UNREGISTERED"))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    if let Some(message) = error.get("message").and_then(|msg| msg.as_str()) {
        let haystack = message.to_ascii_lowercase();
        return haystack.contains("unregistered")
            || haystack.contains("not registered")
            || haystack.contains("invalid registration token")
            || (haystack.contains("registration token") && haystack.contains("invalid"));
    }
    false
}

#[derive(Serialize)]
struct FcmRequest<'a> {
    message: FcmMessage<'a>,
}

#[derive(Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    data: &'a HashMap<String, String>,
    android: FcmAndroidConfig,
}

#[derive(Serialize)]
struct FcmAndroidConfig {
    priority: &'static str,
}
