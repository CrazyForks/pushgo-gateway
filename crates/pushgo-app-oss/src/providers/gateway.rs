use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use reqwest::Client;
use serde::Deserialize;

use pushgo_core::{Error, providers::TokenInfo};

const GATEWAY_TOKEN_ENV: &str = "PUSHGO_GATEWAY_TOKEN";
const TOKEN_ENDPOINT_PATH: &str = "/provider/token";
const TOKEN_REFRESH_BUFFER: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub enum GatewayProvider {
    Apns,
    Fcm,
    Wns,
}

impl GatewayProvider {
    fn as_str(self) -> &'static str {
        match self {
            GatewayProvider::Apns => "apns",
            GatewayProvider::Fcm => "fcm",
            GatewayProvider::Wns => "wns",
        }
    }
}

#[derive(Debug)]
struct GatewayTokenState {
    token: Arc<str>,
    expires_at: Instant,
    project_id: Option<Arc<str>>,
}

pub struct GatewayTokenCache {
    client: Client,
    provider: GatewayProvider,
    base_url: Arc<str>,
    token: Option<Arc<str>>,
    state: Arc<ArcSwap<GatewayTokenState>>,
}

impl GatewayTokenCache {
    pub fn new(client: Client, provider: GatewayProvider, base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let token = std::env::var(GATEWAY_TOKEN_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Arc::from(value.into_boxed_str()));

        let initial = GatewayTokenState {
            token: Arc::from(""),
            expires_at: Instant::now() - Duration::from_secs(1),
            project_id: None,
        };
        Self {
            client,
            provider,
            base_url: Arc::from(base_url.into_boxed_str()),
            token,
            state: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub async fn token_info(&self) -> Result<TokenInfo, Error> {
        let cached = self.state.load();
        let now = Instant::now();
        let remaining = cached.expires_at.saturating_duration_since(now);
        let cached_valid = !cached.token.is_empty() && remaining > Duration::ZERO;
        if cached_valid && remaining > TOKEN_REFRESH_BUFFER {
            return Ok(TokenInfo {
                token: Arc::clone(&cached.token),
                expires_in: remaining.as_secs(),
            });
        }

        match self.fetch_and_store().await {
            Ok(info) => Ok(info),
            Err(err) => {
                if cached_valid {
                    Ok(TokenInfo {
                        token: Arc::clone(&cached.token),
                        expires_in: remaining.as_secs(),
                    })
                } else {
                    Err(err)
                }
            }
        }
    }

    pub async fn token_info_with_project(&self) -> Result<(TokenInfo, Arc<str>), Error> {
        let cached = self.state.load();
        let now = Instant::now();
        let remaining = cached.expires_at.saturating_duration_since(now);
        let cached_valid = !cached.token.is_empty() && remaining > Duration::ZERO;
        if cached_valid
            && remaining > TOKEN_REFRESH_BUFFER
            && let Some(project_id) = &cached.project_id
        {
            return Ok((
                TokenInfo {
                    token: Arc::clone(&cached.token),
                    expires_in: remaining.as_secs(),
                },
                Arc::clone(project_id),
            ));
        }

        match self.fetch_and_store_with_project().await {
            Ok((info, project_id)) => Ok((info, project_id)),
            Err(err) => {
                if cached_valid {
                    if let Some(project_id) = &cached.project_id {
                        Ok((
                            TokenInfo {
                                token: Arc::clone(&cached.token),
                                expires_in: remaining.as_secs(),
                            },
                            Arc::clone(project_id),
                        ))
                    } else {
                        Err(err)
                    }
                } else {
                    Err(err)
                }
            }
        }
    }

    pub async fn refresh_now(&self) -> Result<Arc<str>, Error> {
        let info = self.fetch_and_store().await?;
        Ok(info.token)
    }

    async fn fetch_and_store(&self) -> Result<TokenInfo, Error> {
        let (info, project_id) = self.fetch_token().await?;
        let expires_at = Instant::now() + Duration::from_secs(info.expires_in);
        let state = GatewayTokenState {
            token: Arc::clone(&info.token),
            expires_at,
            project_id,
        };
        self.state.store(Arc::new(state));
        Ok(info)
    }

    async fn fetch_and_store_with_project(&self) -> Result<(TokenInfo, Arc<str>), Error> {
        let (info, project_id) = self.fetch_token().await?;
        let project_id = project_id.ok_or_else(|| {
            Error::Internal("gateway token response missing project_id".to_string())
        })?;
        let expires_at = Instant::now() + Duration::from_secs(info.expires_in);
        let state = GatewayTokenState {
            token: Arc::clone(&info.token),
            expires_at,
            project_id: Some(Arc::clone(&project_id)),
        };
        self.state.store(Arc::new(state));
        Ok((info, project_id))
    }

    async fn fetch_token(&self) -> Result<(TokenInfo, Option<Arc<str>>), Error> {
        let url = format!(
            "{}{}?provider={}",
            self.base_url,
            TOKEN_ENDPOINT_PATH,
            self.provider.as_str()
        );
        let mut request = self.client.get(&url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_ref());
        }

        let response = request
            .send()
            .await
            .map_err(|err| Error::Internal(err.to_string()))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let message = if body.trim().is_empty() {
                format!("gateway error, status {}", status.as_u16())
            } else {
                body
            };
            return Err(Error::Upstream {
                provider: "PushGo Gateway",
                status: status.as_u16(),
                message,
            });
        }

        let parsed: GatewayResponse<GatewayTokenData> =
            serde_json::from_str(&body).map_err(|err| Error::Internal(err.to_string()))?;
        if !parsed.success {
            return Err(Error::Upstream {
                provider: "PushGo Gateway",
                status: status.as_u16(),
                message: parsed
                    .error
                    .unwrap_or_else(|| "gateway returned error".to_string()),
            });
        }
        let data = parsed
            .data
            .ok_or_else(|| Error::Internal("gateway token response missing data".to_string()))?;

        Ok((
            TokenInfo {
                token: Arc::from(data.token.into_boxed_str()),
                expires_in: data.expires_in,
            },
            data.project_id
                .map(|value| Arc::from(value.into_boxed_str())),
        ))
    }
}

#[derive(Deserialize)]
struct GatewayResponse<T> {
    success: bool,
    error: Option<String>,
    data: Option<T>,
}

#[derive(Deserialize)]
struct GatewayTokenData {
    token: String,
    expires_in: u64,
    #[serde(default)]
    project_id: Option<String>,
}
