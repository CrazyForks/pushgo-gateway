use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub apns: ApnsConfig,
    pub fcm: FcmConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApnsConfig {
    pub team_id: String,
    pub key_id: String,
    pub key_pem: String,
    #[serde(default = "default_apns_endpoint")]
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FcmConfig {
    pub project_id: String,
    pub client_email: String,
    pub private_key: String,
}

fn default_apns_endpoint() -> String {
    "https://api.push.apple.com".to_string()
}
