use pushgo_core::{
    Error,
    providers::{BoxFuture, FcmAccess, FcmTokenProvider as FcmTokenProviderTrait},
};

use crate::providers::gateway::{GatewayProvider, GatewayTokenCache};

pub struct FcmTokenProvider {
    cache: GatewayTokenCache,
}

impl FcmTokenProvider {
    pub fn new(gateway_url: &str, client: reqwest::Client) -> Result<Self, Error> {
        let cache = GatewayTokenCache::new(client, GatewayProvider::Fcm, gateway_url);
        Ok(Self { cache })
    }
}

impl FcmTokenProviderTrait for FcmTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>> {
        Box::pin(async move {
            let (token, project_id) = self.cache.token_info_with_project().await?;
            Ok(FcmAccess { token, project_id })
        })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>> {
        Box::pin(async move {
            let (token, project_id) = self.cache.token_info_with_project().await?;
            Ok(FcmAccess { token, project_id })
        })
    }
}
