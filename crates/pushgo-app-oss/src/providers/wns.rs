use pushgo_core::{
    Error,
    providers::{BoxFuture, TokenInfo, WnsTokenProvider as WnsTokenProviderTrait},
};

use crate::providers::gateway::{GatewayProvider, GatewayTokenCache};

pub struct WnsTokenProvider {
    cache: GatewayTokenCache,
}

impl WnsTokenProvider {
    pub fn new(gateway_url: &str, client: reqwest::Client) -> Result<Self, Error> {
        let cache = GatewayTokenCache::new(client, GatewayProvider::Wns, gateway_url);
        Ok(Self { cache })
    }
}

impl WnsTokenProviderTrait for WnsTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info().await })
    }
}
