use std::sync::Arc;

use pushgo_core::{
    Error,
    providers::{ApnsTokenProvider as ApnsTokenProviderTrait, BoxFuture, TokenInfo},
};

use crate::providers::gateway::{GatewayProvider, GatewayTokenCache};

pub struct ApnsTokenProvider {
    cache: GatewayTokenCache,
}

impl ApnsTokenProvider {
    pub fn new(gateway_url: &str, client: reqwest::Client) -> Result<Self, Error> {
        let cache = GatewayTokenCache::new(client, GatewayProvider::Apns, gateway_url);
        Ok(Self { cache })
    }
}

impl ApnsTokenProviderTrait for ApnsTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info().await })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info().await })
    }

    fn refresh_now<'a>(&'a self) -> BoxFuture<'a, Result<Arc<str>, Error>> {
        Box::pin(async move { self.cache.refresh_now().await })
    }
}
