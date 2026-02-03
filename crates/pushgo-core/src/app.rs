use std::sync::Arc;

use axum::Router;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::{
    api::{Error, router::build_router},
    config::CoreArgs,
    dispatch::{DispatchChannels, create_dispatch_channels, spawn_dispatch_workers},
    providers::{ApnsClient, FcmClient, WnsClient},
    storage::{Store, new_store},
};

#[derive(Clone)]
pub(crate) enum AuthMode {
    Disabled,
    SharedToken(Arc<str>),
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub dispatch: DispatchChannels,
    pub auth: AuthMode,
    pub limiter: Option<Arc<RequestLimiter>>,
    pub store: Store,
    pub apns: Arc<dyn ApnsClient>,
    pub fcm: Arc<dyn FcmClient>,
    pub wns: Arc<dyn WnsClient>,
}

pub fn build_app(
    args: &CoreArgs,
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
    docs_html: &'static str,
    include_provider_token: bool,
) -> Result<Router, Box<dyn std::error::Error>> {
    let store = new_store(&args.data_path, args.db_url.as_deref())?;

    let (dispatch, apns_rx, fcm_rx, wns_rx) = create_dispatch_channels();
    spawn_dispatch_workers(
        apns_rx,
        fcm_rx,
        wns_rx,
        Arc::clone(&apns),
        Arc::clone(&fcm),
        Arc::clone(&wns),
        Arc::clone(&store),
    );

    let auth = match args.token.as_deref() {
        None => AuthMode::Disabled,
        Some(token) => AuthMode::SharedToken(Arc::from(token)),
    };

    let max_concurrent = args.max_concurrent;
    let limiter = if max_concurrent == 0 {
        None
    } else {
        Some(Arc::new(RequestLimiter::new(
            max_concurrent,
            max_concurrent,
        )))
    };

    let state = AppState {
        dispatch,
        auth,
        limiter,
        store,
        apns,
        fcm,
        wns,
    };

    Ok(build_router(state, docs_html, include_provider_token))
}

#[derive(Debug)]
pub(crate) struct RequestLimiter {
    in_flight: Arc<Semaphore>,
    queue_slots: Arc<Semaphore>,
    max_queue: usize,
}

impl RequestLimiter {
    /// Create a limiter with in-flight and queue caps.
    ///
    /// `max_in_flight` limits active requests; `max_queue` limits waiters.
    pub fn new(max_in_flight: usize, max_queue: usize) -> Self {
        RequestLimiter {
            in_flight: Arc::new(Semaphore::new(max_in_flight)),
            queue_slots: Arc::new(Semaphore::new(max_queue)),
            max_queue,
        }
    }

    /// Acquire a request permit or return `Error::TooBusy`.
    pub async fn acquire(&self) -> Result<RequestPermit, Error> {
        if self.max_queue == 0 {
            match self.in_flight.clone().try_acquire_owned() {
                Ok(permit) => {
                    return Ok(RequestPermit { _in_flight: permit });
                }
                Err(TryAcquireError::Closed) => {
                    return Err(Error::Internal("request limiter closed".to_string()));
                }
                Err(TryAcquireError::NoPermits) => {
                    return Err(Error::TooBusy);
                }
            }
        }

        match self.queue_slots.clone().try_acquire_owned() {
            Ok(queue_permit) => {
                let in_flight = match self.in_flight.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        return Err(Error::Internal("request limiter closed".to_string()));
                    }
                };
                drop(queue_permit);
                Ok(RequestPermit {
                    _in_flight: in_flight,
                })
            }
            Err(TryAcquireError::Closed) => {
                Err(Error::Internal("request limiter closed".to_string()))
            }
            Err(TryAcquireError::NoPermits) => Err(Error::TooBusy),
        }
    }
}

pub(crate) struct RequestPermit {
    _in_flight: OwnedSemaphorePermit,
}
