use std::sync::Arc;

use async_channel::{Receiver, Sender, TrySendError};

use crate::{
    providers::{ApnsClient, FcmClient, apns::ApnsPayload, fcm::FcmPayload},
    storage::{Platform, Store},
};

const IN_FLIGHT_LIMIT: usize = 100;
const CHANNEL_CAPACITY: usize = 1000;

pub(crate) struct ApnsJob {
    pub channel_id: [u8; 16],
    pub device_token: Arc<str>,
    pub platform: Platform,
    pub payload: Arc<ApnsPayload>,
    pub collapse_id: Option<Arc<str>>,
}

pub(crate) struct FcmJob {
    pub channel_id: [u8; 16],
    pub device_token: Arc<str>,
    pub payload: Arc<FcmPayload>,
}

#[derive(Clone)]
pub(crate) struct DispatchChannels {
    apns_tx: Sender<ApnsJob>,
    fcm_tx: Sender<FcmJob>,
}

#[derive(Debug)]
pub(crate) enum DispatchError {
    QueueFull,
    ChannelClosed,
}

impl DispatchChannels {
    pub(crate) fn try_send_apns(&self, job: ApnsJob) -> Result<(), DispatchError> {
        match self.apns_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Closed(_)) => Err(DispatchError::ChannelClosed),
        }
    }

    pub(crate) fn try_send_fcm(&self, job: FcmJob) -> Result<(), DispatchError> {
        match self.fcm_tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(DispatchError::QueueFull),
            Err(TrySendError::Closed(_)) => Err(DispatchError::ChannelClosed),
        }
    }
}

pub(crate) fn create_dispatch_channels() -> (DispatchChannels, Receiver<ApnsJob>, Receiver<FcmJob>)
{
    let (apns_tx, apns_rx) = async_channel::bounded(CHANNEL_CAPACITY);
    let (fcm_tx, fcm_rx) = async_channel::bounded(CHANNEL_CAPACITY);
    (DispatchChannels { apns_tx, fcm_tx }, apns_rx, fcm_rx)
}

pub(crate) fn spawn_dispatch_workers(
    apns_rx: Receiver<ApnsJob>,
    fcm_rx: Receiver<FcmJob>,
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    store: Store,
) {
    spawn_apns_worker(apns_rx, apns, Arc::clone(&store));
    spawn_fcm_worker(fcm_rx, fcm, store);
}

fn spawn_apns_worker(apns_rx: Receiver<ApnsJob>, apns: Arc<dyn ApnsClient>, store: Store) {
    for _ in 0..IN_FLIGHT_LIMIT {
        let apns_rx = apns_rx.clone();
        let apns = Arc::clone(&apns);
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            while let Ok(job) = apns_rx.recv().await {
                let dispatch = apns
                    .send_to_device(
                        job.device_token.as_ref(),
                        job.platform,
                        job.payload,
                        job.collapse_id,
                    )
                    .await;
                if dispatch.invalid_token {
                    let _ = store.unsubscribe_channel(
                        job.channel_id,
                        job.device_token.as_ref(),
                        job.platform,
                    );
                }
            }
        });
    }
}

fn spawn_fcm_worker(fcm_rx: Receiver<FcmJob>, fcm: Arc<dyn FcmClient>, store: Store) {
    for _ in 0..IN_FLIGHT_LIMIT {
        let fcm_rx = fcm_rx.clone();
        let fcm = Arc::clone(&fcm);
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            while let Ok(job) = fcm_rx.recv().await {
                let dispatch = fcm
                    .send_to_device(job.device_token.as_ref(), job.payload)
                    .await;
                if dispatch.invalid_token {
                    let _ = store.unsubscribe_channel(
                        job.channel_id,
                        job.device_token.as_ref(),
                        Platform::ANDROID,
                    );
                }
            }
        });
    }
}
