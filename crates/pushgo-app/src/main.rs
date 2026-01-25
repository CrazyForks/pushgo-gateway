use std::{error::Error, fs::create_dir_all, net::SocketAddr, sync::Arc};

use axum::Router;
use clap::Parser;
use tokio::{net::TcpListener, signal};

use pushgo_core::{
    app::build_app,
    config::CoreArgs,
    providers::{ApnsService, FcmService},
};

use crate::config::AppConfig;
use crate::providers::{apns::ApnsTokenProvider, fcm::FcmTokenProvider};

mod config;
mod providers;

#[derive(Parser, Debug, Clone)]
#[command(name = "pushgo", version, about = "PushGo 推送网关")]
struct Args {
    #[command(flatten)]
    core: CoreArgs,

    /// Path to the config file with APNs/FCM credentials.
    #[arg(
        env = "PUSHGO_CONFIG",
        long = "config",
        default_value = "./pushgo.config.toml"
    )]
    config_path: String,
}

impl Args {
    fn load_config(&self) -> Result<AppConfig, Box<dyn Error>> {
        let raw = std::fs::read_to_string(&self.config_path).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed to read config file {}: {err}", self.config_path),
            )
        })?;
        let config: AppConfig = toml::from_str(&raw).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse config file {}: {err}", self.config_path),
            )
        })?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args
        .core
        .db_url
        .as_deref()
        .map(|url| url.trim().is_empty())
        .unwrap_or(true)
    {
        create_dir_all(&args.core.data_path).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!(
                    "failed to create data directory {}: {err}",
                    args.core.data_path
                ),
            )
        })?;
    }

    let config = args.load_config()?;

    let apns_token_provider = Arc::new(ApnsTokenProvider::new(&config.apns)?);
    let fcm_token_provider = Arc::new(FcmTokenProvider::new(&config.fcm)?);

    let apns = Arc::new(ApnsService::new(
        apns_token_provider,
        &config.apns.endpoint,
    )?);
    let fcm = Arc::new(FcmService::new(fcm_token_provider)?);

    let docs_html = include_str!("../../pushgo-core/src/api/docs.html");
    let app: Router = build_app(&args.core, apns, fcm, docs_html, true)?;
    let addr: SocketAddr = args.core.http_addr.parse()?;

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Wait for Ctrl+C or SIGTERM, then trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            eprintln!("failed to listen for Ctrl+C: {err}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(err) => {
                eprintln!("failed to listen for SIGTERM: {err}");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
