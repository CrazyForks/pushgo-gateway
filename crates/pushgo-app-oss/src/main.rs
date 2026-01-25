use std::{error::Error, fs::create_dir_all, net::SocketAddr, sync::Arc};

use axum::Router;
use clap::Parser;
use tokio::{net::TcpListener, signal};

use pushgo_core::{
    app::build_app,
    config::CoreArgs,
    providers::{ApnsService, FcmService},
};

use crate::providers::{apns::ApnsTokenProvider, fcm::FcmTokenProvider};

mod providers;

#[derive(Parser, Debug, Clone)]
#[command(name = "pushgo-oss", version, about = "PushGo 推送网关（OSS）")]
struct Args {
    #[command(flatten)]
    core: CoreArgs,

    /// Gateway base URL (OSS mode only).
    #[arg(
        env = "PUSHGO_GATEWAY_URL",
        long = "gateway-url",
        default_value = "https://gateway.pushgo.dev"
    )]
    gateway_url: String,
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

    let client = reqwest::Client::builder()
        .user_agent("pushgo-backend/0.1.0")
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| pushgo_core::Error::Internal(err.to_string()))?;

    let apns_token_provider = Arc::new(ApnsTokenProvider::new(&args.gateway_url, client.clone())?);
    let fcm_token_provider = Arc::new(FcmTokenProvider::new(&args.gateway_url, client)?);

    let apns = Arc::new(ApnsService::new(
        apns_token_provider,
        "https://api.push.apple.com",
    )?);
    let fcm = Arc::new(FcmService::new(fcm_token_provider)?);

    let docs_html = include_str!("../../pushgo-core/src/api/docs_oss.html");
    let app: Router = build_app(&args.core, apns, fcm, docs_html, false)?;
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
