use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "pushgo", version, about = "PushGo 推送网关")]
pub struct CoreArgs {
    /// HTTP bind address.
    #[arg(
        env = "PUSHGO_HTTP_ADDR",
        short = 'a',
        default_value = "127.0.0.1:6666"
    )]
    pub http_addr: String,

    /// Optional Token for API authentication.
    #[arg(env = "PUSHGO_TOKEN", short = 't')]
    pub token: Option<String>,

    /// Max in-flight requests; queue capacity matches this value.
    /// Set to 0 to disable request limiting.
    #[arg(env = "MAX_CONCURRENT", short = 'c', default_value = "200")]
    pub max_concurrent: usize,

    /// Data directory for local storage.
    #[arg(env = "DATA_PATH", short = 'd', default_value = "./data")]
    pub data_path: String,

    /// SQL database URL; uses postgres/mysql based on scheme.
    /// If not set, falls back to the local redb store.
    #[arg(env = "PUSHGO_DB_URL", long = "db-url")]
    pub db_url: Option<String>,
}
