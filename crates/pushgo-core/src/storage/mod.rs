use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use blake3::Hasher;
use chrono::Utc;
use dashmap::DashMap;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sqlx::{MySqlPool, PgPool, Row, mysql::MySqlPoolOptions, postgres::PgPoolOptions};
use std::{path::Path, str::FromStr, sync::Arc};
use thiserror::Error;
use tokio::task::block_in_place;
use uuid::Uuid;

const CHANNELS_META: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("channels_meta");
const DEVICES_TABLE: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("devices");
const SUBS_BY_CHANNEL: TableDefinition<[u8; 48], u8> = TableDefinition::new("subs_by_channel");
const SUBS_BY_DEVICE: TableDefinition<[u8; 48], u8> = TableDefinition::new("subs_by_device");

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    RedbDatabase(#[from] redb::DatabaseError),
    #[error(transparent)]
    RedbTxn(#[from] redb::TransactionError),
    #[error(transparent)]
    RedbTable(#[from] redb::TableError),
    #[error(transparent)]
    RedbCommit(#[from] redb::CommitError),
    #[error(transparent)]
    RedbStorage(#[from] redb::StorageError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("Unsupported database type: {0}")]
    InvalidDatabaseType(String),
    #[error("Database URL is required for {0}")]
    MissingDatabaseUrl(&'static str),
    #[error("Async runtime is not available")]
    RuntimeUnavailable,
    #[error("Invalid device token")]
    InvalidDeviceToken,
    #[error("Invalid platform")]
    InvalidPlatform,
    #[error("Binary Error")]
    BinaryError,
    #[error("Channel not found")]
    ChannelNotFound,
    #[error("Channel password mismatch")]
    ChannelPasswordMismatch,
    #[error("Channel alias missing")]
    ChannelAliasMissing,
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Password hash error: {0}")]
    PasswordHash(String),
}

impl From<argon2::password_hash::Error> for StoreError {
    fn from(err: argon2::password_hash::Error) -> Self {
        StoreError::PasswordHash(err.to_string())
    }
}

type StoreResult<T> = Result<T, StoreError>;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Platform {
    IOS = 1,
    MACOS = 2,
    WATCHOS = 4,
    ANDROID = 5,
    WINDOWS = 6,
}

impl FromStr for Platform {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim();
        let normalized = raw.to_ascii_lowercase();

        match normalized.as_str() {
            "ios" => Ok(Platform::IOS),
            "ipados" => Ok(Platform::IOS),
            "macos" => Ok(Platform::MACOS),
            "watchos" => Ok(Platform::WATCHOS),
            "android" => Ok(Platform::ANDROID),
            "windows" | "win" => Ok(Platform::WINDOWS),
            _ => Err(StoreError::InvalidPlatform),
        }
    }
}

impl Platform {
    #[inline]
    fn to_byte(self) -> u8 {
        self as u8
    }

    #[inline]
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Platform::IOS),
            2 => Some(Platform::MACOS),
            4 => Some(Platform::WATCHOS),
            5 => Some(Platform::ANDROID),
            6 => Some(Platform::WINDOWS),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseKind {
    Redb,
    Postgres,
    Mysql,
}

impl DatabaseKind {
    fn from_url(db_url: Option<&str>) -> StoreResult<Self> {
        let Some(raw) = db_url else {
            return Ok(DatabaseKind::Redb);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(DatabaseKind::Redb);
        }
        let Some((scheme, _)) = trimmed.split_once("://") else {
            return Err(StoreError::InvalidDatabaseType("unknown".to_string()));
        };
        let normalized = scheme.to_ascii_lowercase();
        match normalized.as_str() {
            "postgres" | "postgresql" | "pg" => Ok(DatabaseKind::Postgres),
            "mysql" => Ok(DatabaseKind::Mysql),
            "redb" => Ok(DatabaseKind::Redb),
            other => Err(StoreError::InvalidDatabaseType(other.to_string())),
        }
    }
}

const DEVICEINFO_TOKEN_MIN_LEN: usize = 32;
const DEVICEINFO_TOKEN_MAX_LEN: usize = 128;
const ANDROID_TOKEN_MIN_LEN: usize = 16;
const ANDROID_TOKEN_MAX_LEN: usize = 4096;
const DEVICEINFO_MAGIC: [u8; 2] = *b"DI";
const DEVICEINFO_VERSION: u8 = 1;

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_token(s: &str) -> StoreResult<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(StoreError::InvalidDeviceToken);
    }
    let len = bytes.len() / 2;
    if !(DEVICEINFO_TOKEN_MIN_LEN..=DEVICEINFO_TOKEN_MAX_LEN).contains(&len) {
        return Err(StoreError::InvalidDeviceToken);
    }

    let mut out = Vec::with_capacity(len);
    let mut i = 0usize;
    while i < len {
        let hi = hex_nibble(bytes[i * 2]).ok_or(StoreError::InvalidDeviceToken)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(StoreError::InvalidDeviceToken)?;
        out.push((hi << 4) | lo);
        i += 1;
    }
    Ok(out)
}

fn decode_android_token(s: &str) -> StoreResult<Vec<u8>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(StoreError::InvalidDeviceToken);
    }
    let len = trimmed.len();
    if !(ANDROID_TOKEN_MIN_LEN..=ANDROID_TOKEN_MAX_LEN).contains(&len) {
        return Err(StoreError::InvalidDeviceToken);
    }
    Ok(trimmed.as_bytes().to_vec())
}

fn token_len_valid(platform: Platform, len: usize) -> bool {
    match platform {
        Platform::ANDROID | Platform::WINDOWS => {
            (ANDROID_TOKEN_MIN_LEN..=ANDROID_TOKEN_MAX_LEN).contains(&len)
        }
        _ => (DEVICEINFO_TOKEN_MIN_LEN..=DEVICEINFO_TOKEN_MAX_LEN).contains(&len),
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0F) as usize] as char);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub token_raw: Vec<u8>,
    /// Cached token string for providers (APNs hex, FCM raw).
    pub token_str: Arc<str>,
    pub platform: Platform,
}

impl DeviceInfo {
    /// Parse and validate a client-provided token string.
    pub fn from_token(platform: Platform, token: &str) -> StoreResult<Self> {
        let raw = match platform {
            Platform::ANDROID | Platform::WINDOWS => decode_android_token(token)?,
            _ => decode_hex_token(token)?,
        };
        Self::from_raw(platform, raw)
    }

    /// Build from raw bytes loaded from storage.
    pub fn from_raw(platform: Platform, raw: Vec<u8>) -> StoreResult<Self> {
        let token_str = match platform {
            Platform::ANDROID | Platform::WINDOWS => {
                String::from_utf8(raw.clone()).map_err(|_| StoreError::BinaryError)?
            }
            _ => encode_hex_lower(&raw),
        };
        Ok(DeviceInfo {
            token_raw: raw,
            token_str: Arc::<str>::from(token_str),
            platform,
        })
    }

    /// Binary format (v1):
    /// [ magic: "DI" ][ version: u8 ][ platform: u8 ][ token_len: u16 BE ][ token_raw bytes ].
    ///
    /// Storage keeps raw bytes; string forms are rebuilt in memory.
    pub fn to_bytes(&self) -> StoreResult<Vec<u8>> {
        let token = &self.token_raw;
        let token_len = token.len();
        if !token_len_valid(self.platform, token_len) {
            return Err(StoreError::BinaryError);
        }

        let mut out = Vec::with_capacity(2 + 1 + 1 + 2 + token_len);
        out.extend_from_slice(&DEVICEINFO_MAGIC);
        out.push(DEVICEINFO_VERSION);
        out.push(self.platform.to_byte());
        out.extend_from_slice(&(token_len as u16).to_be_bytes());
        out.extend_from_slice(token);
        Ok(out)
    }

    /// Parse the custom binary format into `DeviceInfo`.
    pub fn from_bytes(bytes: &[u8]) -> StoreResult<Self> {
        // Minimum payload: magic(2) + version(1) + platform(1) + len(2).
        if bytes.len() < 6 {
            return Err(StoreError::BinaryError);
        }

        if bytes[0..2] != DEVICEINFO_MAGIC {
            return Err(StoreError::BinaryError);
        }

        let version = bytes[2];
        if version != DEVICEINFO_VERSION {
            return Err(StoreError::BinaryError);
        }

        let platform = Platform::from_byte(bytes[3]).ok_or(StoreError::BinaryError)?;
        let token_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;

        if !token_len_valid(platform, token_len) {
            return Err(StoreError::BinaryError);
        }

        let expected_total = 6usize.saturating_add(token_len);
        if bytes.len() != expected_total {
            return Err(StoreError::BinaryError);
        }

        let token_slice = &bytes[6..];
        let raw = token_slice.to_vec();

        DeviceInfo::from_raw(platform, raw)
    }

    #[inline]
    pub fn token_str(&self) -> &str {
        self.token_str.as_ref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelMeta {
    password_hash: String,
    alias: String,
    created_at: i64,
    updated_at: i64,
}

fn verify_channel_password(password_hash: &str, password: &str) -> StoreResult<()> {
    let parsed = PasswordHash::new(password_hash)?;
    let verifier = Argon2::default();
    verifier
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| StoreError::ChannelPasswordMismatch)
}

fn hash_channel_password(password: &str) -> StoreResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn device_id_for(platform: Platform, token_raw: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[platform.to_byte()]);
    hasher.update(token_raw);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub alias: String,
}

#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    pub channel_id: [u8; 16],
    pub alias: String,
    pub created: bool,
}

pub trait StoreApi: Send + Sync {
    fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>>;
    fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>>;
    fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome>;
    fn rename_channel(&self, channel_id: [u8; 16], password: &str, alias: &str) -> StoreResult<()>;
    fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool>;
    fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize>;
    fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>>;
}

pub type Store = Arc<dyn StoreApi>;

pub fn new_store<P: AsRef<Path>>(
    data_path: P,
    db_url: Option<&str>,
) -> StoreResult<Store> {
    let db_url = db_url.and_then(|url| {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let kind = DatabaseKind::from_url(db_url)?;
    match kind {
        DatabaseKind::Redb => Ok(Arc::new(RedbStore::new(data_path)?)),
        DatabaseKind::Postgres => {
            let url = db_url.ok_or(StoreError::MissingDatabaseUrl("postgres"))?;
            Ok(Arc::new(build_sql_store(DatabaseKind::Postgres, url)?))
        }
        DatabaseKind::Mysql => {
            let url = db_url.ok_or(StoreError::MissingDatabaseUrl("mysql"))?;
            Ok(Arc::new(build_sql_store(DatabaseKind::Mysql, url)?))
        }
    }
}

fn build_sql_store(kind: DatabaseKind, url: &str) -> StoreResult<SqlxStore> {
    let handle =
        tokio::runtime::Handle::try_current().map_err(|_| StoreError::RuntimeUnavailable)?;
    block_in_place(|| handle.block_on(async { SqlxStore::connect(kind, url).await }))
}

#[derive(Debug, Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    device_cache: Arc<DashMap<[u8; 32], DeviceInfo>>,
}

impl RedbStore {
    pub fn new<P: AsRef<Path>>(data_path: P) -> StoreResult<Self> {
        let db_path = data_path.as_ref().join("db.redb");
        let db = Database::create(db_path)?;
        let txn = db.begin_write()?;

        txn.open_table(CHANNELS_META)?;
        txn.open_table(DEVICES_TABLE)?;
        txn.open_table(SUBS_BY_CHANNEL)?;
        txn.open_table(SUBS_BY_DEVICE)?;
        txn.commit()?;

        Ok(RedbStore {
            db: db.into(),
            device_cache: Default::default(),
        })
    }

    fn channel_meta_for(
        &self,
        table: &redb::Table<'_, [u8; 16], &[u8]>,
        channel_id: [u8; 16],
    ) -> StoreResult<ChannelMeta> {
        let raw = table.get(channel_id)?.ok_or(StoreError::ChannelNotFound)?;
        let meta: ChannelMeta = serde_json::from_slice(raw.value())?;
        Ok(meta)
    }

    fn insert_device(
        &self,
        table: &mut redb::Table<'_, [u8; 32], &[u8]>,
        device_id: [u8; 32],
        device: &DeviceInfo,
    ) -> StoreResult<()> {
        let encoded = device.to_bytes()?;
        table.insert(device_id, encoded.as_slice())?;
        Ok(())
    }

    fn subscription_key(channel_id: [u8; 16], device_id: [u8; 32]) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..16].copy_from_slice(&channel_id);
        out[16..].copy_from_slice(&device_id);
        out
    }

    fn subscription_key_device(device_id: [u8; 32], channel_id: [u8; 16]) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..32].copy_from_slice(&device_id);
        out[32..].copy_from_slice(&channel_id);
        out
    }

    fn channel_range_start(channel_id: [u8; 16]) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..16].copy_from_slice(&channel_id);
        out
    }

    fn channel_range_end(channel_id: [u8; 16]) -> [u8; 48] {
        let mut out = [0xFFu8; 48];
        out[..16].copy_from_slice(&channel_id);
        out
    }

    fn device_range_start(device_id: [u8; 32]) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..32].copy_from_slice(&device_id);
        out
    }

    fn device_range_end(device_id: [u8; 32]) -> [u8; 48] {
        let mut out = [0xFFu8; 48];
        out[..32].copy_from_slice(&device_id);
        out
    }
}

impl StoreApi for RedbStore {
    fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CHANNELS_META)?;
        let meta = match table.get(channel_id)? {
            Some(raw) => serde_json::from_slice::<ChannelMeta>(raw.value())?,
            None => return Ok(None),
        };
        Ok(Some(ChannelInfo { alias: meta.alias }))
    }

    fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CHANNELS_META)?;
        let meta = match table.get(channel_id)? {
            Some(raw) => serde_json::from_slice::<ChannelMeta>(raw.value())?,
            None => return Ok(None),
        };
        verify_channel_password(&meta.password_hash, password)?;
        Ok(Some(ChannelInfo { alias: meta.alias }))
    }

    fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let now = Utc::now().timestamp();

        let wtxn = self.db.begin_write()?;
        let (channel_id, created, channel_alias) = {
            let mut created = false;
            let mut meta_table = wtxn.open_table(CHANNELS_META)?;
            let mut device_table = wtxn.open_table(DEVICES_TABLE)?;
            let mut subs_channel = wtxn.open_table(SUBS_BY_CHANNEL)?;
            let mut subs_device = wtxn.open_table(SUBS_BY_DEVICE)?;

            let (channel_id, channel_alias) = if let Some(channel_id) = channel_id {
                let meta = self.channel_meta_for(&meta_table, channel_id)?;
                verify_channel_password(&meta.password_hash, password)?;
                (channel_id, meta.alias)
            } else {
                let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
                let new_id = Uuid::new_v4().into_bytes();
                let hash = hash_channel_password(password)?;
                let meta = ChannelMeta {
                    password_hash: hash,
                    alias: alias.to_string(),
                    created_at: now,
                    updated_at: now,
                };
                let encoded = serde_json::to_vec(&meta)?;
                meta_table.insert(new_id, encoded.as_slice())?;
                created = true;
                (new_id, meta.alias)
            };
            self.insert_device(&mut device_table, device_id, &device_info)?;

            let key = Self::subscription_key(channel_id, device_id);
            subs_channel.insert(key, 1)?;
            let key_by_device = Self::subscription_key_device(device_id, channel_id);
            subs_device.insert(key_by_device, 1)?;
            (channel_id, created, channel_alias)
        };
        wtxn.commit()?;

        self.device_cache.insert(device_id, device_info);

        Ok(SubscribeOutcome {
            channel_id,
            alias: channel_alias,
            created,
        })
    }

    fn rename_channel(&self, channel_id: [u8; 16], password: &str, alias: &str) -> StoreResult<()> {
        let now = Utc::now().timestamp();
        let wtxn = self.db.begin_write()?;
        {
            let mut meta_table = wtxn.open_table(CHANNELS_META)?;
            let mut meta = self.channel_meta_for(&meta_table, channel_id)?;
            verify_channel_password(&meta.password_hash, password)?;
            meta.alias = alias.to_string();
            meta.updated_at = now;
            let encoded = serde_json::to_vec(&meta)?;
            meta_table.insert(channel_id, encoded.as_slice())?;
        }
        wtxn.commit()?;
        Ok(())
    }

    fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);

        let mut removed = false;

        let wtxn = self.db.begin_write()?;
        {
            let mut subs_channel = wtxn.open_table(SUBS_BY_CHANNEL)?;
            let mut subs_device = wtxn.open_table(SUBS_BY_DEVICE)?;

            let key = Self::subscription_key(channel_id, device_id);
            if subs_channel.remove(key)?.is_some() {
                removed = true;
            }
            let key_by_device = Self::subscription_key_device(device_id, channel_id);
            subs_device.remove(key_by_device)?;
        }
        wtxn.commit()?;

        Ok(removed)
    }

    fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);

        let mut removed = 0usize;

        let wtxn = self.db.begin_write()?;
        {
            let mut subs_channel = wtxn.open_table(SUBS_BY_CHANNEL)?;
            let mut subs_device = wtxn.open_table(SUBS_BY_DEVICE)?;
            let mut device_table = wtxn.open_table(DEVICES_TABLE)?;

            let start = Self::device_range_start(device_id);
            let end = Self::device_range_end(device_id);
            let mut keys = Vec::new();
            for entry in subs_device.range(start..=end)? {
                let (key, _) = entry?;
                keys.push(key.value());
            }

            for key in keys {
                let mut channel_id = [0u8; 16];
                channel_id.copy_from_slice(&key[32..48]);
                let channel_key = Self::subscription_key(channel_id, device_id);
                if subs_channel.remove(channel_key)?.is_some() {
                    removed += 1;
                }
                subs_device.remove(key)?;
            }

            device_table.remove(device_id)?;
        }
        wtxn.commit()?;

        self.device_cache.remove(&device_id);

        Ok(removed)
    }

    fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
        let txn = self.db.begin_read()?;
        let subs = txn.open_table(SUBS_BY_CHANNEL)?;
        let devices_table = txn.open_table(DEVICES_TABLE)?;

        let start = Self::channel_range_start(channel_id);
        let end = Self::channel_range_end(channel_id);
        let mut devices = Vec::new();

        for entry in subs.range(start..=end)? {
            let (key, _) = entry?;
            let key = key.value();
            let mut device_id = [0u8; 32];
            device_id.copy_from_slice(&key[16..48]);

            if let Some(cached) = self.device_cache.get(&device_id) {
                devices.push(cached.clone());
                continue;
            }

            if let Some(raw) = devices_table.get(device_id)? {
                let info = DeviceInfo::from_bytes(raw.value())?;
                self.device_cache.insert(device_id, info.clone());
                devices.push(info);
            }
        }

        Ok(devices)
    }
}

#[derive(Debug, Clone)]
pub struct SqlxStore {
    backend: SqlxBackend,
    device_cache: Arc<DashMap<[u8; 32], DeviceInfo>>,
}

#[derive(Debug, Clone)]
enum SqlxBackend {
    Postgres(PgPool),
    Mysql(MySqlPool),
}

impl SqlxStore {
    async fn connect(kind: DatabaseKind, url: &str) -> StoreResult<Self> {
        let store = match kind {
            DatabaseKind::Postgres => {
                let pool = PgPoolOptions::new()
                    .max_connections(16)
                    .connect(url)
                    .await?;
                SqlxStore {
                    backend: SqlxBackend::Postgres(pool),
                    device_cache: Default::default(),
                }
            }
            DatabaseKind::Mysql => {
                let pool = MySqlPoolOptions::new()
                    .max_connections(16)
                    .connect(url)
                    .await?;
                SqlxStore {
                    backend: SqlxBackend::Mysql(pool),
                    device_cache: Default::default(),
                }
            }
            DatabaseKind::Redb => return Err(StoreError::InvalidDatabaseType("redb".to_string())),
        };
        store.init_schema().await?;
        Ok(store)
    }

    async fn init_schema(&self) -> StoreResult<()> {
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS channels (\
                        channel_id BYTEA PRIMARY KEY,\
                        password_hash TEXT NOT NULL,\
                        alias TEXT NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        updated_at BIGINT NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS devices (\
                        device_id BYTEA PRIMARY KEY,\
                        device_blob BYTEA NOT NULL\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS subscriptions (\
                        channel_id BYTEA NOT NULL,\
                        device_id BYTEA NOT NULL,\
                        PRIMARY KEY (channel_id, device_id)\
                    )",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE INDEX IF NOT EXISTS subscriptions_device_idx \
                    ON subscriptions (device_id)",
                )
                .execute(pool)
                .await?;
            }
            SqlxBackend::Mysql(pool) => {
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS channels (\
                        channel_id BINARY(16) PRIMARY KEY,\
                        password_hash TEXT NOT NULL,\
                        alias TEXT NOT NULL,\
                        created_at BIGINT NOT NULL,\
                        updated_at BIGINT NOT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS devices (\
                        device_id BINARY(32) PRIMARY KEY,\
                        device_blob BLOB NOT NULL\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS subscriptions (\
                        channel_id BINARY(16) NOT NULL,\
                        device_id BINARY(32) NOT NULL,\
                        PRIMARY KEY (channel_id, device_id),\
                        INDEX subscriptions_device_idx (device_id)\
                    ) ENGINE=InnoDB",
                )
                .execute(pool)
                .await?;

                // Ensure the device_id index exists even when the table pre-dates this schema.
                let idx_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(1) \
                     FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() \
                       AND table_name = 'subscriptions' \
                       AND index_name = 'subscriptions_device_idx'",
                )
                .fetch_one(pool)
                .await?;
                if idx_count == 0 {
                    sqlx::query(
                        "CREATE INDEX subscriptions_device_idx ON subscriptions (device_id)",
                    )
                    .execute(pool)
                    .await?;
                }
            }
        }
        Ok(())
    }
}

impl StoreApi for SqlxStore {
    fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        let channel_bytes = channel_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let row =
                                sqlx::query("SELECT alias FROM channels WHERE channel_id = $1")
                                    .bind(&channel_bytes)
                                    .fetch_optional(&pool)
                                    .await?;
                            match row {
                                Some(row) => {
                                    let alias: String = row.try_get("alias")?;
                                    Ok(Some(ChannelInfo { alias }))
                                }
                                None => Ok(None),
                            }
                        })
                })
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let row =
                                sqlx::query("SELECT alias FROM channels WHERE channel_id = ?")
                                    .bind(&channel_bytes)
                                    .fetch_optional(&pool)
                                    .await?;
                            match row {
                                Some(row) => {
                                    let alias: String = row.try_get("alias")?;
                                    Ok(Some(ChannelInfo { alias }))
                                }
                                None => Ok(None),
                            }
                        })
                })
            }
        }
    }

    fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>> {
        let channel_bytes = channel_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let row = sqlx::query(
                                "SELECT password_hash, alias FROM channels WHERE channel_id = $1",
                            )
                            .bind(&channel_bytes)
                            .fetch_optional(&pool)
                            .await?;
                            match row {
                                Some(row) => {
                                    let password_hash: String = row.try_get("password_hash")?;
                                    verify_channel_password(&password_hash, password)?;
                                    let alias: String = row.try_get("alias")?;
                                    Ok(Some(ChannelInfo { alias }))
                                }
                                None => Ok(None),
                            }
                        })
                })
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let row = sqlx::query(
                                "SELECT password_hash, alias FROM channels WHERE channel_id = ?",
                            )
                            .bind(&channel_bytes)
                            .fetch_optional(&pool)
                            .await?;
                            match row {
                                Some(row) => {
                                    let password_hash: String = row.try_get("password_hash")?;
                                    verify_channel_password(&password_hash, password)?;
                                    let alias: String = row.try_get("alias")?;
                                    Ok(Some(ChannelInfo { alias }))
                                }
                                None => Ok(None),
                            }
                        })
                })
            }
        }
    }

    fn subscribe_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let device_blob = device_info.to_bytes()?;
        let now = Utc::now().timestamp();

        let outcome = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                let channel_id = channel_id.map(|id| id.to_vec());
                let alias = alias.map(str::to_string);
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let mut tx = pool.begin().await?;
                            let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                                let row = sqlx::query(
                                    "SELECT password_hash, alias FROM channels WHERE channel_id = $1",
                                )
                                .bind(&channel_id)
                                .fetch_optional(&mut *tx)
                                .await?;
                                let row = row.ok_or(StoreError::ChannelNotFound)?;
                                let password_hash: String = row.try_get("password_hash")?;
                                verify_channel_password(&password_hash, password)?;
                                let channel_alias: String = row.try_get("alias")?;
                                (channel_id, false, channel_alias)
                            } else {
                                let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
                                let new_id = Uuid::new_v4().into_bytes().to_vec();
                                let hash = hash_channel_password(password)?;
                                sqlx::query(
                                    "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                                    VALUES ($1, $2, $3, $4, $5)",
                                )
                                .bind(&new_id)
                                .bind(hash)
                                .bind(&alias)
                                .bind(now)
                                .bind(now)
                                .execute(&mut *tx)
                                .await?;
                                (new_id, true, alias)
                            };

                            sqlx::query(
                                "INSERT INTO devices (device_id, device_blob) VALUES ($1, $2) \
                                ON CONFLICT (device_id) DO UPDATE SET device_blob = EXCLUDED.device_blob",
                            )
                            .bind(&device_id[..])
                            .bind(&device_blob)
                            .execute(&mut *tx)
                            .await?;

                            sqlx::query(
                                "INSERT INTO subscriptions (channel_id, device_id) VALUES ($1, $2) \
                                ON CONFLICT DO NOTHING",
                            )
                            .bind(&channel_bytes)
                            .bind(&device_id[..])
                            .execute(&mut *tx)
                            .await?;

                            tx.commit().await?;

                            let mut channel_id_arr = [0u8; 16];
                            channel_id_arr.copy_from_slice(&channel_bytes);
                            Ok::<SubscribeOutcome, StoreError>(SubscribeOutcome {
                                channel_id: channel_id_arr,
                                alias: channel_alias,
                                created,
                            })
                        })
                })
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                let channel_id = channel_id.map(|id| id.to_vec());
                let alias = alias.map(str::to_string);
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let mut tx = pool.begin().await?;
                            let (channel_bytes, created, channel_alias) = if let Some(channel_id) = channel_id {
                                let row = sqlx::query(
                                    "SELECT password_hash, alias FROM channels WHERE channel_id = ?",
                                )
                                .bind(&channel_id)
                                .fetch_optional(&mut *tx)
                                .await?;
                                let row = row.ok_or(StoreError::ChannelNotFound)?;
                                let password_hash: String = row.try_get("password_hash")?;
                                verify_channel_password(&password_hash, password)?;
                                let channel_alias: String = row.try_get("alias")?;
                                (channel_id, false, channel_alias)
                            } else {
                                let alias = alias.ok_or(StoreError::ChannelAliasMissing)?;
                                let new_id = Uuid::new_v4().into_bytes().to_vec();
                                let hash = hash_channel_password(password)?;
                                sqlx::query(
                                    "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
                                    VALUES (?, ?, ?, ?, ?)",
                                )
                                .bind(&new_id)
                                .bind(hash)
                                .bind(&alias)
                                .bind(now)
                                .bind(now)
                                .execute(&mut *tx)
                                .await?;
                                (new_id, true, alias)
                            };

                            sqlx::query(
                                "INSERT INTO devices (device_id, device_blob) VALUES (?, ?) \
                                ON DUPLICATE KEY UPDATE device_blob = VALUES(device_blob)",
                            )
                            .bind(&device_id[..])
                            .bind(&device_blob)
                            .execute(&mut *tx)
                            .await?;

                            sqlx::query(
                                "INSERT IGNORE INTO subscriptions (channel_id, device_id) VALUES (?, ?)",
                            )
                            .bind(&channel_bytes)
                            .bind(&device_id[..])
                            .execute(&mut *tx)
                            .await?;

                            tx.commit().await?;

                            let mut channel_id_arr = [0u8; 16];
                            channel_id_arr.copy_from_slice(&channel_bytes);
                            Ok::<SubscribeOutcome, StoreError>(SubscribeOutcome {
                                channel_id: channel_id_arr,
                                alias: channel_alias,
                                created,
                            })
                        })
                })
            }
        }?;

        self.device_cache.insert(device_id, device_info);
        Ok(outcome)
    }

    fn rename_channel(&self, channel_id: [u8; 16], password: &str, alias: &str) -> StoreResult<()> {
        let channel_bytes = channel_id.to_vec();
        let now = Utc::now().timestamp();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let mut tx = pool.begin().await?;
                            let row = sqlx::query(
                                "SELECT password_hash FROM channels WHERE channel_id = $1",
                            )
                            .bind(&channel_bytes)
                            .fetch_optional(&mut *tx)
                            .await?;
                            let row = row.ok_or(StoreError::ChannelNotFound)?;
                            let password_hash: String = row.try_get("password_hash")?;
                            verify_channel_password(&password_hash, password)?;
                            sqlx::query(
                                "UPDATE channels SET alias = $1, updated_at = $2 WHERE channel_id = $3",
                            )
                            .bind(alias)
                            .bind(now)
                            .bind(&channel_bytes)
                            .execute(&mut *tx)
                            .await?;
                            tx.commit().await?;
                            Ok(())
                        })
                })
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let mut tx = pool.begin().await?;
                            let row = sqlx::query(
                                "SELECT password_hash FROM channels WHERE channel_id = ?",
                            )
                            .bind(&channel_bytes)
                            .fetch_optional(&mut *tx)
                            .await?;
                            let row = row.ok_or(StoreError::ChannelNotFound)?;
                            let password_hash: String = row.try_get("password_hash")?;
                            verify_channel_password(&password_hash, password)?;
                            sqlx::query(
                                "UPDATE channels SET alias = ?, updated_at = ? WHERE channel_id = ?",
                            )
                            .bind(alias)
                            .bind(now)
                            .bind(&channel_bytes)
                            .execute(&mut *tx)
                            .await?;
                            tx.commit().await?;
                            Ok(())
                        })
                })
            }
        }
    }

    fn unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_token: &str,
        platform: Platform,
    ) -> StoreResult<bool> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        let channel_bytes = channel_id.to_vec();
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let result = sqlx::query(
                                "DELETE FROM subscriptions WHERE channel_id = $1 AND device_id = $2",
                            )
                            .bind(&channel_bytes)
                            .bind(&device_id[..])
                            .execute(&pool)
                            .await?;
                            Ok(result.rows_affected() > 0)
                        })
                })
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let result = sqlx::query(
                                "DELETE FROM subscriptions WHERE channel_id = ? AND device_id = ?",
                            )
                            .bind(&channel_bytes)
                            .bind(&device_id[..])
                            .execute(&pool)
                            .await?;
                            Ok(result.rows_affected() > 0)
                        })
                })
            }
        }
    }

    fn retire_device(&self, device_token: &str, platform: Platform) -> StoreResult<usize> {
        let device_info = DeviceInfo::from_token(platform, device_token)?;
        let device_id = device_id_for(platform, &device_info.token_raw);
        match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                let removed = block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let mut tx = pool.begin().await?;
                            let removed =
                                sqlx::query("DELETE FROM subscriptions WHERE device_id = $1")
                                    .bind(&device_id[..])
                                    .execute(&mut *tx)
                                    .await?
                                    .rows_affected() as usize;
                            sqlx::query("DELETE FROM devices WHERE device_id = $1")
                                .bind(&device_id[..])
                                .execute(&mut *tx)
                                .await?;
                            tx.commit().await?;
                            Ok::<usize, StoreError>(removed)
                        })
                })?;
                self.device_cache.remove(&device_id);
                Ok(removed)
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                let removed = block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let mut tx = pool.begin().await?;
                            let removed =
                                sqlx::query("DELETE FROM subscriptions WHERE device_id = ?")
                                    .bind(&device_id[..])
                                    .execute(&mut *tx)
                                    .await?
                                    .rows_affected() as usize;
                            sqlx::query("DELETE FROM devices WHERE device_id = ?")
                                .bind(&device_id[..])
                                .execute(&mut *tx)
                                .await?;
                            tx.commit().await?;
                            Ok::<usize, StoreError>(removed)
                        })
                })?;
                self.device_cache.remove(&device_id);
                Ok(removed)
            }
        }
    }

    fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
        let channel_bytes = channel_id.to_vec();
        let rows: Vec<(Vec<u8>, Vec<u8>)> = match &self.backend {
            SqlxBackend::Postgres(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let rows = sqlx::query(
                                "SELECT d.device_id, d.device_blob \
                                FROM subscriptions s \
                                JOIN devices d ON s.device_id = d.device_id \
                                WHERE s.channel_id = $1",
                            )
                            .bind(&channel_bytes)
                            .fetch_all(&pool)
                            .await?;
                            let mut output = Vec::with_capacity(rows.len());
                            for row in rows {
                                let device_id: Vec<u8> = row.try_get("device_id")?;
                                let blob: Vec<u8> = row.try_get("device_blob")?;
                                output.push((device_id, blob));
                            }
                            Ok::<Vec<(Vec<u8>, Vec<u8>)>, StoreError>(output)
                        })
                })
            }
            SqlxBackend::Mysql(pool) => {
                let pool = pool.clone();
                block_in_place(|| {
                    tokio::runtime::Handle::try_current()
                        .map_err(|_| StoreError::RuntimeUnavailable)?
                        .block_on(async move {
                            let rows = sqlx::query(
                                "SELECT d.device_id, d.device_blob \
                                FROM subscriptions s \
                                JOIN devices d ON s.device_id = d.device_id \
                                WHERE s.channel_id = ?",
                            )
                            .bind(&channel_bytes)
                            .fetch_all(&pool)
                            .await?;
                            let mut output = Vec::with_capacity(rows.len());
                            for row in rows {
                                let device_id: Vec<u8> = row.try_get("device_id")?;
                                let blob: Vec<u8> = row.try_get("device_blob")?;
                                output.push((device_id, blob));
                            }
                            Ok::<Vec<(Vec<u8>, Vec<u8>)>, StoreError>(output)
                        })
                })
            }
        }?;

        let mut devices = Vec::with_capacity(rows.len());
        for (device_id, blob) in rows {
            let info = DeviceInfo::from_bytes(&blob)?;
            if device_id.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&device_id);
                self.device_cache.insert(id, info.clone());
            }
            devices.push(info);
        }
        Ok(devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_accepts_ipados_alias() {
        let parsed: Platform = "ipados".parse().expect("parse ipados");
        assert_eq!(parsed, Platform::IOS);
    }

    #[test]
    fn subscribe_creates_channel_and_reuses_password() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let store = RedbStore::new(temp_dir.path()).expect("failed to init database");
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let alias = "alerts";
        let password = "supersecret";

        let first = store
            .subscribe_channel(None, Some(alias), password, token, Platform::IOS)
            .expect("initial subscribe failed");
        assert!(first.created);
        assert_eq!(first.alias, alias);

        let second = store
            .subscribe_channel(Some(first.channel_id), None, password, token, Platform::IOS)
            .expect("repeat subscribe failed");
        assert!(!second.created);
        assert_eq!(first.channel_id, second.channel_id);
    }

    #[test]
    fn subscribe_rejects_wrong_password() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let store = RedbStore::new(temp_dir.path()).expect("failed to init database");
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let first = store
            .subscribe_channel(None, Some("updates"), "goodpassword", token, Platform::IOS)
            .expect("initial subscribe failed");
        let err = store
            .subscribe_channel(
                Some(first.channel_id),
                None,
                "badpassword",
                token,
                Platform::IOS,
            )
            .unwrap_err();

        match err {
            StoreError::ChannelPasswordMismatch => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn retire_device_clears_subscriptions() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let store = RedbStore::new(temp_dir.path()).expect("failed to init database");
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        store
            .subscribe_channel(None, Some("alpha"), "password123", token, Platform::IOS)
            .expect("subscribe failed");
        store
            .subscribe_channel(None, Some("beta"), "password123", token, Platform::IOS)
            .expect("subscribe failed");

        let removed = store
            .retire_device(token, Platform::IOS)
            .expect("cleanup failed");
        assert_eq!(removed, 2);
    }
}
