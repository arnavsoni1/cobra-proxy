//! Account, credential, quota, and usage primitives for the authenticated ingress.
//!
//! The runtime opens this store only when `PROXY_INGRESS_MODE=production`,
//! after the Rustls/mTLS configuration has validated. Loopback development
//! mode does not activate account authentication or persistent usage writes.
//!
//! The database contains account and billing metadata only. Tor isolation
//! tokens, destinations, URLs, request paths, and other browsing state must
//! remain outside this store. The SQLite file created here is owner-only, but
//! SQLite is not encrypted by this module; production deployments must place it
//! on reviewed encrypted storage (for example, LUKS) or adopt SQLCipher before
//! retaining customer data.
//!
//! `rusqlite` is synchronous. These management methods are suitable for a
//! management worker or a blocking task, not direct execution on an async proxy
//! request task. The authenticated ingress routes database authentication and
//! usage writes through Tokio blocking workers; in-memory admission remains
//! synchronous and bounded.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter, clock::Clock};
use rusqlite::{
    Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::{
    collections::HashMap,
    error::Error as StdError,
    fmt,
    fs::{self, OpenOptions},
    io,
    num::{NonZeroU32, NonZeroU64},
    path::Path,
    str,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const SCHEMA_VERSION: i64 = 1;
const API_KEY_HASH_VERSION: i64 = 1;
const API_KEY_PREFIX: &str = "pxy_";
const API_KEY_PUBLIC_ID_BYTES: usize = 12;
const API_KEY_PUBLIC_ID_ENCODED_BYTES: usize = 16;
const API_KEY_SECRET_BYTES: usize = 32;
const API_KEY_SECRET_ENCODED_BYTES: usize = 43;
const API_KEY_GENERATION_ATTEMPTS: usize = 4;
const MAX_PROXY_AUTHORIZATION_BYTES: usize = 1_024;
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA_SQL: &str = r#"
CREATE TABLE accounts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email               TEXT NOT NULL COLLATE NOCASE UNIQUE,
    stripe_customer_id  TEXT UNIQUE,
    plan                TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'closed')),
    created_at           INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at           INTEGER NOT NULL CHECK (updated_at >= 0)
);

CREATE TABLE account_limits (
    account_id              INTEGER PRIMARY KEY,
    requests_per_second     INTEGER NOT NULL CHECK (requests_per_second > 0),
    request_burst           INTEGER NOT NULL CHECK (request_burst > 0),
    max_concurrent_tunnels  INTEGER NOT NULL CHECK (max_concurrent_tunnels > 0),
    period_request_limit    INTEGER CHECK (period_request_limit > 0),
    period_byte_limit       INTEGER CHECK (period_byte_limit > 0),
    updated_at              INTEGER NOT NULL CHECK (updated_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'closed')),
    created_at  INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at  INTEGER NOT NULL CHECK (updated_at >= 0),
    UNIQUE (account_id, name),
    UNIQUE (id, account_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE api_keys (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id         TEXT NOT NULL UNIQUE,
    account_id        INTEGER NOT NULL,
    workspace_id      INTEGER NOT NULL,
    label             TEXT NOT NULL,
    key_hash_version  INTEGER NOT NULL,
    key_hash          BLOB NOT NULL CHECK (length(key_hash) = 32),
    status            TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at        INTEGER NOT NULL CHECK (created_at >= 0),
    revoked_at        INTEGER CHECK (revoked_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, account_id)
        REFERENCES workspaces(id, account_id) ON DELETE CASCADE
);

CREATE INDEX api_keys_account_workspace_idx
    ON api_keys(account_id, workspace_id);

CREATE TABLE device_credentials (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id              INTEGER NOT NULL,
    workspace_id            INTEGER NOT NULL,
    label                   TEXT NOT NULL,
    certificate_fingerprint BLOB NOT NULL UNIQUE
                                CHECK (length(certificate_fingerprint) = 32),
    status                  TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at              INTEGER NOT NULL CHECK (created_at >= 0),
    revoked_at              INTEGER CHECK (revoked_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, account_id)
        REFERENCES workspaces(id, account_id) ON DELETE CASCADE
);

CREATE INDEX device_credentials_account_workspace_idx
    ON device_credentials(account_id, workspace_id);

CREATE TABLE usage_periods (
    account_id        INTEGER NOT NULL,
    workspace_id      INTEGER NOT NULL,
    period_start      INTEGER NOT NULL CHECK (period_start >= 0),
    requests_used     INTEGER NOT NULL CHECK (requests_used >= 0),
    bytes_to_tor      INTEGER NOT NULL CHECK (bytes_to_tor >= 0),
    bytes_from_tor    INTEGER NOT NULL CHECK (bytes_from_tor >= 0),
    PRIMARY KEY (account_id, workspace_id, period_start),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, account_id)
        REFERENCES workspaces(id, account_id) ON DELETE CASCADE
);
"#;

macro_rules! private_identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub(crate) struct $name(i64);

        impl $name {
            fn from_database(value: i64) -> Result<Self, AccountManagementError> {
                if value <= 0 {
                    return Err(AccountManagementError::CorruptData(concat!(
                        stringify!($name),
                        " must be positive"
                    )));
                }
                Ok(Self(value))
            }

            fn as_i64(self) -> i64 {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

private_identifier!(AccountId);
private_identifier!(WorkspaceId);
private_identifier!(ApiKeyId);
private_identifier!(DeviceCredentialId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnixTimestamp(i64);

impl UnixTimestamp {
    pub(crate) fn new(seconds: i64) -> Result<Self, AccountManagementError> {
        if seconds < 0 {
            return Err(AccountManagementError::InvalidInput(
                "timestamp must not be negative",
            ));
        }
        Ok(Self(seconds))
    }

    pub(crate) fn now() -> Result<Self, AccountManagementError> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            AccountManagementError::InvalidInput("system clock predates Unix epoch")
        })?;
        let seconds = i64::try_from(elapsed.as_secs())
            .map_err(|_| AccountManagementError::CounterOverflow)?;
        Ok(Self(seconds))
    }

    pub(crate) fn period_start_now(period: Duration) -> Result<Self, AccountManagementError> {
        let period_seconds =
            i64::try_from(period.as_secs()).map_err(|_| AccountManagementError::CounterOverflow)?;
        if period_seconds == 0 {
            return Err(AccountManagementError::InvalidInput(
                "usage period must contain at least one second",
            ));
        }
        let now = Self::now()?.as_i64();
        Ok(Self(now - now.rem_euclid(period_seconds)))
    }

    fn as_i64(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlanCode(String);

impl PlanCode {
    pub(crate) fn new(value: &str) -> Result<Self, AccountManagementError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(AccountManagementError::InvalidInput(
                "plan code must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountStatus {
    Active,
    Suspended,
    Closed,
}

impl AccountStatus {
    fn as_database_value(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    fn from_database(value: &str) -> Result<Self, AccountManagementError> {
        match value {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "closed" => Ok(Self::Closed),
            _ => Err(AccountManagementError::CorruptData(
                "unknown account status",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkspaceStatus {
    Active,
    Suspended,
    Closed,
}

impl WorkspaceStatus {
    fn as_database_value(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    fn from_database(value: &str) -> Result<Self, AccountManagementError> {
        match value {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "closed" => Ok(Self::Closed),
            _ => Err(AccountManagementError::CorruptData(
                "unknown workspace status",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialStatus {
    Active,
    Revoked,
}

impl CredentialStatus {
    fn as_database_value(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    fn from_database(value: &str) -> Result<Self, AccountManagementError> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(AccountManagementError::CorruptData(
                "unknown credential status",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AccountLimits {
    requests_per_second: NonZeroU32,
    request_burst: NonZeroU32,
    max_concurrent_tunnels: NonZeroU32,
    period_request_limit: Option<NonZeroU64>,
    period_byte_limit: Option<NonZeroU64>,
}

impl AccountLimits {
    pub(crate) fn new(
        requests_per_second: u32,
        request_burst: u32,
        max_concurrent_tunnels: u32,
        period_request_limit: Option<u64>,
        period_byte_limit: Option<u64>,
    ) -> Result<Self, AccountManagementError> {
        let requests_per_second = NonZeroU32::new(requests_per_second).ok_or(
            AccountManagementError::InvalidInput("requests per second must be non-zero"),
        )?;
        let request_burst = NonZeroU32::new(request_burst).ok_or(
            AccountManagementError::InvalidInput("request burst must be non-zero"),
        )?;
        let max_concurrent_tunnels = NonZeroU32::new(max_concurrent_tunnels).ok_or(
            AccountManagementError::InvalidInput("concurrent tunnel limit must be non-zero"),
        )?;
        let period_request_limit =
            optional_nonzero_limit(period_request_limit, "period request limit")?;
        let period_byte_limit = optional_nonzero_limit(period_byte_limit, "period byte limit")?;

        Ok(Self {
            requests_per_second,
            request_burst,
            max_concurrent_tunnels,
            period_request_limit,
            period_byte_limit,
        })
    }

    pub(crate) fn requests_per_second(self) -> NonZeroU32 {
        self.requests_per_second
    }

    pub(crate) fn request_burst(self) -> NonZeroU32 {
        self.request_burst
    }

    pub(crate) fn max_concurrent_tunnels(self) -> NonZeroU32 {
        self.max_concurrent_tunnels
    }

    pub(crate) fn period_request_limit(self) -> Option<NonZeroU64> {
        self.period_request_limit
    }

    pub(crate) fn period_byte_limit(self) -> Option<NonZeroU64> {
        self.period_byte_limit
    }

    fn from_database(
        requests_per_second: i64,
        request_burst: i64,
        max_concurrent_tunnels: i64,
        period_request_limit: Option<i64>,
        period_byte_limit: Option<i64>,
    ) -> Result<Self, AccountManagementError> {
        Self::new(
            positive_u32_from_database(requests_per_second, "requests per second")?,
            positive_u32_from_database(request_burst, "request burst")?,
            positive_u32_from_database(max_concurrent_tunnels, "concurrent tunnel limit")?,
            optional_u64_from_database(period_request_limit, "period request limit")?,
            optional_u64_from_database(period_byte_limit, "period byte limit")?,
        )
        .map_err(|_| AccountManagementError::CorruptData("invalid stored account limits"))
    }

    fn database_values(self) -> Result<DatabaseLimitValues, AccountManagementError> {
        Ok(DatabaseLimitValues {
            requests_per_second: i64::from(self.requests_per_second.get()),
            request_burst: i64::from(self.request_burst.get()),
            max_concurrent_tunnels: i64::from(self.max_concurrent_tunnels.get()),
            period_request_limit: optional_limit_to_database(self.period_request_limit)?,
            period_byte_limit: optional_limit_to_database(self.period_byte_limit)?,
        })
    }
}

#[derive(Clone, Copy)]
struct DatabaseLimitValues {
    requests_per_second: i64,
    request_burst: i64,
    max_concurrent_tunnels: i64,
    period_request_limit: Option<i64>,
    period_byte_limit: Option<i64>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    pub(crate) fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateFingerprint([redacted])")
    }
}

pub(crate) struct ApiKeySecret(Zeroizing<String>);

impl ApiKeySecret {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ApiKeySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeySecret([redacted])")
    }
}

pub(crate) struct IssuedApiKey {
    id: ApiKeyId,
    public_id: String,
    secret: ApiKeySecret,
}

impl IssuedApiKey {
    pub(crate) fn id(&self) -> ApiKeyId {
        self.id
    }

    pub(crate) fn public_id(&self) -> &str {
        &self.public_id
    }

    pub(crate) fn secret(&self) -> &ApiKeySecret {
        &self.secret
    }
}

impl fmt::Debug for IssuedApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedApiKey")
            .field("id", &self.id)
            .field("public_id", &self.public_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApiKeyMetadata {
    id: ApiKeyId,
    public_id: String,
    label: String,
    status: CredentialStatus,
    created_at: UnixTimestamp,
    revoked_at: Option<UnixTimestamp>,
}

impl fmt::Debug for ApiKeyMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyMetadata")
            .field("id", &self.id)
            .field("public_id", &"[redacted]")
            .field("label", &self.label)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl ApiKeyMetadata {
    pub(crate) fn id(&self) -> ApiKeyId {
        self.id
    }

    pub(crate) fn public_id(&self) -> &str {
        &self.public_id
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn status(&self) -> CredentialStatus {
        self.status
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceCredentialMetadata {
    id: DeviceCredentialId,
    label: String,
    status: CredentialStatus,
    created_at: UnixTimestamp,
    revoked_at: Option<UnixTimestamp>,
}

impl DeviceCredentialMetadata {
    pub(crate) fn id(&self) -> DeviceCredentialId {
        self.id
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn status(&self) -> CredentialStatus {
        self.status
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AccountRecord {
    id: AccountId,
    email: String,
    stripe_customer_id: Option<String>,
    plan: PlanCode,
    status: AccountStatus,
    limits: AccountLimits,
}

impl fmt::Debug for AccountRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountRecord")
            .field("id", &self.id)
            .field("email", &"[redacted]")
            .field("stripe_customer_id", &"[redacted]")
            .field("plan", &self.plan)
            .field("status", &self.status)
            .field("limits", &self.limits)
            .finish()
    }
}

impl AccountRecord {
    pub(crate) fn id(&self) -> AccountId {
        self.id
    }

    pub(crate) fn email(&self) -> &str {
        &self.email
    }

    pub(crate) fn stripe_customer_id(&self) -> Option<&str> {
        self.stripe_customer_id.as_deref()
    }

    pub(crate) fn plan(&self) -> &PlanCode {
        &self.plan
    }

    pub(crate) fn status(&self) -> AccountStatus {
        self.status
    }

    pub(crate) fn limits(&self) -> AccountLimits {
        self.limits
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceRecord {
    id: WorkspaceId,
    account_id: AccountId,
    name: String,
    status: WorkspaceStatus,
}

impl fmt::Debug for WorkspaceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceRecord")
            .field("id", &self.id)
            .field("account_id", &self.account_id)
            .field("name", &"[redacted]")
            .field("status", &self.status)
            .finish()
    }
}

impl WorkspaceRecord {
    pub(crate) fn id(&self) -> WorkspaceId {
        self.id
    }

    pub(crate) fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn status(&self) -> WorkspaceStatus {
        self.status
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct IngressIdentity {
    account_id: AccountId,
    workspace_id: WorkspaceId,
    api_key_id: ApiKeyId,
    device_credential_id: DeviceCredentialId,
    limits: AccountLimits,
}

impl IngressIdentity {
    pub(crate) fn account_id(self) -> AccountId {
        self.account_id
    }

    pub(crate) fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub(crate) fn api_key_id(self) -> ApiKeyId {
        self.api_key_id
    }

    pub(crate) fn device_credential_id(self) -> DeviceCredentialId {
        self.device_credential_id
    }

    pub(crate) fn limits(self) -> AccountLimits {
        self.limits
    }
}

impl fmt::Debug for IngressIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IngressIdentity([tenant references redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UsageDelta {
    requests: u64,
    bytes_to_tor: u64,
    bytes_from_tor: u64,
}

impl UsageDelta {
    pub(crate) fn new(
        requests: u64,
        bytes_to_tor: u64,
        bytes_from_tor: u64,
    ) -> Result<Self, AccountManagementError> {
        checked_database_counter(requests)?;
        checked_database_counter(bytes_to_tor)?;
        checked_database_counter(bytes_from_tor)?;
        bytes_to_tor
            .checked_add(bytes_from_tor)
            .ok_or(AccountManagementError::CounterOverflow)?;
        Ok(Self {
            requests,
            bytes_to_tor,
            bytes_from_tor,
        })
    }

    pub(crate) fn requests(self) -> u64 {
        self.requests
    }

    pub(crate) fn bytes_to_tor(self) -> u64 {
        self.bytes_to_tor
    }

    pub(crate) fn bytes_from_tor(self) -> u64 {
        self.bytes_from_tor
    }

    pub(crate) fn total_bytes(self) -> Result<u64, AccountManagementError> {
        self.bytes_to_tor
            .checked_add(self.bytes_from_tor)
            .ok_or(AccountManagementError::CounterOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UsageSnapshot {
    account_id: AccountId,
    workspace_id: WorkspaceId,
    period_start: UnixTimestamp,
    requests_used: u64,
    bytes_to_tor: u64,
    bytes_from_tor: u64,
}

impl UsageSnapshot {
    pub(crate) fn account_id(self) -> AccountId {
        self.account_id
    }

    pub(crate) fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub(crate) fn period_start(self) -> UnixTimestamp {
        self.period_start
    }

    pub(crate) fn requests_used(self) -> u64 {
        self.requests_used
    }

    pub(crate) fn bytes_to_tor(self) -> u64 {
        self.bytes_to_tor
    }

    pub(crate) fn bytes_from_tor(self) -> u64 {
        self.bytes_from_tor
    }

    pub(crate) fn total_bytes(self) -> Result<u64, AccountManagementError> {
        self.bytes_to_tor
            .checked_add(self.bytes_from_tor)
            .ok_or(AccountManagementError::CounterOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntityKind {
    Account,
    Workspace,
    ApiKey,
    DeviceCredential,
}

#[derive(Debug)]
pub(crate) enum AccountManagementError {
    Database(rusqlite::Error),
    Io(io::Error),
    Entropy(getrandom::Error),
    InvalidInput(&'static str),
    NotFound(EntityKind),
    Conflict(&'static str),
    UnsupportedSchemaVersion(i64),
    InsecureDatabasePath(&'static str),
    InsecureDatabasePermissions(u32),
    InsecureSecretPath(&'static str),
    InsecureSecretPermissions(u32),
    InvalidSecretLength { expected: usize, actual: usize },
    CorruptData(&'static str),
    CounterOverflow,
    StatePoisoned,
    CredentialGenerationExhausted,
}

impl fmt::Display for AccountManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("account database operation failed"),
            Self::Io(_) => formatter.write_str("account database file operation failed"),
            Self::Entropy(_) => formatter.write_str("secure random generation failed"),
            Self::InvalidInput(detail) => write!(formatter, "invalid account input: {detail}"),
            Self::NotFound(entity) => write!(formatter, "{entity:?} record was not found"),
            Self::Conflict(detail) => write!(formatter, "account state conflict: {detail}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported account schema version {version}")
            }
            Self::InsecureDatabasePath(detail) => {
                write!(formatter, "unsafe account database path: {detail}")
            }
            Self::InsecureDatabasePermissions(mode) => write!(
                formatter,
                "account database permissions are too broad: mode {:o}",
                mode & 0o777
            ),
            Self::InsecureSecretPath(detail) => {
                write!(formatter, "unsafe API-key hash secret path: {detail}")
            }
            Self::InsecureSecretPermissions(mode) => write!(
                formatter,
                "API-key hash secret permissions are too broad: mode {:o}",
                mode & 0o777
            ),
            Self::InvalidSecretLength { expected, actual } => write!(
                formatter,
                "API-key hash secret must contain exactly {expected} bytes, found {actual}"
            ),
            Self::CorruptData(detail) => write!(formatter, "corrupt account data: {detail}"),
            Self::CounterOverflow => formatter.write_str("account counter exceeds supported range"),
            Self::StatePoisoned => formatter.write_str("account state lock is unavailable"),
            Self::CredentialGenerationExhausted => {
                formatter.write_str("could not allocate a unique credential identifier")
            }
        }
    }
}

impl StdError for AccountManagementError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for AccountManagementError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Database(source)
    }
}

impl From<io::Error> for AccountManagementError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<getrandom::Error> for AccountManagementError {
    fn from(source: getrandom::Error) -> Self {
        Self::Entropy(source)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProxyAuthorizationError {
    MissingScheme,
    UnsupportedScheme,
    Oversized,
    InvalidBase64,
    InvalidUtf8,
    MissingPasswordSeparator,
    PasswordMustBeEmpty,
    InvalidApiKeyFormat,
}

impl fmt::Display for ProxyAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingScheme => "proxy authorization is missing its scheme or value",
            Self::UnsupportedScheme => "proxy authorization must use Basic",
            Self::Oversized => "proxy authorization exceeds the configured bound",
            Self::InvalidBase64 => "proxy authorization contains invalid base64",
            Self::InvalidUtf8 => "proxy authorization is not valid UTF-8",
            Self::MissingPasswordSeparator => {
                "proxy authorization must encode an API key followed by a colon"
            }
            Self::PasswordMustBeEmpty => "proxy authorization password must be empty",
            Self::InvalidApiKeyFormat => "proxy authorization contains an invalid API key",
        })
    }
}

impl StdError for ProxyAuthorizationError {}

#[derive(Debug)]
pub(crate) enum AuthenticationError {
    InvalidAuthorization(ProxyAuthorizationError),
    InvalidApiKey,
    ApiKeyRevoked,
    AccountInactive,
    WorkspaceInactive,
    UnknownDevice,
    DeviceRevoked,
    CredentialScopeMismatch,
    Storage(AccountManagementError),
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthorization(_) => "proxy authorization was rejected",
            Self::InvalidApiKey => "API key was rejected",
            Self::ApiKeyRevoked => "API key has been revoked",
            Self::AccountInactive => "account is inactive",
            Self::WorkspaceInactive => "workspace is inactive",
            Self::UnknownDevice => "client certificate is not registered",
            Self::DeviceRevoked => "client certificate has been revoked",
            Self::CredentialScopeMismatch => {
                "client certificate and API key belong to different scopes"
            }
            Self::Storage(_) => "authentication storage operation failed",
        })
    }
}

impl StdError for AuthenticationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidAuthorization(source) => Some(source),
            Self::Storage(source) => Some(source),
            _ => None,
        }
    }
}

impl From<AccountManagementError> for AuthenticationError {
    fn from(source: AccountManagementError) -> Self {
        Self::Storage(source)
    }
}

impl From<rusqlite::Error> for AuthenticationError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Storage(AccountManagementError::Database(source))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UsageQuotaError {
    RequestLimitReached,
    ByteLimitReached,
    CounterOverflow,
    ScopeMismatch,
}

#[derive(Debug)]
pub(crate) enum UsageAdmissionError {
    Quota(UsageQuotaError),
    Storage(AccountManagementError),
}

impl fmt::Display for UsageAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quota(UsageQuotaError::RequestLimitReached) => {
                formatter.write_str("account period request quota has been reached")
            }
            Self::Quota(UsageQuotaError::ByteLimitReached) => {
                formatter.write_str("account period byte quota has been reached")
            }
            Self::Quota(UsageQuotaError::CounterOverflow) => {
                formatter.write_str("account usage counter would overflow")
            }
            Self::Quota(UsageQuotaError::ScopeMismatch) => {
                formatter.write_str("account usage scope does not match the authenticated identity")
            }
            Self::Storage(_) => formatter.write_str("account usage storage operation failed"),
        }
    }
}

impl StdError for UsageAdmissionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Storage(source) => Some(source),
            Self::Quota(_) => None,
        }
    }
}

impl From<AccountManagementError> for UsageAdmissionError {
    fn from(source: AccountManagementError) -> Self {
        Self::Storage(source)
    }
}

impl From<UsageQuotaError> for UsageAdmissionError {
    fn from(source: UsageQuotaError) -> Self {
        Self::Quota(source)
    }
}

#[derive(Debug)]
pub(crate) enum AdmissionError {
    RateLimited { retry_after: Duration },
    TunnelLimitReached { limit: u32 },
    StateCapacityReached,
    StatePoisoned,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { retry_after } => {
                write!(
                    formatter,
                    "account request rate exceeded for {retry_after:?}"
                )
            }
            Self::TunnelLimitReached { limit } => {
                write!(formatter, "account concurrent tunnel limit {limit} reached")
            }
            Self::StateCapacityReached => {
                formatter.write_str("account admission state capacity reached")
            }
            Self::StatePoisoned => formatter.write_str("account admission state is unavailable"),
        }
    }
}

impl StdError for AdmissionError {}

#[derive(Clone)]
pub(crate) struct ApiKeyHasher {
    key: Arc<Zeroizing<[u8; blake3::KEY_LEN]>>,
}

impl ApiKeyHasher {
    pub(crate) fn from_key(key: Zeroizing<[u8; blake3::KEY_LEN]>) -> Self {
        Self { key: Arc::new(key) }
    }

    pub(crate) fn from_key_file(path: &Path) -> Result<Self, AccountManagementError> {
        if path.as_os_str().is_empty() {
            return Err(AccountManagementError::InsecureSecretPath(
                "path must be explicit",
            ));
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(AccountManagementError::InsecureSecretPath(
                "symbolic links are not accepted",
            ));
        }
        if !metadata.is_file() {
            return Err(AccountManagementError::InsecureSecretPath(
                "path is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(AccountManagementError::InsecureSecretPermissions(mode));
            }
        }

        let bytes = Zeroizing::new(fs::read(path)?);
        if bytes.len() != blake3::KEY_LEN {
            return Err(AccountManagementError::InvalidSecretLength {
                expected: blake3::KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut key = Zeroizing::new([0_u8; blake3::KEY_LEN]);
        key.copy_from_slice(bytes.as_slice());
        Ok(Self::from_key(key))
    }

    fn digest(&self, api_key: &str) -> [u8; blake3::OUT_LEN] {
        let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(self.key.as_ref()));
        hasher.update(b"proxy-account-api-key-v1\0");
        hasher.update(api_key.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

impl fmt::Debug for ApiKeyHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyHasher([redacted])")
    }
}

struct GeneratedApiKey {
    public_id: String,
    secret: ApiKeySecret,
    digest: [u8; blake3::OUT_LEN],
}

impl GeneratedApiKey {
    fn generate(hasher: &ApiKeyHasher) -> Result<Self, AccountManagementError> {
        let mut public_bytes = Zeroizing::new([0_u8; API_KEY_PUBLIC_ID_BYTES]);
        let mut secret_bytes = Zeroizing::new([0_u8; API_KEY_SECRET_BYTES]);
        getrandom::fill(public_bytes.as_mut())?;
        getrandom::fill(secret_bytes.as_mut())?;

        let public_id = URL_SAFE_NO_PAD.encode(public_bytes.as_ref());
        let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret_bytes.as_ref()));
        let secret = ApiKeySecret::new(format!(
            "{API_KEY_PREFIX}{public_id}.{}",
            encoded_secret.as_str()
        ));
        let digest = hasher.digest(secret.expose_secret());

        Ok(Self {
            public_id,
            secret,
            digest,
        })
    }
}

struct CredentialLookup {
    api_key_id: i64,
    public_id: String,
    account_id: i64,
    workspace_id: i64,
    key_hash_version: i64,
    key_hash: Vec<u8>,
    api_key_status: String,
    account_status: String,
    workspace_status: String,
    requests_per_second: i64,
    request_burst: i64,
    max_concurrent_tunnels: i64,
    period_request_limit: Option<i64>,
    period_byte_limit: Option<i64>,
}

struct DeviceLookup {
    id: i64,
    account_id: i64,
    workspace_id: i64,
    status: String,
}

struct RawAccountRecord {
    id: i64,
    email: String,
    stripe_customer_id: Option<String>,
    plan: String,
    status: String,
    requests_per_second: i64,
    request_burst: i64,
    max_concurrent_tunnels: i64,
    period_request_limit: Option<i64>,
    period_byte_limit: Option<i64>,
}

pub(crate) struct AccountDatabase {
    connection: Mutex<Connection>,
}

impl fmt::Debug for AccountDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountDatabase([private SQLite connection])")
    }
}

impl AccountDatabase {
    pub(crate) fn open(path: &Path) -> Result<Self, AccountManagementError> {
        prepare_database_file(path)?;
        let mut connection = Connection::open(path)?;
        configure_connection(&mut connection, true)?;
        migrate_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn open_in_memory() -> Result<Self, AccountManagementError> {
        let mut connection = Connection::open_in_memory()?;
        configure_connection(&mut connection, false)?;
        migrate_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AccountManagementError> {
        self.connection
            .lock()
            .map_err(|_| AccountManagementError::StatePoisoned)
    }
}

fn optional_nonzero_limit(
    value: Option<u64>,
    description: &'static str,
) -> Result<Option<NonZeroU64>, AccountManagementError> {
    match value {
        Some(value) => {
            checked_database_counter(value)?;
            NonZeroU64::new(value)
                .map(Some)
                .ok_or(AccountManagementError::InvalidInput(description))
        }
        None => Ok(None),
    }
}

fn checked_database_counter(value: u64) -> Result<i64, AccountManagementError> {
    i64::try_from(value).map_err(|_| AccountManagementError::CounterOverflow)
}

fn optional_limit_to_database(
    value: Option<NonZeroU64>,
) -> Result<Option<i64>, AccountManagementError> {
    value
        .map(|value| checked_database_counter(value.get()))
        .transpose()
}

fn positive_u32_from_database(
    value: i64,
    description: &'static str,
) -> Result<u32, AccountManagementError> {
    let value =
        u32::try_from(value).map_err(|_| AccountManagementError::CorruptData(description))?;
    if value == 0 {
        return Err(AccountManagementError::CorruptData(description));
    }
    Ok(value)
}

fn optional_u64_from_database(
    value: Option<i64>,
    description: &'static str,
) -> Result<Option<u64>, AccountManagementError> {
    value
        .map(|value| {
            if value <= 0 {
                return Err(AccountManagementError::CorruptData(description));
            }
            u64::try_from(value).map_err(|_| AccountManagementError::CorruptData(description))
        })
        .transpose()
}

fn normalize_email(value: &str) -> Result<String, AccountManagementError> {
    let value = value.trim();
    let mut components = value.split('@');
    let local_part = components.next();
    let domain_part = components.next();
    let valid_components = match (local_part, domain_part, components.next()) {
        (Some(local_part), Some(domain_part), None) => {
            !local_part.is_empty() && !domain_part.is_empty()
        }
        _ => false,
    };
    if !valid_components
        || value.len() > 320
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AccountManagementError::InvalidInput(
            "email address is invalid",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn account_record_from_raw(raw: RawAccountRecord) -> Result<AccountRecord, AccountManagementError> {
    Ok(AccountRecord {
        id: AccountId::from_database(raw.id)?,
        email: raw.email,
        stripe_customer_id: raw.stripe_customer_id,
        plan: PlanCode::new(&raw.plan)
            .map_err(|_| AccountManagementError::CorruptData("invalid stored plan code"))?,
        status: AccountStatus::from_database(&raw.status)?,
        limits: AccountLimits::from_database(
            raw.requests_per_second,
            raw.request_burst,
            raw.max_concurrent_tunnels,
            raw.period_request_limit,
            raw.period_byte_limit,
        )?,
    })
}

fn normalize_workspace_name(value: &str) -> Result<String, AccountManagementError> {
    normalize_label_like(value, 128, "workspace name is invalid")
}

fn normalize_credential_label(value: &str) -> Result<String, AccountManagementError> {
    normalize_label_like(value, 64, "credential label is invalid")
}

fn normalize_label_like(
    value: &str,
    maximum_bytes: usize,
    error: &'static str,
) -> Result<String, AccountManagementError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
        || value.contains(['\r', '\n'])
    {
        return Err(AccountManagementError::InvalidInput(error));
    }
    Ok(value.to_owned())
}

fn normalize_stripe_customer_id(
    value: Option<&str>,
) -> Result<Option<String>, AccountManagementError> {
    value
        .map(|value| {
            let value = value.trim();
            if value.is_empty()
                || value.len() > 255
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(AccountManagementError::InvalidInput(
                    "Stripe customer identifier is invalid",
                ));
            }
            Ok(value.to_owned())
        })
        .transpose()
}

fn prepare_database_file(path: &Path) -> Result<(), AccountManagementError> {
    if path.as_os_str().is_empty() {
        return Err(AccountManagementError::InsecureDatabasePath(
            "path must be explicit",
        ));
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(AccountManagementError::InsecureDatabasePath(
                    "symbolic links are not accepted",
                ));
            }
            if !metadata.is_file() {
                return Err(AccountManagementError::InsecureDatabasePath(
                    "path is not a regular file",
                ));
            }
            #[cfg(unix)]
            {
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(AccountManagementError::InsecureDatabasePermissions(mode));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let _file = options.open(path)?;
        }
        Err(error) => return Err(AccountManagementError::Io(error)),
    }

    Ok(())
}

fn configure_connection(
    connection: &mut Connection,
    file_backed: bool,
) -> Result<(), AccountManagementError> {
    connection.busy_timeout(DATABASE_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    connection.pragma_update(None, "synchronous", "FULL")?;

    if file_backed {
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(AccountManagementError::CorruptData(
                "SQLite WAL mode could not be enabled",
            ));
        }
    }
    Ok(())
}

fn migrate_schema(connection: &mut Connection) -> Result<(), AccountManagementError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        SCHEMA_VERSION => Ok(()),
        0 => {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(SCHEMA_SQL)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
            Ok(())
        }
        other => Err(AccountManagementError::UnsupportedSchemaVersion(other)),
    }
}

impl AccountDatabase {
    pub(crate) fn create_account(
        &self,
        email: &str,
        stripe_customer_id: Option<&str>,
        plan: &PlanCode,
        limits: AccountLimits,
        now: UnixTimestamp,
    ) -> Result<AccountRecord, AccountManagementError> {
        let email = normalize_email(email)?;
        let stripe_customer_id = normalize_stripe_customer_id(stripe_customer_id)?;
        let values = limits.database_values()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        match transaction.execute(
            "INSERT INTO accounts (
                email, stripe_customer_id, plan, status, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'active', ?4, ?4)",
            params![email, stripe_customer_id, plan.as_str(), now.as_i64()],
        ) {
            Ok(_) => {}
            Err(error) if is_constraint_violation(&error) => {
                return Err(AccountManagementError::Conflict(
                    "email or Stripe customer identifier already exists",
                ));
            }
            Err(error) => return Err(AccountManagementError::Database(error)),
        }

        let account_id = AccountId::from_database(transaction.last_insert_rowid())?;
        transaction.execute(
            "INSERT INTO account_limits (
                account_id, requests_per_second, request_burst,
                max_concurrent_tunnels, period_request_limit,
                period_byte_limit, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                account_id.as_i64(),
                values.requests_per_second,
                values.request_burst,
                values.max_concurrent_tunnels,
                values.period_request_limit,
                values.period_byte_limit,
                now.as_i64(),
            ],
        )?;
        transaction.commit()?;

        Ok(AccountRecord {
            id: account_id,
            email,
            stripe_customer_id,
            plan: plan.clone(),
            status: AccountStatus::Active,
            limits,
        })
    }

    pub(crate) fn account(
        &self,
        account_id: AccountId,
    ) -> Result<AccountRecord, AccountManagementError> {
        let connection = self.connection()?;
        let raw = connection
            .query_row(
                "SELECT
                    a.id, a.email, a.stripe_customer_id, a.plan, a.status,
                    l.requests_per_second, l.request_burst,
                    l.max_concurrent_tunnels, l.period_request_limit,
                    l.period_byte_limit
                 FROM accounts a
                 JOIN account_limits l ON l.account_id = a.id
                 WHERE a.id = ?1",
                params![account_id.as_i64()],
                |row| {
                    Ok(RawAccountRecord {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        stripe_customer_id: row.get(2)?,
                        plan: row.get(3)?,
                        status: row.get(4)?,
                        requests_per_second: row.get(5)?,
                        request_burst: row.get(6)?,
                        max_concurrent_tunnels: row.get(7)?,
                        period_request_limit: row.get(8)?,
                        period_byte_limit: row.get(9)?,
                    })
                },
            )
            .optional()?;
        let raw = raw.ok_or(AccountManagementError::NotFound(EntityKind::Account))?;
        account_record_from_raw(raw)
    }

    pub(crate) fn account_by_email(
        &self,
        email: &str,
    ) -> Result<AccountRecord, AccountManagementError> {
        let email = normalize_email(email)?;
        let connection = self.connection()?;
        let account_id = connection
            .query_row(
                "SELECT id FROM accounts WHERE email = ?1",
                params![email],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        drop(connection);
        let account_id = account_id
            .ok_or(AccountManagementError::NotFound(EntityKind::Account))
            .and_then(AccountId::from_database)?;
        self.account(account_id)
    }

    pub(crate) fn account_by_stripe_customer_id(
        &self,
        stripe_customer_id: &str,
    ) -> Result<AccountRecord, AccountManagementError> {
        let stripe_customer_id = normalize_stripe_customer_id(Some(stripe_customer_id))?.ok_or(
            AccountManagementError::InvalidInput("Stripe customer identifier is required"),
        )?;
        let connection = self.connection()?;
        let account_id = connection
            .query_row(
                "SELECT id FROM accounts WHERE stripe_customer_id = ?1",
                params![stripe_customer_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        drop(connection);
        let account_id = account_id
            .ok_or(AccountManagementError::NotFound(EntityKind::Account))
            .and_then(AccountId::from_database)?;
        self.account(account_id)
    }

    pub(crate) fn list_accounts(&self) -> Result<Vec<AccountRecord>, AccountManagementError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT
                a.id, a.email, a.stripe_customer_id, a.plan, a.status,
                l.requests_per_second, l.request_burst,
                l.max_concurrent_tunnels, l.period_request_limit,
                l.period_byte_limit
             FROM accounts a
             JOIN account_limits l ON l.account_id = a.id
             ORDER BY a.id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RawAccountRecord {
                id: row.get(0)?,
                email: row.get(1)?,
                stripe_customer_id: row.get(2)?,
                plan: row.get(3)?,
                status: row.get(4)?,
                requests_per_second: row.get(5)?,
                request_burst: row.get(6)?,
                max_concurrent_tunnels: row.get(7)?,
                period_request_limit: row.get(8)?,
                period_byte_limit: row.get(9)?,
            })
        })?;
        let mut accounts = Vec::new();
        for row in rows {
            accounts.push(account_record_from_raw(row?)?);
        }
        Ok(accounts)
    }

    pub(crate) fn set_account_status(
        &self,
        account_id: AccountId,
        status: AccountStatus,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE accounts
             SET status = ?1, updated_at = ?2
             WHERE id = ?3 AND status <> ?1",
            params![
                status.as_database_value(),
                now.as_i64(),
                account_id.as_i64()
            ],
        )?;
        if changed > 0 {
            return Ok(true);
        }
        if record_exists(&connection, "accounts", account_id.as_i64())? {
            Ok(false)
        } else {
            Err(AccountManagementError::NotFound(EntityKind::Account))
        }
    }

    pub(crate) fn update_account_plan_and_limits(
        &self,
        account_id: AccountId,
        plan: &PlanCode,
        limits: AccountLimits,
        now: UnixTimestamp,
    ) -> Result<(), AccountManagementError> {
        let values = limits.database_values()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE accounts SET plan = ?1, updated_at = ?2 WHERE id = ?3",
            params![plan.as_str(), now.as_i64(), account_id.as_i64()],
        )?;
        if changed == 0 {
            return Err(AccountManagementError::NotFound(EntityKind::Account));
        }
        let limits_changed = transaction.execute(
            "UPDATE account_limits SET
                requests_per_second = ?1,
                request_burst = ?2,
                max_concurrent_tunnels = ?3,
                period_request_limit = ?4,
                period_byte_limit = ?5,
                updated_at = ?6
             WHERE account_id = ?7",
            params![
                values.requests_per_second,
                values.request_burst,
                values.max_concurrent_tunnels,
                values.period_request_limit,
                values.period_byte_limit,
                now.as_i64(),
                account_id.as_i64(),
            ],
        )?;
        if limits_changed != 1 {
            return Err(AccountManagementError::CorruptData(
                "account is missing its limits record",
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn set_stripe_customer_id(
        &self,
        account_id: AccountId,
        stripe_customer_id: Option<&str>,
        now: UnixTimestamp,
    ) -> Result<(), AccountManagementError> {
        let stripe_customer_id = normalize_stripe_customer_id(stripe_customer_id)?;
        let connection = self.connection()?;
        let result = connection.execute(
            "UPDATE accounts
             SET stripe_customer_id = ?1, updated_at = ?2
             WHERE id = ?3",
            params![stripe_customer_id, now.as_i64(), account_id.as_i64()],
        );
        match result {
            Ok(0) => Err(AccountManagementError::NotFound(EntityKind::Account)),
            Ok(_) => Ok(()),
            Err(error) if is_constraint_violation(&error) => Err(AccountManagementError::Conflict(
                "Stripe customer identifier already exists",
            )),
            Err(error) => Err(AccountManagementError::Database(error)),
        }
    }

    pub(crate) fn create_workspace(
        &self,
        account_id: AccountId,
        name: &str,
        now: UnixTimestamp,
    ) -> Result<WorkspaceRecord, AccountManagementError> {
        let name = normalize_workspace_name(name)?;
        let connection = self.connection()?;
        if !record_exists(&connection, "accounts", account_id.as_i64())? {
            return Err(AccountManagementError::NotFound(EntityKind::Account));
        }
        let result = connection.execute(
            "INSERT INTO workspaces (
                account_id, name, status, created_at, updated_at
             ) VALUES (?1, ?2, 'active', ?3, ?3)",
            params![account_id.as_i64(), name, now.as_i64()],
        );
        match result {
            Ok(_) => Ok(WorkspaceRecord {
                id: WorkspaceId::from_database(connection.last_insert_rowid())?,
                account_id,
                name,
                status: WorkspaceStatus::Active,
            }),
            Err(error) if is_constraint_violation(&error) => Err(AccountManagementError::Conflict(
                "workspace name already exists for account",
            )),
            Err(error) => Err(AccountManagementError::Database(error)),
        }
    }

    pub(crate) fn workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspaceRecord, AccountManagementError> {
        let connection = self.connection()?;
        let raw = connection
            .query_row(
                "SELECT account_id, name, status FROM workspaces WHERE id = ?1",
                params![workspace_id.as_i64()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (account_id, name, status) =
            raw.ok_or(AccountManagementError::NotFound(EntityKind::Workspace))?;
        Ok(WorkspaceRecord {
            id: workspace_id,
            account_id: AccountId::from_database(account_id)?,
            name,
            status: WorkspaceStatus::from_database(&status)?,
        })
    }

    pub(crate) fn list_workspaces(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<WorkspaceRecord>, AccountManagementError> {
        let connection = self.connection()?;
        if !record_exists(&connection, "accounts", account_id.as_i64())? {
            return Err(AccountManagementError::NotFound(EntityKind::Account));
        }
        let mut statement = connection.prepare(
            "SELECT id, name, status
             FROM workspaces
             WHERE account_id = ?1
             ORDER BY id ASC",
        )?;
        let rows = statement.query_map(params![account_id.as_i64()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut workspaces = Vec::new();
        for row in rows {
            let (id, name, status) = row?;
            workspaces.push(WorkspaceRecord {
                id: WorkspaceId::from_database(id)?,
                account_id,
                name,
                status: WorkspaceStatus::from_database(&status)?,
            });
        }
        Ok(workspaces)
    }

    pub(crate) fn set_workspace_status(
        &self,
        workspace_id: WorkspaceId,
        status: WorkspaceStatus,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE workspaces
             SET status = ?1, updated_at = ?2
             WHERE id = ?3 AND status <> ?1",
            params![
                status.as_database_value(),
                now.as_i64(),
                workspace_id.as_i64()
            ],
        )?;
        if changed > 0 {
            return Ok(true);
        }
        if record_exists(&connection, "workspaces", workspace_id.as_i64())? {
            Ok(false)
        } else {
            Err(AccountManagementError::NotFound(EntityKind::Workspace))
        }
    }

    fn insert_api_key(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        label: &str,
        generated: &GeneratedApiKey,
        now: UnixTimestamp,
    ) -> Result<ApiKeyId, AccountManagementError> {
        let label = normalize_credential_label(label)?;
        let connection = self.connection()?;
        require_workspace_scope(&connection, account_id, workspace_id)?;
        connection.execute(
            "INSERT INTO api_keys (
                public_id, account_id, workspace_id, label,
                key_hash_version, key_hash, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7)",
            params![
                generated.public_id,
                account_id.as_i64(),
                workspace_id.as_i64(),
                label,
                API_KEY_HASH_VERSION,
                generated.digest.as_slice(),
                now.as_i64(),
            ],
        )?;
        ApiKeyId::from_database(connection.last_insert_rowid())
    }

    fn rotate_api_key(
        &self,
        old_api_key_id: ApiKeyId,
        generated: &GeneratedApiKey,
        now: UnixTimestamp,
    ) -> Result<ApiKeyId, AccountManagementError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = transaction
            .query_row(
                "SELECT account_id, workspace_id, label, status
                 FROM api_keys WHERE id = ?1",
                params![old_api_key_id.as_i64()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let (account_id, workspace_id, label, status) =
            old.ok_or(AccountManagementError::NotFound(EntityKind::ApiKey))?;
        if CredentialStatus::from_database(&status)? != CredentialStatus::Active {
            return Err(AccountManagementError::Conflict(
                "only an active API key can be rotated",
            ));
        }

        transaction.execute(
            "INSERT INTO api_keys (
                public_id, account_id, workspace_id, label,
                key_hash_version, key_hash, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7)",
            params![
                generated.public_id,
                account_id,
                workspace_id,
                label,
                API_KEY_HASH_VERSION,
                generated.digest.as_slice(),
                now.as_i64(),
            ],
        )?;
        let new_api_key_id = ApiKeyId::from_database(transaction.last_insert_rowid())?;
        let changed = transaction.execute(
            "UPDATE api_keys
             SET status = 'revoked', revoked_at = ?1
             WHERE id = ?2 AND status = 'active'",
            params![now.as_i64(), old_api_key_id.as_i64()],
        )?;
        if changed != 1 {
            return Err(AccountManagementError::Conflict(
                "API key changed while it was being rotated",
            ));
        }
        transaction.commit()?;
        Ok(new_api_key_id)
    }

    pub(crate) fn revoke_api_key(
        &self,
        api_key_id: ApiKeyId,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE api_keys
             SET status = 'revoked', revoked_at = ?1
             WHERE id = ?2 AND status = 'active'",
            params![now.as_i64(), api_key_id.as_i64()],
        )?;
        if changed > 0 {
            return Ok(true);
        }
        if record_exists(&connection, "api_keys", api_key_id.as_i64())? {
            Ok(false)
        } else {
            Err(AccountManagementError::NotFound(EntityKind::ApiKey))
        }
    }

    pub(crate) fn list_api_keys(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ApiKeyMetadata>, AccountManagementError> {
        let connection = self.connection()?;
        require_workspace_scope(&connection, account_id, workspace_id)?;
        let mut statement = connection.prepare(
            "SELECT id, public_id, label, status, created_at, revoked_at
             FROM api_keys
             WHERE account_id = ?1 AND workspace_id = ?2
             ORDER BY id ASC",
        )?;
        let rows =
            statement.query_map(params![account_id.as_i64(), workspace_id.as_i64()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })?;
        let mut metadata = Vec::new();
        for row in rows {
            let (id, public_id, label, status, created_at, revoked_at) = row?;
            metadata.push(ApiKeyMetadata {
                id: ApiKeyId::from_database(id)?,
                public_id,
                label,
                status: CredentialStatus::from_database(&status)?,
                created_at: UnixTimestamp::new(created_at)
                    .map_err(|_| AccountManagementError::CorruptData("invalid key timestamp"))?,
                revoked_at: revoked_at
                    .map(UnixTimestamp::new)
                    .transpose()
                    .map_err(|_| {
                        AccountManagementError::CorruptData("invalid key revocation timestamp")
                    })?,
            });
        }
        Ok(metadata)
    }

    pub(crate) fn register_device_credential(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        fingerprint: &CertificateFingerprint,
        label: &str,
        now: UnixTimestamp,
    ) -> Result<DeviceCredentialMetadata, AccountManagementError> {
        let label = normalize_credential_label(label)?;
        let connection = self.connection()?;
        require_workspace_scope(&connection, account_id, workspace_id)?;
        let result = connection.execute(
            "INSERT INTO device_credentials (
                account_id, workspace_id, label, certificate_fingerprint,
                status, created_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', ?5)",
            params![
                account_id.as_i64(),
                workspace_id.as_i64(),
                label,
                fingerprint.as_bytes().as_slice(),
                now.as_i64(),
            ],
        );
        match result {
            Ok(_) => Ok(DeviceCredentialMetadata {
                id: DeviceCredentialId::from_database(connection.last_insert_rowid())?,
                label,
                status: CredentialStatus::Active,
                created_at: now,
                revoked_at: None,
            }),
            Err(error) if is_constraint_violation(&error) => Err(AccountManagementError::Conflict(
                "certificate fingerprint is already registered",
            )),
            Err(error) => Err(AccountManagementError::Database(error)),
        }
    }

    pub(crate) fn revoke_device_credential(
        &self,
        device_credential_id: DeviceCredentialId,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE device_credentials
             SET status = 'revoked', revoked_at = ?1
             WHERE id = ?2 AND status = 'active'",
            params![now.as_i64(), device_credential_id.as_i64()],
        )?;
        if changed > 0 {
            return Ok(true);
        }
        if record_exists(
            &connection,
            "device_credentials",
            device_credential_id.as_i64(),
        )? {
            Ok(false)
        } else {
            Err(AccountManagementError::NotFound(
                EntityKind::DeviceCredential,
            ))
        }
    }

    pub(crate) fn list_device_credentials(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<DeviceCredentialMetadata>, AccountManagementError> {
        let connection = self.connection()?;
        require_workspace_scope(&connection, account_id, workspace_id)?;
        let mut statement = connection.prepare(
            "SELECT id, label, status, created_at, revoked_at
             FROM device_credentials
             WHERE account_id = ?1 AND workspace_id = ?2
             ORDER BY id ASC",
        )?;
        let rows =
            statement.query_map(params![account_id.as_i64(), workspace_id.as_i64()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })?;
        let mut metadata = Vec::new();
        for row in rows {
            let (id, label, status, created_at, revoked_at) = row?;
            metadata.push(DeviceCredentialMetadata {
                id: DeviceCredentialId::from_database(id)?,
                label,
                status: CredentialStatus::from_database(&status)?,
                created_at: UnixTimestamp::new(created_at)
                    .map_err(|_| AccountManagementError::CorruptData("invalid device timestamp"))?,
                revoked_at: revoked_at
                    .map(UnixTimestamp::new)
                    .transpose()
                    .map_err(|_| {
                        AccountManagementError::CorruptData("invalid device revocation timestamp")
                    })?,
            });
        }
        Ok(metadata)
    }

    fn authenticate(
        &self,
        public_id: &str,
        digest: &[u8; blake3::OUT_LEN],
        fingerprint: &CertificateFingerprint,
    ) -> Result<IngressIdentity, AuthenticationError> {
        let connection = self.connection()?;
        let credential = connection
            .query_row(
                "SELECT
                    k.id, k.public_id, k.account_id, k.workspace_id,
                    k.key_hash_version, k.key_hash, k.status,
                    a.status, w.status,
                    l.requests_per_second, l.request_burst,
                    l.max_concurrent_tunnels, l.period_request_limit,
                    l.period_byte_limit
                 FROM api_keys k
                 JOIN accounts a ON a.id = k.account_id
                 JOIN workspaces w
                    ON w.id = k.workspace_id AND w.account_id = k.account_id
                 JOIN account_limits l ON l.account_id = k.account_id
                 WHERE k.public_id = ?1",
                params![public_id],
                |row| {
                    Ok(CredentialLookup {
                        api_key_id: row.get(0)?,
                        public_id: row.get(1)?,
                        account_id: row.get(2)?,
                        workspace_id: row.get(3)?,
                        key_hash_version: row.get(4)?,
                        key_hash: row.get(5)?,
                        api_key_status: row.get(6)?,
                        account_status: row.get(7)?,
                        workspace_status: row.get(8)?,
                        requests_per_second: row.get(9)?,
                        request_burst: row.get(10)?,
                        max_concurrent_tunnels: row.get(11)?,
                        period_request_limit: row.get(12)?,
                        period_byte_limit: row.get(13)?,
                    })
                },
            )
            .optional()?
            .ok_or(AuthenticationError::InvalidApiKey)?;

        if credential.public_id != public_id
            || credential.key_hash_version != API_KEY_HASH_VERSION
            || credential.key_hash.len() != blake3::OUT_LEN
        {
            return Err(AuthenticationError::Storage(
                AccountManagementError::CorruptData("invalid stored API key material"),
            ));
        }
        let digest_matches: bool = credential
            .key_hash
            .as_slice()
            .ct_eq(digest.as_slice())
            .into();
        if !digest_matches {
            return Err(AuthenticationError::InvalidApiKey);
        }
        if CredentialStatus::from_database(&credential.api_key_status)? != CredentialStatus::Active
        {
            return Err(AuthenticationError::ApiKeyRevoked);
        }
        if AccountStatus::from_database(&credential.account_status)? != AccountStatus::Active {
            return Err(AuthenticationError::AccountInactive);
        }
        if WorkspaceStatus::from_database(&credential.workspace_status)? != WorkspaceStatus::Active
        {
            return Err(AuthenticationError::WorkspaceInactive);
        }

        let device = connection
            .query_row(
                "SELECT id, account_id, workspace_id, status
                 FROM device_credentials
                 WHERE certificate_fingerprint = ?1",
                params![fingerprint.as_bytes().as_slice()],
                |row| {
                    Ok(DeviceLookup {
                        id: row.get(0)?,
                        account_id: row.get(1)?,
                        workspace_id: row.get(2)?,
                        status: row.get(3)?,
                    })
                },
            )
            .optional()?
            .ok_or(AuthenticationError::UnknownDevice)?;

        if CredentialStatus::from_database(&device.status)? != CredentialStatus::Active {
            return Err(AuthenticationError::DeviceRevoked);
        }
        if device.account_id != credential.account_id
            || device.workspace_id != credential.workspace_id
        {
            return Err(AuthenticationError::CredentialScopeMismatch);
        }

        Ok(IngressIdentity {
            account_id: AccountId::from_database(credential.account_id)?,
            workspace_id: WorkspaceId::from_database(credential.workspace_id)?,
            api_key_id: ApiKeyId::from_database(credential.api_key_id)?,
            device_credential_id: DeviceCredentialId::from_database(device.id)?,
            limits: AccountLimits::from_database(
                credential.requests_per_second,
                credential.request_burst,
                credential.max_concurrent_tunnels,
                credential.period_request_limit,
                credential.period_byte_limit,
            )?,
        })
    }

    pub(crate) fn usage(
        &self,
        identity: IngressIdentity,
        period_start: UnixTimestamp,
    ) -> Result<UsageSnapshot, AccountManagementError> {
        self.usage_for_scope(identity.account_id, identity.workspace_id, period_start)
    }

    pub(crate) fn usage_for_scope(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        period_start: UnixTimestamp,
    ) -> Result<UsageSnapshot, AccountManagementError> {
        let connection = self.connection()?;
        require_workspace_scope(&connection, account_id, workspace_id)?;
        let stored_values = connection
            .query_row(
                "SELECT requests_used, bytes_to_tor, bytes_from_tor
                 FROM usage_periods
                 WHERE account_id = ?1 AND workspace_id = ?2 AND period_start = ?3",
                params![
                    account_id.as_i64(),
                    workspace_id.as_i64(),
                    period_start.as_i64(),
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let values = stored_values.map_or((0, 0, 0), std::convert::identity);

        Ok(UsageSnapshot {
            account_id,
            workspace_id,
            period_start,
            requests_used: nonnegative_u64_from_database(values.0, "requests used")?,
            bytes_to_tor: nonnegative_u64_from_database(values.1, "bytes to Tor")?,
            bytes_from_tor: nonnegative_u64_from_database(values.2, "bytes from Tor")?,
        })
    }

    pub(crate) fn list_usage_for_period(
        &self,
        period_start: UnixTimestamp,
    ) -> Result<Vec<UsageSnapshot>, AccountManagementError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT
                account_id, workspace_id, requests_used,
                bytes_to_tor, bytes_from_tor
             FROM usage_periods
             WHERE period_start = ?1
             ORDER BY account_id ASC, workspace_id ASC",
        )?;
        let rows = statement.query_map(params![period_start.as_i64()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut usage = Vec::new();
        for row in rows {
            let (account_id, workspace_id, requests_used, bytes_to_tor, bytes_from_tor) = row?;
            usage.push(UsageSnapshot {
                account_id: AccountId::from_database(account_id)?,
                workspace_id: WorkspaceId::from_database(workspace_id)?,
                period_start,
                requests_used: nonnegative_u64_from_database(requests_used, "requests used")?,
                bytes_to_tor: nonnegative_u64_from_database(bytes_to_tor, "bytes to Tor")?,
                bytes_from_tor: nonnegative_u64_from_database(bytes_from_tor, "bytes from Tor")?,
            });
        }
        Ok(usage)
    }

    pub(crate) fn record_usage(
        &self,
        identity: IngressIdentity,
        period_start: UnixTimestamp,
        delta: UsageDelta,
    ) -> Result<UsageSnapshot, AccountManagementError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_workspace_scope(&transaction, identity.account_id, identity.workspace_id)?;
        let current = usage_values(&transaction, identity, period_start)?;
        let requests_used = checked_usage_add(current.0, delta.requests)?;
        let bytes_to_tor = checked_usage_add(current.1, delta.bytes_to_tor)?;
        let bytes_from_tor = checked_usage_add(current.2, delta.bytes_from_tor)?;

        transaction.execute(
            "INSERT INTO usage_periods (
                account_id, workspace_id, period_start,
                requests_used, bytes_to_tor, bytes_from_tor
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(account_id, workspace_id, period_start)
             DO UPDATE SET
                requests_used = excluded.requests_used,
                bytes_to_tor = excluded.bytes_to_tor,
                bytes_from_tor = excluded.bytes_from_tor",
            params![
                identity.account_id.as_i64(),
                identity.workspace_id.as_i64(),
                period_start.as_i64(),
                checked_database_counter(requests_used)?,
                checked_database_counter(bytes_to_tor)?,
                checked_database_counter(bytes_from_tor)?,
            ],
        )?;
        transaction.commit()?;

        Ok(UsageSnapshot {
            account_id: identity.account_id,
            workspace_id: identity.workspace_id,
            period_start,
            requests_used,
            bytes_to_tor,
            bytes_from_tor,
        })
    }

    pub(crate) fn record_usage_if_allowed(
        &self,
        identity: IngressIdentity,
        period_start: UnixTimestamp,
        delta: UsageDelta,
    ) -> Result<UsageSnapshot, UsageAdmissionError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AccountManagementError::from)?;
        require_workspace_scope(&transaction, identity.account_id, identity.workspace_id)?;
        let current = usage_values(&transaction, identity, period_start)?;
        let current_snapshot = UsageSnapshot {
            account_id: identity.account_id,
            workspace_id: identity.workspace_id,
            period_start,
            requests_used: current.0,
            bytes_to_tor: current.1,
            bytes_from_tor: current.2,
        };
        check_usage_allowance(identity, current_snapshot, delta)?;

        let requests_used = checked_usage_add(current.0, delta.requests)?;
        let bytes_to_tor = checked_usage_add(current.1, delta.bytes_to_tor)?;
        let bytes_from_tor = checked_usage_add(current.2, delta.bytes_from_tor)?;
        transaction
            .execute(
                "INSERT INTO usage_periods (
                    account_id, workspace_id, period_start,
                    requests_used, bytes_to_tor, bytes_from_tor
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(account_id, workspace_id, period_start)
                 DO UPDATE SET
                    requests_used = excluded.requests_used,
                    bytes_to_tor = excluded.bytes_to_tor,
                    bytes_from_tor = excluded.bytes_from_tor",
                params![
                    identity.account_id.as_i64(),
                    identity.workspace_id.as_i64(),
                    period_start.as_i64(),
                    checked_database_counter(requests_used)?,
                    checked_database_counter(bytes_to_tor)?,
                    checked_database_counter(bytes_from_tor)?,
                ],
            )
            .map_err(AccountManagementError::from)?;
        transaction.commit().map_err(AccountManagementError::from)?;

        Ok(UsageSnapshot {
            account_id: identity.account_id,
            workspace_id: identity.workspace_id,
            period_start,
            requests_used,
            bytes_to_tor,
            bytes_from_tor,
        })
    }
}

fn record_exists(
    connection: &Connection,
    table: &'static str,
    id: i64,
) -> Result<bool, AccountManagementError> {
    let sql = match table {
        "accounts" => "SELECT 1 FROM accounts WHERE id = ?1",
        "workspaces" => "SELECT 1 FROM workspaces WHERE id = ?1",
        "api_keys" => "SELECT 1 FROM api_keys WHERE id = ?1",
        "device_credentials" => "SELECT 1 FROM device_credentials WHERE id = ?1",
        _ => {
            return Err(AccountManagementError::InvalidInput(
                "unsupported account table",
            ));
        }
    };
    let exists = connection
        .query_row(sql, params![id], |row| row.get::<_, i64>(0))
        .optional()?;
    Ok(exists.is_some())
}

fn require_workspace_scope(
    connection: &Connection,
    account_id: AccountId,
    workspace_id: WorkspaceId,
) -> Result<(), AccountManagementError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM workspaces WHERE id = ?1 AND account_id = ?2",
            params![workspace_id.as_i64(), account_id.as_i64()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(AccountManagementError::NotFound(EntityKind::Workspace))
    }
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(database_error, _)
            if database_error.code == ErrorCode::ConstraintViolation
    )
}

fn nonnegative_u64_from_database(
    value: i64,
    description: &'static str,
) -> Result<u64, AccountManagementError> {
    u64::try_from(value).map_err(|_| AccountManagementError::CorruptData(description))
}

fn usage_values(
    transaction: &Transaction<'_>,
    identity: IngressIdentity,
    period_start: UnixTimestamp,
) -> Result<(u64, u64, u64), AccountManagementError> {
    let stored_values = transaction
        .query_row(
            "SELECT requests_used, bytes_to_tor, bytes_from_tor
             FROM usage_periods
             WHERE account_id = ?1 AND workspace_id = ?2 AND period_start = ?3",
            params![
                identity.account_id.as_i64(),
                identity.workspace_id.as_i64(),
                period_start.as_i64(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let values = stored_values.map_or((0, 0, 0), std::convert::identity);
    Ok((
        nonnegative_u64_from_database(values.0, "requests used")?,
        nonnegative_u64_from_database(values.1, "bytes to Tor")?,
        nonnegative_u64_from_database(values.2, "bytes from Tor")?,
    ))
}

fn checked_usage_add(current: u64, delta: u64) -> Result<u64, AccountManagementError> {
    let result = current
        .checked_add(delta)
        .ok_or(AccountManagementError::CounterOverflow)?;
    checked_database_counter(result)?;
    Ok(result)
}

pub(crate) fn extract_proxy_auth_api_key(
    header_value: &str,
) -> Result<ApiKeySecret, ProxyAuthorizationError> {
    if header_value.len() > MAX_PROXY_AUTHORIZATION_BYTES {
        return Err(ProxyAuthorizationError::Oversized);
    }

    let mut parts = header_value.split_ascii_whitespace();
    let scheme = parts.next().ok_or(ProxyAuthorizationError::MissingScheme)?;
    let encoded = parts.next().ok_or(ProxyAuthorizationError::MissingScheme)?;
    if parts.next().is_some() {
        return Err(ProxyAuthorizationError::MissingScheme);
    }
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(ProxyAuthorizationError::UnsupportedScheme);
    }

    let decoded = STANDARD
        .decode(encoded)
        .map(Zeroizing::new)
        .map_err(|_| ProxyAuthorizationError::InvalidBase64)?;
    let decoded =
        str::from_utf8(decoded.as_ref()).map_err(|_| ProxyAuthorizationError::InvalidUtf8)?;
    let (api_key, password) = decoded
        .split_once(':')
        .ok_or(ProxyAuthorizationError::MissingPasswordSeparator)?;
    if !password.is_empty() {
        return Err(ProxyAuthorizationError::PasswordMustBeEmpty);
    }
    parse_api_key_public_id(api_key)?;
    Ok(ApiKeySecret::new(api_key.to_owned()))
}

fn parse_api_key_public_id(api_key: &str) -> Result<&str, ProxyAuthorizationError> {
    let body = api_key
        .strip_prefix(API_KEY_PREFIX)
        .ok_or(ProxyAuthorizationError::InvalidApiKeyFormat)?;
    let (public_id, secret) = body
        .split_once('.')
        .ok_or(ProxyAuthorizationError::InvalidApiKeyFormat)?;
    if public_id.len() != API_KEY_PUBLIC_ID_ENCODED_BYTES
        || secret.len() != API_KEY_SECRET_ENCODED_BYTES
        || secret.contains('.')
        || !public_id.bytes().all(is_base64_url_byte)
        || !secret.bytes().all(is_base64_url_byte)
    {
        return Err(ProxyAuthorizationError::InvalidApiKeyFormat);
    }
    Ok(public_id)
}

fn is_base64_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

pub(crate) fn check_usage_allowance(
    identity: IngressIdentity,
    snapshot: UsageSnapshot,
    proposed: UsageDelta,
) -> Result<(), UsageQuotaError> {
    if snapshot.account_id != identity.account_id || snapshot.workspace_id != identity.workspace_id
    {
        return Err(UsageQuotaError::ScopeMismatch);
    }

    let projected_requests = snapshot
        .requests_used
        .checked_add(proposed.requests)
        .ok_or(UsageQuotaError::CounterOverflow)?;
    if let Some(limit) = identity.limits.period_request_limit
        && (projected_requests > limit.get()
            || (proposed.requests > 0 && snapshot.requests_used >= limit.get()))
    {
        return Err(UsageQuotaError::RequestLimitReached);
    }

    let current_bytes = snapshot
        .bytes_to_tor
        .checked_add(snapshot.bytes_from_tor)
        .ok_or(UsageQuotaError::CounterOverflow)?;
    let proposed_bytes = proposed
        .bytes_to_tor
        .checked_add(proposed.bytes_from_tor)
        .ok_or(UsageQuotaError::CounterOverflow)?;
    let projected_bytes = current_bytes
        .checked_add(proposed_bytes)
        .ok_or(UsageQuotaError::CounterOverflow)?;
    if let Some(limit) = identity.limits.period_byte_limit
        && (projected_bytes > limit.get()
            || (proposed.requests > 0 && current_bytes >= limit.get()))
    {
        return Err(UsageQuotaError::ByteLimitReached);
    }

    Ok(())
}

#[derive(Debug)]
struct AccountAdmissionState {
    limits: Mutex<AccountLimits>,
    request_limiter: Mutex<Arc<DefaultDirectRateLimiter>>,
    active_tunnels: AtomicU32,
    last_used: AtomicU64,
}

impl AccountAdmissionState {
    fn new(limits: AccountLimits, last_used: u64) -> Self {
        Self {
            limits: Mutex::new(limits),
            request_limiter: Mutex::new(Arc::new(request_limiter(limits))),
            active_tunnels: AtomicU32::new(0),
            last_used: AtomicU64::new(last_used),
        }
    }

    fn update_limits(&self, limits: AccountLimits) -> Result<(), AdmissionError> {
        let mut stored_limits = self
            .limits
            .lock()
            .map_err(|_| AdmissionError::StatePoisoned)?;
        if *stored_limits == limits {
            return Ok(());
        }

        let mut limiter = self
            .request_limiter
            .lock()
            .map_err(|_| AdmissionError::StatePoisoned)?;
        *limiter = Arc::new(request_limiter(limits));
        *stored_limits = limits;
        Ok(())
    }

    fn current_limits(&self) -> Result<AccountLimits, AdmissionError> {
        self.limits
            .lock()
            .map(|limits| *limits)
            .map_err(|_| AdmissionError::StatePoisoned)
    }

    fn request_limiter(&self) -> Result<Arc<DefaultDirectRateLimiter>, AdmissionError> {
        self.request_limiter
            .lock()
            .map(|limiter| Arc::clone(&limiter))
            .map_err(|_| AdmissionError::StatePoisoned)
    }

    fn try_acquire_tunnel(self: &Arc<Self>) -> Result<AccountTunnelGuard, AdmissionError> {
        loop {
            let current = self.active_tunnels.load(Ordering::Acquire);
            let limit = self.current_limits()?.max_concurrent_tunnels.get();
            if current >= limit {
                return Err(AdmissionError::TunnelLimitReached { limit });
            }
            match self.active_tunnels.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(AccountTunnelGuard {
                        state: Arc::clone(self),
                    });
                }
                Err(_) => continue,
            }
        }
    }
}

fn request_limiter(limits: AccountLimits) -> DefaultDirectRateLimiter {
    let quota = Quota::per_second(limits.requests_per_second).allow_burst(limits.request_burst);
    RateLimiter::direct(quota)
}

pub(crate) struct AccountTunnelGuard {
    state: Arc<AccountAdmissionState>,
}

impl fmt::Debug for AccountTunnelGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountTunnelGuard([account redacted])")
    }
}

impl Drop for AccountTunnelGuard {
    fn drop(&mut self) {
        let _ = self.state.active_tunnels.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_sub(1),
        );
    }
}

#[derive(Debug)]
pub(crate) struct AccountAdmissionController {
    states: Mutex<HashMap<AccountId, Arc<AccountAdmissionState>>>,
    max_cached_accounts: usize,
    sequence: AtomicU64,
}

impl AccountAdmissionController {
    pub(crate) fn new(max_cached_accounts: usize) -> Result<Self, AccountManagementError> {
        if max_cached_accounts == 0 {
            return Err(AccountManagementError::InvalidInput(
                "admission cache capacity must be non-zero",
            ));
        }
        Ok(Self {
            states: Mutex::new(HashMap::new()),
            max_cached_accounts,
            sequence: AtomicU64::new(1),
        })
    }

    pub(crate) fn check_request_rate(
        &self,
        identity: IngressIdentity,
    ) -> Result<(), AdmissionError> {
        let state = self.state_for(identity.account_id, identity.limits)?;
        let limiter = state.request_limiter()?;
        match limiter.check() {
            Ok(()) => Ok(()),
            Err(not_until) => {
                let retry_after = not_until.wait_time_from(limiter.clock().now());
                Err(AdmissionError::RateLimited { retry_after })
            }
        }
    }

    pub(crate) fn try_acquire_tunnel(
        &self,
        identity: IngressIdentity,
    ) -> Result<AccountTunnelGuard, AdmissionError> {
        self.state_for(identity.account_id, identity.limits)?
            .try_acquire_tunnel()
    }

    pub(crate) fn active_tunnels(&self, identity: IngressIdentity) -> Result<u32, AdmissionError> {
        let state = self.state_for(identity.account_id, identity.limits)?;
        Ok(state.active_tunnels.load(Ordering::Acquire))
    }

    pub(crate) fn cached_account_states(&self) -> Result<usize, AdmissionError> {
        self.states
            .lock()
            .map(|states| states.len())
            .map_err(|_| AdmissionError::StatePoisoned)
    }

    fn state_for(
        &self,
        account_id: AccountId,
        limits: AccountLimits,
    ) -> Result<Arc<AccountAdmissionState>, AdmissionError> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut states = self
            .states
            .lock()
            .map_err(|_| AdmissionError::StatePoisoned)?;

        if let Some(state) = states.get(&account_id) {
            state.update_limits(limits)?;
            state.last_used.store(sequence, Ordering::Release);
            return Ok(Arc::clone(state));
        }

        if states.len() >= self.max_cached_accounts {
            let eviction_candidate = states
                .iter()
                .filter(|(_, state)| {
                    state.active_tunnels.load(Ordering::Acquire) == 0
                        && Arc::strong_count(state) == 1
                })
                .min_by_key(|(_, state)| state.last_used.load(Ordering::Acquire))
                .map(|(account_id, _)| *account_id);
            match eviction_candidate {
                Some(eviction_candidate) => {
                    states.remove(&eviction_candidate);
                }
                None => return Err(AdmissionError::StateCapacityReached),
            }
        }

        let state = Arc::new(AccountAdmissionState::new(limits, sequence));
        states.insert(account_id, Arc::clone(&state));
        Ok(state)
    }
}

pub(crate) struct AccountManager {
    database: AccountDatabase,
    hasher: ApiKeyHasher,
    admission: AccountAdmissionController,
}

impl fmt::Debug for AccountManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountManager")
            .field("database", &self.database)
            .field("hasher", &self.hasher)
            .field("admission", &self.admission)
            .finish()
    }
}

impl AccountManager {
    pub(crate) fn open(
        path: &Path,
        hasher: ApiKeyHasher,
        max_cached_accounts: usize,
    ) -> Result<Self, AccountManagementError> {
        Ok(Self {
            database: AccountDatabase::open(path)?,
            hasher,
            admission: AccountAdmissionController::new(max_cached_accounts)?,
        })
    }

    pub(crate) fn open_in_memory(
        hasher: ApiKeyHasher,
        max_cached_accounts: usize,
    ) -> Result<Self, AccountManagementError> {
        Ok(Self {
            database: AccountDatabase::open_in_memory()?,
            hasher,
            admission: AccountAdmissionController::new(max_cached_accounts)?,
        })
    }

    pub(crate) fn create_account(
        &self,
        email: &str,
        stripe_customer_id: Option<&str>,
        plan: &PlanCode,
        limits: AccountLimits,
        now: UnixTimestamp,
    ) -> Result<AccountRecord, AccountManagementError> {
        self.database
            .create_account(email, stripe_customer_id, plan, limits, now)
    }

    pub(crate) fn account(
        &self,
        account_id: AccountId,
    ) -> Result<AccountRecord, AccountManagementError> {
        self.database.account(account_id)
    }

    pub(crate) fn account_by_email(
        &self,
        email: &str,
    ) -> Result<AccountRecord, AccountManagementError> {
        self.database.account_by_email(email)
    }

    pub(crate) fn account_by_stripe_customer_id(
        &self,
        stripe_customer_id: &str,
    ) -> Result<AccountRecord, AccountManagementError> {
        self.database
            .account_by_stripe_customer_id(stripe_customer_id)
    }

    pub(crate) fn list_accounts(&self) -> Result<Vec<AccountRecord>, AccountManagementError> {
        self.database.list_accounts()
    }

    pub(crate) fn set_account_status(
        &self,
        account_id: AccountId,
        status: AccountStatus,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        self.database.set_account_status(account_id, status, now)
    }

    pub(crate) fn update_account_plan_and_limits(
        &self,
        account_id: AccountId,
        plan: &PlanCode,
        limits: AccountLimits,
        now: UnixTimestamp,
    ) -> Result<(), AccountManagementError> {
        self.database
            .update_account_plan_and_limits(account_id, plan, limits, now)
    }

    pub(crate) fn set_stripe_customer_id(
        &self,
        account_id: AccountId,
        stripe_customer_id: Option<&str>,
        now: UnixTimestamp,
    ) -> Result<(), AccountManagementError> {
        self.database
            .set_stripe_customer_id(account_id, stripe_customer_id, now)
    }

    pub(crate) fn create_workspace(
        &self,
        account_id: AccountId,
        name: &str,
        now: UnixTimestamp,
    ) -> Result<WorkspaceRecord, AccountManagementError> {
        self.database.create_workspace(account_id, name, now)
    }

    pub(crate) fn workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspaceRecord, AccountManagementError> {
        self.database.workspace(workspace_id)
    }

    pub(crate) fn list_workspaces(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<WorkspaceRecord>, AccountManagementError> {
        self.database.list_workspaces(account_id)
    }

    pub(crate) fn set_workspace_status(
        &self,
        workspace_id: WorkspaceId,
        status: WorkspaceStatus,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        self.database
            .set_workspace_status(workspace_id, status, now)
    }

    pub(crate) fn issue_api_key(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        label: &str,
        now: UnixTimestamp,
    ) -> Result<IssuedApiKey, AccountManagementError> {
        for _ in 0..API_KEY_GENERATION_ATTEMPTS {
            let generated = GeneratedApiKey::generate(&self.hasher)?;
            match self
                .database
                .insert_api_key(account_id, workspace_id, label, &generated, now)
            {
                Ok(id) => {
                    return Ok(IssuedApiKey {
                        id,
                        public_id: generated.public_id,
                        secret: generated.secret,
                    });
                }
                Err(AccountManagementError::Database(error)) if is_constraint_violation(&error) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(AccountManagementError::CredentialGenerationExhausted)
    }

    pub(crate) fn rotate_api_key(
        &self,
        old_api_key_id: ApiKeyId,
        now: UnixTimestamp,
    ) -> Result<IssuedApiKey, AccountManagementError> {
        for _ in 0..API_KEY_GENERATION_ATTEMPTS {
            let generated = GeneratedApiKey::generate(&self.hasher)?;
            match self
                .database
                .rotate_api_key(old_api_key_id, &generated, now)
            {
                Ok(id) => {
                    return Ok(IssuedApiKey {
                        id,
                        public_id: generated.public_id,
                        secret: generated.secret,
                    });
                }
                Err(AccountManagementError::Database(error)) if is_constraint_violation(&error) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(AccountManagementError::CredentialGenerationExhausted)
    }

    pub(crate) fn revoke_api_key(
        &self,
        api_key_id: ApiKeyId,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        self.database.revoke_api_key(api_key_id, now)
    }

    pub(crate) fn list_api_keys(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ApiKeyMetadata>, AccountManagementError> {
        self.database.list_api_keys(account_id, workspace_id)
    }

    pub(crate) fn register_device_credential(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        fingerprint: &CertificateFingerprint,
        label: &str,
        now: UnixTimestamp,
    ) -> Result<DeviceCredentialMetadata, AccountManagementError> {
        self.database
            .register_device_credential(account_id, workspace_id, fingerprint, label, now)
    }

    pub(crate) fn revoke_device_credential(
        &self,
        device_credential_id: DeviceCredentialId,
        now: UnixTimestamp,
    ) -> Result<bool, AccountManagementError> {
        self.database
            .revoke_device_credential(device_credential_id, now)
    }

    pub(crate) fn list_device_credentials(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<DeviceCredentialMetadata>, AccountManagementError> {
        self.database
            .list_device_credentials(account_id, workspace_id)
    }

    pub(crate) fn authenticate_ingress(
        &self,
        proxy_authorization: &str,
        fingerprint: &CertificateFingerprint,
    ) -> Result<IngressIdentity, AuthenticationError> {
        let api_key = extract_proxy_auth_api_key(proxy_authorization)
            .map_err(AuthenticationError::InvalidAuthorization)?;
        let public_id = parse_api_key_public_id(api_key.expose_secret())
            .map_err(AuthenticationError::InvalidAuthorization)?;
        let digest = self.hasher.digest(api_key.expose_secret());
        self.database.authenticate(public_id, &digest, fingerprint)
    }

    pub(crate) fn usage(
        &self,
        identity: IngressIdentity,
        period_start: UnixTimestamp,
    ) -> Result<UsageSnapshot, AccountManagementError> {
        self.database.usage(identity, period_start)
    }

    pub(crate) fn usage_for_scope(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        period_start: UnixTimestamp,
    ) -> Result<UsageSnapshot, AccountManagementError> {
        self.database
            .usage_for_scope(account_id, workspace_id, period_start)
    }

    pub(crate) fn list_usage_for_period(
        &self,
        period_start: UnixTimestamp,
    ) -> Result<Vec<UsageSnapshot>, AccountManagementError> {
        self.database.list_usage_for_period(period_start)
    }

    pub(crate) fn record_usage(
        &self,
        identity: IngressIdentity,
        period_start: UnixTimestamp,
        delta: UsageDelta,
    ) -> Result<UsageSnapshot, AccountManagementError> {
        self.database.record_usage(identity, period_start, delta)
    }

    pub(crate) fn admit_request(
        &self,
        identity: IngressIdentity,
        period_start: UnixTimestamp,
    ) -> Result<UsageSnapshot, UsageAdmissionError> {
        let delta = UsageDelta::new(1, 0, 0).map_err(UsageAdmissionError::Storage)?;
        self.database
            .record_usage_if_allowed(identity, period_start, delta)
    }

    pub(crate) fn check_request_rate(
        &self,
        identity: IngressIdentity,
    ) -> Result<(), AdmissionError> {
        self.admission.check_request_rate(identity)
    }

    pub(crate) fn try_acquire_tunnel(
        &self,
        identity: IngressIdentity,
    ) -> Result<AccountTunnelGuard, AdmissionError> {
        self.admission.try_acquire_tunnel(identity)
    }

    pub(crate) fn active_tunnels(&self, identity: IngressIdentity) -> Result<u32, AdmissionError> {
        self.admission.active_tunnels(identity)
    }

    pub(crate) fn cached_account_states(&self) -> Result<usize, AdmissionError> {
        self.admission.cached_account_states()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    type TestResult = Result<(), Box<dyn StdError>>;

    struct TestTenant {
        account: AccountRecord,
        workspace: WorkspaceRecord,
        api_key: IssuedApiKey,
        device: DeviceCredentialMetadata,
        fingerprint: CertificateFingerprint,
    }

    fn timestamp(seconds: i64) -> Result<UnixTimestamp, AccountManagementError> {
        UnixTimestamp::new(seconds)
    }

    fn limits(
        requests_per_second: u32,
        burst: u32,
        tunnels: u32,
        request_limit: Option<u64>,
        byte_limit: Option<u64>,
    ) -> Result<AccountLimits, AccountManagementError> {
        AccountLimits::new(
            requests_per_second,
            burst,
            tunnels,
            request_limit,
            byte_limit,
        )
    }

    fn manager(max_cached_accounts: usize) -> Result<AccountManager, AccountManagementError> {
        AccountManager::open_in_memory(
            ApiKeyHasher::from_key(Zeroizing::new([0x5a; blake3::KEY_LEN])),
            max_cached_accounts,
        )
    }

    fn create_tenant(
        manager: &AccountManager,
        email: &str,
        fingerprint_byte: u8,
        account_limits: AccountLimits,
    ) -> Result<TestTenant, AccountManagementError> {
        let plan = PlanCode::new("pilot")?;
        let account =
            manager.create_account(email, None, &plan, account_limits, timestamp(100)?)?;
        let workspace = manager.create_workspace(account.id(), "default", timestamp(101)?)?;
        let api_key =
            manager.issue_api_key(account.id(), workspace.id(), "primary", timestamp(102)?)?;
        let fingerprint = CertificateFingerprint::from_sha256([fingerprint_byte; 32]);
        let device = manager.register_device_credential(
            account.id(),
            workspace.id(),
            &fingerprint,
            "test connector",
            timestamp(103)?,
        )?;
        Ok(TestTenant {
            account,
            workspace,
            api_key,
            device,
            fingerprint,
        })
    }

    fn basic_header(secret: &ApiKeySecret) -> Zeroizing<String> {
        let credentials = Zeroizing::new(format!("{}:", secret.expose_secret()));
        let encoded = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        Zeroizing::new(format!("Basic {}", encoded.as_str()))
    }

    fn authenticate(
        manager: &AccountManager,
        tenant: &TestTenant,
    ) -> Result<IngressIdentity, AuthenticationError> {
        let header = basic_header(tenant.api_key.secret());
        manager.authenticate_ingress(header.as_str(), &tenant.fingerprint)
    }

    #[test]
    fn file_database_migrates_persists_and_is_owner_only() -> TestResult {
        let temporary_directory = tempfile::tempdir()?;
        let database_path = temporary_directory.path().join("accounts.sqlite3");
        let plan = PlanCode::new("pilot")?;
        let account_limits = limits(5, 10, 2, Some(5_000), Some(1_000_000))?;
        let account_id;

        {
            let manager = AccountManager::open(
                &database_path,
                ApiKeyHasher::from_key(Zeroizing::new([0x11; blake3::KEY_LEN])),
                8,
            )?;
            let account = manager.create_account(
                "Customer@Example.COM",
                Some("cus_test_123"),
                &plan,
                account_limits,
                timestamp(10)?,
            )?;
            account_id = account.id();
            assert_eq!(account.email(), "customer@example.com");
            assert_eq!(account.stripe_customer_id(), Some("cus_test_123"));

            let connection = manager.database.connection()?;
            let schema_version: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            assert_eq!(schema_version, SCHEMA_VERSION);
        }

        #[cfg(unix)]
        {
            let mode = fs::metadata(&database_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let reopened = AccountManager::open(
            &database_path,
            ApiKeyHasher::from_key(Zeroizing::new([0x11; blake3::KEY_LEN])),
            8,
        )?;
        let account = reopened.account(account_id)?;
        assert_eq!(account.email(), "customer@example.com");
        assert_eq!(account.plan(), &plan);
        assert_eq!(account.limits(), account_limits);
        assert_eq!(
            reopened.account_by_email("CUSTOMER@example.com")?.id(),
            account_id
        );
        let accounts = reopened.list_accounts()?;
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id(), account_id);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_database_rejects_broad_permissions_and_symlinks() -> TestResult {
        let temporary_directory = tempfile::tempdir()?;
        let broad_path = temporary_directory.path().join("broad.sqlite3");
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&broad_path)?;
        let result = AccountDatabase::open(&broad_path);
        assert!(matches!(
            result,
            Err(AccountManagementError::InsecureDatabasePermissions(_))
        ));

        let protected_path = temporary_directory.path().join("protected.sqlite3");
        let _database = AccountDatabase::open(&protected_path)?;
        let symlink_path = temporary_directory.path().join("linked.sqlite3");
        std::os::unix::fs::symlink(&protected_path, &symlink_path)?;
        let result = AccountDatabase::open(&symlink_path);
        assert!(matches!(
            result,
            Err(AccountManagementError::InsecureDatabasePath(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn api_key_hash_secret_file_must_be_owner_only_regular_and_exact() -> TestResult {
        let temporary_directory = tempfile::tempdir()?;
        let secret_path = temporary_directory.path().join("api-key-hash-key");
        fs::write(&secret_path, [0x7b; blake3::KEY_LEN])?;
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;
        let hasher = ApiKeyHasher::from_key_file(&secret_path)?;
        assert_eq!(format!("{hasher:?}"), "ApiKeyHasher([redacted])");

        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            ApiKeyHasher::from_key_file(&secret_path),
            Err(AccountManagementError::InsecureSecretPermissions(_))
        ));

        let short_path = temporary_directory.path().join("short-key");
        fs::write(&short_path, [0x11; blake3::KEY_LEN - 1])?;
        fs::set_permissions(&short_path, fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            ApiKeyHasher::from_key_file(&short_path),
            Err(AccountManagementError::InvalidSecretLength { .. })
        ));

        let symlink_path = temporary_directory.path().join("linked-key");
        std::os::unix::fs::symlink(&short_path, &symlink_path)?;
        assert!(matches!(
            ApiKeyHasher::from_key_file(&symlink_path),
            Err(AccountManagementError::InsecureSecretPath(_))
        ));
        Ok(())
    }

    #[test]
    fn usage_period_start_is_aligned_and_nonzero() -> TestResult {
        let period = Duration::from_secs(3_600);
        let start = UnixTimestamp::period_start_now(period)?;
        assert_eq!(start.as_i64().rem_euclid(3_600), 0);
        assert!(UnixTimestamp::period_start_now(Duration::ZERO).is_err());
        Ok(())
    }

    #[test]
    fn basic_proxy_authorization_accepts_only_key_as_username() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "auth-parser@example.com",
            0x21,
            limits(5, 5, 1, None, None)?,
        )?;
        let header = basic_header(tenant.api_key.secret());
        let extracted = extract_proxy_auth_api_key(header.as_str())?;
        assert_eq!(
            extracted.expose_secret(),
            tenant.api_key.secret().expose_secret()
        );

        let nonempty_password = STANDARD.encode(format!(
            "{}:password",
            tenant.api_key.secret().expose_secret()
        ));
        assert!(matches!(
            extract_proxy_auth_api_key(&format!("Basic {nonempty_password}")),
            Err(ProxyAuthorizationError::PasswordMustBeEmpty)
        ));
        assert!(matches!(
            extract_proxy_auth_api_key("Bearer token"),
            Err(ProxyAuthorizationError::UnsupportedScheme)
        ));
        assert!(matches!(
            extract_proxy_auth_api_key("Basic !!!"),
            Err(ProxyAuthorizationError::InvalidBase64)
        ));
        assert!(matches!(
            extract_proxy_auth_api_key("Basic cHh5X2JhZA=="),
            Err(ProxyAuthorizationError::MissingPasswordSeparator)
                | Err(ProxyAuthorizationError::InvalidApiKeyFormat)
        ));
        Ok(())
    }

    #[test]
    fn issued_key_is_hashed_and_authentication_binds_device_scope() -> TestResult {
        let manager = manager(8)?;
        let first = create_tenant(
            &manager,
            "first@example.com",
            0x31,
            limits(10, 10, 2, None, None)?,
        )?;
        let second = create_tenant(
            &manager,
            "second@example.com",
            0x32,
            limits(10, 10, 2, None, None)?,
        )?;

        let identity = authenticate(&manager, &first)?;
        assert_eq!(identity.account_id(), first.account.id());
        assert_eq!(identity.workspace_id(), first.workspace.id());
        assert_eq!(identity.api_key_id(), first.api_key.id());
        assert_eq!(identity.device_credential_id(), first.device.id());

        let raw_key = first.api_key.secret().expose_secret();
        assert!(!format!("{:?}", first.api_key).contains(raw_key));
        let connection = manager.database.connection()?;
        let raw_matches: i64 = connection.query_row(
            "SELECT count(*) FROM api_keys
             WHERE public_id = ?1 OR label = ?1 OR key_hash = CAST(?1 AS BLOB)",
            params![raw_key],
            |row| row.get(0),
        )?;
        assert_eq!(raw_matches, 0);
        drop(connection);

        let mut changed_key = Zeroizing::new(raw_key.to_owned());
        let replacement = if changed_key.ends_with('A') { 'B' } else { 'A' };
        assert!(changed_key.pop().is_some());
        changed_key.push(replacement);
        let changed_secret = ApiKeySecret::new(changed_key.as_str().to_owned());
        let changed_header = basic_header(&changed_secret);
        let wrong_secret =
            manager.authenticate_ingress(changed_header.as_str(), &first.fingerprint);
        assert!(matches!(
            wrong_secret,
            Err(AuthenticationError::InvalidApiKey)
        ));

        let wrong_device_header = basic_header(first.api_key.secret());
        let wrong_scope =
            manager.authenticate_ingress(wrong_device_header.as_str(), &second.fingerprint);
        assert!(matches!(
            wrong_scope,
            Err(AuthenticationError::CredentialScopeMismatch)
        ));

        let unknown_fingerprint = CertificateFingerprint::from_sha256([0xff; 32]);
        let unknown_header = basic_header(first.api_key.secret());
        let unknown = manager.authenticate_ingress(unknown_header.as_str(), &unknown_fingerprint);
        assert!(matches!(unknown, Err(AuthenticationError::UnknownDevice)));

        let cross_tenant_key = manager.issue_api_key(
            first.account.id(),
            second.workspace.id(),
            "invalid scope",
            timestamp(150)?,
        );
        assert!(matches!(
            cross_tenant_key,
            Err(AccountManagementError::NotFound(EntityKind::Workspace))
        ));
        Ok(())
    }

    #[test]
    fn rotation_revokes_old_key_and_returns_new_key_once() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "rotation@example.com",
            0x41,
            limits(10, 10, 2, None, None)?,
        )?;
        let old_header = basic_header(tenant.api_key.secret());
        let replacement = manager.rotate_api_key(tenant.api_key.id(), timestamp(200)?)?;
        assert_ne!(replacement.public_id(), tenant.api_key.public_id());
        assert_ne!(
            replacement.secret().expose_secret(),
            tenant.api_key.secret().expose_secret()
        );

        let old_result = manager.authenticate_ingress(old_header.as_str(), &tenant.fingerprint);
        assert!(matches!(
            old_result,
            Err(AuthenticationError::ApiKeyRevoked)
        ));

        let replacement_header = basic_header(replacement.secret());
        let replacement_identity =
            manager.authenticate_ingress(replacement_header.as_str(), &tenant.fingerprint)?;
        assert_eq!(replacement_identity.api_key_id(), replacement.id());

        let keys = manager.list_api_keys(tenant.account.id(), tenant.workspace.id())?;
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].status(), CredentialStatus::Revoked);
        assert_eq!(keys[1].status(), CredentialStatus::Active);
        assert!(!format!("{keys:?}").contains(replacement.secret().expose_secret()));
        assert!(!format!("{keys:?}").contains(replacement.public_id()));
        Ok(())
    }

    #[test]
    fn revocation_suspension_and_workspace_state_reject_authentication() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "status@example.com",
            0x51,
            limits(10, 10, 2, None, None)?,
        )?;

        manager.set_workspace_status(
            tenant.workspace.id(),
            WorkspaceStatus::Suspended,
            timestamp(200)?,
        )?;
        let suspended_workspace = authenticate(&manager, &tenant);
        assert!(matches!(
            suspended_workspace,
            Err(AuthenticationError::WorkspaceInactive)
        ));
        manager.set_workspace_status(
            tenant.workspace.id(),
            WorkspaceStatus::Active,
            timestamp(201)?,
        )?;

        manager.set_account_status(
            tenant.account.id(),
            AccountStatus::Suspended,
            timestamp(202)?,
        )?;
        let suspended_account = authenticate(&manager, &tenant);
        assert!(matches!(
            suspended_account,
            Err(AuthenticationError::AccountInactive)
        ));
        manager.set_account_status(tenant.account.id(), AccountStatus::Active, timestamp(203)?)?;

        assert!(manager.revoke_api_key(tenant.api_key.id(), timestamp(204)?)?);
        assert!(!manager.revoke_api_key(tenant.api_key.id(), timestamp(205)?)?);
        let revoked_key = authenticate(&manager, &tenant);
        assert!(matches!(
            revoked_key,
            Err(AuthenticationError::ApiKeyRevoked)
        ));
        Ok(())
    }

    #[test]
    fn device_revocation_is_immediate_and_list_output_omits_fingerprint() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "device@example.com",
            0x61,
            limits(10, 10, 2, None, None)?,
        )?;
        assert!(manager.revoke_device_credential(tenant.device.id(), timestamp(300)?)?);
        assert!(!manager.revoke_device_credential(tenant.device.id(), timestamp(301)?)?);
        let result = authenticate(&manager, &tenant);
        assert!(matches!(result, Err(AuthenticationError::DeviceRevoked)));

        let devices =
            manager.list_device_credentials(tenant.account.id(), tenant.workspace.id())?;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].status(), CredentialStatus::Revoked);
        assert!(!format!("{devices:?}").contains("61616161"));
        Ok(())
    }

    #[test]
    fn account_plan_limits_and_stripe_metadata_are_manageable() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "plan@example.com",
            0x71,
            limits(2, 2, 1, Some(100), Some(1_000))?,
        )?;
        let new_plan = PlanCode::new("paid-standard")?;
        let new_limits = limits(20, 30, 5, Some(10_000), Some(50_000_000))?;
        manager.update_account_plan_and_limits(
            tenant.account.id(),
            &new_plan,
            new_limits,
            timestamp(400)?,
        )?;
        manager.set_stripe_customer_id(
            tenant.account.id(),
            Some("cus_paid_456"),
            timestamp(401)?,
        )?;

        let updated = manager.account(tenant.account.id())?;
        assert_eq!(updated.plan(), &new_plan);
        assert_eq!(updated.limits(), new_limits);
        assert_eq!(updated.stripe_customer_id(), Some("cus_paid_456"));
        let debug_output = format!("{updated:?}");
        assert!(!debug_output.contains("plan@example.com"));
        assert!(!debug_output.contains("cus_paid_456"));
        assert_eq!(
            manager.account_by_stripe_customer_id("cus_paid_456")?.id(),
            tenant.account.id()
        );
        let workspaces = manager.list_workspaces(tenant.account.id())?;
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].id(), tenant.workspace.id());
        Ok(())
    }

    #[test]
    fn request_rate_is_per_account_and_reports_retry_delay() -> TestResult {
        let manager = manager(8)?;
        let first = create_tenant(
            &manager,
            "rate-one@example.com",
            0x81,
            limits(1, 2, 1, None, None)?,
        )?;
        let second = create_tenant(
            &manager,
            "rate-two@example.com",
            0x82,
            limits(1, 2, 1, None, None)?,
        )?;
        let first_identity = authenticate(&manager, &first)?;
        let second_identity = authenticate(&manager, &second)?;

        manager.check_request_rate(first_identity)?;
        manager.check_request_rate(first_identity)?;
        let limited = manager.check_request_rate(first_identity);
        match limited {
            Err(AdmissionError::RateLimited { retry_after }) => {
                assert!(!retry_after.is_zero());
            }
            other => return Err(format!("expected rate limit, got {other:?}").into()),
        }
        manager.check_request_rate(second_identity)?;
        Ok(())
    }

    #[test]
    fn concurrent_tunnel_guard_releases_capacity_on_drop() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "tunnel@example.com",
            0x91,
            limits(10, 10, 1, None, None)?,
        )?;
        let identity = authenticate(&manager, &tenant)?;
        let guard = manager.try_acquire_tunnel(identity)?;
        assert_eq!(manager.active_tunnels(identity)?, 1);
        assert!(matches!(
            manager.try_acquire_tunnel(identity),
            Err(AdmissionError::TunnelLimitReached { limit: 1 })
        ));
        drop(guard);
        assert_eq!(manager.active_tunnels(identity)?, 0);
        let replacement_guard = manager.try_acquire_tunnel(identity)?;
        assert_eq!(manager.active_tunnels(identity)?, 1);
        drop(replacement_guard);
        Ok(())
    }

    #[test]
    fn admission_cache_is_bounded_and_does_not_evict_active_accounts() -> TestResult {
        let manager = manager(1)?;
        let first = create_tenant(
            &manager,
            "cache-one@example.com",
            0xa1,
            limits(10, 10, 1, None, None)?,
        )?;
        let second = create_tenant(
            &manager,
            "cache-two@example.com",
            0xa2,
            limits(10, 10, 1, None, None)?,
        )?;
        let first_identity = authenticate(&manager, &first)?;
        let second_identity = authenticate(&manager, &second)?;

        let guard = manager.try_acquire_tunnel(first_identity)?;
        assert!(matches!(
            manager.check_request_rate(second_identity),
            Err(AdmissionError::StateCapacityReached)
        ));
        drop(guard);
        manager.check_request_rate(second_identity)?;
        assert_eq!(manager.cached_account_states()?, 1);
        Ok(())
    }

    #[test]
    fn usage_is_aggregated_by_tenant_and_period_and_enforces_quotas() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "usage@example.com",
            0xb1,
            limits(10, 10, 2, Some(3), Some(100))?,
        )?;
        let identity = authenticate(&manager, &tenant)?;
        let period = timestamp(1_700_000_000)?;

        let empty = manager.usage(identity, period)?;
        assert_eq!(empty.requests_used(), 0);
        assert_eq!(empty.total_bytes()?, 0);

        let first_delta = UsageDelta::new(2, 40, 30)?;
        let first = manager.record_usage(identity, period, first_delta)?;
        assert_eq!(first.requests_used(), 2);
        assert_eq!(first.bytes_to_tor(), 40);
        assert_eq!(first.bytes_from_tor(), 30);
        assert_eq!(first.total_bytes()?, 70);
        assert_eq!(
            check_usage_allowance(identity, first, UsageDelta::new(1, 10, 10)?),
            Ok(())
        );
        assert_eq!(
            check_usage_allowance(identity, first, UsageDelta::new(2, 0, 0)?),
            Err(UsageQuotaError::RequestLimitReached)
        );
        assert_eq!(
            check_usage_allowance(identity, first, UsageDelta::new(0, 20, 20)?),
            Err(UsageQuotaError::ByteLimitReached)
        );

        let second = manager.record_usage(identity, period, UsageDelta::new(1, 10, 10)?)?;
        assert_eq!(second.requests_used(), 3);
        assert_eq!(second.total_bytes()?, 90);
        let billing_view =
            manager.usage_for_scope(tenant.account.id(), tenant.workspace.id(), period)?;
        assert_eq!(billing_view, second);
        let period_usage = manager.list_usage_for_period(period)?;
        assert_eq!(period_usage.len(), 1);
        assert_eq!(period_usage[0].account_id(), tenant.account.id());
        assert_eq!(period_usage[0].workspace_id(), tenant.workspace.id());
        assert_eq!(period_usage[0].period_start(), period);

        let connection = manager.database.connection()?;
        let mut statement = connection.prepare("PRAGMA table_info(usage_periods)")?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        for column in columns {
            let column = column?;
            assert!(!matches!(
                column.as_str(),
                "destination" | "url" | "path" | "isolation_token"
            ));
        }
        Ok(())
    }

    #[test]
    fn request_usage_admission_is_atomic_and_enforces_period_quota() -> TestResult {
        let manager = manager(8)?;
        let tenant = create_tenant(
            &manager,
            "usage-admission@example.com",
            0xb2,
            limits(10, 10, 2, Some(1), Some(100))?,
        )?;
        let identity = authenticate(&manager, &tenant)?;
        let period = timestamp(1_700_100_000)?;

        let admitted = manager.admit_request(identity, period)?;
        assert_eq!(admitted.requests_used(), 1);
        assert!(matches!(
            manager.admit_request(identity, period),
            Err(UsageAdmissionError::Quota(
                UsageQuotaError::RequestLimitReached
            ))
        ));
        assert_eq!(manager.usage(identity, period)?.requests_used(), 1);
        Ok(())
    }

    #[test]
    fn usage_scope_cannot_be_mixed_between_accounts() -> TestResult {
        let manager = manager(8)?;
        let first = create_tenant(
            &manager,
            "usage-scope-one@example.com",
            0xc1,
            limits(10, 10, 1, Some(10), Some(1_000))?,
        )?;
        let second = create_tenant(
            &manager,
            "usage-scope-two@example.com",
            0xc2,
            limits(10, 10, 1, Some(10), Some(1_000))?,
        )?;
        let first_identity = authenticate(&manager, &first)?;
        let second_identity = authenticate(&manager, &second)?;
        let first_usage = manager.usage(first_identity, timestamp(900)?)?;
        assert_eq!(
            check_usage_allowance(second_identity, first_usage, UsageDelta::new(1, 0, 0)?),
            Err(UsageQuotaError::ScopeMismatch)
        );
        Ok(())
    }
}
