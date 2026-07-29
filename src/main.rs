#[allow(dead_code)]
mod account_management;

#[allow(dead_code)]
mod private_ingress;

use account_management::{
	AccountId, AccountManager, AdmissionError as AccountAdmissionError, ApiKeyHasher,
	AuthenticationError, CertificateFingerprint, IngressIdentity, UnixTimestamp, UsageDelta,
	UsageAdmissionError,
};
use private_ingress::{
	RuntimeIngressConfig, load_server_config, validate_negotiated_alpn,
};
use pingora::{
	prelude::*, 
	cache::{
		MemCache, HttpCache, CacheMeta, CacheMetaDefaults, CachePhase, NoCacheReason,
		RespCacheable, Storage, cache_control::CacheControl, filters,
		eviction::{EvictionManager, lru::Manager as LruEvictionManager},
		lock::CacheLock,
		trace::SpanHandle,
		CacheKey
	},
	apps::HttpServerOptions,
	protocols::http::ServerSession,
	proxy::{Session, ProxyHttp, ProxyServiceBuilder},
	server::{configuration::ServerConf, ShutdownWatch},
	services::background::BackgroundService,
	Error,
	upstreams::peer::Proxy as CrateProxy,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::{
	collections::HashMap,
	fmt,
	future::Future,
	hash::{Hash, Hasher},
	process,
	net::{IpAddr, SocketAddr},
	sync::{
		atomic::{AtomicU64, AtomicUsize, Ordering},
		Arc, Mutex, OnceLock
	},
	marker::PhantomData,
	path::Path,
	time::Instant as StdInstant
	//error::Error
};
use pingora_memory_cache::MemoryCache; 
use arti_client::{
	DataStream, ErrorKind, HasKind,
	IsolationToken,
	//isolation::IsolationHelper,
	TorClient, TorClientConfig,
	StreamPrefs, TorAddr
};
use tor_rtcompat::PreferredRuntime;
use tokio::{
	io::{self, AsyncReadExt, AsyncWriteExt},
	runtime::Runtime, 
	net::{TcpListener, TcpStream, UnixListener, UnixStream},
	sync::{watch, OwnedSemaphorePermit, Semaphore},
	task::{JoinError, JoinSet},
	time::Duration
	//sync::{Semaphore, SemaphorePermit}
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use zeroize::{Zeroize, Zeroizing};
//use anyhow::*;

static CACHE: OnceLock<MemCache> = OnceLock::new();
static CACHE_LOCK: OnceLock<CacheLock> = OnceLock::new();
static CACHE_EVICTION: OnceLock<LruEvictionManager<CACHE_LRU_SHARDS>> = OnceLock::new();
const CACHE_MAX_BYTES: usize = 128 * 1024 * 1024;
const CACHE_LRU_SHARDS: usize = 16;
const CACHE_ITEMS_PER_SHARD: usize = 1_024;
const CACHE_LOCK_MAX_AGE: Duration = Duration::from_secs(60);
const CACHE_MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONNECT_HEADERS: usize = 64;
const ISOLATION_HEADER: &str = "X-Proxy-Isolation";
const ISOLATION_MODE_HEADER: &str = "X-Proxy-Isolation-Mode";
const PROXY_AUTHORIZATION_HEADER: &str = "Proxy-Authorization";
const INTERNAL_IDENTITY_HEADER: &str = "X-Proxy-Authenticated-Lease";
const MAX_ISOLATION_ID_BYTES: usize = 64;
const MAX_ISOLATION_TOKENS: usize = 10_000;
const ISOLATION_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
const BRIDGE_SOCKET: &str = "/tmp/proxy-bridge.sock";
const PUBLIC_PROXY_ADDR: &str = "127.0.0.1:8080";
const INTERNAL_PROXY_ADDR: &str = "127.0.0.1:8081";
// Tune based on VPS bandwidth and observed circuit build latency.
const MAX_CONCURRENT_CIRCUIT_BUILDS: usize = 32;
const MAX_ACTIVE_TUNNELS: usize = 256;
const MAX_CONNECTION_TASKS: usize = 512;
const CIRCUIT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10); // tune later
const TUNNEL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_BRIDGE_TASK_DRAIN_SECONDS: u64 = 30;
const DEFAULT_BRIDGE_TASK_FORCE_STOP_SECONDS: u64 = 5;
const MAX_BRIDGE_TASK_SHUTDOWN_SECONDS: u64 = 60 * 60;
const SHUTDOWN_GRACE_MARGIN_SECONDS: u64 = 1;
const GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = 1;
const RETRY_BACKOFF_MIN_MS: u64 = 50;
const RETRY_BACKOFF_JITTER_MS: u64 = 100;
const BREAKER_FAILURE_THRESHOLD: usize = 3;
const BREAKER_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_BREAKER_ENTRIES: usize = 10_000;
const CIRCUIT_METRICS_LOG_INTERVAL: Duration = Duration::from_secs(30);
const PROMETHEUS_ADDR: &str = "127.0.0.1:9090";
const CIRCUIT_CAPACITY_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const BAD_REQUEST_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const FORBIDDEN_RESPONSE: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const BAD_GATEWAY_RESPONSE: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const GATEWAY_TIMEOUT_RESPONSE: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const PROXY_AUTH_REQUIRED_RESPONSE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"private-proxy\", charset=\"UTF-8\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RATE_LIMITED_RESPONSE: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const QUOTA_EXCEEDED_RESPONSE: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const REQUEST_TIMEOUT_RESPONSE: &[u8] = b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const SERVICE_UNAVAILABLE_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

static ISOLATION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static ISOLATION_GROUP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct IsolationRequest {
	identity: Option<String>,
	strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedIsolation {
	identity: String,
	strict: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IsolationMaterial {
	token: IsolationToken,
	group_key: u64,
}

#[derive(Clone, Copy)]
struct IsolationEntry {
	material: IsolationMaterial,
	last_used: StdInstant,
	expires_at: StdInstant,
}

struct IsolationStoreInner {
	entries: HashMap<String, IsolationEntry>,
}

struct IsolationStore {
	inner: Mutex<IsolationStoreInner>,
	capacity: usize,
	ttl: Duration,
}

impl IsolationStore {
	fn new(capacity: usize, ttl: Duration) -> Self {
		assert!(capacity > 0, "isolation store capacity must be positive");
		Self {
			inner: Mutex::new(IsolationStoreInner { entries: HashMap::new() }),
			capacity,
			ttl,
		}
	}

	fn material_for(&self, identity: &str) -> IsolationMaterial {
		self.material_for_at(identity, StdInstant::now())
	}

	fn material_for_at(&self, identity: &str, now: StdInstant) -> IsolationMaterial {
		let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		inner.entries.retain(|_, entry| entry.expires_at > now);
		if let Some(entry) = inner.entries.get_mut(identity) {
			entry.last_used = now;
			entry.expires_at = now + self.ttl;
			return entry.material;
		}

		if inner.entries.len() >= self.capacity {
			let oldest = inner
				.entries
				.iter()
				.min_by_key(|(_, entry)| entry.last_used)
				.map(|(identity, _)| identity.clone());
			if let Some(oldest) = oldest {
				inner.entries.remove(&oldest);
			}
		}

		let material = IsolationMaterial {
			token: IsolationToken::new(),
			group_key: ISOLATION_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed),
		};
		inner.entries.insert(identity.to_owned(), IsolationEntry {
			material,
			last_used: now,
			expires_at: now + self.ttl,
		});
		material
	}

	fn put(&self, identity: &str, token: IsolationToken, ttl: Option<Duration>) {
		let now = StdInstant::now();
		let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		inner.entries.retain(|_, entry| entry.expires_at > now);
		if !inner.entries.contains_key(identity) && inner.entries.len() >= self.capacity {
			let oldest = inner
				.entries
				.iter()
				.min_by_key(|(_, entry)| entry.last_used)
				.map(|(identity, _)| identity.clone());
			if let Some(oldest) = oldest {
				inner.entries.remove(&oldest);
			}
		}
		let group_key = inner
			.entries
			.get(identity)
			.map(|entry| entry.material.group_key)
			.unwrap_or_else(|| ISOLATION_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed));
		inner.entries.insert(identity.to_owned(), IsolationEntry {
			material: IsolationMaterial { token, group_key },
			last_used: now,
			expires_at: now + ttl.unwrap_or(self.ttl),
		});
	}

	fn rotate(&self, identity: &str) -> IsolationMaterial {
		let token = IsolationToken::new();
		self.put(identity, token, None);
		self.material_for(identity)
	}

	fn len(&self) -> usize {
		let now = StdInstant::now();
		let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		inner.entries.retain(|_, entry| entry.expires_at > now);
		inner.entries.len()
	}
}

#[derive(Clone)]
struct TenantIsolationHasher {
	key: Arc<Zeroizing<[u8; blake3::KEY_LEN]>>,
}

impl TenantIsolationHasher {
	fn new() -> anyhow::Result<Self> {
		let mut key = [0_u8; blake3::KEY_LEN];
		getrandom::fill(&mut key)
			.map_err(|error| anyhow::anyhow!("failed to seed tenant isolation: {error}"))?;
		Ok(Self {
			key: Arc::new(Zeroizing::new(key)),
		})
	}

	fn resolve(
		&self,
		identity: IngressIdentity,
		destination: &str,
		request: IsolationRequest,
	) -> ResolvedIsolation {
		let mut hasher =
			Blake3HashAdapter(blake3::Hasher::new_keyed(self.key.as_ref()));
		hasher.0.update(b"proxy-tenant-isolation-v1\0");
		identity.account_id().hash(&mut hasher);
		identity.workspace_id().hash(&mut hasher);
		destination.hash(&mut hasher);
		request.identity.hash(&mut hasher);
		let strict_nonce = if request.strict {
			Some(ISOLATION_ID_COUNTER.fetch_add(1, Ordering::Relaxed))
		} else {
			None
		};
		strict_nonce.hash(&mut hasher);
		ResolvedIsolation {
			identity: hasher.0.finalize().to_hex().to_string(),
			strict: request.strict,
		}
	}
}

struct Blake3HashAdapter(blake3::Hasher);

impl Hasher for Blake3HashAdapter {
	fn finish(&self) -> u64 {
		let mut bytes = [0_u8; 8];
		bytes.copy_from_slice(&self.0.clone().finalize().as_bytes()[..8]);
		u64::from_le_bytes(bytes)
	}

	fn write(&mut self, bytes: &[u8]) {
		self.0.update(bytes);
	}
}

#[derive(Clone)]
struct AuthenticatedRequestContext {
	scope: AccountRequestScope,
	isolation: IsolationRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountRequestScope {
	identity: IngressIdentity,
	period_start: UnixTimestamp,
}

struct DownstreamContextEntry {
	generation: u64,
	context: AuthenticatedRequestContext,
}

struct AuthenticatedDownstreamStore {
	entries: Mutex<HashMap<SocketAddr, DownstreamContextEntry>>,
	capacity: usize,
	sequence: AtomicU64,
}

impl AuthenticatedDownstreamStore {
	fn new(capacity: usize) -> Self {
		assert!(capacity > 0, "authenticated downstream capacity must be positive");
		Self {
			entries: Mutex::new(HashMap::new()),
			capacity,
			sequence: AtomicU64::new(1),
		}
	}

	fn register(
		self: &Arc<Self>,
		address: SocketAddr,
		context: AuthenticatedRequestContext,
	) -> anyhow::Result<AuthenticatedDownstreamGuard> {
		let generation = self.sequence.fetch_add(1, Ordering::Relaxed);
		let mut entries = self
			.entries
			.lock()
			.map_err(|_| anyhow::anyhow!("authenticated downstream store is unavailable"))?;
		if entries.len() >= self.capacity && !entries.contains_key(&address) {
			anyhow::bail!("authenticated downstream store capacity reached");
		}
		if entries
			.insert(address, DownstreamContextEntry { generation, context })
			.is_some()
		{
			anyhow::bail!("duplicate authenticated downstream address");
		}
		Ok(AuthenticatedDownstreamGuard {
			store: Arc::clone(self),
			address,
			generation,
		})
	}

	fn context(&self, address: &SocketAddr) -> Option<AuthenticatedRequestContext> {
		self.entries
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(address)
			.map(|entry| entry.context.clone())
	}

	fn remove(&self, address: SocketAddr, generation: u64) {
		let mut entries = self
			.entries
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		if entries
			.get(&address)
			.is_some_and(|entry| entry.generation == generation)
		{
			entries.remove(&address);
		}
	}
}

struct AuthenticatedDownstreamGuard {
	store: Arc<AuthenticatedDownstreamStore>,
	address: SocketAddr,
	generation: u64,
}

impl Drop for AuthenticatedDownstreamGuard {
	fn drop(&mut self) {
		self.store.remove(self.address, self.generation);
	}
}

struct BridgeIdentityRegistry {
	entries: Mutex<HashMap<String, AccountRequestScope>>,
	capacity: usize,
}

impl BridgeIdentityRegistry {
	fn new(capacity: usize) -> Self {
		assert!(capacity > 0, "bridge identity capacity must be positive");
		Self {
			entries: Mutex::new(HashMap::new()),
			capacity,
		}
	}

	fn issue(
		self: &Arc<Self>,
		scope: AccountRequestScope,
	) -> anyhow::Result<BridgeIdentityLease> {
		for _ in 0..4 {
			let mut bytes = Zeroizing::new([0_u8; 24]);
			getrandom::fill(bytes.as_mut())
				.map_err(|error| anyhow::anyhow!("failed to create bridge identity lease: {error}"))?;
			let token = URL_SAFE_NO_PAD.encode(bytes.as_ref());
			let mut entries = self
				.entries
				.lock()
				.map_err(|_| anyhow::anyhow!("bridge identity registry is unavailable"))?;
			if entries.len() >= self.capacity {
				anyhow::bail!("bridge identity registry capacity reached");
			}
			if entries.insert(token.clone(), scope).is_none() {
				return Ok(BridgeIdentityLease {
					registry: Arc::clone(self),
					token,
				});
			}
		}
		anyhow::bail!("failed to allocate a unique bridge identity lease")
	}

	fn resolve(&self, token: &str) -> Option<AccountRequestScope> {
		self.entries
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(token)
			.copied()
	}

	fn remove(&self, token: &str) {
		self.entries
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.remove(token);
	}
}

struct BridgeIdentityLease {
	registry: Arc<BridgeIdentityRegistry>,
	token: String,
}

impl BridgeIdentityLease {
	fn token(&self) -> &str {
		&self.token
	}
}

impl Drop for BridgeIdentityLease {
	fn drop(&mut self) {
		self.registry.remove(&self.token);
		self.token.zeroize();
	}
}

#[derive(Clone)]
struct AuthenticatedIngressRuntime {
	accounts: Arc<AccountManager>,
	downstream_contexts: Arc<AuthenticatedDownstreamStore>,
	bridge_identities: Arc<BridgeIdentityRegistry>,
	isolation_hasher: TenantIsolationHasher,
	usage_period: Duration,
}

impl AuthenticatedIngressRuntime {
	fn period_start(&self) -> Result<UnixTimestamp, account_management::AccountManagementError> {
		UnixTimestamp::period_start_now(self.usage_period)
	}
}

#[derive(Clone)]
enum PublicIngressRuntime {
	Development {
		listen_addr: SocketAddr,
	},
	AuthenticatedTls {
		listen_addr: SocketAddr,
		acceptor: TlsAcceptor,
		handshake_timeout: Duration,
		first_request_timeout: Duration,
		handshake_semaphore: Arc<Semaphore>,
		max_client_connections: usize,
		authentication: AuthenticatedIngressRuntime,
	},
}

impl PublicIngressRuntime {
	fn listen_addr(&self) -> SocketAddr {
		match self {
			Self::Development { listen_addr }
			| Self::AuthenticatedTls { listen_addr, .. } => *listen_addr,
		}
	}

	fn max_client_connections(&self) -> usize {
		match self {
			Self::Development { .. } => MAX_CONNECTION_TASKS,
			Self::AuthenticatedTls {
				max_client_connections,
				..
			} => *max_client_connections,
		}
	}

	fn authentication(&self) -> Option<AuthenticatedIngressRuntime> {
		match self {
			Self::Development { .. } => None,
			Self::AuthenticatedTls { authentication, .. } => Some(authentication.clone()),
		}
	}
}

fn configured_public_ingress() -> anyhow::Result<PublicIngressRuntime> {
	match RuntimeIngressConfig::from_environment()? {
		RuntimeIngressConfig::Development { listen_addr } => {
			Ok(PublicIngressRuntime::Development { listen_addr })
		}
		RuntimeIngressConfig::Production {
			tls,
			account_database,
			api_key_hash_key_file,
			max_cached_accounts,
			usage_period,
		} => {
			let server_config = load_server_config(&tls)?;
			let api_key_hasher = ApiKeyHasher::from_key_file(&api_key_hash_key_file)?;
			let accounts = Arc::new(AccountManager::open(
				&account_database,
				api_key_hasher,
				max_cached_accounts,
			)?);
			let bridge_identity_capacity = tls
				.capacity
				.max_client_connections
				.checked_mul(4)
				.ok_or_else(|| anyhow::anyhow!("bridge identity capacity overflow"))?;
			let authentication = AuthenticatedIngressRuntime {
				accounts,
				downstream_contexts: Arc::new(AuthenticatedDownstreamStore::new(
					tls.capacity.max_client_connections,
				)),
				bridge_identities: Arc::new(BridgeIdentityRegistry::new(
					bridge_identity_capacity,
				)),
				isolation_hasher: TenantIsolationHasher::new()?,
				usage_period,
			};
			Ok(PublicIngressRuntime::AuthenticatedTls {
				listen_addr: tls.listen_addr,
				acceptor: TlsAcceptor::from(server_config),
				handshake_timeout: tls.timeouts.tls_handshake,
				first_request_timeout: tls.timeouts.first_request,
				handshake_semaphore: Arc::new(Semaphore::new(
					tls.capacity.max_concurrent_handshakes,
				)),
				max_client_connections: tls.capacity.max_client_connections,
				authentication,
			})
		}
	}
}

#[derive(Clone, Copy)]
struct BreakerEntry {
	failures: usize,
	open_until: Option<StdInstant>,
	last_used: StdInstant,
}

struct CircuitBreaker {
	entries: Mutex<HashMap<String, BreakerEntry>>,
	capacity: usize,
	failure_threshold: usize,
	cooldown: Duration,
}

impl CircuitBreaker {
	fn new(capacity: usize, failure_threshold: usize, cooldown: Duration) -> Self {
		assert!(capacity > 0, "circuit breaker capacity must be positive");
		assert!(failure_threshold > 0, "circuit breaker threshold must be positive");
		Self {
			entries: Mutex::new(HashMap::new()),
			capacity,
			failure_threshold,
			cooldown,
		}
	}

	fn allow(&self, destination: &str) -> bool {
		self.allow_at(destination, StdInstant::now())
	}

	fn allow_at(&self, destination: &str, now: StdInstant) -> bool {
		let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let Some(entry) = entries.get_mut(destination) else {
			return true;
		};
		entry.last_used = now;
		match entry.open_until {
			Some(open_until) if open_until > now => false,
			Some(_) => {
				entry.open_until = None;
				entry.failures = self.failure_threshold.saturating_sub(1);
				true
			}
			None => true,
		}
	}

	fn record_failure(&self, destination: &str) {
		self.record_failure_at(destination, StdInstant::now());
	}

	fn record_failure_at(&self, destination: &str, now: StdInstant) {
		let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if !entries.contains_key(destination) && entries.len() >= self.capacity {
			let oldest = entries
				.iter()
				.min_by_key(|(_, entry)| entry.last_used)
				.map(|(destination, _)| destination.clone());
			if let Some(oldest) = oldest {
				entries.remove(&oldest);
			}
		}
		let entry = entries.entry(destination.to_owned()).or_insert(BreakerEntry {
			failures: 0,
			open_until: None,
			last_used: now,
		});
		entry.failures = entry.failures.saturating_add(1);
		entry.last_used = now;
		if entry.failures >= self.failure_threshold {
			entry.open_until = Some(now + self.cooldown);
		}
	}

	fn record_success(&self, destination: &str) {
		let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		entries.remove(destination);
	}

	fn len(&self) -> usize {
		self.entries
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.len()
	}
}

fn validate_isolation_identity(value: &[u8]) -> anyhow::Result<String> {
	if value.is_empty() || value.len() > MAX_ISOLATION_ID_BYTES {
		anyhow::bail!("isolation identity must contain 1-{MAX_ISOLATION_ID_BYTES} bytes");
	}
	if !value
		.iter()
		.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
	{
		anyhow::bail!("isolation identity contains unsupported characters");
	}
	Ok(std::str::from_utf8(value)?.to_owned())
}

fn parse_isolation_mode(value: &[u8]) -> anyhow::Result<bool> {
	if value.eq_ignore_ascii_case(b"session") {
		Ok(false)
	} else if value.eq_ignore_ascii_case(b"strict") {
		Ok(true)
	} else {
		anyhow::bail!("isolation mode must be session or strict");
	}
}

fn resolve_isolation(request: IsolationRequest) -> ResolvedIsolation {
	let identity = if request.strict {
		format!("strict-{}", ISOLATION_ID_COUNTER.fetch_add(1, Ordering::Relaxed))
	} else {
		request.identity.unwrap_or_else(|| {
			format!("anonymous-{}", ISOLATION_ID_COUNTER.fetch_add(1, Ordering::Relaxed))
		})
	};
	ResolvedIsolation { identity, strict: request.strict }
}

fn no_default_cache_freshness(_status: http::StatusCode) -> Option<Duration> {
	None
}

static CACHE_META_DEFAULTS: CacheMetaDefaults =
	CacheMetaDefaults::new(no_default_cache_freshness, 0, 0);

fn cache() -> &'static MemCache {
	CACHE.get_or_init(MemCache::new)
}

fn cache_lock() -> &'static CacheLock {
	CACHE_LOCK.get_or_init(|| CacheLock::new(CACHE_LOCK_MAX_AGE))
}

fn cache_eviction() -> &'static (dyn EvictionManager + Sync) {
	CACHE_EVICTION.get_or_init(|| {
		LruEvictionManager::with_capacity(CACHE_MAX_BYTES, CACHE_ITEMS_PER_SHARD)
	})
}

fn normalized_authority(
	authority: &http::uri::Authority,
	scheme: &str,
) -> (String, u16) {
	let host = authority
		.host()
		.trim_start_matches('[')
		.trim_end_matches(']')
		.trim_end_matches('.')
		.to_ascii_lowercase();
	let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
	(host, authority.port_u16().unwrap_or(default_port))
}

fn canonical_cache_key_parts(request: &RequestHeader) -> anyhow::Result<(String, String)> {
	let host_header = request
		.headers
		.get(http::header::HOST)
		.and_then(|value| value.to_str().ok())
		.ok_or_else(|| anyhow::anyhow!("request is missing a valid Host header"))?;
	let host_authority = host_header
		.parse::<http::uri::Authority>()
		.map_err(|error| anyhow::anyhow!("invalid Host authority: {error}"))?;

	let scheme = request.uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
	if scheme != "http" && scheme != "https" {
		anyhow::bail!("unsupported URI scheme");
	}
	let (host, port) = normalized_authority(&host_authority, &scheme);

	if let Some(uri_authority) = request.uri.authority() {
		let (uri_host, uri_port) = normalized_authority(uri_authority, &scheme);
		if uri_host != host || uri_port != port {
			anyhow::bail!("absolute-form URI authority disagrees with Host header");
		}
	}

	let path_and_query = request
		.uri
		.path_and_query()
		.map(|value| value.as_str())
		.unwrap_or("/")
		.to_owned();
	Ok((format!("{scheme}://{host}:{port}"), path_and_query))
}

fn request_cache_eligible(request: &RequestHeader) -> bool {
	if request.method != http::Method::GET
		|| request.headers.contains_key(http::header::AUTHORIZATION)
		|| request.headers.contains_key(http::header::COOKIE)
	{
		return false;
	}

	let request_cache_control = CacheControl::from_req_headers(request);
	!request_cache_control
		.as_ref()
		.is_some_and(|cache_control| cache_control.no_store() || cache_control.private())
}

fn conservative_response_cacheable(
	request: &RequestHeader,
	response: &ResponseHeader,
) -> RespCacheable {
	// This cache is deliberately shared across isolation identities for performance. Only
	// explicitly public, non-personalized, non-varying responses can cross that boundary.
	if !request_cache_eligible(request) {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("request-policy"));
	}
	if response.status != http::StatusCode::OK {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("status-policy"));
	}
	if response.headers.contains_key(http::header::SET_COOKIE) {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("set-cookie"));
	}
	// Vary is rejected until variance keys are deliberately implemented.
	if response.headers.contains_key(http::header::VARY) {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("vary-unsupported"));
	}

	let Some(cache_control) = CacheControl::from_resp_headers(response) else {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("explicit-freshness-required"));
	};
	if !cache_control.public() || cache_control.private() || cache_control.no_store() {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("shared-cache-policy"));
	}
	let positive_freshness = cache_control
		.s_maxage()
		.ok()
		.flatten()
		.or_else(|| cache_control.max_age().ok().flatten())
		.is_some_and(|seconds| seconds > 0);
	if !positive_freshness {
		return RespCacheable::Uncacheable(NoCacheReason::Custom("positive-freshness-required"));
	}

	filters::resp_cacheable(
		Some(&cache_control),
		response.clone(),
		false,
		&CACHE_META_DEFAULTS,
	)
}

fn cache_status_header(cache: &HttpCache) -> &'static str {
	match cache.phase() {
		CachePhase::Hit => "HIT",
		CachePhase::Stale | CachePhase::StaleUpdating => "STALE",
		CachePhase::Miss | CachePhase::Expired | CachePhase::Revalidated => "MISS",
		CachePhase::Disabled(_) | CachePhase::Bypass | CachePhase::Uninit | CachePhase::CacheKey
		| CachePhase::RevalidatedNoCache(_) => "BYPASS",
	}
}

struct ParsedProxyRequest {
	method: String,
	destination: Option<String>,
	header_len: usize,
	isolation: IsolationRequest,
	proxy_authorization: Option<Zeroizing<String>>,
	internal_identity: Option<String>,
}

impl fmt::Debug for ParsedProxyRequest {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ParsedProxyRequest")
			.field("method", &self.method)
			.field("destination", &self.destination)
			.field("header_len", &self.header_len)
			.field("isolation", &self.isolation)
			.field(
				"proxy_authorization",
				&self.proxy_authorization.as_ref().map(|_| "[redacted]"),
			)
			.field(
				"internal_identity",
				&self.internal_identity.as_ref().map(|_| "[redacted]"),
			)
			.finish()
	}
}

struct ParsedIngressHeaders {
	isolation: IsolationRequest,
	proxy_authorization: Option<Zeroizing<String>>,
	internal_identity: Option<String>,
}

fn ingress_headers_from_httparse(
	headers: &[httparse::Header<'_>],
) -> anyhow::Result<ParsedIngressHeaders> {
	let mut identity = None;
	let mut strict = false;
	let mut mode_seen = false;
	let mut proxy_authorization = None;
	let mut internal_identity = None;
	for header in headers {
		if header.name.eq_ignore_ascii_case(ISOLATION_HEADER) {
			if identity.is_some() {
				anyhow::bail!("duplicate isolation identity header");
			}
			identity = Some(validate_isolation_identity(header.value)?);
		} else if header.name.eq_ignore_ascii_case(ISOLATION_MODE_HEADER) {
			if mode_seen {
				anyhow::bail!("duplicate isolation mode header");
			}
			strict = parse_isolation_mode(header.value)?;
			mode_seen = true;
		} else if header.name.eq_ignore_ascii_case(PROXY_AUTHORIZATION_HEADER) {
			if proxy_authorization.is_some() {
				anyhow::bail!("duplicate proxy authorization header");
			}
			let value = std::str::from_utf8(header.value)
				.map_err(|_| anyhow::anyhow!("proxy authorization is not valid UTF-8"))?;
			proxy_authorization = Some(Zeroizing::new(value.to_owned()));
		} else if header.name.eq_ignore_ascii_case(INTERNAL_IDENTITY_HEADER) {
			if internal_identity.is_some() {
				anyhow::bail!("duplicate internal identity header");
			}
			internal_identity = Some(validate_isolation_identity(header.value)?);
		}
	}
	Ok(ParsedIngressHeaders {
		isolation: IsolationRequest { identity, strict },
		proxy_authorization,
		internal_identity,
	})
}

fn take_isolation_request(request: &mut RequestHeader) -> anyhow::Result<IsolationRequest> {
	let identity = {
		let mut values = request.headers.get_all(ISOLATION_HEADER).iter();
		let identity = values
			.next()
			.map(|value| validate_isolation_identity(value.as_bytes()))
			.transpose()?;
		if values.next().is_some() {
			anyhow::bail!("duplicate isolation identity header");
		}
		identity
	};
	let strict = {
		let mut values = request.headers.get_all(ISOLATION_MODE_HEADER).iter();
		let strict = values
			.next()
			.map(|value| parse_isolation_mode(value.as_bytes()))
			.transpose()?
			.unwrap_or(false);
		if values.next().is_some() {
			anyhow::bail!("duplicate isolation mode header");
		}
		strict
	};

	request.remove_header(ISOLATION_HEADER);
	request.remove_header(ISOLATION_MODE_HEADER);
	request.remove_header(PROXY_AUTHORIZATION_HEADER);
	request.remove_header(INTERNAL_IDENTITY_HEADER);
	Ok(IsolationRequest { identity, strict })
}

fn parse_proxy_request(buffer: &[u8]) -> anyhow::Result<Option<ParsedProxyRequest>> {
	let mut headers = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
	let mut request = httparse::Request::new(&mut headers);
	let httparse::Status::Complete(header_len) = request
		.parse(buffer)
		.map_err(|error| anyhow::anyhow!("malformed HTTP request: {error}"))?
	else {
		return Ok(None);
	};

	if header_len > MAX_CONNECT_HEADER_BYTES {
		anyhow::bail!("request headers exceed {MAX_CONNECT_HEADER_BYTES} bytes");
	}

	let method = request
		.method
		.filter(|method| !method.is_empty())
		.ok_or_else(|| anyhow::anyhow!("HTTP request is missing a method"))?;
	let destination = if method.eq_ignore_ascii_case("CONNECT") {
		Some(
			request
				.path
				.filter(|destination| !destination.is_empty())
				.ok_or_else(|| anyhow::anyhow!("CONNECT request is missing a destination"))?
				.to_owned()
		)
	} else {
		None
	};
	let ingress_headers = ingress_headers_from_httparse(request.headers)?;

	Ok(Some(ParsedProxyRequest {
		method: method.to_owned(),
		destination,
		header_len,
		isolation: ingress_headers.isolation,
		proxy_authorization: ingress_headers.proxy_authorization,
		internal_identity: ingress_headers.internal_identity,
	}))
}

fn strip_ingress_headers(buffer: &[u8], header_len: usize) -> anyhow::Result<Vec<u8>> {
	if header_len > buffer.len() {
		anyhow::bail!("parsed header length exceeds buffered request");
	}
	let mut headers = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
	let mut parsed = httparse::Request::new(&mut headers);
	let status = parsed
		.parse(&buffer[..header_len])
		.map_err(|error| anyhow::anyhow!("malformed HTTP request: {error}"))?;
	if !status.is_complete() {
		anyhow::bail!("request header unexpectedly became incomplete");
	}
	let method = parsed
		.method
		.ok_or_else(|| anyhow::anyhow!("HTTP request is missing a method"))?;
	let path = parsed
		.path
		.ok_or_else(|| anyhow::anyhow!("HTTP request is missing a target"))?;
	let version = parsed
		.version
		.ok_or_else(|| anyhow::anyhow!("HTTP request is missing a version"))?;

	let mut sanitized = Vec::with_capacity(buffer.len());
	sanitized.extend_from_slice(method.as_bytes());
	sanitized.push(b' ');
	sanitized.extend_from_slice(path.as_bytes());
	sanitized.extend_from_slice(b" HTTP/1.");
	sanitized.extend_from_slice(version.to_string().as_bytes());
	sanitized.extend_from_slice(b"\r\n");
	for header in parsed.headers {
		if header.name.eq_ignore_ascii_case(PROXY_AUTHORIZATION_HEADER)
			|| header.name.eq_ignore_ascii_case(ISOLATION_HEADER)
			|| header.name.eq_ignore_ascii_case(ISOLATION_MODE_HEADER)
			|| header.name.eq_ignore_ascii_case(INTERNAL_IDENTITY_HEADER)
		{
			continue;
		}
		sanitized.extend_from_slice(header.name.as_bytes());
		sanitized.extend_from_slice(b": ");
		sanitized.extend_from_slice(header.value);
		sanitized.extend_from_slice(b"\r\n");
	}
	sanitized.extend_from_slice(b"\r\n");
	sanitized.extend_from_slice(&buffer[header_len..]);
	Ok(sanitized)
}

fn parse_connect_request(buffer: &[u8]) -> anyhow::Result<Option<(String, usize)>> {
	let Some(request) = parse_proxy_request(buffer)? else {
		return Ok(None);
	};
	if !request.method.eq_ignore_ascii_case("CONNECT") {
		anyhow::bail!("expected CONNECT request");
	}

	Ok(Some((request.destination.unwrap(), request.header_len)))
}

fn parse_connect_destination(destination: &str) -> anyhow::Result<TorAddr> {
	let authority = destination
		.parse::<http::uri::Authority>()
		.map_err(|error| anyhow::anyhow!("invalid CONNECT authority {destination:?}: {error}"))?;
	let _port = authority
		.port_u16()
		.filter(|port| *port != 0)
		.ok_or_else(|| anyhow::anyhow!("CONNECT destination requires a non-zero port"))?;
	if authority.host().is_empty() {
		anyhow::bail!("CONNECT destination requires a host");
	}

	TorAddr::from(destination)
		.map_err(|error| anyhow::anyhow!("invalid CONNECT destination {destination:?}: {error}"))
}

fn canonical_connect_destination_key(destination: &str) -> anyhow::Result<String> {
	let authority = destination
		.parse::<http::uri::Authority>()
		.map_err(|error| anyhow::anyhow!("invalid CONNECT authority: {error}"))?;
	let port = authority
		.port_u16()
		.filter(|port| *port != 0)
		.ok_or_else(|| anyhow::anyhow!("CONNECT destination requires a non-zero port"))?;
	let host = authority
		.host()
		.trim_start_matches('[')
		.trim_end_matches(']')
		.trim_end_matches('.')
		.to_ascii_lowercase();
	if host.contains(':') {
		Ok(format!("[{host}]:{port}"))
	} else {
		Ok(format!("{host}:{port}"))
	}
}

fn connect_destination_allowed(destination: &str) -> anyhow::Result<bool> {
	let authority = destination
		.parse::<http::uri::Authority>()
		.map_err(|error| anyhow::anyhow!("invalid CONNECT authority {destination:?}: {error}"))?;
	let host = authority
		.host()
		.trim_start_matches('[')
		.trim_end_matches(']')
		.trim_end_matches('.')
		.to_ascii_lowercase();
	if host == "localhost"
		|| host.ends_with(".localhost")
		|| host.ends_with(".local")
		|| host.ends_with(".internal")
		|| host.ends_with(".home")
		|| host.ends_with(".lan")
	{
		return Ok(false);
	}

	let Ok(address) = host.parse::<IpAddr>() else {
		return Ok(true);
	};
	let allowed = match address {
		IpAddr::V4(address) => {
			!address.is_private()
				&& !address.is_loopback()
				&& !address.is_link_local()
				&& !address.is_broadcast()
				&& !address.is_unspecified()
				&& !address.is_multicast()
		}
		IpAddr::V6(address) => {
			!address.is_loopback()
				&& !address.is_unspecified()
				&& !address.is_multicast()
				&& !address.is_unique_local()
				&& !address.is_unicast_link_local()
		}
	};
	Ok(allowed)
}

async fn read_proxy_request<S>(stream: &mut S) -> anyhow::Result<(ParsedProxyRequest, Vec<u8>)>
where
	S: tokio::io::AsyncRead + Unpin,
{
	let mut buffer = Vec::with_capacity(1024);
	let mut chunk = [0_u8; 1024];

	loop {
		if let Some(request) = parse_proxy_request(&buffer)? {
			return Ok((request, buffer));
		}
		if buffer.len() == MAX_CONNECT_HEADER_BYTES {
			anyhow::bail!("request headers exceed {MAX_CONNECT_HEADER_BYTES} bytes");
		}

		let remaining = MAX_CONNECT_HEADER_BYTES - buffer.len();
		let read_capacity = remaining.min(chunk.len());
		let read = stream.read(&mut chunk[..read_capacity]).await?;
		if read == 0 {
			anyhow::bail!("connection closed before a complete HTTP request was received");
		}
		buffer.extend_from_slice(&chunk[..read]);
	}
}

async fn read_connect_request<S>(
	stream: &mut S,
) -> anyhow::Result<(String, IsolationRequest, Option<String>, Vec<u8>)>
where
	S: tokio::io::AsyncRead + Unpin,
{
	let (request, buffer) = read_proxy_request(stream).await?;
	if !request.method.eq_ignore_ascii_case("CONNECT") {
		anyhow::bail!("expected CONNECT request");
	}
	Ok((
		request.destination.unwrap(),
		request.isolation,
		request.internal_identity,
		buffer[request.header_len..].to_vec(),
	))
}

pub struct Proxy{
	request_counter: AtomicUsize,
	cache: Arc<IsolationStore>,
	metrics: Arc<CircuitMetrics>,
	authentication: Option<AuthenticatedIngressRuntime>,
	//isolation_manager: IsolationHelper,
	tor_client: Arc<TorClient<PreferredRuntime>>
}

pub struct RequestCtx{
	id: Option<i64>,
	account_id: Option<AccountId>,
	ingress_identity: Option<IngressIdentity>,
	usage_period_start: Option<UnixTimestamp>,
	bridge_identity_lease: Option<BridgeIdentityLease>,
	token: IsolationToken,
	isolation_identity: String,
	isolation_group_key: u64,
	strict_isolation: bool,
	request_started: tokio::time::Instant,
	cache_started: Option<tokio::time::Instant>,
	cache_lock_recorded: bool,
}

//pub struct RateLimitGuard {
//	semaphore: Arc<Semaphore>, 
//	permit: SemaphorePermit<'static>
//}

/// Owns one global circuit-build admission slot.
///
/// This is deliberately not a per-account request-rate limiter. The owned
/// permit makes release cancellation-safe: every return path, panic unwind,
/// or aborted connection task releases the slot when this guard is dropped.
#[must_use = "dropping the rate-limit guard immediately releases its circuit-build slot"]
#[derive(Debug)]
pub struct RateLimitGuard {
	_permit: OwnedSemaphorePermit,
}

impl From<OwnedSemaphorePermit> for RateLimitGuard {
	fn from(permit: OwnedSemaphorePermit) -> Self {
		Self { _permit: permit }
	}
}

pub struct CircuitHandle<'session, Phase> {
	token: IsolationToken,
	phase: PhantomData<Phase>,
	lifetime: PhantomData<&'session ()>
	// guard: RateLimitGuard
}

const LATENCY_BUCKET_MICROS: [u64; 10] = [
	5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 5_000_000,
	30_000_000,
];

struct LatencyHistogram {
	buckets: [AtomicU64; LATENCY_BUCKET_MICROS.len()],
	count: AtomicU64,
	sum_micros: AtomicU64,
}

impl Default for LatencyHistogram {
	fn default() -> Self {
		Self {
			buckets: std::array::from_fn(|_| AtomicU64::new(0)),
			count: AtomicU64::new(0),
			sum_micros: AtomicU64::new(0),
		}
	}
}

impl LatencyHistogram {
	fn observe(&self, latency: Duration) {
		let micros = latency.as_micros().min(u64::MAX as u128) as u64;
		for (index, upper_bound) in LATENCY_BUCKET_MICROS.iter().enumerate() {
			if micros <= *upper_bound {
				self.buckets[index].fetch_add(1, Ordering::Relaxed);
			}
		}
		self.count.fetch_add(1, Ordering::Relaxed);
		self.sum_micros.fetch_add(micros, Ordering::Relaxed);
	}
}

#[derive(Default)]
struct CircuitMetrics {
	acquire_timeouts: AtomicUsize,
	circuit_build_count: AtomicU64,
	circuit_build_latency_micros: AtomicU64,
	queued_circuit_builds: AtomicUsize,
	active_tunnels: AtomicUsize,
	queued_tunnels: AtomicUsize,
	rejected_tunnels: AtomicUsize,
	completed_tunnels: AtomicUsize,
	connect_timeouts: AtomicUsize,
	idle_timeouts: AtomicUsize,
	retries: AtomicUsize,
	breaker_rejections: AtomicUsize,
	bytes_to_tor: AtomicU64,
	bytes_from_tor: AtomicU64,
	request_counts: Mutex<HashMap<(String, u16), u64>>,
	arti_failures: Mutex<HashMap<&'static str, u64>>,
	request_latency: LatencyHistogram,
	tunnel_latency: LatencyHistogram,
	tor_connect_latency: LatencyHistogram,
	cache_lock_wait: LatencyHistogram,
	request_errors: AtomicU64,
	cache_hits: AtomicU64,
	cache_misses: AtomicU64,
	cache_stale_hits: AtomicU64,
	cache_bypasses: AtomicU64,
	cache_insertions: AtomicU64,
	upstream_reused: AtomicU64,
	upstream_fresh: AtomicU64,
	bridge_tasks_active: AtomicUsize,
	bridge_tasks_completed: AtomicU64,
	bridge_tasks_failed: AtomicU64,
	bridge_tasks_deadline_cancelled: AtomicU64,
	bridge_tasks_force_aborted: AtomicU64,
}

impl CircuitMetrics {
	fn record_build_latency(&self, latency: Duration) {
		let latency_micros = latency.as_micros().min(u64::MAX as u128) as u64;
		self.circuit_build_latency_micros.fetch_add(latency_micros, Ordering::Relaxed);
		self.circuit_build_count.fetch_add(1, Ordering::Relaxed);
		self.tor_connect_latency.observe(latency);
	}

	fn record_request(&self, method: &str, status: u16, latency: Duration) {
		let method = match method {
			"GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT" => method,
			_ => "OTHER",
		};
		let mut counts = self.request_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		*counts.entry((method.to_owned(), status)).or_insert(0) += 1;
		drop(counts);
		self.request_latency.observe(latency);
	}

	fn record_arti_failure(&self, class: &'static str) {
		let mut failures = self.arti_failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		*failures.entry(class).or_insert(0) += 1;
	}

	fn log(&self, circuit_semaphore: &Semaphore) {
		let permits_in_use = MAX_CONCURRENT_CIRCUIT_BUILDS
			.saturating_sub(circuit_semaphore.available_permits());
		let acquire_timeouts = self.acquire_timeouts.load(Ordering::Relaxed);
		let circuit_build_count = self.circuit_build_count.load(Ordering::Relaxed);
		let total_latency_micros = self.circuit_build_latency_micros.load(Ordering::Relaxed);
		let average_latency_ms = if circuit_build_count == 0 {
			0.0
		} else {
			total_latency_micros as f64 / circuit_build_count as f64 / 1_000.0
		};
		let active_tunnels = self.active_tunnels.load(Ordering::Relaxed);
		let queued_tunnels = self.queued_tunnels.load(Ordering::Relaxed);
		let queued_circuit_builds = self.queued_circuit_builds.load(Ordering::Relaxed);
		let rejected_tunnels = self.rejected_tunnels.load(Ordering::Relaxed);
		let completed_tunnels = self.completed_tunnels.load(Ordering::Relaxed);

		eprintln!(
			"[bridge] circuit metrics: permits_in_use={permits_in_use} queued_circuit_builds={queued_circuit_builds} active_tunnels={active_tunnels} queued_tunnels={queued_tunnels} rejected_tunnels={rejected_tunnels} completed_tunnels={completed_tunnels} acquire_timeouts={acquire_timeouts} circuit_build_count={circuit_build_count} average_build_latency_ms={average_latency_ms:.2}"
		);
	}
}

struct AtomicGaugeGuard<'a> {
	counter: &'a AtomicUsize,
}

impl<'a> AtomicGaugeGuard<'a> {
	fn increment(counter: &'a AtomicUsize) -> Self {
		counter.fetch_add(1, Ordering::Relaxed);
		Self { counter }
	}
}

impl Drop for AtomicGaugeGuard<'_> {
	fn drop(&mut self) {
		self.counter.fetch_sub(1, Ordering::Relaxed);
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BridgeTaskDrainConfig {
	drain_timeout: Duration,
	force_stop_timeout: Duration,
}

impl BridgeTaskDrainConfig {
	fn new(drain_timeout: Duration, force_stop_timeout: Duration) -> anyhow::Result<Self> {
		if drain_timeout.is_zero() {
			anyhow::bail!("bridge task drain timeout must be positive");
		}
		if force_stop_timeout.is_zero() {
			anyhow::bail!("bridge task force-stop timeout must be positive");
		}
		if drain_timeout > Duration::from_secs(MAX_BRIDGE_TASK_SHUTDOWN_SECONDS) {
			anyhow::bail!(
				"bridge task drain timeout cannot exceed {MAX_BRIDGE_TASK_SHUTDOWN_SECONDS} seconds"
			);
		}
		if force_stop_timeout > Duration::from_secs(MAX_BRIDGE_TASK_SHUTDOWN_SECONDS) {
			anyhow::bail!(
				"bridge task force-stop timeout cannot exceed {MAX_BRIDGE_TASK_SHUTDOWN_SECONDS} seconds"
			);
		}
		Ok(Self { drain_timeout, force_stop_timeout })
	}

	fn from_environment() -> anyhow::Result<Self> {
		let drain_seconds = shutdown_seconds_from_environment(
			"PROXY_SHUTDOWN_DRAIN_SECONDS",
			DEFAULT_BRIDGE_TASK_DRAIN_SECONDS,
		)?;
		let force_stop_seconds = shutdown_seconds_from_environment(
			"PROXY_SHUTDOWN_FORCE_STOP_SECONDS",
			DEFAULT_BRIDGE_TASK_FORCE_STOP_SECONDS,
		)?;
		Self::new(
			Duration::from_secs(drain_seconds),
			Duration::from_secs(force_stop_seconds),
		)
	}

	fn pingora_grace_period_seconds(&self) -> anyhow::Result<u64> {
		self.drain_timeout
			.as_secs()
			.checked_add(self.force_stop_timeout.as_secs())
			.and_then(|seconds| seconds.checked_add(SHUTDOWN_GRACE_MARGIN_SECONDS))
			.ok_or_else(|| anyhow::anyhow!("bridge shutdown budget exceeds the supported range"))
	}
}

fn shutdown_seconds_from_environment(name: &str, default: u64) -> anyhow::Result<u64> {
	match std::env::var(name) {
		Ok(raw) => {
			let seconds = raw
				.parse::<u64>()
				.map_err(|_| anyhow::anyhow!("{name} must be a positive integer number of seconds"))?;
			if seconds == 0 || seconds > MAX_BRIDGE_TASK_SHUTDOWN_SECONDS {
				anyhow::bail!(
					"{name} must be between 1 and {MAX_BRIDGE_TASK_SHUTDOWN_SECONDS} seconds"
				);
			}
			Ok(seconds)
		}
		Err(std::env::VarError::NotPresent) => Ok(default),
		Err(std::env::VarError::NotUnicode(_)) => {
			anyhow::bail!("{name} must contain valid Unicode")
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeTaskKind {
	Metrics,
	Internal,
	Public,
}

impl BridgeTaskKind {
	fn as_str(self) -> &'static str {
		match self {
			Self::Metrics => "metrics",
			Self::Internal => "internal",
			Self::Public => "public",
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeTaskOutcome {
	Completed(BridgeTaskKind),
	Failed(BridgeTaskKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeTaskCompletion {
	Completed,
	Failed,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BridgeDrainSummary {
	completed: usize,
	failed: usize,
	deadline_cancelled: usize,
	force_aborted: usize,
	deadline_reached: bool,
	termination_confirmed: bool,
	elapsed: Duration,
}

impl BridgeDrainSummary {
	fn observe(&mut self, completion: BridgeTaskCompletion) {
		match completion {
			BridgeTaskCompletion::Completed => self.completed = self.completed.saturating_add(1),
			BridgeTaskCompletion::Failed => self.failed = self.failed.saturating_add(1),
		}
	}
}

struct BridgeTaskGaugeGuard {
	metrics: Arc<CircuitMetrics>,
}

impl BridgeTaskGaugeGuard {
	fn increment(metrics: Arc<CircuitMetrics>) -> Self {
		metrics.bridge_tasks_active.fetch_add(1, Ordering::Relaxed);
		Self { metrics }
	}
}

impl Drop for BridgeTaskGaugeGuard {
	fn drop(&mut self) {
		self.metrics.bridge_tasks_active.fetch_sub(1, Ordering::Relaxed);
	}
}

struct BridgeTaskRegistry {
	tasks: JoinSet<BridgeTaskOutcome>,
	metrics: Arc<CircuitMetrics>,
}

impl BridgeTaskRegistry {
	fn new(metrics: Arc<CircuitMetrics>) -> Self {
		Self {
			tasks: JoinSet::new(),
			metrics,
		}
	}

	fn spawn<F>(&mut self, kind: BridgeTaskKind, task: F)
	where
		F: Future<Output = anyhow::Result<()>> + Send + 'static,
	{
		let active_guard = BridgeTaskGaugeGuard::increment(self.metrics.clone());
		self.tasks.spawn(async move {
			let _active_guard = active_guard;
			match task.await {
				Ok(()) => BridgeTaskOutcome::Completed(kind),
				Err(_) => BridgeTaskOutcome::Failed(kind),
			}
		});
	}

	fn is_empty(&self) -> bool {
		self.tasks.is_empty()
	}

	async fn join_next(&mut self) -> Option<Result<BridgeTaskOutcome, JoinError>> {
		self.tasks.join_next().await
	}

	fn record_join(
		&self,
		joined: Result<BridgeTaskOutcome, JoinError>,
	) -> BridgeTaskCompletion {
		match joined {
			Ok(BridgeTaskOutcome::Completed(_kind)) => {
				self.metrics.bridge_tasks_completed.fetch_add(1, Ordering::Relaxed);
				BridgeTaskCompletion::Completed
			}
			Ok(BridgeTaskOutcome::Failed(kind)) => {
				self.metrics.bridge_tasks_failed.fetch_add(1, Ordering::Relaxed);
				eprintln!(
					"{{\"event\":\"bridge_task\",\"kind\":\"{}\",\"outcome\":\"failed\"}}",
					kind.as_str()
				);
				BridgeTaskCompletion::Failed
			}
			Err(error) => {
				self.metrics.bridge_tasks_failed.fetch_add(1, Ordering::Relaxed);
				let reason = if error.is_panic() { "panic" } else { "cancelled" };
				eprintln!(
					"{{\"event\":\"bridge_task\",\"kind\":\"unknown\",\"outcome\":\"failed\",\"reason\":\"{reason}\"}}"
				);
				BridgeTaskCompletion::Failed
			}
		}
	}

	async fn drain(&mut self, config: BridgeTaskDrainConfig) -> BridgeDrainSummary {
		let started = tokio::time::Instant::now();
		let mut summary = BridgeDrainSummary {
			termination_confirmed: true,
			..BridgeDrainSummary::default()
		};
		while let Some(joined) = self.tasks.try_join_next() {
			summary.observe(self.record_join(joined));
		}
		if self.tasks.is_empty() {
			summary.elapsed = started.elapsed();
			return summary;
		}

		let drain_deadline = tokio::time::sleep(config.drain_timeout);
		tokio::pin!(drain_deadline);
		loop {
			if self.tasks.is_empty() {
				break;
			}
			tokio::select! {
				biased;
				joined = self.tasks.join_next() => {
					if let Some(joined) = joined {
						summary.observe(self.record_join(joined));
					}
				}
				_ = &mut drain_deadline => {
					summary.deadline_reached = true;
					break;
				}
			}
		}

		while let Some(joined) = self.tasks.try_join_next() {
			summary.observe(self.record_join(joined));
		}
		if !self.tasks.is_empty() {
			summary.deadline_cancelled = self.tasks.len();
			self.metrics.bridge_tasks_deadline_cancelled.fetch_add(
				summary.deadline_cancelled as u64,
				Ordering::Relaxed,
			);
			self.tasks.abort_all();
			let termination = async {
				while self.tasks.join_next().await.is_some() {}
			};
			if tokio::time::timeout(config.force_stop_timeout, termination)
				.await
				.is_err()
			{
				summary.force_aborted = self.tasks.len();
				summary.termination_confirmed = false;
				self.metrics.bridge_tasks_force_aborted.fetch_add(
					summary.force_aborted as u64,
					Ordering::Relaxed,
				);
			}
		}
		summary.elapsed = started.elapsed();
		summary
	}
}

fn arti_error_class(error: &arti_client::Error) -> &'static str {
	match error.kind() {
		ErrorKind::RemoteNetworkTimeout | ErrorKind::ExitTimeout => "timeout",
		ErrorKind::RemoteConnectionRefused => "connection_refused",
		ErrorKind::RemoteHostNotFound => "dns",
		ErrorKind::ExitPolicyRejected => "exit_policy",
		ErrorKind::TorAccessFailed | ErrorKind::BootstrapRequired | ErrorKind::DirectoryExpired => "tor_health",
		ErrorKind::RemoteStreamError | ErrorKind::RemoteStreamReset | ErrorKind::RemoteNetworkFailed => "stream",
		_ => "other",
	}
}

fn append_histogram_metrics(
	output: &mut String,
	name: &str,
	help: &str,
	histogram: &LatencyHistogram,
) {
	use std::fmt::Write as _;
	let _ = writeln!(output, "# HELP {name} {help}");
	let _ = writeln!(output, "# TYPE {name} histogram");
	for (index, upper_bound_micros) in LATENCY_BUCKET_MICROS.iter().enumerate() {
		let upper_bound_seconds = *upper_bound_micros as f64 / 1_000_000.0;
		let count = histogram.buckets[index].load(Ordering::Relaxed);
		let _ = writeln!(output, "{name}_bucket{{le=\"{upper_bound_seconds}\"}} {count}");
	}
	let count = histogram.count.load(Ordering::Relaxed);
	let sum_seconds = histogram.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
	let _ = writeln!(output, "{name}_bucket{{le=\"+Inf\"}} {count}");
	let _ = writeln!(output, "{name}_sum {sum_seconds}");
	let _ = writeln!(output, "{name}_count {count}");
}

fn render_prometheus_metrics(
	metrics: &CircuitMetrics,
	token_store: &IsolationStore,
	circuit_breaker: &CircuitBreaker,
) -> String {
	use std::fmt::Write as _;
	let mut output = String::with_capacity(8 * 1024);
	output.push_str("# HELP proxy_requests_total Completed public proxy requests.\n");
	output.push_str("# TYPE proxy_requests_total counter\n");
	let mut request_counts: Vec<_> = metrics
		.request_counts
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
		.iter()
		.map(|((method, status), count)| (method.clone(), *status, *count))
		.collect();
	request_counts.sort_unstable();
	for (method, status, count) in request_counts {
		let _ = writeln!(
			output,
			"proxy_requests_total{{method=\"{method}\",status=\"{status}\"}} {count}"
		);
	}
	append_histogram_metrics(
		&mut output,
		"proxy_request_duration_seconds",
		"End-to-end request latency.",
		&metrics.request_latency,
	);
	append_histogram_metrics(
		&mut output,
		"proxy_tunnel_duration_seconds",
		"CONNECT tunnel lifetime.",
		&metrics.tunnel_latency,
	);
	append_histogram_metrics(
		&mut output,
		"proxy_tor_connect_duration_seconds",
		"Tor stream establishment latency.",
		&metrics.tor_connect_latency,
	);
	append_histogram_metrics(
		&mut output,
		"proxy_cache_lock_wait_seconds",
		"Time from cache enablement until an upstream fetch is selected.",
		&metrics.cache_lock_wait,
	);

	macro_rules! metric {
		($name:literal, $help:literal, $kind:literal, $value:expr) => {{
			let _ = writeln!(output, concat!("# HELP ", $name, " ", $help));
			let _ = writeln!(output, concat!("# TYPE ", $name, " ", $kind));
			let _ = writeln!(output, "{} {}", $name, $value);
		}};
	}
	metric!("proxy_active_tunnels", "Currently active Tor tunnels.", "gauge", metrics.active_tunnels.load(Ordering::Relaxed));
	metric!("proxy_queued_tunnels", "Requests waiting for tunnel capacity.", "gauge", metrics.queued_tunnels.load(Ordering::Relaxed));
	metric!("proxy_queued_circuit_builds", "Requests waiting for circuit-build capacity.", "gauge", metrics.queued_circuit_builds.load(Ordering::Relaxed));
	metric!("proxy_circuit_acquire_timeouts_total", "Requests that timed out waiting for circuit-build capacity.", "counter", metrics.acquire_timeouts.load(Ordering::Relaxed));
	metric!("proxy_circuit_build_attempts_total", "Completed Tor circuit or stream establishment attempts.", "counter", metrics.circuit_build_count.load(Ordering::Relaxed));
	metric!("proxy_circuit_build_latency_microseconds_total", "Cumulative Tor circuit or stream establishment latency in microseconds.", "counter", metrics.circuit_build_latency_micros.load(Ordering::Relaxed));
	metric!("proxy_rejected_tunnels_total", "Tunnel and connection capacity rejections.", "counter", metrics.rejected_tunnels.load(Ordering::Relaxed));
	metric!("proxy_completed_tunnels_total", "Tunnel attempts that acquired active capacity.", "counter", metrics.completed_tunnels.load(Ordering::Relaxed));
	metric!("proxy_connect_timeouts_total", "Tor establishment timeouts.", "counter", metrics.connect_timeouts.load(Ordering::Relaxed));
	metric!("proxy_idle_timeouts_total", "Inactive tunnel timeouts.", "counter", metrics.idle_timeouts.load(Ordering::Relaxed));
	metric!("proxy_request_errors_total", "HTTP requests ending with an internal error.", "counter", metrics.request_errors.load(Ordering::Relaxed));
	metric!("proxy_retries_total", "Tor connection retries.", "counter", metrics.retries.load(Ordering::Relaxed));
	metric!("proxy_circuit_breaker_rejections_total", "Requests rejected by an open circuit breaker.", "counter", metrics.breaker_rejections.load(Ordering::Relaxed));
	metric!("proxy_bytes_to_tor_total", "Payload bytes sent toward Tor.", "counter", metrics.bytes_to_tor.load(Ordering::Relaxed));
	metric!("proxy_bytes_from_tor_total", "Payload bytes received from Tor.", "counter", metrics.bytes_from_tor.load(Ordering::Relaxed));
	metric!("proxy_cache_hits_total", "Fresh shared-cache hits.", "counter", metrics.cache_hits.load(Ordering::Relaxed));
	metric!("proxy_cache_misses_total", "Shared-cache misses.", "counter", metrics.cache_misses.load(Ordering::Relaxed));
	metric!("proxy_cache_stale_hits_total", "Stale shared-cache hits.", "counter", metrics.cache_stale_hits.load(Ordering::Relaxed));
	metric!("proxy_cache_bypasses_total", "Requests bypassing shared cache.", "counter", metrics.cache_bypasses.load(Ordering::Relaxed));
	metric!("proxy_cache_insertions_total", "Responses accepted by cache admission policy.", "counter", metrics.cache_insertions.load(Ordering::Relaxed));
	metric!("proxy_cache_entries", "Assets tracked by cache eviction.", "gauge", cache_eviction().total_items());
	metric!("proxy_cache_bytes", "Bytes tracked by cache eviction.", "gauge", cache_eviction().total_size());
	metric!("proxy_cache_evictions_total", "Assets evicted by the LRU manager.", "counter", cache_eviction().evicted_items());
	metric!("proxy_cache_evicted_bytes_total", "Bytes evicted by the LRU manager.", "counter", cache_eviction().evicted_size());
	metric!("proxy_upstream_connections_reused_total", "HTTP requests reusing an upstream connection.", "counter", metrics.upstream_reused.load(Ordering::Relaxed));
	metric!("proxy_upstream_connections_fresh_total", "HTTP requests using a newly established upstream connection.", "counter", metrics.upstream_fresh.load(Ordering::Relaxed));
	metric!("proxy_bridge_tasks_active", "Currently owned bridge connection tasks.", "gauge", metrics.bridge_tasks_active.load(Ordering::Relaxed));
	metric!("proxy_bridge_tasks_completed_total", "Owned bridge tasks that completed normally.", "counter", metrics.bridge_tasks_completed.load(Ordering::Relaxed));
	metric!("proxy_bridge_tasks_failed_total", "Owned bridge tasks that failed or panicked.", "counter", metrics.bridge_tasks_failed.load(Ordering::Relaxed));
	metric!("proxy_bridge_tasks_deadline_cancelled_total", "Owned bridge tasks cancelled at the natural drain deadline.", "counter", metrics.bridge_tasks_deadline_cancelled.load(Ordering::Relaxed));
	metric!("proxy_bridge_tasks_force_aborted_total", "Owned bridge tasks whose termination exceeded the force-stop timeout.", "counter", metrics.bridge_tasks_force_aborted.load(Ordering::Relaxed));
	metric!("proxy_isolation_tokens", "Current bounded isolation-token entries.", "gauge", token_store.len());
	metric!("proxy_circuit_breaker_entries", "Current destination circuit-breaker entries.", "gauge", circuit_breaker.len());

	output.push_str("# HELP proxy_arti_failures_total Tor connection failures by stable class.\n");
	output.push_str("# TYPE proxy_arti_failures_total counter\n");
	let mut failures: Vec<_> = metrics
		.arti_failures
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
		.iter()
		.map(|(class, count)| (*class, *count))
		.collect();
	failures.sort_unstable();
	for (class, count) in failures {
		let _ = writeln!(output, "proxy_arti_failures_total{{class=\"{class}\"}} {count}");
	}
	output
}

async fn serve_prometheus_connection<S>(
	mut stream: S,
	metrics: Arc<CircuitMetrics>,
	token_store: Arc<IsolationStore>,
	circuit_breaker: Arc<CircuitBreaker>,
) -> io::Result<()>
where
	S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let mut request = Vec::with_capacity(512);
	let mut chunk = [0_u8; 512];
	while request.len() < 4 * 1024 && !request.windows(4).any(|window| window == b"\r\n\r\n") {
		let read = stream.read(&mut chunk).await?;
		if read == 0 {
			return Ok(());
		}
		request.extend_from_slice(&chunk[..read]);
	}
	let metrics_request = request.starts_with(b"GET /metrics ");
	let (status, body) = if metrics_request {
		("200 OK", render_prometheus_metrics(&metrics, &token_store, &circuit_breaker))
	} else {
		("404 Not Found", "not found\n".to_owned())
	};
	let response = format!(
		"HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	);
	stream.write_all(response.as_bytes()).await?;
	stream.shutdown().await
}

struct ActiveTunnelPermit {
	_permit: OwnedSemaphorePermit,
	metrics: Arc<CircuitMetrics>,
}

impl Drop for ActiveTunnelPermit {
	fn drop(&mut self) {
		self.metrics.active_tunnels.fetch_sub(1, Ordering::Relaxed);
		self.metrics.completed_tunnels.fetch_add(1, Ordering::Relaxed);
	}
}

struct TunnelObservation {
	metrics: Arc<CircuitMetrics>,
	started: tokio::time::Instant,
	status: u16,
	error_class: &'static str,
	count_as_public_request: bool,
}

impl TunnelObservation {
	fn new(metrics: Arc<CircuitMetrics>, count_as_public_request: bool) -> Self {
		Self {
			metrics,
			started: tokio::time::Instant::now(),
			status: 500,
			error_class: "internal",
			count_as_public_request,
		}
	}

	fn finish(&mut self, status: u16, error_class: &'static str) {
		self.status = status;
		self.error_class = error_class;
	}
}

impl Drop for TunnelObservation {
	fn drop(&mut self) {
		let latency = self.started.elapsed();
		if self.count_as_public_request {
			self.metrics.record_request("CONNECT", self.status, latency);
		}
		self.metrics.tunnel_latency.observe(latency);
		eprintln!(
			"{{\"event\":\"tunnel\",\"method\":\"CONNECT\",\"status\":{},\"latency_ms\":{:.3},\"error_class\":\"{}\"}}",
			self.status,
			latency.as_secs_f64() * 1_000.0,
			self.error_class,
		);
	}
}

#[derive(Debug)]
enum ConnectFailure {
	Timeout,
	Tor(arti_client::Error),
}

impl ConnectFailure {
	fn retryable(&self) -> bool {
		match self {
			Self::Timeout => true,
			Self::Tor(error) => matches!(
				error.kind(),
				ErrorKind::RemoteNetworkTimeout
					| ErrorKind::ExitTimeout
					| ErrorKind::RemoteStreamError
					| ErrorKind::RemoteStreamReset
					| ErrorKind::RemoteNetworkFailed
			),
		}
	}
}

async fn acquire_active_tunnel_permit<S>(
	stream: &mut S,
	tunnel_semaphore: Arc<Semaphore>,
	metrics: Arc<CircuitMetrics>,
	wait_timeout: Duration,
) -> anyhow::Result<ActiveTunnelPermit>
where
	S: tokio::io::AsyncWrite + Unpin,
{
	let result = {
		let _queued = AtomicGaugeGuard::increment(&metrics.queued_tunnels);
		tokio::time::timeout(wait_timeout, tunnel_semaphore.acquire_owned()).await
	};
	match result {
		Ok(Ok(permit)) => {
			metrics.active_tunnels.fetch_add(1, Ordering::Relaxed);
			Ok(ActiveTunnelPermit { _permit: permit, metrics })
		}
		Ok(Err(error)) => anyhow::bail!("active tunnel semaphore closed: {error}"),
		Err(_) => {
			metrics.rejected_tunnels.fetch_add(1, Ordering::Relaxed);
			let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
			anyhow::bail!("active tunnel capacity exceeded");
		}
	}
}

async fn copy_one_direction<R, W>(
	mut reader: R,
	mut writer: W,
	activity: watch::Sender<u64>,
	byte_counter: Option<&AtomicU64>,
	secondary_byte_counter: Option<&AtomicU64>,
) -> io::Result<u64>
where
	R: tokio::io::AsyncRead + Unpin,
	W: tokio::io::AsyncWrite + Unpin,
{
	let mut bytes_copied = 0_u64;
	let mut buffer = [0_u8; 16 * 1024];
	loop {
		let read = match reader.read(&mut buffer).await {
			Ok(read) => read,
			// Arti can report a remotely closed DataStream as NotConnected rather
			// than EOF. It is a completed tunnel teardown, not an ingress failure.
			Err(error) if error.kind() == io::ErrorKind::NotConnected => {
				shutdown_copy_writer(&mut writer).await?;
				return Ok(bytes_copied);
			}
			Err(error) => return Err(error),
		};
		if read == 0 {
			shutdown_copy_writer(&mut writer).await?;
			return Ok(bytes_copied);
		}
		writer.write_all(&buffer[..read]).await?;
		// Arti's DataStream buffers partial relay cells. write_all() only queues
		// those bytes, so flush before waiting for traffic in the other direction.
		writer.flush().await?;
		bytes_copied = bytes_copied.saturating_add(read as u64);
		if let Some(byte_counter) = byte_counter {
			byte_counter.fetch_add(read as u64, Ordering::Relaxed);
		}
		if let Some(byte_counter) = secondary_byte_counter {
			byte_counter.fetch_add(read as u64, Ordering::Relaxed);
		}
		activity.send_modify(|generation| *generation = generation.wrapping_add(1));
	}
}

async fn shutdown_copy_writer<W>(writer: &mut W) -> io::Result<()>
where
	W: tokio::io::AsyncWrite + Unpin,
{
	match writer.shutdown().await {
		Ok(()) => Ok(()),
		// Arti maps an already-closed DataStream to NotConnected and an
		// already-closed circuit to ConnectionReset. Both are clean only here,
		// after the copy direction has reached its shutdown path.
		Err(error) if matches!(
			error.kind(),
			io::ErrorKind::NotConnected | io::ErrorKind::ConnectionReset
		) => Ok(()),
		Err(error) => Err(error),
	}
}

async fn copy_bidirectional_with_idle_timeout<A, B>(
	a: &mut A,
	b: &mut B,
	idle_timeout: Duration,
) -> io::Result<(u64, u64)>
where
	A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	copy_bidirectional_with_idle_timeout_and_counters(a, b, idle_timeout, None, None).await
}

async fn copy_bidirectional_with_idle_timeout_and_counters<A, B>(
	a: &mut A,
	b: &mut B,
	idle_timeout: Duration,
	bytes_a_to_b: Option<&AtomicU64>,
	bytes_b_to_a: Option<&AtomicU64>,
) -> io::Result<(u64, u64)>
where
	A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	copy_bidirectional_with_idle_timeout_and_counter_sets(
		a,
		b,
		idle_timeout,
		bytes_a_to_b,
		bytes_b_to_a,
		None,
		None,
	)
	.await
}

async fn copy_bidirectional_with_idle_timeout_and_counter_sets<A, B>(
	a: &mut A,
	b: &mut B,
	idle_timeout: Duration,
	bytes_a_to_b: Option<&AtomicU64>,
	bytes_b_to_a: Option<&AtomicU64>,
	secondary_bytes_a_to_b: Option<&AtomicU64>,
	secondary_bytes_b_to_a: Option<&AtomicU64>,
) -> io::Result<(u64, u64)>
where
	A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let (a_reader, a_writer) = tokio::io::split(a);
	let (b_reader, b_writer) = tokio::io::split(b);
	let (activity, mut activity_rx) = watch::channel(0_u64);
	let activity_reverse = activity.clone();
	let copy = async move {
		tokio::try_join!(
			copy_one_direction(
				a_reader,
				b_writer,
				activity,
				bytes_a_to_b,
				secondary_bytes_a_to_b,
			),
			copy_one_direction(
				b_reader,
				a_writer,
				activity_reverse,
				bytes_b_to_a,
				secondary_bytes_b_to_a,
			),
		)
	};
	tokio::pin!(copy);
	let idle = tokio::time::sleep(idle_timeout);
	tokio::pin!(idle);

	loop {
		tokio::select! {
			result = &mut copy => return result,
			changed = activity_rx.changed() => {
				if changed.is_err() {
					return copy.await;
				}
				idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
			}
			_ = &mut idle => {
				return Err(io::Error::new(io::ErrorKind::TimedOut, "tunnel idle timeout"));
			}
		}
	}
}

async fn acquire_circuit_permit<S>(
	stream: &mut S,
	circuit_semaphore: Arc<Semaphore>,
	circuit_metrics: &CircuitMetrics,
	acquire_timeout: Duration,
) -> anyhow::Result<RateLimitGuard>
where
	S: tokio::io::AsyncWrite + Unpin,
{
	let result = {
		let _queued = AtomicGaugeGuard::increment(&circuit_metrics.queued_circuit_builds);
		tokio::time::timeout(acquire_timeout, circuit_semaphore.acquire_owned()).await
	};
	match result {
		Ok(Ok(permit)) => Ok(permit.into()),
		Ok(Err(error)) => {
			let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
			anyhow::bail!("circuit admission semaphore closed: {error}");
		}
		Err(_) => {
			circuit_metrics.acquire_timeouts.fetch_add(1, Ordering::Relaxed);
			let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
			anyhow::bail!("circuit capacity exceeded, request timed out waiting for a slot");
		}
	}
}

#[derive(Debug)]
enum RuntimeAuthenticationError {
	Account(AuthenticationError),
	Worker(JoinError),
}

#[derive(Debug)]
enum RuntimeUsageAdmissionError {
	Account(UsageAdmissionError),
	Worker(JoinError),
}

async fn accept_bounded_tls<S>(
	stream: S,
	acceptor: TlsAcceptor,
	handshake_semaphore: Arc<Semaphore>,
	handshake_timeout: Duration,
) -> anyhow::Result<TlsStream<S>>
where
	S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let handshake_permit = handshake_semaphore
		.try_acquire_owned()
		.map_err(|_| anyhow::anyhow!("TLS handshake capacity reached"))?;
	let tls_stream = tokio::time::timeout(handshake_timeout, acceptor.accept(stream))
		.await
		.map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
		.map_err(|error| anyhow::anyhow!("TLS handshake failed: {error}"))?;
	drop(handshake_permit);
	Ok(tls_stream)
}

fn tls_client_fingerprint<S>(stream: &TlsStream<S>) -> anyhow::Result<CertificateFingerprint> {
	let (_, connection) = stream.get_ref();
	validate_negotiated_alpn(connection.alpn_protocol())?;
	let certificates = connection
		.peer_certificates()
		.ok_or_else(|| anyhow::anyhow!("mTLS connection has no peer certificate"))?;
	let leaf = certificates
		.first()
		.ok_or_else(|| anyhow::anyhow!("mTLS connection has an empty peer certificate chain"))?;
	let digest = Sha256::digest(leaf.as_ref());
	let mut fingerprint = [0_u8; 32];
	fingerprint.copy_from_slice(&digest);
	Ok(CertificateFingerprint::from_sha256(fingerprint))
}

async fn authenticate_account(
	accounts: Arc<AccountManager>,
	proxy_authorization: Zeroizing<String>,
	fingerprint: CertificateFingerprint,
) -> std::result::Result<IngressIdentity, RuntimeAuthenticationError> {
	tokio::task::spawn_blocking(move || {
		accounts.authenticate_ingress(proxy_authorization.as_str(), &fingerprint)
	})
	.await
	.map_err(RuntimeAuthenticationError::Worker)?
	.map_err(RuntimeAuthenticationError::Account)
}

async fn admit_account_request(
	accounts: Arc<AccountManager>,
	identity: IngressIdentity,
	period_start: UnixTimestamp,
) -> std::result::Result<(), RuntimeUsageAdmissionError> {
	tokio::task::spawn_blocking(move || accounts.admit_request(identity, period_start))
		.await
		.map_err(RuntimeUsageAdmissionError::Worker)?
		.map(|_| ())
		.map_err(RuntimeUsageAdmissionError::Account)
}

async fn record_account_bytes(
	accounts: Arc<AccountManager>,
	identity: IngressIdentity,
	period_start: UnixTimestamp,
	bytes_to_tor: u64,
	bytes_from_tor: u64,
) -> anyhow::Result<()> {
	let delta = UsageDelta::new(0, bytes_to_tor, bytes_from_tor)?;
	tokio::task::spawn_blocking(move || accounts.record_usage(identity, period_start, delta))
		.await
		.map_err(|error| anyhow::anyhow!("account usage worker failed: {error}"))??;
	Ok(())
}

#[derive(Clone)]
pub struct Bridge{
	tor: Arc<TorClient<PreferredRuntime>>,
	token_store: Arc<IsolationStore>,
	public_ingress: PublicIngressRuntime,
	authentication: Option<AuthenticatedIngressRuntime>,
	circuit_semaphore: Arc<Semaphore>,
	tunnel_semaphore: Arc<Semaphore>,
	public_connection_semaphore: Arc<Semaphore>,
	internal_connection_semaphore: Arc<Semaphore>,
	circuit_breaker: Arc<CircuitBreaker>,
	circuit_metrics: Arc<CircuitMetrics>,
	//port: u16
}

pub struct TorCircuit {
	runtime: Runtime,
	client: Arc<TorClient<PreferredRuntime>>,
}

struct BridgeShutdown {
	shutdown: watch::Sender<bool>,
}

#[async_trait]
impl BackgroundService for BridgeShutdown {
	async fn start(&self, mut shutdown: ShutdownWatch) {
		if !*shutdown.borrow() {
			let _ = shutdown.changed().await;
		}
		let _ = self.shutdown.send(true);
	}
}

impl TorCircuit {
	pub fn bootstrap(config: TorClientConfig) -> anyhow::Result<Self> {
		let runtime = Runtime::new()
			.map_err(|error| anyhow::anyhow!("failed to create Tor runtime: {error}"))?;
		let client = runtime
			.block_on(TorClient::create_bootstrapped(config))
			.map_err(|error| anyhow::anyhow!("failed to bootstrap Tor client: {error}"))?;

		Ok(Self {
			runtime,
			client: Arc::new(client),
		})
	}

	pub fn client(&self) -> Arc<TorClient<PreferredRuntime>> {
		self.client.clone()
	}

	fn start_bridge(
		&self,
		token_store: Arc<IsolationStore>,
		metrics: Arc<CircuitMetrics>,
		drain_config: BridgeTaskDrainConfig,
		public_ingress: PublicIngressRuntime,
	) -> BridgeShutdown {
		let tor = self.client();
		let (shutdown, shutdown_receiver) = watch::channel(false);
		self.runtime.spawn(async move {
			if let Err(_error) = Bridge::new(tor, token_store, metrics, public_ingress)
				.run_bridge(shutdown_receiver, drain_config)
				.await
			{
				eprintln!("{{\"event\":\"bridge_shutdown\",\"error\":true}}");
			}
		});
		BridgeShutdown { shutdown }
	}
}

impl Proxy {
	fn extract_id(id_option: Option<i64>) -> Result<String, String> {
        id_option
			.map(|val| val.to_string())
            .ok_or("Error: No ID found".to_string())
    }
}

//trait TorStack {
//	
//}

// trait BridgeSession {
// 	fn finish(
// 		&self,
// 		storage: &'static (dyn Storage + Sync),
// 		trace: SpanHandle,
// 		session: &mut Session,
// 		token: IsolationToken
// 	) -> Result<()>;
//
// 	fn persist_token(
//         &self,
//         storage: &'static (dyn Storage + Sync),
//         key: &str,
//         token: IsolationToken,
//         ttl: Option<Duration>,
//     ) -> Result<()>;
//
// 	fn rotate_token(
//         &self,
//         storage: &'static (dyn Storage + Sync),
//         key: &str,
//     ) -> Result<IsolationToken>;
//
// }

#[async_trait]
impl ProxyHttp for Proxy {
	
	type CTX = RequestCtx;
	
	fn new_ctx(&self) -> Self::CTX {
		RequestCtx{
			id: None,
			account_id: None,
			ingress_identity: None,
			usage_period_start: None,
			bridge_identity_lease: None,
			token: IsolationToken::new(),
			isolation_identity: String::new(),
			isolation_group_key: 0,
			strict_isolation: false,
			request_started: tokio::time::Instant::now(),
			cache_started: None,
			cache_lock_recorded: false,
		}			
	}
	
	async fn upstream_peer(
		&self,
		session: &mut Session,
		ctx: &mut Self::CTX
	) -> Result<Box<HttpPeer>> {
		let host = session
			.req_header()
			.headers
			.get(http::header::HOST)
			.and_then(|v| v.to_str().ok())
			.ok_or_else(|| Error::new(InvalidHTTPHeader))?;
		let authority = host
			.parse::<http::uri::Authority>()
			.map_err(|_| Error::new(InvalidHTTPHeader))?;
		let host = authority.host().to_owned();
		let port = authority.port_u16().unwrap_or(80);
		
		let mut peer = HttpPeer::new(
			format!("{host}:{port}"),
			false, //tls
			host.to_string()
		);
		peer.group_key = ctx.isolation_group_key;
		let mut proxy_headers = std::collections::BTreeMap::new();
		proxy_headers.insert(
			ISOLATION_HEADER.to_owned(),
			ctx.isolation_identity.as_bytes().to_vec(),
		);
		proxy_headers.insert(
			ISOLATION_MODE_HEADER.to_owned(),
			if ctx.strict_isolation { b"strict".to_vec() } else { b"session".to_vec() },
		);
		if let Some(lease) = &ctx.bridge_identity_lease {
			proxy_headers.insert(
				INTERNAL_IDENTITY_HEADER.to_owned(),
				lease.token().as_bytes().to_vec(),
			);
		}
		peer.proxy = Some(CrateProxy {
			next_hop: Box::from(Path::new(BRIDGE_SOCKET)),
			host,
			port,
			headers: proxy_headers
		});
		Ok(Box::new(peer))
	}
	
	async fn upstream_request_filter(
		&self, 
		_session: &mut Session,
		upstream_request: &mut RequestHeader,
		ctx: &mut Self::CTX
	) -> Result<()> {
		upstream_request.remove_header(ISOLATION_HEADER);
		upstream_request.remove_header(ISOLATION_MODE_HEADER);
		upstream_request.remove_header(PROXY_AUTHORIZATION_HEADER);
		upstream_request.remove_header(INTERNAL_IDENTITY_HEADER);
		if ctx.strict_isolation {
			upstream_request.insert_header(http::header::CONNECTION, "close")?;
		}
		Ok(())
	}
	
	async fn request_filter(
		&self, 
		session: &mut Session,
		ctx: &mut Self::CTX,
	) -> Result<bool> {
		let isolation = if let Some(authentication) = &self.authentication {
			let Some(client_address) = session
				.client_addr()
				.and_then(|address| address.as_inet())
				.copied()
			else {
				session.respond_error(403).await?;
				return Ok(true);
			};
			let Some(authenticated_context) =
				authentication.downstream_contexts.context(&client_address)
			else {
				session.respond_error(403).await?;
				return Ok(true);
			};
			let _discarded_ingress_headers = take_isolation_request(session.req_header_mut())
				.map_err(|error| {
					Error::because(InvalidHTTPHeader, "invalid isolation header", error)
				})?;
			let destination = canonical_cache_key_parts(session.req_header())
				.map_err(|error| {
					Error::because(InvalidHTTPHeader, "invalid request destination", error)
				})?
				.0;
			let scope = authenticated_context.scope;
			let lease = authentication
				.bridge_identities
				.issue(scope)
				.map_err(|error| {
					Error::because(InternalError, "failed to issue bridge identity", error)
				})?;
			ctx.account_id = Some(scope.identity.account_id());
			ctx.ingress_identity = Some(scope.identity);
			ctx.usage_period_start = Some(scope.period_start);
			ctx.bridge_identity_lease = Some(lease);
			session.as_downstream_mut().set_keepalive(None);
			authentication.isolation_hasher.resolve(
				scope.identity,
				&destination,
				authenticated_context.isolation,
			)
		} else {
			let isolation_request = take_isolation_request(session.req_header_mut())
				.map_err(|error| {
					Error::because(InvalidHTTPHeader, "invalid isolation header", error)
				})?;
			resolve_isolation(isolation_request)
		};
		let new_id = self.request_counter.fetch_add(1, Ordering::Relaxed);
		ctx.id = Some(new_id as i64);
		ctx.strict_isolation = isolation.strict;
		ctx.isolation_identity = isolation.identity;
		let material = if ctx.strict_isolation {
			IsolationMaterial {
				token: IsolationToken::new(),
				group_key: ISOLATION_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed),
			}
		} else {
			self.cache.material_for(&ctx.isolation_identity)
		};
		ctx.token = material.token;
		ctx.isolation_group_key = material.group_key;
		if ctx.strict_isolation {
			session.as_downstream_mut().set_keepalive(None);
		}
		Ok(false)
	}
	
	fn request_cache_filter(
		&self, 
		session: &mut Session,
		ctx: &mut Self::CTX
	) -> Result<()> {
		let request = session.req_header();
		if request.method == http::Method::GET {
			canonical_cache_key_parts(request)
				.map_err(|error| Error::because(InvalidHTTPHeader, "invalid cache authority", error))?;
		}
		if request_cache_eligible(request) {
			ctx.cache_started = Some(tokio::time::Instant::now());
            session.cache.enable(
                cache(),
				Some(cache_eviction()), // eviction policy
                None, // cache predictor 
				Some(cache_lock()), // process-local cache lock
				None  // cache option override
            );
			session.cache.set_max_file_size_bytes(CACHE_MAX_OBJECT_BYTES);
        }
		Ok(())
	}
	
	fn cache_key_callback(
		&self, 
		session: &Session,
		_ctx: &mut Self::CTX
	) -> Result<CacheKey> {
		let (authority_namespace, path_and_query) = canonical_cache_key_parts(session.req_header())
			.map_err(|error| Error::because(InvalidHTTPHeader, "invalid cache authority", error))?;
		Ok(CacheKey::new(authority_namespace, path_and_query, ""))
	}

	fn response_cache_filter(
		&self,
		session: &Session,
		upstream_response: &ResponseHeader,
		_ctx: &mut Self::CTX,
	) -> Result<RespCacheable> {
		let cacheable = conservative_response_cacheable(
			session.req_header(),
			upstream_response,
		);
		if cacheable.is_cacheable() {
			self.metrics.cache_insertions.fetch_add(1, Ordering::Relaxed);
		}
		Ok(cacheable)
	}

	async fn proxy_upstream_filter(
		&self,
		_session: &mut Session,
		ctx: &mut Self::CTX,
	) -> Result<bool> {
		if !ctx.cache_lock_recorded {
			if let Some(started) = ctx.cache_started {
				self.metrics.cache_lock_wait.observe(started.elapsed());
				ctx.cache_lock_recorded = true;
			}
		}
		Ok(true)
	}
	
	async fn response_filter(
		&self,
		session: &mut Session,
		upstream_response: &mut ResponseHeader,
		ctx: &mut Self::CTX,
	) -> Result<(), Box<Error>> {
		upstream_response.insert_header("X-Proxy-Cache", cache_status_header(&session.cache))?;
		match Self::extract_id(ctx.id) {
            Ok(id_string) => {
                match upstream_response.insert_header("Server-Response-ID", id_string) {
                    Ok(_) => {},
                    Err(e) => return Err(e.into()),
                }
            }
			Err(_error_message) => {
				eprintln!("{{\"event\":\"response_id_error\"}}");
            }
        }
		
		Ok(())
	}

	async fn connected_to_upstream(
		&self,
		_session: &mut Session,
		reused: bool,
		_peer: &HttpPeer,
		#[cfg(unix)] _fd: std::os::unix::io::RawFd,
		#[cfg(windows)] _sock: std::os::windows::io::RawSocket,
		_digest: Option<&pingora::protocols::Digest>,
		_ctx: &mut Self::CTX,
	) -> Result<()> {
		if reused {
			self.metrics.upstream_reused.fetch_add(1, Ordering::Relaxed);
		} else {
			self.metrics.upstream_fresh.fetch_add(1, Ordering::Relaxed);
		}
		Ok(())
	}

	async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
		let latency = ctx.request_started.elapsed();
		let method = session.req_header().method.as_str();
		let status = session
			.response_written()
			.map(|response| response.status.as_u16())
			.unwrap_or(if error.is_some() { 502 } else { 0 });
		let cache_status = cache_status_header(&session.cache);
		match cache_status {
			"HIT" => { self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed); }
			"MISS" => { self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed); }
			"STALE" => { self.metrics.cache_stale_hits.fetch_add(1, Ordering::Relaxed); }
			_ => { self.metrics.cache_bypasses.fetch_add(1, Ordering::Relaxed); }
		}
		if error.is_some() {
			self.metrics.request_errors.fetch_add(1, Ordering::Relaxed);
		}
		self.metrics.record_request(method, status, latency);
		eprintln!(
			"{{\"event\":\"http_request\",\"method\":\"{}\",\"status\":{},\"latency_ms\":{:.3},\"cache\":\"{}\",\"error\":{}}}",
			match method {
				"GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => method,
				_ => "OTHER",
			},
			status,
			latency.as_secs_f64() * 1_000.0,
			cache_status,
			error.is_some(),
		);
	}

	fn request_summary(&self, session: &Session, _ctx: &Self::CTX) -> String {
		let method = session.req_header().method.as_str();
		format!(
			"method={}",
			match method {
				"GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => method,
				_ => "OTHER",
			}
		)
	}

	fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, _error: &Error) -> bool {
		true
	}

	fn error_while_proxy(
		&self,
		_peer: &HttpPeer,
		session: &mut Session,
		mut error: Box<Error>,
		_ctx: &mut Self::CTX,
		client_reused: bool,
	) -> Box<Error> {
		error
			.retry
			.decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());
		error
	}
	
}

impl Bridge {
	fn new(
		tor: Arc<TorClient<PreferredRuntime>>,
		token_store: Arc<IsolationStore>,
		circuit_metrics: Arc<CircuitMetrics>,
		public_ingress: PublicIngressRuntime,
	) -> Self {
		let authentication = public_ingress.authentication();
		let max_client_connections = public_ingress.max_client_connections();
		Self {
			tor,
			token_store,
			public_ingress,
			authentication,
			circuit_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CIRCUIT_BUILDS)),
			tunnel_semaphore: Arc::new(Semaphore::new(MAX_ACTIVE_TUNNELS)),
			public_connection_semaphore: Arc::new(Semaphore::new(max_client_connections)),
			internal_connection_semaphore: Arc::new(Semaphore::new(MAX_CONNECTION_TASKS)),
			circuit_breaker: Arc::new(CircuitBreaker::new(
				MAX_BREAKER_ENTRIES,
				BREAKER_FAILURE_THRESHOLD,
				BREAKER_COOLDOWN,
			)),
			circuit_metrics,
		}
	}
	
	async fn run_bridge(
		self,
		mut shutdown: watch::Receiver<bool>,
		drain_config: BridgeTaskDrainConfig,
	) -> anyhow::Result<()> {
		match std::fs::remove_file(BRIDGE_SOCKET) {
			Ok(()) => {}
			Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error.into()),
		}
		let listener = UnixListener::bind(BRIDGE_SOCKET)?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(BRIDGE_SOCKET, std::fs::Permissions::from_mode(0o600))?;
		}
		let public_listener = TcpListener::bind(self.public_ingress.listen_addr()).await?;
		let prometheus_listener = TcpListener::bind(PROMETHEUS_ADDR).await?;
		let mut interval = tokio::time::interval(CIRCUIT_METRICS_LOG_INTERVAL);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		// Tokio intervals tick immediately once; consume that tick so metrics are periodic.
		interval.tick().await;
		let mut task_registry = BridgeTaskRegistry::new(self.circuit_metrics.clone());

		loop {
			tokio::select! {
				biased;
				changed = shutdown.changed() => {
					if changed.is_err() || *shutdown.borrow() {
						break;
					}
				}
				joined = task_registry.join_next(), if !task_registry.is_empty() => {
					if let Some(joined) = joined {
						task_registry.record_join(joined);
					}
				}
				accepted = prometheus_listener.accept() => match accepted {
					Ok((stream, _)) => {
						let metrics = self.circuit_metrics.clone();
						let tokens = self.token_store.clone();
						let breaker = self.circuit_breaker.clone();
						task_registry.spawn(BridgeTaskKind::Metrics, async move {
							serve_prometheus_connection(stream, metrics, tokens, breaker)
								.await
								.map_err(anyhow::Error::from)
						});
					}
					Err(_) => eprintln!("{{\"event\":\"metrics_accept_error\"}}"),
				},
				_ = interval.tick() => {
					self.circuit_metrics.log(&self.circuit_semaphore);
				}
				accepted = listener.accept() => match accepted {
					Ok((mut stream, _)) => {
						let connection_permit = match self
							.internal_connection_semaphore
							.clone()
							.try_acquire_owned()
						{
							Ok(permit) => permit,
							Err(_) => {
								self.circuit_metrics.rejected_tunnels.fetch_add(1, Ordering::Relaxed);
								let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
								continue;
							}
						};
						let bridge = self.clone();
						task_registry.spawn(BridgeTaskKind::Internal, async move {
							let _connection_permit = connection_permit;
							let result = bridge.handle_internal_connect(stream).await;
							if let Err(error) = &result {
								eprintln!("[bridge] internal connection error: {error:#}");
							}
							result
						});
					}
					Err(_) => eprintln!("{{\"event\":\"bridge_accept_error\"}}"),
					},
					accepted = public_listener.accept() => match accepted {
						Ok((mut stream, _)) => {
							let connection_permit = match self.public_connection_semaphore.clone().try_acquire_owned() {
								Ok(permit) => permit,
								Err(_) => {
									self.circuit_metrics.rejected_tunnels.fetch_add(1, Ordering::Relaxed);
									if matches!(&self.public_ingress, PublicIngressRuntime::Development { .. }) {
										let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
									}
									continue;
								}
							};
							let bridge = self.clone();
							task_registry.spawn(BridgeTaskKind::Public, async move {
								let _connection_permit = connection_permit;
								let result = bridge.handle_public_tcp_connection(stream).await;
								if let Err(error) = &result {
									eprintln!("[bridge] ingress connection error: {error:#}");
								}
								result
							});
						}
						Err(_) => eprintln!("{{\"event\":\"ingress_accept_error\"}}"),
					},
				}
			}

		drop(listener);
		drop(public_listener);
		drop(prometheus_listener);
		let drain_summary = task_registry.drain(drain_config).await;
		match std::fs::remove_file(BRIDGE_SOCKET) {
			Ok(()) => {}
			Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => eprintln!("[bridge] failed to remove socket during shutdown: {error}"),
		}
		eprintln!(
			"{{\"event\":\"bridge_shutdown\",\"error\":{},\"drain_deadline_reached\":{},\"completed\":{},\"failed\":{},\"deadline_cancelled\":{},\"force_aborted\":{},\"elapsed_ms\":{}}}",
			!drain_summary.termination_confirmed,
			drain_summary.deadline_reached,
			drain_summary.completed,
			drain_summary.failed,
			drain_summary.deadline_cancelled,
			drain_summary.force_aborted,
			drain_summary.elapsed.as_millis(),
		);
		Ok(())
	}

	async fn handle_public_tcp_connection(&self, stream: TcpStream) -> anyhow::Result<()> {
		match self.public_ingress.clone() {
			PublicIngressRuntime::Development { .. } => {
				self.handle_public_connection(stream, None, None).await
			}
			PublicIngressRuntime::AuthenticatedTls {
				acceptor,
				handshake_timeout,
				first_request_timeout,
				handshake_semaphore,
				authentication,
				..
			} => {
				let tls_stream = accept_bounded_tls(
					stream,
					acceptor,
					handshake_semaphore,
					handshake_timeout,
				)
				.await?;
				let fingerprint = tls_client_fingerprint(&tls_stream)?;
				self.handle_public_connection(
					tls_stream,
					Some((authentication, fingerprint)),
					Some(first_request_timeout),
				)
				.await
			}
		}
	}

	async fn handle_public_connection<S>(
		&self,
		mut stream: S,
		authentication: Option<(AuthenticatedIngressRuntime, CertificateFingerprint)>,
		first_request_timeout: Option<Duration>,
	) -> anyhow::Result<()>
	where
		S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	{
		let ingress_started = tokio::time::Instant::now();
		let request_result = match first_request_timeout {
			Some(timeout) => match tokio::time::timeout(timeout, read_proxy_request(&mut stream)).await {
				Ok(result) => result,
				Err(_) => {
					let _ = stream.write_all(REQUEST_TIMEOUT_RESPONSE).await;
					self.circuit_metrics
						.record_request("OTHER", 408, ingress_started.elapsed());
					anyhow::bail!("first proxy request timed out");
				}
			},
			None => read_proxy_request(&mut stream).await,
		};
		let (mut request, buffer) = match request_result {
			Ok(request) => request,
			Err(error) => {
				let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
				self.circuit_metrics.record_request("OTHER", 400, ingress_started.elapsed());
				return Err(error);
			}
		};
		let mut buffer = Zeroizing::new(buffer);
		if request.internal_identity.is_some() {
			let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
			self.circuit_metrics
				.record_request(&request.method, 400, ingress_started.elapsed());
			anyhow::bail!("public request supplied a reserved internal identity header");
		}

		let account_scope = if let Some((authentication, fingerprint)) = authentication {
			let Some(proxy_authorization) = request.proxy_authorization.take() else {
				let _ = stream.write_all(PROXY_AUTH_REQUIRED_RESPONSE).await;
				self.circuit_metrics
					.record_request(&request.method, 407, ingress_started.elapsed());
				anyhow::bail!("proxy authorization is required");
			};
			let identity = match authenticate_account(
				authentication.accounts.clone(),
				proxy_authorization,
				fingerprint,
			)
			.await
			{
				Ok(identity) => identity,
				Err(RuntimeAuthenticationError::Account(
					AuthenticationError::InvalidAuthorization(_)
					| AuthenticationError::InvalidApiKey
					| AuthenticationError::ApiKeyRevoked,
				)) => {
					let _ = stream.write_all(PROXY_AUTH_REQUIRED_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 407, ingress_started.elapsed());
					anyhow::bail!("proxy authorization was rejected");
				}
				Err(RuntimeAuthenticationError::Account(
					AuthenticationError::AccountInactive
					| AuthenticationError::WorkspaceInactive
					| AuthenticationError::UnknownDevice
					| AuthenticationError::DeviceRevoked
					| AuthenticationError::CredentialScopeMismatch,
				)) => {
					let _ = stream.write_all(FORBIDDEN_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 403, ingress_started.elapsed());
					anyhow::bail!("authenticated account or device is not permitted");
				}
				Err(RuntimeAuthenticationError::Account(AuthenticationError::Storage(_))) => {
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 503, ingress_started.elapsed());
					anyhow::bail!("account authentication service is unavailable");
				}
				Err(RuntimeAuthenticationError::Worker(error)) => {
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 503, ingress_started.elapsed());
					anyhow::bail!("account authentication worker failed: {error}");
				}
			};
			if let Err(error) = authentication.accounts.check_request_rate(identity) {
				let response = if matches!(error, AccountAdmissionError::RateLimited { .. }) {
					RATE_LIMITED_RESPONSE
				} else {
					SERVICE_UNAVAILABLE_RESPONSE
				};
				let status = if matches!(error, AccountAdmissionError::RateLimited { .. }) {
					429
				} else {
					503
				};
				let _ = stream.write_all(response).await;
				self.circuit_metrics
					.record_request(&request.method, status, ingress_started.elapsed());
				anyhow::bail!("account request admission failed: {error}");
			}
			let period_start = match authentication.period_start() {
				Ok(period_start) => period_start,
				Err(error) => {
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 503, ingress_started.elapsed());
					return Err(error.into());
				}
			};
			match admit_account_request(
				authentication.accounts.clone(),
				identity,
				period_start,
			)
			.await
			{
				Ok(()) => {}
				Err(RuntimeUsageAdmissionError::Account(
					UsageAdmissionError::Quota(_),
				)) => {
					let _ = stream.write_all(QUOTA_EXCEEDED_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 429, ingress_started.elapsed());
					anyhow::bail!("account period quota reached");
				}
				Err(RuntimeUsageAdmissionError::Account(
					UsageAdmissionError::Storage(_),
				)) => {
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 503, ingress_started.elapsed());
					anyhow::bail!("account usage admission service is unavailable");
				}
				Err(RuntimeUsageAdmissionError::Worker(error)) => {
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					self.circuit_metrics
						.record_request(&request.method, 503, ingress_started.elapsed());
					anyhow::bail!("account usage admission worker failed: {error}");
				}
			}
			Some((
				authentication,
				AccountRequestScope {
					identity,
					period_start,
				},
			))
		} else {
			None
		};

		if request.method.eq_ignore_ascii_case("CONNECT") {
			let destination = request.destination.unwrap();
			let buffered_tunnel_data = buffer[request.header_len..].to_vec();
			buffer[..request.header_len].zeroize();
			return self
				.handle_connect_request(
					stream,
					destination,
					request.isolation,
					buffered_tunnel_data,
					true,
					account_scope,
				)
				.await;
		}

		let sanitized_buffer = if let Some((authentication, scope)) = &account_scope {
			let sanitized = strip_ingress_headers(&buffer, request.header_len)?;
			buffer[..request.header_len].zeroize();
			Some((
				sanitized,
				authentication.clone(),
				AuthenticatedRequestContext {
					scope: *scope,
					isolation: request.isolation,
				},
			))
		} else {
			None
		};
		let mut pingora_stream = match TcpStream::connect(INTERNAL_PROXY_ADDR).await {
			Ok(stream) => stream,
			Err(error) => {
				let _ = stream.write_all(BAD_GATEWAY_RESPONSE).await;
				return Err(anyhow::anyhow!("failed to reach internal Pingora service: {error}"));
			}
		};
		let _authenticated_downstream_guard = if let Some((
			sanitized,
			authentication,
			context,
		)) = sanitized_buffer
		{
			let address = pingora_stream.local_addr()?;
			let guard = match authentication
				.downstream_contexts
				.register(address, context)
			{
				Ok(guard) => guard,
				Err(error) => {
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					return Err(error);
				}
			};
			pingora_stream.write_all(&sanitized).await?;
			Some(guard)
		} else {
			pingora_stream.write_all(&buffer).await?;
			None
		};
		copy_bidirectional_with_idle_timeout(
			&mut stream,
			&mut pingora_stream,
			TUNNEL_IDLE_TIMEOUT,
		).await?;
		Ok(())
	}

	async fn handle_internal_connect(&self, mut stream: UnixStream) -> anyhow::Result<()> {
		let (dest, isolation, internal_identity, buffered_tunnel_data) =
			match read_connect_request(&mut stream).await {
			Ok(request) => request,
			Err(error) => {
				let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
				return Err(error);
			}
		};
		let account_scope = match (&self.authentication, internal_identity) {
			(Some(authentication), Some(token)) => {
				let Some(scope) = authentication.bridge_identities.resolve(&token) else {
					let _ = stream.write_all(FORBIDDEN_RESPONSE).await;
					anyhow::bail!("internal account identity lease was rejected");
				};
				Some((authentication.clone(), scope))
			}
			(Some(_), None) => {
				let _ = stream.write_all(FORBIDDEN_RESPONSE).await;
				anyhow::bail!("authenticated internal proxy request is missing its identity lease");
			}
			(None, Some(_)) => {
				let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
				anyhow::bail!("development proxy request supplied an internal identity lease");
			}
			(None, None) => None,
		};
		self.handle_connect_request(
			stream,
			dest,
			isolation,
			buffered_tunnel_data,
			false,
			account_scope,
		)
		.await
	}

	async fn connect_with_retry(
		&self,
		target: TorAddr,
		isolation: &ResolvedIsolation,
	) -> std::result::Result<DataStream, ConnectFailure> {
		let deadline = tokio::time::Instant::now() + TOR_CONNECT_TIMEOUT;
		for attempt in 0..=1 {
			let mut prefs = StreamPrefs::new();
			if isolation.strict {
				prefs.isolate_every_stream();
			} else {
				prefs.set_isolation(self.token_store.material_for(&isolation.identity).token);
			}

			let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
			if remaining.is_zero() {
				self.circuit_metrics.connect_timeouts.fetch_add(1, Ordering::Relaxed);
				self.circuit_metrics.record_arti_failure("timeout");
				return Err(ConnectFailure::Timeout);
			}
			let attempt_timeout = if attempt == 0 { remaining / 2 } else { remaining };
			let circuit_build_started = tokio::time::Instant::now();
			let connect_result = tokio::time::timeout(
				attempt_timeout,
				self.tor.connect_with_prefs(target.clone(), &prefs),
			).await;
			self.circuit_metrics.record_build_latency(circuit_build_started.elapsed());
			let failure = match connect_result {
				Ok(Ok(stream)) => return Ok(stream),
				Ok(Err(error)) => {
					self.circuit_metrics.record_arti_failure(arti_error_class(&error));
					ConnectFailure::Tor(error)
				}
				Err(_) => {
					self.circuit_metrics.connect_timeouts.fetch_add(1, Ordering::Relaxed);
					self.circuit_metrics.record_arti_failure("timeout");
					ConnectFailure::Timeout
				}
			};

			if attempt == 1 || !failure.retryable() {
				return Err(failure);
			}
			let retry_number = self.circuit_metrics.retries.fetch_add(1, Ordering::Relaxed) as u64;
			if !isolation.strict {
				self.token_store.rotate(&isolation.identity);
			}
			let backoff = Duration::from_millis(
				RETRY_BACKOFF_MIN_MS + retry_number % RETRY_BACKOFF_JITTER_MS,
			);
			let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
			if remaining <= backoff {
				return Err(failure);
			}
			tokio::time::sleep(backoff).await;
		}
		unreachable!("connection retry loop always returns")
	}

	async fn handle_connect_request<S>(
		&self,
		mut stream: S,
		dest: String,
		isolation_request: IsolationRequest,
		buffered_tunnel_data: Vec<u8>,
		count_as_public_request: bool,
		account_scope: Option<(AuthenticatedIngressRuntime, AccountRequestScope)>,
	) -> anyhow::Result<()>
	where
		S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	{
		let mut observation = TunnelObservation::new(
			self.circuit_metrics.clone(),
			count_as_public_request,
		);
		let target = match parse_connect_destination(&dest) {
			Ok(target) => target,
			Err(error) => {
				observation.finish(400, "invalid_request");
				let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
				return Err(error);
			}
		};
		let breaker_key = canonical_connect_destination_key(&dest)?;
		let destination_allowed = match connect_destination_allowed(&dest) {
			Ok(allowed) => allowed,
			Err(error) => {
				observation.finish(400, "invalid_request");
				let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
				return Err(error);
			}
		};
		if !destination_allowed {
			observation.finish(403, "destination_policy");
			let _ = stream.write_all(FORBIDDEN_RESPONSE).await;
			anyhow::bail!("CONNECT destination rejected by local policy");
		}
		if !self.circuit_breaker.allow(&breaker_key) {
			observation.finish(503, "circuit_breaker");
			self.circuit_metrics.breaker_rejections.fetch_add(1, Ordering::Relaxed);
			let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
			anyhow::bail!("destination circuit breaker is open");
		}

		let _account_tunnel_guard = if let Some((authentication, scope)) = &account_scope {
			match authentication.accounts.try_acquire_tunnel(scope.identity) {
				Ok(guard) => Some(guard),
				Err(AccountAdmissionError::TunnelLimitReached { .. }) => {
					observation.finish(429, "account_tunnel_capacity");
					let _ = stream.write_all(RATE_LIMITED_RESPONSE).await;
					anyhow::bail!("account concurrent tunnel limit reached");
				}
				Err(error) => {
					observation.finish(503, "account_admission");
					let _ = stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await;
					anyhow::bail!("account tunnel admission failed: {error}");
				}
			}
		} else {
			None
		};
		let _active_tunnel_permit = match acquire_active_tunnel_permit(
			&mut stream,
			self.tunnel_semaphore.clone(),
			self.circuit_metrics.clone(),
			TUNNEL_ACQUIRE_TIMEOUT,
		).await {
			Ok(permit) => permit,
			Err(error) => {
				observation.finish(503, "capacity");
				return Err(error);
			}
		};
		let isolation = match &account_scope {
			Some((authentication, scope)) if count_as_public_request => authentication
				.isolation_hasher
				.resolve(scope.identity, &breaker_key, isolation_request),
			_ => resolve_isolation(isolation_request),
		};
		let circuit_permit = match acquire_circuit_permit(
			&mut stream,
			self.circuit_semaphore.clone(),
			&self.circuit_metrics,
			CIRCUIT_ACQUIRE_TIMEOUT,
		).await {
			Ok(permit) => permit,
			Err(error) => {
				observation.finish(503, "circuit_capacity");
				return Err(error);
			}
		};
		let connect_result = self.connect_with_retry(target, &isolation).await;
		// Option A: this permit guards only circuit build/connect work. Holding it for
		// copy_bidirectional would cap long-lived tunnels instead of the costly setup step.
		drop(circuit_permit);

		let mut tor_stream = match connect_result {
			Ok(s)  => {
				self.circuit_breaker.record_success(&breaker_key);
				stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
				observation.finish(200, "stream");
				s
			}
			Err(ConnectFailure::Timeout) => {
				observation.finish(504, "timeout");
				self.circuit_breaker.record_failure(&breaker_key);
				stream.write_all(GATEWAY_TIMEOUT_RESPONSE).await?;
				anyhow::bail!("Tor connection establishment timed out");
			}
			Err(ConnectFailure::Tor(error)) => {
				let error_class = arti_error_class(&error);
				observation.finish(502, error_class);
				self.circuit_breaker.record_failure(&breaker_key);
				stream.write_all(BAD_GATEWAY_RESPONSE).await?;
				anyhow::bail!("Tor connection failed with class {:?}", error.kind());
			}
		};
		let account_bytes_to_tor = AtomicU64::new(0);
		let account_bytes_from_tor = AtomicU64::new(0);
		if !buffered_tunnel_data.is_empty() {
			tor_stream.write_all(&buffered_tunnel_data).await?;
			// These bytes were read alongside the CONNECT header and bypass the
			// regular copy loop, so they need their own explicit Arti flush.
			tor_stream.flush().await?;
			self.circuit_metrics
				.bytes_to_tor
				.fetch_add(buffered_tunnel_data.len() as u64, Ordering::Relaxed);
			if account_scope.is_some() {
				account_bytes_to_tor
					.fetch_add(buffered_tunnel_data.len() as u64, Ordering::Relaxed);
			}
		}

		let copy_result = copy_bidirectional_with_idle_timeout_and_counter_sets(
			&mut stream,
			&mut tor_stream,
			TUNNEL_IDLE_TIMEOUT,
			Some(&self.circuit_metrics.bytes_to_tor),
			Some(&self.circuit_metrics.bytes_from_tor),
			account_scope.as_ref().map(|_| &account_bytes_to_tor),
			account_scope.as_ref().map(|_| &account_bytes_from_tor),
		)
		.await;
		let usage_result = if let Some((authentication, scope)) = &account_scope {
			record_account_bytes(
				authentication.accounts.clone(),
				scope.identity,
				scope.period_start,
				account_bytes_to_tor.load(Ordering::Relaxed),
				account_bytes_from_tor.load(Ordering::Relaxed),
			)
			.await
		} else {
			Ok(())
		};
		match copy_result {
			Ok(bytes) => bytes,
			Err(error) if error.kind() == io::ErrorKind::TimedOut => {
				observation.finish(200, "idle_timeout");
				self.circuit_metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
				if let Err(usage_error) = usage_result {
					eprintln!("{{\"event\":\"account_usage_write_failed\"}}");
					return Err(usage_error);
				}
				return Err(error.into());
			}
			Err(error) => {
				observation.finish(200, "stream");
				if let Err(usage_error) = usage_result {
					eprintln!("{{\"event\":\"account_usage_write_failed\"}}");
					return Err(usage_error);
				}
				return Err(error.into());
			}
		};
		if let Err(error) = usage_result {
			eprintln!("{{\"event\":\"account_usage_write_failed\"}}");
			return Err(error);
		}
		observation.finish(200, "none");
		Ok(()) //for now
	}
}

impl Bridge {
	fn open_circuit<'a, Startup>(
		&self,
		_session: &'a mut Session,
		token: IsolationToken
	) -> CircuitHandle<'a, Startup> {
		CircuitHandle {
			token,
			phase: PhantomData,
			lifetime: PhantomData
		}
	}
}

// impl BridgeSession for Bridge {
// 	fn finish(
// 		&self,
// 		storage: &'static (dyn Storage + Sync),
// 		_trace: SpanHandle,
// 		session: &mut Session,
// 		token: IsolationToken
// 	) -> Result<()> {
// 		let host = session
// 			.req_header()
// 			.headers
// 			.get(http::header::HOST)
// 			.and_then(|value| value.to_str().ok())
// 			.ok_or_else(|| Error::new(InvalidHTTPHeader))?;
// 		let authority = host
// 			.parse::<http::uri::Authority>()
// 			.map_err(|_| Error::new(InvalidHTTPHeader))?;
// 		let key = format!(
// 			"{}:{}",
// 			authority.host(),
// 			authority.port_u16().unwrap_or(80)
// 		);
//
// 		self.persist_token(storage, &key, token, None)
// 	}
//
// 	fn persist_token(
// 		&self,
// 		_storage: &'static (dyn Storage + Sync),
// 		key: &str,
// 		token: IsolationToken,
// 		ttl: Option<Duration>,
// 	) -> Result<()> {
// 		self.token_store.put(key, token, ttl);
// 		Ok(())
// 	}
//
// 	fn rotate_token(
// 		&self,
// 		_storage: &'static (dyn Storage + Sync),
// 		key: &str,
// 	) -> Result<IsolationToken> {
// 		Ok(self.token_store.rotate(key).token)
// 	}
// }

fn proxy_server_configuration(
	bridge_drain_config: BridgeTaskDrainConfig,
) -> anyhow::Result<ServerConf> {
	let mut configuration = ServerConf::new()
		.ok_or_else(|| anyhow::anyhow!("failed to create Pingora server configuration"))?;
	configuration.grace_period_seconds =
		Some(bridge_drain_config.pingora_grace_period_seconds()?);
	configuration.graceful_shutdown_timeout_seconds =
		Some(GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS);
	Ok(configuration)
}

//#[tokio::main]
fn main() -> Result<()> {
	let config = TorClientConfig::default();
	let public_ingress = match configured_public_ingress() {
		Ok(configuration) => configuration,
		Err(error) => {
			eprintln!("{error}");
			process::exit(1);
		}
	};
	let authentication = public_ingress.authentication();
	let bridge_drain_config = match BridgeTaskDrainConfig::from_environment() {
		Ok(configuration) => configuration,
		Err(error) => {
			eprintln!("{error}");
			process::exit(1);
		}
	};
	//let tor_client = match TorClient::create_bootstrapped(config).await {
	//	Ok(client) => client,
	//	Err(e) => {
	//		eprintln!("{}", e);
	//		process::exit(1);
	//	}
	//};
	let tor_circuit = match TorCircuit::bootstrap(config) {
		Ok(circuit) => circuit,
		Err(error) => {
			eprintln!("{error}");
			process::exit(1);
		}
	};
	let tor_client = tor_circuit.client();
	
	let token_store = Arc::new(IsolationStore::new(MAX_ISOLATION_TOKENS, ISOLATION_TOKEN_TTL));
	let metrics = Arc::new(CircuitMetrics::default());
	let bridge_shutdown = tor_circuit.start_bridge(
		token_store.clone(),
		metrics.clone(),
		bridge_drain_config,
		public_ingress,
	);
	
	let server_configuration = match proxy_server_configuration(bridge_drain_config) {
		Ok(configuration) => configuration,
		Err(error) => {
			eprintln!("{error}");
			process::exit(1);
		}
	};
	let mut server = Server::new_with_opt_and_conf(None, server_configuration);
	server.bootstrap();
	server.add_service(background_service("bridge shutdown", bridge_shutdown));
	
	let mut http_options = HttpServerOptions::default();
	http_options.allow_connect_method_proxying = false;

	let mut service = ProxyServiceBuilder::new(&server.configuration, Proxy {
		request_counter: 0.into(), 
		cache: token_store.clone(),
		metrics,
		authentication,
		//isolation_manager: IsolationHelper::new() ### Error, no constructors for traits
		tor_client: tor_client.clone()
	})
	.server_options(http_options)
	.build();
	
	service.add_tcp(INTERNAL_PROXY_ADDR);
	server.add_service(service);
	server.run_forever();
}

#[cfg(test)]
mod tests {
	use super::{
		acquire_active_tunnel_permit, acquire_circuit_permit, canonical_cache_key_parts,
		canonical_connect_destination_key, conservative_response_cacheable, connect_destination_allowed,
		copy_bidirectional_with_idle_timeout, copy_bidirectional_with_idle_timeout_and_counters,
		copy_one_direction,
		parse_connect_destination, parse_connect_request, parse_proxy_request, read_proxy_request,
		proxy_server_configuration, render_prometheus_metrics, request_cache_eligible, resolve_isolation,
		serve_prometheus_connection, strip_ingress_headers, take_isolation_request,
		AccountRequestScope, AuthenticatedDownstreamStore, AuthenticatedRequestContext,
		BridgeIdentityRegistry, BridgeShutdown, BridgeTaskDrainConfig, BridgeTaskKind,
		BridgeTaskRegistry, CircuitBreaker, CircuitMetrics, ConnectFailure, IsolationRequest,
		IsolationStore, TenantIsolationHasher, PUBLIC_PROXY_ADDR,
		GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS, SHUTDOWN_GRACE_MARGIN_SECONDS,
	};
	use super::account_management::{
		AccountLimits, AccountManager, ApiKeyHasher, CertificateFingerprint, IngressIdentity,
		PlanCode, UnixTimestamp,
	};
	use base64::{Engine as _, engine::general_purpose::STANDARD};
	use pingora::prelude::{RequestHeader, ResponseHeader};
	use pingora::services::background::BackgroundService;
	use std::sync::{
		atomic::{AtomicUsize, Ordering},
		Arc, Mutex,
	};
	use std::{
		pin::Pin,
		task::{Context, Poll},
	};
	use std::time::Instant as StdInstant;
	use zeroize::Zeroizing;
	use tokio::{
		io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
		runtime::Runtime,
		sync::{watch, Semaphore},
		time::{timeout, Duration, Instant},
	};

	struct ReadError {
		kind: std::io::ErrorKind,
	}

	impl AsyncRead for ReadError {
		fn poll_read(
			self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
			_buf: &mut ReadBuf<'_>,
		) -> Poll<std::io::Result<()>> {
			Poll::Ready(Err(std::io::Error::new(
				self.kind,
				"read error",
			)))
		}
	}

	struct ClosedStreamShutdownWriter {
		kind: std::io::ErrorKind,
	}

	impl AsyncWrite for ClosedStreamShutdownWriter {
		fn poll_write(
			self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
			buffer: &[u8],
		) -> Poll<std::io::Result<usize>> {
			Poll::Ready(Ok(buffer.len()))
		}

		fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
			Poll::Ready(Ok(()))
		}

		fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
			Poll::Ready(Err(std::io::Error::new(
				self.kind,
				"closed stream teardown",
			)))
		}
	}

	struct FlushGatedWriter {
		pending: Vec<u8>,
		flushed: Arc<Mutex<Vec<u8>>>,
		flush_count: Arc<AtomicUsize>,
	}

	impl FlushGatedWriter {
		fn new() -> (Self, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
			let flushed = Arc::new(Mutex::new(Vec::new()));
			let flush_count = Arc::new(AtomicUsize::new(0));
			(Self {
				pending: Vec::new(),
				flushed: flushed.clone(),
				flush_count: flush_count.clone(),
			}, flushed, flush_count)
		}
	}

	impl AsyncWrite for FlushGatedWriter {
		fn poll_write(
			mut self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
			buffer: &[u8],
		) -> Poll<std::io::Result<usize>> {
			self.pending.extend_from_slice(buffer);
			Poll::Ready(Ok(buffer.len()))
		}

		fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
			let pending = std::mem::take(&mut self.pending);
			self.flushed
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner())
				.extend_from_slice(&pending);
			self.flush_count.fetch_add(1, Ordering::Relaxed);
			Poll::Ready(Ok(()))
		}

		fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
			self.poll_flush(cx)
		}
	}

	fn cache_request(method: &str, uri: &str, host: &str) -> RequestHeader {
		let mut request = RequestHeader::build(method, b"/", None).unwrap();
		request.set_uri(uri.parse().unwrap());
		request.insert_header(http::header::HOST, host).unwrap();
		request
	}

	fn cache_response(cache_control: &str) -> ResponseHeader {
		let mut response = ResponseHeader::build(200, None).unwrap();
		response
			.insert_header(http::header::CACHE_CONTROL, cache_control)
			.unwrap();
		response
	}

	fn provision_test_identity(
		manager: &AccountManager,
		email: &str,
		fingerprint_byte: u8,
	) -> IngressIdentity {
		let now = UnixTimestamp::new(100).unwrap();
		let account = manager
			.create_account(
				email,
				None,
				&PlanCode::new("test").unwrap(),
				AccountLimits::new(100, 100, 8, None, None).unwrap(),
				now,
			)
			.unwrap();
		let workspace = manager
			.create_workspace(account.id(), "default", now)
			.unwrap();
		let api_key = manager
			.issue_api_key(account.id(), workspace.id(), "test", now)
			.unwrap();
		let fingerprint = CertificateFingerprint::from_sha256([fingerprint_byte; 32]);
		manager
			.register_device_credential(
				account.id(),
				workspace.id(),
				&fingerprint,
				"test device",
				now,
			)
			.unwrap();
		let encoded = STANDARD.encode(format!("{}:", api_key.secret().expose_secret()));
		manager
			.authenticate_ingress(&format!("Basic {encoded}"), &fingerprint)
			.unwrap()
	}

	#[test]
	fn shutdown_configuration_is_bounded() {
		let drain_config = BridgeTaskDrainConfig::new(
			Duration::from_secs(1),
			Duration::from_secs(1),
		).unwrap();
		let configuration = proxy_server_configuration(drain_config).unwrap();

		assert_eq!(
			configuration.grace_period_seconds,
			Some(2 + SHUTDOWN_GRACE_MARGIN_SECONDS)
		);
		assert_eq!(
			configuration.graceful_shutdown_timeout_seconds,
			Some(GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS)
		);
	}

	#[test]
	fn bridge_task_drain_configuration_rejects_unsafe_bounds() {
		assert!(
			BridgeTaskDrainConfig::new(Duration::ZERO, Duration::from_secs(1)).is_err()
		);
		assert!(
			BridgeTaskDrainConfig::new(Duration::from_secs(1), Duration::ZERO).is_err()
		);
		assert!(
			BridgeTaskDrainConfig::new(
				Duration::from_secs(super::MAX_BRIDGE_TASK_SHUTDOWN_SECONDS + 1),
				Duration::from_secs(1),
			)
			.is_err()
		);
	}

	#[test]
	fn bridge_task_registry_drains_completed_and_failed_tasks() {
		Runtime::new().unwrap().block_on(async {
			let metrics = Arc::new(CircuitMetrics::default());
			let mut registry = BridgeTaskRegistry::new(metrics.clone());
			registry.spawn(BridgeTaskKind::Public, async { Ok(()) });
			registry.spawn(BridgeTaskKind::Metrics, async {
				anyhow::bail!("deterministic task failure")
			});

			let summary = registry
				.drain(
					BridgeTaskDrainConfig::new(
						Duration::from_millis(250),
						Duration::from_millis(250),
					)
					.unwrap(),
				)
				.await;

			assert_eq!(summary.completed, 1);
			assert_eq!(summary.failed, 1);
			assert_eq!(summary.deadline_cancelled, 0);
			assert!(!summary.deadline_reached);
			assert!(summary.termination_confirmed);
			assert_eq!(metrics.bridge_tasks_active.load(Ordering::Relaxed), 0);
			assert_eq!(metrics.bridge_tasks_completed.load(Ordering::Relaxed), 1);
			assert_eq!(metrics.bridge_tasks_failed.load(Ordering::Relaxed), 1);
		});
	}

	#[test]
	fn bridge_task_registry_cancels_only_after_drain_deadline() {
		Runtime::new().unwrap().block_on(async {
			let metrics = Arc::new(CircuitMetrics::default());
			let mut registry = BridgeTaskRegistry::new(metrics.clone());
			registry.spawn(BridgeTaskKind::Internal, async {
				std::future::pending::<()>().await;
				Ok(())
			});
			let drain_timeout = Duration::from_millis(25);
			let started = Instant::now();

			let summary = registry
				.drain(
					BridgeTaskDrainConfig::new(
						drain_timeout,
						Duration::from_millis(250),
					)
					.unwrap(),
				)
				.await;

			assert!(started.elapsed() >= drain_timeout);
			assert!(summary.deadline_reached);
			assert_eq!(summary.deadline_cancelled, 1);
			assert_eq!(summary.force_aborted, 0);
			assert!(summary.termination_confirmed);
			assert_eq!(metrics.bridge_tasks_active.load(Ordering::Relaxed), 0);
			assert_eq!(
				metrics.bridge_tasks_deadline_cancelled.load(Ordering::Relaxed),
				1
			);
		});
	}

	#[test]
	fn bridge_task_registry_preserves_tunnel_half_closes_during_drain() {
		Runtime::new().unwrap().block_on(async {
			let metrics = Arc::new(CircuitMetrics::default());
			let mut registry = BridgeTaskRegistry::new(metrics.clone());
			let (mut downstream_client, mut downstream_bridge) = tokio::io::duplex(256);
			let (mut upstream_bridge, mut upstream_server) = tokio::io::duplex(256);
			registry.spawn(BridgeTaskKind::Public, async move {
				copy_bidirectional_with_idle_timeout(
					&mut downstream_bridge,
					&mut upstream_bridge,
					Duration::from_secs(1),
				)
				.await
				.map(|_| ())
				.map_err(anyhow::Error::from)
			});

			let draining = registry.drain(
				BridgeTaskDrainConfig::new(
					Duration::from_secs(1),
					Duration::from_millis(250),
				)
				.unwrap(),
			);
			let traffic = async {
				downstream_client.write_all(b"request").await.unwrap();
				downstream_client.shutdown().await.unwrap();
				let mut request = Vec::new();
				upstream_server.read_to_end(&mut request).await.unwrap();
				assert_eq!(request, b"request");

				upstream_server.write_all(b"response").await.unwrap();
				upstream_server.shutdown().await.unwrap();
				let mut response = Vec::new();
				downstream_client.read_to_end(&mut response).await.unwrap();
				assert_eq!(response, b"response");
			};
			let (summary, ()) = tokio::join!(draining, traffic);

			assert_eq!(summary.completed, 1);
			assert_eq!(summary.deadline_cancelled, 0);
			assert!(!summary.deadline_reached);
			assert!(summary.termination_confirmed);
			assert_eq!(metrics.bridge_tasks_active.load(Ordering::Relaxed), 0);
		});
	}

	#[test]
	fn bridge_shutdown_follows_pingora_shutdown() {
		Runtime::new().unwrap().block_on(async {
			let (server_shutdown, server_shutdown_receiver) = watch::channel(false);
			let (bridge_shutdown, mut bridge_shutdown_receiver) = watch::channel(false);
			let relay = BridgeShutdown { shutdown: bridge_shutdown };
			let relaying = tokio::spawn(async move {
				relay.start(server_shutdown_receiver).await;
			});

			server_shutdown.send(true).unwrap();
			timeout(
				Duration::from_millis(250),
				bridge_shutdown_receiver.wait_for(|requested| *requested),
			)
			.await
			.expect("bridge should receive the server shutdown signal")
			.expect("bridge shutdown sender should remain available");
			relaying.await.unwrap();
		});
	}

	#[test]
	fn parses_connect_request_and_reports_header_length() {
		let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nclient-hello";

		let parsed = parse_connect_request(request).unwrap();

		assert_eq!(parsed, Some(("example.com:443".to_owned(), 59)));
	}

	#[test]
	fn leaves_incomplete_requests_unparsed() {
		let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n";

		assert_eq!(parse_connect_request(request).unwrap(), None);
	}

	#[test]
	fn rejects_non_connect_requests() {
		let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

		assert!(parse_connect_request(request).is_err());
	}

	#[test]
	fn rejects_connect_destinations_without_a_valid_port() {
		assert!(parse_connect_destination("example.com:0").is_err());
		assert!(parse_connect_destination("example.com").is_err());
	}

	#[test]
	fn circuit_breaker_destination_keys_are_canonical() {
		assert_eq!(
			canonical_connect_destination_key("Example.COM.:443").unwrap(),
			"example.com:443",
		);
		assert_eq!(
			canonical_connect_destination_key("[2001:DB8::1]:443").unwrap(),
			"[2001:db8::1]:443",
		);
	}

	#[test]
	fn parses_non_connect_request_for_pingora_dispatch() {
		let request = b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
		let parsed = parse_proxy_request(request).unwrap().unwrap();

		assert_eq!(parsed.method, "GET");
		assert_eq!(parsed.destination, None);
		assert_eq!(&request[parsed.header_len..], b"body");
	}

	#[test]
	fn parses_validated_isolation_headers() {
		let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Proxy-Isolation: browser-profile_1\r\nX-Proxy-Isolation-Mode: strict\r\n\r\n";
		let parsed = parse_proxy_request(request).unwrap().unwrap();

		assert_eq!(parsed.isolation.identity.as_deref(), Some("browser-profile_1"));
		assert!(parsed.isolation.strict);
	}

	#[test]
	fn rejects_ambiguous_or_unsafe_isolation_headers() {
		let duplicate = b"CONNECT example.com:443 HTTP/1.1\r\nX-Proxy-Isolation: one\r\nX-Proxy-Isolation: two\r\n\r\n";
		let unsafe_value = b"CONNECT example.com:443 HTTP/1.1\r\nX-Proxy-Isolation: user secret\r\n\r\n";
		let invalid_mode = b"CONNECT example.com:443 HTTP/1.1\r\nX-Proxy-Isolation-Mode: maximum\r\n\r\n";

		assert!(parse_proxy_request(duplicate).is_err());
		assert!(parse_proxy_request(unsafe_value).is_err());
		assert!(parse_proxy_request(invalid_mode).is_err());
	}

	#[test]
	fn proxy_authorization_is_parsed_but_always_redacted() {
		let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic c2Vuc2l0aXZlOg==\r\n\r\n";
		let parsed = parse_proxy_request(request).unwrap().unwrap();
		assert_eq!(
			parsed.proxy_authorization.as_deref().map(String::as_str),
			Some("Basic c2Vuc2l0aXZlOg=="),
		);
		let debug = format!("{parsed:?}");
		assert!(debug.contains("[redacted]"));
		assert!(!debug.contains("c2Vuc2l0aXZlOg"));

		let duplicate = b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic b25lOg==\r\nProxy-Authorization: Basic dHdvOg==\r\n\r\n";
		assert!(parse_proxy_request(duplicate).is_err());
	}

	#[test]
	fn authenticated_ingress_headers_are_removed_before_pingora() {
		let request = b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nProxy-Authorization: Basic c2Vuc2l0aXZlOg==\r\nX-Proxy-Isolation: profile-1\r\nX-Proxy-Isolation-Mode: session\r\nX-Proxy-Authenticated-Lease: reserved-token\r\n\r\nbody";
		let parsed = parse_proxy_request(request).unwrap().unwrap();
		let sanitized = strip_ingress_headers(request, parsed.header_len).unwrap();
		let sanitized = String::from_utf8(sanitized).unwrap();

		assert!(sanitized.starts_with(
			"POST http://example.com/upload HTTP/1.1\r\n"
		));
		assert!(sanitized.contains("Host: example.com\r\n"));
		assert!(sanitized.contains("Content-Length: 4\r\n"));
		assert!(sanitized.ends_with("\r\n\r\nbody"));
		assert!(!sanitized.to_ascii_lowercase().contains("proxy-authorization"));
		assert!(!sanitized.contains("X-Proxy-Isolation"));
		assert!(!sanitized.contains("X-Proxy-Authenticated-Lease"));
	}

	#[test]
	fn isolation_headers_are_removed_before_origin_forwarding() {
		let mut request = cache_request("GET", "http://example.com/item", "example.com");
		request.insert_header("X-Proxy-Isolation", "profile-1").unwrap();
		request.insert_header("X-Proxy-Isolation-Mode", "session").unwrap();
		request
			.insert_header("Proxy-Authorization", "Basic c2Vuc2l0aXZlOg==")
			.unwrap();
		request
			.insert_header("X-Proxy-Authenticated-Lease", "reserved-token")
			.unwrap();

		let isolation = take_isolation_request(&mut request).unwrap();

		assert_eq!(isolation.identity.as_deref(), Some("profile-1"));
		assert!(!isolation.strict);
		assert!(!request.headers.contains_key("X-Proxy-Isolation"));
		assert!(!request.headers.contains_key("X-Proxy-Isolation-Mode"));
		assert!(!request.headers.contains_key("Proxy-Authorization"));
		assert!(!request.headers.contains_key("X-Proxy-Authenticated-Lease"));
	}

	#[test]
	fn authenticated_identity_scopes_isolation_and_opaque_handoffs() {
		let manager = AccountManager::open_in_memory(
			ApiKeyHasher::from_key(Zeroizing::new([0x42; blake3::KEY_LEN])),
			8,
		)
		.unwrap();
		let first = provision_test_identity(&manager, "first-scope@example.com", 0x31);
		let second = provision_test_identity(&manager, "second-scope@example.com", 0x32);
		let hasher = TenantIsolationHasher::new().unwrap();
		let request = || IsolationRequest {
			identity: Some("browser".to_owned()),
			strict: false,
		};
		let first_key = hasher.resolve(first, "example.com:443", request());
		let first_again = hasher.resolve(first, "example.com:443", request());
		let other_account = hasher.resolve(second, "example.com:443", request());
		let other_destination = hasher.resolve(first, "other.example:443", request());
		assert_eq!(first_key.identity, first_again.identity);
		assert_ne!(first_key.identity, other_account.identity);
		assert_ne!(first_key.identity, other_destination.identity);
		assert_eq!(first_key.identity.len(), 64);

		let period_start = UnixTimestamp::new(1_700_000_000).unwrap();
		let scope = AccountRequestScope {
			identity: first,
			period_start,
		};
		let downstream_store = Arc::new(AuthenticatedDownstreamStore::new(1));
		let address = "127.0.0.1:32000".parse().unwrap();
		let guard = downstream_store
			.register(
				address,
				AuthenticatedRequestContext {
					scope,
					isolation: request(),
				},
			)
			.unwrap();
		assert_eq!(
			downstream_store.context(&address).unwrap().scope,
			scope,
		);
		drop(guard);
		assert!(downstream_store.context(&address).is_none());

		let bridge_registry = Arc::new(BridgeIdentityRegistry::new(1));
		let lease = bridge_registry.issue(scope).unwrap();
		assert_eq!(bridge_registry.resolve(lease.token()), Some(scope));
		assert!(!lease.token().contains(&format!("{:?}", first.account_id())));
		let token = lease.token().to_owned();
		drop(lease);
		assert!(bridge_registry.resolve(&token).is_none());
	}

	#[test]
	fn isolation_store_reuses_only_the_same_identity() {
		let store = IsolationStore::new(8, Duration::from_secs(60));
		let first = store.material_for("session-a");
		let same = store.material_for("session-a");
		let different = store.material_for("session-b");

		assert_eq!(first, same);
		assert_ne!(first.token, different.token);
		assert_ne!(first.group_key, different.group_key);
	}

	#[test]
	fn isolation_store_expires_and_stays_bounded() {
		let store = IsolationStore::new(2, Duration::from_secs(5));
		let now = StdInstant::now();
		let first = store.material_for_at("first", now);
		store.material_for_at("second", now + Duration::from_secs(1));
		store.material_for_at("third", now + Duration::from_secs(2));
		assert_eq!(store.len(), 2);
		let first_after_eviction = store.material_for_at("first", now + Duration::from_secs(3));
		assert_ne!(first.token, first_after_eviction.token);

		let expired = store.material_for_at("first", now + Duration::from_secs(9));
		assert_ne!(first_after_eviction.token, expired.token);
		assert!(store.len() <= 2);
	}

	#[test]
	fn strict_isolation_is_unique_per_request() {
		let first = resolve_isolation(IsolationRequest {
			identity: Some("same-session".to_owned()),
			strict: true,
		});
		let second = resolve_isolation(IsolationRequest {
			identity: Some("same-session".to_owned()),
			strict: true,
		});

		assert!(first.strict);
		assert!(second.strict);
		assert_ne!(first.identity, second.identity);
	}

	#[test]
	fn circuit_breaker_opens_then_allows_a_recovery_probe() {
		let breaker = CircuitBreaker::new(8, 3, Duration::from_secs(10));
		let now = StdInstant::now();
		for offset in 0..3 {
			breaker.record_failure_at("example.com:443", now + Duration::from_secs(offset));
		}

		assert!(!breaker.allow_at("example.com:443", now + Duration::from_secs(3)));
		assert!(breaker.allow_at("example.com:443", now + Duration::from_secs(13)));
		breaker.record_success("example.com:443");
		assert!(breaker.allow_at("example.com:443", now + Duration::from_secs(14)));
	}

	#[test]
	fn circuit_breaker_store_stays_bounded() {
		let breaker = CircuitBreaker::new(2, 1, Duration::from_secs(30));
		let now = StdInstant::now();
		breaker.record_failure_at("one:443", now);
		breaker.record_failure_at("two:443", now + Duration::from_secs(1));
		breaker.record_failure_at("three:443", now + Duration::from_secs(2));

		assert_eq!(breaker.len(), 2);
		assert!(breaker.allow_at("one:443", now + Duration::from_secs(3)));
		assert!(!breaker.allow_at("three:443", now + Duration::from_secs(3)));
	}

	#[test]
	fn timeout_failures_are_retryable() {
		assert!(ConnectFailure::Timeout.retryable());
	}

	#[test]
	fn active_tunnel_admission_times_out_with_service_unavailable() {
		Runtime::new().unwrap().block_on(async {
			let semaphore = Arc::new(Semaphore::new(1));
			let _held = semaphore.clone().acquire_owned().await.unwrap();
			let metrics = Arc::new(CircuitMetrics::default());
			let (mut client, mut bridge) = tokio::io::duplex(256);

			let result = acquire_active_tunnel_permit(
				&mut bridge,
				semaphore,
				metrics.clone(),
				Duration::from_millis(10),
			).await;
			assert!(result.is_err());
			drop(bridge);

			let mut response = Vec::new();
			client.read_to_end(&mut response).await.unwrap();
			assert_eq!(response, super::CIRCUIT_CAPACITY_RESPONSE);
			assert_eq!(metrics.queued_tunnels.load(Ordering::Relaxed), 0);
			assert_eq!(metrics.rejected_tunnels.load(Ordering::Relaxed), 1);
		});
	}

	#[test]
	fn tunnel_copy_flushes_data_before_waiting_for_eof() {
		Runtime::new().unwrap().block_on(async {
			let (mut client, bridge_reader) = tokio::io::duplex(64);
			let (writer, flushed, flush_count) = FlushGatedWriter::new();
			let (activity, _activity_rx) = tokio::sync::watch::channel(0_u64);
			let copying = tokio::spawn(async move {
				copy_one_direction(bridge_reader, writer, activity, None, None).await
			});

			client.write_all(b"request").await.unwrap();
			timeout(Duration::from_millis(250), async {
				loop {
					let observed = flushed
						.lock()
						.unwrap_or_else(|poisoned| poisoned.into_inner())
						.clone();
					if observed == b"request" {
						break;
					}
					tokio::task::yield_now().await;
				}
			}).await.expect("copy must flush without waiting for the reader to close");
			assert_eq!(flush_count.load(Ordering::Relaxed), 1);

			client.shutdown().await.unwrap();
			assert_eq!(copying.await.unwrap().unwrap(), 7);
		});
	}

	#[test]
	fn tunnel_copy_normalizes_only_closed_stream_teardown() {
		Runtime::new().unwrap().block_on(async {
			let (activity, _activity_rx) = tokio::sync::watch::channel(0_u64);
			let bytes = copy_one_direction(
				ReadError { kind: std::io::ErrorKind::NotConnected },
				tokio::io::sink(),
				activity,
				None,
				None,
			).await.unwrap();
			assert_eq!(bytes, 0);

			for kind in [
				std::io::ErrorKind::NotConnected,
				std::io::ErrorKind::ConnectionReset,
			] {
				let (activity, _activity_rx) = tokio::sync::watch::channel(0_u64);
				let bytes = copy_one_direction(
					tokio::io::empty(),
					ClosedStreamShutdownWriter { kind },
					activity,
					None,
					None,
				).await.unwrap();
				assert_eq!(bytes, 0);
			}

			let (activity, _activity_rx) = tokio::sync::watch::channel(0_u64);
			let error = copy_one_direction(
				ReadError { kind: std::io::ErrorKind::ConnectionReset },
				tokio::io::sink(),
				activity,
				None,
				None,
			).await.unwrap_err();
			assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
		});
	}

	#[test]
	fn tunnel_copy_preserves_half_closes_and_byte_counts() {
		Runtime::new().unwrap().block_on(async {
			let (mut downstream_client, mut downstream_bridge) = tokio::io::duplex(256);
			let (mut upstream_bridge, mut upstream_server) = tokio::io::duplex(256);
			let copying = tokio::spawn(async move {
				copy_bidirectional_with_idle_timeout(
					&mut downstream_bridge,
					&mut upstream_bridge,
					Duration::from_secs(1),
				).await
			});

			downstream_client.write_all(b"request").await.unwrap();
			downstream_client.shutdown().await.unwrap();
			let mut request = Vec::new();
			upstream_server.read_to_end(&mut request).await.unwrap();
			assert_eq!(request, b"request");

			upstream_server.write_all(b"response").await.unwrap();
			upstream_server.shutdown().await.unwrap();
			let mut response = Vec::new();
			downstream_client.read_to_end(&mut response).await.unwrap();
			assert_eq!(response, b"response");
			assert_eq!(copying.await.unwrap().unwrap(), (7, 8));
		});
	}

	#[test]
	fn tunnel_copy_times_out_only_while_idle() {
		Runtime::new().unwrap().block_on(async {
			let (_downstream_client, mut downstream_bridge) = tokio::io::duplex(64);
			let (mut upstream_bridge, _upstream_server) = tokio::io::duplex(64);
			let result = copy_bidirectional_with_idle_timeout(
				&mut downstream_bridge,
				&mut upstream_bridge,
				Duration::from_millis(20),
			).await;

			assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
		});
	}

	#[test]
	fn tunnel_byte_counters_include_successful_forwarding() {
		Runtime::new().unwrap().block_on(async {
			let (mut downstream_client, mut downstream_bridge) = tokio::io::duplex(64);
			let (mut upstream_bridge, mut upstream_server) = tokio::io::duplex(64);
			let to_tor = std::sync::atomic::AtomicU64::new(0);
			let from_tor = std::sync::atomic::AtomicU64::new(0);
			let transfer = async {
				copy_bidirectional_with_idle_timeout_and_counters(
					&mut downstream_bridge,
					&mut upstream_bridge,
					Duration::from_secs(1),
					Some(&to_tor),
					Some(&from_tor),
				).await
			};
			let endpoints = async {
				downstream_client.write_all(b"abc").await.unwrap();
				downstream_client.shutdown().await.unwrap();
				let mut request = Vec::new();
				upstream_server.read_to_end(&mut request).await.unwrap();
				upstream_server.write_all(b"reply").await.unwrap();
				upstream_server.shutdown().await.unwrap();
				let mut response = Vec::new();
				downstream_client.read_to_end(&mut response).await.unwrap();
			};

			let (transfer_result, ()) = tokio::join!(transfer, endpoints);
			assert_eq!(transfer_result.unwrap(), (3, 5));
			assert_eq!(to_tor.load(Ordering::Relaxed), 3);
			assert_eq!(from_tor.load(Ordering::Relaxed), 5);
		});
	}

	#[test]
	fn prometheus_rendering_exposes_bounded_privacy_safe_metrics() {
		let metrics = CircuitMetrics::default();
		metrics.record_request("GET", 200, Duration::from_millis(25));
		metrics.cache_hits.store(2, Ordering::Relaxed);
		metrics.bytes_to_tor.store(123, Ordering::Relaxed);
		metrics.bridge_tasks_completed.store(4, Ordering::Relaxed);
		metrics.bridge_tasks_deadline_cancelled.store(1, Ordering::Relaxed);
		metrics.record_arti_failure("timeout");
		let tokens = IsolationStore::new(2, Duration::from_secs(60));
		tokens.material_for("private-session-name");
		let breaker = CircuitBreaker::new(2, 1, Duration::from_secs(30));
		breaker.record_failure("secret.example:443");

		let rendered = render_prometheus_metrics(&metrics, &tokens, &breaker);

		assert!(rendered.contains("proxy_requests_total{method=\"GET\",status=\"200\"} 1"));
		assert!(rendered.contains("proxy_cache_hits_total 2"));
		assert!(rendered.contains("proxy_bytes_to_tor_total 123"));
		assert!(rendered.contains("proxy_bridge_tasks_completed_total 4"));
		assert!(rendered.contains("proxy_bridge_tasks_deadline_cancelled_total 1"));
		assert!(rendered.contains("proxy_arti_failures_total{class=\"timeout\"} 1"));
		assert!(rendered.contains("proxy_isolation_tokens 1"));
		assert!(!rendered.contains("private-session-name"));
		assert!(!rendered.contains("secret.example"));
	}

	#[test]
	fn prometheus_http_endpoint_serves_metrics_only_on_the_metrics_path() {
		Runtime::new().unwrap().block_on(async {
			let (mut client, server) = tokio::io::duplex(16 * 1024);
			let metrics = Arc::new(CircuitMetrics::default());
			let tokens = Arc::new(IsolationStore::new(2, Duration::from_secs(60)));
			let breaker = Arc::new(CircuitBreaker::new(2, 1, Duration::from_secs(30)));
			let serving = tokio::spawn(async move {
				serve_prometheus_connection(server, metrics, tokens, breaker).await.unwrap();
			});
			client.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
			let mut response = Vec::new();
			client.read_to_end(&mut response).await.unwrap();
			serving.await.unwrap();
			let response = String::from_utf8(response).unwrap();
			assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
			assert!(response.contains("proxy_active_tunnels"));
		});
	}

	#[test]
	#[ignore = "requires a running proxy, curl, and controlled test-origin environment variables"]
	fn controlled_origin_functional_matrix() {
		let http_url = std::env::var("PROXY_TEST_HTTP_URL")
			.expect("set PROXY_TEST_HTTP_URL to an authorized plain-HTTP test endpoint");
		let https_url = std::env::var("PROXY_TEST_HTTPS_URL")
			.expect("set PROXY_TEST_HTTPS_URL to an authorized HTTPS test endpoint");
		let cacheable_url = std::env::var("PROXY_TEST_CACHEABLE_URL")
			.expect("set PROXY_TEST_CACHEABLE_URL to an endpoint returning public positive max-age");
		let proxy = format!("http://{PUBLIC_PROXY_ADDR}");
		let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };

		let run = |url: &str, proxy_headers: &[&str]| {
			let mut command = std::process::Command::new("curl");
			command.args([
				"--fail",
				"--silent",
				"--show-error",
				"--max-time",
				"120",
				"--proxy",
				&proxy,
				"--dump-header",
				"-",
				"--output",
				null_device,
			]);
			for header in proxy_headers {
				command.args(["--proxy-header", header]);
			}
			let output = command.arg(url).output().expect("curl must be installed");
			assert!(
				output.status.success(),
				"curl verification failed: {}",
				String::from_utf8_lossy(&output.stderr)
			);
			String::from_utf8_lossy(&output.stdout).into_owned()
		};

		run(&http_url, &[]);
		run(
			&https_url,
			&["X-Proxy-Isolation: verification-session", "X-Proxy-Isolation-Mode: session"],
		);
		run(
			&https_url,
			&["X-Proxy-Isolation: verification-session", "X-Proxy-Isolation-Mode: strict"],
		);
		run(&cacheable_url, &[]);
		let second_cache_response = run(&cacheable_url, &[]).to_ascii_lowercase();
		assert!(
			second_cache_response.contains("x-proxy-cache: hit"),
			"the second controlled cacheable request was not a verified cache hit"
		);
	}

	#[test]
	#[ignore = "opt-in local transport benchmark; not a Tor or publishable performance result"]
	fn benchmark_established_tunnel_transport() {
		Runtime::new().unwrap().block_on(async {
			const PAYLOAD_BYTES: usize = 1024 * 1024;
			for concurrency in [1_usize, 5, 10, 25, 50] {
				let workload_started = Instant::now();
				let mut transfers = Vec::with_capacity(concurrency);
				for _ in 0..concurrency {
					transfers.push(tokio::spawn(async move {
						let transfer_started = Instant::now();
						let (mut downstream_client, mut downstream_bridge) = tokio::io::duplex(64 * 1024);
						let (mut upstream_bridge, mut upstream_server) = tokio::io::duplex(64 * 1024);
						let bridge = tokio::spawn(async move {
							copy_bidirectional_with_idle_timeout(
								&mut downstream_bridge,
								&mut upstream_bridge,
								Duration::from_secs(30),
							).await.unwrap()
						});
						let client = tokio::spawn(async move {
							downstream_client.write_all(&vec![b'x'; PAYLOAD_BYTES]).await.unwrap();
							downstream_client.shutdown().await.unwrap();
							let mut response = Vec::new();
							downstream_client.read_to_end(&mut response).await.unwrap();
							assert_eq!(response.len(), PAYLOAD_BYTES);
						});
						let server = tokio::spawn(async move {
							let mut request = Vec::new();
							upstream_server.read_to_end(&mut request).await.unwrap();
							assert_eq!(request.len(), PAYLOAD_BYTES);
							upstream_server.write_all(&vec![b'y'; PAYLOAD_BYTES]).await.unwrap();
							upstream_server.shutdown().await.unwrap();
						});
						let (bridge_result, client_result, server_result) = tokio::join!(bridge, client, server);
						assert_eq!(bridge_result.unwrap(), (PAYLOAD_BYTES as u64, PAYLOAD_BYTES as u64));
						client_result.unwrap();
						server_result.unwrap();
						transfer_started.elapsed()
					}));
				}

				let mut latencies_ms = Vec::with_capacity(concurrency);
				for transfer in transfers {
					latencies_ms.push(transfer.await.unwrap().as_secs_f64() * 1_000.0);
				}
				latencies_ms.sort_by(f64::total_cmp);
				let percentile = |fraction: f64| {
					let index = ((latencies_ms.len() - 1) as f64 * fraction).round() as usize;
					latencies_ms[index]
				};
				let elapsed = workload_started.elapsed();
				let transferred_bytes = concurrency * PAYLOAD_BYTES * 2;
				let throughput_mib_s = transferred_bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
				eprintln!(
					"{{\"benchmark\":\"local_established_tunnel\",\"concurrency\":{concurrency},\"payload_bytes_each_direction\":{PAYLOAD_BYTES},\"throughput_mib_s\":{throughput_mib_s:.2},\"p50_ms\":{:.3},\"p95_ms\":{:.3},\"p99_ms\":{:.3}}}",
					percentile(0.50),
					percentile(0.95),
					percentile(0.99),
				);
			}
		});
	}

	#[test]
	fn destination_policy_rejects_local_network_targets() {
		assert!(!connect_destination_allowed("localhost:443").unwrap());
		assert!(!connect_destination_allowed("127.0.0.1:443").unwrap());
		assert!(!connect_destination_allowed("192.168.1.10:80").unwrap());
		assert!(!connect_destination_allowed("[::1]:443").unwrap());
		assert!(connect_destination_allowed("example.com:443").unwrap());
	}

	#[test]
	fn cache_key_includes_scheme_authority_port_path_and_query() {
		let request = cache_request(
			"GET",
			"https://Example.COM:8443/assets/app.js?v=2",
			"example.com:8443",
		);
		let (namespace, primary) = canonical_cache_key_parts(&request).unwrap();

		assert_eq!(namespace, "https://example.com:8443");
		assert_eq!(primary, "/assets/app.js?v=2");

		let other_host = cache_request("GET", "https://other.example/assets/app.js?v=2", "other.example");
		let other_port = cache_request("GET", "https://example.com:9443/assets/app.js?v=2", "example.com:9443");
		assert_ne!(canonical_cache_key_parts(&other_host).unwrap().0, namespace);
		assert_ne!(canonical_cache_key_parts(&other_port).unwrap().0, namespace);
	}

	#[test]
	fn cache_key_rejects_host_and_absolute_uri_disagreement() {
		let request = cache_request("GET", "http://attacker.example/item", "origin.example");

		assert!(canonical_cache_key_parts(&request).is_err());
	}

	#[test]
	fn cache_policy_requires_explicit_public_freshness() {
		let request = cache_request("GET", "http://example.com/item", "example.com");
		let public = cache_response("public, max-age=60");
		let private = cache_response("private, max-age=60");
		let implicit = cache_response("max-age=60");
		let no_freshness = cache_response("public");

		assert!(conservative_response_cacheable(&request, &public).is_cacheable());
		assert!(!conservative_response_cacheable(&request, &private).is_cacheable());
		assert!(!conservative_response_cacheable(&request, &implicit).is_cacheable());
		assert!(!conservative_response_cacheable(&request, &no_freshness).is_cacheable());
	}

	#[test]
	fn cache_policy_rejects_personalized_or_variant_content() {
		let mut authorized = cache_request("GET", "http://example.com/item", "example.com");
		authorized.insert_header(http::header::AUTHORIZATION, "Bearer secret").unwrap();
		let mut cookie = cache_request("GET", "http://example.com/item", "example.com");
		cookie.insert_header(http::header::COOKIE, "session=secret").unwrap();
		let mut set_cookie = cache_response("public, s-maxage=60");
		set_cookie.insert_header(http::header::SET_COOKIE, "session=secret").unwrap();
		let mut vary = cache_response("public, s-maxage=60");
		vary.insert_header(http::header::VARY, "Accept-Encoding").unwrap();
		let public = cache_response("public, s-maxage=60");

		assert!(!request_cache_eligible(&authorized));
		assert!(!request_cache_eligible(&cookie));
		assert!(!conservative_response_cacheable(&authorized, &public).is_cacheable());
		assert!(!conservative_response_cacheable(&cookie, &public).is_cacheable());
		let ordinary = cache_request("GET", "http://example.com/item", "example.com");
		assert!(!conservative_response_cacheable(&ordinary, &set_cookie).is_cacheable());
		assert!(!conservative_response_cacheable(&ordinary, &vary).is_cacheable());
	}

	#[test]
	fn read_proxy_request_preserves_pipelined_bytes() {
		Runtime::new().unwrap().block_on(async {
			let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\ntls-data";
			let (mut client, mut server) = tokio::io::duplex(256);
			client.write_all(request).await.unwrap();

			let (parsed, buffered) = read_proxy_request(&mut server).await.unwrap();
			assert_eq!(parsed.destination.as_deref(), Some("example.com:443"));
			assert_eq!(&buffered[parsed.header_len..], b"tls-data");
		});
	}

	#[test]
	fn circuit_semaphore_limits_concurrent_builds() {
		Runtime::new().unwrap().block_on(async {
			const CAPACITY: usize = 2;
			let semaphore = Arc::new(Semaphore::new(CAPACITY));
			let first_permit = semaphore.clone().acquire_owned().await.unwrap();
			let second_permit = semaphore.clone().acquire_owned().await.unwrap();

			let waiting_semaphore = semaphore.clone();
			let waiting_attempt = tokio::spawn(async move {
				waiting_semaphore.acquire_owned().await.unwrap()
			});
			tokio::task::yield_now().await;
			assert!(!waiting_attempt.is_finished());
			assert_eq!(semaphore.available_permits(), 0);

			drop(first_permit);
			let third_permit = timeout(Duration::from_millis(250), waiting_attempt)
				.await
				.expect("waiting acquire should complete after a permit is released")
				.unwrap();
			assert_eq!(semaphore.available_permits(), 0);

			drop(second_permit);
			drop(third_permit);
			assert_eq!(semaphore.available_permits(), CAPACITY);
		});
	}

	#[test]
	fn rate_limit_guard_releases_its_owned_permit() {
		Runtime::new().unwrap().block_on(async {
			let semaphore = Arc::new(Semaphore::new(1));
			let metrics = CircuitMetrics::default();
			let mut sink = tokio::io::sink();

			let guard = acquire_circuit_permit(
				&mut sink,
				semaphore.clone(),
				&metrics,
				Duration::from_millis(25),
			).await.unwrap();
			assert_eq!(semaphore.available_permits(), 0);
			assert_eq!(metrics.queued_circuit_builds.load(Ordering::Relaxed), 0);

			drop(guard);
			assert_eq!(semaphore.available_permits(), 1);
		});
	}

	#[test]
	fn cancelled_circuit_wait_cleans_up_its_queue_metric() {
		Runtime::new().unwrap().block_on(async {
			let semaphore = Arc::new(Semaphore::new(1));
			let _held_permit = semaphore.clone().acquire_owned().await.unwrap();
			let metrics = Arc::new(CircuitMetrics::default());
			let task_metrics = metrics.clone();
			let waiting = tokio::spawn(async move {
				let mut sink = tokio::io::sink();
				acquire_circuit_permit(
					&mut sink,
					semaphore,
					&task_metrics,
					Duration::from_secs(30),
				).await
			});

			timeout(Duration::from_millis(250), async {
				while metrics.queued_circuit_builds.load(Ordering::Relaxed) != 1 {
					tokio::task::yield_now().await;
				}
			}).await.expect("circuit acquire should enter the wait queue");

			waiting.abort();
			let _ = waiting.await;
			assert_eq!(metrics.queued_circuit_builds.load(Ordering::Relaxed), 0);
		});
	}

	#[test]
	fn circuit_acquire_times_out_when_capacity_stays_saturated() {
		Runtime::new().unwrap().block_on(async {
			let semaphore = Arc::new(Semaphore::new(1));
			let _held_permit = semaphore.clone().acquire_owned().await.unwrap();
			let metrics = CircuitMetrics::default();
			let mut sink = tokio::io::sink();
			let short_timeout = Duration::from_millis(25);
			let started = Instant::now();

			let result = acquire_circuit_permit(
				&mut sink,
				semaphore,
				&metrics,
				short_timeout,
			).await;
			let elapsed = started.elapsed();

			assert!(result.is_err());
			assert!(result.unwrap_err().to_string().contains("circuit capacity exceeded"));
			assert!(elapsed >= short_timeout);
			assert!(elapsed < Duration::from_millis(500));
			assert_eq!(metrics.acquire_timeouts.load(Ordering::Relaxed), 1);
			assert_eq!(metrics.queued_circuit_builds.load(Ordering::Relaxed), 0);
		});
	}

	#[test]
	fn circuit_acquire_timeout_writes_service_unavailable_response() {
		Runtime::new().unwrap().block_on(async {
			let semaphore = Arc::new(Semaphore::new(1));
			let _held_permit = semaphore.clone().acquire_owned().await.unwrap();
			let metrics = CircuitMetrics::default();
			let (mut client, mut server) = tokio::io::duplex(256);

			let result = acquire_circuit_permit(
				&mut server,
				semaphore,
				&metrics,
				Duration::from_millis(10),
			).await;
			assert!(result.is_err());
			drop(server);

			let mut response = Vec::new();
			client.read_to_end(&mut response).await.unwrap();
			assert_eq!(
				response,
				b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			);
			assert_eq!(metrics.queued_circuit_builds.load(Ordering::Relaxed), 0);
		});
	}

	#[test]
	fn closed_circuit_admission_returns_service_unavailable() {
		Runtime::new().unwrap().block_on(async {
			let semaphore = Arc::new(Semaphore::new(1));
			semaphore.close();
			let metrics = CircuitMetrics::default();
			let (mut client, mut server) = tokio::io::duplex(256);

			let result = acquire_circuit_permit(
				&mut server,
				semaphore,
				&metrics,
				Duration::from_millis(25),
			).await;
			assert!(result.unwrap_err().to_string().contains("semaphore closed"));
			drop(server);

			let mut response = Vec::new();
			client.read_to_end(&mut response).await.unwrap();
			assert_eq!(response, super::CIRCUIT_CAPACITY_RESPONSE);
			assert_eq!(metrics.acquire_timeouts.load(Ordering::Relaxed), 0);
			assert_eq!(metrics.queued_circuit_builds.load(Ordering::Relaxed), 0);
		});
	}
}
