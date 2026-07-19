use pingora::{
	prelude::*, 
	cache::{
		MemCache, HttpCache, CacheMeta, Storage, 
		eviction::{EvictionManager, lru::Manager as LruEvictionManager},
		lock::CacheLock,
		trace::SpanHandle,
		CacheKey
	},
	apps::HttpServerOptions,
	protocols::http::ServerSession,
	proxy::{Session, ProxyHttp, ProxyServiceBuilder},
	Error,
	upstreams::peer::Proxy as CrateProxy,
};
use async_trait::async_trait;
use std::{
	process,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc, OnceLock
	},
	marker::PhantomData,
	path::Path
	//error::Error
};
use pingora_memory_cache::MemoryCache; 
use arti_client::{
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
	sync::{OwnedSemaphorePermit, Semaphore},
	time::Duration
	//sync::{Semaphore, SemaphorePermit}
};
//use anyhow::*;

static CACHE: OnceLock<MemCache> = OnceLock::new();
static CACHE_LOCK: OnceLock<CacheLock> = OnceLock::new();
static CACHE_EVICTION: OnceLock<LruEvictionManager<CACHE_LRU_SHARDS>> = OnceLock::new();
const CACHE_MAX_BYTES: usize = 128 * 1024 * 1024;
const CACHE_LRU_SHARDS: usize = 16;
const CACHE_ITEMS_PER_SHARD: usize = 1_024;
const CACHE_LOCK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONNECT_HEADERS: usize = 64;
const BRIDGE_SOCKET: &str = "/tmp/proxy-bridge.sock";
// Tune based on VPS bandwidth and observed circuit build latency.
const MAX_CONCURRENT_CIRCUIT_BUILDS: usize = 32;
const CIRCUIT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10); // tune later
const CIRCUIT_METRICS_LOG_INTERVAL: Duration = Duration::from_secs(30);
const CIRCUIT_CAPACITY_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

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

fn parse_connect_request(buffer: &[u8]) -> anyhow::Result<Option<(String, usize)>> {
	let mut headers = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
	let mut request = httparse::Request::new(&mut headers);
	let httparse::Status::Complete(header_len) = request
		.parse(buffer)
		.map_err(|error| anyhow::anyhow!("malformed HTTP request: {error}"))?
	else {
		return Ok(None);
	};

	if header_len > MAX_CONNECT_HEADER_BYTES {
		anyhow::bail!("CONNECT request headers exceed {MAX_CONNECT_HEADER_BYTES} bytes");
	}
	if request.method != Some("CONNECT") {
		anyhow::bail!("expected CONNECT request");
	}

	let destination = request
		.path
		.filter(|destination| !destination.is_empty())
		.ok_or_else(|| anyhow::anyhow!("CONNECT request is missing a destination"))?;

	Ok(Some((destination.to_owned(), header_len)))
}

fn parse_connect_destination(destination: &str) -> anyhow::Result<TorAddr> {
	TorAddr::from(destination)
		.map_err(|error| anyhow::anyhow!("invalid CONNECT destination {destination:?}: {error}"))
}

async fn read_connect_request<S>(stream: &mut S) -> anyhow::Result<(String, Vec<u8>)>
where
	S: tokio::io::AsyncRead + Unpin,
{
	let mut buffer = Vec::with_capacity(1024);
	let mut chunk = [0_u8; 1024];

	loop {
		if let Some((destination, header_len)) = parse_connect_request(&buffer)? {
			return Ok((destination, buffer[header_len..].to_vec()));
		}
		if buffer.len() == MAX_CONNECT_HEADER_BYTES {
			anyhow::bail!("CONNECT request headers exceed {MAX_CONNECT_HEADER_BYTES} bytes");
		}

		let remaining = MAX_CONNECT_HEADER_BYTES - buffer.len();
		let read_capacity = remaining.min(chunk.len());
		let read = stream.read(&mut chunk[..read_capacity]).await?;
		if read == 0 {
			anyhow::bail!("connection closed before a complete CONNECT request was received");
		}
		buffer.extend_from_slice(&chunk[..read]);
	}
}

pub struct Proxy{
	request_counter: AtomicUsize,
	cache: Arc<MemoryCache<String, IsolationToken>>,
	//isolation_manager: IsolationHelper,
	tor_client: Arc<TorClient<PreferredRuntime>>
}

pub struct RequestCtx{
	id: Option<i64>,
	token: IsolationToken,
}

//pub struct RateLimitGuard {
//	semaphore: Arc<Semaphore>, 
//	permit: SemaphorePermit<'static>
//}

pub struct CircuitHandle<'session, Phase> {
	token: IsolationToken,
	phase: PhantomData<Phase>,
	lifetime: PhantomData<&'session ()>
	// guard: RateLimitGuard
}

#[derive(Default)]
struct CircuitMetrics {
	acquire_timeouts: AtomicUsize,
	circuit_build_count: AtomicUsize,
	circuit_build_latency_micros: AtomicUsize,
}

impl CircuitMetrics {
	fn record_build_latency(&self, latency: Duration) {
		let latency_micros = latency.as_micros().min(usize::MAX as u128) as usize;
		self.circuit_build_latency_micros.fetch_add(latency_micros, Ordering::Relaxed);
		self.circuit_build_count.fetch_add(1, Ordering::Relaxed);
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

		eprintln!(
			"[bridge] circuit metrics: permits_in_use={permits_in_use} acquire_timeouts={acquire_timeouts} circuit_build_count={circuit_build_count} average_build_latency_ms={average_latency_ms:.2}"
		);
	}
}

async fn acquire_circuit_permit<S>(
	stream: &mut S,
	circuit_semaphore: Arc<Semaphore>,
	circuit_metrics: &CircuitMetrics,
	acquire_timeout: Duration,
) -> anyhow::Result<OwnedSemaphorePermit>
where
	S: tokio::io::AsyncWrite + Unpin,
{
	match tokio::time::timeout(acquire_timeout, circuit_semaphore.acquire_owned()).await {
		Ok(Ok(permit)) => Ok(permit),
		Ok(Err(error)) => anyhow::bail!("circuit admission semaphore closed: {error}"),
		Err(_) => {
			circuit_metrics.acquire_timeouts.fetch_add(1, Ordering::Relaxed);
			let _ = stream.write_all(CIRCUIT_CAPACITY_RESPONSE).await;
			anyhow::bail!("circuit capacity exceeded, request timed out waiting for a slot");
		}
	}
}

#[derive(Clone)]
pub struct Bridge{
	tor: Arc<TorClient<PreferredRuntime>>,
	token_store: Arc<MemoryCache<String, IsolationToken>>,
	circuit_semaphore: Arc<Semaphore>,
	circuit_metrics: Arc<CircuitMetrics>,
	//port: u16
}

pub struct TorCircuit {
	runtime: Runtime,
	client: Arc<TorClient<PreferredRuntime>>,
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

	pub fn start_bridge(
		&self,
		token_store: Arc<MemoryCache<String, IsolationToken>>,
	) {
		let tor = self.client();
		self.runtime.spawn(async move {
			if let Err(error) = Bridge::new(tor, token_store).run_bridge().await {
				eprintln!("[bridge] failed to run: {error}");
			}
		});
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

trait BridgeSession {
	fn finish(
		&self,
		storage: &'static (dyn Storage + Sync),
		trace: SpanHandle,
		session: &mut Session,
		token: IsolationToken
	) -> Result<()>;
	
	fn persist_token(
        &self,
        storage: &'static (dyn Storage + Sync),
        key: &str,
        token: IsolationToken,
        ttl: Option<Duration>,
    ) -> Result<()>;
	
	fn rotate_token(
        &self,
        storage: &'static (dyn Storage + Sync),
        key: &str,
    ) -> Result<IsolationToken>;
	
}

#[async_trait]
impl ProxyHttp for Proxy {
	
	type CTX = RequestCtx;
	
	fn new_ctx(&self) -> Self::CTX {
		RequestCtx{
			id: None,
			token: IsolationToken::new(),
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
		peer.proxy = Some(CrateProxy {
			next_hop: Box::from(Path::new(BRIDGE_SOCKET)),
			host,
			port,
			headers: Default::default()
		});
		Ok(Box::new(peer))
	}
	
	async fn upstream_request_filter(
		&self, 
		session: &mut Session,
		upstream_request: &mut RequestHeader,
		ctx: &mut Self::CTX
	) -> Result<()> {
		Ok(())
	}
	
	async fn request_filter(
		&self, 
		session: &mut Session,
		ctx: &mut Self::CTX,
	) -> Result<bool> {
		let new_id = self.request_counter.fetch_add(1, Ordering::Relaxed);
		ctx.id = Some(new_id as i64);
		Ok(false)
	}
	
	fn request_cache_filter(
		&self, 
		session: &mut Session,
		ctx: &mut Self::CTX
	) -> Result<()> {
		if session.req_header().method == http::Method::GET {
            session.cache.enable(
                cache(),
				Some(cache_eviction()), // eviction policy
                None, // cache predictor 
				Some(cache_lock()), // process-local cache lock
				None  // cache option override
            );
        }
		Ok(())
	}
	
	fn cache_key_callback(
		&self, 
		session: &Session,
		ctx: &mut Self::CTX
	) -> Result<CacheKey> {
		let request = session.req_header();
		let host = request.headers.get(http::header::HOST).and_then(|v| v.to_str().ok());
		let key = format!("{}:{:?}:{}", request.method.as_str(), host, request.uri.path());
		
		match self.cache.get(&key) {
			(Some(existing_key), status) => {
				ctx.token = existing_key;
			}
			(None, status) => {
				self.cache.put(&key.clone(), ctx.token, None);
			}
		};
		
		Ok(CacheKey::new(
			request.method.as_str(),
			format!("{:?}:{}", host, request.uri.path()),
			request.uri.query().unwrap_or("Empty-Response-From-Server")
		))
	}
	
	async fn response_filter(
		&self,
		session: &mut Session,
		upstream_response: &mut ResponseHeader,
		ctx: &mut Self::CTX,
	) -> Result<(), Box<Error>> {
		match Self::extract_id(ctx.id) {
            Ok(id_string) => {
                match upstream_response.insert_header("Server-Response-ID", id_string) {
                    Ok(_) => {},
                    Err(e) => return Err(e.into()),
                }
            }
            Err(error_message) => {
                eprintln!("{}", error_message);
            }
        }
		
		Ok(())
	}
	
}

impl Bridge {
	pub fn new(
		tor: Arc<TorClient<PreferredRuntime>>,
		token_store: Arc<MemoryCache<String, IsolationToken>>
	) -> Self {
		Self {
			tor,
			token_store,
			circuit_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CIRCUIT_BUILDS)),
			circuit_metrics: Arc::new(CircuitMetrics::default()),
		}
	}
	
	pub async fn run_bridge(self) -> anyhow::Result<()> {
		match std::fs::remove_file(BRIDGE_SOCKET) {
			Ok(()) => {}
			Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error.into()),
		}
		let listener = UnixListener::bind(BRIDGE_SOCKET)?;
		let circuit_semaphore = self.circuit_semaphore.clone();
		let circuit_metrics = self.circuit_metrics.clone();
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(CIRCUIT_METRICS_LOG_INTERVAL);
			interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
			// Tokio intervals tick immediately once; consume that tick so metrics are periodic.
			interval.tick().await;
			loop {
				interval.tick().await;
				circuit_metrics.log(&circuit_semaphore);
			}
		});
		
		loop {
			match listener.accept().await {
				Ok((stream, _)) => {
					let tor = self.tor.clone();
					let ts = self.token_store.clone();
					let circuit_semaphore = self.circuit_semaphore.clone();
					let circuit_metrics = self.circuit_metrics.clone();
					tokio::spawn(async move {
						if let Err(e) = Self::handle_connect(
							stream,
							tor,
							ts,
							circuit_semaphore,
							circuit_metrics,
						).await {
							eprintln!("[bridge] {e}");
						}
					});
				}
				Err(e) => eprintln!("[bridge] accept: {e}"),
			}
		}
	}
	
	async fn handle_connect(
		mut stream: UnixStream,
		tor: Arc<TorClient<PreferredRuntime>>,
		token_store: Arc<MemoryCache<String, IsolationToken>>,
		circuit_semaphore: Arc<Semaphore>,
		circuit_metrics: Arc<CircuitMetrics>,
	) -> anyhow::Result<()> {
		let (dest, buffered_tunnel_data) = match read_connect_request(&mut stream).await {
			Ok(request) => request,
			Err(error) => {
				let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
				return Err(error);
			}
		};
		let target = match parse_connect_destination(&dest) {
			Ok(target) => target,
			Err(error) => {
				let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
				return Err(error);
			}
		};
		
		let token = match token_store.get(&dest) {
			(Some(t), _) => t,
			(None,    _) => {
				let t = IsolationToken::new();
				token_store.put(&dest, t, None);
				t
			}
		};
		
		let mut prefs = StreamPrefs::new();
		prefs.set_isolation(token);
		
		let circuit_permit = acquire_circuit_permit(
			&mut stream,
			circuit_semaphore,
			&circuit_metrics,
			CIRCUIT_ACQUIRE_TIMEOUT,
		).await?;
		let circuit_build_started = tokio::time::Instant::now();
		let connect_result = tor.connect_with_prefs(target, &prefs).await;
		circuit_metrics.record_build_latency(circuit_build_started.elapsed());
		// Option A: this permit guards only circuit build/connect work. Holding it for
		// copy_bidirectional would cap long-lived tunnels instead of the costly setup step.
		drop(circuit_permit);

		let mut tor_stream = match connect_result {
			Ok(s)  => {
				stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
				s
			}
			Err(e) => {
				stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
				anyhow::bail!("tor→{dest}: {e}");
			}
		};
		if !buffered_tunnel_data.is_empty() {
			tor_stream.write_all(&buffered_tunnel_data).await?;
		}
		
		tokio::io::copy_bidirectional(&mut stream, &mut tor_stream).await?;
		Ok(()) //for now
	}
}

impl Bridge {
	fn open_circuit<'a, Startup>(
		&self,
		session: &'a mut Session,
		token: IsolationToken
	) -> CircuitHandle<'a, Startup> {
		CircuitHandle {
			token,
			phase: PhantomData,
			lifetime: PhantomData
		}
	}
}

impl BridgeSession for Bridge {
	fn finish(
		&self,
		storage: &'static (dyn Storage + Sync),
		_trace: SpanHandle,
		session: &mut Session,
		token: IsolationToken
	) -> Result<()> {
		let host = session
			.req_header()
			.headers
			.get(http::header::HOST)
			.and_then(|value| value.to_str().ok())
			.ok_or_else(|| Error::new(InvalidHTTPHeader))?;
		let authority = host
			.parse::<http::uri::Authority>()
			.map_err(|_| Error::new(InvalidHTTPHeader))?;
		let key = format!(
			"{}:{}",
			authority.host(),
			authority.port_u16().unwrap_or(80)
		);

		self.persist_token(storage, &key, token, None)
	}

	fn persist_token(
		&self,
		_storage: &'static (dyn Storage + Sync),
		key: &str,
		token: IsolationToken,
		ttl: Option<Duration>,
	) -> Result<()> {
		self.token_store.put(key, token, ttl);
		Ok(())
	}

	fn rotate_token(
		&self,
		storage: &'static (dyn Storage + Sync),
		key: &str,
	) -> Result<IsolationToken> {
		let token = IsolationToken::new();
		self.persist_token(storage, key, token, None)?;
		Ok(token)
	}
}

//#[tokio::main]
fn main() -> Result<()> {
	let config = TorClientConfig::default();
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
	
	let token_store: Arc<MemoryCache<String, IsolationToken>> = Arc::new(MemoryCache::new(10_000));
	tor_circuit.start_bridge(token_store.clone());
	
	let mut server =  match Server::new(None) {
		Ok(s) => {
			s
		}
		Err(e) => {
			eprintln!("{}", e);
			process::exit(1);
		}
	};
	server.bootstrap();
	
	let mut http_options = HttpServerOptions::default();
	http_options.allow_connect_method_proxying = true;

	let mut service = ProxyServiceBuilder::new(&server.configuration, Proxy {
		request_counter: 0.into(), 
		cache: token_store.clone(),
		//isolation_manager: IsolationHelper::new() ### Error, no constructors for traits
		tor_client: tor_client.clone()
	})
	.server_options(http_options)
	.build();
	
	service.add_tcp("127.0.0.1:8080");
	server.add_service(service);
	server.run_forever();
}

#[cfg(test)]
mod tests {
	use super::{
		acquire_circuit_permit, parse_connect_destination, parse_connect_request,
		CircuitMetrics,
	};
	use std::sync::{
		atomic::Ordering,
		Arc,
	};
	use tokio::{
		io::AsyncReadExt,
		runtime::Runtime,
		sync::Semaphore,
		time::{timeout, Duration, Instant},
	};

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
		});
	}
}
