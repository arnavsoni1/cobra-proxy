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

#[derive(Clone)]
pub struct Bridge{
	tor: Arc<TorClient<PreferredRuntime>>,
	token_store: Arc<MemoryCache<String, IsolationToken>>,
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
			token_store
		}
	}
	
	pub async fn run_bridge(self) -> anyhow::Result<()> {
		match std::fs::remove_file(BRIDGE_SOCKET) {
			Ok(()) => {}
			Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error.into()),
		}
		let listener = UnixListener::bind(BRIDGE_SOCKET)?;
		
		loop {
			match listener.accept().await {
				Ok((stream, _)) => {
					let tor = self.tor.clone();
					let ts = self.token_store.clone();
					tokio::spawn(async move {
						if let Err(e) = Self::handle_connect(stream, tor, ts).await {
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
		token_store: Arc<MemoryCache<String, IsolationToken>>
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
		
		let mut tor_stream = match tor.connect_with_prefs(target, &prefs).await {
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
	use super::{parse_connect_destination, parse_connect_request};

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
}
