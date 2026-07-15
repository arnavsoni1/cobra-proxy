use pingora::{
	prelude::*, 
	cache::{
		MemCache, HttpCache, CacheMeta, Storage, 
		trace::SpanHandle,
		CacheKey
	},
	protocols::http::ServerSession,
	proxy::{Session, ProxyHttp},
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
	StreamPrefs
};
use tor_rtcompat::PreferredRuntime;
use tokio::{
	io::{self, AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt},
	runtime::Runtime, 
	net::{TcpListener, TcpStream},
	time::Duration
	//sync::{Semaphore, SemaphorePermit}
};
//use anyhow::*;

static CACHE: OnceLock<MemCache> = OnceLock::new();
fn cache() -> &'static MemCache {
	CACHE.get_or_init(MemCache::new)
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
			.unwrap_or("ipinfo.io");
		// let peer = HttpPeer::new("ipinfo.io:80", false, "ipinfo.io".to_string());
		let port = 80;
		let dest = format!("{host}:{port}");
		
		let mut peer = HttpPeer::new(
			"ipinfo.io:80",
			false, //tls
			host.to_string()
		);
		peer.proxy = Some(CrateProxy {
			next_hop: Box::from(Path::new("127.0.0.1:19050")),
			host: "ipinfo.io".to_string(),  
			port: 80,                 
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
		match upstream_request.insert_header("Host", "ipinfo.io") {
			Ok(()) => {},
			Err(e) => { 
				eprintln!("{}", e);
				process::exit(1);
			}
		};
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
                None, // eviction policy  
                None, // cache predictor 
                None, // distributed lock 
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
		tor: TorClient<PreferredRuntime>,
		token_store: MemoryCache<String, IsolationToken>
	) -> Self {
		Self {
			tor: Arc::new(tor),
			token_store: Arc::new(token_store)
		}
	}
	
	pub async fn run_bridge(
		tor: Arc<TorClient<PreferredRuntime>>,
		token_store: Arc<MemoryCache<String, IsolationToken>>
	) {
		let addr = "127.0.0.1:19050";
		let listener = TcpListener::bind(&addr).await.unwrap();
		
		loop {
			match listener.accept().await {
				Ok((stream, peer)) => {
					let tor = tor.clone();
					let ts = token_store.clone();
					tokio::spawn(async move {
						if let Err(e) = Self::handle_connect(stream, tor, ts).await {
							eprintln!("[bridge] {peer}: {e}");
						}
					});
				}
				Err(e) => eprintln!("[bridge] accept: {e}"),
			}
		}
	}
	
	async fn handle_connect(
		mut stream: TcpStream,
		tor: Arc<TorClient<PreferredRuntime>>,
		token_store: Arc<MemoryCache<String, IsolationToken>>
	) -> anyhow::Result<()> {
		//let (reader, mut writer) = io::split(stream);
		//let mut reader = BufReader::new(reader);
		
		let dest = {
			let mut reader = BufReader::new(&mut stream);
			let mut line   = String::new();
			reader.read_line(&mut line).await?;

			let mut header = String::new();
			loop {
				reader.read_line(&mut header).await?;
				if header.trim().is_empty() { break; }
				header.clear();
			}

			line.split_whitespace()
				.nth(1)
				.ok_or_else(|| anyhow::anyhow!("malformed CONNECT line"))?
				.to_string()
		};
		
		let token = match token_store.get(&dest) {
			(Some(t), _) => t,
			(None,    _) => {
				let t = IsolationToken::new();
				token_store.put(&dest, t, None);
				t
			}
		};
		
		let temp_dest = "ipinfo.io:80";
		
		let mut prefs = StreamPrefs::new();
		prefs.set_isolation(token);
		
		let mut tor_stream = match tor.connect_with_prefs(&temp_dest, &prefs).await {
			Ok(s)  => {
				stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
				s
			}
			Err(e) => {
				stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
				anyhow::bail!("tor→{dest}: {e}");
			}
		};
		
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

//impl BridgeSession for Bridge {
//	fn finish()
//	fn persist_token()
//	fn rotate_token()
//}

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
	let tor_client: Arc<TorClient<PreferredRuntime>> = {
		let rt = Runtime::new().unwrap();
		let client = rt.block_on(async {
			match TorClient::create_bootstrapped(config).await {
				Ok(client) => client,
				Err(e) => {
					eprintln!("{}", e);
					process::exit(1);
				}
			}
		});
		Arc::new(client)
	};
	
	let token_store: Arc<MemoryCache<String, IsolationToken>> = Arc::new(MemoryCache::new(10_000));
	
	{
        let tor   = tor_client.clone();
        let store = token_store.clone();
        std::thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(Bridge::run_bridge(tor, store));
        });
    }
	
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
	
	let mut service = http_proxy_service(&server.configuration, Proxy { 
		request_counter: 0.into(), 
		cache: token_store.clone(),
		//isolation_manager: IsolationHelper::new() ### Error, no constructors for traits
		tor_client: tor_client.clone()
	});
	
	service.add_tcp("127.0.0.1:8080");
	server.add_service(service);
	server.run_forever();
}
