use pingora::{
	prelude::*, 
	cache::{
		MemCache, HttpCache, CacheMeta, Storage, 
		//trace::SpanHandle,
		CacheKey
	},
	protocols::http::ServerSession,
	proxy::{Session, ProxyHttp},
	Error
};
use async_trait::async_trait;
use std::{
	process,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc, OnceLock
	}
	//error::Error
};
use pingora_memory_cache::MemoryCache; 
use arti_client::{
	IsolationToken,
	//isolation::IsolationHelper,
	TorClient, TorClientConfig
};
use tor_rtcompat::PreferredRuntime;
use tokio::{
	io::{self, AsyncReadExt, AsyncWriteExt, BufReader},
	runtime::Runtime, 
	net::{TcpListener, TcpStream}
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
		let peer = HttpPeer::new("ipinfo.io:80", false, "ipinfo.io".to_string());
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
		tor: TorClient<PreferredRuntime>,
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
		stream: TcpStream,
		tor: TorClient<PreferredRuntime>,
		token_store: Arc<MemoryCache<String, IsolationToken>>
	) -> anyhow::Result<()> {
		let (reader, mut writer) = io::split(stream);
		let mut reader = BufReader::new(reader);
		
		Ok(()) //for now
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
		cache: Arc::new(MemoryCache::new(10_000)),
		//isolation_manager: IsolationHelper::new() ### Error, no constructors for traits
		tor_client: tor_client.clone()
	});
	
	service.add_tcp("127.0.0.1:8080");
	server.add_service(service);
	server.run_forever();
}
