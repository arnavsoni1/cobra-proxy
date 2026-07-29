//! Typed configuration and TLS construction for the private ingress.
//!
//! Socket ownership and request dispatch stay in `main.rs`; production runtime
//! configuration from this module is connected there to a bounded
//! `tokio_rustls::TlsAcceptor` loop.

use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use rustls_pemfile::Item;
use std::{
    error::Error as StdError,
    fmt,
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub(crate) const HTTP_1_1_ALPN: &[u8] = b"http/1.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeploymentMode {
    Development,
    Production,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientCertificateMode {
    Required,
    DisabledForDevelopment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApiKeyMode {
    Required,
    DisabledForDevelopment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AlpnPolicy {
    Http11Only,
}

impl AlpnPolicy {
    fn wire_protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Http11Only => vec![HTTP_1_1_ALPN.to_vec()],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateReloadStrategy {
    /// Validate all replacement material before atomically making it available
    /// to new handshakes. Established TLS connections retain their snapshot.
    ValidateThenAtomicSwap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CertificateRotationPolicy {
    pub reload_strategy: CertificateReloadStrategy,
    /// Time during which old and new client trust material may overlap during
    /// a planned rotation. Emergency revocation is handled separately.
    pub trust_overlap: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IngressTimeouts {
    pub tls_handshake: Duration,
    pub first_request: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IngressCapacity {
    /// The public accept loop acquires this dedicated limit before TLS work.
    pub max_concurrent_handshakes: usize,
    pub max_client_connections: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TlsMaterialPaths {
    pub server_certificate_chain: PathBuf,
    pub server_private_key: PathBuf,
    pub client_ca_roots: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IngressConfig {
    pub listen_addr: SocketAddr,
    pub server_names: Vec<String>,
    pub deployment_mode: DeploymentMode,
    pub tls_material: TlsMaterialPaths,
    pub client_certificates: ClientCertificateMode,
    pub api_keys: ApiKeyMode,
    pub alpn: AlpnPolicy,
    pub timeouts: IngressTimeouts,
    pub capacity: IngressCapacity,
    pub certificate_rotation: CertificateRotationPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeIngressConfig {
    Development {
        listen_addr: SocketAddr,
    },
    Production {
        tls: Box<IngressConfig>,
        account_database: PathBuf,
        api_key_hash_key_file: PathBuf,
        max_cached_accounts: usize,
        usage_period: Duration,
    },
}

impl RuntimeIngressConfig {
    pub(crate) fn from_environment() -> Result<Self, PrivateIngressError> {
        Self::from_lookup(&|name| {
            let Some(value) = std::env::var_os(name) else {
                return Ok(None);
            };
            value
                .into_string()
                .map(Some)
                .map_err(|_| PrivateIngressError::RuntimeConfiguration {
                    variable: name,
                    detail: "value is not valid UTF-8".to_owned(),
                })
        })
    }

    fn from_lookup<F>(lookup: &F) -> Result<Self, PrivateIngressError>
    where
        F: Fn(&'static str) -> Result<Option<String>, PrivateIngressError>,
    {
        const MODE: &str = "PROXY_INGRESS_MODE";
        const LISTEN_ADDR: &str = "PROXY_INGRESS_LISTEN_ADDR";
        const SERVER_NAMES: &str = "PROXY_INGRESS_SERVER_NAMES";
        const SERVER_CERT: &str = "PROXY_INGRESS_SERVER_CERT";
        const SERVER_KEY: &str = "PROXY_INGRESS_SERVER_KEY";
        const CLIENT_CA: &str = "PROXY_INGRESS_CLIENT_CA";
        const ACCOUNT_DATABASE: &str = "PROXY_ACCOUNT_DATABASE";
        const API_KEY_HASH_KEY_FILE: &str = "PROXY_API_KEY_HASH_KEY_FILE";
        const TLS_HANDSHAKE_SECONDS: &str = "PROXY_TLS_HANDSHAKE_TIMEOUT_SECONDS";
        const FIRST_REQUEST_SECONDS: &str = "PROXY_FIRST_REQUEST_TIMEOUT_SECONDS";
        const MAX_HANDSHAKES: &str = "PROXY_MAX_CONCURRENT_TLS_HANDSHAKES";
        const MAX_CONNECTIONS: &str = "PROXY_MAX_CLIENT_CONNECTIONS";
        const TRUST_OVERLAP_SECONDS: &str = "PROXY_CERT_TRUST_OVERLAP_SECONDS";
        const MAX_CACHED_ACCOUNTS: &str = "PROXY_MAX_CACHED_ACCOUNTS";
        const USAGE_PERIOD_SECONDS: &str = "PROXY_USAGE_PERIOD_SECONDS";

        let mode = optional_value(lookup, MODE)?
            .unwrap_or_else(|| "development".to_owned())
            .trim()
            .to_ascii_lowercase();
        if mode == "development" {
            let production_only = [
                SERVER_NAMES,
                SERVER_CERT,
                SERVER_KEY,
                CLIENT_CA,
                ACCOUNT_DATABASE,
                API_KEY_HASH_KEY_FILE,
                TLS_HANDSHAKE_SECONDS,
                FIRST_REQUEST_SECONDS,
                MAX_HANDSHAKES,
                MAX_CONNECTIONS,
                TRUST_OVERLAP_SECONDS,
                MAX_CACHED_ACCOUNTS,
                USAGE_PERIOD_SECONDS,
            ];
            for variable in production_only {
                if optional_value(lookup, variable)?.is_some() {
                    return Err(PrivateIngressError::RuntimeConfiguration {
                        variable: MODE,
                        detail:
                            "production credential settings require PROXY_INGRESS_MODE=production"
                                .to_owned(),
                    });
                }
            }
            let listen_addr = optional_value(lookup, LISTEN_ADDR)?
                .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
                .parse::<SocketAddr>()
                .map_err(|error| PrivateIngressError::RuntimeConfiguration {
                    variable: LISTEN_ADDR,
                    detail: error.to_string(),
                })?;
            if !listen_addr.ip().is_loopback() {
                return Err(PrivateIngressError::RuntimeConfiguration {
                    variable: LISTEN_ADDR,
                    detail: "development plaintext ingress must remain loopback-only".to_owned(),
                });
            }
            return Ok(Self::Development { listen_addr });
        }
        if mode != "production" {
            return Err(PrivateIngressError::RuntimeConfiguration {
                variable: MODE,
                detail: "expected development or production".to_owned(),
            });
        }

        let listen_addr = required_value(lookup, LISTEN_ADDR)?
            .parse::<SocketAddr>()
            .map_err(|error| PrivateIngressError::RuntimeConfiguration {
                variable: LISTEN_ADDR,
                detail: error.to_string(),
            })?;
        let server_names = required_value(lookup, SERVER_NAMES)?
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let tls = IngressConfig {
            listen_addr,
            server_names,
            deployment_mode: DeploymentMode::Production,
            tls_material: TlsMaterialPaths {
                server_certificate_chain: PathBuf::from(required_value(lookup, SERVER_CERT)?),
                server_private_key: PathBuf::from(required_value(lookup, SERVER_KEY)?),
                client_ca_roots: Some(PathBuf::from(required_value(lookup, CLIENT_CA)?)),
            },
            client_certificates: ClientCertificateMode::Required,
            api_keys: ApiKeyMode::Required,
            alpn: AlpnPolicy::Http11Only,
            timeouts: IngressTimeouts {
                tls_handshake: duration_value(lookup, TLS_HANDSHAKE_SECONDS, 10)?,
                first_request: duration_value(lookup, FIRST_REQUEST_SECONDS, 10)?,
            },
            capacity: IngressCapacity {
                max_concurrent_handshakes: usize_value(lookup, MAX_HANDSHAKES, 64)?,
                max_client_connections: usize_value(lookup, MAX_CONNECTIONS, 512)?,
            },
            certificate_rotation: CertificateRotationPolicy {
                reload_strategy: CertificateReloadStrategy::ValidateThenAtomicSwap,
                trust_overlap: duration_value(lookup, TRUST_OVERLAP_SECONDS, 86_400)?,
            },
        };
        tls.validate()?;

        Ok(Self::Production {
            tls: Box::new(tls),
            account_database: PathBuf::from(required_value(lookup, ACCOUNT_DATABASE)?),
            api_key_hash_key_file: PathBuf::from(required_value(lookup, API_KEY_HASH_KEY_FILE)?),
            max_cached_accounts: usize_value(lookup, MAX_CACHED_ACCOUNTS, 1_024)?,
            usage_period: duration_value(lookup, USAGE_PERIOD_SECONDS, 2_592_000)?,
        })
    }

    pub(crate) fn listen_addr(&self) -> SocketAddr {
        match self {
            Self::Development { listen_addr } => *listen_addr,
            Self::Production { tls, .. } => tls.listen_addr,
        }
    }
}

fn optional_value<F>(
    lookup: &F,
    variable: &'static str,
) -> Result<Option<String>, PrivateIngressError>
where
    F: Fn(&'static str) -> Result<Option<String>, PrivateIngressError>,
{
    lookup(variable).map(|value| value.filter(|value| !value.trim().is_empty()))
}

fn required_value<F>(lookup: &F, variable: &'static str) -> Result<String, PrivateIngressError>
where
    F: Fn(&'static str) -> Result<Option<String>, PrivateIngressError>,
{
    optional_value(lookup, variable)?.ok_or_else(|| PrivateIngressError::RuntimeConfiguration {
        variable,
        detail: "value is required in production mode".to_owned(),
    })
}

fn duration_value<F>(
    lookup: &F,
    variable: &'static str,
    default_seconds: u64,
) -> Result<Duration, PrivateIngressError>
where
    F: Fn(&'static str) -> Result<Option<String>, PrivateIngressError>,
{
    let seconds = u64_value(lookup, variable, default_seconds)?;
    Ok(Duration::from_secs(seconds))
}

fn usize_value<F>(
    lookup: &F,
    variable: &'static str,
    default: usize,
) -> Result<usize, PrivateIngressError>
where
    F: Fn(&'static str) -> Result<Option<String>, PrivateIngressError>,
{
    let value = optional_value(lookup, variable)?
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| PrivateIngressError::RuntimeConfiguration {
                    variable,
                    detail: error.to_string(),
                })
        })
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(PrivateIngressError::RuntimeConfiguration {
            variable,
            detail: "value must be positive".to_owned(),
        });
    }
    Ok(value)
}

fn u64_value<F>(
    lookup: &F,
    variable: &'static str,
    default: u64,
) -> Result<u64, PrivateIngressError>
where
    F: Fn(&'static str) -> Result<Option<String>, PrivateIngressError>,
{
    let value = optional_value(lookup, variable)?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| PrivateIngressError::RuntimeConfiguration {
                    variable,
                    detail: error.to_string(),
                })
        })
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(PrivateIngressError::RuntimeConfiguration {
            variable,
            detail: "value must be positive".to_owned(),
        });
    }
    Ok(value)
}

impl IngressConfig {
    pub(crate) fn validate(&self) -> Result<(), PrivateIngressError> {
        if self.listen_addr.port() == 0 {
            return Err(PrivateIngressError::InvalidConfiguration(
                "private ingress listen port must be non-zero",
            ));
        }
        if self.server_names.is_empty()
            || self.server_names.iter().any(|name| name.trim().is_empty())
        {
            return Err(PrivateIngressError::InvalidConfiguration(
                "at least one non-empty server name is required",
            ));
        }
        if self
            .tls_material
            .server_certificate_chain
            .as_os_str()
            .is_empty()
        {
            return Err(PrivateIngressError::InvalidConfiguration(
                "server certificate chain path must be explicit",
            ));
        }
        if self.tls_material.server_private_key.as_os_str().is_empty() {
            return Err(PrivateIngressError::InvalidConfiguration(
                "server private key path must be explicit",
            ));
        }
        if self.timeouts.tls_handshake.is_zero() {
            return Err(PrivateIngressError::InvalidConfiguration(
                "TLS handshake timeout must be non-zero",
            ));
        }
        if self.timeouts.first_request.is_zero() {
            return Err(PrivateIngressError::InvalidConfiguration(
                "first-request timeout must be non-zero",
            ));
        }
        if self.capacity.max_concurrent_handshakes == 0 {
            return Err(PrivateIngressError::InvalidConfiguration(
                "maximum concurrent TLS handshakes must be non-zero",
            ));
        }
        if self.capacity.max_client_connections == 0 {
            return Err(PrivateIngressError::InvalidConfiguration(
                "maximum client connections must be non-zero",
            ));
        }
        if matches!(self.client_certificates, ClientCertificateMode::Required) {
            let roots = self.tls_material.client_ca_roots.as_ref().ok_or(
                PrivateIngressError::InvalidConfiguration(
                    "required client authentication needs an explicit client CA path",
                ),
            )?;
            if roots.as_os_str().is_empty() {
                return Err(PrivateIngressError::InvalidConfiguration(
                    "client CA path must be explicit",
                ));
            }
        }
        if matches!(self.deployment_mode, DeploymentMode::Production) {
            if !matches!(self.client_certificates, ClientCertificateMode::Required) {
                return Err(PrivateIngressError::InvalidConfiguration(
                    "production private ingress requires mTLS",
                ));
            }
            if !matches!(self.api_keys, ApiKeyMode::Required) {
                return Err(PrivateIngressError::InvalidConfiguration(
                    "production private ingress requires API-key authentication",
                ));
            }
            if self.certificate_rotation.trust_overlap.is_zero() {
                return Err(PrivateIngressError::InvalidConfiguration(
                    "production certificate rotation requires a non-zero trust overlap",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PemMaterial {
    ServerCertificateChain,
    ServerPrivateKey,
    ClientCaRoots,
}

impl fmt::Display for PemMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::ServerCertificateChain => "server certificate chain",
            Self::ServerPrivateKey => "server private key",
            Self::ClientCaRoots => "client CA roots",
        };
        formatter.write_str(description)
    }
}

#[derive(Debug)]
pub(crate) enum PrivateIngressError {
    InvalidConfiguration(&'static str),
    RuntimeConfiguration {
        variable: &'static str,
        detail: String,
    },
    ReadMaterial {
        material: PemMaterial,
        path: PathBuf,
        source: io::Error,
    },
    MalformedPem {
        material: PemMaterial,
        path: PathBuf,
        source: io::Error,
    },
    InsecurePrivateKeyPath(&'static str),
    InsecurePrivateKeyPermissions(u32),
    EmptyCertificateChain,
    MissingPrivateKey,
    AmbiguousPrivateKeys {
        count: usize,
    },
    EmptyClientRootStore,
    InvalidClientRoot {
        index: usize,
        detail: String,
    },
    TlsConfiguration {
        stage: &'static str,
        detail: String,
    },
    UnsupportedApplicationProtocol,
}

impl fmt::Display for PrivateIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid private ingress configuration: {detail}")
            }
            Self::RuntimeConfiguration { variable, detail } => {
                write!(
                    formatter,
                    "invalid private ingress setting {variable}: {detail}"
                )
            }
            Self::ReadMaterial {
                material,
                path,
                source,
            } => write!(
                formatter,
                "failed to read {material} from {}: {source}",
                path.display()
            ),
            Self::MalformedPem {
                material,
                path,
                source,
            } => write!(
                formatter,
                "malformed {material} PEM in {}: {source}",
                path.display()
            ),
            Self::InsecurePrivateKeyPath(detail) => {
                write!(formatter, "unsafe TLS private key path: {detail}")
            }
            Self::InsecurePrivateKeyPermissions(mode) => write!(
                formatter,
                "TLS private key permissions are too broad: mode {:o}",
                mode & 0o777
            ),
            Self::EmptyCertificateChain => formatter.write_str("server certificate chain is empty"),
            Self::MissingPrivateKey => formatter.write_str("server private key is missing"),
            Self::AmbiguousPrivateKeys { count } => write!(
                formatter,
                "server private key file contains {count} keys; exactly one is required"
            ),
            Self::EmptyClientRootStore => formatter.write_str("client CA root store is empty"),
            Self::InvalidClientRoot { index, detail } => {
                write!(
                    formatter,
                    "client CA certificate {index} is invalid: {detail}"
                )
            }
            Self::TlsConfiguration { stage, detail } => {
                write!(formatter, "failed to configure TLS at {stage}: {detail}")
            }
            Self::UnsupportedApplicationProtocol => {
                formatter.write_str("private ingress requires negotiated ALPN http/1.1")
            }
        }
    }
}

impl StdError for PrivateIngressError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::ReadMaterial { source, .. } | Self::MalformedPem { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn load_server_config(
    config: &IngressConfig,
) -> Result<Arc<ServerConfig>, PrivateIngressError> {
    config.validate()?;

    let certificate_chain = load_certificates(
        &config.tls_material.server_certificate_chain,
        PemMaterial::ServerCertificateChain,
    )?;
    if certificate_chain.is_empty() {
        return Err(PrivateIngressError::EmptyCertificateChain);
    }
    let private_key = load_one_private_key(&config.tls_material.server_private_key)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| PrivateIngressError::TlsConfiguration {
            stage: "protocol versions",
            detail: error.to_string(),
        })?;

    let certificate_builder = match config.client_certificates {
        ClientCertificateMode::Required => {
            let roots_path = config.tls_material.client_ca_roots.as_deref().ok_or(
                PrivateIngressError::InvalidConfiguration(
                    "required client authentication needs an explicit client CA path",
                ),
            )?;
            let roots = load_client_roots(roots_path)?;
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|error| PrivateIngressError::TlsConfiguration {
                    stage: "client certificate verifier",
                    detail: error.to_string(),
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        ClientCertificateMode::DisabledForDevelopment => builder.with_no_client_auth(),
    };

    let mut server_config = certificate_builder
        .with_single_cert(certificate_chain, private_key)
        .map_err(|error| PrivateIngressError::TlsConfiguration {
            stage: "server certificate and private key",
            detail: error.to_string(),
        })?;
    server_config.alpn_protocols = config.alpn.wire_protocols();
    Ok(Arc::new(server_config))
}

pub(crate) fn validate_negotiated_alpn(
    negotiated_protocol: Option<&[u8]>,
) -> Result<(), PrivateIngressError> {
    match negotiated_protocol {
        Some(protocol) if protocol == HTTP_1_1_ALPN => Ok(()),
        _ => Err(PrivateIngressError::UnsupportedApplicationProtocol),
    }
}

fn open_material(
    path: &Path,
    material: PemMaterial,
) -> Result<BufReader<File>, PrivateIngressError> {
    File::open(path)
        .map(BufReader::new)
        .map_err(|source| PrivateIngressError::ReadMaterial {
            material,
            path: path.to_path_buf(),
            source,
        })
}

fn load_certificates(
    path: &Path,
    material: PemMaterial,
) -> Result<Vec<CertificateDer<'static>>, PrivateIngressError> {
    let mut reader = open_material(path, material)?;
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| PrivateIngressError::MalformedPem {
            material,
            path: path.to_path_buf(),
            source,
        })
}

fn load_one_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, PrivateIngressError> {
    let material = PemMaterial::ServerPrivateKey;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| PrivateIngressError::ReadMaterial {
            material,
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(PrivateIngressError::InsecurePrivateKeyPath(
            "symbolic links are not accepted",
        ));
    }
    if !metadata.is_file() {
        return Err(PrivateIngressError::InsecurePrivateKeyPath(
            "path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(PrivateIngressError::InsecurePrivateKeyPermissions(mode));
        }
    }
    let mut reader = open_material(path, material)?;
    let mut keys = Vec::new();
    for item in rustls_pemfile::read_all(&mut reader) {
        let item = item.map_err(|source| PrivateIngressError::MalformedPem {
            material,
            path: path.to_path_buf(),
            source,
        })?;
        match item {
            Item::Pkcs1Key(key) => keys.push(PrivateKeyDer::Pkcs1(key)),
            Item::Pkcs8Key(key) => keys.push(PrivateKeyDer::Pkcs8(key)),
            Item::Sec1Key(key) => keys.push(PrivateKeyDer::Sec1(key)),
            _ => {}
        }
    }
    match keys.len() {
        0 => Err(PrivateIngressError::MissingPrivateKey),
        1 => match keys.pop() {
            Some(key) => Ok(key),
            None => Err(PrivateIngressError::MissingPrivateKey),
        },
        count => Err(PrivateIngressError::AmbiguousPrivateKeys { count }),
    }
}

fn load_client_roots(path: &Path) -> Result<RootCertStore, PrivateIngressError> {
    let certificates = load_certificates(path, PemMaterial::ClientCaRoots)?;
    if certificates.is_empty() {
        return Err(PrivateIngressError::EmptyClientRootStore);
    }

    let mut roots = RootCertStore::empty();
    for (index, certificate) in certificates.into_iter().enumerate() {
        roots
            .add(certificate)
            .map_err(|error| PrivateIngressError::InvalidClientRoot {
                index,
                detail: error.to_string(),
            })?;
    }
    if roots.is_empty() {
        return Err(PrivateIngressError::EmptyClientRootStore);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::{
        AlpnPolicy, ApiKeyMode, CertificateReloadStrategy, CertificateRotationPolicy,
        ClientCertificateMode, DeploymentMode, HTTP_1_1_ALPN, IngressCapacity, IngressConfig,
        IngressTimeouts, PemMaterial, PrivateIngressError, RuntimeIngressConfig, TlsMaterialPaths,
        load_certificates, load_one_private_key, load_server_config, validate_negotiated_alpn,
    };
    use crate::account_management::{
        AccountLimits, AccountManager, ApiKeyHasher, PlanCode, UnixTimestamp,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rustls::{ClientConfig, ProtocolVersion, RootCertStore, pki_types::ServerName};
    use std::{
        collections::HashMap,
        error::Error as StdError,
        fs, io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncWriteExt, DuplexStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use zeroize::Zeroizing;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    const TRUSTED_CA_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBpTCCAU2gAwIBAgIUZ2VAo+EmM/0Hfw+NAaMmj70KOSIwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVUHJveHkgUGhhc2UgMSBUZXN0IENBMCAXDTI2MDcyNDEzMTMz
NVoYDzIxMjYwNjMwMTMxMzM1WjAgMR4wHAYDVQQDDBVQcm94eSBQaGFzZSAxIFRl
c3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATBrItZq34W3gmCfADQfRuO
5OOaZvpSrC1HXlvg37ebUniy2XeN/OLDq3muUakrMRoYHvxlOyW0JfnieByDkANA
o2MwYTAdBgNVHQ4EFgQUEZl49fA1zLZ6NHbx/euUqXGcvRcwHwYDVR0jBBgwFoAU
EZl49fA1zLZ6NHbx/euUqXGcvRcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAQYwCgYIKoZIzj0EAwIDRgAwQwIfaY0AiPWPSkef1xAmT9ZACqPF1qywmxNd
w1Hfz7BUgQIgLUwV2t80yQfdz1rRsw6sI59HFmEfPge6rdS1d5iOVQs=
-----END CERTIFICATE-----
"#;
    const SERVER_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBxTCCAWugAwIBAgIUZKZqio3FnqXqcYUwJehNjFvq1OUwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVUHJveHkgUGhhc2UgMSBUZXN0IENBMCAXDTI2MDcyNDEzMTMz
NVoYDzIxMjYwNjMwMTMxMzM1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAReLipHGFGaSz4x4uOR+B/Rsa0XZ66xQT+HSVxj
zpoo422BFCoovJ8leUwKRXNpwss8wVRDJzEaGdAqJkuWfzcyo4GMMIGJMBQGA1Ud
EQQNMAuCCWxvY2FsaG9zdDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUJ/1ODueOSo2TL+eC6KMBG2cJ
1IEwHwYDVR0jBBgwFoAUEZl49fA1zLZ6NHbx/euUqXGcvRcwCgYIKoZIzj0EAwID
SAAwRQIhAJP91lSeLf6AE1rRhzTWhtD+ydgqDphUswab1Do6MbFfAiB+r/xh6Ekw
TGvzjqiDAUvERfXLXfQ2wyux0RHC1G1seg==
-----END CERTIFICATE-----
"#;
    const SERVER_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwnhccO3SjTrBhILN
jAX2q/gpiW5Lng+kYxpdKqcv5a2hRANCAAReLipHGFGaSz4x4uOR+B/Rsa0XZ66x
QT+HSVxjzpoo422BFCoovJ8leUwKRXNpwss8wVRDJzEaGdAqJkuWfzcy
-----END PRIVATE KEY-----
"#;
    const AUTHORIZED_CLIENT_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtTCCAVugAwIBAgIUZKZqio3FnqXqcYUwJehNjFvq1OYwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVUHJveHkgUGhhc2UgMSBUZXN0IENBMCAXDTI2MDcyNDEzMTMz
NVoYDzIxMjYwNjMwMTMxMzM1WjAcMRowGAYDVQQDDBFhdXRob3JpemVkLWNsaWVu
dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHTxcf6oFarPA0+tBv/y3ZKMy0Hx
rPOToT6ymzA/XtSRKyl/vdHJdNQhKmT5ebYED9zarm/8pUZRMg0wr4YMpmqjdTBz
MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
BwMCMB0GA1UdDgQWBBS4PCJ0W0PLYst0Gr9+OvP1YaFihDAfBgNVHSMEGDAWgBQR
mXj18DXMtno0dvH965SpcZy9FzAKBggqhkjOPQQDAgNIADBFAiEAm9C+QIa+Rbxp
ShQnZwHKuT95zc/AA5MutW3VCPY1YG4CIFgicyni/YXbVyhu6oR8YZ15tiRdxOGk
l0ICZ8Jwl+dY
-----END CERTIFICATE-----
"#;
    const AUTHORIZED_CLIENT_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggCkbN3Tl89zeYrky
3LQMr8BQuDM9p7NE7nC5JCWNlWqhRANCAAR08XH+qBWqzwNPrQb/8t2SjMtB8azz
k6E+spswP17UkSspf73RyXTUISpk+Xm2BA/c2q5v/KVGUTINMK+GDKZq
-----END PRIVATE KEY-----
"#;
    const UNTRUSTED_CLIENT_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIUelFLaPtli1efrjBvDMqyiFj6ceowCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwaUHJveHkgUGhhc2UgMSBVbnRydXN0ZWQgQ0EwIBcNMjYwNzI0
MTMxMzM1WhgPMjEyNjA2MzAxMzEzMzVaMBsxGTAXBgNVBAMMEHVudHJ1c3RlZC1j
bGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATq6knCbr3EZUZ7yvbop281
o6ufEh+In9le6sB4t6HVfTOF+gLSEkKcL1HXESHlyCX2w2d96YAkOou8ObfZ7iYj
o3UwczAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDAjAdBgNVHQ4EFgQURqX/xwJu5vQtSJmL5pNzqy1r8sgwHwYDVR0jBBgw
FoAUii9qIpjm2T1KzF1CXATyIPSWnIswCgYIKoZIzj0EAwIDSAAwRQIhAKrtX1u/
Bz1Fzgkxaj3W2EDsulVN4VKu2T+6srJFR5KNAiBnrKw38S/JlBGIShsocm4UnRR3
OF84jh5DfAeZ6FIgEQ==
-----END CERTIFICATE-----
"#;
    const UNTRUSTED_CLIENT_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmPX/9qw3UUhEwfXJ
xhdXAjyxreldbhOFd7CyHw6p70mhRANCAATq6knCbr3EZUZ7yvbop281o6ufEh+I
n9le6sB4t6HVfTOF+gLSEkKcL1HXESHlyCX2w2d96YAkOou8ObfZ7iYj
-----END PRIVATE KEY-----
"#;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);

    type TestResult<T = ()> = Result<T, Box<dyn StdError + Send + Sync>>;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> io::Result<Self> {
            let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "proxy-private-ingress-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }

        fn write(&self, name: &str, contents: &str) -> io::Result<PathBuf> {
            let path = self.path.join(name);
            fs::write(&path, contents)?;
            #[cfg(unix)]
            if name.contains("key") {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            Ok(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_dir_all(&self.path) {
                eprintln!(
                    "failed to remove private ingress test directory {}: {error}",
                    self.path.display()
                );
            }
        }
    }

    struct FixturePaths {
        _directory: TestDirectory,
        server_certificate_chain: PathBuf,
        server_private_key: PathBuf,
        client_ca_roots: PathBuf,
        authorized_client_certificate: PathBuf,
        authorized_client_private_key: PathBuf,
        untrusted_client_certificate: PathBuf,
        untrusted_client_private_key: PathBuf,
    }

    impl FixturePaths {
        fn create() -> io::Result<Self> {
            let directory = TestDirectory::create()?;
            let server_certificate_chain = directory.write(
                "server-chain.pem",
                &format!("{SERVER_CERTIFICATE}{TRUSTED_CA_CERTIFICATE}"),
            )?;
            let server_private_key = directory.write("server-key.pem", SERVER_PRIVATE_KEY)?;
            let client_ca_roots = directory.write("client-ca.pem", TRUSTED_CA_CERTIFICATE)?;
            let authorized_client_certificate =
                directory.write("authorized-client.pem", AUTHORIZED_CLIENT_CERTIFICATE)?;
            let authorized_client_private_key =
                directory.write("authorized-client-key.pem", AUTHORIZED_CLIENT_PRIVATE_KEY)?;
            let untrusted_client_certificate =
                directory.write("untrusted-client.pem", UNTRUSTED_CLIENT_CERTIFICATE)?;
            let untrusted_client_private_key =
                directory.write("untrusted-client-key.pem", UNTRUSTED_CLIENT_PRIVATE_KEY)?;
            Ok(Self {
                _directory: directory,
                server_certificate_chain,
                server_private_key,
                client_ca_roots,
                authorized_client_certificate,
                authorized_client_private_key,
                untrusted_client_certificate,
                untrusted_client_private_key,
            })
        }

        fn production_config(&self) -> IngressConfig {
            IngressConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443),
                server_names: vec!["localhost".to_owned()],
                deployment_mode: DeploymentMode::Production,
                tls_material: TlsMaterialPaths {
                    server_certificate_chain: self.server_certificate_chain.clone(),
                    server_private_key: self.server_private_key.clone(),
                    client_ca_roots: Some(self.client_ca_roots.clone()),
                },
                client_certificates: ClientCertificateMode::Required,
                api_keys: ApiKeyMode::Required,
                alpn: AlpnPolicy::Http11Only,
                timeouts: IngressTimeouts {
                    tls_handshake: Duration::from_secs(10),
                    first_request: Duration::from_secs(10),
                },
                capacity: IngressCapacity {
                    max_concurrent_handshakes: 64,
                    max_client_connections: 512,
                },
                certificate_rotation: CertificateRotationPolicy {
                    reload_strategy: CertificateReloadStrategy::ValidateThenAtomicSwap,
                    trust_overlap: Duration::from_secs(24 * 60 * 60),
                },
            }
        }
    }

    #[derive(Debug)]
    struct HandshakeObservation {
        protocol_version: Option<ProtocolVersion>,
        alpn_protocol: Option<Vec<u8>>,
        client_fingerprint_available: bool,
    }

    fn client_config(
        fixtures: &FixturePaths,
        client_identity: Option<(&Path, &Path)>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> TestResult<Arc<ClientConfig>> {
        let mut server_roots = RootCertStore::empty();
        for certificate in load_certificates(&fixtures.client_ca_roots, PemMaterial::ClientCaRoots)?
        {
            server_roots.add(certificate)?;
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(server_roots);
        let mut config = match client_identity {
            Some((certificate_path, private_key_path)) => builder.with_client_auth_cert(
                load_certificates(certificate_path, PemMaterial::ServerCertificateChain)?,
                load_one_private_key(private_key_path)?,
            )?,
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = alpn_protocols;
        Ok(Arc::new(config))
    }

    async fn run_handshake(
        server_config: Arc<rustls::ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> (
        Result<HandshakeObservation, String>,
        Result<HandshakeObservation, String>,
    ) {
        let (server_io, client_io): (DuplexStream, DuplexStream) = tokio::io::duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(server_config);
        let connector = TlsConnector::from(client_config);
        let server_name = match ServerName::try_from("localhost") {
            Ok(name) => name,
            Err(error) => {
                let detail = error.to_string();
                return (Err(detail.clone()), Err(detail));
            }
        };

        // Keep both TLS streams alive until both handshake futures settle. If
        // the server-side stream were dropped as soon as its future completed,
        // the client could observe a synthetic broken pipe while sending its
        // final handshake flight over the in-memory transport.
        let (server, client) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io)
        );
        let server = server
            .map(|stream| HandshakeObservation {
                protocol_version: stream.get_ref().1.protocol_version(),
                alpn_protocol: stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
                client_fingerprint_available: crate::tls_client_fingerprint(&stream).is_ok(),
            })
            .map_err(|error| error.to_string());
        let client = client
            .map(|stream| HandshakeObservation {
                protocol_version: stream.get_ref().1.protocol_version(),
                alpn_protocol: stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
                client_fingerprint_available: false,
            })
            .map_err(|error| error.to_string());
        (server, client)
    }

    fn require_error<T>(result: Result<T, PrivateIngressError>) -> TestResult<PrivateIngressError> {
        match result {
            Ok(_) => Err(io::Error::other("expected private ingress operation to fail").into()),
            Err(error) => Ok(error),
        }
    }

    fn runtime_config_from(
        values: &[(&'static str, &'static str)],
    ) -> Result<RuntimeIngressConfig, PrivateIngressError> {
        let values = values
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        RuntimeIngressConfig::from_lookup(&|name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn runtime_config_defaults_to_loopback_development() -> TestResult {
        let config = runtime_config_from(&[])?;
        assert_eq!(
            config,
            RuntimeIngressConfig::Development {
                listen_addr: "127.0.0.1:8080".parse()?,
            }
        );

        let error = runtime_config_from(&[("PROXY_INGRESS_LISTEN_ADDR", "0.0.0.0:8080")])
            .expect_err("plaintext non-loopback ingress must be rejected");
        assert!(matches!(
            error,
            PrivateIngressError::RuntimeConfiguration {
                variable: "PROXY_INGRESS_LISTEN_ADDR",
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn production_runtime_config_requires_and_bounds_auth_settings() -> TestResult {
        let values = [
            ("PROXY_INGRESS_MODE", "production"),
            ("PROXY_INGRESS_LISTEN_ADDR", "0.0.0.0:8443"),
            (
                "PROXY_INGRESS_SERVER_NAMES",
                "proxy.example, proxy-alt.example",
            ),
            ("PROXY_INGRESS_SERVER_CERT", "/run/proxy/server.pem"),
            ("PROXY_INGRESS_SERVER_KEY", "/run/proxy/server-key.pem"),
            ("PROXY_INGRESS_CLIENT_CA", "/run/proxy/client-ca.pem"),
            ("PROXY_ACCOUNT_DATABASE", "/var/lib/proxy/accounts.sqlite3"),
            ("PROXY_API_KEY_HASH_KEY_FILE", "/run/proxy/api-key-hash-key"),
            ("PROXY_MAX_CONCURRENT_TLS_HANDSHAKES", "17"),
            ("PROXY_MAX_CLIENT_CONNECTIONS", "23"),
            ("PROXY_USAGE_PERIOD_SECONDS", "3600"),
        ];
        let config = runtime_config_from(&values)?;
        let RuntimeIngressConfig::Production {
            tls,
            account_database,
            api_key_hash_key_file,
            max_cached_accounts,
            usage_period,
        } = config
        else {
            return Err(io::Error::other("expected production runtime config").into());
        };
        assert_eq!(tls.listen_addr, "0.0.0.0:8443".parse()?);
        assert_eq!(tls.server_names.len(), 2);
        assert_eq!(tls.capacity.max_concurrent_handshakes, 17);
        assert_eq!(tls.capacity.max_client_connections, 23);
        assert_eq!(
            account_database,
            PathBuf::from("/var/lib/proxy/accounts.sqlite3")
        );
        assert_eq!(
            api_key_hash_key_file,
            PathBuf::from("/run/proxy/api-key-hash-key")
        );
        assert_eq!(max_cached_accounts, 1_024);
        assert_eq!(usage_period, Duration::from_secs(3_600));

        let mut invalid = values.to_vec();
        invalid.push(("PROXY_FIRST_REQUEST_TIMEOUT_SECONDS", "0"));
        assert!(runtime_config_from(&invalid).is_err());
        Ok(())
    }

    #[test]
    fn production_rejects_development_auth_bypasses() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let mut config = fixtures.production_config();
        config.client_certificates = ClientCertificateMode::DisabledForDevelopment;
        config.api_keys = ApiKeyMode::DisabledForDevelopment;
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(
            error,
            PrivateIngressError::InvalidConfiguration("production private ingress requires mTLS")
        ));
        Ok(())
    }

    #[test]
    fn loader_rejects_missing_material() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let mut config = fixtures.production_config();
        config.tls_material.server_certificate_chain =
            fixtures._directory.path.join("missing-server.pem");
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(
            error,
            PrivateIngressError::ReadMaterial {
                material: PemMaterial::ServerCertificateChain,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn loader_rejects_malformed_pem() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let malformed_path = fixtures._directory.write(
            "malformed-server.pem",
            "-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----\n",
        )?;
        let mut config = fixtures.production_config();
        config.tls_material.server_certificate_chain = malformed_path;
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(
            error,
            PrivateIngressError::MalformedPem {
                material: PemMaterial::ServerCertificateChain,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn loader_rejects_multiple_private_keys() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let multiple_keys = fixtures._directory.write(
            "multiple-server-keys.pem",
            &format!("{SERVER_PRIVATE_KEY}{AUTHORIZED_CLIENT_PRIVATE_KEY}"),
        )?;
        let mut config = fixtures.production_config();
        config.tls_material.server_private_key = multiple_keys;
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(
            error,
            PrivateIngressError::AmbiguousPrivateKeys { count: 2 }
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_broad_or_linked_private_keys() -> TestResult {
        let fixtures = FixturePaths::create()?;
        fs::set_permissions(
            &fixtures.server_private_key,
            fs::Permissions::from_mode(0o644),
        )?;
        let error = require_error(load_server_config(&fixtures.production_config()))?;
        assert!(matches!(
            error,
            PrivateIngressError::InsecurePrivateKeyPermissions(_)
        ));

        fs::set_permissions(
            &fixtures.server_private_key,
            fs::Permissions::from_mode(0o600),
        )?;
        let linked_key = fixtures._directory.path.join("linked-server-key.pem");
        std::os::unix::fs::symlink(&fixtures.server_private_key, &linked_key)?;
        let mut config = fixtures.production_config();
        config.tls_material.server_private_key = linked_key;
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(
            error,
            PrivateIngressError::InsecurePrivateKeyPath(_)
        ));
        Ok(())
    }

    #[test]
    fn loader_rejects_empty_client_root_store() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let empty_roots = fixtures._directory.write("empty-client-ca.pem", "")?;
        let mut config = fixtures.production_config();
        config.tls_material.client_ca_roots = Some(empty_roots);
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(error, PrivateIngressError::EmptyClientRootStore));
        Ok(())
    }

    #[test]
    fn loader_rejects_certificate_key_mismatch() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let mut config = fixtures.production_config();
        config.tls_material.server_private_key = fixtures.authorized_client_private_key.clone();
        let error = require_error(load_server_config(&config))?;
        assert!(matches!(
            error,
            PrivateIngressError::TlsConfiguration {
                stage: "server certificate and private key",
                ..
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn trusted_client_completes_tls13_http11_handshake() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let server_config = load_server_config(&fixtures.production_config())?;
        assert_eq!(server_config.alpn_protocols, vec![HTTP_1_1_ALPN.to_vec()]);
        let client_config = client_config(
            &fixtures,
            Some((
                &fixtures.authorized_client_certificate,
                &fixtures.authorized_client_private_key,
            )),
            vec![HTTP_1_1_ALPN.to_vec()],
        )?;

        let (server, client) = run_handshake(server_config, client_config).await;
        let server = server.map_err(io::Error::other)?;
        let client = client.map_err(io::Error::other)?;
        assert_eq!(server.protocol_version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(client.protocol_version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.alpn_protocol.as_deref(), Some(HTTP_1_1_ALPN));
        assert_eq!(client.alpn_protocol.as_deref(), Some(HTTP_1_1_ALPN));
        assert!(server.client_fingerprint_available);
        validate_negotiated_alpn(server.alpn_protocol.as_deref())?;
        Ok(())
    }

    #[tokio::test]
    async fn bounded_tls_accept_rejects_capacity_and_slow_handshakes() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let server_config = load_server_config(&fixtures.production_config())?;
        let (capacity_server, _capacity_client) = tokio::io::duplex(1_024);
        let capacity_error = crate::accept_bounded_tls(
            capacity_server,
            TlsAcceptor::from(server_config.clone()),
            Arc::new(tokio::sync::Semaphore::new(0)),
            Duration::from_secs(1),
        )
        .await
        .expect_err("exhausted handshake capacity must reject");
        assert!(capacity_error.to_string().contains("capacity"));

        let (slow_server, _slow_client) = tokio::io::duplex(1_024);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let timeout_error = crate::accept_bounded_tls(
            slow_server,
            TlsAcceptor::from(server_config.clone()),
            semaphore.clone(),
            Duration::from_millis(10),
        )
        .await
        .expect_err("silent TLS client must time out");
        assert!(timeout_error.to_string().contains("timed out"));
        assert_eq!(semaphore.available_permits(), 1);

        let (plaintext_server, mut plaintext_client) = tokio::io::duplex(1_024);
        let accepting = crate::accept_bounded_tls(
            plaintext_server,
            TlsAcceptor::from(server_config),
            Arc::new(tokio::sync::Semaphore::new(1)),
            Duration::from_secs(1),
        );
        let sending_plaintext = async {
            plaintext_client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                .await?;
            plaintext_client.shutdown().await
        };
        let (accept_result, plaintext_result) = tokio::join!(accepting, sending_plaintext);
        plaintext_result?;
        assert!(accept_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn trusted_tls_fingerprint_and_api_key_bind_the_same_account() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let server_config = load_server_config(&fixtures.production_config())?;
        let client_config = client_config(
            &fixtures,
            Some((
                &fixtures.authorized_client_certificate,
                &fixtures.authorized_client_private_key,
            )),
            vec![HTTP_1_1_ALPN.to_vec()],
        )?;
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost")?;
        let (server, client) = tokio::join!(
            TlsAcceptor::from(server_config).accept(server_io),
            TlsConnector::from(client_config).connect(server_name, client_io),
        );
        let mut server = server?;
        let mut client = client?;
        let fingerprint = crate::tls_client_fingerprint(&server)?;

        let manager = AccountManager::open_in_memory(
            ApiKeyHasher::from_key(Zeroizing::new([0x63; blake3::KEY_LEN])),
            8,
        )?;
        let now = UnixTimestamp::new(100)?;
        let account = manager.create_account(
            "tls-account@example.com",
            None,
            &PlanCode::new("test")?,
            AccountLimits::new(10, 10, 2, None, None)?,
            now,
        )?;
        let workspace = manager.create_workspace(account.id(), "default", now)?;
        let api_key = manager.issue_api_key(account.id(), workspace.id(), "test", now)?;
        manager.register_device_credential(
            account.id(),
            workspace.id(),
            &fingerprint,
            "trusted fixture",
            now,
        )?;
        let authorization = STANDARD.encode(format!("{}:", api_key.secret().expose_secret()));
        client
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {authorization}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let (mut request, _) = crate::read_proxy_request(&mut server).await?;
        let proxy_authorization = request
            .proxy_authorization
            .take()
            .ok_or_else(|| io::Error::other("missing parsed proxy authorization"))?;
        let identity = manager.authenticate_ingress(proxy_authorization.as_str(), &fingerprint)?;
        assert_eq!(identity.account_id(), account.id());
        assert_eq!(identity.workspace_id(), workspace.id());
        Ok(())
    }

    #[tokio::test]
    async fn client_without_certificate_is_rejected() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let server_config = load_server_config(&fixtures.production_config())?;
        let client_config = client_config(&fixtures, None, vec![HTTP_1_1_ALPN.to_vec()])?;
        let (server, _) = run_handshake(server_config, client_config).await;
        assert!(server.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn client_signed_by_untrusted_ca_is_rejected() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let server_config = load_server_config(&fixtures.production_config())?;
        let client_config = client_config(
            &fixtures,
            Some((
                &fixtures.untrusted_client_certificate,
                &fixtures.untrusted_client_private_key,
            )),
            vec![HTTP_1_1_ALPN.to_vec()],
        )?;
        let (server, _) = run_handshake(server_config, client_config).await;
        assert!(server.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_application_protocol_is_rejected() -> TestResult {
        let fixtures = FixturePaths::create()?;
        let server_config = load_server_config(&fixtures.production_config())?;
        let client_config = client_config(
            &fixtures,
            Some((
                &fixtures.authorized_client_certificate,
                &fixtures.authorized_client_private_key,
            )),
            vec![b"h2".to_vec()],
        )?;
        let (server, client) = run_handshake(server_config, client_config).await;
        assert!(server.is_err());
        assert!(client.is_err());
        assert!(matches!(
            validate_negotiated_alpn(Some(b"h2")),
            Err(PrivateIngressError::UnsupportedApplicationProtocol)
        ));
        assert!(matches!(
            validate_negotiated_alpn(None),
            Err(PrivateIngressError::UnsupportedApplicationProtocol)
        ));
        Ok(())
    }
}
