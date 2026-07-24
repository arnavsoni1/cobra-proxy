//! Phase 1 configuration and TLS construction for the private ingress.
//!
//! This module intentionally does not bind or accept a socket. Phase 2 will
//! connect the validated `rustls::ServerConfig` to the public accept loop.

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
    /// A dedicated Phase 2 semaphore will use this limit before TLS work.
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
        IngressTimeouts, PemMaterial, PrivateIngressError, TlsMaterialPaths, load_certificates,
        load_one_private_key, load_server_config, validate_negotiated_alpn,
    };
    use rustls::{ClientConfig, ProtocolVersion, RootCertStore, pki_types::ServerName};
    use std::{
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
    use tokio::io::DuplexStream;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

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
            })
            .map_err(|error| error.to_string());
        let client = client
            .map(|stream| HandshakeObservation {
                protocol_version: stream.get_ref().1.protocol_version(),
                alpn_protocol: stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
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
        validate_negotiated_alpn(server.alpn_protocol.as_deref())?;
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
