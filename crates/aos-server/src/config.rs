//! Server configuration, parsed from a TOML file.
//!
//! [`load_config`] reads the file at the given path into a [`ServerConfig`];
//! when the file is absent, built-in defaults apply (listen on
//! `127.0.0.1:5000`, zstd level 3 compression, and a single anonymous-read
//! `default` view with a 7-day binary TTL and 90-day source TTL).
//!
//! Each struct mirrors one TOML section:
//!
//! ```text
//! listen = "0.0.0.0:5000"
//!
//! [build]            # BuildConfig — nix-store --realise knobs
//! [signing]          # SigningConfig — narinfo re-signing key
//! [compression]      # CompressionConfig — NAR response compression
//! [[views]]          # ViewConfig — one table per view
//! [oauth2]           # OAuth2Config — JWT TTL and secret file
//! [bootstrap]        # BootstrapConfig — admin Unix socket
//! [tls]              # TlsConfig — HTTPS settings
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

fn default_listen() -> SocketAddr {
    "127.0.0.1:5000".parse().unwrap()
}

fn default_max_jobs() -> u32 {
    4
}

fn default_compression_algorithm() -> String {
    "zstd".to_string()
}

fn default_compression_level() -> i32 {
    3
}

fn default_max_concurrent_builds() -> u32 {
    4
}

fn default_source_mirror() -> bool {
    true
}

fn default_access_token_ttl() -> u64 {
    3600
}

fn default_bootstrap_socket() -> PathBuf {
    PathBuf::from("/run/aos/bootstrap.sock")
}

fn default_bootstrap_group() -> String {
    "aos-admins".to_string()
}

/// Top-level server configuration (parsed from TOML).
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// `[server]` section (flattened — `listen` is top-level for simplicity).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// `[build]` section.
    #[serde(default)]
    pub build: BuildConfig,

    /// `[signing]` section.
    #[serde(default)]
    pub signing: SigningConfig,

    /// `[compression]` section.
    #[serde(default)]
    pub compression: CompressionConfig,

    /// `[[views]]` — one or more view definitions.
    #[serde(default)]
    pub views: Vec<ViewConfig>,

    /// `[oauth2]` section.
    #[serde(default)]
    pub oauth2: OAuth2Config,

    /// `[bootstrap]` section.
    #[serde(default)]
    pub bootstrap: BootstrapConfig,

    /// `[tls]` section.
    #[serde(default)]
    pub tls: TlsConfig,

    /// `[memo]` section — the L3 network memo tier (RFC-0007 doc 29 §5.5).
    #[serde(default)]
    pub memo: MemoConfig,
}

/// L3 network memo-tier settings.
///
/// The memo endpoint (`/v1/root/{key}`, `/v1/compiled-body/{key}`) is a
/// content-addressed validation catalog, never an authority: it serves opaque
/// self-validating bundle bytes that the fetching evaluator re-hashes and
/// slice-revalidates before use. Reads are always open; writes are gated so a
/// public read mirror never accepts unsolicited records.
///
/// ```toml
/// [memo]
/// writable = true   # a trusted CI/builder publisher; default false (read-only)
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MemoConfig {
    /// Whether `PUT` publishes are accepted (trusted publishers only).
    ///
    /// Defaults to `false`: a server is a read-only mirror unless it is an
    /// explicitly configured trusted publisher.
    #[serde(default)]
    pub writable: bool,
}

/// Build-related settings — controls `nix-store --realise` behaviour.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildConfig {
    /// Parallel build jobs (`--max-jobs`).
    #[serde(default = "default_max_jobs")]
    pub max_jobs: u32,

    /// Cores per build (0 = all available).
    #[serde(default)]
    pub cores_per_build: u32,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            max_jobs: default_max_jobs(),
            cores_per_build: 0,
        }
    }
}

/// Narinfo signing configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SigningConfig {
    /// Path to an ed25519 secret key for re-signing narinfo.
    /// If unset, narinfo is served with the daemon's signatures as-is.
    pub secret_key_file: Option<PathBuf>,
}

/// Default compression for NAR responses.
#[derive(Debug, Clone, Deserialize)]
pub struct CompressionConfig {
    /// Algorithm: "zstd", "xz", or "none".
    #[serde(default = "default_compression_algorithm")]
    pub algorithm: String,

    /// Compression level (meaning depends on algorithm).
    #[serde(default = "default_compression_level")]
    pub level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: default_compression_algorithm(),
            level: default_compression_level(),
        }
    }
}

/// Per-view configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ViewConfig {
    /// View name (used in URL path: `/{name}/...`).
    pub name: String,

    /// Binary output TTL. `None` means "keep forever".
    #[serde(default, with = "humantime_serde")]
    pub ttl: Option<Duration>,

    /// Source tarball TTL. `None` means "keep forever".
    #[serde(default, with = "humantime_serde")]
    pub source_ttl: Option<Duration>,

    /// Whether to retain source inputs alongside build outputs.
    #[serde(default = "default_source_mirror")]
    pub source_mirror: bool,

    /// Allow unauthenticated read access to this view.
    #[serde(default)]
    pub anonymous_read: bool,

    /// Maximum concurrent builds for this view.
    #[serde(default = "default_max_concurrent_builds")]
    pub max_concurrent_builds: u32,

    /// Maximum total store size for this view (e.g., "200G").
    /// Parsed as a human-readable byte size string.
    pub max_store_size: Option<String>,

    /// Maximum number of GC-rooted paths in this view.
    pub max_paths: Option<u64>,
}

/// OAuth2 / JWT configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuth2Config {
    /// JWT access token lifetime in seconds.
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: u64,

    /// Path to the file containing the HMAC-SHA256 secret for JWTs.
    pub jwt_secret_file: Option<PathBuf>,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            access_token_ttl: default_access_token_ttl(),
            jwt_secret_file: None,
        }
    }
}

/// Bootstrap socket configuration for token provisioning.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapConfig {
    /// Path to the Unix domain socket.
    #[serde(default = "default_bootstrap_socket")]
    pub socket: PathBuf,

    /// Unix group allowed to connect and create tokens.
    #[serde(default = "default_bootstrap_group")]
    pub socket_group: String,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            socket: default_bootstrap_socket(),
            socket_group: default_bootstrap_group(),
        }
    }
}

/// TLS / HTTPS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Enable HTTPS. When `true`, the server listens with TLS.
    #[serde(default)]
    pub enabled: bool,

    /// Path to PEM-encoded certificate chain. If absent when `enabled` is
    /// `true`, a self-signed certificate is generated automatically.
    pub cert_file: Option<PathBuf>,

    /// Path to PEM-encoded private key.
    pub key_file: Option<PathBuf>,

    /// Subject Alternative Names for the self-signed certificate.
    /// Defaults to `["localhost", "127.0.0.1", "::1"]`.
    #[serde(default)]
    pub san: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: None,
            key_file: None,
            san: Vec::new(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            build: BuildConfig::default(),
            signing: SigningConfig::default(),
            compression: CompressionConfig::default(),
            views: vec![ViewConfig {
                name: "default".to_string(),
                ttl: Some(Duration::from_secs(7 * 24 * 3600)),
                source_ttl: Some(Duration::from_secs(90 * 24 * 3600)),
                source_mirror: true,
                anonymous_read: true,
                max_concurrent_builds: default_max_concurrent_builds(),
                max_store_size: None,
                max_paths: None,
            }],
            oauth2: OAuth2Config::default(),
            bootstrap: BootstrapConfig::default(),
            tls: TlsConfig::default(),
            memo: MemoConfig::default(),
        }
    }
}

/// Loads the server configuration from a TOML file.
///
/// If `path` does not exist, the built-in [`ServerConfig::default`] is
/// returned instead of an error, so a freshly installed server runs with
/// sensible defaults.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read, or if its
/// contents are not valid TOML for [`ServerConfig`].
pub fn load_config(path: &Path) -> Result<ServerConfig> {
    if !path.exists() {
        return Ok(ServerConfig::default());
    }
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let config: ServerConfig = toml::from_str(&contents)
        .with_context(|| format!("parsing config file {}", path.display()))?;
    Ok(config)
}
