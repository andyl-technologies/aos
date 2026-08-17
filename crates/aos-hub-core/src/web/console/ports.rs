//! Runtime dependencies for authentication and the browser-console shell.
//!
//! Management workflows no longer use Web-specific capability ports: the
//! browser calls the same generated Connect API as the CLI. The only runtime
//! abstraction retained here is bounded outbound HTTP for OIDC ceremonies.

use std::sync::Arc;

use crate::auth::jwt::JwtKeys;
use crate::auth::magic::Mailer;
use crate::auth::seal::SecretSealer;
use crate::backend::BackendBounds;
use crate::db::Database;
use crate::ratelimit::RateLimiter;

/// Dependencies carried by the shared authentication and app-shell router.
#[derive(Clone)]
pub struct ConsoleDeps {
    /// Shared Hub database.
    pub db: Arc<Database>,
    /// JWT keys used by device authorization and browser token exchange.
    pub jwt_keys: JwtKeys,
    /// Externally reachable Hub base URL.
    pub external_url: String,
    /// Whether development login pages may reveal a magic link.
    pub dev: bool,
    /// Abuse limiter for pre-authentication ceremonies.
    pub ratelimit: Arc<dyn RateLimiter>,
    /// Passwordless-login mail sender.
    pub mailer: Arc<dyn Mailer>,
    /// At-rest sealer for OIDC client credentials.
    pub sealer: Arc<dyn SecretSealer>,
    /// Bounded, SSRF-resistant outbound OIDC client.
    pub http: Arc<dyn HttpClient>,
    /// Canonical control-plane service used by retained identity ceremonies.
    pub control: Option<Arc<crate::service::RpcService>>,
}

/// Bounded outbound HTTP required by OIDC login.
///
/// Implementations must reject unsafe destination addresses, cap response
/// bodies, enforce timeouts, and preserve TLS hostname verification.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HttpClient: BackendBounds {
    /// Posts an encoded form and returns its bounded response body.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe URL, network or TLS failure, non-success
    /// status, timeout, or oversized response.
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> anyhow::Result<Vec<u8>>;

    /// Gets a URL and returns its bounded response body.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe URL, network or TLS failure, non-success
    /// status, timeout, or oversized response.
    async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>>;

    /// Probes HTTPS using normal certificate and hostname verification.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe URL, DNS or TLS failure, timeout, or
    /// oversized response.
    async fn probe_https(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        self.get(url).await
    }
}
