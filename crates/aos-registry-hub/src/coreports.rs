//! Native adapters from the hub's concrete types to the core service ports.
//!
//! The shared, transport-free service
//! ([`RpcService`](aos_registry_core::service::RpcService)) depends on a small
//! set of platform ports — a [`RateLimiter`](aos_registry_core::ratelimit::RateLimiter)
//! and a [`SurfaceProvider`](aos_registry_core::fetch::SurfaceProvider) — so the
//! same method bodies run unchanged on the native hub and the Cloudflare Worker.
//! The native hub already owns concrete equivalents (the in-process
//! [`RateLimiter`](crate::ratelimit::RateLimiter) and the filesystem/HTTP
//! [`SurfaceFetch`](crate::fetch::SurfaceFetch) transports), so this module is the
//! thin glue that makes those concrete types *satisfy the core ports*:
//!
//! - [`crate::ratelimit::RateLimiter`] gains an
//!   [`aos_registry_core::ratelimit::RateLimiter`] impl. The core trait method is
//!   `async`; the hub's check is a synchronous counter read-modify-write, so the
//!   impl simply runs it inline. The two enums ([`RateClass`] and
//!   [`RateDecision`]) are mirror-for-mirror and are mapped by name.
//! - [`crate::fetch::LocalFsFetch`] and [`crate::fetch::HttpFetch`] each gain an
//!   [`aos_registry_core::fetch::SurfaceFetch`] impl with the identical
//!   `fetch`/`describe` signatures, delegating to their inherent methods.
//! - [`HubSurfaceProvider`] is the
//!   [`SurfaceProvider`](aos_registry_core::fetch::SurfaceProvider): it resolves a
//!   per-registry fetcher through the existing
//!   [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry) and
//!   re-boxes it as a core [`SurfaceFetch`] via [`CoreFetchAdapter`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use aos_registry_core::auth::seal::SecretSealer;
use aos_registry_core::db::{Database, RegistryRecord};
use aos_registry_core::fetch as core_fetch;
use aos_registry_core::ratelimit as core_rl;
use aos_registry_core::surface_write as core_sw;
use aos_registry_core::web::console::ports as console_ports;

/// Map a core [`RateClass`](core_rl::RateClass) to the hub's own
/// [`RateClass`](crate::ratelimit::RateClass).
///
/// The two enums are variant-for-variant mirrors (the core enum was defined to
/// match the native limiter), so this is a 1:1 rename — the shared service
/// currently meters only [`RateClass::CreateOrg`](core_rl::RateClass::CreateOrg),
/// but every variant is mapped so the port is total.
fn map_class(class: core_rl::RateClass) -> crate::ratelimit::RateClass {
    use crate::ratelimit::RateClass as Hub;
    use core_rl::RateClass as Core;
    match class {
        Core::DeviceAuthorization => Hub::DeviceAuthorization,
        Core::MagicLinkEmail => Hub::MagicLinkEmail,
        Core::MagicLinkIp => Hub::MagicLinkIp,
        Core::PasswordEmail => Hub::PasswordEmail,
        Core::PasswordIp => Hub::PasswordIp,
        Core::TokenExchange => Hub::TokenExchange,
        Core::BrowseSearch => Hub::BrowseSearch,
        Core::CreateOrg => Hub::CreateOrg,
        Core::DeviceActivate => Hub::DeviceActivate,
    }
}

/// Map the hub's [`RateDecision`](crate::ratelimit::RateDecision) to the core's.
fn map_decision(decision: crate::ratelimit::RateDecision) -> core_rl::RateDecision {
    match decision {
        crate::ratelimit::RateDecision::Allowed => core_rl::RateDecision::Allowed,
        crate::ratelimit::RateDecision::Limited { retry_after } => {
            core_rl::RateDecision::Limited { retry_after }
        }
    }
}

/// The hub's in-process limiter, exposed as the core [`RateLimiter`] port.
///
/// The hub's [`check`](crate::ratelimit::RateLimiter::check) is synchronous (a
/// `Mutex`-guarded counter), so the `async` port method runs it inline and
/// completes immediately.
#[async_trait]
impl core_rl::RateLimiter for crate::ratelimit::RateLimiter {
    async fn check(&self, class: core_rl::RateClass, key: &str, now: i64) -> core_rl::RateDecision {
        map_decision(crate::ratelimit::RateLimiter::check(
            self,
            map_class(class),
            key,
            now,
        ))
    }
}

/// The hub's filesystem fetcher, exposed as the core [`SurfaceFetch`] port.
#[async_trait]
impl core_fetch::SurfaceFetch for crate::fetch::LocalFsFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        crate::fetch::SurfaceFetch::fetch(self, path).await
    }

    fn describe(&self) -> String {
        crate::fetch::SurfaceFetch::describe(self)
    }
}

/// The hub's HTTP(S) fetcher, exposed as the core [`SurfaceFetch`] port.
#[async_trait]
impl core_fetch::SurfaceFetch for crate::fetch::HttpFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        crate::fetch::SurfaceFetch::fetch(self, path).await
    }

    fn describe(&self) -> String {
        crate::fetch::SurfaceFetch::describe(self)
    }
}

/// Adapts a boxed hub [`SurfaceFetch`](crate::fetch::SurfaceFetch) to the core
/// [`SurfaceFetch`](core_fetch::SurfaceFetch) port by delegation.
///
/// [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry)
/// returns a `Box<dyn crate::fetch::SurfaceFetch>` (the hub trait object) chosen
/// per registry. The core service needs a `Box<dyn core_fetch::SurfaceFetch>`,
/// and a trait object cannot be re-coerced to a *different* trait, so this
/// concrete wrapper holds the hub box and forwards both methods.
struct CoreFetchAdapter(Box<dyn crate::fetch::SurfaceFetch>);

#[async_trait]
impl core_fetch::SurfaceFetch for CoreFetchAdapter {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        self.0.fetch(path).await
    }

    fn describe(&self) -> String {
        self.0.describe()
    }
}

/// The native [`SurfaceProvider`](core_fetch::SurfaceProvider): resolves a
/// per-registry surface fetcher over the hub's storage bindings.
///
/// Delegates to
/// [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry) —
/// the same resolver the rest of the hub uses — and re-boxes the chosen fetcher
/// through [`CoreFetchAdapter`] so it satisfies the core port.
pub struct HubSurfaceProvider {
    /// The hub database, used to resolve a registry's storage-binding root.
    db: Arc<Database>,
}

impl HubSurfaceProvider {
    /// Build a provider over the hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> HubSurfaceProvider {
        HubSurfaceProvider { db }
    }
}

#[async_trait]
impl core_fetch::SurfaceProvider for HubSurfaceProvider {
    async fn fetcher(&self, registry: &RegistryRecord) -> Result<Box<dyn core_fetch::SurfaceFetch>> {
        let hub_fetch = crate::gitwrite::fetcher_for_registry(&self.db, registry).await?;
        Ok(Box::new(CoreFetchAdapter(hub_fetch)))
    }
}

/// The native [`SurfaceWriteProvider`](core_sw::SurfaceWriteProvider): resolves
/// a per-registry filesystem writer over the hub's storage bindings.
///
/// Resolves the registry's storage-binding root — the *same* root
/// [`HubSurfaceProvider`]/[`crate::fetch::LocalFsFetch`] read from — and returns
/// a [`LocalFsWrite`] rooted there. A registration-only registry has no writable
/// root, so [`writer`](core_sw::SurfaceWriteProvider::writer) errors clearly.
pub struct HubSurfaceWriteProvider {
    /// The hub database, used to resolve a registry's storage-binding root.
    db: Arc<Database>,
}

impl HubSurfaceWriteProvider {
    /// Build a write provider over the hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> HubSurfaceWriteProvider {
        HubSurfaceWriteProvider { db }
    }
}

#[async_trait]
impl core_sw::SurfaceWriteProvider for HubSurfaceWriteProvider {
    async fn writer(&self, registry: &RegistryRecord) -> Result<Box<dyn core_sw::SurfaceWrite>> {
        let root = self
            .db
            .registry_surface_root(registry.id)
            .await?
            .with_context(|| {
                format!(
                    "registry '{}' has no writable storage root (registration-only)",
                    registry.slug
                )
            })?;
        Ok(Box::new(LocalFsWrite { root }))
    }
}

/// A filesystem-backed [`SurfaceWrite`](core_sw::SurfaceWrite) rooted at a
/// registry's storage binding.
///
/// Every logical surface path is resolved with the hub's
/// [`safe_join`](crate::fetch::safe_join) (rejecting `..` and absolute
/// components) before any IO, and writes go through an atomic temp-file +
/// rename so a concurrent reader never sees a half-written object — the exact
/// path-safety and atomicity semantics the hub's original `gitwrite` enforced.
struct LocalFsWrite {
    /// The registry's storage-binding root the logical paths resolve under.
    root: PathBuf,
}

#[async_trait]
impl core_sw::SurfaceWrite for LocalFsWrite {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let target = crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        write_atomic(&target, bytes).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let target = crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        match tokio::fs::remove_file(&target).await {
            Ok(()) => Ok(()),
            // Idempotent: a missing object is a successful delete.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("deleting {}", target.display())),
        }
    }
}

/// Write `bytes` to `target` atomically (temp file + rename), creating parents.
///
/// Mirrors the hub's original `gitwrite::write_atomic` so a concurrent reader
/// never observes a half-written object or ref.
async fn write_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = target.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("writing {}", tmp.display()))?;
    tokio::fs::rename(&tmp, target)
        .await
        .with_context(|| format!("renaming into {}", target.display()))?;
    Ok(())
}

/// Maximum response-body size for an OIDC outbound call: 1 MiB.
///
/// A token-endpoint response and a JWKS document are KB-scale by nature, so a
/// 1 MiB cap leaves ample headroom while ensuring a hostile IdP endpoint cannot
/// stream an unbounded body and OOM the hub.
const MAX_OIDC_BODY_BYTES: u64 = 1024 * 1024;

/// The native [`HttpClient`](console_ports::HttpClient): the hub's hardened
/// [`reqwest`] client behind the shared console's OIDC outbound port.
///
/// Both methods inherit the hardened client's SSRF resolver (which refuses
/// private, loopback, and link-local addresses), its bounded request timeout,
/// and a 1 MiB body cap via [`crate::fetch::read_body_capped`] — the exact
/// hardening the hub's own OIDC code applies — so routing the OIDC flow through
/// this port preserves the multi-tenant safety properties unchanged.
pub struct HubHttpClient {
    /// The hub's shared hardened HTTP client (SSRF-resolving, timeout-bounded).
    client: reqwest::Client,
}

impl HubHttpClient {
    /// Build the port over the hub's hardened [`reqwest`] client.
    #[must_use]
    pub fn new(client: reqwest::Client) -> HubHttpClient {
        HubHttpClient { client }
    }
}

#[async_trait]
impl console_ports::HttpClient for HubHttpClient {
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()
            .with_context(|| format!("POST {url}"))?;
        crate::fetch::read_body_capped(response, MAX_OIDC_BODY_BYTES, "OIDC token response").await
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?;
        crate::fetch::read_body_capped(response, MAX_OIDC_BODY_BYTES, "JWKS document").await
    }
}

/// The native [`ChannelAdvancer`](console_ports::ChannelAdvancer): the hub's
/// [`signing`](crate::signing) module behind the shared console's hosted-key
/// advance port.
///
/// Delegates the entire signing-and-publishing closure to
/// [`crate::signing::advance_channel`] — key load, anti-rollback floor check,
/// partition signing, atomic write, re-index, and audit — and maps its
/// [`AdvanceResult`](crate::signing::AdvanceResult) (field-for-field) to the
/// core [`AdvanceOutcome`](console_ports::AdvanceOutcome).
pub struct HubChannelAdvancer {
    /// The hub database the signer reads keys/floors from and writes the index
    /// and audit rows to.
    db: Arc<Database>,
    /// The at-rest sealer that unseals the registry's hosted signing key.
    sealer: Arc<dyn SecretSealer>,
}

impl HubChannelAdvancer {
    /// Build the advancer over the hub database and at-rest sealer.
    #[must_use]
    pub fn new(db: Arc<Database>, sealer: Arc<dyn SecretSealer>) -> HubChannelAdvancer {
        HubChannelAdvancer { db, sealer }
    }
}

#[async_trait]
impl console_ports::ChannelAdvancer for HubChannelAdvancer {
    async fn advance(
        &self,
        registry: &RegistryRecord,
        channel_name: &str,
        target_semver: &str,
        count: usize,
        when: i64,
    ) -> Result<console_ports::AdvanceOutcome> {
        let result = crate::signing::advance_channel(
            &self.db,
            self.sealer.as_ref(),
            registry,
            channel_name,
            target_semver,
            count,
            when,
        )
        .await?;
        Ok(console_ports::AdvanceOutcome {
            channel: result.channel,
            release: result.release,
            moved: result.moved,
            at_target: result.at_target,
            rollout_percent: result.rollout_percent,
        })
    }
}
