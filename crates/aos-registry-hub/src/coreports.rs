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

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use aos_registry_core::db::{Database, RegistryRecord};
use aos_registry_core::fetch as core_fetch;
use aos_registry_core::ratelimit as core_rl;
use aos_registry_core::reindex as core_reindex;
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

    /// Forwards to the hub fetcher's efficient `metadata`-based size (avoids a
    /// full read, and probes a never-written binding cleanly as `None`).
    async fn size(&self, path: &str) -> Result<Option<u64>> {
        crate::fetch::SurfaceFetch::size(self, path).await
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

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        crate::fetch::SurfaceFetch::size(self, path).await
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

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        self.0.size(path).await
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
/// components), then symlink-canonicalized and required to stay under the real
/// storage root — the same containment the read side
/// ([`LocalFsFetch`](crate::fetch::LocalFsFetch)) enforces, so a symlinked path
/// component cannot steer a write or delete outside the registry's root. Writes
/// go through an atomic temp-file + rename so a concurrent reader never sees a
/// half-written object.
struct LocalFsWrite {
    /// The registry's storage-binding root the logical paths resolve under.
    root: PathBuf,
}

#[async_trait]
impl core_sw::SurfaceWrite for LocalFsWrite {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let target = crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        // Containment: create the parent, then require its real (symlink-
        // resolved) location to live under the real root, so a symlinked
        // component cannot redirect the write outside the storage root. The
        // returned target is rebased onto the canonical parent.
        let contained = self.contained_target(&target).await?;
        write_atomic(&contained, bytes).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let target = crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        // A missing object is a successful (idempotent) delete; an existing one
        // must canonicalize under the root before removal.
        let canonical = match tokio::fs::canonicalize(&target).await {
            Ok(canonical) => canonical,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| format!("resolving {}", target.display()));
            }
        };
        let root = tokio::fs::canonicalize(&self.root)
            .await
            .with_context(|| format!("canonicalizing storage root {}", self.root.display()))?;
        if !canonical.starts_with(&root) {
            bail!("surface path '{path}' escapes the storage root via symlink");
        }
        match tokio::fs::remove_file(&canonical).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("deleting {}", canonical.display())),
        }
    }
}

impl LocalFsWrite {
    /// Resolve `target`'s parent under the real storage root, returning the
    /// write target rebased onto the canonical parent.
    ///
    /// Creates the parent directory, then symlink-canonicalizes both the root
    /// and the parent and requires the parent to stay under the root, so a
    /// symlinked path component cannot redirect the subsequent write outside the
    /// registry's storage root. (`target` itself need not exist yet.)
    ///
    /// # Errors
    ///
    /// Returns an error if the parent cannot be created or canonicalized, if it
    /// escapes the root via a symlink, or if `target` has no file-name segment.
    async fn contained_target(&self, target: &Path) -> Result<PathBuf> {
        let parent = target.parent().unwrap_or(self.root.as_path());
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
        let root = tokio::fs::canonicalize(&self.root)
            .await
            .with_context(|| format!("canonicalizing storage root {}", self.root.display()))?;
        let canonical_parent = tokio::fs::canonicalize(parent)
            .await
            .with_context(|| format!("canonicalizing {}", parent.display()))?;
        if !canonical_parent.starts_with(&root) {
            bail!("surface path escapes the storage root via symlink");
        }
        let file_name = target
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("surface path has no file-name segment"))?;
        Ok(canonical_parent.join(file_name))
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

/// The native [`Reindexer`](core_reindex::Reindexer): re-indexes a managed
/// registry inline from its local surface and records an `index` audit row.
///
/// Resolves the registry's storage-binding root and indexes from a
/// [`LocalFsFetch`](crate::fetch::LocalFsFetch) over it (not the empty
/// `source_url`, as managed registries have no HTTP origin) through
/// [`crate::indexer::index_and_record`], then records a `system`-actor `index`
/// audit row cross-referencing the resulting commit. This is the relocated,
/// byte-identical behavior of the hub's prior facade `reindex`, so a managed
/// publish becomes browse-visible the instant its completing pointer write
/// returns.
pub struct HubReindexer {
    /// The hub database the indexer reads/writes and the audit row lands in.
    db: Arc<Database>,
}

impl HubReindexer {
    /// Build the reindexer over the hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> HubReindexer {
        HubReindexer { db }
    }
}

#[async_trait]
impl core_reindex::Reindexer for HubReindexer {
    async fn reindex(&self, registry: &RegistryRecord) -> Result<Option<String>> {
        let root = self
            .db
            .registry_surface_root(registry.id)
            .await?
            .with_context(|| {
                format!(
                    "registry '{}' has no writable storage root to re-index from",
                    registry.slug
                )
            })?;
        let fetch = crate::fetch::LocalFsFetch::new(&root);
        let outcome = crate::indexer::index_and_record(&self.db, &fetch, registry).await?;
        // Record an `index` audit row so the publish-pipeline view (and the org
        // audit feed) reflects the inline reindex a managed publish triggers.
        // The actor is the hub itself (`system`); the resulting commit cross-
        // references the cryptographic history.
        self.db
            .record_audit(
                "system",
                None,
                "system",
                "index",
                &registry.slug,
                None,
                Some(&outcome.commit),
                None,
                None,
            )
            .await?;
        Ok(Some(outcome.commit))
    }
}
