//! Native adapters from the hub's concrete types to the core service ports.
//!
//! The shared, transport-free service
//! ([`RpcService`](aos_hub_core::service::RpcService)) depends on a small
//! set of platform ports — a [`RateLimiter`](aos_hub_core::ratelimit::RateLimiter)
//! and a [`SurfaceProvider`](aos_hub_core::fetch::SurfaceProvider) — so the
//! same method bodies run unchanged on the native hub and the Cloudflare Worker.
//! The native hub already owns concrete equivalents (the in-process
//! [`RateLimiter`](crate::ratelimit::RateLimiter) and the filesystem/HTTP
//! [`SurfaceFetch`](crate::fetch::SurfaceFetch) transports), so this module is the
//! thin glue that makes those concrete types *satisfy the core ports*:
//!
//! - [`crate::ratelimit::RateLimiter`] gains an
//!   [`aos_hub_core::ratelimit::RateLimiter`] impl. The core trait method is
//!   `async`; the hub's check is a synchronous counter read-modify-write, so the
//!   impl simply runs it inline. The two enums ([`RateClass`] and
//!   [`RateDecision`]) are mirror-for-mirror and are mapped by name.
//! - [`crate::fetch::LocalFsFetch`] and [`crate::fetch::HttpFetch`] each gain an
//!   [`aos_hub_core::fetch::SurfaceFetch`] impl with the identical
//!   `fetch`/`describe` signatures, delegating to their inherent methods.
//! - [`HubSurfaceProvider`] is the
//!   [`SurfaceProvider`](aos_hub_core::fetch::SurfaceProvider): topology reads
//!   open the selected placement's binding and prefix directly; unplaced legacy
//!   registries retain the existing
//!   [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry)
//!   migration fallback through [`CoreFetchAdapter`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use aos_hub_core::auth::seal::SecretSealer;
use aos_hub_core::binding::BindingKind;
use aos_hub_core::db::{Database, RegistryRecord, SurfacePlacementRecord};
use aos_hub_core::fetch as core_fetch;
use aos_hub_core::ratelimit as core_rl;
use aos_hub_core::reindex as core_reindex;
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::surface_write as core_sw;
use aos_hub_core::web::console::ports as console_ports;

/// Classifies native filesystem failures before placement failover.
fn native_placement_read_error(error: anyhow::Error) -> anyhow::Error {
    if error
        .chain()
        .any(|cause| cause.is::<aos_hub_core::placement_read::ClassifiedReadError>())
    {
        return error;
    }
    let detail = format!("{error:#}");
    if error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::fetch::LocalFsReadError>())
        .is_some_and(crate::fetch::LocalFsReadError::is_retryable)
    {
        aos_hub_core::placement_read::retryable_read_error(detail)
    } else {
        aos_hub_core::placement_read::terminal_read_error(detail)
    }
}

/// Resolve a registry's/cache's storage binding into an [`S3Surface`] when it is
/// an external `s3`/`r2` object store, or `Ok(None)` otherwise.
///
/// `binding_id` is the resource's `storage_binding_id` and `sub_prefix` its
/// `prefix`. A non-object-store binding (or no binding) yields `Ok(None)` so the
/// caller falls through to the filesystem/HTTP path. An `s3`/`r2` binding without
/// a configured sealer is an error (its sealed credentials cannot be unsealed).
///
/// # Errors
///
/// Returns an error on database failure, when an `s3`/`r2` binding is present but
/// no sealer is wired, or when [`S3Surface::from_binding`] rejects the binding
/// (missing endpoint or malformed credentials).
async fn s3_surface_for(
    db: &Database,
    sealer: Option<&Arc<dyn SecretSealer>>,
    binding_id: Option<i64>,
    sub_prefix: &str,
) -> Result<Option<S3Surface>> {
    let Some(id) = binding_id else {
        return Ok(None);
    };
    let Some(binding) = db.storage_binding(id).await? else {
        return Ok(None);
    };
    if !matches!(binding.kind.as_str(), "s3" | "r2") {
        return Ok(None);
    }
    let sealer = sealer
        .context("an s3/r2 storage binding requires a configured secret sealer (HUB_SEAL_KEY)")?;
    S3Surface::from_binding(&binding, sub_prefix, sealer.as_ref())
}

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
        crate::fetch::SurfaceFetch::fetch(self, path)
            .await
            .map_err(native_placement_read_error)
    }

    /// Streams the file from disk (`tokio` `ReaderStream`, Range-aware) instead
    /// of buffering — the native side of the shared `cache_serve` path, so a
    /// large NAR never lands in memory.
    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<core_fetch::StreamedRead>> {
        self.stream_read(path, range)
            .await
            .map_err(native_placement_read_error)
    }

    /// Forwards to the hub fetcher's efficient `metadata`-based size (avoids a
    /// full read, and probes a never-written binding cleanly as `None`).
    async fn size(&self, path: &str) -> Result<Option<u64>> {
        crate::fetch::SurfaceFetch::size(self, path)
            .await
            .map_err(native_placement_read_error)
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
/// [`gitwrite::fetcher_for_registry`](crate::gitwrite::fetcher_for_registry) and
/// [`fetch_for_url`](crate::fetch::fetch_for_url) return a
/// `Box<dyn crate::fetch::SurfaceFetch>` (the hub trait object) chosen per
/// registry or source URL. The relocated core indexer
/// ([`aos_hub_core::indexer`]) and the core service need a
/// `Box<dyn core_fetch::SurfaceFetch>`, and a trait object cannot be re-coerced
/// to a *different* trait, so this concrete wrapper holds the hub box and
/// forwards both methods. Callers that already hold a hub fetcher box bridge it
/// to the core port with [`into_core_fetch`].
pub struct CoreFetchAdapter(Box<dyn crate::fetch::SurfaceFetch>);

/// Bridge a hub [`SurfaceFetch`](crate::fetch::SurfaceFetch) box to a boxed core
/// [`SurfaceFetch`](core_fetch::SurfaceFetch) for the relocated core indexer.
///
/// The hub's [`fetch_for_url`](crate::fetch::fetch_for_url) /
/// `fetch_for_registry` return the hub trait object; the relocated
/// [`index_and_record`](aos_hub_core::indexer::index_and_record) reads the
/// core port. This wraps the former in [`CoreFetchAdapter`] so a hub-side caller
/// can drive the shared indexer over any hub-resolved surface fetcher.
#[must_use]
pub fn into_core_fetch(
    fetch: Box<dyn crate::fetch::SurfaceFetch>,
) -> Box<dyn core_fetch::SurfaceFetch> {
    Box::new(CoreFetchAdapter(fetch))
}

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

/// The native [`SurfaceProvider`](core_fetch::SurfaceProvider) over Hub bindings.
///
/// Explicit placements resolve their own binding plus prefix. The registry and
/// cache methods below are retained only for unplaced migration fallbacks and
/// background consumers not yet switched to a topology plan.
pub struct HubSurfaceProvider {
    /// The hub database, used to resolve a registry's storage-binding root.
    db: Arc<Database>,
    /// The secret sealer, required to unseal an `s3`/`r2` binding's credentials.
    /// `None` on paths that never serve an object-store binding.
    sealer: Option<Arc<dyn SecretSealer>>,
    /// Shared HTTP client for proxying reads to an external `s3`/`r2` origin.
    http: reqwest::Client,
}

impl HubSurfaceProvider {
    /// Build a provider over the hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> HubSurfaceProvider {
        HubSurfaceProvider {
            db,
            sealer: None,
            http: reqwest::Client::new(),
        }
    }

    /// Attach the secret sealer so `s3`/`r2` bindings can be served (their sealed
    /// credentials are unsealed to mint presigned URLs).
    #[must_use]
    pub fn with_sealer(mut self, sealer: Arc<dyn SecretSealer>) -> HubSurfaceProvider {
        self.sealer = Some(sealer);
        self
    }
}

#[async_trait]
impl core_fetch::SurfaceProvider for HubSurfaceProvider {
    async fn placement_fetcher(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn core_fetch::SurfaceFetch>> {
        let binding = self
            .db
            .storage_binding(placement.storage_binding_id)
            .await?
            .ok_or_else(|| {
                aos_hub_core::placement_read::terminal_read_error(format!(
                    "placement '{}' references a missing storage binding",
                    placement.name
                ))
            })?;
        match BindingKind::parse(&binding.kind) {
            Some(BindingKind::S3 | BindingKind::R2) => {
                let sealer = self.sealer.as_ref().ok_or_else(|| {
                    aos_hub_core::placement_read::terminal_read_error(format!(
                        "placement '{}' requires a configured secret sealer",
                        placement.name
                    ))
                })?;
                let surface = S3Surface::from_binding(&binding, &placement.prefix, sealer.as_ref())
                    .map_err(|error| {
                        aos_hub_core::placement_read::terminal_read_error(format!(
                            "placement '{}' has invalid object-store configuration: {error:#}",
                            placement.name
                        ))
                    })?
                    .ok_or_else(|| {
                        aos_hub_core::placement_read::terminal_read_error(format!(
                            "placement '{}' could not resolve its object-store binding",
                            placement.name
                        ))
                    })?;
                Ok(Box::new(S3Fetch::new(surface, self.http.clone())))
            }
            Some(BindingKind::LocalFs) => {
                let root = PathBuf::from(&binding.root).join(&placement.prefix);
                Ok(Box::new(crate::fetch::LocalFsFetch::new(root)))
            }
            None => Err(aos_hub_core::placement_read::terminal_read_error(format!(
                "placement '{}' uses unknown storage binding kind '{}'",
                placement.name, binding.kind
            ))),
        }
    }

    async fn fetcher(
        &self,
        registry: &RegistryRecord,
    ) -> Result<Box<dyn core_fetch::SurfaceFetch>> {
        if let Some(surface) = s3_surface_for(
            &self.db,
            self.sealer.as_ref(),
            registry.storage_binding_id,
            &registry.prefix,
        )
        .await?
        {
            return Ok(Box::new(S3Fetch::new(surface, self.http.clone())));
        }
        let hub_fetch = crate::gitwrite::fetcher_for_registry(&self.db, registry).await?;
        Ok(Box::new(CoreFetchAdapter(hub_fetch)))
    }

    async fn cache_fetcher(
        &self,
        cache: &crate::db::Cache,
    ) -> Result<Box<dyn core_fetch::SurfaceFetch>> {
        if let Some(surface) = s3_surface_for(
            &self.db,
            self.sealer.as_ref(),
            cache.storage_binding_id,
            &cache.prefix,
        )
        .await?
        {
            return Ok(Box::new(S3Fetch::new(surface, self.http.clone())));
        }
        let root = self
            .db
            .cache_surface_root(cache.id)
            .await?
            .with_context(|| format!("cache '{}' has no surface root", cache.slug))?;
        // `LocalFsFetch` implements the core `SurfaceFetch` directly (see the impl
        // below), so no `CoreFetchAdapter` is needed.
        Ok(Box::new(crate::fetch::LocalFsFetch::new(root)))
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
    /// The secret sealer, required to unseal an `s3`/`r2` binding's credentials.
    sealer: Option<Arc<dyn SecretSealer>>,
    /// Shared HTTP client for proxying writes to an external `s3`/`r2` origin.
    http: reqwest::Client,
}

impl HubSurfaceWriteProvider {
    /// Build a write provider over the hub database.
    #[must_use]
    pub fn new(db: Arc<Database>) -> HubSurfaceWriteProvider {
        HubSurfaceWriteProvider {
            db,
            sealer: None,
            http: reqwest::Client::new(),
        }
    }

    /// Attach the secret sealer so writes to `s3`/`r2` bindings can be signed.
    #[must_use]
    pub fn with_sealer(mut self, sealer: Arc<dyn SecretSealer>) -> HubSurfaceWriteProvider {
        self.sealer = Some(sealer);
        self
    }
}

#[async_trait]
impl core_sw::SurfaceWriteProvider for HubSurfaceWriteProvider {
    async fn writer(&self, registry: &RegistryRecord) -> Result<Box<dyn core_sw::SurfaceWrite>> {
        if let Some(surface) = s3_surface_for(
            &self.db,
            self.sealer.as_ref(),
            registry.storage_binding_id,
            &registry.prefix,
        )
        .await?
        {
            return Ok(Box::new(S3Write::new(surface, self.http.clone())));
        }
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

    async fn cache_writer(
        &self,
        cache: &crate::db::Cache,
    ) -> Result<Box<dyn core_sw::SurfaceWrite>> {
        if let Some(surface) = s3_surface_for(
            &self.db,
            self.sealer.as_ref(),
            cache.storage_binding_id,
            &cache.prefix,
        )
        .await?
        {
            return Ok(Box::new(S3Write::new(surface, self.http.clone())));
        }
        let root = self
            .db
            .cache_surface_root(cache.id)
            .await?
            .with_context(|| format!("cache '{}' has no surface root", cache.slug))?;
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

    async fn create_multipart(&self, path: &str) -> Result<String> {
        // Validate the eventual target is a safe path before accepting any part,
        // so an unsafe upload fails fast. (The atomic write into place happens at
        // `complete_multipart`.) `path` is otherwise not needed until then — the
        // caller carries it back on every part/complete call.
        crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        let upload_id = uuid::Uuid::new_v4().to_string();
        let dir = self.parts_dir(&upload_id);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating upload staging dir {}", dir.display()))?;
        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        _path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<core_sw::PartTag> {
        let dir = self.parts_dir(&validate_upload_id(upload_id)?);
        if !tokio::fs::try_exists(&dir).await.unwrap_or(false) {
            bail!("unknown multipart upload id");
        }
        // Each part is its own staged file; peak memory is a single part.
        write_atomic(&dir.join(format!("part-{part_number:08}")), bytes).await?;
        Ok(core_sw::PartTag {
            part_number,
            etag: String::new(),
        })
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[core_sw::PartTag],
    ) -> Result<()> {
        let dir = self.parts_dir(&validate_upload_id(upload_id)?);
        let target = crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        let contained = self.contained_target(&target).await?;
        // Concatenate the staged parts in `part_number` order into a temp file,
        // then atomic-rename into place: a reader never sees a partial object,
        // and memory stays bounded to the copy buffer (no part is held whole).
        let mut ordered: Vec<u32> = parts.iter().map(|p| p.part_number).collect();
        ordered.sort_unstable();
        let tmp = contained.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        {
            use tokio::io::AsyncWriteExt as _;
            let out = tokio::fs::File::create(&tmp)
                .await
                .with_context(|| format!("creating {}", tmp.display()))?;
            let mut writer = tokio::io::BufWriter::new(out);
            for n in ordered {
                let part_path = dir.join(format!("part-{n:08}"));
                let mut part = tokio::fs::File::open(&part_path)
                    .await
                    .with_context(|| format!("opening staged part {}", part_path.display()))?;
                tokio::io::copy(&mut part, &mut writer)
                    .await
                    .with_context(|| format!("appending part {n}"))?;
            }
            writer
                .flush()
                .await
                .with_context(|| "flushing assembled object")?;
        }
        tokio::fs::rename(&tmp, &contained)
            .await
            .with_context(|| format!("renaming into {}", contained.display()))?;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        Ok(())
    }

    async fn abort_multipart(&self, _path: &str, upload_id: &str) -> Result<()> {
        let _ = tokio::fs::remove_dir_all(self.parts_dir(&validate_upload_id(upload_id)?)).await;
        Ok(())
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

    /// The staging directory holding an in-progress multipart upload's parts.
    ///
    /// `upload_id` is a validated UUID (see [`validate_upload_id`]), so it cannot
    /// contain path separators; the parts live under a reserved `.uploads/`
    /// prefix inside the storage root, away from the served surface.
    fn parts_dir(&self, upload_id: &str) -> PathBuf {
        self.root.join(".uploads").join(upload_id)
    }
}

/// Validate a multipart upload id is a well-formed UUID, returning its canonical
/// string form.
///
/// Multipart ids reach the filesystem as a path segment, so this rejects any
/// value that is not a UUID — closing off `..`/separator injection through the
/// `upload_id` carried in the wire protocol.
///
/// # Errors
///
/// Returns an error when `upload_id` is not a valid UUID.
fn validate_upload_id(upload_id: &str) -> Result<String> {
    Ok(uuid::Uuid::parse_str(upload_id)
        .context("invalid multipart upload id")?
        .to_string())
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

/// A `reqwest`-backed [`OriginFetch`](core_fetch::OriginFetch) for the native hub.
///
/// Streams a private external origin's bytes through the hub (the proxy-read
/// alternative to a `302` presigned redirect), forwarding a byte range as a
/// `Range` request header and re-deriving the served range/total from the
/// origin's `Content-Range`/`Content-Length` response headers. The body is
/// `reqwest`'s chunked `bytes_stream`, so a large NAR never buffers in the hub.
pub struct ReqwestOriginFetch {
    http: reqwest::Client,
}

impl ReqwestOriginFetch {
    /// Wrap the hub's shared `reqwest` client as an origin proxy fetcher.
    #[must_use]
    pub fn new(http: reqwest::Client) -> ReqwestOriginFetch {
        ReqwestOriginFetch { http }
    }
}

#[async_trait]
impl core_fetch::OriginFetch for ReqwestOriginFetch {
    async fn get_stream(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<core_fetch::StreamedRead>> {
        use reqwest::header;

        let mut req = self.http.get(url);
        if let Some((start, end)) = range {
            // Forward the inclusive range as an HTTP `Range` header; an open-ended
            // request (`end == u64::MAX`) becomes `bytes=start-`.
            let spec = if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            };
            req = req.header(header::RANGE, spec);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("origin GET {url}"))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            bail!("origin GET {url}: status {status}");
        }
        // `Content-Range: bytes start-end/total` on a 206 gives both the served
        // range and the full size; a plain 200 carries the size in
        // `Content-Length` and serves the whole object.
        let served;
        let total;
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let cr = resp
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range)
                .context("origin 206 without a parseable Content-Range")?;
            // Trust nothing from the origin: a malformed `Content-Range`
            // (`end < start`, or `end` past `total`) would underflow/overflow the
            // `Content-Length` arithmetic downstream. Enforce `fetch_stream`'s
            // invariant — `start <= end < total` — at the boundary.
            if cr.0 > cr.1 || cr.1 >= cr.2 {
                bail!(
                    "origin {url}: malformed Content-Range bytes {}-{}/{}",
                    cr.0,
                    cr.1,
                    cr.2
                );
            }
            served = Some((cr.0, cr.1));
            total = cr.2;
        } else {
            served = None;
            total = resp
                .content_length()
                .context("origin 200 without a Content-Length")?;
        }
        // `reqwest::Error` satisfies `Body::from_stream`'s `Into<BoxError>` bound,
        // so the chunked body streams straight through with no re-wrapping.
        Ok(Some(core_fetch::StreamedRead {
            body: axum::body::Body::from_stream(resp.bytes_stream()),
            total,
            range: served,
        }))
    }
}

/// A `reqwest`-backed [`SurfaceFetch`](core_fetch::SurfaceFetch) that reads a
/// registry's (or cache's) surface from an external S3-compatible object store.
///
/// Every read is a plain HTTP request to a short-lived presigned URL minted by
/// the shared [`S3Surface`] signer, so the same binding is served identically on
/// the native hub and the Worker. The hub proxies the bytes (it never hands the
/// origin URL to a client), so registry visibility is enforced exactly as for a
/// filesystem surface.
pub struct S3Fetch {
    surface: S3Surface,
    http: reqwest::Client,
}

impl S3Fetch {
    /// Wrap a resolved [`S3Surface`] and the hub's HTTP client as a fetcher.
    #[must_use]
    pub fn new(surface: S3Surface, http: reqwest::Client) -> S3Fetch {
        S3Fetch { surface, http }
    }
}

#[async_trait]
impl core_fetch::SurfaceFetch for S3Fetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let url =
            self.surface
                .object_url(S3Method::Get, path, aos_hub_core::clock::now_unix_secs())?;
        let resp = self.http.get(&url).send().await.map_err(|error| {
            aos_hub_core::placement_read::retryable_read_error(format!(
                "s3 GET {}: {error}",
                self.surface.describe()
            ))
        })?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        // A 403 is NOT treated as "absent": the hub presigns with the org's own
        // credentials (full access to its bucket), so a 403 means a misconfigured
        // binding (bad/rotated secret, wrong region/bucket, clock skew) — surface
        // it loudly rather than silently serving the registry as empty. (This
        // matches the Worker provider; only a true 404 is a miss.)
        if !status.is_success() {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 GET {path}"),
                status.as_u16(),
            ));
        }
        let bytes = resp.bytes().await.map_err(|error| {
            aos_hub_core::placement_read::retryable_read_error(format!(
                "reading s3 object body: {error}"
            ))
        })?;
        Ok(Some(bytes.to_vec()))
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<core_fetch::StreamedRead>> {
        use reqwest::header;

        // A presigned URL signs only the `Host` header, so a `Range` request
        // header may be added freely without invalidating the signature.
        let url =
            self.surface
                .object_url(S3Method::Get, path, aos_hub_core::clock::now_unix_secs())?;
        let mut req = self.http.get(&url);
        if let Some((start, end)) = range {
            let spec = if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            };
            req = req.header(header::RANGE, spec);
        }
        let resp = req.send().await.map_err(|error| {
            aos_hub_core::placement_read::retryable_read_error(format!("s3 GET {path}: {error}"))
        })?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 GET {path}"),
                status.as_u16(),
            ));
        }
        let served;
        let total;
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let cr = resp
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range)
                .context("s3 206 without a parseable Content-Range")?;
            if cr.0 > cr.1 || cr.1 >= cr.2 {
                bail!(
                    "s3 {path}: malformed Content-Range bytes {}-{}/{}",
                    cr.0,
                    cr.1,
                    cr.2
                );
            }
            served = Some((cr.0, cr.1));
            total = cr.2;
        } else {
            served = None;
            total = resp
                .content_length()
                .context("s3 200 without a Content-Length")?;
        }
        Ok(Some(core_fetch::StreamedRead {
            body: axum::body::Body::from_stream(resp.bytes_stream()),
            total,
            range: served,
        }))
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        let url =
            self.surface
                .object_url(S3Method::Head, path, aos_hub_core::clock::now_unix_secs())?;
        let resp = self
            .http
            .head(&url)
            .send()
            .await
            .with_context(|| format!("s3 HEAD {path}"))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 HEAD {path}"),
                status.as_u16(),
            ));
        }
        Ok(resp.content_length())
    }

    fn describe(&self) -> String {
        self.surface.describe()
    }
}

/// A `reqwest`-backed [`SurfaceWrite`](core_sw::SurfaceWrite) that writes a
/// registry's (or cache's) surface to an external S3-compatible object store.
///
/// The write sibling of [`S3Fetch`]: each `write`/`delete` is a plain HTTP
/// `PUT`/`DELETE` to a presigned URL. A `public` (credential-less) binding is
/// read-only, so [`S3Surface::object_url`] refuses to mint a write URL and these
/// methods surface that error.
pub struct S3Write {
    surface: S3Surface,
    http: reqwest::Client,
}

impl S3Write {
    /// Wrap a resolved [`S3Surface`] and the hub's HTTP client as a writer.
    #[must_use]
    pub fn new(surface: S3Surface, http: reqwest::Client) -> S3Write {
        S3Write { surface, http }
    }
}

#[async_trait]
impl core_sw::SurfaceWrite for S3Write {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let url =
            self.surface
                .object_url(S3Method::Put, path, aos_hub_core::clock::now_unix_secs())?;
        let resp = self
            .http
            .put(&url)
            .body(bytes.to_vec())
            .send()
            .await
            .with_context(|| format!("s3 PUT {path}"))?;
        if !resp.status().is_success() {
            bail!("s3 PUT {path}: status {}", resp.status());
        }
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let url = self.surface.object_url(
            S3Method::Delete,
            path,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .with_context(|| format!("s3 DELETE {path}"))?;
        let status = resp.status();
        // S3 returns 204 for a delete; a missing object is also a success (the
        // delete is idempotent).
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        bail!("s3 DELETE {path}: status {status}");
    }
}

/// Parse a `Content-Range: bytes START-END/TOTAL` value into `(start, end, total)`.
///
/// Returns `None` for an unsatisfiable (`bytes */TOTAL`) or malformed value.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some((
        start.trim().parse().ok()?,
        end.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

#[cfg(test)]
mod multipart_tests {
    use super::*;
    use core_sw::SurfaceWrite as _;

    #[test]
    fn native_placement_io_retries_only_known_transient_kinds() {
        use aos_hub_core::placement_read::{classify_read_error, ReadFailureClass};

        for kind in [
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::ConnectionReset,
        ] {
            let error = crate::fetch::local_fs_io_error("test read", std::io::Error::from(kind));
            assert_eq!(
                classify_read_error(&native_placement_read_error(error)),
                ReadFailureClass::Retryable,
                "{kind:?}"
            );
        }
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::Other,
        ] {
            let error = crate::fetch::local_fs_io_error("test read", std::io::Error::from(kind));
            assert_eq!(
                classify_read_error(&native_placement_read_error(error)),
                ReadFailureClass::Terminal,
                "{kind:?}"
            );
        }
        assert_eq!(
            classify_read_error(&native_placement_read_error(anyhow::anyhow!("unknown"))),
            ReadFailureClass::Terminal
        );
    }

    #[tokio::test]
    async fn local_fs_multipart_assembles_in_order_and_matches_single_write() {
        let dir = tempfile::tempdir().unwrap();
        let w = LocalFsWrite {
            root: dir.path().to_path_buf(),
        };
        let path = "nar/sha256-test.nar.zst";

        let upload_id = w.create_multipart(path).await.unwrap();
        // Upload out of order; complete must reassemble by part_number.
        let p2 = w.upload_part(path, &upload_id, 2, b"-world").await.unwrap();
        let p1 = w.upload_part(path, &upload_id, 1, b"hello").await.unwrap();
        let p3 = w.upload_part(path, &upload_id, 3, b"-again").await.unwrap();
        w.complete_multipart(path, &upload_id, &[p3, p1, p2])
            .await
            .unwrap();

        let assembled = tokio::fs::read(dir.path().join(path)).await.unwrap();
        assert_eq!(assembled, b"hello-world-again");

        // Parity: a single write() of the same bytes yields identical content.
        let single = "nar/single.nar.zst";
        w.write(single, b"hello-world-again").await.unwrap();
        assert_eq!(
            tokio::fs::read(dir.path().join(single)).await.unwrap(),
            assembled
        );

        // The staging dir is removed on completion.
        assert!(!dir.path().join(".uploads").join(&upload_id).exists());
    }

    #[tokio::test]
    async fn local_fs_multipart_rejects_non_uuid_upload_id() {
        let dir = tempfile::tempdir().unwrap();
        let w = LocalFsWrite {
            root: dir.path().to_path_buf(),
        };
        // A non-UUID upload id (path-injection attempt) is rejected, not joined.
        assert!(w.upload_part("nar/x", "../escape", 1, b"x").await.is_err());
        assert!(w.abort_multipart("nar/x", "../escape").await.is_err());
    }
}
