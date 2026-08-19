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
//!   [`SurfaceProvider`](aos_hub_core::fetch::SurfaceProvider): every topology
//!   read opens the selected placement's binding and prefix directly.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use aos_hub_core::binding::BindingKind;
use aos_hub_core::db::{Database, RegistryRecord, SurfacePlacementRecord};
use aos_hub_core::fetch as core_fetch;
use aos_hub_core::ratelimit as core_rl;
use aos_hub_core::reindex as core_reindex;
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::secret_version::{
    validate_secret_version_ref, ResolvedSecretVersion, SecretVersionResolver,
};
use aos_hub_core::storage_credential::{
    DatabaseStorageCredentialResolver, StorageCredentialResolver,
};
use aos_hub_core::surface_write as core_sw;
use aos_hub_core::web::console::ports as console_ports;

/// Loads exact secret-version bindings from an owner-private reference manifest.
///
/// The JSON object maps each opaque provider reference to a local secret-file
/// path. The manifest contains no credential bytes; each referenced file is
/// securely reopened when the exact version is resolved.
///
/// # Errors
///
/// Returns an error when the manifest, a reference, or a secret file is invalid.
pub fn load_secret_version_manifest(path: &Path) -> Result<Arc<dyn SecretVersionResolver>> {
    let manifest = crate::auth::seal::read_secret_file(path)
        .with_context(|| format!("reading secret-version manifest at {}", path.display()))?;
    let paths: std::collections::BTreeMap<String, PathBuf> =
        serde_json::from_slice(&manifest).context("parsing secret-version manifest")?;
    for version_ref in paths.keys() {
        validate_secret_version_ref(version_ref)?;
    }
    Ok(Arc::new(NativeSecretVersionResolver { paths }))
}

struct NativeSecretVersionResolver {
    paths: std::collections::BTreeMap<String, PathBuf>,
}

#[async_trait]
impl SecretVersionResolver for NativeSecretVersionResolver {
    async fn resolve(&self, version_ref: &str) -> Result<ResolvedSecretVersion> {
        validate_secret_version_ref(version_ref)?;
        let path = self
            .paths
            .get(version_ref)
            .context("secret provider has no configured version")?;
        let bytes = crate::auth::seal::read_secret_file_zeroizing(path)
            .context("securely reading configured secret version")?;
        Ok(ResolvedSecretVersion::from_zeroizing(bytes))
    }
}

/// Native controller adapter that exercises exact storage credentials against
/// their configured S3-compatible origin.
pub struct NativeStorageCredentialProbeProvider {
    client: reqwest::Client,
    secrets: Arc<dyn SecretVersionResolver>,
}

impl NativeStorageCredentialProbeProvider {
    /// Creates a probe adapter over the hardened egress client and secret store.
    #[must_use]
    pub fn new(client: reqwest::Client, secrets: Arc<dyn SecretVersionResolver>) -> Self {
        Self { client, secrets }
    }

    async fn send(&self, method: reqwest::Method, url: &str) -> Result<reqwest::StatusCode> {
        Ok(self.client.request(method, url).send().await?.status())
    }
}

#[async_trait]
impl aos_hub_core::topology_probe::StorageCredentialProbeProvider
    for NativeStorageCredentialProbeProvider
{
    async fn probe(
        &self,
        binding: &aos_hub_core::db::StorageBindingRecord,
        credential: &aos_hub_core::db::StorageBindingCredentialRevisionRecord,
        probe_token: &str,
    ) -> Result<aos_hub_core::topology_probe::StorageCredentialProbeEvidence> {
        anyhow::ensure!(
            credential.storage_binding_id == binding.id,
            "credential probe binding identity is inconsistent"
        );
        anyhow::ensure!(
            matches!(
                credential.purpose.as_str(),
                "read" | "write" | "delete" | "list" | "presign"
            ),
            "credential probe purpose is not supported"
        );
        let secret = self
            .secrets
            .resolve(&credential.secret_version_ref)
            .await
            .context("resolving immutable credential version for probe")?;
        aos_hub_core::secret_version::verify_secret_fingerprint(
            &secret,
            &credential.credential_fingerprint,
        )?;
        let surface = S3Surface::from_binding(binding, "", Some(secret.expose_utf8()?))?
            .context("credential probe requires an external S3-compatible binding")?;
        let now = aos_hub_core::clock::now_unix_secs();
        let probe_path = format!(
            ".aos/credential-probes/{}/{}/{}",
            credential.purpose, credential.generation, probe_token
        );
        let mut statuses = serde_json::Map::new();
        let conditional_writes_supported = false;
        let valid = match credential.purpose.as_str() {
            "read" | "presign" => {
                let url = surface.object_url(S3Method::Get, &probe_path, now)?;
                let status = self.send(reqwest::Method::GET, &url).await?;
                statuses.insert("getStatus".into(), status.as_u16().into());
                status.is_success() || status == reqwest::StatusCode::NOT_FOUND
            }
            "list" => {
                let url = surface.list_url(None, 1, now)?;
                let status = self.send(reqwest::Method::GET, &url).await?;
                statuses.insert("listStatus".into(), status.as_u16().into());
                status.is_success()
            }
            "delete" => {
                let url = surface.object_url(S3Method::Delete, &probe_path, now)?;
                let status = self.send(reqwest::Method::DELETE, &url).await?;
                statuses.insert("deleteStatus".into(), status.as_u16().into());
                status.is_success()
            }
            "write" => {
                let recovery_url = surface.list_multipart_uploads_url(&probe_path, now)?;
                let recovery = self.client.get(&recovery_url).send().await?;
                let recovery_status = recovery.status();
                statuses.insert(
                    "multipartRecoveryListStatus".into(),
                    recovery_status.as_u16().into(),
                );
                anyhow::ensure!(
                    recovery_status.is_success(),
                    "multipart recovery listing was rejected"
                );
                let recovery_body = crate::fetch::read_body_capped(
                    recovery,
                    1024 * 1024,
                    "credential multipart recovery listing",
                )
                .await?;
                let recovery_xml = std::str::from_utf8(&recovery_body)
                    .context("credential multipart recovery listing is not UTF-8")?;
                let abandoned = surface.parse_exact_multipart_uploads(&probe_path, recovery_xml)?;
                statuses.insert("recoveredMultipartUploads".into(), abandoned.len().into());
                for upload_id in abandoned {
                    let abort_url = surface.multipart_url(
                        "abort",
                        &probe_path,
                        Some(&upload_id),
                        None,
                        aos_hub_core::clock::now_unix_secs(),
                    )?;
                    let abort = self.send(reqwest::Method::DELETE, &abort_url).await?;
                    anyhow::ensure!(abort.is_success(), "multipart recovery abort was rejected");
                }
                let create_url = surface.multipart_url("create", &probe_path, None, None, now)?;
                let create = self
                    .client
                    .post(&create_url)
                    .body(Vec::new())
                    .send()
                    .await?;
                let create_status = create.status();
                statuses.insert(
                    "multipartCreateStatus".into(),
                    create_status.as_u16().into(),
                );
                if create_status.is_success() {
                    let body = crate::fetch::read_body_capped(
                        create,
                        1024 * 1024,
                        "credential multipart-create probe",
                    )
                    .await?;
                    let upload_id = aos_hub_core::s3surface::parse_multipart_upload_id(
                        std::str::from_utf8(&body)
                            .context("credential multipart-create response is not UTF-8")?,
                    )?;
                    let abort_url = surface.multipart_url(
                        "abort",
                        &probe_path,
                        Some(&upload_id),
                        None,
                        aos_hub_core::clock::now_unix_secs(),
                    )?;
                    let abort = self.send(reqwest::Method::DELETE, &abort_url).await?;
                    statuses.insert("multipartAbortStatus".into(), abort.as_u16().into());
                    abort.is_success()
                } else {
                    false
                }
            }
            _ => false,
        };
        let error = (!valid).then(|| {
            format!(
                "{} capability probe was rejected by origin",
                credential.purpose
            )
        });
        Ok(
            aos_hub_core::topology_probe::StorageCredentialProbeEvidence {
                valid,
                conditional_writes_supported,
                error,
                evidence: serde_json::Value::Object(statuses),
            },
        )
    }
}

/// Native authenticated adapter for the fixed Cloudflare v4 control-plane API.
pub struct CloudflareControlPlaneClient {
    client: reqwest::Client,
    token: String,
}

impl CloudflareControlPlaneClient {
    /// Creates an adapter with a non-empty scoped API token.
    pub async fn new(token: String) -> Result<Self> {
        anyhow::ensure!(!token.trim().is_empty(), "Cloudflare API token is empty");
        Ok(Self {
            client: crate::fetch::hardened_client().await,
            token,
        })
    }
}

#[async_trait]
impl aos_hub_core::topology_probe::CloudflareControlPlaneClient for CloudflareControlPlaneClient {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        anyhow::ensure!(
            path.starts_with("/client/v4/") && !path.contains(['?', '#']),
            "invalid Cloudflare API path"
        );
        let response = self
            .client
            .get(format!("https://api.cloudflare.com{path}"))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        anyhow::ensure!(
            response.content_length().unwrap_or(0) <= 1024 * 1024,
            "Cloudflare API response exceeds 1 MiB"
        );
        let bytes = response.bytes().await?;
        anyhow::ensure!(
            bytes.len() <= 1024 * 1024,
            "Cloudflare API response exceeds 1 MiB"
        );
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod cloudflare_control_plane_tests {
    use super::*;
    use aos_hub_core::topology_probe::CloudflareControlPlaneClient as _;

    #[tokio::test]
    async fn cloudflare_api_token_is_never_rendered_in_errors() {
        let token = "super-secret-cloudflare-token";
        let client = CloudflareControlPlaneClient::new(token.to_string())
            .await
            .unwrap();
        let error = client.get("/not-a-cloudflare-api-path").await.unwrap_err();
        assert!(!format!("{error:#}").contains(token));
    }
}

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

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        self.strong_version(path)
            .await
            .map_err(native_placement_read_error)
    }

    async fn list_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<core_fetch::SurfaceListPage> {
        anyhow::ensure!(
            limit > 0 && limit <= core_fetch::MAX_SURFACE_LIST_PAGE_OBJECTS,
            "invalid filesystem listing page limit"
        );
        anyhow::ensure!(
            cursor.is_none_or(|value| value.len() <= core_fetch::MAX_SURFACE_LIST_CURSOR_BYTES),
            "filesystem listing cursor is too large"
        );
        let root = self.root().to_path_buf();
        let mut pending = vec![root.clone()];
        let mut paths = std::collections::BTreeSet::new();
        let mut has_more = false;
        let mut budget = core_fetch::SurfaceListingBudget::default();
        while let Some(directory) = pending.pop() {
            let mut entries = match tokio::fs::read_dir(&directory).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(native_placement_read_error(
                        crate::fetch::local_fs_io_error(
                            &format!("listing {}", directory.display()),
                            error,
                        ),
                    ));
                }
            };
            while let Some(entry) = entries.next_entry().await.map_err(|error| {
                native_placement_read_error(crate::fetch::local_fs_io_error(
                    &format!("listing {}", directory.display()),
                    error,
                ))
            })? {
                let entry_path = entry.path();
                let relative = entry_path
                    .strip_prefix(&root)
                    .context("listed path escaped its cache surface root")?
                    .components()
                    .map(|component| {
                        component
                            .as_os_str()
                            .to_str()
                            .context("cache surface contains a non-UTF-8 object key")
                    })
                    .collect::<Result<Vec<_>>>()?
                    .join("/");
                // Count every directory entry, not only regular files. A tree
                // containing unbounded empty directories or symlinks must fail
                // closed just like one containing too many object keys.
                budget.record(&relative)?;
                let file_type = entry.file_type().await.map_err(|error| {
                    native_placement_read_error(crate::fetch::local_fs_io_error(
                        &format!("inspecting {}", entry_path.display()),
                        error,
                    ))
                })?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                if cursor.is_some_and(|after| relative.as_str() <= after) {
                    continue;
                }
                paths.insert(relative);
                if paths.len() > limit {
                    paths.pop_last();
                    has_more = true;
                }
            }
        }
        let paths = paths.into_iter().collect::<Vec<_>>();
        let next_cursor = has_more.then(|| paths.last().cloned()).flatten();
        Ok(core_fetch::SurfaceListPage {
            paths,
            evidence: Default::default(),
            next_cursor,
        })
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

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<core_fetch::StreamedRead>> {
        self.stream_read(path, range).await
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        self.strong_version(path).await
    }

    fn describe(&self) -> String {
        crate::fetch::SurfaceFetch::describe(self)
    }
}

/// Adapts a boxed hub [`SurfaceFetch`](crate::fetch::SurfaceFetch) to the core
/// [`SurfaceFetch`](core_fetch::SurfaceFetch) port by delegation.
///
/// [`fetch_mirror_upstream`](crate::fetch::fetch_mirror_upstream) returns a
/// `Box<dyn crate::fetch::SurfaceFetch>` (the hub trait object) for a configured
/// mirror upstream. The relocated core indexer
/// ([`aos_hub_core::indexer`]) and the core service need a
/// `Box<dyn core_fetch::SurfaceFetch>`, and a trait object cannot be re-coerced
/// to a *different* trait, so this concrete wrapper holds the hub box and
/// forwards both methods. Callers that already hold a hub fetcher box bridge it
/// to the core port with [`into_core_fetch`].
pub struct CoreFetchAdapter(Box<dyn crate::fetch::SurfaceFetch>);

/// Bridge a hub [`SurfaceFetch`](crate::fetch::SurfaceFetch) box to a boxed core
/// [`SurfaceFetch`](core_fetch::SurfaceFetch) for the relocated core indexer.
///
/// The hub's surface resolvers return the hub trait object; the relocated
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

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<core_fetch::StreamedRead>> {
        self.0.fetch_stream(path, range).await
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        self.0.inventory_strong_etag(path).await
    }

    fn describe(&self) -> String {
        self.0.describe()
    }
}

/// The native [`SurfaceProvider`](core_fetch::SurfaceProvider) over Hub bindings.
///
/// Explicit placements resolve their own binding plus prefix.
pub struct HubSurfaceProvider {
    /// The hub database, used to resolve a registry's storage-binding root.
    db: Arc<Database>,
    /// The secret sealer, required to unseal an `s3`/`r2` binding's credentials.
    /// `None` on paths that never serve an object-store binding.
    credentials: Option<Arc<dyn StorageCredentialResolver>>,
    /// Shared HTTP client for proxying reads to an external `s3`/`r2` origin.
    http: reqwest::Client,
    image_snapshots: Option<Arc<crate::image_snapshot::ImageSnapshotStore>>,
    image_snapshot_indexing: bool,
}

/// A local mirror placement with a verified upstream fallback.
///
/// Delivery remains placement-planned in the shared core. The native adapter
/// adds pull-through semantics only after that planner selects the mirror's
/// local placement: local bytes win, and an upstream miss is verified and
/// persisted by the mirror implementation before it is returned.
struct PullThroughFetch {
    local: crate::fetch::LocalFsFetch,
    upstream: crate::fetch::HttpFetch,
    root: PathBuf,
    trust_keys: Vec<String>,
    verify: bool,
}

#[async_trait]
impl core_fetch::SurfaceFetch for PullThroughFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        if let Some(result) = crate::mirror::fetch_through(
            &self.local,
            &self.root,
            path,
            &self.trust_keys,
            self.verify,
        )
        .await
        .map_err(native_placement_read_error)?
        {
            return Ok(Some(result.bytes));
        }
        crate::mirror::fetch_through(
            &self.upstream,
            &self.root,
            path,
            &self.trust_keys,
            self.verify,
        )
        .await
        .map(|result| result.map(|result| result.bytes))
        .map_err(native_placement_read_error)
    }

    fn describe(&self) -> String {
        format!("pull-through mirror at {}", self.root.display())
    }
}

impl HubSurfaceProvider {
    /// Build a provider over the hub database and its hardened outbound client.
    ///
    /// The caller injects the single no-proxy, no-automatic-redirect,
    /// connect-time-validating client from [`crate::fetch::hardened_client`].
    /// This constructor deliberately has no reqwest-default fallback.
    #[must_use]
    pub fn new(
        db: Arc<Database>,
        http: reqwest::Client,
        image_snapshots: Option<Arc<crate::image_snapshot::ImageSnapshotStore>>,
    ) -> HubSurfaceProvider {
        HubSurfaceProvider {
            db,
            credentials: None,
            http,
            image_snapshots,
            image_snapshot_indexing: false,
        }
    }

    /// Attaches the Hub-private signed-image snapshot store.
    #[must_use]
    pub fn with_image_snapshots(
        mut self,
        snapshots: Arc<crate::image_snapshot::ImageSnapshotStore>,
    ) -> Self {
        self.image_snapshots = Some(snapshots);
        self
    }

    /// Configures local image reads for pre-commit index verification.
    #[must_use]
    pub fn for_image_indexing(mut self) -> Self {
        self.image_snapshot_indexing = true;
        self
    }

    /// Attach the provider-backed resolver used by private storage bindings.
    #[must_use]
    pub fn with_credentials(
        mut self,
        secrets: Arc<dyn SecretVersionResolver>,
    ) -> HubSurfaceProvider {
        self.credentials = Some(Arc::new(DatabaseStorageCredentialResolver::new(
            Arc::clone(&self.db),
            secrets,
        )));
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
                let resolved =
                    if binding.access_mode.as_deref() == Some("private") {
                        let resolver = self.credentials.as_ref().ok_or_else(|| {
                            aos_hub_core::placement_read::terminal_read_error(format!(
                                "placement '{}' requires a configured credential resolver",
                                placement.name
                            ))
                        })?;
                        Some(resolver.resolve_current(binding.id, "read").await.map_err(
                            |error| {
                                aos_hub_core::placement_read::terminal_read_error(format!(
                                    "placement '{}' read credential: {error:#}",
                                    placement.name
                                ))
                            },
                        )?)
                    } else {
                        None
                    };
                let surface = S3Surface::from_binding(
                    &binding,
                    &placement.prefix,
                    resolved
                        .as_ref()
                        .map(|credential| credential.secret())
                        .transpose()?,
                )
                .map_err(|error| {
                    aos_hub_core::placement_read::terminal_read_error(format!(
                        "placement '{}' has invalid object-store configuration: {error:#}",
                        placement.name,
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
                let root = binding
                    .local_root_path
                    .as_deref()
                    .context("local placement binding has no localRootPath")?;
                let root = PathBuf::from(root).join(&placement.prefix);
                let fetch = crate::fetch::LocalFsFetch::new(&root);
                let fetch = match &self.image_snapshots {
                    Some(store) => fetch
                        .with_image_snapshots(Arc::clone(store))
                        .with_image_snapshot_db(Arc::clone(&self.db)),
                    None => fetch,
                };
                let fetch = if self.image_snapshot_indexing {
                    fetch.with_image_snapshot_indexing()
                } else {
                    fetch
                };
                let mirror = match placement.registry_id {
                    Some(registry_id) => self.db.mirror_source(registry_id).await?,
                    None => None,
                };
                if let Some(mirror) = mirror.filter(|mirror| mirror.mode == "pullthrough") {
                    let registry = self
                        .db
                        .registry_by_id(
                            placement
                                .registry_id
                                .context("pull-through placement has no registry identity")?,
                        )
                        .await?
                        .context("pull-through placement references a missing registry")?;
                    return Ok(Box::new(PullThroughFetch {
                        local: fetch,
                        upstream: crate::fetch::HttpFetch::new(mirror.upstream_url).await,
                        root,
                        trust_keys: registry.trust_keys,
                        verify: mirror.verify,
                    }));
                }
                Ok(Box::new(fetch))
            }
            Some(BindingKind::DeploymentR2) => {
                Err(aos_hub_core::placement_read::terminal_read_error(format!(
                    "placement '{}' uses Worker-only deployment R2 storage",
                    placement.name
                )))
            }
            None => Err(aos_hub_core::placement_read::terminal_read_error(format!(
                "placement '{}' uses unknown storage binding kind '{}'",
                placement.name, binding.kind
            ))),
        }
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
    /// Provider-backed resolver for an `s3`/`r2` binding's credentials.
    credentials: Option<Arc<dyn StorageCredentialResolver>>,
    /// Shared HTTP client for proxying writes to an external `s3`/`r2` origin.
    http: reqwest::Client,
}

impl HubSurfaceWriteProvider {
    /// Build a write provider over the hub database and hardened outbound client.
    #[must_use]
    pub fn new(db: Arc<Database>, http: reqwest::Client) -> HubSurfaceWriteProvider {
        HubSurfaceWriteProvider {
            db,
            credentials: None,
            http,
        }
    }

    /// Attach the provider-backed resolver used to sign private-origin writes.
    #[must_use]
    pub fn with_credentials(
        mut self,
        secrets: Arc<dyn SecretVersionResolver>,
    ) -> HubSurfaceWriteProvider {
        self.credentials = Some(Arc::new(DatabaseStorageCredentialResolver::new(
            Arc::clone(&self.db),
            secrets,
        )));
        self
    }
}

#[async_trait]
impl core_sw::SurfaceWriteProvider for HubSurfaceWriteProvider {
    async fn placement_writer(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn core_sw::SurfaceWrite>> {
        let revision = self
            .db
            .placement_publication_write_revision(placement.id)
            .await?
            .with_context(|| {
                format!(
                    "placement '{}' has no validated publication write capability",
                    placement.name
                )
            })?;
        let binding = self
            .db
            .storage_binding(placement.storage_binding_id)
            .await?
            .with_context(|| {
                format!(
                    "placement '{}' references missing storage binding {}",
                    placement.name, placement.storage_binding_id
                )
            })?;
        match BindingKind::parse(&binding.kind) {
            Some(BindingKind::S3 | BindingKind::R2) => {
                let resolver = self
                    .credentials
                    .as_ref()
                    .context("object-store placement writes require a credential resolver")?;
                let credential = resolver
                    .resolve_exact(
                        binding.id,
                        &revision.write_credential_purpose,
                        revision.write_credential_generation,
                    )
                    .await?;
                let surface = S3Surface::from_binding(
                    &binding,
                    &placement.prefix,
                    Some(credential.secret()?),
                )?
                .context("placement object-store binding cannot be resolved")?;
                Ok(Box::new(S3Write::new(surface, self.http.clone())))
            }
            Some(BindingKind::LocalFs) => Ok(Box::new(LocalFsWrite::new(
                PathBuf::from(
                    binding
                        .local_root_path
                        .as_deref()
                        .context("local placement binding has no localRootPath")?,
                )
                .join(&placement.prefix),
            ))),
            Some(BindingKind::DeploymentR2) => bail!(
                "placement '{}' uses Worker-only deployment R2 storage",
                placement.name
            ),
            None => bail!(
                "placement '{}' uses unsupported storage binding kind '{}'",
                placement.name,
                binding.kind
            ),
        }
    }

    async fn placement_deleter(
        &self,
        placement: &SurfacePlacementRecord,
        expected_binding_resource_version: i64,
        delete_credential_generation: i64,
    ) -> Result<Box<dyn core_sw::SurfaceWrite>> {
        let binding = self
            .db
            .storage_binding(placement.storage_binding_id)
            .await?
            .with_context(|| {
                format!(
                    "placement '{}' references missing storage binding {}",
                    placement.name, placement.storage_binding_id
                )
            })?;
        if binding.resource_version != expected_binding_resource_version {
            bail!(
                "placement '{}' storage binding changed after deletion was planned",
                placement.name
            );
        }
        if !matches!(BindingKind::parse(&binding.kind), Some(BindingKind::S3)) {
            bail!(
                "placement '{}' backend '{}' cannot enforce conditional deletion",
                placement.name,
                binding.kind
            );
        }
        let resolver = self
            .credentials
            .as_ref()
            .context("object-store placement deletion requires a credential resolver")?;
        let credential = resolver
            .resolve_exact(binding.id, "delete", delete_credential_generation)
            .await?;
        let surface =
            S3Surface::from_binding(&binding, &placement.prefix, Some(credential.secret()?))?
                .context("placement object-store binding cannot be resolved")?;
        Ok(Box::new(S3Write::new(surface, self.http.clone())))
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
    #[cfg(test)]
    durability_failure: Option<&'static str>,
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
            Ok(()) => {
                sync_parent_directory(&canonical).await?;
                Ok(())
            }
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
        sync_directory(&dir).await?;
        sync_parent_directory(&dir).await?;
        sync_parent_directory(&self.root.join(".uploads")).await?;
        sync_parent_directory(&self.root).await?;
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
            etag: hex::encode(Sha256::digest(bytes)),
        })
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[core_sw::PartTag],
    ) -> Result<String> {
        let upload_id = validate_upload_id(upload_id)?;
        let dir = self.parts_dir(&upload_id);
        if tokio::fs::try_exists(self.multipart_terminal_marker(&upload_id))
            .await
            .unwrap_or(false)
        {
            return self
                .strong_version(path)
                .await?
                .context("completed filesystem object has no strong identity");
        }
        let target = crate::fetch::safe_join(&self.root, path)
            .with_context(|| format!("resolving surface path {path}"))?;
        let contained = self.contained_target(&target).await?;
        // Concatenate the staged parts in `part_number` order into a temp file,
        // then atomic-rename into place: a reader never sees a partial object,
        // and memory stays bounded to the copy buffer (no part is held whole).
        let mut ordered: Vec<&core_sw::PartTag> = parts.iter().collect();
        ordered.sort_by_key(|part| part.part_number);
        let tmp = contained.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        {
            use tokio::io::AsyncWriteExt as _;
            let out = tokio::fs::File::create(&tmp)
                .await
                .with_context(|| format!("creating {}", tmp.display()))?;
            let mut writer = tokio::io::BufWriter::new(out);
            for part in ordered {
                let part_path = dir.join(format!("part-{:08}", part.part_number));
                let bytes = tokio::fs::read(&part_path)
                    .await
                    .with_context(|| format!("reading staged part {}", part_path.display()))?;
                if hex::encode(Sha256::digest(&bytes)) != part.etag {
                    bail!(
                        "staged multipart part {} changed after admission",
                        part.part_number
                    );
                }
                writer
                    .write_all(&bytes)
                    .await
                    .with_context(|| format!("appending part {}", part.part_number))?;
            }
            writer
                .flush()
                .await
                .with_context(|| "flushing assembled object")?;
            writer
                .get_ref()
                .sync_all()
                .await
                .with_context(|| format!("syncing assembled object {}", tmp.display()))?;
        }
        self.durability_checkpoint("assembled-synced")?;
        // Persist the ambiguous-completion fence before the externally visible
        // rename. If the process dies after this point, recovery must never
        // classify a missing staging directory as "never existed" and release
        // the write ticket: the final object may already have landed.
        let terminal = self.multipart_terminal_marker(&upload_id);
        write_atomic(&terminal, b"completing\n").await?;
        self.durability_checkpoint("completion-marker-synced")?;
        tokio::fs::rename(&tmp, &contained)
            .await
            .with_context(|| format!("renaming into {}", contained.display()))?;
        sync_parent_directory(&contained).await?;
        self.durability_checkpoint("destination-synced")?;
        tokio::fs::remove_dir_all(&dir)
            .await
            .with_context(|| format!("removing completed upload staging dir {}", dir.display()))?;
        sync_parent_directory(&dir).await?;
        self.strong_version(path)
            .await?
            .context("completed filesystem object has no strong identity")
    }

    async fn abort_multipart(
        &self,
        _path: &str,
        upload_id: &str,
    ) -> Result<core_sw::MultipartAbortOutcome> {
        let upload_id = validate_upload_id(upload_id)?;
        if tokio::fs::try_exists(self.multipart_terminal_marker(&upload_id))
            .await
            .unwrap_or(false)
        {
            return Ok(core_sw::MultipartAbortOutcome::PossiblyCompleted);
        }
        let directory = self.parts_dir(&upload_id);
        match tokio::fs::remove_dir_all(&directory).await {
            Ok(()) => {
                sync_parent_directory(&directory).await?;
                Ok(core_sw::MultipartAbortOutcome::Aborted)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(core_sw::MultipartAbortOutcome::Absent)
            }
            Err(error) => Err(error).context("aborting local multipart upload"),
        }
    }

    async fn settle_multipart(&self, _path: &str, upload_id: &str) -> Result<()> {
        let upload_id = validate_upload_id(upload_id)?;
        let marker = self.multipart_terminal_marker(&upload_id);
        match tokio::fs::remove_file(&marker).await {
            Ok(()) => {
                sync_parent_directory(&marker).await?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing settled multipart terminal marker"),
        }
    }
}

impl LocalFsWrite {
    async fn strong_version(&self, path: &str) -> Result<Option<String>> {
        if let Some(digest) = crate::fetch::LocalFsFetch::image_digest(path) {
            return Ok(Some(format!("\"snapshot-sha256-{digest}\"")));
        }
        crate::fetch::LocalFsFetch::new(&self.root)
            .strong_version(path)
            .await
    }

    fn new(root: PathBuf) -> Self {
        Self {
            root,
            #[cfg(test)]
            durability_failure: None,
        }
    }

    #[cfg(test)]
    fn with_durability_failure(mut self, checkpoint: &'static str) -> Self {
        self.durability_failure = Some(checkpoint);
        self
    }

    fn durability_checkpoint(&self, checkpoint: &'static str) -> Result<()> {
        #[cfg(test)]
        if self.durability_failure == Some(checkpoint) {
            bail!("injected durability failure at {checkpoint}");
        }
        let _ = checkpoint;
        Ok(())
    }

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
        sync_directory(parent).await?;
        sync_parent_directory(parent).await?;
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

    /// Returns the durable ambiguity marker for a multipart completion.
    ///
    /// The marker lives outside the parts directory because completion removes
    /// that directory. It is retained only until the durable write ticket
    /// settles; the settlement callback then removes it.
    fn multipart_terminal_marker(&self, upload_id: &str) -> PathBuf {
        self.root
            .join(".uploads")
            .join(format!("{upload_id}.terminal"))
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
        sync_directory(parent).await?;
        sync_parent_directory(parent).await?;
    }
    let tmp = target.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    use tokio::io::AsyncWriteExt as _;
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(bytes)
        .await
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.flush()
        .await
        .with_context(|| format!("flushing {}", tmp.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("syncing {}", tmp.display()))?;
    drop(file);
    tokio::fs::rename(&tmp, target)
        .await
        .with_context(|| format!("renaming into {}", target.display()))?;
    sync_parent_directory(target).await?;
    Ok(())
}

/// Persists directory-entry changes in `path`.
async fn sync_directory(path: &Path) -> Result<()> {
    let directory = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("opening directory {} for sync", path.display()))?;
    directory
        .sync_all()
        .await
        .with_context(|| format!("syncing directory {}", path.display()))
}

/// Persists the directory entry that names `path`.
async fn sync_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent).await?;
    }
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
        crate::fetch::is_safe_remote_url(url).with_context(|| format!("POST {url}"))?;
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
        crate::fetch::is_safe_remote_url(url).with_context(|| format!("GET {url}"))?;
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

    async fn probe_https(&self, url: &str) -> Result<Vec<u8>> {
        crate::fetch::is_safe_remote_url(url).with_context(|| format!("probe {url}"))?;
        let parsed = url::Url::parse(url).with_context(|| format!("probe {url}"))?;
        if parsed.scheme() != "https" {
            bail!("domain TLS probes require https");
        }
        // Any HTTP status is acceptable: reaching it proves the TLS stack
        // validated the certificate chain, current validity, and hostname.
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("TLS probe {url}"))?
            .error_for_status()
            .with_context(|| format!("TLS probe {url}"))?;
        crate::fetch::read_body_capped(response, MAX_OIDC_BODY_BYTES, "domain TLS proof").await
    }
}

/// The native [`Reindexer`](core_reindex::Reindexer): re-indexes a managed
/// registry inline from its local surface and records an `index` audit row.
///
/// Resolves a deterministic reconciled read placement and indexes from a
/// [`LocalFsFetch`](crate::fetch::LocalFsFetch) over it through
/// [`crate::indexer::index_and_record`], then records a `system`-actor `index`
/// audit row cross-referencing the resulting commit. This is the relocated,
/// byte-identical behavior of the hub's prior facade `reindex`, so a managed
/// publish becomes browse-visible the instant its completing pointer write
/// returns.
pub struct HubReindexer {
    /// The hub database the indexer reads/writes and the audit row lands in.
    db: Arc<Database>,
    image_snapshots: Option<Arc<crate::image_snapshot::ImageSnapshotStore>>,
    surfaces: Option<Arc<dyn core_fetch::SurfaceProvider>>,
}

impl HubReindexer {
    /// Build the reindexer over the hub database.
    #[must_use]
    pub fn new(
        db: Arc<Database>,
        image_snapshots: Option<Arc<crate::image_snapshot::ImageSnapshotStore>>,
    ) -> HubReindexer {
        HubReindexer {
            db,
            image_snapshots,
            surfaces: None,
        }
    }

    /// Attaches the configured multi-binding provider used by the serving runtime.
    #[must_use]
    pub fn with_surface_provider(mut self, surfaces: Arc<dyn core_fetch::SurfaceProvider>) -> Self {
        self.surfaces = Some(surfaces);
        self
    }
}

#[async_trait]
impl core_reindex::Reindexer for HubReindexer {
    async fn reindex(&self, registry: &RegistryRecord) -> Result<Option<String>> {
        let placement = self
            .db
            .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await
            .with_context(|| {
                format!(
                    "registry '{}' has no reconciled read placement to re-index from",
                    registry.slug
                )
            })?;
        if let Some(surfaces) = &self.surfaces {
            let fetch = surfaces.placement_fetcher(&placement).await?;
            let outcome = crate::indexer::index_and_record_from_placement(
                &self.db,
                fetch.as_ref(),
                registry,
                Some(placement.id),
            )
            .await?;
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
            return Ok(Some(outcome.commit));
        }
        let binding = self
            .db
            .storage_binding(placement.storage_binding_id)
            .await?
            .context("reindex placement references a missing storage binding")?;
        if BindingKind::parse(&binding.kind) != Some(BindingKind::LocalFs) {
            bail!("native inline reindex requires a local-fs read placement");
        }
        let root = PathBuf::from(
            binding
                .local_root_path
                .context("local reindex binding has no localRootPath")?,
        )
        .join(placement.prefix);
        let fetch = crate::fetch::LocalFsFetch::new(&root);
        let fetch = match &self.image_snapshots {
            Some(store) => fetch
                .with_image_snapshots(Arc::clone(store))
                .with_image_snapshot_db(Arc::clone(&self.db))
                .with_image_snapshot_indexing(),
            None => fetch,
        };
        let outcome = crate::indexer::index_and_record_from_placement(
            &self.db,
            &fetch,
            registry,
            Some(placement.id),
        )
        .await?;
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
            strong_etag: None,
            snapshot_lease_id: None,
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

const MAX_S3_REDIRECTS: usize = 5;

fn url_origin(url: &url::Url) -> (String, Option<String>, Option<u16>) {
    (
        url.scheme().to_string(),
        url.host_str().map(str::to_string),
        url.port_or_known_default(),
    )
}

/// Sends one presigned S3 request over the injected hardened client.
///
/// Automatic redirects are disabled in that client. This loop validates every
/// hop immediately before connecting and never lets presigned authorization
/// cross an origin boundary. Mutating requests do not redirect at all because
/// replaying their body could duplicate a side effect.
async fn send_s3_request(
    http: &reqwest::Client,
    method: reqwest::Method,
    raw_url: &str,
    body: Option<Vec<u8>>,
    range: Option<&str>,
    if_match: Option<&str>,
) -> Result<reqwest::Response> {
    let mut current = url::Url::parse(raw_url).context("invalid presigned S3 URL")?;
    let authenticated_origin = url_origin(&current);
    let mut redirects = 0_usize;
    loop {
        crate::fetch::is_safe_remote_url(current.as_str())?;
        let mut request = http.request(method.clone(), current.clone());
        if let Some(value) = range {
            request = request.header(reqwest::header::RANGE, value);
        }
        if let Some(value) = if_match {
            request = request.header(reqwest::header::IF_MATCH, value);
        }
        if let Some(bytes) = body.as_ref() {
            request = request.body(bytes.clone());
        }
        let response = request.send().await.context("S3 transport failed")?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        anyhow::ensure!(
            matches!(method, reqwest::Method::GET | reqwest::Method::HEAD) && body.is_none(),
            "S3 redirect refused for a mutating request"
        );
        anyhow::ensure!(redirects < MAX_S3_REDIRECTS, "S3 redirect limit exceeded");
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .context("S3 redirect omitted Location")?
            .to_str()
            .context("S3 redirect Location is not text")?;
        let next = current
            .join(location)
            .context("invalid S3 redirect Location")?;
        crate::fetch::is_safe_remote_url(next.as_str())?;
        let next_origin = url_origin(&next);
        anyhow::ensure!(
            next_origin == authenticated_origin,
            "presigned S3 redirect changed origin"
        );
        current = next;
        redirects += 1;
    }
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
        let resp = send_s3_request(&self.http, reqwest::Method::GET, &url, None, None, None)
            .await
            .map_err(|error| {
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
        let bytes = crate::fetch::read_body_capped(
            resp,
            aos_hub_core::s3surface::MAX_S3_BUFFERED_OBJECT_BYTES,
            "reading S3 object body",
        )
        .await
        .map_err(|error| {
            aos_hub_core::placement_read::retryable_read_error(format!(
                "reading s3 object body: {error}"
            ))
        })?;
        Ok(Some(bytes))
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
        let range = range.map(|(start, end)| {
            if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            }
        });
        let resp = send_s3_request(
            &self.http,
            reqwest::Method::GET,
            &url,
            None,
            range.as_deref(),
            None,
        )
        .await
        .map_err(|error| {
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
        let strong_etag = resp
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .map(str::to_string)
            .filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok());
        Ok(Some(core_fetch::StreamedRead {
            body: axum::body::Body::from_stream(resp.bytes_stream()),
            total,
            range: served,
            strong_etag,
            snapshot_lease_id: None,
        }))
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        let url =
            self.surface
                .object_url(S3Method::Head, path, aos_hub_core::clock::now_unix_secs())?;
        let resp = send_s3_request(&self.http, reqwest::Method::HEAD, &url, None, None, None)
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

    async fn list_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<core_fetch::SurfaceListPage> {
        anyhow::ensure!(
            limit > 0 && limit <= core_fetch::MAX_SURFACE_LIST_PAGE_OBJECTS,
            "invalid S3 listing page limit"
        );
        anyhow::ensure!(
            cursor.is_none_or(|value| value.len() <= core_fetch::MAX_SURFACE_LIST_CURSOR_BYTES),
            "S3 listing cursor is too large"
        );
        let url = self
            .surface
            .list_url(cursor, limit, aos_hub_core::clock::now_unix_secs())?;
        let response = send_s3_request(&self.http, reqwest::Method::GET, &url, None, None, None)
            .await
            .with_context(|| format!("s3 list {}", self.surface.describe()))?;
        if !response.status().is_success() {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 list {}", self.surface.describe()),
                response.status().as_u16(),
            ));
        }
        let body = crate::fetch::read_text_capped(
            response,
            aos_hub_core::s3surface::MAX_S3_LIST_PAGE_BYTES,
            "reading S3 ListObjectsV2 page",
        )
        .await
        .with_context(|| format!("reading s3 list {}", self.surface.describe()))?;
        let (keys, next, truncated) = aos_hub_core::s3surface::parse_list_objects_v2(&body)?;
        let mut paths = Vec::new();
        for key in keys {
            if let Some(relative) = self.surface.relative_from_key(&key) {
                if !relative.is_empty() {
                    paths.push(relative);
                    anyhow::ensure!(
                        paths.len() <= limit,
                        "S3 listing page exceeds the requested key limit"
                    );
                }
            }
        }
        paths.sort();
        paths.dedup();
        let next_cursor = if truncated {
            Some(next.context("truncated S3 inventory page has no continuation token")?)
        } else {
            None
        };
        Ok(core_fetch::SurfaceListPage {
            paths,
            evidence: Default::default(),
            next_cursor,
        })
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        let url =
            self.surface
                .object_url(S3Method::Head, path, aos_hub_core::clock::now_unix_secs())?;
        let response = send_s3_request(&self.http, reqwest::Method::HEAD, &url, None, None, None)
            .await
            .with_context(|| format!("s3 inventory HEAD {path}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 inventory HEAD {path}"),
                response.status().as_u16(),
            ));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .map(str::to_string);
        Ok(etag.filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok()))
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
        let resp = send_s3_request(
            &self.http,
            reqwest::Method::PUT,
            &url,
            Some(bytes.to_vec()),
            None,
            None,
        )
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
        let resp = send_s3_request(&self.http, reqwest::Method::DELETE, &url, None, None, None)
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

    async fn delete_if_matches(
        &self,
        path: &str,
        expected: &core_sw::SurfaceDeletePrecondition,
    ) -> Result<core_sw::SurfaceDeleteOutcome> {
        let etag = expected
            .etag
            .as_deref()
            .filter(|etag| !etag.is_empty())
            .context("s3 identity-checked deletion requires a strong ETag")?;
        let etag = core_sw::strong_if_match_etag(etag)?;
        let url = self.surface.object_url(
            S3Method::Delete,
            path,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let response = send_s3_request(
            &self.http,
            reqwest::Method::DELETE,
            &url,
            None,
            None,
            Some(&etag),
        )
        .await
        .with_context(|| format!("s3 conditional DELETE {path}"))?;
        match response.status() {
            status if status.is_success() => Ok(core_sw::SurfaceDeleteOutcome::Deleted {
                etag: expected.etag.clone(),
                content_hash: expected.content_hash.clone(),
                size: expected.size,
            }),
            reqwest::StatusCode::NOT_FOUND => Ok(core_sw::SurfaceDeleteOutcome::NotFound),
            reqwest::StatusCode::PRECONDITION_FAILED => {
                Ok(core_sw::SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "backend object identity changed after inventory".to_string(),
                })
            }
            status => bail!("s3 conditional DELETE {path}: status {status}"),
        }
    }

    async fn create_multipart(&self, path: &str) -> Result<String> {
        let url = self.surface.multipart_url(
            "create",
            path,
            None,
            None,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let response = send_s3_request(
            &self.http,
            reqwest::Method::POST,
            &url,
            Some(Vec::new()),
            None,
            None,
        )
        .await
        .with_context(|| format!("s3 create multipart {path}"))?;
        anyhow::ensure!(
            response.status().is_success(),
            "s3 create multipart failed: {}",
            response.status()
        );
        let body =
            crate::fetch::read_text_capped(response, 1024 * 1024, "S3 create multipart response")
                .await?;
        aos_hub_core::s3surface::parse_multipart_upload_id(&body)
    }

    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<core_sw::PartTag> {
        let url = self.surface.multipart_url(
            "part",
            path,
            Some(upload_id),
            Some(part_number),
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let response = send_s3_request(
            &self.http,
            reqwest::Method::PUT,
            &url,
            Some(bytes.to_vec()),
            None,
            None,
        )
        .await
        .with_context(|| format!("s3 upload part {part_number} for {path}"))?;
        anyhow::ensure!(
            response.status().is_success(),
            "s3 upload part failed: {}",
            response.status()
        );
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .context("S3 upload-part response omitted ETag")?
            .to_str()
            .context("S3 upload-part ETag is not text")?
            .to_string();
        Ok(core_sw::PartTag { part_number, etag })
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[core_sw::PartTag],
    ) -> Result<String> {
        let url = self.surface.multipart_url(
            "complete",
            path,
            Some(upload_id),
            None,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let body = aos_hub_core::s3surface::complete_multipart_xml(parts)?.into_bytes();
        let response = send_s3_request(
            &self.http,
            reqwest::Method::POST,
            &url,
            Some(body),
            None,
            None,
        )
        .await
        .with_context(|| format!("s3 complete multipart {path}"))?;
        anyhow::ensure!(
            response.status().is_success(),
            "s3 complete multipart failed: {}",
            response.status()
        );
        let body =
            crate::fetch::read_text_capped(response, 1024 * 1024, "S3 complete multipart response")
                .await?;
        aos_hub_core::s3surface::complete_multipart_etag(&body)
    }

    async fn abort_multipart(
        &self,
        path: &str,
        upload_id: &str,
    ) -> Result<core_sw::MultipartAbortOutcome> {
        let url = self.surface.multipart_url(
            "abort",
            path,
            Some(upload_id),
            None,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let response = send_s3_request(&self.http, reqwest::Method::DELETE, &url, None, None, None)
            .await
            .with_context(|| format!("s3 abort multipart {path}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(core_sw::MultipartAbortOutcome::Absent);
        }
        anyhow::ensure!(
            response.status().is_success(),
            "s3 abort multipart failed: {}",
            response.status()
        );
        Ok(core_sw::MultipartAbortOutcome::Aborted)
    }
}

/// Parse a `Content-Range: bytes START-END/TOTAL` value into `(start, end, total)`.
///
/// Returns `None` for an unsatisfiable (`bytes */TOTAL`) or malformed value.
pub(crate) fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
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
    fn s3_presigned_redirect_origin_is_exact() {
        let original = url::Url::parse("https://s3.example:443/bucket/key?signature=one").unwrap();
        let same = url::Url::parse("https://s3.example/bucket/other?signature=two").unwrap();
        let changed_host = url::Url::parse("https://other.example/bucket/key").unwrap();
        let changed_scheme = url::Url::parse("http://s3.example/bucket/key").unwrap();
        assert_eq!(url_origin(&original), url_origin(&same));
        assert_ne!(url_origin(&original), url_origin(&changed_host));
        assert_ne!(url_origin(&original), url_origin(&changed_scheme));
    }

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
        let w = LocalFsWrite::new(dir.path().to_path_buf());
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
        assert_eq!(
            w.abort_multipart(path, &upload_id).await.unwrap(),
            core_sw::MultipartAbortOutcome::PossiblyCompleted
        );
        w.settle_multipart(path, &upload_id).await.unwrap();
        assert_eq!(
            w.abort_multipart(path, &upload_id).await.unwrap(),
            core_sw::MultipartAbortOutcome::Absent
        );
    }

    #[tokio::test]
    async fn local_fs_multipart_rejects_non_uuid_upload_id() {
        let dir = tempfile::tempdir().unwrap();
        let w = LocalFsWrite::new(dir.path().to_path_buf());
        // A non-UUID upload id (path-injection attempt) is rejected, not joined.
        assert!(w.upload_part("nar/x", "../escape", 1, b"x").await.is_err());
        assert!(w.abort_multipart("nar/x", "../escape").await.is_err());
    }

    #[tokio::test]
    async fn local_fs_multipart_abort_distinguishes_confirmed_absence() {
        let dir = tempfile::tempdir().unwrap();
        let w = LocalFsWrite::new(dir.path().to_path_buf());
        let upload_id = w.create_multipart("nar/x").await.unwrap();
        assert_eq!(
            w.abort_multipart("nar/x", &upload_id).await.unwrap(),
            core_sw::MultipartAbortOutcome::Aborted
        );
        assert_eq!(
            w.abort_multipart("nar/x", &upload_id).await.unwrap(),
            core_sw::MultipartAbortOutcome::Absent
        );
    }

    #[tokio::test]
    async fn local_fs_completion_marker_is_durable_before_visible_rename() {
        let dir = tempfile::tempdir().unwrap();
        let w = LocalFsWrite::new(dir.path().to_path_buf())
            .with_durability_failure("completion-marker-synced");
        let path = "nar/durable-before-rename.nar";
        let upload_id = w.create_multipart(path).await.unwrap();
        let part = w
            .upload_part(path, &upload_id, 1, b"payload")
            .await
            .unwrap();

        assert!(w
            .complete_multipart(path, &upload_id, &[part])
            .await
            .is_err());
        assert!(!dir.path().join(path).exists());
        assert!(w.multipart_terminal_marker(&upload_id).exists());
        assert_eq!(
            w.abort_multipart(path, &upload_id).await.unwrap(),
            core_sw::MultipartAbortOutcome::PossiblyCompleted
        );
    }

    #[tokio::test]
    async fn local_fs_visible_rename_is_synced_before_staging_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let w = LocalFsWrite::new(dir.path().to_path_buf())
            .with_durability_failure("destination-synced");
        let path = "nar/durable-after-rename.nar";
        let upload_id = w.create_multipart(path).await.unwrap();
        let part = w
            .upload_part(path, &upload_id, 1, b"payload")
            .await
            .unwrap();

        assert!(w
            .complete_multipart(path, &upload_id, &[part])
            .await
            .is_err());
        assert_eq!(
            tokio::fs::read(dir.path().join(path)).await.unwrap(),
            b"payload"
        );
        assert!(w.multipart_terminal_marker(&upload_id).exists());
        assert!(w.parts_dir(&upload_id).exists());
    }
}
