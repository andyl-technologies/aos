//! The transport-free registry-hub service layer (RFC-0004 Phase 5).
//!
//! [`RpcService`] holds the `aos.hub.v1` method bodies once, decoupled
//! from any HTTP framework or wire protocol. Both deployment targets call it:
//!
//! - the **native hub** mounts it behind `axum` (served via `axum::serve`);
//! - the **Cloudflare Worker** mounts the *same* handlers via
//!   `axum-cloudflare-adapter`.
//!
//! Because the `connectrpc` server runtime cannot target `wasm32`, the hub does
//! not run it; instead these methods are served as **Connect-JSON** — plain
//! JSON over HTTP, `POST /aos.hub.v1.{Service}/{Method}` — by a thin `axum`
//! layer (see the worker/native shells). The method bodies here are wholly
//! transport-agnostic: each takes the caller's raw `Authorization` header (so
//! the JWT is verified once, here, against [`JwtKeys`]) plus a request struct
//! from [`aos_proto_types`], and returns a response struct or an [`RpcError`].
//!
//! # Error model
//!
//! [`RpcError`] carries a Connect error code; the transport maps it to the
//! Connect-JSON envelope `{ "code": …, "message": … }` and the matching HTTP
//! status (see [`RpcError::code`] / [`RpcError::http_status`]).
//!
//! ```text
//! POST /aos.hub.v1.RegistryService/GetRegistry
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", "index_state": "fresh", … } }
//!   -> 404 { "code": "not_found", "message": "registry not found" }
//! ```

use std::sync::Arc;

use anyhow::Context as _;
use aos_proto_types as pb;
use aos_registry_surface::object::Oid;

use crate::auth::jwt::{Claims, JwtKeys};
use crate::binding::{BindingKind, RuntimeKind};
use crate::clock;
use crate::db::{Database, FrontendRecord, IndexStatus, RegistryRecord, SurfaceTarget};
use crate::domain::iam::{self, claims_principal, token_allows};
use crate::domain::{Permission, PrincipalKind, Role, Scope};
use crate::fetch::SurfaceProvider;
use crate::keymap;
use crate::lease::PublishLease;
use crate::placement_read::{self, PlacementReadOutcome};
use crate::ratelimit::{RateClass, RateDecision, RateLimiter, MAX_ORGS_PER_OWNER};
use crate::reindex::Reindexer;
use crate::surface_write::SurfaceWriteProvider;

/// Default page size when a list request leaves `page_size` at zero.
const DEFAULT_PAGE_SIZE: u32 = 500;
/// Hard ceiling on page size.
const MAX_PAGE_SIZE: u32 = 1000;

/// Default lifetime, in seconds, of a minted upload credential (1 hour).
///
/// A `MintUploadCredentials` token is a short-lived provisioning secret scoped
/// to one registry; it lives only long enough for a producer to drive a publish.
pub const UPLOAD_CREDENTIAL_TTL_SECS: i64 = 3600;

/// A registry-hub method failure, tagged with a Connect error code.
///
/// Mirrors the subset of `connectrpc::ErrorCode` the hub uses. The transport
/// renders it as the Connect-JSON error envelope plus an HTTP status. The
/// [`RpcError::Internal`] variant carries no public detail — the underlying
/// error is logged at construction (see [`RpcError::internal`]) and the wire
/// message is the generic `"internal error"`, so a database error never leaks
/// its internals to a caller.
#[derive(Debug)]
pub enum RpcError {
    /// An unexpected server-side failure; detail already logged, not exposed.
    Internal,
    /// The request was malformed (bad argument, bad page token, …).
    InvalidArgument(String),
    /// The addressed resource does not exist (or is hidden from the caller).
    NotFound(String),
    /// The caller is authenticated but lacks the required permission.
    PermissionDenied(String),
    /// The caller presented no, or an invalid, credential.
    Unauthenticated(String),
    /// The resource already exists (unique-constraint conflict).
    AlreadyExists(String),
    /// A precondition on system state was not met.
    FailedPrecondition(String),
    /// The caller exceeded a rate limit or quota.
    ResourceExhausted(String),
}

impl RpcError {
    /// Build an [`RpcError::Internal`], logging `err` for operators.
    ///
    /// The returned error exposes only `"internal error"` on the wire; the full
    /// chain is written to the `tracing` log so the detail is recoverable
    /// server-side without leaking to the caller.
    #[must_use]
    pub fn internal(err: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{err:#}"), "rpc failed");
        RpcError::Internal
    }

    /// Build a [`RpcError::NotFound`] reading `"{what} not found"`.
    #[must_use]
    pub fn not_found(what: &str) -> Self {
        RpcError::NotFound(format!("{what} not found"))
    }

    /// Build a [`RpcError::InvalidArgument`] from any message.
    #[must_use]
    pub fn invalid(msg: impl Into<String>) -> Self {
        RpcError::InvalidArgument(msg.into())
    }

    /// The Connect error code string (e.g. `"not_found"`) for the wire envelope.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            RpcError::Internal => "internal",
            RpcError::InvalidArgument(_) => "invalid_argument",
            RpcError::NotFound(_) => "not_found",
            RpcError::PermissionDenied(_) => "permission_denied",
            RpcError::Unauthenticated(_) => "unauthenticated",
            RpcError::AlreadyExists(_) => "already_exists",
            RpcError::FailedPrecondition(_) => "failed_precondition",
            RpcError::ResourceExhausted(_) => "resource_exhausted",
        }
    }

    /// The human-readable message for the wire envelope.
    ///
    /// [`RpcError::Internal`] returns the generic `"internal error"`; all other
    /// variants return their carried message.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            RpcError::Internal => "internal error",
            RpcError::InvalidArgument(m)
            | RpcError::NotFound(m)
            | RpcError::PermissionDenied(m)
            | RpcError::Unauthenticated(m)
            | RpcError::AlreadyExists(m)
            | RpcError::FailedPrecondition(m)
            | RpcError::ResourceExhausted(m) => m,
        }
    }

    /// The HTTP status the Connect protocol maps this code to.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            RpcError::Internal => 500,
            RpcError::InvalidArgument(_) => 400,
            RpcError::NotFound(_) => 404,
            RpcError::PermissionDenied(_) => 403,
            RpcError::Unauthenticated(_) => 401,
            RpcError::AlreadyExists(_) => 409,
            RpcError::FailedPrecondition(_) => 412,
            RpcError::ResourceExhausted(_) => 429,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for RpcError {}

/// Slice one page out of `items` using an opaque numeric offset token.
///
/// Returns the page plus the `next_page_token` (empty once exhausted). The
/// token is the decimal offset of the next item; an unparseable non-empty token
/// is rejected.
///
/// # Errors
///
/// Returns [`RpcError::InvalidArgument`] when `token` is non-empty and does not
/// parse as an offset.
fn paginate<T>(items: Vec<T>, page_size: u32, token: &str) -> Result<(Vec<T>, String), RpcError> {
    let offset: usize = if token.is_empty() {
        0
    } else {
        token
            .parse()
            .map_err(|_| RpcError::invalid("invalid page_token"))?
    };
    let size = match page_size {
        0 => DEFAULT_PAGE_SIZE,
        n => n.min(MAX_PAGE_SIZE),
    } as usize;
    let end = offset.saturating_add(size).min(items.len());
    let next = if end < items.len() {
        end.to_string()
    } else {
        String::new()
    };
    let page = items
        .into_iter()
        .skip(offset)
        .take(end.saturating_sub(offset))
        .collect();
    Ok((page, next))
}

/// Project a [`ChannelSummary`](crate::db::ChannelSummary) onto the wire
/// [`pb::Channel`], dropping empty partition buckets and tagging each present
/// bucket with its index.
fn channel_message(channel: crate::db::ChannelSummary) -> pb::Channel {
    pb::Channel {
        name: channel.name,
        frontier: channel.frontier.unwrap_or_default(),
        partitions: channel
            .partitions
            .iter()
            .enumerate()
            .filter_map(|(bucket, release)| {
                release.as_ref().map(|release| pb::Partition {
                    bucket: bucket as u32,
                    release: release.clone(),
                })
            })
            .collect(),
    }
}

/// The store-hash component of a store path or reference entry.
///
/// `"/nix/store/abc123-foo-1.0"` and `"abc123-foo-1.0"` both yield `"abc123"`.
fn narinfo_store_hash(entry: &str) -> String {
    let base = entry.rsplit('/').next().unwrap_or(entry);
    base.split('-').next().unwrap_or(base).to_string()
}

/// Parse a `.narinfo` body into a [`crate::db::CacheObject`] index row.
///
/// `store_hash` is the primary key carried by the upload path (`<hash>.narinfo`);
/// the rest is read from the body. Returns `None` when the required `StorePath`
/// or `URL` field is absent (a malformed narinfo is not indexed, but its bytes
/// still land on the surface — the surface is the source of truth, the index is
/// rebuildable). Pure string parsing, so it runs on the wasm Worker too.
///
/// Shared with [`crate::cache_scan`], which re-derives the whole index by
/// parsing every narinfo it lists off the surface.
pub(crate) fn parse_cache_narinfo(
    cache_id: i64,
    store_hash: &str,
    text: &str,
    uploaded_at: i64,
) -> Option<crate::db::CacheObject> {
    let mut store_path: Option<String> = None;
    let mut nar_url: Option<String> = None;
    let mut nar_hash = String::new();
    let mut nar_size = 0i64;
    let mut file_hash = String::new();
    let mut file_size = 0i64;
    let mut compression = "none".to_string();
    let mut deriver: Option<String> = None;
    let mut refs: Vec<String> = Vec::new();
    let mut sig: Option<String> = None;
    let mut ca: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "StorePath" => store_path = Some(value.to_string()),
            "URL" => nar_url = Some(value.to_string()),
            "NarHash" => nar_hash = value.to_string(),
            "NarSize" => nar_size = value.parse().unwrap_or(0),
            "FileHash" => file_hash = value.to_string(),
            "FileSize" => file_size = value.parse().unwrap_or(0),
            "Compression" if !value.is_empty() => compression = value.to_string(),
            "Deriver" if !value.is_empty() && value != "unknown-deriver" => {
                deriver = Some(value.to_string());
            }
            "References" => {
                refs = value.split_whitespace().map(narinfo_store_hash).collect();
            }
            // narinfo may carry multiple `Sig:` lines; keep them all (newline-joined).
            "Sig" => {
                sig = Some(match sig.take() {
                    Some(prev) => format!("{prev}\n{value}"),
                    None => value.to_string(),
                });
            }
            "CA" if !value.is_empty() => ca = Some(value.to_string()),
            _ => {}
        }
    }
    let store_path = store_path?;
    Some(crate::db::CacheObject {
        cache_id,
        store_hash: store_hash.to_string(),
        store_name: store_path
            .rsplit('/')
            .next()
            .unwrap_or(&store_path)
            .to_string(),
        nar_url: nar_url?,
        nar_hash,
        nar_size,
        file_hash,
        file_size,
        compression,
        deriver,
        refs,
        sig,
        ca,
        uploaded_at,
        last_accessed_at: None,
    })
}

/// Render a `nix-cache-info` body for a managed cache.
///
/// The three-line file a Nix substituter reads to learn the store directory,
/// whether it answers mass `?path-info` queries, and its substituter priority.
fn render_nix_cache_info(want_mass_query: bool, priority: i64) -> String {
    format!(
        "StoreDir: /nix/store\nWantMassQuery: {}\nPriority: {}\n",
        u8::from(want_mass_query),
        priority,
    )
}

/// Parse a `Range: bytes=START-END` header into an inclusive `(start, end)`.
///
/// Only a single `bytes=` range is supported (the substituter case). An
/// open-ended `bytes=START-` yields `(start, u64::MAX)`, which the streaming
/// fetcher clamps to the object's last byte. Returns `None` for an absent,
/// malformed, multi-range, or suffix (`bytes=-N`) header — the caller then
/// serves the whole object.
fn parse_byte_range(header: Option<&str>) -> Option<(u64, u64)> {
    let spec = header?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = end.trim();
    let end: u64 = if end.is_empty() {
        u64::MAX
    } else {
        end.parse().ok()?
    };
    (start <= end).then_some((start, end))
}

/// Rank a visibility string for ordering comparisons: `public` (2) is the most
/// visible, then `internal` (1), then `private` (0). An unknown value ranks as
/// the most restrictive (`0`) so a typo never widens exposure.
fn visibility_rank(visibility: &str) -> u8 {
    match visibility {
        "public" => 2,
        "internal" => 1,
        _ => 0,
    }
}

/// The verdict of checking a proposed cache⇄registry link against the
/// visibility policy.
///
/// Returned by [`assess_cache_link`], the single chokepoint both the
/// `LinkCache` RPC and the web console route through, so the policy is enforced
/// identically regardless of entry point.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LinkAdvisory {
    /// A blocking rejection reason, or `None` if the link is permitted.
    ///
    /// Set when *advertising* a cache **less** visible than the registry: the
    /// registry's consumers would be handed a substituter URL they cannot read
    /// (e.g. a private cache advertised on a public registry → anonymous
    /// consumers get a 403). Such a link is refused.
    pub reject: Option<String>,
    /// A non-blocking warning the operator should see, or `None`.
    ///
    /// Set when *rooting* a **less**-visible registry's packages into a **more**-
    /// visible cache (e.g. a private registry's closures pinned into a public
    /// cache): the link is allowed — an operator may intend a public mirror —
    /// but it publishes that registry's build outputs more widely than the
    /// registry's own metadata, which is a content-exposure foot-gun.
    pub warning: Option<String>,
}

/// Assess a proposed cache⇄registry link against the visibility policy.
///
/// Visibility ranks `public > internal > private` ([`visibility_rank`]). The
/// rules, in terms of "who can read what":
///
/// - A registry's consumers must be able to read any cache it **advertises** —
///   so advertising a cache *less* visible than the registry is rejected
///   ([`LinkAdvisory::reject`]).
/// - A cache holding a registry's **package closures** is at least as readable
///   as the cache itself — so rooting a *less*-visible registry into a *more*-
///   visible cache is warned ([`LinkAdvisory::warning`]), since it widens who
///   can fetch those closures.
///
/// The two pull in opposite directions; the calm configuration is a cache whose
/// visibility equals the registry's.
#[must_use]
pub fn assess_cache_link(
    cache_slug: &str,
    cache_visibility: &str,
    registry_slug: &str,
    registry_visibility: &str,
    advertised: bool,
    roots_packages: bool,
) -> LinkAdvisory {
    let reg_rank = visibility_rank(registry_visibility);
    let cache_rank = visibility_rank(cache_visibility);
    let reject = (advertised && cache_rank < reg_rank).then(|| {
        format!(
            "cannot advertise cache '{cache_slug}' ({cache_visibility}) on the more-visible \
             registry '{registry_slug}' ({registry_visibility}): its consumers could not read \
             the cache"
        )
    });
    let warning = (roots_packages && reg_rank < cache_rank).then(|| {
        format!(
            "rooting the less-visible registry '{registry_slug}' ({registry_visibility}) into the \
             more-visible cache '{cache_slug}' ({cache_visibility}) exposes that registry's \
             package closures more widely than its metadata"
        )
    });
    LinkAdvisory { reject, warning }
}

/// Project a [`CacheObject`](crate::db::CacheObject) onto the wire [`pb::CacheObject`].
fn cache_object_message(o: crate::db::CacheObject) -> pb::CacheObject {
    pb::CacheObject {
        store_hash: o.store_hash,
        store_name: o.store_name,
        nar_url: o.nar_url,
        nar_hash: o.nar_hash,
        nar_size: o.nar_size,
        file_hash: o.file_hash,
        file_size: o.file_size,
        compression: o.compression,
        deriver: o.deriver.unwrap_or_default(),
        refs: o.refs,
        sig: o.sig.unwrap_or_default(),
        ca: o.ca.unwrap_or_default(),
        uploaded_at: o.uploaded_at,
    }
}

/// Project an [`OrgRecord`](crate::db::OrgRecord) onto the wire [`pb::Org`].
fn org_message(org: &crate::db::OrgRecord) -> pb::Org {
    pb::Org {
        slug: org.slug.clone(),
        name: org.name.clone(),
        created_at: org.created_at,
    }
}

/// Build the wire [`pb::Project`] for a project at `path`/`name` under `org_slug`.
fn project_message(org_slug: String, path: String, name: String) -> pb::Project {
    pb::Project {
        org_slug,
        path,
        name,
    }
}

/// The canonical instance-settings keys editable over the API/CLI.
///
/// This is the wire/CLI surface — the same keys the `/-/instance` console
/// writes. `default_storage_root` is deliberately excluded: storage is the
/// deployment default and is read-only in the console.
const INSTANCE_KEYS: &[&str] = &[
    "site_title",
    "tagline",
    "announcement",
    "tos_url",
    "privacy_url",
    "support_url",
    "signup_policy",
    "signup_domains",
    "password_login",
    "caches_public",
    "session_lifetime_secs",
    "default_crawl_policy",
    "max_upload_bytes",
];

/// Whether `key` is a recognized instance-settings key.
fn is_instance_key(key: &str) -> bool {
    INSTANCE_KEYS.contains(&key)
}

/// Validate and normalize an instance-settings value for `key`, returning the
/// stored form (or `None` to clear the key when the value is blank).
///
/// Free-text keys pass through trimmed; the enum and numeric keys are checked so
/// an invalid value is rejected before any write.
///
/// # Errors
///
/// Returns [`RpcError::InvalidArgument`] for an unknown key or a value that does
/// not satisfy that key's constraint.
fn normalize_instance_value(key: &str, value: &str) -> Result<Option<String>, RpcError> {
    if !is_instance_key(key) {
        return Err(RpcError::invalid(format!(
            "unknown instance setting: {key}"
        )));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match key {
        "signup_policy" => {
            // Round-trip through the parser so only the two canonical strings
            // store; anything else is a client error rather than a silent
            // fail-closed to invite_only.
            if trimmed != "open" && trimmed != "invite_only" {
                return Err(RpcError::invalid(
                    "signup_policy must be 'open' or 'invite_only'",
                ));
            }
            Ok(Some(trimmed.to_string()))
        }
        "default_crawl_policy" => {
            let policy = crate::crawl::CrawlPolicy::parse(trimmed)
                .map_err(|e| RpcError::invalid(e.to_string()))?;
            Ok(Some(policy.as_str().to_string()))
        }
        "password_login" | "caches_public" => {
            // Normalize the various truthy/falsy spellings to on/off.
            let on = !matches!(trimmed, "off" | "false" | "0" | "no");
            Ok(Some(if on { "on" } else { "off" }.to_string()))
        }
        "signup_domains" => {
            // Normalize to a lowercased, comma-joined allowlist.
            let domains: Vec<String> = trimmed
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase)
                .collect();
            if domains.is_empty() {
                Ok(None)
            } else {
                Ok(Some(domains.join(",")))
            }
        }
        "session_lifetime_secs" | "max_upload_bytes" => {
            let n: i64 = trimmed
                .parse()
                .map_err(|_| RpcError::invalid(format!("{key} must be a non-negative integer")))?;
            if n < 0 {
                return Err(RpcError::invalid(format!("{key} must be non-negative")));
            }
            Ok(Some(n.to_string()))
        }
        _ => Ok(Some(trimmed.to_string())),
    }
}

/// Build the wire [`pb::InstanceSettings`] from the loaded settings bundle.
///
/// Unset optionals (`session_lifetime_secs`/`max_upload_bytes`) map to `0`,
/// which the wire contract documents as "use the built-in default".
fn instance_settings_to_pb(s: &crate::db::InstanceSettings) -> pb::InstanceSettings {
    pb::InstanceSettings {
        site_title: s.site_title.clone().unwrap_or_default(),
        tagline: s.tagline.clone().unwrap_or_default(),
        announcement: s.announcement.clone().unwrap_or_default(),
        tos_url: s.tos_url.clone().unwrap_or_default(),
        privacy_url: s.privacy_url.clone().unwrap_or_default(),
        support_url: s.support_url.clone().unwrap_or_default(),
        signup_policy: s.signup_policy.as_str().to_string(),
        signup_domains: s.signup_domains.clone(),
        password_login: s.password_login,
        session_lifetime_secs: s.session_lifetime_secs.unwrap_or(0),
        default_crawl_policy: s.default_crawl_policy.clone(),
        max_upload_bytes: s.max_upload_bytes.unwrap_or(0),
    }
}

/// Build the wire [`pb::Binding`] for a storage binding under `org_slug`.
///
/// `expose_root` gates the admin-only `root`/`endpoint` detail (the hub's
/// storage layout): a plain member sees an empty `root`/`endpoint`. The sealed
/// credential is never placed on the wire regardless.
fn binding_message(
    org_slug: String,
    b: &crate::db::StorageBindingRecord,
    expose_root: bool,
) -> pb::Binding {
    // For an s3/r2 binding the "region" lives inside the sealed credential_ref
    // (access_key:secret_key:region); it is not separately surfaced here to avoid
    // an unseal on a list call. The access mode and endpoint are non-secret.
    pb::Binding {
        org_slug,
        name: b.name.clone(),
        kind: b.kind.clone(),
        root: if expose_root {
            b.root.clone()
        } else {
            String::new()
        },
        access: if b.kind == "local_fs" {
            String::new()
        } else {
            b.access.clone()
        },
        endpoint: if expose_root {
            b.endpoint.clone().unwrap_or_default()
        } else {
            String::new()
        },
        region: String::new(),
    }
}

/// Build the wire [`pb::Webhook`] for a webhook subscription under `org_slug`.
fn webhook_message(
    id: i64,
    org_slug: String,
    url: String,
    events: Vec<String>,
    active: bool,
    created_at: i64,
) -> pb::Webhook {
    pb::Webhook {
        id,
        org_slug,
        url,
        events,
        active,
        created_at,
    }
}

/// Project a [`ChangesetRow`](crate::db::ChangesetRow) onto the wire
/// [`pb::Changeset`], flattening its optional summary/applied/revert fields.
fn changeset_message(row: crate::db::ChangesetRow) -> pb::Changeset {
    pb::Changeset {
        change_id: row.change_id,
        actor_label: row.actor_label,
        scope: row.scope,
        status: row.status,
        summary: row.summary.unwrap_or_default(),
        created_at: row.created_at,
        applied_at: row.applied_at.unwrap_or_default(),
        reverted_by_change_id: row.reverted_by_change_id.unwrap_or_default(),
    }
}

/// A buffered compatibility payload for an internal machine-surface lookup.
///
/// [`RpcService::facade_fetch`] remains for bounded internal browse lookups and
/// nested-resolution compatibility. Public registry/cache machine routes use
/// [`RpcService::registry_serve`] / [`RpcService::cache_serve`] so large objects
/// stream. The fixed header values still come from runtime-neutral [`keymap`].
#[derive(Debug)]
pub struct FacadeObject {
    /// The object's bytes, read from the registry's surface store. Empty when
    /// [`redirect`](Self::redirect) is set.
    pub bytes: Vec<u8>,
    /// The `Content-Type` header value for the requested machine path.
    pub content_type: &'static str,
    /// The `Cache-Control` header value for the requested machine path.
    pub cache_control: &'static str,
    /// When `Some`, the object is not served inline but as a temporary (`302`)
    /// redirect to this presigned origin URL — the authenticated-origin read of
    /// a private external binding (RFC-0004 "presigned GET → 302"). `302`
    /// (temporary), never a cacheable permanent redirect, since the URL expires.
    pub redirect: Option<String>,
}

/// Result of the placement-aware registry streaming path.
pub enum RegistryServeOutcome {
    /// A streamed response was opened from the selected backend.
    Response(axum::response::Response),
    /// Topology was configured, but the path was not servable.
    NotFound,
    /// The atomic read-plan snapshot had no placements and its migration reader missed.
    UnplacedNotFound,
}

/// Authorization evidence accepted by the shared machine-surface streamers.
///
/// Worker and other transport-neutral callers pass their raw authorization
/// header so [`RpcService`] remains the authorization boundary. The native
/// transport may instead pass [`PreauthorizedSession`](Self::PreauthorizedSession)
/// only after its session-aware registry/cache gate has validated the cookie
/// against the requested surface. The service still checks resource liveness
/// for both variants, so org suspension and cache deletion take effect between
/// the transport gate and placement selection.
#[derive(Clone, Copy, Debug)]
pub enum ReadAuthorization<'a> {
    /// A raw `Authorization` header, or `None` for an anonymous request.
    AuthorizationHeader(Option<&'a str>),
    /// A native browser session already authorized for this exact surface.
    PreauthorizedSession,
}

/// Maximum surface-file upload size accepted by a single facade `PUT` (256 MiB).
///
/// Generously sized for release packs while still bounding a single request; a
/// body past this cap is rejected as [`FacadeWrite::TooLarge`]. The transport
/// renders that as `413 Payload Too Large`, and the deployment additionally
/// caps the request body at this size at the transport layer.
pub const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Upper bound on nodes returned by `CacheClosure`, so a pathological closure
/// cannot produce an unbounded response.
const MAX_CLOSURE_NODES: usize = 10_000;

/// Validity window for a presigned cache-read URL. Long enough for a client to
/// follow the `302` and complete the origin fetch, short enough that a leaked
/// URL is useless within minutes.
const PRESIGN_EXPIRES_SECS: u32 = 300;

/// The outcome of a facade write ([`RpcService::put_machine_path`]) or write-side
/// probe ([`RpcService::head_machine_path`]), rendered by the transport.
///
/// Unlike the read RPCs (which return [`RpcError`]), the facade write path mounts
/// on the raw `/{slug}/{*path}` route and renders plain HTTP statuses (the wire
/// contract `apr origin upload` expects), so it carries its own result enum
/// rather than the Connect error envelope. The transport maps each variant to a
/// fixed status, preserving the byte-identical `201`/`200`/`400`/`401`/`403`/
/// `404`/`405`/`409`/`413`/`507`/`500` contract of the prior hub facade.
#[derive(Debug)]
pub enum FacadeWrite {
    /// The write created a new object: `201 Created`.
    Created,
    /// The write overwrote an existing object: `200 OK`.
    Overwritten,
    /// The probed object exists: `200 OK` (HEAD only).
    Present,
    /// The slug is unknown or under a soft-deleted org: `404 Not Found`.
    NotFound,
    /// The registry exists but is not writable through the facade (no storage
    /// binding / not locally writable): `405 Method Not Allowed`, with a reason.
    NotWritable(&'static str),
    /// The path is not a machine path or escapes the surface root: `400 Bad
    /// Request`, with a reason.
    BadPath(&'static str),
    /// No, or an invalid, bearer JWT: `401 Unauthorized`, with a reason.
    Unauthorized(&'static str),
    /// A valid token lacking `Publish` on the registry scope: `403 Forbidden`.
    Forbidden,
    /// Another token holds the registry publish lease: `409 Conflict`.
    LeaseConflict,
    /// The body exceeds [`MAX_UPLOAD_BYTES`]: `413 Payload Too Large`.
    TooLarge,
    /// The org's storage quota would be exceeded: `507 Insufficient Storage`.
    QuotaExceeded,
    /// An internal IO/database failure (already logged): `500`.
    Internal,
}

/// Whether a surface-relative path is a *mutable pointer* (vs. an immutable
/// content-addressed object).
///
/// Mirrors the producer's classification (`StaticOriginClass` in
/// `static_upload.rs` and [`keymap::cache_control`]): `HEAD`, `info/refs`,
/// `objects/info/**`, `channels/**`, and `nix-cache-info` are pointers rewritten
/// on each publish; everything else (loose objects, release packs, narinfos,
/// NARs) is content-addressed and immutable. Only pointer writes take the
/// publish lease and trigger a re-index.
fn is_mutable_pointer(path: &str) -> bool {
    path == "HEAD"
        || path == "info/refs"
        || path == "nix-cache-info"
        || path.starts_with("objects/info/")
        || path.starts_with("channels/")
}

/// Whether a successful write of `path` should trigger a re-index.
///
/// The two pointers that *complete* a publish — `info/refs` (the git surface)
/// and `nix-cache-info` (the cache surface) — drive a re-index; they are written
/// last in the producer's phase-major order, so by the time they land the
/// objects they reference are already present.
fn triggers_reindex(path: &str) -> bool {
    path == "info/refs" || path == "nix-cache-info"
}

/// The shared, transport-free implementation of the `aos.hub.v1` services.
///
/// Holds only data the method bodies need — the [`Database`], the [`JwtKeys`]
/// that verify (and mint) bearer tokens, and the externally reachable base URL
/// used to build canonical upload URLs. The rate limiter and other
/// platform-specific seams arrive as ports as the write path is folded in.
pub struct RpcService {
    /// The hub database (one implementation over the async `Backend`).
    pub db: Arc<Database>,
    /// HS256 keys verifying the bearer JWT on authenticated calls.
    pub jwt_keys: JwtKeys,
    /// Externally reachable base URL, used to build the canonical upload URL.
    pub external_url: String,
    /// The abuse-bound rate limiter (the [`RateLimiter`] port), metering
    /// `CreateOrg` per principal.
    pub ratelimit: Arc<dyn RateLimiter>,
    /// The per-registry surface-read port (the [`SurfaceProvider`]), resolving a
    /// [`SurfaceFetch`](crate::fetch::SurfaceFetch) for the `GitService` reads.
    ///
    /// The native hub resolves a filesystem or HTTP fetcher per the registry's
    /// storage binding; the Worker returns an R2-backed fetcher scoped to the
    /// registry's prefix.
    pub surface: Arc<dyn SurfaceProvider>,
    /// The per-registry surface-*write* port (the [`SurfaceWriteProvider`]),
    /// resolving a [`SurfaceWrite`](crate::surface_write::SurfaceWrite) for the
    /// facade upload `PUT`.
    ///
    /// The native hub returns a filesystem writer rooted at the registry's
    /// storage binding (atomic temp-file + rename, symlink-contained); the Worker
    /// returns an R2-backed writer scoped to the registry's prefix.
    pub surface_write: Arc<dyn SurfaceWriteProvider>,
    /// The publish lease ([`PublishLease`]), serializing a registry's
    /// mutable-pointer flips across concurrent publishers.
    ///
    /// The native hub uses an in-memory lease
    /// ([`InMemoryLease`](crate::lease::InMemoryLease)); the Worker uses a
    /// D1-backed lease shared across isolates.
    pub lease: Arc<dyn PublishLease>,
    /// The post-publish reindexer ([`Reindexer`]), run inline when a
    /// publish-completing pointer write lands.
    ///
    /// The native hub re-indexes synchronously from the local surface; the Worker
    /// defers to its Cron-trigger indexer (a logged no-op).
    pub reindexer: Arc<dyn Reindexer>,
    /// The secret sealer ([`SecretSealer`](crate::auth::seal::SecretSealer)) used
    /// to unseal a cache's hosted Ed25519 key for server-side narinfo signing.
    ///
    /// `None` disables hub-side signing — a key-bearing cache then relies on the
    /// uploader's own `Sig:` lines (BYO signing). Both shells wire their sealer
    /// (the native `HUB_SEAL_KEY` sealer; the Worker's `HUB_SEAL_KEY` binding).
    pub sealer: Option<Arc<dyn crate::auth::seal::SecretSealer>>,
    /// The authenticated-origin proxy-read fetcher
    /// ([`OriginFetch`](crate::fetch::OriginFetch)), used to stream a private
    /// external origin's bytes through the hub instead of `302`-redirecting the
    /// client to a presigned URL.
    ///
    /// `None` (the default) disables hub-side proxying: a private-origin cache
    /// then always serves a presigned `302`. Wired per shell via
    /// [`with_origin_fetch`](Self::with_origin_fetch) — the native hub a
    /// `reqwest` streamer, the Worker a Fetch-API streamer. Streamed proxying is
    /// only engaged when the cache's primary frontend's
    /// [`ProxyConfig::stream`](crate::db::ProxyConfig::stream) is set.
    pub origin_fetch: Option<Arc<dyn crate::fetch::OriginFetch>>,
    /// The hot-state key-value store ([`KvStore`](crate::kv::KvStore)) for
    /// read-through caching of point-key lookups — sessions, tokens, instance
    /// config, frontend routing, trust rosters (RFC-0004 ch.14 Phase C).
    ///
    /// `None` (the default) routes every such read straight to the database, the
    /// pre-Phase-C behavior; wired per shell via [`with_kv`](Self::with_kv) — the
    /// Worker a Workers KV store (`WorkerKv`), the native hub an in-process or
    /// embedded store. When present, the cache-aside read path
    /// ([`crate::cache::read_through`]) serves hot keys off KV with a short TTL
    /// and invalidates on write, keeping these reads off the D1 session cost.
    pub kv: Option<Arc<dyn crate::kv::KvStore>>,
}

/// The KV key a session resolution is cached under: `sess:` + the SHA-256 hex of
/// the cookie secret (never the raw secret, which must not appear in a key).
fn session_cache_key(secret: &str) -> String {
    format!("sess:{}", crate::auth::token::sha256_hex(secret))
}

/// The serializable projection of a [`ResolvedSession`](crate::web::session::ResolvedSession)
/// stored in KV (RFC-0004 ch.14 Phase C).
///
/// Mirrors `SessionAuth`'s integer fields plus the user's email — everything the
/// resolution carries except the secret (re-attached on read). Kept local to the
/// service so the `db` types need no serde derives.
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedSession {
    user_id: i64,
    auth_level: i64,
    last_authenticated_at: i64,
    expires_at: i64,
    email: String,
}

impl CachedSession {
    /// Projects a freshly-resolved session into its cacheable form.
    fn from_resolved(rs: &crate::web::session::ResolvedSession) -> CachedSession {
        CachedSession {
            user_id: rs.auth.user_id,
            auth_level: rs.auth.auth_level,
            last_authenticated_at: rs.auth.last_authenticated_at,
            expires_at: rs.auth.expires_at,
            email: rs.email.clone(),
        }
    }

    /// Rebuilds a [`ResolvedSession`](crate::web::session::ResolvedSession) from a
    /// cached projection, or `None` when it has expired as of `now`.
    ///
    /// The expiry recheck makes the short cache TTL safe: an entry that expires
    /// mid-window is never served, exactly as `validate_session` would reject it.
    fn into_resolved(self, secret: &str, now: i64) -> Option<crate::web::session::ResolvedSession> {
        if self.expires_at <= now {
            return None;
        }
        Some(crate::web::session::ResolvedSession {
            secret: secret.to_string(),
            auth: crate::db::SessionAuth {
                user_id: self.user_id,
                auth_level: self.auth_level,
                last_authenticated_at: self.last_authenticated_at,
                expires_at: self.expires_at,
            },
            email: self.email,
        })
    }
}

impl RpcService {
    /// Construct the service over its dependencies.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<Database>,
        jwt_keys: JwtKeys,
        external_url: String,
        ratelimit: Arc<dyn RateLimiter>,
        surface: Arc<dyn SurfaceProvider>,
        surface_write: Arc<dyn SurfaceWriteProvider>,
        lease: Arc<dyn PublishLease>,
        reindexer: Arc<dyn Reindexer>,
        sealer: Option<Arc<dyn crate::auth::seal::SecretSealer>>,
    ) -> Self {
        Self {
            db,
            jwt_keys,
            external_url,
            ratelimit,
            surface,
            surface_write,
            lease,
            reindexer,
            sealer,
            origin_fetch: None,
            kv: None,
        }
    }

    /// Attach a [`KvStore`](crate::kv::KvStore) for read-through caching of hot
    /// point-key state, returning the modified service.
    ///
    /// Without it, sessions/tokens/config/routing reads go straight to the
    /// database; with it, those reads are served cache-aside off KV with a short
    /// TTL and invalidated on write (RFC-0004 ch.14 Phase C).
    #[must_use]
    pub fn with_kv(mut self, kv: Arc<dyn crate::kv::KvStore>) -> Self {
        self.kv = Some(kv);
        self
    }

    /// Resolves a session from its cookie secret, read-through cached in KV when
    /// a [`KvStore`](crate::kv::KvStore) is attached (RFC-0004 ch.14 Phase C).
    ///
    /// On the hot path — the session lookup runs on **every** authenticated
    /// request — this serves the resolution from KV (sub-ms, off the D1 session
    /// cost) for [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS), and additionally
    /// avoids the `last_seen_at` write `validate_session` performs on a cache
    /// hit. Expiry is still enforced exactly: the cached `expires_at` is
    /// re-checked against the current clock, so an expired session is never
    /// served from cache even within the TTL window. Revocation lag is bounded
    /// to the TTL (≤60 s) plus any explicit [`invalidate_session_cache`] on
    /// logout — the eventual-consistency contract this tier accepts.
    ///
    /// With no `kv` attached this is exactly
    /// [`resolve_session`](crate::web::session::resolve_session) against the
    /// database (the pre-Phase-C path).
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read failure or a database failure while loading
    /// the session.
    pub async fn resolve_session_cached(
        &self,
        secret: &str,
    ) -> anyhow::Result<Option<crate::web::session::ResolvedSession>> {
        let Some(kv) = &self.kv else {
            return crate::web::session::resolve_session(&self.db, secret).await;
        };
        let key = session_cache_key(secret);
        let db = &self.db;
        let cached: Option<CachedSession> = crate::cache::read_through(
            kv.as_ref(),
            &key,
            Some(crate::cache::HOT_TTL_SECS),
            || async move {
                Ok(crate::web::session::resolve_session(db, secret)
                    .await?
                    .map(|rs| CachedSession::from_resolved(&rs)))
            },
        )
        .await?;
        let now = clock::now_unix_secs();
        Ok(cached.and_then(|c| c.into_resolved(secret, now)))
    }

    /// Invalidates the KV-cached session resolution for `secret` (delete-on-write).
    ///
    /// Call on logout / session revocation so the change is observed at the next
    /// read rather than after the TTL. A no-op when no [`KvStore`](crate::kv::KvStore)
    /// is attached.
    pub async fn invalidate_session_cache(&self, secret: &str) {
        if let Some(kv) = &self.kv {
            crate::cache::invalidate(kv.as_ref(), &session_cache_key(secret)).await;
        }
    }

    /// The instance settings, read-through cached in KV when one is attached
    /// (RFC-0004 ch.14 Phase C, the `cfg:instance` singleton).
    ///
    /// A short-TTL cache off the database; the eventual-consistency contract
    /// (≤ [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS) staleness) is acceptable
    /// for site chrome / signup policy. Falls back to the database with no `kv`.
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read or database failure.
    pub async fn instance_settings_cached(&self) -> anyhow::Result<crate::db::InstanceSettings> {
        let Some(kv) = &self.kv else {
            return self.db.instance_settings().await;
        };
        let db = &self.db;
        let cached = crate::cache::read_through(
            kv.as_ref(),
            "cfg:instance",
            Some(crate::cache::HOT_TTL_SECS),
            || async move { db.instance_settings().await.map(Some) },
        )
        .await?;
        // `instance_settings` always yields a value (defaults), so a `None` here
        // can only be a transient miss; fall back to a direct read.
        match cached {
            Some(settings) => Ok(settings),
            None => self.db.instance_settings().await,
        }
    }

    /// Invalidates the cached instance settings (call after a settings save).
    pub async fn invalidate_instance_settings_cache(&self) {
        if let Some(kv) = &self.kv {
            crate::cache::invalidate(kv.as_ref(), "cfg:instance").await;
        }
    }

    /// A registry's trust-key roster, read-through cached in KV when one is
    /// attached (RFC-0004 ch.14 Phase C, `roster:{registry_id}`).
    ///
    /// Each entry is `(key_id, public_key, status)` as
    /// [`Database::list_roster`](crate::db::Database::list_roster) returns. A
    /// short-TTL cache off the database; falls back to the database with no `kv`.
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read or database failure.
    pub async fn list_roster_cached(
        &self,
        registry_id: i64,
    ) -> anyhow::Result<Vec<(String, String, String)>> {
        let Some(kv) = &self.kv else {
            return self.db.list_roster(registry_id).await;
        };
        let key = format!("roster:{registry_id}");
        let db = &self.db;
        let cached = crate::cache::read_through(
            kv.as_ref(),
            &key,
            Some(crate::cache::HOT_TTL_SECS),
            || async move { db.list_roster(registry_id).await.map(Some) },
        )
        .await?;
        match cached {
            Some(roster) => Ok(roster),
            None => self.db.list_roster(registry_id).await,
        }
    }

    /// Invalidates a registry's cached roster (call after a key rotation/change).
    pub async fn invalidate_roster_cache(&self, registry_id: i64) {
        if let Some(kv) = &self.kv {
            crate::cache::invalidate(kv.as_ref(), &format!("roster:{registry_id}")).await;
        }
    }

    /// Validates an API-token secret, read-through cached in KV when one is
    /// attached, with **revocation safety via a tombstone** (RFC-0004 ch.14
    /// Phase C, `tok:{hash}` + `tokrev:{token_id}`).
    ///
    /// Token auth runs on every API request; this serves the validated
    /// [`TokenAuth`](crate::db::TokenAuth) from KV (sub-ms, off the D1 session
    /// cost) for [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS), and skips the
    /// `last_used_at` write `validate_token` performs on a cache hit.
    ///
    /// Because the cache is keyed by the token **secret** but revocation is by
    /// token **id**, a naive TTL cache could serve a revoked token until the TTL.
    /// Instead, [`invalidate_token_cache`] writes a `tokrev:{token_id}` tombstone
    /// on revoke/rotate, and this method **rejects any cached resolution whose
    /// token id is tombstoned** — so a revoke is observed immediately, not after
    /// the TTL. (After the resolution TTL the entry re-validates from the
    /// database, which already excludes revoked/rotated tokens.)
    ///
    /// With no `kv` attached this is exactly
    /// [`validate_token`](crate::db::Database::validate_token).
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read or database failure.
    pub async fn validate_token_cached(
        &self,
        secret: &str,
    ) -> anyhow::Result<Option<crate::db::TokenAuth>> {
        let Some(kv) = &self.kv else {
            return self.db.validate_token(secret).await;
        };
        let key = format!("tok:{}", crate::auth::token::sha256_hex(secret));
        let db = &self.db;
        let cached: Option<crate::db::TokenAuth> = crate::cache::read_through(
            kv.as_ref(),
            &key,
            Some(crate::cache::HOT_TTL_SECS),
            || async move { db.validate_token(secret).await },
        )
        .await?;
        // Reject a cached resolution whose token was revoked/rotated since it was
        // cached (the tombstone written by `invalidate_token_cache`).
        if let Some(auth) = &cached {
            let tomb = format!("tokrev:{}", auth.token_id);
            if kv.get(&tomb).await?.is_some() {
                return Ok(None);
            }
        }
        Ok(cached)
    }

    /// Tombstones a token id so any KV-cached resolution for it is rejected
    /// (call on revoke/rotate). A no-op when no [`KvStore`](crate::kv::KvStore)
    /// is attached.
    ///
    /// The tombstone outlives the resolution cache TTL (so no stale resolution
    /// can outlast it), after which the resolution re-validates from the database.
    pub async fn invalidate_token_cache(&self, token_id: &str) {
        if let Some(kv) = &self.kv {
            // 10× the resolution TTL is a generous margin over any cached entry's
            // lifetime (and clock skew); the value is irrelevant (presence is).
            let ttl = crate::cache::HOT_TTL_SECS * 10;
            let _ = kv.put(&format!("tokrev:{token_id}"), b"1", Some(ttl)).await;
        }
    }

    /// Attach an [`OriginFetch`](crate::fetch::OriginFetch) for streamed proxying
    /// of private-origin cache reads, returning the modified service.
    ///
    /// Without it, a private-origin cache serves a presigned `302`; with it, a
    /// cache whose primary frontend sets `proxy_config.stream` has its origin
    /// bytes streamed through the hub instead.
    #[must_use]
    pub fn with_origin_fetch(mut self, origin_fetch: Arc<dyn crate::fetch::OriginFetch>) -> Self {
        self.origin_fetch = Some(origin_fetch);
        self
    }

    /// Verify the bearer JWT carried in a raw `Authorization` header value.
    ///
    /// `auth` is the verbatim header (e.g. `"Bearer eyJ…"`); the caller's
    /// transport supplies it. Mirrors the native hub's `require_claims`.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] when the header is absent, is not a
    /// `Bearer` token, or fails JWT verification.
    pub fn require_claims(&self, auth: Option<&str>) -> Result<Claims, RpcError> {
        let header =
            auth.ok_or_else(|| RpcError::Unauthenticated("missing Authorization header".into()))?;
        let token = header.strip_prefix("Bearer ").ok_or_else(|| {
            RpcError::Unauthenticated("Authorization header must start with Bearer".into())
        })?;
        self.jwt_keys
            .verify(token)
            .map_err(|e| RpcError::Unauthenticated(e.to_string()))
    }

    /// Verify an *optional* bearer JWT.
    ///
    /// A wholly absent `Authorization` header yields `Ok(None)` (an anonymous
    /// caller); a header that is present but malformed or fails verification
    /// still errors, so a bad token is never silently downgraded to anonymous.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] when a header is present but is not
    /// a valid `Bearer` JWT.
    pub fn optional_claims(&self, auth: Option<&str>) -> Result<Option<Claims>, RpcError> {
        match auth {
            None => Ok(None),
            Some(_) => self.require_claims(auth).map(Some),
        }
    }

    /// Require that a verified caller holds `perm` on `scope`.
    ///
    /// Two-sided: both the token's own grant *and* the principal's *current*
    /// memberships must cover the action, so a revoked role denies immediately
    /// even on an unexpired token.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::PermissionDenied`] when either check fails, and
    /// [`RpcError::Internal`] on a database failure loading memberships.
    pub async fn require_permission(
        &self,
        claims: &Claims,
        perm: Permission,
        scope: &Scope,
    ) -> Result<(), RpcError> {
        let denied =
            || RpcError::PermissionDenied(format!("{} permission required", perm.as_str()));
        if !token_allows(claims, perm, scope) {
            return Err(denied());
        }
        let principal = claims_principal(claims).ok_or_else(denied)?;
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?;
        if iam::allow(&grants, perm, scope) {
            Ok(())
        } else {
            Err(denied())
        }
    }

    /// Non-erroring form of [`Self::require_permission`] for list filters.
    ///
    /// Applies the same two-sided test but returns `false` (fail-closed) on any
    /// denial, database failure, unknown principal, or anonymous caller — so a
    /// "list what I can see" call drops, rather than rejects, hidden records.
    async fn claims_allow(&self, claims: Option<&Claims>, perm: Permission, scope: &Scope) -> bool {
        let Some(claims) = claims else {
            return false;
        };
        if !token_allows(claims, perm, scope) {
            return false;
        }
        let Some(principal) = claims_principal(claims) else {
            return false;
        };
        match self.db.effective_scopes(principal).await {
            Ok(grants) => iam::allow(&grants, perm, scope),
            Err(_) => false,
        }
    }

    /// Whether `claims` may read `registry`, as a non-erroring list filter.
    ///
    /// A registry under a soft-deleted org is hidden; a `public` (or unowned
    /// phase-1) registry reads anonymously; an `internal`/`private` registry
    /// needs [`Permission::Read`] on the registry scope.
    async fn can_read(&self, claims: Option<&Claims>, registry: &RegistryRecord) -> bool {
        if let Some(org_id) = registry.org_id {
            if !matches!(self.db.org_is_active(org_id).await, Ok(true)) {
                return false;
            }
        }
        if registry.visibility == "public" || registry.org_id.is_none() {
            return true;
        }
        self.claims_allow(claims, Permission::Read, &Scope::parse(&registry.slug))
            .await
    }

    /// Erroring access gate for single-registry reads.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for a registry under a soft-deleted org,
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] when a
    /// non-public registry is read without authority, and [`RpcError::Internal`]
    /// on database failure.
    async fn require_read(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
    ) -> Result<(), RpcError> {
        if let Some(org_id) = registry.org_id {
            if !self
                .db
                .org_is_active(org_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::not_found("registry"));
            }
        }
        if registry.visibility == "public" || registry.org_id.is_none() {
            return Ok(());
        }
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::Read, &Scope::parse(&registry.slug))
            .await
    }

    /// Authorize a registry machine read while rechecking registry liveness.
    async fn require_registry_stream_read(
        &self,
        auth: ReadAuthorization<'_>,
        registry: &RegistryRecord,
    ) -> Result<(), RpcError> {
        match auth {
            ReadAuthorization::AuthorizationHeader(header) => {
                self.require_read(header, registry).await
            }
            ReadAuthorization::PreauthorizedSession => {
                if let Some(org_id) = registry.org_id {
                    if !self
                        .db
                        .org_is_active(org_id)
                        .await
                        .map_err(RpcError::internal)?
                    {
                        return Err(RpcError::not_found("registry"));
                    }
                }
                Ok(())
            }
        }
    }

    /// Resolve a registry by slug or map a miss to `NotFound`.
    async fn registry_or_not_found(&self, slug: &str) -> Result<RegistryRecord, RpcError> {
        self.db
            .registry_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))
    }

    /// Resolve a registry's last-indexed HEAD commit oid.
    ///
    /// The `GitService` reads walk from the registry's tracked-branch HEAD, the
    /// last commit the indexer verified.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::FailedPrecondition`] when the registry has not been
    /// indexed yet, [`RpcError::InvalidArgument`] when the recorded commit is
    /// not a valid oid, and [`RpcError::Internal`] on database failure.
    async fn head_commit(&self, registry: &RegistryRecord) -> Result<Oid, RpcError> {
        let hex = self
            .db
            .index_status(registry.id)
            .await
            .map_err(RpcError::internal)?
            .and_then(|s| s.last_indexed_commit)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("registry has no indexed commit yet".into())
            })?;
        Oid::from_hex(&hex).map_err(|e| RpcError::invalid(format!("{e:#}")))
    }

    /// Build the wire [`pb::Registry`] for `record`, folding in its index status,
    /// cache stack, and trust roster.
    async fn registry_message(
        &self,
        record: &RegistryRecord,
        status: Option<IndexStatus>,
    ) -> Result<pb::Registry, RpcError> {
        let caches = self
            .db
            .list_advertised_caches(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|(url, priority)| pb::Cache { url, priority })
            .collect();
        let roster = self
            .db
            .list_roster(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|(id, key, status)| pb::RosterKey { id, key, status })
            .collect();
        let status = status.unwrap_or(IndexStatus {
            state: "empty".into(),
            error: None,
            last_indexed_commit: None,
            name: None,
            description: None,
            readme: None,
            indexed_at: None,
        });
        Ok(pb::Registry {
            slug: record.slug.clone(),
            name: status.name.unwrap_or_default(),
            description: status.description.unwrap_or_default(),
            source_url: record.source_url.clone(),
            index_state: status.state,
            index_error: status.error.unwrap_or_default(),
            last_indexed_commit: status.last_indexed_commit.unwrap_or_default(),
            indexed_at: status.indexed_at.unwrap_or_default(),
            trust_keys: record.trust_keys.clone(),
            caches,
            roster,
            crawl_policy: record.crawl_policy.clone(),
            llms_txt_body: record.llms_txt_body.clone().unwrap_or_default(),
        })
    }

    /// Whether `claims`'s principal may create an org under `invite_only`.
    ///
    /// Permitted for a service-account caller, an existing org member, an
    /// instance admin (an `iam.admin` grant at the instance root), or a user
    /// holding a live invitation for their email.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    async fn signup_permitted(&self, claims: &Claims) -> Result<bool, RpcError> {
        let Some(principal) = claims_principal(claims) else {
            return Ok(false);
        };
        if principal.kind != PrincipalKind::User {
            return Ok(true);
        }
        if self
            .db
            .user_has_any_membership(principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(true);
        }
        // Instance admin: an iam.admin grant at the instance root.
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?;
        if iam::allow(&grants, Permission::IamAdmin, &Scope::root()) {
            return Ok(true);
        }
        // A live invitation for the caller's email.
        if let Some(email) = self
            .db
            .user_email(principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            if self
                .db
                .has_pending_invitation(&email)
                .await
                .map_err(RpcError::internal)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Enforces the instance email-domain allowlist at the signup moment.
    ///
    /// When `signup_domains` is set (non-empty), a *new* user principal — one
    /// with no existing membership and no instance-admin grant — must present an
    /// email whose lowercased domain is on the allowlist. Service accounts,
    /// existing members, and instance admins are exempt (the allowlist gates who
    /// may join, not who may keep operating). A user with no email on file is
    /// rejected when the allowlist is active (fail closed).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::PermissionDenied`] when the caller's email domain is
    /// not allowlisted, and [`RpcError::Internal`] on database failure.
    async fn enforce_signup_domain(&self, claims: &Claims) -> Result<(), RpcError> {
        let settings = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        if settings.signup_domains.is_empty() {
            return Ok(());
        }
        let Some(principal) = claims_principal(claims) else {
            return Ok(());
        };
        // Only user signups are gated; service accounts are provisioned by admins.
        if principal.kind != PrincipalKind::User {
            return Ok(());
        }
        // Established users (already a member or an instance admin) are exempt.
        if self
            .db
            .user_has_any_membership(principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(());
        }
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?;
        if iam::allow(&grants, Permission::IamAdmin, &Scope::root()) {
            return Ok(());
        }
        // A new user: their email domain must be on the allowlist.
        let email = self
            .db
            .user_email(principal.id)
            .await
            .map_err(RpcError::internal)?;
        let domain = email
            .as_deref()
            .and_then(|e| e.rsplit_once('@'))
            .map(|(_, d)| d.to_lowercase());
        match domain {
            Some(d) if settings.signup_domains.iter().any(|allowed| allowed == &d) => Ok(()),
            _ => Err(RpcError::PermissionDenied(
                "your email domain is not permitted to sign up on this instance".into(),
            )),
        }
    }

    /// `OrganizationService.CreateOrg` — create an org and grant the caller `Owner`.
    ///
    /// The bootstrap exception: any authenticated principal may create an org.
    /// A user caller is granted `Owner` at the new org's scope; a
    /// service-account caller creates the org without an auto-grant. Bounded two
    /// ways against namespace pollution (sec L-3): a per-principal creation rate
    /// limit ([`RateClass::CreateOrg`]) and a per-owner total cap
    /// ([`MAX_ORGS_PER_OWNER`]).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the instance is `invite_only` and the
    /// caller is not permitted, [`RpcError::ResourceExhausted`] when the caller
    /// exceeds the creation rate or owns [`MAX_ORGS_PER_OWNER`] orgs,
    /// [`RpcError::InvalidArgument`] for an empty name or invalid slug,
    /// [`RpcError::AlreadyExists`] when the slug is taken, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn create_org(
        &self,
        auth: Option<&str>,
        req: pb::CreateOrgRequest,
    ) -> Result<pb::CreateOrgResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.name.is_empty() {
            return Err(RpcError::invalid("org name is required"));
        }
        // Validate the slug before creating the org or granting any membership:
        // a slug like "/" or "/victimorg" would otherwise normalize (via
        // `Scope::parse`) into an unintended ancestor scope and hand the caller
        // Owner over the instance root or a victim org (sec CR-2).
        iam::validate_org_slug(&req.slug)
            .map_err(|e| RpcError::invalid(format!("org slug: {e}")))?;
        // Instance signup policy: `invite_only` requires the caller to already
        // be a member, hold a live invitation, or be an instance admin.
        if self.db.signup_policy().await.map_err(RpcError::internal)?
            == crate::db::SignupPolicy::InviteOnly
            && !self.signup_permitted(&claims).await?
        {
            return Err(RpcError::PermissionDenied(
                "org creation is invite-only on this instance".into(),
            ));
        }
        // Instance email-domain allowlist: when set, a *new* user signing up
        // (creating their first org) must have an allowlisted email domain.
        // Existing members and instance admins are exempt — the allowlist gates
        // the signup moment, not established tenants.
        self.enforce_signup_domain(&claims).await?;
        // Bound the creation rate per authenticated principal (the JWT owner),
        // after the cheap input/policy gates so a rejected request does not
        // consume the caller's creation budget.
        let rl_key = format!("{}:{}", claims.owner_kind, claims.owner_id);
        if let RateDecision::Limited { retry_after } = self
            .ratelimit
            .check(RateClass::CreateOrg, &rl_key, clock::now_unix_secs())
            .await
        {
            return Err(RpcError::ResourceExhausted(format!(
                "org creation rate limit exceeded; retry after {retry_after}s"
            )));
        }
        // Per-owner total cap: a user principal may own only so many orgs, so a
        // slow loop cannot accumulate past the burst the rate limit blunts.
        if let Some(principal) = claims_principal(&claims) {
            if principal.kind == PrincipalKind::User
                && self
                    .db
                    .count_user_owned_orgs(principal.id)
                    .await
                    .map_err(RpcError::internal)?
                    >= MAX_ORGS_PER_OWNER
            {
                return Err(RpcError::ResourceExhausted(format!(
                    "owned-org limit reached ({MAX_ORGS_PER_OWNER} max); contact an instance admin"
                )));
            }
        }
        let id = self
            .db
            .create_org(&req.slug, &req.name)
            .await
            .map_err(|e| RpcError::AlreadyExists(format!("{e:#}")))?;
        // Auto-grant the creating user Owner on the new org.
        if let Some(principal) = claims_principal(&claims) {
            if principal.kind == PrincipalKind::User {
                self.db
                    .grant_membership(
                        principal.kind.as_str(),
                        principal.id,
                        &req.slug,
                        Role::Owner.as_str(),
                    )
                    .await
                    .map_err(RpcError::internal)?;
            }
        }
        let org = self
            .db
            .org_by_id(id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("org {id} vanished after creation"))
            })?;
        Ok(pb::CreateOrgResponse {
            org: Some(org_message(&org)),
        })
    }

    /// `RegistryService.ListRegistries` — the registries the caller may read.
    ///
    /// Visibility-filters every record through [`Self::can_read`]: anonymous
    /// callers see the public slice, members additionally see their orgs'
    /// registries; hidden records are dropped, not errored.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a present-but-invalid bearer
    /// JWT, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_registries(
        &self,
        auth: Option<&str>,
        req: pb::ListRegistriesRequest,
    ) -> Result<pb::ListRegistriesResponse, RpcError> {
        let claims = self.optional_claims(auth)?;
        let records = self
            .db
            .list_registries()
            .await
            .map_err(RpcError::internal)?;
        let mut registries = Vec::with_capacity(records.len());
        for record in &records {
            if !self.can_read(claims.as_ref(), record).await {
                continue;
            }
            let status = self
                .db
                .index_status(record.id)
                .await
                .map_err(RpcError::internal)?;
            registries.push(self.registry_message(record, status).await?);
        }
        let (registries, next_page_token) = paginate(registries, req.page_size, &req.page_token)?;
        Ok(pb::ListRegistriesResponse {
            registries,
            next_page_token,
        })
    }

    /// `RegistryService.GetRegistry` — one registry by slug.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_registry(
        &self,
        auth: Option<&str>,
        req: pb::GetRegistryRequest,
    ) -> Result<pb::GetRegistryResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let status = self
            .db
            .index_status(record.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetRegistryResponse {
            registry: Some(self.registry_message(&record, status).await?),
        })
    }

    /// `RegistryService.ListReleases` — verified signed releases, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_releases(
        &self,
        auth: Option<&str>,
        req: pb::ListReleasesRequest,
    ) -> Result<pb::ListReleasesResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let releases: Vec<pb::Release> = self
            .db
            .list_releases(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|r| pb::Release {
                semver: r.semver,
                tag_oid: r.tag_oid,
                commit_oid: r.commit_oid,
                signer: r.signer.unwrap_or_default(),
                tagged_at: r.tagged_at.unwrap_or_default(),
            })
            .collect();
        let (releases, next_page_token) = paginate(releases, req.page_size, &req.page_token)?;
        Ok(pb::ListReleasesResponse {
            releases,
            next_page_token,
        })
    }

    /// `PackageService.ListPackages` — package summaries with the newest version.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_packages(
        &self,
        auth: Option<&str>,
        req: pb::ListPackagesRequest,
    ) -> Result<pb::ListPackagesResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let packages: Vec<pb::PackageSummary> = self
            .db
            .list_packages(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|p| pb::PackageSummary {
                name: p.name,
                description: p.description,
                license: p.license,
                latest_version: p.latest_version.unwrap_or_default(),
            })
            .collect();
        let (packages, next_page_token) = paginate(packages, req.page_size, &req.page_token)?;
        Ok(pb::ListPackagesResponse {
            packages,
            next_page_token,
        })
    }

    /// `PackageService.GetPackage` — full version × platform detail for one package.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug, package name, or a
    /// soft-deleted owning org,
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] when a
    /// non-public registry is read without authority, and [`RpcError::Internal`]
    /// on database failure.
    pub async fn get_package(
        &self,
        auth: Option<&str>,
        req: pb::GetPackageRequest,
    ) -> Result<pb::GetPackageResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let detail = self
            .db
            .package_detail(record.id, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("package"))?;
        let versions = detail
            .versions
            .into_iter()
            .map(|v| pb::Version {
                version: v.version,
                previous: v.previous.unwrap_or_default(),
                platforms: v
                    .platforms
                    .into_iter()
                    .map(|p| pb::Platform {
                        platform: p.platform,
                        store_path: p.store_path,
                        nar_hash: p.nar_hash,
                        nar_size: p.nar_size,
                        closure_size: p.closure_size,
                    })
                    .collect(),
            })
            .collect();
        Ok(pb::GetPackageResponse {
            package: Some(pb::Package {
                name: detail.name,
                description: detail.description,
                homepage: detail.homepage.unwrap_or_default(),
                license: detail.license,
                maintainer: detail.maintainer,
                sysroot: detail.sysroot,
                versions,
            }),
        })
    }

    /// `ChannelService.ListChannels` — channels with full partition maps.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_channels(
        &self,
        auth: Option<&str>,
        req: pb::ListChannelsRequest,
    ) -> Result<pb::ListChannelsResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let channels: Vec<pb::Channel> = self
            .db
            .list_channels(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(channel_message)
            .collect();
        let (channels, next_page_token) = paginate(channels, req.page_size, &req.page_token)?;
        Ok(pb::ListChannelsResponse {
            channels,
            next_page_token,
        })
    }

    /// `ChannelService.GetChannel` — one channel's partition map by name.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug, channel name, or a
    /// soft-deleted owning org,
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] when a
    /// non-public registry is read without authority, and [`RpcError::Internal`]
    /// on database failure.
    pub async fn get_channel(
        &self,
        auth: Option<&str>,
        req: pb::GetChannelRequest,
    ) -> Result<pb::GetChannelResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let channel = self
            .db
            .list_channels(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|c| c.name == req.name)
            .ok_or_else(|| RpcError::not_found("channel"))?;
        Ok(pb::GetChannelResponse {
            channel: Some(channel_message(channel)),
        })
    }

    /// Resolve an org by slug or map a miss to `NotFound`.
    async fn org_or_not_found(&self, slug: &str) -> Result<crate::db::OrgRecord, RpcError> {
        self.db
            .org_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("org"))
    }

    /// `OrganizationService.GetOrg` — look up an organization by slug.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug and
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_org(
        &self,
        _auth: Option<&str>,
        req: pb::GetOrgRequest,
    ) -> Result<pb::GetOrgResponse, RpcError> {
        let org = self.org_or_not_found(&req.slug).await?;
        Ok(pb::GetOrgResponse {
            org: Some(org_message(&org)),
        })
    }

    /// `OrganizationService.ListOrgs` — the organizations the caller is a member of,
    /// ordered by slug.
    ///
    /// This is *not* a public directory: the caller must present a bearer JWT,
    /// and each org is included only when that caller holds
    /// [`Permission::Read`] covering its scope (soft-deleted orgs are already
    /// excluded by [`Database::list_orgs`](crate::db::Database::list_orgs)).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_orgs(
        &self,
        auth: Option<&str>,
        req: pb::ListOrgsRequest,
    ) -> Result<pb::ListOrgsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let all_orgs = self.db.list_orgs().await.map_err(RpcError::internal)?;
        let mut orgs: Vec<pb::Org> = Vec::new();
        for org in all_orgs.iter() {
            if self
                .claims_allow(Some(&claims), Permission::Read, &Scope::parse(&org.slug))
                .await
            {
                orgs.push(org_message(org));
            }
        }
        let (orgs, next_page_token) = paginate(orgs, req.page_size, &req.page_token)?;
        Ok(pb::ListOrgsResponse {
            orgs,
            next_page_token,
        })
    }

    /// `ProjectService.ListProjects` — an org's projects, ordered by path.
    ///
    /// The project tree is org-internal: the caller must present a bearer JWT
    /// granting [`Permission::Read`] on the org scope. An anonymous or
    /// non-member caller is denied, so the project layout never leaks across
    /// tenants.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::PermissionDenied`] when the caller lacks `Read` on the org
    /// scope, and [`RpcError::Internal`] on database failure.
    pub async fn list_projects(
        &self,
        auth: Option<&str>,
        req: pb::ListProjectsRequest,
    ) -> Result<pb::ListProjectsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(&claims, Permission::Read, &Scope::parse(&org.slug))
            .await?;
        let projects: Vec<pb::Project> = self
            .db
            .list_projects(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|p| pb::Project {
                org_slug: org.slug.clone(),
                path: p.path,
                name: p.name,
            })
            .collect();
        Ok(pb::ListProjectsResponse { projects })
    }

    /// `StorageBindingService.ListBindings` — an org's storage bindings, by name.
    ///
    /// The caller must present a bearer JWT granting [`Permission::Read`] on
    /// the org scope. A binding's `root` is the on-disk path on the hub host,
    /// so it is returned **only** to a caller who additionally holds
    /// [`Permission::RegistryConfigure`] on the org; a plain member sees the
    /// binding's name and kind, but `root` is redacted to the empty string.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::PermissionDenied`] when the caller lacks `Read` on the org
    /// scope, and [`RpcError::Internal`] on database failure.
    pub async fn list_bindings(
        &self,
        auth: Option<&str>,
        req: pb::ListBindingsRequest,
    ) -> Result<pb::ListBindingsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        let scope = Scope::parse(&org.slug);
        self.require_permission(&claims, Permission::Read, &scope)
            .await?;
        // The `root` host path is an admin-only detail: only a caller who could
        // create or delete bindings (RegistryConfigure) sees it. A plain member
        // gets an empty `root` so the hub's filesystem layout never leaks.
        let expose_root = self
            .claims_allow(Some(&claims), Permission::RegistryConfigure, &scope)
            .await;
        let bindings: Vec<pb::Binding> = self
            .db
            .list_storage_bindings(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|b| binding_message(org.slug.clone(), &b, expose_root))
            .collect();
        Ok(pb::ListBindingsResponse { bindings })
    }

    /// Resolves and authorizes a typed topology surface reference.
    async fn readable_topology_surface(
        &self,
        auth: Option<&str>,
        surface: Option<pb::SurfaceRef>,
    ) -> Result<crate::db::SurfaceTarget, RpcError> {
        match surface.and_then(|surface| surface.target) {
            Some(pb::surface_ref::Target::RegistrySlug(slug)) if !slug.is_empty() => {
                let registry = self.registry_or_not_found(&slug).await?;
                self.require_read(auth, &registry).await?;
                Ok(crate::db::SurfaceTarget::Registry(registry.id))
            }
            Some(pb::surface_ref::Target::CacheSlug(slug)) if !slug.is_empty() => {
                let cache = self.cache_or_not_found(&slug).await?;
                self.require_cache_read(auth, &cache).await?;
                Ok(crate::db::SurfaceTarget::BinaryCache(cache.id))
            }
            Some(_) => Err(RpcError::invalid("surface slug must not be empty")),
            None => Err(RpcError::invalid(
                "surface must select exactly one registrySlug or cacheSlug",
            )),
        }
    }

    /// Resolves a typed surface and requires topology write authority.
    ///
    /// The IAM model does not yet have a dedicated `topology.manage` verb.
    /// Placement changes therefore temporarily use the stronger
    /// [`Permission::StorageManage`] capability on the owning organization;
    /// org-less resources require root [`Permission::IamAdmin`]. This mapping
    /// is intentionally centralized so a future dedicated verb is one change.
    async fn writable_topology_surface(
        &self,
        auth: Option<&str>,
        surface: Option<pb::SurfaceRef>,
    ) -> Result<(crate::db::SurfaceTarget, Option<i64>), RpcError> {
        let claims = self.require_claims(auth)?;
        let (target, org_id) = match surface.and_then(|surface| surface.target) {
            Some(pb::surface_ref::Target::RegistrySlug(slug)) if !slug.is_empty() => {
                let registry = self.registry_or_not_found(&slug).await?;
                (
                    crate::db::SurfaceTarget::Registry(registry.id),
                    registry.org_id,
                )
            }
            Some(pb::surface_ref::Target::CacheSlug(slug)) if !slug.is_empty() => {
                let cache = self.cache_or_not_found(&slug).await?;
                if cache.deleted_at.is_some() {
                    return Err(RpcError::not_found("cache"));
                }
                (
                    crate::db::SurfaceTarget::BinaryCache(cache.id),
                    cache.org_id,
                )
            }
            Some(_) => return Err(RpcError::invalid("surface slug must not be empty")),
            None => {
                return Err(RpcError::invalid(
                    "surface must select exactly one registrySlug or cacheSlug",
                ))
            }
        };
        match org_id {
            Some(id) => {
                if !self
                    .db
                    .org_is_active(id)
                    .await
                    .map_err(RpcError::internal)?
                {
                    return Err(RpcError::not_found("surface"));
                }
                let org = self
                    .db
                    .org_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("org"))?;
                self.require_permission(
                    &claims,
                    Permission::StorageManage,
                    &Scope::parse(&org.slug),
                )
                .await?;
            }
            None => {
                self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
                    .await?;
            }
        }
        Ok((target, org_id))
    }

    /// Resolves a storage binding by its stable name in a surface's scope.
    async fn topology_binding_id(&self, org_id: Option<i64>, name: &str) -> Result<i64, RpcError> {
        if name.is_empty() {
            return Err(RpcError::invalid("storageBindingName is required"));
        }
        let binding = match org_id {
            Some(id) => self
                .db
                .storage_binding_by_name(id, name)
                .await
                .map_err(RpcError::internal)?,
            None => None,
        };
        if let Some(binding) = binding {
            return Ok(binding.id);
        }
        self.db
            .instance_default_binding()
            .await
            .map_err(RpcError::internal)?
            .filter(|binding| binding.name == name)
            .map(|binding| binding.id)
            .ok_or_else(|| RpcError::not_found("storage binding"))
    }

    /// Finds one placement by its stable name within an already-resolved surface.
    async fn topology_placement(
        &self,
        surface: crate::db::SurfaceTarget,
        name: &str,
    ) -> Result<crate::db::SurfacePlacementRecord, RpcError> {
        if name.is_empty() {
            return Err(RpcError::invalid("placement name must not be empty"));
        }
        self.db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|placement| placement.name == name)
            .ok_or_else(|| RpcError::not_found("placement"))
    }

    /// Parses and verifies an opaque placement resource version.
    fn expected_placement_version(
        expected: &str,
        placement: &crate::db::SurfacePlacementRecord,
    ) -> Result<i64, RpcError> {
        let version = expected.parse::<i64>().map_err(|_| {
            RpcError::invalid("expectedResourceVersion must be a positive opaque version")
        })?;
        if version <= 0 {
            return Err(RpcError::invalid(
                "expectedResourceVersion must be a positive opaque version",
            ));
        }
        if version != placement.resource_version {
            return Err(RpcError::FailedPrecondition(
                "placement resource version is stale".to_string(),
            ));
        }
        Ok(version)
    }

    /// Requires an explicitly present proto3 optional placement field.
    fn required_placement_field<T>(value: Option<T>, name: &str) -> Result<T, RpcError> {
        value.ok_or_else(|| RpcError::invalid(format!("{name} must be specified")))
    }

    /// Maps typed placement-create failures without parsing SQL-driver text.
    fn placement_create_error(error: anyhow::Error) -> RpcError {
        let Some(failure) = crate::db::surface_placement_create_failure(&error) else {
            return RpcError::internal(error);
        };
        match failure.kind() {
            crate::db::SurfacePlacementCreateFailureKind::InvalidArgument => {
                RpcError::invalid(failure.public_message())
            }
            crate::db::SurfacePlacementCreateFailureKind::AlreadyExists => {
                RpcError::AlreadyExists(failure.public_message().to_string())
            }
            crate::db::SurfacePlacementCreateFailureKind::Conflict => {
                RpcError::FailedPrecondition(failure.public_message().to_string())
            }
        }
    }

    /// Returns a stable route-pin precondition without backend constraint text.
    fn placement_route_pin_error(
        blockers: crate::db::SurfacePlacementBlockers,
    ) -> Option<RpcError> {
        if blockers.direct_route {
            Some(RpcError::FailedPrecondition(
                "placement is pinned by a direct delivery route".to_string(),
            ))
        } else if blockers.routed_policy {
            Some(RpcError::FailedPrecondition(
                "placement is pinned by a delivery-route placement policy".to_string(),
            ))
        } else {
            None
        }
    }

    /// Returns the first stable metadata-deletion precondition.
    fn placement_delete_blocker_error(
        blockers: crate::db::SurfacePlacementBlockers,
    ) -> Option<RpcError> {
        if blockers.direct_route {
            Some(RpcError::FailedPrecondition(
                "placement is referenced by a direct delivery route".to_string(),
            ))
        } else if blockers.policy_member {
            Some(RpcError::FailedPrecondition(
                "placement is referenced by a placement policy".to_string(),
            ))
        } else if blockers.object_presence {
            Some(RpcError::FailedPrecondition(
                "placement has object-presence inventory".to_string(),
            ))
        } else if blockers.publication {
            Some(RpcError::FailedPrecondition(
                "placement has registry-publication state".to_string(),
            ))
        } else if blockers.deletion_job {
            Some(RpcError::FailedPrecondition(
                "placement has object-deletion jobs".to_string(),
            ))
        } else if blockers.topology_operation {
            Some(RpcError::FailedPrecondition(
                "placement has topology operations".to_string(),
            ))
        } else {
            None
        }
    }

    /// Builds the public placement message without exposing database identity
    /// or backend-specific shard configuration.
    async fn placement_message(
        &self,
        placement: crate::db::SurfacePlacementRecord,
    ) -> Result<pb::Placement, RpcError> {
        let binding = self
            .db
            .storage_binding(placement.storage_binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!(
                    "placement '{}' references missing storage binding {}",
                    placement.name,
                    placement.storage_binding_id
                ))
            })?;
        Ok(pb::Placement {
            name: placement.name,
            storage_binding_name: binding.name,
            prefix: placement.prefix,
            role: placement.role,
            state: placement.state,
            completeness: placement.completeness,
            read_enabled: placement.read_enabled,
            write_enabled: placement.write_enabled,
            read_order: placement.read_order,
            write_order: placement.write_order,
            created_at: placement.created_at,
            updated_at: placement.updated_at,
            resource_version: placement.resource_version.to_string(),
        })
    }

    /// `TopologyService.ListPlacements` — lists physical placements by stable name.
    ///
    /// Registry visibility and cache visibility use their existing read gates;
    /// private surfaces therefore require the same bearer authority as their
    /// other public read APIs.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidArgument`] for a missing surface or malformed
    /// page token, the surface's usual authentication/authorization errors,
    /// [`RpcError::NotFound`] for an unknown surface, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_placements(
        &self,
        auth: Option<&str>,
        req: pb::ListPlacementsRequest,
    ) -> Result<pb::ListPlacementsResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let records = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?;
        let mut placements = Vec::with_capacity(records.len());
        for record in records {
            placements.push(self.placement_message(record).await?);
        }
        let (placements, next_page_token) = paginate(placements, req.page_size, &req.page_token)?;
        Ok(pb::ListPlacementsResponse {
            placements,
            next_page_token,
        })
    }

    /// `TopologyService.GetPlacement` — reads one placement by surface-local name.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidArgument`] for a missing surface or empty
    /// placement name, the surface's usual authentication/authorization errors,
    /// [`RpcError::NotFound`] for an unknown surface or placement, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_placement(
        &self,
        auth: Option<&str>,
        req: pb::GetPlacementRequest,
    ) -> Result<pb::GetPlacementResponse, RpcError> {
        if req.name.is_empty() {
            return Err(RpcError::invalid("placement name must not be empty"));
        }
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let placement = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|placement| placement.name == req.name)
            .ok_or_else(|| RpcError::not_found("placement"))?;
        Ok(pb::GetPlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        })
    }

    /// `TopologyService.CreatePlacement` — creates one physical placement.
    ///
    /// Until IAM gains a dedicated topology verb, this requires the stronger
    /// [`Permission::StorageManage`] permission on the owning organization (or
    /// root [`Permission::IamAdmin`] for an org-less surface). Shards are not
    /// accepted until their partition rule has a typed public representation.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown surface or binding, [`RpcError::InvalidArgument`] for invalid
    /// placement fields, [`RpcError::AlreadyExists`] for a name collision,
    /// [`RpcError::FailedPrecondition`] for a physical-location or primary
    /// conflict, and [`RpcError::Internal`] for an unclassified database error.
    pub async fn create_placement(
        &self,
        auth: Option<&str>,
        req: pb::CreatePlacementRequest,
    ) -> Result<pb::CreatePlacementResponse, RpcError> {
        let (surface, org_id) = self.writable_topology_surface(auth, req.surface).await?;
        if req.name.is_empty() {
            return Err(RpcError::invalid("placement name must not be empty"));
        }
        if req.role == "shard" {
            return Err(RpcError::invalid(
                "shard placements require a future typed partition-rule API",
            ));
        }
        let read_enabled = Self::required_placement_field(req.read_enabled, "readEnabled")?;
        let write_enabled = Self::required_placement_field(req.write_enabled, "writeEnabled")?;
        let read_order = Self::required_placement_field(req.read_order, "readOrder")?;
        let write_order = Self::required_placement_field(req.write_order, "writeOrder")?;
        let binding_id = self
            .topology_binding_id(org_id, &req.storage_binding_name)
            .await?;
        let placement = self
            .db
            .create_surface_placement(&crate::db::NewSurfacePlacement {
                surface,
                name: req.name,
                storage_binding_id: binding_id,
                prefix: req.prefix,
                role: req.role,
                state: "provisioning".to_string(),
                completeness: "unknown".to_string(),
                partition_rule_json: None,
                read_enabled,
                write_enabled,
                read_order,
                write_order,
            })
            .await
            .map_err(Self::placement_create_error)?;
        Ok(pb::CreatePlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        })
    }

    /// `TopologyService.UpdatePlacement` — replaces desired selection fields.
    ///
    /// Observed state and completeness, role, binding, prefix, and any internal
    /// shard rule remain unchanged. Disabling read selection must use the drain
    /// workflow; changing write authority awaits atomic promotion. The database
    /// state machine validates the resulting record and performs the CAS.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown placement, [`RpcError::InvalidArgument`] for malformed fields
    /// or versions, and [`RpcError::FailedPrecondition`] for a stale CAS or a
    /// placement currently pinned by a delivery route.
    pub async fn update_placement(
        &self,
        auth: Option<&str>,
        req: pb::UpdatePlacementRequest,
    ) -> Result<pb::UpdatePlacementResponse, RpcError> {
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let current = self.topology_placement(surface, &req.name).await?;
        let expected = Self::expected_placement_version(&req.expected_resource_version, &current)?;
        let read_enabled = Self::required_placement_field(req.read_enabled, "readEnabled")?;
        let write_enabled = Self::required_placement_field(req.write_enabled, "writeEnabled")?;
        let read_order = Self::required_placement_field(req.read_order, "readOrder")?;
        let write_order = Self::required_placement_field(req.write_order, "writeOrder")?;
        if write_enabled != current.write_enabled {
            return Err(RpcError::FailedPrecondition(
                "write authority changes require atomic placement promotion".to_string(),
            ));
        }
        if current.role == "archive" && read_enabled {
            return Err(RpcError::invalid(
                "archive placements cannot be read-enabled",
            ));
        }
        if current.read_enabled && !read_enabled {
            return Err(RpcError::FailedPrecondition(
                "disabling read selection requires DrainPlacement".to_string(),
            ));
        }
        if !current.read_enabled
            && read_enabled
            && matches!(current.state.as_str(), "draining" | "offline")
        {
            return Err(RpcError::FailedPrecondition(
                "a draining or offline placement cannot be re-enabled by UpdatePlacement"
                    .to_string(),
            ));
        }
        let update = self
            .db
            .update_surface_placement(
                current.id,
                &crate::db::UpdateSurfacePlacement {
                    expected_version: expected,
                    state: current.state.clone(),
                    completeness: current.completeness.clone(),
                    partition_rule_json: current.partition_rule_json.clone(),
                    read_enabled,
                    write_enabled,
                    read_order,
                    write_order,
                },
            )
            .await;
        let placement = match update {
            Ok(placement) => placement,
            Err(error) => {
                let latest = self
                    .db
                    .surface_placement(current.id)
                    .await
                    .map_err(RpcError::internal)?;
                let Some(latest) = latest else {
                    return Err(RpcError::FailedPrecondition(
                        "placement changed during update".to_string(),
                    ));
                };
                if latest.resource_version != expected {
                    return Err(RpcError::FailedPrecondition(
                        "placement resource version is stale".to_string(),
                    ));
                }
                let blockers = self
                    .db
                    .surface_placement_blockers(current.id)
                    .await
                    .map_err(RpcError::internal)?;
                if let Some(error) = Self::placement_route_pin_error(blockers) {
                    return Err(error);
                }
                return Err(RpcError::internal(error));
            }
        };
        Ok(pb::UpdatePlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        })
    }

    /// `TopologyService.DrainPlacement` — plans or applies a safe drain.
    ///
    /// Applying revalidates the CAS and route pins, preserves completeness and
    /// ordering, then transitions a non-primary placement to `draining` and
    /// disables selection. A primary cannot be drained until a future atomic
    /// promotion API moves write authority elsewhere.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown placement, [`RpcError::InvalidArgument`] for a malformed
    /// version, and [`RpcError::FailedPrecondition`] for a primary or stale CAS.
    pub async fn drain_placement(
        &self,
        auth: Option<&str>,
        req: pb::DrainPlacementRequest,
    ) -> Result<pb::DrainPlacementResponse, RpcError> {
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let current = self.topology_placement(surface, &req.name).await?;
        let expected = Self::expected_placement_version(&req.expected_resource_version, &current)?;
        if current.role == "primary" {
            return Err(RpcError::FailedPrecondition(
                "a primary placement cannot drain before write authority is promoted".to_string(),
            ));
        }
        let blockers = self
            .db
            .surface_placement_blockers(current.id)
            .await
            .map_err(RpcError::internal)?;
        if let Some(error) = Self::placement_route_pin_error(blockers) {
            return Err(error);
        }
        let plan = pb::PlacementMutationPlan {
            operation: "drain".to_string(),
            placement_name: current.name.clone(),
            current_resource_version: current.resource_version.to_string(),
            effects: vec![
                "transition state to draining".to_string(),
                "disable read selection".to_string(),
                "disable write selection".to_string(),
            ],
        };
        if !req.apply {
            return Ok(pb::DrainPlacementResponse {
                plan: Some(plan),
                placement: Some(self.placement_message(current).await?),
                applied: false,
            });
        }
        let blockers = self
            .db
            .surface_placement_blockers(current.id)
            .await
            .map_err(RpcError::internal)?;
        if let Some(error) = Self::placement_route_pin_error(blockers) {
            return Err(error);
        }
        let drain = self
            .db
            .update_surface_placement(
                current.id,
                &crate::db::UpdateSurfacePlacement {
                    expected_version: expected,
                    state: "draining".to_string(),
                    completeness: current.completeness.clone(),
                    partition_rule_json: current.partition_rule_json.clone(),
                    read_enabled: false,
                    write_enabled: false,
                    read_order: current.read_order,
                    write_order: current.write_order,
                },
            )
            .await;
        let placement = match drain {
            Ok(placement) => placement,
            Err(error) => {
                let latest = self
                    .db
                    .surface_placement(current.id)
                    .await
                    .map_err(RpcError::internal)?;
                let Some(latest) = latest else {
                    return Err(RpcError::FailedPrecondition(
                        "placement changed during drain".to_string(),
                    ));
                };
                if latest.resource_version != expected {
                    return Err(RpcError::FailedPrecondition(
                        "placement resource version is stale".to_string(),
                    ));
                }
                let blockers = self
                    .db
                    .surface_placement_blockers(current.id)
                    .await
                    .map_err(RpcError::internal)?;
                if let Some(error) = Self::placement_route_pin_error(blockers) {
                    return Err(error);
                }
                return Err(RpcError::internal(error));
            }
        };
        Ok(pb::DrainPlacementResponse {
            plan: Some(plan),
            placement: Some(self.placement_message(placement).await?),
            applied: true,
        })
    }

    /// `TopologyService.DeletePlacement` — plans or applies metadata deletion.
    ///
    /// The backing objects are deliberately left intact. Plan and apply reject
    /// primary placements and placements referenced by routes, policies,
    /// object inventory, publications, jobs, or operations. Apply revalidates
    /// those references and the CAS immediately before the guarded delete.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown placement, [`RpcError::InvalidArgument`] for a malformed
    /// version, and [`RpcError::FailedPrecondition`] when deletion is unsafe or
    /// the resource-version CAS is stale.
    pub async fn delete_placement(
        &self,
        auth: Option<&str>,
        req: pb::DeletePlacementRequest,
    ) -> Result<pb::DeletePlacementResponse, RpcError> {
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let current = self.topology_placement(surface, &req.name).await?;
        let expected = Self::expected_placement_version(&req.expected_resource_version, &current)?;
        if current.role == "primary" {
            return Err(RpcError::FailedPrecondition(
                "a primary placement cannot be deleted".to_string(),
            ));
        }
        let blockers = self
            .db
            .surface_placement_blockers(current.id)
            .await
            .map_err(RpcError::internal)?;
        if let Some(error) = Self::placement_delete_blocker_error(blockers) {
            return Err(error);
        }
        let plan = pb::PlacementMutationPlan {
            operation: "delete".to_string(),
            placement_name: current.name.clone(),
            current_resource_version: current.resource_version.to_string(),
            effects: vec![
                "remove placement topology metadata".to_string(),
                "leave backing storage objects unchanged".to_string(),
            ],
        };
        if !req.apply {
            return Ok(pb::DeletePlacementResponse {
                plan: Some(plan),
                applied: false,
            });
        }
        let blockers = self
            .db
            .surface_placement_blockers(current.id)
            .await
            .map_err(RpcError::internal)?;
        if let Some(error) = Self::placement_delete_blocker_error(blockers) {
            return Err(error);
        }
        let deleted = match self.db.delete_surface_placement(current.id, expected).await {
            Ok(deleted) => deleted,
            Err(error) => {
                let blockers = self
                    .db
                    .surface_placement_blockers(current.id)
                    .await
                    .map_err(RpcError::internal)?;
                if let Some(error) = Self::placement_delete_blocker_error(blockers) {
                    return Err(error);
                }
                return Err(RpcError::internal(error));
            }
        };
        if !deleted {
            let latest = self
                .db
                .surface_placement(current.id)
                .await
                .map_err(RpcError::internal)?;
            if latest.is_some_and(|latest| latest.resource_version != expected) {
                return Err(RpcError::FailedPrecondition(
                    "placement resource version is stale".to_string(),
                ));
            }
            return Err(RpcError::FailedPrecondition(
                "placement deletion preconditions changed".to_string(),
            ));
        }
        Ok(pb::DeletePlacementResponse {
            plan: Some(plan),
            applied: true,
        })
    }

    /// `AuditService.ListAudit` — recent audit entries at a scope, newest first.
    ///
    /// The caller must hold [`Permission::AuditRead`] (admin+) on the queried
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read` on the
    /// scope, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_audit(
        &self,
        auth: Option<&str>,
        req: pb::ListAuditRequest,
    ) -> Result<pb::ListAuditResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&req.scope);
        self.require_permission(&claims, Permission::AuditRead, &scope)
            .await?;
        let entries: Vec<pb::AuditEntry> = self
            .db
            .list_audit(&req.scope)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|row| pb::AuditEntry {
                change_id: row.change_id.unwrap_or_default(),
                actor_label: row.actor_label,
                action: row.action,
                scope: row.scope,
                result_commit: row.result_commit.unwrap_or_default(),
                result_tag: row.result_tag.unwrap_or_default(),
                detail: row.detail.unwrap_or_default(),
                created_at: row.created_at,
            })
            .collect();
        let (entries, next_page_token) = paginate(entries, req.page_size, &req.page_token)?;
        Ok(pb::ListAuditResponse {
            entries,
            next_page_token,
        })
    }

    /// `InstanceService.GetInstanceSettings` — the full editable instance
    /// settings bundle (branding, footer, identity policy, serving defaults).
    ///
    /// The machine mirror of the `/-/instance` console: every field carries its
    /// effective value (a stored override or the documented default). Requires
    /// [`Permission::IamAdmin`] at the instance root, the same authority the
    /// console enforces.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller is not an instance admin,
    /// and [`RpcError::Internal`] on database failure.
    pub async fn get_instance_settings(
        &self,
        auth: Option<&str>,
        _req: pb::GetInstanceSettingsRequest,
    ) -> Result<pb::GetInstanceSettingsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;
        let settings = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetInstanceSettingsResponse {
            settings: Some(instance_settings_to_pb(&settings)),
        })
    }

    /// `InstanceService.UpdateInstanceSettings` — set and/or clear instance
    /// settings keys, then return the updated bundle.
    ///
    /// Each entry in `values` is validated per key (an unknown key, or a value
    /// outside the allowed set for `signup_policy`/`default_crawl_policy`/the
    /// numeric keys, is rejected before any write) and then applied through
    /// [`Database::set_instance_config`] — a blank value, or any key listed in
    /// `clear`, resets that key to its default. The whole update is audited at
    /// the instance root and the resulting bundle is returned. Requires
    /// [`Permission::IamAdmin`] at the instance root.
    ///
    /// Note that branding/footer changes are seeded into each shell's page
    /// chrome at startup (and refreshed live by the console on save); a change
    /// made over this RPC takes effect on the next chrome refresh for already
    /// running shells.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller is not an instance admin,
    /// [`RpcError::InvalidArgument`] for an unknown key or an invalid value, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn update_instance_settings(
        &self,
        auth: Option<&str>,
        req: pb::UpdateInstanceSettingsRequest,
    ) -> Result<pb::UpdateInstanceSettingsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;

        // Validate every key/value before writing anything, so a bad entry never
        // leaves a partially applied update.
        let mut writes: Vec<(String, Option<String>)> = Vec::new();
        for (key, value) in &req.values {
            let normalized = normalize_instance_value(key, value)?;
            writes.push((key.clone(), normalized));
        }
        for key in &req.clear {
            if !is_instance_key(key) {
                return Err(RpcError::invalid(format!(
                    "unknown instance setting: {key}"
                )));
            }
            writes.push((key.clone(), None));
        }

        for (key, value) in &writes {
            self.db
                .set_instance_config(key, value.as_deref())
                .await
                .map_err(RpcError::internal)?;
        }

        // Audit the change at the instance root, listing the touched keys.
        let principal = claims_principal(&claims);
        let actor_id = principal.as_ref().map(|p| p.id);
        let actor_kind = claims.owner_kind.clone();
        let actor_label = claims.sub.clone();
        let mut touched: Vec<&str> = writes.iter().map(|(k, _)| k.as_str()).collect();
        touched.sort_unstable();
        touched.dedup();
        let detail = touched.join(", ");
        if let Err(err) = self
            .db
            .record_audit(
                &actor_kind,
                actor_id,
                &actor_label,
                "instance.settings",
                "",
                None,
                None,
                None,
                Some(&detail),
            )
            .await
        {
            tracing::warn!(error = %format!("{err:#}"), "recording instance.settings audit");
        }

        let settings = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::UpdateInstanceSettingsResponse {
            settings: Some(instance_settings_to_pb(&settings)),
        })
    }

    /// `IdentityService.CreateServiceAccount` — create (or return) an org-owned
    /// service account, a non-human principal for CI/automation.
    ///
    /// Idempotent: returns the existing account when one of that name already
    /// exists in the org. Requires [`Permission::IamAdmin`] at the org scope (or
    /// the instance root) — the same authority the console enforces.
    ///
    /// # Errors
    ///
    /// [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller is not an org/instance
    /// admin, [`RpcError::InvalidArgument`] for an unknown org, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn create_service_account(
        &self,
        auth: Option<&str>,
        req: pb::CreateServiceAccountRequest,
    ) -> Result<pb::CreateServiceAccountResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::invalid(format!("no org '{}'", req.org_slug)))?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&req.org_slug))
            .await?;
        let id = match self
            .db
            .service_account_by_name(org.id, &req.name)
            .await
            .map_err(RpcError::internal)?
        {
            Some(id) => id,
            None => self
                .db
                .create_service_account(org.id, &req.name)
                .await
                .map_err(RpcError::internal)?,
        };
        Ok(pb::CreateServiceAccountResponse {
            service_account: Some(pb::ServiceAccount {
                id,
                org_slug: req.org_slug,
                name: req.name,
            }),
        })
    }

    /// Resolves a principal reference to its numeric id.
    ///
    /// A `"user"` ref is an email (created on first reference, matching the
    /// invite/grant flow); a `"service_account"` ref is `"<org>/<name>"` and must
    /// already exist.
    ///
    /// # Errors
    ///
    /// [`RpcError::InvalidArgument`] for an unknown kind, a malformed
    /// service-account ref, or an unknown org/service account; [`RpcError::Internal`]
    /// on database failure.
    async fn resolve_principal_id(&self, kind: &str, principal_ref: &str) -> Result<i64, RpcError> {
        match kind {
            "user" => self
                .db
                .find_or_create_user(principal_ref)
                .await
                .map_err(RpcError::internal),
            "service_account" => {
                let (org_slug, name) = principal_ref.split_once('/').ok_or_else(|| {
                    RpcError::invalid("service_account ref must be '<org>/<name>'")
                })?;
                let org = self
                    .db
                    .org_by_slug(org_slug)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::invalid(format!("no org '{org_slug}'")))?;
                self.db
                    .service_account_by_name(org.id, name)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::invalid(format!("no service account '{principal_ref}'"))
                    })
            }
            other => Err(RpcError::invalid(format!(
                "unknown principal kind '{other}'"
            ))),
        }
    }

    /// `IdentityService.GrantMembership` — grant a role to a principal at a scope.
    ///
    /// Requires [`Permission::IamAdmin`] at the target scope.
    ///
    /// # Errors
    ///
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] on auth,
    /// [`RpcError::InvalidArgument`] for an unknown role/principal, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn grant_membership(
        &self,
        auth: Option<&str>,
        req: pb::GrantMembershipRequest,
    ) -> Result<pb::GrantMembershipResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&req.scope);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let role = Role::parse(&req.role)
            .ok_or_else(|| RpcError::invalid(format!("unknown role '{}'", req.role)))?;
        let principal_id = self
            .resolve_principal_id(&req.principal_kind, &req.principal_ref)
            .await?;
        self.db
            .grant_membership(
                &req.principal_kind,
                principal_id,
                scope.as_str(),
                role.as_str(),
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GrantMembershipResponse {})
    }

    /// `IdentityService.RevokeMembership` — revoke a principal's grant at a scope
    /// (a no-op when none exists). Requires [`Permission::IamAdmin`] at the scope.
    ///
    /// # Errors
    ///
    /// Auth errors as [`grant_membership`](Self::grant_membership);
    /// [`RpcError::Internal`] on database failure.
    pub async fn revoke_membership(
        &self,
        auth: Option<&str>,
        req: pb::RevokeMembershipRequest,
    ) -> Result<pb::RevokeMembershipResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&req.scope);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let principal_id = self
            .resolve_principal_id(&req.principal_kind, &req.principal_ref)
            .await?;
        self.db
            .revoke_membership(&req.principal_kind, principal_id, scope.as_str())
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::RevokeMembershipResponse {})
    }

    /// `IdentityService.MintToken` — mint a registry-scoped bearer token for `owner`.
    ///
    /// The token's permissions are intersected with the **owner's** effective
    /// grants at the scope, so a token can never exceed its owner's authority.
    /// The secret is returned exactly once. Requires [`Permission::IamAdmin`] at
    /// the scope.
    ///
    /// # Errors
    ///
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] on auth,
    /// [`RpcError::InvalidArgument`] for a malformed owner or unknown permission,
    /// and [`RpcError::Internal`] on database failure.
    pub async fn mint_token(
        &self,
        auth: Option<&str>,
        req: pb::MintTokenRequest,
    ) -> Result<pb::MintTokenResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&req.scope);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let (kind, principal_ref) = req.owner.split_once(':').ok_or_else(|| {
            RpcError::invalid("owner must be 'user:<email>' or 'service_account:<org>/<name>'")
        })?;
        let owner_id = self.resolve_principal_id(kind, principal_ref).await?;
        let owner = match kind {
            "user" => crate::domain::Principal::user(owner_id),
            "service_account" => crate::domain::Principal::service_account(owner_id),
            other => return Err(RpcError::invalid(format!("unknown owner kind '{other}'"))),
        };
        let mut perms = Vec::new();
        for verb in &req.permissions {
            let perm = crate::auth::permission_from_str(verb)
                .ok_or_else(|| RpcError::invalid(format!("unknown permission '{verb}'")))?;
            perms.push(perm);
        }
        // A token can never exceed its owner's authority.
        let grants = self
            .db
            .effective_scopes(owner)
            .await
            .map_err(RpcError::internal)?;
        perms.retain(|p| iam::allow(&grants, *p, &scope));
        let (token_id, secret) = self
            .db
            .create_token(
                owner,
                scope.as_str(),
                &perms,
                Some("minted via IdentityService"),
                None,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::MintTokenResponse { token_id, secret })
    }

    /// `IdentityService.RevokeToken` — revoke a token by id.
    ///
    /// Requires [`Permission::IamAdmin`] at the instance root (an instance admin
    /// may revoke any token); per-owner self-revoke remains the console's path.
    ///
    /// # Errors
    ///
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] on auth;
    /// [`RpcError::Internal`] on database failure.
    pub async fn revoke_token(
        &self,
        auth: Option<&str>,
        req: pb::RevokeTokenRequest,
    ) -> Result<pb::RevokeTokenResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;
        self.db
            .revoke_token(&req.token_id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::RevokeTokenResponse {})
    }

    /// `IdentityService.ListTokens` — the caller's own active tokens, filtered to
    /// `scope` (empty `scope` lists all).
    ///
    /// # Errors
    ///
    /// [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT;
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_tokens(
        &self,
        auth: Option<&str>,
        req: pb::ListTokensRequest,
    ) -> Result<pb::ListTokensResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let principal = claims_principal(&claims).ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("bearer claims carry no principal"))
        })?;
        let want = Scope::parse(&req.scope);
        let rows = self
            .db
            .list_tokens_for(principal)
            .await
            .map_err(RpcError::internal)?;
        let owner = format!("{}:{}", principal.kind.as_str(), principal.id);
        let tokens = rows
            .into_iter()
            .filter(|(_, scope, _)| req.scope.is_empty() || Scope::parse(scope) == want)
            .map(|(token_id, scope, perms)| pb::TokenInfo {
                token_id,
                owner: owner.clone(),
                scope,
                permissions: perms.iter().map(|p| p.as_str().to_string()).collect(),
                created_at: 0,
                expires_at: 0,
            })
            .collect();
        Ok(pb::ListTokensResponse { tokens })
    }

    /// `RegistryConfigurationService.ListChangesets` — change-sets at a scope, newest first.
    ///
    /// Reads require [`Permission::AuditRead`] on the scope (RegistryConfigurationService
    /// reads are an admin+ surface, same as the audit feed).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read` on the
    /// scope, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_changesets(
        &self,
        auth: Option<&str>,
        req: pb::ListChangesetsRequest,
    ) -> Result<pb::ListChangesetsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = Scope::parse(&req.scope);
        self.require_permission(&claims, Permission::AuditRead, &scope)
            .await?;
        let changesets: Vec<pb::Changeset> = self
            .db
            .list_changesets(&req.scope)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(changeset_message)
            .collect();
        let (changesets, next_page_token) = paginate(changesets, req.page_size, &req.page_token)?;
        Ok(pb::ListChangesetsResponse {
            changesets,
            next_page_token,
        })
    }

    /// `RegistryConfigurationService.GetChangeset` — one change-set's revisions and diffs.
    ///
    /// Loads the change-set summary plus its revisions, each rendered with the
    /// field-level diff [`crate::config::semantic_diff`] produces (the
    /// terraform-plan review view). Reads require [`Permission::AuditRead`] on
    /// the change-set's recorded scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown `change_id`,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read` on the
    /// change-set's scope, and [`RpcError::Internal`] on database failure.
    pub async fn get_changeset(
        &self,
        auth: Option<&str>,
        req: pb::GetChangesetRequest,
    ) -> Result<pb::GetChangesetResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let summary = self
            .db
            .changeset(&req.change_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("changeset"))?;
        self.require_permission(
            &claims,
            Permission::AuditRead,
            &Scope::parse(&summary.scope),
        )
        .await?;
        let change_id = crate::config::ChangeId(summary.change_id.clone());
        let revisions: Vec<pb::Revision> = crate::config::review(&self.db, &change_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|(revision, diffs)| pb::Revision {
                object_type: revision.object_type,
                object_id: revision.object_id,
                op: revision.op.as_str().to_string(),
                diffs: diffs
                    .into_iter()
                    .map(|d| pb::FieldDiff {
                        field: d.field,
                        old: d.old.unwrap_or_default(),
                        new: d.new.unwrap_or_default(),
                    })
                    .collect(),
            })
            .collect();
        Ok(pb::GetChangesetResponse {
            changeset: Some(changeset_message(summary)),
            revisions,
        })
    }

    /// `WebhookService.ListWebhooks` — an org's webhook subscriptions.
    ///
    /// Secrets are omitted. Requires [`Permission::MembersManage`] on the org
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `members.manage` on
    /// the org, [`RpcError::NotFound`] for an unknown org, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_webhooks(
        &self,
        auth: Option<&str>,
        req: pb::ListWebhooksRequest,
    ) -> Result<pb::ListWebhooksResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(&claims, Permission::MembersManage, &Scope::parse(&org.slug))
            .await?;
        let webhooks: Vec<pb::Webhook> = self
            .db
            .list_webhooks(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|w| pb::Webhook {
                id: w.id,
                org_slug: org.slug.clone(),
                url: w.url,
                events: w.events,
                active: w.active,
                created_at: w.created_at,
            })
            .collect();
        Ok(pb::ListWebhooksResponse { webhooks })
    }

    /// `RegistryService.CreateRegistry` — create an org-owned, storage-bound
    /// managed registry (phase 2c write path).
    ///
    /// The registry is created at the canonical path `{org}/{project_path}/{name}`
    /// with the given visibility, optionally bound to a named storage binding
    /// plus prefix, and indexed lazily by the background re-indexer. Requires
    /// [`Permission::RegistryConfigure`] on the org scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `registry.configure`
    /// on the org scope, [`RpcError::NotFound`] for an unknown org or
    /// `binding_name`, [`RpcError::InvalidArgument`] for a missing name or bad
    /// visibility, [`RpcError::AlreadyExists`] when a registry occupies the
    /// canonical path, and [`RpcError::Internal`] on database failure.
    pub async fn create_registry(
        &self,
        auth: Option<&str>,
        req: pb::CreateRegistryRequest,
    ) -> Result<pb::CreateRegistryResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.slug),
        )
        .await?;
        if req.name.is_empty() {
            return Err(RpcError::invalid("registry name is required"));
        }
        let visibility = match req.visibility.as_str() {
            "" => "private",
            v @ ("public" | "internal" | "private") => v,
            other => return Err(RpcError::invalid(format!("invalid visibility '{other}'"))),
        };
        let binding_id = if req.binding_name.is_empty() {
            None
        } else {
            Some(
                self.db
                    .storage_binding_by_name(org.id, &req.binding_name)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("storage binding"))?
                    .id,
            )
        };
        let id = self
            .db
            .create_managed_registry(
                org.id,
                &req.project_path,
                &req.name,
                visibility,
                binding_id,
                &req.prefix,
                &req.trust_keys,
                true,
            )
            .await
            .map_err(|e| RpcError::AlreadyExists(format!("{e:#}")))?;
        let mut record = self
            .db
            .registry_by_scope(&org.slug, &req.project_path, &req.name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("registry {id} vanished after creation"))
            })?;
        // Seed the new registry's crawl policy from the instance default when the
        // operator has set one other than the built-in `allow_all`. New
        // registries inherit the instance posture (e.g. an AI-averse instance
        // defaulting to `allow_no_ai`); a per-registry override can be applied
        // later via `set_crawl_policy`.
        if let Some(default) = self
            .db
            .instance_config_get("default_crawl_policy")
            .await
            .map_err(RpcError::internal)?
        {
            if let Ok(policy) = crate::crawl::CrawlPolicy::parse(&default) {
                if policy.as_str() != record.crawl_policy {
                    self.db
                        .set_registry_crawl_policy(&record.slug, policy.as_str())
                        .await
                        .map_err(RpcError::internal)?;
                    record.crawl_policy = policy.as_str().to_string();
                }
            }
        }
        let status = self
            .db
            .index_status(record.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::CreateRegistryResponse {
            registry: Some(self.registry_message(&record, status).await?),
        })
    }

    /// Set a registry's crawl policy through an audited change-set.
    ///
    /// Mirrors the visibility write path: resolves the registry, validates the
    /// policy string against [`CrawlPolicy`](crate::crawl::CrawlPolicy),
    /// authorizes [`Permission::RegistryConfigure`] at the registry scope, then
    /// applies [`change_registry_crawl_policy`](crate::config::change_registry_crawl_policy).
    /// The applied policy is echoed back.
    ///
    /// # Errors
    ///
    /// [`RpcError::InvalidArgument`] for an unknown policy, [`RpcError::NotFound`]
    /// for an absent registry, an auth error without
    /// [`Permission::RegistryConfigure`], and [`RpcError::Internal`] on failure.
    pub async fn set_crawl_policy(
        &self,
        auth: Option<&str>,
        req: pb::SetCrawlPolicyRequest,
    ) -> Result<pb::SetCrawlPolicyResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let policy = crate::crawl::CrawlPolicy::parse(&req.policy)
            .map_err(|e| RpcError::invalid(e.to_string()))?;
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&registry.slug),
        )
        .await?;
        let actor = claims_principal(&claims)
            .ok_or_else(|| RpcError::Unauthenticated("missing principal".into()))?;
        crate::config::change_registry_crawl_policy(
            &self.db,
            &actor,
            &claims.sub,
            registry.id,
            policy.as_str(),
        )
        .await
        .map_err(RpcError::internal)?;
        Ok(pb::SetCrawlPolicyResponse {
            policy: policy.as_str().to_string(),
        })
    }

    /// `RegistryService.ChangeRegistryStorage` — migrate a registry's surface to
    /// a different storage backend.
    ///
    /// Resolves the target binding (empty name = the deployment default), then
    /// runs the shared [`migrate_registry_storage`](crate::migrate::migrate_registry_storage)
    /// — the exact copy-then-repoint-then-reindex the web console invokes, so the
    /// machine and human paths cannot drift.
    ///
    /// # Errors
    ///
    /// Auth errors; [`RpcError::NotFound`] for an unknown registry;
    /// [`RpcError::InvalidArgument`] for an unknown binding, an org-less
    /// registry, a no-op move, or a surface that cannot be enumerated.
    pub async fn change_registry_storage(
        &self,
        auth: Option<&str>,
        req: pb::ChangeRegistryStorageRequest,
    ) -> Result<pb::ChangeRegistryStorageResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&registry.slug),
        )
        .await?;
        let new_binding_id = self
            .resolve_storage_binding(registry.org_id, &req.binding_name)
            .await?;
        let stats = crate::migrate::migrate_registry_storage(
            &self.db,
            self.surface.as_ref(),
            self.surface_write.as_ref(),
            self.reindexer.as_ref(),
            &registry,
            new_binding_id,
        )
        .await
        .map_err(|err| RpcError::invalid(format!("{err:#}")))?;
        Ok(pb::ChangeRegistryStorageResponse {
            objects: stats.objects as u64,
            bytes: stats.bytes,
        })
    }

    /// Resolve a storage-binding name to its id within `org_id`.
    ///
    /// An empty name resolves to `None` (the deployment default store).
    ///
    /// # Errors
    ///
    /// [`RpcError::InvalidArgument`] when a non-empty name names no binding in
    /// the org, or when the resource has no org; [`RpcError::Internal`] on a DB
    /// failure.
    async fn resolve_storage_binding(
        &self,
        org_id: Option<i64>,
        name: &str,
    ) -> Result<Option<i64>, RpcError> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(None);
        }
        let org_id =
            org_id.ok_or_else(|| RpcError::invalid("resource has no organization".to_string()))?;
        let binding = self
            .db
            .storage_binding_by_name(org_id, name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::invalid(format!("unknown storage binding '{name}'")))?;
        Ok(Some(binding.id))
    }

    // -- BinaryCacheService (RFC-0004 "11-caches") ---------------------------------

    /// Resolve a managed cache by slug or map a miss to `NotFound`.
    async fn cache_or_not_found(&self, slug: &str) -> Result<crate::db::Cache, RpcError> {
        self.db
            .cache_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache"))
    }

    /// Authorize a cache write: `registry.configure` on the owning org, or
    /// `iam.admin` on root for an instance-level cache.
    async fn require_cache_admin(
        &self,
        auth: Option<&str>,
        org_id: Option<i64>,
    ) -> Result<(), RpcError> {
        let claims = self.require_claims(auth)?;
        match org_id {
            Some(id) => {
                // A tombstoned (soft-deleted) org stops accepting mutations to
                // its caches, mirroring the registry write path's `resolve_writable`
                // → `org_is_active` gate. Without this, a cache under a deleted
                // org would keep accepting uploads and charge its quota.
                if !self
                    .db
                    .org_is_active(id)
                    .await
                    .map_err(RpcError::internal)?
                {
                    return Err(RpcError::not_found("cache"));
                }
                let org = self
                    .db
                    .org_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("org"))?;
                self.require_permission(
                    &claims,
                    Permission::RegistryConfigure,
                    &Scope::parse(&org.slug),
                )
                .await
            }
            None => {
                self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
                    .await
            }
        }
    }

    /// Authorize a cache read: public caches are open; otherwise `read` on the
    /// owning org (or `iam.admin` on root for a private instance-level cache).
    async fn require_cache_read(
        &self,
        auth: Option<&str>,
        cache: &crate::db::Cache,
    ) -> Result<(), RpcError> {
        // A soft-deleted (tombstoned) cache is invisible to reads — symmetric
        // with `list_caches`, which filters `deleted_at`, and with the facade.
        // Unconditional: a standalone cache (org_id = None) has no org-activity
        // check to fall back on, and registries rely on org-level soft-delete
        // only (they carry no per-row tombstone), so this guard is cache-specific.
        if cache.deleted_at.is_some() {
            return Err(RpcError::not_found("cache"));
        }
        if let Some(org_id) = cache.org_id {
            if !self
                .db
                .org_is_active(org_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::not_found("cache"));
            }
        }
        if cache.visibility == "public" {
            return Ok(());
        }
        let claims = self.require_claims(auth)?;
        match cache.org_id {
            Some(id) => {
                let org = self
                    .db
                    .org_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("cache"))?;
                self.require_permission(&claims, Permission::Read, &Scope::parse(&org.slug))
                    .await
            }
            None => {
                self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
                    .await
            }
        }
    }

    /// Authorize a cache machine read while rechecking cache liveness.
    async fn require_cache_stream_read(
        &self,
        auth: ReadAuthorization<'_>,
        cache: &crate::db::Cache,
    ) -> Result<(), RpcError> {
        match auth {
            ReadAuthorization::AuthorizationHeader(header) => {
                self.require_cache_read(header, cache).await
            }
            ReadAuthorization::PreauthorizedSession => {
                if cache.deleted_at.is_some() {
                    return Err(RpcError::not_found("cache"));
                }
                if let Some(org_id) = cache.org_id {
                    if !self
                        .db
                        .org_is_active(org_id)
                        .await
                        .map_err(RpcError::internal)?
                    {
                        return Err(RpcError::not_found("cache"));
                    }
                }
                Ok(())
            }
        }
    }

    /// Build the wire [`pb::ManagedCache`] for a cache record, resolving its org
    /// slug and binding name; `stats` folds in usage/link/root counts.
    async fn managed_cache_message(
        &self,
        c: &crate::db::Cache,
        stats: bool,
    ) -> Result<pb::ManagedCache, RpcError> {
        let org_slug = match c.org_id {
            Some(id) => self
                .db
                .org_by_id(id)
                .await
                .map_err(RpcError::internal)?
                .map(|o| o.slug)
                .unwrap_or_default(),
            None => String::new(),
        };
        // A binding-less cache uses the deployment's default storage; its wire
        // `binding_name` is empty (the client renders it as "default").
        let binding_name = match c.storage_binding_id {
            Some(id) => self
                .db
                .storage_binding(id)
                .await
                .map_err(RpcError::internal)?
                .map(|b| b.name)
                .unwrap_or_default(),
            None => String::new(),
        };
        let (used_bytes, object_count, link_count, root_count) = if stats {
            let u = self
                .db
                .cache_usage(c.id)
                .await
                .map_err(RpcError::internal)?;
            let links = self
                .db
                .list_cache_links(c.id)
                .await
                .map_err(RpcError::internal)?
                .len() as i64;
            let roots = self
                .db
                .list_cache_roots(c.id)
                .await
                .map_err(RpcError::internal)?
                .len() as i64;
            (u.used_bytes, u.object_count, links, roots)
        } else {
            (0, 0, 0, 0)
        };
        Ok(pb::ManagedCache {
            slug: c.slug.clone(),
            name: c.name.clone(),
            org_slug,
            binding_name,
            prefix: c.prefix.clone(),
            visibility: c.visibility.clone(),
            priority: c.priority,
            compression: c.compression.clone(),
            want_mass_query: c.want_mass_query,
            signed: c.hosted_key_id.is_some(),
            created_at: c.created_at,
            used_bytes,
            object_count,
            link_count,
            root_count,
        })
    }

    /// `BinaryCacheService.CreateCache` — create an org-owned managed cache.
    ///
    /// An empty `binding_name` uses the deployment's default storage (the
    /// binding-less path); otherwise the named storage binding backs the cache.
    ///
    /// # Errors
    ///
    /// [`RpcError::InvalidArgument`] for a missing slug/org or bad
    /// visibility, [`RpcError::NotFound`] for an unknown org/binding,
    /// [`RpcError::PermissionDenied`] without `registry.configure`,
    /// [`RpcError::AlreadyExists`] for a duplicate slug, [`RpcError::Internal`]
    /// on database failure.
    pub async fn create_cache(
        &self,
        auth: Option<&str>,
        req: pb::CreateCacheRequest,
    ) -> Result<pb::CreateCacheResponse, RpcError> {
        if req.slug.is_empty() {
            return Err(RpcError::invalid("cache slug is required"));
        }
        if req.org_slug.is_empty() {
            return Err(RpcError::invalid("org_slug is required to create a cache"));
        }
        // An empty `binding_name` means the deployment's default storage (the
        // binding-less path) — exactly as a registry with no binding.
        let visibility = match req.visibility.as_str() {
            "" => "private",
            v @ ("public" | "internal" | "private") => v,
            other => return Err(RpcError::invalid(format!("invalid visibility '{other}'"))),
        };
        // Validate the prefix here so a malformed one is a 400 (the DB's bail!
        // would otherwise be folded into the duplicate-slug AlreadyExists below).
        if !req.prefix.is_empty() {
            let rel = std::path::Path::new(&req.prefix);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|comp| !matches!(comp, std::path::Component::Normal(_)))
            {
                return Err(RpcError::invalid(format!(
                    "cache prefix '{}' must be a relative path with no '..' components",
                    req.prefix
                )));
            }
        }
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_cache_admin(auth, Some(org.id)).await?;
        let binding_id = if req.binding_name.is_empty() {
            None
        } else {
            Some(
                self.db
                    .storage_binding_by_name(org.id, &req.binding_name)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("storage binding"))?
                    .id,
            )
        };
        let name = if req.name.is_empty() {
            &req.slug
        } else {
            &req.name
        };
        let priority = if req.priority == 0 { 40 } else { req.priority };
        let compression = if req.compression.is_empty() {
            "zstd"
        } else {
            &req.compression
        };
        let id = self
            .db
            .create_cache(
                Some(org.id),
                &req.slug,
                name,
                binding_id,
                &req.prefix,
                None,
                visibility,
                priority,
                compression,
                req.want_mass_query,
            )
            .await
            .map_err(|e| RpcError::AlreadyExists(format!("{e:#}")))?;
        let c = self
            .db
            .cache_by_id(id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("cache {id} vanished after creation"))
            })?;
        Ok(pb::CreateCacheResponse {
            cache: Some(self.managed_cache_message(&c, true).await?),
        })
    }

    /// `BinaryCacheService.GetCache` — a cache's configuration + usage.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors for a non-public
    /// cache read without authority, [`RpcError::Internal`] on database failure.
    pub async fn get_cache(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheRequest,
    ) -> Result<pb::GetCacheResponse, RpcError> {
        let c = self.cache_or_not_found(&req.slug).await?;
        self.require_cache_read(auth, &c).await?;
        Ok(pb::GetCacheResponse {
            cache: Some(self.managed_cache_message(&c, true).await?),
        })
    }

    /// `BinaryCacheService.ListCaches` — servable caches, visibility-filtered.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown `org_slug` filter,
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_caches(
        &self,
        auth: Option<&str>,
        req: pb::ListCachesRequest,
    ) -> Result<pb::ListCachesResponse, RpcError> {
        let all = if req.org_slug.is_empty() {
            self.db.list_caches().await.map_err(RpcError::internal)?
        } else {
            let org = self.org_or_not_found(&req.org_slug).await?;
            self.db
                .list_caches_for_org(org.id)
                .await
                .map_err(RpcError::internal)?
        };
        // `list_caches_for_org` is the unfiltered admin/export view; exclude
        // soft-deleted caches here so the API matches the global listing.
        let all: Vec<_> = all.into_iter().filter(|c| c.deleted_at.is_none()).collect();
        let mut out = Vec::new();
        for c in &all {
            // Surface public caches to everyone; gate the rest on read authority.
            if c.visibility == "public" || self.require_cache_read(auth, c).await.is_ok() {
                out.push(self.managed_cache_message(c, false).await?);
            }
        }
        Ok(pb::ListCachesResponse { caches: out })
    }

    /// `BinaryCacheService.UpdateCache` — update a cache's mutable fields.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, [`RpcError::InvalidArgument`]
    /// for a bad visibility, auth errors, [`RpcError::Internal`] on failure.
    pub async fn update_cache(
        &self,
        auth: Option<&str>,
        req: pb::UpdateCacheRequest,
    ) -> Result<pb::UpdateCacheResponse, RpcError> {
        let c = self.cache_or_not_found(&req.slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        // Partial update: an omitted field keeps the current value.
        let visibility = match req.visibility {
            Some(v) => match v.as_str() {
                "public" | "internal" | "private" => v,
                other => {
                    return Err(RpcError::invalid(format!("invalid visibility '{other}'")));
                }
            },
            None => c.visibility.clone(),
        };
        let name = req.name.unwrap_or_else(|| c.name.clone());
        let priority = req.priority.unwrap_or(c.priority);
        let compression = req.compression.unwrap_or_else(|| c.compression.clone());
        let want_mass_query = req.want_mass_query.unwrap_or(c.want_mass_query);
        self.db
            .update_cache(
                c.id,
                &name,
                &visibility,
                priority,
                &compression,
                want_mass_query,
                c.hosted_key_id,
            )
            .await
            .map_err(RpcError::internal)?;
        let c = self.cache_or_not_found(&req.slug).await?;
        Ok(pb::UpdateCacheResponse {
            cache: Some(self.managed_cache_message(&c, true).await?),
        })
    }

    /// `BinaryCacheService.DeleteCache` — soft- or hard-delete a cache.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn delete_cache(
        &self,
        auth: Option<&str>,
        req: pb::DeleteCacheRequest,
    ) -> Result<pb::DeleteCacheResponse, RpcError> {
        let c = self.cache_or_not_found(&req.slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        let deleted = if req.hard {
            self.db
                .delete_cache(c.id)
                .await
                .map_err(RpcError::internal)?
        } else {
            let grace = if req.grace_secs == 0 {
                30 * 86_400
            } else {
                req.grace_secs
            };
            let now = crate::clock::now_unix_secs();
            self.db
                .soft_delete_cache(c.id, now + grace)
                .await
                .map_err(RpcError::internal)?
        };
        Ok(pb::DeleteCacheResponse { deleted })
    }

    /// The consumer-facing base URL for a registry's git surface.
    ///
    /// Prefers a **direct, advertised** git frontend the registry is reachable
    /// at — its own (an operator override), else one **inherited from its
    /// storage binding** (the bucket's public CDN origin, with the registry's
    /// `prefix` appended) — so clients fetch the git wire surface straight from
    /// the bucket (RFC-0004 §12). Falls back to the hub-served
    /// `{external_url}/{slug}` when no such frontend exists. Surfaced in the
    /// browse UI's setup snippets.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_consumer_url(
        &self,
        registry: &RegistryRecord,
    ) -> Result<String, RpcError> {
        let own = self
            .db
            .list_frontends(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let advertise = self
            .db
            .registry_advertises_storage_frontend(registry.id)
            .await
            .map_err(RpcError::internal)?;
        match self
            .direct_consumer_url(
                &own,
                registry.storage_binding_id,
                &registry.prefix,
                FrontendSurface::Git,
                advertise,
            )
            .await?
        {
            Some(url) => Ok(url),
            None => Ok(format!(
                "{}/{}",
                self.external_url.trim_end_matches('/'),
                registry.slug
            )),
        }
    }

    /// Resolve the consumer-facing base URL a binary cache is served at.
    ///
    /// Mirrors [`registry_consumer_url`](Self::registry_consumer_url) for the
    /// Nix binary-cache surface: prefers a **direct, advertised** cache
    /// frontend — the cache's own (an operator override), else one inherited
    /// from its storage binding (the bucket's public CDN origin, with the
    /// cache's `prefix` appended) — so substituters fetch `narinfo`/`nar`
    /// straight from the bucket. Falls back to the hub-served
    /// `{external_url}/{cache_slug}` when no such frontend exists. This is the
    /// URL the `/-/settings/caches` reconciliation view matches against the
    /// registry's committed `[caches]`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_consumer_url(&self, cache: &crate::db::Cache) -> Result<String, RpcError> {
        cache_consumer_url(&self.db, &self.external_url, cache)
            .await
            .map_err(RpcError::internal)
    }

    /// Resolve a direct, advertised frontend a surface is reachable at, deriving
    /// its consumer-facing base URL — its own `own_frontends` (an operator
    /// override), else one inherited from its storage binding (or the
    /// singleton instance-default binding when `storage_binding_id` is `None`,
    /// i.e. the consumer uses default storage), with `prefix` appended.
    ///
    /// An inherited frontend is honored only over a `public` binding (the create
    /// gate already forbids a Direct frontend over a private one; this re-checks
    /// defensively) and only when `advertise_inherited` is set — the consumer's
    /// per-binding opt-out (RFC-0004 §12). A consumer's *own* frontends are
    /// always honored regardless. Returns `None` when no direct frontend serves
    /// `surface`, so the caller falls back to its hub-served URL.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    async fn direct_consumer_url(
        &self,
        own_frontends: &[FrontendRecord],
        storage_binding_id: Option<i64>,
        prefix: &str,
        surface: FrontendSurface,
        advertise_inherited: bool,
    ) -> Result<Option<String>, RpcError> {
        if let Some(f) = pick_direct_frontend(own_frontends, surface) {
            return Ok(Some(frontend_base_url(&f.domain, &f.base_path, "")));
        }
        if !advertise_inherited {
            return Ok(None);
        }
        let binding = match storage_binding_id {
            Some(id) => self
                .db
                .storage_binding(id)
                .await
                .map_err(RpcError::internal)?,
            None => self
                .db
                .instance_default_binding()
                .await
                .map_err(RpcError::internal)?,
        };
        if let Some(binding) = binding {
            if binding.access == "public" {
                let inherited = self
                    .db
                    .list_storage_frontends(binding.id)
                    .await
                    .map_err(RpcError::internal)?;
                if let Some(f) = pick_direct_frontend(&inherited, surface) {
                    return Ok(Some(frontend_base_url(&f.domain, &f.base_path, prefix)));
                }
            }
        }
        Ok(None)
    }

    /// `BinaryCacheService.LinkCache` — link (or update) a cache⇄registry association.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache or registry, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn link_cache(
        &self,
        auth: Option<&str>,
        req: pb::LinkCacheRequest,
    ) -> Result<pb::LinkCacheResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        let claims = self.require_claims(auth)?;
        let r = self.registry_or_not_found(&req.registry_slug).await?;
        // The advertise flag writes through to the registry's committed
        // registry.toml, so it additionally requires registry.configure on the
        // registry — matching the web console's link handler.
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&r.slug),
        )
        .await?;
        // Cross-visibility safety (RFC-0004 "11-caches"), enforced through the
        // shared chokepoint so the RPC and the web console agree exactly.
        let advisory = assess_cache_link(
            &c.slug,
            &c.visibility,
            &r.slug,
            &r.visibility,
            req.advertised,
            req.roots_packages,
        );
        if let Some(reject) = advisory.reject {
            return Err(RpcError::invalid(reject));
        }
        if let Some(warning) = advisory.warning {
            tracing::warn!("{warning}");
        }
        self.db
            .link_cache(c.id, r.id, req.roots_packages, req.advertised)
            .await
            .map_err(RpcError::internal)?;
        // A link is a purely operational association (GC-root pinning + the
        // autofill suggestion source); it never writes the registry's signed
        // `registry.toml`. Advertising a cache to consumers is an explicit edit
        // of the committed `[[caches]]` config (see the config editor), so there
        // is no change request to promote here. `change_id` stays empty.
        Ok(pb::LinkCacheResponse {
            change_id: String::new(),
        })
    }

    /// `BinaryCacheService.ChangeCacheStorage` — migrate a cache's surface to a
    /// different storage backend.
    ///
    /// Resolves the target binding (empty name = the deployment default), then
    /// runs the shared [`migrate_cache_storage`](crate::migrate::migrate_cache_storage)
    /// — the same copy-then-repoint-then-reconcile the web console invokes.
    ///
    /// # Errors
    ///
    /// Auth errors; [`RpcError::NotFound`] for an unknown cache;
    /// [`RpcError::InvalidArgument`] for an unknown binding, a no-op move, or a
    /// surface that cannot be enumerated.
    pub async fn change_cache_storage(
        &self,
        auth: Option<&str>,
        req: pb::ChangeCacheStorageRequest,
    ) -> Result<pb::ChangeCacheStorageResponse, RpcError> {
        let cache = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, cache.org_id).await?;
        let new_binding_id = self
            .resolve_storage_binding(cache.org_id, &req.binding_name)
            .await?;
        let stats = crate::migrate::migrate_cache_storage(
            &self.db,
            self.surface.as_ref(),
            self.surface_write.as_ref(),
            &cache,
            new_binding_id,
        )
        .await
        .map_err(|err| RpcError::invalid(format!("{err:#}")))?;
        Ok(pb::ChangeCacheStorageResponse {
            objects: stats.objects as u64,
            bytes: stats.bytes,
        })
    }

    /// `BinaryCacheService.UnlinkCache` — remove a cache⇄registry association.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache or registry, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn unlink_cache(
        &self,
        auth: Option<&str>,
        req: pb::UnlinkCacheRequest,
    ) -> Result<pb::UnlinkCacheResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        let claims = self.require_claims(auth)?;
        let r = self.registry_or_not_found(&req.registry_slug).await?;
        // Unlinking de-advertises, which edits the registry's committed config,
        // so it also requires registry.configure on the registry.
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&r.slug),
        )
        .await?;
        let removed = self
            .db
            .unlink_cache(c.id, r.id)
            .await
            .map_err(RpcError::internal)?;
        // Unlinking only drops the operational association; it never rewrites the
        // registry's committed `[[caches]]`. If the cache was advertised in the
        // config, removing that entry is an explicit config edit. `change_id`
        // stays empty.
        Ok(pb::UnlinkCacheResponse {
            removed,
            change_id: String::new(),
        })
    }

    /// `BinaryCacheService.ListCacheLinks` — a cache's registry links.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_cache_links(
        &self,
        auth: Option<&str>,
        req: pb::ListCacheLinksRequest,
    ) -> Result<pb::ListCacheLinksResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &c).await?;
        let mut links = Vec::new();
        for l in self
            .db
            .list_cache_links(c.id)
            .await
            .map_err(RpcError::internal)?
        {
            let registry_slug = self
                .db
                .registry_by_id(l.registry_id)
                .await
                .map_err(RpcError::internal)?
                .map(|r| r.slug)
                .unwrap_or_default();
            links.push(pb::CacheLink {
                registry_slug,
                roots_packages: l.roots_packages,
                advertised: l.advertised,
            });
        }
        Ok(pb::ListCacheLinksResponse { links })
    }

    /// `BinaryCacheService.SetCacheGcPolicy` — replace a cache's GC policy.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn set_cache_gc_policy(
        &self,
        auth: Option<&str>,
        req: pb::SetCacheGcPolicyRequest,
    ) -> Result<pb::SetCacheGcPolicyResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        let p = req.policy.unwrap_or_default();
        self.db
            .set_cache_gc_policy(&crate::db::CacheGcPolicy {
                cache_id: c.id,
                max_bytes: p.max_bytes,
                max_objects: p.max_objects,
                ttl_unreferenced_secs: p.ttl_unreferenced_secs,
                keep_release_versions: p.keep_release_versions,
                keep_channel_frontier: p.keep_channel_frontier,
                schedule_secs: p.schedule_secs,
                updated_at: 0,
            })
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::SetCacheGcPolicyResponse {})
    }

    /// `BinaryCacheService.GetCacheGcPolicy` — a cache's GC policy, if set.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_cache_gc_policy(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheGcPolicyRequest,
    ) -> Result<pb::GetCacheGcPolicyResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &c).await?;
        let policy = self
            .db
            .cache_gc_policy(c.id)
            .await
            .map_err(RpcError::internal)?
            .map(|p| pb::CacheGcPolicyMsg {
                max_bytes: p.max_bytes,
                max_objects: p.max_objects,
                ttl_unreferenced_secs: p.ttl_unreferenced_secs,
                keep_release_versions: p.keep_release_versions,
                keep_channel_frontier: p.keep_channel_frontier,
                schedule_secs: p.schedule_secs,
            });
        Ok(pb::GetCacheGcPolicyResponse { policy })
    }

    /// `BinaryCacheService.PinCachePath` — pin a store path (or renew its deadline).
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn pin_cache_path(
        &self,
        auth: Option<&str>,
        req: pb::PinCachePathRequest,
    ) -> Result<pb::PinCachePathResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        self.db
            .pin_cache_path(c.id, &req.store_hash, req.expires_at)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::PinCachePathResponse {})
    }

    /// `BinaryCacheService.UnpinCachePath` — remove a manual GC pin.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn unpin_cache_path(
        &self,
        auth: Option<&str>,
        req: pb::UnpinCachePathRequest,
    ) -> Result<pb::UnpinCachePathResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, c.org_id).await?;
        let removed = self
            .db
            .unpin_cache_path(c.id, &req.store_hash)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::UnpinCachePathResponse { removed })
    }

    /// `BinaryCacheService.ListCacheRoots` — a cache's GC roots.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_cache_roots(
        &self,
        auth: Option<&str>,
        req: pb::ListCacheRootsRequest,
    ) -> Result<pb::ListCacheRootsResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &c).await?;
        let roots = self
            .db
            .list_cache_roots(c.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|r| pb::CacheRoot {
                store_hash: r.store_hash,
                root_kind: r.root_kind,
                root_ref: r.root_ref,
                expires_at: r.expires_at,
                created_at: r.created_at,
            })
            .collect();
        Ok(pb::ListCacheRootsResponse { roots })
    }

    /// `BinaryCacheService.SearchCache` — search a cache's objects.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn search_cache(
        &self,
        auth: Option<&str>,
        req: pb::SearchCacheRequest,
    ) -> Result<pb::SearchCacheResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &c).await?;
        let limit = if req.limit == 0 { 50 } else { req.limit };
        let objects = self
            .db
            .search_cache_objects(c.id, &req.query, limit)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(cache_object_message)
            .collect();
        Ok(pb::SearchCacheResponse { objects })
    }

    /// `BinaryCacheService.GetCacheObject` — one object's narinfo metadata.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_cache_object(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheObjectRequest,
    ) -> Result<pb::GetCacheObjectResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &c).await?;
        let object = self
            .db
            .cache_object(c.id, &req.store_hash)
            .await
            .map_err(RpcError::internal)?
            .map(cache_object_message);
        Ok(pb::GetCacheObjectResponse { object })
    }

    /// `BinaryCacheService.ListCacheGcRuns` — a cache's recent GC runs.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_cache_gc_runs(
        &self,
        auth: Option<&str>,
        req: pb::ListCacheGcRunsRequest,
    ) -> Result<pb::ListCacheGcRunsResponse, RpcError> {
        let c = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &c).await?;
        let limit = if req.limit == 0 { 10 } else { req.limit };
        let runs = self
            .db
            .list_cache_gc_runs(c.id, limit)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|r| pb::CacheGcRun {
                id: r.id,
                started_at: r.started_at,
                finished_at: r.finished_at,
                status: r.status,
                error: r.error.unwrap_or_default(),
                scanned: r.scanned,
                retained: r.retained,
                deleted_objects: r.deleted_objects,
                freed_bytes: r.freed_bytes,
            })
            .collect();
        Ok(pb::ListCacheGcRunsResponse { runs })
    }

    /// `BinaryCacheService.RunCacheGc` — garbage-collect a cache (mark/sweep).
    ///
    /// Runs the shared [`crate::gc::sweep_cache`] over this service's write port,
    /// so the native hub and the Worker GC identically. A real run records a
    /// `cache_gc_runs` row; a `dry_run` only reports what would be reclaimed.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors, and
    /// [`RpcError::Internal`] on database/surface failure (a failed real run is
    /// recorded as `failed`).
    pub async fn run_cache_gc(
        &self,
        auth: Option<&str>,
        req: pb::RunCacheGcRequest,
    ) -> Result<pb::RunCacheGcResponse, RpcError> {
        let cache = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, cache.org_id).await?;
        let now = clock::now_unix_secs();
        if req.dry_run {
            let stats =
                crate::gc::sweep_cache(&self.db, self.surface_write.as_ref(), &cache, true, now)
                    .await
                    .map_err(RpcError::internal)?;
            return Ok(pb::RunCacheGcResponse {
                scanned: stats.scanned,
                retained: stats.retained,
                deleted_objects: stats.deleted_objects,
                freed_bytes: stats.freed_bytes,
                dry_run: true,
            });
        }
        let run_id = self
            .db
            .start_cache_gc_run(cache.id)
            .await
            .map_err(RpcError::internal)?;
        match crate::gc::sweep_cache(&self.db, self.surface_write.as_ref(), &cache, false, now)
            .await
        {
            Ok(stats) => {
                self.db
                    .finish_cache_gc_run(
                        run_id,
                        "ok",
                        None,
                        stats.scanned,
                        stats.retained,
                        stats.deleted_objects,
                        stats.freed_bytes,
                    )
                    .await
                    .map_err(RpcError::internal)?;
                tracing::info!(
                    cache = %cache.slug,
                    run_id,
                    scanned = stats.scanned,
                    retained = stats.retained,
                    deleted_objects = stats.deleted_objects,
                    freed_bytes = stats.freed_bytes,
                    "cache gc completed"
                );
                Ok(pb::RunCacheGcResponse {
                    scanned: stats.scanned,
                    retained: stats.retained,
                    deleted_objects: stats.deleted_objects,
                    freed_bytes: stats.freed_bytes,
                    dry_run: false,
                })
            }
            Err(err) => {
                tracing::warn!(
                    cache = %cache.slug,
                    run_id,
                    error = %format!("{err:#}"),
                    "cache gc failed"
                );
                let _ = self
                    .db
                    .finish_cache_gc_run(run_id, "failed", Some(format!("{err:#}")), 0, 0, 0, 0)
                    .await;
                Err(RpcError::internal(err))
            }
        }
    }

    /// `BinaryCacheService.MintCacheUploadCredentials` — a presigned `PUT` URL for
    /// uploading one object directly to a cache's private external origin.
    ///
    /// Requires cache-write authority. Returns an empty `upload_url` when the
    /// cache's binding is not a presign-configured private external origin (the
    /// caller then uploads through the facade `PUT` instead). The URL carries no
    /// long-lived secret and expires after [`PRESIGN_EXPIRES_SECS`].
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors, and
    /// [`RpcError::Internal`] on a signing or database failure.
    pub async fn mint_cache_upload_credentials(
        &self,
        auth: Option<&str>,
        req: pb::MintCacheUploadCredentialsRequest,
    ) -> Result<pb::MintCacheUploadCredentialsResponse, RpcError> {
        let cache = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_admin(auth, cache.org_id).await?;
        let now = clock::now_unix_secs();
        let expires_at = now + i64::from(PRESIGN_EXPIRES_SECS);
        // Batch form: one round-trip mints a URL per path (the single-path
        // `upload_url` is unused). A non-machine path or a non-presignable cache
        // yields an empty URL for that entry, so the client falls back per-NAR.
        if !req.paths.is_empty() {
            let mut uploads = Vec::with_capacity(req.paths.len());
            for path in &req.paths {
                let upload_url = if keymap::is_machine_path(path) {
                    self.presign_cache_write(&cache, path, now)
                        .await
                        .map_err(RpcError::internal)?
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                uploads.push(pb::PresignedUpload {
                    path: path.clone(),
                    upload_url,
                    expires_at,
                });
            }
            return Ok(pb::MintCacheUploadCredentialsResponse {
                upload_url: String::new(),
                expires_at,
                uploads,
            });
        }
        // Only canonical machine paths are mintable — a presigned PUT bypasses the
        // facade's narinfo signing, so an arbitrary key would land unvalidated.
        // Mirrors the facade `put_cache_path` machine-path guard.
        if !keymap::is_machine_path(&req.path) {
            return Err(RpcError::invalid("not a cache machine path"));
        }
        let url = self
            .presign_cache_write(&cache, &req.path, now)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::MintCacheUploadCredentialsResponse {
            upload_url: url.unwrap_or_default(),
            expires_at,
            uploads: Vec::new(),
        })
    }

    /// `BinaryCacheService.RegisterCacheNarinfos` — write + index a batch of narinfos.
    ///
    /// Used after the NAR bytes were uploaded directly to the origin via
    /// presigned URLs: the client sends the (small) narinfos and the hub writes
    /// each to the surface and updates the index in one round-trip, so a bulk
    /// push is bounded by direct-to-origin NAR throughput rather than per-object
    /// Worker round-trips. Each narinfo goes through the same write path as a
    /// facade `PUT` ([`Self::put_cache_path`]): auth, server-side signing for a
    /// key-bearing cache, surface write, quota, and index write-through.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::invalid`] for a malformed narinfo path or oversize body, and
    /// [`RpcError::Internal`] on a surface/database failure.
    pub async fn register_cache_narinfos(
        &self,
        auth: Option<&str>,
        req: pb::RegisterCacheNarinfosRequest,
    ) -> Result<pb::RegisterCacheNarinfosResponse, RpcError> {
        let cache = self.cache_or_not_found(&req.cache_slug).await?;
        // Fail fast on auth; `put_cache_path` re-checks per write (cheap).
        self.require_cache_admin(auth, cache.org_id).await?;
        let mut registered = 0i64;
        for n in &req.narinfos {
            let path = format!("{}.narinfo", n.store_hash);
            match self
                .put_cache_path(auth, &cache, &path, n.narinfo.as_bytes())
                .await
            {
                FacadeWrite::Created | FacadeWrite::Overwritten => registered += 1,
                FacadeWrite::BadPath(reason) => return Err(RpcError::invalid(reason)),
                FacadeWrite::TooLarge => return Err(RpcError::invalid("narinfo too large")),
                FacadeWrite::QuotaExceeded => {
                    return Err(RpcError::invalid("org storage quota exceeded"));
                }
                FacadeWrite::NotFound => return Err(RpcError::not_found("cache")),
                FacadeWrite::Unauthorized(reason) | FacadeWrite::NotWritable(reason) => {
                    return Err(RpcError::invalid(reason));
                }
                other => {
                    return Err(RpcError::internal(anyhow::anyhow!(
                        "narinfo register failed: {other:?}"
                    )));
                }
            }
        }
        Ok(pb::RegisterCacheNarinfosResponse { registered })
    }

    /// `BinaryCacheService.CacheClosure` — the transitive closure of a store path.
    ///
    /// Breadth-first over `cache_objects.refs` from `store_hash` (root first); a
    /// reference absent from the cache appears with `present = false`. Bounded at
    /// [`MAX_CLOSURE_NODES`] to keep the response finite.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn cache_closure(
        &self,
        auth: Option<&str>,
        req: pb::CacheClosureRequest,
    ) -> Result<pb::CacheClosureResponse, RpcError> {
        let cache = self.cache_or_not_found(&req.cache_slug).await?;
        self.require_cache_read(auth, &cache).await?;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        queue.push_back(req.store_hash.clone());
        let mut nodes = Vec::new();
        let mut total_size = 0i64;
        while let Some(hash) = queue.pop_front() {
            if nodes.len() >= MAX_CLOSURE_NODES {
                break;
            }
            if !seen.insert(hash.clone()) {
                continue;
            }
            match self
                .db
                .cache_object(cache.id, &hash)
                .await
                .map_err(RpcError::internal)?
            {
                Some(object) => {
                    total_size += object.file_size;
                    for r in &object.refs {
                        if !seen.contains(r) {
                            queue.push_back(r.clone());
                        }
                    }
                    nodes.push(pb::CacheClosureNode {
                        store_hash: object.store_hash,
                        store_name: object.store_name,
                        file_size: object.file_size,
                        refs: object.refs,
                        present: true,
                    });
                }
                None => nodes.push(pb::CacheClosureNode {
                    store_hash: hash,
                    store_name: String::new(),
                    file_size: 0,
                    refs: Vec::new(),
                    present: false,
                }),
            }
        }
        Ok(pb::CacheClosureResponse { nodes, total_size })
    }

    /// `ProjectService.CreateProject` — create a project at a materialized path
    /// under an org.
    ///
    /// Requires [`Permission::RegistryConfigure`] on the org scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `registry.configure`
    /// on the org scope, [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::InvalidArgument`] for an empty name, [`RpcError::AlreadyExists`]
    /// when `(org, path)` exists, and [`RpcError::Internal`] on database failure.
    pub async fn create_project(
        &self,
        auth: Option<&str>,
        req: pb::CreateProjectRequest,
    ) -> Result<pb::CreateProjectResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.slug),
        )
        .await?;
        if req.name.is_empty() {
            return Err(RpcError::invalid("project name is required"));
        }
        self.db
            .create_project(org.id, &req.path, &req.name)
            .await
            .map_err(|e| RpcError::AlreadyExists(format!("{e:#}")))?;
        Ok(pb::CreateProjectResponse {
            project: Some(project_message(org.slug, req.path, req.name)),
        })
    }

    /// `StorageBindingService.CreateBinding` — create a storage binding under an org.
    ///
    /// The `kind` must be a known [`BindingKind`](crate::binding::BindingKind)
    /// (`local_fs`, `s3`, or `r2`) that the serving runtime supports — the
    /// Worker rejects `local_fs` (it has no filesystem); both runtimes accept
    /// `s3`/`r2` (see [`RuntimeKind`](crate::binding::RuntimeKind)). An empty
    /// `kind` defaults to `local_fs`. An `s3`/`r2` binding additionally carries an
    /// `endpoint`, optional `region`, and (when `access` is `private`, the
    /// default) an `access_key_id`/`secret_access_key` pair, which is sealed at
    /// rest. Requires [`Permission::RegistryConfigure`] on the org scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `registry.configure`
    /// on the org scope, [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::InvalidArgument`] for an empty name/root, an unknown kind, or
    /// a kind the serving runtime does not support,
    /// [`RpcError::AlreadyExists`] when `(org, name)` exists, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn create_binding(
        &self,
        auth: Option<&str>,
        req: pb::CreateBindingRequest,
    ) -> Result<pb::CreateBindingResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.slug),
        )
        .await?;
        if req.name.is_empty() || req.root.is_empty() {
            return Err(RpcError::invalid("binding name and root are required"));
        }
        let kind_str = if req.kind.is_empty() {
            "local_fs"
        } else {
            req.kind.as_str()
        };
        let kind = BindingKind::parse(kind_str).ok_or_else(|| {
            RpcError::invalid(format!(
                "unknown storage binding kind '{kind_str}' (expected local_fs, s3, or r2)"
            ))
        })?;
        // The serving process's runtime gates which kinds are usable (the Worker
        // has no filesystem). `current()` reflects this process, so the check is
        // correct here.
        let runtime = RuntimeKind::current();
        if !runtime.supports(kind) {
            let supported = runtime
                .supported_binding_kinds()
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(RpcError::invalid(format!(
                "storage binding kind '{kind_str}' is not supported on the {} runtime; \
                 supported kinds: [{supported}]",
                runtime.name(),
            )));
        }
        // An s3/r2 binding needs the origin sealed; without a wired sealer a
        // private binding's credentials could not be stored safely.
        let origin = if kind.requires_origin_config() {
            Some(crate::binding_provision::OriginInput {
                endpoint: &req.endpoint,
                region: &req.region,
                access_key_id: &req.access_key_id,
                secret_access_key: &req.secret_access_key,
                // Default to private (the common case: an org's own bucket);
                // "public" opts into a credential-less read-only mirror.
                private: req.access.trim() != "public",
            })
        } else {
            None
        };
        let sealer = self.sealer.as_ref().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("no secret sealer configured on this hub"))
        })?;
        crate::binding_provision::provision_binding(
            &self.db,
            sealer.as_ref(),
            crate::binding_provision::NewBinding {
                org_id: org.id,
                name: &req.name,
                kind,
                root: &req.root,
                origin,
            },
        )
        .await
        .map_err(|e| match e {
            crate::binding_provision::ProvisionError::Invalid(m) => RpcError::invalid(m),
            crate::binding_provision::ProvisionError::AlreadyExists(m) => {
                RpcError::AlreadyExists(format!("storage binding '{m}' already exists"))
            }
            crate::binding_provision::ProvisionError::Backend(e) => RpcError::internal(e),
        })?;
        let record = self
            .db
            .storage_binding_by_name(org.id, req.name.trim())
            .await
            .map_err(RpcError::internal)?;
        let binding = record
            .map(|b| binding_message(org.slug.clone(), &b, true))
            .unwrap_or_else(|| pb::Binding {
                org_slug: org.slug,
                name: req.name,
                kind: kind.as_str().to_string(),
                root: req.root,
                access: String::new(),
                endpoint: String::new(),
                region: String::new(),
            });
        Ok(pb::CreateBindingResponse {
            binding: Some(binding),
        })
    }

    /// `WebhookService.CreateWebhook` — subscribe an org's HTTP endpoint to
    /// registry events.
    ///
    /// The webhook is created under the named org subscribed to `events` (an
    /// empty list subscribes to all event types). A `secret` may be supplied;
    /// otherwise a random `aos_`-prefixed one is generated. The signing secret is
    /// returned exactly once in [`pb::CreateWebhookResponse::secret`] — it is
    /// never echoed by [`Self::list_webhooks`]. Requires
    /// [`Permission::MembersManage`] (admin+) on the org scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `members.manage` on
    /// the org, [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::InvalidArgument`] for an empty URL or a URL that fails the
    /// SSRF guard ([`crate::url_guard::is_safe_remote_url`] — loopback/
    /// link-local/private/non-`http(s)` targets), and [`RpcError::Internal`] on
    /// database failure.
    pub async fn create_webhook(
        &self,
        auth: Option<&str>,
        req: pb::CreateWebhookRequest,
    ) -> Result<pb::CreateWebhookResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(&claims, Permission::MembersManage, &Scope::parse(&org.slug))
            .await?;
        if req.url.is_empty() {
            return Err(RpcError::invalid("webhook url is required"));
        }
        // The delivery worker POSTs to this URL from inside the hub network, so
        // reject loopback/link-local/private/non-http(s) targets (create_webhook
        // re-checks; this surfaces a clear invalid-argument error).
        if let Err(err) = crate::url_guard::is_safe_remote_url(&req.url) {
            return Err(RpcError::invalid(format!("rejecting webhook url: {err:#}")));
        }
        let secret = if req.secret.is_empty() {
            crate::auth::token::generate_token().0
        } else {
            req.secret.clone()
        };
        let events: Vec<String> = req.events.clone();
        let id = self
            .db
            .create_webhook(org.id, &req.url, &secret, &events)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::CreateWebhookResponse {
            webhook: Some(webhook_message(id, org.slug, req.url, events, true, 0)),
            secret,
        })
    }

    /// `WebhookService.DeleteWebhook` — remove a webhook (and its queued
    /// deliveries) by id.
    ///
    /// Requires [`Permission::MembersManage`] on the *owning org's* scope,
    /// resolved from the webhook's `org_id` so the check binds to the resource
    /// being deleted rather than a caller-supplied scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown webhook id or its (vanished) org,
    /// [`RpcError::PermissionDenied`] when the caller lacks `members.manage` on
    /// the owning org, and [`RpcError::Internal`] on database failure.
    pub async fn delete_webhook(
        &self,
        auth: Option<&str>,
        req: pb::DeleteWebhookRequest,
    ) -> Result<pb::DeleteWebhookResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let webhook = self
            .db
            .webhook(req.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("webhook"))?;
        let org = self
            .db
            .org_by_id(webhook.org_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("org"))?;
        self.require_permission(&claims, Permission::MembersManage, &Scope::parse(&org.slug))
            .await?;
        let deleted = self
            .db
            .delete_webhook(req.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::DeleteWebhookResponse { deleted })
    }

    /// `PublishService.MintUploadCredentials` — issue a short-lived,
    /// registry-scoped upload credential.
    ///
    /// The caller must already hold `publish` on the registry's canonical scope
    /// (the same right the upload facade requires). On success the hub mints a
    /// fresh provisioning token *owned by the calling principal*, scoped to
    /// exactly that registry with only the `publish` permission and a short
    /// expiry ([`UPLOAD_CREDENTIAL_TTL_SECS`]). The response carries that token
    /// (shown once), the canonical facade `upload_url` (`{external_url}/{slug}`),
    /// and the expiry.
    ///
    /// Token ownership keeps the credential clamped: it deadens the instant the
    /// owner's `publish` grant is removed, so a minted credential never outlives
    /// the authority that minted it.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown registry slug,
    /// [`RpcError::PermissionDenied`] when the caller lacks `publish` on the
    /// registry scope or has no resolvable principal, and [`RpcError::Internal`]
    /// on database failure.
    pub async fn mint_upload_credentials(
        &self,
        auth: Option<&str>,
        req: pb::MintUploadCredentialsRequest,
    ) -> Result<pb::MintUploadCredentialsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.slug).await?;
        let scope = Scope::parse(&registry.slug);
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;

        let owner = claims_principal(&claims)
            .ok_or_else(|| RpcError::PermissionDenied("unknown principal kind".into()))?;
        let expires_at = clock::now_unix_secs() + UPLOAD_CREDENTIAL_TTL_SECS;
        let (_id, secret) = self
            .db
            .create_token(
                owner,
                &registry.slug,
                &[Permission::Publish],
                Some("upload credential (MintUploadCredentials)"),
                Some(expires_at),
            )
            .await
            .map_err(RpcError::internal)?;
        let upload_url = format!(
            "{}/{}",
            self.external_url.trim_end_matches('/'),
            registry.slug
        );
        Ok(pb::MintUploadCredentialsResponse {
            token: secret,
            upload_url,
            expires_at,
        })
    }

    /// `RegistryConfigurationService.RevertChangeset` — draft and apply a forward revert.
    ///
    /// Drafts the snapshot-targeted forward revert ([`crate::config::revert`])
    /// and immediately applies it, returning the new revert change-set. The
    /// revert re-enters the same apply path, so a `registry`-visibility
    /// revision's revert calls [`Database::set_registry_visibility`] again.
    ///
    /// Authz approximates the RFC's "same permission the original change
    /// required" as `registry.configure` on the change-set's scope — the admin+
    /// verb gating the SQL-backed configuration this engine records.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown `change_id`,
    /// [`RpcError::PermissionDenied`] when the caller lacks `registry.configure`
    /// on the change-set's scope, [`RpcError::FailedPrecondition`] when the
    /// change-set has no revisions to revert, and [`RpcError::Internal`] on
    /// database failure.
    pub async fn revert_changeset(
        &self,
        auth: Option<&str>,
        req: pb::RevertChangesetRequest,
    ) -> Result<pb::RevertChangesetResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let summary = self
            .db
            .changeset(&req.change_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("changeset"))?;
        let scope = Scope::parse(&summary.scope);
        self.require_permission(&claims, Permission::RegistryConfigure, &scope)
            .await?;

        let Some(actor) = claims_principal(&claims) else {
            return Err(RpcError::PermissionDenied("unknown principal kind".into()));
        };
        let actor_label = format!("{}:{}", claims.owner_kind, claims.owner_id);
        let original = crate::config::ChangeId(summary.change_id.clone());

        // Draft the forward revert; live state for conflict detection comes from
        // the registries table (the object type this phase mutates).
        let draft = crate::config::revert(
            &self.db,
            &original,
            &actor,
            &actor_label,
            |object_type: &str, object_id: &str| {
                let is_registry = object_type == "registry";
                let object_id = object_id.to_string();
                async move {
                    if is_registry {
                        self.db
                            .registry_by_slug(&object_id)
                            .await
                            .ok()
                            .flatten()
                            .map(|r| serde_json::json!({ "visibility": r.visibility }))
                    } else {
                        None
                    }
                }
            },
        )
        .await
        .map_err(|e| RpcError::FailedPrecondition(format!("{e:#}")))?;

        // Apply the revert draft: re-run each revision's live mutation.
        crate::config::apply(&self.db, &draft.change_id, "changeset.revert", |rev| {
            let rev = rev.clone();
            async move { apply_revert_revision(&self.db, &rev).await }
        })
        .await
        .map_err(RpcError::internal)?;

        let reverted = self
            .db
            .changeset(draft.change_id.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("revert change-set vanished")))?;
        Ok(pb::RevertChangesetResponse {
            changeset: Some(changeset_message(reverted)),
        })
    }

    /// `GitService.GitLog` — the committed commit log of a registry's tracked
    /// branch.
    ///
    /// Walks the verified HEAD commit's first-parent history through the
    /// committed git surface, newest first. Reads follow registry visibility:
    /// the caller must hold [`Permission::Read`] on the registry scope (a
    /// `public` registry's read is anonymous; see the access matrix). Each
    /// entry carries the `AOS-Change-Id` trailer when the commit was authored or
    /// promoted through the hub.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug,
    /// [`RpcError::PermissionDenied`] when the caller cannot read the registry,
    /// [`RpcError::FailedPrecondition`] when the registry has no indexed HEAD
    /// yet, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database or surface-read failure.
    pub async fn git_log(
        &self,
        auth: Option<&str>,
        req: pb::GitLogRequest,
    ) -> Result<pb::GitLogResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        let head = self.head_commit(&registry).await?;
        let fetch = self
            .surface
            .fetcher(&registry)
            .await
            .map_err(RpcError::internal)?;
        let log = crate::git::commit_log(fetch.as_ref(), head, crate::git::GIT_LOG_LIMIT)
            .await
            .map_err(RpcError::internal)?;
        let commits: Vec<pb::GitCommit> = log
            .into_iter()
            .map(|c| pb::GitCommit {
                oid: c.oid,
                parents: c.parents,
                message: c.message,
                author: c.author,
                when: c.when,
                change_id: c.change_id.unwrap_or_default(),
            })
            .collect();
        let (commits, next_page_token) = paginate(commits, req.page_size, &req.page_token)?;
        Ok(pb::GitLogResponse {
            commits,
            next_page_token,
        })
    }

    /// `GitService.GitDiff` — a textual diff of committed config files between
    /// commits.
    ///
    /// Diffs `registry.toml` and `keys.toml` between `from_oid` and `to_oid`
    /// (an empty `to_oid` defaults to the current HEAD; an empty `from_oid`
    /// renders the whole `to` tree as additions). Requires
    /// [`Permission::Read`] on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug,
    /// [`RpcError::PermissionDenied`] when the caller cannot read the registry,
    /// [`RpcError::InvalidArgument`] for a malformed oid,
    /// [`RpcError::FailedPrecondition`] when no HEAD is available to default
    /// `to_oid`, and [`RpcError::Internal`] on database or surface-read failure.
    pub async fn git_diff(
        &self,
        auth: Option<&str>,
        req: pb::GitDiffRequest,
    ) -> Result<pb::GitDiffResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        let from = if req.from_oid.is_empty() {
            None
        } else {
            Some(Oid::from_hex(&req.from_oid).map_err(|e| RpcError::invalid(format!("{e:#}")))?)
        };
        let to = if req.to_oid.is_empty() {
            self.head_commit(&registry).await?
        } else {
            Oid::from_hex(&req.to_oid).map_err(|e| RpcError::invalid(format!("{e:#}")))?
        };
        let fetch = self
            .surface
            .fetcher(&registry)
            .await
            .map_err(RpcError::internal)?;
        let diff = crate::git::diff_config_files(fetch.as_ref(), from, to)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GitDiffResponse { diff })
    }

    /// `GitService.ListChangeRequests` — the registry's draft git-backed change
    /// requests.
    ///
    /// Surfaces every change-set the hub recorded as a git-backed change request
    /// (one with a draft ref and commit), with each edited file's unified diff
    /// (computed from the recorded old/new file contents) and the `apr change
    /// merge` command a maintainer runs to promote it. Listing the change
    /// requests is an admin+ surface: the caller must hold
    /// [`Permission::AuditRead`] on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown slug,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_change_requests(
        &self,
        auth: Option<&str>,
        req: pb::ListChangeRequestsRequest,
    ) -> Result<pb::ListChangeRequestsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.slug).await?;
        let scope = Scope::parse(&registry.slug);
        self.require_permission(&claims, Permission::AuditRead, &scope)
            .await?;

        let upload_url = format!(
            "{}/{}",
            self.external_url.trim_end_matches('/'),
            registry.slug
        );
        let changesets = self
            .db
            .list_changesets(&registry.slug)
            .await
            .map_err(RpcError::internal)?;
        let mut change_requests = Vec::new();
        for cs in changesets.into_iter().filter(|cs| cs.git_ref.is_some()) {
            let file_diffs = self
                .db
                .list_revisions(&cs.change_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.object_type == "registry_file")
                .map(|r| pb::FileDiff {
                    diff: crate::git::unified_diff(
                        &r.object_id,
                        r.old_json.as_deref().unwrap_or_default(),
                        r.new_json.as_deref().unwrap_or_default(),
                    ),
                    path: r.object_id,
                })
                .collect();
            change_requests.push(pb::ChangeRequest {
                merge_command: crate::git::merge_command(
                    &upload_url,
                    &crate::config::ChangeId(cs.change_id.clone()),
                ),
                change_id: cs.change_id,
                git_ref: cs.git_ref.unwrap_or_default(),
                git_commit: cs.git_commit.unwrap_or_default(),
                status: cs.status,
                summary: cs.summary.unwrap_or_default(),
                actor_label: cs.actor_label,
                created_at: cs.created_at,
                file_diffs,
            });
        }
        Ok(pb::ListChangeRequestsResponse { change_requests })
    }

    /// Serve one machine path for a registry from the surface store.
    ///
    /// The shared machine-surface facade, single-sourced across both deployment
    /// targets (the native hub's `compat` serve path and the Cloudflare Worker's
    /// R2 facade): every registry URL is simultaneously a dumb-HTTP git origin
    /// and a Nix binary cache (RFC-0004 "URL design"), and this reads that
    /// surface through the shared placement planner and [`SurfaceProvider`] port
    /// so selection, failover, and the byte-and-header contract are written once.
    /// A surface with no placement rows uses the resource-based migration
    /// fallback; once any placement exists, the request never bypasses topology.
    ///
    /// Returns `Ok(None)` — which the transport renders as a `404` — when
    /// `machine_path` is not part of the machine surface ([`keymap::is_machine_path`])
    /// or the surface store has no such object. On a hit it returns the
    /// [`FacadeObject`] carrying the bytes plus the path's
    /// [`keymap::content_type`]/[`keymap::cache_control`].
    ///
    /// Reads follow registry visibility exactly as the other read RPCs do (see
    /// [`Self::require_read`]): a `public` registry serves anonymously, while an
    /// `internal`/`private` registry requires a bearer JWT granting
    /// [`Permission::Read`] on the registry scope — so the facade never
    /// discloses a hidden registry's bytes to an unauthorized caller.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a registry under a
    /// soft-deleted org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority, and
    /// [`RpcError::Internal`] when resolving the surface fetcher or reading the
    /// object fails.
    pub async fn facade_fetch(
        &self,
        auth: Option<&str>,
        slug: &str,
        machine_path: &str,
    ) -> Result<Option<FacadeObject>, RpcError> {
        if !keymap::is_machine_path(machine_path) {
            return Ok(None);
        }
        // A registry slug wins; a slug that is not a registry falls through to a
        // managed cache (the two are separate namespaces). Both shells reach this
        // one method, so cache serving is at parity automatically.
        if let Some(registry) = self
            .db
            .registry_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
        {
            self.require_read(auth, &registry).await?;
            let bytes = match placement_read::fetch_from_placements(
                self.db.as_ref(),
                self.surface.as_ref(),
                SurfaceTarget::Registry(registry.id),
                machine_path,
            )
            .await
            .map_err(RpcError::internal)?
            {
                PlacementReadOutcome::Found(read) => read.value,
                PlacementReadOutcome::NotFound => return Ok(None),
                PlacementReadOutcome::NoPlacements => {
                    // Transitional migration fallback, selected only when the
                    // planner's one-statement snapshot saw zero placement rows.
                    // The final cutover backfills all surfaces and deletes this
                    // branch together with resource-level storage columns.
                    let fetch = self
                        .surface
                        .fetcher(&registry)
                        .await
                        .map_err(RpcError::internal)?;
                    let Some(bytes) = fetch
                        .fetch(machine_path)
                        .await
                        .map_err(RpcError::internal)?
                    else {
                        return Ok(None);
                    };
                    bytes
                }
            };
            return Ok(Some(FacadeObject {
                bytes,
                content_type: keymap::content_type(machine_path),
                cache_control: keymap::cache_control(machine_path),
                redirect: None,
            }));
        }
        if let Some(cache) = self
            .db
            .cache_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
        {
            return self.cache_facade_fetch(auth, &cache, machine_path).await;
        }
        Err(RpcError::not_found("registry"))
    }

    /// Serve a managed cache's machine surface.
    ///
    /// `nix-cache-info` is generated from the cache's config; `<hash>.narinfo`
    /// and `nar/<file>` are served as stored bytes from the cache surface. Reads
    /// honor the cache's visibility ([`Self::require_cache_read`]) and use
    /// ordered placement failover when topology is configured.
    ///
    /// # Errors
    ///
    /// Auth errors for a non-public cache read without authority, and
    /// [`RpcError::Internal`] on store/database failure. `Ok(None)` is a 404 for
    /// an absent object.
    async fn cache_facade_fetch(
        &self,
        auth: Option<&str>,
        cache: &crate::db::Cache,
        path: &str,
    ) -> Result<Option<FacadeObject>, RpcError> {
        self.require_cache_read(auth, cache).await?;
        if path == "nix-cache-info" {
            let body = render_nix_cache_info(cache.want_mass_query, cache.priority);
            return Ok(Some(FacadeObject {
                bytes: body.into_bytes(),
                content_type: keymap::content_type(path),
                cache_control: keymap::cache_control(path),
                redirect: None,
            }));
        }
        match placement_read::fetch_from_placements(
            self.db.as_ref(),
            self.surface.as_ref(),
            SurfaceTarget::BinaryCache(cache.id),
            path,
        )
        .await
        .map_err(RpcError::internal)?
        {
            PlacementReadOutcome::Found(read) => {
                if let Some(hash) = path.strip_suffix(".narinfo").filter(|h| !h.contains('/')) {
                    let _ = self
                        .db
                        .touch_cache_object(cache.id, hash, clock::now_unix_secs())
                        .await;
                }
                return Ok(Some(FacadeObject {
                    bytes: read.value,
                    content_type: keymap::content_type(path),
                    cache_control: keymap::cache_control(path),
                    redirect: None,
                }));
            }
            PlacementReadOutcome::NotFound => return Ok(None),
            PlacementReadOutcome::NoPlacements => {
                // Transitional zero-placement snapshot: continue into the
                // resource-level migration reader below. Deleted at cutover.
            }
        }
        // Authenticated-origin read: when the cache's binding is a private
        // external origin (presign-mode), the hub holds no local bytes — it mints
        // a short-lived presigned GET URL and the client fetches the origin
        // directly (`302`). `nix-cache-info` above is always hub-generated, so it
        // is never presigned.
        if let Some(url) = self
            .presign_cache_read(cache, path, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(Some(FacadeObject {
                bytes: Vec::new(),
                content_type: keymap::content_type(path),
                cache_control: keymap::cache_control(path),
                redirect: Some(url),
            }));
        }
        let fetch = self
            .surface
            .cache_fetcher(cache)
            .await
            .map_err(RpcError::internal)?;
        let Some(bytes) = fetch.fetch(path).await.map_err(RpcError::internal)? else {
            return Ok(None);
        };
        // Tap the LRU access signal on a narinfo read — the canonical "this path
        // was requested" event a substituter emits before fetching the NAR.
        // Best-effort and debounced (see `Database::touch_cache_object`): a
        // failure or a no-op never affects the served bytes.
        if let Some(hash) = path.strip_suffix(".narinfo").filter(|h| !h.contains('/')) {
            let _ = self
                .db
                .touch_cache_object(cache.id, hash, clock::now_unix_secs())
                .await;
        }
        Ok(Some(FacadeObject {
            bytes,
            content_type: keymap::content_type(path),
            cache_control: keymap::cache_control(path),
            redirect: None,
        }))
    }

    /// Mint a presigned `GET` URL for a cache object on a private external
    /// origin, or `Ok(None)` when the cache is not presign-configured.
    ///
    /// A cache is presign-configured when its storage binding is `access =
    /// private` with both an `endpoint` (the S3/R2 API origin) and a sealed
    /// `credential_ref` (the SigV4 credentials). The sealed plaintext is
    /// `access_key:secret_key:region` (the secret may itself contain `:`; only
    /// the first and last separators are split on). The signed object key is
    /// `{prefix}/{path}` under the binding's origin host. Returns `Ok(None)` when
    /// not presign-mode or when no sealer is wired (the read then falls through
    /// to local byte serving).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, an unsealing failure, a malformed
    /// `credential_ref`, or when the SigV4 signer rejects the inputs.
    pub async fn presign_cache_read(
        &self,
        cache: &crate::db::Cache,
        path: &str,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        self.presign_cache(cache, path, now, false).await
    }

    /// Mint a presigned `PUT` URL for uploading a cache object to a private
    /// external origin, or `Ok(None)` when the cache is not presign-configured.
    ///
    /// The upload sibling of [`Self::presign_cache_read`] (the `mint` purpose).
    ///
    /// # Errors
    ///
    /// Same as [`Self::presign_cache_read`].
    pub async fn presign_cache_write(
        &self,
        cache: &crate::db::Cache,
        path: &str,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        self.presign_cache(cache, path, now, true).await
    }

    /// Shared presigner behind [`Self::presign_cache_read`]/[`Self::presign_cache_write`].
    /// `write` selects a `PUT` (upload) over a `GET` (download) URL.
    async fn presign_cache(
        &self,
        cache: &crate::db::Cache,
        path: &str,
        now: i64,
        write: bool,
    ) -> anyhow::Result<Option<String>> {
        let Some(sealer) = self.sealer.as_ref() else {
            return Ok(None);
        };
        // A default-storage (binding-less) cache is never presigned — it is
        // served from the deployment's own storage, not a private external origin.
        let Some(binding_id) = cache.storage_binding_id else {
            return Ok(None);
        };
        let Some(binding) = self.db.storage_binding(binding_id).await? else {
            return Ok(None);
        };
        if binding.access != "private" {
            return Ok(None);
        }
        let (Some(base_url), Some(credential_ref)) = (
            binding.endpoint.as_deref(),
            binding.credential_ref.as_deref(),
        ) else {
            return Ok(None);
        };
        // The prefix is the cache's isolation boundary within a (possibly shared)
        // bucket. Reject a traversal/structural path BEFORE signing, so a crafted
        // `..` can never mint a valid signature for an object outside this
        // cache's prefix on a path-normalizing origin — the same guard the write
        // path and the local-bytes read path enforce. An invalid path is simply
        // not presignable (`None`); the caller then 404s it.
        if crate::url_guard::validate_http_surface_path(path).is_err() {
            return Ok(None);
        }
        let creds = sealer
            .unseal(credential_ref)
            .context("unsealing cache origin credentials")?;
        let (access_key, rest) = creds
            .split_once(':')
            .context("credential_ref must be access_key:secret_key:region")?;
        let (secret_key, region) = rest
            .rsplit_once(':')
            .context("credential_ref must be access_key:secret_key:region")?;

        // Origin scheme + host from the base URL. The scheme follows the operator's
        // configured `endpoint` (real S3/R2 is `https`; a plaintext origin
        // — e.g. a local dev/test endpoint — stays `http`); it is not signed, so
        // it never affects the signature.
        let scheme = if base_url.starts_with("http://") {
            "http"
        } else {
            "https"
        };
        let host = base_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        // Signed object key: the binding prefix joined with the requested path.
        let object_path = format!("/{}/{}", cache.prefix.trim_matches('/'), path);

        let params = crate::sigv4::PresignParams {
            access_key,
            secret_key,
            region,
            service: "s3",
            scheme,
            host,
            path: &object_path,
            expires_secs: PRESIGN_EXPIRES_SECS,
            amz_date: &crate::sigv4::amz_date_from_unix(now),
        };
        let url = if write {
            crate::sigv4::presign_put_url(&params)?
        } else {
            crate::sigv4::presign_get_url(&params)?
        };
        Ok(Some(url))
    }

    /// Serve the instance-root `robots.txt` body.
    ///
    /// Returns the operator's custom override verbatim when one is set, else the
    /// document generated from the root crawl policy (see
    /// [`crate::robots::render_robots`]). The result is always a complete file
    /// body; the route layer wraps it in a `text/plain` response.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_root_robots(&self) -> Result<String, RpcError> {
        if let Some(body) = self
            .db
            .root_robots_body()
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(body);
        }
        let policy = self
            .db
            .root_crawl_policy()
            .await
            .map_err(RpcError::internal)?;
        let llms_url = format!("{}/llms.txt", self.external_url.trim_end_matches('/'));
        Ok(crate::robots::render_robots(policy, Some(&llms_url)))
    }

    /// Serve the instance-root `llms.txt` body.
    ///
    /// Returns the operator's custom override verbatim when one is set, else the
    /// document generated from the instance's **public** registries (see
    /// [`crate::robots::render_root_llms`]).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_root_llms(&self) -> Result<String, RpcError> {
        if let Some(body) = self.db.root_llms_body().await.map_err(RpcError::internal)? {
            return Ok(body);
        }
        let base = self.external_url.trim_end_matches('/');
        let brand = self
            .db
            .instance_config_get("brand")
            .await
            .map_err(RpcError::internal)?
            .unwrap_or_default();
        let registries = self
            .db
            .list_registries()
            .await
            .map_err(RpcError::internal)?;
        let views: Vec<crate::robots::RootRegistryView> = registries
            .into_iter()
            .filter(|r| r.visibility == "public")
            .map(|r| crate::robots::RootRegistryView {
                browse_url: format!("{base}/{}/", r.slug),
                slug: r.slug,
                description: None,
            })
            .collect();
        Ok(crate::robots::render_root_llms(&brand, &views))
    }

    /// Serve a registry's `robots.txt`, or `None` when the registry is not
    /// public.
    ///
    /// Anonymous serving path: only a **public** registry is exposed (a private
    /// or internal registry, or an absent slug, returns `None` → `404`),
    /// consistent with the anonymous browse gate. A registry with a custom
    /// `robots.txt`... is not modeled per-registry; the per-registry document is
    /// always generated from the registry's [`crate::crawl::CrawlPolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_registry_robots(&self, slug: &str) -> Result<Option<String>, RpcError> {
        let Some(registry) = self.public_registry(slug).await? else {
            return Ok(None);
        };
        let policy = crate::crawl::CrawlPolicy::parse_or_default(&registry.crawl_policy);
        let base = self.external_url.trim_end_matches('/');
        let llms_url = format!("{base}/{}/llms.txt", registry.slug);
        Ok(Some(crate::robots::render_robots(policy, Some(&llms_url))))
    }

    /// Serve a registry's `llms.txt`, or `None` when the registry is not public.
    ///
    /// Anonymous serving path: only a **public** registry is exposed. A registry
    /// with a custom `llms_txt_body` override is served verbatim; otherwise the
    /// document is generated from the registry's indexed packages and channels
    /// (see [`crate::robots::render_registry_llms`]).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_registry_llms(&self, slug: &str) -> Result<Option<String>, RpcError> {
        let Some(registry) = self.public_registry(slug).await? else {
            return Ok(None);
        };
        if let Some(body) = registry.llms_txt_body.clone() {
            return Ok(Some(body));
        }
        let status = self
            .db
            .index_status(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let packages = self
            .db
            .list_packages(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let channels = self
            .db
            .list_channels(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let base = self.external_url.trim_end_matches('/');
        let view = crate::robots::RegistryView {
            base_url: base.to_string(),
            name: status.as_ref().and_then(|s| s.name.clone()),
            description: status.as_ref().and_then(|s| s.description.clone()),
            packages: packages
                .into_iter()
                .map(|p| crate::robots::PackageView {
                    browse_url: format!("{base}/{}/-/packages/{}", registry.slug, p.name),
                    name: p.name,
                    description: p.description,
                })
                .collect(),
            channels: channels
                .into_iter()
                .map(|c| crate::robots::ChannelView {
                    name: c.name,
                    frontier: c.frontier,
                })
                .collect(),
            slug: registry.slug.clone(),
        };
        Ok(Some(crate::robots::render_registry_llms(&view)))
    }

    /// Load a registry by slug only when it is publicly visible.
    ///
    /// The shared anonymous-visibility gate for the `robots.txt`/`llms.txt`
    /// serving paths: returns the [`RegistryRecord`] only for a `public`
    /// registry under an active org, and `None` for an absent, internal, or
    /// private registry — the two are deliberately indistinguishable to a
    /// crawler.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    async fn public_registry(&self, slug: &str) -> Result<Option<RegistryRecord>, RpcError> {
        let Some(registry) = self
            .db
            .registry_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
        else {
            return Ok(None);
        };
        if registry.visibility != "public" {
            return Ok(None);
        }
        if let Some(org_id) = registry.org_id {
            if !matches!(self.db.org_is_active(org_id).await, Ok(true)) {
                return Ok(None);
            }
        }
        Ok(Some(registry))
    }

    /// Serves one registry machine object as a streaming, range-aware response.
    ///
    /// Placement selection and every retry complete before the response body is
    /// returned. A body-stream failure is therefore reported on the selected
    /// placement's response and is never spliced with bytes from a replica.
    /// During the incremental migration only, a one-statement snapshot with no
    /// configured placements uses the resource-level reader; the final topology
    /// cutover removes that branch after backfill.
    ///
    /// # Errors
    ///
    /// Returns an authentication/authorization error when the registry is not
    /// readable by the caller, or [`RpcError::Internal`] on planning or backend
    /// failure.
    pub async fn registry_serve(
        &self,
        auth: ReadAuthorization<'_>,
        registry: &RegistryRecord,
        path: &str,
        range_header: Option<&str>,
    ) -> Result<RegistryServeOutcome, RpcError> {
        if !keymap::is_machine_path(path) {
            return Ok(RegistryServeOutcome::NotFound);
        }
        // Reload by id to establish the authorization/serve linearization
        // point. Route resolution may have happened before a concurrent delete;
        // only this fresh row may drive auth, placement planning, or migration
        // fallback decisions.
        let registry = self
            .db
            .registry_by_id(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        self.require_registry_stream_read(auth, &registry).await?;
        let requested = parse_byte_range(range_header);
        let read = match placement_read::stream_from_placements(
            self.db.as_ref(),
            self.surface.as_ref(),
            SurfaceTarget::Registry(registry.id),
            path,
            requested,
        )
        .await
        .map_err(RpcError::internal)?
        {
            PlacementReadOutcome::Found(read) => read.value,
            PlacementReadOutcome::NotFound => return Ok(RegistryServeOutcome::NotFound),
            PlacementReadOutcome::NoPlacements => {
                // Registration-only HTTP surfaces retain their direct legacy
                // redirect during migration. Proxying through the default
                // buffered fetch implementation would regress large NARs and
                // release packs. Topology-backed HTTP placements use their
                // streaming adapter above instead.
                if registry.source_url.starts_with("http://")
                    || registry.source_url.starts_with("https://")
                {
                    let location =
                        format!("{}/{}", registry.source_url.trim_end_matches('/'), path);
                    let response = axum::response::Response::builder()
                        .status(axum::http::StatusCode::FOUND)
                        .header(axum::http::header::LOCATION, location)
                        .header(
                            axum::http::header::CACHE_CONTROL,
                            keymap::cache_control(path),
                        )
                        .body(axum::body::Body::empty())
                        .map_err(|error| RpcError::internal(anyhow::anyhow!("{error}")))?;
                    return Ok(RegistryServeOutcome::Response(response));
                }
                let fetch = self
                    .surface
                    .fetcher(&registry)
                    .await
                    .map_err(RpcError::internal)?;
                let Some(read) = fetch
                    .fetch_stream(path, requested)
                    .await
                    .map_err(RpcError::internal)?
                else {
                    return Ok(RegistryServeOutcome::UnplacedNotFound);
                };
                read
            }
        };
        Ok(RegistryServeOutcome::Response(
            Self::streamed_surface_response(path, read)?,
        ))
    }

    /// Serve a managed cache's machine surface as a **streaming** response — the
    /// single shared cache-read path both shells route through.
    ///
    /// This replaces the former native-only `cache_serve_file` so the native hub
    /// and the Worker stream NAR/narinfo through the *same* code: visibility gate
    /// → generated `nix-cache-info` → placement selection/failover → legacy
    /// presigned-`302` for an unplaced private origin → a streaming body from
    /// [`SurfaceFetch::fetch_stream`](crate::fetch::SurfaceFetch::fetch_stream)
    /// honoring `Range:` (`206` + `Content-Range`). Each shell's fetcher supplies
    /// the stream (native: a `tokio` file `ReaderStream`; Worker: an R2 ranged
    /// GET), so a large NAR never buffers into memory on either.
    ///
    /// Returns `Ok(None)` for an absent object (the caller renders `404`).
    ///
    /// # Errors
    ///
    /// Auth/visibility errors for a non-public cache read without authority, and
    /// [`RpcError::Internal`] on store/database failure.
    pub async fn cache_serve(
        &self,
        auth: ReadAuthorization<'_>,
        cache: &crate::db::Cache,
        path: &str,
        range_header: Option<&str>,
    ) -> Result<Option<axum::response::Response>, RpcError> {
        use axum::http::{header, StatusCode};
        // As for registries, discard the route's potentially stale snapshot.
        // Soft/hard deletion must win before generated responses, topology
        // planning, or any resource-level migration fallback can serve bytes.
        let cache = self
            .db
            .cache_by_id(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache"))?;
        self.require_cache_stream_read(auth, &cache).await?;

        // `nix-cache-info` is hub-generated — small, never streamed or presigned.
        if path == "nix-cache-info" {
            let body = render_nix_cache_info(cache.want_mass_query, cache.priority);
            let resp = axum::response::IntoResponse::into_response((
                [
                    (header::CONTENT_TYPE, keymap::content_type(path)),
                    (header::CACHE_CONTROL, keymap::cache_control(path)),
                ],
                body,
            ));
            return Ok(Some(resp));
        }

        let requested = parse_byte_range(range_header);
        match placement_read::stream_from_placements(
            self.db.as_ref(),
            self.surface.as_ref(),
            SurfaceTarget::BinaryCache(cache.id),
            path,
            requested,
        )
        .await
        .map_err(RpcError::internal)?
        {
            PlacementReadOutcome::Found(read) => {
                if let Some(hash) = path.strip_suffix(".narinfo").filter(|h| !h.contains('/')) {
                    let _ = self
                        .db
                        .touch_cache_object(cache.id, hash, clock::now_unix_secs())
                        .await;
                }
                return Ok(Some(Self::streamed_surface_response(path, read.value)?));
            }
            PlacementReadOutcome::NotFound => return Ok(None),
            PlacementReadOutcome::NoPlacements => {
                // Transitional zero-placement snapshot: continue into the
                // resource-level migration reader below. Deleted at cutover.
            }
        }

        // A private external origin: the hub holds no local bytes. Either stream
        // the origin through the hub (proxy mode) or `302` the client to the
        // presigned URL — the same signed URL, differing only in who fetches it.
        if let Some(url) = self
            .presign_cache_read(&cache, path, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
        {
            // Streamed proxy: only when an OriginFetch is wired AND the cache's
            // primary frontend opts into it (`proxy_config.stream`). The hub
            // fetches the presigned URL and streams the body, so the origin
            // endpoint never reaches the client.
            if let Some(origin) = &self.origin_fetch {
                if let Some(proxy) = self.cache_streamed_proxy_config(&cache).await {
                    let Some(read) = origin
                        .get_stream(&url, requested)
                        .await
                        .map_err(RpcError::internal)?
                    else {
                        return Ok(None);
                    };
                    // Enforce the frontend's `max_body_bytes` guard against an
                    // oversized origin object (the origin declares its full size
                    // via Content-Length / Content-Range `total`).
                    if read.total > proxy.max_body_bytes {
                        return Err(RpcError::internal(anyhow::anyhow!(
                            "origin object {} bytes exceeds proxy max_body_bytes {}",
                            read.total,
                            proxy.max_body_bytes
                        )));
                    }
                    return Ok(Some(Self::streamed_surface_response(path, read)?));
                }
            }
            // Otherwise redirect the client to the presigned origin URL.
            let location = axum::http::HeaderValue::from_str(&url)
                .map_err(|e| RpcError::internal(anyhow::anyhow!("{e}")))?;
            return Ok(Some(axum::response::IntoResponse::into_response((
                StatusCode::FOUND,
                [(header::LOCATION, location)],
            ))));
        }

        // Stream the object (or a byte range) through the shared fetch port.
        let fetch = self
            .surface
            .cache_fetcher(&cache)
            .await
            .map_err(RpcError::internal)?;
        let Some(read) = fetch
            .fetch_stream(path, requested)
            .await
            .map_err(RpcError::internal)?
        else {
            return Ok(None);
        };

        // Tap the LRU access signal on a narinfo read (best-effort, debounced).
        if let Some(hash) = path.strip_suffix(".narinfo").filter(|h| !h.contains('/')) {
            let _ = self
                .db
                .touch_cache_object(cache.id, hash, clock::now_unix_secs())
                .await;
        }

        Ok(Some(Self::streamed_surface_response(path, read)?))
    }

    /// The proxy tuning to use for streamed proxying of a cache's private origin,
    /// or `None` to fall back to the default `302` presigned redirect.
    ///
    /// Consults the cache's *primary* serving frontend (or, if none is flagged
    /// primary, the highest-`consumer_priority` one — `list_cache_frontends`
    /// orders by `consumer_priority DESC, domain`, a deterministic order). Returns
    /// the frontend's [`ProxyConfig`](crate::db::ProxyConfig) only when its
    /// [`stream`](crate::db::ProxyConfig::stream) flag is set; otherwise (no
    /// frontend, no proxy config, `stream = false`, or a DB error) returns `None`
    /// so the safe default (`302`) always applies.
    async fn cache_streamed_proxy_config(
        &self,
        cache: &crate::db::Cache,
    ) -> Option<crate::db::ProxyConfig> {
        let frontends = self.db.list_cache_frontends(cache.id).await.ok()?;
        let chosen = frontends
            .iter()
            .find(|f| f.is_primary)
            .or_else(|| frontends.first());
        chosen
            .and_then(|f| f.proxy_config.as_ref())
            .filter(|p| p.stream)
            .cloned()
    }

    /// Builds the `200`/`206` response for a streamed surface object.
    ///
    /// Shared by the local-surface read and the streamed-origin proxy: a
    /// `StreamedRead` with a `Some` range becomes a `206 Partial Content` with
    /// `Content-Range`/`Content-Length`, and a `None` range a `200 OK` with
    /// `Content-Length`; both advertise `Accept-Ranges: bytes`. The selected
    /// topology placement is recorded only in structured server logs so an
    /// unauthenticated response cannot disclose internal storage topology.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] if the response builder rejects a header.
    fn streamed_surface_response(
        path: &str,
        read: crate::fetch::StreamedRead,
    ) -> Result<axum::response::Response, RpcError> {
        use axum::http::{header, StatusCode};
        let ct = keymap::content_type(path);
        let cc = keymap::cache_control(path);
        let mut builder = axum::response::Response::builder();
        if keymap::is_producer_document(path) {
            builder = builder
                .header(header::CONTENT_SECURITY_POLICY, "sandbox")
                .header(header::CONTENT_DISPOSITION, "attachment");
        }
        let resp = match read.range {
            Some((start, end)) => builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CACHE_CONTROL, cc)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", read.total),
                )
                .header(header::CONTENT_LENGTH, end - start + 1)
                .body(read.body),
            None => builder
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CACHE_CONTROL, cc)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_LENGTH, read.total)
                .body(read.body),
        }
        .map_err(|e| RpcError::internal(anyhow::anyhow!("{e}")))?;
        Ok(resp)
    }

    /// Write one object (`<hash>.narinfo` or `nar/<file>`) into a managed cache's
    /// surface — the cache half of the upload facade, so `nix copy --to
    /// <hub>/<cache>` works on both shells.
    ///
    /// Simpler than the registry write: NARs/narinfo are content-addressed and
    /// immutable, so there is no publish lease and no re-index. Requires cache
    /// write authority ([`Self::require_cache_admin`]); charges the org storage
    /// The effective per-request upload cap in bytes.
    ///
    /// The instance `max_upload_bytes` setting overrides the built-in
    /// [`MAX_UPLOAD_BYTES`] when an operator has set a positive value; otherwise
    /// the built-in default applies. Read on the write path so a change takes
    /// effect without a restart; a malformed or non-positive stored value falls
    /// back to the default (fail safe).
    async fn effective_max_upload_bytes(&self) -> usize {
        match self.db.instance_config_get("max_upload_bytes").await {
            Ok(Some(v)) => v
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .map_or(MAX_UPLOAD_BYTES, |n| {
                    usize::try_from(n).unwrap_or(MAX_UPLOAD_BYTES)
                }),
            _ => MAX_UPLOAD_BYTES,
        }
    }

    /// quota with a TOCTOU-safe reserve-before-write.
    async fn put_cache_path(
        &self,
        auth: Option<&str>,
        cache: &crate::db::Cache,
        path: &str,
        body: &[u8],
    ) -> FacadeWrite {
        if cache.deleted_at.is_some() {
            return FacadeWrite::NotFound;
        }
        if let Err(deny) = self.require_cache_admin(auth, cache.org_id).await {
            return auth_denial_to_facade_write(deny);
        }
        if !keymap::is_machine_path(path) {
            return FacadeWrite::BadPath("not a machine path");
        }
        if crate::url_guard::validate_http_surface_path(path).is_err() {
            return FacadeWrite::BadPath("unsafe surface path");
        }
        if body.len() > self.effective_max_upload_bytes().await {
            return FacadeWrite::TooLarge;
        }
        // Server-side narinfo signing: a key-bearing cache signs each uploaded
        // root-level `<hash>.narinfo` with its hosted Ed25519 key (replacing any
        // prior hub sig, preserving other keys' sigs), so consumers can verify
        // against the cache's trusted-public-key. NARs are content-addressed and
        // never signed. Requires both a hosted key and a wired sealer; without a
        // sealer the uploader's own `Sig:` lines pass through unchanged. A
        // sign/unseal failure fails the upload rather than silently storing an
        // unsigned narinfo for a cache that promises signatures.
        let signed_holder: Option<Vec<u8>> = if let (Some(_hash), Some(key_id), Some(sealer)) = (
            path.strip_suffix(".narinfo").filter(|h| !h.contains('/')),
            cache.hosted_key_id,
            self.sealer.as_ref(),
        ) {
            let text = match std::str::from_utf8(body) {
                Ok(text) => text,
                Err(_) => return FacadeWrite::BadPath("narinfo is not valid UTF-8"),
            };
            let (key_name, signing_key, _public) = match self
                .db
                .load_hosted_signing_key(sealer.as_ref(), key_id)
                .await
            {
                Ok(key) => key,
                Err(err) => return internal_write(err),
            };
            match crate::nix_sign::sign_narinfo(text, &key_name, &signing_key) {
                Ok(signed) => Some(signed.into_bytes()),
                Err(err) => return internal_write(err),
            }
        } else {
            None
        };
        let body: &[u8] = signed_holder.as_deref().unwrap_or(body);
        let writer = match self.surface_write.cache_writer(cache).await {
            Ok(writer) => writer,
            Err(err) => {
                tracing::warn!(
                    slug = %cache.slug,
                    error = %format!("{err:#}"),
                    "no writable surface for cache upload"
                );
                return FacadeWrite::NotWritable("cache surface is not writable");
            }
        };
        // Overwrite delta for the org quota: read the old size cheaply first.
        let old_len: Option<i64> = match self.surface.cache_fetcher(cache).await {
            Ok(fetch) => match fetch.size(path).await {
                Ok(size) => size.map(|s| s as i64),
                Err(err) => return internal_write(err),
            },
            Err(err) => return internal_write(err),
        };
        let existed = old_len.is_some();
        let delta_bytes = body.len() as i64 - old_len.unwrap_or(0);
        let delta_objects = i64::from(!existed);
        if let Some(org_id) = cache.org_id {
            match self
                .db
                .reserve_org_usage(org_id, delta_bytes, delta_objects)
                .await
            {
                Ok(true) => {}
                Ok(false) => return FacadeWrite::QuotaExceeded,
                Err(err) => return internal_write(err),
            }
        }
        if let Err(err) = writer.write(path, body).await {
            // Give the reservation back so a failed upload does not leak quota.
            if let Some(org_id) = cache.org_id {
                let _ = self
                    .db
                    .reserve_org_usage(org_id, -delta_bytes, -delta_objects)
                    .await;
            }
            return internal_write(err);
        }
        // Write-through the narinfo index so search / GC / browse see the upload.
        // Best-effort: the bytes are already durable on the surface (the source
        // of truth), and `cache_objects` is rebuildable by a re-scan, so a parse
        // or DB hiccup here is logged, not fatal to the upload.
        // Only a root-level `<hash>.narinfo` is a real index unit; a non-root
        // `*.narinfo` (a slash in the stem) is not a Nix narinfo location, so it
        // must not create a slash-bearing `cache_objects` primary key.
        if let Some(store_hash) = path.strip_suffix(".narinfo").filter(|h| !h.contains('/')) {
            if let Ok(text) = std::str::from_utf8(body) {
                if let Some(object) =
                    parse_cache_narinfo(cache.id, store_hash, text, clock::now_unix_secs())
                {
                    if let Err(err) = self.db.upsert_cache_object(&object).await {
                        tracing::warn!(
                            slug = %cache.slug, %store_hash,
                            error = %format!("{err:#}"),
                            "cache narinfo indexed write-through failed"
                        );
                    } else if let Err(err) = self.db.refresh_cache_usage(cache.id).await {
                        tracing::warn!(
                            slug = %cache.slug,
                            error = %format!("{err:#}"),
                            "cache usage refresh failed"
                        );
                    }
                }
            }
        }
        if existed {
            FacadeWrite::Overwritten
        } else {
            FacadeWrite::Created
        }
    }

    /// Resolve a managed registry by slug, requiring it be writable, or return
    /// the denial [`FacadeWrite`].
    ///
    /// `404` for an unknown slug or a registry under a soft-deleted org (the same
    /// contract the read facade enforces). `405` for a registry that exists but
    /// has no storage binding / no locally-writable surface root (it is read-only
    /// through the facade). On success, returns the record; the actual writable
    /// surface is obtained from the [`SurfaceWriteProvider`].
    async fn resolve_writable(&self, slug: &str) -> Result<RegistryRecord, FacadeWrite> {
        let registry = match self.db.registry_by_slug(slug).await {
            Ok(Some(registry)) => registry,
            Ok(None) => return Err(FacadeWrite::NotFound),
            Err(err) => return Err(internal_write(err)),
        };
        // A registry owned by a soft-deleted org stops serving immediately and
        // must not accept uploads: indistinguishable from one that never existed.
        if let Some(org_id) = registry.org_id {
            match self.db.org_is_active(org_id).await {
                Ok(true) => {}
                Ok(false) => return Err(FacadeWrite::NotFound),
                Err(err) => return Err(internal_write(err)),
            }
        }
        // A managed registry has a storage binding; that is what makes it
        // writable. Unowned phase-1 registries (no binding) are read-only.
        if registry.storage_binding_id.is_none() {
            return Err(FacadeWrite::NotWritable(
                "registry has no storage binding; uploads are not supported",
            ));
        }
        Ok(registry)
    }

    /// Authorize a write: require a Bearer JWT granting [`Permission::Publish`]
    /// on the registry's canonical scope, returning the token id on success.
    ///
    /// `401` when the `Authorization: Bearer <jwt>` header is missing or the JWT
    /// does not verify; `403` when it verifies but does not grant `Publish` on
    /// the registry scope.
    fn authorize_publish(
        &self,
        registry: &RegistryRecord,
        auth: Option<&str>,
    ) -> Result<String, FacadeWrite> {
        let value = auth.ok_or(FacadeWrite::Unauthorized("missing Authorization header"))?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(FacadeWrite::Unauthorized(
                "Authorization header must start with Bearer",
            ))?;
        let claims = self
            .jwt_keys
            .verify(token)
            .map_err(|_| FacadeWrite::Unauthorized("invalid token"))?;
        let scope = Scope::parse(&registry.slug);
        if token_allows(&claims, Permission::Publish, &scope) {
            Ok(claims.sub)
        } else {
            Err(FacadeWrite::Forbidden)
        }
    }

    /// Give a previously-made quota reservation back, best-effort.
    ///
    /// Called when a write is rejected *after* its quota was atomically reserved
    /// (a publish-lease conflict or a write failure), so a rejected upload does
    /// not permanently consume an org's quota. A failure is logged, not fatal
    /// (usage is approximate and reconciled by re-index/GC). No-op for an unowned
    /// registry (`org_id` is `None`).
    async fn release_reservation(
        &self,
        registry: &RegistryRecord,
        delta_bytes: i64,
        delta_objects: i64,
    ) {
        let Some(org_id) = registry.org_id else {
            return;
        };
        if let Err(err) = self
            .db
            .reserve_org_usage(org_id, -delta_bytes, -delta_objects)
            .await
        {
            tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "releasing quota reservation after a rejected upload failed"
            );
        }
    }

    /// Handle a facade `PUT` of one surface path for a managed registry.
    ///
    /// The shared, transport-free upload handler, single-sourced across the
    /// native hub and the Cloudflare Worker. It preserves every check, in order:
    /// [`resolve_writable`](Self::resolve_writable) (writable storage root, else
    /// `404`/`405`), [`authorize_publish`](Self::authorize_publish)
    /// ([`Permission::Publish`] at the registry scope, else `401`/`403`),
    /// [`is_machine_path`](keymap::is_machine_path) (`400`), the
    /// [`MAX_UPLOAD_BYTES`] cap (`413`), the **quota reserve-before-write**
    /// ([`reserve_org_usage`](crate::db::Database::reserve_org_usage) → `507`,
    /// charging the overwrite *delta* via the surface [`size`](crate::fetch::SurfaceFetch::size)),
    /// the **publish lease** for mutable pointers (`409` on conflict), the
    /// symlink-contained write through the [`SurfaceWrite`](crate::surface_write::SurfaceWrite)
    /// port, and the **inline re-index** for completing pointers via the
    /// [`Reindexer`] port. A reservation made for a write that is then rejected
    /// (lease conflict, write failure) is released, so a rejected upload never
    /// leaks quota.
    ///
    /// Returns [`FacadeWrite::Created`] (new file) or [`FacadeWrite::Overwritten`]
    /// (overwrite) on success; the transport renders the small `{"path": …}` JSON
    /// body and the status. Every denial maps to its [`FacadeWrite`] variant.
    ///
    /// # Errors
    ///
    /// Never returns `Err`: every failure is encoded as a [`FacadeWrite`] variant
    /// the transport renders as the matching HTTP status (internal failures are
    /// logged and surface as [`FacadeWrite::Internal`] → `500`).
    pub async fn put_machine_path(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        body: &[u8],
    ) -> FacadeWrite {
        // A managed cache write (content-addressed NARs/narinfo; no publish
        // lease, no re-index). Caches and registries are separate slug
        // namespaces, so a registry slug is never a cache. Both shells reach
        // this one method, so cache writes are at parity automatically.
        match self.db.cache_by_slug(slug).await {
            Ok(Some(cache)) => return self.put_cache_path(auth, &cache, path, body).await,
            Ok(None) => {}
            Err(err) => return internal_write(err),
        }
        let registry = match self.resolve_writable(slug).await {
            Ok(registry) => registry,
            Err(deny) => return deny,
        };
        let token_id = match self.authorize_publish(&registry, auth) {
            Ok(token_id) => token_id,
            Err(deny) => return deny,
        };

        if !keymap::is_machine_path(path) {
            return FacadeWrite::BadPath("not a machine path");
        }
        // Lexical traversal guard (portable across the native filesystem writer
        // and the R2 writer): reject `..`/absolute/doubled-slash paths up front
        // with `400`, before reserving quota or writing. The native writer
        // additionally enforces symlink containment at write time.
        if crate::url_guard::validate_http_surface_path(path).is_err() {
            return FacadeWrite::BadPath("unsafe surface path");
        }
        if body.len() > self.effective_max_upload_bytes().await {
            return FacadeWrite::TooLarge;
        }

        // The writable surface for this registry (the native filesystem writer
        // rooted at the storage binding, or the R2 writer scoped to the prefix).
        // A registration-only registry with no writable root errors here, which
        // maps to the `405` contract.
        let writer = match self.surface_write.writer(&registry).await {
            Ok(writer) => writer,
            Err(err) => {
                tracing::warn!(
                    slug = %registry.slug,
                    error = %format!("{err:#}"),
                    "no writable surface for upload"
                );
                return FacadeWrite::NotWritable("registry surface is not writable");
            }
        };

        // The old object size, if any, drives the overwrite delta. Read it
        // through the surface read port before reserving and writing, so an
        // overwrite charges only the size change and a new object charges its
        // full size.
        let old_len: Option<i64> = match self.surface.fetcher(&registry).await {
            Ok(fetch) => match fetch.size(path).await {
                Ok(size) => size.map(|s| s as i64),
                Err(err) => return internal_write(err),
            },
            Err(err) => return internal_write(err),
        };
        let existed = old_len.is_some();
        let new_len = body.len() as i64;
        // Charge the *delta*: new minus old on an overwrite (may be negative when
        // shrinking), or the full size for a new object.
        let delta_bytes = new_len - old_len.unwrap_or(0);
        let delta_objects = i64::from(!existed);

        // Quota gate (org-owned registries only): atomically check *and* reserve
        // the delta before any bytes land, rejecting an over-quota write `507`.
        // The reserve-then-write order closes the check-then-write TOCTOU window.
        if let Some(org_id) = registry.org_id {
            match self
                .db
                .reserve_org_usage(org_id, delta_bytes, delta_objects)
                .await
            {
                Ok(true) => {}
                Ok(false) => return FacadeWrite::QuotaExceeded,
                Err(err) => return internal_write(err),
            }
        }

        let mutable = is_mutable_pointer(path);
        if mutable {
            // Serialize this registry's pointer flips: the first mutable-pointer
            // write of a publish takes the lease; a different token is blocked
            // `409` while it is live. The reservation is released on conflict so
            // the rejected write does not leak quota.
            if let Err(holder) = self
                .lease
                .acquire(registry.id, &token_id, clock::now_unix_secs())
                .await
            {
                self.release_reservation(&registry, delta_bytes, delta_objects)
                    .await;
                tracing::warn!(
                    slug = %registry.slug,
                    %path,
                    held_by = %holder,
                    "publish lease conflict"
                );
                return FacadeWrite::LeaseConflict;
            }
        }

        if let Err(err) = writer.write(path, body).await {
            // The write failed after reserving (and possibly after taking the
            // lease); give the reservation back and release the lease so a failed
            // upload does not permanently consume quota or block other writers.
            self.release_reservation(&registry, delta_bytes, delta_objects)
                .await;
            if mutable {
                self.lease.release(registry.id, &token_id).await;
            }
            return internal_write(err);
        }

        // A pointer that completes a publish re-indexes inline (native) or defers
        // to the Cron indexer (Worker), per the [`Reindexer`] port.
        if mutable && triggers_reindex(path) {
            if let Err(err) = self.reindexer.reindex(&registry).await {
                // The bytes landed; a failed re-index is logged but the upload
                // itself succeeded.
                tracing::warn!(
                    slug = %registry.slug,
                    error = %format!("{err:#}"),
                    "re-index after pointer flip failed"
                );
            }
        }

        if existed {
            FacadeWrite::Overwritten
        } else {
            FacadeWrite::Created
        }
    }

    /// Resolve and authorize a writable surface for an upload to `(slug, path)`,
    /// returning the backend writer.
    ///
    /// Shared by the multipart upload methods ([`initiate_upload`](Self::initiate_upload),
    /// [`upload_part`](Self::upload_part), [`complete_upload`](Self::complete_upload),
    /// [`abort_upload`](Self::abort_upload)) so every multipart call enforces the
    /// *same* path-safety, authorization, and storage resolution as the
    /// single-`PUT` facade: a managed cache (its own slug namespace) requires
    /// cache-admin; a registry requires `Publish`. Re-resolving per call is what
    /// lets the protocol stay stateless (each request re-authorizes and rebuilds
    /// the writer; the backend holds the in-flight multipart state).
    ///
    /// Multipart is used only for large, content-addressed `nar/**` objects,
    /// which are never the mutable pointers the single-`PUT` path gates with a
    /// publish lease/quota-reservation/re-index, so those steps do not apply
    /// here. (A registry's per-write quota is still enforced at the single-`PUT`
    /// boundary for the small objects that flow through it.)
    ///
    /// # Errors
    ///
    /// Returns a [`FacadeWrite`] denial: `BadPath` for a non-machine/unsafe
    /// path, the auth denial for a missing/insufficient credential, `NotFound`
    /// for a deleted cache, `NotWritable` when the surface has no writable root,
    /// or an internal error on a store/db failure.
    async fn resolve_upload_writer(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
    ) -> Result<Box<dyn crate::surface_write::SurfaceWrite>, FacadeWrite> {
        if !keymap::is_machine_path(path) {
            return Err(FacadeWrite::BadPath("not a machine path"));
        }
        if crate::url_guard::validate_http_surface_path(path).is_err() {
            return Err(FacadeWrite::BadPath("unsafe surface path"));
        }
        match self.db.cache_by_slug(slug).await {
            Ok(Some(cache)) => {
                if cache.deleted_at.is_some() {
                    return Err(FacadeWrite::NotFound);
                }
                if let Err(deny) = self.require_cache_admin(auth, cache.org_id).await {
                    return Err(auth_denial_to_facade_write(deny));
                }
                return self
                    .surface_write
                    .cache_writer(&cache)
                    .await
                    .map_err(|_| FacadeWrite::NotWritable("cache surface is not writable"));
            }
            Ok(None) => {}
            Err(err) => return Err(internal_write(err)),
        }
        let registry = self.resolve_writable(slug).await?;
        let _token_id = self.authorize_publish(&registry, auth)?;
        self.surface_write
            .writer(&registry)
            .await
            .map_err(|_| FacadeWrite::NotWritable("registry surface is not writable"))
    }

    /// Begin a multipart upload of `path` under `slug`, returning the backend's
    /// opaque `upload_id`.
    ///
    /// Authorizes exactly as the single-`PUT` path
    /// ([`resolve_upload_writer`](Self::resolve_upload_writer)); the client then
    /// streams parts via [`upload_part`](Self::upload_part) and finalizes with
    /// [`complete_upload`](Self::complete_upload), each echoing this `upload_id`.
    ///
    /// # Errors
    ///
    /// Returns a [`FacadeWrite`] denial (see
    /// [`resolve_upload_writer`](Self::resolve_upload_writer)) or an internal
    /// error when the backend cannot begin a multipart upload.
    pub async fn initiate_upload(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
    ) -> Result<String, FacadeWrite> {
        let writer = self.resolve_upload_writer(auth, slug, path).await?;
        writer.create_multipart(path).await.map_err(internal_write)
    }

    /// Upload one part (`part_number`, 1-based) of the in-progress multipart
    /// upload `upload_id` for `(slug, path)`, returning its
    /// [`PartTag`](crate::surface_write::PartTag).
    ///
    /// Re-authorizes the caller and rebuilds the backend writer, then streams
    /// the single sub-cap part straight to the backend — peak memory is one part.
    ///
    /// # Errors
    ///
    /// Returns a [`FacadeWrite`] denial or an internal error when the part
    /// cannot be uploaded.
    pub async fn upload_part(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        upload_id: &str,
        part_number: u32,
        body: &[u8],
    ) -> Result<crate::surface_write::PartTag, FacadeWrite> {
        let writer = self.resolve_upload_writer(auth, slug, path).await?;
        writer
            .upload_part(path, upload_id, part_number, body)
            .await
            .map_err(internal_write)
    }

    /// Finalize the multipart upload `upload_id` for `(slug, path)`, assembling
    /// `parts` into the object.
    ///
    /// # Errors
    ///
    /// Returns a [`FacadeWrite`] denial or an internal error when assembly
    /// fails. On success returns [`FacadeWrite::Created`].
    pub async fn complete_upload(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        upload_id: &str,
        parts: &[crate::surface_write::PartTag],
    ) -> FacadeWrite {
        let writer = match self.resolve_upload_writer(auth, slug, path).await {
            Ok(writer) => writer,
            Err(deny) => return deny,
        };
        match writer.complete_multipart(path, upload_id, parts).await {
            Ok(()) => FacadeWrite::Created,
            Err(err) => internal_write(err),
        }
    }

    /// Abort the multipart upload `upload_id` for `(slug, path)`, freeing backend
    /// state. Best-effort; an unknown upload is not an error.
    ///
    /// # Errors
    ///
    /// Returns a [`FacadeWrite`] denial, or an internal error only on a fatal
    /// backend failure.
    pub async fn abort_upload(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        upload_id: &str,
    ) -> FacadeWrite {
        let writer = match self.resolve_upload_writer(auth, slug, path).await {
            Ok(writer) => writer,
            Err(deny) => return deny,
        };
        match writer.abort_multipart(path, upload_id).await {
            Ok(()) => FacadeWrite::Created,
            Err(err) => internal_write(err),
        }
    }

    /// Handle a facade `HEAD` of one surface path for a managed registry.
    ///
    /// Lets an uploader skip files it has already pushed:
    /// [`FacadeWrite::Present`] (`200`) when the file exists,
    /// [`FacadeWrite::NotFound`] (`404`) when it does not. Authorization matches
    /// [`put_machine_path`](Self::put_machine_path) (a probe reveals surface
    /// contents, so it requires `Publish`).
    ///
    /// # Errors
    ///
    /// Never returns `Err`: every failure is encoded as a [`FacadeWrite`] variant
    /// (`401`/`403`/`404`/`405`/`400`/`500`).
    pub async fn head_machine_path(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
    ) -> FacadeWrite {
        // Cache HEAD (e.g. `nix copy` skipping already-pushed objects, or a
        // substituter probe). Read visibility, not write auth: a public cache's
        // existence probe is open, unlike a registry HEAD (which reveals an
        // upload surface and thus needs Publish).
        match self.db.cache_by_slug(slug).await {
            Ok(Some(cache)) => {
                if let Err(deny) = self.require_cache_read(auth, &cache).await {
                    return auth_denial_to_facade_write(deny);
                }
                if !keymap::is_machine_path(path) {
                    return FacadeWrite::BadPath("not a machine path");
                }
                if path == "nix-cache-info" {
                    return FacadeWrite::Present;
                }
                return match self.surface.cache_fetcher(&cache).await {
                    Ok(fetch) => match fetch.size(path).await {
                        Ok(Some(_)) => FacadeWrite::Present,
                        Ok(None) => FacadeWrite::NotFound,
                        Err(err) => internal_write(err),
                    },
                    Err(err) => internal_write(err),
                };
            }
            Ok(None) => {}
            Err(err) => return internal_write(err),
        }
        let registry = match self.resolve_writable(slug).await {
            Ok(registry) => registry,
            Err(deny) => return deny,
        };
        if let Err(deny) = self.authorize_publish(&registry, auth) {
            return deny;
        }
        if !keymap::is_machine_path(path) {
            return FacadeWrite::BadPath("not a machine path");
        }
        if crate::url_guard::validate_http_surface_path(path).is_err() {
            return FacadeWrite::BadPath("unsafe surface path");
        }
        // Probe existence through the surface read port (filesystem stat / R2
        // head); a missing surface fetcher is an internal error.
        match self.surface.fetcher(&registry).await {
            Ok(fetch) => match fetch.size(path).await {
                Ok(Some(_)) => FacadeWrite::Present,
                Ok(None) => FacadeWrite::NotFound,
                Err(err) => internal_write(err),
            },
            Err(err) => internal_write(err),
        }
    }
}

/// Log an internal error and map it to [`FacadeWrite::Internal`] (`500`).
fn internal_write(err: anyhow::Error) -> FacadeWrite {
    tracing::error!(error = %format!("{err:#}"), "facade write failed");
    FacadeWrite::Internal
}

/// Map a cache-write auth denial ([`RpcError`]) onto the facade's wire outcome.
fn auth_denial_to_facade_write(err: RpcError) -> FacadeWrite {
    match err {
        RpcError::Unauthenticated(_) => FacadeWrite::Unauthorized("authentication required"),
        RpcError::PermissionDenied(_) => FacadeWrite::Forbidden,
        RpcError::NotFound(_) => FacadeWrite::NotFound,
        // require_cache_admin only yields the three denials above plus Internal.
        _ => FacadeWrite::Internal,
    }
}

/// Apply one revision of a revert draft to its live object.
///
/// Only `registry`-visibility revisions carry a live mutation this phase;
/// `token`/`invitation` exemption revisions are records-only (no live credential
/// or grant is resurrected), so they apply as no-ops.
async fn apply_revert_revision(
    db: &Database,
    revision: &crate::config::Revision,
) -> anyhow::Result<()> {
    if revision.object_type == "registry" {
        if let Some(visibility) = revision
            .new_json
            .as_ref()
            .and_then(|v| v.get("visibility"))
            .and_then(|v| v.as_str())
        {
            if let Some(record) = db.registry_by_slug(&revision.object_id).await? {
                db.set_registry_visibility(record.id, visibility).await?;
            }
        }
    }
    Ok(())
}

/// A surface a frontend may serve, for [`pick_direct_frontend`] eligibility.
#[derive(Clone, Copy)]
enum FrontendSurface {
    /// The dumb-HTTP git wire surface (a registry's clone/fetch endpoint).
    Git,
    /// The Nix binary-cache surface (`narinfo`/`nar`).
    Cache,
}

impl FrontendSurface {
    /// Whether `f` advertises this surface.
    fn served_by(self, f: &FrontendRecord) -> bool {
        match self {
            Self::Git => f.serves_git,
            Self::Cache => f.serves_cache,
        }
    }
}

/// Pick the highest-priority `direct`, advertised frontend in `frontends` that
/// serves `surface`, if any.
///
/// The `list_*` queries return frontends ordered by `consumer_priority DESC`,
/// so an explicit `is_primary` wins and otherwise the first (highest-priority)
/// eligible row does. Used by [`RpcService::cache_consumer_url`] and
/// [`RpcService::registry_consumer_url`] to advertise a bucket-direct URL when
/// one exists (RFC-0004 §12).
/// Resolve the consumer-facing base URL a binary cache is served at, over a
/// bare [`Database`] handle and `external_url` (no [`RpcService`] needed).
///
/// Prefers a **direct, advertised** cache frontend — the cache's own, else one
/// inherited from a public storage binding (with the cache's `prefix`
/// appended), gated by the cache's per-binding advertise opt-out — and falls
/// back to the hub-served `{external_url}/{cache_slug}`. The console's
/// `/-/settings/caches` reconciliation view calls this to match a managed
/// cache against a registry's committed `[caches]` URLs without constructing a
/// full [`RpcService`]; [`RpcService::cache_consumer_url`] delegates here.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn cache_consumer_url(
    db: &Database,
    external_url: &str,
    cache: &crate::db::Cache,
) -> anyhow::Result<String> {
    let own = db.list_cache_frontends(cache.id).await?;
    let advertise = db.cache_advertises_storage_frontend(cache.id).await?;
    if let Some(f) = pick_direct_frontend(&own, FrontendSurface::Cache) {
        return Ok(frontend_base_url(&f.domain, &f.base_path, ""));
    }
    if advertise {
        let binding = match cache.storage_binding_id {
            Some(id) => db.storage_binding(id).await?,
            None => db.instance_default_binding().await?,
        };
        if let Some(binding) = binding {
            if binding.access == "public" {
                let inherited = db.list_storage_frontends(binding.id).await?;
                if let Some(f) = pick_direct_frontend(&inherited, FrontendSurface::Cache) {
                    return Ok(frontend_base_url(&f.domain, &f.base_path, &cache.prefix));
                }
            }
        }
    }
    Ok(format!(
        "{}/{}",
        external_url.trim_end_matches('/'),
        cache.slug
    ))
}

fn pick_direct_frontend(
    frontends: &[FrontendRecord],
    surface: FrontendSurface,
) -> Option<&FrontendRecord> {
    let eligible: Vec<&FrontendRecord> = frontends
        .iter()
        .filter(|f| f.mode == "direct" && f.advertised && surface.served_by(f))
        .collect();
    eligible
        .iter()
        .copied()
        .find(|f| f.is_primary)
        .or_else(|| eligible.first().copied())
}

/// Join a frontend `domain`, its `base_path`, and a consumer `prefix` into a
/// consumer-facing base URL (`https://{domain}/{base_path}/{prefix}`), dropping
/// empty/`/`-only segments.
///
/// `prefix` is the consumer's upload location within the bucket, so an inherited
/// storage-binding frontend resolves to where that consumer's objects actually
/// live; pass `""` for a per-consumer frontend whose `base_path` is already the
/// consumer's root.
fn frontend_base_url(domain: &str, base_path: &str, prefix: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in [base_path, prefix] {
        let trimmed = segment.trim_matches('/');
        if !trimmed.is_empty() {
            segments.push(trimmed);
        }
    }
    if segments.is_empty() {
        format!("https://{domain}")
    } else {
        format!("https://{domain}/{}", segments.join("/"))
    }
}

#[cfg(test)]
mod cache_facade_tests {
    use super::{
        assess_cache_link, narinfo_store_hash, parse_cache_narinfo, render_nix_cache_info,
        visibility_rank, LinkAdvisory, RpcService,
    };
    use crate::fetch::StreamedRead;

    #[test]
    fn visibility_rank_orders_public_over_internal_over_private() {
        assert!(visibility_rank("public") > visibility_rank("internal"));
        assert!(visibility_rank("internal") > visibility_rank("private"));
        // An unknown value is treated as the most restrictive, never widening.
        assert_eq!(visibility_rank("bogus"), visibility_rank("private"));
    }

    #[test]
    fn assess_cache_link_rejects_advertising_a_less_visible_cache() {
        // Public registry, private cache, advertised → consumers couldn't read
        // it, so the link is refused.
        let a = assess_cache_link("c", "private", "r", "public", true, false);
        assert!(a.reject.is_some(), "{a:?}");
        assert!(a.warning.is_none());
        // Not advertised: no consumer is handed the cache, so nothing to reject.
        let a = assess_cache_link("c", "private", "r", "public", false, false);
        assert_eq!(a, LinkAdvisory::default());
    }

    #[test]
    fn assess_cache_link_warns_on_rooting_into_a_more_visible_cache() {
        // Private registry, public cache, rooting its packages → exposes the
        // registry's closures more widely. Allowed (no reject) but warned.
        let a = assess_cache_link("c", "public", "r", "private", false, true);
        assert!(a.reject.is_none(), "{a:?}");
        assert!(a.warning.is_some());
        // Advertising the more-visible cache is fine — consumers can read it.
        let a = assess_cache_link("c", "public", "r", "private", true, false);
        assert_eq!(a, LinkAdvisory::default());
    }

    #[test]
    fn assess_cache_link_is_calm_at_equal_visibility() {
        let a = assess_cache_link("c", "internal", "r", "internal", true, true);
        assert_eq!(a, LinkAdvisory::default());
    }

    #[test]
    fn narinfo_store_hash_strips_path_and_name() {
        assert_eq!(narinfo_store_hash("/nix/store/abc123-foo-1.0"), "abc123");
        assert_eq!(narinfo_store_hash("abc123-foo-1.0"), "abc123");
        assert_eq!(narinfo_store_hash("abc123"), "abc123");
    }

    #[test]
    fn parse_narinfo_extracts_fields_and_refs() {
        let text = "StorePath: /nix/store/abc-foo-1.0\n\
                    URL: nar/deadbeef.nar.zst\n\
                    Compression: zstd\n\
                    NarHash: sha256:aaa\n\
                    NarSize: 100\n\
                    FileHash: sha256:bbb\n\
                    FileSize: 50\n\
                    References: abc-foo-1.0 def-bar-2.0\n\
                    Deriver: ghi-foo.drv\n\
                    Sig: key:sigvalue\n";
        let o = parse_cache_narinfo(7, "abc", text, 123).unwrap();
        assert_eq!(o.cache_id, 7);
        assert_eq!(o.store_hash, "abc");
        assert_eq!(o.store_name, "abc-foo-1.0");
        assert_eq!(o.nar_url, "nar/deadbeef.nar.zst");
        assert_eq!(o.compression, "zstd");
        assert_eq!(o.nar_size, 100);
        assert_eq!(o.file_size, 50);
        assert_eq!(o.refs, vec!["abc".to_string(), "def".to_string()]);
        assert_eq!(o.deriver.as_deref(), Some("ghi-foo.drv"));
        assert_eq!(o.sig.as_deref(), Some("key:sigvalue"));
        assert_eq!(o.uploaded_at, 123);
    }

    #[test]
    fn parse_narinfo_keeps_multiple_sig_lines() {
        let text = "StorePath: /nix/store/x-a\nURL: nar/y.nar\nSig: k1:a\nSig: k2:b\n";
        let o = parse_cache_narinfo(1, "x", text, 0).unwrap();
        assert_eq!(o.sig.as_deref(), Some("k1:a\nk2:b"));
    }

    #[test]
    fn parse_narinfo_empty_compression_keeps_default() {
        let text = "StorePath: /nix/store/x-a\nURL: nar/y.nar\nCompression:\n";
        let o = parse_cache_narinfo(1, "x", text, 0).unwrap();
        assert_eq!(o.compression, "none");
    }

    #[test]
    fn parse_narinfo_requires_storepath_and_url() {
        assert!(parse_cache_narinfo(1, "x", "Compression: zstd\n", 0).is_none());
        assert!(parse_cache_narinfo(1, "x", "StorePath: /nix/store/x-a\n", 0).is_none());
    }

    #[test]
    fn nix_cache_info_shape() {
        let s = render_nix_cache_info(true, 40);
        assert!(s.contains("StoreDir: /nix/store"), "{s}");
        assert!(s.contains("WantMassQuery: 1"), "{s}");
        assert!(s.contains("Priority: 40"), "{s}");
        assert!(render_nix_cache_info(false, 7).contains("WantMassQuery: 0"));
    }

    #[test]
    fn streamed_topology_read_does_not_expose_the_placement() {
        let response = RpcService::streamed_surface_response(
            "nar/example.nar",
            StreamedRead {
                body: axum::body::Body::from("data"),
                total: 4,
                range: None,
            },
        )
        .unwrap();
        assert!(!response.headers().contains_key("x-aos-placement"));
    }

    #[test]
    fn streamed_producer_document_is_inert() {
        let response = RpcService::streamed_surface_response(
            "index.html",
            StreamedRead {
                body: axum::body::Body::from("<script>bad()</script>"),
                total: 22,
                range: None,
            },
        )
        .unwrap();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_SECURITY_POLICY)
                .and_then(|value| value.to_str().ok()),
            Some("sandbox")
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok()),
            Some("attachment")
        );
    }
}

#[cfg(test)]
mod frontend_url_tests {
    use super::{frontend_base_url, pick_direct_frontend, FrontendSurface};
    use crate::db::FrontendRecord;

    /// The cache surface, the subject of these tests.
    const CACHE: FrontendSurface = FrontendSurface::Cache;

    fn frontend(mode: &str, advertised: bool, serves_cache: bool) -> FrontendRecord {
        FrontendRecord {
            id: 0,
            registry_id: None,
            cache_id: None,
            storage_binding_id: Some(1),
            domain: "cdn.example.com".into(),
            base_path: String::new(),
            mode: mode.into(),
            serves_git: true,
            serves_cache,
            serves_web: true,
            consumer_priority: 100,
            advertised,
            proxy_config: None,
            is_primary: false,
            created_at: 0,
        }
    }

    #[test]
    fn base_url_joins_and_trims_segments() {
        assert_eq!(
            frontend_base_url("cdn.example.com", "/v1/", "acme/prod/"),
            "https://cdn.example.com/v1/acme/prod"
        );
        assert_eq!(
            frontend_base_url("cdn.example.com", "", "acme"),
            "https://cdn.example.com/acme"
        );
        // An empty base_path and prefix (a per-consumer frontend at the root).
        assert_eq!(
            frontend_base_url("cdn.example.com", "", ""),
            "https://cdn.example.com"
        );
    }

    #[test]
    fn pick_requires_direct_advertised_and_serving() {
        // Proxied, unadvertised, or non-cache-serving frontends are ineligible.
        assert!(pick_direct_frontend(&[frontend("proxied", true, true)], CACHE).is_none());
        assert!(pick_direct_frontend(&[frontend("direct", false, true)], CACHE).is_none());
        assert!(pick_direct_frontend(&[frontend("direct", true, false)], CACHE).is_none());
        assert!(pick_direct_frontend(&[frontend("direct", true, true)], CACHE).is_some());
        // The same row serves the git surface (serves_git is true in the fixture).
        assert!(
            pick_direct_frontend(&[frontend("direct", true, false)], FrontendSurface::Git)
                .is_some()
        );
    }

    #[test]
    fn pick_prefers_primary_then_priority_order() {
        let mut primary = frontend("direct", true, true);
        primary.domain = "primary.example.com".into();
        primary.is_primary = true;
        let mut first = frontend("direct", true, true);
        first.domain = "first.example.com".into();
        // `is_primary` wins regardless of list position.
        let list = [first.clone(), primary.clone()];
        assert_eq!(
            pick_direct_frontend(&list, CACHE).unwrap().domain,
            "primary.example.com"
        );
        // Without a primary, the first (highest-priority) eligible row wins.
        let list = [first, frontend("direct", true, true)];
        assert_eq!(
            pick_direct_frontend(&list, CACHE).unwrap().domain,
            "first.example.com"
        );
    }
}

#[cfg(test)]
mod placement_mutation_tests {
    use super::{RpcError, RpcService};
    use crate::db::SurfacePlacementBlockers;

    #[test]
    fn blocker_errors_are_stable_topology_preconditions() {
        let direct = RpcService::placement_route_pin_error(SurfacePlacementBlockers {
            direct_route: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(direct.code(), "failed_precondition");
        assert_eq!(
            direct.message(),
            "placement is pinned by a direct delivery route"
        );

        let routed = RpcService::placement_route_pin_error(SurfacePlacementBlockers {
            routed_policy: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            routed.message(),
            "placement is pinned by a delivery-route placement policy"
        );

        let cases = [
            (
                SurfacePlacementBlockers {
                    direct_route: true,
                    ..Default::default()
                },
                "placement is referenced by a direct delivery route",
            ),
            (
                SurfacePlacementBlockers {
                    policy_member: true,
                    ..Default::default()
                },
                "placement is referenced by a placement policy",
            ),
            (
                SurfacePlacementBlockers {
                    object_presence: true,
                    ..Default::default()
                },
                "placement has object-presence inventory",
            ),
            (
                SurfacePlacementBlockers {
                    publication: true,
                    ..Default::default()
                },
                "placement has registry-publication state",
            ),
            (
                SurfacePlacementBlockers {
                    deletion_job: true,
                    ..Default::default()
                },
                "placement has object-deletion jobs",
            ),
            (
                SurfacePlacementBlockers {
                    topology_operation: true,
                    ..Default::default()
                },
                "placement has topology operations",
            ),
        ];
        for (blockers, expected) in cases {
            let error = RpcService::placement_delete_blocker_error(blockers).unwrap();
            assert_eq!(error.code(), "failed_precondition");
            assert_eq!(error.message(), expected);
            assert!(!error.message().contains("FOREIGN KEY"));
        }
    }

    #[test]
    fn unclassified_create_failures_remain_internal() {
        let error = RpcService::placement_create_error(anyhow::anyhow!("database unavailable"));
        assert!(matches!(error, RpcError::Internal));
        assert_eq!(error.message(), "internal error");
    }
}
