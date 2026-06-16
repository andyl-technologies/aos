//! The transport-free registry-hub service layer (RFC-0004 Phase 5).
//!
//! [`RpcService`] holds the `aos.registry.v1` method bodies once, decoupled
//! from any HTTP framework or wire protocol. Both deployment targets call it:
//!
//! - the **native hub** mounts it behind `axum` (served via `axum::serve`);
//! - the **Cloudflare Worker** mounts the *same* handlers via
//!   `axum-cloudflare-adapter`.
//!
//! Because the `connectrpc` server runtime cannot target `wasm32`, the hub does
//! not run it; instead these methods are served as **Connect-JSON** — plain
//! JSON over HTTP, `POST /aos.registry.v1.{Service}/{Method}` — by a thin `axum`
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
//! POST /aos.registry.v1.RegistryService/GetRegistry
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", "index_state": "fresh", … } }
//!   -> 404 { "code": "not_found", "message": "registry not found" }
//! ```

use std::sync::Arc;

use aos_proto_types as pb;

use crate::auth::jwt::{Claims, JwtKeys};
use crate::db::{Database, IndexStatus, RegistryRecord};
use crate::domain::iam::{self, claims_principal, token_allows};
use crate::domain::{Permission, Scope};

/// Default page size when a list request leaves `page_size` at zero.
const DEFAULT_PAGE_SIZE: u32 = 500;
/// Hard ceiling on page size.
const MAX_PAGE_SIZE: u32 = 1000;

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

/// Project an [`OrgRecord`](crate::db::OrgRecord) onto the wire [`pb::Org`].
fn org_message(org: &crate::db::OrgRecord) -> pb::Org {
    pb::Org {
        slug: org.slug.clone(),
        name: org.name.clone(),
        created_at: org.created_at,
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

/// The shared, transport-free implementation of the `aos.registry.v1` services.
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
}

impl RpcService {
    /// Construct the service over its dependencies.
    #[must_use]
    pub fn new(db: Arc<Database>, jwt_keys: JwtKeys, external_url: String) -> Self {
        Self {
            db,
            jwt_keys,
            external_url,
        }
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
        let denied = || RpcError::PermissionDenied(format!("{} permission required", perm.as_str()));
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

    /// Resolve a registry by slug or map a miss to `NotFound`.
    async fn registry_or_not_found(&self, slug: &str) -> Result<RegistryRecord, RpcError> {
        self.db
            .registry_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))
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
            .list_caches(record.id)
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
            state: "indexing".into(),
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
        let records = self.db.list_registries().await.map_err(RpcError::internal)?;
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

    /// `OrgService.GetOrg` — look up an organization by slug.
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

    /// `OrgService.ListOrgs` — the organizations the caller is a member of,
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

    /// `StorageService.ListBindings` — an org's storage bindings, by name.
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
            .map(|b| pb::Binding {
                org_slug: org.slug.clone(),
                name: b.name,
                kind: b.kind,
                root: if expose_root { b.root } else { String::new() },
            })
            .collect();
        Ok(pb::ListBindingsResponse { bindings })
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

    /// `ConfigService.ListChangesets` — change-sets at a scope, newest first.
    ///
    /// Reads require [`Permission::AuditRead`] on the scope (ConfigService
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

    /// `ConfigService.GetChangeset` — one change-set's revisions and diffs.
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
        self.require_permission(&claims, Permission::AuditRead, &Scope::parse(&summary.scope))
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
}
