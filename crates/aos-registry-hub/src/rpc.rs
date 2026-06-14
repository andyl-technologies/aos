//! ConnectRPC implementation of the `aos.registry.v1` read-path services.
//!
//! The browser, the CLIs, and third parties share one schema
//! (`crates/aos-proto/src/proto/aos/registry/v1/registry.proto`): registry
//! summaries with verified index status, package listings and detail,
//! channel partition maps, and signed releases. Everything answers from
//! the rebuildable index — these RPCs never touch a registry surface
//! directly, so they are as fast and as available as the database.
//!
//! Phase-1 read-path RPCs are public, matching the anonymous browse pages.
//! Phase-2c adds the tenancy write-path services — [`OrgService`],
//! [`ProjectService`], [`StorageService`], and `RegistryService.CreateRegistry`
//! — which mutate the system of record and so are *authenticated*: the
//! caller presents the same `Authorization: Bearer <jwt>` it would on a
//! machine path, read out of the Connect [`Context`] (mirroring
//! `aos-server`'s `require_rpc_claims`). `CreateOrg` is the bootstrap
//! exception — any authenticated principal may create an org and is granted
//! `Owner` on it — while the other mutations require the caller's JWT to
//! carry `registry.configure` on the org scope.
//!
//! List RPCs paginate with opaque offset tokens.

// `ConnectError`'s size is fixed by the connectrpc service traits, which
// return it un-boxed; boxing the local helpers would only add unwrapping
// noise at every `?` site.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use aos_proto::aos::registry::v1::*;
use axum::http::header;
use buffa::view::OwnedView;
use buffa::MessageField;
use connectrpc::{ConnectError, Context, ErrorCode};

use crate::auth::jwt::{Claims, JwtKeys};
use crate::auth::permission_from_str;
use crate::db::{Database, IndexStatus, RegistryRecord};
use crate::domain::{iam, Permission, Principal, PrincipalKind, Scope};

/// Default page size when a list request leaves `page_size` at zero.
const DEFAULT_PAGE_SIZE: u32 = 500;
/// Hard ceiling on page size.
const MAX_PAGE_SIZE: u32 = 1000;

/// Default lifetime, in seconds, of a minted upload credential (1 hour).
///
/// A `MintUploadCredentials` token is a short-lived provisioning secret
/// scoped to one registry; it lives only long enough for a producer to drive a
/// publish.
pub const UPLOAD_CREDENTIAL_TTL_SECS: i64 = 3600;

/// Shared implementation state for all registry-hub ConnectRPC services.
pub struct RegistryRpc {
    /// The hub database.
    pub db: Arc<Database>,
    /// HS256 keys for verifying the bearer JWT on mutating RPCs.
    pub jwt_keys: JwtKeys,
    /// The externally reachable base URL, used to build the canonical upload
    /// URL returned by `MintUploadCredentials`.
    pub external_url: String,
}

fn internal(err: anyhow::Error) -> ConnectError {
    tracing::error!(error = %format!("{err:#}"), "rpc failed");
    ConnectError::new(ErrorCode::Internal, "internal error")
}

fn not_found(what: &str) -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, format!("{what} not found"))
}

fn invalid(msg: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, msg.into())
}

/// Slice one page out of `items` using an opaque offset token.
///
/// Returns the page and the `next_page_token` (empty when exhausted).
fn paginate<T>(
    items: Vec<T>,
    page_size: u32,
    token: &str,
) -> Result<(Vec<T>, String), ConnectError> {
    let offset: usize = if token.is_empty() {
        0
    } else {
        token
            .parse()
            .map_err(|_| ConnectError::new(ErrorCode::InvalidArgument, "invalid page_token"))?
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

impl RegistryRpc {
    fn registry_or_not_found(&self, slug: &str) -> Result<RegistryRecord, ConnectError> {
        self.db
            .registry_by_slug(slug)
            .map_err(internal)?
            .ok_or_else(|| not_found("registry"))
    }

    fn registry_message(
        &self,
        record: &RegistryRecord,
        status: Option<IndexStatus>,
    ) -> Result<Registry, ConnectError> {
        let caches = self
            .db
            .list_caches(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|(url, priority)| Cache {
                url,
                priority,
                ..Default::default()
            })
            .collect();
        let roster = self
            .db
            .list_roster(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|(id, key, status)| RosterKey {
                id,
                key,
                status,
                ..Default::default()
            })
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
        Ok(Registry {
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
            ..Default::default()
        })
    }

    /// Decode and verify the bearer JWT carried by a mutating RPC.
    ///
    /// Mirrors `aos-server`'s `require_rpc_claims`: pulls
    /// `Authorization: Bearer <jwt>` out of the Connect [`Context`] and
    /// verifies it with the hub's HS256 keys.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` when the header is missing, not ASCII, not
    /// a `Bearer` token, or fails JWT verification.
    fn require_claims(&self, ctx: &Context) -> Result<Claims, ConnectError> {
        let header = ctx
            .header(&header::AUTHORIZATION)
            .ok_or_else(|| {
                ConnectError::new(ErrorCode::Unauthenticated, "missing Authorization header")
            })?
            .to_str()
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "invalid Authorization header encoding",
                )
            })?;
        let token = header.strip_prefix("Bearer ").ok_or_else(|| {
            ConnectError::new(
                ErrorCode::Unauthenticated,
                "Authorization header must start with Bearer",
            )
        })?;
        self.jwt_keys
            .verify(token)
            .map_err(|e| ConnectError::new(ErrorCode::Unauthenticated, e.to_string()))
    }

    /// Require that a verified caller holds `perm` on `scope`.
    ///
    /// Combines the JWT's *own* grant (scope-contains plus explicit verbs)
    /// with the owner's *current* memberships: the action is allowed only if
    /// both the token and the principal's live grants cover it, so a revoked
    /// role denies immediately even on an unexpired token.
    ///
    /// # Errors
    ///
    /// Returns `PermissionDenied` when either the token or the principal's
    /// current memberships fail to authorize the action, and `Internal` on a
    /// database failure while loading memberships.
    fn require_permission(
        &self,
        claims: &Claims,
        perm: Permission,
        scope: &Scope,
    ) -> Result<(), ConnectError> {
        let token_ok = Scope::parse(&claims.scope).contains(scope)
            && claims
                .perms
                .iter()
                .filter_map(|p| permission_from_str(p))
                .any(|p| p == perm);
        if !token_ok {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                format!("{} permission required", perm.as_str()),
            ));
        }
        let Some(principal) = claims_principal(claims) else {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "unknown principal kind",
            ));
        };
        let grants = self.db.effective_scopes(principal).map_err(internal)?;
        if iam::allow(&grants, perm, scope) {
            Ok(())
        } else {
            Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                format!("{} permission required", perm.as_str()),
            ))
        }
    }

    /// Whether `claims`'s principal may create an org under `invite_only`.
    ///
    /// Permitted when the caller is an existing member of some org, holds a
    /// live invitation for their email, or is an instance admin (an
    /// `iam.admin`-bearing grant at the instance root). Service-account
    /// callers are permitted (a CI principal acts on behalf of an already
    /// provisioned org).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    fn signup_permitted(&self, claims: &Claims) -> Result<bool, anyhow::Error> {
        let Some(principal) = claims_principal(claims) else {
            return Ok(false);
        };
        if principal.kind != PrincipalKind::User {
            return Ok(true);
        }
        if self.db.user_has_any_membership(principal.id)? {
            return Ok(true);
        }
        // Instance admin: an iam.admin grant at the instance root.
        let grants = self.db.effective_scopes(principal)?;
        if iam::allow(&grants, Permission::IamAdmin, &Scope::root()) {
            return Ok(true);
        }
        // A live invitation for the caller's email.
        if let Some(email) = self.db.user_email(principal.id)? {
            if self.db.has_pending_invitation(&email)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Authorize a read of `registry` over a Connect context, following
    /// registry visibility and the owning org's lifecycle.
    ///
    /// A registry owned by a soft-deleted org returns `NotFound`: a deleted
    /// org stops serving immediately, so its registries must be indistinguishable
    /// from never having existed (the same contract the browse/read facade
    /// enforces). For a live org, a `public` registry (and any unowned phase-1
    /// registry) reads anonymously; an `internal` or `private` registry requires
    /// a bearer JWT granting [`Permission::Read`] on the registry scope
    /// (intersected with the owner's current grants by
    /// [`Self::require_permission`]).
    ///
    /// # Errors
    ///
    /// Returns `NotFound` when the owning org is soft-deleted, and
    /// `Unauthenticated`/`PermissionDenied` when a non-public registry is read
    /// without sufficient authority.
    fn require_read(&self, ctx: &Context, registry: &RegistryRecord) -> Result<(), ConnectError> {
        if let Some(org_id) = registry.org_id {
            if !self.db.org_is_active(org_id).map_err(internal)? {
                return Err(not_found("registry"));
            }
        }
        if registry.visibility == "public" || registry.org_id.is_none() {
            return Ok(());
        }
        let claims = self.require_claims(ctx)?;
        self.require_permission(&claims, Permission::Read, &Scope::parse(&registry.slug))
    }

    /// The current verified HEAD commit oid of a registry's tracked branch.
    ///
    /// # Errors
    ///
    /// Returns `FailedPrecondition` when the registry has no indexed HEAD yet,
    /// `InvalidArgument` for a malformed stored oid, and `Internal` on database
    /// failure.
    fn head_commit(
        &self,
        registry: &RegistryRecord,
    ) -> Result<crate::surface::object::Oid, ConnectError> {
        let hex = self
            .db
            .index_status(registry.id)
            .map_err(internal)?
            .and_then(|s| s.last_indexed_commit)
            .ok_or_else(|| {
                ConnectError::new(
                    ErrorCode::FailedPrecondition,
                    "registry has no indexed commit yet",
                )
            })?;
        crate::surface::object::Oid::from_hex(&hex).map_err(|e| invalid(format!("{e:#}")))
    }

    /// Resolve an org by slug or map a miss to `NotFound`.
    fn org_or_not_found(&self, slug: &str) -> Result<crate::db::OrgRecord, ConnectError> {
        self.db
            .org_by_slug(slug)
            .map_err(internal)?
            .ok_or_else(|| not_found("org"))
    }
}

/// Map a JWT's owner claims to a domain [`Principal`], if the kind is known.
fn claims_principal(claims: &Claims) -> Option<Principal> {
    PrincipalKind::parse(&claims.owner_kind).map(|kind| Principal {
        kind,
        id: claims.owner_id,
    })
}

fn org_message(org: &crate::db::OrgRecord) -> Org {
    Org {
        slug: org.slug.clone(),
        name: org.name.clone(),
        created_at: org.created_at,
        ..Default::default()
    }
}

impl RegistryService for RegistryRpc {
    /// `ListRegistries` — every registered registry with index status.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for a malformed `page_token` and
    /// `Internal` on database failure.
    async fn list_registries(
        &self,
        ctx: Context,
        req: OwnedView<ListRegistriesRequestView<'static>>,
    ) -> Result<(ListRegistriesResponse, Context), ConnectError> {
        let records = self.db.list_registries().map_err(internal)?;
        let mut registries = Vec::with_capacity(records.len());
        for record in &records {
            let status = self.db.index_status(record.id).map_err(internal)?;
            registries.push(self.registry_message(record, status)?);
        }
        let (registries, next_page_token) = paginate(registries, req.page_size, req.page_token)?;
        Ok((
            ListRegistriesResponse {
                registries,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetRegistry` — one registry by slug.
    ///
    /// Reads follow registry visibility (and the owning org's lifecycle): a
    /// private/internal registry requires `Read`, and a registry owned by a
    /// soft-deleted org returns `NotFound`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug or a soft-deleted owning org,
    /// `Unauthenticated`/`PermissionDenied` when a non-public registry is read
    /// without sufficient authority, and `Internal` on database failure.
    async fn get_registry(
        &self,
        ctx: Context,
        req: OwnedView<GetRegistryRequestView<'static>>,
    ) -> Result<(GetRegistryResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        self.require_read(&ctx, &record)?;
        let status = self.db.index_status(record.id).map_err(internal)?;
        Ok((
            GetRegistryResponse {
                registry: Some(self.registry_message(&record, status)?).into(),
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListReleases` — verified signed releases, newest first.
    ///
    /// Reads follow registry visibility (and the owning org's lifecycle): a
    /// private/internal registry requires `Read`, and a registry owned by a
    /// soft-deleted org returns `NotFound`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug or a soft-deleted owning org,
    /// `Unauthenticated`/`PermissionDenied` when a non-public registry is read
    /// without sufficient authority, `InvalidArgument` for a malformed
    /// `page_token`, and `Internal` on database failure.
    async fn list_releases(
        &self,
        ctx: Context,
        req: OwnedView<ListReleasesRequestView<'static>>,
    ) -> Result<(ListReleasesResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        self.require_read(&ctx, &record)?;
        let releases: Vec<Release> = self
            .db
            .list_releases(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|r| Release {
                semver: r.semver,
                tag_oid: r.tag_oid,
                commit_oid: r.commit_oid,
                signer: r.signer.unwrap_or_default(),
                tagged_at: r.tagged_at.unwrap_or_default(),
                ..Default::default()
            })
            .collect();
        let (releases, next_page_token) = paginate(releases, req.page_size, req.page_token)?;
        Ok((
            ListReleasesResponse {
                releases,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `CreateRegistry` — create an org-owned, storage-bound managed
    /// registry (phase 2c write path).
    ///
    /// The registry is created at the canonical path
    /// `{org}/{project_path}/{name}` with the given visibility, optionally
    /// bound to a named storage binding plus prefix, and indexed lazily by
    /// the background re-indexer.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `registry.configure` on the
    /// org scope, `NotFound` for an unknown org or `binding_name`,
    /// `InvalidArgument` for a missing name or bad visibility,
    /// `AlreadyExists` when a registry occupies the canonical path, and
    /// `Internal` on database failure.
    async fn create_registry(
        &self,
        ctx: Context,
        req: OwnedView<CreateRegistryRequestView<'static>>,
    ) -> Result<(CreateRegistryResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let org = self.org_or_not_found(req.org_slug)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.slug),
        )?;
        if req.name.is_empty() {
            return Err(invalid("registry name is required"));
        }
        let visibility = match req.visibility {
            "" => "private",
            v @ ("public" | "internal" | "private") => v,
            other => return Err(invalid(format!("invalid visibility '{other}'"))),
        };
        let binding_id = if req.binding_name.is_empty() {
            None
        } else {
            Some(
                self.db
                    .storage_binding_by_name(org.id, req.binding_name)
                    .map_err(internal)?
                    .ok_or_else(|| not_found("storage binding"))?
                    .id,
            )
        };
        let trust_keys: Vec<String> = req.trust_keys.iter().map(|s| s.to_string()).collect();
        let id = self
            .db
            .create_managed_registry(
                org.id,
                req.project_path,
                req.name,
                visibility,
                binding_id,
                req.prefix,
                &trust_keys,
                true,
            )
            .map_err(|e| ConnectError::new(ErrorCode::AlreadyExists, format!("{e:#}")))?;
        let record = self
            .db
            .registry_by_scope(&org.slug, req.project_path, req.name)
            .map_err(internal)?
            .ok_or_else(|| internal(anyhow::anyhow!("registry {id} vanished after creation")))?;
        let status = self.db.index_status(record.id).map_err(internal)?;
        Ok((
            CreateRegistryResponse {
                registry: MessageField::some(self.registry_message(&record, status)?),
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl OrgService for RegistryRpc {
    /// `CreateOrg` — create an organization and grant the caller `Owner`.
    ///
    /// The bootstrap exception: any authenticated principal may create an
    /// org. When the caller's JWT owner is a user, that user is granted the
    /// `Owner` role at the new org's scope so they can immediately configure
    /// it; a service-account caller creates the org without an auto-grant.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `InvalidArgument` for an empty slug or name, `AlreadyExists` when the
    /// slug is taken, and `Internal` on database failure.
    async fn create_org(
        &self,
        ctx: Context,
        req: OwnedView<CreateOrgRequestView<'static>>,
    ) -> Result<(CreateOrgResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        if req.slug.is_empty() || req.name.is_empty() {
            return Err(invalid("org slug and name are required"));
        }
        // Instance signup policy: `open` lets any authenticated principal
        // create an org; `invite_only` requires the caller to already be a
        // member, hold a live invitation, or be an instance admin.
        if self.db.signup_policy().map_err(internal)? == crate::db::SignupPolicy::InviteOnly
            && !self.signup_permitted(&claims).map_err(internal)?
        {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "org creation is invite-only on this instance",
            ));
        }
        let id = self
            .db
            .create_org(req.slug, req.name)
            .map_err(|e| ConnectError::new(ErrorCode::AlreadyExists, format!("{e:#}")))?;
        // Auto-grant the creating user Owner on the new org.
        if let Some(principal) = claims_principal(&claims) {
            if principal.kind == PrincipalKind::User {
                self.db
                    .grant_membership(
                        principal.kind.as_str(),
                        principal.id,
                        req.slug,
                        crate::domain::Role::Owner.as_str(),
                    )
                    .map_err(internal)?;
            }
        }
        let org = self
            .db
            .org_by_id(id)
            .map_err(internal)?
            .ok_or_else(|| internal(anyhow::anyhow!("org {id} vanished after creation")))?;
        Ok((
            CreateOrgResponse {
                org: MessageField::some(org_message(&org)),
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetOrg` — look up an organization by slug.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug and `Internal` on database
    /// failure.
    async fn get_org(
        &self,
        ctx: Context,
        req: OwnedView<GetOrgRequestView<'static>>,
    ) -> Result<(GetOrgResponse, Context), ConnectError> {
        let org = self.org_or_not_found(req.slug)?;
        Ok((
            GetOrgResponse {
                org: MessageField::some(org_message(&org)),
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListOrgs` — every organization, ordered by slug.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for a malformed `page_token` and `Internal`
    /// on database failure.
    async fn list_orgs(
        &self,
        ctx: Context,
        req: OwnedView<ListOrgsRequestView<'static>>,
    ) -> Result<(ListOrgsResponse, Context), ConnectError> {
        let orgs: Vec<Org> = self
            .db
            .list_orgs()
            .map_err(internal)?
            .iter()
            .map(org_message)
            .collect();
        let (orgs, next_page_token) = paginate(orgs, req.page_size, req.page_token)?;
        Ok((
            ListOrgsResponse {
                orgs,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl ProjectService for RegistryRpc {
    /// `CreateProject` — create a project at a materialized path under an org.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `registry.configure` on the
    /// org scope, `NotFound` for an unknown org, `InvalidArgument` for an
    /// empty name, `AlreadyExists` when `(org, path)` exists, and `Internal`
    /// on database failure.
    async fn create_project(
        &self,
        ctx: Context,
        req: OwnedView<CreateProjectRequestView<'static>>,
    ) -> Result<(CreateProjectResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let org = self.org_or_not_found(req.org_slug)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.slug),
        )?;
        if req.name.is_empty() {
            return Err(invalid("project name is required"));
        }
        self.db
            .create_project(org.id, req.path, req.name)
            .map_err(|e| ConnectError::new(ErrorCode::AlreadyExists, format!("{e:#}")))?;
        Ok((
            CreateProjectResponse {
                project: MessageField::some(Project {
                    org_slug: org.slug,
                    path: req.path.to_string(),
                    name: req.name.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListProjects` — an org's projects, ordered by materialized path.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown org and `Internal` on database
    /// failure.
    async fn list_projects(
        &self,
        ctx: Context,
        req: OwnedView<ListProjectsRequestView<'static>>,
    ) -> Result<(ListProjectsResponse, Context), ConnectError> {
        let org = self.org_or_not_found(req.org_slug)?;
        let projects: Vec<Project> = self
            .db
            .list_projects(org.id)
            .map_err(internal)?
            .into_iter()
            .map(|p| Project {
                org_slug: org.slug.clone(),
                path: p.path,
                name: p.name,
                ..Default::default()
            })
            .collect();
        Ok((
            ListProjectsResponse {
                projects,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl StorageService for RegistryRpc {
    /// `CreateBinding` — create a storage binding under an org.
    ///
    /// Only the `local_fs` kind is supported this phase (where `root` is a
    /// filesystem path).
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `registry.configure` on the
    /// org scope, `NotFound` for an unknown org, `InvalidArgument` for an
    /// empty name/root or unsupported kind, `AlreadyExists` when
    /// `(org, name)` exists, and `Internal` on database failure.
    async fn create_binding(
        &self,
        ctx: Context,
        req: OwnedView<CreateBindingRequestView<'static>>,
    ) -> Result<(CreateBindingResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let org = self.org_or_not_found(req.org_slug)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.slug),
        )?;
        if req.name.is_empty() || req.root.is_empty() {
            return Err(invalid("binding name and root are required"));
        }
        let kind = if req.kind.is_empty() {
            "local_fs"
        } else {
            req.kind
        };
        self.db
            .create_storage_binding(org.id, req.name, kind, req.root)
            .map_err(|e| {
                if kind == "local_fs" {
                    ConnectError::new(ErrorCode::AlreadyExists, format!("{e:#}"))
                } else {
                    invalid(format!("{e:#}"))
                }
            })?;
        Ok((
            CreateBindingResponse {
                binding: MessageField::some(Binding {
                    org_slug: org.slug,
                    name: req.name.to_string(),
                    kind: kind.to_string(),
                    root: req.root.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListBindings` — an org's storage bindings, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown org and `Internal` on database
    /// failure.
    async fn list_bindings(
        &self,
        ctx: Context,
        req: OwnedView<ListBindingsRequestView<'static>>,
    ) -> Result<(ListBindingsResponse, Context), ConnectError> {
        let org = self.org_or_not_found(req.org_slug)?;
        let bindings: Vec<Binding> = self
            .db
            .list_storage_bindings(org.id)
            .map_err(internal)?
            .into_iter()
            .map(|b| Binding {
                org_slug: org.slug.clone(),
                name: b.name,
                kind: b.kind,
                root: b.root,
                ..Default::default()
            })
            .collect();
        Ok((
            ListBindingsResponse {
                bindings,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl AuditService for RegistryRpc {
    /// `ListAudit` — recent audit entries at a scope, newest first.
    ///
    /// Authz mirrors phase-2c: the caller must hold `audit.read` (admin+) on
    /// the queried scope, checked through [`RegistryRpc::require_permission`].
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `audit.read` on the scope,
    /// `InvalidArgument` for a malformed `page_token`, and `Internal` on
    /// database failure.
    async fn list_audit(
        &self,
        ctx: Context,
        req: OwnedView<ListAuditRequestView<'static>>,
    ) -> Result<(ListAuditResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let scope = Scope::parse(req.scope);
        self.require_permission(&claims, Permission::AuditRead, &scope)?;
        let entries: Vec<AuditEntry> = self
            .db
            .list_audit(req.scope)
            .map_err(internal)?
            .into_iter()
            .map(|row| AuditEntry {
                change_id: row.change_id.unwrap_or_default(),
                actor_label: row.actor_label,
                action: row.action,
                scope: row.scope,
                result_commit: row.result_commit.unwrap_or_default(),
                result_tag: row.result_tag.unwrap_or_default(),
                detail: row.detail.unwrap_or_default(),
                created_at: row.created_at,
                ..Default::default()
            })
            .collect();
        let (entries, next_page_token) = paginate(entries, req.page_size, req.page_token)?;
        Ok((
            ListAuditResponse {
                entries,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl ConfigService for RegistryRpc {
    /// `ListChangesets` — change-sets at a scope, newest first.
    ///
    /// Reads require `audit.read` on the scope (RFC-0004 "Access matrix":
    /// ConfigService reads are an admin+ surface, same as the audit feed).
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `audit.read` on the scope,
    /// `InvalidArgument` for a malformed `page_token`, and `Internal` on
    /// database failure.
    async fn list_changesets(
        &self,
        ctx: Context,
        req: OwnedView<ListChangesetsRequestView<'static>>,
    ) -> Result<(ListChangesetsResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let scope = Scope::parse(req.scope);
        self.require_permission(&claims, Permission::AuditRead, &scope)?;
        let changesets: Vec<Changeset> = self
            .db
            .list_changesets(req.scope)
            .map_err(internal)?
            .into_iter()
            .map(changeset_message)
            .collect();
        let (changesets, next_page_token) = paginate(changesets, req.page_size, req.page_token)?;
        Ok((
            ListChangesetsResponse {
                changesets,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetChangeset` — one change-set's revisions and semantic diffs.
    ///
    /// Loads the change-set summary plus its revisions, each rendered with
    /// the field-level diff [`crate::config::semantic_diff`] produces (the
    /// terraform-plan review view). Reads require `audit.read` on the
    /// change-set's recorded scope.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `NotFound` for an unknown `change_id`, `PermissionDenied` when the
    /// caller lacks `audit.read` on the change-set's scope, and `Internal`
    /// on database failure.
    async fn get_changeset(
        &self,
        ctx: Context,
        req: OwnedView<GetChangesetRequestView<'static>>,
    ) -> Result<(GetChangesetResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let summary = self
            .db
            .changeset(req.change_id)
            .map_err(internal)?
            .ok_or_else(|| not_found("changeset"))?;
        self.require_permission(
            &claims,
            Permission::AuditRead,
            &Scope::parse(&summary.scope),
        )?;
        let change_id = crate::config::ChangeId(summary.change_id.clone());
        let revisions: Vec<Revision> = crate::config::review(&self.db, &change_id)
            .map_err(internal)?
            .into_iter()
            .map(|(revision, diffs)| Revision {
                object_type: revision.object_type,
                object_id: revision.object_id,
                op: revision.op.as_str().to_string(),
                diffs: diffs
                    .into_iter()
                    .map(|d| FieldDiff {
                        field: d.field,
                        old: d.old.unwrap_or_default(),
                        new: d.new.unwrap_or_default(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .collect();
        Ok((
            GetChangesetResponse {
                changeset: MessageField::some(changeset_message(summary)),
                revisions,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `RevertChangeset` — draft and apply a forward revert of a change-set.
    ///
    /// Drafts the snapshot-targeted forward revert
    /// ([`crate::config::revert`]) and immediately applies it, returning the
    /// new revert change-set. The revert re-enters the same apply path, so a
    /// `registry`-visibility revision's revert calls
    /// [`crate::db::Database::set_registry_visibility`] again.
    ///
    /// Authz approximation: the RFC requires "the same permission the
    /// original change required". This is approximated as `registry.configure`
    /// on the change-set's scope — the admin+ verb that gates the SQL-backed
    /// configuration this engine records. A future refinement could store
    /// the exact permission per change-set.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `NotFound` for an unknown `change_id`, `PermissionDenied` when the
    /// caller lacks `registry.configure` on the change-set's scope,
    /// `FailedPrecondition` when the change-set has no revisions to revert,
    /// and `Internal` on database failure.
    async fn revert_changeset(
        &self,
        ctx: Context,
        req: OwnedView<RevertChangesetRequestView<'static>>,
    ) -> Result<(RevertChangesetResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let summary = self
            .db
            .changeset(req.change_id)
            .map_err(internal)?
            .ok_or_else(|| not_found("changeset"))?;
        let scope = Scope::parse(&summary.scope);
        self.require_permission(&claims, Permission::RegistryConfigure, &scope)?;

        let Some(actor) = claims_principal(&claims) else {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "unknown principal kind",
            ));
        };
        let actor_label = format!("{}:{}", claims.owner_kind, claims.owner_id);
        let original = crate::config::ChangeId(summary.change_id.clone());

        // Draft the forward revert; live state for conflict detection comes
        // from the registries table (the object type this phase mutates
        // through the engine).
        let draft = crate::config::revert(
            &self.db,
            &original,
            &actor,
            &actor_label,
            |object_type, object_id| {
                if object_type == "registry" {
                    self.db
                        .registry_by_slug(object_id)
                        .ok()
                        .flatten()
                        .map(|r| serde_json::json!({ "visibility": r.visibility }))
                } else {
                    None
                }
            },
        )
        .map_err(|e| ConnectError::new(ErrorCode::FailedPrecondition, format!("{e:#}")))?;

        // Apply the revert draft: re-run each revision's live mutation.
        crate::config::apply(&self.db, &draft.change_id, "changeset.revert", |rev| {
            apply_revert_revision(&self.db, rev)
        })
        .map_err(internal)?;

        let reverted = self
            .db
            .changeset(draft.change_id.as_str())
            .map_err(internal)?
            .ok_or_else(|| internal(anyhow::anyhow!("revert change-set vanished")))?;
        Ok((
            RevertChangesetResponse {
                changeset: MessageField::some(changeset_message(reverted)),
                ..Default::default()
            },
            ctx,
        ))
    }
}

/// Apply one revision of a revert draft to its live object.
///
/// Only `registry`-visibility revisions carry a live mutation this phase;
/// `token`/`invitation` exemption revisions are records-only (no live
/// credential or grant is resurrected), so they apply as no-ops.
fn apply_revert_revision(db: &Database, revision: &crate::config::Revision) -> anyhow::Result<()> {
    if revision.object_type == "registry" {
        if let Some(visibility) = revision
            .new_json
            .as_ref()
            .and_then(|v| v.get("visibility"))
            .and_then(|v| v.as_str())
        {
            if let Some(record) = db.registry_by_slug(&revision.object_id)? {
                db.set_registry_visibility(record.id, visibility)?;
            }
        }
    }
    Ok(())
}

/// Map a stored change-set summary row to its wire message.
fn changeset_message(row: crate::db::ChangesetRow) -> Changeset {
    Changeset {
        change_id: row.change_id,
        actor_label: row.actor_label,
        scope: row.scope,
        status: row.status,
        summary: row.summary.unwrap_or_default(),
        created_at: row.created_at,
        applied_at: row.applied_at.unwrap_or_default(),
        reverted_by_change_id: row.reverted_by_change_id.unwrap_or_default(),
        ..Default::default()
    }
}

impl PackageService for RegistryRpc {
    /// `ListPackages` — package summaries with the newest version.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `InvalidArgument` for a
    /// malformed `page_token`, and `Internal` on database failure.
    async fn list_packages(
        &self,
        ctx: Context,
        req: OwnedView<ListPackagesRequestView<'static>>,
    ) -> Result<(ListPackagesResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let packages: Vec<PackageSummary> = self
            .db
            .list_packages(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|p| PackageSummary {
                name: p.name,
                description: p.description,
                license: p.license,
                latest_version: p.latest_version.unwrap_or_default(),
                ..Default::default()
            })
            .collect();
        let (packages, next_page_token) = paginate(packages, req.page_size, req.page_token)?;
        Ok((
            ListPackagesResponse {
                packages,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetPackage` — full version × platform detail for one package.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug or package name and
    /// `Internal` on database failure.
    async fn get_package(
        &self,
        ctx: Context,
        req: OwnedView<GetPackageRequestView<'static>>,
    ) -> Result<(GetPackageResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let detail = self
            .db
            .package_detail(record.id, req.name)
            .map_err(internal)?
            .ok_or_else(|| not_found("package"))?;
        let versions = detail
            .versions
            .into_iter()
            .map(|v| Version {
                version: v.version,
                previous: v.previous.unwrap_or_default(),
                platforms: v
                    .platforms
                    .into_iter()
                    .map(|p| Platform {
                        platform: p.platform,
                        store_path: p.store_path,
                        nar_hash: p.nar_hash,
                        nar_size: p.nar_size,
                        closure_size: p.closure_size,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .collect();
        Ok((
            GetPackageResponse {
                package: MessageField::some(Package {
                    name: detail.name,
                    description: detail.description,
                    homepage: detail.homepage.unwrap_or_default(),
                    license: detail.license,
                    maintainer: detail.maintainer,
                    sysroot: detail.sysroot,
                    versions,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl ChannelService for RegistryRpc {
    /// `ListChannels` — channels with full partition maps.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `InvalidArgument` for a
    /// malformed `page_token`, and `Internal` on database failure.
    async fn list_channels(
        &self,
        ctx: Context,
        req: OwnedView<ListChannelsRequestView<'static>>,
    ) -> Result<(ListChannelsResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let channels: Vec<Channel> = self
            .db
            .list_channels(record.id)
            .map_err(internal)?
            .into_iter()
            .map(channel_message)
            .collect();
        let (channels, next_page_token) = paginate(channels, req.page_size, req.page_token)?;
        Ok((
            ListChannelsResponse {
                channels,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetChannel` — one channel's partition map by name.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug or channel name and
    /// `Internal` on database failure.
    async fn get_channel(
        &self,
        ctx: Context,
        req: OwnedView<GetChannelRequestView<'static>>,
    ) -> Result<(GetChannelResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let channel = self
            .db
            .list_channels(record.id)
            .map_err(internal)?
            .into_iter()
            .find(|c| c.name == req.name)
            .ok_or_else(|| not_found("channel"))?;
        Ok((
            GetChannelResponse {
                channel: Some(channel_message(channel)).into(),
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl WebhookService for RegistryRpc {
    /// `CreateWebhook` — subscribe an org's HTTP endpoint to registry events.
    ///
    /// The webhook is created under the named org subscribed to `events` (an
    /// empty list subscribes to all event types). A `secret` may be supplied;
    /// otherwise a random `aos_`-prefixed one is generated. The signing secret
    /// is returned exactly once in [`CreateWebhookResponse::secret`] — it is
    /// never echoed by [`Self::list_webhooks`].
    ///
    /// Authz: requires [`Permission::MembersManage`] (admin+) on the org scope
    /// — managing notification endpoints is an org-administration surface.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `members.manage` on the org,
    /// `NotFound` for an unknown org, `InvalidArgument` for an empty URL or a
    /// URL that fails the SSRF guard
    /// ([`crate::fetch::is_safe_remote_url`] — loopback/link-local/private/
    /// non-`http(s)` targets), and `Internal` on database failure.
    async fn create_webhook(
        &self,
        ctx: Context,
        req: OwnedView<CreateWebhookRequestView<'static>>,
    ) -> Result<(CreateWebhookResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let org = self.org_or_not_found(req.org_slug)?;
        self.require_permission(&claims, Permission::MembersManage, &Scope::parse(&org.slug))?;
        if req.url.is_empty() {
            return Err(invalid("webhook url is required"));
        }
        // The delivery worker POSTs to this URL from inside the hub network, so
        // reject loopback/link-local/private/non-http(s) targets (create_webhook
        // re-checks; this surfaces a clear invalid-argument error).
        if let Err(err) = crate::fetch::is_safe_remote_url(req.url) {
            return Err(invalid(format!("rejecting webhook url: {err:#}")));
        }
        let secret = if req.secret.is_empty() {
            crate::auth::token::generate_token().0
        } else {
            req.secret.to_string()
        };
        let events: Vec<String> = req.events.iter().map(|s| s.to_string()).collect();
        let id = self
            .db
            .create_webhook(org.id, req.url, &secret, &events)
            .map_err(internal)?;
        Ok((
            CreateWebhookResponse {
                webhook: MessageField::some(Webhook {
                    id,
                    org_slug: org.slug,
                    url: req.url.to_string(),
                    events,
                    active: true,
                    ..Default::default()
                }),
                secret,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListWebhooks` — an org's webhook subscriptions (secrets omitted).
    ///
    /// Authz: requires [`Permission::MembersManage`] on the org scope.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `PermissionDenied` when the caller lacks `members.manage` on the org,
    /// `NotFound` for an unknown org, and `Internal` on database failure.
    async fn list_webhooks(
        &self,
        ctx: Context,
        req: OwnedView<ListWebhooksRequestView<'static>>,
    ) -> Result<(ListWebhooksResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let org = self.org_or_not_found(req.org_slug)?;
        self.require_permission(&claims, Permission::MembersManage, &Scope::parse(&org.slug))?;
        let webhooks: Vec<Webhook> = self
            .db
            .list_webhooks(org.id)
            .map_err(internal)?
            .into_iter()
            .map(|w| Webhook {
                id: w.id,
                org_slug: org.slug.clone(),
                url: w.url,
                events: w.events,
                active: w.active,
                created_at: w.created_at,
                ..Default::default()
            })
            .collect();
        Ok((
            ListWebhooksResponse {
                webhooks,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `DeleteWebhook` — remove a webhook (and its queued deliveries) by id.
    ///
    /// Authz: requires [`Permission::MembersManage`] on the *owning org's*
    /// scope, resolved from the webhook's `org_id` so the check binds to the
    /// resource being deleted rather than a caller-supplied scope.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `NotFound` for an unknown webhook id or its (vanished) org,
    /// `PermissionDenied` when the caller lacks `members.manage` on the owning
    /// org, and `Internal` on database failure.
    async fn delete_webhook(
        &self,
        ctx: Context,
        req: OwnedView<DeleteWebhookRequestView<'static>>,
    ) -> Result<(DeleteWebhookResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let webhook = self
            .db
            .webhook(req.id)
            .map_err(internal)?
            .ok_or_else(|| not_found("webhook"))?;
        let org = self
            .db
            .org_by_id(webhook.org_id)
            .map_err(internal)?
            .ok_or_else(|| not_found("org"))?;
        self.require_permission(&claims, Permission::MembersManage, &Scope::parse(&org.slug))?;
        let deleted = self.db.delete_webhook(req.id).map_err(internal)?;
        Ok((
            DeleteWebhookResponse {
                deleted,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl PublishService for RegistryRpc {
    /// `MintUploadCredentials` — issue a short-lived, registry-scoped upload
    /// credential.
    ///
    /// The caller must already hold `publish` on the registry's canonical
    /// scope (the same right the upload facade requires). On success the hub
    /// mints a fresh provisioning token *owned by the calling principal*,
    /// scoped to exactly that registry with only the `publish` permission and a
    /// short expiry ([`UPLOAD_CREDENTIAL_TTL_SECS`]). The response carries that
    /// token (shown once), the canonical facade `upload_url`
    /// (`{external_url}/{slug}`), and the expiry — so a producer can
    /// `apr origin upload --upload-url <upload_url> --token <token>` (or
    /// exchange the token at `/oauth2/token` for a bearer JWT).
    ///
    /// Token ownership keeps the credential clamped: it deadens the instant the
    /// owner's `publish` grant is removed, so a minted credential never
    /// outlives the authority that minted it.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT,
    /// `NotFound` for an unknown registry slug, `PermissionDenied` when the
    /// caller lacks `publish` on the registry scope or has no resolvable
    /// principal, and `Internal` on database failure.
    async fn mint_upload_credentials(
        &self,
        ctx: Context,
        req: OwnedView<MintUploadCredentialsRequestView<'static>>,
    ) -> Result<(MintUploadCredentialsResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let registry = self.registry_or_not_found(req.slug)?;
        let scope = Scope::parse(&registry.slug);
        self.require_permission(&claims, Permission::Publish, &scope)?;

        let Some(owner) = claims_principal(&claims) else {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "unknown principal kind",
            ));
        };
        let expires_at = unix_now() + UPLOAD_CREDENTIAL_TTL_SECS;
        let (_id, secret) = self
            .db
            .create_token(
                owner,
                &registry.slug,
                &[Permission::Publish],
                Some("upload credential (MintUploadCredentials)"),
                Some(expires_at),
            )
            .map_err(internal)?;
        let upload_url = format!(
            "{}/{}",
            self.external_url.trim_end_matches('/'),
            registry.slug
        );
        Ok((
            MintUploadCredentialsResponse {
                token: secret,
                upload_url,
                expires_at,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl GitService for RegistryRpc {
    /// `GitLog` — the committed commit log of a registry's tracked branch.
    ///
    /// Walks the verified HEAD commit's first-parent history through the
    /// committed git surface, newest first. Reads follow registry visibility:
    /// the caller must hold [`Permission::Read`] on the registry scope (a
    /// `public` registry's read is anonymous; see the access matrix). Each
    /// entry carries the `AOS-Change-Id` trailer when the commit was authored
    /// or promoted through the hub.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `PermissionDenied` when the
    /// caller cannot read the registry, `FailedPrecondition` when the registry
    /// has no indexed HEAD yet, `InvalidArgument` for a malformed `page_token`,
    /// and `Internal` on database or surface-read failure.
    async fn git_log(
        &self,
        ctx: Context,
        req: OwnedView<GitLogRequestView<'static>>,
    ) -> Result<(GitLogResponse, Context), ConnectError> {
        let registry = self.registry_or_not_found(req.slug)?;
        self.require_read(&ctx, &registry)?;
        let head = self.head_commit(&registry)?;
        let fetch = crate::gitwrite::fetcher_for_registry(&self.db, &registry).map_err(internal)?;
        let log = crate::gitwrite::commit_log(fetch.as_ref(), head, GIT_LOG_LIMIT)
            .await
            .map_err(internal)?;
        let commits: Vec<GitCommit> = log
            .into_iter()
            .map(|c| GitCommit {
                oid: c.oid,
                parents: c.parents,
                message: c.message,
                author: c.author,
                when: c.when,
                change_id: c.change_id.unwrap_or_default(),
                ..Default::default()
            })
            .collect();
        let (commits, next_page_token) = paginate(commits, req.page_size, req.page_token)?;
        Ok((
            GitLogResponse {
                commits,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GitDiff` — a textual diff of committed config files between commits.
    ///
    /// Diffs `registry.toml` and `keys.toml` between `from_oid` and `to_oid`
    /// (an empty `to_oid` defaults to the current HEAD; an empty `from_oid`
    /// renders the whole `to` tree as additions). Requires
    /// [`Permission::Read`] on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `PermissionDenied` when the
    /// caller cannot read the registry, `InvalidArgument` for a malformed oid,
    /// `FailedPrecondition` when no HEAD is available to default `to_oid`, and
    /// `Internal` on database or surface-read failure.
    async fn git_diff(
        &self,
        ctx: Context,
        req: OwnedView<GitDiffRequestView<'static>>,
    ) -> Result<(GitDiffResponse, Context), ConnectError> {
        let registry = self.registry_or_not_found(req.slug)?;
        self.require_read(&ctx, &registry)?;
        let from = if req.from_oid.is_empty() {
            None
        } else {
            Some(
                crate::surface::object::Oid::from_hex(req.from_oid)
                    .map_err(|e| invalid(format!("{e:#}")))?,
            )
        };
        let to = if req.to_oid.is_empty() {
            self.head_commit(&registry)?
        } else {
            crate::surface::object::Oid::from_hex(req.to_oid)
                .map_err(|e| invalid(format!("{e:#}")))?
        };
        let fetch = crate::gitwrite::fetcher_for_registry(&self.db, &registry).map_err(internal)?;
        let diff = crate::gitwrite::diff_config_files(fetch.as_ref(), from, to)
            .await
            .map_err(internal)?;
        Ok((
            GitDiffResponse {
                diff,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListChangeRequests` — the registry's draft git-backed change requests.
    ///
    /// Surfaces every change-set the hub recorded as a git-backed change
    /// request (one with a draft ref and commit), with each edited file's
    /// unified diff (computed from the recorded old/new file contents) and the
    /// `apr change merge` command a maintainer runs to promote it. Listing the
    /// change requests is an admin+ surface: the caller must hold
    /// [`Permission::AuditRead`] on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a missing/invalid bearer JWT, `NotFound`
    /// for an unknown slug, `PermissionDenied` when the caller lacks
    /// `audit.read`, and `Internal` on database failure.
    async fn list_change_requests(
        &self,
        ctx: Context,
        req: OwnedView<ListChangeRequestsRequestView<'static>>,
    ) -> Result<(ListChangeRequestsResponse, Context), ConnectError> {
        let claims = self.require_claims(&ctx)?;
        let registry = self.registry_or_not_found(req.slug)?;
        let scope = Scope::parse(&registry.slug);
        self.require_permission(&claims, Permission::AuditRead, &scope)?;

        let upload_url = format!(
            "{}/{}",
            self.external_url.trim_end_matches('/'),
            registry.slug
        );
        let change_requests = self
            .db
            .list_changesets(&registry.slug)
            .map_err(internal)?
            .into_iter()
            .filter(|cs| cs.git_ref.is_some())
            .map(|cs| {
                let file_diffs = self
                    .db
                    .list_revisions(&cs.change_id)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| r.object_type == "registry_file")
                    .map(|r| FileDiff {
                        diff: crate::gitwrite::unified_diff(
                            &r.object_id,
                            r.old_json.as_deref().unwrap_or_default(),
                            r.new_json.as_deref().unwrap_or_default(),
                        ),
                        path: r.object_id,
                        ..Default::default()
                    })
                    .collect();
                ChangeRequest {
                    merge_command: crate::gitwrite::merge_command(
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
                    ..Default::default()
                }
            })
            .collect();
        Ok((
            ListChangeRequestsResponse {
                change_requests,
                ..Default::default()
            },
            ctx,
        ))
    }
}

/// Maximum commits returned by one `GitLog` walk.
const GIT_LOG_LIMIT: usize = 1000;

/// Current Unix time in seconds (saturating at 0 before the epoch).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn channel_message(channel: crate::db::ChannelSummary) -> Channel {
    Channel {
        name: channel.name,
        frontier: channel.frontier.unwrap_or_default(),
        partitions: channel
            .partitions
            .iter()
            .enumerate()
            .filter_map(|(bucket, release)| {
                release.as_ref().map(|release| Partition {
                    bucket: bucket as u32,
                    release: release.clone(),
                    ..Default::default()
                })
            })
            .collect(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginate_slices_and_tokens() {
        let items: Vec<u32> = (0..10).collect();
        let (page, next) = paginate(items.clone(), 4, "").unwrap();
        assert_eq!(page, vec![0, 1, 2, 3]);
        assert_eq!(next, "4");
        let (page, next) = paginate(items.clone(), 4, "8").unwrap();
        assert_eq!(page, vec![8, 9]);
        assert_eq!(next, "");
        assert!(paginate(items, 4, "bogus").is_err());
    }

    #[test]
    fn paginate_defaults_and_caps_page_size() {
        let items: Vec<u32> = (0..2000).collect();
        let (page, _) = paginate(items.clone(), 0, "").unwrap();
        assert_eq!(page.len(), DEFAULT_PAGE_SIZE as usize);
        let (page, _) = paginate(items, 9999, "").unwrap();
        assert_eq!(page.len(), MAX_PAGE_SIZE as usize);
    }
}
