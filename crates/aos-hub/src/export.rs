//! Org backup/export: a portable JSON bundle of the SQL system of record
//! plus copyable registry surfaces (RFC-0004 "Offboarding and export").
//!
//! Export is advertised as genuinely easy here: a registry *is* a portable git
//! surface + bucket prefix, and the SQL system of record exports as JSON. This
//! module produces both halves:
//!
//! - [`export_org`] returns an [`ExportManifest`] — the org row, its projects,
//!   its registries' metadata, its managed caches' metadata, its memberships,
//!   its tokens' **metadata only** (never a hash or secret), its storage
//!   bindings (paths, no credentials), an audit slice, and the
//!   configuration-changeset history.
//! - [`export_registry_surface`] copies the registry's reconciled local
//!   placement into a destination directory — a portable,
//!   re-servable git + nix-cache surface.
//!
//! # Manifest shape
//!
//! ```text
//! {
//!   "version": 1,
//!   "exported_at": 1730000000,
//!   "org": { "slug": "acme", "name": "Acme, Inc.", "created_at": … },
//!   "projects": [ { "path": "infra", "name": "Infra", … } ],
//!   "registries": [ { "slug": "acme/infra/prod/cdn", "visibility": "private",
//!                     "prefix": "cdn", "trust_keys": [ … ] } ],
//!   "caches": [ { "slug": "acme-cache", "visibility": "public",
//!                 "prefix": "cache", "priority": 40, "compression": "zstd" } ],
//!   "memberships": [ { "principal_kind": "user", "principal_id": 1,
//!                      "scope": "acme", "role": "owner" } ],
//!   "tokens": [ { "id": "…", "scope": "acme/infra/prod/cdn",
//!                 "permissions": ["publish"], "created_at": …,
//!                 "expires_at": null, "last_used_at": … } ],   // NO hash/secret
//!   "bindings": [ { "name": "primary", "kind": "local_fs",
//!                           "local_root_path": "/srv/aos-hub" } ], // NO credentials
//!   "audit": [ { "action": "registry.visibility", "scope": "…", … } ],
//!   "changesets": [ { "change_id": "…", "status": "applied", … } ]
//! }
//! ```
//!
//! The token and binding entries are **data contracts**: they carry no
//! `hash`, no secret, and no bucket credentials — an export bundle is safe to
//! hand to the offboarding org.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::db::Database;

/// One exported project row.
#[derive(Debug, Clone, Serialize)]
pub struct ExportProject {
    /// Materialized path within the org (`""` for an org-root project).
    pub path: String,
    /// Human-readable project name.
    pub name: String,
    /// Unix time the project was created.
    pub created_at: i64,
}

/// One exported registry's metadata (no surface bytes — those copy separately).
#[derive(Debug, Clone, Serialize)]
pub struct ExportRegistry {
    /// Canonical slug (`{org}/{project_path}/{name}`).
    pub slug: String,
    /// Visibility: `public`, `internal`, or `private`.
    pub visibility: String,
    /// Owning project's materialized path.
    pub project_path: String,
    /// Pinned trust anchors (`name:Ed25519:<base64>`).
    pub trust_keys: Vec<String>,
    /// Whether indexing requires signatures.
    pub require_signatures: bool,
}

/// One exported managed cache's metadata (no NAR/narinfo surface bytes — those
/// copy separately, like a registry's surface).
#[derive(Debug, Clone, Serialize)]
pub struct ExportCache {
    /// URL slug the cache is served under (globally unique).
    pub slug: String,
    /// Human-readable display name.
    pub name: String,
    /// Visibility: `public`, `internal`, or `private`.
    pub visibility: String,
    /// `nix-cache-info` `Priority` (substituter ordering; lower = preferred).
    pub priority: i64,
    /// Default NAR compression (`zstd` | `xz` | `none`).
    pub compression: String,
    /// `nix-cache-info` `WantMassQuery` flag.
    pub want_mass_query: bool,
    /// Soft-delete tombstone (unix seconds), or `None` while live.
    pub deleted_at: Option<i64>,
}

/// One exported membership grant.
#[derive(Debug, Clone, Serialize)]
pub struct ExportMembership {
    /// `user` or `service_account`.
    pub principal_kind: String,
    /// The principal's row id.
    pub principal_id: i64,
    /// The immutable authorization scope the grant is bound to.
    pub scope: String,
    /// The role granted.
    pub role: String,
}

/// One exported token's **metadata** — never the hash or secret.
#[derive(Debug, Clone, Serialize)]
pub struct ExportToken {
    /// The token id (UUID).
    pub id: String,
    /// `user` or `service_account`.
    pub owner_kind: String,
    /// The owning principal's row id.
    pub owner_id: i64,
    /// The immutable authorization scope the token is bound to.
    pub scope: String,
    /// The permission verbs the token grants.
    pub permissions: Vec<String>,
    /// Unix time the token was created.
    pub created_at: i64,
    /// Unix time the token expires, or `None`.
    pub expires_at: Option<i64>,
    /// Unix time the token was last used, or `None`.
    pub last_used_at: Option<i64>,
}

/// One exported binding (paths only — no credentials).
#[derive(Debug, Clone, Serialize)]
pub struct ExportBinding {
    /// Binding name, unique within the org.
    pub name: String,
    /// Backend kind (`local_fs`, `s3`, or `r2`).
    pub kind: String,
    /// Local-filesystem root, only for `local_fs`.
    pub local_root_path: Option<String>,
    /// Object-store bucket, only for `s3`/`r2`.
    pub object_bucket: Option<String>,
    /// Binding-owned object-store prefix.
    pub object_prefix: Option<String>,
    /// Canonical object-store endpoint scheme.
    pub endpoint_scheme: Option<String>,
    /// Canonical object-store endpoint host representation.
    pub endpoint_host_kind: Option<String>,
    /// Canonical object-store endpoint host bytes.
    pub endpoint_host_bytes: Option<Vec<u8>>,
    /// Canonical object-store endpoint port.
    pub endpoint_port: Option<i64>,
    /// Request-signing region.
    pub signing_region: Option<String>,
    /// Public or private object-store access mode.
    pub access_mode: Option<String>,
}

/// One exported audit row.
#[derive(Debug, Clone, Serialize)]
pub struct ExportAudit {
    /// Human label of the actor.
    pub actor_label: String,
    /// The action verb.
    pub action: String,
    /// The scope the action targeted.
    pub scope: String,
    /// The change-set this row ties to, or `None`.
    pub change_id: Option<String>,
    /// Unix time the row was recorded.
    pub created_at: i64,
}

/// One exported configuration changeset summary.
#[derive(Debug, Clone, Serialize)]
pub struct ExportChangeset {
    /// Stable change-set id.
    pub change_id: String,
    /// Human label of the actor that opened it.
    pub actor_label: String,
    /// The scope it targets.
    pub scope: String,
    /// Lifecycle status (`draft`/`applied`/`reverted`).
    pub status: String,
    /// One-line summary.
    pub summary: Option<String>,
    /// Unix time it was created.
    pub created_at: i64,
}

/// The exported org bundle.
///
/// A portable JSON snapshot of the org's SQL system of record. See the
/// [module docs](self) for the shape and the redaction guarantees.
#[derive(Debug, Clone, Serialize)]
pub struct ExportManifest {
    /// Manifest schema version.
    pub version: u32,
    /// Unix time the export was produced.
    pub exported_at: i64,
    /// The org slug.
    pub org_slug: String,
    /// The org display name.
    pub org_name: String,
    /// Unix time the org was created.
    pub org_created_at: i64,
    /// The org's projects.
    pub projects: Vec<ExportProject>,
    /// The org's registries' metadata.
    pub registries: Vec<ExportRegistry>,
    /// The org's managed binary caches' metadata.
    pub caches: Vec<ExportCache>,
    /// The org's membership grants.
    pub memberships: Vec<ExportMembership>,
    /// The org's tokens' metadata (no secrets).
    pub tokens: Vec<ExportToken>,
    /// The org's bindings (no credentials).
    pub bindings: Vec<ExportBinding>,
    /// The org's audit slice.
    pub audit: Vec<ExportAudit>,
    /// The org's configuration-changeset history.
    pub changesets: Vec<ExportChangeset>,
}

/// Build an [`ExportManifest`] for one org from its SQL system of record.
///
/// Gathers the org row, projects, registries, managed caches, memberships,
/// token metadata (redacted), bindings, the audit slice at or below the
/// org scope, and the changeset history. Resolves the org including soft-deleted
/// ones (export runs during the offboarding grace window).
///
/// # Errors
///
/// Returns an error when no org has `org_slug`, or on database failure.
pub async fn export_org(db: &Database, org_slug: &str) -> Result<ExportManifest> {
    let org = db
        .org_by_slug_including_deleted(org_slug)
        .await?
        .with_context(|| format!("no org '{org_slug}'"))?;

    let projects = db
        .list_projects(org.id)
        .await?
        .into_iter()
        .map(|p| ExportProject {
            path: p.path,
            name: p.name,
            created_at: p.created_at,
        })
        .collect();

    let registries = db
        .list_registries_including_org(org.id)
        .await?
        .into_iter()
        .map(|r| ExportRegistry {
            slug: r.slug,
            visibility: r.visibility,
            project_path: r.project_path,
            trust_keys: r.trust_keys,
            require_signatures: r.require_signatures,
        })
        .collect();

    let caches = db
        .list_binary_caches_for_org(org.id)
        .await?
        .into_iter()
        .map(|c| ExportCache {
            slug: c.slug,
            name: c.name,
            visibility: c.visibility,
            priority: c.priority,
            compression: c.compression,
            want_mass_query: c.want_mass_query,
            deleted_at: c.deleted_at,
        })
        .collect();

    let memberships = db
        .list_memberships_under(&org.stable_id)
        .await?
        .into_iter()
        .map(
            |(principal_kind, principal_id, scope, role)| ExportMembership {
                principal_kind,
                principal_id,
                scope,
                role,
            },
        )
        .collect();

    let tokens = db
        .export_org_token_metadata(org.id)
        .await?
        .into_iter()
        .map(
            |(
                id,
                owner_kind,
                owner_id,
                scope,
                perms_json,
                created_at,
                expires_at,
                last_used_at,
            )| {
                ExportToken {
                    id,
                    owner_kind,
                    owner_id,
                    scope,
                    permissions: serde_json::from_str(&perms_json).unwrap_or_default(),
                    created_at,
                    expires_at,
                    last_used_at,
                }
            },
        )
        .collect();

    let bindings = db
        .list_bindings(org.id)
        .await?
        .into_iter()
        .map(|b| ExportBinding {
            name: b.name,
            kind: b.kind,
            local_root_path: b.local_root_path,
            object_bucket: b.object_bucket,
            object_prefix: b.object_prefix,
            endpoint_scheme: b.endpoint_scheme,
            endpoint_host_kind: b.endpoint_host_kind,
            endpoint_host_bytes: b.endpoint_host_bytes,
            endpoint_port: b.endpoint_port,
            signing_region: b.signing_region,
            access_mode: b.access_mode,
        })
        .collect();

    let audit = db
        .list_audit(&org.slug)
        .await?
        .into_iter()
        .map(|a| ExportAudit {
            actor_label: a.actor_label,
            action: a.action,
            scope: a.scope,
            change_id: a.change_id,
            created_at: a.created_at,
        })
        .collect();

    let changesets = db
        .list_changesets(&org.slug)
        .await?
        .into_iter()
        .map(|c| ExportChangeset {
            change_id: c.change_id,
            actor_label: c.actor_label,
            scope: c.scope,
            status: c.status,
            summary: c.summary,
            created_at: c.created_at,
        })
        .collect();

    Ok(ExportManifest {
        version: 1,
        exported_at: now_secs(),
        org_slug: org.slug,
        org_name: org.name,
        org_created_at: org.created_at,
        projects,
        registries,
        caches,
        memberships,
        tokens,
        bindings,
        audit,
        changesets,
    })
}

/// Copy a registry's on-disk surface into `dest_dir`, returning the number of
/// files copied.
///
/// The surface is resolved through the first reconciled read placement. The
/// git + nix-cache files are copied as a
/// portable, re-servable surface: pointed at by a new binding it serves
/// `apm`/Nix unchanged. Returns `0` when the registry has no local surface (an
/// non-local placement).
///
/// # Errors
///
/// Returns an error on database failure or an IO failure while copying.
pub async fn export_registry_surface(
    db: &Database,
    registry_id: i64,
    dest_dir: &Path,
) -> Result<usize> {
    let placement = db
        .reconciled_surface_reader(crate::db::SurfaceTarget::Registry(registry_id))
        .await?;
    let binding = db
        .binding(placement.binding_id)
        .await?
        .context("export placement references a missing binding")?;
    if binding.kind != "local_fs" {
        return Ok(0);
    }
    let root = std::path::PathBuf::from(
        binding
            .local_root_path
            .context("local export binding has no localRootPath")?,
    )
    .join(placement.prefix);
    if !root.exists() {
        return Ok(0);
    }
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("creating export dir {}", dest_dir.display()))?;
    copy_tree(&root, dest_dir)
}

/// Recursively copy every file under `src` into `dest`, returning the count.
fn copy_tree(src: &Path, dest: &Path) -> Result<usize> {
    let mut copied = 0;
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            std::fs::create_dir_all(&to).with_context(|| format!("creating {}", to.display()))?;
            copied += copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)
                .with_context(|| format!("copying {} -> {}", from.display(), to.display()))?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// Hard-delete every org whose offboarding grace window has elapsed by `now`.
///
/// The purge job (RFC-0004 offboarding): each org past its `purge_after` is
/// hard-deleted, cascading away its entire SQL system of record. Returns the
/// slugs purged. **Bucket/LocalFs content removal is a separate, deliberately
/// gated step** — this function only removes SQL rows; the surface bytes under
/// a binding root persist until an operator deletes them (the local hub can do
/// so via the `org delete --purge-content` path). Errors purging one org are
/// logged and the job continues with the rest.
///
/// # Errors
///
/// Returns an error on a database failure while listing purgeable orgs.
pub async fn purge_expired_orgs(db: &Database, now: i64) -> Result<Vec<String>> {
    let mut purged = Vec::new();
    for org in db.list_purgeable_orgs(now).await? {
        match db.hard_purge_org(org.id, now).await {
            Ok(true) => purged.push(org.slug),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    org = %org.slug,
                    error = %format!("{err:#}"),
                    "purging expired org failed"
                );
            }
        }
    }
    Ok(purged)
}

/// Current Unix time in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
