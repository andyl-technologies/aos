//! Hub storage: the registry system of record plus the rebuildable index.
//!
//! Three kinds of tables live in one sqlite database, with sharply
//! different contracts (RFC-0004 "Stance"):
//!
//! - **System of record** — `registries`, `channel_floors`, the
//!   phase-2a tenancy tables `orgs`, `projects`, `users`,
//!   `user_identities`, `service_accounts`, `memberships`, and
//!   `invitations`, the phase-2b authentication tables `tokens`,
//!   `sessions`, `device_codes`, and `magic_links`, and the phase-2c
//!   `bindings` and topology-placement tables that bind a surface to
//!   one or more physical locations: facts that exist nowhere on the surface
//!   (slug, source URL, trust anchors, the anti-rollback floor each
//!   channel has reached, the org → project → registry hierarchy and who
//!   may act on it, where each managed registry's bytes live, plus the
//!   credentials principals authenticate with), and the phase-3a
//!   configuration-history tables `audit_log`, `change_requests`, and
//!   `change_request_revisions` (the append-only record of every SQL-backed
//!   mutation, who performed it, and the before/after object snapshots), and
//!   the phase-3d per-org SSO tables `org_idp_configs`, `org_domains`, and
//!   `oidc_flows` (each org's OIDC identity provider with its sealed client
//!   secret, the DNS-TXT-captured domains that route email-first logins to
//!   it, and the short-lived in-flight authorization-code requests), and the
//!   immutable signing-key identity, generation, and typed-usage tables:
//!   facts that exist nowhere on the surface (slug, source URL, trust
//!   anchors, the anti-rollback floor each channel has reached, the
//!   org → project → registry hierarchy and who may act on it, where each
//!   managed registry's bytes live, the credentials principals authenticate
//!   with, and the audit trail of how the configuration reached its current
//!   state). Losing these loses real state; floors in particular survive
//!   every re-index, and
//!   ownership/grants/storage/credentials/history are never rebuildable
//!   from the surface.
//! - **Rebuildable index** — `registry_index`, `packages`,
//!   `package_versions`, `version_platforms`, `channels`,
//!   `channel_partitions`, `releases`, and `key_rosters`
//!   (a registry's flattened advertised cache stack): derived from the
//!   verified surface by the indexer and safely droppable; a re-index
//!   reconstructs it.
//!
//! Managed **binary caches** are a
//! first-class sibling of registries — hub-hosted Nix binary caches. Their
//! system-of-record tables separate registry retention subscriptions and
//! population targets from cache-global GC policy. Logical `cache_objects`,
//! placement-scoped presence, immutable mark/plan generations, and deletion
//! operations preserve the evidence required for safe multi-placement GC.
//!
//! Registry mirroring configuration and observations are system-of-record
//! state. Delivery identity, endpoints, gateways, and routes are modeled by
//! the normalized topology tables described in RFC-0012.
//!
//! The phase-future passkeys / WebAuthn tables (v17) are **system of record**:
//! `webauthn_credentials` (one registered passkey per row — the base64url
//! credential id, the base64 COSE public key, and the monotonic signature
//! counter; the hub is its own relying party with a hard `attestation: none`
//! policy, so no attestation statement is ever stored) and
//! `webauthn_challenges` (short-lived, single-use registration/assertion
//! ceremony state, the same shape as `oidc_flows`). Losing the credentials
//! de-registers every passkey; the challenges are transient.
//!
//! The `users.password_hash` column (v18) is **system of record**: the
//! Argon2id PHC string for accounts that have set an email + password login
//! (`NULL` = no password set). Only the one-way hash is stored, never the
//! plaintext, so a database leak yields no usable credential. See
//! [`aos_hub_model::auth::password`] for the KDF.
//!
//! Migrations are ordered SQL statements tracked in `schema_version`,
//! applied at open. The async backend owns connection and transaction policy;
//! typed queries preserve the same migration identity and atomic mutation
//! contracts on native SQL engines and Worker colocated SQLite.
//!
//! # Tenancy hierarchy (v3)
//!
//! Phase 2a adds the multi-tenant system of record. A **project** locates
//! itself inside its org with a *materialized path* — the slash-joined
//! chain of ancestor project names, with `''` for a project that sits
//! directly under the org root. A registry then lives at
//! `{org}/{project_path}/{registry_slug}`. Those strings are routing and
//! display identities only. Authorization uses separately generated,
//! non-reusable scope keys stored in `authorization_scopes`:
//!
//! ```text
//! instance scope      "instance"
//! org scope           "org:<32 lowercase hexadecimal digits>"
//! project scope       "project:<32 lowercase hexadecimal digits>"
//! registry scope      "registry:<32 lowercase hexadecimal digits>"
//! cache scope         "cache:<32 lowercase hexadecimal digits>"
//! ```
//!
//! Roles inherit through the persisted ancestor graph: an org-incarnation
//! grant covers its project and surface scopes, while purge and recreation
//! generate unrelated identities. The pure graph-context decision logic lives in
//! [`aos_hub_model::domain::iam`]; this module only stores and lists the rows.
//!
//! Existing phase-1 `registries` rows acquire `org_id IS NULL`,
//! `project_path = ''`, and `visibility = 'public'` — the RFC's
//! instance-level *unowned public registry* that phase 2 adopts unchanged.
//!
//! # Storage topology
//!
//! Registries and caches are logical identities. Every physical byte path is
//! represented by a placement that names one typed binding and one
//! binding-relative prefix. Reads select eligible placements; writes require a
//! fully reconciled write authority. No resource-global storage pointer or
//! physical-source fallback exists.
//!
//! ## Canonical registry identity
//!
//! Phase-1 registries are addressed by a flat `slug`; phase-2 managed
//! registries are addressed by the canonical path
//! `{org}/{project_path}/{registry}`. Rather than add a second identifier
//! column (and the awkward partial-unique index that phase-1 `NULL`
//! ownership would require), a managed registry stores its **full
//! canonical path as its `slug`** — `"acme/infra/prod/cdn"`, or
//! `"acme/cdn"` when `project_path` is empty. The existing
//! `UNIQUE(slug)` constraint then enforces canonical uniqueness for free,
//! one router shape ([`Database::registry_by_slug`]) resolves both flat
//! and nested registries, and [`Database::registry_by_scope`] simply
//! builds the canonical string and delegates to it.
//!
//! # Configuration history (v7)
//!
//! Phase 3a adds the SQL system-of-record's configuration history
//! (RFC-0004 "Configuration management" and "Tenancy and IAM"). Three
//! append-only tables — never `UPDATE`d row-by-row except for the
//! changeset lifecycle stamps — record every mutation of the SQL-backed
//! config (visibility, memberships, tokens metadata, bindings,
//! registry config) and who performed it.
//!
//! A **changeset** is a unit of review: an actor opens a draft, stages one
//! or more **revisions** (full before/after JSON snapshots of each touched
//! object), and applies it atomically. Each apply writes exactly one
//! **audit-log** row carrying the changeset's `change_id`, so the audit
//! feed and the revision log share one join key. A **revert** is a
//! snapshot-targeted *forward* changeset (never a literal restore): it
//! drafts new revisions targeting each original revision's `old_json`,
//! flags conflicts where the live object has since diverged, and stamps the
//! original's `reverted_by_change_id`.
//!
//! ```text
//! audit_log         id  change_id  actor_kind  actor_label       action
//!                   1   c1a2…      user        alice@acme.com    registry.visibility
//!                       scope "acme/infra/prod/cdn"  result_commit ""  result_tag ""
//!                       detail '{"old":"public","new":"private"}'  created_at 1730000000
//!
//! change_requests change_id c1a2…  actor_label alice@acme.com
//!                   scope "acme/infra/prod/cdn"  status applied
//!                   summary "set cdn visibility to private"
//!                   created_at 1730000000  applied_at 1730000000
//!                   reverted_by_change_id NULL
//!
//! change_request_revisions  id 1  change_id c1a2…  object_type registry
//!                   object_id "acme/infra/prod/cdn"  op update  seq 0
//!                   old_json '{"visibility":"public"}'
//!                   new_json '{"visibility":"private"}'
//! ```
//!
//! `change_id` is a UUID v4 (the crate's existing `uuid` dependency); rows
//! order by `created_at` rather than by a sortable id, so no new dependency
//! (a ULID generator) is taken on. The engine that drives these tables —
//! drafting, staging, semantic-diffing, applying, and reverting — lives in
//! the service configuration layer; this module only stores and lists the rows.
//!
//! ## Security-object revert exemptions
//!
//! Reverting a security-sensitive object never resurrects a live
//! credential or grant (RFC-0004): a `token` revert renders as an
//! "issue replacement" note (a no-op create), and a `membership` delete
//! reverts to an *invitation* rather than a silent re-admit. These are
//! encoded as operation/notes by the service configuration-revert operation.
//!
//! # Per-org OIDC SSO (v9)
//!
//! Phase 3d adds per-org single sign-on (RFC-0004 "Per-org OIDC SSO"). Three
//! tables hold facts that exist nowhere on the surface: an org's identity
//! provider, the domains it has captured, and the in-flight login state.
//!
//! ```text
//! org_idp_configs   org_id 1  issuer "https://idp.acme.example"
//!                   authorization_endpoint ".../authorize"
//!                   token_endpoint ".../token"  jwks_uri ".../jwks"
//!                   client_id "hub"  client_secret_enc "<sealed>"
//!                   scopes "openid email profile"  groups_claim "groups"
//!                   role_map_json '{"acme-admins":"admin"}'
//!                   allow_jit 1  enforce_sso 1  default_role "viewer"
//!
//! org_domains       domain "acme.com"  org_id 1
//!                   txt_challenge "aos-domain-verify=<random>"
//!                   verified_at 1730000000        -- NULL until verified
//!
//! oidc_flows        state "<opaque>"  org_id 1  nonce "<opaque>"
//!                   code_verifier "<43..128 chars>"  redirect_after "/"
//!                   created_at 1730000000  expires_at 1730000600
//! ```
//!
//! Login keys identities on `(issuer, subject)` — never bare email — through
//! [`Database::link_or_create_identity`]: an existing `(iss, sub)` resolves to
//! its user, an IdP-verified email on a captured domain links to an existing
//! user, and otherwise a fresh user + identity is provisioned (when
//! `allow_jit`). The OIDC flow itself — PKCE, the authorization URL, the token
//! exchange, and JWKS-backed RS256 id_token verification — lives in
//! the hub's `auth::oidc` module; this module only stores and lists the rows.
//!
//! # Signing-key lifecycle
//!
//! Signing trust is modeled by immutable public generations. A stable key
//! identity advances by appending a generation and retiring its predecessor;
//! typed usage rows pin each registry, cache, or channel purpose to one exact
//! generation. Private-key material never enters this database boundary.
//! Custody is an explicit generation attribute resolved by the signing
//! provider only when an authorized operation needs a signature.
//!
//! # Outbound webhooks (v11)
//!
//! Phase 4 adds **webhooks** (RFC-0004 "webhooks/notifications"). An org
//! subscribes an HTTP endpoint to a set of registry event types; each event
//! the hub raises ([`aos_hub_model::webhook::WebhookEvent`]) fans out into a durable
//! at-least-once delivery queue.
//!
//! ```text
//! webhooks            id 1  org_id 1  url "https://ci.acme/aos-hook"
//!                     secret "<shared>"  events '["index.completed"]'  active 1
//!
//! webhook_deliveries  id 1  webhook_id 1  event "index.completed"
//!                     payload '{"registry":"acme/cdn",…}'  status pending
//!                     attempts 0  next_attempt_at 1730000000
//! ```
//!
//! `secret` is stored as plaintext (not a hash): the subscriber needs the same
//! secret to verify the `X-AOS-Signature` HMAC. A delivery walks `pending ->
//! delivered | failed`; a non-2xx response increments `attempts` and schedules
//! `next_attempt_at` with exponential backoff up to the attempt cap. The
//! dispatch/delivery logic lives in the service webhook dispatcher; this module only
//! stores and lists the rows.
//!
//! # Operations: quotas, signup policy, soft-delete (v13)
//!
//! The operations chapter of RFC-0004 ("Operations: migrations, backup,
//! quotas, observability, offboarding") adds four tables/columns that are all
//! **system of record** — none is rebuildable from the surface.
//!
//! ```text
//! org_quotas       org_id 1  max_bytes 1073741824  max_objects 100000
//!                  max_registries 50  max_tokens 200    -- NULL = unlimited
//!
//! org_usage        org_id 1  used_bytes 532480  object_count 412
//!                  updated_at 1730000000             -- running totals on upload
//!
//! instance_config  config_key "signup_policy"  value "invite_only"   -- 'open'|'invite_only'
//!
//! orgs (+columns)  deleted_at 1730000000  purge_after 1732592000  -- NULL = active
//! ```
//!
//! - `org_quotas` caps an org's hub-managed storage: bytes, object count,
//!   registries, and active tokens. A `NULL` cell is unlimited; typed upload
//!   admission rejects an over-quota write with `507 Insufficient Storage`
//!   ([`Database::would_exceed_quota`]), matching `aos-server`'s `max_paths`
//!   contract.
//! - `org_usage` holds running totals maintained on every successful upload
//!   ([`Database::add_org_usage`]). Usage is *approximate* — it counts bytes as
//!   written; a re-index/GC reconciliation that rebuilds it from the surface is
//!   a later refinement, so a deleted object's bytes linger until then.
//! - `instance_config` is the instance-wide key/value store; its first key is
//!   `signup_policy` (`open` allows any authenticated user to create an org;
//!   `invite_only`, the default, requires an invitation or existing
//!   membership). See [`Database::signup_policy`].
//! - The `orgs.deleted_at`/`orgs.purge_after` columns implement soft-delete
//!   with a grace window (RFC-0004 offboarding): [`Database::soft_delete_org`]
//!   stamps both, [`Database::restore_org`] clears them, the purge job
//!   ([`Database::list_purgeable_orgs`] + [`Database::hard_purge_org`]) hard
//!   deletes past the grace, and the serving paths
//!   ([`Database::org_by_slug`], [`Database::list_registries`], …) exclude
//!   soft-deleted orgs so a tombstoned org stops serving immediately.

// `Path` is used only by the native `open`/`connect` constructors (gated off
// wasm32).
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::Digest as _;

use crate::backend::{Backend, CheckedStatement, Statement};
use crate::dialect::Dialect;
use crate::value::{Row, Value};
use aos_hub_model::domain::Permission;

// SqlxBackend is the native driver (sqlx does not build for wasm32); the
// constructors that build one are native-only. The Worker constructs a
// `Database` from its Durable Object SQLite `Backend` via
// [`Database::with_backend`].
#[cfg(not(target_arch = "wasm32"))]
use crate::backend::SqlxBackend;

/// Builds a `Vec<Value>` parameter list from a heterogeneous set of bindable
/// values, mirroring rusqlite's `params!` ergonomics for the [`Backend`] API.
///
/// Each argument is converted via [`ToValue`], so `i64`, `Option<i64>`,
/// `&str`, `String`, `bool`, `u32`, … all bind directly.
macro_rules! vals {
    ($($v:expr),* $(,)?) => {
        vec![$( crate::value::ToValue::to_value(&$v) ),*]
    };
}

// Durable Object SQLite crosses the Wasm/JavaScript boundary once per SQL
// statement, even when all statements belong to one storage transaction. A
// complete registry generation can contain thousands of catalog rows, so
// issuing one INSERT per row exhausts a queue activation before the atomic
// snapshot becomes visible. Cloudflare Durable Object SQLite accepts at most
// 100 bound parameters per query; size chunks from their actual row width so
// every statement honors that limit while collapsing the hot path.
const SNAPSHOT_MAX_BOUND_PARAMETERS: usize = 100;

fn extend_multirow_insert(
    statements: &mut Vec<Statement>,
    insert: &str,
    rows: &[Vec<Value>],
    suffix: &str,
) -> Result<()> {
    let Some(first) = rows.first() else {
        return Ok(());
    };
    anyhow::ensure!(!first.is_empty(), "multi-row insert has no columns");
    anyhow::ensure!(
        rows.iter().all(|row| row.len() == first.len()),
        "multi-row insert has inconsistent row widths"
    );
    anyhow::ensure!(
        first.len() <= SNAPSHOT_MAX_BOUND_PARAMETERS,
        "multi-row insert exceeds the SQL binding limit"
    );
    let rows_per_insert = SNAPSHOT_MAX_BOUND_PARAMETERS / first.len();

    for chunk in rows.chunks(rows_per_insert) {
        let mut parameter = 1;
        let mut tuples = Vec::with_capacity(chunk.len());
        let mut params = Vec::with_capacity(chunk.len() * first.len());
        for row in chunk {
            let placeholders = (0..row.len())
                .map(|_| {
                    let placeholder = format!("?{parameter}");
                    parameter += 1;
                    placeholder
                })
                .collect::<Vec<_>>()
                .join(", ");
            tuples.push(format!("({placeholders})"));
            params.extend(row.iter().cloned());
        }
        statements.push(Statement::new(
            format!("{insert} VALUES {}{suffix}", tuples.join(", ")),
            params,
        ));
    }
    Ok(())
}

fn extend_release_artifact_inserts(
    statements: &mut Vec<Statement>,
    snapshot_id: &str,
    rows: &[Vec<Value>],
) -> Result<()> {
    anyhow::ensure!(
        rows.iter().all(|row| row.len() == 7),
        "release artifact insert has an inconsistent row width"
    );
    let rows_per_insert = (SNAPSHOT_MAX_BOUND_PARAMETERS - 1) / 7;
    for chunk in rows.chunks(rows_per_insert) {
        let mut parameter = 2;
        let mut tuples = Vec::with_capacity(chunk.len());
        let mut params = vals![snapshot_id];
        for row in chunk {
            let placeholders = (0..row.len())
                .map(|_| {
                    let placeholder = format!("?{parameter}");
                    parameter += 1;
                    placeholder
                })
                .collect::<Vec<_>>()
                .join(", ");
            tuples.push(format!("({placeholders})"));
            params.extend(row.iter().cloned());
        }
        statements.push(Statement::new(
            format!(
                "WITH input(package_name, package_version, platform, artifact_kind,
                            store_path, store_hash, metadata_digest) AS
                   (VALUES {})
                 INSERT INTO release_artifacts
                   (snapshot_id, release_id, registry_id, package_name,
                    package_version, platform, artifact_kind, store_path,
                    store_hash, metadata_digest)
                 SELECT ?1, ras.release_id, ras.registry_id, input.package_name,
                        input.package_version, input.platform, input.artifact_kind,
                        input.store_path, input.store_hash, input.metadata_digest
                   FROM release_artifact_snapshots ras CROSS JOIN input
                  WHERE ras.snapshot_id = ?1 AND ras.state = 'building'",
                tuples.join(", ")
            ),
            params,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_insert_tests {
    use super::{
        extend_multirow_insert, extend_release_artifact_inserts, Statement, Value,
        SNAPSHOT_MAX_BOUND_PARAMETERS,
    };

    #[test]
    fn multirow_inserts_respect_durable_object_parameter_limit() {
        let rows = vec![vec![Value::Int(1); 9]; 123];
        let mut statements = Vec::<Statement>::new();

        extend_multirow_insert(&mut statements, "INSERT INTO example", &rows, "").unwrap();

        assert_eq!(statements.len(), 12);
        assert!(statements
            .iter()
            .all(|statement| statement.params.len() <= SNAPSHOT_MAX_BOUND_PARAMETERS));
    }

    #[test]
    fn release_artifact_inserts_include_shared_snapshot_parameter_in_limit() {
        let rows = vec![vec![Value::Int(1); 7]; 100];
        let mut statements = Vec::<Statement>::new();

        extend_release_artifact_inserts(&mut statements, "snapshot", &rows).unwrap();

        assert_eq!(statements.len(), 8);
        assert!(statements
            .iter()
            .all(|statement| statement.params.len() <= SNAPSHOT_MAX_BOUND_PARAMETERS));
    }
}

mod cache_write_admission;
pub use cache_write_admission::*;
mod delivery_identity;
pub use delivery_identity::*;
mod delivery_workflow;
mod direct_delivery;
mod publication_delivery;
pub use delivery_workflow::*;
mod egress_nonce;
mod gc_topology;
pub use gc_topology::*;
mod oci;
pub use oci::*;
mod oci_admin;
pub use oci_admin::*;
mod oci_gc;
pub use oci_gc::*;
mod ability_deployment_overlays;
pub use ability_deployment_overlays::*;
mod oci_namespaces;
pub use oci_namespaces::*;
mod oci_release_projection;
mod placement_policy;
mod publication_admission;
mod registry_delete;
pub use registry_delete::*;
mod registry_delete_operation;
pub use registry_delete_operation::*;
mod registry_delete_readiness;
pub use registry_delete_readiness::*;
mod native_documentation;
mod registry_index_build;
mod release_browse;
pub use native_documentation::{NativeDocumentationIndex, NativeDocumentationLocator};
mod release_publication;
mod staged_releases;
#[cfg(test)]
mod staged_retention_tests;
pub use release_browse::*;
mod settings_reads;
pub(crate) mod surface_topology;
pub use surface_topology::*;
mod signing_keys;
mod topology;
mod worker_jobs;
pub use placement_policy::*;
pub use publication_admission::*;
pub use registry_index_build::*;
pub use release_publication::*;
pub use signing_keys::*;
pub use staged_releases::*;
pub use topology::*;
pub use worker_jobs::*;

/// Grace period, in seconds, during which a rotated token's old secret
/// keeps validating after its `revoked_at` stamp (RFC-0004 fixes the
/// `aos-server` bug where this window was recorded but not honored).
const ROTATION_GRACE_SECS: i64 = 3600;

/// Maximum `audit_log` rows scanned per [`Database::list_audit`] call.
///
/// The audit log is append-only and unbounded, so the query reads at most this
/// many most-recent rows (`ORDER BY id DESC LIMIT`) before scope-filtering them
/// in Rust — a single request can never materialize the whole table. Generous
/// enough that a paged console/RPC view always sees recent activity.
const MAX_AUDIT_SCAN: i64 = 10_000;

/// Largest integer that every Hub SQL transport represents exactly.
///
/// Native drivers preserve the full SQLite/PostgreSQL/MySQL `i64` range, but
/// Durable Object SQL crosses the JavaScript number boundary. Relational ids
/// generated by shared core must therefore remain in the positive exact
/// integer range common to every runtime.
const PORTABLE_RELATIONAL_ID_MAX: i64 = 9_007_199_254_740_991;

/// Derives a positive, cross-runtime relational key from a stable incarnation.
pub fn portable_relational_id(incarnation: uuid::Uuid) -> i64 {
    (incarnation.as_u128() % PORTABLE_RELATIONAL_ID_MAX as u128) as i64 + 1
}

/// Ordered, append-only schema migrations; index = version - 1.
///
/// The first entry is the immutable first stable production baseline. Databases
/// from development histories must be reset before deploying this checkpoint;
/// subsequent production changes require new forward migrations.
///
/// | Version | Script | Change |
/// | --- | --- | --- |
/// | 1 | `schema.sql` | Production baseline. |
/// | 2 | `release_channel_advances.sql` | Channel ledger that admits per-train channel names. |
/// | 3 | `staged_releases.sql` | Private release drafts, retention roots, and public catalog selections. |
/// | 4 | `oci_registry_retirement.sql` | Reviewed OCI catalog retirement flag on GC runs. |
/// | 5 | `oci_namespace_routes.sql` | Instance-owned OCI root routes and per-registry OCI namespaces. |
/// | 6 | `migration-0006-release-ability-graphs.sql` | Native release ability references. |
/// | 7 | `migration-0007-native-documentation.sql` | Native documentation and search projections. |
/// | 8 | `migration-0008-native-deployment-report.sql` | Native deployment reports and replay fences. |
pub const MIGRATIONS: &[&str] = &[
    include_str!("schema.sql"),
    include_str!("release_channel_advances.sql"),
    include_str!("staged_releases.sql"),
    include_str!("oci_registry_retirement.sql"),
    include_str!("oci_namespace_routes.sql"),
    include_str!("migration-0006-release-ability-graphs.sql"),
    include_str!("migration-0007-native-documentation.sql"),
    include_str!("migration-0008-native-deployment-report.sql"),
];

/// Identifies the production migration lineage independently of its version.
///
/// Historical development ledgers are incompatible even when their integer
/// version happens to match a production migration.
pub const SCHEMA_IDENTITY: &str = "aos-hub/production-baseline/1";

/// Returns every migration's individual SQL statements, in order.
///
/// Splits the [`MIGRATIONS`] scripts at statement boundaries via
/// [`split_statements`](crate::backend::split_statements), flattened across all
/// versions. Useful for tooling that must apply the schema outside the
/// [`Database`] migration path — e.g. seeding a test HubDb over its binding, or the
/// `aos-hub schema dump` command.
#[must_use]
pub fn migration_statements() -> Vec<String> {
    MIGRATIONS
        .iter()
        .flat_map(|m| crate::backend::split_statements(m))
        .collect()
}

/// Returns a MySQL migration statement that is safe to replay after DDL's
/// implicit commit boundary.
fn mysql_replay_safe_migration_sql(sql: &str) -> String {
    if sql.contains("CREATE TABLE ") && !sql.contains("CREATE TABLE IF NOT EXISTS ") {
        return sql.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1);
    }
    if sql.contains("CREATE VIEW ") {
        return sql.replacen("CREATE VIEW ", "CREATE OR REPLACE VIEW ", 1);
    }
    if sql.contains("ALTER TABLE ")
        && sql.contains("ADD COLUMN ")
        && !sql.contains("ADD COLUMN IF NOT EXISTS ")
    {
        return sql.replacen("ADD COLUMN ", "ADD COLUMN IF NOT EXISTS ", 1);
    }
    if sql.contains("INSERT INTO ") && !sql.contains("ON CONFLICT") {
        return sql.replacen("INSERT INTO ", "INSERT IGNORE INTO ", 1);
    }
    sql.to_string()
}

/// Extracts the table and index names from a migration `CREATE INDEX`.
fn mysql_migration_index_identity(sql: &str) -> Option<(&str, &str)> {
    let start = sql
        .find("CREATE UNIQUE INDEX ")
        .map(|offset| offset + "CREATE UNIQUE INDEX ".len())
        .or_else(|| {
            sql.find("CREATE INDEX ")
                .map(|offset| offset + "CREATE INDEX ".len())
        })?;
    let rest = sql.get(start..)?.trim_start();
    let index_end = rest.find(char::is_whitespace)?;
    let index = rest.get(..index_end)?.trim_matches('`');
    let after_index = rest.get(index_end..)?.trim_start();
    let after_on = after_index.strip_prefix("ON ")?.trim_start();
    let table_end = after_on
        .find(|character: char| character.is_whitespace() || character == '(')
        .unwrap_or(after_on.len());
    let table = after_on.get(..table_end)?.trim_matches('`');
    (!table.is_empty() && !index.is_empty()).then_some((table, index))
}

/// Whether any error in `err`'s chain is a [`LastOwnerError`].
///
/// Walks the full `anyhow` context chain, so classification survives any
/// number of `.context(…)` layers added by callers.
#[must_use]
pub fn is_last_owner_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<LastOwnerError>().is_some())
}

const BINDING_READ_DETAIL_SQL: &str =
    "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key, \
     resource_version, created_at, updated_at \
     FROM bindings WHERE stable_id = ?1";

const BINDING_READ_SUMMARY_SQL: &str =
    "SELECT id, org_id, name, kind, is_instance_default, stable_id \
     FROM bindings WHERE org_id = ?1 ORDER BY name";

fn invitation_record_from_row(row: Row) -> Result<InvitationRecord> {
    Ok(InvitationRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        email: row.get(2)?,
        scope: row.get(3)?,
        role: row.get(4)?,
        created_at: row.get(5)?,
        accepted_at: row.get(6)?,
        cancelled_at: row.get(7)?,
        expires_at: row.get(8)?,
    })
}

pub use aos_hub_model::identity::IdpConfigRecord;

pub use aos_hub_model::identity::TokenAuth;

/// One resolved closure edge: a store-hash prefix and the package that
/// publishes it, when resolvable within the same registry.
///
/// `(hash, name, version)` — `name` and `version` are `Some` when some package
/// in the registry owns the store path with this hash prefix, and `None` for a
/// hash that points outside the registry's package set (e.g. a stdenv path).
/// Returned in input order by [`Database::resolve_reference_names`].
pub type ResolvedReference = (String, Option<String>, Option<String>);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSystemImageIdentity {
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    delivery: aos_registry_format::manifest::ImageDelivery,
}

fn encode_stored_system_image(image: &IndexedSystemImage) -> Result<String> {
    serde_json::to_string(&StoredSystemImageIdentity {
        store_path: image.store_path.clone(),
        nar_hash: image.nar_hash.clone(),
        nar_size: image.nar_size,
        delivery: image.delivery.clone(),
    })
    .context("encoding signed image artifact identity")
}

fn decode_stored_system_image(encoded: &str) -> Result<StoredSystemImageIdentity> {
    if let Ok(image) = serde_json::from_str(encoded) {
        return Ok(image);
    }

    let delivery =
        serde_json::from_str(encoded).context("decoding signed image delivery metadata")?;
    Ok(StoredSystemImageIdentity {
        store_path: String::new(),
        nar_hash: String::new(),
        nar_size: 0,
        delivery,
    })
}

/// Finds a typed placement-create failure in an error context chain.
#[must_use]
pub fn surface_placement_create_failure(
    error: &anyhow::Error,
) -> Option<&SurfacePlacementCreateFailure> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SurfacePlacementCreateFailure>())
}

/// Finds a typed caller-correctable authority failure in an error chain.
#[must_use]
pub fn surface_write_authority_mutation_failure(
    error: &anyhow::Error,
) -> Option<&SurfaceWriteAuthorityMutationFailure> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SurfaceWriteAuthorityMutationFailure>())
}

/// Maximum number of placement observations persisted in one atomic batch.
///
/// The bound matches the Worker surface-list page so one provider page maps to
/// one database round trip without allowing an unbounded transaction.
pub const MAX_PLACEMENT_SCAN_PRESENCE_BATCH: usize = 256;

// Durable Object SQLite accepts at most 100 bound parameters per statement.
// The placement occupies one slot in each bulk delete.
const MAX_PLACEMENT_SCAN_DELETE_IDS: usize = 99;

fn row_to_webhook(row: &Row) -> Result<WebhookRecord> {
    let events_json: String = row.get(5)?;
    Ok(WebhookRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        url: row.get(2)?,
        secret_version_ref: row.get(3)?,
        credential_fingerprint: row.get(4)?,
        events: serde_json::from_str(&events_json).unwrap_or_default(),
        active: row.get(6)?,
        created_at: row.get(7)?,
        resource_version: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

/// Maximum active and inactive webhook subscriptions retained by one org.
pub const MAX_WEBHOOKS_PER_ORG: usize = 100;

/// The hub database handle.
pub struct Database {
    pub(super) backend: Box<dyn Backend>,
}

impl Database {
    /// The instance-config key the sealed draft-signing seed is stored under.
    const DRAFT_SIGNING_KEY: &'static str = "draft_signing_key";
}

/// The wire names of a permission slice, for JSON storage.
fn permission_names(permissions: &[aos_hub_model::domain::Permission]) -> Vec<&'static str> {
    permissions.iter().map(|p| p.as_str()).collect()
}

fn operation_target_control_permission(
    target_kind: &str,
    primary_permission: aos_hub_model::domain::Permission,
) -> aos_hub_model::domain::Permission {
    use aos_hub_model::domain::Permission;
    match target_kind {
        "registry" => Permission::RegistryConfigure,
        "placement" => Permission::PlacementManage,
        "placement_policy" => Permission::PlacementPolicyManage,
        "domain" => Permission::DomainManage,
        "network_policy" => Permission::NetworkPolicyManage,
        "endpoint" => Permission::EndpointManage,
        "gateway" => Permission::GatewayManage,
        "route" => Permission::RouteManage,
        "binding" => Permission::BindingManage,
        _ => primary_permission,
    }
}

/// Parse a JSON array of permission verb names into domain permissions,
/// skipping any unknown verb (forward-compatibility with a newer writer).
fn parse_permission_names(json: &str) -> Vec<aos_hub_model::domain::Permission> {
    let names: Vec<String> = serde_json::from_str(json).unwrap_or_default();
    names
        .iter()
        .filter_map(|n| aos_hub_model::auth::permission_from_str(n))
        .collect()
}

/// The column list every `RegistryRecord` query selects, in the order
/// [`row_to_registry`] reads.
const REGISTRY_COLUMNS: &str = "id, stable_id, scope_key, owner_scope_key, slug, \
     trust_keys, require_signatures, org_id, project_path, visibility, \
     crawl_policy, llms_txt_body, resource_version, updated_at";

/// `binary_caches` columns in the canonical order [`row_to_binary_cache`] expects.
const BINARY_CACHE_COLUMNS: &str =
    "id, stable_id, scope_key, owner_scope_key, org_id, slug, name, \
     visibility, priority, compression, want_mass_query, \
     created_at, deleted_at, purge_after, resource_version, updated_at";

/// Maps a `binary_caches` row into a [`BinaryCache`].
fn row_to_binary_cache(row: &Row) -> Result<BinaryCache> {
    Ok(BinaryCache {
        id: row.get(0)?,
        stable_id: row.get(1)?,
        scope_key: row.get(2)?,
        owner_scope_key: row.get(3)?,
        org_id: row.get(4)?,
        slug: row.get(5)?,
        name: row.get(6)?,
        visibility: row.get(7)?,
        priority: row.get(8)?,
        compression: row.get(9)?,
        want_mass_query: row.get(10)?,
        created_at: row.get(11)?,
        deleted_at: row.get(12)?,
        purge_after: row.get(13)?,
        resource_version: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn row_to_registry(row: &Row) -> Result<RegistryRecord> {
    let trust_json: String = row.get(5)?;
    Ok(RegistryRecord {
        id: row.get(0)?,
        stable_id: row.get(1)?,
        scope_key: row.get(2)?,
        owner_scope_key: row.get(3)?,
        slug: row.get(4)?,
        trust_keys: serde_json::from_str(&trust_json).unwrap_or_default(),
        require_signatures: row.get(6)?,
        org_id: row.get(7)?,
        project_path: row.get(8)?,
        visibility: row.get(9)?,
        crawl_policy: row.get(10)?,
        llms_txt_body: row.get(11)?,
        resource_version: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

/// Map a `mirror_sources` row (selected in column order
/// `upstream_url, mode, verify, schedule_secs, last_sync_at, last_sync_status,
/// last_sync_error, upstream_frontier`) into a [`MirrorSource`].
fn row_to_mirror_source(row: &Row) -> Result<MirrorSource> {
    Ok(MirrorSource {
        upstream_url: row.get(0)?,
        mode: row.get(1)?,
        verify: row.get(2)?,
        schedule_secs: row.get(3)?,
        last_sync_at: row.get(4)?,
        last_sync_status: row.get(5)?,
        last_sync_error: row.get(6)?,
        upstream_frontier: row.get(7)?,
    })
}

/// Normalizes a topology-domain hostname without accepting URL components.
fn normalize_topology_hostname(hostname: &str) -> Result<String> {
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.contains(char::is_whitespace)
        || hostname.contains(['/', ':', '?', '#'])
    {
        bail!(
            "domain hostname must contain only a host, without scheme, port, path, query, or fragment"
        );
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("domain hostname '{hostname}' contains an invalid DNS label");
        }
    }
    Ok(hostname)
}

/// Normalizes a safe binding-relative placement prefix.
fn normalize_placement_prefix(prefix: &str) -> Result<String> {
    if prefix != prefix.trim() {
        bail!("placement prefix must not have surrounding whitespace");
    }
    let prefix = prefix.trim_matches('/');
    if prefix.contains("//") || prefix.split('/').any(|part| matches!(part, "." | "..")) {
        bail!("placement prefix must be a safe binding-relative path");
    }
    if prefix.is_empty() {
        return Ok(String::new());
    }
    validate_key_bytes(prefix, "placement prefix", 512)?;
    Ok(prefix.to_string())
}

fn validate_key_bytes(value: &str, label: &str, capacity: usize) -> Result<()> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > capacity
        || value.chars().any(char::is_control)
    {
        bail!(
            "{label} must be non-empty, have no surrounding whitespace or control characters, and fit in {capacity} UTF-8 bytes"
        );
    }
    Ok(())
}

fn validate_stable_name(value: &str, label: &str) -> Result<()> {
    validate_key_bytes(value, label, 64)?;
    if value != value.trim() || value.contains('/') {
        bail!("{label} must be a stable name without surrounding whitespace or '/'");
    }
    Ok(())
}

fn validate_json_value(json: &str, label: &str) -> Result<()> {
    serde_json::from_str::<serde_json::Value>(json)
        .with_context(|| format!("invalid {label} JSON"))?;
    Ok(())
}

fn validate_json_object(json: &str, label: &str) -> Result<()> {
    if !serde_json::from_str::<serde_json::Value>(json)
        .with_context(|| format!("invalid {label} JSON"))?
        .is_object()
    {
        bail!("{label} must be a JSON object");
    }
    Ok(())
}

fn validate_placement_spec(
    kind: &str,
    desired_state: &str,
    hash_range: Option<SurfacePlacementHashRange>,
    desired_read_enabled: bool,
) -> Result<()> {
    if !matches!(kind, "complete" | "shard" | "archive") {
        bail!("invalid placement kind '{kind}'");
    }
    if !matches!(desired_state, "active" | "offline") {
        bail!("new placements must have desired state 'active' or 'offline'");
    }
    if (kind == "shard") != hash_range.is_some() {
        bail!("only shard placements require a hash range");
    }
    if let Some(range) = hash_range {
        if range.start < 0 || range.start >= range.end || range.end > 65_536 {
            bail!("shard hash range must be non-empty and half-open within 0..65536");
        }
    }
    if kind == "archive" && desired_read_enabled {
        bail!("an archive placement cannot be read-enabled");
    }
    Ok(())
}

const PLACEMENT_COLUMNS: &str = "id, registry_id, cache_id, name, binding_id,
    prefix, derived_role, state, completeness, hash_range_start, hash_range_end,
    mutable_publication_id, effective_read_enabled, effective_write_enabled, read_order,
    created_at, updated_at,
    resource_version, kind, desired_state, desired_read_enabled, write_spec_version,
    requires_conditional_writes,
    observed_at, observation_version, watermark_resource_version,
    watermark_pending_publication_id, write_authority_id,
    authority_desired_placement_id, authority_observed_placement_id,
    authority_desired_write_spec_version, authority_observed_write_spec_version,
    authority_desired_binding_write_revision, authority_observed_binding_write_revision,
    authority_desired_generation, authority_observed_generation,
    authority_reconciliation_state";
const PLACEMENT_COLUMN_COUNT: usize = 37;
const BINDING_WRITE_REVISION_COLUMNS: &str = "binding_id, revision,
    write_credential_version_ref, write_credential_purpose, write_credential_generation,
    writes_supported, conditional_writes_supported,
    revision_fingerprint, capability_fingerprint, created_at";
const BINDING_WRITE_OBSERVATION_COLUMNS: &str = "binding_id, revision, state,
    validated_at, error, observation_version";
const WRITE_AUTHORITY_COLUMNS: &str = "id, incarnation_id, registry_id, cache_id, mode,
    desired_placement_id, desired_write_spec_version, desired_binding_write_revision,
    desired_generation, observed_placement_id, observed_write_spec_version,
    observed_binding_write_revision, observed_generation, reconciliation_state,
    reconciliation_error, resource_version, created_at, updated_at";
const SURFACE_OBJECT_COLUMNS: &str = "id, registry_id, cache_id, object_key,
    object_kind, content_hash, size, mutable_publication_id, lifecycle_state,
    tombstoned_at, created_at, updated_at, resource_version";
const POPULATION_COLUMNS: &str = "id, cache_id, registry_id, trigger_kind, required,
    placement_policy_revision_id, selector_json, validation_gate, enabled, resource_version,
    created_at, updated_at";
const PLAN_COLUMNS: &str = "plan_id, plan_kind, actor_kind, actor_id, actor_label,
    scope, input_versions_json, effects_json, warnings_json, confirmation_hash,
    request_idempotency_key, request_digest, apply_idempotency_key, apply_result_json,
    created_at, expires_at, applied_at";
const OPERATION_COLUMNS: &str = "operation_id, operation_kind, authorization_scope_key,
    control_permission, primary_target_kind, primary_target_stable_id,
    primary_target_generation_key, primary_target_configuration_digest,
    state, progress_current, progress_total, detail_json, error,
    created_at, started_at, finished_at, resource_version";

fn row_to_domain(row: &Row) -> Result<DomainRecord> {
    Ok(DomainRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        hostname: row.get(2)?,
        desired_dns_provider: row.get(3)?,
        observed_dns_state: row.get(4)?,
        desired_tls_provider: row.get(5)?,
        observed_tls_state: row.get(6)?,
        access_provider_json: row.get(7)?,
        verified_at: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        resource_version: row.get(11)?,
    })
}

fn row_to_surface_placement(row: &Row) -> Result<SurfacePlacementRecord> {
    Ok(SurfacePlacementRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        cache_id: row.get(2)?,
        name: row.get(3)?,
        binding_id: row.get(4)?,
        prefix: row.get(5)?,
        derived_role: row.get(6)?,
        state: row.get(7)?,
        completeness: row.get(8)?,
        hash_range_start: row.get(9)?,
        hash_range_end: row.get(10)?,
        mutable_publication_id: row.get(11)?,
        effective_read_enabled: row.get(12)?,
        effective_write_enabled: row.get(13)?,
        read_order: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
        resource_version: row.get(17)?,
        kind: row.get(18)?,
        desired_state: row.get(19)?,
        desired_read_enabled: row.get(20)?,
        write_spec_version: row.get(21)?,
        requires_conditional_writes: row.get(22)?,
        observed_at: row.get(23)?,
        observation_version: row.get(24)?,
        watermark_resource_version: row.get(25)?,
        watermark_pending_publication_id: row.get(26)?,
        write_authority_id: row.get(27)?,
        authority_desired_placement_id: row.get(28)?,
        authority_observed_placement_id: row.get(29)?,
        authority_desired_write_spec_version: row.get(30)?,
        authority_observed_write_spec_version: row.get(31)?,
        authority_desired_binding_write_revision: row.get(32)?,
        authority_observed_binding_write_revision: row.get(33)?,
        authority_desired_generation: row.get(34)?,
        authority_observed_generation: row.get(35)?,
        authority_reconciliation_state: row.get(36)?,
    })
}

fn row_to_binding_write_revision(row: &Row) -> Result<BindingWriteRevisionRecord> {
    Ok(BindingWriteRevisionRecord {
        binding_id: row.get(0)?,
        revision: row.get(1)?,
        write_credential_version_ref: row.get(2)?,
        write_credential_purpose: row.get(3)?,
        write_credential_generation: row.get(4)?,
        writes_supported: row.get(5)?,
        conditional_writes_supported: row.get(6)?,
        revision_fingerprint: row.get(7)?,
        capability_fingerprint: row.get(8)?,
        created_at: row.get(9)?,
    })
}

fn row_to_binding_write_observation(row: &Row) -> Result<BindingWriteObservationRecord> {
    Ok(BindingWriteObservationRecord {
        binding_id: row.get(0)?,
        revision: row.get(1)?,
        state: row.get(2)?,
        validated_at: row.get(3)?,
        error: row.get(4)?,
        observation_version: row.get(5)?,
    })
}

fn row_to_surface_write_authority(row: &Row) -> Result<SurfaceWriteAuthorityRecord> {
    Ok(SurfaceWriteAuthorityRecord {
        id: row.get(0)?,
        incarnation_id: row.get(1)?,
        registry_id: row.get(2)?,
        cache_id: row.get(3)?,
        mode: row.get(4)?,
        desired_placement_id: row.get(5)?,
        desired_write_spec_version: row.get(6)?,
        desired_binding_write_revision: row.get(7)?,
        desired_generation: row.get(8)?,
        observed_placement_id: row.get(9)?,
        observed_write_spec_version: row.get(10)?,
        observed_binding_write_revision: row.get(11)?,
        observed_generation: row.get(12)?,
        reconciliation_state: row.get(13)?,
        reconciliation_error: row.get(14)?,
        resource_version: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

fn row_to_cache_population_target(row: &Row) -> Result<CachePopulationTargetRecord> {
    Ok(CachePopulationTargetRecord {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        registry_id: row.get(2)?,
        trigger_kind: row.get(3)?,
        required: row.get(4)?,
        placement_policy_revision_id: row.get(5)?,
        selector_json: row.get(6)?,
        validation_gate: row.get(7)?,
        enabled: row.get(8)?,
        resource_version: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn row_to_surface_object(row: &Row) -> Result<SurfaceObjectRecord> {
    Ok(SurfaceObjectRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        cache_id: row.get(2)?,
        object_key: row.get(3)?,
        object_kind: row.get(4)?,
        content_hash: row.get(5)?,
        size: row.get(6)?,
        mutable_publication_id: row.get(7)?,
        lifecycle_state: row.get(8)?,
        tombstoned_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        resource_version: row.get(12)?,
    })
}

fn row_to_topology_plan(row: &Row) -> Result<TopologyPlanRecord> {
    Ok(TopologyPlanRecord {
        plan_id: row.get(0)?,
        plan_kind: row.get(1)?,
        actor_kind: row.get(2)?,
        actor_id: row.get(3)?,
        actor_label: row.get(4)?,
        scope: row.get(5)?,
        input_versions_json: row.get(6)?,
        effects_json: row.get(7)?,
        warnings_json: row.get(8)?,
        confirmation_hash: row.get(9)?,
        request_idempotency_key: row.get(10)?,
        request_digest: row.get(11)?,
        apply_idempotency_key: row.get(12)?,
        apply_result_json: row.get(13)?,
        created_at: row.get(14)?,
        expires_at: row.get(15)?,
        applied_at: row.get(16)?,
    })
}

fn row_to_topology_operation(row: &Row) -> Result<TopologyOperationRecord> {
    Ok(TopologyOperationRecord {
        operation_id: row.get(0)?,
        operation_kind: row.get(1)?,
        authorization_scope_key: row.get(2)?,
        control_permission: row.get(3)?,
        primary_target_kind: row.get(4)?,
        primary_target_stable_id: row.get(5)?,
        primary_target_generation_key: row.get(6)?,
        primary_target_configuration_digest: row.get(7)?,
        state: row.get(8)?,
        progress_current: row.get(9)?,
        progress_total: row.get(10)?,
        detail_json: row.get(11)?,
        error: row.get(12)?,
        created_at: row.get(13)?,
        started_at: row.get(14)?,
        finished_at: row.get(15)?,
        resource_version: row.get(16)?,
    })
}

fn row_to_idp_config(row: &Row) -> Result<IdpConfigRecord> {
    Ok(IdpConfigRecord {
        org_id: row.get(0)?,
        issuer: row.get(1)?,
        authorization_endpoint: row.get(2)?,
        token_endpoint: row.get(3)?,
        jwks_uri: row.get(4)?,
        client_id: row.get(5)?,
        client_secret_enc: row.get(6)?,
        scopes: row.get(7)?,
        groups_claim: row.get(8)?,
        role_map_json: row.get(9)?,
        allow_jit: row.get(10)?,
        enforce_sso: row.get(11)?,
        default_role: row.get(12)?,
        resource_version: row.get(13)?,
        incarnation_id: row.get(14)?,
        mutation_plan_id: row.get(15)?,
    })
}

/// The host portion of an issuer URL, for synthesizing a JIT pseudo-email
/// when the IdP supplies no address. Falls back to the raw issuer string.
fn issuer_host(issuer: &str) -> String {
    url::Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| issuer.replace(['/', ':'], "."))
}

/// The `change_requests` columns, in the order [`row_to_changeset`] reads.
const CHANGESET_COLUMNS: &str = "change_id, actor_kind, actor_id, actor_label, scope, status, \
     summary, created_at, applied_at, reverted_by_change_id, git_ref, git_commit, \
     title, body, closed_at";

fn row_to_changeset(row: &Row) -> Result<ChangesetRow> {
    Ok(ChangesetRow {
        change_id: row.get(0)?,
        actor_kind: row.get(1)?,
        actor_id: row.get(2)?,
        actor_label: row.get(3)?,
        scope: row.get(4)?,
        status: row.get(5)?,
        summary: row.get(6)?,
        created_at: row.get(7)?,
        applied_at: row.get(8)?,
        reverted_by_change_id: row.get(9)?,
        git_ref: row.get(10)?,
        git_commit: row.get(11)?,
        title: row.get(12)?,
        body: row.get(13)?,
        closed_at: row.get(14)?,
    })
}

fn row_to_oidc_flow(row: &Row) -> Result<OidcFlowRecord> {
    Ok(OidcFlowRecord {
        state: row.get(0)?,
        org_id: row.get(1)?,
        nonce: row.get(2)?,
        code_verifier: row.get(3)?,
        redirect_after: row.get(4)?,
        expires_at: row.get(5)?,
    })
}

fn row_to_webauthn_challenge(row: &Row) -> Result<WebauthnChallengeRecord> {
    Ok(WebauthnChallengeRecord {
        challenge: row.get(0)?,
        user_id: row.get(1)?,
        kind: row.get(2)?,
        expires_at: row.get(3)?,
    })
}

fn row_to_webauthn_credential(row: &Row) -> Result<WebauthnCredentialRecord> {
    Ok(WebauthnCredentialRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        credential_id: row.get(2)?,
        public_key: row.get(3)?,
        sign_count: row.get(4)?,
        transports: row.get(5)?,
        label: row.get(6)?,
        created_at: row.get(7)?,
        last_used_at: row.get(8)?,
    })
}

fn row_to_org(row: &Row) -> Result<OrgRecord> {
    Ok(OrgRecord {
        id: row.get(0)?,
        stable_id: row.get(1)?,
        slug: row.get(2)?,
        name: row.get(3)?,
        created_at: row.get(4)?,
        resource_version: row.get(5)?,
        updated_at: row.get::<Option<i64>>(6)?.unwrap_or(row.get(4)?),
    })
}

fn row_to_binding(row: &Row) -> Result<BindingRecord> {
    Ok(BindingRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        is_instance_default: row.get(4)?,
        stable_id: row.get(5)?,
        owner_scope_key: row.get(6)?,
        local_root_path: row.get(7)?,
        object_bucket: row.get(8)?,
        object_prefix: row.get(9)?,
        endpoint_scheme: row.get(10)?,
        endpoint_host_kind: row.get(11)?,
        endpoint_host_bytes: row.get(12)?,
        endpoint_port: row.get(13)?,
        signing_region: row.get(14)?,
        access_mode: row.get(15)?,
        resource_version: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

fn row_to_binding_read_detail(row: &Row) -> Result<BindingReadDetail> {
    Ok(BindingReadDetail {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        is_instance_default: row.get(4)?,
        stable_id: row.get(5)?,
        owner_scope_key: row.get(6)?,
        resource_version: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn row_to_binding_read_summary(row: &Row) -> Result<BindingReadSummary> {
    Ok(BindingReadSummary {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        is_instance_default: row.get(4)?,
        stable_id: row.get(5)?,
    })
}

/// Builds a managed registry's canonical slug from its coordinates.
///
/// `"{org}/{project_path}/{name}"`, collapsing to `"{org}/{name}"` when
/// `project_path` is empty. The `project_path` is normalized of leading
/// and trailing slashes so `"infra/"` and `"/infra"` build identically.
fn canonical_slug(org_slug: &str, project_path: &str, name: &str) -> String {
    let project_path = project_path.trim_matches('/');
    if project_path.is_empty() {
        format!("{org_slug}/{name}")
    } else {
        format!("{org_slug}/{project_path}/{name}")
    }
}

fn unix_now() -> i64 {
    aos_hub_model::clock::now_unix_secs()
}

fn store_hash_component(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.split('-').next().unwrap_or(base).to_string()
}

fn oci_release_root_statements(
    registry_id: i64,
    release: &ReleaseArtifactSnapshot,
    root: &ContainerReleaseRootSnapshot,
    placement_id: i64,
    created_at: i64,
) -> Result<Vec<CheckedStatement>> {
    let repository = aos_oci_types::RepositoryName::parse(&root.repository)
        .context("signed container release repository is malformed")?;
    anyhow::ensure!(
        root.container_name == repository.as_str(),
        "signed container name does not match its OCI repository"
    );
    let index_digest = aos_oci_types::Sha256Digest::parse(&root.index_digest)
        .context("signed container release index digest is malformed")?;
    let media_type = aos_oci_types::MediaType::parse(&root.index_media_type)
        .context("signed container release index media type is malformed")?;
    anyhow::ensure!(
        media_type == aos_oci_types::MediaType::OciImageIndex,
        "signed container release root is not an OCI image index"
    );
    let index_size = i64::try_from(root.index_size)
        .context("signed container release index size exceeds int64")?;
    anyhow::ensure!(index_size > 0, "signed container release index is empty");
    anyhow::ensure!(
        root.catalog_digest.len() == 64
            && root
                .catalog_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "signed container release catalog digest is not lowercase SHA-256"
    );
    validate_container_release_descriptor_snapshot(root, placement_id)?;

    let mut statements = oci_release_placement_fence_statements(root, registry_id, placement_id)?;
    statements.push(
        Statement::new(
            "INSERT INTO oci_release_roots
           (registry_id, release_id, release_tag, repository_id, container_name,
            index_digest, source_commit, verified_tag_oid, catalog_digest,
            created_at)
         SELECT ?1, rel.id, rel.semver, repository.id, ?4, ?5,
                rel.commit_oid, rel.tag_oid, ?9, ?10
         FROM releases rel
         JOIN oci_repositories repository
           ON repository.registry_id = rel.registry_id
          AND repository.name = ?3 AND repository.lifecycle_state = 'active'
         JOIN oci_repository_objects link
           ON link.repository_id = repository.id
          AND link.registry_id = repository.registry_id
          AND link.digest = ?5 AND link.object_kind = 'manifest'
         JOIN oci_manifests manifest
           ON manifest.registry_id = link.registry_id
          AND manifest.digest = link.digest
          AND manifest.media_type = ?6 AND manifest.byte_size = ?7
         JOIN oci_blobs blob
           ON blob.registry_id = link.registry_id AND blob.digest = link.digest
          AND link.media_type = ?6 AND blob.byte_size = ?7
          AND blob.lifecycle_state = 'active'
         JOIN surface_objects object
           ON object.id = blob.surface_object_id
          AND object.registry_id = blob.registry_id
          AND object.object_kind = 'immutable'
          AND object.lifecycle_state = 'active'
          AND object.content_hash = ?12 AND object.size = ?7
         JOIN object_placements presence
           ON presence.surface_object_id = object.id
          AND presence.registry_id = object.registry_id
          AND presence.placement_id = ?13
          AND presence.state = 'present'
          AND presence.observed_hash = ?12
          AND presence.observed_size = ?7
          AND presence.etag IS NOT NULL
          AND presence.catalog_object_resource_version = object.resource_version
         WHERE rel.registry_id = ?1 AND rel.semver = ?2
           AND rel.commit_oid = ?8 AND rel.tag_oid = ?11",
            vals![
                registry_id,
                release.release_tag,
                repository.as_str(),
                root.container_name,
                index_digest.to_string(),
                media_type.as_str(),
                index_size,
                release.source_commit,
                root.catalog_digest,
                created_at,
                release.verified_tag_oid,
                index_digest.encoded(),
                placement_id
            ]
            .to_vec(),
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            "INSERT INTO oci_release_provenance
               (registry_id, repository_id, root_digest, package_name,
                release_tag, channel_name, signed_release_root,
                catalog_digest, verification, verified_at)
             SELECT ?1, repository.id, ?3, ?4, ?5, NULL, ?6, ?7,
                    'verified', ?8
             FROM oci_repositories repository
             WHERE repository.registry_id = ?1 AND repository.name = ?2
               AND repository.lifecycle_state = 'active'",
            vals![
                registry_id,
                repository.as_str(),
                index_digest.to_string(),
                root.package_name,
                release.release_tag,
                release.verified_tag_oid,
                format!("sha256:{}", root.catalog_digest),
                created_at
            ]
            .to_vec(),
        )
        .expecting(1),
    );
    for member in &root.closure_members {
        let layer_digest = aos_oci_types::Sha256Digest::parse(&member.layer_digest)
            .context("signed closure member layer digest is malformed")?;
        let nar_size = i64::try_from(member.nar_size)
            .context("signed closure member NAR size exceeds int64")?;
        statements.push(
            Statement::new(
                "INSERT INTO oci_release_closure_members
                   (registry_id, repository_id, root_digest, release_tag,
                    store_path, nar_hash, nar_size, layer_digest, is_direct)
                 SELECT ?1, repository.id, ?3, ?4, ?5, ?6, ?7, ?8, ?9
                 FROM oci_repositories repository
                 WHERE repository.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'",
                vals![
                    registry_id,
                    repository.as_str(),
                    index_digest.to_string(),
                    release.release_tag,
                    member.store_path,
                    member.nar_hash,
                    nar_size,
                    layer_digest.to_string(),
                    member.direct
                ]
                .to_vec(),
            )
            .expecting(1),
        );
    }
    for evidence in &root.evidence {
        anyhow::ensure!(
            matches!(
                evidence.kind.as_str(),
                "closure"
                    | "abilities"
                    | "sbom"
                    | "source"
                    | "license"
                    | "provenance"
                    | "signature"
            ),
            "signed container evidence kind is invalid"
        );
        let digest = aos_oci_types::Sha256Digest::parse(&evidence.digest)
            .context("signed container evidence digest is malformed")?;
        let media_type = aos_oci_types::MediaType::parse(&evidence.media_type)
            .context("signed container evidence media type is malformed")?;
        let referrer_digest = aos_oci_types::Sha256Digest::parse(&evidence.referrer_digest)
            .context("signed container evidence referrer digest is malformed")?;
        statements.push(
            Statement::new(
                "INSERT INTO oci_release_evidence
                   (registry_id, repository_id, root_digest, release_tag,
                    evidence_kind, digest, media_type, verification,
                    referrer_digest)
                 SELECT ?1, repository.id, ?3, ?4, ?5, ?6, ?7, 'verified', ?8
                 FROM oci_repositories repository
                 WHERE repository.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'",
                vals![
                    registry_id,
                    repository.as_str(),
                    index_digest.to_string(),
                    release.release_tag,
                    evidence.kind,
                    digest.to_string(),
                    media_type.as_str(),
                    referrer_digest.to_string()
                ]
                .to_vec(),
            )
            .expecting(1),
        );
    }
    for layer in &root.layers {
        let digest = aos_oci_types::Sha256Digest::parse(&layer.digest)
            .context("signed closure layer digest is malformed")?;
        let diff_id = aos_oci_types::Sha256Digest::parse(&layer.diff_id)
            .context("signed closure layer DiffID is malformed")?;
        let compressed_size = i64::try_from(layer.compressed_size)
            .context("signed closure layer compressed size exceeds int64")?;
        let uncompressed_size = i64::try_from(layer.uncompressed_size)
            .context("signed closure layer uncompressed size exceeds int64")?;
        statements.push(
            Statement::new(
                "UPDATE oci_release_layers
                 SET unpacked_byte_size = ?5, diff_id = ?6,
                     closure_group = ?7, verified_at = ?8
                 WHERE registry_id = ?1 AND root_digest = ?3 AND digest = ?4
                   AND compressed_byte_size = ?9
                   AND repository_id = (SELECT id FROM oci_repositories
                     WHERE registry_id = ?1 AND name = ?2
                       AND lifecycle_state = 'active')",
                vals![
                    registry_id,
                    repository.as_str(),
                    index_digest.to_string(),
                    digest.to_string(),
                    uncompressed_size,
                    diff_id.to_string(),
                    layer.name,
                    created_at,
                    compressed_size
                ]
                .to_vec(),
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_repositories SET updated_at = updated_at
                 WHERE registry_id = ?1 AND name = ?2
                   AND lifecycle_state = 'active'
                   AND EXISTS (SELECT 1 FROM oci_release_layers projected
                     WHERE projected.repository_id = oci_repositories.id
                       AND projected.root_digest = ?3 AND projected.digest = ?4
                       AND projected.compressed_byte_size = ?5
                       AND projected.unpacked_byte_size = ?6
                       AND projected.diff_id = ?7
                       AND projected.closure_group = ?8)",
                vals![
                    registry_id,
                    repository.as_str(),
                    index_digest.to_string(),
                    digest.to_string(),
                    compressed_size,
                    uncompressed_size,
                    diff_id.to_string(),
                    layer.name
                ]
                .to_vec(),
            )
            .expecting(1),
        );
    }
    statements.push(
        Statement::new(
            "UPDATE oci_image_config_projections
             SET compressed_byte_size = (SELECT COALESCE(SUM(compressed_byte_size), 0)
                   FROM oci_release_layers layer
                   WHERE layer.repository_id = oci_image_config_projections.repository_id
                     AND layer.root_digest = oci_image_config_projections.root_digest
                     AND layer.manifest_digest = oci_image_config_projections.manifest_digest)
                   + (SELECT byte_size FROM oci_blobs config
                       WHERE config.registry_id = oci_image_config_projections.registry_id
                         AND config.digest = oci_image_config_projections.config_digest),
                 unpacked_byte_size = (SELECT COALESCE(SUM(unpacked_byte_size), 0)
                   FROM oci_release_layers layer
                   WHERE layer.repository_id = oci_image_config_projections.repository_id
                     AND layer.root_digest = oci_image_config_projections.root_digest
                     AND layer.manifest_digest = oci_image_config_projections.manifest_digest),
                 verified_at = ?4
             WHERE registry_id = ?1 AND root_digest = ?3
               AND repository_id = (SELECT id FROM oci_repositories
                 WHERE registry_id = ?1 AND name = ?2 AND lifecycle_state = 'active')",
            vals![
                registry_id,
                repository.as_str(),
                index_digest.to_string(),
                created_at
            ]
            .to_vec(),
        )
        .unchecked(),
    );
    for descriptor in &root.required_descriptors {
        statements.push(oci_release_descriptor_placement_guard(
            registry_id,
            repository.as_str(),
            descriptor,
        )?);
    }
    Ok(statements)
}

fn oci_release_placement_fence_statements(
    root: &ContainerReleaseRootSnapshot,
    registry_id: i64,
    placement_id: i64,
) -> Result<Vec<CheckedStatement>> {
    let descriptor = root
        .required_descriptors
        .first()
        .context("signed container release has no required descriptor placement")?;
    Ok(vec![
        Statement::new(
            "UPDATE surface_placements SET updated_at = updated_at
             WHERE id = ?1 AND registry_id = ?2 AND resource_version = ?3",
            vals![
                placement_id,
                registry_id,
                descriptor.placement_resource_version
            ]
            .to_vec(),
        )
        .expecting(1),
        Statement::new(
            "UPDATE surface_placement_observations SET observed_at = observed_at
             WHERE placement_id = ?1 AND observation_version = ?2
               AND state = 'ready' AND completeness = 'complete'",
            vals![placement_id, descriptor.placement_observation_version].to_vec(),
        )
        .expecting(1),
    ])
}

fn validate_container_release_descriptor_snapshot(
    root: &ContainerReleaseRootSnapshot,
    placement_id: i64,
) -> Result<()> {
    let index_digest = aos_oci_types::Sha256Digest::parse(&root.index_digest)
        .context("signed container release index digest is malformed")?;
    let mut digests = std::collections::BTreeSet::new();
    let mut roles = std::collections::BTreeMap::<ContainerReleaseDescriptorRole, usize>::new();
    let mut placement_fence = None;

    for descriptor in &root.required_descriptors {
        let digest = aos_oci_types::Sha256Digest::parse(&descriptor.digest)
            .context("signed container descriptor digest is malformed")?;
        let media_type = aos_oci_types::MediaType::parse(&descriptor.media_type)
            .context("signed container descriptor media type is malformed")?;
        anyhow::ensure!(
            descriptor.byte_size > 0,
            "signed container descriptor is empty"
        );
        anyhow::ensure!(
            descriptor.surface_object_id > 0
                && descriptor.object_resource_version > 0
                && descriptor.placement_resource_version > 0
                && descriptor.placement_observation_version > 0
                && descriptor.observed_inventory_generation > 0
                && descriptor.observed_at > 0
                && !descriptor.strong_etag.is_empty(),
            "signed container descriptor placement fence is malformed"
        );
        anyhow::ensure!(
            descriptor.placement_id == placement_id,
            "signed container descriptor was observed on a different placement"
        );
        anyhow::ensure!(
            digests.insert(digest),
            "signed container descriptor snapshot repeats digest {digest}"
        );
        *roles.entry(descriptor.role).or_default() += 1;

        let fence = (
            descriptor.placement_id,
            descriptor.placement_resource_version,
            descriptor.placement_observation_version,
        );
        if let Some(expected) = placement_fence {
            anyhow::ensure!(
                fence == expected,
                "signed container descriptor observations cross a placement revision"
            );
        } else {
            placement_fence = Some(fence);
        }

        match descriptor.role {
            ContainerReleaseDescriptorRole::Index => anyhow::ensure!(
                digest == index_digest
                    && media_type == aos_oci_types::MediaType::OciImageIndex
                    && descriptor.byte_size == root.index_size,
                "signed container index placement conflicts with its release root"
            ),
            ContainerReleaseDescriptorRole::PlatformManifest
            | ContainerReleaseDescriptorRole::NixClosure
            | ContainerReleaseDescriptorRole::Abilities
            | ContainerReleaseDescriptorRole::Sbom
            | ContainerReleaseDescriptorRole::Source
            | ContainerReleaseDescriptorRole::License
            | ContainerReleaseDescriptorRole::Provenance
            | ContainerReleaseDescriptorRole::Signature => anyhow::ensure!(
                media_type == aos_oci_types::MediaType::OciImageManifest,
                "signed container required descriptor is not an OCI image manifest"
            ),
        }
    }

    anyhow::ensure!(
        roles.get(&ContainerReleaseDescriptorRole::Index) == Some(&1),
        "signed container descriptor snapshot requires exactly one index"
    );
    let platform_count = roles
        .get(&ContainerReleaseDescriptorRole::PlatformManifest)
        .copied()
        .unwrap_or_default();
    anyhow::ensure!(
        (1..=aos_oci_types::limits::MAX_PLATFORMS_PER_INDEX).contains(&platform_count),
        "signed container descriptor snapshot has an invalid platform count"
    );
    for role in [
        ContainerReleaseDescriptorRole::NixClosure,
        ContainerReleaseDescriptorRole::Sbom,
        ContainerReleaseDescriptorRole::Source,
        ContainerReleaseDescriptorRole::License,
        ContainerReleaseDescriptorRole::Provenance,
        ContainerReleaseDescriptorRole::Signature,
    ] {
        anyhow::ensure!(
            roles.get(&role) == Some(&1),
            "signed container descriptor snapshot has an incomplete evidence set"
        );
    }
    anyhow::ensure!(
        roles
            .get(&ContainerReleaseDescriptorRole::Abilities)
            .copied()
            .unwrap_or_default()
            <= 1,
        "signed container descriptor snapshot repeats static ability evidence"
    );
    Ok(())
}

fn oci_release_descriptor_placement_guard(
    registry_id: i64,
    repository: &str,
    descriptor: &VerifiedContainerReleaseDescriptor,
) -> Result<CheckedStatement> {
    let digest = aos_oci_types::Sha256Digest::parse(&descriptor.digest)
        .context("signed container descriptor digest is malformed")?;
    let media_type = aos_oci_types::MediaType::parse(&descriptor.media_type)
        .context("signed container descriptor media type is malformed")?;
    let byte_size = i64::try_from(descriptor.byte_size)
        .context("signed container descriptor size exceeds int64")?;

    Ok(Statement::new(
        "UPDATE object_placements SET observed_at = observed_at
         WHERE surface_object_id = ?1 AND placement_id = ?2
           AND registry_id = ?3 AND state = 'present'
           AND observed_hash = ?4 AND observed_size = ?5
           AND etag = ?6
           AND observed_inventory_generation = ?7
           AND observed_at = ?8
           AND catalog_object_resource_version = ?9
           AND EXISTS (
             SELECT 1
             FROM oci_repositories repository
             JOIN oci_repository_objects link
               ON link.repository_id = repository.id
              AND link.registry_id = repository.registry_id
             JOIN oci_manifests manifest
               ON manifest.registry_id = link.registry_id
              AND manifest.digest = link.digest
             JOIN oci_blobs blob
               ON blob.registry_id = link.registry_id
              AND blob.digest = link.digest
             JOIN surface_objects object
               ON object.id = blob.surface_object_id
              AND object.registry_id = blob.registry_id
             WHERE repository.registry_id = ?3
               AND repository.name = ?10
               AND repository.lifecycle_state = 'active'
               AND link.digest = ?11 AND link.object_kind = 'manifest'
               AND manifest.media_type = ?12 AND manifest.byte_size = ?5
               AND link.media_type = ?12 AND blob.byte_size = ?5
               AND blob.lifecycle_state = 'active'
               AND object.id = ?1 AND object.object_kind = 'immutable'
               AND object.lifecycle_state = 'active'
               AND object.content_hash = ?4 AND object.size = ?5
               AND object.resource_version = ?9)",
        vals![
            descriptor.surface_object_id,
            descriptor.placement_id,
            registry_id,
            digest.encoded(),
            byte_size,
            descriptor.strong_etag,
            descriptor.observed_inventory_generation,
            descriptor.observed_at,
            descriptor.object_resource_version,
            repository,
            digest.to_string(),
            media_type.as_str()
        ]
        .to_vec(),
    )
    .expecting(1))
}

/// Computes the immutable identity of every retention-relevant index row.
fn index_snapshot_digest(snapshot: &IndexSnapshot) -> Result<String> {
    let releases = snapshot
        .releases
        .iter()
        .map(|release| {
            serde_json::json!({
                "semver": release.semver,
                "tag_oid": release.tag_oid,
                "commit_oid": release.commit_oid,
                "signer": release.signer,
                "tagged_at": release.tagged_at,
                "pack_present": release.pack_present,
            })
        })
        .collect::<Vec<_>>();
    let release_artifacts = snapshot
        .release_artifact_snapshots
        .iter()
        .map(|release| {
            serde_json::json!({
                "release_tag": release.release_tag,
                "source_commit": release.source_commit,
                "verified_tag_oid": release.verified_tag_oid,
                "manifest_digest": release.manifest_digest,
                "artifacts": release.artifacts,
                "container_release": release.container_release.as_ref().map(|root| serde_json::json!({
                    "repository": root.repository,
                    "container_name": root.container_name,
                    "index_digest": root.index_digest,
                    "index_media_type": root.index_media_type,
                    "index_size": root.index_size,
                    "catalog_digest": root.catalog_digest,
                    "package_name": root.package_name,
                    "closure_members": root.closure_members,
                    "layers": root.layers,
                    "evidence": root.evidence,
                    "required_descriptors": root.required_descriptors.iter().map(|descriptor| serde_json::json!({
                        "role": descriptor.role.as_str(),
                        "digest": descriptor.digest,
                        "media_type": descriptor.media_type,
                        "byte_size": descriptor.byte_size,
                        "surface_object_id": descriptor.surface_object_id,
                        "object_resource_version": descriptor.object_resource_version,
                        "placement_id": descriptor.placement_id,
                        "placement_resource_version": descriptor.placement_resource_version,
                        "placement_observation_version": descriptor.placement_observation_version,
                        "observed_inventory_generation": descriptor.observed_inventory_generation,
                        "observed_at": descriptor.observed_at,
                        "strong_etag": descriptor.strong_etag,
                    })).collect::<Vec<_>>(),
                })),
            })
        })
        .collect::<Vec<_>>();
    let release_images = snapshot
        .release_images
        .iter()
        .map(|catalog| {
            let images = catalog
                .images
                .iter()
                .map(|image| {
                    serde_json::json!({
                        "package": image.package,
                        "release": image.release,
                        "platform": image.platform,
                        "format": image.format,
                        "delivery": image.delivery,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "release_tag": catalog.release_tag,
                "source_commit": catalog.source_commit,
                "verified_tag_oid": catalog.verified_tag_oid,
                "catalog_digest": catalog.catalog_digest,
                "images": images,
            })
        })
        .collect::<Vec<_>>();
    let channels = snapshot
        .channels
        .iter()
        .map(|channel| {
            serde_json::json!({
                "name": channel.name,
                "frontier": channel.frontier,
                "partitions": channel.partitions,
            })
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "public_catalog_commit": snapshot.public_catalog_commit,
        "public_catalog_release": snapshot.public_catalog_release,
        "commit": snapshot.commit,
        "name": snapshot.name,
        "description": snapshot.description,
        "readme": snapshot.readme,
        "caches": snapshot.caches,
        "cache_stack": snapshot.cache_stack,
        "roster": snapshot.roster,
        "packages": format!("{:?}", snapshot.packages),
        "releases": releases,
        "release_artifacts": release_artifacts,
        "release_images": release_images,
        "channels": channels,
        "refs_digest": snapshot.refs_digest,
    });
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        &document,
    )?)))
}

/// Extends an index identity with one complete incremental channel snapshot.
fn incremental_index_digest(previous: &str, channels: &[ChannelSummary]) -> Result<String> {
    let channels = channels
        .iter()
        .map(|channel| {
            serde_json::json!({
                "name": channel.name,
                "frontier": channel.frontier,
                "partitions": channel.partitions,
            })
        })
        .collect::<Vec<_>>();
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        &serde_json::json!({"previous": previous, "channels": channels}),
    )?)))
}

/// Strip C0 control characters (except tab) from a string destined for the
/// audit log or a structured log field.
///
/// Audit `actor_label`/`scope`/`detail` and similar fields can carry
/// caller-controlled text (token labels, package names, OIDC subjects, fetch
/// URLs). A `CR`/`LF` or other C0 control embedded in that text could forge or
/// corrupt a log line (log injection) or store a value that misleads an
/// operator reading the audit feed. The WebUI HTML-escapes on render, so this
/// is *not* an XSS guard — it protects log/stored integrity. `\t` (0x09) is
/// preserved as benign whitespace; every other character below `0x20` and the
/// `DEL` (0x7f) control are replaced with a single space, so the field's length
/// and word boundaries are preserved while line and field structure cannot be
/// broken.
fn sanitize_log_text(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == '\t' {
                c
            } else if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

mod queries;

#[cfg(all(not(target_arch = "wasm32"), any(test, feature = "test-fixtures")))]
pub mod fixtures;

mod records;
pub use records::*;
