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
//!   `storage_bindings` table (with the `registries.storage_binding_id`
//!   and `registries.prefix` columns that bind a managed registry's
//!   surface to a binding root): facts that exist nowhere on the surface
//!   (slug, source URL, trust anchors, the anti-rollback floor each
//!   channel has reached, the org → project → registry hierarchy and who
//!   may act on it, where each managed registry's bytes live, plus the
//!   credentials principals authenticate with), and the phase-3a
//!   configuration-history tables `audit_log`, `config_changesets`, and
//!   `config_revisions` (the append-only record of every SQL-backed
//!   mutation, who performed it, and the before/after object snapshots):
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
//!   `channel_partitions`, `releases`, `key_rosters`, `caches`: derived
//!   from the verified surface by the indexer and safely droppable; a
//!   re-index reconstructs it.
//! - **Operational history** — `validation_runs` and
//!   `validation_findings`: records of past consistency-validation runs.
//!   Not derived from the surface, but droppable without losing
//!   registration state.
//!
//! Migrations are ordered SQL statements tracked in `schema_version`,
//!  applied at open. The connection is wrapped in a `Mutex` following the
//! pattern of `aos-server`'s token store; hub queries are short and
//! page-shaped, so a single writer is ample for phase 1.
//!
//! # Tenancy hierarchy (v3)
//!
//! Phase 2a adds the multi-tenant system of record. A **project** locates
//! itself inside its org with a *materialized path* — the slash-joined
//! chain of ancestor project names, with `''` for a project that sits
//! directly under the org root. A registry then lives at
//! `{org}/{project_path}/{registry_slug}`. Scopes (the strings stored in
//! `memberships.scope` / `invitations.scope`) are prefixes of that path:
//!
//! ```text
//! orgs                acme
//! projects            (org acme, path "")              -> scope "acme"
//!                     (org acme, path "infra")         -> scope "acme/infra"
//!                     (org acme, path "infra/prod")    -> scope "acme/infra/prod"
//! registries          slug "cdn", project_path "infra/prod", org acme
//!                                                      -> scope "acme/infra/prod/cdn"
//!
//! memberships.scope   ""                  instance root (every org/project)
//!                     "acme"              the whole org
//!                     "acme/infra"        a project subtree
//!                     "acme/infra/prod/cdn"   one registry
//! ```
//!
//! Roles inherit downward: a grant at `acme` covers every project and
//! registry beneath it. The pure containment/decision logic lives in
//! [`crate::domain::iam`]; this module only stores and lists the rows.
//!
//! Existing phase-1 `registries` rows acquire `org_id IS NULL`,
//! `project_path = ''`, and `visibility = 'public'` — the RFC's
//! instance-level *unowned public registry* that phase 2 adopts unchanged.
//!
//! # Storage bindings (v5)
//!
//! Phase 2c adds the storage system of record (RFC-0004 "Storage:
//! `StorageBinding` and shared buckets"). A registry never owns a bucket
//! directly; it references a **storage binding** plus a sub-prefix, and
//! its on-disk surface lives at `{binding.root}/{prefix}`:
//!
//! ```text
//! storage_bindings   id  org_id  name      kind        root
//!                    1   acme    primary   local_fs    /srv/aos-hub
//!
//! registries (managed)  slug "acme/infra/prod/cdn"
//!                       storage_binding_id = 1
//!                       prefix = "infra/prod/cdn"
//!                       surface root -> /srv/aos-hub/infra/prod/cdn
//! ```
//!
//! `kind` is the binding backend; only `local_fs` (a filesystem path in
//! `root`) is implemented in this phase — S3/R2 kinds are later phases,
//! modeled by the column but rejected by [`Database::create_storage_binding`].
//!
//! Phase-1 `file://` registries keep `storage_binding_id NULL` and
//! `prefix = ''`; their `source_url` path remains the surface, served
//! exactly as before. [`Database::registry_surface_root`] resolves the
//! on-disk surface directory for either shape, with the binding taking
//! precedence over `source_url`.
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
//! config (visibility, memberships, tokens metadata, storage bindings,
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
//! config_changesets change_id c1a2…  actor_label alice@acme.com
//!                   scope "acme/infra/prod/cdn"  status applied
//!                   summary "set cdn visibility to private"
//!                   created_at 1730000000  applied_at 1730000000
//!                   reverted_by_change_id NULL
//!
//! config_revisions  id 1  change_id c1a2…  object_type registry
//!                   object_id "acme/infra/prod/cdn"  op update  seq 0
//!                   old_json '{"visibility":"public"}'
//!                   new_json '{"visibility":"private"}'
//! ```
//!
//! `change_id` is a UUID v4 (the crate's existing `uuid` dependency); rows
//! order by `created_at` rather than by a sortable id, so no new dependency
//! (a ULID generator) is taken on. The engine that drives these tables —
//! drafting, staging, semantic-diffing, applying, and reverting — lives in
//! [`crate::config`]; this module only stores and lists the rows.
//!
//! ## Security-object revert exemptions
//!
//! Reverting a security-sensitive object never resurrects a live
//! credential or grant (RFC-0004): a `token` revert renders as an
//! "issue replacement" note (a no-op create), and a `membership` delete
//! reverts to an *invitation* rather than a silent re-admit. These are
//! encoded as operation/notes by [`crate::config::revert`].

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// Grace period, in seconds, during which a rotated token's old secret
/// keeps validating after its `revoked_at` stamp (RFC-0004 fixes the
/// `aos-server` bug where this window was recorded but not honored).
const ROTATION_GRACE_SECS: i64 = 3600;

/// Ordered schema migrations; index = version - 1.
const MIGRATIONS: &[&str] = &[
    // v1: initial schema.
    "
    CREATE TABLE registries (
        id          INTEGER PRIMARY KEY,
        slug        TEXT NOT NULL UNIQUE,
        source_url  TEXT NOT NULL,
        trust_keys  TEXT NOT NULL DEFAULT '[]',  -- JSON array of name:Ed25519:b64
        require_signatures INTEGER NOT NULL DEFAULT 1,
        created_at  INTEGER NOT NULL
    );
    CREATE TABLE registry_index (
        registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
        state       TEXT NOT NULL,                -- fresh|indexing|stale|failed
        error       TEXT,
        last_indexed_commit TEXT,
        name        TEXT,
        description TEXT,
        indexed_at  INTEGER
    );
    CREATE TABLE packages (
        id          INTEGER PRIMARY KEY,
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        description TEXT NOT NULL,
        homepage    TEXT,
        license     TEXT NOT NULL,
        maintainer  TEXT NOT NULL,
        sysroot     INTEGER NOT NULL,
        UNIQUE (registry_id, name)
    );
    CREATE TABLE package_versions (
        id          INTEGER PRIMARY KEY,
        package_id  INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
        version     TEXT NOT NULL,
        previous    TEXT,
        UNIQUE (package_id, version)
    );
    CREATE TABLE version_platforms (
        id          INTEGER PRIMARY KEY,
        version_id  INTEGER NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
        platform    TEXT NOT NULL,
        store_path  TEXT NOT NULL,
        nar_hash    TEXT NOT NULL,
        nar_size    INTEGER NOT NULL,
        closure_size INTEGER NOT NULL,
        refs        TEXT NOT NULL,                -- JSON array of store hashes
        images      TEXT NOT NULL,                -- JSON array of {format,store_path,nar_hash,nar_size}
        UNIQUE (version_id, platform)
    );
    CREATE TABLE channels (
        id          INTEGER PRIMARY KEY,
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        frontier    TEXT,
        UNIQUE (registry_id, name)
    );
    CREATE TABLE channel_partitions (
        channel_id  INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
        bucket      INTEGER NOT NULL,
        release     TEXT NOT NULL,
        PRIMARY KEY (channel_id, bucket)
    );
    CREATE TABLE releases (
        id          INTEGER PRIMARY KEY,
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        semver      TEXT NOT NULL,
        tag_oid     TEXT NOT NULL,
        commit_oid  TEXT NOT NULL,
        signer      TEXT,
        tagged_at   INTEGER,
        UNIQUE (registry_id, semver)
    );
    CREATE TABLE key_rosters (
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        key_id      TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        status      TEXT NOT NULL,                -- active|revoked
        PRIMARY KEY (registry_id, key_id)
    );
    CREATE TABLE caches (
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        url         TEXT NOT NULL,
        priority    INTEGER NOT NULL
    );
    ",
    // v2: anti-rollback channel floors (system of record), consistency
    // validation history, per-release pack presence, and the refs digest
    // that powers incremental channel refresh.
    "
    CREATE TABLE channel_floors (
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        channel     TEXT NOT NULL,
        floor       TEXT NOT NULL,
        PRIMARY KEY (registry_id, channel)
    );
    CREATE TABLE validation_runs (
        id          INTEGER PRIMARY KEY,
        registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        cache_url   TEXT NOT NULL,
        depth       TEXT NOT NULL,
        checked     INTEGER NOT NULL,
        missing     INTEGER NOT NULL,
        reachable   INTEGER NOT NULL,
        started_at  INTEGER NOT NULL,
        finished_at INTEGER NOT NULL
    );
    CREATE TABLE validation_findings (
        run_id      INTEGER NOT NULL REFERENCES validation_runs(id) ON DELETE CASCADE,
        store_hash  TEXT NOT NULL,
        status      TEXT NOT NULL,
        PRIMARY KEY (run_id, store_hash)
    );
    ALTER TABLE releases ADD COLUMN pack_present INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE registry_index ADD COLUMN refs_digest TEXT;
    ",
    // v3: multi-tenant system of record (RFC-0004 "Tenancy and IAM").
    // Orgs, projects (materialized-path hierarchy), users and their OIDC
    // identities, service accounts, role memberships, and invitations.
    // Existing registries gain ownership columns; phase-1 rows become
    // unowned public registries (org_id NULL).
    "
    CREATE TABLE orgs (
        id          INTEGER PRIMARY KEY,
        slug        TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL,
        created_at  INTEGER NOT NULL
    );
    CREATE TABLE projects (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        path        TEXT NOT NULL,                -- materialized path; '' = org root
        name        TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        UNIQUE (org_id, path)
    );
    CREATE TABLE users (
        id           INTEGER PRIMARY KEY,
        email        TEXT NOT NULL UNIQUE,
        display_name TEXT,
        created_at   INTEGER NOT NULL,
        deleted_at   INTEGER
    );
    CREATE TABLE user_identities (
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        issuer      TEXT NOT NULL,                -- OIDC iss
        subject     TEXT NOT NULL,                -- OIDC sub
        email       TEXT,
        last_login  INTEGER,
        PRIMARY KEY (issuer, subject)
    );
    CREATE TABLE service_accounts (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        UNIQUE (org_id, name)
    );
    CREATE TABLE memberships (
        id             INTEGER PRIMARY KEY,
        principal_kind TEXT NOT NULL,             -- 'user' | 'service_account'
        principal_id   INTEGER NOT NULL,
        scope          TEXT NOT NULL,             -- scope path string
        role           TEXT NOT NULL,             -- one of the five role names
        created_at     INTEGER NOT NULL,
        UNIQUE (principal_kind, principal_id, scope)
    );
    CREATE TABLE invitations (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        email       TEXT NOT NULL,
        scope       TEXT NOT NULL,
        role        TEXT NOT NULL,
        token_hash  TEXT NOT NULL UNIQUE,         -- SHA-256 of the invite secret
        created_at  INTEGER NOT NULL,
        accepted_at INTEGER,
        expires_at  INTEGER NOT NULL
    );
    ALTER TABLE registries ADD COLUMN org_id INTEGER;
    ALTER TABLE registries ADD COLUMN project_path TEXT NOT NULL DEFAULT '';
    ALTER TABLE registries ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public';
    ",
    // v4: authentication system of record (RFC-0004 "Authentication:
    // sessions, tokens, SSO"). Provisioning tokens owned by a principal
    // and scoped to a path-prefix + permission set; human cookie sessions
    // with a sudo `auth_level`; RFC8628 device-authorization codes; and
    // single-use email magic links. Only hashes of every secret are
    // stored — a database leak never yields a usable credential.
    "
    CREATE TABLE tokens (
        id          TEXT PRIMARY KEY,
        hash        TEXT UNIQUE NOT NULL,         -- SHA-256 hex of the secret
        owner_kind  TEXT NOT NULL,                -- 'user' | 'service_account'
        owner_id    INTEGER NOT NULL,
        scope       TEXT NOT NULL,                -- scope-path string
        permissions TEXT NOT NULL,                -- JSON array of permission verbs
        comment     TEXT,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER,
        revoked_at  INTEGER,
        last_used_at INTEGER
    );
    CREATE TABLE sessions (
        id_hash     TEXT PRIMARY KEY,             -- SHA-256 hex of the cookie secret
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at  INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        auth_level  INTEGER NOT NULL DEFAULT 0,   -- 1 = sudo-capable
        last_authenticated_at INTEGER NOT NULL
    );
    CREATE TABLE device_codes (
        device_code_hash TEXT PRIMARY KEY,        -- SHA-256 hex of the device-code secret
        user_code   TEXT UNIQUE NOT NULL,         -- short human-typed code
        scope       TEXT NOT NULL,                -- requested scope-path string
        permissions TEXT NOT NULL,                -- requested permission verbs (JSON array)
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        approved_by_user INTEGER,                 -- approving user id once approved
        denied      INTEGER NOT NULL DEFAULT 0,
        issued_token_id TEXT,                     -- id of the minted token, once approved
        issued_token_secret TEXT                  -- the minted secret, delivered once at poll
    );
    CREATE TABLE magic_links (
        token_hash  TEXT PRIMARY KEY,             -- SHA-256 hex of the link secret
        email       TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        consumed_at INTEGER
    );
    ",
    // v5: storage system of record (RFC-0004 "Storage: StorageBinding and
    // shared buckets"). A binding is a named backend rooted at some
    // location under an org; a managed registry references a binding plus a
    // sub-prefix, so its surface lives at {binding.root}/{prefix}. Only the
    // local_fs kind is implemented this phase (root = filesystem path);
    // S3/R2 kinds are modeled by the column for later phases. Phase-1
    // file:// registries keep storage_binding_id NULL and prefix '' — their
    // source_url path stays the surface.
    "
    CREATE TABLE storage_bindings (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        kind        TEXT NOT NULL,                -- 'local_fs' (S3/R2 later)
        root        TEXT NOT NULL,                -- filesystem path for local_fs
        created_at  INTEGER NOT NULL,
        UNIQUE (org_id, name)
    );
    ALTER TABLE registries ADD COLUMN storage_binding_id INTEGER;
    ALTER TABLE registries ADD COLUMN prefix TEXT NOT NULL DEFAULT '';
    ",
    // v6: split token rotation from hard revocation. `rotated_at` carries
    // the grace window (a rotated secret stays valid briefly so in-flight
    // clients are not cut off); `revoked_at` is an immediate hard cutoff
    // with no grace (a leaked secret denied at once). Before this split,
    // revocation reused the rotation grace and a revoked secret kept
    // minting JWTs for an hour.
    "
    ALTER TABLE tokens ADD COLUMN rotated_at INTEGER;
    ",
    // v7: configuration history (RFC-0004 \"Configuration management\").
    // The append-only audit log plus the SQL-backed change-set/revision
    // log over the SQL system of record (visibility, memberships, tokens
    // metadata, storage bindings, registry config). Rows are appended,
    // never rewritten in place (except the changeset lifecycle stamps:
    // status, applied_at, reverted_by_change_id). change_id is a UUID v4;
    // ordering is by created_at, taking on no new sortable-id dependency.
    "
    CREATE TABLE audit_log (
        id           INTEGER PRIMARY KEY,
        change_id    TEXT,                       -- ties to a changeset (nullable)
        actor_kind   TEXT NOT NULL,              -- user|service_account|key|system
        actor_id     INTEGER,                    -- principal row id, when applicable
        actor_label  TEXT NOT NULL,              -- human string (email, sa:org/name, fpr, system)
        action       TEXT NOT NULL,              -- the mutating verb
        scope        TEXT NOT NULL,              -- scope-path string
        result_commit TEXT,                      -- resulting git commit hash (surface ops)
        result_tag   TEXT,                       -- resulting git tag hash (surface ops)
        detail       TEXT,                       -- free-form (often compact JSON)
        created_at   INTEGER NOT NULL
    );
    CREATE INDEX audit_log_scope_idx ON audit_log (scope, id);
    CREATE INDEX audit_log_change_idx ON audit_log (change_id);
    CREATE TABLE config_changesets (
        change_id    TEXT PRIMARY KEY,           -- UUID v4
        actor_kind   TEXT NOT NULL,
        actor_id     INTEGER,
        actor_label  TEXT NOT NULL,
        scope        TEXT NOT NULL,
        status       TEXT NOT NULL,              -- draft|applied|reverted
        summary      TEXT,
        created_at   INTEGER NOT NULL,
        applied_at   INTEGER,
        reverted_by_change_id TEXT
    );
    CREATE INDEX config_changesets_scope_idx ON config_changesets (scope, created_at);
    CREATE TABLE config_revisions (
        id           INTEGER PRIMARY KEY,
        change_id    TEXT NOT NULL REFERENCES config_changesets(change_id) ON DELETE CASCADE,
        object_type  TEXT NOT NULL,
        object_id    TEXT NOT NULL,
        op           TEXT NOT NULL,              -- create|update|delete
        old_json     TEXT,                       -- full object snapshot before
        new_json     TEXT,                       -- full object snapshot after
        seq          INTEGER NOT NULL
    );
    CREATE INDEX config_revisions_change_idx ON config_revisions (change_id, seq);
    ",
];

/// A registered registry (system-of-record row).
#[derive(Debug, Clone)]
pub struct RegistryRecord {
    /// Database id.
    pub id: i64,
    /// URL path slug the registry is served under.
    ///
    /// For phase-1 unowned registries this is a flat slug (`"cdn"`); for
    /// phase-2 managed registries it is the full canonical path
    /// (`"acme/infra/prod/cdn"`) — see the [module docs](self).
    pub slug: String,
    /// Surface source: `file://` path or `http(s)://` base URL.
    ///
    /// Empty (`""`) for a managed registry, whose surface is located via
    /// its storage binding instead (see [`RegistryRecord::storage_binding_id`]).
    pub source_url: String,
    /// Pinned trust anchors in `name:Ed25519:<base64>` form.
    pub trust_keys: Vec<String>,
    /// Whether indexing fails closed on missing/invalid signatures.
    pub require_signatures: bool,
    /// Owning org id, or `None` for an instance-level unowned registry.
    pub org_id: Option<i64>,
    /// Owning project's materialized path (`""` for an org-root registry).
    pub project_path: String,
    /// Visibility: `public`, `internal`, or `private`.
    pub visibility: String,
    /// Storage binding this managed registry's surface lives under, or
    /// `None` for a phase-1 `file://`/`http` registry.
    pub storage_binding_id: Option<i64>,
    /// Sub-prefix under the binding root (`""` when unbound).
    pub prefix: String,
}

/// A storage binding (system-of-record row): a named backend an org's
/// managed registries place their surfaces under.
///
/// A registry's surface lives at `{root}/{prefix}` (see
/// [`Database::registry_surface_root`]).
#[derive(Debug, Clone)]
pub struct StorageBindingRecord {
    /// Database id.
    pub id: i64,
    /// Owning org id.
    pub org_id: i64,
    /// Binding name, unique within the org.
    pub name: String,
    /// Backend kind; `local_fs` is the only kind implemented this phase.
    pub kind: String,
    /// Backend root: a filesystem path for `local_fs`.
    pub root: String,
    /// Unix time the binding was created.
    pub created_at: i64,
}

/// An organization (tenant boundary) system-of-record row.
#[derive(Debug, Clone)]
pub struct OrgRecord {
    /// Database id.
    pub id: i64,
    /// URL-safe unique slug the org is addressed by.
    pub slug: String,
    /// Human-readable display name.
    pub name: String,
    /// Unix time the org was created.
    pub created_at: i64,
}

/// A project (materialized-path node) system-of-record row.
#[derive(Debug, Clone)]
pub struct ProjectRecord {
    /// Database id.
    pub id: i64,
    /// Owning org id.
    pub org_id: i64,
    /// Materialized path within the org (`""` for an org-root project).
    pub path: String,
    /// Human-readable display name.
    pub name: String,
    /// Unix time the project was created.
    pub created_at: i64,
}

/// A pending invitation system-of-record row.
#[derive(Debug, Clone)]
pub struct InvitationRecord {
    /// Database id.
    pub id: i64,
    /// Org the invitation grants membership in.
    pub org_id: i64,
    /// Invited email address.
    pub email: String,
    /// Scope path the resulting grant is bound to.
    pub scope: String,
    /// Role the resulting grant confers.
    pub role: String,
}

/// A validated provisioning token: who owns it and what it may do.
///
/// Produced by [`Database::validate_token`] after a secret checks out
/// (hash matches, not expired, not hard-revoked, and — if rotated — still
/// inside the rotation grace window). The `scope`/`permissions` here are
/// the token's *own* grants. The RPC plane additionally intersects them
/// with the owner's current memberships at decision time
/// ([`Database::effective_scopes`]); the machine plane authorizes from
/// these grants alone, bounded by the JWT TTL (see `auth::extract`).
#[derive(Debug, Clone)]
pub struct TokenAuth {
    /// The token's id (UUID); the JWT `sub` and the revoke/rotate key.
    pub token_id: String,
    /// The principal that owns the token.
    pub owner: crate::domain::Principal,
    /// The scope path the token is bound to.
    pub scope: crate::domain::Scope,
    /// The permission verbs the token grants.
    pub permissions: Vec<crate::domain::Permission>,
}

/// A validated human session: the user and their current sudo level.
///
/// Produced by [`Database::validate_session`] after a cookie secret checks
/// out (hash matches and the session has not expired); validation also
/// bumps `last_seen_at`.
#[derive(Debug, Clone)]
pub struct SessionAuth {
    /// The authenticated user's id.
    pub user_id: i64,
    /// `1` when the session is sudo-capable (re-authenticated recently).
    pub auth_level: i64,
    /// Unix time the user last (re-)authenticated, for sudo freshness.
    pub last_authenticated_at: i64,
    /// Unix time the session expires.
    pub expires_at: i64,
}

/// Index freshness state for one registry.
#[derive(Debug, Clone)]
pub struct IndexStatus {
    /// `fresh`, `indexing`, `stale`, or `failed`.
    pub state: String,
    /// Failure detail when `state = failed`.
    pub error: Option<String>,
    /// The commit the current index was built from.
    pub last_indexed_commit: Option<String>,
    /// Committed registry name from `registry.toml`.
    pub name: Option<String>,
    /// Committed registry description.
    pub description: Option<String>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
}

/// One package row for index pages.
#[derive(Debug, Clone)]
pub struct PackageRow {
    /// Package name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// SPDX license identifier.
    pub license: String,
    /// Latest indexed version string.
    pub latest_version: Option<String>,
}

/// Full package detail for the package page.
#[derive(Debug, Clone)]
pub struct PackageDetail {
    /// Package name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Optional homepage URL.
    pub homepage: Option<String>,
    /// SPDX license identifier.
    pub license: String,
    /// Maintainer handle.
    pub maintainer: String,
    /// Whether the package is a system toplevel.
    pub sysroot: bool,
    /// Versions, newest first, with their platform artifacts.
    pub versions: Vec<VersionDetail>,
}

/// One version of a package, with platform artifacts.
#[derive(Debug, Clone)]
pub struct VersionDetail {
    /// Version string.
    pub version: String,
    /// Previous version in the sysroot chain.
    pub previous: Option<String>,
    /// Per-platform artifacts.
    pub platforms: Vec<PlatformDetail>,
}

/// One platform artifact row.
#[derive(Debug, Clone)]
pub struct PlatformDetail {
    /// Platform triple.
    pub platform: String,
    /// Store path of the output.
    pub store_path: String,
    /// NAR hash.
    pub nar_hash: String,
    /// NAR size in bytes.
    pub nar_size: u64,
    /// Closure size in bytes.
    pub closure_size: u64,
    /// Referenced store hashes (the `refs` JSON column).
    pub refs: Vec<String>,
    /// Sysroot disk images (the `images` JSON column).
    pub images: Vec<ImageDetail>,
}

/// One sysroot disk image attached to a platform artifact.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImageDetail {
    /// Image format (e.g. `qcow2`, `raw`).
    pub format: String,
    /// Store path of the image.
    pub store_path: String,
    /// NAR hash of the image.
    #[serde(default)]
    pub nar_hash: String,
    /// NAR size of the image in bytes.
    #[serde(default)]
    pub nar_size: u64,
}

/// One channel with partition rollout summary.
#[derive(Debug, Clone)]
pub struct ChannelSummary {
    /// Channel name.
    pub name: String,
    /// Newest release any partition targets.
    pub frontier: Option<String>,
    /// Partition targets by bucket (0..=255); `None` = unassigned.
    pub partitions: Vec<Option<String>>,
}

/// One verified release row.
#[derive(Debug, Clone)]
pub struct ReleaseRow {
    /// Release version.
    pub semver: String,
    /// Tag object id.
    pub tag_oid: String,
    /// Release commit id.
    pub commit_oid: String,
    /// Trusted key (base64) that signed the tag.
    pub signer: Option<String>,
    /// Tagger timestamp, Unix seconds.
    pub tagged_at: Option<i64>,
    /// Whether the per-release `objects/info/packs` listing exists on the
    /// surface (the release ships a full pack).
    pub pack_present: bool,
}

/// One recorded consistency-validation run against a cache endpoint.
#[derive(Debug, Clone)]
pub struct ValidationRunRow {
    /// Run id (foreign key for [`Database::validation_missing`]).
    pub id: i64,
    /// The cache endpoint that was validated.
    pub cache_url: String,
    /// Validation depth (`presence` in phase 1).
    pub depth: String,
    /// Number of store hashes probed.
    pub checked: u64,
    /// Number of probed hashes whose narinfo was absent.
    pub missing: u64,
    /// Whether the cache endpoint was reachable at all.
    pub reachable: bool,
    /// Unix time the run finished.
    pub finished_at: i64,
}

/// The full index payload one successful indexing run produces.
#[derive(Debug, Default)]
pub struct IndexSnapshot {
    /// The commit the snapshot was loaded from.
    pub commit: String,
    /// Committed registry name.
    pub name: String,
    /// Committed registry description.
    pub description: Option<String>,
    /// Committed `[[caches]]` entries as `(url, priority)`.
    pub caches: Vec<(String, u32)>,
    /// Roster entries as `(key_id, public_key, status)`.
    pub roster: Vec<(String, String, String)>,
    /// Full package documents.
    pub packages: Vec<aos_package::registry::parse::PackageToml>,
    /// Verified releases.
    pub releases: Vec<ReleaseRow>,
    /// Channels with verified partition maps.
    pub channels: Vec<ChannelSummary>,
    /// SHA-256 hex digest of the raw `info/refs` bytes the snapshot was
    /// built from; powers the incremental channel-refresh fast path.
    pub refs_digest: Option<String>,
}

/// One append-only audit-log row (system-of-record).
///
/// Records a single mutating action: the actor, the action verb, the
/// targeted scope, the optional change-set join key, and the optional
/// cryptographic-history cross-references for surface-touching operations.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// Row id (monotonic; orders entries within a scope).
    pub id: i64,
    /// The change-set this entry ties to, or `None` when not change-set
    /// driven.
    pub change_id: Option<String>,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Human label of the actor (email, `sa:org/name`, key fingerprint, or
    /// `system`).
    pub actor_label: String,
    /// The action verb (e.g. `registry.visibility`, `membership.grant`).
    pub action: String,
    /// Scope path the action targeted.
    pub scope: String,
    /// Resulting git commit hash for surface-touching ops, when applicable.
    pub result_commit: Option<String>,
    /// Resulting git tag hash for surface-touching ops, when applicable.
    pub result_tag: Option<String>,
    /// Free-form detail (often a compact JSON object).
    pub detail: Option<String>,
    /// Unix time the entry was recorded.
    pub created_at: i64,
}

/// One configuration change-set summary row (system-of-record).
#[derive(Debug, Clone)]
pub struct ChangesetRow {
    /// Stable change-set id (UUID v4); the audit/revision join key.
    pub change_id: String,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Owning principal's row id, when applicable.
    pub actor_id: Option<i64>,
    /// Human label of the actor that opened the change-set.
    pub actor_label: String,
    /// Scope path the change-set targets.
    pub scope: String,
    /// Lifecycle status: `draft`, `applied`, or `reverted`.
    pub status: String,
    /// One-line human summary.
    pub summary: Option<String>,
    /// Unix time the change-set was created.
    pub created_at: i64,
    /// Unix time the change-set was applied, or `None` when never applied.
    pub applied_at: Option<i64>,
    /// The change-set that reverted this one, or `None`.
    pub reverted_by_change_id: Option<String>,
}

/// One revision row within a change-set (system-of-record).
///
/// A revision is a staged operation on one object, carrying the full
/// before/after JSON snapshots that diffs and reverts are computed from.
/// Rows are never updated once written.
#[derive(Debug, Clone)]
pub struct RevisionRow {
    /// Row id.
    pub id: i64,
    /// The change-set this revision belongs to.
    pub change_id: String,
    /// The object's type (e.g. `registry`, `membership`, `token`).
    pub object_type: String,
    /// The object's stable id within its type.
    pub object_id: String,
    /// The operation: `create`, `update`, or `delete`.
    pub op: String,
    /// Full object snapshot before the change (`None` for a create).
    pub old_json: Option<String>,
    /// Full object snapshot after the change (`None` for a delete).
    pub new_json: Option<String>,
    /// Ordinal of this revision within its change-set, from `0`.
    pub seq: i64,
}

/// The hub database handle.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (creating and migrating if needed) the hub database.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or a migration fails.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening hub database {}", path.display()))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory database (tests only).
    ///
    /// `serve --dev` does *not* use this: dev mode persists a regular
    /// `hub.db` under its `--root` directory (defaulting to `./.aos-hub`).
    ///
    /// # Errors
    ///
    /// Returns an error if a migration fails.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
            [],
        )?;
        let current: i64 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0);
        let target = MIGRATIONS.len() as i64;
        if current > target {
            bail!("hub database schema {current} is newer than this build supports ({target})");
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            conn.execute_batch(sql)
                .with_context(|| format!("applying migration v{}", i + 1))?;
        }
        conn.execute("DELETE FROM schema_version", [])?;
        conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [target])?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned mutex means another thread panicked mid-query; the
        // connection itself is still structurally usable for new calls.
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    // -- system of record ---------------------------------------------------

    /// Register a registry (or update its source/trust on re-registration).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn register_registry(
        &self,
        slug: &str,
        source_url: &str,
        trust_keys: &[String],
        require_signatures: bool,
    ) -> Result<i64> {
        let conn = self.lock();
        let now = unix_now();
        conn.execute(
            "INSERT INTO registries (slug, source_url, trust_keys, require_signatures, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(slug) DO UPDATE SET
                 source_url = excluded.source_url,
                 trust_keys = excluded.trust_keys,
                 require_signatures = excluded.require_signatures",
            params![
                slug,
                source_url,
                serde_json::to_string(trust_keys)?,
                require_signatures as i64,
                now,
            ],
        )?;
        let id: i64 = conn.query_row("SELECT id FROM registries WHERE slug = ?1", [slug], |r| {
            r.get(0)
        })?;
        conn.execute(
            "INSERT INTO registry_index (registry_id, state)
             VALUES (?1, 'indexing')
             ON CONFLICT(registry_id) DO NOTHING",
            [id],
        )?;
        Ok(id)
    }

    /// Look up a registry by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn registry_by_slug(&self, slug: &str) -> Result<Option<RegistryRecord>> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE slug = ?1"),
            [slug],
            row_to_registry,
        )
        .optional()
        .context("loading registry by slug")
    }

    /// List all registered registries.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_registries(&self) -> Result<Vec<RegistryRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {REGISTRY_COLUMNS} FROM registries ORDER BY slug"
        ))?;
        let rows = stmt.query_map([], row_to_registry)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -- index writes -------------------------------------------------------

    /// Replace a registry's entire index with a fresh snapshot, atomically.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    pub fn apply_snapshot(&self, registry_id: i64, snapshot: &IndexSnapshot) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        for table in ["packages", "channels", "releases", "key_rosters", "caches"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE registry_id = ?1"),
                [registry_id],
            )?;
        }

        for package in &snapshot.packages {
            tx.execute(
                "INSERT INTO packages
                 (registry_id, name, description, homepage, license, maintainer, sysroot)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    registry_id,
                    package.package.name,
                    package.package.description,
                    package.package.homepage,
                    package.package.license,
                    package.package.maintainer,
                    package.package.sysroot as i64,
                ],
            )?;
            let package_id = tx.last_insert_rowid();
            for version in &package.versions {
                tx.execute(
                    "INSERT INTO package_versions (package_id, version, previous)
                     VALUES (?1, ?2, ?3)",
                    params![package_id, version.version, version.previous],
                )?;
                let version_id = tx.last_insert_rowid();
                for (platform, entry) in &version.platforms {
                    let images = entry
                        .images
                        .iter()
                        .map(|i| {
                            serde_json::json!({
                                "format": i.format,
                                "store_path": i.store_path,
                                "nar_hash": i.nar_hash,
                                "nar_size": i.nar_size,
                            })
                        })
                        .collect::<Vec<_>>();
                    tx.execute(
                        "INSERT INTO version_platforms
                         (version_id, platform, store_path, nar_hash, nar_size,
                          closure_size, refs, images)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            version_id,
                            platform,
                            entry.store_path,
                            entry.nar_hash,
                            entry.nar_size as i64,
                            entry.closure_size as i64,
                            serde_json::to_string(&entry.references)?,
                            serde_json::Value::Array(images).to_string(),
                        ],
                    )?;
                }
            }
        }

        for release in &snapshot.releases {
            tx.execute(
                "INSERT INTO releases
                 (registry_id, semver, tag_oid, commit_oid, signer, tagged_at, pack_present)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    registry_id,
                    release.semver,
                    release.tag_oid,
                    release.commit_oid,
                    release.signer,
                    release.tagged_at,
                    release.pack_present as i64,
                ],
            )?;
        }

        for channel in &snapshot.channels {
            tx.execute(
                "INSERT INTO channels (registry_id, name, frontier) VALUES (?1, ?2, ?3)",
                params![registry_id, channel.name, channel.frontier],
            )?;
            let channel_id = tx.last_insert_rowid();
            for (bucket, release) in channel.partitions.iter().enumerate() {
                if let Some(release) = release {
                    tx.execute(
                        "INSERT INTO channel_partitions (channel_id, bucket, release)
                         VALUES (?1, ?2, ?3)",
                        params![channel_id, bucket as i64, release],
                    )?;
                }
            }
        }

        for (key_id, public_key, status) in &snapshot.roster {
            tx.execute(
                "INSERT INTO key_rosters (registry_id, key_id, public_key, status)
                 VALUES (?1, ?2, ?3, ?4)",
                params![registry_id, key_id, public_key, status],
            )?;
        }
        for (url, priority) in &snapshot.caches {
            tx.execute(
                "INSERT INTO caches (registry_id, url, priority) VALUES (?1, ?2, ?3)",
                params![registry_id, url, *priority as i64],
            )?;
        }

        tx.execute(
            "INSERT INTO registry_index
             (registry_id, state, error, last_indexed_commit, name, description,
              indexed_at, refs_digest)
             VALUES (?1, 'fresh', NULL, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(registry_id) DO UPDATE SET
                 state = 'fresh', error = NULL,
                 last_indexed_commit = excluded.last_indexed_commit,
                 name = excluded.name, description = excluded.description,
                 indexed_at = excluded.indexed_at,
                 refs_digest = excluded.refs_digest",
            params![
                registry_id,
                snapshot.commit,
                snapshot.name,
                snapshot.description,
                unix_now(),
                snapshot.refs_digest,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Record an indexing failure without touching the last good index.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn mark_index_failed(&self, registry_id: i64, error: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'failed', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'failed', error = excluded.error",
            params![registry_id, error],
        )?;
        Ok(())
    }

    /// Mark a registry's index stale (surface unreachable), keeping the
    /// last good index.
    ///
    /// Like [`Database::mark_index_failed`] but for transient transport
    /// failures: the surface could not be *read*, as opposed to being
    /// read and found invalid.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn mark_index_stale(&self, registry_id: i64, error: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'stale', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'stale', error = excluded.error",
            params![registry_id, error],
        )?;
        Ok(())
    }

    /// Replace a registry's channels (and partitions) without touching the
    /// rest of the index.
    ///
    /// This is the write half of the incremental channel refresh: when the
    /// ref advertisement is unchanged, only the mutable channel partitions
    /// need re-verifying, so only `channels`/`channel_partitions` are
    /// rewritten (in one transaction) and `registry_index.indexed_at` is
    /// bumped. Everything else — packages, releases, roster, caches — is
    /// left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    pub fn update_channels(&self, registry_id: i64, channels: &[ChannelSummary]) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        // Deleting channels cascades to channel_partitions.
        tx.execute("DELETE FROM channels WHERE registry_id = ?1", [registry_id])?;
        for channel in channels {
            tx.execute(
                "INSERT INTO channels (registry_id, name, frontier) VALUES (?1, ?2, ?3)",
                params![registry_id, channel.name, channel.frontier],
            )?;
            let channel_id = tx.last_insert_rowid();
            for (bucket, release) in channel.partitions.iter().enumerate() {
                if let Some(release) = release {
                    tx.execute(
                        "INSERT INTO channel_partitions (channel_id, bucket, release)
                         VALUES (?1, ?2, ?3)",
                        params![channel_id, bucket as i64, release],
                    )?;
                }
            }
        }
        tx.execute(
            "UPDATE registry_index SET indexed_at = ?2 WHERE registry_id = ?1",
            params![registry_id, unix_now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    // -- anti-rollback floors ------------------------------------------------

    /// The recorded anti-rollback floor for one channel, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn channel_floor(&self, registry_id: i64, channel: &str) -> Result<Option<String>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT floor FROM channel_floors WHERE registry_id = ?1 AND channel = ?2",
            params![registry_id, channel],
            |row| row.get(0),
        )
        .optional()
        .context("loading channel floor")
    }

    /// Set (or overwrite) the anti-rollback floor for one channel.
    ///
    /// Callers are responsible for only ever *raising* the floor; this
    /// method records whatever it is given.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_channel_floor(&self, registry_id: i64, channel: &str, floor: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO channel_floors (registry_id, channel, floor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(registry_id, channel) DO UPDATE SET floor = excluded.floor",
            params![registry_id, channel, floor],
        )?;
        Ok(())
    }

    // -- consistency validation ----------------------------------------------

    /// Record one validation run with its missing-hash findings; returns
    /// the run id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    // The argument list mirrors the validation_runs row one-to-one.
    #[allow(clippy::too_many_arguments)]
    pub fn record_validation_run(
        &self,
        registry_id: i64,
        cache_url: &str,
        depth: &str,
        checked: u64,
        missing_hashes: &[String],
        reachable: bool,
        started_at: i64,
        finished_at: i64,
    ) -> Result<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO validation_runs
             (registry_id, cache_url, depth, checked, missing, reachable,
              started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                registry_id,
                cache_url,
                depth,
                checked as i64,
                missing_hashes.len() as i64,
                reachable as i64,
                started_at,
                finished_at,
            ],
        )?;
        let run_id = tx.last_insert_rowid();
        for hash in missing_hashes {
            tx.execute(
                "INSERT OR IGNORE INTO validation_findings (run_id, store_hash, status)
                 VALUES (?1, ?2, 'missing')",
                params![run_id, hash],
            )?;
        }
        tx.commit()?;
        Ok(run_id)
    }

    /// The latest validation run per cache URL for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn latest_validation_runs(&self, registry_id: i64) -> Result<Vec<ValidationRunRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT v.id, v.cache_url, v.depth, v.checked, v.missing, v.reachable, v.finished_at
             FROM validation_runs v
             WHERE v.registry_id = ?1
               AND v.id = (SELECT MAX(id) FROM validation_runs
                           WHERE registry_id = ?1 AND cache_url = v.cache_url)
             ORDER BY v.cache_url",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok(ValidationRunRow {
                id: row.get(0)?,
                cache_url: row.get(1)?,
                depth: row.get(2)?,
                checked: row.get::<_, i64>(3)? as u64,
                missing: row.get::<_, i64>(4)? as u64,
                reachable: row.get::<_, i64>(5)? != 0,
                finished_at: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The store hashes a validation run found missing, sorted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn validation_missing(&self, run_id: i64) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT store_hash FROM validation_findings
             WHERE run_id = ?1 AND status = 'missing' ORDER BY store_hash",
        )?;
        let rows = stmt.query_map([run_id], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Every distinct store hash the registry's index references, sorted.
    ///
    /// The union of (a) the hash prefix of every `version_platforms`
    /// `store_path` basename — the text before the first `-` — and (b)
    /// every entry of the per-platform `refs` JSON arrays. Basenames with
    /// no `-` separator carry no extractable hash and are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn all_store_hashes(&self, registry_id: i64) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT vp.store_path, vp.refs FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut hashes = std::collections::BTreeSet::new();
        for row in rows {
            let (store_path, refs_json) = row?;
            let basename = store_path.rsplit('/').next().unwrap_or(&store_path);
            if let Some((hash, _)) = basename.split_once('-') {
                hashes.insert(hash.to_string());
            }
            // The refs column is index-written JSON; tolerate (skip) a
            // malformed value the same way registry rows are read.
            let refs: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
            hashes.extend(refs);
        }
        Ok(hashes.into_iter().collect())
    }

    // -- index reads --------------------------------------------------------

    /// The index status for a registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn index_status(&self, registry_id: i64) -> Result<Option<IndexStatus>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT state, error, last_indexed_commit, name, description, indexed_at
             FROM registry_index WHERE registry_id = ?1",
            [registry_id],
            |row| {
                Ok(IndexStatus {
                    state: row.get(0)?,
                    error: row.get(1)?,
                    last_indexed_commit: row.get(2)?,
                    name: row.get(3)?,
                    description: row.get(4)?,
                    indexed_at: row.get(5)?,
                })
            },
        )
        .optional()
        .context("loading index status")
    }

    /// List packages with their newest indexed version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_packages(&self, registry_id: i64) -> Result<Vec<PackageRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT p.name, p.description, p.license,
                    (SELECT v.version FROM package_versions v
                     WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1)
             FROM packages p WHERE p.registry_id = ?1 ORDER BY p.name",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok(PackageRow {
                name: row.get(0)?,
                description: row.get(1)?,
                license: row.get(2)?,
                latest_version: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Load one package's full detail.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn package_detail(&self, registry_id: i64, name: &str) -> Result<Option<PackageDetail>> {
        let conn = self.lock();
        let header = conn
            .query_row(
                "SELECT id, name, description, homepage, license, maintainer, sysroot
                 FROM packages WHERE registry_id = ?1 AND name = ?2",
                params![registry_id, name],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        PackageDetail {
                            name: row.get(1)?,
                            description: row.get(2)?,
                            homepage: row.get(3)?,
                            license: row.get(4)?,
                            maintainer: row.get(5)?,
                            sysroot: row.get::<_, i64>(6)? != 0,
                            versions: Vec::new(),
                        },
                    ))
                },
            )
            .optional()?;
        let Some((package_id, mut detail)) = header else {
            return Ok(None);
        };

        let mut stmt = conn.prepare(
            "SELECT id, version, previous FROM package_versions
             WHERE package_id = ?1 ORDER BY id DESC",
        )?;
        let versions = stmt
            .query_map([package_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut platform_stmt = conn.prepare(
            "SELECT platform, store_path, nar_hash, nar_size, closure_size, refs, images
             FROM version_platforms WHERE version_id = ?1 ORDER BY platform",
        )?;
        for (version_id, version, previous) in versions {
            let platforms = platform_stmt
                .query_map([version_id], |row| {
                    // refs/images are index-written JSON; tolerate (skip) a
                    // malformed value the same way registry rows are read.
                    let refs_json: String = row.get(5)?;
                    let images_json: String = row.get(6)?;
                    Ok(PlatformDetail {
                        platform: row.get(0)?,
                        store_path: row.get(1)?,
                        nar_hash: row.get(2)?,
                        nar_size: row.get::<_, i64>(3)? as u64,
                        closure_size: row.get::<_, i64>(4)? as u64,
                        refs: serde_json::from_str(&refs_json).unwrap_or_default(),
                        images: serde_json::from_str(&images_json).unwrap_or_default(),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            detail.versions.push(VersionDetail {
                version,
                previous,
                platforms,
            });
        }
        Ok(Some(detail))
    }

    /// List channels with their full partition maps.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_channels(&self, registry_id: i64) -> Result<Vec<ChannelSummary>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, frontier FROM channels WHERE registry_id = ?1 ORDER BY name",
        )?;
        let channels = stmt
            .query_map([registry_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut partition_stmt =
            conn.prepare("SELECT bucket, release FROM channel_partitions WHERE channel_id = ?1")?;
        let mut out = Vec::with_capacity(channels.len());
        for (channel_id, name, frontier) in channels {
            let mut partitions = vec![None; 256];
            let rows = partition_stmt.query_map([channel_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (bucket, release) = row?;
                if let Some(slot) = partitions.get_mut(bucket as usize) {
                    *slot = Some(release);
                }
            }
            out.push(ChannelSummary {
                name,
                frontier,
                partitions,
            });
        }
        Ok(out)
    }

    /// List verified releases, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_releases(&self, registry_id: i64) -> Result<Vec<ReleaseRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT semver, tag_oid, commit_oid, signer, tagged_at, pack_present
             FROM releases WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok(ReleaseRow {
                semver: row.get(0)?,
                tag_oid: row.get(1)?,
                commit_oid: row.get(2)?,
                signer: row.get(3)?,
                tagged_at: row.get(4)?,
                pack_present: row.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The `info/refs` digest the current index was built from, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn refs_digest(&self, registry_id: i64) -> Result<Option<String>> {
        let conn = self.lock();
        let digest: Option<Option<String>> = conn
            .query_row(
                "SELECT refs_digest FROM registry_index WHERE registry_id = ?1",
                [registry_id],
                |row| row.get(0),
            )
            .optional()
            .context("loading refs digest")?;
        Ok(digest.flatten())
    }

    /// The roster as `(key_id, public_key, status)` rows.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_roster(&self, registry_id: i64) -> Result<Vec<(String, String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT key_id, public_key, status FROM key_rosters
             WHERE registry_id = ?1 ORDER BY status, key_id",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Committed `[[caches]]` entries as `(url, priority)`, highest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_caches(&self, registry_id: i64) -> Result<Vec<(String, u32)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT url, priority FROM caches WHERE registry_id = ?1 ORDER BY priority DESC",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok((row.get(0)?, row.get::<_, i64>(1)? as u32))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -- tenancy: orgs and projects -----------------------------------------

    /// Create an organization; returns its new id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `slug` is already taken.
    pub fn create_org(&self, slug: &str, name: &str) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO orgs (slug, name, created_at) VALUES (?1, ?2, ?3)",
            params![slug, name, unix_now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Look up an organization by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn org_by_slug(&self, slug: &str) -> Result<Option<OrgRecord>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, slug, name, created_at FROM orgs WHERE slug = ?1",
            [slug],
            |row| {
                Ok(OrgRecord {
                    id: row.get(0)?,
                    slug: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        )
        .optional()
        .context("loading org by slug")
    }

    /// Create a project under an org at a materialized path; returns its id.
    ///
    /// Pass `""` as `path` for a project that sits directly under the org
    /// root.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `(org_id, path)` already exists or `org_id` does not
    /// reference an org.
    pub fn create_project(&self, org_id: i64, path: &str, name: &str) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO projects (org_id, path, name, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![org_id, path, name, unix_now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// List an org's projects, ordered by materialized path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_projects(&self, org_id: i64) -> Result<Vec<ProjectRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, org_id, path, name, created_at FROM projects
             WHERE org_id = ?1 ORDER BY path",
        )?;
        let rows = stmt.query_map([org_id], |row| {
            Ok(ProjectRecord {
                id: row.get(0)?,
                org_id: row.get(1)?,
                path: row.get(2)?,
                name: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -- tenancy: principals -------------------------------------------------

    /// Create a user; returns the new user id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `email` is already registered.
    pub fn create_user(&self, email: &str, display_name: Option<&str>) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO users (email, display_name, created_at) VALUES (?1, ?2, ?3)",
            params![email, display_name, unix_now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Look up a non-deleted user's id by email.
    ///
    /// Soft-deleted users (those with `deleted_at` set) are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn user_by_email(&self, email: &str) -> Result<Option<i64>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id FROM users WHERE email = ?1 AND deleted_at IS NULL",
            [email],
            |row| row.get(0),
        )
        .optional()
        .context("loading user by email")
    }

    /// Create a service account under an org; returns the new id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `(org_id, name)` already exists.
    pub fn create_service_account(&self, org_id: i64, name: &str) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO service_accounts (org_id, name, created_at) VALUES (?1, ?2, ?3)",
            params![org_id, name, unix_now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Look up a service account's id by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn service_account_by_name(&self, org_id: i64, name: &str) -> Result<Option<i64>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id FROM service_accounts WHERE org_id = ?1 AND name = ?2",
            params![org_id, name],
            |row| row.get(0),
        )
        .optional()
        .context("loading service account by name")
    }

    // -- tenancy: memberships ------------------------------------------------

    /// Grant (or update) a principal's role at a scope.
    ///
    /// A principal has at most one role per scope; re-granting the same
    /// `(principal_kind, principal_id, scope)` overwrites the role. The
    /// `scope` and `role` strings are the wire forms produced by
    /// [`crate::domain::Scope::as_str`] and [`crate::domain::Role::as_str`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn grant_membership(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
        role: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO memberships
             (principal_kind, principal_id, scope, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(principal_kind, principal_id, scope)
             DO UPDATE SET role = excluded.role",
            params![principal_kind, principal_id, scope, role, unix_now()],
        )?;
        Ok(())
    }

    /// Revoke a principal's grant at a scope.
    ///
    /// A no-op when no such grant exists.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn revoke_membership(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 AND scope = ?3",
            params![principal_kind, principal_id, scope],
        )?;
        Ok(())
    }

    /// List a principal's grants as `(scope, role)` strings, ordered by
    /// scope.
    ///
    /// These pairs feed [`crate::domain::iam::allow`] after parsing with
    /// [`crate::domain::Scope::parse`] and [`crate::domain::Role::parse`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_memberships_for(
        &self,
        principal_kind: &str,
        principal_id: i64,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT scope, role FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 ORDER BY scope",
        )?;
        let rows = stmt.query_map(params![principal_kind, principal_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// List the principals granted a role directly at one scope.
    ///
    /// Returns `(principal_kind, principal_id, role)` for the grants whose
    /// `scope` equals `scope` exactly — it does **not** expand inherited
    /// grants from ancestor scopes; that inheritance is resolved by
    /// [`crate::domain::iam::allow`] at decision time.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_members_of_scope(&self, scope: &str) -> Result<Vec<(String, i64, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT principal_kind, principal_id, role FROM memberships
             WHERE scope = ?1 ORDER BY principal_kind, principal_id",
        )?;
        let rows = stmt.query_map([scope], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Resolve a principal's effective grants as parsed `(Scope, Role)`
    /// pairs ready for [`crate::domain::iam::allow`].
    ///
    /// This is the thin domain-db bridge: it reads `memberships` via
    /// [`Database::list_memberships_for`] and parses each row into the
    /// pure domain types. Rows whose stored `role` is not one of the five
    /// known role names are skipped (forward-compatibility with a future
    /// role added by a newer writer); scopes always parse.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn effective_scopes(
        &self,
        principal: crate::domain::Principal,
    ) -> Result<Vec<(crate::domain::Scope, crate::domain::Role)>> {
        let rows = self.list_memberships_for(principal.kind.as_str(), principal.id)?;
        Ok(rows
            .into_iter()
            .filter_map(|(scope, role)| {
                crate::domain::Role::parse(&role)
                    .map(|role| (crate::domain::Scope::parse(&scope), role))
            })
            .collect())
    }

    // -- tenancy: registry ownership ----------------------------------------

    /// Bind a registry to an org/project and set its visibility.
    ///
    /// Pass `None` for `org_id` to leave (or make) the registry an
    /// instance-level unowned public registry. `project_path` is the
    /// owning project's materialized path (`""` for an org-root registry);
    /// `visibility` is `public`, `internal`, or `private`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_registry_ownership(
        &self,
        registry_id: i64,
        org_id: Option<i64>,
        project_path: &str,
        visibility: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE registries
             SET org_id = ?2, project_path = ?3, visibility = ?4
             WHERE id = ?1",
            params![registry_id, org_id, project_path, visibility],
        )?;
        Ok(())
    }

    /// Resolve a managed registry by its canonical `{org}/{project_path}/{name}`
    /// coordinates.
    ///
    /// Builds the canonical slug (`"{org}/{name}"` when `project_path` is
    /// empty, otherwise `"{org}/{project_path}/{name}"`) and delegates to
    /// [`Database::registry_by_slug`] — managed registries store their full
    /// canonical path as their slug (see the [module docs](self)). Returns
    /// `Ok(None)` when no registry has that canonical path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn registry_by_scope(
        &self,
        org_slug: &str,
        project_path: &str,
        name: &str,
    ) -> Result<Option<RegistryRecord>> {
        self.registry_by_slug(&canonical_slug(org_slug, project_path, name))
    }

    /// Create a managed (org-owned, storage-bound) registry; returns its id.
    ///
    /// The registry is stored with its full canonical path
    /// (`{org}/{project_path}/{name}`) as its slug, an empty `source_url`
    /// (its surface is located via the binding), and the given ownership,
    /// storage binding, prefix, and trust configuration. Canonical
    /// uniqueness is enforced both by the up-front
    /// [`Database::registry_by_scope`] check and by the underlying
    /// `UNIQUE(slug)` constraint.
    ///
    /// # Errors
    ///
    /// Returns an error when a registry already exists at the canonical
    /// path, when `prefix` contains a path-traversal component (`..`, an
    /// absolute segment), or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub fn create_managed_registry(
        &self,
        org_id: i64,
        project_path: &str,
        name: &str,
        visibility: &str,
        binding_id: Option<i64>,
        prefix: &str,
        trust_keys: &[String],
        require_signatures: bool,
    ) -> Result<i64> {
        // Defense in depth: the per-file upload tail is already constrained
        // by `safe_join`, but a `..` in the binding prefix would relocate
        // the whole surface root, so reject it at creation.
        if !prefix.is_empty() {
            let rel = std::path::Path::new(prefix);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                bail!("registry prefix '{prefix}' must be a relative path with no '..' components");
            }
        }
        let org_slug = self
            .org_by_id(org_id)?
            .with_context(|| format!("no org with id {org_id}"))?
            .slug;
        let slug = canonical_slug(&org_slug, project_path, name);
        if self.registry_by_slug(&slug)?.is_some() {
            bail!("a registry already exists at '{slug}'");
        }
        let conn = self.lock();
        conn.execute(
            "INSERT INTO registries
             (slug, source_url, trust_keys, require_signatures, created_at,
              org_id, project_path, visibility, storage_binding_id, prefix)
             VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                slug,
                serde_json::to_string(trust_keys)?,
                require_signatures as i64,
                unix_now(),
                org_id,
                project_path,
                visibility,
                binding_id,
                prefix,
            ],
        )?;
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO registry_index (registry_id, state)
             VALUES (?1, 'indexing')
             ON CONFLICT(registry_id) DO NOTHING",
            [id],
        )?;
        Ok(id)
    }

    // -- storage bindings ----------------------------------------------------

    /// Create a storage binding under an org; returns its new id.
    ///
    /// Only `local_fs` is a valid `kind` this phase (where `root` is a
    /// filesystem path); other kinds are rejected up front.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported `kind`, on a unique-constraint
    /// violation when `(org_id, name)` already exists, or on database
    /// failure.
    pub fn create_storage_binding(
        &self,
        org_id: i64,
        name: &str,
        kind: &str,
        root: &str,
    ) -> Result<i64> {
        if kind != "local_fs" {
            bail!("unsupported storage binding kind '{kind}' (only 'local_fs' is supported)");
        }
        let conn = self.lock();
        conn.execute(
            "INSERT INTO storage_bindings (org_id, name, kind, root, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![org_id, name, kind, root, unix_now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Look up a storage binding by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn storage_binding(&self, id: i64) -> Result<Option<StorageBindingRecord>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, org_id, name, kind, root, created_at
             FROM storage_bindings WHERE id = ?1",
            [id],
            row_to_storage_binding,
        )
        .optional()
        .context("loading storage binding by id")
    }

    /// Look up a storage binding by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn storage_binding_by_name(
        &self,
        org_id: i64,
        name: &str,
    ) -> Result<Option<StorageBindingRecord>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, org_id, name, kind, root, created_at
             FROM storage_bindings WHERE org_id = ?1 AND name = ?2",
            params![org_id, name],
            row_to_storage_binding,
        )
        .optional()
        .context("loading storage binding by name")
    }

    /// List an org's storage bindings, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_storage_bindings(&self, org_id: i64) -> Result<Vec<StorageBindingRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, org_id, name, kind, root, created_at
             FROM storage_bindings WHERE org_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map([org_id], row_to_storage_binding)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Bind a registry to a storage binding and sub-prefix.
    ///
    /// After this, [`Database::registry_surface_root`] resolves the
    /// registry's surface to `{binding.root}/{prefix}`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_registry_storage(
        &self,
        registry_id: i64,
        binding_id: i64,
        prefix: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE registries SET storage_binding_id = ?2, prefix = ?3 WHERE id = ?1",
            params![registry_id, binding_id, prefix],
        )?;
        Ok(())
    }

    /// Resolve the on-disk surface directory for a registry, if any.
    ///
    /// Precedence:
    ///
    /// 1. **Storage-bound** (`storage_binding_id` set) — the binding's
    ///    `root` joined with the registry's `prefix`. This wins even if a
    ///    `source_url` is also present.
    /// 2. **`file://` (or bare-path) source** — the `source_url` path.
    /// 3. **`http(s)://` source** — `Ok(None)`; the surface is remote and
    ///    has no local directory (the facade redirects upstream).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure (including a registry whose
    /// `storage_binding_id` points at a missing binding).
    pub fn registry_surface_root(&self, registry_id: i64) -> Result<Option<PathBuf>> {
        let Some(registry) = ({
            let conn = self.lock();
            conn.query_row(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE id = ?1"),
                [registry_id],
                row_to_registry,
            )
            .optional()
            .context("loading registry for surface resolution")?
        }) else {
            return Ok(None);
        };
        if let Some(binding_id) = registry.storage_binding_id {
            let binding = self.storage_binding(binding_id)?.with_context(|| {
                format!("registry {registry_id} bound to missing storage binding {binding_id}")
            })?;
            let mut path = PathBuf::from(binding.root);
            if !registry.prefix.is_empty() {
                path.push(&registry.prefix);
            }
            return Ok(Some(path));
        }
        let source = registry.source_url.as_str();
        if source.is_empty() || source.starts_with("http://") || source.starts_with("https://") {
            return Ok(None);
        }
        let path = source.strip_prefix("file://").unwrap_or(source);
        Ok(Some(PathBuf::from(path)))
    }

    /// Look up an organization by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn org_by_id(&self, id: i64) -> Result<Option<OrgRecord>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, slug, name, created_at FROM orgs WHERE id = ?1",
            [id],
            |row| {
                Ok(OrgRecord {
                    id: row.get(0)?,
                    slug: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        )
        .optional()
        .context("loading org by id")
    }

    /// List all organizations, ordered by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_orgs(&self) -> Result<Vec<OrgRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT id, slug, name, created_at FROM orgs ORDER BY slug")?;
        let rows = stmt.query_map([], |row| {
            Ok(OrgRecord {
                id: row.get(0)?,
                slug: row.get(1)?,
                name: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -- tenancy: invitations ------------------------------------------------

    /// Create an invitation; returns its new id.
    ///
    /// The caller passes the SHA-256 hash of the invite secret as
    /// `token_hash` (the secret itself is never stored). `expires_at` is a
    /// Unix timestamp after which [`Database::accept_invitation`] refuses
    /// the invite.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `token_hash` collides.
    pub fn create_invitation(
        &self,
        org_id: i64,
        email: &str,
        scope: &str,
        role: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO invitations
             (org_id, email, scope, role, token_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                org_id,
                email,
                scope,
                role,
                token_hash,
                unix_now(),
                expires_at
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Accept an invitation by its token hash, returning its details.
    ///
    /// Succeeds only for an invitation that is unexpired (`expires_at` is
    /// in the future relative to the current clock) and not already
    /// accepted; on success it stamps `accepted_at` and returns the
    /// invitation so the caller can mint the corresponding membership.
    /// Returns `Ok(None)` when no matching, live, unaccepted invitation
    /// exists — covering unknown hashes, expired invites, and replays
    /// alike, without distinguishing them to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn accept_invitation(&self, token_hash: &str) -> Result<Option<InvitationRecord>> {
        let conn = self.lock();
        let now = unix_now();
        let record = conn
            .query_row(
                "SELECT id, org_id, email, scope, role FROM invitations
                 WHERE token_hash = ?1 AND accepted_at IS NULL AND expires_at > ?2",
                params![token_hash, now],
                |row| {
                    Ok(InvitationRecord {
                        id: row.get(0)?,
                        org_id: row.get(1)?,
                        email: row.get(2)?,
                        scope: row.get(3)?,
                        role: row.get(4)?,
                    })
                },
            )
            .optional()
            .context("loading invitation by hash")?;
        if let Some(record) = &record {
            conn.execute(
                "UPDATE invitations SET accepted_at = ?2 WHERE id = ?1",
                params![record.id, now],
            )?;
        }
        Ok(record)
    }

    // -- auth: provisioning tokens ------------------------------------------

    /// Mint a provisioning token owned by `owner`, returning `(id, secret)`.
    ///
    /// The caller is handed the plaintext `secret` exactly once; only its
    /// SHA-256 hash is stored. `scope` is the path-prefix the token is
    /// bound to and `permissions` the verbs it carries; `expires_at`, when
    /// set, is the Unix time after which [`Database::validate_token`] stops
    /// accepting the secret.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a hash collision.
    pub fn create_token(
        &self,
        owner: crate::domain::Principal,
        scope: &str,
        permissions: &[crate::domain::Permission],
        comment: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<(String, String)> {
        let (secret, hash) = crate::auth::token::generate_token();
        let id = uuid::Uuid::new_v4().to_string();
        let perms_json = serde_json::to_string(&permission_names(permissions))?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO tokens
             (id, hash, owner_kind, owner_id, scope, permissions, comment, created_at,
              expires_at, revoked_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
            params![
                id,
                hash,
                owner.kind.as_str(),
                owner.id,
                crate::domain::Scope::parse(scope).as_str(),
                perms_json,
                comment,
                unix_now(),
                expires_at,
            ],
        )?;
        Ok((id, secret))
    }

    /// Validate a token secret, returning its [`TokenAuth`] when live.
    ///
    /// A secret is accepted when its hash is known, it is not expired, and
    /// it is either not revoked or still inside the
    /// [`ROTATION_GRACE_SECS`] window after its `revoked_at` stamp (so a
    /// rotated token's old secret keeps working briefly). On success
    /// `last_used_at` is bumped to now. Returns `Ok(None)` for any
    /// unknown, expired, or fully-revoked secret without distinguishing
    /// the reason.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or a malformed stored row.
    pub fn validate_token(&self, secret: &str) -> Result<Option<TokenAuth>> {
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, owner_kind, owner_id, scope, permissions, expires_at,
                        revoked_at, rotated_at
                 FROM tokens WHERE hash = ?1",
                [&hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                    ))
                },
            )
            .optional()
            .context("loading token by hash")?;
        let Some((id, owner_kind, owner_id, scope, perms_json, expires_at, revoked_at, rotated_at)) =
            row
        else {
            return Ok(None);
        };
        if let Some(exp) = expires_at {
            if now >= exp {
                return Ok(None);
            }
        }
        // A hard revocation cuts off immediately; a rotation grants the
        // grace window so in-flight clients can finish.
        if revoked_at.is_some() {
            return Ok(None);
        }
        if let Some(rotated) = rotated_at {
            if now >= rotated + ROTATION_GRACE_SECS {
                return Ok(None);
            }
        }
        let Some(kind) = crate::domain::PrincipalKind::parse(&owner_kind) else {
            return Ok(None);
        };
        let permissions = parse_permission_names(&perms_json);
        conn.execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(Some(TokenAuth {
            token_id: id,
            owner: crate::domain::Principal { kind, id: owner_id },
            scope: crate::domain::Scope::parse(&scope),
            permissions,
        }))
    }

    /// Revoke a token by id, stamping `revoked_at = now`.
    ///
    /// A no-op when the id is unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn revoke_token(&self, token_id: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![token_id, unix_now()],
        )?;
        Ok(())
    }

    /// List a principal's non-revoked tokens as `(id, scope, permissions)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_tokens_for(
        &self,
        owner: crate::domain::Principal,
    ) -> Result<Vec<(String, String, Vec<crate::domain::Permission>)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, scope, permissions FROM tokens
             WHERE owner_kind = ?1 AND owner_id = ?2 AND revoked_at IS NULL
             ORDER BY created_at",
        )?;
        let rows = stmt.query_map(params![owner.kind.as_str(), owner.id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, scope, perms_json) = row?;
            out.push((id, scope, parse_permission_names(&perms_json)));
        }
        Ok(out)
    }

    /// Rotate a token: revoke the old one and mint a replacement with the
    /// same owner, scope, permissions, comment, and expiry.
    ///
    /// The old secret keeps validating for [`ROTATION_GRACE_SECS`] after
    /// rotation (its `revoked_at` is stamped now, and
    /// [`Database::validate_token`] honors the grace window) so in-flight
    /// clients are not cut off mid-request. Returns `(new_id, new_secret)`,
    /// or `Ok(None)` when the id is unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or a malformed stored row.
    pub fn rotate_token(&self, token_id: &str) -> Result<Option<(String, String)>> {
        let now = unix_now();
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let old = tx
            .query_row(
                "SELECT owner_kind, owner_id, scope, permissions, comment, expires_at
                 FROM tokens WHERE id = ?1 AND revoked_at IS NULL",
                [token_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()
            .context("looking up token for rotation")?;
        let Some((owner_kind, owner_id, scope, perms_json, comment, expires_at)) = old else {
            return Ok(None);
        };
        tx.execute(
            "UPDATE tokens SET rotated_at = ?2 WHERE id = ?1",
            params![token_id, now],
        )?;
        let (secret, hash) = crate::auth::token::generate_token();
        let new_id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO tokens
             (id, hash, owner_kind, owner_id, scope, permissions, comment, created_at,
              expires_at, revoked_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
            params![
                new_id, hash, owner_kind, owner_id, scope, perms_json, comment, now, expires_at,
            ],
        )?;
        tx.commit()?;
        Ok(Some((new_id, secret)))
    }

    // -- auth: human sessions -----------------------------------------------

    /// Create a session for `user_id`, returning the opaque cookie secret.
    ///
    /// Only the SHA-256 hash of the secret is stored. The session expires
    /// `ttl_secs` from now; `auth_level` is `1` for a sudo-capable session
    /// (the user re-authenticated) and `0` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn create_session(&self, user_id: i64, ttl_secs: i64, auth_level: i64) -> Result<String> {
        let secret = crate::auth::session::new_session_secret();
        let hash = crate::auth::token::sha256_hex(&secret);
        let now = unix_now();
        let conn = self.lock();
        conn.execute(
            "INSERT INTO sessions
             (id_hash, user_id, created_at, last_seen_at, expires_at, auth_level,
              last_authenticated_at)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?3)",
            params![hash, user_id, now, now + ttl_secs, auth_level],
        )?;
        Ok(secret)
    }

    /// Validate a session cookie secret, returning its [`SessionAuth`].
    ///
    /// Accepts the secret when its hash is known and the session has not
    /// expired, bumping `last_seen_at` to now. Returns `Ok(None)` for an
    /// unknown or expired session.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn validate_session(&self, secret: &str) -> Result<Option<SessionAuth>> {
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT user_id, auth_level, last_authenticated_at, expires_at
                 FROM sessions WHERE id_hash = ?1",
                [&hash],
                |row| {
                    Ok(SessionAuth {
                        user_id: row.get(0)?,
                        auth_level: row.get(1)?,
                        last_authenticated_at: row.get(2)?,
                        expires_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .context("loading session by hash")?;
        let Some(session) = row else {
            return Ok(None);
        };
        if now >= session.expires_at {
            return Ok(None);
        }
        conn.execute(
            "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
            params![hash, now],
        )?;
        Ok(Some(session))
    }

    /// Revoke a single session by its cookie secret.
    ///
    /// A no-op when the secret is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn revoke_session(&self, secret: &str) -> Result<()> {
        let hash = crate::auth::token::sha256_hex(secret);
        let conn = self.lock();
        conn.execute("DELETE FROM sessions WHERE id_hash = ?1", [&hash])?;
        Ok(())
    }

    /// Revoke every session belonging to a user ("sign out everywhere").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn revoke_all_user_sessions(&self, user_id: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
        Ok(())
    }

    /// Elevate a session to sudo: set `auth_level = 1` and stamp
    /// `last_authenticated_at = now`.
    ///
    /// A no-op when the secret is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn elevate_session(&self, secret: &str) -> Result<()> {
        let hash = crate::auth::token::sha256_hex(secret);
        let conn = self.lock();
        conn.execute(
            "UPDATE sessions SET auth_level = 1, last_authenticated_at = ?2 WHERE id_hash = ?1",
            params![hash, unix_now()],
        )?;
        Ok(())
    }

    // -- auth: device authorization (RFC 8628) ------------------------------

    /// Start a device-authorization grant, storing only secret hashes.
    ///
    /// Returns `(device_code_secret, user_code, expires_in_secs)`: the
    /// device code is the long secret the CLI polls with, the `user_code`
    /// is the short string the human types into `/activate`. `scope` and
    /// `permissions` record what the CLI *requested*; approval clamps them
    /// to the approver's grants.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a `user_code`
    /// collision.
    pub fn start_device_authorization(
        &self,
        scope: &str,
        permissions: &[crate::domain::Permission],
    ) -> Result<(String, String, i64)> {
        let secret = crate::auth::device::new_device_code();
        let hash = crate::auth::token::sha256_hex(&secret);
        let user_code = crate::auth::device::new_user_code();
        let now = unix_now();
        let ttl = crate::auth::device::DEVICE_CODE_TTL_SECS;
        let perms_json = serde_json::to_string(&permission_names(permissions))?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO device_codes
             (device_code_hash, user_code, scope, permissions, created_at, expires_at,
              approved_by_user, denied, issued_token_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, NULL)",
            params![
                hash,
                user_code,
                crate::domain::Scope::parse(scope).as_str(),
                perms_json,
                now,
                now + ttl,
            ],
        )?;
        Ok((secret, user_code, ttl))
    }

    /// Approve a device grant by its `user_code`, minting a token owned by
    /// `approver` and scope/permission-clamped to `approver_grants`.
    ///
    /// The requested scope is clamped to the smallest scope the approver
    /// may grant (if the approver holds no grant covering it, the request
    /// is denied), and the requested permissions are intersected with what
    /// the approver actually holds at that scope. The minted token's id is
    /// recorded so [`Database::poll_device`] can hand back its secret.
    /// Returns `Ok(false)` when the `user_code` is unknown, already
    /// resolved (approved or denied), or expired.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn approve_device(
        &self,
        user_code: &str,
        approver: crate::domain::Principal,
        approver_grants: &[(crate::domain::Scope, crate::domain::Role)],
    ) -> Result<bool> {
        let now = unix_now();
        let row = {
            let conn = self.lock();
            conn.query_row(
                "SELECT scope, permissions FROM device_codes
                 WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
                   AND expires_at > ?2",
                params![user_code, now],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .context("loading device code for approval")?
        };
        let Some((scope, perms_json)) = row else {
            return Ok(false);
        };
        let requested_scope = crate::domain::Scope::parse(&scope);
        let requested = parse_permission_names(&perms_json);
        // Clamp: keep only requested permissions the approver may actually
        // grant at the requested scope (downward inheritance via `allow`).
        let granted: Vec<crate::domain::Permission> = requested
            .into_iter()
            .filter(|perm| crate::domain::iam::allow(approver_grants, *perm, &requested_scope))
            .collect();
        let (token_id, secret) =
            self.create_token(approver, requested_scope.as_str(), &granted, None, None)?;
        // Stow the minted secret on the device row: it is delivered exactly
        // once to the polling CLI by `poll_device`, never persisted in the
        // clear anywhere a human session can read it.
        let conn = self.lock();
        conn.execute(
            "UPDATE device_codes
             SET approved_by_user = ?2, issued_token_id = ?3, issued_token_secret = ?4
             WHERE user_code = ?1",
            params![user_code, approver.id, token_id, secret],
        )?;
        Ok(true)
    }

    /// Deny a device grant by its `user_code`.
    ///
    /// Returns `Ok(false)` when the code is unknown or already resolved.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn deny_device(&self, user_code: &str) -> Result<bool> {
        let conn = self.lock();
        let n = conn.execute(
            "UPDATE device_codes SET denied = 1
             WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0",
            [user_code],
        )?;
        Ok(n > 0)
    }

    /// Poll a device grant by its device-code secret.
    ///
    /// Returns [`DevicePollResult::Pending`] while the user has neither
    /// approved nor denied (or after expiry with no resolution),
    /// [`DevicePollResult::Denied`] on denial, and
    /// [`DevicePollResult::Approved`] carrying the minted token's secret
    /// once approved. The token secret is recovered from
    /// `issued_token_id`; see [`Database::approve_device`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn poll_device(&self, device_code_secret: &str) -> Result<DevicePollResult> {
        let hash = crate::auth::token::sha256_hex(device_code_secret);
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT denied, approved_by_user, issued_token_secret
                 FROM device_codes WHERE device_code_hash = ?1",
                [&hash],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .context("loading device code for poll")?;
        let Some((denied, approved_by, issued_token_secret)) = row else {
            return Ok(DevicePollResult::Pending);
        };
        if denied != 0 {
            return Ok(DevicePollResult::Denied);
        }
        if approved_by.is_none() {
            // Pending whether or not the window has lapsed; an expired-and-
            // unapproved grant simply never resolves.
            return Ok(DevicePollResult::Pending);
        }
        // Approved: hand back the minted secret stowed at approval time.
        match issued_token_secret {
            Some(secret) => Ok(DevicePollResult::Approved(secret)),
            None => Ok(DevicePollResult::Pending),
        }
    }

    // -- auth: magic links --------------------------------------------------

    /// Create a single-use email magic link, returning the link secret.
    ///
    /// Only the SHA-256 hash is stored; the link expires in
    /// [`crate::auth::magic::MAGIC_LINK_TTL_SECS`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn create_magic_link(&self, email: &str) -> Result<String> {
        let secret = crate::auth::magic::new_magic_secret();
        let hash = crate::auth::token::sha256_hex(&secret);
        let now = unix_now();
        let conn = self.lock();
        conn.execute(
            "INSERT INTO magic_links (token_hash, email, created_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                hash,
                email,
                now,
                now + crate::auth::magic::MAGIC_LINK_TTL_SECS
            ],
        )?;
        Ok(secret)
    }

    /// Consume a magic link by its secret, returning the bound email once.
    ///
    /// Succeeds only for a link that is unexpired and not already consumed;
    /// on success it stamps `consumed_at` so the same secret cannot be used
    /// twice. Returns `Ok(None)` for unknown, expired, or replayed links.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn consume_magic_link(&self, secret: &str) -> Result<Option<String>> {
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        let conn = self.lock();
        // Claim-then-read in one statement: the conditional UPDATE is the
        // single-use gate, so two concurrent consumptions of the same link
        // cannot both succeed (the second stamps zero rows). RETURNING ties
        // the claim to the email atomically.
        let email: Option<String> = conn
            .query_row(
                "UPDATE magic_links SET consumed_at = ?2
                 WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2
                 RETURNING email",
                params![hash, now],
                |row| row.get(0),
            )
            .optional()
            .context("consuming magic link by hash")?;
        Ok(email)
    }

    // -- registry config setters --------------------------------------------

    /// Set a registry's visibility (`public`, `internal`, or `private`).
    ///
    /// The simple live-object mutation the change-set engine's apply step
    /// invokes for a registry-visibility change (see
    /// [`crate::config::change_registry_visibility`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_registry_visibility(&self, registry_id: i64, visibility: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE registries SET visibility = ?2 WHERE id = ?1",
            params![registry_id, visibility],
        )?;
        Ok(())
    }

    // -- audit log ----------------------------------------------------------

    /// Append one audit-log row; returns its new id.
    ///
    /// Append-only: every mutating action that goes through the hub's
    /// SQL-backed write paths records exactly one row here. `change_id`
    /// ties the row to a configuration change-set when applicable;
    /// `result_commit`/`result_tag` cross-reference the cryptographic
    /// history for surface-touching operations (RFC-0004 "Tenancy and IAM").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub fn record_audit(
        &self,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        action: &str,
        scope: &str,
        change_id: Option<&str>,
        result_commit: Option<&str>,
        result_tag: Option<&str>,
        detail: Option<&str>,
    ) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO audit_log
             (change_id, actor_kind, actor_id, actor_label, action, scope,
              result_commit, result_tag, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                change_id,
                actor_kind,
                actor_id,
                actor_label,
                action,
                scope,
                result_commit,
                result_tag,
                detail,
                unix_now(),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// List audit entries at or below `scope`, newest first.
    ///
    /// Returns entries whose recorded `scope` is `scope` or any descendant
    /// of it (so an org-scoped query surfaces actions on its registries),
    /// using the same segment-boundary containment as
    /// [`crate::domain::Scope::contains`]. The root scope (`""`) lists every
    /// entry instance-wide.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_audit(&self, scope: &str) -> Result<Vec<AuditRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, change_id, actor_kind, actor_label, action, scope,
                    result_commit, result_tag, detail, created_at
             FROM audit_log ORDER BY id DESC",
        )?;
        let target = crate::domain::Scope::parse(scope);
        let rows = stmt.query_map([], |row| {
            Ok(AuditRow {
                id: row.get(0)?,
                change_id: row.get(1)?,
                actor_kind: row.get(2)?,
                actor_label: row.get(3)?,
                action: row.get(4)?,
                scope: row.get(5)?,
                result_commit: row.get(6)?,
                result_tag: row.get(7)?,
                detail: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let row = row?;
            if target.contains(&crate::domain::Scope::parse(&row.scope)) {
                out.push(row);
            }
        }
        Ok(out)
    }

    // -- configuration change-sets ------------------------------------------

    /// Create a change-set in `draft` status; returns nothing (the caller
    /// supplies the `change_id`).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a primary-key
    /// collision on `change_id`.
    pub fn create_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO config_changesets
             (change_id, actor_kind, actor_id, actor_label, scope, status,
              summary, created_at, applied_at, reverted_by_change_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'draft', ?6, ?7, NULL, NULL)",
            params![
                change_id,
                actor_kind,
                actor_id,
                actor_label,
                scope,
                summary,
                unix_now(),
            ],
        )?;
        Ok(())
    }

    /// Append a revision to a change-set; returns the assigned `seq`.
    ///
    /// The `seq` is the next ordinal for the change-set (its current
    /// revision count), so revisions apply in insertion order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key
    /// violation when `change_id` is unknown.
    pub fn add_revision(
        &self,
        change_id: &str,
        object_type: &str,
        object_id: &str,
        op: &str,
        old_json: Option<&str>,
        new_json: Option<&str>,
    ) -> Result<i64> {
        let conn = self.lock();
        let seq: i64 = conn.query_row(
            "SELECT COUNT(*) FROM config_revisions WHERE change_id = ?1",
            [change_id],
            |row| row.get(0),
        )?;
        conn.execute(
            "INSERT INTO config_revisions
             (change_id, object_type, object_id, op, old_json, new_json, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                change_id,
                object_type,
                object_id,
                op,
                old_json,
                new_json,
                seq
            ],
        )?;
        Ok(seq)
    }

    /// Load one change-set summary by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn changeset(&self, change_id: &str) -> Result<Option<ChangesetRow>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT change_id, actor_kind, actor_id, actor_label, scope, status,
                    summary, created_at, applied_at, reverted_by_change_id
             FROM config_changesets WHERE change_id = ?1",
            [change_id],
            row_to_changeset,
        )
        .optional()
        .context("loading changeset by id")
    }

    /// List a change-set's revisions in `seq` order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_revisions(&self, change_id: &str) -> Result<Vec<RevisionRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, change_id, object_type, object_id, op, old_json, new_json, seq
             FROM config_revisions WHERE change_id = ?1 ORDER BY seq",
        )?;
        let rows = stmt.query_map([change_id], |row| {
            Ok(RevisionRow {
                id: row.get(0)?,
                change_id: row.get(1)?,
                object_type: row.get(2)?,
                object_id: row.get(3)?,
                op: row.get(4)?,
                old_json: row.get(5)?,
                new_json: row.get(6)?,
                seq: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Set a change-set's lifecycle status, optionally stamping
    /// `applied_at` and/or `reverted_by_change_id`.
    ///
    /// Pass `applied_at = Some(t)` when transitioning to `applied`, and
    /// `reverted_by = Some(id)` when marking a change-set reverted by
    /// another. `None` arguments leave the corresponding columns untouched.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_changeset_status(
        &self,
        change_id: &str,
        status: &str,
        applied_at: Option<i64>,
        reverted_by: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE config_changesets
             SET status = ?2,
                 applied_at = COALESCE(?3, applied_at),
                 reverted_by_change_id = COALESCE(?4, reverted_by_change_id)
             WHERE change_id = ?1",
            params![change_id, status, applied_at, reverted_by],
        )?;
        Ok(())
    }

    /// Apply a change-set atomically: run `apply_fn` for each revision in
    /// `seq` order inside one transaction, then stamp `status = 'applied'`
    /// and `applied_at = now`.
    ///
    /// The caller supplies `apply_fn`, the live-object mutation for one
    /// revision (e.g. setting a registry's visibility). If any invocation
    /// fails the whole transaction rolls back and neither the live objects
    /// nor the changeset status change. The closure is `FnMut` so callers
    /// may thread mutable state through it.
    ///
    /// Note that `apply_fn` mutates live objects through a *separate*
    /// connection (it receives only the [`RevisionRow`], not the
    /// transaction), so its writes are not rolled back by a later revision's
    /// failure; the engine stages revisions only for changes whose live
    /// writes are individually idempotent and re-appliable (visibility,
    /// membership grants/revokes), so a partial apply is recoverable by
    /// re-applying.
    ///
    /// # Errors
    ///
    /// Returns an error if loading the revisions fails, if any `apply_fn`
    /// call returns an error, or on database failure committing the
    /// transaction.
    pub fn apply_changeset<F>(&self, change_id: &str, mut apply_fn: F) -> Result<()>
    where
        F: FnMut(&RevisionRow) -> Result<()>,
    {
        let revisions = self.list_revisions(change_id)?;
        for revision in &revisions {
            apply_fn(revision)?;
        }
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE config_changesets SET status = 'applied', applied_at = ?2
             WHERE change_id = ?1",
            params![change_id, unix_now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// List change-sets at or below `scope`, newest first.
    ///
    /// Uses the same segment-boundary containment as [`Database::list_audit`]:
    /// a query at an org scope surfaces change-sets targeting its registries.
    /// The root scope (`""`) lists every change-set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_changesets(&self, scope: &str) -> Result<Vec<ChangesetRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT change_id, actor_kind, actor_id, actor_label, scope, status,
                    summary, created_at, applied_at, reverted_by_change_id
             FROM config_changesets ORDER BY created_at DESC, change_id DESC",
        )?;
        let target = crate::domain::Scope::parse(scope);
        let rows = stmt.query_map([], row_to_changeset)?;
        let mut out = Vec::new();
        for row in rows {
            let row = row?;
            if target.contains(&crate::domain::Scope::parse(&row.scope)) {
                out.push(row);
            }
        }
        Ok(out)
    }
}

/// The outcome of polling a device-authorization grant (RFC 8628).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePollResult {
    /// The user has neither approved nor denied yet.
    Pending,
    /// The user denied the request.
    Denied,
    /// The user approved; carries the minted token's secret.
    Approved(String),
}

/// The wire names of a permission slice, for JSON storage.
fn permission_names(permissions: &[crate::domain::Permission]) -> Vec<&'static str> {
    permissions.iter().map(|p| p.as_str()).collect()
}

/// Parse a JSON array of permission verb names into domain permissions,
/// skipping any unknown verb (forward-compatibility with a newer writer).
fn parse_permission_names(json: &str) -> Vec<crate::domain::Permission> {
    let names: Vec<String> = serde_json::from_str(json).unwrap_or_default();
    names
        .iter()
        .filter_map(|n| crate::auth::permission_from_str(n))
        .collect()
}

/// The column list every `RegistryRecord` query selects, in the order
/// [`row_to_registry`] reads.
const REGISTRY_COLUMNS: &str = "id, slug, source_url, trust_keys, require_signatures, \
     org_id, project_path, visibility, storage_binding_id, prefix";

fn row_to_registry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RegistryRecord> {
    let trust_json: String = row.get(3)?;
    Ok(RegistryRecord {
        id: row.get(0)?,
        slug: row.get(1)?,
        source_url: row.get(2)?,
        trust_keys: serde_json::from_str(&trust_json).unwrap_or_default(),
        require_signatures: row.get::<_, i64>(4)? != 0,
        org_id: row.get(5)?,
        project_path: row.get(6)?,
        visibility: row.get(7)?,
        storage_binding_id: row.get(8)?,
        prefix: row.get(9)?,
    })
}

fn row_to_changeset(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChangesetRow> {
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
    })
}

fn row_to_storage_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<StorageBindingRecord> {
    Ok(StorageBindingRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        root: row.get(4)?,
        created_at: row.get(5)?,
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_register_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        {
            let db = Database::open(&path).unwrap();
            db.register_registry("demo", "file:///srv/demo", &["k".into()], true)
                .unwrap();
        }
        let db = Database::open(&path).unwrap();
        let reg = db.registry_by_slug("demo").unwrap().unwrap();
        assert_eq!(reg.trust_keys, vec!["k".to_string()]);
        assert!(reg.require_signatures);
        assert_eq!(db.index_status(reg.id).unwrap().unwrap().state, "indexing");
    }

    #[test]
    fn snapshot_replace_is_idempotent() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        let package: aos_package::registry::parse::PackageToml = toml::from_str(
            r#"
            [package]
            name = "curl"
            description = "URL transfers"
            license = "MIT"
            maintainer = "aos"
            [[versions]]
            version = "8.5.0"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/abc-curl-8.5.0"
            nar_hash = "sha256:aa"
            nar_size = 10
            closure_size = 20
            source_drv = "/var/lib/store/abc.drv"
            source_nar_hash = "sha256:bb"
            "#,
        )
        .unwrap();
        let snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            description: None,
            caches: vec![("https://cache.example".into(), 40)],
            roster: vec![("alice".into(), "demo:Ed25519:AA".into(), "active".into())],
            packages: vec![package],
            releases: vec![ReleaseRow {
                semver: "1.0.0".into(),
                tag_oid: "t".repeat(64),
                commit_oid: "c".repeat(64),
                signer: None,
                tagged_at: Some(1),
                pack_present: true,
            }],
            channels: vec![ChannelSummary {
                name: "stable".into(),
                frontier: Some("1.0.0".into()),
                partitions: vec![Some("1.0.0".into()); 256],
            }],
            refs_digest: Some("d".repeat(64)),
        };
        db.apply_snapshot(id, &snapshot).unwrap();
        db.apply_snapshot(id, &snapshot).unwrap();

        let packages = db.list_packages(id).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].latest_version.as_deref(), Some("8.5.0"));
        let detail = db.package_detail(id, "curl").unwrap().unwrap();
        assert_eq!(detail.versions[0].platforms[0].platform, "x86_64-linux");
        let channels = db.list_channels(id).unwrap();
        assert_eq!(channels[0].partitions.iter().flatten().count(), 256);
        assert_eq!(db.index_status(id).unwrap().unwrap().state, "fresh");
        assert_eq!(db.list_caches(id).unwrap()[0].1, 40);
        assert!(db.list_releases(id).unwrap()[0].pack_present);
        assert_eq!(
            db.refs_digest(id).unwrap().as_deref(),
            Some(&*"d".repeat(64))
        );
        assert_eq!(db.all_store_hashes(id).unwrap(), vec!["abc".to_string()]);
    }

    #[test]
    fn failure_marks_state_without_dropping_index() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        let snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            ..Default::default()
        };
        db.apply_snapshot(id, &snapshot).unwrap();
        db.mark_index_failed(id, "upstream unreachable").unwrap();
        let status = db.index_status(id).unwrap().unwrap();
        assert_eq!(status.state, "failed");
        assert_eq!(status.error.as_deref(), Some("upstream unreachable"));
        // The last good index survives.
        assert_eq!(
            status.last_indexed_commit.as_deref(),
            Some(&*"c".repeat(64))
        );

        db.mark_index_stale(id, "connection refused").unwrap();
        let status = db.index_status(id).unwrap().unwrap();
        assert_eq!(status.state, "stale");
        assert_eq!(status.error.as_deref(), Some("connection refused"));
        assert_eq!(
            status.last_indexed_commit.as_deref(),
            Some(&*"c".repeat(64))
        );
    }

    #[test]
    fn v1_database_migrates_to_v2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        // Build a v1-only database by hand, with a row in each altered table.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATIONS[0]).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (1);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO registries (slug, source_url, created_at) VALUES ('demo', '/srv', 0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO registry_index (registry_id, state) VALUES (1, 'fresh')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO releases (registry_id, semver, tag_oid, commit_oid)
                 VALUES (1, '1.0.0', 't', 'c')",
                [],
            )
            .unwrap();
        }

        // Reopening migrates to v2 and the new surface works.
        let db = Database::open(&path).unwrap();
        let releases = db.list_releases(1).unwrap();
        assert_eq!(releases.len(), 1);
        assert!(!releases[0].pack_present, "v1 rows default pack_present=0");
        assert!(db.refs_digest(1).unwrap().is_none());
        db.set_channel_floor(1, "stable", "1.0.0").unwrap();
        assert_eq!(
            db.channel_floor(1, "stable").unwrap().as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn v2_database_migrates_to_v3() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        // Build a v2 database by hand with one phase-1 registry row.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATIONS[0]).unwrap();
            conn.execute_batch(MIGRATIONS[1]).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (2);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO registries (slug, source_url, created_at)
                 VALUES ('legacy', '/srv/legacy', 0)",
                [],
            )
            .unwrap();
        }

        // Reopening migrates to v3.
        let db = Database::open(&path).unwrap();
        let conn = db.lock();
        // New tenancy tables exist (querying a missing table would error).
        for table in [
            "orgs",
            "projects",
            "users",
            "user_identities",
            "service_accounts",
            "memberships",
            "invitations",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0, "{table} should start empty");
        }
        // The phase-1 registry became an unowned public registry.
        let (org_id, project_path, visibility): (Option<i64>, String, String) = conn
            .query_row(
                "SELECT org_id, project_path, visibility FROM registries WHERE slug = 'legacy'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(org_id, None);
        assert_eq!(project_path, "");
        assert_eq!(visibility, "public");
    }

    #[test]
    fn v6_database_migrates_to_v7() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        // Build a v6 database by hand (apply migrations v1..=v6).
        {
            let conn = Connection::open(&path).unwrap();
            for m in &MIGRATIONS[..6] {
                conn.execute_batch(m).unwrap();
            }
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (6);",
            )
            .unwrap();
        }

        // Reopening migrates to v7; the configuration-history tables exist
        // and start empty.
        let db = Database::open(&path).unwrap();
        {
            let conn = db.lock();
            for table in ["audit_log", "config_changesets", "config_revisions"] {
                let count: i64 = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 0, "{table} should start empty");
            }
        }
        // The new surface works end to end through the public methods.
        db.create_changeset("cs1", "system", None, "system", "acme", Some("test"))
            .unwrap();
        db.add_revision(
            "cs1",
            "registry",
            "acme/cdn",
            "update",
            Some(r#"{"visibility":"public"}"#),
            Some(r#"{"visibility":"private"}"#),
        )
        .unwrap();
        assert_eq!(db.list_revisions("cs1").unwrap().len(), 1);
        let id = db
            .record_audit(
                "system",
                None,
                "system",
                "test.action",
                "acme",
                Some("cs1"),
                None,
                None,
                Some("d"),
            )
            .unwrap();
        assert!(id > 0);
        assert_eq!(db.list_audit("acme").unwrap().len(), 1);
        assert_eq!(db.list_changesets("acme").unwrap().len(), 1);
    }

    #[test]
    fn audit_and_changeset_scope_containment() {
        let db = Database::open_in_memory().unwrap();
        db.record_audit(
            "system",
            None,
            "system",
            "a",
            "acme/infra/prod/cdn",
            None,
            None,
            None,
            None,
        )
        .unwrap();
        db.record_audit(
            "system", None, "system", "b", "globex", None, None, None, None,
        )
        .unwrap();
        // An org-scoped query surfaces the registry-scoped row but not the
        // sibling org's.
        let rows = db.list_audit("acme").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "a");
        // The root scope lists everything, newest first.
        let all = db.list_audit("").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].action, "b", "newest first");
    }

    #[test]
    fn orgs_projects_and_principals_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme, Inc.").unwrap();
        assert_eq!(db.org_by_slug("acme").unwrap().unwrap().id, org);
        assert!(db.org_by_slug("nope").unwrap().is_none());

        db.create_project(org, "", "Root").unwrap();
        db.create_project(org, "infra", "Infra").unwrap();
        db.create_project(org, "infra/prod", "Prod").unwrap();
        let projects = db.list_projects(org).unwrap();
        assert_eq!(projects.len(), 3);
        assert_eq!(projects[0].path, "");
        assert_eq!(projects[1].path, "infra");
        assert_eq!(projects[2].path, "infra/prod");

        let user = db.create_user("dev@acme.com", Some("Dev")).unwrap();
        assert_eq!(db.user_by_email("dev@acme.com").unwrap(), Some(user));
        assert!(db.user_by_email("ghost@acme.com").unwrap().is_none());

        let sa = db.create_service_account(org, "ci").unwrap();
        assert!(sa > 0);
    }

    #[test]
    fn memberships_grant_revoke_and_list() {
        let db = Database::open_in_memory().unwrap();
        let user = db.create_user("dev@acme.com", None).unwrap();
        db.grant_membership("user", user, "acme", "admin").unwrap();
        db.grant_membership("user", user, "acme/infra", "maintainer")
            .unwrap();
        // Re-granting overwrites the role at the same scope.
        db.grant_membership("user", user, "acme", "owner").unwrap();

        let grants = db.list_memberships_for("user", user).unwrap();
        assert_eq!(
            grants,
            vec![
                ("acme".to_string(), "owner".to_string()),
                ("acme/infra".to_string(), "maintainer".to_string()),
            ]
        );

        // effective_scopes parses into domain types.
        let scopes = db
            .effective_scopes(crate::domain::Principal::user(user))
            .unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(crate::domain::iam::allow(
            &scopes,
            crate::domain::Permission::IamAdmin,
            &crate::domain::Scope::parse("acme/infra/prod/cdn"),
        ));

        // list_members_of_scope returns exact-scope grants only (the
        // org grant at "acme", not the inherited "acme/infra" one).
        let members = db.list_members_of_scope("acme").unwrap();
        assert_eq!(
            members,
            vec![("user".to_string(), user, "owner".to_string())]
        );

        db.revoke_membership("user", user, "acme").unwrap();
        let grants = db.list_memberships_for("user", user).unwrap();
        assert_eq!(
            grants,
            vec![("acme/infra".to_string(), "maintainer".to_string())]
        );
    }

    #[test]
    fn registry_ownership_can_be_set() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        let reg = db.register_registry("cdn", "/srv/cdn", &[], false).unwrap();
        db.set_registry_ownership(reg, Some(org), "infra/prod", "private")
            .unwrap();
        let conn = db.lock();
        let (got_org, path, vis): (Option<i64>, String, String) = conn
            .query_row(
                "SELECT org_id, project_path, visibility FROM registries WHERE id = ?1",
                [reg],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(got_org, Some(org));
        assert_eq!(path, "infra/prod");
        assert_eq!(vis, "private");
    }

    #[test]
    fn invitations_create_accept_and_expire() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        let far_future = unix_now() + 86_400;

        db.create_invitation(
            org,
            "new@acme.com",
            "acme/infra",
            "developer",
            "hash-a",
            far_future,
        )
        .unwrap();
        let accepted = db.accept_invitation("hash-a").unwrap().unwrap();
        assert_eq!(accepted.email, "new@acme.com");
        assert_eq!(accepted.scope, "acme/infra");
        assert_eq!(accepted.role, "developer");
        // A second accept of the same hash is rejected (already accepted).
        assert!(db.accept_invitation("hash-a").unwrap().is_none());
        // Unknown hash is rejected.
        assert!(db.accept_invitation("hash-missing").unwrap().is_none());

        // An already-expired invitation cannot be accepted.
        let past = unix_now() - 10;
        db.create_invitation(org, "late@acme.com", "acme", "viewer", "hash-b", past)
            .unwrap();
        assert!(db.accept_invitation("hash-b").unwrap().is_none());
    }

    #[test]
    fn v3_database_migrates_to_v4() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        // Build a v3 database by hand with one user (FK target for sessions).
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATIONS[0]).unwrap();
            conn.execute_batch(MIGRATIONS[1]).unwrap();
            conn.execute_batch(MIGRATIONS[2]).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (3);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (email, created_at) VALUES ('a@b.com', 0)",
                [],
            )
            .unwrap();
        }
        // Reopening migrates to v4: the auth tables exist and are empty.
        let db = Database::open(&path).unwrap();
        let conn = db.lock();
        for table in ["tokens", "sessions", "device_codes", "magic_links"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0, "{table} should start empty");
        }
    }

    #[test]
    fn tokens_create_validate_revoke_and_list() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().unwrap();
        let owner = Principal::user(7);
        let (id, secret) = db
            .create_token(
                owner,
                "acme/infra",
                &[Permission::Read, Permission::Publish],
                Some("ci"),
                None,
            )
            .unwrap();
        assert!(secret.starts_with("aos_"));

        let auth = db.validate_token(&secret).unwrap().unwrap();
        assert_eq!(auth.token_id, id);
        assert_eq!(auth.owner, owner);
        assert_eq!(auth.scope.as_str(), "acme/infra");
        assert_eq!(
            auth.permissions,
            vec![Permission::Read, Permission::Publish]
        );

        // last_used_at is bumped on validation.
        let used: Option<i64> = db
            .lock()
            .query_row(
                "SELECT last_used_at FROM tokens WHERE id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(used.is_some());

        let list = db.list_tokens_for(owner).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, id);

        db.revoke_token(&id).unwrap();
        // Revoked-now is still inside grace, but a revoked token in the far
        // past would be invalid; here we just confirm the revoke ran.
        assert!(db.list_tokens_for(owner).unwrap().is_empty());

        // Unknown secret is rejected.
        assert!(db.validate_token("aos_deadbeef").unwrap().is_none());
    }

    #[test]
    fn tokens_expired_is_rejected() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().unwrap();
        let past = unix_now() - 10;
        let (_, secret) = db
            .create_token(
                Principal::user(1),
                "acme",
                &[Permission::Read],
                None,
                Some(past),
            )
            .unwrap();
        assert!(db.validate_token(&secret).unwrap().is_none());
    }

    #[test]
    fn tokens_rotation_honors_grace_window() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().unwrap();
        let owner = Principal::user(3);
        let (old_id, old_secret) = db
            .create_token(owner, "acme", &[Permission::Read], Some("c"), None)
            .unwrap();

        let (new_id, new_secret) = db.rotate_token(&old_id).unwrap().unwrap();
        assert_ne!(old_id, new_id);
        assert_ne!(old_secret, new_secret);

        // New token validates and carries the same scope/perms.
        let new_auth = db.validate_token(&new_secret).unwrap().unwrap();
        assert_eq!(new_auth.scope.as_str(), "acme");
        assert_eq!(new_auth.permissions, vec![Permission::Read]);

        // The OLD secret still validates — it was rotated now, but within
        // the grace window.
        assert!(db.validate_token(&old_secret).unwrap().is_some());

        // Force the old token's rotated_at to be older than the grace
        // window: now it is invalid.
        db.lock()
            .execute(
                "UPDATE tokens SET rotated_at = ?2 WHERE id = ?1",
                params![old_id, unix_now() - ROTATION_GRACE_SECS - 1],
            )
            .unwrap();
        assert!(db.validate_token(&old_secret).unwrap().is_none());

        // Rotating an already-rotated token mints again from it (it was
        // never hard-revoked).
        assert!(db.rotate_token(&old_id).unwrap().is_some());
    }

    #[test]
    fn revoked_token_is_denied_immediately_without_grace() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().unwrap();
        let (id, secret) = db
            .create_token(Principal::user(7), "acme", &[Permission::Read], None, None)
            .unwrap();
        assert!(db.validate_token(&secret).unwrap().is_some());
        db.revoke_token(&id).unwrap();
        // A hard revocation cuts off at once — no rotation grace.
        assert!(db.validate_token(&secret).unwrap().is_none());
    }

    #[test]
    fn sessions_create_validate_expire_and_revoke() {
        let db = Database::open_in_memory().unwrap();
        let user = db.create_user("dev@acme.com", None).unwrap();
        let secret = db.create_session(user, 3600, 0).unwrap();
        let session = db.validate_session(&secret).unwrap().unwrap();
        assert_eq!(session.user_id, user);
        assert_eq!(session.auth_level, 0);

        // Elevate sets sudo.
        db.elevate_session(&secret).unwrap();
        assert_eq!(db.validate_session(&secret).unwrap().unwrap().auth_level, 1);

        // Revoke one session.
        db.revoke_session(&secret).unwrap();
        assert!(db.validate_session(&secret).unwrap().is_none());

        // An expired session is rejected.
        let expired = db.create_session(user, -10, 0).unwrap();
        assert!(db.validate_session(&expired).unwrap().is_none());

        // revoke_all clears everything.
        let s1 = db.create_session(user, 3600, 0).unwrap();
        let s2 = db.create_session(user, 3600, 0).unwrap();
        db.revoke_all_user_sessions(user).unwrap();
        assert!(db.validate_session(&s1).unwrap().is_none());
        assert!(db.validate_session(&s2).unwrap().is_none());
    }

    #[test]
    fn device_flow_full_path_with_scope_clamping() {
        use crate::domain::{Permission, Principal, Role, Scope};
        let db = Database::open_in_memory().unwrap();
        let approver = db.create_user("admin@acme.com", None).unwrap();
        // The approver is a maintainer at acme: read+publish, but NOT
        // members.manage.
        let grants = vec![(Scope::parse("acme"), Role::Maintainer)];

        // CLI requests read + publish + members.manage at acme/infra.
        let (device_code, user_code, ttl) = db
            .start_device_authorization(
                "acme/infra",
                &[
                    Permission::Read,
                    Permission::Publish,
                    Permission::MembersManage,
                ],
            )
            .unwrap();
        assert_eq!(ttl, crate::auth::device::DEVICE_CODE_TTL_SECS);
        assert_eq!(user_code.len(), 9);

        // Pending before approval.
        assert_eq!(
            db.poll_device(&device_code).unwrap(),
            DevicePollResult::Pending
        );

        // Approve as the maintainer.
        assert!(db
            .approve_device(&user_code, Principal::user(approver), &grants)
            .unwrap());

        // Poll returns Approved with a token secret.
        let result = db.poll_device(&device_code).unwrap();
        let DevicePollResult::Approved(token_secret) = result else {
            panic!("expected Approved, got {result:?}");
        };

        // The minted token is owned by the approver and clamped: it has
        // read+publish (maintainer at acme covers acme/infra) but NOT
        // members.manage.
        let auth = db.validate_token(&token_secret).unwrap().unwrap();
        assert_eq!(auth.owner, Principal::user(approver));
        assert_eq!(auth.scope.as_str(), "acme/infra");
        assert!(auth.permissions.contains(&Permission::Read));
        assert!(auth.permissions.contains(&Permission::Publish));
        assert!(!auth.permissions.contains(&Permission::MembersManage));
    }

    #[test]
    fn device_flow_deny_and_unknown() {
        use crate::domain::Permission;
        let db = Database::open_in_memory().unwrap();
        let (device_code, user_code, _) = db
            .start_device_authorization("acme", &[Permission::Read])
            .unwrap();
        assert!(db.deny_device(&user_code).unwrap());
        assert_eq!(
            db.poll_device(&device_code).unwrap(),
            DevicePollResult::Denied
        );

        // An unknown user_code cannot be approved or denied.
        assert!(!db
            .approve_device("ZZZZ-9999", crate::domain::Principal::user(1), &[])
            .unwrap());
        assert!(!db.deny_device("ZZZZ-9999").unwrap());
        // An unknown device_code polls as Pending.
        assert_eq!(
            db.poll_device("unknown").unwrap(),
            DevicePollResult::Pending
        );
    }

    #[test]
    fn device_flow_expiry_blocks_approval() {
        use crate::domain::Permission;
        let db = Database::open_in_memory().unwrap();
        let (_device_code, user_code, _) = db
            .start_device_authorization("acme", &[Permission::Read])
            .unwrap();
        // Force the grant to be expired.
        db.lock()
            .execute(
                "UPDATE device_codes SET expires_at = ?1 WHERE user_code = ?2",
                params![unix_now() - 1, user_code],
            )
            .unwrap();
        assert!(!db
            .approve_device(&user_code, crate::domain::Principal::user(1), &[])
            .unwrap());
    }

    #[test]
    fn magic_links_single_use_and_expiry() {
        let db = Database::open_in_memory().unwrap();
        let secret = db.create_magic_link("user@acme.com").unwrap();
        assert_eq!(
            db.consume_magic_link(&secret).unwrap().as_deref(),
            Some("user@acme.com")
        );
        // Second consume fails (already consumed).
        assert!(db.consume_magic_link(&secret).unwrap().is_none());
        // Unknown secret fails.
        assert!(db.consume_magic_link("nope").unwrap().is_none());

        // An expired link cannot be consumed.
        let expired = db.create_magic_link("late@acme.com").unwrap();
        db.lock()
            .execute(
                "UPDATE magic_links SET expires_at = ?1 WHERE email = 'late@acme.com'",
                params![unix_now() - 1],
            )
            .unwrap();
        assert!(db.consume_magic_link(&expired).unwrap().is_none());
    }

    #[test]
    fn channel_floors_persist_and_overwrite() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        assert!(db.channel_floor(id, "stable").unwrap().is_none());
        db.set_channel_floor(id, "stable", "1.0.0").unwrap();
        db.set_channel_floor(id, "stable", "1.2.0").unwrap();
        assert_eq!(
            db.channel_floor(id, "stable").unwrap().as_deref(),
            Some("1.2.0")
        );
    }

    #[test]
    fn validation_runs_record_and_query() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        let run = db
            .record_validation_run(
                id,
                "https://cache.example",
                "presence",
                3,
                &["aaa".into(), "bbb".into()],
                true,
                10,
                11,
            )
            .unwrap();
        // A newer run for the same cache supersedes it.
        db.record_validation_run(
            id,
            "https://cache.example",
            "presence",
            3,
            &[],
            true,
            20,
            21,
        )
        .unwrap();
        db.record_validation_run(id, "file:///srv/cache", "presence", 0, &[], false, 20, 21)
            .unwrap();

        let latest = db.latest_validation_runs(id).unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].cache_url, "file:///srv/cache");
        assert!(!latest[0].reachable);
        assert_eq!(latest[1].cache_url, "https://cache.example");
        assert_eq!(latest[1].missing, 0);
        assert_eq!(
            db.validation_missing(run).unwrap(),
            vec!["aaa".to_string(), "bbb".to_string()]
        );
    }

    #[test]
    fn v4_database_migrates_to_v5() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        // Build a v4 database by hand with one phase-1 file:// registry row.
        {
            let conn = Connection::open(&path).unwrap();
            for migration in &MIGRATIONS[..4] {
                conn.execute_batch(migration).unwrap();
            }
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (4);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO registries (slug, source_url, created_at)
                 VALUES ('legacy', 'file:///srv/legacy', 0)",
                [],
            )
            .unwrap();
        }

        // Reopening migrates to v5: the storage table exists and the
        // phase-1 registry's new columns default to unbound.
        let db = Database::open(&path).unwrap();
        let conn = db.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM storage_bindings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "storage_bindings should start empty");
        let (binding, prefix): (Option<i64>, String) = conn
            .query_row(
                "SELECT storage_binding_id, prefix FROM registries WHERE slug = 'legacy'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(binding, None);
        assert_eq!(prefix, "");
        drop(conn);

        // The legacy registry's surface is still its source_url path.
        let legacy = db.registry_by_slug("legacy").unwrap().unwrap();
        assert_eq!(
            db.registry_surface_root(legacy.id).unwrap(),
            Some(PathBuf::from("/srv/legacy"))
        );
    }

    #[test]
    fn storage_bindings_crud_and_kind_validation() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        let id = db
            .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
            .unwrap();
        let binding = db.storage_binding(id).unwrap().unwrap();
        assert_eq!(binding.name, "primary");
        assert_eq!(binding.kind, "local_fs");
        assert_eq!(binding.root, "/srv/aos-hub");
        assert_eq!(
            db.storage_binding_by_name(org, "primary")
                .unwrap()
                .unwrap()
                .id,
            id
        );
        assert!(db.storage_binding_by_name(org, "nope").unwrap().is_none());

        db.create_storage_binding(org, "secondary", "local_fs", "/srv/other")
            .unwrap();
        let all = db.list_storage_bindings(org).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "primary");
        assert_eq!(all[1].name, "secondary");

        // Unsupported kinds are rejected up front.
        assert!(db
            .create_storage_binding(org, "r2", "external_r2", "s3://bucket")
            .is_err());
    }

    #[test]
    fn surface_root_precedence_managed_file_and_http() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        let binding = db
            .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
            .unwrap();

        // Managed: binding root joined with prefix.
        let managed = db
            .create_managed_registry(
                org,
                "infra/prod",
                "cdn",
                "private",
                Some(binding),
                "infra/prod/cdn",
                &[],
                true,
            )
            .unwrap();
        assert_eq!(
            db.registry_surface_root(managed).unwrap(),
            Some(PathBuf::from("/srv/aos-hub/infra/prod/cdn"))
        );

        // file:// source (no binding): the source path.
        let file = db
            .register_registry("filereg", "file:///srv/file", &[], false)
            .unwrap();
        assert_eq!(
            db.registry_surface_root(file).unwrap(),
            Some(PathBuf::from("/srv/file"))
        );

        // bare path source: also a local surface.
        let bare = db
            .register_registry("barereg", "/srv/bare", &[], false)
            .unwrap();
        assert_eq!(
            db.registry_surface_root(bare).unwrap(),
            Some(PathBuf::from("/srv/bare"))
        );

        // http source: no local surface.
        let http = db
            .register_registry("httpreg", "https://cdn.example/", &[], false)
            .unwrap();
        assert_eq!(db.registry_surface_root(http).unwrap(), None);

        // Binding wins even when a source_url is also present.
        db.set_registry_storage(file, binding, "moved").unwrap();
        assert_eq!(
            db.registry_surface_root(file).unwrap(),
            Some(PathBuf::from("/srv/aos-hub/moved"))
        );

        // Unknown registry id: None.
        assert_eq!(db.registry_surface_root(9999).unwrap(), None);
    }

    #[test]
    fn managed_registry_canonical_slug_and_scope_lookup() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();

        // A traversal-bearing prefix is rejected (defense in depth).
        assert!(db
            .create_managed_registry(org, "infra", "evil", "public", None, "../../etc", &[], true)
            .is_err());

        // With a project path.
        let cdn = db
            .create_managed_registry(org, "infra/prod", "cdn", "public", None, "", &[], true)
            .unwrap();
        let record = db.registry_by_slug("acme/infra/prod/cdn").unwrap().unwrap();
        assert_eq!(record.id, cdn);
        assert_eq!(
            record.source_url, "",
            "managed registries have no source_url"
        );
        assert_eq!(record.org_id, Some(org));
        assert_eq!(record.project_path, "infra/prod");
        assert_eq!(record.visibility, "public");
        // registry_by_scope builds the same canonical slug.
        assert_eq!(
            db.registry_by_scope("acme", "infra/prod", "cdn")
                .unwrap()
                .unwrap()
                .id,
            cdn
        );
        // project_path normalization: leading/trailing slashes collapse.
        assert_eq!(
            db.registry_by_scope("acme", "/infra/prod/", "cdn")
                .unwrap()
                .unwrap()
                .id,
            cdn
        );

        // Org-root registry (empty project path) -> "acme/web".
        let web = db
            .create_managed_registry(org, "", "web", "internal", None, "", &[], true)
            .unwrap();
        assert_eq!(db.registry_by_slug("acme/web").unwrap().unwrap().id, web);
        assert_eq!(
            db.registry_by_scope("acme", "", "web").unwrap().unwrap().id,
            web
        );

        // Duplicate canonical path is rejected.
        assert!(db
            .create_managed_registry(org, "infra/prod", "cdn", "public", None, "", &[], true)
            .is_err());

        // A flat phase-1 slug coexists and resolves by its bare slug.
        db.register_registry("legacy", "/srv/legacy", &[], false)
            .unwrap();
        assert!(db.registry_by_slug("legacy").unwrap().is_some());
        assert!(db
            .registry_by_scope("acme", "", "legacy")
            .unwrap()
            .is_none());
    }

    #[test]
    fn update_channels_replaces_only_channels() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        let snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            releases: vec![ReleaseRow {
                semver: "1.0.0".into(),
                tag_oid: "t".repeat(64),
                commit_oid: "c".repeat(64),
                signer: None,
                tagged_at: Some(1),
                pack_present: false,
            }],
            channels: vec![ChannelSummary {
                name: "stable".into(),
                frontier: Some("1.0.0".into()),
                partitions: vec![Some("1.0.0".into()); 256],
            }],
            ..Default::default()
        };
        db.apply_snapshot(id, &snapshot).unwrap();

        let mut partitions = vec![Some("1.0.0".to_string()); 256];
        partitions[0] = None;
        db.update_channels(
            id,
            &[ChannelSummary {
                name: "stable".into(),
                frontier: Some("1.0.0".into()),
                partitions,
            }],
        )
        .unwrap();

        let channels = db.list_channels(id).unwrap();
        assert_eq!(channels[0].partitions.iter().flatten().count(), 255);
        // Releases (and the rest of the index) are untouched.
        assert_eq!(db.list_releases(id).unwrap().len(), 1);
        assert_eq!(db.index_status(id).unwrap().unwrap().state, "fresh");
    }
}
