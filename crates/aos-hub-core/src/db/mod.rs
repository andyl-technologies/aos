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
//!   mutation, who performed it, and the before/after object snapshots), and
//!   the phase-3d per-org SSO tables `org_idp_configs`, `org_domains`, and
//!   `oidc_flows` (each org's OIDC identity provider with its sealed client
//!   secret, the DNS-TXT-captured domains that route email-first logins to
//!   it, and the short-lived in-flight authorization-code requests), and
//!   the phase-4a `hosted_keys` table (an org's opt-in hub-held Ed25519
//!   signing keys, each holding a sealed seed the hub unseals only to sign,
//!   bound to a registry through the additive `registries.hosted_key_id`
//!   column):
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
//!   `channel_partitions`, `releases`, `key_rosters`, `advertised_caches`
//!   (a registry's flattened advertised cache stack — renamed from `caches`
//!   in v22 when the managed-cache table took that name): derived from the
//!   verified surface by the indexer and safely droppable; a re-index
//!   reconstructs it.
//!
//! Phase-future managed **caches** (v22, RFC-0004 "11-caches") are a
//! first-class sibling of registries — hub-hosted Nix binary caches. Their
//! system-of-record tables (`caches`, `cache_registry_links`,
//! `cache_gc_policy`, manual `cache_gc_roots`) sit alongside `registries`,
//! while `cache_objects` (the narinfo index), `cache_usage`, `cache_gc_runs`,
//! and derived `cache_gc_roots` are rebuildable from a bucket re-scan.
//! - **Operational history** — `validation_runs`, `validation_findings`, and
//!   `repair_jobs` (v14): records of past consistency-validation runs (each
//!   finding flagged `missing` or, at deep depth, `corrupt`) and the repair
//!   attempts that copied missing objects between caches. Not derived from the
//!   surface, but droppable without losing registration state.
//!
//! The phase-future mirroring and frontend topology (v16) splits across these
//! contracts too: `mirror_sources` (a registry's upstream URL + mode — full or
//! pull-through — and the last-sync record) and `frontends` (the direct/proxied
//! domains serving a registry's surfaces) are **system of record**, while
//! `frontend_probes` (the latest reachability/freshness observation per
//! frontend) is a **rebuildable** observation refreshed on every probe.
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
//! [`crate::auth::password`] for the KDF.
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
//! # Hosted signing keys (v10)
//!
//! Phase 4a adds **hosted signing keys** (RFC-0004 "hosted keys"). Signing
//! is client-side by default — the hub holds no private key and a web edit
//! only ever records a *prepared* operation the maintainer signs locally.
//! An org may instead *opt in* to a hub-held key so the hub can advance
//! channels and re-sign tags directly from the web, every use audited.
//!
//! ```text
//! hosted_keys   id 1  org_id 1  key_id "acme-release"
//!               public_key "acme-release:Ed25519:AAAAC3Nz…"
//!               secret_enc "<sealed 32-byte Ed25519 seed>"
//!               created_at 1730000000
//!
//! registries (managed)  slug "acme/infra/prod/cdn"
//!                       hosted_key_id = 1   -- NULL = BYO-key (the default)
//! ```
//!
//! The seed is held **sealed** by a [`crate::auth::seal::SecretSealer`] and
//! unsealed only at the instant of a signature
//! ([`Database::load_hosted_signing_key`]). The `public_key` is the
//! registry trusted-key line operators pin as a trust anchor, so the hub's
//! own signatures verify through the same indexer path
//! ([`aos_registry_surface::tag::verify_signed_tag`]) as any client's. The
//! operations a hosted key unlocks live in the hub's `signing` module; this module
//! only stores and lists the rows.
//!
//! # Outbound webhooks (v11)
//!
//! Phase 4 adds **webhooks** (RFC-0004 "webhooks/notifications"). An org
//! subscribes an HTTP endpoint to a set of registry event types; each event
//! the hub raises ([`crate::webhook::WebhookEvent`]) fans out into a durable
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
//! dispatch/delivery logic lives in [`crate::webhook`]; this module only
//! stores and lists the rows.
//!
//! # Cache freshness probes (v12)
//!
//! Phase-1 "frontend freshness probes". For each committed `[caches]` URL the
//! hub knows, a lightweight reachability probe records whether the cache serves
//! a `nix-cache-info`, how long the probe took, and when it ran. These rows are
//! purely **observational** (rebuildable from the next probe), so they live in
//! the index/derived set rather than the system of record.
//!
//! ```text
//! cache_probes  registry_id 1  cache_url "https://cdn.example.com"
//!               status "ok"  observed_nix_cache_info 1
//!               latency_ms 42  checked_at 1730000000
//! ```
//!
//! `status` is `ok` (reachable, valid `nix-cache-info`), `stale` (reachable but
//! no/empty `nix-cache-info`), or `unreachable` (transport failure or missing
//! file root). The probing logic lives in the hub's `probe` module.
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
//!   registries, and active tokens. A `NULL` cell is unlimited; the upload
//!   facade rejects an over-quota write with `507 Insufficient Storage`
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
// wasm32); `PathBuf` is used by record types on every target.
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::backend::{Backend, Statement};
use crate::dialect::Dialect;
use crate::value::{Row, ToValue};

// SqlxBackend is the native driver (sqlx does not build for wasm32); the
// constructors that build one are native-only. The Worker constructs a
// `Database` from its own D1 `Backend` via [`Database::with_backend`].
#[cfg(not(target_arch = "wasm32"))]
use crate::backend::SqlxBackend;

/// Builds a `Vec<Value>` parameter list from a heterogeneous set of bindable
/// values, mirroring rusqlite's `params!` ergonomics for the [`Backend`] API.
///
/// Each argument is converted via [`ToValue`], so `i64`, `Option<i64>`,
/// `&str`, `String`, `bool`, `u32`, … all bind directly.
macro_rules! vals {
    ($($v:expr),* $(,)?) => {
        [$( ToValue::to_value(&$v) ),*]
    };
}

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

/// Debounce window for [`Database::touch_cache_object`]: an object's
/// `last_accessed_at` is rewritten at most once per hour, so a substituter that
/// re-probes the same narinfo thousands of times an hour costs one write, not
/// thousands. The LRU signal only needs hour-granularity recency.
const LRU_TOUCH_DEBOUNCE_SECS: i64 = 3600;

/// Ordered schema migrations; index = version - 1.
pub const MIGRATIONS: &[&str] = &[
    // v1: initial schema.
    "
    CREATE TABLE registries (
        id          INTEGER PRIMARY KEY,
        slug        TEXT NOT NULL UNIQUE,
        source_url  TEXT NOT NULL,
        trust_keys  LONGTEXT NOT NULL DEFAULT ('[]'),  -- JSON array of name:Ed25519:b64 (unbounded; never truncate)
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
        refs        LONGTEXT NOT NULL,            -- JSON array of store hashes (unbounded; never truncate)
        images      LONGTEXT NOT NULL,            -- JSON array of {format,store_path,nar_hash,nar_size} (unbounded)
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
        public_key  LONGTEXT NOT NULL,            -- name:Alg:<base64> key line (unbounded; never truncate)
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
        -- IDTEXT: security-identity columns, binary-collated on mysql so the
        -- composite PK and `identity_user` lookup match OIDC iss/sub byte-for-
        -- byte. Without it, mysql's default case-insensitive collation would
        -- collapse case-variant `sub` values onto one user_id and let an
        -- attacker log in as the victim (sec M-6). sqlite/postgres are already
        -- case-sensitive. Email is intentionally left case-insensitive (M-7).
        issuer      IDTEXT NOT NULL,              -- OIDC iss
        subject     IDTEXT NOT NULL,              -- OIDC sub
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
        issued_token_secret LONGTEXT              -- the minted secret, delivered once at poll (unbounded; never truncate)
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
    // v8: committed cache-stack expression (RFC-0004 \"Cache stores, stacks,
    // and consistency validation\"). When a registry's committed
    // registry.toml carries a [caches] table in stack form, the indexer parses
    // it into the nestable try/mirror model and stores it here as JSON (see
    // crate::stack), so stack-aware coverage validation can recover the
    // mirror groups without re-reading the surface. NULL for registries whose
    // [caches] is a legacy flat list; the flattened endpoints still
    // populate the caches table either way, so the column is purely additive.
    "
    ALTER TABLE registry_index ADD COLUMN cache_stack LONGTEXT; -- JSON cache stack (unbounded; never truncate)
    ",
    // v9: per-org OIDC SSO (RFC-0004 \"Per-org OIDC SSO\"). Three
    // system-of-record tables that exist nowhere on the registry surface:
    //
    // - org_idp_configs: one IdP per org. The authorization-code + PKCE
    //   endpoints, client id, and the sealed client secret (client_secret_enc;
    //   see crate::auth::seal::SecretSealer), plus the groups->role mapping
    //   (role_map_json) re-evaluated on every SSO login, and the enforce_sso /
    //   allow_jit policy flags. Encrypted at rest; the column never holds the
    //   plaintext secret.
    // - org_domains: DNS-TXT domain capture. A domain is claimed by an org
    //   with a txt_challenge the org publishes; verified_at is stamped once the
    //   challenge is observed (the actual DNS lookup is the caller's, kept
    //   offline-testable — see Database::verify_org_domain). Only verified
    //   domains route email-first logins to the org's IdP.
    // - oidc_flows: short-lived in-flight authorization-code requests, keyed by
    //   the opaque `state`. Holds the PKCE code_verifier and the nonce the
    //   id_token is checked against; single-use (deleted on callback) and
    //   garbage by expires_at (~10 min TTL).
    "
    CREATE TABLE org_idp_configs (
        org_id                INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
        issuer                TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        token_endpoint        TEXT NOT NULL,
        jwks_uri              TEXT NOT NULL,
        client_id             TEXT NOT NULL,
        client_secret_enc     LONGTEXT,                   -- sealed; never plaintext (unbounded; never truncate)
        scopes                TEXT NOT NULL DEFAULT 'openid email profile',
        groups_claim          TEXT,
        role_map_json         LONGTEXT NOT NULL DEFAULT ('{}'), -- OIDC group->role JSON (unbounded; never truncate)
        allow_jit             INTEGER NOT NULL DEFAULT 1,
        enforce_sso           INTEGER NOT NULL DEFAULT 0,
        default_role          TEXT NOT NULL DEFAULT 'viewer',
        created_at            INTEGER NOT NULL,
        updated_at            INTEGER NOT NULL
    );
    CREATE TABLE org_domains (
        domain       TEXT PRIMARY KEY,
        org_id       INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        txt_challenge TEXT NOT NULL,
        verified_at  INTEGER
    );
    CREATE INDEX org_domains_org_idx ON org_domains (org_id);
    CREATE TABLE oidc_flows (
        state          TEXT PRIMARY KEY,
        org_id         INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        nonce          TEXT NOT NULL,
        code_verifier  TEXT NOT NULL,
        redirect_after TEXT,
        created_at     INTEGER NOT NULL,
        expires_at     INTEGER NOT NULL
    );
    ",
    // v10: hosted signing keys (RFC-0004 \"hosted keys\"). An org may enroll a
    // hub-held Ed25519 signing key so the hub itself can advance channels and
    // re-sign tags directly from the web — every use audited. The 32-byte
    // Ed25519 *seed* is held sealed (secret_enc; see crate::auth::oidc::
    // SecretSealer), never plaintext; public_key is the registry trusted-key
    // line (name:Ed25519:<base64>) callers pin as a trust anchor.
    //
    // Hosted keys are strictly opt-in: a registry references one through the
    // additive registries.hosted_key_id column. NULL (the default) keeps the
    // BYO-key behavior — the channel console only ever prepares client-signed
    // operations and the hub holds no key for that registry.
    "
    CREATE TABLE hosted_keys (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        key_id      TEXT NOT NULL,
        public_key  LONGTEXT NOT NULL,            -- name:Ed25519:<base64> trusted-key line (unbounded; never truncate)
        secret_enc  LONGTEXT NOT NULL,            -- sealed 32-byte Ed25519 seed; never plaintext (unbounded; never truncate)
        created_at  INTEGER NOT NULL,
        UNIQUE (org_id, key_id)
    );
    ALTER TABLE registries ADD COLUMN hosted_key_id INTEGER;
    ",
    // v11: outbound webhooks (RFC-0004 phase 4 \"webhooks/notifications\").
    // The system of record for an org's HTTP notification subscriptions plus
    // the at-least-once delivery queue that fans registry events out to them.
    //
    // - webhooks: one subscription. `events` is a JSON array of the event-type
    //   strings the hook wants (e.g. [\"index.completed\",\"channel.advanced\"]);
    //   an empty array means \"all events\". `secret` is the shared secret the
    //   HMAC-SHA256 body signature (X-AOS-Signature) is computed under — it is
    //   sent to the subscriber's own endpoint, so unlike a credential hash it is
    //   stored as the plaintext the signature needs.
    // - webhook_deliveries: the durable delivery queue. Each row is one
    //   attempt-bearing delivery of one event payload to one webhook. `status`
    //   walks pending -> delivered | failed; a non-2xx response increments
    //   `attempts` and schedules `next_attempt_at` with exponential backoff
    //   until the attempt cap, after which it is marked failed. The queue is
    //   the source of truth for the delivery worker and the /metrics gauges.
    "
    CREATE TABLE webhooks (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        url         TEXT NOT NULL,
        secret      LONGTEXT NOT NULL,            -- HMAC-SHA256 signing secret, shared with subscriber (unbounded; never truncate)
        events      TEXT NOT NULL,                -- JSON array of subscribed event-type strings ([] = all)
        active      INTEGER NOT NULL DEFAULT 1,
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX webhooks_org_idx ON webhooks (org_id);
    CREATE TABLE webhook_deliveries (
        id              INTEGER PRIMARY KEY,
        webhook_id      INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
        event           TEXT NOT NULL,            -- the event-type string
        payload         LONGTEXT NOT NULL,        -- the JSON body, as signed and POSTed (unbounded; never truncate)
        status          TEXT NOT NULL,            -- pending|delivered|failed
        response_code   INTEGER,                  -- last HTTP status observed, when any
        attempts        INTEGER NOT NULL DEFAULT 0,
        created_at      INTEGER NOT NULL,
        delivered_at    INTEGER,                  -- set when status becomes delivered
        next_attempt_at INTEGER                   -- earliest retry time for a pending row
    );
    CREATE INDEX webhook_deliveries_due_idx
        ON webhook_deliveries (status, next_attempt_at);
    ",
    // v12: cache freshness probes (phase-1 \"frontend freshness probes\").
    // Observational reachability/latency for each committed [caches] URL,
    // upserted on every probe. Derived/rebuildable, not a system of record.
    "
    CREATE TABLE cache_probes (
        registry_id             INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        cache_url               TEXT NOT NULL,
        status                  TEXT NOT NULL,   -- ok | stale | unreachable
        observed_nix_cache_info INTEGER NOT NULL,-- 1 when nix-cache-info was served
        latency_ms              INTEGER NOT NULL,
        checked_at              INTEGER NOT NULL,
        PRIMARY KEY (registry_id, cache_url)
    );
    ",
    // v13: operations — quotas, instance signup policy, and org soft-delete
    // (RFC-0004 \"Operations: migrations, backup, quotas, observability,
    // offboarding\"). All system of record; none rebuildable from the surface.
    //
    // - org_quotas: per-org caps on hub-managed storage. NULL = unlimited.
    //   Enforced at the upload facade with 507 (the aos-server max_paths
    //   contract) plus registry/token count gates in the create paths.
    // - org_usage: running byte/object totals maintained on each upload. The
    //   counts are approximate (bytes as written); a GC/re-index reconciliation
    //   is a later refinement.
    // - instance_config: instance-wide key/value settings. signup_policy is
    //   'open' or 'invite_only' (default invite_only); gates org creation.
    // - orgs.deleted_at / purge_after: soft-delete with a grace window. A
    //   soft-deleted org stops serving (the serving queries filter it out) but
    //   its data persists until the purge job hard-deletes it past purge_after.
    "
    CREATE TABLE org_quotas (
        org_id         INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
        max_bytes      INTEGER,                  -- NULL = unlimited
        max_objects    INTEGER,                  -- NULL = unlimited
        max_registries INTEGER,                  -- NULL = unlimited
        max_tokens     INTEGER                   -- NULL = unlimited
    );
    CREATE TABLE org_usage (
        org_id       INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
        used_bytes   INTEGER NOT NULL DEFAULT 0,
        object_count INTEGER NOT NULL DEFAULT 0,
        updated_at   INTEGER NOT NULL
    );
    CREATE TABLE instance_config (
        config_key   TEXT PRIMARY KEY,
        value        TEXT NOT NULL
    );
    ALTER TABLE orgs ADD COLUMN deleted_at INTEGER;
    ALTER TABLE orgs ADD COLUMN purge_after INTEGER;
    ",
    // v14: repair jobs (RFC-0004 "Cache stores, stacks, and consistency
    // validation" — the one-click repair that copies missing objects from a
    // member that has them). One row per attempted (cache, hash) repair, so
    // the health page can render a repair-job history alongside validation
    // findings. status is one of pending | done | failed | plan_only:
    //
    // - pending:   recorded but not yet executed.
    // - done:      the object was copied/PUT into the target cache.
    // - failed:    execution attempted and errored (see `error`).
    // - plan_only: a target the hub is not authorized to write (an arbitrary
    //   external http cache with no upload credential); recorded for
    //   visibility but never executed.
    "
    CREATE TABLE repair_jobs (
        id               INTEGER PRIMARY KEY,
        registry_id      INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        cache_url        TEXT NOT NULL,
        store_hash       TEXT NOT NULL,
        source_cache_url TEXT NOT NULL,
        status           TEXT NOT NULL,
        error            TEXT,
        created_at       INTEGER NOT NULL,
        finished_at      INTEGER
    );
    ",
    // v15: git-backed configuration change requests (RFC-0004 "Configuration
    // management", git-backed path). A SQL-only change-set leaves both columns
    // NULL; a git-backed change request records the draft ref the hub wrote and
    // the signed commit oid it points at, so the console and `apr change` can
    // surface and promote it. The draft commit is signed by a per-instance
    // draft-signing key kept in instance_config under 'draft_signing_key' — a
    // sealed Ed25519 seed that is deliberately NOT in any registry's roster, so
    // a draft never verifies for consumers until a maintainer re-signs it with
    // a roster key (`apr change merge`).
    "
    ALTER TABLE config_changesets ADD COLUMN git_ref TEXT;
    ALTER TABLE config_changesets ADD COLUMN git_commit TEXT;
    ",
    // v16: registry mirroring + frontends (RFC-0004 "Mirroring other
    // registries" and "Frontends: direct and proxied domains").
    //
    // - mirror_sources: a registry with a row here is a *mirror* of an upstream
    //   registry. `mode` is 'full' (a scheduled job copies the verified upstream
    //   surface byte-identically into the local binding, immutable-first, and
    //   refuses to flip pointers on a verification failure — consumers keep the
    //   upstream's trust anchors) or 'pullthrough' (a proxied frontend that
    //   fetches-on-miss from upstream, verifies content-addressed payloads by
    //   hash, persists them, and serves). `verify` (default on) gates whether the
    //   full-mirror sync verifies signatures before accepting; `schedule_secs` is
    //   the full-mirror cadence. The last_sync_* columns and `upstream_frontier`
    //   record the most recent sync outcome for the registry health page. System
    //   of record (the upstream URL and mode exist nowhere on the local surface).
    // - frontends: the domains that serve a registry's surfaces (RFC-0004's
    //   `Frontend`). `mode` is 'direct' (the hub is not in the serving path — a
    //   CNAME to an R2 custom domain or CloudFront; the hub only probes it) or
    //   'proxied' (the hub's facade serves it, enabling bearer auth + HTML).
    //   serves_git/serves_cache/serves_web pick the advertised surface subset;
    //   consumer_priority maps to the [caches] priority an advertised cache
    //   frontend would carry (informational here — registry.toml [caches] is
    //   signed tree content the hub never silently edits). UNIQUE(domain,
    //   base_path) keeps one frontend per served URL. System of record.
    // - frontend_probes: the latest reachability/freshness observation per
    //   frontend (RFC-0004's FrontendProbe — observed_frontier + lag_releases vs
    //   the local index frontier), upserted on every probe. Rebuildable.
    "
    CREATE TABLE mirror_sources (
        registry_id      INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
        upstream_url     TEXT NOT NULL,
        mode             TEXT NOT NULL,              -- full | pullthrough
        verify           INTEGER NOT NULL DEFAULT 1,
        schedule_secs    INTEGER NOT NULL DEFAULT 3600,
        last_sync_at     INTEGER,
        last_sync_status TEXT,                       -- ok | failed
        last_sync_error  TEXT,
        upstream_frontier TEXT
    );
    CREATE TABLE frontends (
        id               INTEGER PRIMARY KEY,
        registry_id      INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        domain           TEXT NOT NULL,
        base_path        TEXT NOT NULL DEFAULT '',
        mode             TEXT NOT NULL,              -- direct | proxied
        serves_git       INTEGER NOT NULL DEFAULT 1,
        serves_cache     INTEGER NOT NULL DEFAULT 1,
        serves_web       INTEGER NOT NULL DEFAULT 1,
        consumer_priority INTEGER NOT NULL DEFAULT 100,
        advertised       INTEGER NOT NULL DEFAULT 1,
        created_at       INTEGER NOT NULL,
        UNIQUE (domain, base_path)
    );
    CREATE INDEX frontends_registry_idx ON frontends (registry_id);
    CREATE TABLE frontend_probes (
        frontend_id      INTEGER PRIMARY KEY REFERENCES frontends(id) ON DELETE CASCADE,
        status           TEXT,                       -- ok | stale | unreachable
        observed_frontier TEXT,
        lag_releases     INTEGER,
        latency_ms       INTEGER,
        checked_at       INTEGER
    );
    ",
    // v17: passkeys / WebAuthn (RFC-0004 "Passkeys/WebAuthn"). The hub is its
    // own WebAuthn relying party with a hard `attestation: none` policy (see
    // crate::auth::webauthn), so the only credential material it persists is the
    // public key — never an attestation statement, never a secret. Two tables:
    //
    // - webauthn_credentials: one row per registered passkey. `credential_id`
    //   is the base64url of the authenticator's raw credential id (the lookup
    //   key an assertion arrives with) and is UNIQUE across all users.
    //   `public_key` is the base64 of the credential's COSE public key as the
    //   authenticator emitted it; the verifier re-decodes it on every assertion.
    //   `sign_count` is the authenticator's signature counter, enforced
    //   monotonic on assertion to detect a cloned authenticator. `transports`
    //   and `label` are advisory metadata. ON DELETE CASCADE drops a user's
    //   passkeys when the user is hard-deleted.
    // - webauthn_challenges: short-lived (~5 min) in-flight ceremony state keyed
    //   by the random `challenge` (base64url). `kind` is 'registration' or
    //   'assertion'. `user_id` is the registering user for a registration
    //   ceremony, or NULL for a usernameless (discoverable-credential) assertion
    //   ceremony where the user is resolved from the presented credential.
    //   Single-use: consumed (deleted) on verify; garbage by `expires_at`. This
    //   mirrors oidc_flows (v9) — the same short-lived, single-use ceremony-state
    //   shape, never present on any registry surface.
    "
    CREATE TABLE webauthn_credentials (
        id            INTEGER PRIMARY KEY,
        user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id TEXT NOT NULL UNIQUE,         -- base64url of the raw cred id
        public_key    LONGTEXT NOT NULL,            -- base64 of the COSE public key (RSA keys exceed 255 chars; never truncate)
        sign_count    INTEGER NOT NULL DEFAULT 0,   -- authenticator signature counter
        transports    TEXT,                         -- advisory: JSON array of transports
        label         TEXT,                         -- advisory: human label
        created_at    INTEGER NOT NULL,
        last_used_at  INTEGER
    );
    CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);
    CREATE TABLE webauthn_challenges (
        challenge   TEXT PRIMARY KEY,               -- base64url random challenge
        user_id     INTEGER,                        -- registering user, or NULL (usernameless assertion)
        kind        TEXT NOT NULL,                  -- 'registration' | 'assertion'
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    );
    ",
    // v18: email + password login (RFC-0004, operator-requested reversal of the
    // original "no passwords" stance). One nullable column on `users` holds the
    // Argon2id PHC string for accounts that have set a password; NULL means no
    // password is set and the password login path fails generically for that
    // user (the account still logs in via magic link / passkey / SSO). Only the
    // one-way hash is ever stored — never the plaintext — so a database leak
    // never yields a usable credential. See crate::auth::password for the KDF.
    "
    ALTER TABLE users ADD COLUMN password_hash TEXT;
    ",
    // v19: record the source derivation store path per platform artifact, so
    // the package detail page can surface and link the derivation that
    // produced each output (RFC-0004 "package browser" parity with the
    // nixos-search source/derivation link). The column defaults to the empty
    // string for rows written before this migration; re-indexing backfills it.
    "
    ALTER TABLE version_platforms ADD COLUMN source_drv TEXT NOT NULL DEFAULT '';
    ",
    // v20: a longer README-style preamble for a registry, committed in
    // `registry.toml` as `[registry] readme`, shown above the registry home.
    // Nullable; re-indexing backfills it from the surface.
    "
    ALTER TABLE registry_index ADD COLUMN readme TEXT;
    ",
    // v21: cross-process publish leases (RFC-0004 Phase 5 "later phase
    // multi-process" lease). Serializes a registry's mutable-pointer flips
    // across worker isolates / hub replicas, replacing the process-local
    // in-memory lease that cannot serialize when two publishers land on
    // different isolates. One live lease per registry; `holder_token_id` is the
    // JWT `sub` that holds it and `deadline` is the unix-seconds expiry after
    // which another token may take over. The native single-replica hub still
    // uses the in-memory lease; this table backs the Worker's D1 lease.
    "
    CREATE TABLE publish_leases (
        registry_id     INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
        holder_token_id TEXT    NOT NULL,
        deadline        INTEGER NOT NULL
    );
    ",
    // v22: managed caches (RFC-0004 "11-caches"). A cache is a first-class
    // sibling of a registry — a hub-hosted Nix binary cache (nix-cache-info +
    // content-addressed NARs + Ed25519-signed narinfo) backed by a storage
    // binding, optionally signed by a hosted key, exposed through frontends.
    //
    // The pre-existing rebuildable `caches` table (the flattened advertised
    // cache stack) is renamed `advertised_caches` to free the `caches` name for
    // the managed object; it is rebuilt from each registry's committed
    // `[caches]` on every index, so the rename loses no system-of-record
    // data. `cache_probes`/validation reference a `cache_url` *string*, not a
    // foreign key, so they are unaffected.
    //
    // SoR: `caches`, `cache_registry_links`, `cache_gc_policy`, and the manual
    // rows of `cache_gc_roots`. Rebuildable from a bucket re-scan: `cache_objects`
    // (the narinfo index), `cache_usage`, `cache_gc_runs`, and the `derived` rows
    // of `cache_gc_roots`.
    "
    ALTER TABLE caches RENAME TO advertised_caches;

    CREATE TABLE caches (
        id                 INTEGER PRIMARY KEY,
        org_id             INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
        slug               TEXT    NOT NULL UNIQUE,
        name               TEXT    NOT NULL,
        storage_binding_id INTEGER NOT NULL REFERENCES storage_bindings(id),
        prefix             TEXT    NOT NULL,
        hosted_key_id      INTEGER REFERENCES hosted_keys(id),
        visibility         TEXT    NOT NULL,
        priority           INTEGER NOT NULL DEFAULT 40,
        compression        TEXT    NOT NULL DEFAULT 'zstd',
        want_mass_query    INTEGER NOT NULL DEFAULT 1,
        created_at         INTEGER NOT NULL,
        deleted_at         INTEGER,
        purge_after        INTEGER
    );

    CREATE TABLE cache_registry_links (
        cache_id       INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        registry_id    INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        roots_packages INTEGER NOT NULL DEFAULT 0,
        advertised     INTEGER NOT NULL DEFAULT 0,
        created_at     INTEGER NOT NULL,
        PRIMARY KEY (cache_id, registry_id)
    );

    CREATE TABLE cache_gc_policy (
        cache_id              INTEGER PRIMARY KEY REFERENCES caches(id) ON DELETE CASCADE,
        max_bytes             INTEGER,
        max_objects           INTEGER,
        ttl_unreferenced_secs INTEGER,
        keep_release_versions INTEGER,
        keep_channel_frontier INTEGER NOT NULL DEFAULT 1,
        schedule_secs         INTEGER,
        updated_at            INTEGER NOT NULL
    );

    CREATE TABLE cache_gc_roots (
        id         INTEGER PRIMARY KEY,
        cache_id   INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        store_hash TEXT    NOT NULL,
        root_kind  TEXT    NOT NULL,
        root_ref   TEXT    NOT NULL,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        UNIQUE (cache_id, store_hash, root_kind, root_ref)
    );

    CREATE TABLE cache_objects (
        cache_id         INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        store_hash       TEXT    NOT NULL,
        store_name       TEXT    NOT NULL,
        nar_url          TEXT    NOT NULL,
        nar_hash         TEXT    NOT NULL,
        nar_size         INTEGER NOT NULL,
        file_hash        TEXT    NOT NULL,
        file_size        INTEGER NOT NULL,
        compression      TEXT    NOT NULL,
        deriver          TEXT,
        refs             TEXT    NOT NULL,
        sig              TEXT,
        ca               TEXT,
        uploaded_at      INTEGER NOT NULL,
        last_accessed_at INTEGER,
        PRIMARY KEY (cache_id, store_hash)
    );
    CREATE INDEX idx_cache_objects_file_hash ON cache_objects (cache_id, file_hash);
    CREATE INDEX idx_cache_objects_name      ON cache_objects (cache_id, store_name);

    CREATE TABLE cache_usage (
        cache_id     INTEGER PRIMARY KEY REFERENCES caches(id) ON DELETE CASCADE,
        used_bytes   INTEGER NOT NULL DEFAULT 0,
        object_count INTEGER NOT NULL DEFAULT 0,
        updated_at   INTEGER NOT NULL
    );

    CREATE TABLE cache_gc_runs (
        id              INTEGER PRIMARY KEY,
        cache_id        INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        started_at      INTEGER NOT NULL,
        finished_at     INTEGER,
        status          TEXT    NOT NULL,
        error           TEXT,
        scanned         INTEGER NOT NULL DEFAULT 0,
        retained        INTEGER NOT NULL DEFAULT 0,
        deleted_objects INTEGER NOT NULL DEFAULT 0,
        freed_bytes     INTEGER NOT NULL DEFAULT 0
    );
    ",
    // v23: storage-binding access mode (RFC-0004 "11-caches", frontend slice).
    // A binding is `public` (its objects are reachable at a stable origin URL —
    // a public bucket / CDN, eligible for a Direct frontend) or `private` (only
    // the hub may read it; reads must be proxied or presigned, never Direct).
    // `public_base_url` is the origin a Direct frontend rewrites to for a public
    // binding; `credential_ref` names the sealed credential (in `hosted_keys` /
    // a secret store) the hub uses to sign authenticated-origin reads for a
    // private binding. Additive columns with safe defaults — existing bindings
    // stay `public` (today's behavior), so this migration is backwards-neutral.
    "
    ALTER TABLE storage_bindings ADD COLUMN access TEXT NOT NULL DEFAULT 'public';
    ALTER TABLE storage_bindings ADD COLUMN public_base_url TEXT;
    ALTER TABLE storage_bindings ADD COLUMN credential_ref TEXT;
    ",
    // v24: cache frontends (RFC-0004 "11-caches", frontend slice). A frontend
    // may front a managed *cache* instead of a registry. `registry_id` was
    // `NOT NULL`; SQLite cannot relax a column constraint in place, so this is
    // the documented table rebuild: a new `frontends` with `registry_id` and a
    // new `cache_id` both nullable and a CHECK enforcing **exactly one** target,
    // copy the rows (all existing rows are registry frontends → `cache_id` NULL),
    // drop, rename, re-create the indexes. Row ids are preserved so any external
    // reference stays valid. NOTE: dropping the old `frontends` cascades through
    // `frontend_probes`' `ON DELETE CASCADE`, clearing probe rows — these are
    // *rebuildable* observations the probe job re-populates on its next tick, so
    // no system-of-record data is lost.
    "
    CREATE TABLE frontends_new (
        id               INTEGER PRIMARY KEY,
        registry_id      INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id         INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        domain           TEXT NOT NULL,
        base_path        TEXT NOT NULL DEFAULT '',
        mode             TEXT NOT NULL,
        serves_git       INTEGER NOT NULL DEFAULT 1,
        serves_cache     INTEGER NOT NULL DEFAULT 1,
        serves_web       INTEGER NOT NULL DEFAULT 1,
        consumer_priority INTEGER NOT NULL DEFAULT 100,
        advertised       INTEGER NOT NULL DEFAULT 1,
        created_at       INTEGER NOT NULL,
        CHECK ((registry_id IS NULL) <> (cache_id IS NULL)),
        UNIQUE (domain, base_path)
    );
    INSERT INTO frontends_new
        (id, registry_id, cache_id, domain, base_path, mode, serves_git,
         serves_cache, serves_web, consumer_priority, advertised, created_at)
        SELECT id, registry_id, NULL, domain, base_path, mode, serves_git,
               serves_cache, serves_web, consumer_priority, advertised, created_at
        FROM frontends;
    DROP TABLE frontends;
    ALTER TABLE frontends_new RENAME TO frontends;
    CREATE INDEX frontends_registry_idx ON frontends (registry_id);
    CREATE INDEX frontends_cache_idx ON frontends (cache_id);
    ",
    // v25: frontend proxy settings (RFC-0004 "11-caches", proxy slice). A
    // `proxied` frontend's behavior tuning — timeouts, streaming, body cap,
    // retries/failover, Range/Cache-Control passthrough — is carried as a JSON
    // `proxy_config` blob (NULL = conservative defaults), and `is_primary` marks
    // the preferred frontend a consumer should reach first. Additive columns
    // with safe defaults, so existing frontends keep today's behavior.
    "
    ALTER TABLE frontends ADD COLUMN proxy_config TEXT;
    ALTER TABLE frontends ADD COLUMN is_primary INTEGER NOT NULL DEFAULT 0;
    ",
    // v26: per-registry crawl policy and custom llms.txt (RFC-0004 registry
    // hub, robots/llms slice). `crawl_policy` is the three-valued
    // allow_all|allow_no_ai|deny_all posture backing the generated robots.txt;
    // `llms_txt_body`, when non-NULL, is an operator-authored llms.txt served
    // verbatim instead of the generated document. Additive with a permissive
    // default, so existing registries keep allow-all crawling.
    "
    ALTER TABLE registries ADD COLUMN crawl_policy TEXT NOT NULL DEFAULT 'allow_all';
    ALTER TABLE registries ADD COLUMN llms_txt_body TEXT;
    ",
    // v27: a managed cache may use the deployment's DEFAULT storage instead of a
    // custom storage binding, exactly as a registry does — so `storage_binding_id`
    // becomes nullable (NULL = default storage; the surface roots on the
    // deployment bucket / default storage root by the cache's prefix). SQLite
    // cannot drop a column's NOT NULL in place, so the table is recreated (FK
    // enforcement is off in this connection, so the child tables that reference
    // caches(id) are undisturbed — they re-resolve to the renamed table by name).
    "
    CREATE TABLE caches_v27 (
        id                 INTEGER PRIMARY KEY,
        org_id             INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
        slug               TEXT    NOT NULL UNIQUE,
        name               TEXT    NOT NULL,
        storage_binding_id INTEGER REFERENCES storage_bindings(id),
        prefix             TEXT    NOT NULL,
        hosted_key_id      INTEGER REFERENCES hosted_keys(id),
        visibility         TEXT    NOT NULL,
        priority           INTEGER NOT NULL DEFAULT 40,
        compression        TEXT    NOT NULL DEFAULT 'zstd',
        want_mass_query    INTEGER NOT NULL DEFAULT 1,
        created_at         INTEGER NOT NULL,
        deleted_at         INTEGER,
        purge_after        INTEGER
    );
    INSERT INTO caches_v27
        (id, org_id, slug, name, storage_binding_id, prefix, hosted_key_id,
         visibility, priority, compression, want_mass_query, created_at,
         deleted_at, purge_after)
        SELECT id, org_id, slug, name, storage_binding_id, prefix, hosted_key_id,
               visibility, priority, compression, want_mass_query, created_at,
               deleted_at, purge_after
        FROM caches;
    DROP TABLE caches;
    ALTER TABLE caches_v27 RENAME TO caches;
    ",
    // v28: the rate-limiter fixed-window counter table (RFC-0004 abuse
    // throttling). The Cloudflare Worker previously created this lazily on every
    // request (a `CREATE TABLE IF NOT EXISTS` D1 round-trip per request, even on
    // read-only browse pages that never meter); owning it in the schema lets a
    // freshly `init`-ed deployment skip that DDL entirely. `IF NOT EXISTS` keeps
    // the migration idempotent over a deployment whose Worker already created the
    // table before this migration shipped (the Worker still self-heals an
    // older D1 via its isolate-guarded lazy create). See the `aos-hub-worker`
    // `workerlimit` module for the column semantics.
    "
    CREATE TABLE IF NOT EXISTS rate_limits (
        class  TEXT    NOT NULL,
        key    TEXT    NOT NULL,
        window INTEGER NOT NULL,
        count  INTEGER NOT NULL,
        PRIMARY KEY (class, key, window)
    );
    ",
    // v29: storage-binding frontends (RFC-0004 §12 "storage-binding frontends").
    // A frontend may now front a *storage binding* (a bucket's public CDN
    // origin) instead of a single registry/cache, so every registry/cache
    // stored in that binding inherits a direct-from-bucket frontend with its
    // object paths derived from its own `prefix`. `registry_id` was one of two
    // nullable targets under a 2-way XOR CHECK; SQLite cannot relax a CHECK in
    // place, so this is the documented table rebuild (cf. v24): a third nullable
    // target `storage_binding_id` and a portable "exactly one target" CHECK
    // (CASE-summed so it holds on sqlite/postgres/mysql alike). All existing
    // rows are registry/cache frontends → `storage_binding_id` NULL. Row ids are
    // preserved. As in v24 the drop cascades `frontend_probes` (rebuildable
    // observations the probe job re-populates), so no system-of-record is lost.
    "
    CREATE TABLE frontends_new (
        id               INTEGER PRIMARY KEY,
        registry_id      INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id         INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        storage_binding_id INTEGER REFERENCES storage_bindings(id) ON DELETE CASCADE,
        domain           TEXT NOT NULL,
        base_path        TEXT NOT NULL DEFAULT '',
        mode             TEXT NOT NULL,
        serves_git       INTEGER NOT NULL DEFAULT 1,
        serves_cache     INTEGER NOT NULL DEFAULT 1,
        serves_web       INTEGER NOT NULL DEFAULT 1,
        consumer_priority INTEGER NOT NULL DEFAULT 100,
        advertised       INTEGER NOT NULL DEFAULT 1,
        proxy_config     TEXT,
        is_primary       INTEGER NOT NULL DEFAULT 0,
        created_at       INTEGER NOT NULL,
        CHECK ((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN storage_binding_id IS NULL THEN 0 ELSE 1 END) = 1),
        UNIQUE (domain, base_path)
    );
    INSERT INTO frontends_new
        (id, registry_id, cache_id, storage_binding_id, domain, base_path, mode,
         serves_git, serves_cache, serves_web, consumer_priority, advertised,
         proxy_config, is_primary, created_at)
        SELECT id, registry_id, cache_id, NULL, domain, base_path, mode,
               serves_git, serves_cache, serves_web, consumer_priority, advertised,
               proxy_config, is_primary, created_at
        FROM frontends;
    DROP TABLE frontends;
    ALTER TABLE frontends_new RENAME TO frontends;
    CREATE INDEX frontends_registry_idx ON frontends (registry_id);
    CREATE INDEX frontends_cache_idx ON frontends (cache_id);
    CREATE INDEX frontends_storage_idx ON frontends (storage_binding_id);
    ",
    // v30: the instance default storage becomes a real, editable binding row
    // (RFC-0004 §12). `org_id` becomes nullable (an instance-level binding has
    // no owning org) and a new `is_instance_default` flag marks the singleton
    // row that registries/caches with `storage_binding_id IS NULL` inherit
    // frontends from — so the default bucket can carry a `public_base_url` +
    // frontends and be edited through the same form as custom bindings.
    // Surface-root resolution is UNCHANGED: a NULL `storage_binding_id` still
    // means "default storage via the runtime port"; this row only anchors the
    // default's frontends and editable settings. SQLite cannot relax
    // `org_id NOT NULL` in place, so the table is rebuilt exactly as v27 rebuilt
    // `caches` (FK enforcement is off in this connection, so the child tables
    // referencing storage_bindings(id) re-resolve to the renamed table by name;
    // ids are preserved). The seeded row's `kind`/`root` are placeholders the
    // deploy and the settings UI correct to the runtime's actual default
    // storage; it is seeded `private` so it is never Direct-eligible until an
    // operator explicitly publishes it.
    "
    CREATE TABLE storage_bindings_new (
        id              INTEGER PRIMARY KEY,
        org_id          INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
        name            TEXT NOT NULL,
        kind            TEXT NOT NULL,
        root            TEXT NOT NULL,
        access          TEXT NOT NULL DEFAULT 'public',
        public_base_url TEXT,
        credential_ref  TEXT,
        is_instance_default INTEGER NOT NULL DEFAULT 0,
        created_at      INTEGER NOT NULL,
        UNIQUE (org_id, name)
    );
    INSERT INTO storage_bindings_new
        (id, org_id, name, kind, root, access, public_base_url, credential_ref,
         is_instance_default, created_at)
        SELECT id, org_id, name, kind, root, access, public_base_url, credential_ref,
               0, created_at
        FROM storage_bindings;
    DROP TABLE storage_bindings;
    ALTER TABLE storage_bindings_new RENAME TO storage_bindings;
    INSERT INTO storage_bindings
        (org_id, name, kind, root, access, public_base_url, is_instance_default, created_at)
        VALUES (NULL, 'default', 'r2', '', 'private', NULL, 1, 0);
    ",
    // v31: per-consumer advertise toggle for an inherited storage frontend
    // (RFC-0004 §12). A registry/cache stored in a binding inherits that
    // binding's frontends by default; this flag lets a specific consumer opt out
    // of advertising the *inherited* one (its own per-consumer frontends are
    // unaffected) — e.g. to keep a particular registry hub-proxied even though
    // its bucket is public. Additive columns default to advertise (today's
    // behavior), so this is backwards-neutral.
    "
    ALTER TABLE registries ADD COLUMN advertise_storage_frontend INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE caches ADD COLUMN advertise_storage_frontend INTEGER NOT NULL DEFAULT 1;
    ",
    // v32: PR-style review surface for git-backed config change requests
    // (RFC-0004 "Web change requests"). Three additive columns on
    // config_changesets carry the human title/body a proposer types when
    // opening a change (the git commit message stays the deterministic
    // `config: edit ...` summary) and a `closed_at` timestamp.
    //
    // `closed_at` is an ORTHOGONAL axis, deliberately NOT a new `status` value:
    // the indexer auto-merges a draft via mark_changeset_applied_commit guarded
    // `WHERE status = 'draft'`, so a `status='closed'` row whose ref is later
    // promoted by `apr change merge` would never flip to applied. Modeling
    // "withdrawn" as `closed_at IS NOT NULL` (status untouched) keeps auto-merge
    // armed; reopen clears `closed_at` and a reopened→merged change still flips.
    //
    // change_comments and change_reviews are the discussion + advisory-review
    // log a change accrues in the console. Reviews are advisory only — there is
    // no server-side merge, so an approval gates nothing; it is recorded for the
    // timeline. Both cascade-delete with their changeset.
    "
    ALTER TABLE config_changesets ADD COLUMN title TEXT;        -- PR title (NULL for pre-v32 rows)
    ALTER TABLE config_changesets ADD COLUMN body TEXT;         -- PR description (plain text)
    ALTER TABLE config_changesets ADD COLUMN closed_at INTEGER; -- set on close; NULL when open/reopened
    CREATE TABLE change_comments (
        id          INTEGER PRIMARY KEY,
        change_id   TEXT NOT NULL REFERENCES config_changesets(change_id) ON DELETE CASCADE,
        actor_kind  TEXT NOT NULL,
        actor_id    INTEGER,
        actor_label TEXT NOT NULL,
        body        TEXT NOT NULL,
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX change_comments_change_idx ON change_comments (change_id, id);
    CREATE TABLE change_reviews (
        id          INTEGER PRIMARY KEY,
        change_id   TEXT NOT NULL REFERENCES config_changesets(change_id) ON DELETE CASCADE,
        actor_kind  TEXT NOT NULL,
        actor_id    INTEGER,
        actor_label TEXT NOT NULL,
        verdict     TEXT NOT NULL,                              -- approve | request_changes
        body        TEXT,                                       -- optional review note
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX change_reviews_change_idx ON change_reviews (change_id, id);
    ",
    // v33: rename storage_bindings.public_base_url -> endpoint (RFC-0004 §12
    // follow-up). The column only ever held the S3/R2 API endpoint the hub
    // writes objects through and presigns reads against (see `s3surface`) — it
    // was never a separate public read origin. Consumer-facing read URLs live
    // in `frontends`. The old name, plus a serving-page field labeled "public
    // base URL" with a CDN-domain placeholder, invited operators to overwrite
    // the API endpoint with a CDN domain, silently breaking the write/presign
    // path. Renaming the column makes its single role honest. SQLite (>=3.25)
    // and D1 support RENAME COLUMN directly — no table rebuild needed.
    "
    ALTER TABLE storage_bindings RENAME COLUMN public_base_url TO endpoint;
    ",
    // v34: RFC-0012 topology foundation. This is intentionally additive: the
    // existing runtime continues to use the v33 binding/frontend/cache-link
    // representation until the coordinated hard cutover switches every
    // interface and then removes those legacy objects. New code may build and
    // test the final resource boundaries without a production dual-read path.
    "
    ALTER TABLE channels ADD COLUMN active INTEGER NOT NULL DEFAULT 1;

    CREATE TABLE domains (
        id                   INTEGER PRIMARY KEY,
        org_id               INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
        hostname             KEYTEXT255 NOT NULL UNIQUE,
        desired_dns_provider KEYTEXT64,
        observed_dns_state   KEYTEXT32 NOT NULL DEFAULT 'unconfigured',
        desired_tls_provider KEYTEXT64,
        observed_tls_state   KEYTEXT32 NOT NULL DEFAULT 'unconfigured',
        access_provider_json LONGTEXT NOT NULL DEFAULT ('{}'),
        verified_at          INTEGER,
        created_at           INTEGER NOT NULL,
        updated_at           INTEGER NOT NULL,
        resource_version     INTEGER NOT NULL DEFAULT 1,
        CHECK (observed_dns_state IN ('unconfigured', 'pending', 'verified', 'failed')),
        CHECK (observed_tls_state IN ('unconfigured', 'pending', 'active', 'failed')),
        CHECK ((verified_at IS NULL AND NOT (
                observed_dns_state = 'verified' AND observed_tls_state = 'active'))
            OR (verified_at IS NOT NULL
                AND observed_dns_state = 'verified' AND observed_tls_state = 'active'))
    );
    CREATE INDEX domains_org_idx ON domains (org_id, hostname);

    -- Publication rows have no general-purpose CRUD API. The future atomic
    -- publisher is the sole intended writer; ordinary topology writes may
    -- only reference a ready same-registry publication through guarded SQL.
    CREATE TABLE registry_publications (
        publication_id       KEYTEXT64 PRIMARY KEY,
        registry_id          INTEGER NOT NULL REFERENCES registries(id),
        ordinal              INTEGER NOT NULL,
        generation           KEYTEXT128 NOT NULL,
        manifest_digest      KEYTEXT128 NOT NULL,
        refs_digest          KEYTEXT128 NOT NULL,
        default_commit       KEYTEXT128,
        parent_publication_id KEYTEXT64,
        state                KEYTEXT32 NOT NULL,
        mutation_version     INTEGER NOT NULL DEFAULT 0,
        created_at           INTEGER NOT NULL,
        completed_at         INTEGER,
        retired_at           INTEGER,
        CHECK (ordinal > 0),
        CHECK (state IN ('preparing', 'writing_pointers', 'ready', 'failed', 'retired')),
        CHECK ((state IN ('preparing', 'writing_pointers')
                AND completed_at IS NULL AND retired_at IS NULL)
            OR (state = 'ready' AND completed_at IS NOT NULL AND retired_at IS NULL)
            OR (state = 'failed' AND completed_at IS NOT NULL AND retired_at IS NULL)
            OR (state = 'retired' AND completed_at IS NOT NULL
                AND retired_at IS NOT NULL AND retired_at >= completed_at)),
        UNIQUE (registry_id, ordinal),
        UNIQUE (registry_id, generation),
        UNIQUE (registry_id, manifest_digest),
        UNIQUE (publication_id, registry_id),
        FOREIGN KEY (parent_publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id)
    );

    CREATE TABLE registry_publication_state (
        registry_id           INTEGER PRIMARY KEY REFERENCES registries(id),
        current_publication_id KEYTEXT64,
        next_ordinal          INTEGER NOT NULL DEFAULT 1,
        resource_version      INTEGER NOT NULL DEFAULT 1,
        updated_at            INTEGER NOT NULL,
        CHECK (next_ordinal > 0),
        FOREIGN KEY (current_publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id)
    );

    CREATE TABLE registry_index_publication_state (
        registry_id   INTEGER PRIMARY KEY REFERENCES registry_index(registry_id),
        publication_id KEYTEXT64 NOT NULL,
        FOREIGN KEY (publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id)
    );

    CREATE TABLE surface_placements (
        id                   INTEGER PRIMARY KEY,
        registry_id          INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id             INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        primary_registry_id  INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        primary_cache_id     INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        name                 KEYTEXT64 NOT NULL,
        storage_binding_id   INTEGER NOT NULL REFERENCES storage_bindings(id),
        prefix               KEYTEXT512 NOT NULL,
        role                 KEYTEXT32 NOT NULL,
        state                KEYTEXT32 NOT NULL,
        completeness         KEYTEXT32 NOT NULL,
        partition_rule_json  LONGTEXT,
        mutable_publication_id KEYTEXT64,
        read_enabled         INTEGER NOT NULL DEFAULT 1,
        write_enabled        INTEGER NOT NULL DEFAULT 0,
        read_order           INTEGER NOT NULL DEFAULT 0,
        write_order          INTEGER NOT NULL DEFAULT 0,
        created_at           INTEGER NOT NULL,
        updated_at           INTEGER NOT NULL,
        resource_version     INTEGER NOT NULL DEFAULT 1,
        CHECK ((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
        CHECK ((role = 'primary'
                AND ((registry_id IS NOT NULL
                      AND primary_registry_id = registry_id
                      AND primary_cache_id IS NULL)
                  OR (cache_id IS NOT NULL
                      AND primary_cache_id = cache_id
                      AND primary_registry_id IS NULL)))
            OR (role <> 'primary'
                AND primary_registry_id IS NULL
                AND primary_cache_id IS NULL)),
        CHECK (role IN ('primary', 'replica', 'shard', 'archive')),
        CHECK (state IN ('provisioning', 'syncing', 'ready', 'degraded',
                         'draining', 'offline')),
        CHECK (completeness IN ('complete', 'partial', 'unknown')),
        CHECK ((role = 'shard' AND partition_rule_json IS NOT NULL)
            OR (role <> 'shard' AND partition_rule_json IS NULL)),
        CHECK ((role = 'primary' AND write_enabled = 1)
            OR (role <> 'primary' AND write_enabled = 0)),
        CHECK (role <> 'archive' OR read_enabled = 0),
        CHECK (role <> 'shard' OR completeness = 'partial'),
        -- v34 deliberately rejects every physical-location collision. An
        -- equivalence record is evidence, not authority to create an alias;
        -- a later reviewed alias workflow can replace this with a canonical
        -- physical-location resource without making ordinary writes unsafe.
        UNIQUE (storage_binding_id, prefix),
        UNIQUE (registry_id, name),
        UNIQUE (cache_id, name),
        UNIQUE (primary_registry_id),
        UNIQUE (primary_cache_id),
        UNIQUE (id, registry_id),
        FOREIGN KEY (mutable_publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id)
    );
    CREATE INDEX surface_placements_registry_idx
        ON surface_placements (registry_id, read_order, id);
    CREATE INDEX surface_placements_cache_idx
        ON surface_placements (cache_id, read_order, id);

    CREATE TABLE placement_policies (
        id               INTEGER PRIMARY KEY,
        registry_id      INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id         INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        name             KEYTEXT64 NOT NULL,
        kind             KEYTEXT32 NOT NULL,
        config_json      LONGTEXT NOT NULL DEFAULT ('{}'),
        resource_version INTEGER NOT NULL DEFAULT 1,
        created_at       INTEGER NOT NULL,
        updated_at       INTEGER NOT NULL,
        CHECK ((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
        CHECK (kind IN ('ordered_failover', 'latency_preferred',
                        'hash_partition', 'local_then_remote')),
        UNIQUE (registry_id, name),
        UNIQUE (cache_id, name)
    );

    CREATE TABLE placement_policy_members (
        policy_id    INTEGER NOT NULL REFERENCES placement_policies(id) ON DELETE CASCADE,
        placement_id INTEGER NOT NULL REFERENCES surface_placements(id),
        member_order INTEGER NOT NULL,
        required     INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (policy_id, placement_id),
        UNIQUE (policy_id, member_order)
    );

    CREATE TABLE placement_equivalences (
        id                            INTEGER PRIMARY KEY,
        placement_a_id                INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE CASCADE,
        placement_b_id                INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE CASCADE,
        physical_identity_fingerprint KEYTEXT128 NOT NULL,
        confirmed_by                  KEYTEXT128 NOT NULL,
        confirmed_at                  INTEGER NOT NULL,
        validation_revision           KEYTEXT128 NOT NULL,
        resource_version              INTEGER NOT NULL DEFAULT 1,
        created_at                    INTEGER NOT NULL,
        updated_at                    INTEGER NOT NULL,
        CHECK (placement_a_id < placement_b_id),
        UNIQUE (placement_a_id, placement_b_id)
    );

    CREATE TABLE storage_gateways (
        id                       INTEGER PRIMARY KEY,
        org_id                   INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
        storage_binding_id       INTEGER NOT NULL REFERENCES storage_bindings(id) ON DELETE CASCADE,
        domain_id                INTEGER NOT NULL REFERENCES domains(id),
        base_path                KEYTEXT512 NOT NULL DEFAULT '',
        origin_path_rewrite      KEYTEXT512 NOT NULL DEFAULT '',
        access_policy_json       LONGTEXT NOT NULL DEFAULT ('{}'),
        enabled                  INTEGER NOT NULL DEFAULT 1,
        desired_generation       INTEGER NOT NULL DEFAULT 1,
        observed_generation      INTEGER NOT NULL DEFAULT 0,
        reconciliation_state     KEYTEXT32 NOT NULL DEFAULT 'pending',
        reconciliation_error     LONGTEXT,
        resource_version         INTEGER NOT NULL DEFAULT 1,
        created_at               INTEGER NOT NULL,
        updated_at               INTEGER NOT NULL,
        CHECK (reconciliation_state IN ('pending', 'reconciling', 'ready', 'failed')),
        UNIQUE (domain_id, base_path)
    );
    CREATE INDEX storage_gateways_binding_idx ON storage_gateways (storage_binding_id, id);

    CREATE TABLE topology_defaults (
        id                 INTEGER PRIMARY KEY,
        scope_kind         KEYTEXT32 NOT NULL,
        org_id             INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
        scope_key          KEYTEXT64 NOT NULL UNIQUE,
        storage_binding_id INTEGER REFERENCES storage_bindings(id),
        domain_id          INTEGER REFERENCES domains(id),
        storage_gateway_id INTEGER REFERENCES storage_gateways(id),
        resource_version   INTEGER NOT NULL DEFAULT 1,
        created_at         INTEGER NOT NULL,
        updated_at         INTEGER NOT NULL,
        CHECK ((scope_kind = 'instance' AND org_id IS NULL AND scope_key = 'instance')
            OR (scope_kind = 'organization' AND org_id IS NOT NULL))
    );
    CREATE UNIQUE INDEX topology_defaults_org_idx ON topology_defaults (org_id);

    CREATE TABLE delivery_routes (
        id                  INTEGER PRIMARY KEY,
        domain_id           INTEGER NOT NULL REFERENCES domains(id),
        storage_gateway_id  INTEGER REFERENCES storage_gateways(id),
        gateway_generation  INTEGER,
        base_path           KEYTEXT512 NOT NULL DEFAULT '',
        registry_id         INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id            INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        mode                KEYTEXT32 NOT NULL,
        access_policy_json  LONGTEXT NOT NULL DEFAULT ('{}'),
        placement_id        INTEGER REFERENCES surface_placements(id),
        placement_policy_id INTEGER REFERENCES placement_policies(id),
        serves_git          INTEGER NOT NULL DEFAULT 0,
        serves_cache        INTEGER NOT NULL DEFAULT 0,
        serves_web          INTEGER NOT NULL DEFAULT 0,
        enabled             INTEGER NOT NULL DEFAULT 1,
        readiness_state     KEYTEXT32 NOT NULL DEFAULT 'ready',
        resource_version    INTEGER NOT NULL DEFAULT 1,
        created_at          INTEGER NOT NULL,
        updated_at          INTEGER NOT NULL,
        CHECK ((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
        CHECK ((CASE WHEN placement_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN placement_policy_id IS NULL THEN 0 ELSE 1 END) = 1),
        CHECK (mode IN ('hub_proxy', 'hub_redirect', 'direct')),
        CHECK (mode <> 'direct' OR placement_id IS NOT NULL),
        CHECK (readiness_state IN ('pending', 'ready', 'degraded', 'failed')),
        CHECK (serves_git = 1 OR serves_cache = 1 OR serves_web = 1),
        CHECK ((storage_gateway_id IS NULL AND gateway_generation IS NULL)
            OR (storage_gateway_id IS NOT NULL AND gateway_generation IS NOT NULL
                AND mode = 'direct')),
        UNIQUE (domain_id, base_path)
    );
    CREATE INDEX delivery_routes_registry_idx ON delivery_routes (registry_id, id);
    CREATE INDEX delivery_routes_cache_idx ON delivery_routes (cache_id, id);

    CREATE TABLE canonical_routes (
        id                INTEGER PRIMARY KEY,
        registry_id       INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id          INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        audience          KEYTEXT32 NOT NULL,
        delivery_route_id INTEGER NOT NULL REFERENCES delivery_routes(id),
        created_at        INTEGER NOT NULL,
        updated_at        INTEGER NOT NULL,
        resource_version  INTEGER NOT NULL DEFAULT 1,
        CHECK ((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
        CHECK (audience IN ('git', 'nix_cache', 'web')),
        UNIQUE (registry_id, audience),
        UNIQUE (cache_id, audience)
    );

    CREATE TABLE surface_objects (
        id                 INTEGER PRIMARY KEY,
        registry_id        INTEGER REFERENCES registries(id) ON DELETE CASCADE,
        cache_id           INTEGER REFERENCES caches(id) ON DELETE CASCADE,
        object_key         KEYTEXT512 NOT NULL,
        object_kind        KEYTEXT32 NOT NULL,
        content_hash       KEYTEXT128,
        size               INTEGER,
        mutable_publication_id KEYTEXT64,
        lifecycle_state    KEYTEXT32 NOT NULL DEFAULT 'active',
        tombstoned_at      INTEGER,
        created_at         INTEGER NOT NULL,
        updated_at         INTEGER NOT NULL,
        resource_version   INTEGER NOT NULL DEFAULT 1,
        CHECK ((CASE WHEN registry_id IS NULL THEN 0 ELSE 1 END)
             + (CASE WHEN cache_id IS NULL THEN 0 ELSE 1 END) = 1),
        CHECK ((object_kind = 'immutable' AND mutable_publication_id IS NULL)
            OR (object_kind = 'mutable_pointer' AND registry_id IS NOT NULL
                AND mutable_publication_id IS NOT NULL)),
        CHECK ((lifecycle_state = 'active' AND tombstoned_at IS NULL)
            OR (lifecycle_state = 'tombstoned' AND tombstoned_at IS NOT NULL)),
        UNIQUE (registry_id, object_key),
        UNIQUE (cache_id, object_key),
        UNIQUE (id, registry_id),
        FOREIGN KEY (mutable_publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id)
    );

    CREATE TABLE object_placements (
        surface_object_id INTEGER NOT NULL REFERENCES surface_objects(id),
        placement_id      INTEGER NOT NULL REFERENCES surface_placements(id),
        state             KEYTEXT32 NOT NULL,
        observed_hash     KEYTEXT128,
        observed_size     INTEGER,
        etag              KEYTEXT255,
        deletion_job_id   KEYTEXT64,
        observed_at       INTEGER NOT NULL,
        CHECK (state IN ('present', 'copying', 'missing', 'corrupt', 'deleting')),
        CHECK ((state = 'deleting' AND deletion_job_id IS NOT NULL)
            OR (state <> 'deleting' AND deletion_job_id IS NULL)),
        PRIMARY KEY (surface_object_id, placement_id)
    );

    CREATE TABLE registry_publication_objects (
        publication_id    KEYTEXT64 NOT NULL REFERENCES registry_publications(publication_id),
        registry_id       INTEGER NOT NULL REFERENCES registries(id),
        surface_object_id INTEGER NOT NULL,
        object_kind       KEYTEXT32 NOT NULL,
        expected_hash     KEYTEXT128 NOT NULL,
        expected_size     INTEGER NOT NULL,
        CHECK (object_kind IN ('immutable', 'mutable_pointer')),
        CHECK (expected_size >= 0),
        PRIMARY KEY (publication_id, surface_object_id),
        FOREIGN KEY (publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id),
        FOREIGN KEY (surface_object_id, registry_id)
            REFERENCES surface_objects(id, registry_id)
    );

    CREATE TABLE registry_publication_placements (
        publication_id KEYTEXT64 NOT NULL REFERENCES registry_publications(publication_id),
        registry_id    INTEGER NOT NULL REFERENCES registries(id),
        placement_id   INTEGER NOT NULL,
        required       INTEGER NOT NULL DEFAULT 1,
        state          KEYTEXT32 NOT NULL,
        observed_at    INTEGER NOT NULL,
        CHECK (state IN ('preparing', 'writing_pointers', 'ready', 'failed', 'retired')),
        PRIMARY KEY (publication_id, placement_id),
        FOREIGN KEY (publication_id, registry_id)
            REFERENCES registry_publications(publication_id, registry_id),
        FOREIGN KEY (placement_id, registry_id)
            REFERENCES surface_placements(id, registry_id)
    );

    CREATE TABLE object_deletion_jobs (
        job_id             KEYTEXT64 PRIMARY KEY,
        surface_object_id  INTEGER NOT NULL REFERENCES surface_objects(id),
        placement_id       INTEGER NOT NULL REFERENCES surface_placements(id),
        state              KEYTEXT32 NOT NULL DEFAULT 'preparing',
        active_slot        INTEGER DEFAULT 1,
        attempt_count      INTEGER NOT NULL DEFAULT 0,
        error              LONGTEXT,
        created_at         INTEGER NOT NULL,
        started_at         INTEGER,
        finished_at        INTEGER,
        resource_version   INTEGER NOT NULL DEFAULT 1,
        CHECK (state IN ('preparing', 'pending', 'running', 'succeeded', 'failed', 'cancelled')),
        CHECK (attempt_count >= 0),
        CHECK ((state IN ('preparing', 'pending')
                AND started_at IS NULL AND finished_at IS NULL)
            OR (state = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
            OR (state IN ('succeeded', 'failed', 'cancelled')
                AND started_at IS NOT NULL AND finished_at IS NOT NULL)),
        CHECK ((state IN ('preparing', 'pending', 'running', 'failed') AND active_slot = 1)
            OR (state IN ('succeeded', 'cancelled') AND active_slot IS NULL)),
        UNIQUE (surface_object_id, placement_id, active_slot)
    );
    CREATE INDEX object_deletion_jobs_state_idx
        ON object_deletion_jobs (state, created_at, job_id);

    CREATE TABLE cache_retention_subscriptions (
        id                           INTEGER PRIMARY KEY,
        cache_id                     INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        registry_id                  INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        selector_json                LONGTEXT NOT NULL,
        removal_grace_secs           INTEGER NOT NULL DEFAULT 0,
        exposure_acknowledged_at     INTEGER,
        enabled                      INTEGER NOT NULL DEFAULT 1,
        last_successful_revision     KEYTEXT128,
        last_refresh_at              INTEGER,
        current_refresh_id            KEYTEXT64,
        refresh_state                KEYTEXT32 NOT NULL DEFAULT 'stale',
        refresh_error                LONGTEXT,
        retired_at                   INTEGER,
        resource_version             INTEGER NOT NULL DEFAULT 1,
        created_at                   INTEGER NOT NULL,
        updated_at                   INTEGER NOT NULL,
        CHECK (refresh_state IN ('fresh', 'stale', 'refreshing', 'failed')),
        CHECK (retired_at IS NULL OR enabled = 0),
        UNIQUE (cache_id, registry_id),
        UNIQUE (id, cache_id, registry_id)
    );

    CREATE TABLE cache_population_targets (
        id                  INTEGER PRIMARY KEY,
        cache_id            INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        registry_id         INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        trigger_kind        KEYTEXT32 NOT NULL,
        required            INTEGER NOT NULL DEFAULT 0,
        placement_policy_id INTEGER REFERENCES placement_policies(id),
        selector_json       LONGTEXT NOT NULL,
        validation_gate     KEYTEXT32 NOT NULL,
        enabled             INTEGER NOT NULL DEFAULT 1,
        resource_version    INTEGER NOT NULL DEFAULT 1,
        created_at          INTEGER NOT NULL,
        updated_at          INTEGER NOT NULL,
        CHECK (trigger_kind IN ('release', 'manual', 'continuous')),
        CHECK (validation_gate IN ('none', 'presence', 'closure', 'deep')),
        UNIQUE (cache_id, registry_id, trigger_kind)
    );

    CREATE TABLE cache_retention_refreshes (
        refresh_id       KEYTEXT64 PRIMARY KEY,
        subscription_id  INTEGER NOT NULL REFERENCES cache_retention_subscriptions(id),
        parent_refresh_id KEYTEXT64 REFERENCES cache_retention_refreshes(refresh_id),
        state             KEYTEXT32 NOT NULL DEFAULT 'running',
        source_revision   KEYTEXT128,
        error             LONGTEXT,
        started_at        INTEGER NOT NULL,
        activated_at      INTEGER,
        grace_until       INTEGER,
        finished_at       INTEGER,
        expected_reason_count INTEGER NOT NULL,
        CHECK (expected_reason_count >= 0),
        CHECK (state IN ('running', 'staged', 'failed')),
        CHECK ((state = 'running' AND finished_at IS NULL AND error IS NULL)
            OR (state = 'staged' AND finished_at IS NOT NULL
                AND source_revision IS NOT NULL AND error IS NULL
                AND activated_at IS NOT NULL AND grace_until >= activated_at)
            OR (state = 'failed' AND finished_at IS NOT NULL AND error IS NOT NULL))
    );

    CREATE TABLE release_artifacts (
        release_id      INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
        package_name    KEYTEXT128 NOT NULL,
        package_version KEYTEXT64 NOT NULL,
        platform        KEYTEXT64 NOT NULL,
        artifact_kind   KEYTEXT32 NOT NULL,
        store_path      KEYTEXT512 NOT NULL,
        store_hash      KEYTEXT64 NOT NULL,
        CHECK (artifact_kind IN ('output', 'image', 'source_derivation')),
        PRIMARY KEY (release_id, package_name, package_version, platform,
                     artifact_kind, store_hash)
    );
    CREATE INDEX release_artifacts_hash_idx ON release_artifacts (store_hash, release_id);
    CREATE UNIQUE INDEX releases_id_registry_idx ON releases (id, registry_id);

    CREATE TABLE manual_retention_roots (
        id               INTEGER PRIMARY KEY,
        cache_id         INTEGER NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
        store_hash       KEYTEXT64 NOT NULL,
        reason           LONGTEXT NOT NULL,
        created_by       KEYTEXT128 NOT NULL,
        created_at       INTEGER NOT NULL,
        deleted_at       INTEGER,
        resource_version INTEGER NOT NULL DEFAULT 1,
        UNIQUE (id, cache_id)
    );
    CREATE INDEX manual_retention_roots_cache_idx
        ON manual_retention_roots (cache_id, deleted_at, id);

    CREATE TABLE retention_leases (
        id                       INTEGER PRIMARY KEY,
        manual_retention_root_id INTEGER NOT NULL REFERENCES manual_retention_roots(id) ON DELETE CASCADE,
        begins_at                INTEGER NOT NULL,
        expires_at               INTEGER NOT NULL,
        renewed_from_lease_id    INTEGER,
        renewed_by               KEYTEXT128 NOT NULL,
        renewed_at               INTEGER NOT NULL,
        resource_version         INTEGER NOT NULL DEFAULT 1,
        CHECK (expires_at > begins_at),
        UNIQUE (id, manual_retention_root_id),
        FOREIGN KEY (renewed_from_lease_id, manual_retention_root_id)
            REFERENCES retention_leases(id, manual_retention_root_id)
    );

    CREATE TABLE cache_root_reasons (
        id                        INTEGER PRIMARY KEY,
        cache_id                  INTEGER NOT NULL REFERENCES caches(id),
        registry_id               INTEGER REFERENCES registries(id),
        store_hash                KEYTEXT64 NOT NULL,
        reason_key                KEYTEXT255 NOT NULL,
        source_kind               KEYTEXT32 NOT NULL,
        refresh_id                KEYTEXT64 REFERENCES cache_retention_refreshes(refresh_id),
        retention_subscription_id INTEGER REFERENCES cache_retention_subscriptions(id),
        manual_retention_root_id   INTEGER REFERENCES manual_retention_roots(id),
        retention_lease_id         INTEGER REFERENCES retention_leases(id),
        release_id                 INTEGER REFERENCES releases(id),
        channel_id                 INTEGER REFERENCES channels(id),
        partition_bucket           INTEGER,
        source_ref                 KEYTEXT255 NOT NULL,
        source_revision            KEYTEXT128 NOT NULL,
        expires_at                 INTEGER,
        refreshed_at               INTEGER NOT NULL,
        CHECK (source_kind IN ('manual', 'lease', 'registry_catalog', 'release', 'channel')),
        CHECK ((source_kind = 'manual'
                AND registry_id IS NULL AND retention_subscription_id IS NULL
                AND refresh_id IS NULL
                AND manual_retention_root_id IS NOT NULL
                AND retention_lease_id IS NULL AND release_id IS NULL
                AND channel_id IS NULL AND partition_bucket IS NULL)
            OR (source_kind = 'lease'
                AND registry_id IS NULL AND retention_subscription_id IS NULL
                AND refresh_id IS NULL
                AND manual_retention_root_id IS NOT NULL
                AND retention_lease_id IS NOT NULL AND release_id IS NULL
                AND channel_id IS NULL AND partition_bucket IS NULL)
            OR (source_kind = 'registry_catalog'
                AND registry_id IS NOT NULL AND retention_subscription_id IS NOT NULL
                AND refresh_id IS NOT NULL
                AND manual_retention_root_id IS NULL
                AND retention_lease_id IS NULL AND release_id IS NULL
                AND channel_id IS NULL AND partition_bucket IS NULL)
            OR (source_kind = 'channel'
                AND registry_id IS NOT NULL AND retention_subscription_id IS NOT NULL
                AND refresh_id IS NOT NULL
                AND manual_retention_root_id IS NULL
                AND retention_lease_id IS NULL AND release_id IS NOT NULL
                AND channel_id IS NOT NULL AND partition_bucket IS NOT NULL)
            OR (source_kind = 'release'
                AND registry_id IS NOT NULL AND retention_subscription_id IS NOT NULL
                AND refresh_id IS NOT NULL
                AND manual_retention_root_id IS NULL
                AND retention_lease_id IS NULL AND release_id IS NOT NULL
                AND channel_id IS NULL AND partition_bucket IS NULL)),
        UNIQUE (refresh_id, reason_key),
        UNIQUE (manual_retention_root_id, reason_key),
        FOREIGN KEY (retention_subscription_id, cache_id, registry_id)
            REFERENCES cache_retention_subscriptions(id, cache_id, registry_id),
        FOREIGN KEY (manual_retention_root_id, cache_id)
            REFERENCES manual_retention_roots(id, cache_id),
        FOREIGN KEY (retention_lease_id, manual_retention_root_id)
            REFERENCES retention_leases(id, manual_retention_root_id),
        FOREIGN KEY (release_id, registry_id)
            REFERENCES releases(id, registry_id)
    );
    CREATE INDEX cache_root_reasons_cache_idx
        ON cache_root_reasons (cache_id, store_hash, expires_at);

    CREATE TABLE registry_cache_stack_entries (
        registry_id      INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
        stack_path       KEYTEXT512 NOT NULL,
        committed_url    LONGTEXT NOT NULL,
        resolved_priority INTEGER NOT NULL,
        cache_id         INTEGER REFERENCES caches(id) ON DELETE SET NULL,
        delivery_route_id INTEGER REFERENCES delivery_routes(id) ON DELETE SET NULL,
        indexed_commit   KEYTEXT128 NOT NULL,
        PRIMARY KEY (registry_id, stack_path)
    );

    CREATE TABLE topology_plans (
        plan_id             KEYTEXT64 PRIMARY KEY,
        plan_kind           KEYTEXT64 NOT NULL,
        actor_kind          KEYTEXT32 NOT NULL,
        actor_id            INTEGER,
        actor_label         TEXT NOT NULL,
        scope               KEYTEXT255 NOT NULL,
        input_versions_json LONGTEXT NOT NULL,
        effects_json        LONGTEXT NOT NULL,
        warnings_json       LONGTEXT NOT NULL,
        confirmation_hash   KEYTEXT128,
        created_at          INTEGER NOT NULL,
        expires_at          INTEGER NOT NULL,
        applied_at          INTEGER,
        CHECK (expires_at > created_at),
        CHECK (actor_kind IN ('user', 'service_account', 'key', 'system'))
    );
    CREATE INDEX topology_plans_scope_idx ON topology_plans (scope, created_at);

    CREATE TABLE topology_operations (
        operation_id     KEYTEXT64 PRIMARY KEY,
        operation_kind   KEYTEXT64 NOT NULL,
        registry_id      INTEGER REFERENCES registries(id),
        cache_id         INTEGER REFERENCES caches(id),
        placement_id     INTEGER REFERENCES surface_placements(id),
        state            KEYTEXT32 NOT NULL,
        progress_current INTEGER NOT NULL DEFAULT 0,
        progress_total   INTEGER,
        detail_json      LONGTEXT NOT NULL DEFAULT ('{}'),
        error            LONGTEXT,
        created_at       INTEGER NOT NULL,
        started_at       INTEGER,
        finished_at      INTEGER,
        resource_version INTEGER NOT NULL DEFAULT 1,
        CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
        CHECK (progress_current >= 0),
        CHECK (progress_total IS NULL OR progress_total >= progress_current),
        CHECK ((state = 'pending' AND started_at IS NULL AND finished_at IS NULL)
            OR (state = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
            OR (state IN ('succeeded', 'failed', 'cancelled')
                AND started_at IS NOT NULL AND finished_at IS NOT NULL)),
        CHECK (started_at IS NULL OR started_at >= created_at),
        CHECK (finished_at IS NULL OR finished_at >= started_at),
        CHECK (state <> 'succeeded' OR error IS NULL),
        CHECK (state <> 'failed' OR error IS NOT NULL)
    );
    CREATE INDEX topology_operations_registry_idx
        ON topology_operations (registry_id, created_at);
    CREATE INDEX topology_operations_cache_idx
        ON topology_operations (cache_id, created_at);
    ",
];

/// Returns every migration's individual SQL statements, in order.
///
/// Splits the [`MIGRATIONS`] scripts at statement boundaries via
/// [`split_statements`](crate::backend::split_statements), flattened across all
/// versions. Useful for tooling that must apply the schema outside the
/// [`Database`] migration path — e.g. seeding a test D1 over its binding, or the
/// `aos-hub schema dump` command.
#[must_use]
pub fn migration_statements() -> Vec<String> {
    MIGRATIONS
        .iter()
        .flat_map(|m| crate::backend::split_statements(m))
        .collect()
}

/// Marker error: a membership mutation was refused because it would leave an
/// org with zero owners.
///
/// Raised inside the transaction of [`Database::revoke_membership_owner_safe`]
/// and [`Database::set_membership_role_owner_safe`] (rolling the write back)
/// so a caller can classify the failure through `anyhow` context chains via
/// [`is_last_owner_error`] and surface it as a `409 Conflict` rather than a
/// generic `500`.
#[derive(Debug, thiserror::Error)]
#[error("refusing to leave org scope '{0}' without an owner")]
pub struct LastOwnerError(pub String);

/// Whether any error in `err`'s chain is a [`LastOwnerError`].
///
/// Walks the full `anyhow` context chain, so classification survives any
/// number of `.context(…)` layers added by callers.
#[must_use]
pub fn is_last_owner_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<LastOwnerError>().is_some())
}

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
    /// The hosted signing key this registry has enrolled, or `None` for a
    /// BYO-key registry (the default — the channel console only prepares
    /// client-signed operations).
    pub hosted_key_id: Option<i64>,
    /// Crawl posture for the generated `robots.txt`: one of `allow_all`,
    /// `allow_no_ai`, or `deny_all` (see [`crate::crawl::CrawlPolicy`]).
    pub crawl_policy: String,
    /// Operator-authored `llms.txt` body served verbatim, or `None` to serve
    /// the document generated from the registry's packages and channels.
    pub llms_txt_body: Option<String>,
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
    /// Owning org id, or `None` for the instance-level default binding
    /// ([`is_instance_default`](Self::is_instance_default)).
    pub org_id: Option<i64>,
    /// Binding name, unique within the org.
    pub name: String,
    /// Backend kind: `local_fs` (a host directory), or `s3`/`r2` (an external
    /// S3-compatible object store reached via presigned URLs).
    pub kind: String,
    /// Backend root: a filesystem path for `local_fs`, or the bucket name
    /// (optionally `bucket/sub-prefix`) for `s3`/`r2`.
    pub root: String,
    /// Access mode: `public` (Direct-eligible — consumers may be steered to a
    /// `direct` frontend) or `private` (hub-only; reads must be proxied or
    /// presigned).
    pub access: String,
    /// The S3/R2 API endpoint the hub writes objects through and presigns reads
    /// against (path-style `{endpoint}/{bucket}/{key}`); `None` for `local_fs`
    /// or when unset. This is the bucket's *origin*, not a consumer-facing read
    /// URL — those live in [`FrontendRecord`]s attached to the binding.
    pub endpoint: Option<String>,
    /// For a `private` binding, the sealed credential reference the hub uses to
    /// sign authenticated-origin reads; `None` when unset.
    pub credential_ref: Option<String>,
    /// Whether this is the singleton instance-level default storage binding —
    /// the anchor for the default bucket's frontends and public settings, which
    /// registries/caches with `storage_binding_id IS NULL` inherit (RFC-0004
    /// §12). Exactly one row carries this; it has a `None` `org_id`.
    pub is_instance_default: bool,
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

/// Per-org quota caps on hub-managed resources (system-of-record row).
///
/// Mirrors the `org_quotas` row. Every cap is optional: `None` means *that*
/// dimension is unlimited (an org with no `org_quotas` row at all is
/// unlimited on every dimension). Quotas are enforced at the upload facade
/// (bytes/objects, via [`Database::would_exceed_quota`]) and in the
/// registry/token create paths (counts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgQuota {
    /// Maximum total stored bytes, or `None` for unlimited.
    pub max_bytes: Option<i64>,
    /// Maximum total stored objects, or `None` for unlimited.
    pub max_objects: Option<i64>,
    /// Maximum number of registries, or `None` for unlimited.
    pub max_registries: Option<i64>,
    /// Maximum number of active (non-revoked) tokens, or `None` for unlimited.
    pub max_tokens: Option<i64>,
}

/// Per-org running usage totals (system-of-record row).
///
/// Mirrors the `org_usage` row. The totals are maintained incrementally on
/// each upload ([`Database::add_org_usage`]) and are *approximate* — they
/// count bytes as written, so a deleted object's bytes linger until a
/// re-index/GC reconciliation (a later refinement) rebuilds them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgUsage {
    /// Total bytes written under the org's managed registries.
    pub used_bytes: i64,
    /// Total objects written under the org's managed registries.
    pub object_count: i64,
    /// Unix time the totals were last updated.
    pub updated_at: i64,
}

/// The editable instance-wide settings bundle (RFC-0004 console).
///
/// Every field is persisted in the `instance_config` key/value table and is
/// configurable via the WebUI, the API, and the CLI; the deploy seeds initial
/// values but never owns them thereafter. Optional fields are `None`/empty when
/// unset and fall back to a documented default. Loaded by
/// [`Database::instance_settings`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct InstanceSettings {
    /// Operator-chosen site title shown in the masthead and page titles; `None`
    /// falls back to the deploy `--brand` (or empty).
    pub site_title: Option<String>,
    /// Short tagline shown under the brand on the home page.
    pub tagline: Option<String>,
    /// A global announcement banner rendered on every console page; `None` for
    /// no banner.
    pub announcement: Option<String>,
    /// Terms-of-service URL for the footer.
    pub tos_url: Option<String>,
    /// Privacy-policy URL for the footer.
    pub privacy_url: Option<String>,
    /// Support/contact URL for the footer.
    pub support_url: Option<String>,
    /// Who may create organizations (also exposed standalone as
    /// [`Database::signup_policy`]).
    pub signup_policy: SignupPolicy,
    /// Lowercased email-domain allowlist for signup; empty allows any domain.
    pub signup_domains: Vec<String>,
    /// Whether local password login is offered (else SSO/magic-link only).
    /// Defaults to `true`.
    pub password_login: bool,
    /// Whether the binary-caches surface (the masthead caches tab, the global
    /// caches list, and direct cache pages) is visible to logged-out visitors.
    /// Defaults to `false` — caches are a signed-in-only surface.
    pub caches_public: bool,
    /// Session absolute lifetime in seconds; `None` uses the built-in default.
    pub session_lifetime_secs: Option<i64>,
    /// Default `robots.txt` crawl policy new registries inherit
    /// (`allow_all`/`allow_no_ai`/`deny_all`). Defaults to `allow_all`.
    pub default_crawl_policy: String,
    /// Maximum surface upload size in bytes; `None` uses the built-in default.
    pub max_upload_bytes: Option<i64>,
}

/// The instance-wide policy gating who may create organizations.
///
/// Stored in `instance_config` under the key `signup_policy`; see
/// [`Database::signup_policy`]. The default is [`SignupPolicy::InviteOnly`]
/// (the hosted-instance posture: free hub-managed storage behind open signup
/// is an abuse magnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum SignupPolicy {
    /// Any authenticated principal may create an org.
    Open,
    /// Org creation requires an invitation or an existing membership (or an
    /// instance admin). The safe default.
    #[default]
    InviteOnly,
}

impl SignupPolicy {
    /// The wire string stored in `instance_config.value`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SignupPolicy::Open => "open",
            SignupPolicy::InviteOnly => "invite_only",
        }
    }

    /// Parse a stored policy string, defaulting to [`SignupPolicy::InviteOnly`]
    /// for any unknown value (fail closed).
    #[must_use]
    pub fn parse(s: &str) -> SignupPolicy {
        match s {
            "open" => SignupPolicy::Open,
            _ => SignupPolicy::InviteOnly,
        }
    }
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

/// An org's OIDC identity-provider configuration (system-of-record row).
///
/// Mirrors the `org_idp_configs` row one-to-one. The client secret is held
/// **sealed** in [`IdpConfigRecord::client_secret_enc`]; unseal it through a
/// [`crate::auth::seal::SecretSealer`] only at the moment of the token
/// exchange, never store or log the plaintext.
#[derive(Debug, Clone)]
pub struct IdpConfigRecord {
    /// Owning org id (the table's primary key — one IdP per org).
    pub org_id: i64,
    /// The IdP's issuer identifier; the `iss` claim every id_token must carry.
    pub issuer: String,
    /// The OAuth2 authorization endpoint the browser is redirected to.
    pub authorization_endpoint: String,
    /// The OAuth2 token endpoint the authorization code is exchanged at.
    pub token_endpoint: String,
    /// The JWKS endpoint whose keys verify the id_token signature.
    pub jwks_uri: String,
    /// The client id registered with the IdP for this hub.
    pub client_id: String,
    /// The sealed client secret, or `None` for a public client.
    ///
    /// Sealed by a [`crate::auth::seal::SecretSealer`]; never the plaintext.
    pub client_secret_enc: Option<String>,
    /// The space-separated scope string requested at authorization.
    pub scopes: String,
    /// The id_token claim carrying the user's groups, or `None` to skip
    /// group→role mapping.
    pub groups_claim: Option<String>,
    /// The `group -> role` mapping as a JSON object string, applied on every
    /// SSO login.
    pub role_map_json: String,
    /// Whether an unknown `(iss, sub)` may be just-in-time provisioned.
    pub allow_jit: bool,
    /// Whether members of the org are forced through SSO (email-first login
    /// on a captured domain redirects to the IdP rather than offering magic
    /// links).
    pub enforce_sso: bool,
    /// The role a JIT-provisioned user receives at the org scope when no
    /// group mapping applies.
    pub default_role: String,
}

/// A hosted (hub-held) Ed25519 signing key (system-of-record row).
///
/// Mirrors the `hosted_keys` row. The 32-byte Ed25519 *seed* is held
/// **sealed** in [`HostedKeyRecord::secret_enc`]; unseal it to a usable
/// signing key through [`Database::load_hosted_signing_key`] only at the
/// instant of a signature, never store or log the plaintext seed.
#[derive(Debug, Clone)]
pub struct HostedKeyRecord {
    /// Database id (the value [`RegistryRecord::hosted_key_id`] references).
    pub id: i64,
    /// Owning org id.
    pub org_id: i64,
    /// Operator-chosen key id, unique within the org.
    pub key_id: String,
    /// The public trusted-key line (`name:Ed25519:<base64>`) to pin as a
    /// registry trust anchor.
    pub public_key: String,
    /// The sealed 32-byte Ed25519 seed; never the plaintext.
    pub secret_enc: String,
    /// Unix time the key was created.
    pub created_at: i64,
}

/// A captured (DNS-TXT-verifiable) email domain bound to an org.
#[derive(Debug, Clone)]
pub struct OrgDomainRecord {
    /// The fully-qualified domain (lowercased).
    pub domain: String,
    /// The org that claimed the domain.
    pub org_id: i64,
    /// The TXT record value the org must publish to prove control.
    pub txt_challenge: String,
    /// Unix time the domain was verified, or `None` while unverified.
    pub verified_at: Option<i64>,
}

/// An in-flight OIDC authorization-code request (system-of-record row).
///
/// Created at the hub's `auth::oidc::begin_login` and consumed exactly once at
/// the callback by [`Database::take_oidc_flow`]; carries the PKCE
/// `code_verifier` and the `nonce` the returned id_token is checked against.
#[derive(Debug, Clone)]
pub struct OidcFlowRecord {
    /// The opaque CSRF `state` value echoed back by the IdP.
    pub state: String,
    /// The org whose IdP this flow targets.
    pub org_id: i64,
    /// The nonce bound into the authorization request; the id_token's `nonce`
    /// claim must equal it.
    pub nonce: String,
    /// The PKCE code verifier whose S256 challenge was sent at authorization.
    pub code_verifier: String,
    /// Where to send the browser after a successful login, or `None` for the
    /// instance home.
    pub redirect_after: Option<String>,
    /// Unix time the flow expires; a callback after this is rejected.
    pub expires_at: i64,
}

/// A registered passkey / WebAuthn credential (system-of-record row).
///
/// Created at [`crate::auth::webauthn::finish_registration`] and looked up by
/// [`Database::webauthn_credential_by_id`] on every assertion. The hub stores
/// only the public key (the `attestation: none` policy means no attestation
/// statement is ever persisted), so a database leak yields nothing usable for
/// impersonation.
#[derive(Debug, Clone)]
pub struct WebauthnCredentialRecord {
    /// Database id.
    pub id: i64,
    /// Owning user id.
    pub user_id: i64,
    /// The authenticator's raw credential id, base64url-encoded; the lookup key
    /// an assertion arrives with, UNIQUE across all users.
    pub credential_id: String,
    /// The credential's COSE public key, base64-encoded as the authenticator
    /// emitted it; re-decoded by the verifier on every assertion.
    pub public_key: String,
    /// The authenticator's signature counter, enforced monotonic on assertion
    /// to detect a cloned authenticator.
    pub sign_count: i64,
    /// Advisory transports the authenticator reported (JSON array), or `None`.
    pub transports: Option<String>,
    /// A human label for the passkey, or `None`.
    pub label: Option<String>,
    /// Unix time the credential was registered.
    pub created_at: i64,
    /// Unix time the credential last authenticated a login, or `None`.
    pub last_used_at: Option<i64>,
}

/// An in-flight WebAuthn ceremony challenge (system-of-record row).
///
/// Created at the start of a registration or assertion ceremony and consumed
/// exactly once at verify by [`Database::take_webauthn_challenge`]. Mirrors
/// [`OidcFlowRecord`]'s short-lived, single-use shape: the random `challenge`
/// the client signs into `clientDataJSON` must match a live, unexpired row, and
/// taking it deletes it so a challenge can never be replayed.
#[derive(Debug, Clone)]
pub struct WebauthnChallengeRecord {
    /// The random challenge value, base64url-encoded.
    pub challenge: String,
    /// The registering user for a registration ceremony, or `None` for a
    /// usernameless assertion ceremony (resolved from the presented credential).
    pub user_id: Option<i64>,
    /// The ceremony kind: `"registration"` or `"assertion"`.
    pub kind: String,
    /// Unix time the challenge expires; a verify after this is rejected.
    pub expires_at: i64,
}

/// The outcome of [`Database::link_or_create_identity`]: the resolved user and
/// how the identity was reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityLink {
    /// An existing `(iss, sub)` identity resolved to this user id.
    Existing(i64),
    /// A verified email on a captured domain linked to an existing user.
    Linked(i64),
    /// A fresh user and identity were provisioned (JIT).
    Created(i64),
}

impl IdentityLink {
    /// The resolved user id, regardless of how it was reconciled.
    #[must_use]
    pub fn user_id(&self) -> i64 {
        match self {
            IdentityLink::Existing(id) | IdentityLink::Linked(id) | IdentityLink::Created(id) => {
                *id
            }
        }
    }
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

impl SessionAuth {
    /// Whether this session is currently sudo-capable at time `now`.
    ///
    /// True when the session was minted sudo (`auth_level == 1`) **and** the
    /// last re-authentication is within
    /// [`SUDO_WINDOW_SECS`](crate::auth::session::SUDO_WINDOW_SECS) of `now`.
    /// Destructive operations gate on this so a long-lived but stale session
    /// cannot perform them without the user re-authenticating.
    #[must_use]
    pub fn is_sudo(&self, now: i64) -> bool {
        self.auth_level == 1
            && now.saturating_sub(self.last_authenticated_at)
                < crate::auth::session::SUDO_WINDOW_SECS
    }
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
    /// Committed registry readme (longer preamble), shown on the home page.
    pub readme: Option<String>,
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
    /// Closure size in bytes of the latest version's primary platform
    /// artifact (the platform that sorts first), or `None` when the latest
    /// version has no platform artifacts.
    pub closure_size: Option<u64>,
    /// Platform triples published for the latest version, sorted.
    pub platforms: Vec<String>,
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

/// One resolved closure edge: a store-hash prefix and the package that
/// publishes it, when resolvable within the same registry.
///
/// `(hash, name, version)` — `name` and `version` are `Some` when some package
/// in the registry owns the store path with this hash prefix, and `None` for a
/// hash that points outside the registry's package set (e.g. a stdenv path).
/// Returned in input order by [`Database::resolve_reference_names`].
pub type ResolvedReference = (String, Option<String>, Option<String>);

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
    /// Store path of the derivation that produced this output, or empty when
    /// the index did not record one (rows written before schema v19).
    pub source_drv: String,
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

/// The classification of one [`validation finding`](ValidationFinding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    /// The narinfo (or, at integrity depth, its NAR) was absent.
    Missing,
    /// The NAR was present but its downloaded content did not match its
    /// declared hash (recorded only at deep depth).
    Corrupt,
}

impl FindingStatus {
    /// The status label stored in `validation_findings.status`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Missing => "missing",
            FindingStatus::Corrupt => "corrupt",
        }
    }
}

/// One per-hash finding of a validation run.
#[derive(Debug, Clone)]
pub struct ValidationFinding {
    /// The store hash the finding concerns.
    pub store_hash: String,
    /// Whether the hash is missing or corrupt.
    pub status: FindingStatus,
}

/// One recorded repair-job attempt.
///
/// See the [repair-jobs migration docs](self) (v14) for the `status`
/// vocabulary (`pending | done | failed | plan_only`).
#[derive(Debug, Clone)]
pub struct RepairJobRow {
    /// Repair-job id.
    pub id: i64,
    /// The cache the object was (to be) copied into.
    pub cache_url: String,
    /// The store hash repaired.
    pub store_hash: String,
    /// The cache the object was copied from.
    pub source_cache_url: String,
    /// Lifecycle status: `pending`, `done`, `failed`, or `plan_only`.
    pub status: String,
    /// Failure detail when `status` is `failed` (else `None`).
    pub error: Option<String>,
    /// Unix time the job was recorded.
    pub created_at: i64,
    /// Unix time the job finished (`None` while pending).
    pub finished_at: Option<i64>,
}

/// The latest freshness probe of one committed cache endpoint.
///
/// See the [cache-freshness migration docs](self) for the `status` vocabulary
/// and the probing logic in the hub's `probe` module.
#[derive(Debug, Clone)]
pub struct CacheProbeRow {
    /// The committed cache endpoint that was probed.
    pub cache_url: String,
    /// Probe outcome: `ok`, `stale`, or `unreachable`.
    pub status: String,
    /// Whether a `nix-cache-info` document was served by the cache.
    pub observed_nix_cache_info: bool,
    /// Round-trip latency of the probe, in milliseconds.
    pub latency_ms: i64,
    /// Unix time the probe ran.
    pub checked_at: i64,
}

/// A registry's upstream mirror source (system-of-record row).
///
/// A registry that has a `mirror_sources` row *is* a mirror (see
/// [`Database::is_mirror`]). The [`MirrorSource::mode`] selects the
/// replication strategy: `full` copies the verified upstream surface into the
/// local binding on a schedule; `pullthrough` fetches-on-miss through a
/// proxied frontend. See the hub's `mirror` module for the sync and fetch logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSource {
    /// The upstream registry surface URL (`file://`, `/path`, or `http(s)://`).
    pub upstream_url: String,
    /// Replication mode: `full` (scheduled byte-identical copy) or
    /// `pullthrough` (fetch-on-miss proxy).
    pub mode: String,
    /// Whether the full-mirror sync verifies upstream signatures before
    /// accepting anything (default `true`; a poisoned upstream never
    /// propagates).
    pub verify: bool,
    /// Full-mirror sync cadence, in seconds.
    pub schedule_secs: i64,
    /// Unix time of the last completed sync attempt, or `None` if never run.
    pub last_sync_at: Option<i64>,
    /// Outcome of the last sync attempt: `ok` or `failed`, or `None` if never
    /// run.
    pub last_sync_status: Option<String>,
    /// Failure detail when [`Self::last_sync_status`] is `failed`.
    pub last_sync_error: Option<String>,
    /// The upstream channel frontier observed at the last successful sync.
    pub upstream_frontier: Option<String>,
}

/// Behavior tuning for a `proxied` frontend (RFC-0004 "11-caches" proxy slice).
///
/// Serialized as the `frontends.proxy_config` JSON blob; a `NULL` column means
/// "use these conservative defaults" ([`ProxyConfig::default`]). All fields are
/// `#[serde(default)]`, so a partial blob (an older or hand-written row) fills
/// the rest from the defaults rather than failing to parse.
///
/// ```text
/// { "connect_timeout_secs": 5, "read_timeout_secs": 30, "stream": true,
///   "max_body_bytes": 5368709120, "retries": 2, "failover": true,
///   "pass_range": true, "pass_cache_control": true }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// TCP/TLS connect timeout to the origin, in seconds.
    pub connect_timeout_secs: u32,
    /// Per-request read timeout from the origin, in seconds.
    pub read_timeout_secs: u32,
    /// Stream the origin response through rather than buffering it.
    pub stream: bool,
    /// Maximum proxied body size in bytes (a guard against unbounded origins).
    pub max_body_bytes: u64,
    /// How many times to retry a failed origin fetch before giving up.
    pub retries: u32,
    /// Fall over to the next-priority frontend on origin failure.
    pub failover: bool,
    /// Forward the client's `Range` header to the origin (ranged reads).
    pub pass_range: bool,
    /// Forward the origin's `Cache-Control` header back to the client.
    pub pass_cache_control: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            connect_timeout_secs: 5,
            read_timeout_secs: 30,
            stream: true,
            max_body_bytes: 5 * 1024 * 1024 * 1024,
            retries: 2,
            failover: true,
            pass_range: true,
            pass_cache_control: true,
        }
    }
}

/// A frontend domain serving some subset of a registry's or cache's surfaces
/// (system-of-record row; RFC-0004 "Frontends: direct and proxied domains").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendRecord {
    /// Database id.
    pub id: i64,
    /// The registry this frontend serves, or `None` for a cache frontend.
    /// Exactly one of `registry_id`/`cache_id` is set.
    pub registry_id: Option<i64>,
    /// The managed cache this frontend serves, or `None` otherwise.
    pub cache_id: Option<i64>,
    /// The storage binding this frontend serves (a bucket's public origin),
    /// inherited by every registry/cache stored in that binding (RFC-0004 §12),
    /// or `None` for a per-consumer frontend. Exactly one of
    /// `registry_id`/`cache_id`/`storage_binding_id` is set.
    pub storage_binding_id: Option<i64>,
    /// The domain the frontend is reachable at (e.g. `cdn.acme.com`).
    pub domain: String,
    /// A path prefix under the domain the registry surface lives at (`""` for
    /// the domain root).
    pub base_path: String,
    /// Serving mode: `direct` (hub not in the path; probe-only) or `proxied`
    /// (the hub's facade serves it).
    pub mode: String,
    /// Whether the frontend serves the dumb-HTTP git surface.
    pub serves_git: bool,
    /// Whether the frontend serves the Nix binary-cache surface.
    pub serves_cache: bool,
    /// Whether the frontend serves the static web surface.
    pub serves_web: bool,
    /// The `[caches]` priority an advertised cache frontend would carry
    /// (informational; the committed cache stack is signed tree content).
    pub consumer_priority: i64,
    /// Whether the frontend is advertised to consumers.
    pub advertised: bool,
    /// Proxy behavior tuning for a `proxied` frontend; `None` ⇒ defaults.
    pub proxy_config: Option<ProxyConfig>,
    /// Whether this is the preferred frontend a consumer should reach first.
    pub is_primary: bool,
    /// Unix time the frontend was created.
    pub created_at: i64,
}

/// The latest reachability/freshness observation of one frontend
/// (rebuildable; RFC-0004's `FrontendProbe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendProbeRow {
    /// The frontend the observation concerns.
    pub frontend_id: i64,
    /// Probe outcome: `ok`, `stale`, or `unreachable`, or `None` if never
    /// probed.
    pub status: Option<String>,
    /// The channel frontier the frontend's surface advertised, when observed.
    pub observed_frontier: Option<String>,
    /// How many releases behind the local index frontier the frontend is, when
    /// computable.
    pub lag_releases: Option<i64>,
    /// Round-trip latency of the probe, in milliseconds.
    pub latency_ms: Option<i64>,
    /// Unix time the probe ran.
    pub checked_at: Option<i64>,
}

/// A verified hostname whose paths may be mapped to Hub surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    /// Database id.
    pub id: i64,
    /// Owning organization, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Lowercase hostname without a scheme or path.
    pub hostname: String,
    /// Configured DNS provider identifier, when Hub-managed.
    pub desired_dns_provider: Option<String>,
    /// DNS lifecycle state.
    pub observed_dns_state: String,
    /// Configured TLS provider identifier, when Hub-managed.
    pub desired_tls_provider: Option<String>,
    /// TLS lifecycle state.
    pub observed_tls_state: String,
    /// Serialized external-access-provider declaration.
    pub access_provider_json: String,
    /// Verification time, or `None` while unverified.
    pub verified_at: Option<i64>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One immutable registry publication assembled before mutable pointers move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationRecord {
    /// Stable opaque publication id.
    pub publication_id: String,
    /// Registry whose bytes and pointers are published.
    pub registry_id: i64,
    /// Monotonic per-registry ordering number.
    pub ordinal: i64,
    /// Source generation identifier.
    pub generation: String,
    /// Digest of the immutable publication manifest.
    pub manifest_digest: String,
    /// Digest of the complete refs snapshot.
    pub refs_digest: String,
    /// Default Git commit, when the registry defines one.
    pub default_commit: Option<String>,
    /// Immediately preceding publication, when any.
    pub parent_publication_id: Option<String>,
    /// `preparing`, `writing_pointers`, `ready`, `failed`, or `retired`.
    pub state: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Completion time once ready or retired.
    pub completed_at: Option<i64>,
    /// Retirement time.
    pub retired_at: Option<i64>,
}

/// The single authoritative current-publication pointer for a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationStateRecord {
    /// Registry owning this singleton state row.
    pub registry_id: i64,
    /// Current ready publication, or `None` before first publication.
    pub current_publication_id: Option<String>,
    /// Ordinal reserved for the next publication.
    pub next_ordinal: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// Immutable expected-object snapshot captured by one publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationObjectRecord {
    /// Publication owning the snapshot entry.
    pub publication_id: String,
    /// Registry repeated to enforce same-registry composite references.
    pub registry_id: i64,
    /// Logical surface object.
    pub surface_object_id: i64,
    /// Snapshotted object kind.
    pub object_kind: String,
    /// Expected content digest.
    pub expected_hash: String,
    /// Expected byte size.
    pub expected_size: i64,
}

/// Per-placement progress toward publishing one registry generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationPlacementRecord {
    /// Publication being materialized.
    pub publication_id: String,
    /// Registry repeated to enforce same-registry composite references.
    pub registry_id: i64,
    /// Destination registry placement.
    pub placement_id: i64,
    /// Whether failure prevents the publication becoming current.
    pub required: bool,
    /// `preparing`, `writing_pointers`, `ready`, `failed`, or `retired`.
    pub state: String,
    /// Last observed transition time in Unix seconds.
    pub observed_at: i64,
}

/// Expected object snapshot attached to a preparing registry publication.
#[derive(Debug, Clone)]
pub struct SetRegistryPublicationObject {
    /// Publication receiving the immutable snapshot row.
    pub publication_id: String,
    /// Logical registry object included by the publication.
    pub surface_object_id: i64,
    /// Snapshotted object kind.
    pub object_kind: String,
    /// Expected content digest.
    pub expected_hash: String,
    /// Expected byte size.
    pub expected_size: i64,
}

/// Desired per-placement publication progress update.
#[derive(Debug, Clone)]
pub struct SetRegistryPublicationPlacement {
    /// Publication being materialized.
    pub publication_id: String,
    /// Destination registry placement.
    pub placement_id: i64,
    /// Whether this placement gates publication readiness.
    pub required: bool,
    /// Publication progress state.
    pub state: String,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
}

/// One physical placement of a registry or binary-cache surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfacePlacementRecord {
    /// Database id.
    pub id: i64,
    /// Registry target, or `None` for a binary-cache placement.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry placement.
    pub cache_id: Option<i64>,
    /// Stable human-readable name within the surface.
    pub name: String,
    /// Storage binding containing the placement.
    pub storage_binding_id: i64,
    /// Surface-relative prefix within the binding.
    pub prefix: String,
    /// Placement role: `primary`, `replica`, `shard`, or `archive`.
    pub role: String,
    /// Operational state.
    pub state: String,
    /// Inventory completeness: `complete`, `partial`, or `unknown`.
    pub completeness: String,
    /// Serialized shard rule; present only for a `shard` placement.
    pub partition_rule_json: Option<String>,
    /// Last completely published mutable-pointer publication.
    pub mutable_publication_id: Option<String>,
    /// Whether reads may select this placement.
    pub read_enabled: bool,
    /// Whether writes may select this placement.
    pub write_enabled: bool,
    /// Lower ordinal is preferred for reads.
    pub read_order: i64,
    /// Lower ordinal is preferred for writes.
    pub write_order: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// A named placement-selection policy for one surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPolicyRecord {
    /// Database id.
    pub id: i64,
    /// Registry target, or `None` for a binary-cache policy.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry policy.
    pub cache_id: Option<i64>,
    /// Stable name within the owning surface.
    pub name: String,
    /// Selection algorithm.
    pub kind: String,
    /// Algorithm-specific serialized configuration.
    pub config_json: String,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// A hostname/path mapping from a domain to one surface and placement policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRouteRecord {
    /// Database id.
    pub id: i64,
    /// Domain owning the hostname.
    pub domain_id: i64,
    /// Source storage gateway for a materialized direct route.
    pub storage_gateway_id: Option<i64>,
    /// Gateway generation that produced this route.
    pub gateway_generation: Option<i64>,
    /// Normalized rooted path, or the empty string for the domain root.
    pub base_path: String,
    /// Registry target, or `None` for a binary-cache route.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry route.
    pub cache_id: Option<i64>,
    /// Delivery mode: `hub_proxy`, `hub_redirect`, or `direct`.
    pub mode: String,
    /// Serialized authorization/access policy.
    pub access_policy_json: String,
    /// Direct placement selection, if this route does not use a policy.
    pub placement_id: Option<i64>,
    /// Placement policy selection, if this route does not pin a placement.
    pub placement_policy_id: Option<i64>,
    /// Whether the route serves the Git surface.
    pub serves_git: bool,
    /// Whether the route serves the Nix-cache surface.
    pub serves_cache: bool,
    /// Whether the route serves the Web surface.
    pub serves_web: bool,
    /// Whether request matching may select the route.
    pub enabled: bool,
    /// Reconciliation/readiness state used by canonical selection.
    pub readiness_state: String,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// Creation-time topology defaults for the instance or one organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyDefaultsRecord {
    /// Database id.
    pub id: i64,
    /// Scope discriminator: `instance` or `organization`.
    pub scope_kind: String,
    /// Organization id for an organization-scoped row.
    pub org_id: Option<i64>,
    /// Stable uniqueness key (`instance` or `org:<id>`).
    pub scope_key: String,
    /// Default storage binding for new placements.
    pub storage_binding_id: Option<i64>,
    /// Default domain for new delivery routes.
    pub domain_id: Option<i64>,
    /// Default storage gateway for new direct routes.
    pub storage_gateway_id: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// A registry-derived retention policy owned by one binary cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRetentionSubscriptionRecord {
    /// Database id.
    pub id: i64,
    /// Binary cache whose GC roots the selector contributes to.
    pub cache_id: i64,
    /// Registry supplying verified artifacts.
    pub registry_id: i64,
    /// Serialized typed retention selector.
    pub selector_json: String,
    /// Grace time before removed reasons become collectable.
    pub removal_grace_secs: i64,
    /// Explicit public-exposure acknowledgement time, when required.
    pub exposure_acknowledged_at: Option<i64>,
    /// Whether refresh evaluates this subscription.
    pub enabled: bool,
    /// Last registry revision successfully materialized.
    pub last_successful_revision: Option<String>,
    /// Last refresh attempt time.
    pub last_refresh_at: Option<i64>,
    /// Authoritative active immutable refresh generation.
    pub current_refresh_id: Option<String>,
    /// Refresh lifecycle: `fresh`, `stale`, `refreshing`, or `failed`.
    pub refresh_state: String,
    /// Last refresh error; prior successful reasons remain live on failure.
    pub refresh_error: Option<String>,
    /// Retirement time, or `None` while the subscription is active.
    pub retired_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// A registry workflow destination that populates one binary cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePopulationTargetRecord {
    /// Database id.
    pub id: i64,
    /// Destination binary cache.
    pub cache_id: i64,
    /// Source registry.
    pub registry_id: i64,
    /// Population trigger: `release`, `manual`, or `continuous`.
    pub trigger_kind: String,
    /// Whether failure blocks the publishing workflow.
    pub required: bool,
    /// Placement write policy, when population does not use the cache default.
    pub placement_policy_id: Option<i64>,
    /// Serialized artifact selector.
    pub selector_json: String,
    /// Required validation gate.
    pub validation_gate: String,
    /// Whether the target may enqueue population work.
    pub enabled: bool,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// One logical object owned by a registry or binary-cache surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceObjectRecord {
    /// Database id.
    pub id: i64,
    /// Registry target, or `None` for a binary-cache object.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry object.
    pub cache_id: Option<i64>,
    /// Surface-relative object key.
    pub object_key: String,
    /// Content digest, when known.
    pub content_hash: Option<String>,
    /// Object size in bytes, when known.
    pub size: Option<i64>,
    /// Object kind: `immutable` or `mutable_pointer`.
    pub object_kind: String,
    /// Authoritative publication owning a mutable pointer.
    pub mutable_publication_id: Option<String>,
    /// Logical lifecycle: `active` or `tombstoned`.
    pub lifecycle_state: String,
    /// Tombstone time, or `None` while active.
    pub tombstoned_at: Option<i64>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Observed presence of one logical object at one same-surface placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPlacementRecord {
    /// Logical object.
    pub surface_object_id: i64,
    /// Physical placement.
    pub placement_id: i64,
    /// Presence state.
    pub state: String,
    /// Observed content digest.
    pub observed_hash: Option<String>,
    /// Observed size in bytes.
    pub observed_size: Option<i64>,
    /// Backend entity tag.
    pub etag: Option<String>,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
}

/// Durable deletion of a tombstoned object from one placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDeletionJobRecord {
    /// Stable opaque job id.
    pub job_id: String,
    /// Tombstoned logical object.
    pub surface_object_id: i64,
    /// Placement from which the object is deleted.
    pub placement_id: i64,
    /// Job lifecycle state.
    pub state: String,
    /// Number of physical deletion attempts.
    pub attempt_count: i64,
    /// Last failure detail.
    pub error: Option<String>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Start time in Unix seconds.
    pub started_at: Option<i64>,
    /// Finish time in Unix seconds.
    pub finished_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// A typed reference to either kind of servable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceTarget {
    /// A registry surface by database id.
    Registry(i64),
    /// A managed binary-cache surface by database id.
    BinaryCache(i64),
}

impl SurfaceTarget {
    /// Returns the nullable database ids used by the topology tables.
    fn ids(self) -> (Option<i64>, Option<i64>) {
        match self {
            Self::Registry(id) => (Some(id), None),
            Self::BinaryCache(id) => (None, Some(id)),
        }
    }
}

/// Input for creating a domain resource.
#[derive(Debug, Clone)]
pub struct NewDomain {
    /// Owning organization, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Hostname without scheme, port, path, query, or fragment.
    pub hostname: String,
    /// Optional DNS provider identifier.
    pub desired_dns_provider: Option<String>,
    /// Optional TLS provider identifier.
    pub desired_tls_provider: Option<String>,
    /// Serialized external-access-provider declaration.
    pub access_provider_json: String,
}

/// Input for a version-checked domain lifecycle update.
#[derive(Debug, Clone)]
pub struct UpdateDomain {
    /// Expected optimistic-concurrency version.
    pub expected_version: i64,
    /// Optional DNS provider identifier.
    pub desired_dns_provider: Option<String>,
    /// Optional TLS provider identifier.
    pub desired_tls_provider: Option<String>,
    /// Serialized external-access-provider declaration.
    pub access_provider_json: String,
}

/// Input for creating a physical surface placement.
#[derive(Debug, Clone)]
pub struct NewSurfacePlacement {
    /// Surface receiving the placement.
    pub surface: SurfaceTarget,
    /// Stable human-readable name within the surface.
    pub name: String,
    /// Storage binding containing the placement.
    pub storage_binding_id: i64,
    /// Surface-relative prefix within the binding.
    pub prefix: String,
    /// `primary`, `replica`, `shard`, or `archive`.
    pub role: String,
    /// Initial operational state.
    pub state: String,
    /// Initial inventory completeness.
    pub completeness: String,
    /// Serialized shard rule, required only for `shard`.
    pub partition_rule_json: Option<String>,
    /// Whether reads may select the placement.
    pub read_enabled: bool,
    /// Whether writes may select the placement.
    pub write_enabled: bool,
    /// Lower ordinal is preferred for reads.
    pub read_order: i64,
    /// Lower ordinal is preferred for writes.
    pub write_order: i64,
}

/// Input for a version-checked placement update.
#[derive(Debug, Clone)]
pub struct UpdateSurfacePlacement {
    /// Expected optimistic-concurrency version.
    pub expected_version: i64,
    /// New operational state.
    pub state: String,
    /// New inventory completeness.
    pub completeness: String,
    /// Serialized shard rule, required only for `shard`.
    pub partition_rule_json: Option<String>,
    /// Whether reads may select the placement.
    pub read_enabled: bool,
    /// Whether writes may select the placement.
    pub write_enabled: bool,
    /// Lower ordinal is preferred for reads.
    pub read_order: i64,
    /// Lower ordinal is preferred for writes.
    pub write_order: i64,
}

/// Input for creating a placement-selection policy.
#[derive(Debug, Clone)]
pub struct NewPlacementPolicy {
    /// Surface owning the policy.
    pub surface: SurfaceTarget,
    /// Stable name within the surface.
    pub name: String,
    /// Selection algorithm.
    pub kind: String,
    /// Serialized algorithm-specific configuration.
    pub config_json: String,
}

/// One desired member of a placement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementPolicyMemberInput {
    /// Placement to select.
    pub placement_id: i64,
    /// Lower ordinal is selected first.
    pub member_order: i64,
    /// Whether an unavailable member makes the policy unhealthy.
    pub required: bool,
}

/// One stored member of a placement-selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementPolicyMemberRecord {
    /// Owning policy.
    pub policy_id: i64,
    /// Selected placement.
    pub placement_id: i64,
    /// Lower ordinal is selected first.
    pub member_order: i64,
    /// Whether an unavailable member makes the policy unhealthy.
    pub required: bool,
}

/// A route's placement selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePlacementSelector {
    /// Pin the route to one placement.
    Placement(i64),
    /// Select through a named placement policy.
    Policy(i64),
}

impl RoutePlacementSelector {
    /// Returns the nullable ids used by `delivery_routes`.
    fn ids(self) -> (Option<i64>, Option<i64>) {
        match self {
            Self::Placement(id) => (Some(id), None),
            Self::Policy(id) => (None, Some(id)),
        }
    }
}

/// Input for creating a delivery route.
#[derive(Debug, Clone)]
pub struct NewDeliveryRoute {
    /// Domain owning the route's hostname.
    pub domain_id: i64,
    /// Materializing storage gateway, for a gateway-derived direct route.
    pub storage_gateway_id: Option<i64>,
    /// Gateway generation that materialized the route.
    pub gateway_generation: Option<i64>,
    /// Rooted path, or empty for the hostname root.
    pub base_path: String,
    /// Surface served by the route.
    pub surface: SurfaceTarget,
    /// `hub_proxy`, `hub_redirect`, or `direct`.
    pub mode: String,
    /// Serialized authorization/access policy.
    pub access_policy_json: String,
    /// Placement or placement-policy selector.
    pub selector: RoutePlacementSelector,
    /// Whether the route serves Git.
    pub serves_git: bool,
    /// Whether the route serves the Nix cache protocol.
    pub serves_cache: bool,
    /// Whether the route serves Web pages.
    pub serves_web: bool,
    /// Whether request matching may select the route.
    pub enabled: bool,
}

/// Input for a version-checked delivery-route behavior update.
#[derive(Debug, Clone)]
pub struct UpdateDeliveryRoute {
    /// Expected optimistic-concurrency version.
    pub expected_version: i64,
    /// Delivery mode.
    pub mode: String,
    /// Serialized authorization/access policy.
    pub access_policy_json: String,
    /// Whether the route serves Git.
    pub serves_git: bool,
    /// Whether the route serves the Nix cache protocol.
    pub serves_cache: bool,
    /// Whether the route serves Web pages.
    pub serves_web: bool,
    /// Whether request matching may select the route.
    pub enabled: bool,
}

/// One canonical route selection for a protocol audience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRouteRecord {
    /// Database id.
    pub id: i64,
    /// Surface owning the selection.
    pub surface: SurfaceTarget,
    /// `git`, `nix_cache`, or `web`.
    pub audience: String,
    /// Selected delivery route.
    pub delivery_route_id: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Scope receiving creation-time topology defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyScope {
    /// Instance scope.
    Instance,
    /// Organization scope by database id.
    Organization(i64),
}

/// Input for setting creation-time topology defaults.
#[derive(Debug, Clone)]
pub struct SetTopologyDefaults {
    /// Scope receiving the defaults.
    pub scope: TopologyScope,
    /// Default storage binding for new placements.
    pub storage_binding_id: Option<i64>,
    /// Default domain for new routes.
    pub domain_id: Option<i64>,
    /// Default storage gateway for new direct routes.
    pub storage_gateway_id: Option<i64>,
    /// Expected version, or `None` when creating the row.
    pub expected_version: Option<i64>,
}

/// Input for creating or replacing a retention subscription.
#[derive(Debug, Clone)]
pub struct SetCacheRetentionSubscription {
    /// Destination binary cache.
    pub cache_id: i64,
    /// Artifact-source registry.
    pub registry_id: i64,
    /// Serialized typed selector.
    pub selector_json: String,
    /// Grace time before removed reasons become collectable.
    pub removal_grace_secs: i64,
    /// Explicit public-exposure acknowledgement time.
    pub exposure_acknowledged_at: Option<i64>,
    /// Whether refresh evaluates this subscription.
    pub enabled: bool,
    /// Expected version, or `None` when creating the subscription.
    pub expected_version: Option<i64>,
}

/// One immutable registry-derived reason staged by a retention refresh.
#[derive(Debug, Clone)]
pub struct RetentionRefreshReasonInput {
    /// Stable reason identity within the cache.
    pub reason_key: String,
    /// Nix store hash retained by the reason.
    pub store_hash: String,
    /// `registry_catalog`, `release`, or `channel`.
    pub source_kind: String,
    /// Human-inspectable source identity.
    pub source_ref: String,
    /// Stable release provenance for release/channel reasons.
    pub release_id: Option<i64>,
    /// Channel provenance for channel reasons.
    pub channel_id: Option<i64>,
    /// Channel partition bucket for channel reasons.
    pub partition_bucket: Option<i64>,
    /// Optional reason-specific expiry.
    pub expires_at: Option<i64>,
}

/// Input for creating or updating a logical surface object.
#[derive(Debug, Clone)]
pub struct SetSurfaceObject {
    /// Owning surface.
    pub surface: SurfaceTarget,
    /// Surface-relative object key.
    pub object_key: String,
    /// Content digest, when known.
    pub content_hash: Option<String>,
    /// Object size in bytes, when known.
    pub size: Option<i64>,
    /// `immutable` or `mutable_pointer`.
    pub object_kind: String,
    /// Authoritative registry publication for a mutable pointer.
    pub mutable_publication_id: Option<String>,
}

/// Input for recording same-surface object presence.
#[derive(Debug, Clone)]
pub struct SetObjectPlacement {
    /// Logical object.
    pub surface_object_id: i64,
    /// Placement observing the object.
    pub placement_id: i64,
    /// `present`, `copying`, `missing`, `corrupt`, or `deleting`.
    pub state: String,
    /// Observed content digest.
    pub observed_hash: Option<String>,
    /// Observed size in bytes.
    pub observed_size: Option<i64>,
    /// Backend entity tag.
    pub etag: Option<String>,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
}

/// Input for scheduling one physical deletion of a tombstoned object.
#[derive(Debug, Clone)]
pub struct NewObjectDeletionJob {
    /// Stable opaque job id.
    pub job_id: String,
    /// Tombstoned logical object.
    pub surface_object_id: i64,
    /// Same-surface placement containing the object.
    pub placement_id: i64,
}

/// Input for creating or replacing a population target.
#[derive(Debug, Clone)]
pub struct SetCachePopulationTarget {
    /// Destination binary cache.
    pub cache_id: i64,
    /// Artifact-source registry.
    pub registry_id: i64,
    /// `release`, `manual`, or `continuous`.
    pub trigger_kind: String,
    /// Whether failure blocks publication.
    pub required: bool,
    /// Placement policy controlling destination writes.
    pub placement_policy_id: Option<i64>,
    /// Serialized artifact selector.
    pub selector_json: String,
    /// `none`, `presence`, `closure`, or `deep`.
    pub validation_gate: String,
    /// Whether population work may be enqueued.
    pub enabled: bool,
    /// Expected version, or `None` when creating the target.
    pub expected_version: Option<i64>,
}

/// An immutable semantic plan awaiting an explicit apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPlanRecord {
    /// Stable opaque plan id.
    pub plan_id: String,
    /// Operation family that produced the plan.
    pub plan_kind: String,
    /// Actor kind captured at planning time.
    pub actor_kind: String,
    /// Actor database id, when applicable.
    pub actor_id: Option<i64>,
    /// Human-readable actor label.
    pub actor_label: String,
    /// Authorization scope.
    pub scope: String,
    /// Serialized input resource versions.
    pub input_versions_json: String,
    /// Serialized semantic effects.
    pub effects_json: String,
    /// Serialized warnings.
    pub warnings_json: String,
    /// Hash of a required confirmation token.
    pub confirmation_hash: Option<String>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Expiry time in Unix seconds.
    pub expires_at: i64,
    /// Apply time, or `None` while unused.
    pub applied_at: Option<i64>,
}

/// Input for storing an immutable semantic plan.
#[derive(Debug, Clone)]
pub struct NewTopologyPlan {
    /// Stable opaque plan id.
    pub plan_id: String,
    /// Operation family that produced the plan.
    pub plan_kind: String,
    /// Actor kind captured at planning time.
    pub actor_kind: String,
    /// Actor database id, when applicable.
    pub actor_id: Option<i64>,
    /// Human-readable actor label.
    pub actor_label: String,
    /// Authorization scope.
    pub scope: String,
    /// Serialized input resource versions.
    pub input_versions_json: String,
    /// Serialized semantic effects.
    pub effects_json: String,
    /// Serialized warnings.
    pub warnings_json: String,
    /// Hash of a required confirmation token.
    pub confirmation_hash: Option<String>,
    /// Expiry time in Unix seconds.
    pub expires_at: i64,
}

/// A durable long-running topology operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyOperationRecord {
    /// Stable opaque operation id.
    pub operation_id: String,
    /// Operation family.
    pub operation_kind: String,
    /// Registry target, when applicable.
    pub registry_id: Option<i64>,
    /// Binary-cache target, when applicable.
    pub cache_id: Option<i64>,
    /// Placement target, when applicable.
    pub placement_id: Option<i64>,
    /// Lifecycle state.
    pub state: String,
    /// Completed work units.
    pub progress_current: i64,
    /// Total work units, when known.
    pub progress_total: Option<i64>,
    /// Serialized operation-specific status.
    pub detail_json: String,
    /// Failure detail.
    pub error: Option<String>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Start time in Unix seconds.
    pub started_at: Option<i64>,
    /// Finish time in Unix seconds.
    pub finished_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Input for creating a durable topology operation.
#[derive(Debug, Clone)]
pub struct NewTopologyOperation {
    /// Stable opaque operation id.
    pub operation_id: String,
    /// Operation family.
    pub operation_kind: String,
    /// Optional surface target.
    pub surface: Option<SurfaceTarget>,
    /// Optional placement target.
    pub placement_id: Option<i64>,
    /// Serialized operation-specific status.
    pub detail_json: String,
    /// Total work units, when known.
    pub progress_total: Option<i64>,
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
    /// Committed registry readme (longer preamble).
    pub readme: Option<String>,
    /// The committed `[caches]` stack flattened to `(url, priority)` entries.
    ///
    /// This is the priority list a stack-unaware client resolves; when the
    /// snapshot also carries a [`Self::cache_stack`] it is the flattening of
    /// that same stack.
    pub caches: Vec<(String, u32)>,
    /// The committed `[caches]` stack expression as compact JSON
    /// ([`crate::stack::StackNode::to_json`]), or `None` when the registry's
    /// `[caches]` is a legacy flat list.
    pub cache_stack: Option<String>,
    /// Roster entries as `(key_id, public_key, status)`.
    pub roster: Vec<(String, String, String)>,
    /// Full package documents.
    pub packages: Vec<aos_registry_surface::manifest::PackageToml>,
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
    /// Draft ref the hub wrote for a git-backed change request
    /// (`refs/hub/changes/<change_id>`), or `None` for a SQL-only change-set.
    pub git_ref: Option<String>,
    /// Signed draft-commit oid the [`Self::git_ref`] points at, or `None` for
    /// a SQL-only change-set.
    pub git_commit: Option<String>,
    /// Human title the proposer gave the change request, or `None` for change-
    /// sets opened before the review surface existed (fall back to
    /// [`Self::summary`]).
    pub title: Option<String>,
    /// Optional free-text description the proposer wrote, or `None`.
    pub body: Option<String>,
    /// Unix time an open draft was *withdrawn* (closed without merging), or
    /// `None` when open or reopened. Orthogonal to [`Self::status`]: a closed
    /// change-set keeps `status = 'draft'` so the indexer can still flip it to
    /// `applied` if its ref is later promoted.
    pub closed_at: Option<i64>,
}

/// One discussion comment on a change request (system-of-record row).
#[derive(Debug, Clone)]
pub struct ChangeCommentRow {
    /// Row id (monotonic; the timeline orders by it).
    pub id: i64,
    /// The change-set this comment belongs to.
    pub change_id: String,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Owning principal's row id, when applicable.
    pub actor_id: Option<i64>,
    /// Human label of the comment's author.
    pub actor_label: String,
    /// The comment text (plain, rendered escaped).
    pub body: String,
    /// Unix time the comment was posted.
    pub created_at: i64,
}

/// One advisory review on a change request (system-of-record row).
///
/// Reviews carry no enforcement: promotion is via `apr change merge`, so an
/// `approve` unlocks nothing. They are recorded for the conversation timeline.
#[derive(Debug, Clone)]
pub struct ChangeReviewRow {
    /// Row id (monotonic; the timeline orders by it).
    pub id: i64,
    /// The change-set this review belongs to.
    pub change_id: String,
    /// Actor kind: `user`, `service_account`, `key`, or `system`.
    pub actor_kind: String,
    /// Owning principal's row id, when applicable.
    pub actor_id: Option<i64>,
    /// Human label of the reviewer.
    pub actor_label: String,
    /// The verdict: `approve` or `request_changes`.
    pub verdict: String,
    /// Optional review note, or `None`.
    pub body: Option<String>,
    /// Unix time the review was submitted.
    pub created_at: i64,
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

/// One webhook subscription (system-of-record row).
///
/// An org's HTTP notification endpoint plus the event types it wants and the
/// shared secret its deliveries are HMAC-signed under (see [`crate::webhook`]).
#[derive(Debug, Clone)]
pub struct WebhookRecord {
    /// Database id.
    pub id: i64,
    /// Owning org id.
    pub org_id: i64,
    /// Destination URL each subscribed event is `POST`ed to.
    pub url: String,
    /// The HMAC-SHA256 signing secret shared with the subscriber.
    pub secret: String,
    /// Subscribed event-type strings; empty means *all* events.
    pub events: Vec<String>,
    /// Whether the subscription currently receives deliveries.
    pub active: bool,
    /// Unix time the subscription was created.
    pub created_at: i64,
}

impl WebhookRecord {
    /// Whether this webhook is subscribed to `event_type`.
    ///
    /// An empty subscription list matches every event.
    #[must_use]
    pub fn subscribes_to(&self, event_type: &str) -> bool {
        self.events.is_empty() || self.events.iter().any(|e| e == event_type)
    }
}

/// A due delivery joined with its webhook's URL and secret.
///
/// Produced by [`Database::due_deliveries`]; the [delivery worker]
/// (`crate::webhook::deliver_one`) needs the URL and secret alongside the
/// payload to sign and `POST` it.
#[derive(Debug, Clone)]
pub struct DueDelivery {
    /// The `webhook_deliveries` row id.
    pub id: i64,
    /// The webhook this delivery targets.
    pub webhook_id: i64,
    /// The event-type string, mirrored into the `X-AOS-Event` header.
    pub event: String,
    /// The exact JSON body to sign and `POST`.
    pub payload: String,
    /// How many attempts have already been made (for backoff scheduling).
    pub attempts: i64,
    /// The destination URL.
    pub url: String,
    /// The HMAC-SHA256 signing secret.
    pub secret: String,
}

fn row_to_webhook(row: &Row) -> Result<WebhookRecord> {
    let events_json: String = row.get(4)?;
    Ok(WebhookRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        url: row.get(2)?,
        secret: row.get(3)?,
        events: serde_json::from_str(&events_json).unwrap_or_default(),
        active: row.get(5)?,
        created_at: row.get(6)?,
    })
}

/// The hub database handle.
pub struct Database {
    backend: Box<dyn Backend>,
}

impl Database {
    /// Open (creating and migrating if needed) the hub sqlite database.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or a migration fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open(path: &Path) -> Result<Self> {
        let path_str = path
            .to_str()
            .with_context(|| format!("hub database path is not valid UTF-8: {}", path.display()))?;
        let backend = SqlxBackend::connect_sqlite(path_str)
            .await
            .with_context(|| format!("opening hub database {}", path.display()))?;
        Self::with_backend(Box::new(backend)).await
    }

    /// Open an in-memory sqlite database (tests only).
    ///
    /// `serve --dev` does *not* use this: dev mode persists a regular
    /// `hub.db` under its `--root` directory (defaulting to `./.aos-hub`).
    ///
    /// # Errors
    ///
    /// Returns an error if a migration fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open_in_memory() -> Result<Self> {
        let backend = SqlxBackend::connect_sqlite(":memory:").await?;
        Self::with_backend(Box::new(backend)).await
    }

    /// Connect to a hub database by URL, dispatching on the scheme.
    ///
    /// The native self-hosting entry point (RFC-0004 "Database abstraction"):
    ///
    /// - `sqlite://<path>`, `file://<path>`, or a bare filesystem path → the
    ///   always-available sqlite [`SqlxBackend`].
    /// - `postgres://…` / `postgresql://…` → the postgres [`SqlxBackend`], when
    ///   the crate is built with the `postgres` feature (else an error).
    /// - `mysql://…` → the mysql [`SqlxBackend`], when built with the `mysql`
    ///   feature (else an error).
    ///
    /// In every case the schema is created and migrated to the current
    /// version before returning.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported scheme, a backend whose feature is
    /// not enabled, a connection failure, or a migration failure.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(url: &str) -> Result<Self> {
        if let Some(rest) = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
        {
            let _ = rest;
            #[cfg(feature = "postgres")]
            {
                let backend = SqlxBackend::connect_postgres(url).await?;
                return Self::with_backend(Box::new(backend)).await;
            }
            #[cfg(not(feature = "postgres"))]
            {
                bail!("postgres support not compiled in (build with --features postgres)");
            }
        }
        if let Some(rest) = url.strip_prefix("mysql://") {
            let _ = rest;
            #[cfg(feature = "mysql")]
            {
                let backend = SqlxBackend::connect_mysql(url).await?;
                return Self::with_backend(Box::new(backend)).await;
            }
            #[cfg(not(feature = "mysql"))]
            {
                bail!("mysql support not compiled in (build with --features mysql)");
            }
        }
        // sqlite:// or file:// or a bare path.
        let path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("file://"))
            .unwrap_or(url);
        if path.is_empty() || path == ":memory:" {
            return Self::open_in_memory().await;
        }
        Self::open(Path::new(path)).await
    }

    pub async fn with_backend(backend: Box<dyn Backend>) -> Result<Self> {
        let db = Self { backend };
        db.migrate().await?;
        Ok(db)
    }

    /// Wraps an already-migrated `backend` **without** running migrations.
    ///
    /// For read paths that open a fresh handle per request against a database
    /// some other path already migrated — notably the Cloudflare Worker, whose
    /// schema is applied by the operator CLI (`aos-hub init --target
    /// d1:<name>`) and which must not pay a migration round-trip on every read.
    /// Use
    /// [`with_backend`](Self::with_backend) when the caller owns the schema and
    /// should migrate it.
    #[must_use]
    pub fn attach(backend: Box<dyn Backend>) -> Self {
        Self { backend }
    }

    /// The SQL dialect of the underlying backend.
    fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    async fn migrate(&self) -> Result<()> {
        self.backend
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
                &[],
            )
            .await?;
        let current: i64 = self
            .backend
            .query_opt("SELECT version FROM schema_version", &[])
            .await?
            .map(|row| row.get::<i64>(0))
            .transpose()?
            .unwrap_or(0);
        let target = MIGRATIONS.len() as i64;
        if current > target {
            bail!("hub database schema {current} is newer than this build supports ({target})");
        }
        // Apply all pending migrations as ONE batch. The Cloudflare D1 remote
        // backend runs each `execute_batch` as a separate `wrangler d1 execute
        // --file` round-trip, and a later migration that ALTERs a table created
        // by an earlier one is not reliably consistent across those separate
        // remote executions — so a single combined batch (which the local sqlite
        // and worker-D1 backends run identically) is the portable path.
        if (current as usize) < MIGRATIONS.len() {
            let pending = MIGRATIONS[current as usize..].join("\n");
            self.backend
                .execute_batch(&pending)
                .await
                .with_context(|| format!("applying migrations v{}..=v{}", current + 1, target))?;
        }
        self.backend
            .execute("DELETE FROM schema_version", &[])
            .await?;
        self.backend
            .execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                &vals![target],
            )
            .await?;
        Ok(())
    }

    // -- system of record ---------------------------------------------------

    /// Register a registry (or update its source/trust on re-registration).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn register_registry(
        &self,
        slug: &str,
        source_url: &str,
        trust_keys: &[String],
        require_signatures: bool,
    ) -> Result<i64> {
        let now = unix_now();
        self.backend.execute(
            "INSERT INTO registries (slug, source_url, trust_keys, require_signatures, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(slug) DO UPDATE SET
                 source_url = excluded.source_url,
                 trust_keys = excluded.trust_keys,
                 require_signatures = excluded.require_signatures",
            &vals![
                slug,
                source_url,
                serde_json::to_string(trust_keys)?,
                require_signatures,
                now,
            ],
        ).await?;
        let id: i64 = self
            .backend
            .query_opt("SELECT id FROM registries WHERE slug = ?1", &vals![slug])
            .await?
            .context("registry row missing after upsert")?
            .get(0)?;
        // A freshly-created registry has nothing published yet, so it starts in
        // the terminal `empty` state — not `indexing` (which reads as work in
        // progress). The indexer's transient-error guard protects this state, so
        // a flaky `info/refs` read can't bump an empty registry to `pending`; the
        // first successful surface read after a publish moves it to `fresh`.
        self.backend
            .execute(
                "INSERT INTO registry_index (registry_id, state)
             VALUES (?1, 'empty')
             ON CONFLICT(registry_id) DO NOTHING",
                &vals![id],
            )
            .await?;
        Ok(id)
    }

    /// Look up a registry by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_by_slug(&self, slug: &str) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE slug = ?1"),
                &vals![slug],
            )
            .await
            .context("loading registry by slug")?
            .map(|row| row_to_registry(&row))
            .transpose()
    }

    /// Look up a registry by its database id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_by_id(&self, registry_id: i64) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE id = ?1"),
                &vals![registry_id],
            )
            .await
            .context("loading registry by id")?
            .map(|row| row_to_registry(&row))
            .transpose()
    }

    /// List all registered registries that are servable.
    ///
    /// Registries owned by a soft-deleted org are excluded (a tombstoned org
    /// stops serving every one of its registries); unowned phase-1 registries
    /// (`org_id IS NULL`) always pass.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_registries(&self) -> Result<Vec<RegistryRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {REGISTRY_COLUMNS} FROM registries r
                 WHERE r.org_id IS NULL
                    OR NOT EXISTS (
                        SELECT 1 FROM orgs o
                        WHERE o.id = r.org_id AND o.deleted_at IS NOT NULL
                    )
                 ORDER BY r.slug"
                ),
                &[],
            )
            .await?;
        rows.iter().map(row_to_registry).collect()
    }

    /// List the registries owned by one org, ordered by slug.
    ///
    /// Unlike [`Database::list_registries`], this does **not** filter by the
    /// owning org's soft-delete state — it is the admin/export view, so it
    /// returns an org's registries even while the org is tombstoned during its
    /// offboarding grace window.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_registries_including_org(&self, org_id: i64) -> Result<Vec<RegistryRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {REGISTRY_COLUMNS} FROM registries WHERE org_id = ?1 ORDER BY slug"
                ),
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_registry).collect()
    }

    // -- index writes -------------------------------------------------------

    /// Replace a registry's entire index with a fresh snapshot, atomically.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    pub async fn apply_snapshot(&self, registry_id: i64, snapshot: &IndexSnapshot) -> Result<()> {
        // Assign surrogate ids client-side so the whole snapshot is one
        // self-contained batch (D1 has no mid-batch `last_insert_rowid`). The
        // bases are read once before the batch; the indexer runs sequentially
        // per registry (main.rs), so no concurrent writer collides on them, and
        // assigning ids in insertion order preserves the `MAX(package_versions
        // .id)` "latest version" ordering the read path relies on. Leaf tables
        // (version_platforms, releases) keep implicit autoincrement — nothing
        // reads their id back.
        let mut next_package = self.max_id("packages").await?;
        let mut next_version = self.max_id("package_versions").await?;
        let mut next_channel = self.max_id("channels").await?;

        let mut stmts: Vec<Statement> = Vec::new();
        for table in ["packages", "key_rosters", "advertised_caches"] {
            stmts.push(Statement::new(
                format!("DELETE FROM {table} WHERE registry_id = ?1"),
                vals![registry_id].to_vec(),
            ));
        }

        for package in &snapshot.packages {
            next_package += 1;
            let package_id = next_package;
            stmts.push(Statement::new(
                "INSERT INTO packages
                 (id, registry_id, name, description, homepage, license, maintainer, sysroot)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vals![
                    package_id,
                    registry_id,
                    package.package.name,
                    package.package.description,
                    package.package.homepage,
                    package.package.license,
                    package.package.maintainer,
                    package.package.sysroot,
                ]
                .to_vec(),
            ));
            for version in &package.versions {
                next_version += 1;
                let version_id = next_version;
                stmts.push(Statement::new(
                    "INSERT INTO package_versions (id, package_id, version, previous)
                     VALUES (?1, ?2, ?3, ?4)",
                    vals![version_id, package_id, version.version, version.previous].to_vec(),
                ));
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
                    stmts.push(Statement::new(
                        "INSERT INTO version_platforms
                         (version_id, platform, store_path, nar_hash, nar_size,
                          closure_size, refs, images, source_drv)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        vals![
                            version_id,
                            platform,
                            entry.store_path,
                            entry.nar_hash,
                            entry.nar_size,
                            entry.closure_size,
                            serde_json::to_string(&entry.references)?,
                            serde_json::Value::Array(images).to_string(),
                            entry.source_drv,
                        ]
                        .to_vec(),
                    ));
                }
            }
        }

        for release in &snapshot.releases {
            if let Some(existing) = self
                .backend
                .query_opt(
                    "SELECT tag_oid, commit_oid FROM releases
                     WHERE registry_id = ?1 AND semver = ?2",
                    &vals![registry_id, release.semver],
                )
                .await?
            {
                let existing_tag_oid: String = existing.get(0)?;
                let existing_commit_oid: String = existing.get(1)?;
                if existing_tag_oid != release.tag_oid || existing_commit_oid != release.commit_oid
                {
                    bail!(
                        "release '{}' changed stable tag/commit identity",
                        release.semver
                    );
                }
            }
            stmts.push(Statement::new(
                "INSERT INTO releases
                 (registry_id, semver, tag_oid, commit_oid, signer, tagged_at, pack_present)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(registry_id, semver) DO UPDATE SET
                   signer = excluded.signer, tagged_at = excluded.tagged_at,
                   pack_present = excluded.pack_present",
                vals![
                    registry_id,
                    release.semver,
                    release.tag_oid,
                    release.commit_oid,
                    release.signer,
                    release.tagged_at,
                    release.pack_present,
                ]
                .to_vec(),
            ));
        }

        stmts.push(Statement::new(
            "UPDATE channels SET active = 0 WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        for channel in &snapshot.channels {
            let channel_id = if let Some(row) = self
                .backend
                .query_opt(
                    "SELECT id FROM channels WHERE registry_id = ?1 AND name = ?2",
                    &vals![registry_id, channel.name],
                )
                .await?
            {
                row.get(0)?
            } else {
                next_channel += 1;
                next_channel
            };
            stmts.push(Statement::new(
                "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT(registry_id, name) DO UPDATE SET
                   frontier = excluded.frontier, active = 1",
                vals![channel_id, registry_id, channel.name, channel.frontier].to_vec(),
            ));
            for (bucket, release) in channel.partitions.iter().enumerate() {
                if let Some(release) = release {
                    stmts.push(Statement::new(
                        "INSERT INTO channel_partitions (channel_id, bucket, release)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(channel_id, bucket) DO UPDATE SET release = excluded.release",
                        vals![channel_id, bucket as i64, release].to_vec(),
                    ));
                } else {
                    stmts.push(Statement::new(
                        "DELETE FROM channel_partitions WHERE channel_id = ?1 AND bucket = ?2",
                        vals![channel_id, bucket as i64].to_vec(),
                    ));
                }
            }
        }

        for (key_id, public_key, status) in &snapshot.roster {
            stmts.push(Statement::new(
                "INSERT INTO key_rosters (registry_id, key_id, public_key, status)
                 VALUES (?1, ?2, ?3, ?4)",
                vals![registry_id, key_id, public_key, status].to_vec(),
            ));
        }
        for (url, priority) in &snapshot.caches {
            stmts.push(Statement::new(
                "INSERT INTO advertised_caches (registry_id, url, priority) VALUES (?1, ?2, ?3)",
                vals![registry_id, url, *priority].to_vec(),
            ));
        }

        self.backend.batch(&stmts).await?;
        for release in &snapshot.releases {
            let row = self
                .backend
                .query_opt(
                    "SELECT 1 FROM releases WHERE registry_id = ?1 AND semver = ?2
                   AND tag_oid = ?3 AND commit_oid = ?4",
                    &vals![
                        registry_id,
                        release.semver,
                        release.tag_oid,
                        release.commit_oid
                    ],
                )
                .await?;
            if row.is_none() {
                bail!(
                    "release '{}' stable identity changed during snapshot application",
                    release.semver
                );
            }
        }
        self.backend
            .execute(
                "INSERT INTO registry_index
             (registry_id, state, error, last_indexed_commit, name, description, readme,
              indexed_at, refs_digest, cache_stack)
             VALUES (?1, 'fresh', NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(registry_id) DO UPDATE SET
                 state = 'fresh', error = NULL,
                 last_indexed_commit = excluded.last_indexed_commit,
                 name = excluded.name, description = excluded.description,
                 readme = excluded.readme,
                 indexed_at = excluded.indexed_at,
                 refs_digest = excluded.refs_digest,
                 cache_stack = excluded.cache_stack",
                &vals![
                    registry_id,
                    snapshot.commit,
                    snapshot.name,
                    snapshot.description,
                    snapshot.readme,
                    unix_now(),
                    snapshot.refs_digest,
                    snapshot.cache_stack,
                ],
            )
            .await?;
        Ok(())
    }

    /// Returns the current maximum `id` in `table`, or `0` when it is empty.
    ///
    /// Used to allocate surrogate ids client-side before a batch insert, so the
    /// batch carries no mid-flight `last_insert_rowid` round-trip (the seam the
    /// native backends and Cloudflare D1 share). `table` must be a trusted
    /// literal — it is interpolated directly into the query.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    async fn max_id(&self, table: &str) -> Result<i64> {
        let row = self
            .backend
            .query_opt(&format!("SELECT COALESCE(MAX(id), 0) FROM {table}"), &[])
            .await?
            .context("COALESCE(MAX(id), 0) returned no row")?;
        row.get(0)
    }

    /// Record an indexing failure without touching the last good index.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_index_failed(&self, registry_id: i64, error: &str) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'failed', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'failed', error = excluded.error",
                &vals![registry_id, error],
            )
            .await?;
        Ok(())
    }

    /// Mark a registry's index `pending`: it has no published surface yet (a
    /// freshly-created registry whose `info/refs` does not exist).
    ///
    /// This is a benign, non-error state — distinct from `failed` (a real,
    /// surfaced indexing error) — so a newly created registry reads as "nothing
    /// published yet" rather than broken. The `error` column is cleared.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_index_pending(&self, registry_id: i64) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'pending', NULL)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'pending', error = NULL",
                &vals![registry_id],
            )
            .await?;
        Ok(())
    }

    /// Mark a registry's index `empty`: it was indexed successfully and there is
    /// nothing published yet (no `info/refs` surface).
    ///
    /// This is a *terminal success* state — the index ran to completion and
    /// found no content — distinct from `pending` (a transient backend hiccup
    /// awaiting retry) and from `failed` (a real error). `indexed_at` is stamped
    /// so the registry reads as "checked, nothing here" rather than "never
    /// indexed", and the last-commit / refs-digest are cleared so the next pass
    /// (once something is published) takes the full index path, not the
    /// unchanged-refs fast path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_index_empty(&self, registry_id: i64) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO registry_index (registry_id, state, error, indexed_at)
             VALUES (?1, 'empty', NULL, ?2)
             ON CONFLICT(registry_id) DO UPDATE SET
                 state = 'empty', error = NULL,
                 last_indexed_commit = NULL, refs_digest = NULL,
                 indexed_at = excluded.indexed_at",
                &vals![registry_id, unix_now()],
            )
            .await?;
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
    pub async fn mark_index_stale(&self, registry_id: i64, error: &str) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'stale', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'stale', error = excluded.error",
                &vals![registry_id, error],
            )
            .await?;
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
    pub async fn update_channels(
        &self,
        registry_id: i64,
        channels: &[ChannelSummary],
    ) -> Result<()> {
        // Client-side channel ids (assigned in order) so this is one batch with
        // no mid-flight `last_insert_rowid`; the per-registry sequential indexer
        // rules out a concurrent writer colliding on the id base.
        let mut next_channel = self.max_id("channels").await?;
        let mut stmts: Vec<Statement> = Vec::new();
        stmts.push(Statement::new(
            "UPDATE channels SET active = 0 WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        for channel in channels {
            let channel_id = if let Some(row) = self
                .backend
                .query_opt(
                    "SELECT id FROM channels WHERE registry_id = ?1 AND name = ?2",
                    &vals![registry_id, channel.name],
                )
                .await?
            {
                row.get(0)?
            } else {
                next_channel += 1;
                next_channel
            };
            stmts.push(Statement::new(
                "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT(registry_id, name) DO UPDATE SET
                   frontier = excluded.frontier, active = 1",
                vals![channel_id, registry_id, channel.name, channel.frontier].to_vec(),
            ));
            for (bucket, release) in channel.partitions.iter().enumerate() {
                if let Some(release) = release {
                    stmts.push(Statement::new(
                        "INSERT INTO channel_partitions (channel_id, bucket, release)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(channel_id, bucket) DO UPDATE SET
                           release = excluded.release",
                        vals![channel_id, bucket as i64, release].to_vec(),
                    ));
                } else {
                    stmts.push(Statement::new(
                        "DELETE FROM channel_partitions
                         WHERE channel_id = ?1 AND bucket = ?2",
                        vals![channel_id, bucket as i64].to_vec(),
                    ));
                }
            }
        }
        stmts.push(Statement::new(
            "UPDATE registry_index SET indexed_at = ?2 WHERE registry_id = ?1",
            vals![registry_id, unix_now()].to_vec(),
        ));
        self.backend.batch(&stmts).await
    }

    // -- anti-rollback floors ------------------------------------------------

    /// The recorded anti-rollback floor for one channel, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn channel_floor(&self, registry_id: i64, channel: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT floor FROM channel_floors WHERE registry_id = ?1 AND channel = ?2",
                &vals![registry_id, channel],
            )
            .await
            .context("loading channel floor")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Set (or overwrite) the anti-rollback floor for one channel.
    ///
    /// Callers are responsible for only ever *raising* the floor; this
    /// method records whatever it is given.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_channel_floor(
        &self,
        registry_id: i64,
        channel: &str,
        floor: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO channel_floors (registry_id, channel, floor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(registry_id, channel) DO UPDATE SET floor = excluded.floor",
                &vals![registry_id, channel, floor],
            )
            .await?;
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
    pub async fn record_validation_run(
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
        let findings: Vec<ValidationFinding> = missing_hashes
            .iter()
            .map(|hash| ValidationFinding {
                store_hash: hash.clone(),
                status: FindingStatus::Missing,
            })
            .collect();
        self.record_validation_run_with_findings(
            registry_id,
            cache_url,
            depth,
            checked,
            &findings,
            reachable,
            started_at,
            finished_at,
        )
        .await
    }

    /// Record one validation run, classifying each finding as `missing` or
    /// `corrupt`.
    ///
    /// The run's `missing` count column is the total number of findings (a
    /// hash that is absent *or* whose downloaded content does not match its
    /// declared hash is, either way, a hash that does not resolve correctly in
    /// the cache). Each finding row carries its own status so the health page
    /// can flag deep-validation corruption distinctly from plain absence.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_validation_run_with_findings(
        &self,
        registry_id: i64,
        cache_url: &str,
        depth: &str,
        checked: u64,
        findings: &[ValidationFinding],
        reachable: bool,
        started_at: i64,
        finished_at: i64,
    ) -> Result<i64> {
        // validation_runs.id feeds each finding's run_id and is read back as
        // MAX(id) for "latest run per cache" (latest_validation_runs) and
        // returned to the caller, so assign it client-side in monotonic order
        // rather than via last_insert_rowid. A concurrent run would collide on
        // the id and its batch would roll back (no corruption); validation is
        // driven per-registry, so that path is effectively sequential.
        let run_id = self.max_id("validation_runs").await? + 1;
        let mut stmts: Vec<Statement> = vec![Statement::new(
            "INSERT INTO validation_runs
             (id, registry_id, cache_url, depth, checked, missing, reachable,
              started_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            vals![
                run_id,
                registry_id,
                cache_url,
                depth,
                checked,
                findings.len() as i64,
                reachable,
                started_at,
                finished_at,
            ]
            .to_vec(),
        )];
        for finding in findings {
            stmts.push(Statement::new(
                "INSERT INTO validation_findings (run_id, store_hash, status)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(run_id, store_hash) DO NOTHING",
                vals![run_id, finding.store_hash, finding.status.as_str()].to_vec(),
            ));
        }
        self.backend.batch(&stmts).await?;
        Ok(run_id)
    }

    /// The latest validation run per cache URL for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn latest_validation_runs(&self, registry_id: i64) -> Result<Vec<ValidationRunRow>> {
        let rows = self.backend.query(
            "SELECT v.id, v.cache_url, v.depth, v.checked, v.missing, v.reachable, v.finished_at
             FROM validation_runs v
             WHERE v.registry_id = ?1
               AND v.id = (SELECT MAX(id) FROM validation_runs
                           WHERE registry_id = ?1 AND cache_url = v.cache_url)
             ORDER BY v.cache_url",
            &vals![registry_id],
        ).await?;
        rows.iter()
            .map(|row| {
                Ok(ValidationRunRow {
                    id: row.get(0)?,
                    cache_url: row.get(1)?,
                    depth: row.get(2)?,
                    checked: row.get(3)?,
                    missing: row.get(4)?,
                    reachable: row.get(5)?,
                    finished_at: row.get(6)?,
                })
            })
            .collect()
    }

    /// The store hashes a validation run found missing, sorted.
    ///
    /// Includes only `missing` findings (absent narinfo/NAR); deep-validation
    /// `corrupt` findings are reported separately by [`Self::validation_corrupt`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn validation_missing(&self, run_id: i64) -> Result<Vec<String>> {
        let rows = self
            .backend
            .query(
                "SELECT store_hash FROM validation_findings
             WHERE run_id = ?1 AND status = 'missing' ORDER BY store_hash",
                &vals![run_id],
            )
            .await?;
        rows.iter().map(|row| row.get(0)).collect()
    }

    /// The store hashes a validation run found corrupt, sorted.
    ///
    /// A `corrupt` finding is recorded only at the hub's `validation::ValidationDepth::Deep`:
    /// a hash whose narinfo and NAR are present, but the downloaded NAR's
    /// content hash does not match the narinfo's declared `FileHash`/`NarHash`.
    /// This is distinct from a `missing` finding (which repair can fix by
    /// copying); corruption flags a cache that must be re-uploaded from a good
    /// source.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn validation_corrupt(&self, run_id: i64) -> Result<Vec<String>> {
        let rows = self
            .backend
            .query(
                "SELECT store_hash FROM validation_findings
             WHERE run_id = ?1 AND status = 'corrupt' ORDER BY store_hash",
                &vals![run_id],
            )
            .await?;
        rows.iter().map(|row| row.get(0)).collect()
    }

    /// Record a repair-job attempt and return its id.
    ///
    /// `status` is one of `pending`, `done`, `failed`, or `plan_only`;
    /// `error` carries the failure detail for `failed` jobs (else `None`), and
    /// `finished_at` is the completion time for terminal jobs (`None` while
    /// pending).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_repair_job(
        &self,
        registry_id: i64,
        cache_url: &str,
        store_hash: &str,
        source_cache_url: &str,
        status: &str,
        error: Option<&str>,
        created_at: i64,
        finished_at: Option<i64>,
    ) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO repair_jobs
             (registry_id, cache_url, store_hash, source_cache_url, status, error,
              created_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &vals![
                    registry_id,
                    cache_url,
                    store_hash,
                    source_cache_url,
                    status,
                    error,
                    created_at,
                    finished_at,
                ],
            )
            .await
    }

    /// The most recent repair jobs for one registry, newest first.
    ///
    /// Capped at `limit` rows for the health-page history.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_repair_jobs(
        &self,
        registry_id: i64,
        limit: i64,
    ) -> Result<Vec<RepairJobRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, cache_url, store_hash, source_cache_url, status, error,
                    created_at, finished_at
             FROM repair_jobs
             WHERE registry_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
                &vals![registry_id, limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(RepairJobRow {
                    id: row.get(0)?,
                    cache_url: row.get(1)?,
                    store_hash: row.get(2)?,
                    source_cache_url: row.get(3)?,
                    status: row.get(4)?,
                    error: row.get(5)?,
                    created_at: row.get(6)?,
                    finished_at: row.get(7)?,
                })
            })
            .collect()
    }

    /// Prune `repair_jobs` rows older than `created_before`, returning the
    /// number deleted.
    ///
    /// `repair_jobs` is an unbounded append-only audit of every repair attempt;
    /// without retention it grows without limit on a busy hub. The serve loop
    /// calls this periodically with `now - retention_window` so the table keeps
    /// only recent history (the health page already pages with a `LIMIT`).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn prune_repair_jobs(&self, created_before: i64) -> Result<u64> {
        self.backend
            .execute(
                "DELETE FROM repair_jobs WHERE created_at < ?1",
                &vals![created_before],
            )
            .await
    }

    /// Records (upserting) the latest freshness probe of one cache endpoint.
    ///
    /// One row is kept per `(registry_id, cache_url)`; re-probing overwrites
    /// the prior observation. See the hub's `probe` module for the producer.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn upsert_cache_probe(
        &self,
        registry_id: i64,
        cache_url: &str,
        status: &str,
        observed_nix_cache_info: bool,
        latency_ms: i64,
        checked_at: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO cache_probes
             (registry_id, cache_url, status, observed_nix_cache_info, latency_ms, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(registry_id, cache_url) DO UPDATE SET
               status = excluded.status,
               observed_nix_cache_info = excluded.observed_nix_cache_info,
               latency_ms = excluded.latency_ms,
               checked_at = excluded.checked_at",
                &vals![
                    registry_id,
                    cache_url,
                    status,
                    observed_nix_cache_info,
                    latency_ms,
                    checked_at,
                ],
            )
            .await?;
        Ok(())
    }

    /// The latest freshness probe per committed cache, for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_probes(&self, registry_id: i64) -> Result<Vec<CacheProbeRow>> {
        let rows = self
            .backend
            .query(
                "SELECT cache_url, status, observed_nix_cache_info, latency_ms, checked_at
             FROM cache_probes WHERE registry_id = ?1 ORDER BY cache_url",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(CacheProbeRow {
                    cache_url: row.get(0)?,
                    status: row.get(1)?,
                    observed_nix_cache_info: row.get(2)?,
                    latency_ms: row.get(3)?,
                    checked_at: row.get(4)?,
                })
            })
            .collect()
    }

    // -- mirror sources + frontends (v16) -----------------------------------

    /// Mark a registry as a mirror of `upstream_url` in `mode`.
    ///
    /// Idempotent: re-running for the same registry updates the upstream URL,
    /// mode, verify flag, and schedule, preserving the last-sync record. `mode`
    /// must be `full` or `pullthrough`. The `upstream_url` is validated as a
    /// safe remote target ([`crate::url_guard::is_safe_remote_url`]) so a mirror
    /// can never be pointed at the local filesystem or an internal address.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode`, an unsafe (local/internal
    /// or non-HTTP) `upstream_url`, or on database failure.
    pub async fn create_mirror_source(
        &self,
        registry_id: i64,
        upstream_url: &str,
        mode: &str,
        verify: bool,
        schedule_secs: i64,
    ) -> Result<()> {
        if !matches!(mode, "full" | "pullthrough") {
            bail!("unsupported mirror mode '{mode}' (expected full or pullthrough)");
        }
        crate::url_guard::is_safe_remote_url(upstream_url)
            .with_context(|| format!("rejecting mirror upstream '{upstream_url}'"))?;
        self.backend
            .execute(
                "INSERT INTO mirror_sources
             (registry_id, upstream_url, mode, verify, schedule_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(registry_id) DO UPDATE SET
               upstream_url = excluded.upstream_url,
               mode = excluded.mode,
               verify = excluded.verify,
               schedule_secs = excluded.schedule_secs",
                &vals![registry_id, upstream_url, mode, verify, schedule_secs],
            )
            .await?;
        Ok(())
    }

    /// Load a registry's mirror source, if it is a mirror.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mirror_source(&self, registry_id: i64) -> Result<Option<MirrorSource>> {
        self.backend
            .query_opt(
                "SELECT upstream_url, mode, verify, schedule_secs, last_sync_at,
                        last_sync_status, last_sync_error, upstream_frontier
                 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading mirror source")?
            .map(|row| row_to_mirror_source(&row))
            .transpose()
    }

    /// List every registry that has a mirror source, paired with the source.
    ///
    /// Used by the serve loop to find mirrors due for a scheduled full sync.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_mirror_sources(&self) -> Result<Vec<(i64, MirrorSource)>> {
        let rows = self
            .backend
            .query(
                "SELECT registry_id, upstream_url, mode, verify, schedule_secs, last_sync_at,
                    last_sync_status, last_sync_error, upstream_frontier
             FROM mirror_sources ORDER BY registry_id",
                &[],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let registry_id: i64 = row.get(0)?;
                Ok((
                    registry_id,
                    MirrorSource {
                        upstream_url: row.get(1)?,
                        mode: row.get(2)?,
                        verify: row.get(3)?,
                        schedule_secs: row.get(4)?,
                        last_sync_at: row.get(5)?,
                        last_sync_status: row.get(6)?,
                        last_sync_error: row.get(7)?,
                        upstream_frontier: row.get(8)?,
                    },
                ))
            })
            .collect()
    }

    /// Whether `registry_id` is a mirror (has a `mirror_sources` row).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn is_mirror(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .is_some())
    }

    /// Stop mirroring: remove a registry's mirror source. Returns whether a row
    /// was removed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_mirror_source(&self, registry_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Record the outcome of a mirror sync attempt.
    ///
    /// `status` is `ok` or `failed`; on success `error` is `None` and
    /// `upstream_frontier` records the synced frontier, on failure `error`
    /// carries the detail and the prior `upstream_frontier` is preserved (so a
    /// failed sync never overwrites the last good frontier with `NULL`).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn update_mirror_sync(
        &self,
        registry_id: i64,
        at: i64,
        status: &str,
        error: Option<&str>,
        upstream_frontier: Option<&str>,
    ) -> Result<()> {
        // On a failed sync, keep the prior upstream_frontier (COALESCE the new
        // NULL onto the old value) so the health page still shows the last good
        // frontier.
        self.backend
            .execute(
                "UPDATE mirror_sources SET
               last_sync_at = ?2,
               last_sync_status = ?3,
               last_sync_error = ?4,
               upstream_frontier = COALESCE(?5, upstream_frontier)
             WHERE registry_id = ?1",
                &vals![registry_id, at, status, error, upstream_frontier],
            )
            .await?;
        Ok(())
    }

    /// Create a frontend serving a registry; returns its new id.
    ///
    /// `mode` must be `direct` or `proxied`. The `(domain, base_path)` pair is
    /// unique across all frontends. The frontend's probe URL (its `domain`,
    /// defaulting to `https://` when no scheme is given) is validated as a safe
    /// remote target ([`crate::url_guard::is_safe_remote_url`]) so a frontend can
    /// never be pointed at the local filesystem or an internal address.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode`, a `(domain, base_path)`
    /// collision, an unsafe (local/internal or non-HTTP) `domain`, or on
    /// database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_frontend(
        &self,
        registry_id: i64,
        domain: &str,
        base_path: &str,
        mode: &str,
        serves_git: bool,
        serves_cache: bool,
        serves_web: bool,
        consumer_priority: i64,
        advertised: bool,
    ) -> Result<i64> {
        if !matches!(mode, "direct" | "proxied") {
            bail!("unsupported frontend mode '{mode}' (expected direct or proxied)");
        }
        // A Direct frontend hands consumers the binding's own origin URL, so the
        // binding must be publicly readable. Rooting a Direct frontend over a
        // private binding would publish unreadable (or, worse, leak-prone) URLs;
        // such a binding must be served proxied/presigned instead. (RFC-0004
        // "Backend access mode".)
        if mode == "direct" {
            let binding_id = self
                .registry_by_id(registry_id)
                .await
                .context("loading registry for frontend access check")?
                .and_then(|r| r.storage_binding_id);
            if let Some(binding_id) = binding_id {
                if let Some(binding) = self.storage_binding(binding_id).await? {
                    if binding.access == "private" {
                        bail!(
                            "cannot create a Direct frontend over private storage binding \
                             '{}': private bindings must be served proxied or presigned",
                            binding.name
                        );
                    }
                }
            }
        }
        // Validate + normalize the bare host and rooted base path (lowercased so
        // a request `Host`, which the dispatcher lowercases, matches and the
        // UNIQUE(domain, base_path) constraint can't be dodged by case).
        let (domain, base_path) = validate_frontend_target(domain, base_path)?;
        self.backend
            .execute_insert(
                "INSERT INTO frontends
             (registry_id, domain, base_path, mode, serves_git, serves_cache,
              serves_web, consumer_priority, advertised, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &vals![
                    registry_id,
                    domain,
                    base_path,
                    mode,
                    serves_git,
                    serves_cache,
                    serves_web,
                    consumer_priority,
                    advertised,
                    unix_now(),
                ],
            )
            .await
    }

    /// Update an existing frontend's mutable fields (domain, base path, mode,
    /// serves-flags, consumer priority, advertised) by id.
    ///
    /// The target (registry / cache / storage binding) is fixed at creation and
    /// not changed here. `domain`/`base_path` are validated and normalized exactly
    /// as on create ([`validate_frontend_target`]); a `direct` mode is rejected
    /// when the frontend's underlying storage binding is `private` (same rule as
    /// create), so an edit can't sneak a Direct frontend onto a private binding.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown id, an invalid mode/domain/base path, a
    /// Direct-over-private violation, or a database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_frontend(
        &self,
        id: i64,
        domain: &str,
        base_path: &str,
        mode: &str,
        serves_git: bool,
        serves_cache: bool,
        serves_web: bool,
        consumer_priority: i64,
        advertised: bool,
    ) -> Result<()> {
        if !matches!(mode, "direct" | "proxied") {
            bail!("unsupported frontend mode '{mode}' (expected direct or proxied)");
        }
        // Resolve the frontend's target to enforce the Direct-over-private rule.
        let row = self
            .backend
            .query_opt(
                "SELECT registry_id, cache_id, storage_binding_id FROM frontends WHERE id = ?1",
                &vals![id],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("frontend {id} not found"))?;
        if mode == "direct" {
            let registry_id: Option<i64> = row.get(0)?;
            let cache_id: Option<i64> = row.get(1)?;
            let binding_id: Option<i64> = match row.get::<Option<i64>>(2)? {
                Some(b) => Some(b),
                None => match (registry_id, cache_id) {
                    (Some(r), _) => self
                        .registry_by_id(r)
                        .await?
                        .and_then(|x| x.storage_binding_id),
                    (_, Some(c)) => self
                        .cache_by_id(c)
                        .await?
                        .and_then(|x| x.storage_binding_id),
                    _ => None,
                },
            };
            if let Some(binding_id) = binding_id {
                if let Some(binding) = self.storage_binding(binding_id).await? {
                    if binding.access == "private" {
                        bail!(
                            "cannot set a Direct frontend over private storage binding '{}': \
                             private bindings must be served proxied or presigned",
                            binding.name
                        );
                    }
                }
            }
        }
        let (domain, base_path) = validate_frontend_target(domain, base_path)?;
        self.backend
            .execute(
                "UPDATE frontends SET domain = ?2, base_path = ?3, mode = ?4, \
                 serves_git = ?5, serves_cache = ?6, serves_web = ?7, \
                 consumer_priority = ?8, advertised = ?9 WHERE id = ?1",
                &vals![
                    id,
                    domain,
                    base_path,
                    mode,
                    serves_git,
                    serves_cache,
                    serves_web,
                    consumer_priority,
                    advertised
                ],
            )
            .await?;
        Ok(())
    }

    /// List a registry's frontends, ordered by descending consumer priority
    /// then domain.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_frontends(&self, registry_id: i64) -> Result<Vec<FrontendRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, registry_id, cache_id, storage_binding_id, domain, base_path, mode, serves_git,
                    serves_cache, serves_web, consumer_priority, advertised,
                    proxy_config, is_primary, created_at
             FROM frontends WHERE registry_id = ?1
             ORDER BY consumer_priority DESC, domain",
                &vals![registry_id],
            )
            .await?;
        rows.iter().map(row_to_frontend).collect()
    }

    /// Create a frontend that fronts a managed *cache* (rather than a registry).
    ///
    /// The cache-serving sibling of [`Database::create_frontend`]: the new row
    /// carries `cache_id` and a `NULL` `registry_id` (the table's `CHECK`
    /// enforces exactly one). A **Direct** frontend over a cache whose storage
    /// binding is `private` is rejected — a private binding must be proxied or
    /// presigned, never handed out as a direct origin URL.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode`, a Direct frontend over a
    /// private binding, a `(domain, base_path)` collision, an unsafe `domain`,
    /// or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_cache_frontend(
        &self,
        cache_id: i64,
        domain: &str,
        base_path: &str,
        mode: &str,
        serves_cache: bool,
        consumer_priority: i64,
        advertised: bool,
    ) -> Result<i64> {
        if !matches!(mode, "direct" | "proxied") {
            bail!("unsupported frontend mode '{mode}' (expected direct or proxied)");
        }
        if mode == "direct" {
            if let Some(cache) = self.cache_by_id(cache_id).await? {
                // Default-storage (binding-less) caches have no private-binding
                // constraint to check.
                if let Some(binding) = match cache.storage_binding_id {
                    Some(id) => self.storage_binding(id).await?,
                    None => None,
                } {
                    if binding.access == "private" {
                        bail!(
                            "cannot create a Direct frontend over private storage binding \
                             '{}': private bindings must be served proxied or presigned",
                            binding.name
                        );
                    }
                }
            }
        }
        // Validate + normalize the bare host and rooted base path.
        let (domain, base_path) = validate_frontend_target(domain, base_path)?;
        self.backend
            .execute_insert(
                "INSERT INTO frontends
                 (cache_id, domain, base_path, mode, serves_git, serves_cache,
                  serves_web, consumer_priority, advertised, created_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, ?6, ?7, ?8)",
                &vals![
                    cache_id,
                    domain,
                    base_path,
                    mode,
                    serves_cache,
                    consumer_priority,
                    advertised,
                    unix_now()
                ],
            )
            .await
    }

    /// Create a frontend that fronts a *storage binding* — a bucket's public
    /// CDN origin — inherited by every registry/cache stored in that binding
    /// (RFC-0004 §12 "storage-binding frontends").
    ///
    /// The new row carries `storage_binding_id` with `registry_id`/`cache_id`
    /// `NULL` (the table `CHECK` enforces exactly one target). A **Direct**
    /// frontend is rejected over a `private` binding: a private bucket must be
    /// served proxied/presigned, never handed out as a public origin URL.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode`, a Direct frontend over a
    /// private binding, an unknown binding, a `(domain, base_path)` collision,
    /// an unsafe `domain`, or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_storage_frontend(
        &self,
        storage_binding_id: i64,
        domain: &str,
        base_path: &str,
        mode: &str,
        serves_git: bool,
        serves_cache: bool,
        serves_web: bool,
        consumer_priority: i64,
        advertised: bool,
    ) -> Result<i64> {
        if !matches!(mode, "direct" | "proxied") {
            bail!("unsupported frontend mode '{mode}' (expected direct or proxied)");
        }
        let binding = self
            .storage_binding(storage_binding_id)
            .await?
            .with_context(|| format!("storage binding {storage_binding_id} not found"))?;
        if mode == "direct" && binding.access == "private" {
            bail!(
                "cannot create a Direct frontend over private storage binding '{}': \
                 private bindings must be served proxied or presigned",
                binding.name
            );
        }
        // Validate + normalize the bare host and rooted base path.
        let (domain, base_path) = validate_frontend_target(domain, base_path)?;
        self.backend
            .execute_insert(
                "INSERT INTO frontends
                 (storage_binding_id, domain, base_path, mode, serves_git, serves_cache,
                  serves_web, consumer_priority, advertised, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &vals![
                    storage_binding_id,
                    domain,
                    base_path,
                    mode,
                    serves_git,
                    serves_cache,
                    serves_web,
                    consumer_priority,
                    advertised,
                    unix_now(),
                ],
            )
            .await
    }

    /// List a storage binding's frontends, ordered by descending consumer
    /// priority then domain.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_storage_frontends(
        &self,
        storage_binding_id: i64,
    ) -> Result<Vec<FrontendRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, registry_id, cache_id, storage_binding_id, domain, base_path, mode, serves_git,
                    serves_cache, serves_web, consumer_priority, advertised,
                    proxy_config, is_primary, created_at
             FROM frontends WHERE storage_binding_id = ?1
             ORDER BY consumer_priority DESC, domain",
                &vals![storage_binding_id],
            )
            .await?;
        rows.iter().map(row_to_frontend).collect()
    }

    /// Set a frontend's proxy tuning and primary flag. Returns `false` when no
    /// frontend has `id`.
    ///
    /// `config` is serialized to the `proxy_config` JSON blob (`None` clears it
    /// back to the conservative defaults). `is_primary` marks the preferred
    /// frontend a consumer reaches first.
    ///
    /// # Errors
    ///
    /// Returns an error when `config` cannot be serialized or on database failure.
    pub async fn set_frontend_proxy(
        &self,
        id: i64,
        config: Option<&ProxyConfig>,
        is_primary: bool,
    ) -> Result<bool> {
        let json = match config {
            Some(c) => Some(serde_json::to_string(c).context("serializing proxy config")?),
            None => None,
        };
        let n = self
            .backend
            .execute(
                "UPDATE frontends SET proxy_config = ?2, is_primary = ?3 WHERE id = ?1",
                &vals![id, json, is_primary],
            )
            .await?;
        Ok(n > 0)
    }

    /// List a managed cache's frontends, ordered by descending consumer
    /// priority then domain.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_frontends(&self, cache_id: i64) -> Result<Vec<FrontendRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, registry_id, cache_id, storage_binding_id, domain, base_path, mode, serves_git,
                    serves_cache, serves_web, consumer_priority, advertised,
                    proxy_config, is_primary, created_at
             FROM frontends WHERE cache_id = ?1
             ORDER BY consumer_priority DESC, domain",
                &vals![cache_id],
            )
            .await?;
        rows.iter().map(row_to_frontend).collect()
    }

    /// List the frontends bound to a serving `domain`, most specific
    /// (longest `base_path`) first.
    ///
    /// Used by the request-time domain dispatcher to map an incoming `Host` to
    /// the registry/cache it serves; the caller picks the first row whose
    /// `base_path` prefixes the request path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn frontends_by_domain(&self, domain: &str) -> Result<Vec<FrontendRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, registry_id, cache_id, storage_binding_id, domain, base_path, mode, serves_git,
                    serves_cache, serves_web, consumer_priority, advertised,
                    proxy_config, is_primary, created_at
             FROM frontends WHERE domain = ?1
             ORDER BY LENGTH(base_path) DESC, consumer_priority DESC",
                &vals![domain],
            )
            .await?;
        rows.iter().map(row_to_frontend).collect()
    }

    /// Delete a frontend by id; returns whether a row was removed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_frontend(&self, frontend_id: i64) -> Result<bool> {
        let affected = self
            .backend
            .execute("DELETE FROM frontends WHERE id = ?1", &vals![frontend_id])
            .await?;
        Ok(affected > 0)
    }

    /// Record (upsert) the latest probe observation for a frontend.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn upsert_frontend_probe(
        &self,
        frontend_id: i64,
        status: &str,
        observed_frontier: Option<&str>,
        lag_releases: Option<i64>,
        latency_ms: i64,
        checked_at: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO frontend_probes
             (frontend_id, status, observed_frontier, lag_releases, latency_ms, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(frontend_id) DO UPDATE SET
               status = excluded.status,
               observed_frontier = excluded.observed_frontier,
               lag_releases = excluded.lag_releases,
               latency_ms = excluded.latency_ms,
               checked_at = excluded.checked_at",
                &vals![
                    frontend_id,
                    status,
                    observed_frontier,
                    lag_releases,
                    latency_ms,
                    checked_at,
                ],
            )
            .await?;
        Ok(())
    }

    /// The latest probe per frontend of one registry, keyed by frontend id.
    ///
    /// Frontends that have never been probed are omitted; the health page joins
    /// them back in from [`Database::list_frontends`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_frontend_probes(&self, registry_id: i64) -> Result<Vec<FrontendProbeRow>> {
        let rows = self
            .backend
            .query(
                "SELECT fp.frontend_id, fp.status, fp.observed_frontier, fp.lag_releases,
                    fp.latency_ms, fp.checked_at
             FROM frontend_probes fp
             JOIN frontends f ON f.id = fp.frontend_id
             WHERE f.registry_id = ?1
             ORDER BY fp.frontend_id",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(FrontendProbeRow {
                    frontend_id: row.get(0)?,
                    status: row.get(1)?,
                    observed_frontier: row.get(2)?,
                    lag_releases: row.get(3)?,
                    latency_ms: row.get(4)?,
                    checked_at: row.get(5)?,
                })
            })
            .collect()
    }

    // -- topology resources -------------------------------------------------

    /// Creates a normalized domain in instance or organization scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hostname or access-provider document,
    /// a missing organization, a hostname collision, or a database failure.
    pub async fn create_domain(&self, input: &NewDomain) -> Result<DomainRecord> {
        let hostname = normalize_topology_hostname(&input.hostname)?;
        if let Some(provider) = input.desired_dns_provider.as_deref() {
            validate_key_bytes(provider, "DNS provider", 64)?;
        }
        if let Some(provider) = input.desired_tls_provider.as_deref() {
            validate_key_bytes(provider, "TLS provider", 64)?;
        }
        validate_json_object(&input.access_provider_json, "domain access provider")?;
        let now = unix_now();
        let affected = if let Some(org_id) = input.org_id {
            self.backend
                .execute(
                    "INSERT INTO domains (org_id, hostname, desired_dns_provider, desired_tls_provider,
                    access_provider_json, created_at, updated_at)
                 SELECT id, ?2, ?3, ?4, ?5, ?6, ?6 FROM orgs WHERE id = ?1",
                    &vals![
                        org_id,
                        hostname,
                        input.desired_dns_provider,
                        input.desired_tls_provider,
                        input.access_provider_json,
                        now
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO domains (org_id, hostname, desired_dns_provider, desired_tls_provider,
                    access_provider_json, created_at, updated_at)
                 VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?5)",
                    &vals![
                        hostname,
                        input.desired_dns_provider,
                        input.desired_tls_provider,
                        input.access_provider_json,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("domain organization does not exist");
        }
        self.domain_by_hostname(&hostname)
            .await?
            .context("created domain disappeared")
    }

    /// Returns a domain by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn domain(&self, id: i64) -> Result<Option<DomainRecord>> {
        let rows = self.backend.query(
            "SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
             FROM domains WHERE id = ?1", &vals![id]).await?;
        rows.first().map(row_to_domain).transpose()
    }

    /// Returns a domain by its globally unique normalized hostname.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn domain_by_hostname(&self, hostname: &str) -> Result<Option<DomainRecord>> {
        let hostname = normalize_topology_hostname(hostname)?;
        let rows = self.backend.query(
            "SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
             FROM domains WHERE hostname = ?1", &vals![hostname]).await?;
        rows.first().map(row_to_domain).transpose()
    }

    /// Lists instance-scoped domains or the domains owned by one organization.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_domains(&self, org_id: Option<i64>) -> Result<Vec<DomainRecord>> {
        let (sql, values) = match org_id {
            Some(id) => ("SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                    observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
                 FROM domains WHERE org_id = ?1 ORDER BY hostname", vals![id]),
            None => ("SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                    observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
                 FROM domains WHERE org_id IS NULL ORDER BY hostname", vals![]),
        };
        self.backend
            .query(sql, &values)
            .await?
            .iter()
            .map(row_to_domain)
            .collect()
    }

    /// Updates a domain's desired provider and access configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid provider/JSON values, a stale version, a missing
    /// domain, or database failure.
    pub async fn update_domain(&self, id: i64, input: &UpdateDomain) -> Result<DomainRecord> {
        if let Some(provider) = input.desired_dns_provider.as_deref() {
            validate_key_bytes(provider, "DNS provider", 64)?;
        }
        if let Some(provider) = input.desired_tls_provider.as_deref() {
            validate_key_bytes(provider, "TLS provider", 64)?;
        }
        validate_json_object(&input.access_provider_json, "domain access provider")?;
        let affected = self
            .backend
            .execute(
                "UPDATE domains SET observed_dns_state = CASE
                      WHEN desired_dns_provider = ?3 OR
                        (desired_dns_provider IS NULL AND ?3 IS NULL)
                      THEN observed_dns_state
                      WHEN ?3 IS NULL THEN 'unconfigured' ELSE 'pending' END,
                    observed_tls_state = CASE
                      WHEN desired_tls_provider = ?4 OR
                        (desired_tls_provider IS NULL AND ?4 IS NULL)
                      THEN observed_tls_state
                      WHEN ?4 IS NULL THEN 'unconfigured' ELSE 'pending' END,
                    verified_at = CASE WHEN
                      (desired_dns_provider = ?3 OR
                        (desired_dns_provider IS NULL AND ?3 IS NULL)) AND
                      (desired_tls_provider = ?4 OR
                        (desired_tls_provider IS NULL AND ?4 IS NULL))
                      THEN verified_at ELSE NULL END,
                    desired_dns_provider = ?3, desired_tls_provider = ?4,
                    access_provider_json = ?5,
                    updated_at = ?6,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND resource_version = ?2",
                &vals![
                    id,
                    input.expected_version,
                    input.desired_dns_provider,
                    input.desired_tls_provider,
                    input.access_provider_json,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("domain is missing or its resource version is stale");
        }
        self.domain(id).await?.context("updated domain disappeared")
    }

    /// Records reconciler-observed DNS/TLS state separately from desired config.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or inconsistent observed state, a stale
    /// version, a missing domain, or database failure.
    pub async fn record_domain_observation(
        &self,
        id: i64,
        expected_version: i64,
        dns_state: &str,
        tls_state: &str,
        verified_at: Option<i64>,
    ) -> Result<DomainRecord> {
        if !matches!(
            dns_state,
            "unconfigured" | "pending" | "verified" | "failed"
        ) {
            bail!("invalid observed DNS state '{dns_state}'");
        }
        if !matches!(tls_state, "unconfigured" | "pending" | "active" | "failed") {
            bail!("invalid observed TLS state '{tls_state}'");
        }
        if verified_at.is_some() != (dns_state == "verified" && tls_state == "active") {
            bail!("verified_at requires verified DNS and active TLS, and vice versa");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE domains SET observed_dns_state = ?3, observed_tls_state = ?4,
                verified_at = ?5, updated_at = ?6,
                resource_version = resource_version + 1
             WHERE id = ?1 AND resource_version = ?2",
                &vals![
                    id,
                    expected_version,
                    dns_state,
                    tls_state,
                    verified_at,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("domain is missing or its resource version is stale");
        }
        self.domain(id)
            .await?
            .context("observed domain disappeared")
    }

    /// Deletes a domain when its optimistic-concurrency version matches.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when dependent routes/defaults exist.
    pub async fn delete_domain(&self, id: i64, expected_version: i64) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM domains WHERE id = ?1 AND resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }

    /// Attaches one same-registry, content-exact object snapshot to a preparing publication.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/content, incompatible ownership/state, or database failure.
    pub async fn set_registry_publication_object(
        &self,
        input: &SetRegistryPublicationObject,
    ) -> Result<RegistryPublicationObjectRecord> {
        validate_key_bytes(&input.publication_id, "publication id", 64)?;
        validate_key_bytes(&input.expected_hash, "publication object hash", 128)?;
        if !matches!(input.object_kind.as_str(), "immutable" | "mutable_pointer")
            || input.expected_size < 0
        {
            bail!("publication object kind/size is invalid");
        }
        // Serialize manifest mutation against the publication row before the
        // child write. The child INSERT rechecks `preparing`, so a freeze that
        // wins after this fence makes the mutation fail closed; a crash after
        // the bump merely leaves a harmless skipped version.
        self.backend
            .execute(
                "UPDATE registry_publications
                 SET mutation_version = mutation_version + 1
                 WHERE publication_id = ?1 AND state = 'preparing'",
                &vals![input.publication_id],
            )
            .await?;
        let affected = self.backend.execute(
            "INSERT INTO registry_publication_objects
             (publication_id, registry_id, surface_object_id, object_kind, expected_hash, expected_size)
             SELECT pub.publication_id, pub.registry_id, o.id, ?3, ?4, ?5
             FROM registry_publications pub JOIN surface_objects o
               ON o.registry_id = pub.registry_id
             WHERE pub.publication_id = ?1 AND o.id = ?2 AND pub.state = 'preparing'
               AND o.lifecycle_state = 'active' AND o.object_kind = ?3
               AND o.content_hash = ?4 AND o.size = ?5
               AND (?3 <> 'mutable_pointer'
                 OR o.mutable_publication_id = pub.publication_id)
             ON CONFLICT(publication_id, surface_object_id) DO UPDATE SET
               object_kind = excluded.object_kind, expected_hash = excluded.expected_hash,
               expected_size = excluded.expected_size",
            &vals![input.publication_id, input.surface_object_id, input.object_kind,
                input.expected_hash, input.expected_size],
        ).await?;
        let _ = affected;
        let record = RegistryPublicationObjectRecord {
            publication_id: input.publication_id.clone(),
            registry_id: self
                .backend
                .query_opt(
                    "SELECT registry_id FROM registry_publications WHERE publication_id = ?1",
                    &vals![input.publication_id],
                )
                .await?
                .context("publication disappeared")?
                .get(0)?,
            surface_object_id: input.surface_object_id,
            object_kind: input.object_kind.clone(),
            expected_hash: input.expected_hash.clone(),
            expected_size: input.expected_size,
        };
        let exact = self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publication_objects po
             JOIN registry_publications pub ON pub.publication_id = po.publication_id
             WHERE po.publication_id = ?1 AND po.surface_object_id = ?2
               AND pub.state = 'preparing'
               AND object_kind = ?3 AND expected_hash = ?4 AND expected_size = ?5",
                &vals![
                    input.publication_id,
                    input.surface_object_id,
                    input.object_kind,
                    input.expected_hash,
                    input.expected_size
                ],
            )
            .await?;
        if exact.is_none() {
            bail!("publication object must exactly match an active object on the same registry");
        }
        Ok(record)
    }

    /// Records non-authoritative per-placement publication progress.
    ///
    /// Only [`Database::finalize_registry_pointer_advance`] may mark a placement
    /// ready, because readiness must be coupled to its authoritative watermark.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid progress, cross-registry placement, incomplete presence, or database failure.
    pub async fn set_registry_publication_placement(
        &self,
        input: &SetRegistryPublicationPlacement,
    ) -> Result<RegistryPublicationPlacementRecord> {
        if !matches!(input.state.as_str(), "preparing" | "failed" | "retired") {
            bail!("invalid publication-placement state '{}'", input.state);
        }
        let exists = self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publication_placements
                 WHERE publication_id = ?1 AND placement_id = ?2",
                &vals![input.publication_id, input.placement_id],
            )
            .await?
            .is_some();
        if exists {
            self.backend
                .execute(
                    "UPDATE registry_publication_placements
                     SET state = ?4, observed_at = ?5
                     WHERE publication_id = ?1 AND placement_id = ?2
                       AND required = ?3
                       AND EXISTS (SELECT 1 FROM registry_publications pub
                         WHERE pub.publication_id = ?1 AND (
                           (?4 = 'preparing' AND pub.state = 'preparing') OR
                           (?4 = 'failed' AND pub.state IN
                             ('preparing', 'writing_pointers', 'failed')) OR
                           (?4 = 'retired' AND pub.state = 'retired')))
                       AND ((state = 'preparing' AND ?4 = 'failed')
                         OR (state = 'writing_pointers' AND ?4 = 'failed')
                         OR (state = 'failed' AND ?4 IN ('preparing', 'retired'))
                         OR (state = 'ready' AND ?4 = 'retired')
                         OR (state = ?4 AND required = ?3 AND observed_at = ?5))",
                    &vals![
                        input.publication_id,
                        input.placement_id,
                        input.required,
                        input.state,
                        input.observed_at
                    ],
                )
                .await?;
        } else {
            if input.state != "preparing" {
                bail!("new publication placement progress must start preparing");
            }
            // Required-placement membership is part of the frozen manifest.
            // Fence on the parent row before inserting it for the same reason
            // as publication-object attachment above.
            self.backend
                .execute(
                    "UPDATE registry_publications
                     SET mutation_version = mutation_version + 1
                     WHERE publication_id = ?1 AND state = 'preparing'",
                    &vals![input.publication_id],
                )
                .await?;
            self.backend
                .execute(
                    "INSERT INTO registry_publication_placements
                     (publication_id, registry_id, placement_id, required, state, observed_at)
                     SELECT pub.publication_id, pub.registry_id, p.id, ?3, 'preparing', ?5
                     FROM registry_publications pub JOIN surface_placements p
                       ON p.registry_id = pub.registry_id
                     WHERE pub.publication_id = ?1 AND p.id = ?2
                       AND pub.state = 'preparing'",
                    &vals![
                        input.publication_id,
                        input.placement_id,
                        input.required,
                        input.state,
                        input.observed_at
                    ],
                )
                .await?;
        }
        let row = self
            .backend
            .query_opt(
                "SELECT registry_id, required, state, observed_at
             FROM registry_publication_placements
             WHERE publication_id = ?1 AND placement_id = ?2
               AND required = ?3 AND state = ?4 AND observed_at = ?5",
                &vals![
                    input.publication_id,
                    input.placement_id,
                    input.required,
                    input.state,
                    input.observed_at
                ],
            )
            .await?
            .context("publication placement transition is invalid or cross-registry")?;
        Ok(RegistryPublicationPlacementRecord {
            publication_id: input.publication_id.clone(),
            registry_id: row.get(0)?,
            placement_id: input.placement_id,
            required: row.get(1)?,
            state: row.get(2)?,
            observed_at: row.get(3)?,
        })
    }

    /// Begins a mutable-pointer advance by first clearing the placement watermark.
    ///
    /// A crash between the clear and progress transition is fail-closed: readers
    /// never mistake the old watermark for the new publication.
    ///
    /// # Errors
    ///
    /// Returns an error for stale placement/publication progress or database failure.
    pub async fn begin_registry_pointer_advance(
        &self,
        publication_id: &str,
        placement_id: i64,
        expected_placement_version: i64,
        observed_at: i64,
    ) -> Result<SurfacePlacementRecord> {
        let cleared = self
            .backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = NULL,
                resource_version = CASE WHEN resource_version = ?3
                  THEN resource_version + 1 ELSE resource_version END,
                updated_at = ?4
             WHERE id = ?2 AND registry_id = (
               SELECT registry_id FROM registry_publications WHERE publication_id = ?1)
               AND EXISTS (SELECT 1 FROM registry_publications pub
                 WHERE pub.publication_id = ?1
                   AND pub.state = 'writing_pointers')
               AND ((resource_version = ?3 AND EXISTS (
                 SELECT 1 FROM registry_publication_placements pp
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state = 'preparing')) OR
                 (resource_version = ?3 + 1 AND mutable_publication_id IS NULL
                   AND updated_at = ?4
                   AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                     WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                       AND pp.state IN ('preparing', 'writing_pointers'))))",
                &vals![
                    publication_id,
                    placement_id,
                    expected_placement_version,
                    observed_at
                ],
            )
            .await?;
        if cleared != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM surface_placements p
                 JOIN registry_publication_placements pp ON pp.placement_id = p.id
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE p.id = ?2 AND pp.publication_id = ?1
                   AND p.resource_version = ?3 + 1
                   AND p.mutable_publication_id IS NULL AND p.updated_at = ?4
                   AND pp.state IN ('preparing', 'writing_pointers')
                   AND pub.state = 'writing_pointers'",
                    &vals![
                        publication_id,
                        placement_id,
                        expected_placement_version,
                        observed_at
                    ],
                )
                .await?
                .is_none()
        {
            bail!("placement pointer advance is stale or cross-registry");
        }
        let moved = self.backend.execute(
            "UPDATE registry_publication_placements SET state = 'writing_pointers', observed_at = ?3
             WHERE publication_id = ?1 AND placement_id = ?2
               AND state IN ('preparing', 'writing_pointers')
               AND EXISTS (SELECT 1 FROM registry_publications pub
                 WHERE pub.publication_id = ?1 AND pub.state = 'writing_pointers')",
            &vals![publication_id, placement_id, observed_at],
        ).await?;
        if moved != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM registry_publication_placements pp
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state = 'writing_pointers'
                   AND pub.state = 'writing_pointers'",
                    &vals![publication_id, placement_id],
                )
                .await?
                .is_none()
        {
            bail!("publication placement is not ready to write pointers");
        }
        self.surface_placement(placement_id)
            .await?
            .context("placement disappeared")
    }

    /// Publishes the authoritative placement watermark with one guarded CAS.
    ///
    /// # Errors
    ///
    /// Returns an error unless every manifest object is present exactly, progress
    /// is writing pointers, placement version is current, and ownership matches.
    pub async fn finalize_registry_pointer_advance(
        &self,
        publication_id: &str,
        placement_id: i64,
        expected_placement_version: i64,
        observed_at: i64,
    ) -> Result<SurfacePlacementRecord> {
        let published = self
            .backend
            .execute(
                "UPDATE surface_placements SET
                resource_version = CASE WHEN mutable_publication_id = ?1
                  THEN resource_version ELSE resource_version + 1 END,
                mutable_publication_id = ?1,
                updated_at = ?4
             WHERE id = ?2
               AND (resource_version = ?3 OR
                 (mutable_publication_id = ?1 AND resource_version = ?3 + 1))
               AND registry_id = (
               SELECT registry_id FROM registry_publications WHERE publication_id = ?1)
               AND EXISTS (SELECT 1 FROM registry_publications pub
                 WHERE pub.publication_id = ?1
                   AND pub.state = 'writing_pointers')
               AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state IN ('writing_pointers', 'ready'))
               AND EXISTS (SELECT 1 FROM registry_publication_objects
                 WHERE publication_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM registry_publication_objects po
                 WHERE po.publication_id = ?1 AND NOT EXISTS (
                   SELECT 1 FROM object_placements op
                   WHERE op.surface_object_id = po.surface_object_id
                     AND op.placement_id = ?2 AND op.state = 'present'
                     AND op.observed_hash = po.expected_hash
                     AND op.observed_size = po.expected_size))",
                &vals![
                    publication_id,
                    placement_id,
                    expected_placement_version,
                    observed_at
                ],
            )
            .await?;
        if published != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM surface_placements p
                 JOIN registry_publication_placements pp ON pp.placement_id = p.id
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE p.id = ?2 AND pp.publication_id = ?1
                   AND p.resource_version = ?3 + 1
                   AND p.mutable_publication_id = ?1 AND p.updated_at = ?4
                   AND pp.state IN ('writing_pointers', 'ready')
                   AND pub.state = 'writing_pointers'",
                    &vals![
                        publication_id,
                        placement_id,
                        expected_placement_version,
                        observed_at
                    ],
                )
                .await?
                .is_none()
        {
            bail!("placement watermark CAS is stale or cross-registry");
        }
        let ready = self
            .backend
            .execute(
                "UPDATE registry_publication_placements
                 SET state = 'ready', observed_at = ?3
                 WHERE publication_id = ?1 AND placement_id = ?2
                   AND state IN ('writing_pointers', 'ready')
                   AND EXISTS (SELECT 1 FROM registry_publications pub
                     WHERE pub.publication_id = ?1 AND pub.state = 'writing_pointers')
                   AND EXISTS (SELECT 1 FROM surface_placements p
                     WHERE p.id = ?2 AND p.mutable_publication_id = ?1)",
                &vals![publication_id, placement_id, observed_at],
            )
            .await?;
        if ready != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM registry_publication_placements pp
                 JOIN surface_placements p ON p.id = pp.placement_id
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state = 'ready' AND p.mutable_publication_id = ?1
                   AND pub.state = 'writing_pointers'",
                    &vals![publication_id, placement_id],
                )
                .await?
                .is_none()
        {
            bail!("publication placement progress could not record the published watermark");
        }
        self.surface_placement(placement_id)
            .await?
            .context("placement disappeared")
    }

    /// Advances a publication state by compare-and-set.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid transition, unmet required placements, stale state, or database failure.
    pub async fn advance_registry_publication(
        &self,
        publication_id: &str,
        expected_state: &str,
        next_state: &str,
        at: i64,
    ) -> Result<bool> {
        let valid = matches!(
            (expected_state, next_state),
            ("preparing", "writing_pointers")
                | ("preparing", "failed")
                | ("writing_pointers", "ready")
                | ("writing_pointers", "failed")
                | ("failed", "retired")
                | ("ready", "retired")
        );
        if !valid {
            bail!("invalid publication state transition {expected_state}->{next_state}");
        }
        Ok(self
            .backend
            .execute(
                "UPDATE registry_publications SET state = ?3,
               completed_at = CASE WHEN ?3 IN ('ready','failed') THEN ?4 ELSE completed_at END,
               retired_at = CASE WHEN ?3 = 'retired' THEN ?4 ELSE retired_at END
             WHERE publication_id = ?1 AND state = ?2
               AND (?3 <> 'ready' OR (EXISTS (
                 SELECT 1 FROM registry_publication_placements pp
                 WHERE pp.publication_id = ?1 AND pp.required = 1)
                 AND NOT EXISTS (
                   SELECT 1 FROM registry_publication_placements pp
                   JOIN surface_placements p ON p.id = pp.placement_id
                   WHERE pp.publication_id = ?1 AND pp.required = 1
                     AND (pp.state <> 'ready'
                       OR p.mutable_publication_id <> ?1
                       OR p.mutable_publication_id IS NULL))))
               AND (?3 <> 'retired' OR NOT EXISTS (
                 SELECT 1 FROM registry_publication_state ps
                 WHERE ps.current_publication_id = ?1)) ",
                &vals![publication_id, expected_state, next_state, at],
            )
            .await?
            == 1)
    }

    /// Lists registry-derived GC roots reachable from current refresh lineages.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn active_cache_retention_hashes(
        &self,
        cache_id: i64,
        at: i64,
    ) -> Result<Vec<String>> {
        let rows = self
            .backend
            .query(
                "WITH RECURSIVE lineage(subscription_id, refresh_id) AS (
               SELECT id, current_refresh_id FROM cache_retention_subscriptions
                WHERE cache_id = ?1 AND current_refresh_id IS NOT NULL
                  AND (retired_at IS NULL OR retired_at + removal_grace_secs > ?2)
               UNION ALL
               SELECT lineage.subscription_id, child.parent_refresh_id
                FROM lineage JOIN cache_retention_refreshes child
                  ON child.refresh_id = lineage.refresh_id
                WHERE child.parent_refresh_id IS NOT NULL AND child.grace_until > ?2
             )
             SELECT DISTINCT rr.store_hash FROM cache_root_reasons rr
             JOIN lineage ON lineage.refresh_id = rr.refresh_id
             WHERE rr.expires_at IS NULL OR rr.expires_at > ?2
             ORDER BY rr.store_hash",
                &vals![cache_id, at],
            )
            .await?;
        rows.iter().map(|row| row.get(0)).collect()
    }

    /// Compare-and-sets the one authoritative current ready publication for a registry.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale version, non-ready/cross-registry publication, or database failure.
    pub async fn set_current_registry_publication(
        &self,
        registry_id: i64,
        publication_id: &str,
        expected_version: Option<i64>,
    ) -> Result<RegistryPublicationStateRecord> {
        if let Some(row) = self
            .backend
            .query_opt(
                "SELECT registry_id, current_publication_id, next_ordinal,
                resource_version, updated_at
             FROM registry_publication_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        {
            let current: Option<String> = row.get(1)?;
            let version: i64 = row.get(3)?;
            if current.as_deref() == Some(publication_id)
                && expected_version.map_or(true, |expected| expected == version)
            {
                return Ok(RegistryPublicationStateRecord {
                    registry_id: row.get(0)?,
                    current_publication_id: current,
                    next_ordinal: row.get(2)?,
                    resource_version: version,
                    updated_at: row.get(4)?,
                });
            }
        }
        let now = unix_now();
        let affected = if let Some(version) = expected_version {
            self.backend
                .execute(
                    "UPDATE registry_publication_state SET current_publication_id = ?2,
                    next_ordinal = CASE WHEN next_ordinal <= (SELECT ordinal
                      FROM registry_publications WHERE publication_id = ?2)
                      THEN (SELECT ordinal + 1 FROM registry_publications WHERE publication_id = ?2)
                      ELSE next_ordinal END,
                    resource_version = resource_version + 1, updated_at = ?4
                 WHERE registry_id = ?1 AND resource_version = ?3 AND EXISTS (
                   SELECT 1 FROM registry_publications pub
                   WHERE pub.publication_id = ?2 AND pub.registry_id = ?1 AND pub.state = 'ready'
                     AND pub.parent_publication_id = registry_publication_state.current_publication_id
                     AND pub.ordinal > (SELECT current.ordinal FROM registry_publications current
                       WHERE current.publication_id = registry_publication_state.current_publication_id)
                     AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                       WHERE pp.publication_id = pub.publication_id AND pp.required = 1)
                     AND NOT EXISTS (SELECT 1 FROM registry_publication_placements pp
                       JOIN surface_placements p ON p.id = pp.placement_id
                       WHERE pp.publication_id = pub.publication_id AND pp.required = 1
                         AND (pp.state <> 'ready'
                           OR p.mutable_publication_id <> pub.publication_id
                           OR p.mutable_publication_id IS NULL)))",
                    &vals![registry_id, publication_id, version, now],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO registry_publication_state
                 (registry_id, current_publication_id, next_ordinal, updated_at)
                 SELECT ?1, pub.publication_id, pub.ordinal + 1, ?3
                 FROM registry_publications pub
                 WHERE pub.publication_id = ?2 AND pub.registry_id = ?1 AND pub.state = 'ready'
                   AND pub.parent_publication_id IS NULL
                   AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                     WHERE pp.publication_id = pub.publication_id AND pp.required = 1)
                   AND NOT EXISTS (SELECT 1 FROM registry_publication_placements pp
                     JOIN surface_placements p ON p.id = pp.placement_id
                     WHERE pp.publication_id = pub.publication_id AND pp.required = 1
                       AND (pp.state <> 'ready'
                         OR p.mutable_publication_id <> pub.publication_id
                         OR p.mutable_publication_id IS NULL))",
                    &vals![registry_id, publication_id, now],
                )
                .await?
        };
        if affected != 1 {
            bail!("current publication CAS is stale or publication is not ready on this registry");
        }
        let row = self.backend.query_opt(
            "SELECT registry_id, current_publication_id, next_ordinal, resource_version, updated_at
             FROM registry_publication_state WHERE registry_id = ?1",
            &vals![registry_id],
        ).await?.context("publication state disappeared")?;
        Ok(RegistryPublicationStateRecord {
            registry_id: row.get(0)?,
            current_publication_id: row.get(1)?,
            next_ordinal: row.get(2)?,
            resource_version: row.get(3)?,
            updated_at: row.get(4)?,
        })
    }

    /// Creates one physical placement after atomically checking binding ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid placement fields, an absent/cross-scope
    /// surface or binding, a primary/location collision, or database failure.
    pub async fn create_surface_placement(
        &self,
        input: &NewSurfacePlacement,
    ) -> Result<SurfacePlacementRecord> {
        validate_stable_name(&input.name, "placement name")?;
        validate_placement_fields(
            input.role.as_str(),
            input.state.as_str(),
            input.completeness.as_str(),
            input.partition_rule_json.as_deref(),
            input.read_enabled,
            input.write_enabled,
        )?;
        let prefix = normalize_placement_prefix(&input.prefix)?;
        if let Some(json) = input.partition_rule_json.as_deref() {
            validate_json_object(json, "placement partition rule")?;
        }
        let (registry_id, cache_id) = input.surface.ids();
        let (primary_registry_id, primary_cache_id) = if input.role == "primary" {
            (registry_id, cache_id)
        } else {
            (None, None)
        };
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO surface_placements
                (registry_id, cache_id, primary_registry_id, primary_cache_id,
                 name, storage_binding_id, prefix, role, state, completeness,
                 partition_rule_json, read_enabled, write_enabled, read_order,
                 write_order, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, ?5, b.id, ?7, ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16, ?16
             FROM storage_bindings b
             LEFT JOIN registries r ON r.id = ?1
             LEFT JOIN caches c ON c.id = ?2
             WHERE b.id = ?6
               AND ((?1 IS NOT NULL AND r.id IS NOT NULL
                     AND (b.is_instance_default = 1 OR b.org_id = r.org_id))
                 OR (?2 IS NOT NULL AND c.id IS NOT NULL
                     AND (b.is_instance_default = 1 OR b.org_id = c.org_id)))",
                &vals![
                    registry_id,
                    cache_id,
                    primary_registry_id,
                    primary_cache_id,
                    input.name,
                    input.storage_binding_id,
                    prefix,
                    input.role,
                    input.state,
                    input.completeness,
                    input.partition_rule_json,
                    input.read_enabled,
                    input.write_enabled,
                    input.read_order,
                    input.write_order,
                    now
                ],
            )
            .await?;
        if affected != 1 {
            bail!("surface and storage binding must exist in a compatible scope");
        }
        self.surface_placement_at(input.storage_binding_id, &prefix)
            .await?
            .context("created placement disappeared")
    }

    /// Returns a placement by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_placement(&self, id: i64) -> Result<Option<SurfacePlacementRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {PLACEMENT_COLUMNS} FROM surface_placements WHERE id = ?1"),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_surface_placement).transpose()
    }

    /// Returns the placement occupying one binding-relative location.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_placement_at(
        &self,
        binding_id: i64,
        prefix: &str,
    ) -> Result<Option<SurfacePlacementRecord>> {
        let rows = self.backend.query(&format!("SELECT {PLACEMENT_COLUMNS} FROM surface_placements WHERE storage_binding_id = ?1 AND prefix = ?2"), &vals![binding_id, prefix]).await?;
        rows.first().map(row_to_surface_placement).transpose()
    }

    /// Lists placements belonging to one surface in selection order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_surface_placements(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<SurfacePlacementRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM surface_placements
             WHERE registry_id = ?1 OR cache_id = ?2
             ORDER BY read_order, name"
                ),
                &vals![registry_id, cache_id],
            )
            .await?;
        rows.iter().map(row_to_surface_placement).collect()
    }

    /// Updates mutable placement selection fields with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields, a stale version, a primary
    /// collision, a missing placement, or database failure.
    pub async fn update_surface_placement(
        &self,
        id: i64,
        input: &UpdateSurfacePlacement,
    ) -> Result<SurfacePlacementRecord> {
        let existing = self
            .surface_placement(id)
            .await?
            .context("placement does not exist")?;
        validate_placement_fields(
            existing.role.as_str(),
            input.state.as_str(),
            input.completeness.as_str(),
            input.partition_rule_json.as_deref(),
            input.read_enabled,
            input.write_enabled,
        )?;
        if let Some(json) = input.partition_rule_json.as_deref() {
            validate_json_object(json, "placement partition rule")?;
        }
        let affected = self
            .backend
            .execute(
                "UPDATE surface_placements SET state = ?3, completeness = ?4,
                partition_rule_json = ?5,
                read_enabled = ?6, write_enabled = ?7,
                read_order = ?8, write_order = ?9,
                resource_version = resource_version + 1, updated_at = ?10
             WHERE id = ?1 AND resource_version = ?2
               AND NOT EXISTS (
                 SELECT 1 FROM delivery_routes r
                 WHERE r.placement_id = ?1 OR EXISTS (
                   SELECT 1 FROM placement_policy_members pm
                   WHERE pm.policy_id = r.placement_policy_id
                     AND pm.placement_id = ?1))",
                &vals![
                    id,
                    input.expected_version,
                    input.state,
                    input.completeness,
                    input.partition_rule_json,
                    input.read_enabled,
                    input.write_enabled,
                    input.read_order,
                    input.write_order,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("placement is missing or its resource version is stale");
        }
        self.surface_placement(id)
            .await?
            .context("updated placement disappeared")
    }

    /// Deletes a placement at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when routes/policies still reference it.
    pub async fn delete_surface_placement(&self, id: i64, expected_version: i64) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM surface_placements
                 WHERE id = ?1 AND resource_version = ?2 AND role <> 'primary'",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }

    /// Creates a logical object on an existing surface.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty key, negative size, missing surface,
    /// duplicate key, or database failure.
    pub async fn create_surface_object(
        &self,
        input: &SetSurfaceObject,
    ) -> Result<SurfaceObjectRecord> {
        validate_key_bytes(&input.object_key, "surface object key", 512)?;
        if !matches!(input.object_kind.as_str(), "immutable" | "mutable_pointer") {
            bail!("invalid surface-object kind '{}'", input.object_kind);
        }
        if (input.object_kind == "immutable") != input.mutable_publication_id.is_none() {
            bail!("immutable objects cannot name a publication and mutable pointers must name one");
        }
        if input.size.is_some_and(|size| size < 0) {
            bail!("surface object size cannot be negative");
        }
        if let Some(hash) = input.content_hash.as_deref() {
            validate_key_bytes(hash, "content hash", 128)?;
        }
        if let Some(publication_id) = input.mutable_publication_id.as_deref() {
            validate_key_bytes(publication_id, "mutable publication id", 64)?;
        }
        let (registry_id, cache_id) = input.surface.ids();
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO surface_objects (registry_id, cache_id, object_key,
                object_kind, content_hash, size, mutable_publication_id, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8
             WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                AND (?4 = 'immutable' OR EXISTS (
                  SELECT 1 FROM registry_publications pub
                  WHERE pub.publication_id = ?7 AND pub.registry_id = ?1))
                OR (EXISTS (SELECT 1 FROM caches WHERE id = ?2) AND ?4 = 'immutable')",
                &vals![
                    registry_id,
                    cache_id,
                    input.object_key,
                    input.object_kind,
                    input.content_hash,
                    input.size,
                    input.mutable_publication_id,
                    now
                ],
            )
            .await?;
        if affected != 1 {
            bail!("surface object target does not exist");
        }
        self.surface_object_named(input.surface, &input.object_key)
            .await?
            .context("created surface object disappeared")
    }

    /// Returns a logical object by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_object(&self, id: i64) -> Result<Option<SurfaceObjectRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {SURFACE_OBJECT_COLUMNS} FROM surface_objects WHERE id = ?1"),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_surface_object).transpose()
    }

    /// Returns a logical object by surface-relative key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_object_named(
        &self,
        surface: SurfaceTarget,
        object_key: &str,
    ) -> Result<Option<SurfaceObjectRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {SURFACE_OBJECT_COLUMNS} FROM surface_objects
                WHERE (registry_id = ?1 OR cache_id = ?2) AND object_key = ?3"
                ),
                &vals![registry_id, cache_id, object_key],
            )
            .await?;
        rows.first().map(row_to_surface_object).transpose()
    }

    /// Logically tombstones an unreferenced registry object before physical deletion.
    ///
    /// Generic tombstoning is deliberately registry-only. Cache objects remain
    /// fail-closed until root-aware cache GC owns their plan/apply lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn tombstone_surface_object(
        &self,
        id: i64,
        expected_version: i64,
        tombstoned_at: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "UPDATE surface_objects SET lifecycle_state = 'tombstoned',
                tombstoned_at = ?3, updated_at = ?3,
                resource_version = resource_version + 1
             WHERE id = ?1 AND resource_version = ?2 AND lifecycle_state = 'active'
               AND registry_id IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1 FROM registry_publication_objects po
                 JOIN registry_publications pub
                   ON pub.publication_id = po.publication_id
                 WHERE po.surface_object_id = ?1 AND pub.state <> 'retired')",
                &vals![id, expected_version, tombstoned_at],
            )
            .await?
            == 1)
    }

    /// Records object presence only when object and placement own the same surface.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state/size, cross-surface references,
    /// missing resources, or database failure.
    pub async fn set_object_placement(
        &self,
        input: &SetObjectPlacement,
    ) -> Result<ObjectPlacementRecord> {
        if !matches!(
            input.state.as_str(),
            "present" | "copying" | "missing" | "corrupt"
        ) {
            bail!("invalid object-placement state '{}'", input.state);
        }
        if input.observed_size.is_some_and(|size| size < 0) {
            bail!("observed object size cannot be negative");
        }
        if input.state == "present"
            && (input.observed_hash.is_none() || input.observed_size.is_none())
        {
            bail!("present object observations require the expected hash and size");
        }
        if let Some(hash) = input.observed_hash.as_deref() {
            validate_key_bytes(hash, "observed hash", 128)?;
        }
        if let Some(etag) = input.etag.as_deref() {
            validate_key_bytes(etag, "object ETag", 255)?;
        }
        let exists = self
            .backend
            .query_opt(
                "SELECT 1 FROM object_placements
                 WHERE surface_object_id = ?1 AND placement_id = ?2",
                &vals![input.surface_object_id, input.placement_id],
            )
            .await?
            .is_some();
        if exists {
            self.backend
                .execute(
                    "UPDATE object_placements SET state = ?3, observed_hash = ?4,
                    observed_size = ?5, etag = ?6, observed_at = ?7
                 WHERE surface_object_id = ?1 AND placement_id = ?2
                   AND deletion_job_id IS NULL AND state <> 'deleting'
                   AND EXISTS (SELECT 1 FROM surface_objects o
                     JOIN surface_placements p ON p.id = ?2
                     WHERE o.id = ?1
                       AND ((o.registry_id IS NOT NULL AND o.registry_id = p.registry_id)
                         OR (o.cache_id IS NOT NULL AND o.cache_id = p.cache_id))
                       AND (?3 <> 'present' OR
                         (o.content_hash = ?4 AND o.size = ?5)))",
                    &vals![
                        input.surface_object_id,
                        input.placement_id,
                        input.state,
                        input.observed_hash,
                        input.observed_size,
                        input.etag,
                        input.observed_at
                    ],
                )
                .await?;
        } else {
            self.backend
                .execute(
                    "INSERT INTO object_placements (surface_object_id, placement_id, state,
                    observed_hash, observed_size, etag, observed_at)
                 SELECT o.id, p.id, ?3, ?4, ?5, ?6, ?7
                 FROM surface_objects o JOIN surface_placements p ON p.id = ?2
                 WHERE o.id = ?1
                   AND ((o.registry_id IS NOT NULL AND o.registry_id = p.registry_id)
                     OR (o.cache_id IS NOT NULL AND o.cache_id = p.cache_id))
                   AND (?3 <> 'present' OR (o.content_hash = ?4 AND o.size = ?5))",
                    &vals![
                        input.surface_object_id,
                        input.placement_id,
                        input.state,
                        input.observed_hash,
                        input.observed_size,
                        input.etag,
                        input.observed_at
                    ],
                )
                .await?;
        }
        let record = self
            .object_placement(input.surface_object_id, input.placement_id)
            .await?
            .context("object placement is missing or belongs to another surface")?;
        if record.state != input.state
            || record.observed_hash != input.observed_hash
            || record.observed_size != input.observed_size
            || record.etag != input.etag
            || record.observed_at != input.observed_at
        {
            bail!("object presence requires an object and placement on the same surface");
        }
        Ok(record)
    }

    /// Returns one object-placement observation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn object_placement(
        &self,
        object_id: i64,
        placement_id: i64,
    ) -> Result<Option<ObjectPlacementRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT surface_object_id, placement_id, state, observed_hash,
                observed_size, etag, observed_at FROM object_placements
             WHERE surface_object_id = ?1 AND placement_id = ?2",
                &vals![object_id, placement_id],
            )
            .await?;
        rows.first().map(row_to_object_placement).transpose()
    }

    /// Schedules durable physical deletion for a tombstoned same-surface object.
    ///
    /// # Errors
    ///
    /// Returns an error unless presence is recorded at the placement, the
    /// object is tombstoned, the relationship is same-surface, or on database failure.
    pub async fn create_object_deletion_job(
        &self,
        input: &NewObjectDeletionJob,
    ) -> Result<ObjectDeletionJobRecord> {
        validate_key_bytes(&input.job_id, "object deletion job id", 64)?;
        let now = unix_now();
        // Phase 1 is durable and happens before presence mutation, so job-id or
        // active-slot conflicts cannot strand an object behind the wrong link.
        self.backend
            .execute(
                "INSERT INTO object_deletion_jobs
                 (job_id, surface_object_id, placement_id, state, created_at)
                 SELECT ?1, o.id, p.id, 'preparing', ?4
                 FROM surface_objects o JOIN surface_placements p ON p.id = ?3
                 JOIN object_placements op ON op.surface_object_id = o.id
                   AND op.placement_id = p.id
                 WHERE o.id = ?2 AND o.lifecycle_state = 'tombstoned'
                   AND (op.state IN ('present', 'corrupt')
                     OR (op.state = 'deleting' AND op.deletion_job_id = ?1))
                   AND ((o.registry_id IS NOT NULL AND o.registry_id = p.registry_id)
                     OR (o.cache_id IS NOT NULL AND o.cache_id = p.cache_id))
                 ON CONFLICT(job_id) DO NOTHING",
                &vals![
                    input.job_id,
                    input.surface_object_id,
                    input.placement_id,
                    now
                ],
            )
            .await?;
        let job = self
            .object_deletion_job(&input.job_id)
            .await?
            .context("preparing deletion job was not created")?;
        if job.surface_object_id != input.surface_object_id
            || job.placement_id != input.placement_id
            || !matches!(job.state.as_str(), "preparing" | "pending")
        {
            bail!("deletion job identity conflicts with existing work");
        }
        if job.state == "pending" {
            let linked = self
                .backend
                .query_opt(
                    "SELECT 1 FROM object_placements WHERE surface_object_id = ?2
                   AND placement_id = ?3 AND state = 'deleting'
                   AND deletion_job_id = ?1",
                    &vals![input.job_id, input.surface_object_id, input.placement_id],
                )
                .await?;
            if linked.is_none() {
                bail!("pending deletion job has lost its authoritative presence link");
            }
            return Ok(job);
        }

        // Phase 2 links presence. A retry after either this CAS or the durable
        // insert above accepts the exact state and continues.
        self.backend
            .execute(
                "UPDATE object_placements SET state = 'deleting', observed_at = ?4,
                    deletion_job_id = ?1
                 WHERE surface_object_id = ?2 AND placement_id = ?3
                   AND (state IN ('present', 'corrupt')
                     OR (state = 'deleting' AND deletion_job_id = ?1))
                   AND EXISTS (SELECT 1 FROM object_deletion_jobs j
                     WHERE j.job_id = ?1 AND j.surface_object_id = ?2
                       AND j.placement_id = ?3 AND j.state = 'preparing')",
                &vals![
                    input.job_id,
                    input.surface_object_id,
                    input.placement_id,
                    now
                ],
            )
            .await?;
        let linked = self
            .backend
            .query_opt(
                "SELECT 1 FROM object_placements WHERE surface_object_id = ?2
               AND placement_id = ?3 AND state = 'deleting'
               AND deletion_job_id = ?1",
                &vals![input.job_id, input.surface_object_id, input.placement_id],
            )
            .await?;
        if linked.is_none() {
            self.backend
                .execute(
                    "UPDATE object_deletion_jobs SET state = 'cancelled', active_slot = NULL,
                    error = 'presence could not be linked', started_at = ?2,
                    finished_at = ?2, resource_version = resource_version + 1
                 WHERE job_id = ?1 AND state = 'preparing'",
                    &vals![input.job_id, now],
                )
                .await?;
            bail!("deletion jobs require tombstoned, same-surface recorded presence");
        }

        // Phase 3 exposes the job to workers only after its exact link exists.
        self.backend
            .execute(
                "UPDATE object_deletion_jobs SET state = 'pending',
                resource_version = resource_version + 1
             WHERE job_id = ?1 AND state = 'preparing'
               AND EXISTS (SELECT 1 FROM object_placements op
                 WHERE op.surface_object_id = object_deletion_jobs.surface_object_id
                   AND op.placement_id = object_deletion_jobs.placement_id
                   AND op.state = 'deleting' AND op.deletion_job_id = ?1)",
                &vals![input.job_id],
            )
            .await?;
        let pending = self
            .object_deletion_job(&input.job_id)
            .await?
            .context("prepared deletion job disappeared")?;
        if pending.state != "pending" {
            bail!("deletion job could not become pending after presence linked");
        }
        Ok(pending)
    }

    /// Returns a durable object deletion job.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn object_deletion_job(
        &self,
        job_id: &str,
    ) -> Result<Option<ObjectDeletionJobRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {DELETION_JOB_COLUMNS} FROM object_deletion_jobs WHERE job_id = ?1"
                ),
                &vals![job_id],
            )
            .await?;
        rows.first().map(row_to_object_deletion_job).transpose()
    }

    /// Claims a pending or failed physical-deletion job for one worker attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, stale, or non-claimable job, or on database failure.
    pub async fn claim_object_deletion_job(
        &self,
        job_id: &str,
        expected_version: i64,
        started_at: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        let linked = self
            .backend
            .execute(
                "UPDATE object_placements SET state = 'deleting', deletion_job_id = ?1,
                    observed_at = ?3
                 WHERE (state IN ('present', 'corrupt') AND deletion_job_id IS NULL
                     OR state = 'deleting' AND deletion_job_id = ?1)
                   AND EXISTS (SELECT 1 FROM object_deletion_jobs j
                     WHERE j.job_id = ?1 AND j.resource_version = ?2
                       AND j.state IN ('pending', 'failed')
                       AND j.surface_object_id = object_placements.surface_object_id
                       AND j.placement_id = object_placements.placement_id)",
                &vals![job_id, expected_version, started_at],
            )
            .await?;
        if linked != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM object_deletion_jobs j
                 JOIN object_placements op
                   ON op.surface_object_id = j.surface_object_id
                  AND op.placement_id = j.placement_id
                 WHERE j.job_id = ?1 AND j.resource_version = ?2
                   AND j.state IN ('pending', 'failed')
                   AND op.state = 'deleting' AND op.deletion_job_id = ?1",
                    &vals![job_id, expected_version],
                )
                .await?
                .is_none()
        {
            bail!("deletion job is missing, stale, or not claimable");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE object_deletion_jobs SET state = 'running', started_at = ?3,
                    finished_at = NULL, error = NULL,
                    attempt_count = attempt_count + 1,
                    resource_version = resource_version + 1
                 WHERE job_id = ?1 AND resource_version = ?2
                   AND state IN ('pending', 'failed')
                   AND EXISTS (SELECT 1 FROM object_placements op
                     WHERE op.surface_object_id = object_deletion_jobs.surface_object_id
                       AND op.placement_id = object_deletion_jobs.placement_id
                       AND op.state = 'deleting' AND op.deletion_job_id = ?1)",
                &vals![job_id, expected_version, started_at],
            )
            .await?;
        let job = self
            .object_deletion_job(job_id)
            .await?
            .context("claimed deletion job disappeared")?;
        if job.state != "running"
            || job.resource_version != expected_version + 1
            || job.started_at != Some(started_at)
        {
            bail!("deletion job is missing, stale, or not claimable");
        }
        let _ = affected;
        Ok(job)
    }

    /// Completes a claimed deletion attempt and reconciles observed presence.
    ///
    /// A terminal job row is authoritative. Retrying the same completion safely
    /// reconciles the placement after a failure between the two guarded writes.
    ///
    /// # Errors
    ///
    /// Returns an error for inconsistent outcome fields, a stale/non-running job, or database failure.
    pub async fn finish_object_deletion_job(
        &self,
        job_id: &str,
        expected_version: i64,
        succeeded: bool,
        error: Option<&str>,
        finished_at: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        if succeeded == error.is_some() {
            bail!("successful deletion has no error and failed deletion requires one");
        }
        let job_state = if succeeded { "succeeded" } else { "failed" };
        let presence_state = if succeeded { "missing" } else { "corrupt" };
        let affected = self
            .backend
            .execute(
                "UPDATE object_deletion_jobs SET state = ?3, error = ?4,
                    finished_at = ?5,
                    active_slot = CASE WHEN ?3 = 'succeeded' THEN NULL ELSE 1 END,
                    resource_version = resource_version + 1
                 WHERE job_id = ?1 AND resource_version = ?2 AND state = 'running'
                   AND EXISTS (SELECT 1 FROM object_placements op
                     WHERE op.surface_object_id = object_deletion_jobs.surface_object_id
                       AND op.placement_id = object_deletion_jobs.placement_id
                       AND op.state = 'deleting' AND op.deletion_job_id = ?1)",
                &vals![job_id, expected_version, job_state, error, finished_at],
            )
            .await?;
        let job = self
            .object_deletion_job(job_id)
            .await?
            .context("deletion job does not exist")?;
        let exact_terminal_retry = affected == 0
            && job.resource_version == expected_version
            && job.state == job_state
            && job.error.as_deref() == error
            && job.finished_at == Some(finished_at);
        if affected != 1 && !exact_terminal_retry {
            bail!("deletion job is stale or not running");
        }
        self.backend
            .execute(
                "UPDATE object_placements SET state = ?2, observed_at = ?3,
                deletion_job_id = NULL
             WHERE state = 'deleting' AND deletion_job_id = ?1",
                &vals![job_id, presence_state, finished_at],
            )
            .await?;
        let terminal_version = if affected == 1 {
            expected_version + 1
        } else {
            expected_version
        };
        if job.resource_version != terminal_version || job.state != job_state {
            bail!("deletion job is stale or not running");
        }
        Ok(job)
    }

    /// Creates a named placement policy for an existing surface.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed config, a missing surface, a name
    /// collision, or database failure.
    pub async fn create_placement_policy(
        &self,
        input: &NewPlacementPolicy,
    ) -> Result<PlacementPolicyRecord> {
        validate_stable_name(&input.name, "placement policy name")?;
        if !matches!(
            input.kind.as_str(),
            "ordered_failover" | "latency_preferred" | "hash_partition" | "local_then_remote"
        ) {
            bail!("invalid placement-policy kind '{}'", input.kind);
        }
        validate_json_object(&input.config_json, "placement policy config")?;
        let (registry_id, cache_id) = input.surface.ids();
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO placement_policies (registry_id, cache_id, name, kind,
                config_json, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?6
             WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                OR EXISTS (SELECT 1 FROM caches WHERE id = ?2)",
                &vals![
                    registry_id,
                    cache_id,
                    input.name,
                    input.kind,
                    input.config_json,
                    now
                ],
            )
            .await?;
        if affected != 1 {
            bail!("placement-policy surface does not exist");
        }
        self.placement_policy_named(input.surface, &input.name)
            .await?
            .context("created placement policy disappeared")
    }

    /// Returns a placement policy by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn placement_policy(&self, id: i64) -> Result<Option<PlacementPolicyRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {POLICY_COLUMNS} FROM placement_policies WHERE id = ?1"),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_placement_policy).transpose()
    }

    /// Returns a named policy on one surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn placement_policy_named(
        &self,
        surface: SurfaceTarget,
        name: &str,
    ) -> Result<Option<PlacementPolicyRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self.backend.query(&format!("SELECT {POLICY_COLUMNS} FROM placement_policies WHERE (registry_id = ?1 OR cache_id = ?2) AND name = ?3"), &vals![registry_id, cache_id, name]).await?;
        rows.first().map(row_to_placement_policy).transpose()
    }

    /// Lists placement policies owned by one surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_placement_policies(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<PlacementPolicyRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend.query(&format!("SELECT {POLICY_COLUMNS} FROM placement_policies WHERE registry_id = ?1 OR cache_id = ?2 ORDER BY name"), &vals![registry_id, cache_id]).await?.iter().map(row_to_placement_policy).collect()
    }

    /// Adds a policy member only when policy and placement own the same surface.
    ///
    /// # Errors
    ///
    /// Returns an error for a cross-surface member, duplicate placement/order,
    /// missing resource, or database failure.
    pub async fn add_placement_policy_member(
        &self,
        policy_id: i64,
        input: PlacementPolicyMemberInput,
    ) -> Result<()> {
        let now = unix_now();
        self.backend.batch(&[
            Statement::new("INSERT INTO placement_policy_members (policy_id, placement_id, member_order, required)
             SELECT pol.id, p.id, ?3, ?4 FROM placement_policies pol
             JOIN surface_placements p ON p.id = ?2
             WHERE pol.id = ?1
               AND ((pol.registry_id IS NOT NULL AND pol.registry_id = p.registry_id)
                 OR (pol.cache_id IS NOT NULL AND pol.cache_id = p.cache_id))
               AND p.role <> 'archive' AND p.read_enabled = 1
               AND p.completeness = 'complete'
               AND p.state IN ('ready', 'degraded')
               AND NOT EXISTS (SELECT 1 FROM delivery_routes
                   WHERE placement_policy_id = pol.id)", vals![policy_id, input.placement_id, input.member_order, input.required].to_vec()),
            Statement::new("UPDATE placement_policies SET resource_version = resource_version + 1,
                updated_at = ?3 WHERE id = ?1 AND EXISTS (
                  SELECT 1 FROM placement_policy_members
                  WHERE policy_id = ?1 AND placement_id = ?2)",
                vals![policy_id, input.placement_id, now].to_vec()),
        ]).await?;
        if !self
            .list_placement_policy_members(policy_id)
            .await?
            .iter()
            .any(|member| member.placement_id == input.placement_id)
        {
            bail!("policy member must select a placement on the same surface");
        }
        Ok(())
    }

    /// Lists a policy's ordered placement members.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_placement_policy_members(
        &self,
        policy_id: i64,
    ) -> Result<Vec<PlacementPolicyMemberRecord>> {
        let rows = self.backend.query("SELECT policy_id, placement_id, member_order, required FROM placement_policy_members WHERE policy_id = ?1 ORDER BY member_order", &vals![policy_id]).await?;
        rows.iter()
            .map(|row| {
                Ok(PlacementPolicyMemberRecord {
                    policy_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    member_order: row.get(2)?,
                    required: row.get(3)?,
                })
            })
            .collect()
    }

    /// Updates a placement policy's algorithm with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed config, invalid kind, a stale version,
    /// a missing policy, or database failure.
    pub async fn update_placement_policy(
        &self,
        id: i64,
        expected_version: i64,
        kind: &str,
        config_json: &str,
    ) -> Result<PlacementPolicyRecord> {
        if !matches!(
            kind,
            "ordered_failover" | "latency_preferred" | "hash_partition" | "local_then_remote"
        ) {
            bail!("invalid placement-policy kind '{kind}'");
        }
        validate_json_object(config_json, "placement policy config")?;
        let affected = self
            .backend
            .execute(
                "UPDATE placement_policies SET kind = ?3, config_json = ?4,
                resource_version = resource_version + 1, updated_at = ?5
             WHERE id = ?1 AND resource_version = ?2
               AND NOT EXISTS (SELECT 1 FROM delivery_routes
                   WHERE placement_policy_id = ?1)",
                &vals![id, expected_version, kind, config_json, unix_now()],
            )
            .await?;
        if affected != 1 {
            bail!("placement policy is missing or its resource version is stale");
        }
        self.placement_policy(id)
            .await?
            .context("updated placement policy disappeared")
    }

    /// Deletes a placement policy at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or while a route/target references it.
    pub async fn delete_placement_policy(&self, id: i64, expected_version: i64) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM placement_policies WHERE id = ?1 AND resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }

    /// Removes one placement from a policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn remove_placement_policy_member(
        &self,
        policy_id: i64,
        placement_id: i64,
    ) -> Result<bool> {
        let exists = self
            .list_placement_policy_members(policy_id)
            .await?
            .iter()
            .any(|member| member.placement_id == placement_id);
        if !exists {
            return Ok(false);
        }
        self.backend
            .batch(&[
                Statement::new(
                    "DELETE FROM placement_policy_members
                 WHERE policy_id = ?1 AND placement_id = ?2
                   AND NOT EXISTS (SELECT 1 FROM delivery_routes
                       WHERE placement_policy_id = ?1)",
                    vals![policy_id, placement_id].to_vec(),
                ),
                Statement::new(
                    "UPDATE placement_policies SET resource_version = resource_version + 1,
                updated_at = ?3 WHERE id = ?1 AND NOT EXISTS (
                  SELECT 1 FROM placement_policy_members
                  WHERE policy_id = ?1 AND placement_id = ?2)",
                    vals![policy_id, placement_id, unix_now()].to_vec(),
                ),
            ])
            .await?;
        Ok(!self
            .list_placement_policy_members(policy_id)
            .await?
            .iter()
            .any(|member| member.placement_id == placement_id))
    }

    /// Creates a hostname/path route with a same-surface placement selector.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid path, JSON, mode, capabilities, domain
    /// ownership, selector ownership, private direct origin, gateway
    /// provenance, route collision, or database failure.
    pub async fn create_delivery_route(
        &self,
        input: &NewDeliveryRoute,
    ) -> Result<DeliveryRouteRecord> {
        let base_path = normalize_topology_base_path(&input.base_path)?;
        validate_json_object(&input.access_policy_json, "route access policy")?;
        if !matches!(input.mode.as_str(), "hub_proxy" | "hub_redirect" | "direct") {
            bail!(
                "invalid delivery-route mode '{}', expected hub_proxy, hub_redirect, or direct",
                input.mode
            );
        }
        if !(input.serves_git || input.serves_cache || input.serves_web) {
            bail!("a delivery route must serve at least one protocol audience");
        }
        if matches!(input.surface, SurfaceTarget::BinaryCache(_)) && input.serves_git {
            bail!("a binary-cache route cannot serve the Git protocol");
        }
        if input.storage_gateway_id.is_some() != input.gateway_generation.is_some() {
            bail!("storage gateway and gateway generation must be supplied together");
        }
        if input.storage_gateway_id.is_some() && input.mode != "direct" {
            bail!("storage gateway provenance is valid only for direct routes");
        }
        let (registry_id, cache_id) = input.surface.ids();
        let (placement_id, policy_id) = input.selector.ids();
        if input.mode == "direct" && policy_id.is_some() {
            bail!("direct routes require one concrete placement, not a placement policy");
        }
        if let Some(gateway_id) = input.storage_gateway_id {
            let placement_id = placement_id.context(
                "gateway-derived direct routes require one concrete placement, not a policy",
            )?;
            let row = self
                .backend
                .query_opt(
                    "SELECT g.base_path, p.prefix FROM storage_gateways g
                 JOIN surface_placements p ON p.storage_binding_id = g.storage_binding_id
                 WHERE g.id = ?1 AND p.id = ?2",
                    &vals![gateway_id, placement_id],
                )
                .await?
                .context("gateway and placement must share one storage binding")?;
            let gateway_base: String = row.get(0)?;
            let placement_prefix: String = row.get(1)?;
            let derived_path = join_topology_paths(&gateway_base, &placement_prefix)?;
            if base_path != derived_path {
                bail!(
                    "gateway-derived route path must equal gateway base path plus placement prefix"
                );
            }
        }
        let now = unix_now();
        let affected = if let Some(placement_id) = placement_id {
            self.backend
                .execute(
                    "INSERT INTO delivery_routes
                    (domain_id, storage_gateway_id, gateway_generation, base_path,
                     registry_id, cache_id, mode, access_policy_json, placement_id,
                     placement_policy_id, serves_git, serves_cache, serves_web,
                     enabled, created_at, updated_at)
                 SELECT d.id, ?2, ?3, ?4, ?5, ?6, ?7, ?8, p.id, NULL,
                        ?11, ?12, ?13, ?14, ?15, ?15
                 FROM domains d JOIN surface_placements p ON p.id = ?9
                 LEFT JOIN registries r ON r.id = ?5
                 LEFT JOIN caches c ON c.id = ?6
                 JOIN storage_bindings b ON b.id = p.storage_binding_id
                 WHERE d.id = ?1
                   AND (?14 = 0 OR (d.verified_at IS NOT NULL
                     AND d.observed_dns_state = 'verified'
                     AND d.observed_tls_state = 'active'))
                   AND ((?5 IS NOT NULL AND p.registry_id = ?5 AND r.id IS NOT NULL)
                     OR (?6 IS NOT NULL AND p.cache_id = ?6 AND c.id IS NOT NULL))
                   AND (d.org_id IS NULL OR d.org_id = COALESCE(r.org_id, c.org_id))
                   AND p.role <> 'archive' AND p.read_enabled = 1
                   AND p.completeness = 'complete'
                   AND p.state IN ('ready', 'degraded')
                   AND (?7 <> 'direct' OR ?2 IS NOT NULL OR b.access = 'public')
                   AND (?2 IS NULL OR EXISTS (
                        SELECT 1 FROM storage_gateways g
                        WHERE g.id = ?2 AND g.domain_id = d.id
                          AND g.storage_binding_id = p.storage_binding_id
                          AND g.enabled = 1 AND g.reconciliation_state = 'ready'
                          AND g.desired_generation = ?3
                          AND g.observed_generation = ?3))",
                    &vals![
                        input.domain_id,
                        input.storage_gateway_id,
                        input.gateway_generation,
                        base_path,
                        registry_id,
                        cache_id,
                        input.mode,
                        input.access_policy_json,
                        placement_id,
                        policy_id,
                        input.serves_git,
                        input.serves_cache,
                        input.serves_web,
                        input.enabled,
                        now
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO delivery_routes
                    (domain_id, storage_gateway_id, gateway_generation, base_path,
                     registry_id, cache_id, mode, access_policy_json, placement_id,
                     placement_policy_id, serves_git, serves_cache, serves_web,
                     enabled, created_at, updated_at)
                 SELECT d.id, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, pol.id,
                        ?11, ?12, ?13, ?14, ?15, ?15
                 FROM domains d JOIN placement_policies pol ON pol.id = ?10
                 LEFT JOIN registries r ON r.id = ?5
                 LEFT JOIN caches c ON c.id = ?6
                 WHERE d.id = ?1
                   AND ?7 <> 'direct'
                   AND (?14 = 0 OR (d.verified_at IS NOT NULL
                     AND d.observed_dns_state = 'verified'
                     AND d.observed_tls_state = 'active'))
                   AND ((?5 IS NOT NULL AND pol.registry_id = ?5 AND r.id IS NOT NULL)
                     OR (?6 IS NOT NULL AND pol.cache_id = ?6 AND c.id IS NOT NULL))
                   AND (d.org_id IS NULL OR d.org_id = COALESCE(r.org_id, c.org_id))
                   AND EXISTS (SELECT 1 FROM placement_policy_members WHERE policy_id = pol.id)
                   AND NOT EXISTS (
                        SELECT 1 FROM placement_policy_members pm
                        JOIN surface_placements p ON p.id = pm.placement_id
                        WHERE pm.policy_id = pol.id
                          AND (p.role = 'archive' OR p.read_enabled = 0
                            OR p.completeness <> 'complete'
                            OR p.state NOT IN ('ready', 'degraded')))
                   AND (?7 <> 'direct' OR ?2 IS NOT NULL OR NOT EXISTS (
                        SELECT 1 FROM placement_policy_members pm
                        JOIN surface_placements p ON p.id = pm.placement_id
                        JOIN storage_bindings b ON b.id = p.storage_binding_id
                        WHERE pm.policy_id = pol.id AND b.access <> 'public'))
                   AND (?2 IS NULL OR EXISTS (
                        SELECT 1 FROM storage_gateways g WHERE g.id = ?2
                          AND g.domain_id = d.id
                          AND g.enabled = 1 AND g.reconciliation_state = 'ready'
                          AND g.desired_generation = ?3
                          AND g.observed_generation = ?3
                          AND NOT EXISTS (
                            SELECT 1 FROM placement_policy_members pm
                            JOIN surface_placements p ON p.id = pm.placement_id
                            WHERE pm.policy_id = pol.id
                              AND p.storage_binding_id <> g.storage_binding_id)))",
                    &vals![
                        input.domain_id,
                        input.storage_gateway_id,
                        input.gateway_generation,
                        base_path,
                        registry_id,
                        cache_id,
                        input.mode,
                        input.access_policy_json,
                        placement_id,
                        policy_id,
                        input.serves_git,
                        input.serves_cache,
                        input.serves_web,
                        input.enabled,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("route domain, surface, selector, access mode, and gateway must be compatible");
        }
        self.delivery_route_at(input.domain_id, &base_path)
            .await?
            .context("created delivery route disappeared")
    }

    /// Returns a delivery route by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delivery_route(&self, id: i64) -> Result<Option<DeliveryRouteRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {ROUTE_COLUMNS} FROM delivery_routes WHERE id = ?1"),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_delivery_route).transpose()
    }

    /// Returns the route occupying one domain-relative path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delivery_route_at(
        &self,
        domain_id: i64,
        base_path: &str,
    ) -> Result<Option<DeliveryRouteRecord>> {
        let rows = self.backend.query(&format!("SELECT {ROUTE_COLUMNS} FROM delivery_routes WHERE domain_id = ?1 AND base_path = ?2"), &vals![domain_id, base_path]).await?;
        rows.first().map(row_to_delivery_route).transpose()
    }

    /// Lists all routes for one surface in domain/path order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_delivery_routes(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<DeliveryRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend.query(&format!("SELECT {ROUTE_COLUMNS} FROM delivery_routes WHERE registry_id = ?1 OR cache_id = ?2 ORDER BY domain_id, base_path"), &vals![registry_id, cache_id]).await?.iter().map(row_to_delivery_route).collect()
    }

    /// Updates a route's behavior without changing its identity or selector.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid mode/JSON/capabilities, a private direct
    /// origin without a gateway, a stale version, or database failure.
    pub async fn update_delivery_route(
        &self,
        id: i64,
        input: &UpdateDeliveryRoute,
    ) -> Result<DeliveryRouteRecord> {
        if !matches!(input.mode.as_str(), "hub_proxy" | "hub_redirect" | "direct") {
            bail!("invalid delivery-route mode '{}'", input.mode);
        }
        if !(input.serves_git || input.serves_cache || input.serves_web) {
            bail!("a delivery route must serve at least one protocol audience");
        }
        validate_json_object(&input.access_policy_json, "route access policy")?;
        let affected = self
            .backend
            .execute(
                "UPDATE delivery_routes SET mode = ?3, access_policy_json = ?4,
                serves_git = ?5, serves_cache = ?6, serves_web = ?7,
                enabled = ?8, resource_version = resource_version + 1,
                updated_at = ?9
             WHERE id = ?1 AND resource_version = ?2
               AND (cache_id IS NULL OR ?5 = 0)
               AND (?8 = 0 OR EXISTS (SELECT 1 FROM domains d
                   WHERE d.id = delivery_routes.domain_id
                     AND d.verified_at IS NOT NULL
                     AND d.observed_dns_state = 'verified'
                     AND d.observed_tls_state = 'active'))
               AND (?8 = 1 OR NOT EXISTS (SELECT 1 FROM canonical_routes
                   WHERE delivery_route_id = ?1))
               AND NOT EXISTS (SELECT 1 FROM canonical_routes cr
                   WHERE cr.delivery_route_id = ?1 AND
                     ((cr.audience = 'git' AND ?5 = 0)
                       OR (cr.audience = 'nix_cache' AND ?6 = 0)
                       OR (cr.audience = 'web' AND ?7 = 0)))
               AND (storage_gateway_id IS NULL OR ?3 = 'direct')
               AND (?3 <> 'direct' OR placement_id IS NOT NULL)
               AND (storage_gateway_id IS NULL OR EXISTS (
                    SELECT 1 FROM storage_gateways g
                    WHERE g.id = delivery_routes.storage_gateway_id
                      AND g.enabled = 1 AND g.reconciliation_state = 'ready'
                      AND g.observed_generation = delivery_routes.gateway_generation))
               AND ((placement_id IS NOT NULL AND EXISTS (
                    SELECT 1 FROM surface_placements p
                    WHERE p.id = delivery_routes.placement_id
                      AND p.state IN ('ready', 'degraded')))
                 OR (placement_policy_id IS NOT NULL AND EXISTS (
                    SELECT 1 FROM placement_policy_members pm
                    WHERE pm.policy_id = delivery_routes.placement_policy_id)
                   AND NOT EXISTS (
                    SELECT 1 FROM placement_policy_members pm
                    JOIN surface_placements p ON p.id = pm.placement_id
                    WHERE pm.policy_id = delivery_routes.placement_policy_id
                      AND p.state NOT IN ('ready', 'degraded'))))
               AND (?3 <> 'direct' OR storage_gateway_id IS NOT NULL
                 OR (placement_id IS NOT NULL AND EXISTS (
                    SELECT 1 FROM surface_placements p
                    JOIN storage_bindings b ON b.id = p.storage_binding_id
                    WHERE p.id = delivery_routes.placement_id AND b.access = 'public'))
                 OR (placement_policy_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM placement_policy_members pm
                    JOIN surface_placements p ON p.id = pm.placement_id
                    JOIN storage_bindings b ON b.id = p.storage_binding_id
                    WHERE pm.policy_id = delivery_routes.placement_policy_id
                      AND b.access <> 'public')))",
                &vals![
                    id,
                    input.expected_version,
                    input.mode,
                    input.access_policy_json,
                    input.serves_git,
                    input.serves_cache,
                    input.serves_web,
                    input.enabled,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("delivery route is missing, stale, or incompatible with the requested behavior");
        }
        self.delivery_route(id)
            .await?
            .context("updated delivery route disappeared")
    }

    /// Deletes a route at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_delivery_route(&self, id: i64, expected_version: i64) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM delivery_routes WHERE id = ?1 AND resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }

    /// Sets the canonical route for one surface/audience with version checking.
    ///
    /// # Errors
    ///
    /// Returns an error when the route targets another surface, lacks the
    /// audience capability, the expected version is stale, or on database failure.
    pub async fn set_canonical_route(
        &self,
        surface: SurfaceTarget,
        audience: &str,
        route_id: i64,
        expected_version: Option<i64>,
    ) -> Result<CanonicalRouteRecord> {
        if !matches!(audience, "git" | "nix_cache" | "web") {
            bail!("invalid canonical-route audience '{audience}'");
        }
        let (registry_id, cache_id) = surface.ids();
        let now = unix_now();
        let capability = match audience {
            "git" => "serves_git",
            "nix_cache" => "serves_cache",
            _ => "serves_web",
        };
        let sql = if expected_version.is_none() {
            format!(
                "INSERT INTO canonical_routes (registry_id, cache_id, audience,
                    delivery_route_id, created_at, updated_at)
                 SELECT ?1, ?2, ?3, r.id, ?5, ?5 FROM delivery_routes r
                 WHERE r.id = ?4 AND (r.registry_id = ?1 OR r.cache_id = ?2)
                   AND r.enabled = 1 AND r.readiness_state = 'ready'
                   AND r.{capability} = 1
                   AND EXISTS (SELECT 1 FROM domains d WHERE d.id = r.domain_id
                     AND d.verified_at IS NOT NULL AND d.observed_dns_state = 'verified'
                     AND d.observed_tls_state = 'active')
                   AND (r.storage_gateway_id IS NULL OR EXISTS (
                     SELECT 1 FROM storage_gateways g WHERE g.id = r.storage_gateway_id
                       AND g.enabled = 1 AND g.reconciliation_state = 'ready'
                       AND g.observed_generation = r.gateway_generation))
                   AND (r.mode <> 'direct' OR r.storage_gateway_id IS NOT NULL
                     OR (r.placement_id IS NOT NULL AND EXISTS (
                       SELECT 1 FROM surface_placements p JOIN storage_bindings b
                         ON b.id = p.storage_binding_id
                       WHERE p.id = r.placement_id AND b.access = 'public'))
                     OR (r.placement_policy_id IS NOT NULL AND NOT EXISTS (
                       SELECT 1 FROM placement_policy_members pm
                       JOIN surface_placements p ON p.id = pm.placement_id
                       JOIN storage_bindings b ON b.id = p.storage_binding_id
                       WHERE pm.policy_id = r.placement_policy_id
                         AND b.access <> 'public')))"
            )
        } else {
            format!(
                "UPDATE canonical_routes SET delivery_route_id = ?4,
                    updated_at = ?5, resource_version = resource_version + 1
                 WHERE (registry_id = ?1 OR cache_id = ?2) AND audience = ?3
                   AND resource_version = ?6 AND EXISTS (
                     SELECT 1 FROM delivery_routes r WHERE r.id = ?4
                       AND (r.registry_id = ?1 OR r.cache_id = ?2)
                       AND r.enabled = 1 AND r.readiness_state = 'ready'
                       AND r.{capability} = 1
                       AND EXISTS (SELECT 1 FROM domains d WHERE d.id = r.domain_id
                         AND d.verified_at IS NOT NULL AND d.observed_dns_state = 'verified'
                         AND d.observed_tls_state = 'active')
                       AND (r.storage_gateway_id IS NULL OR EXISTS (
                         SELECT 1 FROM storage_gateways g WHERE g.id = r.storage_gateway_id
                           AND g.enabled = 1 AND g.reconciliation_state = 'ready'
                           AND g.observed_generation = r.gateway_generation))
                       AND (r.mode <> 'direct' OR r.storage_gateway_id IS NOT NULL
                         OR (r.placement_id IS NOT NULL AND EXISTS (
                           SELECT 1 FROM surface_placements p JOIN storage_bindings b
                             ON b.id = p.storage_binding_id
                           WHERE p.id = r.placement_id AND b.access = 'public'))
                         OR (r.placement_policy_id IS NOT NULL AND NOT EXISTS (
                           SELECT 1 FROM placement_policy_members pm
                           JOIN surface_placements p ON p.id = pm.placement_id
                           JOIN storage_bindings b ON b.id = p.storage_binding_id
                           WHERE pm.policy_id = r.placement_policy_id
                             AND b.access <> 'public'))))"
            )
        };
        let affected = if let Some(version) = expected_version {
            self.backend
                .execute(
                    &sql,
                    &vals![registry_id, cache_id, audience, route_id, now, version],
                )
                .await?
        } else {
            self.backend
                .execute(&sql, &vals![registry_id, cache_id, audience, route_id, now])
                .await?
        };
        if affected != 1 {
            bail!("canonical route is incompatible, missing, duplicated, or stale");
        }
        self.configured_canonical_route(surface, audience)
            .await?
            .context("canonical route disappeared")
    }

    /// Returns the configured canonical row for a surface/audience.
    ///
    /// This management view deliberately does not filter on observed route,
    /// domain, or gateway health, so a degraded selection and its version remain
    /// inspectable and modifiable.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn configured_canonical_route(
        &self,
        surface: SurfaceTarget,
        audience: &str,
    ) -> Result<Option<CanonicalRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self
            .backend
            .query(
                "SELECT id, registry_id, cache_id, audience, delivery_route_id,
                    created_at, updated_at, resource_version
                 FROM canonical_routes
                 WHERE (registry_id = ?1 OR cache_id = ?2) AND audience = ?3",
                &vals![registry_id, cache_id, audience],
            )
            .await?;
        rows.first().map(row_to_canonical_route).transpose()
    }

    /// Resolves the healthy canonical route for a surface/audience.
    ///
    /// Unlike [`Database::configured_canonical_route`], this serving view returns
    /// `None` while the selected route, domain, or gateway is unhealthy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn canonical_route(
        &self,
        surface: SurfaceTarget,
        audience: &str,
    ) -> Result<Option<CanonicalRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self
            .backend
            .query(
                "SELECT cr.id, cr.registry_id, cr.cache_id, cr.audience,
                    cr.delivery_route_id, cr.created_at, cr.updated_at, cr.resource_version
                 FROM canonical_routes cr
                 JOIN delivery_routes r ON r.id = cr.delivery_route_id
                 JOIN domains d ON d.id = r.domain_id
                 LEFT JOIN storage_gateways g ON g.id = r.storage_gateway_id
                 WHERE (cr.registry_id = ?1 OR cr.cache_id = ?2) AND cr.audience = ?3
                   AND r.enabled = 1 AND r.readiness_state = 'ready'
                   AND d.verified_at IS NOT NULL
                   AND d.observed_dns_state = 'verified' AND d.observed_tls_state = 'active'
                   AND ((cr.audience = 'git' AND r.serves_git = 1)
                     OR (cr.audience = 'nix_cache' AND r.serves_cache = 1)
                     OR (cr.audience = 'web' AND r.serves_web = 1))
                   AND (r.storage_gateway_id IS NULL OR
                     (g.enabled = 1 AND g.reconciliation_state = 'ready'
                       AND g.observed_generation = r.gateway_generation))
                   AND (r.mode <> 'direct' OR r.storage_gateway_id IS NOT NULL
                     OR (r.placement_id IS NOT NULL AND EXISTS (
                       SELECT 1 FROM surface_placements p JOIN storage_bindings b
                         ON b.id = p.storage_binding_id
                       WHERE p.id = r.placement_id AND b.access = 'public'))
                     OR (r.placement_policy_id IS NOT NULL AND NOT EXISTS (
                       SELECT 1 FROM placement_policy_members pm
                       JOIN surface_placements p ON p.id = pm.placement_id
                       JOIN storage_bindings b ON b.id = p.storage_binding_id
                       WHERE pm.policy_id = r.placement_policy_id
                         AND b.access <> 'public'))) ",
                &vals![registry_id, cache_id, audience],
            )
            .await?;
        rows.first().map(row_to_canonical_route).transpose()
    }

    /// Lists configured canonical rows for one surface.
    ///
    /// This is the unfiltered management counterpart to
    /// [`Database::list_canonical_routes`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_configured_canonical_routes(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<CanonicalRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                "SELECT id, registry_id, cache_id, audience, delivery_route_id,
                    created_at, updated_at, resource_version
                 FROM canonical_routes
                 WHERE registry_id = ?1 OR cache_id = ?2
                 ORDER BY audience",
                &vals![registry_id, cache_id],
            )
            .await?
            .iter()
            .map(row_to_canonical_route)
            .collect()
    }

    /// Lists healthy resolved canonical routes for one surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_canonical_routes(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<CanonicalRouteRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                "SELECT cr.id, cr.registry_id, cr.cache_id, cr.audience,
                    cr.delivery_route_id, cr.created_at, cr.updated_at, cr.resource_version
                 FROM canonical_routes cr JOIN delivery_routes r ON r.id = cr.delivery_route_id
                 JOIN domains d ON d.id = r.domain_id
                 LEFT JOIN storage_gateways g ON g.id = r.storage_gateway_id
                 WHERE (cr.registry_id = ?1 OR cr.cache_id = ?2)
                   AND r.enabled = 1 AND r.readiness_state = 'ready'
                   AND d.verified_at IS NOT NULL AND d.observed_dns_state = 'verified'
                   AND d.observed_tls_state = 'active'
                   AND ((cr.audience = 'git' AND r.serves_git = 1)
                     OR (cr.audience = 'nix_cache' AND r.serves_cache = 1)
                     OR (cr.audience = 'web' AND r.serves_web = 1))
                   AND (r.storage_gateway_id IS NULL OR
                     (g.enabled = 1 AND g.reconciliation_state = 'ready'
                       AND g.observed_generation = r.gateway_generation))
                   AND (r.mode <> 'direct' OR r.storage_gateway_id IS NOT NULL
                     OR (r.placement_id IS NOT NULL AND EXISTS (
                       SELECT 1 FROM surface_placements p JOIN storage_bindings b
                         ON b.id = p.storage_binding_id
                       WHERE p.id = r.placement_id AND b.access = 'public'))
                     OR (r.placement_policy_id IS NOT NULL AND NOT EXISTS (
                       SELECT 1 FROM placement_policy_members pm
                       JOIN surface_placements p ON p.id = pm.placement_id
                       JOIN storage_bindings b ON b.id = p.storage_binding_id
                       WHERE pm.policy_id = r.placement_policy_id
                         AND b.access <> 'public')))
                 ORDER BY cr.audience",
                &vals![registry_id, cache_id],
            )
            .await?
            .iter()
            .map(row_to_canonical_route)
            .collect()
    }

    /// Creates or version-updates topology defaults after checking scope ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/cross-scope references, a stale version,
    /// a duplicate create, or database failure.
    pub async fn set_topology_defaults(
        &self,
        input: &SetTopologyDefaults,
    ) -> Result<TopologyDefaultsRecord> {
        let (scope_kind, org_id, scope_key) = match input.scope {
            TopologyScope::Instance => ("instance", None, "instance".to_string()),
            TopologyScope::Organization(id) => ("organization", Some(id), format!("org:{id}")),
        };
        let owned = match input.scope {
            TopologyScope::Instance => self.backend.query(
                "SELECT
                  (?1 IS NULL OR EXISTS (SELECT 1 FROM storage_bindings WHERE id = ?1 AND is_instance_default = 1))
                  AND (?2 IS NULL OR EXISTS (SELECT 1 FROM domains WHERE id = ?2 AND org_id IS NULL))
                  AND (?3 IS NULL OR (?1 IS NOT NULL AND ?2 IS NOT NULL AND EXISTS (
                    SELECT 1 FROM storage_gateways WHERE id = ?3 AND org_id IS NULL
                      AND storage_binding_id = ?1 AND domain_id = ?2)))",
                &vals![input.storage_binding_id, input.domain_id, input.storage_gateway_id]).await?,
            TopologyScope::Organization(id) => self.backend.query(
                "SELECT EXISTS (SELECT 1 FROM orgs WHERE id = ?1)
                  AND (?2 IS NULL OR EXISTS (SELECT 1 FROM storage_bindings WHERE id = ?2 AND (org_id = ?1 OR is_instance_default = 1)))
                  AND (?3 IS NULL OR EXISTS (SELECT 1 FROM domains WHERE id = ?3 AND (org_id = ?1 OR org_id IS NULL)))
                  AND (?4 IS NULL OR (?2 IS NOT NULL AND ?3 IS NOT NULL AND EXISTS (
                    SELECT 1 FROM storage_gateways WHERE id = ?4
                      AND (org_id = ?1 OR org_id IS NULL)
                      AND storage_binding_id = ?2 AND domain_id = ?3)))",
                &vals![id, input.storage_binding_id, input.domain_id, input.storage_gateway_id]).await?,
        };
        if !owned
            .first()
            .context("ownership query returned no row")?
            .get::<bool>(0)?
        {
            bail!("topology defaults may reference only resources visible in their scope");
        }
        let now = unix_now();
        let affected = if let Some(version) = input.expected_version {
            self.backend
                .execute(
                    "UPDATE topology_defaults SET storage_binding_id = ?2, domain_id = ?3,
                    storage_gateway_id = ?4, resource_version = resource_version + 1,
                    updated_at = ?5 WHERE scope_key = ?1 AND resource_version = ?6",
                    &vals![
                        scope_key,
                        input.storage_binding_id,
                        input.domain_id,
                        input.storage_gateway_id,
                        now,
                        version
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO topology_defaults (scope_kind, org_id, scope_key,
                    storage_binding_id, domain_id, storage_gateway_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    &vals![
                        scope_kind,
                        org_id,
                        scope_key,
                        input.storage_binding_id,
                        input.domain_id,
                        input.storage_gateway_id,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("topology defaults are missing, duplicated, or stale");
        }
        self.topology_defaults(input.scope)
            .await?
            .context("topology defaults disappeared")
    }

    /// Returns topology defaults for one scope.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_defaults(
        &self,
        scope: TopologyScope,
    ) -> Result<Option<TopologyDefaultsRecord>> {
        let key = match scope {
            TopologyScope::Instance => "instance".to_string(),
            TopologyScope::Organization(id) => format!("org:{id}"),
        };
        let rows = self
            .backend
            .query(
                "SELECT id, scope_kind, org_id, scope_key,
            storage_binding_id, domain_id, storage_gateway_id, resource_version,
            created_at, updated_at FROM topology_defaults WHERE scope_key = ?1",
                &vals![key],
            )
            .await?;
        rows.first().map(row_to_topology_defaults).transpose()
    }

    /// Deletes topology defaults at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_topology_defaults(
        &self,
        scope: TopologyScope,
        expected_version: i64,
    ) -> Result<bool> {
        let key = match scope {
            TopologyScope::Instance => "instance".to_string(),
            TopologyScope::Organization(id) => format!("org:{id}"),
        };
        Ok(self
            .backend
            .execute(
                "DELETE FROM topology_defaults WHERE scope_key = ?1 AND resource_version = ?2",
                &vals![key, expected_version],
            )
            .await?
            == 1)
    }

    /// Creates or version-updates one registry-derived cache retention subscription.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed selectors, negative grace, missing
    /// resources, a stale version, a duplicate create, or database failure.
    pub async fn set_cache_retention_subscription(
        &self,
        input: &SetCacheRetentionSubscription,
    ) -> Result<CacheRetentionSubscriptionRecord> {
        validate_json_object(&input.selector_json, "retention selector")?;
        if input.removal_grace_secs < 0 {
            bail!("retention removal grace cannot be negative");
        }
        let now = unix_now();
        let affected = if let Some(version) = input.expected_version {
            self.backend
                .execute(
                    "UPDATE cache_retention_subscriptions SET selector_json = ?3,
                    removal_grace_secs = ?4, exposure_acknowledged_at = ?5,
                    enabled = ?6, refresh_state = 'stale', retired_at = NULL,
                    resource_version = resource_version + 1,
                    updated_at = ?7 WHERE cache_id = ?1 AND registry_id = ?2
                    AND resource_version = ?8",
                    &vals![
                        input.cache_id,
                        input.registry_id,
                        input.selector_json,
                        input.removal_grace_secs,
                        input.exposure_acknowledged_at,
                        input.enabled,
                        now,
                        version
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO cache_retention_subscriptions (cache_id, registry_id,
                    selector_json, removal_grace_secs, exposure_acknowledged_at,
                    enabled, created_at, updated_at)
                 SELECT c.id, r.id, ?3, ?4, ?5, ?6, ?7, ?7
                 FROM caches c CROSS JOIN registries r WHERE c.id = ?1 AND r.id = ?2",
                    &vals![
                        input.cache_id,
                        input.registry_id,
                        input.selector_json,
                        input.removal_grace_secs,
                        input.exposure_acknowledged_at,
                        input.enabled,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("retention subscription is missing, duplicated, stale, or references missing resources");
        }
        self.cache_retention_subscription(input.cache_id, input.registry_id)
            .await?
            .context("retention subscription disappeared")
    }

    /// Returns one cache/registry retention subscription.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_retention_subscription(
        &self,
        cache_id: i64,
        registry_id: i64,
    ) -> Result<Option<CacheRetentionSubscriptionRecord>> {
        let rows = self.backend.query(&format!("SELECT {RETENTION_COLUMNS} FROM cache_retention_subscriptions WHERE cache_id = ?1 AND registry_id = ?2"), &vals![cache_id, registry_id]).await?;
        rows.first()
            .map(row_to_cache_retention_subscription)
            .transpose()
    }

    /// Lists retention subscriptions owned by one cache.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_retention_subscriptions(
        &self,
        cache_id: i64,
    ) -> Result<Vec<CacheRetentionSubscriptionRecord>> {
        self.backend.query(&format!("SELECT {RETENTION_COLUMNS} FROM cache_retention_subscriptions WHERE cache_id = ?1 ORDER BY registry_id"), &vals![cache_id]).await?.iter().map(row_to_cache_retention_subscription).collect()
    }

    /// Soft-retires a retention subscription without deleting prior root reasons.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn retire_cache_retention_subscription(
        &self,
        id: i64,
        expected_version: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "UPDATE cache_retention_subscriptions
                 SET enabled = 0, retired_at = ?3, refresh_state = 'stale',
                     resource_version = resource_version + 1, updated_at = ?3
                 WHERE id = ?1 AND resource_version = ?2 AND retired_at IS NULL",
                &vals![id, expected_version, unix_now()],
            )
            .await?
            == 1)
    }

    /// Begins an unreachable immutable retention generation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/count, stale subscription, or database failure.
    pub async fn begin_cache_retention_refresh(
        &self,
        refresh_id: &str,
        subscription_id: i64,
        expected_version: i64,
        source_revision: &str,
        expected_reason_count: i64,
        started_at: i64,
    ) -> Result<()> {
        validate_key_bytes(refresh_id, "retention refresh id", 64)?;
        validate_key_bytes(source_revision, "retention source revision", 128)?;
        if expected_reason_count < 0 {
            bail!("expected reason count cannot be negative");
        }
        let affected = self
            .backend
            .execute(
                "INSERT INTO cache_retention_refreshes
             (refresh_id, subscription_id, parent_refresh_id, source_revision,
              started_at, expected_reason_count)
             SELECT ?1, id, current_refresh_id, ?4, ?6, ?5
             FROM cache_retention_subscriptions
             WHERE id = ?2 AND resource_version = ?3 AND enabled = 1 AND retired_at IS NULL",
                &vals![
                    refresh_id,
                    subscription_id,
                    expected_version,
                    source_revision,
                    expected_reason_count,
                    started_at
                ],
            )
            .await?;
        if affected != 1 {
            bail!("retention subscription is stale, disabled, retired, or missing");
        }
        Ok(())
    }

    /// Stages one immutable source-proven retention reason under a refresh id.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid provenance, duplicate identity, inactive refresh, or database failure.
    pub async fn stage_cache_retention_reason(
        &self,
        refresh_id: &str,
        input: &RetentionRefreshReasonInput,
        refreshed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(&input.reason_key, "retention reason key", 255)?;
        validate_key_bytes(&input.store_hash, "retention store hash", 64)?;
        validate_key_bytes(&input.source_ref, "retention source ref", 255)?;
        if !matches!(
            input.source_kind.as_str(),
            "registry_catalog" | "release" | "channel"
        ) {
            bail!(
                "invalid registry-derived retention source kind '{}'",
                input.source_kind
            );
        }
        let affected = self
            .backend
            .execute(
                "INSERT INTO cache_root_reasons
             (cache_id, registry_id, store_hash, reason_key, source_kind, refresh_id,
              retention_subscription_id, release_id, channel_id, partition_bucket,
              source_ref, source_revision, expires_at, refreshed_at)
             SELECT sub.cache_id, sub.registry_id, ?2, ?3, ?4, rr.refresh_id,
                    sub.id, ?6, ?7, ?8, ?5, rr.source_revision, ?9, ?10
             FROM cache_retention_refreshes rr
             JOIN cache_retention_subscriptions sub ON sub.id = rr.subscription_id
             WHERE rr.refresh_id = ?1 AND rr.state = 'running'
               AND ((?4 = 'registry_catalog' AND ?6 IS NULL AND ?7 IS NULL AND ?8 IS NULL)
                 OR (?4 = 'release' AND ?6 IS NOT NULL AND ?7 IS NULL AND ?8 IS NULL
                   AND EXISTS (SELECT 1 FROM releases rel
                     JOIN release_artifacts ra ON ra.release_id = rel.id
                     WHERE rel.id = ?6 AND rel.registry_id = sub.registry_id
                       AND ra.store_hash = ?2))
                 OR (?4 = 'channel' AND ?6 IS NOT NULL AND ?7 IS NOT NULL AND ?8 IS NOT NULL
                   AND EXISTS (SELECT 1 FROM channels ch JOIN channel_partitions cp
                     ON cp.channel_id = ch.id AND cp.bucket = ?8
                     JOIN releases rel ON rel.id = ?6 AND rel.registry_id = ch.registry_id
                       AND rel.semver = cp.release
                     JOIN release_artifacts ra ON ra.release_id = rel.id
                       AND ra.store_hash = ?2
                     WHERE ch.id = ?7 AND ch.registry_id = sub.registry_id)))",
                &vals![
                    refresh_id,
                    input.store_hash,
                    input.reason_key,
                    input.source_kind,
                    input.source_ref,
                    input.release_id,
                    input.channel_id,
                    input.partition_bucket,
                    input.expires_at,
                    refreshed_at
                ],
            )
            .await?;
        if affected != 1 {
            bail!("retention reason provenance is invalid or duplicated");
        }
        Ok(())
    }

    /// Seals a complete staged generation, then advances the subscription with one pointer CAS.
    ///
    /// Old reasons remain immutable and reachable through the parent lineage until grace expires.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete staging, stale lineage/version, retired subscription, or database failure.
    pub async fn commit_cache_retention_refresh(
        &self,
        refresh_id: &str,
        expected_version: i64,
        activated_at: i64,
    ) -> Result<CacheRetentionSubscriptionRecord> {
        let sealed = self
            .backend
            .execute(
                "UPDATE cache_retention_refreshes SET state = 'staged',
                activated_at = ?2, grace_until = ?2 + (SELECT removal_grace_secs
                  FROM cache_retention_subscriptions WHERE id = subscription_id),
                finished_at = ?2
             WHERE refresh_id = ?1 AND state = 'running'
               AND expected_reason_count = (SELECT COUNT(*) FROM cache_root_reasons
                 WHERE refresh_id = ?1)",
                &vals![refresh_id, activated_at],
            )
            .await?;
        if sealed != 1 {
            let staged = self
                .backend
                .query_opt(
                    "SELECT 1 FROM cache_retention_refreshes rr
                 WHERE rr.refresh_id = ?1 AND rr.state = 'staged' AND rr.activated_at = ?2
                   AND rr.expected_reason_count = (SELECT COUNT(*) FROM cache_root_reasons
                     WHERE refresh_id = rr.refresh_id)",
                    &vals![refresh_id, activated_at],
                )
                .await?;
            if staged.is_none() {
                bail!("retention refresh staging is incomplete or terminal with different inputs");
            }
        }
        let advanced = self.backend.execute(
            "UPDATE cache_retention_subscriptions SET current_refresh_id = ?1,
                last_successful_revision = (SELECT source_revision FROM cache_retention_refreshes
                  WHERE refresh_id = ?1), last_refresh_at = ?3,
                refresh_state = 'fresh', refresh_error = NULL,
                resource_version = resource_version + 1, updated_at = ?3
             WHERE id = (SELECT subscription_id FROM cache_retention_refreshes WHERE refresh_id = ?1)
               AND resource_version = ?2 AND enabled = 1 AND retired_at IS NULL
               AND (current_refresh_id = (SELECT parent_refresh_id
                      FROM cache_retention_refreshes WHERE refresh_id = ?1)
                 OR (current_refresh_id IS NULL AND (SELECT parent_refresh_id
                      FROM cache_retention_refreshes WHERE refresh_id = ?1) IS NULL))
               AND EXISTS (SELECT 1 FROM cache_retention_refreshes
                 WHERE refresh_id = ?1 AND state = 'staged')",
            &vals![refresh_id, expected_version, activated_at],
        ).await?;
        if advanced != 1 {
            let already_current = self
                .backend
                .query_opt(
                    "SELECT 1 FROM cache_retention_subscriptions WHERE current_refresh_id = ?1",
                    &vals![refresh_id],
                )
                .await?;
            if already_current.is_none() {
                bail!("retention refresh pointer CAS is stale or subscription is inactive");
            }
        }
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {RETENTION_COLUMNS} FROM cache_retention_subscriptions
                WHERE current_refresh_id = ?1"
                ),
                &vals![refresh_id],
            )
            .await?;
        rows.first()
            .map(row_to_cache_retention_subscription)
            .transpose()?
            .context("committed retention subscription disappeared")
    }

    /// Marks an unreachable staging refresh failed without changing active roots.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty error, non-running refresh, or database failure.
    pub async fn fail_cache_retention_refresh(
        &self,
        refresh_id: &str,
        error: &str,
        finished_at: i64,
    ) -> Result<bool> {
        if error.trim().is_empty() {
            bail!("retention refresh failure requires an error");
        }
        let failed = self
            .backend
            .execute(
                "UPDATE cache_retention_refreshes SET state = 'failed', error = ?2,
                finished_at = ?3 WHERE refresh_id = ?1 AND state = 'running'",
                &vals![refresh_id, error, finished_at],
            )
            .await?
            == 1;
        if failed {
            self.backend
                .execute(
                    "UPDATE cache_retention_subscriptions SET refresh_state = 'failed',
                    refresh_error = ?2, last_refresh_at = ?3, updated_at = ?3,
                    resource_version = resource_version + 1
                 WHERE id = (SELECT subscription_id FROM cache_retention_refreshes
                   WHERE refresh_id = ?1)
                   AND (current_refresh_id = (SELECT parent_refresh_id
                          FROM cache_retention_refreshes WHERE refresh_id = ?1)
                     OR (current_refresh_id IS NULL AND (SELECT parent_refresh_id
                          FROM cache_retention_refreshes WHERE refresh_id = ?1) IS NULL))
                   AND (last_refresh_at IS NULL OR last_refresh_at <= (
                     SELECT started_at FROM cache_retention_refreshes
                     WHERE refresh_id = ?1))
                   AND NOT EXISTS (SELECT 1 FROM cache_retention_refreshes newer
                     WHERE newer.subscription_id = cache_retention_subscriptions.id
                       AND newer.started_at > (SELECT started_at
                         FROM cache_retention_refreshes WHERE refresh_id = ?1))",
                    &vals![refresh_id, error, finished_at],
                )
                .await?;
        }
        Ok(failed)
    }

    /// Creates or version-updates one registry-to-cache population effect.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed selectors, invalid vocabulary, a policy
    /// on another cache, missing resources, stale version, or database failure.
    pub async fn set_cache_population_target(
        &self,
        input: &SetCachePopulationTarget,
    ) -> Result<CachePopulationTargetRecord> {
        validate_json_object(&input.selector_json, "population selector")?;
        if !matches!(
            input.trigger_kind.as_str(),
            "release" | "manual" | "continuous"
        ) {
            bail!(
                "invalid population trigger '{}', expected release, manual, or continuous",
                input.trigger_kind
            );
        }
        if !matches!(
            input.validation_gate.as_str(),
            "none" | "presence" | "closure" | "deep"
        ) {
            bail!(
                "invalid population validation gate '{}'",
                input.validation_gate
            );
        }
        let now = unix_now();
        let affected = if let Some(version) = input.expected_version {
            self.backend
                .execute(
                    "UPDATE cache_population_targets SET required = ?4,
                    placement_policy_id = ?5, selector_json = ?6,
                    validation_gate = ?7, enabled = ?8,
                    resource_version = resource_version + 1, updated_at = ?9
                 WHERE cache_id = ?1 AND registry_id = ?2 AND trigger_kind = ?3
                   AND resource_version = ?10
                   AND (?5 IS NULL OR EXISTS (SELECT 1 FROM placement_policies
                       WHERE id = ?5 AND cache_id = ?1))",
                    &vals![
                        input.cache_id,
                        input.registry_id,
                        input.trigger_kind,
                        input.required,
                        input.placement_policy_id,
                        input.selector_json,
                        input.validation_gate,
                        input.enabled,
                        now,
                        version
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO cache_population_targets (cache_id, registry_id,
                    trigger_kind, required, placement_policy_id, selector_json,
                    validation_gate, enabled, created_at, updated_at)
                 SELECT c.id, r.id, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9
                 FROM caches c CROSS JOIN registries r WHERE c.id = ?1 AND r.id = ?2
                   AND (?5 IS NULL OR EXISTS (SELECT 1 FROM placement_policies
                       WHERE id = ?5 AND cache_id = c.id))",
                    &vals![
                        input.cache_id,
                        input.registry_id,
                        input.trigger_kind,
                        input.required,
                        input.placement_policy_id,
                        input.selector_json,
                        input.validation_gate,
                        input.enabled,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("population target is missing, duplicated, stale, or topologically incompatible");
        }
        self.cache_population_target(input.cache_id, input.registry_id, &input.trigger_kind)
            .await?
            .context("population target disappeared")
    }

    /// Returns one population target.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_population_target(
        &self,
        cache_id: i64,
        registry_id: i64,
        trigger_kind: &str,
    ) -> Result<Option<CachePopulationTargetRecord>> {
        let rows = self.backend.query(&format!("SELECT {POPULATION_COLUMNS} FROM cache_population_targets WHERE cache_id = ?1 AND registry_id = ?2 AND trigger_kind = ?3"), &vals![cache_id, registry_id, trigger_kind]).await?;
        rows.first().map(row_to_cache_population_target).transpose()
    }

    /// Lists population targets that write to one cache.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_population_targets(
        &self,
        cache_id: i64,
    ) -> Result<Vec<CachePopulationTargetRecord>> {
        self.backend.query(&format!("SELECT {POPULATION_COLUMNS} FROM cache_population_targets WHERE cache_id = ?1 ORDER BY registry_id, trigger_kind"), &vals![cache_id]).await?.iter().map(row_to_cache_population_target).collect()
    }

    /// Deletes a population target at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_cache_population_target(
        &self,
        id: i64,
        expected_version: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM cache_population_targets WHERE id = ?1 AND resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }

    /// Stores an immutable, expiring semantic topology plan.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, non-future expiry, duplicate id,
    /// or database failure.
    pub async fn create_topology_plan(
        &self,
        input: &NewTopologyPlan,
    ) -> Result<TopologyPlanRecord> {
        validate_key_bytes(&input.plan_id, "topology plan id", 64)?;
        validate_key_bytes(&input.plan_kind, "topology plan kind", 64)?;
        validate_key_bytes(&input.actor_kind, "topology plan actor kind", 32)?;
        if !matches!(
            input.actor_kind.as_str(),
            "user" | "service_account" | "key" | "system"
        ) {
            bail!("invalid topology plan actor kind '{}'", input.actor_kind);
        }
        validate_key_bytes(&input.scope, "topology plan scope", 255)?;
        if let Some(hash) = input.confirmation_hash.as_deref() {
            validate_key_bytes(hash, "confirmation hash", 128)?;
        }
        validate_json_value(&input.input_versions_json, "plan input versions")?;
        validate_json_value(&input.effects_json, "plan effects")?;
        validate_json_value(&input.warnings_json, "plan warnings")?;
        let now = unix_now();
        if input.expires_at <= now {
            bail!("topology plan expiry must be in the future");
        }
        self.backend
            .execute(
                "INSERT INTO topology_plans (plan_id, plan_kind, actor_kind, actor_id,
                actor_label, scope, input_versions_json, effects_json, warnings_json,
                confirmation_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                &vals![
                    input.plan_id,
                    input.plan_kind,
                    input.actor_kind,
                    input.actor_id,
                    input.actor_label,
                    input.scope,
                    input.input_versions_json,
                    input.effects_json,
                    input.warnings_json,
                    input.confirmation_hash,
                    now,
                    input.expires_at
                ],
            )
            .await?;
        self.topology_plan(&input.plan_id)
            .await?
            .context("created topology plan disappeared")
    }

    /// Returns a topology plan by opaque id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_plan(&self, plan_id: &str) -> Result<Option<TopologyPlanRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {PLAN_COLUMNS} FROM topology_plans WHERE plan_id = ?1"),
                &vals![plan_id],
            )
            .await?;
        rows.first().map(row_to_topology_plan).transpose()
    }

    /// Lists plans in one authorization scope, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_topology_plans(&self, scope: &str) -> Result<Vec<TopologyPlanRecord>> {
        self.backend.query(&format!("SELECT {PLAN_COLUMNS} FROM topology_plans WHERE scope = ?1 ORDER BY created_at DESC, plan_id"), &vals![scope]).await?.iter().map(row_to_topology_plan).collect()
    }

    /// Creates a durable topology operation after validating its target tuple.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed detail, an incompatible surface and
    /// placement, a missing target, duplicate id, or database failure.
    pub async fn create_topology_operation(
        &self,
        input: &NewTopologyOperation,
    ) -> Result<TopologyOperationRecord> {
        validate_key_bytes(&input.operation_id, "topology operation id", 64)?;
        validate_key_bytes(&input.operation_kind, "topology operation kind", 64)?;
        validate_json_value(&input.detail_json, "operation detail")?;
        if input.progress_total.is_some_and(|total| total < 0) {
            bail!("operation progress total cannot be negative");
        }
        let (registry_id, cache_id) = input
            .surface
            .map(SurfaceTarget::ids)
            .unwrap_or((None, None));
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO topology_operations (operation_id, operation_kind,
                registry_id, cache_id, placement_id, state, progress_total,
                detail_json, created_at)
             SELECT ?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?8
             WHERE (?3 IS NULL OR EXISTS (SELECT 1 FROM registries WHERE id = ?3))
               AND (?4 IS NULL OR EXISTS (SELECT 1 FROM caches WHERE id = ?4))
               AND (?5 IS NULL OR EXISTS (SELECT 1 FROM surface_placements p
                    WHERE p.id = ?5 AND ((?3 IS NOT NULL AND p.registry_id = ?3)
                      OR (?4 IS NOT NULL AND p.cache_id = ?4))))",
                &vals![
                    input.operation_id,
                    input.operation_kind,
                    registry_id,
                    cache_id,
                    input.placement_id,
                    input.progress_total,
                    input.detail_json,
                    now
                ],
            )
            .await?;
        if affected != 1 {
            bail!("operation targets must exist and a placement must belong to its surface");
        }
        self.topology_operation(&input.operation_id)
            .await?
            .context("created topology operation disappeared")
    }

    /// Returns a topology operation by opaque id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn topology_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<TopologyOperationRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations WHERE operation_id = ?1"
                ),
                &vals![operation_id],
            )
            .await?;
        rows.first().map(row_to_topology_operation).transpose()
    }

    /// Lists operations for a surface, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_topology_operations(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<TopologyOperationRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend.query(&format!("SELECT {OPERATION_COLUMNS} FROM topology_operations WHERE registry_id = ?1 OR cache_id = ?2 ORDER BY created_at DESC, operation_id"), &vals![registry_id, cache_id]).await?.iter().map(row_to_topology_operation).collect()
    }

    /// Advances an operation with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state, malformed detail, a stale
    /// version, missing operation, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_topology_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        state: &str,
        progress_current: i64,
        progress_total: Option<i64>,
        detail_json: &str,
        error: Option<&str>,
        started_at: Option<i64>,
        finished_at: Option<i64>,
    ) -> Result<TopologyOperationRecord> {
        if !matches!(state, "running" | "succeeded" | "failed" | "cancelled") {
            bail!("invalid topology-operation state '{state}'");
        }
        validate_json_value(detail_json, "operation detail")?;
        if progress_current < 0 || progress_total.is_some_and(|total| total < progress_current) {
            bail!("operation progress must be non-negative and cannot exceed its total");
        }
        match state {
            "running" if started_at.is_none() || finished_at.is_some() || error.is_some() => {
                bail!("a running operation requires started_at and no finish/error")
            }
            "succeeded" if started_at.is_none() || finished_at.is_none() || error.is_some() => {
                bail!("a succeeded operation requires start/finish times and no error")
            }
            "failed" if started_at.is_none() || finished_at.is_none() || error.is_none() => {
                bail!("a failed operation requires start/finish times and an error")
            }
            "cancelled" if started_at.is_none() || finished_at.is_none() => {
                bail!("a cancelled operation requires start/finish times")
            }
            _ => {}
        }
        if finished_at
            .zip(started_at)
            .is_some_and(|(finish, start)| finish < start)
        {
            bail!("operation finish time cannot precede its start time");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE topology_operations SET state = ?3, progress_current = ?4,
                progress_total = COALESCE(?5, progress_total), detail_json = ?6, error = ?7,
                started_at = ?8, finished_at = ?9,
                resource_version = resource_version + 1
             WHERE operation_id = ?1 AND resource_version = ?2
               AND progress_current <= ?4
               AND (progress_total IS NULL OR ?5 IS NULL OR progress_total = ?5)
               AND (?3 <> 'succeeded' OR COALESCE(?5, progress_total) IS NULL
                    OR ?4 = COALESCE(?5, progress_total))
               AND ((state = 'pending' AND ?3 IN ('running', 'cancelled'))
                 OR (state = 'running' AND ?3 IN ('succeeded', 'failed', 'cancelled'))) ",
                &vals![
                    operation_id,
                    expected_version,
                    state,
                    progress_current,
                    progress_total,
                    detail_json,
                    error,
                    started_at,
                    finished_at
                ],
            )
            .await?;
        if affected != 1 {
            bail!("topology operation is missing or its resource version is stale");
        }
        self.topology_operation(operation_id)
            .await?
            .context("updated topology operation disappeared")
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
    pub async fn all_store_hashes(&self, registry_id: i64) -> Result<Vec<String>> {
        let rows = self
            .backend
            .query(
                "SELECT vp.store_path, vp.refs FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1",
                &vals![registry_id],
            )
            .await?;
        let mut hashes = std::collections::BTreeSet::new();
        for row in &rows {
            let store_path: String = row.get(0)?;
            let refs_json: String = row.get(1)?;
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
    pub async fn index_status(&self, registry_id: i64) -> Result<Option<IndexStatus>> {
        self.backend
            .query_opt(
                "SELECT state, error, last_indexed_commit, name, description, readme, indexed_at
                 FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading index status")?
            .map(|row| {
                Ok(IndexStatus {
                    state: row.get(0)?,
                    error: row.get(1)?,
                    last_indexed_commit: row.get(2)?,
                    name: row.get(3)?,
                    description: row.get(4)?,
                    readme: row.get(5)?,
                    indexed_at: row.get(6)?,
                })
            })
            .transpose()
    }

    /// List every package in a registry with its newest indexed version.
    ///
    /// Used by the registry home, the indexer's package count, and the
    /// `ListPackages` RPC. For the anonymous browse UI — whose request cost an
    /// attacker controls by indexing an arbitrarily large registry — prefer
    /// [`Database::list_packages_capped`], which bounds the rows loaded.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_packages(&self, registry_id: i64) -> Result<Vec<PackageRow>> {
        let (rows, _truncated) = self.query_package_rows(registry_id, None).await?;
        Ok(rows)
    }

    /// List a registry's packages for the browse UI, capped at `limit` rows.
    ///
    /// Identical in shape to [`Database::list_packages`] but applies a DB-side
    /// `LIMIT` so a pathologically large registry cannot force the hub to
    /// materialize an unbounded package set per anonymous page view. Returns
    /// the (name-ordered) rows and a `truncated` flag that is `true` when the
    /// registry holds more packages than `limit` — the handler surfaces this as
    /// a "showing first N of many" indicator. The rich client-side filter still
    /// operates over the capped set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_packages_capped(
        &self,
        registry_id: i64,
        limit: usize,
    ) -> Result<(Vec<PackageRow>, bool)> {
        self.query_package_rows(registry_id, Some(limit)).await
    }

    /// Single-query package listing shared by [`Database::list_packages`] and
    /// [`Database::list_packages_capped`].
    ///
    /// Joins each package to its newest version (`MAX(package_versions.id)`)
    /// and that version's platform artifacts in **one** round-trip — replacing
    /// the former per-package sub-query (an O(packages) N+1) with a single
    /// `LEFT JOIN`. Rows arrive ordered by package name then platform, so the
    /// per-package platform list and primary-platform closure size are folded
    /// in a single linear pass.
    ///
    /// When `limit` is `Some(n)`, the package set is bounded with a DB-side
    /// `LIMIT` over a name-ordered subquery; the returned flag is `true` when
    /// the registry actually holds more than `n` packages. With `None` every
    /// package is returned and the flag is always `false`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    async fn query_package_rows(
        &self,
        registry_id: i64,
        limit: Option<usize>,
    ) -> Result<(Vec<PackageRow>, bool)> {
        // Bound the *packages* (not the joined platform rows) so the LIMIT
        // selects whole packages: filter to a capped name-ordered subset of
        // package ids, then join in their newest version's platforms. One
        // extra row beyond the cap is requested to detect truncation without a
        // second COUNT query.
        let probe = limit.map(|n| n.saturating_add(1) as i64);
        let rows = match probe {
            Some(probe) => {
                self.backend
                    .query(
                        "SELECT p.id, p.name, p.description, p.license,
                        (SELECT v.version FROM package_versions v
                         WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1),
                        vp.platform, vp.closure_size
                 FROM (SELECT id, name, description, license
                       FROM packages
                       WHERE registry_id = ?1
                       ORDER BY name LIMIT ?2) p
                 LEFT JOIN version_platforms vp
                   ON vp.version_id = (SELECT MAX(v.id) FROM package_versions v
                                       WHERE v.package_id = p.id)
                 ORDER BY p.name, vp.platform",
                        &vals![registry_id, probe],
                    )
                    .await?
            }
            None => {
                self.backend
                    .query(
                        "SELECT p.id, p.name, p.description, p.license,
                        (SELECT v.version FROM package_versions v
                         WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1),
                        vp.platform, vp.closure_size
                 FROM packages p
                 LEFT JOIN version_platforms vp
                   ON vp.version_id = (SELECT MAX(v.id) FROM package_versions v
                                       WHERE v.package_id = p.id)
                 WHERE p.registry_id = ?1
                 ORDER BY p.name, vp.platform",
                        &vals![registry_id],
                    )
                    .await?
            }
        };

        // Fold the joined rows into one [`PackageRow`] per package, in the
        // name order the query guarantees. A package with no platform
        // artifacts appears as a single row with NULL platform/closure.
        let mut out: Vec<PackageRow> = Vec::new();
        let mut current_id: Option<i64> = None;
        for row in &rows {
            let package_id: i64 = row.get(0)?;
            if current_id != Some(package_id) {
                current_id = Some(package_id);
                out.push(PackageRow {
                    name: row.get(1)?,
                    description: row.get(2)?,
                    license: row.get(3)?,
                    latest_version: row.get(4)?,
                    closure_size: None,
                    platforms: Vec::new(),
                });
            }
            // `out` is non-empty: the first iteration always pushes (its id
            // cannot equal the sentinel `None`), and later iterations only skip
            // the push when the current package's row is already on top.
            if let Some(entry) = out.last_mut() {
                if let Some(platform) = row.get::<Option<String>>(5)? {
                    entry.platforms.push(platform);
                    if entry.closure_size.is_none() {
                        entry.closure_size = row.get::<Option<u64>>(6)?;
                    }
                }
            }
        }

        // The probe row (cap + 1th package) signals truncation; drop it so the
        // caller sees exactly `limit` packages.
        let truncated = match limit {
            Some(n) if out.len() > n => {
                out.truncate(n);
                true
            }
            _ => false,
        };
        Ok((out, truncated))
    }

    /// Load one package's full detail.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn package_detail(
        &self,
        registry_id: i64,
        name: &str,
    ) -> Result<Option<PackageDetail>> {
        let header = self
            .backend
            .query_opt(
                "SELECT id, name, description, homepage, license, maintainer, sysroot
             FROM packages WHERE registry_id = ?1 AND name = ?2",
                &vals![registry_id, name],
            )
            .await?;
        let Some(header) = header else {
            return Ok(None);
        };
        let package_id: i64 = header.get(0)?;
        let mut detail = PackageDetail {
            name: header.get(1)?,
            description: header.get(2)?,
            homepage: header.get(3)?,
            license: header.get(4)?,
            maintainer: header.get(5)?,
            sysroot: header.get(6)?,
            versions: Vec::new(),
        };

        let version_rows = self
            .backend
            .query(
                "SELECT id, version, previous FROM package_versions
             WHERE package_id = ?1 ORDER BY id DESC",
                &vals![package_id],
            )
            .await?;
        let versions = version_rows
            .iter()
            .map(|row| {
                Ok((
                    row.get::<i64>(0)?,
                    row.get::<String>(1)?,
                    row.get::<Option<String>>(2)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        for (version_id, version, previous) in versions {
            let platform_rows = self
                .backend
                .query(
                    "SELECT platform, store_path, nar_hash, nar_size, closure_size, refs, images,
                        source_drv
                 FROM version_platforms WHERE version_id = ?1 ORDER BY platform",
                    &vals![version_id],
                )
                .await?;
            let platforms = platform_rows
                .iter()
                .map(|row| {
                    // refs/images are index-written JSON; tolerate (skip) a
                    // malformed value the same way registry rows are read.
                    let refs_json: String = row.get(5)?;
                    let images_json: String = row.get(6)?;
                    Ok(PlatformDetail {
                        platform: row.get(0)?,
                        store_path: row.get(1)?,
                        nar_hash: row.get(2)?,
                        nar_size: row.get(3)?,
                        closure_size: row.get(4)?,
                        source_drv: row.get(7)?,
                        refs: serde_json::from_str(&refs_json).unwrap_or_default(),
                        images: serde_json::from_str(&images_json).unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            detail.versions.push(VersionDetail {
                version,
                previous,
                platforms,
            });
        }
        Ok(Some(detail))
    }

    /// Build the registry's store-hash → (package name, version) index.
    ///
    /// Loads every `version_platforms` row once and maps the store-path hash
    /// prefix (the basename text before the first `-`) to the owning package's
    /// name and version. When two artifacts share a hash prefix the first
    /// `ORDER BY` winner is kept; the platform triple is dropped because a
    /// dependency edge points at a store path, not a platform.
    ///
    /// This is the dialect-safe primitive the closure-browser reads:
    /// [`resolve_reference_names`](Self::resolve_reference_names) and
    /// [`reverse_dependencies`](Self::reverse_dependencies) both resolve in
    /// Rust against this map rather than relying on backend JSON functions.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    async fn store_hash_index(
        &self,
        registry_id: i64,
    ) -> Result<std::collections::HashMap<String, (String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT vp.store_path, p.name, pv.version
             FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1
             ORDER BY p.name, pv.id DESC",
                &vals![registry_id],
            )
            .await?;
        let mut index = std::collections::HashMap::new();
        for row in &rows {
            let store_path: String = row.get(0)?;
            let name: String = row.get(1)?;
            let version: String = row.get(2)?;
            let basename = store_path.rsplit('/').next().unwrap_or(&store_path);
            if let Some((hash, _)) = basename.split_once('-') {
                index.entry(hash.to_string()).or_insert((name, version));
            }
        }
        Ok(index)
    }

    /// Resolve store-hash prefixes to the packages that publish them.
    ///
    /// For each hash in `hashes`, returns `(hash, name, version)` where `name`
    /// and `version` are `Some` when some package in `registry_id` publishes an
    /// artifact whose store-path hash prefix equals that hash, and `None` when
    /// the hash belongs to a store path outside this registry's package set
    /// (e.g. a stdenv closure dependency). Output order matches `hashes`.
    ///
    /// This turns the opaque `refs` closure-edge list on the package page into
    /// a legible dependency list: resolvable hashes link to their package page,
    /// unresolvable ones fall back to their narinfo permalink. Resolution runs
    /// in Rust against `store_hash_index`, so it is
    /// independent of the backend's JSON-function dialect.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn resolve_reference_names(
        &self,
        registry_id: i64,
        hashes: &[String],
    ) -> Result<Vec<ResolvedReference>> {
        let index = self.store_hash_index(registry_id).await?;
        Ok(hashes
            .iter()
            .map(|hash| match index.get(hash) {
                Some((name, version)) => (hash.clone(), Some(name.clone()), Some(version.clone())),
                None => (hash.clone(), None, None),
            })
            .collect())
    }

    /// Find the packages whose runtime closure references `store_hash`.
    ///
    /// Returns `(name, version)` for every artifact in `registry_id` whose
    /// `refs` JSON array contains `store_hash` — the reverse of the dependency
    /// edge, i.e. "required by". Results are de-duplicated by package name
    /// (keeping the newest version seen) and sorted by name, so a package that
    /// depends on the target across several versions appears once.
    ///
    /// The `refs` column is index-written JSON; rows whose value does not parse
    /// as a string array are skipped, matching how the rest of the index reads
    /// tolerate malformed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn reverse_dependencies(
        &self,
        registry_id: i64,
        store_hash: &str,
    ) -> Result<Vec<(String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT p.name, pv.version, vp.refs
             FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1
             ORDER BY p.name, pv.id DESC",
                &vals![registry_id],
            )
            .await?;
        // De-duplicate by name, keeping the first (newest, by the ORDER BY)
        // version that references the target hash.
        let mut seen = std::collections::BTreeMap::new();
        for row in &rows {
            let name: String = row.get(0)?;
            let version: String = row.get(1)?;
            let refs_json: String = row.get(2)?;
            let refs: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
            if refs.iter().any(|r| r == store_hash) {
                seen.entry(name).or_insert(version);
            }
        }
        Ok(seen.into_iter().collect())
    }

    /// The store-path hash of a package's latest version on a chosen platform.
    ///
    /// Returns the basename hash prefix (text before the first `-`) of the
    /// newest version's artifact, preferring the given `platform` and otherwise
    /// falling back to whichever platform sorts first. Returns `None` when the
    /// package has no versions, no platform artifacts, or a store path with no
    /// extractable hash. This is the key used to look up the package's
    /// "required by" set via [`reverse_dependencies`](Self::reverse_dependencies).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn primary_store_hash(
        &self,
        registry_id: i64,
        name: &str,
        platform: &str,
    ) -> Result<Option<String>> {
        let rows = self
            .backend
            .query(
                "SELECT vp.platform, vp.store_path
             FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1 AND p.name = ?2
               AND pv.id = (SELECT MAX(v.id) FROM package_versions v
                            WHERE v.package_id = p.id)
             ORDER BY vp.platform",
                &vals![registry_id, name],
            )
            .await?;
        let mut fallback: Option<String> = None;
        for row in &rows {
            let row_platform: String = row.get(0)?;
            let store_path: String = row.get(1)?;
            let basename = store_path.rsplit('/').next().unwrap_or(&store_path);
            let Some((hash, _)) = basename.split_once('-') else {
                continue;
            };
            if row_platform == platform {
                return Ok(Some(hash.to_string()));
            }
            fallback.get_or_insert_with(|| hash.to_string());
        }
        Ok(fallback)
    }

    /// List channels with their full partition maps.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_channels(&self, registry_id: i64) -> Result<Vec<ChannelSummary>> {
        let channel_rows = self
            .backend
            .query(
                "SELECT id, name, frontier FROM channels
                 WHERE registry_id = ?1 AND active = 1 ORDER BY name",
                &vals![registry_id],
            )
            .await?;
        let channels = channel_rows
            .iter()
            .map(|row| {
                Ok((
                    row.get::<i64>(0)?,
                    row.get::<String>(1)?,
                    row.get::<Option<String>>(2)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut out = Vec::with_capacity(channels.len());
        for (channel_id, name, frontier) in channels {
            let mut partitions = vec![None; 256];
            let rows = self
                .backend
                .query(
                    "SELECT bucket, release FROM channel_partitions WHERE channel_id = ?1",
                    &vals![channel_id],
                )
                .await?;
            for row in &rows {
                let bucket: i64 = row.get(0)?;
                let release: String = row.get(1)?;
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
    /// Naturally bounded: the indexer writes at most
    /// the hub's `indexer::MAX_SEMVER_TAGS` (1024) release rows
    /// per registry, so the result set cannot grow without bound and needs no
    /// additional DB-side `LIMIT`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_releases(&self, registry_id: i64) -> Result<Vec<ReleaseRow>> {
        let rows = self
            .backend
            .query(
                "SELECT semver, tag_oid, commit_oid, signer, tagged_at, pack_present
             FROM releases WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ReleaseRow {
                    semver: row.get(0)?,
                    tag_oid: row.get(1)?,
                    commit_oid: row.get(2)?,
                    signer: row.get(3)?,
                    tagged_at: row.get(4)?,
                    pack_present: row.get(5)?,
                })
            })
            .collect()
    }

    /// The `info/refs` digest the current index was built from, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn refs_digest(&self, registry_id: i64) -> Result<Option<String>> {
        let digest: Option<Option<String>> = self
            .backend
            .query_opt(
                "SELECT refs_digest FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading refs digest")?
            .map(|row| row.get::<Option<String>>(0))
            .transpose()?;
        Ok(digest.flatten())
    }

    /// The roster as `(key_id, public_key, status)` rows.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_roster(&self, registry_id: i64) -> Result<Vec<(String, String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT key_id, public_key, status FROM key_rosters
             WHERE registry_id = ?1 ORDER BY status, key_id",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .collect()
    }

    /// Committed `[caches]` entries as `(url, priority)`, highest first.
    ///
    /// These are the cache *endpoints a registry advertises* to consumers (the
    /// flattened cache stack), not the hub's managed [`Cache`] objects — see
    /// [`Database::list_caches`] for the latter. Stored in `advertised_caches`
    /// (renamed from `caches` in v22 when the managed-cache table took that name)
    /// and rebuilt from the committed `registry.toml` on every index.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_advertised_caches(&self, registry_id: i64) -> Result<Vec<(String, u32)>> {
        let rows = self
            .backend
            .query(
                "SELECT url, priority FROM advertised_caches WHERE registry_id = ?1 ORDER BY priority DESC",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get::<u32>(1)?)))
            .collect()
    }

    /// The committed cache-stack expression for a registry, parsed.
    ///
    /// Returns the stored stack ([`crate::stack::StackNode`]) when the
    /// registry's committed `registry.toml` carried a `[caches]` table in stack
    /// form at index time, or `None` when its `[caches]` is a legacy flat list.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or when the stored stack JSON
    /// fails to parse (an internal-consistency error — the indexer only ever
    /// stores well-formed JSON).
    pub async fn registry_cache_stack(
        &self,
        registry_id: i64,
    ) -> Result<Option<crate::stack::StackNode>> {
        let json: Option<String> = self
            .backend
            .query_opt(
                "SELECT cache_stack FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading registry cache stack")?
            .map(|row| row.get::<Option<String>>(0))
            .transpose()?
            .flatten();
        match json {
            Some(json) => Ok(Some(crate::stack::StackNode::from_json(&json)?)),
            None => Ok(None),
        }
    }

    // -- tenancy: orgs and projects -----------------------------------------

    /// Create an organization; returns its new id.
    ///
    /// The `slug` is validated against the canonical single-segment ruleset
    /// ([`crate::domain::iam::validate_org_slug`]) as a persistence-layer
    /// backstop: an org slug is a single URL/scope path segment, so it may
    /// not contain `/` or any out-of-charset character. This prevents any
    /// caller — RPC, console, or CLI — from writing a slug that
    /// [`crate::domain::Scope::parse`] would later normalize into an
    /// unintended ancestor scope (sec CR-2).
    ///
    /// # Errors
    ///
    /// Returns an error when `slug` fails validation, and on database
    /// failure, including a unique-constraint violation when `slug` is
    /// already taken.
    pub async fn create_org(&self, slug: &str, name: &str) -> Result<i64> {
        crate::domain::iam::validate_org_slug(slug)
            .map_err(|e| anyhow::anyhow!("invalid org slug '{slug}': {e}"))?;
        self.backend
            .execute_insert(
                "INSERT INTO orgs (slug, name, created_at) VALUES (?1, ?2, ?3)",
                &vals![slug, name, unix_now()],
            )
            .await
    }

    /// Look up an active organization by slug.
    ///
    /// Soft-deleted orgs (those with `deleted_at` set) are **excluded** so a
    /// tombstoned org stops resolving on every serving path. Use
    /// [`Database::org_by_slug_including_deleted`] for the admin/restore path
    /// that must still see them during the grace window.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_slug(&self, slug: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, slug, name, created_at FROM orgs
                 WHERE slug = ?1 AND deleted_at IS NULL",
                &vals![slug],
            )
            .await
            .context("loading org by slug")?
            .map(|row| row_to_org(&row))
            .transpose()
    }

    /// Look up an organization by slug, *including* soft-deleted ones.
    ///
    /// The admin-visible variant of [`Database::org_by_slug`]: it resolves an
    /// org even after it has been soft-deleted, so the restore and export
    /// paths can act on it during its grace window.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_slug_including_deleted(&self, slug: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, slug, name, created_at FROM orgs WHERE slug = ?1",
                &vals![slug],
            )
            .await
            .context("loading org by slug (incl. deleted)")?
            .map(|row| row_to_org(&row))
            .transpose()
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
    pub async fn create_project(&self, org_id: i64, path: &str, name: &str) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO projects (org_id, path, name, created_at) VALUES (?1, ?2, ?3, ?4)",
                &vals![org_id, path, name, unix_now()],
            )
            .await
    }

    /// List an org's projects, ordered by materialized path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_projects(&self, org_id: i64) -> Result<Vec<ProjectRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, path, name, created_at FROM projects
             WHERE org_id = ?1 ORDER BY path",
                &vals![org_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ProjectRecord {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    path: row.get(2)?,
                    name: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .collect()
    }

    /// Delete a project by id, scoped to its org; returns whether a row was
    /// removed. The caller must ensure no registry still references the
    /// project path (see [`RegistryRecord::project_path`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_project(&self, org_id: i64, project_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM projects WHERE id = ?1 AND org_id = ?2",
                &vals![project_id, org_id],
            )
            .await?;
        Ok(n > 0)
    }

    // -- tenancy: principals -------------------------------------------------

    /// Create a user; returns the new user id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `email` is already registered.
    pub async fn create_user(&self, email: &str, display_name: Option<&str>) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO users (email, display_name, created_at) VALUES (?1, ?2, ?3)",
                &vals![email, display_name, unix_now()],
            )
            .await
    }

    /// Look up a non-deleted user's id by email.
    ///
    /// Soft-deleted users (those with `deleted_at` set) are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_by_email(&self, email: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT id FROM users WHERE email = ?1 AND deleted_at IS NULL",
                &vals![email],
            )
            .await
            .context("loading user by email")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Look up a non-deleted user's email by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_email(&self, user_id: i64) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT email FROM users WHERE id = ?1 AND deleted_at IS NULL",
                &vals![user_id],
            )
            .await
            .context("loading user email by id")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Find a user by email, creating one if absent; returns the user id.
    ///
    /// The human-login path: a magic link or an invitation accepts an email
    /// and needs the user row whether or not it already exists. The lookup
    /// and insert run under one connection lock, so two concurrent first
    /// sign-ins for the same address resolve to one row (the second insert
    /// hits the `UNIQUE(email)` constraint and falls back to the lookup).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn find_or_create_user(&self, email: &str) -> Result<i64> {
        if let Some(id) = self.user_by_email(email).await? {
            return Ok(id);
        }
        self.backend
            .execute(
                "INSERT INTO users (email, display_name, created_at) VALUES (?1, NULL, ?2)
             ON CONFLICT(email) DO NOTHING",
                &vals![email, unix_now()],
            )
            .await?;
        self.backend
            .query_opt("SELECT id FROM users WHERE email = ?1", &vals![email])
            .await?
            .context("resolving user id after insert")?
            .get(0)
    }

    // -- auth: passwords (migration v18) -------------------------------------

    /// Set (or replace) a user's password hash.
    ///
    /// `password_hash` is an Argon2id PHC string from
    /// [`crate::auth::password::hash_password`] — never a plaintext password.
    /// Overwriting an existing hash is how a password change is recorded; a
    /// later `NULL` (not exposed here) would clear it. Targets only a
    /// non-deleted user.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_user_password(&self, user_id: i64, password_hash: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE users SET password_hash = ?2 WHERE id = ?1 AND deleted_at IS NULL",
                &vals![user_id, password_hash],
            )
            .await?;
        Ok(())
    }

    /// Look up a user's id and stored password hash by email, for login.
    ///
    /// Returns `Ok(Some((user_id, phc)))` only when a non-deleted user exists
    /// for `email` **and** has a password set; returns `Ok(None)` when no such
    /// user exists *or* the user has no password (`password_hash IS NULL`).
    /// The caller verifies `phc` with
    /// [`crate::auth::password::verify_password`] and must surface the same
    /// generic "invalid email or password" outcome for both the `None` and the
    /// wrong-password cases, so the password login path never reveals whether
    /// an email is registered.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_for_password(&self, email: &str) -> Result<Option<(i64, String)>> {
        let row = self
            .backend
            .query_opt(
                "SELECT id, password_hash FROM users
                 WHERE email = ?1 AND deleted_at IS NULL AND password_hash IS NOT NULL",
                &vals![email],
            )
            .await
            .context("loading user for password login")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let user_id: i64 = row.get(0)?;
        let hash: String = row.get(1)?;
        Ok(Some((user_id, hash)))
    }

    /// Report whether a non-deleted user has a password set.
    ///
    /// Used by the account page to show whether a password is currently
    /// configured. Returns `Ok(false)` for an unknown or soft-deleted user, or
    /// a user whose `password_hash IS NULL`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_has_password(&self, user_id: i64) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT 1 FROM users
                 WHERE id = ?1 AND deleted_at IS NULL AND password_hash IS NOT NULL",
                &vals![user_id],
            )
            .await
            .context("checking whether user has a password")?;
        Ok(row.is_some())
    }

    /// The requested scope and permissions of a live, unresolved device
    /// grant, looked up by its `user_code`.
    ///
    /// Returns `Ok(None)` when the code is unknown, already approved or
    /// denied, or expired — the same fail-closed shape as approval. Used by
    /// the `/activate` page to show what the CLI is asking for before the
    /// human approves. Permissions come back as their wire-name strings.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn pending_device_request(
        &self,
        user_code: &str,
    ) -> Result<Option<(String, Vec<String>)>> {
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT scope, permissions FROM device_codes
                 WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
                   AND expires_at > ?2",
                &vals![user_code, now],
            )
            .await
            .context("loading pending device request")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let scope: String = row.get(0)?;
        let perms_json: String = row.get(1)?;
        let perms: Vec<String> = serde_json::from_str(&perms_json).unwrap_or_default();
        Ok(Some((scope, perms)))
    }

    /// Create a service account under an org; returns the new id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `(org_id, name)` already exists.
    pub async fn create_service_account(&self, org_id: i64, name: &str) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO service_accounts (org_id, name, created_at) VALUES (?1, ?2, ?3)",
                &vals![org_id, name, unix_now()],
            )
            .await
    }

    /// Look up a service account's id by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn service_account_by_name(&self, org_id: i64, name: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT id FROM service_accounts WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
            .await
            .context("loading service account by name")?
            .map(|row| row.get(0))
            .transpose()
    }

    // -- tenancy: memberships ------------------------------------------------

    /// Grant (or update) a principal's role at a scope.
    ///
    /// A principal has at most one role per scope; re-granting the same
    /// `(principal_kind, principal_id, scope)` overwrites the role. The
    /// `scope` and `role` strings are the wire forms produced by
    /// [`crate::domain::Scope::as_str`] and [`crate::domain::Role::as_str`].
    ///
    /// As a persistence-layer backstop (sec CR-2), `scope` is required to be
    /// in canonical form ([`crate::domain::Scope::is_canonical`]): a
    /// non-canonical scope such as `"/"`, `"/victimorg"`, `"foo/"`, or
    /// `"foo//bar"` is rejected, because [`crate::domain::Scope::parse`] would
    /// normalize it into a *different*, broader scope than its literal text —
    /// the exact surprise that lets a caller smuggle an instance-root or
    /// victim-org grant. Legitimately formed scopes round-trip and are
    /// accepted: the instance root `""`, an org `"acme"`, and a multi-segment
    /// registry scope `"acme/cdn"` all pass.
    ///
    /// # Errors
    ///
    /// Returns an error when `scope` is not in canonical form, and on
    /// database failure.
    pub async fn grant_membership(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
        role: &str,
    ) -> Result<()> {
        if !crate::domain::Scope::is_canonical(scope) {
            bail!("refusing to grant membership at non-canonical scope '{scope}'");
        }
        self.backend
            .execute(
                "INSERT INTO memberships
             (principal_kind, principal_id, scope, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(principal_kind, principal_id, scope)
             DO UPDATE SET role = excluded.role",
                &vals![principal_kind, principal_id, scope, role, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Creates (or updates) the instance root admin: a user with `email` and
    /// `plaintext` password, granted [`Role::Owner`](crate::domain::Role::Owner)
    /// at the instance-root scope (`""`).
    ///
    /// Single source of truth for root bootstrap, shared by the native CLI
    /// (`aos-hub init`/`worker install`) and the worker's seal-gated
    /// `HubDb` bootstrap endpoint (RFC-0004 ch.14 Phase E), so both shells create
    /// an identical root. Idempotent: re-running resets the password and
    /// re-asserts the grant. Returns the normalized email and the user id.
    ///
    /// # Errors
    ///
    /// Returns an error if `plaintext` is empty, password hashing fails, or any
    /// database operation fails.
    pub async fn bootstrap_root(&self, email: &str, plaintext: &str) -> Result<(String, i64)> {
        let email = email.trim().to_lowercase();
        if plaintext.is_empty() {
            bail!("password must not be empty");
        }
        let user_id = self.find_or_create_user(&email).await?;
        let hash = crate::auth::password::hash_password(plaintext)?;
        self.set_user_password(user_id, &hash).await?;
        // `Role::Owner` at root (`""`) carries `Permission::IamAdmin`, making this
        // a true instance administrator (can create orgs, administer the whole
        // instance) rather than a login-only account under invite-only signup.
        self.grant_membership("user", user_id, "", crate::domain::Role::Owner.as_str())
            .await?;
        Ok((email, user_id))
    }

    /// Revoke a principal's grant at a scope.
    ///
    /// A no-op when no such grant exists.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_membership(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "DELETE FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 AND scope = ?3",
                &vals![principal_kind, principal_id, scope],
            )
            .await?;
        Ok(())
    }

    /// Revoke a principal's grant at a scope, refusing to orphan the org.
    ///
    /// Performs the read of the surviving owner count **and** the revoke
    /// inside one transaction, so a naive check-then-act race (two concurrent
    /// "remove owner A" / "remove owner B" both snapshotting two owners and
    /// both applying) can no longer leave the scope with zero owners. After
    /// the delete, the owners remaining at `scope` are re-counted *inside the
    /// same transaction*: when the revoked principal had held `owner` and the
    /// delete would drop the owner count to zero, the transaction is rolled
    /// back with a [`LastOwnerError`] and no change is made.
    ///
    /// The guard fires only when at least one owner existed before the write
    /// (a scope that legitimately has no owners — e.g. a non-org scope — is
    /// never forced to acquire one). Otherwise this behaves like
    /// [`Database::revoke_membership`].
    ///
    /// # Errors
    ///
    /// Returns a [`LastOwnerError`] (classifiable via
    /// [`is_last_owner_error`]) when the revoke would leave the scope without
    /// an owner, or an error on database failure.
    pub async fn revoke_membership_owner_safe(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<()> {
        // Classify, then act: a revoke orphans the org only when the target is
        // the scope's sole *user* owner. Read that fact, refuse if so, else
        // delete. Replaces the count-write-recount interactive transaction with
        // a single read + single write, so it runs on every backend including
        // D1 (no interactive transaction). The delete is idempotent when the
        // membership is absent.
        let (owners, target_is_owner) = self
            .owner_membership_state(principal_kind, principal_id, scope)
            .await?;
        if target_is_owner && owners <= 1 {
            return Err(anyhow::Error::new(LastOwnerError(scope.to_string())));
        }
        self.backend
            .execute(
                "DELETE FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 AND scope = ?3",
                &vals![principal_kind, principal_id, scope],
            )
            .await?;
        Ok(())
    }

    /// Owner-safety state for a principal at `scope`: `(user_owner_count,
    /// target_is_user_owner)`.
    ///
    /// The count considers only `user` principals with the `owner` role (the
    /// rule that an org must retain a human owner); `target_is_user_owner` is
    /// true only when the principal is a `user` *and* currently an owner there,
    /// so revoking or demoting a non-user or non-owner never trips the guard.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    async fn owner_membership_state(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
    ) -> Result<(i64, bool)> {
        let row = self
            .backend
            .query_opt(
                "SELECT
                   (SELECT COUNT(*) FROM memberships
                      WHERE scope = ?1 AND principal_kind = 'user' AND role = 'owner'),
                   EXISTS(SELECT 1 FROM memberships
                      WHERE scope = ?1 AND principal_kind = ?2 AND principal_id = ?3
                        AND role = 'owner')",
                &vals![scope, principal_kind, principal_id],
            )
            .await?
            .context("owner-state query returned no row")?;
        let owners: i64 = row.get(0)?;
        let target_owner: i64 = row.get(1)?;
        Ok((owners, principal_kind == "user" && target_owner == 1))
    }

    /// Set a principal's role at a scope, refusing to orphan the org.
    ///
    /// The owner-safe counterpart of [`Database::grant_membership`] for
    /// **role changes**: it upserts the role and then re-counts the owners
    /// surviving at `scope` *inside the same transaction*. When the change
    /// demotes the sole remaining owner — dropping the owner count to zero
    /// where it had been positive — the transaction is rolled back with a
    /// [`LastOwnerError`] and no change is made, closing the check-then-act
    /// race that two concurrent demotes would otherwise win.
    ///
    /// The scope must be canonical (same precondition as
    /// [`Database::grant_membership`]).
    ///
    /// # Errors
    ///
    /// Returns a [`LastOwnerError`] (classifiable via
    /// [`is_last_owner_error`]) when the change would leave the scope without
    /// an owner, or an error on database failure or a non-canonical scope.
    pub async fn set_membership_role_owner_safe(
        &self,
        principal_kind: &str,
        principal_id: i64,
        scope: &str,
        role: &str,
    ) -> Result<()> {
        if !crate::domain::Scope::is_canonical(scope) {
            bail!("refusing to grant membership at non-canonical scope '{scope}'");
        }
        let now = unix_now();
        // A role change orphans the org only when it demotes the scope's sole
        // user owner (to a non-owner role). Classify, refuse if so, else upsert
        // — a single read + single write in place of the count-write-recount
        // transaction, so it runs on D1 too. Promotions and changes to a
        // non-owner or non-sole owner never trip the guard.
        if role != "owner" {
            let (owners, target_is_owner) = self
                .owner_membership_state(principal_kind, principal_id, scope)
                .await?;
            if target_is_owner && owners <= 1 {
                return Err(anyhow::Error::new(LastOwnerError(scope.to_string())));
            }
        }
        self.backend
            .execute(
                "INSERT INTO memberships
             (principal_kind, principal_id, scope, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(principal_kind, principal_id, scope)
             DO UPDATE SET role = excluded.role",
                &vals![principal_kind, principal_id, scope, role, now],
            )
            .await?;
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
    pub async fn list_memberships_for(
        &self,
        principal_kind: &str,
        principal_id: i64,
    ) -> Result<Vec<(String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT scope, role FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 ORDER BY scope",
                &vals![principal_kind, principal_id],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?)))
            .collect()
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
    pub async fn list_members_of_scope(&self, scope: &str) -> Result<Vec<(String, i64, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT principal_kind, principal_id, role FROM memberships
             WHERE scope = ?1 ORDER BY principal_kind, principal_id",
                &vals![scope],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .collect()
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
    pub async fn effective_scopes(
        &self,
        principal: crate::domain::Principal,
    ) -> Result<Vec<(crate::domain::Scope, crate::domain::Role)>> {
        let rows = self
            .list_memberships_for(principal.kind.as_str(), principal.id)
            .await?;
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
    pub async fn set_registry_ownership(
        &self,
        registry_id: i64,
        org_id: Option<i64>,
        project_path: &str,
        visibility: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE registries
             SET org_id = ?2, project_path = ?3, visibility = ?4
             WHERE id = ?1",
                &vals![registry_id, org_id, project_path, visibility],
            )
            .await?;
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
    pub async fn registry_by_scope(
        &self,
        org_slug: &str,
        project_path: &str,
        name: &str,
    ) -> Result<Option<RegistryRecord>> {
        self.registry_by_slug(&canonical_slug(org_slug, project_path, name))
            .await
    }

    /// Create a managed (org-owned, storage-bound) registry; returns its id.
    ///
    /// The registry is stored with its full canonical path
    /// (`{org}/{project_path}/{name}`) as its slug, an empty `source_url`
    /// (its surface is located via the binding or the deployment default
    /// storage), and the given ownership, storage binding, prefix, and trust
    /// configuration. Canonical uniqueness is enforced both by the up-front
    /// [`Database::registry_by_scope`] check and by the underlying
    /// `UNIQUE(slug)` constraint.
    ///
    /// `binding_id` is optional: `None` means the registry roots on the
    /// deployment's default storage (the single R2 bucket on the Worker, or
    /// the configured [`Database::default_storage_root`] on the native hub),
    /// addressed purely by its `prefix`.
    ///
    /// When `prefix` is empty it is auto-derived from the registry's slug —
    /// the canonical path that already uniquely identifies the registry — so
    /// a zero-config create still gets a stable, unique storage prefix. The
    /// derived prefix may contain `/` (the slug's path separators); that is a
    /// valid R2/filesystem key prefix. A non-empty `prefix` must be unique
    /// across all other registries, since two registries sharing a prefix
    /// would read and write the same surface objects.
    ///
    /// # Errors
    ///
    /// Returns an error when a registry already exists at the canonical
    /// path, when the effective `prefix` is already used by another registry,
    /// when `prefix` contains a path-traversal component (`..`, an absolute
    /// segment), or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_managed_registry(
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
        let org_slug = self
            .org_by_id(org_id)
            .await?
            .with_context(|| format!("no org with id {org_id}"))?
            .slug;
        let slug = canonical_slug(&org_slug, project_path, name);
        // An empty prefix auto-derives from the slug — the registry's unique
        // canonical identity — so a zero-config create still lands on a stable,
        // collision-free storage prefix. The slug's `/` separators are valid
        // path components and are kept verbatim.
        let prefix = if prefix.is_empty() {
            slug.as_str()
        } else {
            prefix
        };
        // Defense in depth: the per-file upload tail is already constrained
        // by `safe_join`, but a `..` in the binding prefix would relocate
        // the whole surface root, so reject it at creation. A derived prefix
        // (the slug) is always a clean relative path, so this only ever
        // rejects a caller-supplied prefix.
        {
            let rel = std::path::Path::new(prefix);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                bail!("registry prefix '{prefix}' must be a relative path with no '..' components");
            }
        }
        if self.registry_by_slug(&slug).await?.is_some() {
            bail!("a registry already exists at '{slug}'");
        }
        // Two registries sharing a storage prefix would read and write the same
        // surface objects, so reject a collision. A SELECT-count over the
        // low-volume admin path is sufficient (no concurrent-create race window
        // worth a unique index here, since slug uniqueness already serializes
        // the common case and the default prefix equals the unique slug).
        let prefix_uses: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM registries WHERE prefix = ?1",
                &vals![prefix],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()?
            .unwrap_or(0);
        if prefix_uses > 0 {
            bail!("a registry already uses storage prefix '{prefix}'");
        }
        // Slugs are unique across registries and caches (shared facade namespace).
        if self.cache_by_slug(&slug).await?.is_some() {
            bail!("a cache already exists at '{slug}' (slugs are unique across registries and caches)");
        }
        // Per-org registry-count quota (NULL/unset = unlimited).
        if let Some(max_registries) = self.org_quota(org_id).await?.max_registries {
            if self.org_registry_count(org_id).await? >= max_registries {
                bail!("org registry quota of {max_registries} reached");
            }
        }
        let id = self
            .backend
            .execute_insert(
                "INSERT INTO registries
             (slug, source_url, trust_keys, require_signatures, created_at,
              org_id, project_path, visibility, storage_binding_id, prefix)
             VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &vals![
                    slug,
                    serde_json::to_string(trust_keys)?,
                    require_signatures,
                    unix_now(),
                    org_id,
                    project_path,
                    visibility,
                    binding_id,
                    prefix,
                ],
            )
            .await?;
        // A freshly-created registry has nothing published yet, so it starts in
        // the terminal `empty` state — not `indexing` (which reads as work in
        // progress). The indexer's transient-error guard protects this state, so
        // a flaky `info/refs` read can't bump an empty registry to `pending`; the
        // first successful surface read after a publish moves it to `fresh`.
        self.backend
            .execute(
                "INSERT INTO registry_index (registry_id, state)
             VALUES (?1, 'empty')
             ON CONFLICT(registry_id) DO NOTHING",
                &vals![id],
            )
            .await?;
        Ok(id)
    }

    /// Delete a registry row, cascading its rebuildable index.
    ///
    /// Removes the `registries` row by id; the index tables
    /// (`registry_index`, `packages`, `channels`, the roster, validation runs,
    /// …) all carry `ON DELETE CASCADE` foreign keys on `registries(id)`, so
    /// they are removed in the same statement. This is the registry analog of
    /// the org [`Database::hard_purge_org`] hard delete.
    ///
    /// This does **not** delete the registry's surface content on the storage
    /// binding's backend (the `{root}/{prefix}` directory): that content lives
    /// outside SQL and is left in place, so the same surface can be re-bound by
    /// a new managed registry later. Returns `Ok(false)` when no registry has
    /// the given id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_registry(&self, registry_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute("DELETE FROM registries WHERE id = ?1", &vals![registry_id])
            .await?;
        Ok(n > 0)
    }

    // -- managed caches ------------------------------------------------------

    /// Create a managed cache; returns its new id.
    ///
    /// `org_id` is `None` for an instance-level standalone cache.
    /// `storage_binding_id` is `None` to use the deployment's **default
    /// storage** (the binding-less path, exactly as for a registry): an empty
    /// `prefix` then defaults to the `slug`, so the cache's surface is isolated
    /// under `<default storage>/<slug>`. With a binding, an empty `prefix` roots
    /// the surface directly at the binding root. The `prefix` is validated like a
    /// registry prefix (relative, no `..`). Fails if a cache already exists at
    /// `slug`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe prefix, a duplicate slug, or database
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_cache(
        &self,
        org_id: Option<i64>,
        slug: &str,
        name: &str,
        storage_binding_id: Option<i64>,
        prefix: &str,
        hosted_key_id: Option<i64>,
        visibility: &str,
        priority: i64,
        compression: &str,
        want_mass_query: bool,
    ) -> Result<i64> {
        // A binding-less (default-storage) cache isolates within the shared
        // deployment bucket by its slug when no explicit prefix is given —
        // mirroring `create_managed_registry`'s slug-derived prefix.
        let derived_prefix;
        let prefix = if !prefix.is_empty() {
            prefix
        } else if storage_binding_id.is_none() {
            derived_prefix = slug.to_string();
            &derived_prefix
        } else {
            prefix
        };
        if !prefix.is_empty() {
            let rel = std::path::Path::new(prefix);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                bail!("cache prefix '{prefix}' must be a relative path with no '..' components");
            }
        }
        if self.cache_by_slug(slug).await?.is_some() {
            bail!("a cache already exists at '{slug}'");
        }
        // Slugs are unique *across* registries and caches: the facade serves both
        // from one `/{slug}/…` namespace, so a shared slug would route reads and
        // writes to different objects.
        if self.registry_by_slug(slug).await?.is_some() {
            bail!("a registry already exists at '{slug}' (slugs are unique across registries and caches)");
        }
        self.backend
            .execute_insert(
                "INSERT INTO caches
                 (org_id, slug, name, storage_binding_id, prefix, hosted_key_id,
                  visibility, priority, compression, want_mass_query, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                &vals![
                    org_id,
                    slug,
                    name,
                    storage_binding_id,
                    prefix,
                    hosted_key_id,
                    visibility,
                    priority,
                    compression,
                    want_mass_query,
                    unix_now()
                ],
            )
            .await
    }

    /// Look up a cache by its URL slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_by_slug(&self, slug: &str) -> Result<Option<Cache>> {
        self.backend
            .query_opt(
                &format!("SELECT {CACHE_COLUMNS} FROM caches WHERE slug = ?1"),
                &vals![slug],
            )
            .await
            .context("loading cache by slug")?
            .map(|row| row_to_cache(&row))
            .transpose()
    }

    /// Look up a cache by its database id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_by_id(&self, id: i64) -> Result<Option<Cache>> {
        self.backend
            .query_opt(
                &format!("SELECT {CACHE_COLUMNS} FROM caches WHERE id = ?1"),
                &vals![id],
            )
            .await
            .context("loading cache by id")?
            .map(|row| row_to_cache(&row))
            .transpose()
    }

    /// List all servable caches.
    ///
    /// Excludes soft-deleted caches and caches owned by a soft-deleted org (the
    /// registry-parallel of [`Database::list_registries`]); instance-level
    /// caches (`org_id IS NULL`) always pass.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_caches(&self) -> Result<Vec<Cache>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {CACHE_COLUMNS} FROM caches c
                     WHERE c.deleted_at IS NULL
                       AND (c.org_id IS NULL
                            OR NOT EXISTS (
                                SELECT 1 FROM orgs o
                                WHERE o.id = c.org_id AND o.deleted_at IS NOT NULL))
                     ORDER BY c.slug"
                ),
                &[],
            )
            .await?;
        rows.iter().map(row_to_cache).collect()
    }

    /// List the caches owned by one org, ordered by slug (admin/export view; does
    /// not filter by the org's soft-delete state).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_caches_for_org(&self, org_id: i64) -> Result<Vec<Cache>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {CACHE_COLUMNS} FROM caches WHERE org_id = ?1 ORDER BY slug"),
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_cache).collect()
    }

    /// Update a cache's mutable fields. Returns `false` if no cache has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_cache(
        &self,
        id: i64,
        name: &str,
        visibility: &str,
        priority: i64,
        compression: &str,
        want_mass_query: bool,
        hosted_key_id: Option<i64>,
    ) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE caches SET name = ?2, visibility = ?3, priority = ?4,
                 compression = ?5, want_mass_query = ?6, hosted_key_id = ?7
                 WHERE id = ?1",
                &vals![
                    id,
                    name,
                    visibility,
                    priority,
                    compression,
                    want_mass_query,
                    hosted_key_id
                ],
            )
            .await?;
        Ok(n > 0)
    }

    /// Soft-delete a cache (tombstone with a purge deadline). Returns `false` if
    /// no live cache has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn soft_delete_cache(&self, id: i64, purge_after: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE caches SET deleted_at = ?2, purge_after = ?3
                 WHERE id = ?1 AND deleted_at IS NULL",
                &vals![id, unix_now(), purge_after],
            )
            .await?;
        Ok(n > 0)
    }

    /// Hard-delete a cache row, cascading its links/policy/roots/objects/usage/runs.
    ///
    /// Does not remove the cache's surface content on the storage backend (that
    /// lives outside SQL), mirroring [`Database::delete_registry`]. Returns
    /// `false` if no cache has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_cache(&self, id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute("DELETE FROM caches WHERE id = ?1", &vals![id])
            .await?;
        Ok(n > 0)
    }

    /// Link (or update the link between) a cache and a registry.
    ///
    /// Upserts on `(cache_id, registry_id)`, so calling it again updates the
    /// `roots_packages` / `advertised` flags in place.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn link_cache(
        &self,
        cache_id: i64,
        registry_id: i64,
        roots_packages: bool,
        advertised: bool,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO cache_registry_links
                 (cache_id, registry_id, roots_packages, advertised, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(cache_id, registry_id) DO UPDATE SET
                   roots_packages = excluded.roots_packages,
                   advertised = excluded.advertised",
                &vals![
                    cache_id,
                    registry_id,
                    roots_packages,
                    advertised,
                    unix_now()
                ],
            )
            .await?;
        Ok(())
    }

    /// Remove a cache⇄registry link. Returns `false` if no such link existed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn unlink_cache(&self, cache_id: i64, registry_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM cache_registry_links WHERE cache_id = ?1 AND registry_id = ?2",
                &vals![cache_id, registry_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// List a cache's registry links.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_links(&self, cache_id: i64) -> Result<Vec<CacheRegistryLink>> {
        let rows = self
            .backend
            .query(
                "SELECT cache_id, registry_id, roots_packages, advertised, created_at
                 FROM cache_registry_links WHERE cache_id = ?1 ORDER BY registry_id",
                &vals![cache_id],
            )
            .await?;
        rows.iter().map(row_to_cache_link).collect()
    }

    /// List the cache links that name a given registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_links_for_registry(
        &self,
        registry_id: i64,
    ) -> Result<Vec<CacheRegistryLink>> {
        let rows = self
            .backend
            .query(
                "SELECT cache_id, registry_id, roots_packages, advertised, created_at
                 FROM cache_registry_links WHERE registry_id = ?1 ORDER BY cache_id",
                &vals![registry_id],
            )
            .await?;
        rows.iter().map(row_to_cache_link).collect()
    }

    /// Set (upsert) a cache's GC policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_cache_gc_policy(&self, p: &CacheGcPolicy) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO cache_gc_policy
                 (cache_id, max_bytes, max_objects, ttl_unreferenced_secs,
                  keep_release_versions, keep_channel_frontier, schedule_secs, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(cache_id) DO UPDATE SET
                   max_bytes = excluded.max_bytes,
                   max_objects = excluded.max_objects,
                   ttl_unreferenced_secs = excluded.ttl_unreferenced_secs,
                   keep_release_versions = excluded.keep_release_versions,
                   keep_channel_frontier = excluded.keep_channel_frontier,
                   schedule_secs = excluded.schedule_secs,
                   updated_at = excluded.updated_at",
                &vals![
                    p.cache_id,
                    p.max_bytes,
                    p.max_objects,
                    p.ttl_unreferenced_secs,
                    p.keep_release_versions,
                    p.keep_channel_frontier,
                    p.schedule_secs,
                    unix_now()
                ],
            )
            .await?;
        Ok(())
    }

    /// Fetch a cache's GC policy, if one has been set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_gc_policy(&self, cache_id: i64) -> Result<Option<CacheGcPolicy>> {
        self.backend
            .query_opt(
                "SELECT cache_id, max_bytes, max_objects, ttl_unreferenced_secs,
                 keep_release_versions, keep_channel_frontier, schedule_secs, updated_at
                 FROM cache_gc_policy WHERE cache_id = ?1",
                &vals![cache_id],
            )
            .await?
            .map(|row| row_to_cache_gc_policy(&row))
            .transpose()
    }

    /// Pin a store path as a manual GC root (or renew its deadline in place).
    ///
    /// Upserts the `manual` root for `store_hash`, so passing a new `expires_at`
    /// renews the pin **without re-uploading** the NAR. `expires_at = None`
    /// pins indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn pin_cache_path(
        &self,
        cache_id: i64,
        store_hash: &str,
        expires_at: Option<i64>,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO cache_gc_roots
                 (cache_id, store_hash, root_kind, root_ref, expires_at, created_at)
                 VALUES (?1, ?2, 'manual', '', ?3, ?4)
                 ON CONFLICT(cache_id, store_hash, root_kind, root_ref)
                 DO UPDATE SET expires_at = excluded.expires_at",
                &vals![cache_id, store_hash, expires_at, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Remove a manual GC pin. Returns `false` if no manual pin existed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn unpin_cache_path(&self, cache_id: i64, store_hash: &str) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM cache_gc_roots
                 WHERE cache_id = ?1 AND store_hash = ?2 AND root_kind = 'manual'",
                &vals![cache_id, store_hash],
            )
            .await?;
        Ok(n > 0)
    }

    /// List a cache's GC roots (manual + derived), oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_roots(&self, cache_id: i64) -> Result<Vec<CacheGcRoot>> {
        let rows = self
            .backend
            .query(
                "SELECT id, cache_id, store_hash, root_kind, root_ref, expires_at, created_at
                 FROM cache_gc_roots WHERE cache_id = ?1 ORDER BY id",
                &vals![cache_id],
            )
            .await?;
        rows.iter().map(row_to_cache_gc_root).collect()
    }

    /// Insert or update a cache's narinfo-index row for one store path.
    ///
    /// # Errors
    ///
    /// Returns an error if `refs` cannot be serialized, or on database failure.
    pub async fn upsert_cache_object(&self, o: &CacheObject) -> Result<()> {
        let refs_json = serde_json::to_string(&o.refs)?;
        self.backend
            .execute(
                "INSERT INTO cache_objects
                 (cache_id, store_hash, store_name, nar_url, nar_hash, nar_size,
                  file_hash, file_size, compression, deriver, refs, sig, ca,
                  uploaded_at, last_accessed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                 ON CONFLICT(cache_id, store_hash) DO UPDATE SET
                   store_name = excluded.store_name, nar_url = excluded.nar_url,
                   nar_hash = excluded.nar_hash, nar_size = excluded.nar_size,
                   file_hash = excluded.file_hash, file_size = excluded.file_size,
                   compression = excluded.compression, deriver = excluded.deriver,
                   refs = excluded.refs, sig = excluded.sig, ca = excluded.ca,
                   uploaded_at = excluded.uploaded_at",
                &vals![
                    o.cache_id,
                    o.store_hash,
                    o.store_name,
                    o.nar_url,
                    o.nar_hash,
                    o.nar_size,
                    o.file_hash,
                    o.file_size,
                    o.compression,
                    o.deriver,
                    refs_json,
                    o.sig,
                    o.ca,
                    o.uploaded_at,
                    o.last_accessed_at
                ],
            )
            .await?;
        Ok(())
    }

    /// Fetch one cache object by store hash.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_object(
        &self,
        cache_id: i64,
        store_hash: &str,
    ) -> Result<Option<CacheObject>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {CACHE_OBJECT_COLUMNS} FROM cache_objects
                     WHERE cache_id = ?1 AND store_hash = ?2"
                ),
                &vals![cache_id, store_hash],
            )
            .await?
            .map(|row| row_to_cache_object(&row))
            .transpose()
    }

    /// List a cache's objects (by name), up to `limit`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_objects(&self, cache_id: i64, limit: i64) -> Result<Vec<CacheObject>> {
        // A negative `limit` means "all objects" (the GC sweep). The clause is
        // omitted rather than passing a huge sentinel like `i64::MAX`: the D1
        // backend binds integers as `f64`, and `i64::MAX` as `f64` is not a valid
        // `LIMIT` integer there (`SQLITE_MISMATCH`). Native sqlite tolerates the
        // sentinel, but omitting the clause is correct on every backend.
        let rows = if limit < 0 {
            self.backend
                .query(
                    &format!(
                        "SELECT {CACHE_OBJECT_COLUMNS} FROM cache_objects
                         WHERE cache_id = ?1 ORDER BY store_name"
                    ),
                    &vals![cache_id],
                )
                .await?
        } else {
            self.backend
                .query(
                    &format!(
                        "SELECT {CACHE_OBJECT_COLUMNS} FROM cache_objects
                         WHERE cache_id = ?1 ORDER BY store_name LIMIT ?2"
                    ),
                    &vals![cache_id, limit],
                )
                .await?
        };
        rows.iter().map(row_to_cache_object).collect()
    }

    /// Search a cache's objects by store name, hash, or deriver substring.
    ///
    /// A substring (`LIKE`) match over the indexed `store_name`/`store_hash`/
    /// `deriver` columns; full-text ranking is a later enhancement (D-web).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn search_cache_objects(
        &self,
        cache_id: i64,
        query: &str,
        limit: i64,
    ) -> Result<Vec<CacheObject>> {
        let like = format!("%{query}%");
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {CACHE_OBJECT_COLUMNS} FROM cache_objects
                     WHERE cache_id = ?1
                       AND (store_name LIKE ?2 OR store_hash LIKE ?2 OR deriver LIKE ?2)
                     ORDER BY store_name LIMIT ?3"
                ),
                &vals![cache_id, like, limit],
            )
            .await?;
        rows.iter().map(row_to_cache_object).collect()
    }

    /// Record that a cache object was read, feeding the GC's LRU eviction order.
    ///
    /// Updates `last_accessed_at`, but **debounced**: at most one write per
    /// object per [`LRU_TOUCH_DEBOUNCE_SECS`] window, so a high-QPS substituter
    /// probing the same narinfo does not turn every read into a write. The signal
    /// is advisory — GC *correctness* comes from roots, not recency (RFC-0004
    /// "11-caches" LRU access signal), so a missed touch only affects eviction
    /// order, never whether a rooted path survives. A no-op when the object is
    /// absent or was touched recently.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn touch_cache_object(
        &self,
        cache_id: i64,
        store_hash: &str,
        now: i64,
    ) -> Result<()> {
        let stale_before = now - LRU_TOUCH_DEBOUNCE_SECS;
        self.backend
            .execute(
                "UPDATE cache_objects SET last_accessed_at = ?3
                 WHERE cache_id = ?1 AND store_hash = ?2
                   AND (last_accessed_at IS NULL OR last_accessed_at < ?4)",
                &vals![cache_id, store_hash, now, stale_before],
            )
            .await?;
        Ok(())
    }

    /// Delete a cache object's narinfo row. Returns `false` if it did not exist.
    ///
    /// The NAR blob is reference-counted by [`Database::nar_refcount`]; callers
    /// (the GC sweep) delete the blob only once that count reaches zero.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_cache_object(&self, cache_id: i64, store_hash: &str) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM cache_objects WHERE cache_id = ?1 AND store_hash = ?2",
                &vals![cache_id, store_hash],
            )
            .await?;
        Ok(n > 0)
    }

    /// Count narinfo rows referencing a NAR `file_hash` across every cache that
    /// shares a storage binding + prefix (the content-addressed NAR refcount).
    ///
    /// A NAR blob is safe to delete only when this returns zero.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn nar_refcount(
        &self,
        storage_binding_id: Option<i64>,
        prefix: &str,
        file_hash: &str,
    ) -> Result<i64> {
        // `IS` (not `=`) so a NULL binding (default-storage caches) matches other
        // NULL-binding rows — `= NULL` is never true in SQL. Default-storage
        // caches carry distinct (slug-derived) prefixes, so the count stays
        // correctly scoped to physically-shared objects.
        let row = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM cache_objects o
                 JOIN caches c ON c.id = o.cache_id
                 WHERE c.storage_binding_id IS ?1 AND c.prefix = ?2 AND o.file_hash = ?3",
                &vals![storage_binding_id, prefix, file_hash],
            )
            .await?;
        Ok(row.map(|r| r.get::<i64>(0)).transpose()?.unwrap_or(0))
    }

    /// A cache's stored usage totals (zeroed default when never computed).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_usage(&self, cache_id: i64) -> Result<CacheUsage> {
        match self
            .backend
            .query_opt(
                "SELECT used_bytes, object_count, updated_at FROM cache_usage WHERE cache_id = ?1",
                &vals![cache_id],
            )
            .await?
        {
            Some(r) => Ok(CacheUsage {
                used_bytes: r.get(0)?,
                object_count: r.get(1)?,
                updated_at: r.get(2)?,
            }),
            None => Ok(CacheUsage::default()),
        }
    }

    /// Instance-wide cache aggregates for the `/metrics` endpoint.
    ///
    /// Counts live (non-soft-deleted) caches, sums their objects and bytes
    /// (objects of soft-deleted caches are excluded by the join), and totals the
    /// lifetime GC outcomes. See [`CacheMetrics`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_metrics(&self) -> Result<CacheMetrics> {
        // Exclude both per-cache tombstones and caches under a soft-deleted org,
        // matching `list_caches`'s servable-surface predicate so the gauges track
        // what is actually served during an org's offboarding grace window.
        const LIVE_ORG: &str = "(c.org_id IS NULL OR NOT EXISTS \
             (SELECT 1 FROM orgs o WHERE o.id = c.org_id AND o.deleted_at IS NOT NULL))";
        let cache_count = match self
            .backend
            .query_opt(
                &format!("SELECT COUNT(*) FROM caches c WHERE c.deleted_at IS NULL AND {LIVE_ORG}"),
                &[],
            )
            .await?
        {
            Some(r) => r.get::<i64>(0)?,
            None => 0,
        };
        let (object_count, used_bytes) = match self
            .backend
            .query_opt(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(co.file_size), 0)
                     FROM cache_objects co JOIN caches c ON c.id = co.cache_id
                     WHERE c.deleted_at IS NULL AND {LIVE_ORG}"
                ),
                &[],
            )
            .await?
        {
            Some(r) => (r.get::<i64>(0)?, r.get::<i64>(1)?),
            None => (0, 0),
        };
        let (gc_runs_ok, gc_freed_bytes) = match self
            .backend
            .query_opt(
                "SELECT COUNT(*), COALESCE(SUM(freed_bytes), 0)
                 FROM cache_gc_runs WHERE status = 'ok'",
                &[],
            )
            .await?
        {
            Some(r) => (r.get::<i64>(0)?, r.get::<i64>(1)?),
            None => (0, 0),
        };
        let gc_runs_failed = match self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM cache_gc_runs WHERE status = 'failed'",
                &[],
            )
            .await?
        {
            Some(r) => r.get::<i64>(0)?,
            None => 0,
        };
        Ok(CacheMetrics {
            cache_count,
            object_count,
            used_bytes,
            gc_runs_ok,
            gc_runs_failed,
            gc_freed_bytes,
        })
    }

    /// Recompute and persist a cache's usage from its objects; returns the totals.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn refresh_cache_usage(&self, cache_id: i64) -> Result<CacheUsage> {
        let (used_bytes, object_count) = match self
            .backend
            .query_opt(
                "SELECT COALESCE(SUM(file_size), 0), COUNT(*) FROM cache_objects WHERE cache_id = ?1",
                &vals![cache_id],
            )
            .await?
        {
            Some(r) => (r.get::<i64>(0)?, r.get::<i64>(1)?),
            None => (0, 0),
        };
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO cache_usage (cache_id, used_bytes, object_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(cache_id) DO UPDATE SET
                   used_bytes = excluded.used_bytes,
                   object_count = excluded.object_count,
                   updated_at = excluded.updated_at",
                &vals![cache_id, used_bytes, object_count, now],
            )
            .await?;
        Ok(CacheUsage {
            used_bytes,
            object_count,
            updated_at: now,
        })
    }

    /// Open a GC run row for a cache; returns its id. The sweep fills the rest
    /// via [`Database::finish_cache_gc_run`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn start_cache_gc_run(&self, cache_id: i64) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO cache_gc_runs (cache_id, started_at, status)
                 VALUES (?1, ?2, 'running')",
                &vals![cache_id, unix_now()],
            )
            .await
    }

    /// Close out a GC run row with its outcome and counters.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_cache_gc_run(
        &self,
        run_id: i64,
        status: &str,
        error: Option<String>,
        scanned: i64,
        retained: i64,
        deleted_objects: i64,
        freed_bytes: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE cache_gc_runs SET finished_at = ?2, status = ?3, error = ?4,
                 scanned = ?5, retained = ?6, deleted_objects = ?7, freed_bytes = ?8
                 WHERE id = ?1",
                &vals![
                    run_id,
                    unix_now(),
                    status,
                    error,
                    scanned,
                    retained,
                    deleted_objects,
                    freed_bytes
                ],
            )
            .await?;
        Ok(())
    }

    /// List a cache's GC runs, most recent first, up to `limit`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_cache_gc_runs(&self, cache_id: i64, limit: i64) -> Result<Vec<CacheGcRun>> {
        let rows = self
            .backend
            .query(
                "SELECT id, cache_id, started_at, finished_at, status, error,
                 scanned, retained, deleted_objects, freed_bytes
                 FROM cache_gc_runs WHERE cache_id = ?1 ORDER BY id DESC LIMIT ?2",
                &vals![cache_id, limit],
            )
            .await?;
        rows.iter().map(row_to_cache_gc_run).collect()
    }

    /// The store-path hash components of every platform artifact a registry
    /// currently indexes.
    ///
    /// Used to derive a linked cache's GC roots (RFC-0004 "11-caches": pin GC
    /// roots to AOS packages) — every store path the registry exposes is kept in
    /// a cache linked with `roots_packages`, so GC never reclaims a NAR a
    /// published package needs.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_store_hashes(&self, registry_id: i64) -> Result<Vec<String>> {
        // Both the primary platform `store_path` AND each image `store_path` in
        // the `images` JSON are live artifacts the registry exposes; a linked
        // cache must root them all, or GC could reclaim a NAR a published image
        // needs.
        let rows = self
            .backend
            .query(
                "SELECT vp.store_path, vp.images FROM version_platforms vp
                 JOIN package_versions pv ON pv.id = vp.version_id
                 JOIN packages p ON p.id = pv.package_id
                 WHERE p.registry_id = ?1",
                &vals![registry_id],
            )
            .await?;
        let store_hash = |path: &str| -> String {
            let base = path.rsplit('/').next().unwrap_or(path);
            base.split('-').next().unwrap_or(base).to_string()
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let store_path: String = row.get(0)?;
            out.push(store_hash(&store_path));
            let images: String = row.get(1)?;
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&images) {
                for image in arr {
                    if let Some(path) = image.get("store_path").and_then(|v| v.as_str()) {
                        out.push(store_hash(path));
                    }
                }
            }
        }
        Ok(out)
    }

    // -- storage bindings ----------------------------------------------------

    /// Create a storage binding under an org; returns its new id.
    ///
    /// `kind` must be a known [`BindingKind`](crate::binding::BindingKind)
    /// (`local_fs`, `s3`, or `r2`); the kind string is stored verbatim. This
    /// shared layer validates only that the kind is *known* — whether the kind
    /// is *usable* depends on the serving runtime (see
    /// [`RuntimeKind`](crate::binding::RuntimeKind)) and is enforced at the
    /// serving surfaces (the `create_binding` RPC and the WebUI handler), not
    /// here, because the offline CLI writes through this method without knowing
    /// the deployment runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown `kind`, on a unique-constraint
    /// violation when `(org_id, name)` already exists, or on database
    /// failure.
    pub async fn create_storage_binding(
        &self,
        org_id: i64,
        name: &str,
        kind: &str,
        root: &str,
    ) -> Result<i64> {
        crate::binding::BindingKind::parse(kind).ok_or_else(|| {
            anyhow::anyhow!("unknown storage binding kind '{kind}' (expected local_fs, s3, or r2)")
        })?;
        self.backend
            .execute_insert(
                "INSERT INTO storage_bindings (org_id, name, kind, root, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                &vals![org_id, name, kind, root, unix_now()],
            )
            .await
    }

    /// Set a storage binding's access mode and origin/credential metadata.
    ///
    /// `access` must be `public` or `private`. `endpoint` is the S3/R2 API
    /// endpoint the hub writes/presigns against; `credential_ref` is the sealed
    /// credential a private binding's authenticated-origin reads sign with.
    /// Returns `false` when no binding has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid `access` value or on database failure.
    pub async fn set_storage_binding_access(
        &self,
        id: i64,
        access: &str,
        endpoint: Option<&str>,
        credential_ref: Option<&str>,
    ) -> Result<bool> {
        if !matches!(access, "public" | "private") {
            bail!("invalid storage-binding access '{access}' (expected public or private)");
        }
        let n = self
            .backend
            .execute(
                "UPDATE storage_bindings
                 SET access = ?2, endpoint = ?3, credential_ref = ?4
                 WHERE id = ?1",
                &vals![id, access, endpoint, credential_ref],
            )
            .await?;
        Ok(n > 0)
    }

    /// Look up a storage binding by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn storage_binding(&self, id: i64) -> Result<Option<StorageBindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, root, access, endpoint,
                 credential_ref, is_instance_default, created_at
                 FROM storage_bindings WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading storage binding by id")?
            .map(|row| row_to_storage_binding(&row))
            .transpose()
    }

    /// The singleton instance-level default storage binding (RFC-0004 §12) — the
    /// anchor for the default bucket's frontends and public settings that
    /// registries/caches with `storage_binding_id IS NULL` inherit. `None` only
    /// on a database predating migration v30.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_default_binding(&self) -> Result<Option<StorageBindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, root, access, endpoint,
                 credential_ref, is_instance_default, created_at
                 FROM storage_bindings WHERE is_instance_default = 1 LIMIT 1",
                &[],
            )
            .await
            .context("loading instance default storage binding")?
            .map(|row| row_to_storage_binding(&row))
            .transpose()
    }

    /// Update a storage binding's access mode (`public`/`private`) and its
    /// `endpoint` — the S3/R2 API endpoint the hub writes objects through and
    /// presigns reads against. Returns `false` when no binding has `id`.
    ///
    /// Setting `access = "private"` clears the binding's Direct eligibility;
    /// existing Direct frontends over it then no longer resolve to an advertised
    /// URL (the resolver re-checks `access == "public"`). The `endpoint` is the
    /// bucket's *origin*, never a consumer-facing read URL — consumer read URLs
    /// are served by [`FrontendRecord`]s, not this field.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_binding_public(
        &self,
        id: i64,
        access: &str,
        endpoint: Option<&str>,
    ) -> Result<bool> {
        let access = match access {
            "public" | "private" => access,
            other => bail!("unknown storage access mode '{other}' (expected public or private)"),
        };
        // The endpoint is the bucket origin the hub writes/presigns against, so
        // require a safe http(s) origin.
        if let Some(url) = endpoint {
            if !url.trim().is_empty() {
                crate::url_guard::is_safe_remote_url(url.trim())
                    .with_context(|| format!("rejecting endpoint URL '{url}'"))?;
            }
        }
        let n = self
            .backend
            .execute(
                "UPDATE storage_bindings SET access = ?2, endpoint = ?3 WHERE id = ?1",
                &vals![id, access, endpoint],
            )
            .await?;
        Ok(n > 0)
    }

    /// Whether `id` in `table` advertises its inherited storage-binding frontend
    /// (RFC-0004 §12), defaulting to `true` when the row or column is absent.
    ///
    /// `table` is always a fixed internal literal (`"registries"` / `"caches"`),
    /// never caller input, so the interpolation introduces no injection.
    async fn advertises_storage_frontend(&self, table: &str, id: i64) -> Result<bool> {
        let sql = format!("SELECT advertise_storage_frontend FROM {table} WHERE id = ?1");
        let v: Option<i64> = self
            .backend
            .query_opt(&sql, &vals![id])
            .await?
            .map(|r| r.get(0))
            .transpose()?;
        Ok(v.map(|n| n != 0).unwrap_or(true))
    }

    /// Set whether `id` in `table` advertises its inherited storage frontend.
    /// Returns `false` when no row has `id`.
    async fn set_advertises_storage_frontend(
        &self,
        table: &str,
        id: i64,
        advertise: bool,
    ) -> Result<bool> {
        let sql = format!("UPDATE {table} SET advertise_storage_frontend = ?2 WHERE id = ?1");
        let n = self.backend.execute(&sql, &vals![id, advertise]).await?;
        Ok(n > 0)
    }

    /// Whether a registry advertises its inherited storage-binding frontend.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_advertises_storage_frontend(&self, id: i64) -> Result<bool> {
        self.advertises_storage_frontend("registries", id).await
    }

    /// Whether a managed cache advertises its inherited storage-binding frontend.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_advertises_storage_frontend(&self, id: i64) -> Result<bool> {
        self.advertises_storage_frontend("caches", id).await
    }

    /// Set whether a registry advertises its inherited storage frontend.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_registry_advertise_storage_frontend(
        &self,
        id: i64,
        advertise: bool,
    ) -> Result<bool> {
        self.set_advertises_storage_frontend("registries", id, advertise)
            .await
    }

    /// Set whether a managed cache advertises its inherited storage frontend.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_cache_advertise_storage_frontend(
        &self,
        id: i64,
        advertise: bool,
    ) -> Result<bool> {
        self.set_advertises_storage_frontend("caches", id, advertise)
            .await
    }

    /// Look up a storage binding by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn storage_binding_by_name(
        &self,
        org_id: i64,
        name: &str,
    ) -> Result<Option<StorageBindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, root, access, endpoint,
                 credential_ref, is_instance_default, created_at
                 FROM storage_bindings WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
            .await
            .context("loading storage binding by name")?
            .map(|row| row_to_storage_binding(&row))
            .transpose()
    }

    /// List an org's storage bindings, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_storage_bindings(&self, org_id: i64) -> Result<Vec<StorageBindingRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, name, kind, root, access, endpoint,
                 credential_ref, is_instance_default, created_at
             FROM storage_bindings WHERE org_id = ?1 ORDER BY name",
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_storage_binding).collect()
    }

    /// Delete a storage binding by id, scoped to its org; returns whether a row
    /// was removed. The caller must ensure no registry still references it
    /// (see [`RegistryRecord::storage_binding_id`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_storage_binding(&self, org_id: i64, binding_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM storage_bindings WHERE id = ?1 AND org_id = ?2",
                &vals![binding_id, org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Bind a registry to a storage binding and sub-prefix.
    ///
    /// After this, [`Database::registry_surface_root`] resolves the
    /// registry's surface to `{binding.root}/{prefix}`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_registry_storage(
        &self,
        registry_id: i64,
        binding_id: Option<i64>,
        prefix: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE registries SET storage_binding_id = ?2, prefix = ?3 WHERE id = ?1",
                &vals![registry_id, binding_id, prefix],
            )
            .await?;
        Ok(())
    }

    /// Bind a cache to a storage binding (or `None` for default storage) and
    /// sub-prefix.
    ///
    /// The cache analog of [`Database::set_registry_storage`]. After this,
    /// [`Database::cache_surface_root`] resolves the cache's surface to the new
    /// `{binding.root}/{prefix}` (or the deployment default at `{prefix}`).
    /// This re-points the columns only; moving the surface bytes between stores
    /// is the migration layer's job ([`crate::migrate`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_cache_storage(
        &self,
        cache_id: i64,
        binding_id: Option<i64>,
        prefix: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE caches SET storage_binding_id = ?2, prefix = ?3 WHERE id = ?1",
                &vals![cache_id, binding_id, prefix],
            )
            .await?;
        Ok(())
    }

    /// Resolve the on-disk surface directory for a registry, if any.
    ///
    /// Precedence:
    ///
    /// 1. **Storage-bound** (`storage_binding_id` set) — the binding's
    ///    `root` joined with the registry's `prefix`. This wins even if a
    ///    `source_url` is also present.
    /// 2. **Default-storage managed** (no binding, empty `source_url`,
    ///    non-empty `prefix`) — the deployment
    ///    [`default_storage_root`](Database::default_storage_root) joined with
    ///    the registry's `prefix`. Resolves to `Ok(None)` when no default root
    ///    is configured (the native hub has no implicit object store, so such a
    ///    registry is unservable until one is set). The Worker never reaches
    ///    this branch — it serves managed registries by `prefix` against its
    ///    single R2 bucket without calling this method.
    /// 3. **`file://` (or bare-path) source** — the `source_url` path.
    /// 4. **`http(s)://` source** — `Ok(None)`; the surface is remote and
    ///    has no local directory (the facade redirects upstream).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure (including a registry whose
    /// `storage_binding_id` points at a missing binding).
    pub async fn registry_surface_root(&self, registry_id: i64) -> Result<Option<PathBuf>> {
        let registry = self
            .backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE id = ?1"),
                &vals![registry_id],
            )
            .await
            .context("loading registry for surface resolution")?
            .map(|row| row_to_registry(&row))
            .transpose()?;
        let Some(registry) = registry else {
            return Ok(None);
        };
        if let Some(binding_id) = registry.storage_binding_id {
            let binding = self.storage_binding(binding_id).await?.with_context(|| {
                format!("registry {registry_id} bound to missing storage binding {binding_id}")
            })?;
            let mut path = PathBuf::from(binding.root);
            if !registry.prefix.is_empty() {
                path.push(&registry.prefix);
            }
            return Ok(Some(path));
        }
        let source = registry.source_url.as_str();
        // A managed, binding-less registry (empty source, non-empty prefix)
        // roots on the deployment's default storage. On the native hub that
        // default must be configured explicitly; when it is, the surface is
        // `{default_root}/{prefix}`, otherwise the registry is unservable
        // (`None`). The Worker addresses these by prefix against its single R2
        // bucket and never calls this method.
        if source.is_empty() && !registry.prefix.is_empty() {
            return Ok(self.default_storage_root().await?.map(|root| {
                let mut path = PathBuf::from(root);
                path.push(&registry.prefix);
                path
            }));
        }
        if source.is_empty() || source.starts_with("http://") || source.starts_with("https://") {
            return Ok(None);
        }
        let path = source.strip_prefix("file://").unwrap_or(source);
        Ok(Some(PathBuf::from(path)))
    }

    /// Resolve a cache's surface root: its storage binding's root joined with the
    /// cache prefix. `None` when the cache does not exist.
    ///
    /// The cache analog of [`Database::registry_surface_root`]. A cache always
    /// has a storage binding (the column is `NOT NULL`), so — unlike a registry —
    /// there is no unbound/`source_url` fallback.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache's storage binding is missing, or on database
    /// failure.
    pub async fn cache_surface_root(&self, cache_id: i64) -> Result<Option<PathBuf>> {
        let Some(cache) = self.cache_by_id(cache_id).await? else {
            return Ok(None);
        };
        // A binding-less cache roots on the deployment's default storage by its
        // prefix — the same resolution a default-storage registry uses. Without a
        // configured default root, there is no native surface (`None`); on the
        // Worker the R2 provider serves it from the deployment bucket by prefix.
        let Some(binding_id) = cache.storage_binding_id else {
            let Some(root) = self.default_storage_root().await? else {
                return Ok(None);
            };
            let mut path = PathBuf::from(root);
            if !cache.prefix.is_empty() {
                path.push(&cache.prefix);
            }
            return Ok(Some(path));
        };
        let binding = self.storage_binding(binding_id).await?.with_context(|| {
            format!("cache {cache_id} bound to missing storage binding {binding_id}")
        })?;
        let mut path = PathBuf::from(binding.root);
        if !cache.prefix.is_empty() {
            path.push(&cache.prefix);
        }
        Ok(Some(path))
    }

    // -- hosted signing keys (v10) ------------------------------------------

    /// Enroll a fresh hosted signing key for an org; returns its public
    /// trusted-key line.
    ///
    /// Generates a new Ed25519 keypair, seals its 32-byte seed with `sealer`,
    /// and stores the row. Nothing but the *sealed* seed is persisted, and the
    /// plaintext seed never leaves this call. The returned line
    /// (`<key_id>:Ed25519:<base64>`) is what operators pin as a registry trust
    /// anchor so the hub's signatures verify through the indexer.
    ///
    /// # Errors
    ///
    /// Returns an error when a key with `key_id` already exists in the org,
    /// when sealing fails, or on database failure.
    pub async fn create_hosted_key(
        &self,
        sealer: &dyn crate::auth::seal::SecretSealer,
        org_id: i64,
        key_id: &str,
    ) -> Result<String> {
        use rand::Rng as _;

        let seed: [u8; 32] = rand::rng().random();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key =
            aos_registry_surface::sshsig::trusted_key_line(key_id, &signing_key.verifying_key());
        // Seal the seed as a hex string so the placeholder XOR sealer (which
        // operates on UTF-8 plaintext) round-trips it losslessly.
        let secret_enc = sealer.seal(&hex::encode(seed))?;
        self.backend
            .execute(
                "INSERT INTO hosted_keys (org_id, key_id, public_key, secret_enc, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &vals![org_id, key_id, public_key, secret_enc, unix_now()],
            )
            .await
            .with_context(|| format!("enrolling hosted key '{key_id}' in org {org_id}"))?;
        Ok(public_key)
    }

    /// Load one hosted-key row by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn hosted_key(&self, id: i64) -> Result<Option<HostedKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, key_id, public_key, secret_enc, created_at
                 FROM hosted_keys WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading hosted key by id")?
            .map(|row| row_to_hosted_key(&row))
            .transpose()
    }

    /// Look up a hosted key by its org and key id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn hosted_key_by_name(
        &self,
        org_id: i64,
        key_id: &str,
    ) -> Result<Option<HostedKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, key_id, public_key, secret_enc, created_at
                 FROM hosted_keys WHERE org_id = ?1 AND key_id = ?2",
                &vals![org_id, key_id],
            )
            .await
            .context("loading hosted key by name")?
            .map(|row| row_to_hosted_key(&row))
            .transpose()
    }

    /// List an org's hosted signing keys, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_hosted_keys(&self, org_id: i64) -> Result<Vec<HostedKeyRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, key_id, public_key, secret_enc, created_at
             FROM hosted_keys WHERE org_id = ?1 ORDER BY created_at, id",
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_hosted_key).collect()
    }

    /// Unseal a hosted key into a usable Ed25519 signing key.
    ///
    /// Loads the row, unseals its seed through `sealer`, and reconstructs the
    /// [`ed25519_dalek::SigningKey`]. Returns the key id, the signing key, and
    /// the public trusted-key line (so callers can confirm the hub's own
    /// public anchor in one read). The plaintext seed is materialized only on
    /// the stack for the duration of the call.
    ///
    /// # Errors
    ///
    /// Returns an error when no hosted key has `id`, when the sealed seed
    /// cannot be unsealed or is not a 32-byte hex string, or on database
    /// failure.
    pub async fn load_hosted_signing_key(
        &self,
        sealer: &dyn crate::auth::seal::SecretSealer,
        id: i64,
    ) -> Result<(String, ed25519_dalek::SigningKey, String)> {
        let record = self
            .hosted_key(id)
            .await?
            .with_context(|| format!("no hosted key with id {id}"))?;
        let seed_hex = sealer
            .unseal(&record.secret_enc)
            .with_context(|| format!("unsealing hosted key '{}'", record.key_id))?;
        let seed_bytes = hex::decode(seed_hex.trim())
            .with_context(|| format!("decoding hosted key '{}' seed", record.key_id))?;
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "hosted key '{}' seed must be 32 bytes, got {}",
                record.key_id,
                seed_bytes.len()
            )
        })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok((record.key_id, signing_key, record.public_key))
    }

    /// Bind (or unbind) a registry's hosted signing key.
    ///
    /// Setting `hosted_key_id` opts the registry into the direct (web-signed)
    /// channel-advance and tag-resign path; `None` reverts it to BYO-key
    /// (prepared-operation-only) behavior.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_registry_hosted_key(
        &self,
        registry_id: i64,
        hosted_key_id: Option<i64>,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE registries SET hosted_key_id = ?2 WHERE id = ?1",
                &vals![registry_id, hosted_key_id],
            )
            .await?;
        Ok(())
    }

    /// Look up an organization by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_id(&self, id: i64) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, slug, name, created_at FROM orgs WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading org by id")?
            .map(|row| row_to_org(&row))
            .transpose()
    }

    /// List all active organizations, ordered by slug.
    ///
    /// Soft-deleted orgs are excluded (see [`Database::org_by_slug`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_orgs(&self) -> Result<Vec<OrgRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, slug, name, created_at FROM orgs
             WHERE deleted_at IS NULL ORDER BY slug",
                &[],
            )
            .await?;
        rows.iter().map(row_to_org).collect()
    }

    // -- operations: quotas, usage, signup policy, offboarding (v13) ---------

    /// Set (or replace) an org's quota caps.
    ///
    /// Each cap is optional: pass `None` to leave that dimension unlimited.
    /// Upserts the single `org_quotas` row.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_org_quota(&self, org_id: i64, quota: &OrgQuota) -> Result<()> {
        self.backend.execute(
            "INSERT INTO org_quotas (org_id, max_bytes, max_objects, max_registries, max_tokens)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(org_id) DO UPDATE SET
                 max_bytes = excluded.max_bytes,
                 max_objects = excluded.max_objects,
                 max_registries = excluded.max_registries,
                 max_tokens = excluded.max_tokens",
            &vals![
                org_id,
                quota.max_bytes,
                quota.max_objects,
                quota.max_registries,
                quota.max_tokens,
            ],
        ).await?;
        Ok(())
    }

    /// Look up an org's quota caps.
    ///
    /// Returns [`OrgQuota::default`] (all dimensions unlimited) when the org
    /// has no `org_quotas` row.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_quota(&self, org_id: i64) -> Result<OrgQuota> {
        let row = self
            .backend
            .query_opt(
                "SELECT max_bytes, max_objects, max_registries, max_tokens
             FROM org_quotas WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?;
        match row {
            Some(row) => Ok(OrgQuota {
                max_bytes: row.get(0)?,
                max_objects: row.get(1)?,
                max_registries: row.get(2)?,
                max_tokens: row.get(3)?,
            }),
            None => Ok(OrgQuota::default()),
        }
    }

    /// Look up an org's current usage totals.
    ///
    /// Returns [`OrgUsage::default`] (all zero) when the org has no
    /// `org_usage` row yet.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_usage(&self, org_id: i64) -> Result<OrgUsage> {
        let row = self
            .backend
            .query_opt(
                "SELECT used_bytes, object_count, updated_at FROM org_usage WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?;
        match row {
            Some(row) => Ok(OrgUsage {
                used_bytes: row.get(0)?,
                object_count: row.get(1)?,
                updated_at: row.get(2)?,
            }),
            None => Ok(OrgUsage::default()),
        }
    }

    /// Add `delta_bytes`/`delta_objects` to an org's running usage totals.
    ///
    /// Upserts the `org_usage` row, creating it on first use. Called by the
    /// upload facade after a successful write of a new object. The totals are
    /// approximate (see [`OrgUsage`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn add_org_usage(
        &self,
        org_id: i64,
        delta_bytes: i64,
        delta_objects: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(org_id) DO UPDATE SET
                 used_bytes = org_usage.used_bytes + excluded.used_bytes,
                 object_count = org_usage.object_count + excluded.object_count,
                 updated_at = excluded.updated_at",
                &vals![org_id, delta_bytes, delta_objects, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Whether writing `additional_bytes` more would exceed an org's byte quota.
    ///
    /// Returns `true` only when the org has a `max_bytes` cap *and*
    /// `used_bytes + additional_bytes` would exceed it. An org with no cap (or
    /// no quota row) never exceeds. The object-count cap is checked separately
    /// by the caller against [`Database::org_quota`]/[`Database::org_usage`].
    ///
    /// This is a *read-only* check and is therefore racy against concurrent
    /// writers; the upload facade reserves atomically with
    /// [`Database::reserve_org_usage`] instead. This method is retained for
    /// read-only quota reporting.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn would_exceed_quota(&self, org_id: i64, additional_bytes: i64) -> Result<bool> {
        let quota = self.org_quota(org_id).await?;
        let Some(max_bytes) = quota.max_bytes else {
            return Ok(false);
        };
        let used = self.org_usage(org_id).await?.used_bytes;
        Ok(used.saturating_add(additional_bytes) > max_bytes)
    }

    /// Atomically check an org's quota and, if the write fits, reserve it.
    ///
    /// In a single transaction this reads the org's `max_bytes`/`max_objects`
    /// caps and current usage, decides whether applying `delta_bytes` (which
    /// may be negative on a shrinking overwrite) and `delta_objects` keeps both
    /// dimensions within their caps, and — only when it fits — updates
    /// `org_usage` by the deltas. Returns `true` when the reservation was made,
    /// `false` when it would exceed a cap (no update performed).
    ///
    /// Folding the check and the update into one transaction closes the
    /// check-then-write TOCTOU window that a separate `would_exceed_quota`
    /// followed by `add_org_usage` left open: two concurrent uploads can no
    /// longer both observe headroom and then both consume it. Usage is clamped
    /// at zero so a negative delta never drives the stored total below zero.
    ///
    /// A `NULL`/absent cap is unlimited for that dimension. An org with no
    /// `org_usage` row is treated as zero usage and a row is inserted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn reserve_org_usage(
        &self,
        org_id: i64,
        delta_bytes: i64,
        delta_objects: i64,
    ) -> Result<bool> {
        // Optimistic concurrency in place of the interactive transaction (so
        // this runs on D1): read caps + current usage, check the cap in Rust
        // (kept out of SQL to stay dialect-portable — no GREATEST/MAX scalar),
        // then write the new totals behind a compare-and-set guard. A
        // concurrent reservation that moved usage since the read fails the CAS
        // (0 rows) and we re-read and retry, so the quota cannot be oversold.
        const MAX_ATTEMPTS: usize = 8;
        let now = unix_now();
        for _ in 0..MAX_ATTEMPTS {
            let caps = self
                .backend
                .query_opt(
                    "SELECT max_bytes, max_objects FROM org_quotas WHERE org_id = ?1",
                    &vals![org_id],
                )
                .await?;
            let (max_bytes, max_objects): (Option<i64>, Option<i64>) = match caps {
                Some(row) => (row.get(0)?, row.get(1)?),
                None => (None, None),
            };
            let usage = self
                .backend
                .query_opt(
                    "SELECT used_bytes, object_count FROM org_usage WHERE org_id = ?1",
                    &vals![org_id],
                )
                .await?;
            let (used_bytes, object_count, row_exists): (i64, i64, bool) = match usage {
                Some(row) => (row.get(0)?, row.get(1)?, true),
                None => (0, 0, false),
            };

            let new_bytes = used_bytes.saturating_add(delta_bytes).max(0);
            let new_objects = object_count.saturating_add(delta_objects).max(0);

            if max_bytes.is_some_and(|max| new_bytes > max)
                || max_objects.is_some_and(|max| new_objects > max)
            {
                return Ok(false);
            }

            // It fits: reserve, but only if usage is unchanged since the read.
            let affected =
                if row_exists {
                    self.backend.execute(
                    "UPDATE org_usage SET used_bytes = ?2, object_count = ?3, updated_at = ?4
                     WHERE org_id = ?1 AND used_bytes = ?5 AND object_count = ?6",
                    &vals![org_id, new_bytes, new_objects, now, used_bytes, object_count],
                ).await?
                } else {
                    self.backend
                        .execute(
                            "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(org_id) DO NOTHING",
                            &vals![org_id, new_bytes, new_objects, now],
                        )
                        .await?
                };
            if affected == 1 {
                return Ok(true);
            }
            // Raced with a concurrent reservation; re-read and retry.
        }
        bail!("reserve_org_usage: too much write contention on org {org_id}")
    }

    /// Read an instance-config value by key.
    ///
    /// Returns `None` when the key is unset.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_get(&self, key: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT value FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Set an instance-config value, upserting the key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_set(&self, key: &str, value: &str) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO instance_config (config_key, value) VALUES (?1, ?2)
             ON CONFLICT(config_key) DO UPDATE SET value = excluded.value",
                &vals![key, value],
            )
            .await?;
        Ok(())
    }

    /// Delete an instance-config value by key (a no-op when the key is unset).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_delete(&self, key: &str) -> Result<()> {
        self.backend
            .execute(
                "DELETE FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )
            .await?;
        Ok(())
    }

    /// The instance-config key the sealed draft-signing seed is stored under.
    const DRAFT_SIGNING_KEY: &'static str = "draft_signing_key";

    /// Load (or, on first use, generate and persist) the per-instance
    /// draft-signing key.
    ///
    /// Web edits to git-backed config are committed as change requests to
    /// `refs/hub/changes/<change_id>`, signed by this key (RFC-0004
    /// "Configuration management", git-backed path). The key is deliberately
    /// **not** in any registry's roster — a draft never verifies for consumers
    /// until a maintainer re-signs it with a roster key (`apr change merge`) —
    /// so it carries no consumption trust; it exists only to produce a
    /// well-formed signed commit object the hub and `apr` can fetch and diff.
    ///
    /// The seed is sealed at rest with the instance [`SecretSealer`](crate::auth::seal::SecretSealer) exactly as
    /// hosted keys are ([`Self::create_hosted_key`]): the 32-byte seed is
    /// hex-encoded, then sealed, then stored as the `draft_signing_key`
    /// instance-config value. Returns the usable signing key together with its
    /// public trusted-key line (named `aos-hub-draft`), for surfacing in the UI
    /// and for round-trip verification in tests.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or when an existing sealed value
    /// cannot be unsealed or decoded into a 32-byte seed (tampering or a key
    /// mismatch).
    pub async fn get_or_create_draft_signing_key(
        &self,
        sealer: &dyn crate::auth::seal::SecretSealer,
    ) -> Result<(ed25519_dalek::SigningKey, String)> {
        let seed: [u8; 32] = match self.instance_config_get(Self::DRAFT_SIGNING_KEY).await? {
            Some(sealed) => {
                let seed_hex = sealer
                    .unseal(&sealed)
                    .context("unsealing the draft-signing key")?;
                hex::decode(seed_hex.trim())
                    .context("decoding the draft-signing key seed")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("draft-signing key seed is not 32 bytes"))?
            }
            None => {
                use rand::Rng as _;
                let seed: [u8; 32] = rand::rng().random();
                let sealed = sealer.seal(&hex::encode(seed))?;
                self.instance_config_set(Self::DRAFT_SIGNING_KEY, &sealed)
                    .await?;
                seed
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_line = aos_registry_surface::sshsig::trusted_key_line(
            "aos-hub-draft",
            &signing_key.verifying_key(),
        );
        Ok((signing_key, public_line))
    }

    /// The instance's signup policy (defaulting to invite-only when unset).
    ///
    /// Reads the `signup_policy` instance-config key and parses it through
    /// [`SignupPolicy::parse`] (any unknown value falls closed to
    /// invite-only).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn signup_policy(&self) -> Result<SignupPolicy> {
        Ok(self
            .instance_config_get("signup_policy")
            .await?
            .map(|v| SignupPolicy::parse(&v))
            .unwrap_or(SignupPolicy::InviteOnly))
    }

    /// Set the instance signup policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_signup_policy(&self, policy: SignupPolicy) -> Result<()> {
        self.instance_config_set("signup_policy", policy.as_str())
            .await
    }

    /// The deployment's default storage root for binding-less managed
    /// registries (unset by default).
    ///
    /// A managed registry created with no storage binding roots its surface on
    /// the deployment's default storage, addressed purely by its `prefix`. On
    /// the Cloudflare Worker that default is the single hub-owned R2 bucket,
    /// addressed by prefix without consulting this value. On the native hub
    /// there is no implicit object store, so the default storage root must be
    /// configured explicitly (e.g. `aos-hub instance set-default-storage-root
    /// /srv/aos-hub/registries`); until it is set,
    /// [`Database::registry_surface_root`] resolves a binding-less registry to
    /// `None` (unservable) rather than guessing a path.
    ///
    /// Reads the `default_storage_root` instance-config key; returns `None`
    /// when unset.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn default_storage_root(&self) -> Result<Option<String>> {
        self.instance_config_get("default_storage_root").await
    }

    /// Set the deployment's default storage root (see
    /// [`Database::default_storage_root`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_default_storage_root(&self, root: &str) -> Result<()> {
        self.instance_config_set("default_storage_root", root).await
    }

    /// Deletes an `instance_config` key (clearing an optional setting back to
    /// its default), a no-op when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_config_clear(&self, key: &str) -> Result<()> {
        self.backend
            .execute(
                "DELETE FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )
            .await?;
        Ok(())
    }

    /// Loads the full editable instance-settings bundle from `instance_config`.
    ///
    /// Every field falls back to a documented default when its key is unset, so
    /// a fresh deployment reads as sensible defaults until an admin (or the
    /// deploy-time seed) overrides them. Read by the instance-settings console
    /// and the API/CLI; the branding/footer subset is also seeded into the page
    /// chrome at startup.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn instance_settings(&self) -> Result<InstanceSettings> {
        let get = |k: &'static str| self.instance_config_get(k);
        Ok(InstanceSettings {
            site_title: get("site_title").await?,
            tagline: get("tagline").await?,
            announcement: get("announcement").await?,
            tos_url: get("tos_url").await?,
            privacy_url: get("privacy_url").await?,
            support_url: get("support_url").await?,
            signup_policy: self.signup_policy().await?,
            signup_domains: get("signup_domains")
                .await?
                .map(|v| {
                    v.split(|c: char| c == ',' || c.is_whitespace())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_lowercase())
                        .collect()
                })
                .unwrap_or_default(),
            password_login: get("password_login")
                .await?
                .map(|v| v != "off" && v != "false" && v != "0")
                .unwrap_or(true),
            caches_public: get("caches_public")
                .await?
                .map(|v| v == "on" || v == "true" || v == "1")
                .unwrap_or(false),
            session_lifetime_secs: get("session_lifetime_secs")
                .await?
                .and_then(|v| v.parse().ok()),
            default_crawl_policy: get("default_crawl_policy")
                .await?
                .unwrap_or_else(|| "allow_all".to_string()),
            max_upload_bytes: get("max_upload_bytes").await?.and_then(|v| v.parse().ok()),
        })
    }

    /// Upserts a single instance-config key, or clears it when `value` is
    /// `None`/blank (resetting to the default).
    ///
    /// The typed front door the console/API/CLI setters share, so an empty form
    /// field consistently means "reset" rather than "store an empty string".
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_instance_config(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            Some(v) => self.instance_config_set(key, v).await,
            None => self.instance_config_clear(key).await,
        }
    }

    /// The number of active (non-revoked) tokens owned by any principal in an
    /// org.
    ///
    /// Counts tokens whose owner is the org's service accounts; user-owned
    /// tokens are not scoped to a single org, so the per-org token quota
    /// governs the org's service-account publishers (the CI surface). Used by
    /// the token-mint quota gate.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_active_token_count(&self, org_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM tokens
                 WHERE owner_kind = 'service_account'
                   AND revoked_at IS NULL
                   AND owner_id IN (SELECT id FROM service_accounts WHERE org_id = ?1)",
                &vals![org_id],
            )
            .await?
            .context("token count query returned no row")?
            .get(0)
    }

    /// List token *metadata* (never the hash/secret) for an org's service
    /// accounts, for export.
    ///
    /// Returns `(token_id, owner_kind, owner_id, scope, permissions_json,
    /// created_at, expires_at, last_used_at)` for every token owned by a
    /// service account in `org_id`. The `hash` column is deliberately excluded
    /// — an export carries no usable credential (RFC-0004 offboarding).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::type_complexity)]
    pub async fn export_org_token_metadata(
        &self,
        org_id: i64,
    ) -> Result<
        Vec<(
            String,
            String,
            i64,
            String,
            String,
            i64,
            Option<i64>,
            Option<i64>,
        )>,
    > {
        let rows = self
            .backend
            .query(
                "SELECT id, owner_kind, owner_id, scope, permissions, created_at, expires_at,
                    last_used_at
             FROM tokens
             WHERE owner_kind = 'service_account'
               AND owner_id IN (SELECT id FROM service_accounts WHERE org_id = ?1)
             ORDER BY created_at, id",
                &vals![org_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .collect()
    }

    /// List every membership grant at a scope at or below `scope_prefix`.
    ///
    /// Returns `(principal_kind, principal_id, scope, role)` for grants whose
    /// scope is `scope_prefix` or a descendant of it (segment-boundary match),
    /// for org export. Passing an org slug returns the org's whole grant tree.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_memberships_under(
        &self,
        scope_prefix: &str,
    ) -> Result<Vec<(String, i64, String, String)>> {
        let prefix = crate::domain::Scope::parse(scope_prefix);
        let rows = self
            .backend
            .query(
                "SELECT principal_kind, principal_id, scope, role FROM memberships
             ORDER BY scope, principal_kind, principal_id",
                &[],
            )
            .await?;
        let mut out = Vec::new();
        for row in &rows {
            let kind: String = row.get(0)?;
            let pid: i64 = row.get(1)?;
            let scope: String = row.get(2)?;
            let role: String = row.get(3)?;
            if prefix.contains(&crate::domain::Scope::parse(&scope)) {
                out.push((kind, pid, scope, role));
            }
        }
        Ok(out)
    }

    /// Whether a user holds any role grant at any scope.
    ///
    /// Used by the `invite_only` signup gate: an existing member of some org
    /// may create another org without an invitation (RFC-0004).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    /// The number of orgs a user currently *owns* (holds an `Owner`
    /// membership on at an org-root scope).
    ///
    /// Used by the org-creation cap (the hub's `ratelimit::MAX_ORGS_PER_OWNER`) to bound namespace
    /// pollution: an `Owner` membership's scope is the org slug (a single path
    /// segment with no `/`), which is exactly what `CreateOrg` grants the
    /// creator, so counting those rows counts the principal's owned orgs.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn count_user_owned_orgs(&self, user_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1
                   AND role = 'owner' AND scope NOT LIKE '%/%'",
                &vals![user_id],
            )
            .await?
            .context("owned-org count query returned no row")?
            .get(0)
    }

    pub async fn user_has_any_membership(&self, user_id: i64) -> Result<bool> {
        let count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1",
                &vals![user_id],
            )
            .await?
            .context("membership count query returned no row")?
            .get(0)?;
        Ok(count > 0)
    }

    /// Whether a live (unexpired, unaccepted) invitation exists for `email`.
    ///
    /// Used by the `invite_only` signup gate. A user invited to any org may
    /// create their own org (RFC-0004 "open membership-by-invitation").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn has_pending_invitation(&self, email: &str) -> Result<bool> {
        let now = unix_now();
        let count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM invitations
                 WHERE email = ?1 AND accepted_at IS NULL AND expires_at > ?2",
                &vals![email, now],
            )
            .await?
            .context("invitation count query returned no row")?
            .get(0)?;
        Ok(count > 0)
    }

    /// The number of registries owned by an org.
    ///
    /// Used by the registry-create quota gate.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_registry_count(&self, org_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM registries WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?
            .context("registry count query returned no row")?
            .get(0)
    }

    /// Whether an org exists and is not soft-deleted.
    ///
    /// The serving paths consult this to stop serving a tombstoned org's
    /// registries without disclosing their existence.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_is_active(&self, org_id: i64) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT 1 FROM orgs WHERE id = ?1 AND deleted_at IS NULL",
                &vals![org_id],
            )
            .await?;
        Ok(row.is_some())
    }

    /// Soft-delete an org, opening a `grace_secs` grace window.
    ///
    /// Stamps `deleted_at = now` and `purge_after = now + grace_secs`. The org
    /// immediately stops serving (the serving queries exclude soft-deleted
    /// orgs), but its data persists until the purge job hard-deletes it past
    /// `purge_after`. Returns `Ok(false)` when the org is unknown or already
    /// soft-deleted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn soft_delete_org(&self, org_id: i64, grace_secs: i64) -> Result<bool> {
        let now = unix_now();
        let n = self
            .backend
            .execute(
                "UPDATE orgs SET deleted_at = ?2, purge_after = ?3
             WHERE id = ?1 AND deleted_at IS NULL",
                &vals![org_id, now, now + grace_secs],
            )
            .await?;
        Ok(n > 0)
    }

    /// Restore a soft-deleted org within its grace window.
    ///
    /// Clears `deleted_at`/`purge_after`, returning the org to active serving.
    /// Returns `Ok(false)` when the org is unknown or was not soft-deleted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn restore_org(&self, org_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE orgs SET deleted_at = NULL, purge_after = NULL
             WHERE id = ?1 AND deleted_at IS NOT NULL",
                &vals![org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// List orgs whose grace window has elapsed (`purge_after <= now`).
    ///
    /// These are the orgs the purge job ([`Database::hard_purge_org`]) hard
    /// deletes. Returns the admin-visible records (soft-deleted orgs are
    /// otherwise hidden).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_purgeable_orgs(&self, now: i64) -> Result<Vec<OrgRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, slug, name, created_at FROM orgs
             WHERE deleted_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after <= ?1
             ORDER BY slug",
                &vals![now],
            )
            .await?;
        rows.iter().map(row_to_org).collect()
    }

    /// Hard-delete an org row, cascading to everything it owns.
    ///
    /// The org's `ON DELETE CASCADE` foreign keys remove its projects,
    /// registries, service accounts, memberships, bindings, quotas, usage, and
    /// the rest of its SQL system of record. Bucket/LocalFs content removal is
    /// a *separate* step (the caller deletes the binding root dir), since the
    /// surface lives outside SQL. Returns `Ok(false)` when the org is unknown.
    ///
    /// SECURITY: the delete re-asserts the exact predicate
    /// [`Database::list_purgeable_orgs`] selects on — still soft-deleted and
    /// past its grace window — rather than deleting on `id` alone. The purge job
    /// lists purgeable orgs and then deletes them one by one with no transaction
    /// spanning the list and the delete, while [`Database::restore_org`] can
    /// clear `deleted_at`/`purge_after` concurrently (via the `org restore`
    /// CLI). Were the delete unconditional, a restore landing in that window
    /// would be silently destroyed, cascading away the now-active org's
    /// projects, registries, members, tokens, and bindings. Re-checking the
    /// predicate makes the delete a no-op (returning `Ok(false)`) for any org
    /// restored after it was listed. The caller passes the *same* `now` it gave
    /// [`Database::list_purgeable_orgs`] (see
    /// the hub's `export::purge_expired_orgs`), so one
    /// consistent timestamp spans the list and every delete in a purge tick.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn hard_purge_org(&self, org_id: i64, now: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM orgs
             WHERE id = ?1
               AND deleted_at IS NOT NULL
               AND purge_after IS NOT NULL
               AND purge_after <= ?2",
                &vals![org_id, now],
            )
            .await?;
        Ok(n > 0)
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
    pub async fn create_invitation(
        &self,
        org_id: i64,
        email: &str,
        scope: &str,
        role: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO invitations
             (org_id, email, scope, role, token_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    org_id,
                    email,
                    scope,
                    role,
                    token_hash,
                    unix_now(),
                    expires_at
                ],
            )
            .await
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
    pub async fn accept_invitation(&self, token_hash: &str) -> Result<Option<InvitationRecord>> {
        let now = unix_now();
        let record = self
            .backend
            .query_opt(
                "SELECT id, org_id, email, scope, role FROM invitations
                 WHERE token_hash = ?1 AND accepted_at IS NULL AND expires_at > ?2",
                &vals![token_hash, now],
            )
            .await
            .context("loading invitation by hash")?
            .map(|row| -> Result<InvitationRecord> {
                Ok(InvitationRecord {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    email: row.get(2)?,
                    scope: row.get(3)?,
                    role: row.get(4)?,
                })
            })
            .transpose()?;
        if let Some(record) = &record {
            self.backend
                .execute(
                    "UPDATE invitations SET accepted_at = ?2 WHERE id = ?1",
                    &vals![record.id, now],
                )
                .await?;
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
    pub async fn create_token(
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
        self.backend
            .execute(
                "INSERT INTO tokens
             (id, hash, owner_kind, owner_id, scope, permissions, comment, created_at,
              expires_at, revoked_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
                &vals![
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
            )
            .await?;
        Ok((id, secret))
    }

    /// Validate a token secret, returning its [`TokenAuth`] when live.
    ///
    /// A secret is accepted when its hash is known, it is not expired, and
    /// it is either not revoked or still inside the
    /// `ROTATION_GRACE_SECS` window after its `revoked_at` stamp (so a
    /// rotated token's old secret keeps working briefly). On success
    /// `last_used_at` is bumped to now. Returns `Ok(None)` for any
    /// unknown, expired, or fully-revoked secret without distinguishing
    /// the reason.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or a malformed stored row.
    pub async fn validate_token(&self, secret: &str) -> Result<Option<TokenAuth>> {
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT id, owner_kind, owner_id, scope, permissions, expires_at,
                        revoked_at, rotated_at
                 FROM tokens WHERE hash = ?1",
                &vals![hash],
            )
            .await
            .context("loading token by hash")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: String = row.get(0)?;
        let owner_kind: String = row.get(1)?;
        let owner_id: i64 = row.get(2)?;
        let scope: String = row.get(3)?;
        let perms_json: String = row.get(4)?;
        let expires_at: Option<i64> = row.get(5)?;
        let revoked_at: Option<i64> = row.get(6)?;
        let rotated_at: Option<i64> = row.get(7)?;
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
        // Stamping `last_used_at` is bookkeeping, not part of the validation
        // decision: a failure here (e.g. a schema drift on the touch column)
        // must never turn a valid token into an authentication error. Log and
        // continue so the caller still receives the resolved `TokenAuth`.
        if let Err(e) = self
            .backend
            .execute(
                "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
                &vals![id, now],
            )
            .await
        {
            tracing::warn!(error = %e, token_id = %id, "failed to stamp token last_used_at");
        }
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
    pub async fn revoke_token(&self, token_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                &vals![token_id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// List a principal's non-revoked tokens as `(id, scope, permissions)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_tokens_for(
        &self,
        owner: crate::domain::Principal,
    ) -> Result<Vec<(String, String, Vec<crate::domain::Permission>)>> {
        let rows = self
            .backend
            .query(
                "SELECT id, scope, permissions FROM tokens
             WHERE owner_kind = ?1 AND owner_id = ?2 AND revoked_at IS NULL
             ORDER BY created_at",
                &vals![owner.kind.as_str(), owner.id],
            )
            .await?;
        let mut out = Vec::new();
        for row in &rows {
            let id: String = row.get(0)?;
            let scope: String = row.get(1)?;
            let perms_json: String = row.get(2)?;
            out.push((id, scope, parse_permission_names(&perms_json)));
        }
        Ok(out)
    }

    /// Rotate a token: revoke the old one and mint a replacement with the
    /// same owner, scope, permissions, comment, and expiry.
    ///
    /// The old secret keeps validating for `ROTATION_GRACE_SECS` after
    /// rotation (its `revoked_at` is stamped now, and
    /// [`Database::validate_token`] honors the grace window) so in-flight
    /// clients are not cut off mid-request. Returns `(new_id, new_secret)`,
    /// or `Ok(None)` when the id is unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or a malformed stored row.
    pub async fn rotate_token(&self, token_id: &str) -> Result<Option<(String, String)>> {
        let now = unix_now();
        // Read the live token first (outside the write batch); the revoke +
        // re-mint below is then a self-contained, D1-batchable unit. The id is
        // assigned client-side, so no `last_insert_rowid` round-trip is needed.
        let Some(old) = self
            .backend
            .query_opt(
                "SELECT owner_kind, owner_id, scope, permissions, comment, expires_at
             FROM tokens WHERE id = ?1 AND revoked_at IS NULL",
                &vals![token_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let owner_kind: String = old.get(0)?;
        let owner_id: i64 = old.get(1)?;
        let scope: String = old.get(2)?;
        let perms_json: String = old.get(3)?;
        let comment: Option<String> = old.get(4)?;
        let expires_at: Option<i64> = old.get(5)?;
        let (secret, hash) = crate::auth::token::generate_token();
        let new_id = uuid::Uuid::new_v4().to_string();
        self.backend
            .batch(&[
                Statement::new(
                    "UPDATE tokens SET rotated_at = ?2 WHERE id = ?1",
                    vals![token_id, now].to_vec(),
                ),
                Statement::new(
                    "INSERT INTO tokens
                 (id, hash, owner_kind, owner_id, scope, permissions, comment, created_at,
                  expires_at, revoked_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
                    vals![
                        new_id, hash, owner_kind, owner_id, scope, perms_json, comment, now,
                        expires_at,
                    ]
                    .to_vec(),
                ),
            ])
            .await?;
        Ok(Some((new_id, secret)))
    }

    // -- auth: human sessions -----------------------------------------------

    /// Create a session for `user_id`, returning the opaque cookie secret.
    ///
    /// Only the SHA-256 hash of the secret is stored. `ttl_secs` is the
    /// session's **absolute** lifetime: `expires_at` is stamped to
    /// `now + ttl_secs` (callers pass
    /// [`ABSOLUTE_LIFETIME_SECS`](crate::auth::session::ABSOLUTE_LIFETIME_SECS)).
    /// An independent idle timeout is enforced in
    /// [`validate_session`](Self::validate_session) via `last_seen_at`.
    /// `auth_level` is `1` for a sudo-capable session (the user
    /// re-authenticated) and `0` otherwise; `last_authenticated_at` is stamped
    /// to now so the sudo window is meaningful.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn create_session(
        &self,
        user_id: i64,
        ttl_secs: i64,
        auth_level: i64,
    ) -> Result<String> {
        let secret = crate::auth::session::new_session_secret();
        let hash = crate::auth::token::sha256_hex(&secret);
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO sessions
             (id_hash, user_id, created_at, last_seen_at, expires_at, auth_level,
              last_authenticated_at)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?3)",
                &vals![hash, user_id, now, now + ttl_secs, auth_level],
            )
            .await?;
        Ok(secret)
    }

    /// Validate a session cookie secret, returning its [`SessionAuth`].
    ///
    /// Accepts the secret when its hash is known and the session is live under
    /// all three lifetime bounds, then bumps `last_seen_at` to now (sliding
    /// the idle window). Returns `Ok(None)` for an unknown session or one that
    /// has crossed any bound:
    ///
    /// - **absolute deadline**: `now >= expires_at` (the
    ///   [`ABSOLUTE_LIFETIME_SECS`](crate::auth::session::ABSOLUTE_LIFETIME_SECS)
    ///   cap stamped at creation, also covered by `created_at`);
    /// - **idle timeout**: `now - last_seen_at` exceeds
    ///   [`IDLE_TIMEOUT_SECS`](crate::auth::session::IDLE_TIMEOUT_SECS);
    /// - **absolute lifetime**: `now - created_at` exceeds
    ///   [`ABSOLUTE_LIFETIME_SECS`](crate::auth::session::ABSOLUTE_LIFETIME_SECS).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn validate_session(&self, secret: &str) -> Result<Option<SessionAuth>> {
        use crate::auth::session::{ABSOLUTE_LIFETIME_SECS, IDLE_TIMEOUT_SECS};
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT user_id, auth_level, last_authenticated_at, expires_at,
                        created_at, last_seen_at
                 FROM sessions WHERE id_hash = ?1",
                &vals![hash],
            )
            .await
            .context("loading session by hash")?
            .map(|row| -> Result<(SessionAuth, i64, i64)> {
                let auth = SessionAuth {
                    user_id: row.get(0)?,
                    auth_level: row.get(1)?,
                    last_authenticated_at: row.get(2)?,
                    expires_at: row.get(3)?,
                };
                let created_at: i64 = row.get(4)?;
                let last_seen_at: i64 = row.get(5)?;
                Ok((auth, created_at, last_seen_at))
            })
            .transpose()?;
        let Some((session, created_at, last_seen_at)) = row else {
            return Ok(None);
        };
        // Absolute deadline (the stamped cap), idle timeout (no activity for
        // too long), and the absolute lifetime from creation. A session that
        // crosses any bound is dead; expire it so the row does not linger.
        let dead = now >= session.expires_at
            || now.saturating_sub(last_seen_at) > IDLE_TIMEOUT_SECS
            || now.saturating_sub(created_at) > ABSOLUTE_LIFETIME_SECS;
        if dead {
            self.backend
                .execute("DELETE FROM sessions WHERE id_hash = ?1", &vals![hash])
                .await?;
            return Ok(None);
        }
        self.backend
            .execute(
                "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
                &vals![hash, now],
            )
            .await?;
        Ok(Some(session))
    }

    /// The signed-in user's email for a session secret, without bumping
    /// `last_seen_at` (the masthead reads this on every page render).
    ///
    /// Returns `None` when the secret is unknown, the session is expired, or
    /// the user was deleted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn session_email(&self, secret: &str) -> Result<Option<String>> {
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        self.backend
            .query_opt(
                "SELECT u.email FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.id_hash = ?1 AND s.expires_at > ?2 AND u.deleted_at IS NULL",
                &vals![hash, now],
            )
            .await
            .context("loading session email")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Revoke a single session by its cookie secret.
    ///
    /// A no-op when the secret is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_session(&self, secret: &str) -> Result<()> {
        let hash = crate::auth::token::sha256_hex(secret);
        self.backend
            .execute("DELETE FROM sessions WHERE id_hash = ?1", &vals![hash])
            .await?;
        Ok(())
    }

    /// Revoke every session belonging to a user ("sign out everywhere").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn revoke_all_user_sessions(&self, user_id: i64) -> Result<()> {
        self.backend
            .execute("DELETE FROM sessions WHERE user_id = ?1", &vals![user_id])
            .await?;
        Ok(())
    }

    // -- offboarding: ownership transfer + user deletion (v13) --------------

    /// The org slugs where `user_id` is the *sole* `Owner`.
    ///
    /// An org's owners are the user principals holding the `owner` role at the
    /// org's own scope (`scope == org.slug`). This returns the slugs of orgs
    /// for which `user_id` is the only such owner — exactly the orgs whose
    /// ownership must be transferred before the user can be deleted (RFC-0004
    /// offboarding). Soft-deleted orgs are skipped (they are en route to purge
    /// anyway).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn sole_owned_orgs(&self, user_id: i64) -> Result<Vec<String>> {
        // Orgs where the user is an owner at the org scope.
        let rows = self
            .backend
            .query(
                "SELECT o.id, o.slug FROM orgs o
             JOIN memberships m
               ON m.scope = o.slug
              AND m.principal_kind = 'user'
              AND m.principal_id = ?1
              AND m.role = 'owner'
             WHERE o.deleted_at IS NULL",
                &vals![user_id],
            )
            .await?;
        let mut sole = Vec::new();
        for row in &rows {
            let org_slug: String = row.get(1)?;
            let owner_count: i64 = self
                .backend
                .query_opt(
                    "SELECT COUNT(*) FROM memberships
                     WHERE scope = ?1 AND principal_kind = 'user' AND role = 'owner'",
                    &vals![org_slug],
                )
                .await?
                .context("owner count query returned no row")?
                .get(0)?;
            if owner_count <= 1 {
                sole.push(org_slug);
            }
        }
        Ok(sole)
    }

    /// Transfer org ownership from one user to another at the org scope.
    ///
    /// Grants `to_user` the `owner` role at `org.slug` and revokes `from_user`'s
    /// owner grant there, in one transaction. The recipient need not have been
    /// a member previously. Returns an error when the org is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error when no org has `org_id`, or on database failure.
    pub async fn transfer_org_ownership(
        &self,
        org_id: i64,
        from_user: i64,
        to_user: i64,
    ) -> Result<()> {
        let org = self
            .org_by_id(org_id)
            .await?
            .with_context(|| format!("no org with id {org_id}"))?;
        let now = unix_now();
        // Two self-contained writes with all values known up front: a batch,
        // so this commits atomically on both native SQL and Cloudflare D1.
        self.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO memberships
                 (principal_kind, principal_id, scope, role, created_at)
                 VALUES ('user', ?1, ?2, 'owner', ?3)
                 ON CONFLICT(principal_kind, principal_id, scope)
                 DO UPDATE SET role = excluded.role",
                    vals![to_user, org.slug, now].to_vec(),
                ),
                Statement::new(
                    "DELETE FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1 AND scope = ?2",
                    vals![from_user, org.slug].to_vec(),
                ),
            ])
            .await?;
        Ok(())
    }

    /// Soft-delete a user, failing if they are the sole owner of any org.
    ///
    /// RFC-0004 offboarding: a user may not be deleted while they are the only
    /// `Owner` of an org — the ownership must be transferred first
    /// ([`Database::transfer_org_ownership`]). On the blocking path this
    /// returns an `Err` whose message lists the offending org slugs and makes
    /// no change. On success it stamps `users.deleted_at`, revokes every
    /// session the user holds, and hard-revokes every token they own (their
    /// credentials deaden immediately), all in one transaction. Returns
    /// `Ok(false)` when the user is unknown or already deleted.
    ///
    /// # Errors
    ///
    /// Returns an error (listing the orgs) when the user is the sole owner of
    /// any org, or on database failure.
    pub async fn delete_user(&self, user_id: i64) -> Result<bool> {
        let now = unix_now();
        // Derive the orgs the user solely owns in one query (an owner grant at a
        // non-deleted org with no *other* user owner) and refuse the delete when
        // any remain. The race a concurrent demote could open — dropping an
        // org's other owner between this read and the delete — is closed not by
        // a transaction (D1 has none) but by repeating the same NOT EXISTS guard
        // in the soft-delete's WHERE, so the user can never be deleted while
        // sole owner of any org.
        let blocking: Vec<String> = self
            .backend
            .query(
                "SELECT o.slug FROM orgs o
                 JOIN memberships m
                   ON m.scope = o.slug AND m.principal_kind = 'user'
                  AND m.principal_id = ?1 AND m.role = 'owner'
                 WHERE o.deleted_at IS NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM memberships m2
                     WHERE m2.scope = o.slug AND m2.principal_kind = 'user'
                       AND m2.role = 'owner' AND m2.principal_id <> ?1)",
                &vals![user_id],
            )
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect::<Result<_>>()?;
        if !blocking.is_empty() {
            bail!(
                "user {user_id} is the sole owner of: {} — transfer ownership before deleting",
                blocking.join(", ")
            );
        }
        // Guarded soft-delete: applies only if the user still owns no org solely
        // (re-evaluated atomically here), and only if not already deleted.
        let deleted = self
            .backend
            .execute(
                "UPDATE users SET deleted_at = ?2
             WHERE id = ?1 AND deleted_at IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM orgs o
                 JOIN memberships m
                   ON m.scope = o.slug AND m.principal_kind = 'user'
                  AND m.principal_id = ?1 AND m.role = 'owner'
                 WHERE o.deleted_at IS NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM memberships m2
                     WHERE m2.scope = o.slug AND m2.principal_kind = 'user'
                       AND m2.role = 'owner' AND m2.principal_id <> ?1))",
                &vals![user_id, now],
            )
            .await?;
        if deleted == 0 {
            // Already deleted/unknown, or a concurrent change just made the user
            // a sole owner (the guard held): make no further change.
            return Ok(false);
        }
        // The user is deadened; revoke their live credentials together.
        self.backend
            .batch(&[
                Statement::new(
                    "DELETE FROM sessions WHERE user_id = ?1",
                    vals![user_id].to_vec(),
                ),
                Statement::new(
                    "UPDATE tokens SET revoked_at = ?2
                 WHERE owner_kind = 'user' AND owner_id = ?1 AND revoked_at IS NULL",
                    vals![user_id, now].to_vec(),
                ),
            ])
            .await?;
        Ok(true)
    }

    /// Elevate a session to sudo: set `auth_level = 1` and stamp
    /// `last_authenticated_at = now`.
    ///
    /// A no-op when the secret is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn elevate_session(&self, secret: &str) -> Result<()> {
        let hash = crate::auth::token::sha256_hex(secret);
        self.backend
            .execute(
                "UPDATE sessions SET auth_level = 1, last_authenticated_at = ?2 WHERE id_hash = ?1",
                &vals![hash, unix_now()],
            )
            .await?;
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
    pub async fn start_device_authorization(
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
        self.backend
            .execute(
                "INSERT INTO device_codes
             (device_code_hash, user_code, scope, permissions, created_at, expires_at,
              approved_by_user, denied, issued_token_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, NULL)",
                &vals![
                    hash,
                    user_code,
                    crate::domain::Scope::parse(scope).as_str(),
                    perms_json,
                    now,
                    now + ttl,
                ],
            )
            .await?;
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
    /// # Atomicity
    ///
    /// The claim, the token mint, and the write of the minted secret happen
    /// inside one transaction. The grant is claimed by a conditional
    /// `UPDATE … WHERE approved_by_user IS NULL AND denied = 0 AND
    /// expires_at > ?` stamping `approved_by_user`; the mint proceeds only
    /// when that update touches exactly one row. Two concurrent approvals of
    /// the same `user_code` therefore cannot both mint — the loser's
    /// conditional claim stamps zero rows and it returns `Ok(false)` without
    /// minting, so no orphaned-but-live provisioning token is ever issued
    /// (the failure mode this method was hardened against). This mirrors the
    /// claim-then-act idiom of [`Database::consume_magic_link`] and
    /// [`Database::deny_device`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn approve_device(
        &self,
        user_code: &str,
        approver: crate::domain::Principal,
        approver_grants: &[(crate::domain::Scope, crate::domain::Role)],
    ) -> Result<bool> {
        let now = unix_now();
        // Atomically CLAIM the grant with a conditional update — the
        // single-approval gate. A second concurrent approval finds the row
        // already stamped and matches zero rows. Once we hold the claim
        // (claimed == 1) the row is ours, so the follow-up read is race-free; no
        // interactive transaction is needed (D1-safe).
        let claimed = self
            .backend
            .execute(
                "UPDATE device_codes SET approved_by_user = ?2
             WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
               AND expires_at > ?3",
                &vals![user_code, approver.id, now],
            )
            .await?;
        if claimed == 0 {
            // Unknown, already approved/denied, or expired: do NOT mint.
            return Ok(false);
        }
        let row = self
            .backend
            .query_opt(
                "SELECT scope, permissions FROM device_codes WHERE user_code = ?1",
                &vals![user_code],
            )
            .await?
            .context("device code vanished after claim")?;
        let scope: String = row.get(0)?;
        let perms_json: String = row.get(1)?;
        let requested_scope = crate::domain::Scope::parse(&scope);
        let requested = parse_permission_names(&perms_json);
        // Clamp: keep only requested permissions the approver may actually
        // grant at the requested scope (downward inheritance via `allow`).
        let granted: Vec<crate::domain::Permission> = requested
            .into_iter()
            .filter(|perm| crate::domain::iam::allow(approver_grants, *perm, &requested_scope))
            .collect();
        let (secret, hash) = crate::auth::token::generate_token();
        let token_id = uuid::Uuid::new_v4().to_string();
        let perms_out = serde_json::to_string(&permission_names(&granted))?;
        // Mint the token and stow its one-time secret together, atomically. The
        // secret is delivered exactly once to the polling CLI by `poll_device`,
        // never persisted in the clear where a human session can read it.
        self.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO tokens
                 (id, hash, owner_kind, owner_id, scope, permissions, comment, created_at,
                  expires_at, revoked_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, NULL, NULL, NULL)",
                    vals![
                        token_id,
                        hash,
                        approver.kind.as_str(),
                        approver.id,
                        requested_scope.as_str(),
                        perms_out,
                        now,
                    ]
                    .to_vec(),
                ),
                Statement::new(
                    "UPDATE device_codes
                 SET issued_token_id = ?2, issued_token_secret = ?3
                 WHERE user_code = ?1",
                    vals![user_code, token_id, secret].to_vec(),
                ),
            ])
            .await?;
        Ok(true)
    }

    /// Deny a device grant by its `user_code`.
    ///
    /// Returns `Ok(false)` when the code is unknown or already resolved.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn deny_device(&self, user_code: &str) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE device_codes SET denied = 1
             WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0",
                &vals![user_code],
            )
            .await?;
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
    pub async fn poll_device(&self, device_code_secret: &str) -> Result<DevicePollResult> {
        let hash = crate::auth::token::sha256_hex(device_code_secret);
        let row = self
            .backend
            .query_opt(
                "SELECT denied, approved_by_user, issued_token_secret
                 FROM device_codes WHERE device_code_hash = ?1",
                &vals![hash],
            )
            .await
            .context("loading device code for poll")?;
        let Some(row) = row else {
            return Ok(DevicePollResult::Pending);
        };
        let denied: i64 = row.get(0)?;
        let approved_by: Option<i64> = row.get(1)?;
        let issued_token_secret: Option<String> = row.get(2)?;
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
    pub async fn create_magic_link(&self, email: &str) -> Result<String> {
        let secret = crate::auth::magic::new_magic_secret();
        let hash = crate::auth::token::sha256_hex(&secret);
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO magic_links (token_hash, email, created_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
                &vals![
                    hash,
                    email,
                    now,
                    now + crate::auth::magic::MAGIC_LINK_TTL_SECS
                ],
            )
            .await?;
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
    pub async fn consume_magic_link(&self, secret: &str) -> Result<Option<String>> {
        let hash = crate::auth::token::sha256_hex(secret);
        let now = unix_now();
        // Claim-then-read: the conditional UPDATE is the single-use gate, so
        // two concurrent consumptions of the same link cannot both succeed
        // (the second stamps zero rows). On sqlite/postgres a single
        // `UPDATE … RETURNING email` ties the claim to the email atomically;
        // MySQL has no `UPDATE … RETURNING`, so a transactional
        // select-claim-then-read preserves the same single-use guarantee.
        if self.dialect() == Dialect::Mysql {
            // MySQL lacks `UPDATE … RETURNING`; the conditional UPDATE is still
            // the single-use claim gate (a replay stamps zero rows), so the
            // follow-up read only fires — and only returns an email — when this
            // call won the claim.
            let claimed = self
                .backend
                .execute(
                    "UPDATE magic_links SET consumed_at = ?2
                     WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                    &vals![hash, now],
                )
                .await
                .context("consuming magic link by hash")?;
            if claimed == 0 {
                return Ok(None);
            }
            let email = self
                .backend
                .query_opt(
                    "SELECT email FROM magic_links WHERE token_hash = ?1",
                    &vals![hash],
                )
                .await?
                .map(|r| r.get(0))
                .transpose()?;
            return Ok(email);
        }
        let email: Option<String> = self
            .backend
            .query_opt(
                "UPDATE magic_links SET consumed_at = ?2
                 WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2
                 RETURNING email",
                &vals![hash, now],
            )
            .await
            .context("consuming magic link by hash")?
            .map(|row| row.get(0))
            .transpose()?;
        Ok(email)
    }

    // -- auth: per-org OIDC SSO ---------------------------------------------

    /// Create or replace an org's OIDC identity-provider configuration.
    ///
    /// One IdP per org (the `org_id` primary key); re-calling overwrites the
    /// existing configuration and bumps `updated_at`. `client_secret_enc`
    /// must already be **sealed** by a [`crate::auth::seal::SecretSealer`] —
    /// this method stores the value verbatim and never sees the plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key
    /// violation when `org_id` does not reference an org.
    pub async fn upsert_idp_config(&self, config: &IdpConfigRecord) -> Result<()> {
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO org_idp_configs
             (org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
              client_id, client_secret_enc, scopes, groups_claim, role_map_json,
              allow_jit, enforce_sso, default_role, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)
             ON CONFLICT(org_id) DO UPDATE SET
                 issuer = excluded.issuer,
                 authorization_endpoint = excluded.authorization_endpoint,
                 token_endpoint = excluded.token_endpoint,
                 jwks_uri = excluded.jwks_uri,
                 client_id = excluded.client_id,
                 client_secret_enc = excluded.client_secret_enc,
                 scopes = excluded.scopes,
                 groups_claim = excluded.groups_claim,
                 role_map_json = excluded.role_map_json,
                 allow_jit = excluded.allow_jit,
                 enforce_sso = excluded.enforce_sso,
                 default_role = excluded.default_role,
                 updated_at = excluded.updated_at",
                &vals![
                    config.org_id,
                    config.issuer,
                    config.authorization_endpoint,
                    config.token_endpoint,
                    config.jwks_uri,
                    config.client_id,
                    config.client_secret_enc,
                    config.scopes,
                    config.groups_claim,
                    config.role_map_json,
                    config.allow_jit,
                    config.enforce_sso,
                    config.default_role,
                    now,
                ],
            )
            .await?;
        Ok(())
    }

    /// Remove an org's OIDC identity-provider configuration; returns whether a
    /// row was deleted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_idp_config(&self, org_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM org_idp_configs WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Load an org's OIDC identity-provider configuration, if configured.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn idp_config(&self, org_id: i64) -> Result<Option<IdpConfigRecord>> {
        self.backend
            .query_opt(
                "SELECT org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
                        client_id, client_secret_enc, scopes, groups_claim, role_map_json,
                        allow_jit, enforce_sso, default_role
                 FROM org_idp_configs WHERE org_id = ?1",
                &vals![org_id],
            )
            .await
            .context("loading idp config by org id")?
            .map(|row| row_to_idp_config(&row))
            .transpose()
    }

    /// Claim a domain for an org with a fresh DNS-TXT challenge.
    ///
    /// Returns the generated `txt_challenge` value the org must publish as a
    /// TXT record at the domain to prove control; the domain starts
    /// **unverified** (`verified_at` NULL) until [`Database::verify_org_domain`]
    /// stamps it. Re-claiming a domain *owned by the same org* rotates its
    /// challenge and resets it to unverified.
    ///
    /// A domain is a global, uniquely-keyed routing key (it steers
    /// domain-based SSO login), so it may belong to at most one org. Claiming
    /// a domain already held by a **different** org is refused — without this
    /// guard the `ON CONFLICT(domain)` upsert would silently re-point the row
    /// at the caller's org and reset its verification, letting one org seize
    /// another's verified domain (a cross-tenant claim theft / login DoS).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or if the domain is already
    /// claimed by a different organization.
    pub async fn add_org_domain(&self, org_id: i64, domain: &str) -> Result<String> {
        let domain = domain.trim().to_lowercase();
        let challenge = format!(
            "aos-domain-verify={}",
            crate::auth::session::new_session_secret()
        );
        // The ownership check and the upsert must be atomic: a check-then-act
        // split lets two org admins racing the same domain both read "no
        // conflict" and both upsert, the last writer re-pointing `org_id` and
        // wiping the victim's `verified_at` (a cross-tenant domain login-DoS).
        // sqlite/postgres do it in one guarded upsert (the `DO UPDATE … WHERE`
        // only fires when the row is already ours). MySQL has no WHERE on `ON
        // DUPLICATE KEY UPDATE`, so it reads the current owner first and bails
        // on a foreign claim, then upserts. NOTE: unlike the single-statement
        // guarded upsert, this read-then-write carries a small residual race —
        // two admins racing the *same* unclaimed domain could both read "no
        // owner" and both upsert, the last writer winning. The guarded upsert on
        // sqlite/postgres closes that window; mysql cannot express it, so this
        // path accepts the narrow race (a freshly-claimed domain is still
        // unverified until a DNS-TXT proof, which the loser would have to win
        // independently).
        if self.dialect() == Dialect::Mysql {
            let existing = self
                .backend
                .query_opt(
                    "SELECT org_id FROM org_domains WHERE domain = ?1",
                    &vals![domain],
                )
                .await?;
            if let Some(row) = existing {
                let owner_org: i64 = row.get(0)?;
                if owner_org != org_id {
                    anyhow::bail!("domain '{domain}' is already claimed by another organization");
                }
            }
            self.backend
                .execute(
                    "INSERT INTO org_domains (domain, org_id, txt_challenge, verified_at)
                     VALUES (?1, ?2, ?3, NULL)
                     ON CONFLICT(domain) DO UPDATE SET
                         org_id = excluded.org_id,
                         txt_challenge = excluded.txt_challenge,
                         verified_at = NULL",
                    &vals![domain, org_id, challenge],
                )
                .await?;
        } else {
            // The `WHERE org_domains.org_id = excluded.org_id` guard makes the
            // upsert a no-op (0 rows) when a *different* org holds the claim, so
            // a single statement enforces the invariant atomically.
            let affected = self
                .backend
                .execute(
                    "INSERT INTO org_domains (domain, org_id, txt_challenge, verified_at)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(domain) DO UPDATE SET
                     org_id = excluded.org_id,
                     txt_challenge = excluded.txt_challenge,
                     verified_at = NULL
                 WHERE org_domains.org_id = excluded.org_id",
                    &vals![domain, org_id, challenge],
                )
                .await?;
            if affected == 0 {
                anyhow::bail!("domain '{domain}' is already claimed by another organization");
            }
        }
        Ok(challenge)
    }

    /// List an org's claimed email domains (verified and pending), by domain.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_org_domains(&self, org_id: i64) -> Result<Vec<OrgDomainRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT domain, org_id, txt_challenge, verified_at
             FROM org_domains WHERE org_id = ?1 ORDER BY domain",
                &vals![org_id],
            )
            .await?;
        rows.iter()
            .map(|row| -> Result<OrgDomainRecord> {
                Ok(OrgDomainRecord {
                    domain: row.get(0)?,
                    org_id: row.get(1)?,
                    txt_challenge: row.get(2)?,
                    verified_at: row.get(3)?,
                })
            })
            .collect()
    }

    /// Look up a claimed domain (verified or not).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_domain(&self, domain: &str) -> Result<Option<OrgDomainRecord>> {
        let domain = domain.trim().to_lowercase();
        self.backend
            .query_opt(
                "SELECT domain, org_id, txt_challenge, verified_at FROM org_domains WHERE domain = ?1",
                &vals![domain],
            ).await
            .context("loading org domain")?
            .map(|row| -> Result<OrgDomainRecord> {
                Ok(OrgDomainRecord {
                    domain: row.get(0)?,
                    org_id: row.get(1)?,
                    txt_challenge: row.get(2)?,
                    verified_at: row.get(3)?,
                })
            })
            .transpose()
    }

    /// Mark a claimed domain verified (stamp `verified_at = now`).
    ///
    /// This is the **persistence hook**: the actual DNS-TXT lookup is the
    /// caller's responsibility (an ops tool or the CLI resolving the TXT
    /// record and matching it against [`OrgDomainRecord::txt_challenge`]).
    /// Keeping the lookup outside the database makes the capture flow
    /// offline-testable and lets a real resolver drop in without touching the
    /// store. Returns `Ok(false)` when no such domain is claimed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn verify_org_domain(&self, domain: &str) -> Result<bool> {
        let domain = domain.trim().to_lowercase();
        let n = self
            .backend
            .execute(
                "UPDATE org_domains SET verified_at = ?2 WHERE domain = ?1",
                &vals![domain, unix_now()],
            )
            .await?;
        Ok(n > 0)
    }

    /// Release a claimed domain (verified or not); returns whether a row was
    /// removed. Scoped by `org_id` so one org cannot drop another's claim.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_org_domain(&self, org_id: i64, domain: &str) -> Result<bool> {
        let domain = domain.trim().to_lowercase();
        let n = self
            .backend
            .execute(
                "DELETE FROM org_domains WHERE domain = ?1 AND org_id = ?2",
                &vals![domain, org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Resolve the org that owns a **verified** domain, if any.
    ///
    /// Only verified domains route logins; an unverified claim returns
    /// `Ok(None)` so a forged claim cannot capture another org's users.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_for_domain(&self, domain: &str) -> Result<Option<i64>> {
        let domain = domain.trim().to_lowercase();
        self.backend
            .query_opt(
                "SELECT org_id FROM org_domains WHERE domain = ?1 AND verified_at IS NOT NULL",
                &vals![domain],
            )
            .await
            .context("resolving org for verified domain")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Record an in-flight OIDC authorization-code request.
    ///
    /// Stores the opaque `state`, the `nonce` the id_token will be checked
    /// against, and the PKCE `code_verifier`, with an `expires_at` `ttl_secs`
    /// from now. The row is consumed exactly once at the callback by
    /// [`Database::take_oidc_flow`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a `state` collision.
    pub async fn create_oidc_flow(
        &self,
        state: &str,
        org_id: i64,
        nonce: &str,
        code_verifier: &str,
        redirect_after: Option<&str>,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO oidc_flows
             (state, org_id, nonce, code_verifier, redirect_after, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    state,
                    org_id,
                    nonce,
                    code_verifier,
                    redirect_after,
                    now,
                    now + ttl_secs
                ],
            )
            .await?;
        Ok(())
    }

    /// Consume an OIDC flow by its `state`, returning it exactly once.
    ///
    /// Deletes the row and returns it in one statement (`DELETE … RETURNING`),
    /// so a replayed or forged `state` finds nothing — the single-use,
    /// CSRF-defeating gate. Returns `Ok(None)` for an unknown, already-consumed,
    /// or expired flow.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn take_oidc_flow(&self, state: &str) -> Result<Option<OidcFlowRecord>> {
        let now = unix_now();
        // sqlite/postgres do the delete-and-read in one `DELETE … RETURNING`;
        // MySQL lacks it, so select-then-delete inside a transaction keeps the
        // single-use, CSRF-defeating gate (the delete claims the state).
        let row: Option<OidcFlowRecord> = if self.dialect() == Dialect::Mysql {
            // MySQL lacks `DELETE … RETURNING`; read the row, then DELETE — the
            // DELETE is the single-use claim gate. Only return the row if the
            // DELETE affected a row, so a concurrent consumer that already
            // claimed the state gets `None` here.
            let selected = self
                .backend
                .query_opt(
                    "SELECT state, org_id, nonce, code_verifier, redirect_after, expires_at
                     FROM oidc_flows WHERE state = ?1",
                    &vals![state],
                )
                .await?;
            if let Some(r) = selected {
                let claimed = self
                    .backend
                    .execute("DELETE FROM oidc_flows WHERE state = ?1", &vals![state])
                    .await?;
                if claimed > 0 {
                    Some(row_to_oidc_flow(&r)?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            self.backend
                .query_opt(
                    "DELETE FROM oidc_flows WHERE state = ?1
                     RETURNING state, org_id, nonce, code_verifier, redirect_after, expires_at",
                    &vals![state],
                )
                .await
                .context("consuming oidc flow by state")?
                .map(|row| row_to_oidc_flow(&row))
                .transpose()?
        };
        // Even though the row is deleted, an expired flow must not authenticate.
        match row {
            Some(flow) if now < flow.expires_at => Ok(Some(flow)),
            _ => Ok(None),
        }
    }

    // -- WebAuthn / passkeys (migration v17) --------------------------------

    /// Stage a WebAuthn ceremony challenge with a short TTL.
    ///
    /// `kind` is `"registration"` or `"assertion"`; `user_id` is the
    /// registering user for a registration ceremony, or `None` for a
    /// usernameless assertion ceremony (the user is resolved from the presented
    /// credential at verify). The challenge is consumed exactly once by
    /// [`Database::take_webauthn_challenge`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure (including a `challenge` collision,
    /// which cannot happen for a 256-bit random value in practice).
    pub async fn create_webauthn_challenge(
        &self,
        challenge: &str,
        user_id: Option<i64>,
        kind: &str,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = unix_now();
        self.backend
            .execute(
                "INSERT INTO webauthn_challenges (challenge, user_id, kind, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                &vals![challenge, user_id, kind, now, now + ttl_secs],
            )
            .await?;
        Ok(())
    }

    /// Consume a WebAuthn challenge by value *and kind*, returning it once.
    ///
    /// Deletes the row and returns it (`DELETE … RETURNING` on sqlite/postgres,
    /// a select-then-delete transaction on MySQL), so a replayed challenge finds
    /// nothing — the single-use, anti-replay gate. Returns `Ok(None)` for an
    /// unknown, already-consumed, expired, or wrong-`kind` challenge.
    ///
    /// The delete is scoped to **both** `challenge` and `kind`: a submission of
    /// a known challenge value through the *other* ceremony's endpoint (the
    /// wrong `kind`) matches no row and therefore deletes nothing, so it cannot
    /// consume a victim's in-flight challenge of the other kind. (A challenge is
    /// a 256-bit random value, so a cross-kind collision is implausible, but the
    /// kind-scoped delete makes the property explicit and robust.)
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn take_webauthn_challenge(
        &self,
        challenge: &str,
        kind: &str,
    ) -> Result<Option<WebauthnChallengeRecord>> {
        let now = unix_now();
        let row: Option<WebauthnChallengeRecord> = if self.dialect() == Dialect::Mysql {
            // mysql lacks DELETE ... RETURNING: read the row, then claim it via
            // the delete's rows-affected (sequential statements — mysql is never
            // the D1 target, which uses the single-statement RETURNING path).
            let selected = self
                .backend
                .query_opt(
                    "SELECT challenge, user_id, kind, expires_at
                     FROM webauthn_challenges WHERE challenge = ?1 AND kind = ?2",
                    &vals![challenge, kind],
                )
                .await?;
            if let Some(r) = selected {
                let n = self
                    .backend
                    .execute(
                        "DELETE FROM webauthn_challenges WHERE challenge = ?1 AND kind = ?2",
                        &vals![challenge, kind],
                    )
                    .await?;
                if n > 0 {
                    Some(row_to_webauthn_challenge(&r)?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            self.backend
                .query_opt(
                    "DELETE FROM webauthn_challenges WHERE challenge = ?1 AND kind = ?2
                     RETURNING challenge, user_id, kind, expires_at",
                    &vals![challenge, kind],
                )
                .await
                .context("consuming webauthn challenge")?
                .map(|row| row_to_webauthn_challenge(&row))
                .transpose()?
        };
        // The row is deleted (already kind-scoped), but an expired challenge
        // must still not authenticate.
        match row {
            Some(rec) if now < rec.expires_at => Ok(Some(rec)),
            _ => Ok(None),
        }
    }

    /// Persist a newly-registered WebAuthn credential, returning its id.
    ///
    /// `credential_id` is the base64url of the authenticator's raw credential
    /// id; `public_key` is the base64 of its COSE public key. `sign_count` is
    /// the authenticator's initial signature counter.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a `UNIQUE(credential_id)`
    /// violation when the same credential is registered twice.
    pub async fn add_webauthn_credential(
        &self,
        user_id: i64,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
        transports: Option<&str>,
        label: Option<&str>,
    ) -> Result<i64> {
        self.backend
            .execute_insert(
                "INSERT INTO webauthn_credentials
             (user_id, credential_id, public_key, sign_count, transports, label, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    transports,
                    label,
                    unix_now()
                ],
            )
            .await
    }

    /// Look up a WebAuthn credential by its base64url credential id.
    ///
    /// Returns `Ok(None)` when no credential with that id is registered (the
    /// assertion is for an unknown or de-registered passkey).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn webauthn_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredentialRecord>> {
        self.backend
            .query_opt(
                "SELECT id, user_id, credential_id, public_key, sign_count, transports,
                        label, created_at, last_used_at
                 FROM webauthn_credentials WHERE credential_id = ?1",
                &vals![credential_id],
            )
            .await
            .context("loading webauthn credential by id")?
            .map(|row| row_to_webauthn_credential(&row))
            .transpose()
    }

    /// List a user's registered WebAuthn credentials, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_user_credentials(
        &self,
        user_id: i64,
    ) -> Result<Vec<WebauthnCredentialRecord>> {
        self.backend
            .query(
                "SELECT id, user_id, credential_id, public_key, sign_count, transports,
                        label, created_at, last_used_at
                 FROM webauthn_credentials WHERE user_id = ?1
                 ORDER BY created_at DESC, id DESC",
                &vals![user_id],
            )
            .await
            .context("listing user webauthn credentials")?
            .iter()
            .map(row_to_webauthn_credential)
            .collect()
    }

    /// Delete one of a user's passkeys by its row id.
    ///
    /// Scoped to `user_id` so a caller can only remove their own credential.
    /// Returns `false` when no matching credential exists (already gone, or not
    /// owned by the user).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_webauthn_credential(&self, user_id: i64, id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM webauthn_credentials WHERE id = ?1 AND user_id = ?2",
                &vals![id, user_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Update a credential's stored signature counter.
    ///
    /// Called after a successful assertion to advance the monotonic counter the
    /// next assertion is checked against.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn update_credential_sign_count(&self, id: i64, sign_count: i64) -> Result<()> {
        self.backend
            .execute(
                "UPDATE webauthn_credentials SET sign_count = ?2 WHERE id = ?1",
                &vals![id, sign_count],
            )
            .await?;
        Ok(())
    }

    /// Stamp a credential's `last_used_at` to now.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn touch_credential(&self, id: i64) -> Result<()> {
        self.backend
            .execute(
                "UPDATE webauthn_credentials SET last_used_at = ?2 WHERE id = ?1",
                &vals![id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Reconcile an OIDC identity to a hub user, JIT-provisioning if allowed.
    ///
    /// Identities are keyed on `(issuer, subject)` — never bare email — so an
    /// IdP that recycles an email address can never silently take over another
    /// user's account. Resolution, in order:
    ///
    /// 1. An existing `(issuer, subject)` identity resolves to its user
    ///    ([`IdentityLink::Existing`]); its `email`/`last_login` are refreshed.
    /// 2. Otherwise, when `email` is IdP-*verified* and its domain is captured
    ///    by `org_id`, the identity links to the existing user with that email
    ///    ([`IdentityLink::Linked`]).
    /// 3. Otherwise, when `allow_jit`, a *fresh* user and identity are created
    ///    ([`IdentityLink::Created`]) — JIT never reconciles onto an existing
    ///    user by email. If the asserted email already belongs to a user, the
    ///    login is refused (the only safe email→user link is step 2's verified
    ///    captured-domain path); a self-hosted IdP could otherwise assert a
    ///    victim's address and graft onto their account.
    ///
    /// Returns `Ok(None)` when no identity exists, no auto-link applies, and
    /// `allow_jit` is false — the caller rejects the login.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or when `allow_jit` JIT would
    /// collide onto a pre-existing account by email (see step 3) — the caller
    /// maps the error to a denied login.
    pub async fn link_or_create_identity(
        &self,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
        email_verified: bool,
        org_id: i64,
        allow_jit: bool,
    ) -> Result<Option<IdentityLink>> {
        let now = unix_now();
        // 1. Existing identity.
        if let Some(user_id) = self.identity_user(issuer, subject).await? {
            self.backend
                .execute(
                    "UPDATE user_identities SET email = ?3, last_login = ?4
                 WHERE issuer = ?1 AND subject = ?2",
                    &vals![issuer, subject, email, now],
                )
                .await?;
            return Ok(Some(IdentityLink::Existing(user_id)));
        }
        // 2. Auto-link a verified email on a captured domain to an existing user.
        if email_verified {
            if let Some(addr) = email {
                let domain = addr.rsplit_once('@').map(|(_, d)| d.to_lowercase());
                let captured = match &domain {
                    Some(d) => self.org_for_domain(d).await? == Some(org_id),
                    None => false,
                };
                if captured {
                    if let Some(user_id) = self.user_by_email(addr).await? {
                        self.insert_identity(issuer, subject, user_id, email, now)
                            .await?;
                        return Ok(Some(IdentityLink::Linked(user_id)));
                    }
                }
            }
        }
        // 3. JIT-provision a brand-new user + identity.
        if !allow_jit {
            return Ok(None);
        }
        // A user needs an email (the users table requires a unique address);
        // synthesize a stable, non-colliding pseudo-address from the identity
        // when the IdP supplies none, so JIT never fails for a bare profile.
        let user_email = match email {
            Some(addr) => addr.to_string(),
            None => format!("{subject}@{}", issuer_host(issuer)),
        };
        // JIT must *create* a user — never reconcile onto an existing one by
        // email. A self-hosted IdP can assert any address, so grafting a new
        // `(iss, sub)` onto a pre-existing account by matching email is an
        // account-takeover primitive: the safe email→user link is step 2's
        // verified-domain path alone. If the asserted email already belongs to
        // a user, refuse — the account holder must capture and verify the
        // domain to link the IdP, not have JIT silently adopt it.
        if self.user_by_email(&user_email).await?.is_some() {
            bail!(
                "an account with this email already exists and cannot be \
                 just-in-time linked; verify the email's domain to link it"
            );
        }
        let user_id = self.create_user(&user_email, None).await?;
        self.insert_identity(issuer, subject, user_id, email, now)
            .await?;
        Ok(Some(IdentityLink::Created(user_id)))
    }

    /// The user id linked to an `(issuer, subject)` identity, if any.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn identity_user(&self, issuer: &str, subject: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT user_id FROM user_identities WHERE issuer = ?1 AND subject = ?2",
                &vals![issuer, subject],
            )
            .await
            .context("loading identity user")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Insert a new `(issuer, subject)` identity for a user.
    async fn insert_identity(
        &self,
        issuer: &str,
        subject: &str,
        user_id: i64,
        email: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO user_identities (user_id, issuer, subject, email, last_login)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                &vals![user_id, issuer, subject, email, now],
            )
            .await?;
        Ok(())
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
    pub async fn set_registry_visibility(&self, registry_id: i64, visibility: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE registries SET visibility = ?2 WHERE id = ?1",
                &vals![registry_id, visibility],
            )
            .await?;
        Ok(())
    }

    /// Set a registry's crawl policy by slug.
    ///
    /// Writes the `crawl_policy` column directly (the policy string is validated
    /// at the CLI / API / console boundary via
    /// [`CrawlPolicy::parse`](crate::crawl::CrawlPolicy::parse)). The generated
    /// `robots.txt` reflects the change on the next read.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure. A slug that names no registry is a
    /// silent no-op (zero rows updated), matching SQL `UPDATE` semantics.
    pub async fn set_registry_crawl_policy(&self, slug: &str, policy: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE registries SET crawl_policy = ?2 WHERE slug = ?1",
                &vals![slug, policy],
            )
            .await?;
        Ok(())
    }

    /// Set or clear a registry's custom `llms.txt` body by slug.
    ///
    /// A `Some(body)` stores an operator-authored document served verbatim; a
    /// `None` clears the override so the hub serves the document generated from
    /// the registry's packages and channels instead.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure. A slug that names no registry is a
    /// silent no-op (zero rows updated).
    pub async fn set_registry_llms_txt(&self, slug: &str, body: Option<&str>) -> Result<()> {
        self.backend
            .execute(
                "UPDATE registries SET llms_txt_body = ?2 WHERE slug = ?1",
                &vals![slug, body],
            )
            .await?;
        Ok(())
    }

    /// The instance-root crawl policy (defaulting to allow-all when unset).
    ///
    /// Reads the `root_crawl_policy` instance-config key and parses it leniently
    /// through [`CrawlPolicy::parse_or_default`](crate::crawl::CrawlPolicy::parse_or_default)
    /// so a malformed stored value never breaks the generated root `robots.txt`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn root_crawl_policy(&self) -> Result<crate::crawl::CrawlPolicy> {
        Ok(self
            .instance_config_get("root_crawl_policy")
            .await?
            .map(|v| crate::crawl::CrawlPolicy::parse_or_default(&v))
            .unwrap_or_default())
    }

    /// Set the instance-root crawl policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_root_crawl_policy(&self, policy: crate::crawl::CrawlPolicy) -> Result<()> {
        self.instance_config_set("root_crawl_policy", policy.as_str())
            .await
    }

    /// The operator-authored instance-root `robots.txt` override, if any.
    ///
    /// `None` means the hub serves the document generated from
    /// [`Self::root_crawl_policy`] instead of a custom body.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn root_robots_body(&self) -> Result<Option<String>> {
        self.instance_config_get("root_robots_body").await
    }

    /// Set or clear the instance-root `robots.txt` override.
    ///
    /// A `Some(body)` is served verbatim; a `None` clears the override (an empty
    /// `robots.txt` value is stored as the empty string and so still counts as a
    /// custom override — pass `None` to revert to the generated document).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_root_robots_body(&self, body: Option<&str>) -> Result<()> {
        match body {
            Some(value) => self.instance_config_set("root_robots_body", value).await,
            None => self.instance_config_delete("root_robots_body").await,
        }
    }

    /// The operator-authored instance-root `llms.txt` override, if any.
    ///
    /// `None` means the hub serves the document generated from the instance's
    /// public registries instead of a custom body.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn root_llms_body(&self) -> Result<Option<String>> {
        self.instance_config_get("root_llms_body").await
    }

    /// Set or clear the instance-root `llms.txt` override.
    ///
    /// A `Some(body)` is served verbatim; a `None` clears the override so the
    /// generated document is served instead.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_root_llms_body(&self, body: Option<&str>) -> Result<()> {
        match body {
            Some(value) => self.instance_config_set("root_llms_body", value).await,
            None => self.instance_config_delete("root_llms_body").await,
        }
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
    pub async fn record_audit(
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
        // Sanitize the caller-controlled text fields against log/stored
        // injection: `actor_label` (token/session labels), `scope` (registry and
        // org slugs), and `detail` (free-form context, often a URL or name) can
        // carry attacker-influenced strings. Stripping embedded C0 controls here
        // — the single audit choke point — protects every caller without
        // touching the dozens of call sites. `actor_kind`/`action` are
        // hub-internal enum literals and are recorded verbatim.
        let actor_label = sanitize_log_text(actor_label);
        let scope = sanitize_log_text(scope);
        let detail = detail.map(sanitize_log_text);
        self.backend
            .execute_insert(
                "INSERT INTO audit_log
             (change_id, actor_kind, actor_id, actor_label, action, scope,
              result_commit, result_tag, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &vals![
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
            )
            .await
    }

    /// List audit entries at or below `scope`, newest first.
    ///
    /// Returns entries whose recorded `scope` is `scope` or any descendant
    /// of it (so an org-scoped query surfaces actions on its registries),
    /// using the same segment-boundary containment as
    /// [`crate::domain::Scope::contains`]. The root scope (`""`) lists every
    /// entry instance-wide.
    ///
    /// The `audit_log` is append-only and grows without bound, so the DB read
    /// is capped at `MAX_AUDIT_SCAN` **most-recent** rows before the
    /// scope filter is applied in Rust: a single request can never materialize
    /// the whole table. Scope-filtered results are therefore drawn from the
    /// most recent `MAX_AUDIT_SCAN` entries — ample for the console's paged
    /// audit view and the `ListAudit` RPC, which surface recent activity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_audit(&self, scope: &str) -> Result<Vec<AuditRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, actor_kind, actor_label, action, scope,
                    result_commit, result_tag, detail, created_at
             FROM audit_log ORDER BY id DESC LIMIT ?1",
                &vals![MAX_AUDIT_SCAN],
            )
            .await?;
        let target = crate::domain::Scope::parse(scope);
        let mut out = Vec::new();
        for row in &rows {
            let entry = AuditRow {
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
            };
            if target.contains(&crate::domain::Scope::parse(&entry.scope)) {
                out.push(entry);
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
    pub async fn create_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO config_changesets
             (change_id, actor_kind, actor_id, actor_label, scope, status,
              summary, created_at, applied_at, reverted_by_change_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'draft', ?6, ?7, NULL, NULL)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    scope,
                    summary,
                    unix_now(),
                ],
            )
            .await?;
        Ok(())
    }

    /// Create a git-backed change-request change-set in `draft` status.
    ///
    /// Identical to [`Self::create_changeset`] but additionally records the
    /// draft ref (`refs/hub/changes/<change_id>`) the hub wrote and the signed
    /// draft-commit oid it points at (RFC-0004 "Configuration management",
    /// git-backed path). These columns are `NULL` for SQL-only change-sets;
    /// their presence is what marks a change-set as a git-backed change request
    /// the console and `apr change` surface and promote.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a primary-key collision
    /// on `change_id`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_git_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
        git_ref: &str,
        git_commit: &str,
        title: Option<&str>,
        body: Option<&str>,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO config_changesets
             (change_id, actor_kind, actor_id, actor_label, scope, status,
              summary, created_at, applied_at, reverted_by_change_id, git_ref, git_commit,
              title, body)
             VALUES (?1, ?2, ?3, ?4, ?5, 'draft', ?6, ?7, NULL, NULL, ?8, ?9, ?10, ?11)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    scope,
                    summary,
                    unix_now(),
                    git_ref,
                    git_commit,
                    title,
                    body,
                ],
            )
            .await?;
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
    pub async fn add_revision(
        &self,
        change_id: &str,
        object_type: &str,
        object_id: &str,
        op: &str,
        old_json: Option<&str>,
        new_json: Option<&str>,
    ) -> Result<i64> {
        let seq: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM config_revisions WHERE change_id = ?1",
                &vals![change_id],
            )
            .await?
            .context("count query returned no row")?
            .get(0)?;
        self.backend
            .execute(
                "INSERT INTO config_revisions
             (change_id, object_type, object_id, op, old_json, new_json, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    change_id,
                    object_type,
                    object_id,
                    op,
                    old_json,
                    new_json,
                    seq
                ],
            )
            .await?;
        Ok(seq)
    }

    /// Load one change-set summary by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn changeset(&self, change_id: &str) -> Result<Option<ChangesetRow>> {
        self.backend
            .query_opt(
                &format!("SELECT {CHANGESET_COLUMNS} FROM config_changesets WHERE change_id = ?1"),
                &vals![change_id],
            )
            .await
            .context("loading changeset by id")?
            .map(|row| row_to_changeset(&row))
            .transpose()
    }

    /// List a change-set's revisions in `seq` order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_revisions(&self, change_id: &str) -> Result<Vec<RevisionRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, object_type, object_id, op, old_json, new_json, seq
             FROM config_revisions WHERE change_id = ?1 ORDER BY seq",
                &vals![change_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
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
            })
            .collect()
    }

    /// Withdraw an open draft change request (close without merging).
    ///
    /// Stamps `closed_at = now` on a change-set that is still `draft` and not
    /// already closed. This is hub-side advisory metadata only — it never
    /// touches `status` or the git ref, so a closed change can still be promoted
    /// by `apr change merge` (the indexer would then flip it to `applied`).
    /// Idempotent: closing an already-closed or non-draft row affects no rows.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn close_changeset(&self, change_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE config_changesets SET closed_at = ?2
             WHERE change_id = ?1 AND status = 'draft' AND closed_at IS NULL",
                &vals![change_id, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Reopen a closed change request, clearing its `closed_at` stamp.
    ///
    /// Only affects a `draft` row (a merged or reverted change-set is terminal
    /// and cannot be reopened). Clearing `closed_at` re-arms the indexer's
    /// auto-merge detection. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn reopen_changeset(&self, change_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE config_changesets SET closed_at = NULL
             WHERE change_id = ?1 AND status = 'draft'",
                &vals![change_id],
            )
            .await?;
        Ok(())
    }

    /// Append a discussion comment to a change request.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key violation
    /// when `change_id` is unknown.
    pub async fn add_change_comment(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        body: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO change_comments
             (change_id, actor_kind, actor_id, actor_label, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    body,
                    unix_now()
                ],
            )
            .await?;
        Ok(())
    }

    /// List a change request's discussion comments, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_change_comments(&self, change_id: &str) -> Result<Vec<ChangeCommentRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, actor_kind, actor_id, actor_label, body, created_at
             FROM change_comments WHERE change_id = ?1 ORDER BY id",
                &vals![change_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ChangeCommentRow {
                    id: row.get(0)?,
                    change_id: row.get(1)?,
                    actor_kind: row.get(2)?,
                    actor_id: row.get(3)?,
                    actor_label: row.get(4)?,
                    body: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .collect()
    }

    /// Record an advisory review (`approve` or `request_changes`) on a change.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key violation
    /// when `change_id` is unknown.
    pub async fn add_change_review(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        verdict: &str,
        body: Option<&str>,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO change_reviews
             (change_id, actor_kind, actor_id, actor_label, verdict, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &vals![
                    change_id,
                    actor_kind,
                    actor_id,
                    actor_label,
                    verdict,
                    body,
                    unix_now()
                ],
            )
            .await?;
        Ok(())
    }

    /// List a change request's advisory reviews, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_change_reviews(&self, change_id: &str) -> Result<Vec<ChangeReviewRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, actor_kind, actor_id, actor_label, verdict, body, created_at
             FROM change_reviews WHERE change_id = ?1 ORDER BY id",
                &vals![change_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ChangeReviewRow {
                    id: row.get(0)?,
                    change_id: row.get(1)?,
                    actor_kind: row.get(2)?,
                    actor_id: row.get(3)?,
                    actor_label: row.get(4)?,
                    verdict: row.get(5)?,
                    body: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .collect()
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
    pub async fn set_changeset_status(
        &self,
        change_id: &str,
        status: &str,
        applied_at: Option<i64>,
        reverted_by: Option<&str>,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE config_changesets
             SET status = ?2,
                 applied_at = COALESCE(?3, applied_at),
                 reverted_by_change_id = COALESCE(?4, reverted_by_change_id)
             WHERE change_id = ?1",
                &vals![change_id, status, applied_at, reverted_by],
            )
            .await?;
        Ok(())
    }

    /// Mark a git-backed change request applied, linking the promoting commit.
    ///
    /// Called by the indexer when it re-walks a registry surface and finds the
    /// verified HEAD commit carries an `AOS-Change-Id: <change_id>` trailer
    /// matching a `draft` change request (RFC-0004 "Configuration management",
    /// cross-referencing): the maintainer's `apr change merge` re-signed and
    /// pushed the draft, so the change request is now live. Stamps
    /// `status = 'applied'`, `applied_at = now`, and rewrites `git_commit` to
    /// the *promoting* (roster-signed) commit oid — the draft commit is
    /// superseded. Idempotent: re-marking an already-applied row is a harmless
    /// no-op on a status-guarded `UPDATE`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_changeset_applied_commit(
        &self,
        change_id: &str,
        commit_oid: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "UPDATE config_changesets
             SET status = 'applied', applied_at = ?2, git_commit = ?3
             WHERE change_id = ?1 AND status = 'draft'",
                &vals![change_id, unix_now(), commit_oid],
            )
            .await?;
        Ok(())
    }

    /// Whether an audit row already records `result_commit`.
    ///
    /// The indexer synthesizes one `external` audit entry per out-of-band
    /// (direct-publish) commit it observes; this check keeps that synthesis
    /// idempotent across re-indexes, so the same commit is never audited twice
    /// (RFC-0004 "Configuration management", cross-referencing).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn audit_exists_for_commit(&self, action: &str, result_commit: &str) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM audit_log WHERE action = ?1 AND result_commit = ?2 LIMIT 1",
                &vals![action, result_commit],
            )
            .await?
            .is_some())
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
    pub async fn apply_changeset<F>(&self, change_id: &str, mut apply_fn: F) -> Result<()>
    where
        F: for<'r> FnMut(
            &'r RevisionRow,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'r>>,
    {
        let revisions = self.list_revisions(change_id).await?;
        for revision in &revisions {
            apply_fn(revision).await?;
        }
        self.mark_changeset_applied(change_id).await?;
        Ok(())
    }

    /// Stamps a change-set `applied`, recording the current time.
    ///
    /// This is the single status write that follows a change-set's
    /// per-revision live mutations; it is atomic on its own, so no transaction
    /// is needed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_changeset_applied(&self, change_id: &str) -> Result<()> {
        self.backend
            .execute(
                "UPDATE config_changesets SET status = 'applied', applied_at = ?2
             WHERE change_id = ?1",
                &vals![change_id, unix_now()],
            )
            .await?;
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
    pub async fn list_changesets(&self, scope: &str) -> Result<Vec<ChangesetRow>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {CHANGESET_COLUMNS} FROM config_changesets \
                 ORDER BY created_at DESC, change_id DESC"
                ),
                &[],
            )
            .await?;
        let target = crate::domain::Scope::parse(scope);
        let mut out = Vec::new();
        for row in &rows {
            let changeset = row_to_changeset(row)?;
            if target.contains(&crate::domain::Scope::parse(&changeset.scope)) {
                out.push(changeset);
            }
        }
        Ok(out)
    }

    // -- webhooks -----------------------------------------------------------

    /// Create a webhook subscription under an org; returns its id.
    ///
    /// `events` is the set of event-type strings the hook subscribes to (an
    /// empty slice subscribes to *all* events). `secret` is the shared HMAC
    /// secret the [`X-AOS-Signature`](crate::webhook) header is computed under;
    /// it is stored as plaintext because the subscriber needs the same secret
    /// to verify deliveries.
    ///
    /// `url` is validated against the SSRF guard
    /// ([`crate::url_guard::is_safe_remote_url`]) — the delivery worker `POST`s to
    /// it from inside the hub network, so a loopback/link-local/private or
    /// non-`http(s)` target is rejected here, just as mirror upstreams and
    /// frontend domains are.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` fails the SSRF guard, or on database
    /// failure.
    pub async fn create_webhook(
        &self,
        org_id: i64,
        url: &str,
        secret: &str,
        events: &[String],
    ) -> Result<i64> {
        crate::url_guard::is_safe_remote_url(url)
            .with_context(|| format!("rejecting webhook url '{url}'"))?;
        self.backend
            .execute_insert(
                "INSERT INTO webhooks (org_id, url, secret, events, active, created_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                &vals![
                    org_id,
                    url,
                    secret,
                    serde_json::to_string(events)?,
                    unix_now()
                ],
            )
            .await
    }

    /// List an org's webhook subscriptions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_webhooks(&self, org_id: i64) -> Result<Vec<WebhookRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, url, secret, events, active, created_at
             FROM webhooks WHERE org_id = ?1 ORDER BY id",
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_webhook).collect()
    }

    /// Load one webhook by id, regardless of org.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn webhook(&self, id: i64) -> Result<Option<WebhookRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, url, secret, events, active, created_at
                 FROM webhooks WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading webhook by id")?
            .map(|row| row_to_webhook(&row))
            .transpose()
    }

    /// Delete a webhook (and, by cascade, its deliveries); returns whether a
    /// row was removed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_webhook(&self, id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute("DELETE FROM webhooks WHERE id = ?1", &vals![id])
            .await?;
        Ok(n > 0)
    }

    /// Enable or disable a webhook; returns whether a row was updated.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_webhook_active(&self, id: i64, active: bool) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE webhooks SET active = ?2 WHERE id = ?1",
                &vals![id, active],
            )
            .await?;
        Ok(n > 0)
    }

    /// Enqueue one pending delivery of `event`/`payload` to a webhook.
    ///
    /// The row starts `pending` with `attempts = 0` and `next_attempt_at`
    /// equal to now, so the delivery worker picks it up on its next sweep.
    /// Returns the delivery id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn enqueue_delivery(
        &self,
        webhook_id: i64,
        event: &str,
        payload: &str,
    ) -> Result<i64> {
        let now = unix_now();
        self.backend
            .execute_insert(
                "INSERT INTO webhook_deliveries
             (webhook_id, event, payload, status, attempts, created_at, next_attempt_at)
             VALUES (?1, ?2, ?3, 'pending', 0, ?4, ?4)",
                &vals![webhook_id, event, payload, now],
            )
            .await
    }

    /// List deliveries that are due: `pending` and whose `next_attempt_at` is
    /// at or before `now`, joined with their (active) webhook's URL and secret,
    /// oldest first.
    ///
    /// Deliveries whose webhook has since been deleted or deactivated are
    /// excluded — a disabled subscription stops receiving without leaving its
    /// queued rows stuck.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_deliveries(&self, now: i64) -> Result<Vec<DueDelivery>> {
        let rows = self
            .backend
            .query(
                "SELECT d.id, d.webhook_id, d.event, d.payload, d.attempts, w.url, w.secret
             FROM webhook_deliveries d
             JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 AND w.active = 1
             ORDER BY d.id",
                &vals![now],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(DueDelivery {
                    id: row.get(0)?,
                    webhook_id: row.get(1)?,
                    event: row.get(2)?,
                    payload: row.get(3)?,
                    attempts: row.get(4)?,
                    url: row.get(5)?,
                    secret: row.get(6)?,
                })
            })
            .collect()
    }

    /// Record the outcome of one delivery attempt.
    ///
    /// `status` is the new lifecycle state (`delivered`, `failed`, or
    /// `pending` for a scheduled retry), `response_code` the observed HTTP
    /// status (or `None` when the request never completed), `attempts` the new
    /// attempt count, and `next_attempt_at` the earliest retry time for a row
    /// left `pending`. `delivered_at` is stamped iff `status == "delivered"`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_delivery(
        &self,
        id: i64,
        status: &str,
        response_code: Option<i64>,
        attempts: i64,
        next_attempt_at: Option<i64>,
    ) -> Result<()> {
        let delivered_at = (status == "delivered").then(unix_now);
        self.backend
            .execute(
                "UPDATE webhook_deliveries
             SET status = ?2, response_code = ?3, attempts = ?4,
                 next_attempt_at = ?5, delivered_at = ?6
             WHERE id = ?1",
                &vals![
                    id,
                    status,
                    response_code,
                    attempts,
                    next_attempt_at,
                    delivered_at
                ],
            )
            .await?;
        Ok(())
    }

    /// Count webhook deliveries grouped by lifecycle status.
    ///
    /// Returns `(pending, delivered, failed)` totals across all webhooks,
    /// powering the `/metrics` gauges.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delivery_status_counts(&self) -> Result<(u64, u64, u64)> {
        let mut counts = [0u64; 3];
        for (slot, status) in counts.iter_mut().zip(["pending", "delivered", "failed"]) {
            *slot = self
                .backend
                .query_opt(
                    "SELECT COUNT(*) FROM webhook_deliveries WHERE status = ?1",
                    &vals![status],
                )
                .await?
                .context("count query returned no row")?
                .get::<u64>(0)?;
        }
        Ok((counts[0], counts[1], counts[2]))
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
     org_id, project_path, visibility, storage_binding_id, prefix, hosted_key_id, \
     crawl_policy, llms_txt_body";

/// A managed cache (system-of-record row) — a hub-hosted Nix binary cache.
///
/// A cache is a first-class sibling of a [`RegistryRecord`]: an org-scoped (or
/// instance-level) surface backed by a storage binding plus a `prefix`,
/// optionally signed by a hosted key, and exposed through one or more
/// frontends. Where a registry serves a git wire surface, a cache serves a Nix
/// binary cache (`nix-cache-info` + content-addressed NARs + Ed25519-signed
/// `.narinfo`). See RFC-0004 `11-caches`.
#[derive(Debug, Clone)]
pub struct Cache {
    /// Database id.
    pub id: i64,
    /// Owning org, or `None` for an instance-level standalone cache.
    pub org_id: Option<i64>,
    /// URL slug the cache is served under (globally unique).
    pub slug: String,
    /// Human-readable display name.
    pub name: String,
    /// Storage binding holding this cache's NAR/narinfo surface, or `None` to
    /// use the deployment's default storage (rooted by [`prefix`](Self::prefix)),
    /// exactly as a binding-less registry does.
    pub storage_binding_id: Option<i64>,
    /// Sub-path under the binding root where this cache's surface lives.
    pub prefix: String,
    /// Hosted Ed25519 key signing `.narinfo`, or `None` for an unsigned cache.
    pub hosted_key_id: Option<i64>,
    /// Access scope: `public` | `internal` | `private`.
    pub visibility: String,
    /// `nix-cache-info` `Priority` (substituter ordering; lower = preferred).
    pub priority: i64,
    /// Default NAR compression (`zstd` | `xz` | `none`).
    pub compression: String,
    /// `nix-cache-info` `WantMassQuery` flag.
    pub want_mass_query: bool,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Soft-delete tombstone (unix seconds), or `None` while live.
    pub deleted_at: Option<i64>,
    /// When a soft-deleted cache becomes eligible for hard purge.
    pub purge_after: Option<i64>,
}

/// A registry⇄cache association (many-to-many; both flags independent).
#[derive(Debug, Clone)]
pub struct CacheRegistryLink {
    /// The linked cache.
    pub cache_id: i64,
    /// The linked registry.
    pub registry_id: i64,
    /// The registry's live store paths pin GC roots in this cache.
    pub roots_packages: bool,
    /// This cache's URL is advertised in the registry's cache stack.
    pub advertised: bool,
    /// Link creation time (unix seconds).
    pub created_at: i64,
}

/// A cache's garbage-collection retention policy (`NULL` field = unlimited).
#[derive(Debug, Clone)]
pub struct CacheGcPolicy {
    /// The cache this policy governs.
    pub cache_id: i64,
    /// Soft byte cap that triggers LRU eviction of unrooted objects.
    pub max_bytes: Option<i64>,
    /// Soft object-count cap that triggers LRU eviction of unrooted objects.
    pub max_objects: Option<i64>,
    /// Grace period before an unreachable object is swept (seconds).
    pub ttl_unreferenced_secs: Option<i64>,
    /// Per linked registry, keep the closures of the N most-recent releases.
    pub keep_release_versions: Option<i64>,
    /// Always retain live channel-frontier closures.
    pub keep_channel_frontier: bool,
    /// Scheduled GC cadence (seconds), or `None` for on-demand only.
    pub schedule_secs: Option<i64>,
    /// Last policy update (unix seconds).
    pub updated_at: i64,
}

/// A garbage-collection root pinning a store path (and its closure) in a cache.
#[derive(Debug, Clone)]
pub struct CacheGcRoot {
    /// Database id.
    pub id: i64,
    /// The cache this root belongs to.
    pub cache_id: i64,
    /// The rooted store-path hash component.
    pub store_hash: String,
    /// `manual` | `release` | `channel` | `package_version` | `derived`.
    pub root_kind: String,
    /// Provenance for a derived root (e.g. `registry:42:channel:stable`); `""` for manual.
    pub root_ref: String,
    /// Manual-pin deadline (unix seconds); `None` = unlimited. Past it, the pin stops rooting.
    pub expires_at: Option<i64>,
    /// Root creation time (unix seconds).
    pub created_at: i64,
}

/// One narinfo-indexed object in a cache (rebuildable from the bucket).
#[derive(Debug, Clone)]
pub struct CacheObject {
    /// The owning cache.
    pub cache_id: i64,
    /// Store-path hash component (the `.narinfo` key).
    pub store_hash: String,
    /// Store-path name component (`<hash>-<name>`), for search/display.
    pub store_name: String,
    /// Relative URL of the NAR under the cache surface (`nar/<file-hash>.nar.<ext>`).
    pub nar_url: String,
    /// `NarHash` (sha256 of the uncompressed NAR).
    pub nar_hash: String,
    /// `NarSize` (uncompressed NAR byte length).
    pub nar_size: i64,
    /// `FileHash` (sha256 of the compressed NAR; the content address).
    pub file_hash: String,
    /// `FileSize` (compressed NAR byte length on disk).
    pub file_size: i64,
    /// NAR compression (`zstd` | `xz` | `none`).
    pub compression: String,
    /// `Deriver`, when known.
    pub deriver: Option<String>,
    /// Closure edges: the store hashes this path references.
    pub refs: Vec<String>,
    /// `Sig` line (`<keyname>:<base64>`), when signed.
    pub sig: Option<String>,
    /// `CA` (content-addressed derivation marker), when present.
    pub ca: Option<String>,
    /// Upload/index time (unix seconds).
    pub uploaded_at: i64,
    /// Last observed access (unix seconds), for LRU; `None` until first tap.
    pub last_accessed_at: Option<i64>,
}

/// A cache's running storage totals.
#[derive(Debug, Clone, Default)]
pub struct CacheUsage {
    /// Sum of `file_size` across the cache's objects.
    pub used_bytes: i64,
    /// Number of indexed objects.
    pub object_count: i64,
    /// Last recompute time (unix seconds).
    pub updated_at: i64,
}

/// Instance-wide cache aggregates for the `/metrics` exposition.
///
/// Computed across all *non-soft-deleted* caches in a few aggregate queries
/// (see [`Database::cache_metrics`]) rather than per-cache, so a scrape stays
/// cheap regardless of cache count.
#[derive(Debug, Clone, Default)]
pub struct CacheMetrics {
    /// Number of live (not soft-deleted) managed caches.
    pub cache_count: i64,
    /// Total indexed objects across live caches.
    pub object_count: i64,
    /// Total `file_size` bytes across live caches' objects.
    pub used_bytes: i64,
    /// Lifetime count of completed GC runs (`status = 'ok'`).
    pub gc_runs_ok: i64,
    /// Lifetime count of failed GC runs (`status = 'failed'`).
    pub gc_runs_failed: i64,
    /// Lifetime bytes reclaimed by completed GC runs.
    pub gc_freed_bytes: i64,
}

/// A past (or in-flight) garbage-collection run over a cache.
#[derive(Debug, Clone)]
pub struct CacheGcRun {
    /// Database id.
    pub id: i64,
    /// The cache this run swept.
    pub cache_id: i64,
    /// Start time (unix seconds).
    pub started_at: i64,
    /// Completion time (unix seconds), or `None` while running.
    pub finished_at: Option<i64>,
    /// `running` | `ok` | `failed`.
    pub status: String,
    /// Failure detail when `status = failed`.
    pub error: Option<String>,
    /// Objects examined.
    pub scanned: i64,
    /// Objects retained (reachable from a live root).
    pub retained: i64,
    /// Objects deleted.
    pub deleted_objects: i64,
    /// Bytes reclaimed.
    pub freed_bytes: i64,
}

/// `caches` columns in the canonical order [`row_to_cache`] expects.
const CACHE_COLUMNS: &str = "id, org_id, slug, name, storage_binding_id, prefix, \
     hosted_key_id, visibility, priority, compression, want_mass_query, \
     created_at, deleted_at, purge_after";

/// `cache_objects` columns in the canonical order [`row_to_cache_object`] expects.
const CACHE_OBJECT_COLUMNS: &str = "cache_id, store_hash, store_name, nar_url, nar_hash, \
     nar_size, file_hash, file_size, compression, deriver, refs, sig, ca, \
     uploaded_at, last_accessed_at";

/// Map a `caches` row (column order [`CACHE_COLUMNS`]) into a [`Cache`].
fn row_to_cache(row: &Row) -> Result<Cache> {
    Ok(Cache {
        id: row.get(0)?,
        org_id: row.get(1)?,
        slug: row.get(2)?,
        name: row.get(3)?,
        storage_binding_id: row.get(4)?,
        prefix: row.get(5)?,
        hosted_key_id: row.get(6)?,
        visibility: row.get(7)?,
        priority: row.get(8)?,
        compression: row.get(9)?,
        want_mass_query: row.get(10)?,
        created_at: row.get(11)?,
        deleted_at: row.get(12)?,
        purge_after: row.get(13)?,
    })
}

/// Map a `cache_objects` row (column order [`CACHE_OBJECT_COLUMNS`]) into a [`CacheObject`].
fn row_to_cache_object(row: &Row) -> Result<CacheObject> {
    let refs_json: String = row.get(10)?;
    Ok(CacheObject {
        cache_id: row.get(0)?,
        store_hash: row.get(1)?,
        store_name: row.get(2)?,
        nar_url: row.get(3)?,
        nar_hash: row.get(4)?,
        nar_size: row.get(5)?,
        file_hash: row.get(6)?,
        file_size: row.get(7)?,
        compression: row.get(8)?,
        deriver: row.get(9)?,
        // Strict (unlike registry trust-keys): a corrupt closure must not silently
        // read as empty — a GC sweep would treat a NAR's real references as
        // collectable. Only ever written via `serde_json::to_string`, so a parse
        // failure is genuine corruption worth surfacing.
        refs: serde_json::from_str(&refs_json).context("parsing cache_objects.refs")?,
        sig: row.get(11)?,
        ca: row.get(12)?,
        uploaded_at: row.get(13)?,
        last_accessed_at: row.get(14)?,
    })
}

/// Map a `cache_registry_links` row (`cache_id, registry_id, roots_packages, advertised, created_at`).
fn row_to_cache_link(row: &Row) -> Result<CacheRegistryLink> {
    Ok(CacheRegistryLink {
        cache_id: row.get(0)?,
        registry_id: row.get(1)?,
        roots_packages: row.get(2)?,
        advertised: row.get(3)?,
        created_at: row.get(4)?,
    })
}

/// Map a `cache_gc_policy` row into a [`CacheGcPolicy`].
fn row_to_cache_gc_policy(row: &Row) -> Result<CacheGcPolicy> {
    Ok(CacheGcPolicy {
        cache_id: row.get(0)?,
        max_bytes: row.get(1)?,
        max_objects: row.get(2)?,
        ttl_unreferenced_secs: row.get(3)?,
        keep_release_versions: row.get(4)?,
        keep_channel_frontier: row.get(5)?,
        schedule_secs: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

/// Map a `cache_gc_roots` row into a [`CacheGcRoot`].
fn row_to_cache_gc_root(row: &Row) -> Result<CacheGcRoot> {
    Ok(CacheGcRoot {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        store_hash: row.get(2)?,
        root_kind: row.get(3)?,
        root_ref: row.get(4)?,
        expires_at: row.get(5)?,
        created_at: row.get(6)?,
    })
}

/// Map a `cache_gc_runs` row into a [`CacheGcRun`].
fn row_to_cache_gc_run(row: &Row) -> Result<CacheGcRun> {
    Ok(CacheGcRun {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        status: row.get(4)?,
        error: row.get(5)?,
        scanned: row.get(6)?,
        retained: row.get(7)?,
        deleted_objects: row.get(8)?,
        freed_bytes: row.get(9)?,
    })
}

fn row_to_registry(row: &Row) -> Result<RegistryRecord> {
    let trust_json: String = row.get(3)?;
    Ok(RegistryRecord {
        id: row.get(0)?,
        slug: row.get(1)?,
        source_url: row.get(2)?,
        trust_keys: serde_json::from_str(&trust_json).unwrap_or_default(),
        require_signatures: row.get(4)?,
        org_id: row.get(5)?,
        project_path: row.get(6)?,
        visibility: row.get(7)?,
        storage_binding_id: row.get(8)?,
        prefix: row.get(9)?,
        hosted_key_id: row.get(10)?,
        crawl_policy: row.get(11)?,
        llms_txt_body: row.get(12)?,
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

/// The URL a frontend's machine surface is probed at, from its `domain`.
///
/// Mirrors the probe's scheme rule (see `crate::probe`): a `domain` that
/// already carries an `http://`/`https://` scheme is used as-is; otherwise
/// `https://` is prepended. Used to validate a frontend domain as a safe
/// remote target at creation.
fn frontend_probe_url(domain: &str) -> String {
    if domain.starts_with("http://") || domain.starts_with("https://") {
        domain.to_string()
    } else {
        format!("https://{}", domain.trim_end_matches('/'))
    }
}

/// Validate a frontend `domain` + `base_path`, returning the normalized
/// `(domain, base_path)` to store.
///
/// A frontend `domain` is normally a **bare host** — the request `Host` the
/// dispatcher matches and the host consumer URLs are built from by string
/// concatenation. The default scheme is `https://`, but an explicit
/// `http://`/`https://` prefix is honored and stored as-is for a plain-HTTP
/// internal frontend (and the test harness): the probe and consumer-URL layers
/// read the scheme back off the stored `domain` (see
/// [`frontend_probe_url`] and `crate::probe`). Only the host part may carry a
/// path — an embedded path would corrupt the built URLs — so it is rejected here
/// rather than stored. The probe URL is additionally run through the SSRF guard
/// ([`is_safe_remote_url`](crate::url_guard::is_safe_remote_url)). `base_path`
/// must be empty or a rooted path (`/…`) with no scheme or `..`.
///
/// # Errors
///
/// Returns an error when `domain` carries a path/whitespace or a scheme other
/// than `http://`/`https://`, is not a plausible host, fails the SSRF guard, or
/// `base_path` is not a safe rooted path.
fn validate_frontend_target(domain: &str, base_path: &str) -> Result<(String, String)> {
    let domain = domain.trim().to_ascii_lowercase();
    // The stored domain keeps any explicit scheme (the probe reads it back), so
    // validate the host part with the scheme stripped off.
    let host = domain
        .strip_prefix("https://")
        .or_else(|| domain.strip_prefix("http://"))
        .unwrap_or(&domain);
    if host.contains("://") {
        bail!(
            "frontend domain '{domain}' must be a host, optionally prefixed with http:// or https://"
        );
    }
    if host.contains('/') {
        bail!(
            "frontend domain '{domain}' must be a host only; put any path in the base path field"
        );
    }
    if host.is_empty() || host.contains(char::is_whitespace) || !host.contains('.') {
        bail!("frontend domain '{domain}' is not a valid host");
    }
    crate::url_guard::is_safe_remote_url(&frontend_probe_url(&domain))
        .with_context(|| format!("rejecting frontend domain '{domain}'"))?;
    let base_path = base_path.trim();
    if !base_path.is_empty() {
        if base_path.contains("://") || base_path.contains("..") || base_path.contains("//") {
            bail!("frontend base path '{base_path}' must be a simple rooted path with no scheme or '..'");
        }
        if !base_path.starts_with('/') {
            bail!("frontend base path '{base_path}' must start with '/' (or be empty for the domain root)");
        }
    }
    Ok((domain, base_path.to_string()))
}

/// Normalizes a topology-domain hostname without accepting URL components.
fn normalize_topology_hostname(hostname: &str) -> Result<String> {
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.contains(char::is_whitespace)
        || hostname.contains(['/', ':', '?', '#'])
    {
        bail!("domain hostname must contain only a host, without scheme, port, path, query, or fragment");
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

/// Normalizes a delivery base path to empty-at-root and no trailing slash.
fn normalize_topology_base_path(base_path: &str) -> Result<String> {
    let path = base_path.trim();
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }
    if !path.starts_with('/') || path.contains(['?', '#']) || path.contains("//") {
        bail!("delivery base path must be empty or a simple rooted path");
    }
    if path
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        bail!("delivery base path cannot contain '.' or '..' components");
    }
    let normalized = path.trim_end_matches('/');
    validate_key_bytes(normalized, "delivery base path", 512)?;
    Ok(normalized.to_string())
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

/// Joins a normalized rooted gateway base with a binding-relative placement prefix.
fn join_topology_paths(base_path: &str, placement_prefix: &str) -> Result<String> {
    let joined = match (base_path.is_empty(), placement_prefix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => format!("/{placement_prefix}"),
        (false, true) => base_path.to_string(),
        (false, false) => format!("{base_path}/{placement_prefix}"),
    };
    normalize_topology_base_path(&joined)
}

fn validate_key_bytes(value: &str, label: &str, capacity: usize) -> Result<()> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > capacity
        || value.chars().any(char::is_control)
    {
        bail!("{label} must be non-empty, have no surrounding whitespace or control characters, and fit in {capacity} UTF-8 bytes");
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

fn validate_placement_fields(
    role: &str,
    state: &str,
    completeness: &str,
    partition_rule_json: Option<&str>,
    read_enabled: bool,
    write_enabled: bool,
) -> Result<()> {
    if !matches!(role, "primary" | "replica" | "shard" | "archive") {
        bail!("invalid placement role '{role}'");
    }
    if !matches!(
        state,
        "provisioning" | "syncing" | "ready" | "degraded" | "draining" | "offline"
    ) {
        bail!("invalid placement state '{state}'");
    }
    if !matches!(completeness, "complete" | "partial" | "unknown") {
        bail!("invalid placement completeness '{completeness}'");
    }
    if (role == "shard") != partition_rule_json.is_some() {
        bail!("only shard placements require a partition rule");
    }
    if role == "primary" && !write_enabled {
        bail!("a primary placement must be write-enabled");
    }
    if role != "primary" && write_enabled {
        bail!("only a primary placement may be write-enabled");
    }
    if role == "archive" && read_enabled {
        bail!("an archive placement cannot be read-enabled");
    }
    if role == "shard" && completeness != "partial" {
        bail!("a shard placement must declare partial completeness");
    }
    Ok(())
}

fn surface_from_ids(registry_id: Option<i64>, cache_id: Option<i64>) -> Result<SurfaceTarget> {
    match (registry_id, cache_id) {
        (Some(id), None) => Ok(SurfaceTarget::Registry(id)),
        (None, Some(id)) => Ok(SurfaceTarget::BinaryCache(id)),
        _ => bail!("corrupt topology row: surface target must satisfy XOR"),
    }
}

const PLACEMENT_COLUMNS: &str = "id, registry_id, cache_id, name, storage_binding_id,
    prefix, role, state, completeness, partition_rule_json, mutable_publication_id,
    read_enabled, write_enabled, read_order, write_order, created_at, updated_at,
    resource_version";
const POLICY_COLUMNS: &str = "id, registry_id, cache_id, name, kind, config_json,
    resource_version, created_at, updated_at";
const ROUTE_COLUMNS: &str = "id, domain_id, storage_gateway_id, gateway_generation,
    base_path, registry_id, cache_id, mode, access_policy_json, placement_id,
    placement_policy_id, serves_git, serves_cache, serves_web, enabled,
    readiness_state, resource_version, created_at, updated_at";
const RETENTION_COLUMNS: &str = "id, cache_id, registry_id, selector_json,
    removal_grace_secs, exposure_acknowledged_at, enabled,
    last_successful_revision, last_refresh_at, current_refresh_id, refresh_state, refresh_error,
    retired_at, resource_version, created_at, updated_at";
const SURFACE_OBJECT_COLUMNS: &str = "id, registry_id, cache_id, object_key,
    object_kind, content_hash, size, mutable_publication_id, lifecycle_state,
    tombstoned_at, created_at, updated_at, resource_version";
const DELETION_JOB_COLUMNS: &str = "job_id, surface_object_id, placement_id, state,
    attempt_count, error, created_at, started_at, finished_at, resource_version";
const POPULATION_COLUMNS: &str = "id, cache_id, registry_id, trigger_kind, required,
    placement_policy_id, selector_json, validation_gate, enabled, resource_version,
    created_at, updated_at";
const PLAN_COLUMNS: &str = "plan_id, plan_kind, actor_kind, actor_id, actor_label,
    scope, input_versions_json, effects_json, warnings_json, confirmation_hash,
    created_at, expires_at, applied_at";
const OPERATION_COLUMNS: &str = "operation_id, operation_kind, registry_id, cache_id,
    placement_id, state, progress_current, progress_total, detail_json, error,
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
        storage_binding_id: row.get(4)?,
        prefix: row.get(5)?,
        role: row.get(6)?,
        state: row.get(7)?,
        completeness: row.get(8)?,
        partition_rule_json: row.get(9)?,
        mutable_publication_id: row.get(10)?,
        read_enabled: row.get(11)?,
        write_enabled: row.get(12)?,
        read_order: row.get(13)?,
        write_order: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
        resource_version: row.get(17)?,
    })
}

fn row_to_placement_policy(row: &Row) -> Result<PlacementPolicyRecord> {
    Ok(PlacementPolicyRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        cache_id: row.get(2)?,
        name: row.get(3)?,
        kind: row.get(4)?,
        config_json: row.get(5)?,
        resource_version: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn row_to_delivery_route(row: &Row) -> Result<DeliveryRouteRecord> {
    Ok(DeliveryRouteRecord {
        id: row.get(0)?,
        domain_id: row.get(1)?,
        storage_gateway_id: row.get(2)?,
        gateway_generation: row.get(3)?,
        base_path: row.get(4)?,
        registry_id: row.get(5)?,
        cache_id: row.get(6)?,
        mode: row.get(7)?,
        access_policy_json: row.get(8)?,
        placement_id: row.get(9)?,
        placement_policy_id: row.get(10)?,
        serves_git: row.get(11)?,
        serves_cache: row.get(12)?,
        serves_web: row.get(13)?,
        enabled: row.get(14)?,
        readiness_state: row.get(15)?,
        resource_version: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

fn row_to_canonical_route(row: &Row) -> Result<CanonicalRouteRecord> {
    let registry_id = row.get(1)?;
    let cache_id = row.get(2)?;
    Ok(CanonicalRouteRecord {
        id: row.get(0)?,
        surface: surface_from_ids(registry_id, cache_id)?,
        audience: row.get(3)?,
        delivery_route_id: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        resource_version: row.get(7)?,
    })
}

fn row_to_topology_defaults(row: &Row) -> Result<TopologyDefaultsRecord> {
    Ok(TopologyDefaultsRecord {
        id: row.get(0)?,
        scope_kind: row.get(1)?,
        org_id: row.get(2)?,
        scope_key: row.get(3)?,
        storage_binding_id: row.get(4)?,
        domain_id: row.get(5)?,
        storage_gateway_id: row.get(6)?,
        resource_version: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn row_to_cache_retention_subscription(row: &Row) -> Result<CacheRetentionSubscriptionRecord> {
    Ok(CacheRetentionSubscriptionRecord {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        registry_id: row.get(2)?,
        selector_json: row.get(3)?,
        removal_grace_secs: row.get(4)?,
        exposure_acknowledged_at: row.get(5)?,
        enabled: row.get(6)?,
        last_successful_revision: row.get(7)?,
        last_refresh_at: row.get(8)?,
        current_refresh_id: row.get(9)?,
        refresh_state: row.get(10)?,
        refresh_error: row.get(11)?,
        retired_at: row.get(12)?,
        resource_version: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn row_to_cache_population_target(row: &Row) -> Result<CachePopulationTargetRecord> {
    Ok(CachePopulationTargetRecord {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        registry_id: row.get(2)?,
        trigger_kind: row.get(3)?,
        required: row.get(4)?,
        placement_policy_id: row.get(5)?,
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

fn row_to_object_placement(row: &Row) -> Result<ObjectPlacementRecord> {
    Ok(ObjectPlacementRecord {
        surface_object_id: row.get(0)?,
        placement_id: row.get(1)?,
        state: row.get(2)?,
        observed_hash: row.get(3)?,
        observed_size: row.get(4)?,
        etag: row.get(5)?,
        observed_at: row.get(6)?,
    })
}

fn row_to_object_deletion_job(row: &Row) -> Result<ObjectDeletionJobRecord> {
    Ok(ObjectDeletionJobRecord {
        job_id: row.get(0)?,
        surface_object_id: row.get(1)?,
        placement_id: row.get(2)?,
        state: row.get(3)?,
        attempt_count: row.get(4)?,
        error: row.get(5)?,
        created_at: row.get(6)?,
        started_at: row.get(7)?,
        finished_at: row.get(8)?,
        resource_version: row.get(9)?,
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
        created_at: row.get(10)?,
        expires_at: row.get(11)?,
        applied_at: row.get(12)?,
    })
}

fn row_to_topology_operation(row: &Row) -> Result<TopologyOperationRecord> {
    Ok(TopologyOperationRecord {
        operation_id: row.get(0)?,
        operation_kind: row.get(1)?,
        registry_id: row.get(2)?,
        cache_id: row.get(3)?,
        placement_id: row.get(4)?,
        state: row.get(5)?,
        progress_current: row.get(6)?,
        progress_total: row.get(7)?,
        detail_json: row.get(8)?,
        error: row.get(9)?,
        created_at: row.get(10)?,
        started_at: row.get(11)?,
        finished_at: row.get(12)?,
        resource_version: row.get(13)?,
    })
}

/// Map a `frontends` row into a [`FrontendRecord`] (columns in the order
/// [`Database::list_frontends`] selects).
fn row_to_frontend(row: &Row) -> Result<FrontendRecord> {
    // Column order matches the shared `FRONTEND_COLUMNS` SELECT list.
    // A malformed/partial proxy_config never fails the row: an unparseable blob
    // falls back to conservative defaults (Some(default)), and NULL ⇒ None.
    let proxy_config: Option<String> = row.get(12)?;
    let proxy_config =
        proxy_config.map(|json| serde_json::from_str::<ProxyConfig>(&json).unwrap_or_default());
    Ok(FrontendRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        cache_id: row.get(2)?,
        storage_binding_id: row.get(3)?,
        domain: row.get(4)?,
        base_path: row.get(5)?,
        mode: row.get(6)?,
        serves_git: row.get(7)?,
        serves_cache: row.get(8)?,
        serves_web: row.get(9)?,
        consumer_priority: row.get(10)?,
        advertised: row.get(11)?,
        proxy_config,
        is_primary: row.get(13)?,
        created_at: row.get(14)?,
    })
}

fn row_to_hosted_key(row: &Row) -> Result<HostedKeyRecord> {
    Ok(HostedKeyRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        key_id: row.get(2)?,
        public_key: row.get(3)?,
        secret_enc: row.get(4)?,
        created_at: row.get(5)?,
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

/// The `config_changesets` columns, in the order [`row_to_changeset`] reads.
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
        slug: row.get(1)?,
        name: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn row_to_storage_binding(row: &Row) -> Result<StorageBindingRecord> {
    Ok(StorageBindingRecord {
        id: row.get(0)?,
        org_id: row.get(1)?,
        name: row.get(2)?,
        kind: row.get(3)?,
        root: row.get(4)?,
        access: row.get(5)?,
        endpoint: row.get(6)?,
        credential_ref: row.get(7)?,
        is_instance_default: row.get(8)?,
        created_at: row.get(9)?,
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
    crate::clock::now_unix_secs()
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
mod tests {
    use super::*;
    // The in-module migration tests stage an old-schema sqlite file with raw
    // rusqlite, then reopen it through the sqlx [`Database`] to assert the
    // upgrade path; post-migration assertions use the async [`Backend`] API on
    // `db.backend`.
    use rusqlite::Connection;

    #[tokio::test]
    async fn migrate_register_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        {
            let db = Database::open(&path).await.unwrap();
            db.register_registry("demo", "file:///srv/demo", &["k".into()], true)
                .await
                .unwrap();
        }
        let db = Database::open(&path).await.unwrap();
        let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
        assert_eq!(reg.trust_keys, vec!["k".to_string()]);
        assert!(reg.require_signatures);
        assert_eq!(
            db.index_status(reg.id).await.unwrap().unwrap().state,
            "empty"
        );
    }

    #[tokio::test]
    async fn snapshot_replace_is_idempotent() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();
        let package: aos_registry_surface::manifest::PackageToml = toml::from_str(
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
        let mut snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            description: None,
            readme: None,
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
            cache_stack: None,
        };
        db.apply_snapshot(id, &snapshot).await.unwrap();
        let release_id: i64 = db
            .backend
            .query_opt(
                "SELECT id FROM releases WHERE registry_id = ?1 AND semver = '1.0.0'",
                &vals![id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO release_artifacts
             (release_id, package_name, package_version, platform, artifact_kind,
              store_path, store_hash)
             VALUES (?1, 'curl', '8.5.0', 'x86_64-linux', 'output',
                     '/nix/store/abc-curl', 'abc')",
                &vals![release_id],
            )
            .await
            .unwrap();
        db.apply_snapshot(id, &snapshot).await.unwrap();
        let stable_release_id: i64 = db
            .backend
            .query_opt(
                "SELECT id FROM releases WHERE registry_id = ?1 AND semver = '1.0.0'",
                &vals![id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(stable_release_id, release_id);
        let artifact_count: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM release_artifacts WHERE release_id = ?1",
                &vals![release_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(artifact_count, 1);

        let channel_id: i64 = db
            .backend
            .query_opt(
                "SELECT id FROM channels WHERE registry_id = ?1 AND name = 'stable'",
                &vals![id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        let channels = std::mem::take(&mut snapshot.channels);
        db.apply_snapshot(id, &snapshot).await.unwrap();
        assert!(db.list_channels(id).await.unwrap().is_empty());
        snapshot.channels = channels;
        db.apply_snapshot(id, &snapshot).await.unwrap();
        let restored_channel_id: i64 = db
            .backend
            .query_opt(
                "SELECT id FROM channels WHERE registry_id = ?1 AND name = 'stable'",
                &vals![id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(restored_channel_id, channel_id);
        let mut refreshed_channels = snapshot.channels.clone();
        refreshed_channels[0].partitions[0] = None;
        db.update_channels(id, &refreshed_channels).await.unwrap();
        db.update_channels(id, &refreshed_channels).await.unwrap();
        assert_eq!(
            db.list_channels(id).await.unwrap()[0]
                .partitions
                .iter()
                .flatten()
                .count(),
            255
        );
        db.apply_snapshot(id, &snapshot).await.unwrap();

        snapshot.releases[0].tag_oid = "force-retag".repeat(8);
        snapshot.releases[0].commit_oid = "changed-commit".repeat(8);
        assert!(db.apply_snapshot(id, &snapshot).await.is_err());
        let unchanged_release = db
            .backend
            .query_opt(
                "SELECT id, tag_oid, commit_oid FROM releases
                 WHERE registry_id = ?1 AND semver = '1.0.0'",
                &vals![id],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged_release.get::<i64>(0).unwrap(), release_id);
        assert_eq!(unchanged_release.get::<String>(1).unwrap(), "t".repeat(64));
        assert_eq!(unchanged_release.get::<String>(2).unwrap(), "c".repeat(64));
        let artifact_count_after_retag: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM release_artifacts WHERE release_id = ?1",
                &vals![release_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(artifact_count_after_retag, 1);

        let packages = db.list_packages(id).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].latest_version.as_deref(), Some("8.5.0"));
        let detail = db.package_detail(id, "curl").await.unwrap().unwrap();
        assert_eq!(detail.versions[0].platforms[0].platform, "x86_64-linux");
        let channels = db.list_channels(id).await.unwrap();
        assert_eq!(channels[0].partitions.iter().flatten().count(), 256);
        assert_eq!(db.index_status(id).await.unwrap().unwrap().state, "fresh");
        assert_eq!(db.list_advertised_caches(id).await.unwrap()[0].1, 40);
        assert!(db.list_releases(id).await.unwrap()[0].pack_present);
        assert_eq!(
            db.refs_digest(id).await.unwrap().as_deref(),
            Some(&*"d".repeat(64))
        );
        assert_eq!(
            db.all_store_hashes(id).await.unwrap(),
            vec!["abc".to_string()]
        );
    }

    #[tokio::test]
    async fn closure_resolution_resolves_refs_and_reverse_deps() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();
        // curl's closure references zlib (zzz) plus an out-of-registry hash
        // (qqq, e.g. a stdenv path); source_drv is recorded per the v19 column.
        let curl: aos_registry_surface::manifest::PackageToml = toml::from_str(
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
            source_drv = "/var/lib/store/dabc-curl-8.5.0.drv"
            source_nar_hash = "sha256:bb"
            references = ["zzz", "qqq"]
            "#,
        )
        .unwrap();
        let zlib: aos_registry_surface::manifest::PackageToml = toml::from_str(
            r#"
            [package]
            name = "zlib"
            description = "compression"
            license = "Zlib"
            maintainer = "aos"
            [[versions]]
            version = "1.3.1"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/zzz-zlib-1.3.1"
            nar_hash = "sha256:cc"
            nar_size = 5
            closure_size = 8
            source_drv = "/var/lib/store/dzzz-zlib-1.3.1.drv"
            source_nar_hash = "sha256:dd"
            references = []
            "#,
        )
        .unwrap();
        let snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            packages: vec![curl, zlib],
            ..Default::default()
        };
        db.apply_snapshot(id, &snapshot).await.unwrap();

        // The v19 source_drv column round-trips into PlatformDetail.
        let detail = db.package_detail(id, "curl").await.unwrap().unwrap();
        assert_eq!(
            detail.versions[0].platforms[0].source_drv,
            "/var/lib/store/dabc-curl-8.5.0.drv"
        );

        // resolve_reference_names: zzz resolves to zlib, qqq stays unresolved.
        let resolved = db
            .resolve_reference_names(id, &["zzz".to_string(), "qqq".to_string()])
            .await
            .unwrap();
        assert_eq!(
            resolved,
            vec![
                (
                    "zzz".to_string(),
                    Some("zlib".to_string()),
                    Some("1.3.1".to_string())
                ),
                ("qqq".to_string(), None, None),
            ]
        );

        // reverse_dependencies: curl requires zlib (zzz).
        let reverse = db.reverse_dependencies(id, "zzz").await.unwrap();
        assert_eq!(reverse, vec![("curl".to_string(), "8.5.0".to_string())]);
        // qqq is referenced by curl too (a second closure edge).
        assert_eq!(
            db.reverse_dependencies(id, "qqq").await.unwrap(),
            vec![("curl".to_string(), "8.5.0".to_string())]
        );
        // Nothing references a hash that appears in no closure.
        assert!(db
            .reverse_dependencies(id, "nope")
            .await
            .unwrap()
            .is_empty());

        // primary_store_hash prefers the named platform and falls back.
        assert_eq!(
            db.primary_store_hash(id, "zlib", "x86_64-linux")
                .await
                .unwrap(),
            Some("zzz".to_string())
        );
        assert_eq!(
            db.primary_store_hash(id, "zlib", "aarch64-linux")
                .await
                .unwrap(),
            Some("zzz".to_string()),
            "falls back to the first platform when the requested one is absent"
        );
        assert_eq!(
            db.primary_store_hash(id, "absent", "x86_64-linux")
                .await
                .unwrap(),
            None
        );

        // list_packages carries the latest version's closure size + platforms,
        // now via a single JOIN (no per-package N+1 sub-query).
        let packages = db.list_packages(id).await.unwrap();
        assert_eq!(packages.len(), 2, "both packages, name-ordered");
        assert_eq!(packages[0].name, "curl");
        let curl_row = packages.iter().find(|p| p.name == "curl").unwrap();
        assert_eq!(curl_row.closure_size, Some(20));
        assert_eq!(curl_row.platforms, vec!["x86_64-linux".to_string()]);

        // The capped browse listing returns the same rows under a high cap and
        // reports truncation when the cap is below the package count.
        let (uncapped, trunc) = db.list_packages_capped(id, 1000).await.unwrap();
        assert_eq!(uncapped.len(), 2);
        assert!(!trunc, "two packages are well under the cap");
        let (capped, trunc) = db.list_packages_capped(id, 1).await.unwrap();
        assert_eq!(capped.len(), 1, "cap limits the loaded set");
        assert_eq!(capped[0].name, "curl", "cap takes the name-ordered prefix");
        assert!(trunc, "a registry larger than the cap is flagged truncated");
    }

    #[tokio::test]
    async fn failure_marks_state_without_dropping_index() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();
        let snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            ..Default::default()
        };
        db.apply_snapshot(id, &snapshot).await.unwrap();
        db.mark_index_failed(id, "upstream unreachable")
            .await
            .unwrap();
        let status = db.index_status(id).await.unwrap().unwrap();
        assert_eq!(status.state, "failed");
        assert_eq!(status.error.as_deref(), Some("upstream unreachable"));
        // The last good index survives.
        assert_eq!(
            status.last_indexed_commit.as_deref(),
            Some(&*"c".repeat(64))
        );

        db.mark_index_stale(id, "connection refused").await.unwrap();
        let status = db.index_status(id).await.unwrap().unwrap();
        assert_eq!(status.state, "stale");
        assert_eq!(status.error.as_deref(), Some("connection refused"));
        assert_eq!(
            status.last_indexed_commit.as_deref(),
            Some(&*"c".repeat(64))
        );
    }

    #[tokio::test]
    async fn v1_database_migrates_to_v2() {
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
        let db = Database::open(&path).await.unwrap();
        let releases = db.list_releases(1).await.unwrap();
        assert_eq!(releases.len(), 1);
        assert!(!releases[0].pack_present, "v1 rows default pack_present=0");
        assert!(db.refs_digest(1).await.unwrap().is_none());
        db.set_channel_floor(1, "stable", "1.0.0").await.unwrap();
        assert_eq!(
            db.channel_floor(1, "stable").await.unwrap().as_deref(),
            Some("1.0.0")
        );
    }

    #[tokio::test]
    async fn v2_database_migrates_to_v3() {
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
        let db = Database::open(&path).await.unwrap();
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
            let count: i64 = db
                .backend
                .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
                .await
                .unwrap()
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(count, 0, "{table} should start empty");
        }
        // The phase-1 registry became an unowned public registry.
        let row = db
            .backend
            .query_opt(
                "SELECT org_id, project_path, visibility FROM registries WHERE slug = 'legacy'",
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        let org_id: Option<i64> = row.get(0).unwrap();
        let project_path: String = row.get(1).unwrap();
        let visibility: String = row.get(2).unwrap();
        assert_eq!(org_id, None);
        assert_eq!(project_path, "");
        assert_eq!(visibility, "public");
    }

    #[tokio::test]
    async fn v6_database_migrates_to_v7() {
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
        let db = Database::open(&path).await.unwrap();
        for table in ["audit_log", "config_changesets", "config_revisions"] {
            let count: i64 = db
                .backend
                .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
                .await
                .unwrap()
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(count, 0, "{table} should start empty");
        }
        // The new surface works end to end through the public methods.
        db.create_changeset("cs1", "system", None, "system", "acme", Some("test"))
            .await
            .unwrap();
        db.add_revision(
            "cs1",
            "registry",
            "acme/cdn",
            "update",
            Some(r#"{"visibility":"public"}"#),
            Some(r#"{"visibility":"private"}"#),
        )
        .await
        .unwrap();
        assert_eq!(db.list_revisions("cs1").await.unwrap().len(), 1);
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
            .await
            .unwrap();
        assert!(id > 0);
        assert_eq!(db.list_audit("acme").await.unwrap().len(), 1);
        assert_eq!(db.list_changesets("acme").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn v7_database_migrates_to_v8_and_stores_cache_stack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        // Build a v7 database by hand (apply migrations v1..=v7).
        {
            let conn = Connection::open(&path).unwrap();
            for m in &MIGRATIONS[..7] {
                conn.execute_batch(m).unwrap();
            }
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (7);",
            )
            .unwrap();
        }

        // Reopening migrates to v8; registry_index gains the cache_stack
        // column, which round-trips a parsed stack through a snapshot.
        let db = Database::open(&path).await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();
        assert!(db.registry_cache_stack(id).await.unwrap().is_none());

        let stack = crate::stack::StackNode::Mirror(vec![
            crate::stack::StackNode::Endpoint("https://a".into()),
            crate::stack::StackNode::Endpoint("https://b".into()),
        ]);
        db.apply_snapshot(
            id,
            &IndexSnapshot {
                commit: "c".repeat(64),
                name: "demo".into(),
                cache_stack: Some(stack.to_json().unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(db.registry_cache_stack(id).await.unwrap(), Some(stack));
    }

    #[tokio::test]
    async fn audit_and_changeset_scope_containment() {
        let db = Database::open_in_memory().await.unwrap();
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
        .await
        .unwrap();
        db.record_audit(
            "system", None, "system", "b", "globex", None, None, None, None,
        )
        .await
        .unwrap();
        // An org-scoped query surfaces the registry-scoped row but not the
        // sibling org's.
        let rows = db.list_audit("acme").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "a");
        // The root scope lists everything, newest first.
        let all = db.list_audit("").await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].action, "b", "newest first");
    }

    #[test]
    fn sanitize_log_text_strips_c0_controls_but_keeps_tab() {
        // CR/LF and other C0 controls collapse to spaces; a tab is preserved.
        assert_eq!(sanitize_log_text("a\r\nb"), "a  b");
        assert_eq!(sanitize_log_text("x\tnice"), "x\tnice");
        assert_eq!(sanitize_log_text("ctrl\x07bell\x7fdel"), "ctrl bell del");
        assert_eq!(sanitize_log_text("clean/path-1.0"), "clean/path-1.0");
    }

    #[tokio::test]
    async fn record_audit_sanitizes_crlf_in_detail_and_label() {
        let db = Database::open_in_memory().await.unwrap();
        // A forged label/detail with embedded CRLF must be stored sanitized so a
        // reader of the audit feed (or a log line derived from it) cannot be
        // fooled by an injected newline.
        db.record_audit(
            "token",
            None,
            "label\r\nINJECTED admin",
            "publish",
            "acme/cdn",
            None,
            None,
            None,
            Some("fetching http://host/x\r\nFAKE: line"),
        )
        .await
        .unwrap();
        let rows = db.list_audit("acme/cdn").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            !rows[0].actor_label.contains('\n') && !rows[0].actor_label.contains('\r'),
            "label retained CR/LF: {:?}",
            rows[0].actor_label
        );
        let detail = rows[0].detail.as_deref().unwrap_or("");
        assert!(
            !detail.contains('\n') && !detail.contains('\r'),
            "detail retained CR/LF: {detail:?}"
        );
        assert!(
            detail.contains("http://host/x"),
            "content preserved: {detail:?}"
        );
    }

    #[tokio::test]
    async fn draft_signing_key_is_generated_once_and_persists() {
        let db = Database::open_in_memory().await.unwrap();
        let sealer = crate::auth::seal::dev_sealer();
        let (key1, line1) = db
            .get_or_create_draft_signing_key(sealer.as_ref())
            .await
            .unwrap();
        // A second call returns the same key (persisted seed), not a fresh one.
        let (key2, line2) = db
            .get_or_create_draft_signing_key(sealer.as_ref())
            .await
            .unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        assert_eq!(line1, line2);
        assert!(line1.starts_with("aos-hub-draft:Ed25519:"));
        // The stored value is sealed, not the raw seed.
        let stored = db
            .instance_config_get("draft_signing_key")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored, hex::encode(key1.to_bytes()));
    }

    #[tokio::test]
    async fn git_changeset_records_ref_and_commit() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_git_changeset(
            "ch-1",
            "user",
            Some(7),
            "alice@acme.com",
            "acme/cdn",
            Some("edit registry.toml"),
            "refs/hub/changes/ch-1",
            "abc123",
            None,
            None,
        )
        .await
        .unwrap();
        let cs = db.changeset("ch-1").await.unwrap().unwrap();
        assert_eq!(cs.status, "draft");
        assert_eq!(cs.git_ref.as_deref(), Some("refs/hub/changes/ch-1"));
        assert_eq!(cs.git_commit.as_deref(), Some("abc123"));
        // A plain change-set leaves both columns NULL.
        db.create_changeset("ch-2", "user", Some(7), "alice@acme.com", "acme", None)
            .await
            .unwrap();
        let plain = db.changeset("ch-2").await.unwrap().unwrap();
        assert!(plain.git_ref.is_none());
        assert!(plain.git_commit.is_none());
    }

    #[tokio::test]
    async fn mark_changeset_applied_commit_links_promoting_commit() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_git_changeset(
            "ch-3",
            "user",
            Some(7),
            "alice@acme.com",
            "acme/cdn",
            Some("edit"),
            "refs/hub/changes/ch-3",
            "draftoid",
            None,
            None,
        )
        .await
        .unwrap();
        db.mark_changeset_applied_commit("ch-3", "rosteroid")
            .await
            .unwrap();
        let cs = db.changeset("ch-3").await.unwrap().unwrap();
        assert_eq!(cs.status, "applied");
        assert!(cs.applied_at.is_some());
        assert_eq!(cs.git_commit.as_deref(), Some("rosteroid"));
        // Re-marking an applied row is a no-op (status-guarded UPDATE).
        db.mark_changeset_applied_commit("ch-3", "otheroid")
            .await
            .unwrap();
        let again = db.changeset("ch-3").await.unwrap().unwrap();
        assert_eq!(again.git_commit.as_deref(), Some("rosteroid"));
    }

    /// The central regression guard for the `closed_at`-axis design: closing and
    /// reopening a draft must leave `status = 'draft'`, so the indexer's
    /// `status='draft'`-guarded auto-merge still fires for a reopened change.
    #[tokio::test]
    async fn close_reopen_preserves_draft_auto_merge() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_git_changeset(
            "ch-cr",
            "user",
            Some(1),
            "alice@acme.com",
            "acme/cdn",
            Some("edit"),
            "refs/hub/changes/ch-cr",
            "draftoid",
            Some("tighten caches"),
            Some("body text"),
        )
        .await
        .unwrap();
        // Title/body round-trip; opens un-closed.
        let cs = db.changeset("ch-cr").await.unwrap().unwrap();
        assert_eq!(cs.title.as_deref(), Some("tighten caches"));
        assert_eq!(cs.body.as_deref(), Some("body text"));
        assert!(cs.closed_at.is_none());

        // Close stamps closed_at but never touches status.
        db.close_changeset("ch-cr").await.unwrap();
        let cs = db.changeset("ch-cr").await.unwrap().unwrap();
        assert_eq!(cs.status, "draft");
        assert!(cs.closed_at.is_some());

        // Reopen clears closed_at.
        db.reopen_changeset("ch-cr").await.unwrap();
        let cs = db.changeset("ch-cr").await.unwrap().unwrap();
        assert!(cs.closed_at.is_none());

        // Auto-merge still flips the reopened draft to applied.
        db.mark_changeset_applied_commit("ch-cr", "rosteroid")
            .await
            .unwrap();
        let cs = db.changeset("ch-cr").await.unwrap().unwrap();
        assert_eq!(cs.status, "applied");
        assert_eq!(cs.git_commit.as_deref(), Some("rosteroid"));
    }

    #[tokio::test]
    async fn change_comments_and_reviews_record_and_list_in_order() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_git_changeset(
            "ch-d",
            "user",
            Some(1),
            "alice@acme.com",
            "acme/cdn",
            Some("edit"),
            "refs/hub/changes/ch-d",
            "draftoid",
            None,
            None,
        )
        .await
        .unwrap();
        db.add_change_comment("ch-d", "user", Some(1), "alice@acme.com", "first")
            .await
            .unwrap();
        db.add_change_comment("ch-d", "user", Some(2), "bob@acme.com", "second")
            .await
            .unwrap();
        let comments = db.list_change_comments("ch-d").await.unwrap();
        assert_eq!(comments.len(), 2);
        assert_eq!(comments[0].body, "first");
        assert_eq!(comments[1].body, "second");

        db.add_change_review(
            "ch-d",
            "user",
            Some(2),
            "bob@acme.com",
            "approve",
            Some("lgtm"),
        )
        .await
        .unwrap();
        let reviews = db.list_change_reviews("ch-d").await.unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].verdict, "approve");
        assert_eq!(reviews[0].body.as_deref(), Some("lgtm"));
    }

    #[tokio::test]
    async fn audit_exists_for_commit_is_specific_to_action_and_commit() {
        let db = Database::open_in_memory().await.unwrap();
        assert!(!db
            .audit_exists_for_commit("index.external_commit", "oid-1")
            .await
            .unwrap());
        db.record_audit(
            "key",
            None,
            "key:abc",
            "index.external_commit",
            "acme/cdn",
            None,
            Some("oid-1"),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(db
            .audit_exists_for_commit("index.external_commit", "oid-1")
            .await
            .unwrap());
        // A different commit, or a different action, does not match.
        assert!(!db
            .audit_exists_for_commit("index.external_commit", "oid-2")
            .await
            .unwrap());
        assert!(!db.audit_exists_for_commit("index", "oid-1").await.unwrap());
    }

    #[tokio::test]
    async fn orgs_projects_and_principals_roundtrip() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
        assert_eq!(db.org_by_slug("acme").await.unwrap().unwrap().id, org);
        assert!(db.org_by_slug("nope").await.unwrap().is_none());

        db.create_project(org, "", "Root").await.unwrap();
        db.create_project(org, "infra", "Infra").await.unwrap();
        db.create_project(org, "infra/prod", "Prod").await.unwrap();
        let projects = db.list_projects(org).await.unwrap();
        assert_eq!(projects.len(), 3);
        assert_eq!(projects[0].path, "");
        assert_eq!(projects[1].path, "infra");
        assert_eq!(projects[2].path, "infra/prod");

        let user = db.create_user("dev@acme.com", Some("Dev")).await.unwrap();
        assert_eq!(db.user_by_email("dev@acme.com").await.unwrap(), Some(user));
        assert!(db.user_by_email("ghost@acme.com").await.unwrap().is_none());

        let sa = db.create_service_account(org, "ci").await.unwrap();
        assert!(sa > 0);
    }

    #[tokio::test]
    async fn memberships_grant_revoke_and_list() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();
        db.grant_membership("user", user, "acme", "admin")
            .await
            .unwrap();
        db.grant_membership("user", user, "acme/infra", "maintainer")
            .await
            .unwrap();
        // Re-granting overwrites the role at the same scope.
        db.grant_membership("user", user, "acme", "owner")
            .await
            .unwrap();

        let grants = db.list_memberships_for("user", user).await.unwrap();
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
            .await
            .unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(crate::domain::iam::allow(
            &scopes,
            crate::domain::Permission::IamAdmin,
            &crate::domain::Scope::parse("acme/infra/prod/cdn"),
        ));

        // list_members_of_scope returns exact-scope grants only (the
        // org grant at "acme", not the inherited "acme/infra" one).
        let members = db.list_members_of_scope("acme").await.unwrap();
        assert_eq!(
            members,
            vec![("user".to_string(), user, "owner".to_string())]
        );

        db.revoke_membership("user", user, "acme").await.unwrap();
        let grants = db.list_memberships_for("user", user).await.unwrap();
        assert_eq!(
            grants,
            vec![("acme/infra".to_string(), "maintainer".to_string())]
        );
    }

    #[tokio::test]
    async fn registry_ownership_can_be_set() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let reg = db
            .register_registry("cdn", "/srv/cdn", &[], false)
            .await
            .unwrap();
        db.set_registry_ownership(reg, Some(org), "infra/prod", "private")
            .await
            .unwrap();
        let row = db
            .backend
            .query_opt(
                "SELECT org_id, project_path, visibility FROM registries WHERE id = ?1",
                &vals![reg],
            )
            .await
            .unwrap()
            .unwrap();
        let got_org: Option<i64> = row.get(0).unwrap();
        let path: String = row.get(1).unwrap();
        let vis: String = row.get(2).unwrap();
        assert_eq!(got_org, Some(org));
        assert_eq!(path, "infra/prod");
        assert_eq!(vis, "private");
    }

    #[tokio::test]
    async fn invitations_create_accept_and_expire() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let far_future = unix_now() + 86_400;

        db.create_invitation(
            org,
            "new@acme.com",
            "acme/infra",
            "developer",
            "hash-a",
            far_future,
        )
        .await
        .unwrap();
        let accepted = db.accept_invitation("hash-a").await.unwrap().unwrap();
        assert_eq!(accepted.email, "new@acme.com");
        assert_eq!(accepted.scope, "acme/infra");
        assert_eq!(accepted.role, "developer");
        // A second accept of the same hash is rejected (already accepted).
        assert!(db.accept_invitation("hash-a").await.unwrap().is_none());
        // Unknown hash is rejected.
        assert!(db
            .accept_invitation("hash-missing")
            .await
            .unwrap()
            .is_none());

        // An already-expired invitation cannot be accepted.
        let past = unix_now() - 10;
        db.create_invitation(org, "late@acme.com", "acme", "viewer", "hash-b", past)
            .await
            .unwrap();
        assert!(db.accept_invitation("hash-b").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn v3_database_migrates_to_v4() {
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
        let db = Database::open(&path).await.unwrap();
        for table in ["tokens", "sessions", "device_codes", "magic_links"] {
            let count: i64 = db
                .backend
                .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
                .await
                .unwrap()
                .unwrap()
                .get(0)
                .unwrap();
            assert_eq!(count, 0, "{table} should start empty");
        }
    }

    #[tokio::test]
    async fn tokens_create_validate_revoke_and_list() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().await.unwrap();
        let owner = Principal::user(7);
        let (id, secret) = db
            .create_token(
                owner,
                "acme/infra",
                &[Permission::Read, Permission::Publish],
                Some("ci"),
                None,
            )
            .await
            .unwrap();
        assert!(secret.starts_with("aos_"));

        let auth = db.validate_token(&secret).await.unwrap().unwrap();
        assert_eq!(auth.token_id, id);
        assert_eq!(auth.owner, owner);
        assert_eq!(auth.scope.as_str(), "acme/infra");
        assert_eq!(
            auth.permissions,
            vec![Permission::Read, Permission::Publish]
        );

        // last_used_at is bumped on validation.
        let used: Option<i64> = db
            .backend
            .query_opt("SELECT last_used_at FROM tokens WHERE id = ?1", &vals![id])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert!(used.is_some());

        let list = db.list_tokens_for(owner).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, id);

        db.revoke_token(&id).await.unwrap();
        // Revoked-now is still inside grace, but a revoked token in the far
        // past would be invalid; here we just confirm the revoke ran.
        assert!(db.list_tokens_for(owner).await.unwrap().is_empty());

        // Unknown secret is rejected.
        assert!(db.validate_token("aos_deadbeef").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tokens_expired_is_rejected() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().await.unwrap();
        let past = unix_now() - 10;
        let (_, secret) = db
            .create_token(
                Principal::user(1),
                "acme",
                &[Permission::Read],
                None,
                Some(past),
            )
            .await
            .unwrap();
        assert!(db.validate_token(&secret).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tokens_rotation_honors_grace_window() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().await.unwrap();
        let owner = Principal::user(3);
        let (old_id, old_secret) = db
            .create_token(owner, "acme", &[Permission::Read], Some("c"), None)
            .await
            .unwrap();

        let (new_id, new_secret) = db.rotate_token(&old_id).await.unwrap().unwrap();
        assert_ne!(old_id, new_id);
        assert_ne!(old_secret, new_secret);

        // New token validates and carries the same scope/perms.
        let new_auth = db.validate_token(&new_secret).await.unwrap().unwrap();
        assert_eq!(new_auth.scope.as_str(), "acme");
        assert_eq!(new_auth.permissions, vec![Permission::Read]);

        // The OLD secret still validates — it was rotated now, but within
        // the grace window.
        assert!(db.validate_token(&old_secret).await.unwrap().is_some());

        // Force the old token's rotated_at to be older than the grace
        // window: now it is invalid.
        db.backend
            .execute(
                "UPDATE tokens SET rotated_at = ?2 WHERE id = ?1",
                &vals![old_id, unix_now() - ROTATION_GRACE_SECS - 1],
            )
            .await
            .unwrap();
        assert!(db.validate_token(&old_secret).await.unwrap().is_none());

        // Rotating an already-rotated token mints again from it (it was
        // never hard-revoked).
        assert!(db.rotate_token(&old_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoked_token_is_denied_immediately_without_grace() {
        use crate::domain::{Permission, Principal};
        let db = Database::open_in_memory().await.unwrap();
        let (id, secret) = db
            .create_token(Principal::user(7), "acme", &[Permission::Read], None, None)
            .await
            .unwrap();
        assert!(db.validate_token(&secret).await.unwrap().is_some());
        db.revoke_token(&id).await.unwrap();
        // A hard revocation cuts off at once — no rotation grace.
        assert!(db.validate_token(&secret).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sessions_create_validate_expire_and_revoke() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();
        let secret = db.create_session(user, 3600, 0).await.unwrap();
        let session = db.validate_session(&secret).await.unwrap().unwrap();
        assert_eq!(session.user_id, user);
        assert_eq!(session.auth_level, 0);

        // Elevate sets sudo.
        db.elevate_session(&secret).await.unwrap();
        assert_eq!(
            db.validate_session(&secret)
                .await
                .unwrap()
                .unwrap()
                .auth_level,
            1
        );

        // Revoke one session.
        db.revoke_session(&secret).await.unwrap();
        assert!(db.validate_session(&secret).await.unwrap().is_none());

        // An expired session is rejected.
        let expired = db.create_session(user, -10, 0).await.unwrap();
        assert!(db.validate_session(&expired).await.unwrap().is_none());

        // revoke_all clears everything.
        let s1 = db.create_session(user, 3600, 0).await.unwrap();
        let s2 = db.create_session(user, 3600, 0).await.unwrap();
        db.revoke_all_user_sessions(user).await.unwrap();
        assert!(db.validate_session(&s1).await.unwrap().is_none());
        assert!(db.validate_session(&s2).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn session_idle_and_absolute_timeouts_enforced() {
        use crate::auth::session::{ABSOLUTE_LIFETIME_SECS, IDLE_TIMEOUT_SECS};
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();
        let now = unix_now();

        // A fresh session validates.
        let secret = db
            .create_session(user, ABSOLUTE_LIFETIME_SECS, 1)
            .await
            .unwrap();
        assert!(db.validate_session(&secret).await.unwrap().is_some());
        let hash = crate::auth::token::sha256_hex(&secret);

        // Backdate last_seen_at past the idle timeout: the session is rejected
        // (and the dead row is deleted).
        db.backend
            .execute(
                "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
                &vals![hash, now - IDLE_TIMEOUT_SECS - 1],
            )
            .await
            .unwrap();
        assert!(
            db.validate_session(&secret).await.unwrap().is_none(),
            "idle out"
        );

        // A fresh session whose created_at is older than the absolute cap is
        // rejected even though it was just "seen".
        let secret2 = db
            .create_session(user, ABSOLUTE_LIFETIME_SECS, 1)
            .await
            .unwrap();
        let hash2 = crate::auth::token::sha256_hex(&secret2);
        db.backend
            .execute(
                "UPDATE sessions SET created_at = ?2, last_seen_at = ?3 WHERE id_hash = ?1",
                &vals![hash2, now - ABSOLUTE_LIFETIME_SECS - 1, now],
            )
            .await
            .unwrap();
        assert!(
            db.validate_session(&secret2).await.unwrap().is_none(),
            "absolute cap"
        );

        // Activity slides the idle window: a session seen just under the idle
        // limit validates, and validation bumps last_seen_at to now.
        let secret3 = db
            .create_session(user, ABSOLUTE_LIFETIME_SECS, 1)
            .await
            .unwrap();
        let hash3 = crate::auth::token::sha256_hex(&secret3);
        db.backend
            .execute(
                "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
                &vals![hash3, now - IDLE_TIMEOUT_SECS + 60],
            )
            .await
            .unwrap();
        assert!(db.validate_session(&secret3).await.unwrap().is_some());
        let seen: i64 = db
            .backend
            .query_opt(
                "SELECT last_seen_at FROM sessions WHERE id_hash = ?1",
                &vals![hash3],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert!(seen >= now, "last_seen_at slid forward to now");
    }

    #[tokio::test]
    async fn session_is_sudo_window() {
        use crate::auth::session::SUDO_WINDOW_SECS;
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("dev@acme.com", None).await.unwrap();

        // A fresh auth_level=1 session is sudo.
        let secret = db.create_session(user, 3600, 1).await.unwrap();
        let session = db.validate_session(&secret).await.unwrap().unwrap();
        let now = unix_now();
        assert!(session.is_sudo(now));
        // Past the window it is no longer sudo.
        assert!(!session.is_sudo(now + SUDO_WINDOW_SECS + 1));

        // An auth_level=0 session is never sudo.
        let weak = db.create_session(user, 3600, 0).await.unwrap();
        let weak = db.validate_session(&weak).await.unwrap().unwrap();
        assert!(!weak.is_sudo(now));
    }

    #[tokio::test]
    async fn device_flow_full_path_with_scope_clamping() {
        use crate::domain::{Permission, Principal, Role, Scope};
        let db = Database::open_in_memory().await.unwrap();
        let approver = db.create_user("admin@acme.com", None).await.unwrap();
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
            .await
            .unwrap();
        assert_eq!(ttl, crate::auth::device::DEVICE_CODE_TTL_SECS);
        assert_eq!(user_code.len(), 9);

        // Pending before approval.
        assert_eq!(
            db.poll_device(&device_code).await.unwrap(),
            DevicePollResult::Pending
        );

        // Approve as the maintainer.
        assert!(db
            .approve_device(&user_code, Principal::user(approver), &grants)
            .await
            .unwrap());

        // Poll returns Approved with a token secret.
        let result = db.poll_device(&device_code).await.unwrap();
        let DevicePollResult::Approved(token_secret) = result else {
            panic!("expected Approved, got {result:?}");
        };

        // The minted token is owned by the approver and clamped: it has
        // read+publish (maintainer at acme covers acme/infra) but NOT
        // members.manage.
        let auth = db.validate_token(&token_secret).await.unwrap().unwrap();
        assert_eq!(auth.owner, Principal::user(approver));
        assert_eq!(auth.scope.as_str(), "acme/infra");
        assert!(auth.permissions.contains(&Permission::Read));
        assert!(auth.permissions.contains(&Permission::Publish));
        assert!(!auth.permissions.contains(&Permission::MembersManage));
    }

    #[tokio::test]
    async fn device_flow_deny_and_unknown() {
        use crate::domain::Permission;
        let db = Database::open_in_memory().await.unwrap();
        let (device_code, user_code, _) = db
            .start_device_authorization("acme", &[Permission::Read])
            .await
            .unwrap();
        assert!(db.deny_device(&user_code).await.unwrap());
        assert_eq!(
            db.poll_device(&device_code).await.unwrap(),
            DevicePollResult::Denied
        );

        // An unknown user_code cannot be approved or denied.
        assert!(!db
            .approve_device("ZZZZ-9999", crate::domain::Principal::user(1), &[])
            .await
            .unwrap());
        assert!(!db.deny_device("ZZZZ-9999").await.unwrap());
        // An unknown device_code polls as Pending.
        assert_eq!(
            db.poll_device("unknown").await.unwrap(),
            DevicePollResult::Pending
        );
    }

    #[tokio::test]
    async fn device_flow_expiry_blocks_approval() {
        use crate::domain::Permission;
        let db = Database::open_in_memory().await.unwrap();
        let (_device_code, user_code, _) = db
            .start_device_authorization("acme", &[Permission::Read])
            .await
            .unwrap();
        // Force the grant to be expired.
        db.backend
            .execute(
                "UPDATE device_codes SET expires_at = ?1 WHERE user_code = ?2",
                &vals![unix_now() - 1, user_code],
            )
            .await
            .unwrap();
        assert!(!db
            .approve_device(&user_code, crate::domain::Principal::user(1), &[])
            .await
            .unwrap());
    }

    /// M-3: a second approval of an already-approved `user_code` is a no-op —
    /// it returns `Ok(false)` and mints no second token. The atomic claim
    /// (`UPDATE … WHERE approved_by_user IS NULL`) stamps zero rows on the
    /// re-approval, so exactly one token exists per approval and no orphaned,
    /// un-pollable token is ever issued.
    #[tokio::test]
    async fn approve_device_is_idempotent_one_token_per_approval() {
        use crate::domain::{Permission, Principal, Role, Scope};
        let db = Database::open_in_memory().await.unwrap();
        let approver = db.create_user("admin@acme.com", None).await.unwrap();
        let principal = Principal::user(approver);
        let grants = vec![(Scope::parse("acme"), Role::Owner)];
        let (device_code, user_code, _) = db
            .start_device_authorization("acme", &[Permission::Read])
            .await
            .unwrap();

        // First approval mints exactly one token.
        assert!(db
            .approve_device(&user_code, principal, &grants)
            .await
            .unwrap());
        assert_eq!(db.list_tokens_for(principal).await.unwrap().len(), 1);
        let DevicePollResult::Approved(first_secret) = db.poll_device(&device_code).await.unwrap()
        else {
            panic!("expected Approved after first approval");
        };

        // A second approval of the same user_code is refused and mints nothing.
        assert!(!db
            .approve_device(&user_code, principal, &grants)
            .await
            .unwrap());
        assert_eq!(
            db.list_tokens_for(principal).await.unwrap().len(),
            1,
            "no second token minted on re-approval"
        );
        // The pollable secret is unchanged: still the single first token.
        let DevicePollResult::Approved(secret_again) = db.poll_device(&device_code).await.unwrap()
        else {
            panic!("expected Approved on re-poll");
        };
        assert_eq!(
            secret_again, first_secret,
            "the one token's secret is stable"
        );
    }

    /// M-3: a denied grant cannot subsequently be approved (the claim's
    /// `denied = 0` predicate matches zero rows), so no token is minted.
    #[tokio::test]
    async fn approve_device_after_deny_mints_nothing() {
        use crate::domain::{Permission, Principal, Role, Scope};
        let db = Database::open_in_memory().await.unwrap();
        let approver = db.create_user("admin@acme.com", None).await.unwrap();
        let principal = Principal::user(approver);
        let grants = vec![(Scope::parse("acme"), Role::Owner)];
        let (_device_code, user_code, _) = db
            .start_device_authorization("acme", &[Permission::Read])
            .await
            .unwrap();
        assert!(db.deny_device(&user_code).await.unwrap());
        assert!(!db
            .approve_device(&user_code, principal, &grants)
            .await
            .unwrap());
        assert!(
            db.list_tokens_for(principal).await.unwrap().is_empty(),
            "a denied grant mints no token"
        );
    }

    /// M-2: the transactional owner-safe revoke refuses to remove an org's last
    /// owner and rolls the delete back, but happily removes one of several
    /// owners.
    #[tokio::test]
    async fn revoke_membership_owner_safe_keeps_one_owner() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_org("acme", "Acme").await.unwrap();
        let alice = db.create_user("alice@acme.com", None).await.unwrap();
        let bob = db.create_user("bob@acme.com", None).await.unwrap();
        db.grant_membership("user", alice, "acme", "owner")
            .await
            .unwrap();
        db.grant_membership("user", bob, "acme", "owner")
            .await
            .unwrap();

        // Removing one of two owners succeeds.
        db.revoke_membership_owner_safe("user", bob, "acme")
            .await
            .unwrap();
        assert_eq!(owner_count(&db, "acme").await, 1);

        // Removing the now-sole owner is refused with a LastOwnerError and the
        // grant survives.
        let err = db
            .revoke_membership_owner_safe("user", alice, "acme")
            .await
            .unwrap_err();
        assert!(is_last_owner_error(&err), "got: {err:#}");
        assert_eq!(
            owner_count(&db, "acme").await,
            1,
            "the last owner is preserved"
        );
    }

    /// M-2: the transactional owner-safe role change refuses to demote an org's
    /// last owner; demoting one of several owners is fine. Two sequential
    /// demotes still leave at least one owner (the second is rejected).
    #[tokio::test]
    async fn set_membership_role_owner_safe_blocks_last_owner_demotion() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_org("acme", "Acme").await.unwrap();
        let alice = db.create_user("alice@acme.com", None).await.unwrap();
        let bob = db.create_user("bob@acme.com", None).await.unwrap();
        db.grant_membership("user", alice, "acme", "owner")
            .await
            .unwrap();
        db.grant_membership("user", bob, "acme", "owner")
            .await
            .unwrap();

        // Demoting one of two owners to admin succeeds.
        db.set_membership_role_owner_safe("user", bob, "acme", "admin")
            .await
            .unwrap();
        assert_eq!(owner_count(&db, "acme").await, 1);

        // Demoting the last owner is rejected; the org keeps an owner.
        let err = db
            .set_membership_role_owner_safe("user", alice, "acme", "admin")
            .await
            .unwrap_err();
        assert!(is_last_owner_error(&err), "got: {err:#}");
        assert_eq!(
            owner_count(&db, "acme").await,
            1,
            "the last owner is preserved"
        );
    }

    /// M-2: `delete_user` re-checks sole ownership inside its transaction, so a
    /// user who is the only owner of an org cannot be deleted; once another
    /// owner exists, the delete succeeds.
    #[tokio::test]
    async fn delete_user_re_checks_sole_ownership_in_tx() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_org("acme", "Acme").await.unwrap();
        let alice = db.create_user("alice@acme.com", None).await.unwrap();
        db.grant_membership("user", alice, "acme", "owner")
            .await
            .unwrap();

        // Sole owner: deletion is blocked.
        assert!(db.delete_user(alice).await.is_err());
        assert!(db.user_by_email("alice@acme.com").await.unwrap().is_some());

        // With a co-owner, deletion proceeds (the soft-delete leaves the
        // membership rows; what matters is that bob is still a live owner).
        let bob = db.create_user("bob@acme.com", None).await.unwrap();
        db.grant_membership("user", bob, "acme", "owner")
            .await
            .unwrap();
        assert!(db.delete_user(alice).await.unwrap());
        assert!(
            db.list_members_of_scope("acme")
                .await
                .unwrap()
                .iter()
                .any(|(k, id, r)| k == "user" && *id == bob && r == "owner"),
            "bob remains the org owner"
        );
    }

    /// Count the `owner`-role user grants at `scope`.
    async fn owner_count(db: &Database, scope: &str) -> usize {
        db.list_members_of_scope(scope)
            .await
            .unwrap()
            .iter()
            .filter(|(k, _, r)| k == "user" && r == "owner")
            .count()
    }

    #[tokio::test]
    async fn magic_links_single_use_and_expiry() {
        let db = Database::open_in_memory().await.unwrap();
        let secret = db.create_magic_link("user@acme.com").await.unwrap();
        assert_eq!(
            db.consume_magic_link(&secret).await.unwrap().as_deref(),
            Some("user@acme.com")
        );
        // Second consume fails (already consumed).
        assert!(db.consume_magic_link(&secret).await.unwrap().is_none());
        // Unknown secret fails.
        assert!(db.consume_magic_link("nope").await.unwrap().is_none());

        // An expired link cannot be consumed.
        let expired = db.create_magic_link("late@acme.com").await.unwrap();
        db.backend
            .execute(
                "UPDATE magic_links SET expires_at = ?1 WHERE email = 'late@acme.com'",
                &vals![unix_now() - 1],
            )
            .await
            .unwrap();
        assert!(db.consume_magic_link(&expired).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn channel_floors_persist_and_overwrite() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();
        assert!(db.channel_floor(id, "stable").await.unwrap().is_none());
        db.set_channel_floor(id, "stable", "1.0.0").await.unwrap();
        db.set_channel_floor(id, "stable", "1.2.0").await.unwrap();
        assert_eq!(
            db.channel_floor(id, "stable").await.unwrap().as_deref(),
            Some("1.2.0")
        );
    }

    #[tokio::test]
    async fn validation_runs_record_and_query() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
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
            .await
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
        .await
        .unwrap();
        db.record_validation_run(id, "file:///srv/cache", "presence", 0, &[], false, 20, 21)
            .await
            .unwrap();

        let latest = db.latest_validation_runs(id).await.unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].cache_url, "file:///srv/cache");
        assert!(!latest[0].reachable);
        assert_eq!(latest[1].cache_url, "https://cache.example");
        assert_eq!(latest[1].missing, 0);
        assert_eq!(
            db.validation_missing(run).await.unwrap(),
            vec!["aaa".to_string(), "bbb".to_string()]
        );
    }

    #[tokio::test]
    async fn take_webauthn_challenge_is_scoped_by_kind() {
        let db = Database::open_in_memory().await.unwrap();
        // A registration challenge is in flight for a victim.
        db.create_webauthn_challenge("chal-abc", Some(1), "registration", 300)
            .await
            .unwrap();

        // Submitting that known challenge value through the *assertion* endpoint
        // (wrong kind) consumes nothing and leaves the row intact.
        assert!(db
            .take_webauthn_challenge("chal-abc", "assertion")
            .await
            .unwrap()
            .is_none());

        // The registration challenge is still consumable via its own kind.
        let taken = db
            .take_webauthn_challenge("chal-abc", "registration")
            .await
            .unwrap()
            .expect("registration challenge survived the cross-kind attempt");
        assert_eq!(taken.kind, "registration");

        // And it is single-use: a second take finds nothing.
        assert!(db
            .take_webauthn_challenge("chal-abc", "registration")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn prune_repair_jobs_removes_old_rows() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();
        // An old job (created_at = 100) and a recent one (created_at = 10_000).
        db.record_repair_job(
            id,
            "file:///c",
            "old01",
            "file:///s",
            "done",
            None,
            100,
            Some(101),
        )
        .await
        .unwrap();
        db.record_repair_job(
            id,
            "file:///c",
            "new01",
            "file:///s",
            "done",
            None,
            10_000,
            Some(10_001),
        )
        .await
        .unwrap();
        assert_eq!(db.list_repair_jobs(id, 10).await.unwrap().len(), 2);

        // Pruning everything created before 1_000 removes only the old row.
        let pruned = db.prune_repair_jobs(1_000).await.unwrap();
        assert_eq!(pruned, 1);
        let remaining = db.list_repair_jobs(id, 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].store_hash, "new01");
    }

    #[tokio::test]
    async fn list_audit_is_bounded_and_newest_first() {
        let db = Database::open_in_memory().await.unwrap();
        // Append a batch of audit rows under one scope.
        let rows = 50;
        for i in 0..rows {
            db.record_audit(
                "user",
                None,
                "alice@acme.com",
                &format!("action.{i}"),
                "acme/infra",
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }

        // A root-scoped query returns every row (all under the cap), capped at
        // MAX_AUDIT_SCAN, newest (highest id) first.
        let all = db.list_audit("").await.unwrap();
        assert_eq!(all.len(), rows);
        assert!(
            all.len() <= MAX_AUDIT_SCAN as usize,
            "bounded by the scan cap"
        );
        assert_eq!(
            all[0].action,
            format!("action.{}", rows - 1),
            "newest first"
        );
        for pair in all.windows(2) {
            assert!(pair[0].id > pair[1].id, "ids strictly descending");
        }

        // Scope filtering still works over the bounded read.
        assert_eq!(db.list_audit("acme").await.unwrap().len(), rows);
        assert!(db.list_audit("other").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn v4_database_migrates_to_v5() {
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
        let db = Database::open(&path).await.unwrap();
        let count: i64 = db
            .backend
            .query_opt("SELECT COUNT(*) FROM storage_bindings", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        // v30 seeds exactly one row — the instance-default binding (RFC-0004
        // §12); no *user* bindings are created by the migration.
        assert_eq!(count, 1, "only the seeded instance-default binding exists");
        let defaults: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM storage_bindings WHERE is_instance_default = 1",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(
            defaults, 1,
            "exactly one instance-default binding is seeded"
        );
        let row = db
            .backend
            .query_opt(
                "SELECT storage_binding_id, prefix FROM registries WHERE slug = 'legacy'",
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        let binding: Option<i64> = row.get(0).unwrap();
        let prefix: String = row.get(1).unwrap();
        assert_eq!(binding, None);
        assert_eq!(prefix, "");

        // The legacy registry's surface is still its source_url path.
        let legacy = db.registry_by_slug("legacy").await.unwrap().unwrap();
        assert_eq!(
            db.registry_surface_root(legacy.id).await.unwrap(),
            Some(PathBuf::from("/srv/legacy"))
        );
    }

    #[tokio::test]
    async fn storage_bindings_crud_and_kind_validation() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let id = db
            .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
            .await
            .unwrap();
        let binding = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(binding.name, "primary");
        assert_eq!(binding.kind, "local_fs");
        assert_eq!(binding.root, "/srv/aos-hub");
        assert_eq!(
            db.storage_binding_by_name(org, "primary")
                .await
                .unwrap()
                .unwrap()
                .id,
            id
        );
        assert!(db
            .storage_binding_by_name(org, "nope")
            .await
            .unwrap()
            .is_none());

        db.create_storage_binding(org, "secondary", "local_fs", "/srv/other")
            .await
            .unwrap();
        let all = db.list_storage_bindings(org).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "primary");
        assert_eq!(all[1].name, "secondary");

        // Unsupported kinds are rejected up front.
        assert!(db
            .create_storage_binding(org, "r2", "external_r2", "s3://bucket")
            .await
            .is_err());

        // Access mode defaults to public; set-access updates it + metadata.
        assert_eq!(binding.access, "public");
        assert_eq!(binding.endpoint, None);
        assert!(db
            .set_storage_binding_access(id, "private", None, Some("sealed:cred-1"))
            .await
            .unwrap());
        let b = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(b.access, "private");
        assert_eq!(b.credential_ref.as_deref(), Some("sealed:cred-1"));
        assert!(db
            .set_storage_binding_access(id, "public", Some("https://cdn.example/"), None)
            .await
            .unwrap());
        let b = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(b.access, "public");
        assert_eq!(b.endpoint.as_deref(), Some("https://cdn.example/"));
        // An invalid access value is rejected.
        assert!(db
            .set_storage_binding_access(id, "bogus", None, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn storage_frontends_reject_direct_over_private_binding() {
        // RFC-0004 §12 security boundary: a private binding can never carry a
        // Direct frontend, so its objects are never handed out as a public URL.
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let id = db
            .create_storage_binding(org, "bucket", "r2", "acme-bucket")
            .await
            .unwrap();
        assert!(db.set_binding_public(id, "private", None).await.unwrap());

        // Direct over a private binding is rejected; proxied is allowed.
        assert!(db
            .create_storage_frontend(
                id,
                "cdn.acme.com",
                "",
                "direct",
                true,
                true,
                true,
                100,
                true
            )
            .await
            .is_err());
        assert!(db
            .create_storage_frontend(
                id,
                "proxy.acme.com",
                "",
                "proxied",
                true,
                true,
                true,
                100,
                true
            )
            .await
            .is_ok());

        // Publish the binding: a Direct frontend is now allowed.
        assert!(db
            .set_binding_public(id, "public", Some("https://cdn.acme.com"))
            .await
            .unwrap());
        assert!(db
            .create_storage_frontend(
                id,
                "cdn.acme.com",
                "",
                "direct",
                true,
                true,
                true,
                100,
                true
            )
            .await
            .is_ok());

        let list = db.list_storage_frontends(id).await.unwrap();
        assert_eq!(list.len(), 2, "the proxied and the direct frontend");
        assert!(list.iter().all(|f| f.storage_binding_id == Some(id)
            && f.registry_id.is_none()
            && f.cache_id.is_none()));

        // The seeded instance-default binding exists, is org-less, and ships
        // private — never Direct-eligible until an operator publishes it.
        let def = db.instance_default_binding().await.unwrap().unwrap();
        assert!(def.is_instance_default);
        assert_eq!(def.org_id, None);
        assert_eq!(def.access, "private");
    }

    #[tokio::test]
    async fn advertise_storage_frontend_toggle_defaults_on_and_updates() {
        // RFC-0004 §12: a consumer advertises its inherited storage frontend by
        // default and can opt out per-consumer.
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let reg = db
            .create_managed_registry(org, "team", "cdn", "public", None, "", &[], false)
            .await
            .unwrap();
        assert!(db.registry_advertises_storage_frontend(reg).await.unwrap());
        assert!(db
            .set_registry_advertise_storage_frontend(reg, false)
            .await
            .unwrap());
        assert!(!db.registry_advertises_storage_frontend(reg).await.unwrap());
        // Re-enabling restores the default behavior.
        assert!(db
            .set_registry_advertise_storage_frontend(reg, true)
            .await
            .unwrap());
        assert!(db.registry_advertises_storage_frontend(reg).await.unwrap());
        // A missing id is a no-op update (and reads as the default).
        assert!(!db
            .set_cache_advertise_storage_frontend(9999, false)
            .await
            .unwrap());
        assert!(db.cache_advertises_storage_frontend(9999).await.unwrap());
    }

    #[tokio::test]
    async fn managed_registry_without_binding_auto_derives_prefix_from_slug() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        // No binding, empty prefix: the prefix falls back to the canonical slug.
        let id = db
            .create_managed_registry(org, "team", "cdn", "public", None, "", &[], false)
            .await
            .unwrap();
        let reg = db.registry_by_slug("acme/team/cdn").await.unwrap().unwrap();
        assert_eq!(reg.id, id);
        assert_eq!(reg.storage_binding_id, None);
        assert_eq!(reg.prefix, "acme/team/cdn");
    }

    #[tokio::test]
    async fn managed_registry_rejects_duplicate_prefix() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        db.create_managed_registry(org, "", "first", "public", None, "shared", &[], false)
            .await
            .unwrap();
        // A different registry asking for the same explicit prefix collides.
        let err = db
            .create_managed_registry(org, "", "second", "public", None, "shared", &[], false)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("storage prefix 'shared'"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn default_storage_root_round_trips() {
        let db = Database::open_in_memory().await.unwrap();
        assert_eq!(db.default_storage_root().await.unwrap(), None);
        db.set_default_storage_root("/srv/aos-hub/registries")
            .await
            .unwrap();
        assert_eq!(
            db.default_storage_root().await.unwrap().as_deref(),
            Some("/srv/aos-hub/registries")
        );
    }

    #[tokio::test]
    async fn surface_root_uses_default_storage_for_binding_less_managed_registry() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let id = db
            .create_managed_registry(org, "", "cdn", "public", None, "", &[], false)
            .await
            .unwrap();
        // Without a default storage root configured, the surface is unservable.
        assert_eq!(db.registry_surface_root(id).await.unwrap(), None);
        // Once configured, it resolves to `{default_root}/{prefix}` (the prefix
        // having auto-derived to the slug).
        db.set_default_storage_root("/srv/aos-hub/registries")
            .await
            .unwrap();
        assert_eq!(
            db.registry_surface_root(id).await.unwrap(),
            Some(PathBuf::from("/srv/aos-hub/registries/acme/cdn"))
        );
    }

    #[tokio::test]
    async fn direct_frontend_over_private_binding_is_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let binding = db
            .create_storage_binding(org, "primary", "local_fs", "/srv")
            .await
            .unwrap();
        let reg = db
            .create_managed_registry(org, "", "cdn", "public", Some(binding), "cdn", &[], false)
            .await
            .unwrap();
        // While the binding is public, a Direct frontend is allowed.
        assert!(db
            .create_frontend(
                reg,
                "direct.example",
                "",
                "direct",
                true,
                true,
                true,
                100,
                true
            )
            .await
            .is_ok());
        // Make the binding private: a new Direct frontend is now rejected, but a
        // proxied frontend over the same private binding is allowed.
        db.set_storage_binding_access(binding, "private", None, Some("c"))
            .await
            .unwrap();
        assert!(db
            .create_frontend(
                reg,
                "direct2.example",
                "",
                "direct",
                true,
                true,
                true,
                100,
                true
            )
            .await
            .is_err());
        assert!(db
            .create_frontend(
                reg,
                "proxied.example",
                "",
                "proxied",
                true,
                true,
                true,
                100,
                true
            )
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn cache_frontends_coexist_with_registry_frontends() {
        let (db, org, binding) = cache_fixture().await;
        // A registry and a cache, each with its own frontend, share the table.
        let reg = db
            .create_managed_registry(org, "", "cdn", "public", Some(binding), "cdn", &[], false)
            .await
            .unwrap();
        let cache = db
            .create_cache(
                Some(org),
                "acme-cache",
                "Cache",
                Some(binding),
                "c",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        db.create_frontend(
            reg,
            "reg.example",
            "",
            "proxied",
            true,
            true,
            true,
            100,
            true,
        )
        .await
        .unwrap();
        db.create_cache_frontend(cache, "cache.example", "", "proxied", true, 40, true)
            .await
            .unwrap();

        // Each lists only its own frontends (the rebuilt table keys both targets).
        let reg_fes = db.list_frontends(reg).await.unwrap();
        assert_eq!(reg_fes.len(), 1);
        assert_eq!(reg_fes[0].registry_id, Some(reg));
        assert_eq!(reg_fes[0].cache_id, None);
        let cache_fes = db.list_cache_frontends(cache).await.unwrap();
        assert_eq!(cache_fes.len(), 1);
        assert_eq!(cache_fes[0].cache_id, Some(cache));
        assert_eq!(cache_fes[0].registry_id, None);
        // The registry-scoped list never leaks the cache frontend, and vice versa.
        assert!(db
            .list_cache_frontends(cache)
            .await
            .unwrap()
            .iter()
            .all(|f| f.registry_id.is_none()));

        // A Direct cache frontend over a private binding is rejected.
        db.set_storage_binding_access(binding, "private", None, Some("c"))
            .await
            .unwrap();
        assert!(db
            .create_cache_frontend(cache, "direct.example", "", "direct", true, 40, true)
            .await
            .is_err());

        // Proxy settings: default until set, then round-trip + primary flag.
        let cache_fe = db.list_cache_frontends(cache).await.unwrap()[0].id;
        assert!(db.list_cache_frontends(cache).await.unwrap()[0]
            .proxy_config
            .is_none());
        assert!(!db.list_cache_frontends(cache).await.unwrap()[0].is_primary);
        let cfg = ProxyConfig {
            read_timeout_secs: 90,
            stream: false,
            retries: 5,
            ..ProxyConfig::default()
        };
        assert!(db
            .set_frontend_proxy(cache_fe, Some(&cfg), true)
            .await
            .unwrap());
        let fe = &db.list_cache_frontends(cache).await.unwrap()[0];
        assert_eq!(fe.proxy_config.as_ref().unwrap().read_timeout_secs, 90);
        assert!(!fe.proxy_config.as_ref().unwrap().stream);
        assert_eq!(fe.proxy_config.as_ref().unwrap().retries, 5);
        // An unset field keeps the conservative default.
        assert_eq!(fe.proxy_config.as_ref().unwrap().connect_timeout_secs, 5);
        assert!(fe.is_primary);
        // Clearing reverts to defaults (None).
        assert!(db.set_frontend_proxy(cache_fe, None, false).await.unwrap());
        assert!(db.list_cache_frontends(cache).await.unwrap()[0]
            .proxy_config
            .is_none());
    }

    /// Set up an org + binding and return `(db, org_id, binding_id)`.
    async fn cache_fixture() -> (Database, i64, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let binding = db
            .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
            .await
            .unwrap();
        (db, org, binding)
    }

    #[tokio::test]
    async fn caches_crud_and_servable_filter() {
        let (db, org, binding) = cache_fixture().await;
        let id = db
            .create_cache(
                Some(org),
                "acme-cache",
                "Acme Cache",
                Some(binding),
                "caches/acme",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        // Duplicate slug rejected; unsafe prefix rejected.
        assert!(db
            .create_cache(
                None,
                "acme-cache",
                "x",
                Some(binding),
                "",
                None,
                "public",
                40,
                "zstd",
                true
            )
            .await
            .is_err());
        assert!(db
            .create_cache(
                None,
                "bad",
                "x",
                Some(binding),
                "../escape",
                None,
                "public",
                40,
                "zstd",
                true
            )
            .await
            .is_err());

        let c = db.cache_by_slug("acme-cache").await.unwrap().unwrap();
        assert_eq!(c.id, id);
        assert_eq!(c.org_id, Some(org));
        assert_eq!(c.prefix, "caches/acme");
        assert!(c.want_mass_query);
        assert_eq!(
            db.cache_by_id(id).await.unwrap().unwrap().slug,
            "acme-cache"
        );

        // An instance-level standalone cache (no org).
        db.create_cache(
            None,
            "standalone",
            "Standalone",
            Some(binding),
            "caches/std",
            None,
            "public",
            30,
            "xz",
            false,
        )
        .await
        .unwrap();
        assert_eq!(db.list_caches().await.unwrap().len(), 2);
        assert_eq!(db.list_caches_for_org(org).await.unwrap().len(), 1);

        db.update_cache(id, "Renamed", "private", 10, "none", false, None)
            .await
            .unwrap();
        let c = db.cache_by_id(id).await.unwrap().unwrap();
        assert_eq!(c.name, "Renamed");
        assert_eq!(c.visibility, "private");
        assert_eq!(c.priority, 10);
        assert!(!c.want_mass_query);

        // Soft-delete drops it from the servable list; hard-delete removes the row.
        assert!(db.soft_delete_cache(id, unix_now() + 100).await.unwrap());
        assert_eq!(db.list_caches().await.unwrap().len(), 1);
        assert!(db.delete_cache(id).await.unwrap());
        assert!(db.cache_by_id(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn binding_less_cache_rides_default_storage() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        db.set_default_storage_root("/srv/aos").await.unwrap();
        // No binding: the cache uses the deployment's default storage and its
        // prefix auto-derives from the slug (like a binding-less registry).
        let id = db
            .create_cache(
                Some(org),
                "build",
                "Build",
                None,
                "",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        let c = db.cache_by_id(id).await.unwrap().unwrap();
        assert_eq!(c.storage_binding_id, None);
        assert_eq!(c.prefix, "build");
        // The surface roots on the default storage root by that prefix.
        assert_eq!(
            db.cache_surface_root(id).await.unwrap().unwrap(),
            std::path::PathBuf::from("/srv/aos/build")
        );
        // With no default storage root configured, a binding-less cache has no
        // native surface (the Worker still serves it from R2 by prefix).
        let db2 = Database::open_in_memory().await.unwrap();
        let org2 = db2.create_org("b", "B").await.unwrap();
        let id2 = db2
            .create_cache(
                Some(org2),
                "c2",
                "C2",
                None,
                "",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        assert!(db2.cache_surface_root(id2).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_caches_excludes_soft_deleted_org() {
        let (db, org, binding) = cache_fixture().await;
        db.create_cache(
            Some(org),
            "owned",
            "Owned",
            Some(binding),
            "p1",
            None,
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
        db.create_cache(
            None,
            "standalone",
            "Standalone",
            Some(binding),
            "p2",
            None,
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
        assert_eq!(db.list_caches().await.unwrap().len(), 2);
        // Soft-deleting the org drops its cache from the servable list; the
        // instance-level (org_id IS NULL) cache still passes.
        assert!(db.soft_delete_org(org, 86_400).await.unwrap());
        let live = db.list_caches().await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].slug, "standalone");
    }

    #[tokio::test]
    async fn cache_links_gc_policy_and_pins() {
        let (db, org, binding) = cache_fixture().await;
        let cache = db
            .create_cache(
                Some(org),
                "c",
                "C",
                Some(binding),
                "p",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        let reg = db
            .create_managed_registry(org, "", "reg", "public", Some(binding), "reg", &[], false)
            .await
            .unwrap();

        // Link upserts: a second call updates the flags in place.
        db.link_cache(cache, reg, false, true).await.unwrap();
        db.link_cache(cache, reg, true, true).await.unwrap();
        let links = db.list_cache_links(cache).await.unwrap();
        assert_eq!(links.len(), 1);
        assert!(links[0].roots_packages && links[0].advertised);
        assert_eq!(db.cache_links_for_registry(reg).await.unwrap().len(), 1);
        assert!(db.unlink_cache(cache, reg).await.unwrap());
        assert!(db.list_cache_links(cache).await.unwrap().is_empty());

        // GC policy upsert.
        db.set_cache_gc_policy(&CacheGcPolicy {
            cache_id: cache,
            max_bytes: Some(1_000_000),
            max_objects: None,
            ttl_unreferenced_secs: Some(86_400),
            keep_release_versions: Some(3),
            keep_channel_frontier: true,
            schedule_secs: Some(3600),
            updated_at: 0,
        })
        .await
        .unwrap();
        let p = db.cache_gc_policy(cache).await.unwrap().unwrap();
        assert_eq!(p.max_bytes, Some(1_000_000));
        assert_eq!(p.keep_release_versions, Some(3));

        // Manual pin: renewable in place (no re-insert), then unpin.
        db.pin_cache_path(cache, "abc123", None).await.unwrap();
        db.pin_cache_path(cache, "abc123", Some(999)).await.unwrap(); // renew
        let roots = db.list_cache_roots(cache).await.unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].root_kind, "manual");
        assert_eq!(roots[0].expires_at, Some(999));
        assert!(db.unpin_cache_path(cache, "abc123").await.unwrap());
        assert!(db.list_cache_roots(cache).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cache_objects_search_refcount_and_usage() {
        let (db, org, binding) = cache_fixture().await;
        let cache = db
            .create_cache(
                Some(org),
                "c",
                "C",
                Some(binding),
                "p",
                None,
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        let obj = CacheObject {
            cache_id: cache,
            store_hash: "aaaa".into(),
            store_name: "aaaa-hello-1.0".into(),
            nar_url: "nar/ff.nar.zst".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 4096,
            file_hash: "ff".into(),
            file_size: 1024,
            compression: "zstd".into(),
            deriver: Some("dddd-hello.drv".into()),
            refs: vec!["bbbb".into(), "cccc".into()],
            sig: None,
            ca: None,
            uploaded_at: unix_now(),
            last_accessed_at: None,
        };
        db.upsert_cache_object(&obj).await.unwrap();
        let got = db.cache_object(cache, "aaaa").await.unwrap().unwrap();
        assert_eq!(got.refs, vec!["bbbb".to_string(), "cccc".to_string()]);
        assert_eq!(got.file_size, 1024);

        // Search by name / deriver substring.
        assert_eq!(
            db.search_cache_objects(cache, "hello", 50)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(db
            .search_cache_objects(cache, "absent", 50)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.list_cache_objects(cache, 50).await.unwrap().len(), 1);

        // Usage recompute.
        let usage = db.refresh_cache_usage(cache).await.unwrap();
        assert_eq!(usage.used_bytes, 1024);
        assert_eq!(usage.object_count, 1);
        assert_eq!(db.cache_usage(cache).await.unwrap().used_bytes, 1024);

        // LRU access signal: first touch lands; a touch within the debounce
        // window is a no-op; a touch past it updates.
        db.touch_cache_object(cache, "aaaa", 1_000).await.unwrap();
        assert_eq!(
            db.cache_object(cache, "aaaa")
                .await
                .unwrap()
                .unwrap()
                .last_accessed_at,
            Some(1_000)
        );
        db.touch_cache_object(cache, "aaaa", 1_500).await.unwrap(); // within 3600s
        assert_eq!(
            db.cache_object(cache, "aaaa")
                .await
                .unwrap()
                .unwrap()
                .last_accessed_at,
            Some(1_000),
            "debounced touch is a no-op"
        );
        db.touch_cache_object(cache, "aaaa", 1_000 + 3_601)
            .await
            .unwrap();
        assert_eq!(
            db.cache_object(cache, "aaaa")
                .await
                .unwrap()
                .unwrap()
                .last_accessed_at,
            Some(4_601),
            "touch past the debounce window updates"
        );
        // Touching an absent object is a harmless no-op.
        db.touch_cache_object(cache, "nope", 9_999).await.unwrap();

        // Content-addressed NAR refcount across the binding+prefix.
        assert_eq!(db.nar_refcount(Some(binding), "p", "ff").await.unwrap(), 1);
        assert!(db.delete_cache_object(cache, "aaaa").await.unwrap());
        assert_eq!(db.nar_refcount(Some(binding), "p", "ff").await.unwrap(), 0);

        // GC run lifecycle.
        let run = db.start_cache_gc_run(cache).await.unwrap();
        db.finish_cache_gc_run(run, "ok", None, 10, 8, 2, 2048)
            .await
            .unwrap();
        let runs = db.list_cache_gc_runs(cache, 10).await.unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "ok");
        assert_eq!(runs[0].freed_bytes, 2048);

        // Instance-wide metrics aggregate live caches and lifetime GC totals.
        // (The one object above was deleted, so object/byte counts are zero now.)
        let m = db.cache_metrics().await.unwrap();
        assert_eq!(m.cache_count, 1);
        assert_eq!(m.object_count, 0);
        assert_eq!(m.used_bytes, 0);
        assert_eq!(m.gc_runs_ok, 1);
        assert_eq!(m.gc_runs_failed, 0);
        assert_eq!(m.gc_freed_bytes, 2048);

        // Soft-deleting the owning org drops its cache from the live gauges
        // (the row's own `deleted_at` stays NULL until hard purge), matching
        // `list_caches`'s servable-surface predicate. Lifetime GC counters,
        // being historical, are unaffected.
        assert!(db.soft_delete_org(org, 86_400).await.unwrap());
        let m = db.cache_metrics().await.unwrap();
        assert_eq!(m.cache_count, 0);
        assert_eq!(m.gc_runs_ok, 1);
    }

    #[tokio::test]
    async fn advertised_caches_rename_preserves_advertised_list() {
        // After v22 the registry's advertised cache list lives in
        // `advertised_caches`; the `caches` table is the managed object.
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let binding = db
            .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
            .await
            .unwrap();
        // A managed cache and a registry coexist without table collision.
        db.create_cache(
            Some(org),
            "c",
            "C",
            Some(binding),
            "p",
            None,
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
        db.create_managed_registry(org, "", "reg", "public", Some(binding), "reg", &[], false)
            .await
            .unwrap();
        // list_advertised_caches reads the renamed table (empty until indexed).
        let reg = db.registry_by_slug("acme/reg").await.unwrap().unwrap();
        assert!(db.list_advertised_caches(reg.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn surface_root_precedence_managed_file_and_http() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let binding = db
            .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
            .await
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
            .await
            .unwrap();
        assert_eq!(
            db.registry_surface_root(managed).await.unwrap(),
            Some(PathBuf::from("/srv/aos-hub/infra/prod/cdn"))
        );

        // file:// source (no binding): the source path.
        let file = db
            .register_registry("filereg", "file:///srv/file", &[], false)
            .await
            .unwrap();
        assert_eq!(
            db.registry_surface_root(file).await.unwrap(),
            Some(PathBuf::from("/srv/file"))
        );

        // bare path source: also a local surface.
        let bare = db
            .register_registry("barereg", "/srv/bare", &[], false)
            .await
            .unwrap();
        assert_eq!(
            db.registry_surface_root(bare).await.unwrap(),
            Some(PathBuf::from("/srv/bare"))
        );

        // http source: no local surface.
        let http = db
            .register_registry("httpreg", "https://cdn.example/", &[], false)
            .await
            .unwrap();
        assert_eq!(db.registry_surface_root(http).await.unwrap(), None);

        // Binding wins even when a source_url is also present.
        db.set_registry_storage(file, Some(binding), "moved")
            .await
            .unwrap();
        assert_eq!(
            db.registry_surface_root(file).await.unwrap(),
            Some(PathBuf::from("/srv/aos-hub/moved"))
        );

        // Unknown registry id: None.
        assert_eq!(db.registry_surface_root(9999).await.unwrap(), None);
    }

    #[tokio::test]
    async fn managed_registry_canonical_slug_and_scope_lookup() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();

        // A traversal-bearing prefix is rejected (defense in depth).
        assert!(db
            .create_managed_registry(org, "infra", "evil", "public", None, "../../etc", &[], true)
            .await
            .is_err());

        // With a project path.
        let cdn = db
            .create_managed_registry(org, "infra/prod", "cdn", "public", None, "", &[], true)
            .await
            .unwrap();
        let record = db
            .registry_by_slug("acme/infra/prod/cdn")
            .await
            .unwrap()
            .unwrap();
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
                .await
                .unwrap()
                .unwrap()
                .id,
            cdn
        );
        // project_path normalization: leading/trailing slashes collapse.
        assert_eq!(
            db.registry_by_scope("acme", "/infra/prod/", "cdn")
                .await
                .unwrap()
                .unwrap()
                .id,
            cdn
        );

        // Org-root registry (empty project path) -> "acme/web".
        let web = db
            .create_managed_registry(org, "", "web", "internal", None, "", &[], true)
            .await
            .unwrap();
        assert_eq!(
            db.registry_by_slug("acme/web").await.unwrap().unwrap().id,
            web
        );
        assert_eq!(
            db.registry_by_scope("acme", "", "web")
                .await
                .unwrap()
                .unwrap()
                .id,
            web
        );

        // Duplicate canonical path is rejected.
        assert!(db
            .create_managed_registry(org, "infra/prod", "cdn", "public", None, "", &[], true)
            .await
            .is_err());

        // A flat phase-1 slug coexists and resolves by its bare slug.
        db.register_registry("legacy", "/srv/legacy", &[], false)
            .await
            .unwrap();
        assert!(db.registry_by_slug("legacy").await.unwrap().is_some());
        assert!(db
            .registry_by_scope("acme", "", "legacy")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn update_channels_replaces_only_channels() {
        let db = Database::open_in_memory().await.unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .await
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
        db.apply_snapshot(id, &snapshot).await.unwrap();

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
        .await
        .unwrap();

        let channels = db.list_channels(id).await.unwrap();
        assert_eq!(channels[0].partitions.iter().flatten().count(), 255);
        // Releases (and the rest of the index) are untouched.
        assert_eq!(db.list_releases(id).await.unwrap().len(), 1);
        assert_eq!(db.index_status(id).await.unwrap().unwrap().state, "fresh");
    }

    // -- operations: quotas, usage, signup policy, offboarding (v13) --------

    #[tokio::test]
    async fn quota_defaults_to_unlimited_and_round_trips() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        // No quota row: every dimension unlimited.
        assert_eq!(db.org_quota(org).await.unwrap(), OrgQuota::default());
        assert!(!db.would_exceed_quota(org, i64::MAX / 2).await.unwrap());

        let quota = OrgQuota {
            max_bytes: Some(1000),
            max_objects: Some(10),
            max_registries: Some(2),
            max_tokens: Some(5),
        };
        db.set_org_quota(org, &quota).await.unwrap();
        assert_eq!(db.org_quota(org).await.unwrap(), quota);
    }

    #[tokio::test]
    async fn usage_accumulates_and_drives_would_exceed_quota() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        db.set_org_quota(
            org,
            &OrgQuota {
                max_bytes: Some(100),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(db.org_usage(org).await.unwrap(), OrgUsage::default());
        // 60 more fits under 100.
        assert!(!db.would_exceed_quota(org, 60).await.unwrap());
        db.add_org_usage(org, 60, 1).await.unwrap();
        assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 60);
        assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);
        // 60 + 50 = 110 > 100: would exceed.
        assert!(db.would_exceed_quota(org, 50).await.unwrap());
        // 60 + 40 = 100 is not *over* 100.
        assert!(!db.would_exceed_quota(org, 40).await.unwrap());
    }

    #[tokio::test]
    async fn reserve_org_usage_is_atomic_and_charges_deltas() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        db.set_org_quota(
            org,
            &OrgQuota {
                max_bytes: Some(100),
                max_objects: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // First reservation of 60 bytes / 1 object fits and is recorded.
        assert!(db.reserve_org_usage(org, 60, 1).await.unwrap());
        assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 60);
        assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);

        // A second reservation that would push past the byte cap (60+50 > 100)
        // is rejected and leaves usage untouched — the check-and-reserve is one
        // step, so it cannot be raced through.
        assert!(!db.reserve_org_usage(org, 50, 1).await.unwrap());
        assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 60);
        assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);

        // A reservation that fits the byte cap but exceeds the object cap is
        // rejected too (object_count 1 + 2 > 2).
        assert!(!db.reserve_org_usage(org, 10, 2).await.unwrap());
        assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);

        // 40 more bytes lands exactly at the cap and a 2nd object.
        assert!(db.reserve_org_usage(org, 40, 1).await.unwrap());
        assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 100);
        assert_eq!(db.org_usage(org).await.unwrap().object_count, 2);

        // A shrinking overwrite charges a negative delta and frees room; usage
        // never goes below zero.
        assert!(db.reserve_org_usage(org, -30, 0).await.unwrap());
        assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 70);
        assert!(db.reserve_org_usage(org, -1_000, -10).await.unwrap());
        assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
        assert_eq!(db.org_usage(org).await.unwrap().object_count, 0);
    }

    #[tokio::test]
    async fn signup_policy_defaults_invite_only_and_round_trips() {
        let db = Database::open_in_memory().await.unwrap();
        assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::InviteOnly);
        db.set_signup_policy(SignupPolicy::Open).await.unwrap();
        assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::Open);
        // An unknown stored value falls closed to invite-only.
        db.instance_config_set("signup_policy", "garbage")
            .await
            .unwrap();
        assert_eq!(db.signup_policy().await.unwrap(), SignupPolicy::InviteOnly);
    }

    #[tokio::test]
    async fn registry_crawl_policy_and_llms_defaults_and_round_trip() {
        use crate::crawl::CrawlPolicy;
        let db = Database::open_in_memory().await.unwrap();
        db.register_registry("demo", "/srv/demo", &[], false)
            .await
            .unwrap();

        // The new columns default permissively / null on an existing registry.
        let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
        assert_eq!(reg.crawl_policy, "allow_all");
        assert_eq!(reg.llms_txt_body, None);

        // Crawl policy round-trips by slug.
        db.set_registry_crawl_policy("demo", CrawlPolicy::DenyAll.as_str())
            .await
            .unwrap();
        let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
        assert_eq!(reg.crawl_policy, "deny_all");

        // Custom llms.txt sets and clears.
        db.set_registry_llms_txt("demo", Some("# custom\n"))
            .await
            .unwrap();
        assert_eq!(
            db.registry_by_slug("demo")
                .await
                .unwrap()
                .unwrap()
                .llms_txt_body,
            Some("# custom\n".to_string())
        );
        db.set_registry_llms_txt("demo", None).await.unwrap();
        assert_eq!(
            db.registry_by_slug("demo")
                .await
                .unwrap()
                .unwrap()
                .llms_txt_body,
            None
        );
    }

    #[tokio::test]
    async fn root_crawl_policy_and_overrides_round_trip() {
        use crate::crawl::CrawlPolicy;
        let db = Database::open_in_memory().await.unwrap();
        // Defaults to allow-all when unset.
        assert_eq!(db.root_crawl_policy().await.unwrap(), CrawlPolicy::AllowAll);
        db.set_root_crawl_policy(CrawlPolicy::AllowNoAi)
            .await
            .unwrap();
        assert_eq!(
            db.root_crawl_policy().await.unwrap(),
            CrawlPolicy::AllowNoAi
        );
        // A corrupt stored value reads as the permissive default (lenient read).
        db.instance_config_set("root_crawl_policy", "garbage")
            .await
            .unwrap();
        assert_eq!(db.root_crawl_policy().await.unwrap(), CrawlPolicy::AllowAll);

        // Root robots/llms overrides set and clear.
        assert_eq!(db.root_robots_body().await.unwrap(), None);
        db.set_root_robots_body(Some("User-agent: *\n"))
            .await
            .unwrap();
        assert_eq!(
            db.root_robots_body().await.unwrap(),
            Some("User-agent: *\n".to_string())
        );
        db.set_root_robots_body(None).await.unwrap();
        assert_eq!(db.root_robots_body().await.unwrap(), None);

        db.set_root_llms_body(Some("# hub\n")).await.unwrap();
        assert_eq!(
            db.root_llms_body().await.unwrap(),
            Some("# hub\n".to_string())
        );
        db.set_root_llms_body(None).await.unwrap();
        assert_eq!(db.root_llms_body().await.unwrap(), None);
    }

    #[tokio::test]
    async fn soft_delete_excludes_from_serving_then_restore() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        db.register_owned(org, "acme/cdn").await;
        assert!(db.org_by_slug("acme").await.unwrap().is_some());
        assert_eq!(db.list_orgs().await.unwrap().len(), 1);
        assert_eq!(db.list_registries().await.unwrap().len(), 1);

        assert!(db.soft_delete_org(org, 30 * 86_400).await.unwrap());
        // Excluded from active serving queries...
        assert!(db.org_by_slug("acme").await.unwrap().is_none());
        assert!(db.list_orgs().await.unwrap().is_empty());
        assert!(db.list_registries().await.unwrap().is_empty());
        assert!(!db.org_is_active(org).await.unwrap());
        // ...but still visible to the admin/restore path.
        assert!(db
            .org_by_slug_including_deleted("acme")
            .await
            .unwrap()
            .is_some());

        assert!(db.restore_org(org).await.unwrap());
        assert!(db.org_by_slug("acme").await.unwrap().is_some());
        assert_eq!(db.list_registries().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mirror_and_frontend_creation_reject_unsafe_targets() {
        // The lib test binary never sets the escape hatch.
        assert!(std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_none());
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let reg = db
            .create_managed_registry(org, "infra/prod", "cdn", "public", None, "", &[], false)
            .await
            .unwrap();

        // A file:// or loopback mirror upstream is rejected at creation.
        assert!(db
            .create_mirror_source(reg, "file:///srv/secret", "full", true, 3600)
            .await
            .is_err());
        assert!(db
            .create_mirror_source(reg, "http://127.0.0.1/", "full", true, 3600)
            .await
            .is_err());
        assert!(db
            .create_mirror_source(reg, "http://169.254.169.254/", "full", true, 3600)
            .await
            .is_err());

        // A loopback frontend domain is rejected at creation.
        assert!(db
            .create_frontend(reg, "127.0.0.1", "", "direct", true, true, false, 100, true)
            .await
            .is_err());
        assert!(db
            .create_frontend(
                reg,
                "http://10.0.0.1",
                "",
                "direct",
                true,
                true,
                false,
                100,
                true
            )
            .await
            .is_err());

        // A public literal mirror passes creation (no DNS needed).
        assert!(db
            .create_mirror_source(reg, "https://93.184.216.34/", "full", true, 3600)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn purge_only_after_grace_window() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let now = unix_now();
        db.soft_delete_org(org, 100).await.unwrap();
        // Not yet purgeable just after deletion.
        assert!(db.list_purgeable_orgs(now).await.unwrap().is_empty());
        // Past the grace window it is listed and can be purged.
        let purgeable = db.list_purgeable_orgs(now + 200).await.unwrap();
        assert_eq!(purgeable.len(), 1);
        assert!(db.hard_purge_org(org, now + 200).await.unwrap());
        assert!(db
            .org_by_slug_including_deleted("acme")
            .await
            .unwrap()
            .is_none());
    }

    // regression: a restore landing between `list_purgeable_orgs` and
    // `hard_purge_org` (the unguarded list+delete race) must not destroy the
    // now-active org. `hard_purge_org` re-asserts the soft-deleted/past-grace
    // predicate, so the delete is a no-op once the org is restored.
    #[tokio::test]
    async fn purge_is_no_op_for_org_restored_in_window() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        db.register_owned(org, "acme/cdn").await;
        // Soft-delete with a zero grace window so the org is purgeable now.
        db.soft_delete_org(org, 0).await.unwrap();
        let purgeable = db.list_purgeable_orgs(unix_now()).await.unwrap();
        assert_eq!(purgeable.len(), 1);

        // The admin restores it before the purge job reaches the delete.
        assert!(db.restore_org(org).await.unwrap());

        // The purge delete is now a no-op: it returns `Ok(false)` and the
        // org — and everything it owns — survives.
        assert!(!db.hard_purge_org(org, unix_now()).await.unwrap());
        assert!(db.org_by_slug("acme").await.unwrap().is_some());
        assert!(db.org_is_active(org).await.unwrap());
        assert_eq!(db.list_registries().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sole_owner_delete_blocked_then_transfer_succeeds() {
        use crate::domain::{Permission, Principal, Role};
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        let alice = db.create_user("alice@acme.com", None).await.unwrap();
        let bob = db.create_user("bob@acme.com", None).await.unwrap();
        db.grant_membership("user", alice, "acme", "owner")
            .await
            .unwrap();
        // Alice has a token + a session, to confirm they deaden on deletion.
        let (token_id, secret) = db
            .create_token(
                Principal::user(alice),
                "acme",
                &[Permission::Read],
                None,
                None,
            )
            .await
            .unwrap();
        let session = db.create_session(alice, 3600, 1).await.unwrap();

        // Alice is the sole owner: deletion is blocked.
        assert_eq!(
            db.sole_owned_orgs(alice).await.unwrap(),
            vec!["acme".to_string()]
        );
        assert!(db.delete_user(alice).await.is_err());
        // The token and session are untouched by the failed delete.
        assert!(db.validate_token(&secret).await.unwrap().is_some());
        assert!(db.validate_session(&session).await.unwrap().is_some());

        // Transfer ownership to Bob, then Alice is deletable.
        db.transfer_org_ownership(org, alice, bob).await.unwrap();
        assert!(db.sole_owned_orgs(alice).await.unwrap().is_empty());
        assert!(db.delete_user(alice).await.unwrap());
        // Alice's credentials deaden immediately.
        assert!(db.validate_token(&secret).await.unwrap().is_none());
        assert!(db.validate_session(&session).await.unwrap().is_none());
        assert!(db.user_email(alice).await.unwrap().is_none());
        let _ = token_id;
        // Bob now owns acme.
        let grants = db.effective_scopes(Principal::user(bob)).await.unwrap();
        assert!(grants
            .iter()
            .any(|(s, r)| s.as_str() == "acme" && *r == Role::Owner));
    }

    #[tokio::test]
    async fn create_org_backstop_rejects_non_segment_slugs() {
        // CR-2 persistence backstop: even if a caller bypasses the RPC/console
        // validator, the db refuses to write an org slug that is not a single
        // path segment, so it can never normalize into an ancestor scope.
        let db = Database::open_in_memory().await.unwrap();
        for bad in ["/", "/victimorg", "foo/bar", "foo ", "Acme", ""] {
            assert!(
                db.create_org(bad, "Name").await.is_err(),
                "create_org should reject slug {bad:?}"
            );
            assert!(db.org_by_slug(bad).await.unwrap().is_none());
        }
        // A normal single-segment slug still succeeds.
        assert!(db.create_org("acme", "Acme").await.is_ok());
        assert_eq!(db.org_by_slug("acme").await.unwrap().unwrap().slug, "acme");
    }

    #[tokio::test]
    async fn grant_membership_backstop_rejects_non_canonical_scopes() {
        // CR-2 persistence backstop: grant_membership refuses any scope that
        // `Scope::parse` would normalize into a different (broader) string,
        // blocking the "/"->root and "/victimorg"->victimorg escalations.
        use crate::domain::{Principal, Role};
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@example.com", None).await.unwrap();
        for bad in ["/", "/victimorg", "foo/", "foo//bar", "/foo/"] {
            assert!(
                db.grant_membership("user", user, bad, Role::Owner.as_str())
                    .await
                    .is_err(),
                "grant_membership should reject non-canonical scope {bad:?}"
            );
        }
        // The user gained no grant from any rejected call.
        assert!(db
            .effective_scopes(Principal::user(user))
            .await
            .unwrap()
            .is_empty());

        // Legitimately formed scopes still work: the instance root "", an org
        // scope "acme", and a multi-segment registry scope "acme/cdn".
        for good in ["", "acme", "acme/cdn", "acme/infra/prod/cdn"] {
            db.grant_membership("user", user, good, Role::Viewer.as_str())
                .await
                .unwrap_or_else(|e| panic!("scope {good:?} should be accepted: {e}"));
        }
        let scopes: Vec<String> = db
            .effective_scopes(Principal::user(user))
            .await
            .unwrap()
            .into_iter()
            .map(|(s, _)| s.as_str().to_string())
            .collect();
        assert!(scopes.iter().any(|s| s.is_empty()), "root scope granted");
        assert!(scopes.iter().any(|s| s == "acme/cdn"));
    }

    fn topology_placement(
        surface: SurfaceTarget,
        name: &str,
        prefix: &str,
        read_order: i64,
    ) -> NewSurfacePlacement {
        NewSurfacePlacement {
            surface,
            name: name.to_string(),
            storage_binding_id: 0,
            prefix: prefix.to_string(),
            role: "replica".to_string(),
            state: "ready".to_string(),
            completeness: "complete".to_string(),
            partition_rule_json: None,
            read_enabled: true,
            write_enabled: false,
            read_order,
            write_order: 0,
        }
    }

    #[tokio::test]
    async fn topology_v34_opens_and_rejects_xor_and_location_collisions() {
        let db = Database::open_in_memory().await.unwrap();
        let version: i64 = db
            .backend
            .query_opt("SELECT version FROM schema_version", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);

        let org = db.create_org("topology", "Topology").await.unwrap();
        let binding = db
            .create_storage_binding(org, "placement", "local_fs", "/tmp/topology")
            .await
            .unwrap();
        let registry = db
            .create_managed_registry(
                org,
                "",
                "registry",
                "public",
                Some(binding),
                "legacy-registry",
                &[],
                false,
            )
            .await
            .unwrap();
        let cache = db
            .create_cache(
                Some(org),
                "topology-cache",
                "Topology cache",
                Some(binding),
                "legacy-cache",
                None,
                "public",
                10,
                "zstd",
                true,
            )
            .await
            .unwrap();

        let raw_xor = db
            .backend
            .execute(
                "INSERT INTO surface_placements (registry_id, cache_id, name,
                storage_binding_id, prefix, role, state, completeness,
                read_enabled, write_enabled, created_at, updated_at)
             VALUES (?1, ?2, 'invalid-xor', ?3, 'invalid-xor', 'replica',
                'ready', 'complete', 1, 0, ?4, ?4)",
                &vals![registry, cache, binding, unix_now()],
            )
            .await;
        assert!(
            raw_xor.is_err(),
            "database CHECK must reject a dual-surface row"
        );

        let mut first = topology_placement(SurfaceTarget::Registry(registry), "one", "same", 0);
        first.storage_binding_id = binding;
        db.create_surface_placement(&first).await.unwrap();
        let mut collision = topology_placement(SurfaceTarget::BinaryCache(cache), "two", "same", 1);
        collision.storage_binding_id = binding;
        assert!(
            db.create_surface_placement(&collision).await.is_err(),
            "physical-location aliases require a future reviewed equivalence workflow"
        );
    }

    #[tokio::test]
    async fn topology_rejects_cross_scope_and_cross_surface_relationships() {
        let db = Database::open_in_memory().await.unwrap();
        let org_a = db.create_org("orga", "Org A").await.unwrap();
        let org_b = db.create_org("orgb", "Org B").await.unwrap();
        let binding_a = db
            .create_storage_binding(org_a, "a", "local_fs", "/tmp/a")
            .await
            .unwrap();
        let binding_b = db
            .create_storage_binding(org_b, "b", "local_fs", "/tmp/b")
            .await
            .unwrap();
        let registry = db
            .create_managed_registry(
                org_a,
                "",
                "registry",
                "public",
                Some(binding_a),
                "legacy-a",
                &[],
                false,
            )
            .await
            .unwrap();
        let cache = db
            .create_cache(
                Some(org_a),
                "cache-a",
                "Cache A",
                Some(binding_a),
                "legacy-cache-a",
                None,
                "public",
                10,
                "zstd",
                true,
            )
            .await
            .unwrap();

        let mut wrong_binding =
            topology_placement(SurfaceTarget::Registry(registry), "wrong", "wrong", 0);
        wrong_binding.storage_binding_id = binding_b;
        assert!(db.create_surface_placement(&wrong_binding).await.is_err());

        let mut registry_placement = topology_placement(
            SurfaceTarget::Registry(registry),
            "registry-primary",
            "registry-placement",
            0,
        );
        registry_placement.storage_binding_id = binding_a;
        let registry_placement = db
            .create_surface_placement(&registry_placement)
            .await
            .unwrap();
        let mut cache_placement = topology_placement(
            SurfaceTarget::BinaryCache(cache),
            "cache-primary",
            "cache-placement",
            0,
        );
        cache_placement.storage_binding_id = binding_a;
        let cache_placement = db.create_surface_placement(&cache_placement).await.unwrap();
        let policy = db
            .create_placement_policy(&NewPlacementPolicy {
                surface: SurfaceTarget::Registry(registry),
                name: "read".to_string(),
                kind: "ordered_failover".to_string(),
                config_json: "{}".to_string(),
            })
            .await
            .unwrap();
        assert!(db
            .add_placement_policy_member(
                policy.id,
                PlacementPolicyMemberInput {
                    placement_id: cache_placement.id,
                    member_order: 0,
                    required: true,
                }
            )
            .await
            .is_err());
        db.add_placement_policy_member(
            policy.id,
            PlacementPolicyMemberInput {
                placement_id: registry_placement.id,
                member_order: 0,
                required: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.placement_policy(policy.id)
                .await
                .unwrap()
                .unwrap()
                .resource_version,
            policy.resource_version + 1
        );

        let domain = db
            .create_domain(&NewDomain {
                org_id: Some(org_a),
                hostname: "Routes.Example.COM.".to_string(),
                desired_dns_provider: None,
                desired_tls_provider: None,
                access_provider_json: "{}".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(domain.hostname, "routes.example.com");
        let bad_route = NewDeliveryRoute {
            domain_id: domain.id,
            storage_gateway_id: None,
            gateway_generation: None,
            base_path: "/cache/".to_string(),
            surface: SurfaceTarget::BinaryCache(cache),
            mode: "hub_proxy".to_string(),
            access_policy_json: "{}".to_string(),
            selector: RoutePlacementSelector::Placement(cache_placement.id),
            serves_git: true,
            serves_cache: true,
            serves_web: false,
            enabled: true,
        };
        assert!(db.create_delivery_route(&bad_route).await.is_err());
        let domain = db
            .record_domain_observation(
                domain.id,
                domain.resource_version,
                "verified",
                "active",
                Some(unix_now()),
            )
            .await
            .unwrap();
        assert!(db
            .create_delivery_route(&NewDeliveryRoute {
                domain_id: domain.id,
                storage_gateway_id: None,
                gateway_generation: None,
                base_path: "/direct-policy".to_string(),
                surface: SurfaceTarget::Registry(registry),
                mode: "direct".to_string(),
                access_policy_json: "{}".to_string(),
                selector: RoutePlacementSelector::Policy(policy.id),
                serves_git: true,
                serves_cache: false,
                serves_web: false,
                enabled: true,
            })
            .await
            .is_err());
        let route = db
            .create_delivery_route(&NewDeliveryRoute {
                domain_id: domain.id,
                storage_gateway_id: None,
                gateway_generation: None,
                base_path: "/cache".to_string(),
                surface: SurfaceTarget::BinaryCache(cache),
                mode: "hub_proxy".to_string(),
                access_policy_json: "{}".to_string(),
                selector: RoutePlacementSelector::Placement(cache_placement.id),
                serves_git: false,
                serves_cache: true,
                serves_web: true,
                enabled: true,
            })
            .await
            .unwrap();
        db.set_canonical_route(
            SurfaceTarget::BinaryCache(cache),
            "nix_cache",
            route.id,
            None,
        )
        .await
        .unwrap();
        assert!(db
            .update_delivery_route(
                route.id,
                &UpdateDeliveryRoute {
                    expected_version: route.resource_version,
                    mode: route.mode.clone(),
                    access_policy_json: route.access_policy_json.clone(),
                    serves_git: false,
                    serves_cache: false,
                    serves_web: true,
                    enabled: true,
                }
            )
            .await
            .is_err());
        let pending_domain = db
            .update_domain(
                domain.id,
                &UpdateDomain {
                    expected_version: domain.resource_version,
                    desired_dns_provider: Some("dns-provider-2".to_string()),
                    desired_tls_provider: domain.desired_tls_provider.clone(),
                    access_provider_json: domain.access_provider_json.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(pending_domain.observed_dns_state, "pending");
        assert!(pending_domain.verified_at.is_none());
        assert!(db
            .canonical_route(SurfaceTarget::BinaryCache(cache), "nix_cache")
            .await
            .unwrap()
            .is_none());
        let domain = db
            .record_domain_observation(
                pending_domain.id,
                pending_domain.resource_version,
                "verified",
                "active",
                Some(unix_now()),
            )
            .await
            .unwrap();
        let degraded_domain = db
            .record_domain_observation(
                domain.id,
                domain.resource_version,
                "pending",
                "pending",
                None,
            )
            .await
            .unwrap();
        assert!(db
            .canonical_route(SurfaceTarget::BinaryCache(cache), "nix_cache")
            .await
            .unwrap()
            .is_none());
        let configured = db
            .configured_canonical_route(SurfaceTarget::BinaryCache(cache), "nix_cache")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(configured.delivery_route_id, route.id);
        assert_eq!(
            db.list_configured_canonical_routes(SurfaceTarget::BinaryCache(cache))
                .await
                .unwrap(),
            vec![configured.clone()]
        );
        db.record_domain_observation(
            degraded_domain.id,
            degraded_domain.resource_version,
            "verified",
            "active",
            Some(unix_now()),
        )
        .await
        .unwrap();
        let updated_canonical = db
            .set_canonical_route(
                SurfaceTarget::BinaryCache(cache),
                "nix_cache",
                route.id,
                Some(configured.resource_version),
            )
            .await
            .unwrap();
        assert_eq!(
            updated_canonical.resource_version,
            configured.resource_version + 1
        );
        db.set_binding_public(binding_a, "public", None)
            .await
            .unwrap();
        db.update_delivery_route(
            route.id,
            &UpdateDeliveryRoute {
                expected_version: route.resource_version,
                mode: "direct".to_string(),
                access_policy_json: route.access_policy_json.clone(),
                serves_git: false,
                serves_cache: true,
                serves_web: true,
                enabled: true,
            },
        )
        .await
        .unwrap();
        assert!(db
            .canonical_route(SurfaceTarget::BinaryCache(cache), "nix_cache")
            .await
            .unwrap()
            .is_some());
        db.set_binding_public(binding_a, "private", None)
            .await
            .unwrap();
        assert!(db
            .canonical_route(SurfaceTarget::BinaryCache(cache), "nix_cache")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .configured_canonical_route(SurfaceTarget::BinaryCache(cache), "nix_cache")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn topology_orders_named_placements_and_rejects_stale_versions() {
        assert_eq!(join_topology_paths("", "").unwrap(), "");
        assert_eq!(
            join_topology_paths("/cdn", "registry/main").unwrap(),
            "/cdn/registry/main"
        );
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("ordered", "Ordered").await.unwrap();
        let binding = db
            .create_storage_binding(org, "ordered", "local_fs", "/tmp/ordered")
            .await
            .unwrap();
        let registry = db
            .create_managed_registry(
                org,
                "",
                "registry",
                "public",
                Some(binding),
                "legacy-ordered",
                &[],
                false,
            )
            .await
            .unwrap();
        for (name, prefix, order) in [
            ("zeta", "zeta", 0),
            ("alpha", "alpha", 0),
            ("middle", "middle", 1),
            ("binding-root", "", 2),
        ] {
            let mut input =
                topology_placement(SurfaceTarget::Registry(registry), name, prefix, order);
            input.storage_binding_id = binding;
            db.create_surface_placement(&input).await.unwrap();
        }
        let placements = db
            .list_surface_placements(SurfaceTarget::Registry(registry))
            .await
            .unwrap();
        assert_eq!(
            placements
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta", "middle", "binding-root"]
        );
        let selected = &placements[0];
        let update = UpdateSurfacePlacement {
            expected_version: selected.resource_version,
            state: "degraded".to_string(),
            completeness: selected.completeness.clone(),
            partition_rule_json: selected.partition_rule_json.clone(),
            read_enabled: selected.read_enabled,
            write_enabled: selected.write_enabled,
            read_order: selected.read_order,
            write_order: selected.write_order,
        };
        let updated = db
            .update_surface_placement(selected.id, &update)
            .await
            .unwrap();
        assert_eq!(updated.resource_version, selected.resource_version + 1);
        assert!(db
            .update_surface_placement(selected.id, &update)
            .await
            .is_err());

        let defaults = db
            .set_topology_defaults(&SetTopologyDefaults {
                scope: TopologyScope::Organization(org),
                storage_binding_id: Some(binding),
                domain_id: None,
                storage_gateway_id: None,
                expected_version: None,
            })
            .await
            .unwrap();
        let stale_defaults = SetTopologyDefaults {
            scope: TopologyScope::Organization(org),
            storage_binding_id: Some(binding),
            domain_id: None,
            storage_gateway_id: None,
            expected_version: Some(defaults.resource_version + 1),
        };
        assert!(db.set_topology_defaults(&stale_defaults).await.is_err());
    }

    #[tokio::test]
    async fn publication_topology_enforces_authoritative_same_registry_ownership() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("publication", "Publication").await.unwrap();
        let binding = db
            .create_storage_binding(org, "publication", "local_fs", "/tmp/publication")
            .await
            .unwrap();
        let first = db
            .create_managed_registry(
                org,
                "",
                "first",
                "public",
                Some(binding),
                "legacy-first",
                &[],
                false,
            )
            .await
            .unwrap();
        let second = db
            .create_managed_registry(
                org,
                "",
                "second",
                "public",
                Some(binding),
                "legacy-second",
                &[],
                false,
            )
            .await
            .unwrap();
        let now = unix_now();
        db.backend
            .execute(
                "INSERT INTO registry_publications
                 (publication_id, registry_id, ordinal, generation,
                  manifest_digest, refs_digest, default_commit, state,
                  created_at)
                 VALUES ('pub-first-1', ?1, 1, 'generation-1', 'manifest-1',
                         'refs-1', 'commit-1', 'preparing', ?2)",
                &vals![first, now],
            )
            .await
            .unwrap();
        let mut placement =
            topology_placement(SurfaceTarget::Registry(first), "published", "published", 0);
        placement.storage_binding_id = binding;
        let placement = db.create_surface_placement(&placement).await.unwrap();
        let mut cross = topology_placement(SurfaceTarget::Registry(second), "cross", "cross", 0);
        cross.storage_binding_id = binding;
        let cross = db.create_surface_placement(&cross).await.unwrap();

        let pointer = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(first),
                object_key: "refs/heads/main".to_string(),
                content_hash: Some("pointer-hash".to_string()),
                size: Some(42),
                object_kind: "mutable_pointer".to_string(),
                mutable_publication_id: Some("pub-first-1".to_string()),
            })
            .await
            .unwrap();
        db.set_registry_publication_object(&SetRegistryPublicationObject {
            publication_id: "pub-first-1".to_string(),
            surface_object_id: pointer.id,
            object_kind: "mutable_pointer".to_string(),
            expected_hash: "pointer-hash".to_string(),
            expected_size: 42,
        })
        .await
        .unwrap();
        db.backend
            .execute(
                "INSERT INTO registry_publications
                 (publication_id, registry_id, ordinal, generation,
                  manifest_digest, refs_digest, state, created_at)
                 VALUES ('pub-other-3', ?1, 3, 'generation-3',
                         'manifest-3', 'refs-3', 'preparing', ?2)",
                &vals![first, now],
            )
            .await
            .unwrap();
        assert!(db
            .set_registry_publication_object(&SetRegistryPublicationObject {
                publication_id: "pub-other-3".to_string(),
                surface_object_id: pointer.id,
                object_kind: "mutable_pointer".to_string(),
                expected_hash: "pointer-hash".to_string(),
                expected_size: 42,
            })
            .await
            .is_err());
        assert!(!db
            .tombstone_surface_object(pointer.id, pointer.resource_version, now)
            .await
            .unwrap());
        db.set_object_placement(&SetObjectPlacement {
            surface_object_id: pointer.id,
            placement_id: placement.id,
            state: "present".to_string(),
            observed_hash: Some("pointer-hash".to_string()),
            observed_size: Some(42),
            etag: Some("etag-1".to_string()),
            observed_at: now,
        })
        .await
        .unwrap();
        assert!(db
            .begin_registry_pointer_advance(
                "pub-first-1",
                placement.id,
                placement.resource_version,
                now,
            )
            .await
            .is_err());
        assert_eq!(
            db.surface_placement(placement.id)
                .await
                .unwrap()
                .unwrap()
                .resource_version,
            placement.resource_version
        );
        db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
            publication_id: "pub-first-1".to_string(),
            placement_id: placement.id,
            required: true,
            state: "preparing".to_string(),
            observed_at: now,
        })
        .await
        .unwrap();
        assert!(db
            .set_registry_publication_placement(&SetRegistryPublicationPlacement {
                publication_id: "pub-first-1".to_string(),
                placement_id: placement.id,
                required: false,
                state: "preparing".to_string(),
                observed_at: now,
            })
            .await
            .is_err());
        let frozen_mutation_version: i64 = db
            .backend
            .query_opt(
                "SELECT mutation_version FROM registry_publications
                 WHERE publication_id = 'pub-first-1'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(frozen_mutation_version, 2);
        assert!(db
            .set_registry_publication_placement(&SetRegistryPublicationPlacement {
                publication_id: "pub-first-1".to_string(),
                placement_id: placement.id,
                required: true,
                state: "ready".to_string(),
                observed_at: now,
            })
            .await
            .is_err());
        assert!(db
            .begin_registry_pointer_advance(
                "pub-first-1",
                placement.id,
                placement.resource_version,
                now,
            )
            .await
            .is_err());
        assert!(db
            .advance_registry_publication("pub-first-1", "preparing", "writing_pointers", now)
            .await
            .unwrap());
        assert!(db
            .set_registry_publication_object(&SetRegistryPublicationObject {
                publication_id: "pub-first-1".to_string(),
                surface_object_id: pointer.id,
                object_kind: "mutable_pointer".to_string(),
                expected_hash: "pointer-hash".to_string(),
                expected_size: 42,
            })
            .await
            .is_err());
        let after_frozen_append: i64 = db
            .backend
            .query_opt(
                "SELECT mutation_version FROM registry_publications
                 WHERE publication_id = 'pub-first-1'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(after_frozen_append, frozen_mutation_version);
        // Simulate a process dying after the authoritative watermark clear and
        // version bump but before placement progress leaves `preparing`.
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = NULL,
                    resource_version = resource_version + 1, updated_at = ?2
                 WHERE id = ?1",
                &vals![placement.id, now],
            )
            .await
            .unwrap();
        let cleared = db
            .begin_registry_pointer_advance(
                "pub-first-1",
                placement.id,
                placement.resource_version,
                now,
            )
            .await
            .unwrap();
        assert!(cleared.mutable_publication_id.is_none());
        let recleared = db
            .begin_registry_pointer_advance(
                "pub-first-1",
                placement.id,
                placement.resource_version,
                now,
            )
            .await
            .unwrap();
        assert_eq!(recleared.resource_version, cleared.resource_version);
        let published = db
            .finalize_registry_pointer_advance(
                "pub-first-1",
                placement.id,
                cleared.resource_version,
                now,
            )
            .await
            .unwrap();
        assert_eq!(
            published.mutable_publication_id.as_deref(),
            Some("pub-first-1")
        );
        let republished = db
            .finalize_registry_pointer_advance(
                "pub-first-1",
                placement.id,
                cleared.resource_version,
                now,
            )
            .await
            .unwrap();
        assert_eq!(republished.resource_version, published.resource_version);
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = NULL WHERE id = ?1",
                &vals![placement.id],
            )
            .await
            .unwrap();
        assert!(!db
            .advance_registry_publication("pub-first-1", "writing_pointers", "ready", now)
            .await
            .unwrap());
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = 'pub-first-1'
                 WHERE id = ?1",
                &vals![placement.id],
            )
            .await
            .unwrap();
        assert!(db
            .advance_registry_publication("pub-first-1", "writing_pointers", "ready", now)
            .await
            .unwrap());
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = NULL WHERE id = ?1",
                &vals![placement.id],
            )
            .await
            .unwrap();
        assert!(db
            .set_current_registry_publication(first, "pub-first-1", None)
            .await
            .is_err());
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = 'pub-first-1'
                 WHERE id = ?1",
                &vals![placement.id],
            )
            .await
            .unwrap();
        let current = db
            .set_current_registry_publication(first, "pub-first-1", None)
            .await
            .unwrap();
        assert_eq!(
            current.current_publication_id.as_deref(),
            Some("pub-first-1")
        );
        db.backend
            .execute(
                "INSERT INTO registry_publications
                 (publication_id, registry_id, ordinal, generation,
                  manifest_digest, refs_digest, state, created_at, completed_at)
                 VALUES ('pub-fork-4', ?1, 4, 'generation-4',
                         'manifest-4', 'refs-4', 'ready', ?2, ?2)",
                &vals![first, now],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO registry_publication_placements
                 (publication_id, registry_id, placement_id, required, state, observed_at)
                 VALUES ('pub-fork-4', ?1, ?2, 1, 'ready', ?3)",
                &vals![first, placement.id, now],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = 'pub-fork-4'
                 WHERE id = ?1",
                &vals![placement.id],
            )
            .await
            .unwrap();
        assert!(db
            .set_current_registry_publication(first, "pub-fork-4", Some(current.resource_version),)
            .await
            .is_err());
        db.backend
            .execute(
                "UPDATE surface_placements SET mutable_publication_id = 'pub-first-1'
                 WHERE id = ?1",
                &vals![placement.id],
            )
            .await
            .unwrap();
        assert!(db
            .set_current_registry_publication(second, "pub-first-1", None)
            .await
            .is_err());
        assert!(db
            .set_registry_publication_placement(&SetRegistryPublicationPlacement {
                publication_id: "pub-first-1".to_string(),
                placement_id: placement.id,
                required: true,
                state: "retired".to_string(),
                observed_at: now + 1,
            })
            .await
            .is_err());
        assert!(!db
            .advance_registry_publication("pub-first-1", "ready", "retired", now + 1)
            .await
            .unwrap());
        assert!(!db
            .tombstone_surface_object(pointer.id, pointer.resource_version, now)
            .await
            .unwrap());
        db.backend
            .execute(
                "INSERT INTO registry_publications
                 (publication_id, registry_id, ordinal, generation,
                  manifest_digest, refs_digest, state, created_at)
                 VALUES ('pub-failed-2', ?1, 2, 'generation-2',
                         'manifest-2', 'refs-2', 'preparing', ?2)",
                &vals![first, now],
            )
            .await
            .unwrap();
        let failed_object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(first),
                object_key: "objects/failed-publication".to_string(),
                content_hash: Some("failed-hash".to_string()),
                size: Some(9),
                object_kind: "immutable".to_string(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        db.set_registry_publication_object(&SetRegistryPublicationObject {
            publication_id: "pub-failed-2".to_string(),
            surface_object_id: failed_object.id,
            object_kind: "immutable".to_string(),
            expected_hash: "failed-hash".to_string(),
            expected_size: 9,
        })
        .await
        .unwrap();
        db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
            publication_id: "pub-failed-2".to_string(),
            placement_id: placement.id,
            required: false,
            state: "preparing".to_string(),
            observed_at: now + 1,
        })
        .await
        .unwrap();
        assert!(db
            .advance_registry_publication("pub-failed-2", "preparing", "failed", now + 1)
            .await
            .unwrap());
        db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
            publication_id: "pub-failed-2".to_string(),
            placement_id: placement.id,
            required: false,
            state: "failed".to_string(),
            observed_at: now + 1,
        })
        .await
        .unwrap();
        assert!(db
            .set_registry_publication_placement(&SetRegistryPublicationPlacement {
                publication_id: "pub-failed-2".to_string(),
                placement_id: placement.id,
                required: false,
                state: "retired".to_string(),
                observed_at: now + 2,
            })
            .await
            .is_err());
        assert!(!db
            .tombstone_surface_object(failed_object.id, failed_object.resource_version, now + 1)
            .await
            .unwrap());
        assert!(db
            .advance_registry_publication("pub-failed-2", "failed", "retired", now + 2)
            .await
            .unwrap());
        db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
            publication_id: "pub-failed-2".to_string(),
            placement_id: placement.id,
            required: false,
            state: "retired".to_string(),
            observed_at: now + 2,
        })
        .await
        .unwrap();
        assert!(db
            .tombstone_surface_object(failed_object.id, failed_object.resource_version, now + 2)
            .await
            .unwrap());
        let garbage = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(first),
                object_key: "objects/garbage".to_string(),
                content_hash: Some("garbage-hash".to_string()),
                size: Some(7),
                object_kind: "immutable".to_string(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        db.set_object_placement(&SetObjectPlacement {
            surface_object_id: garbage.id,
            placement_id: placement.id,
            state: "present".to_string(),
            observed_hash: Some("garbage-hash".to_string()),
            observed_size: Some(7),
            etag: None,
            observed_at: now,
        })
        .await
        .unwrap();
        assert!(db
            .tombstone_surface_object(garbage.id, garbage.resource_version, now)
            .await
            .unwrap());
        // Simulate a Worker failure after the presence link but before the
        // preparing job becomes pending.
        db.backend
            .execute(
                "INSERT INTO object_deletion_jobs
                 (job_id, surface_object_id, placement_id, state, created_at)
                 VALUES ('delete-pointer-1', ?1, ?2, 'preparing', ?3)",
                &vals![garbage.id, placement.id, now],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE object_placements SET state = 'deleting',
                    deletion_job_id = 'delete-pointer-1'
                 WHERE surface_object_id = ?1 AND placement_id = ?2",
                &vals![garbage.id, placement.id],
            )
            .await
            .unwrap();
        let deletion = db
            .create_object_deletion_job(&NewObjectDeletionJob {
                job_id: "delete-pointer-1".to_string(),
                surface_object_id: garbage.id,
                placement_id: placement.id,
            })
            .await
            .unwrap();
        assert_eq!(deletion.state, "pending");
        let deletion_retry = db
            .create_object_deletion_job(&NewObjectDeletionJob {
                job_id: deletion.job_id.clone(),
                surface_object_id: garbage.id,
                placement_id: placement.id,
            })
            .await
            .unwrap();
        assert_eq!(deletion_retry, deletion);
        db.set_object_placement(&SetObjectPlacement {
            surface_object_id: failed_object.id,
            placement_id: placement.id,
            state: "present".to_string(),
            observed_hash: Some("failed-hash".to_string()),
            observed_size: Some(9),
            etag: None,
            observed_at: now,
        })
        .await
        .unwrap();
        assert!(db
            .create_object_deletion_job(&NewObjectDeletionJob {
                job_id: deletion.job_id.clone(),
                surface_object_id: failed_object.id,
                placement_id: placement.id,
            })
            .await
            .is_err());
        assert_eq!(
            db.object_placement(failed_object.id, placement.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "present"
        );
        assert!(db
            .set_object_placement(&SetObjectPlacement {
                surface_object_id: garbage.id,
                placement_id: placement.id,
                state: "corrupt".to_string(),
                observed_hash: None,
                observed_size: None,
                etag: None,
                observed_at: now,
            })
            .await
            .is_err());
        assert_eq!(
            db.object_placement(garbage.id, placement.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "deleting"
        );
        let claimed = db
            .claim_object_deletion_job(&deletion.job_id, deletion.resource_version, now + 1)
            .await
            .unwrap();
        let failed = db
            .finish_object_deletion_job(
                &claimed.job_id,
                claimed.resource_version,
                false,
                Some("backend unavailable"),
                now + 2,
            )
            .await
            .unwrap();
        assert_eq!(failed.state, "failed");
        assert!(db
            .create_object_deletion_job(&NewObjectDeletionJob {
                job_id: "delete-conflicting-active".to_string(),
                surface_object_id: garbage.id,
                placement_id: placement.id,
            })
            .await
            .is_err());
        let after_conflict = db
            .object_placement(garbage.id, placement.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_conflict.state, "corrupt");
        let retried = db
            .claim_object_deletion_job(&failed.job_id, failed.resource_version, now + 3)
            .await
            .unwrap();
        let finished = db
            .finish_object_deletion_job(
                &retried.job_id,
                retried.resource_version,
                true,
                None,
                now + 4,
            )
            .await
            .unwrap();
        assert_eq!(finished.state, "succeeded");
        let reconciled = db
            .finish_object_deletion_job(
                &finished.job_id,
                finished.resource_version,
                true,
                None,
                now + 4,
            )
            .await
            .unwrap();
        assert_eq!(reconciled, finished);
        assert_eq!(
            db.object_placement(garbage.id, placement.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "missing"
        );
        assert!(db
            .set_object_placement(&SetObjectPlacement {
                surface_object_id: garbage.id,
                placement_id: placement.id,
                state: "deleting".to_string(),
                observed_hash: None,
                observed_size: None,
                etag: None,
                observed_at: now + 5,
            })
            .await
            .is_err());
        db.set_object_placement(&SetObjectPlacement {
            surface_object_id: garbage.id,
            placement_id: placement.id,
            state: "present".to_string(),
            observed_hash: Some("garbage-hash".to_string()),
            observed_size: Some(7),
            etag: None,
            observed_at: now + 5,
        })
        .await
        .unwrap();
        db.backend
            .execute(
                "INSERT INTO object_deletion_jobs
                 (job_id, surface_object_id, placement_id, state, created_at)
                 VALUES ('delete-pointer-2', ?1, ?2, 'preparing', ?3)",
                &vals![garbage.id, placement.id, now + 5],
            )
            .await
            .unwrap();
        let second_deletion = db
            .create_object_deletion_job(&NewObjectDeletionJob {
                job_id: "delete-pointer-2".to_string(),
                surface_object_id: garbage.id,
                placement_id: placement.id,
            })
            .await
            .unwrap();
        assert_eq!(second_deletion.state, "pending");
        assert!(db
            .set_registry_publication_placement(&SetRegistryPublicationPlacement {
                publication_id: "pub-first-1".to_string(),
                placement_id: cross.id,
                required: true,
                state: "preparing".to_string(),
                observed_at: now,
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn retention_retirement_preserves_structurally_proven_root_reasons() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("retention", "Retention").await.unwrap();
        let binding = db
            .create_storage_binding(org, "retention", "local_fs", "/tmp/retention")
            .await
            .unwrap();
        let registry = db
            .create_managed_registry(
                org,
                "",
                "source",
                "public",
                Some(binding),
                "source",
                &[],
                false,
            )
            .await
            .unwrap();
        let cache = db
            .create_cache(
                Some(org),
                "retained",
                "Retained",
                Some(binding),
                "retained",
                None,
                "public",
                10,
                "zstd",
                true,
            )
            .await
            .unwrap();
        let cache_object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::BinaryCache(cache),
                object_key: "nar/cache-only".to_string(),
                content_hash: Some("cache-hash".to_string()),
                size: Some(5),
                object_kind: "immutable".to_string(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        assert!(!db
            .tombstone_surface_object(cache_object.id, cache_object.resource_version, unix_now())
            .await
            .unwrap());
        let subscription = db
            .set_cache_retention_subscription(&SetCacheRetentionSubscription {
                cache_id: cache,
                registry_id: registry,
                selector_json: "{\"tags\":3}".to_string(),
                removal_grace_secs: 86_400,
                exposure_acknowledged_at: None,
                enabled: true,
                expected_version: None,
            })
            .await
            .unwrap();
        let now = unix_now();
        db.begin_cache_retention_refresh(
            "refresh-1",
            subscription.id,
            subscription.resource_version,
            "revision-1",
            1,
            now,
        )
        .await
        .unwrap();
        db.stage_cache_retention_reason(
            "refresh-1",
            &RetentionRefreshReasonInput {
                reason_key: "catalog:tag:v1:hash-1".to_string(),
                store_hash: "hash-1".to_string(),
                source_kind: "registry_catalog".to_string(),
                source_ref: "tag:v1".to_string(),
                release_id: None,
                channel_id: None,
                partition_bucket: None,
                expires_at: None,
            },
            now,
        )
        .await
        .unwrap();
        let committed = db
            .commit_cache_retention_refresh("refresh-1", subscription.resource_version, now)
            .await
            .unwrap();
        // Retry after the seal/pointer boundary is idempotent.
        db.commit_cache_retention_refresh("refresh-1", subscription.resource_version, now)
            .await
            .unwrap();
        db.begin_cache_retention_refresh(
            "refresh-stale",
            subscription.id,
            committed.resource_version,
            "revision-stale",
            0,
            now + 1,
        )
        .await
        .unwrap();
        db.begin_cache_retention_refresh(
            "refresh-2",
            subscription.id,
            committed.resource_version,
            "revision-2",
            0,
            now + 2,
        )
        .await
        .unwrap();
        let committed = db
            .commit_cache_retention_refresh("refresh-2", committed.resource_version, now + 3)
            .await
            .unwrap();
        assert!(db
            .fail_cache_retention_refresh("refresh-stale", "late stale failure", now + 4)
            .await
            .unwrap());
        let after_stale_failure = db
            .cache_retention_subscription(cache, registry)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_stale_failure.refresh_state, "fresh");
        assert_eq!(after_stale_failure.refresh_error, None);
        assert_eq!(
            after_stale_failure.current_refresh_id.as_deref(),
            Some("refresh-2")
        );
        db.begin_cache_retention_refresh(
            "refresh-failed",
            subscription.id,
            committed.resource_version,
            "revision-3",
            0,
            now + 5,
        )
        .await
        .unwrap();
        assert!(db
            .fail_cache_retention_refresh("refresh-failed", "source unavailable", now + 6)
            .await
            .unwrap());
        let after_failure = db
            .cache_retention_subscription(cache, registry)
            .await
            .unwrap()
            .unwrap();
        let current: String = db
            .backend
            .query_opt(
                "SELECT current_refresh_id FROM cache_retention_subscriptions WHERE id = ?1",
                &vals![subscription.id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(current, "refresh-2");
        assert_eq!(
            after_failure.last_successful_revision.as_deref(),
            Some("revision-2")
        );
        assert_eq!(after_failure.refresh_state, "failed");
        assert_eq!(
            db.active_cache_retention_hashes(cache, now + 6)
                .await
                .unwrap(),
            vec!["hash-1"]
        );
        assert!(db
            .retire_cache_retention_subscription(subscription.id, after_failure.resource_version,)
            .await
            .unwrap());
        let count: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM cache_root_reasons WHERE retention_subscription_id = ?1",
                &vals![subscription.id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(count, 1);
        assert!(db
            .backend
            .execute(
                "DELETE FROM cache_retention_subscriptions WHERE id = ?1",
                &vals![subscription.id],
            )
            .await
            .is_err());
    }

    /// Test helper: register a managed registry owned by `org` at `slug` with a
    /// local_fs binding, so serving queries can exclude it on soft-delete.
    impl Database {
        async fn register_owned(&self, org_id: i64, slug: &str) {
            let binding = self
                .create_storage_binding(org_id, "primary", "local_fs", "/tmp/aos-hub-test")
                .await
                .unwrap();
            // The slug is `org/name`; split off the name for the canonical path.
            let name = slug.rsplit('/').next().unwrap();
            self.create_managed_registry(
                org_id,
                "",
                name,
                "public",
                Some(binding),
                name,
                &[],
                false,
            )
            .await
            .unwrap();
        }
    }
}
