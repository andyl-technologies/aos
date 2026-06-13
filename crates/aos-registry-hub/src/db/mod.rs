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
//!   `channel_partitions`, `releases`, `key_rosters`, `caches`: derived
//!   from the verified surface by the indexer and safely droppable; a
//!   re-index reconstructs it.
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
//! [`crate::auth::oidc`]; this module only stores and lists the rows.
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
//! The seed is held **sealed** by a [`crate::auth::oidc::SecretSealer`] and
//! unsealed only at the instant of a signature
//! ([`Database::load_hosted_signing_key`]). The `public_key` is the
//! registry trusted-key line operators pin as a trust anchor, so the hub's
//! own signatures verify through the same indexer path
//! ([`crate::surface::tag::verify_signed_tag`]) as any client's. The
//! operations a hosted key unlocks live in [`crate::signing`]; this module
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
//! Phase-1 "frontend freshness probes". For each committed `[[caches]]` URL the
//! hub knows, a lightweight reachability probe records whether the cache serves
//! a `nix-cache-info`, how long the probe took, and when it ran. These rows are
//! purely **observational** (rebuildable from the next probe), so they live in
//! the index/derived set rather than the system of record.
//!
//! ```text
//! cache_probes  registry_id 1  cache_url "https://cdn.aos.andyl.org"
//!               status "ok"  observed_nix_cache_info 1
//!               latency_ms 42  checked_at 1730000000
//! ```
//!
//! `status` is `ok` (reachable, valid `nix-cache-info`), `stale` (reachable but
//! no/empty `nix-cache-info`), or `unreachable` (transport failure or missing
//! file root). The probing logic lives in [`crate::probe`].
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

pub mod backend;
pub mod dialect;
pub mod value;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rusqlite::Connection;

use self::backend::{Backend, SqliteBackend};
use self::dialect::Dialect;
use self::value::{Row, ToValue};

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
    // v8: committed cache-stack expression (RFC-0004 \"Cache stores, stacks,
    // and consistency validation\"). When a registry's committed
    // registry.toml carries a [cache_stack] section, the indexer parses it
    // into the nestable try/mirror model and stores it here as JSON (see
    // crate::stack), so stack-aware coverage validation can recover the
    // mirror groups without re-reading the surface. NULL for registries that
    // only use the flat [[caches]] list; the flattened endpoints still
    // populate the caches table either way, so the column is purely additive.
    "
    ALTER TABLE registry_index ADD COLUMN cache_stack TEXT;
    ",
    // v9: per-org OIDC SSO (RFC-0004 \"Per-org OIDC SSO\"). Three
    // system-of-record tables that exist nowhere on the registry surface:
    //
    // - org_idp_configs: one IdP per org. The authorization-code + PKCE
    //   endpoints, client id, and the sealed client secret (client_secret_enc;
    //   see crate::auth::oidc::SecretSealer), plus the groups->role mapping
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
        client_secret_enc     TEXT,                       -- sealed; never plaintext
        scopes                TEXT NOT NULL DEFAULT 'openid email profile',
        groups_claim          TEXT,
        role_map_json         TEXT NOT NULL DEFAULT '{}',
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
        public_key  TEXT NOT NULL,                -- name:Ed25519:<base64> trusted-key line
        secret_enc  TEXT NOT NULL,                -- sealed 32-byte Ed25519 seed; never plaintext
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
        secret      TEXT NOT NULL,                -- HMAC-SHA256 signing secret (shared with subscriber)
        events      TEXT NOT NULL,                -- JSON array of subscribed event-type strings ([] = all)
        active      INTEGER NOT NULL DEFAULT 1,
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX webhooks_org_idx ON webhooks (org_id);
    CREATE TABLE webhook_deliveries (
        id              INTEGER PRIMARY KEY,
        webhook_id      INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
        event           TEXT NOT NULL,            -- the event-type string
        payload         TEXT NOT NULL,            -- the JSON body, as signed and POSTed
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
    // Observational reachability/latency for each committed [[caches]] URL,
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
    //   consumer_priority maps to the [[caches]] priority an advertised cache
    //   frontend would carry (informational here — registry.toml [[caches]] is
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
        public_key    TEXT NOT NULL,                -- base64 of the COSE public key
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
    /// The hosted signing key this registry has enrolled, or `None` for a
    /// BYO-key registry (the default — the channel console only prepares
    /// client-signed operations).
    pub hosted_key_id: Option<i64>,
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

/// The instance-wide policy gating who may create organizations.
///
/// Stored in `instance_config` under the key `signup_policy`; see
/// [`Database::signup_policy`]. The default is [`SignupPolicy::InviteOnly`]
/// (the hosted-instance posture: free hub-managed storage behind open signup
/// is an abuse magnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupPolicy {
    /// Any authenticated principal may create an org.
    Open,
    /// Org creation requires an invitation or an existing membership (or an
    /// instance admin).
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
/// [`crate::auth::oidc::SecretSealer`] only at the moment of the token
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
    /// Sealed by a [`crate::auth::oidc::SecretSealer`]; never the plaintext.
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
/// Created at [`crate::auth::oidc::begin_login`] and consumed exactly once at
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
/// and the probing logic in [`crate::probe`].
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
/// proxied frontend. See [`crate::mirror`] for the sync and fetch logic.
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

/// A frontend domain serving some subset of a registry's surfaces
/// (system-of-record row; RFC-0004 "Frontends: direct and proxied domains").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendRecord {
    /// Database id.
    pub id: i64,
    /// The registry this frontend serves.
    pub registry_id: i64,
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
    /// The `[[caches]]` priority an advertised cache frontend would carry
    /// (informational; the committed mirror list is signed tree content).
    pub consumer_priority: i64,
    /// Whether the frontend is advertised to consumers.
    pub advertised: bool,
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
    ///
    /// When the snapshot carries a [`Self::cache_stack`], the stack's
    /// flattened endpoints are folded into this list (union, for display and
    /// for stack-unaware clients).
    pub caches: Vec<(String, u32)>,
    /// The committed `[cache_stack]` expression as compact JSON
    /// ([`crate::stack::StackNode::to_json`]), or `None` when the registry
    /// uses only the flat `[[caches]]` list.
    pub cache_stack: Option<String>,
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
    /// Draft ref the hub wrote for a git-backed change request
    /// (`refs/hub/changes/<change_id>`), or `None` for a SQL-only change-set.
    pub git_ref: Option<String>,
    /// Signed draft-commit oid the [`Self::git_ref`] points at, or `None` for
    /// a SQL-only change-set.
    pub git_commit: Option<String>,
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
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening hub database {}", path.display()))?;
        Self::from_sqlite(conn)
    }

    /// Open an in-memory sqlite database (tests only).
    ///
    /// `serve --dev` does *not* use this: dev mode persists a regular
    /// `hub.db` under its `--root` directory (defaulting to `./.aos-hub`).
    ///
    /// # Errors
    ///
    /// Returns an error if a migration fails.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_sqlite(Connection::open_in_memory()?)
    }

    /// Connect to a hub database by URL, dispatching on the scheme.
    ///
    /// The native self-hosting entry point (RFC-0004 "Database abstraction"):
    ///
    /// - `sqlite://<path>`, `file://<path>`, or a bare filesystem path → the
    ///   always-available [`SqliteBackend`].
    /// - `postgres://…` / `postgresql://…` → the [`PostgresBackend`], when the
    ///   crate is built with the `postgres` feature (else an error).
    /// - `mysql://…` → the [`MysqlBackend`], when built with the `mysql`
    ///   feature (else an error).
    ///
    /// In every case the schema is created and migrated to the current
    /// version before returning.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported scheme, a backend whose feature is
    /// not enabled, a connection failure, or a migration failure.
    pub fn connect(url: &str) -> Result<Self> {
        if let Some(rest) = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
        {
            let _ = rest;
            #[cfg(feature = "postgres")]
            {
                let backend = backend::PostgresBackend::connect(url)?;
                return Self::with_backend(Box::new(backend));
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
                let backend = backend::MysqlBackend::connect(url)?;
                return Self::with_backend(Box::new(backend));
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
            return Self::open_in_memory();
        }
        Self::open(Path::new(path))
    }

    fn from_sqlite(conn: Connection) -> Result<Self> {
        let backend = SqliteBackend::new(conn)?;
        Self::with_backend(Box::new(backend))
    }

    fn with_backend(backend: Box<dyn Backend>) -> Result<Self> {
        let db = Self { backend };
        db.migrate()?;
        Ok(db)
    }

    /// The SQL dialect of the underlying backend.
    fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    fn migrate(&self) -> Result<()> {
        self.backend.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
            &[],
        )?;
        let current: i64 = self
            .backend
            .query_opt("SELECT version FROM schema_version", &[])?
            .map(|row| row.get::<i64>(0))
            .transpose()?
            .unwrap_or(0);
        let target = MIGRATIONS.len() as i64;
        if current > target {
            bail!("hub database schema {current} is newer than this build supports ({target})");
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            self.backend
                .execute_batch(sql)
                .with_context(|| format!("applying migration v{}", i + 1))?;
        }
        self.backend.execute("DELETE FROM schema_version", &[])?;
        self.backend.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            &vals![target],
        )?;
        Ok(())
    }

    /// Locks the underlying sqlite connection for tests that need raw
    /// rusqlite access.
    ///
    /// # Panics
    ///
    /// Panics if the backend is not a [`SqliteBackend`]. Only the in-module
    /// migration tests use this, and they always open sqlite.
    #[cfg(test)]
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.backend
            .as_sqlite()
            .expect("lock() is sqlite-only (test helper)")
            .lock()
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
        )?;
        let id: i64 = self
            .backend
            .query_opt("SELECT id FROM registries WHERE slug = ?1", &vals![slug])?
            .context("registry row missing after upsert")?
            .get(0)?;
        self.backend.execute(
            "INSERT INTO registry_index (registry_id, state)
             VALUES (?1, 'indexing')
             ON CONFLICT(registry_id) DO NOTHING",
            &vals![id],
        )?;
        Ok(id)
    }

    /// Look up a registry by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn registry_by_slug(&self, slug: &str) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE slug = ?1"),
                &vals![slug],
            )
            .context("loading registry by slug")?
            .map(|row| row_to_registry(&row))
            .transpose()
    }

    /// Look up a registry by its database id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn registry_by_id(&self, registry_id: i64) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE id = ?1"),
                &vals![registry_id],
            )
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
    pub fn list_registries(&self) -> Result<Vec<RegistryRecord>> {
        let rows = self.backend.query(
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
        )?;
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
    pub fn list_registries_including_org(&self, org_id: i64) -> Result<Vec<RegistryRecord>> {
        let rows = self.backend.query(
            &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE org_id = ?1 ORDER BY slug"),
            &vals![org_id],
        )?;
        rows.iter().map(row_to_registry).collect()
    }

    // -- index writes -------------------------------------------------------

    /// Replace a registry's entire index with a fresh snapshot, atomically.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    pub fn apply_snapshot(&self, registry_id: i64, snapshot: &IndexSnapshot) -> Result<()> {
        self.backend.with_tx(&mut |tx| {
            for table in ["packages", "channels", "releases", "key_rosters", "caches"] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE registry_id = ?1"),
                    &vals![registry_id],
                )?;
            }

            for package in &snapshot.packages {
                let package_id = tx.execute_insert(
                    "INSERT INTO packages
                     (registry_id, name, description, homepage, license, maintainer, sysroot)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    &vals![
                        registry_id,
                        package.package.name,
                        package.package.description,
                        package.package.homepage,
                        package.package.license,
                        package.package.maintainer,
                        package.package.sysroot,
                    ],
                )?;
                for version in &package.versions {
                    let version_id = tx.execute_insert(
                        "INSERT INTO package_versions (package_id, version, previous)
                         VALUES (?1, ?2, ?3)",
                        &vals![package_id, version.version, version.previous],
                    )?;
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
                            &vals![
                                version_id,
                                platform,
                                entry.store_path,
                                entry.nar_hash,
                                entry.nar_size,
                                entry.closure_size,
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
                    &vals![
                        registry_id,
                        release.semver,
                        release.tag_oid,
                        release.commit_oid,
                        release.signer,
                        release.tagged_at,
                        release.pack_present,
                    ],
                )?;
            }

            for channel in &snapshot.channels {
                let channel_id = tx.execute_insert(
                    "INSERT INTO channels (registry_id, name, frontier) VALUES (?1, ?2, ?3)",
                    &vals![registry_id, channel.name, channel.frontier],
                )?;
                for (bucket, release) in channel.partitions.iter().enumerate() {
                    if let Some(release) = release {
                        tx.execute(
                            "INSERT INTO channel_partitions (channel_id, bucket, release)
                             VALUES (?1, ?2, ?3)",
                            &vals![channel_id, bucket as i64, release],
                        )?;
                    }
                }
            }

            for (key_id, public_key, status) in &snapshot.roster {
                tx.execute(
                    "INSERT INTO key_rosters (registry_id, key_id, public_key, status)
                     VALUES (?1, ?2, ?3, ?4)",
                    &vals![registry_id, key_id, public_key, status],
                )?;
            }
            for (url, priority) in &snapshot.caches {
                tx.execute(
                    "INSERT INTO caches (registry_id, url, priority) VALUES (?1, ?2, ?3)",
                    &vals![registry_id, url, *priority],
                )?;
            }

            tx.execute(
                "INSERT INTO registry_index
                 (registry_id, state, error, last_indexed_commit, name, description,
                  indexed_at, refs_digest, cache_stack)
                 VALUES (?1, 'fresh', NULL, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(registry_id) DO UPDATE SET
                     state = 'fresh', error = NULL,
                     last_indexed_commit = excluded.last_indexed_commit,
                     name = excluded.name, description = excluded.description,
                     indexed_at = excluded.indexed_at,
                     refs_digest = excluded.refs_digest,
                     cache_stack = excluded.cache_stack",
                &vals![
                    registry_id,
                    snapshot.commit,
                    snapshot.name,
                    snapshot.description,
                    unix_now(),
                    snapshot.refs_digest,
                    snapshot.cache_stack,
                ],
            )?;
            Ok(())
        })
    }

    /// Record an indexing failure without touching the last good index.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn mark_index_failed(&self, registry_id: i64, error: &str) -> Result<()> {
        self.backend.execute(
            "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'failed', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'failed', error = excluded.error",
            &vals![registry_id, error],
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
        self.backend.execute(
            "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'stale', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'stale', error = excluded.error",
            &vals![registry_id, error],
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
        self.backend.with_tx(&mut |tx| {
            // Deleting channels cascades to channel_partitions.
            tx.execute(
                "DELETE FROM channels WHERE registry_id = ?1",
                &vals![registry_id],
            )?;
            for channel in channels {
                let channel_id = tx.execute_insert(
                    "INSERT INTO channels (registry_id, name, frontier) VALUES (?1, ?2, ?3)",
                    &vals![registry_id, channel.name, channel.frontier],
                )?;
                for (bucket, release) in channel.partitions.iter().enumerate() {
                    if let Some(release) = release {
                        tx.execute(
                            "INSERT INTO channel_partitions (channel_id, bucket, release)
                             VALUES (?1, ?2, ?3)",
                            &vals![channel_id, bucket as i64, release],
                        )?;
                    }
                }
            }
            tx.execute(
                "UPDATE registry_index SET indexed_at = ?2 WHERE registry_id = ?1",
                &vals![registry_id, unix_now()],
            )?;
            Ok(())
        })
    }

    // -- anti-rollback floors ------------------------------------------------

    /// The recorded anti-rollback floor for one channel, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn channel_floor(&self, registry_id: i64, channel: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT floor FROM channel_floors WHERE registry_id = ?1 AND channel = ?2",
                &vals![registry_id, channel],
            )
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
    pub fn set_channel_floor(&self, registry_id: i64, channel: &str, floor: &str) -> Result<()> {
        self.backend.execute(
            "INSERT INTO channel_floors (registry_id, channel, floor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(registry_id, channel) DO UPDATE SET floor = excluded.floor",
            &vals![registry_id, channel, floor],
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
    pub fn record_validation_run_with_findings(
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
        let mut run_id = 0_i64;
        self.backend.with_tx(&mut |tx| {
            run_id = tx.execute_insert(
                "INSERT INTO validation_runs
                 (registry_id, cache_url, depth, checked, missing, reachable,
                  started_at, finished_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &vals![
                    registry_id,
                    cache_url,
                    depth,
                    checked,
                    findings.len() as i64,
                    reachable,
                    started_at,
                    finished_at,
                ],
            )?;
            for finding in findings {
                tx.execute(
                    "INSERT INTO validation_findings (run_id, store_hash, status)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(run_id, store_hash) DO NOTHING",
                    &vals![run_id, finding.store_hash, finding.status.as_str()],
                )?;
            }
            Ok(())
        })?;
        Ok(run_id)
    }

    /// The latest validation run per cache URL for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn latest_validation_runs(&self, registry_id: i64) -> Result<Vec<ValidationRunRow>> {
        let rows = self.backend.query(
            "SELECT v.id, v.cache_url, v.depth, v.checked, v.missing, v.reachable, v.finished_at
             FROM validation_runs v
             WHERE v.registry_id = ?1
               AND v.id = (SELECT MAX(id) FROM validation_runs
                           WHERE registry_id = ?1 AND cache_url = v.cache_url)
             ORDER BY v.cache_url",
            &vals![registry_id],
        )?;
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
    pub fn validation_missing(&self, run_id: i64) -> Result<Vec<String>> {
        let rows = self.backend.query(
            "SELECT store_hash FROM validation_findings
             WHERE run_id = ?1 AND status = 'missing' ORDER BY store_hash",
            &vals![run_id],
        )?;
        rows.iter().map(|row| row.get(0)).collect()
    }

    /// The store hashes a validation run found corrupt, sorted.
    ///
    /// A `corrupt` finding is recorded only at [`crate::validation::ValidationDepth::Deep`]:
    /// a hash whose narinfo and NAR are present, but the downloaded NAR's
    /// content hash does not match the narinfo's declared `FileHash`/`NarHash`.
    /// This is distinct from a `missing` finding (which repair can fix by
    /// copying); corruption flags a cache that must be re-uploaded from a good
    /// source.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn validation_corrupt(&self, run_id: i64) -> Result<Vec<String>> {
        let rows = self.backend.query(
            "SELECT store_hash FROM validation_findings
             WHERE run_id = ?1 AND status = 'corrupt' ORDER BY store_hash",
            &vals![run_id],
        )?;
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
    pub fn record_repair_job(
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
        self.backend.execute_insert(
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
    }

    /// The most recent repair jobs for one registry, newest first.
    ///
    /// Capped at `limit` rows for the health-page history.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_repair_jobs(&self, registry_id: i64, limit: i64) -> Result<Vec<RepairJobRow>> {
        let rows = self.backend.query(
            "SELECT id, cache_url, store_hash, source_cache_url, status, error,
                    created_at, finished_at
             FROM repair_jobs
             WHERE registry_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
            &vals![registry_id, limit],
        )?;
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

    /// Records (upserting) the latest freshness probe of one cache endpoint.
    ///
    /// One row is kept per `(registry_id, cache_url)`; re-probing overwrites
    /// the prior observation. See [`crate::probe`] for the producer.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn upsert_cache_probe(
        &self,
        registry_id: i64,
        cache_url: &str,
        status: &str,
        observed_nix_cache_info: bool,
        latency_ms: i64,
        checked_at: i64,
    ) -> Result<()> {
        self.backend.execute(
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
        )?;
        Ok(())
    }

    /// The latest freshness probe per committed cache, for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_cache_probes(&self, registry_id: i64) -> Result<Vec<CacheProbeRow>> {
        let rows = self.backend.query(
            "SELECT cache_url, status, observed_nix_cache_info, latency_ms, checked_at
             FROM cache_probes WHERE registry_id = ?1 ORDER BY cache_url",
            &vals![registry_id],
        )?;
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
    /// must be `full` or `pullthrough`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode` or on database failure.
    pub fn create_mirror_source(
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
        self.backend.execute(
            "INSERT INTO mirror_sources
             (registry_id, upstream_url, mode, verify, schedule_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(registry_id) DO UPDATE SET
               upstream_url = excluded.upstream_url,
               mode = excluded.mode,
               verify = excluded.verify,
               schedule_secs = excluded.schedule_secs",
            &vals![registry_id, upstream_url, mode, verify, schedule_secs],
        )?;
        Ok(())
    }

    /// Load a registry's mirror source, if it is a mirror.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn mirror_source(&self, registry_id: i64) -> Result<Option<MirrorSource>> {
        self.backend
            .query_opt(
                "SELECT upstream_url, mode, verify, schedule_secs, last_sync_at,
                        last_sync_status, last_sync_error, upstream_frontier
                 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
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
    pub fn list_mirror_sources(&self) -> Result<Vec<(i64, MirrorSource)>> {
        let rows = self.backend.query(
            "SELECT registry_id, upstream_url, mode, verify, schedule_secs, last_sync_at,
                    last_sync_status, last_sync_error, upstream_frontier
             FROM mirror_sources ORDER BY registry_id",
            &[],
        )?;
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
    pub fn is_mirror(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )?
            .is_some())
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
    pub fn update_mirror_sync(
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
        self.backend.execute(
            "UPDATE mirror_sources SET
               last_sync_at = ?2,
               last_sync_status = ?3,
               last_sync_error = ?4,
               upstream_frontier = COALESCE(?5, upstream_frontier)
             WHERE registry_id = ?1",
            &vals![registry_id, at, status, error, upstream_frontier],
        )?;
        Ok(())
    }

    /// Create a frontend serving a registry; returns its new id.
    ///
    /// `mode` must be `direct` or `proxied`. The `(domain, base_path)` pair is
    /// unique across all frontends.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode`, a `(domain, base_path)`
    /// collision, or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub fn create_frontend(
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
        self.backend.execute_insert(
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
    }

    /// List a registry's frontends, ordered by descending consumer priority
    /// then domain.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_frontends(&self, registry_id: i64) -> Result<Vec<FrontendRecord>> {
        let rows = self.backend.query(
            "SELECT id, registry_id, domain, base_path, mode, serves_git, serves_cache,
                    serves_web, consumer_priority, advertised, created_at
             FROM frontends WHERE registry_id = ?1
             ORDER BY consumer_priority DESC, domain",
            &vals![registry_id],
        )?;
        rows.iter().map(row_to_frontend).collect()
    }

    /// Delete a frontend by id; returns whether a row was removed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn delete_frontend(&self, frontend_id: i64) -> Result<bool> {
        let affected = self
            .backend
            .execute("DELETE FROM frontends WHERE id = ?1", &vals![frontend_id])?;
        Ok(affected > 0)
    }

    /// Record (upsert) the latest probe observation for a frontend.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn upsert_frontend_probe(
        &self,
        frontend_id: i64,
        status: &str,
        observed_frontier: Option<&str>,
        lag_releases: Option<i64>,
        latency_ms: i64,
        checked_at: i64,
    ) -> Result<()> {
        self.backend.execute(
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
        )?;
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
    pub fn list_frontend_probes(&self, registry_id: i64) -> Result<Vec<FrontendProbeRow>> {
        let rows = self.backend.query(
            "SELECT fp.frontend_id, fp.status, fp.observed_frontier, fp.lag_releases,
                    fp.latency_ms, fp.checked_at
             FROM frontend_probes fp
             JOIN frontends f ON f.id = fp.frontend_id
             WHERE f.registry_id = ?1
             ORDER BY fp.frontend_id",
            &vals![registry_id],
        )?;
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
        let rows = self.backend.query(
            "SELECT vp.store_path, vp.refs FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1",
            &vals![registry_id],
        )?;
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
    pub fn index_status(&self, registry_id: i64) -> Result<Option<IndexStatus>> {
        self.backend
            .query_opt(
                "SELECT state, error, last_indexed_commit, name, description, indexed_at
                 FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .context("loading index status")?
            .map(|row| {
                Ok(IndexStatus {
                    state: row.get(0)?,
                    error: row.get(1)?,
                    last_indexed_commit: row.get(2)?,
                    name: row.get(3)?,
                    description: row.get(4)?,
                    indexed_at: row.get(5)?,
                })
            })
            .transpose()
    }

    /// List packages with their newest indexed version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_packages(&self, registry_id: i64) -> Result<Vec<PackageRow>> {
        let rows = self.backend.query(
            "SELECT p.name, p.description, p.license,
                    (SELECT v.version FROM package_versions v
                     WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1)
             FROM packages p WHERE p.registry_id = ?1 ORDER BY p.name",
            &vals![registry_id],
        )?;
        rows.iter()
            .map(|row| {
                Ok(PackageRow {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    license: row.get(2)?,
                    latest_version: row.get(3)?,
                })
            })
            .collect()
    }

    /// Load one package's full detail.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn package_detail(&self, registry_id: i64, name: &str) -> Result<Option<PackageDetail>> {
        let header = self.backend.query_opt(
            "SELECT id, name, description, homepage, license, maintainer, sysroot
             FROM packages WHERE registry_id = ?1 AND name = ?2",
            &vals![registry_id, name],
        )?;
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

        let version_rows = self.backend.query(
            "SELECT id, version, previous FROM package_versions
             WHERE package_id = ?1 ORDER BY id DESC",
            &vals![package_id],
        )?;
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
            let platform_rows = self.backend.query(
                "SELECT platform, store_path, nar_hash, nar_size, closure_size, refs, images
                 FROM version_platforms WHERE version_id = ?1 ORDER BY platform",
                &vals![version_id],
            )?;
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

    /// List channels with their full partition maps.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_channels(&self, registry_id: i64) -> Result<Vec<ChannelSummary>> {
        let channel_rows = self.backend.query(
            "SELECT id, name, frontier FROM channels WHERE registry_id = ?1 ORDER BY name",
            &vals![registry_id],
        )?;
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
            let rows = self.backend.query(
                "SELECT bucket, release FROM channel_partitions WHERE channel_id = ?1",
                &vals![channel_id],
            )?;
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
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_releases(&self, registry_id: i64) -> Result<Vec<ReleaseRow>> {
        let rows = self.backend.query(
            "SELECT semver, tag_oid, commit_oid, signer, tagged_at, pack_present
             FROM releases WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC",
            &vals![registry_id],
        )?;
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
    pub fn refs_digest(&self, registry_id: i64) -> Result<Option<String>> {
        let digest: Option<Option<String>> = self
            .backend
            .query_opt(
                "SELECT refs_digest FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
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
    pub fn list_roster(&self, registry_id: i64) -> Result<Vec<(String, String, String)>> {
        let rows = self.backend.query(
            "SELECT key_id, public_key, status FROM key_rosters
             WHERE registry_id = ?1 ORDER BY status, key_id",
            &vals![registry_id],
        )?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .collect()
    }

    /// Committed `[[caches]]` entries as `(url, priority)`, highest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_caches(&self, registry_id: i64) -> Result<Vec<(String, u32)>> {
        let rows = self.backend.query(
            "SELECT url, priority FROM caches WHERE registry_id = ?1 ORDER BY priority DESC",
            &vals![registry_id],
        )?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get::<u32>(1)?)))
            .collect()
    }

    /// The committed cache-stack expression for a registry, parsed.
    ///
    /// Returns the stored stack ([`crate::stack::StackNode`]) when the
    /// registry's committed `registry.toml` carried a `[cache_stack]` section
    /// at index time, or `None` when it uses only the flat `[[caches]]` list.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or when the stored stack JSON
    /// fails to parse (an internal-consistency error — the indexer only ever
    /// stores well-formed JSON).
    pub fn registry_cache_stack(
        &self,
        registry_id: i64,
    ) -> Result<Option<crate::stack::StackNode>> {
        let json: Option<String> = self
            .backend
            .query_opt(
                "SELECT cache_stack FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
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
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `slug` is already taken.
    pub fn create_org(&self, slug: &str, name: &str) -> Result<i64> {
        self.backend.execute_insert(
            "INSERT INTO orgs (slug, name, created_at) VALUES (?1, ?2, ?3)",
            &vals![slug, name, unix_now()],
        )
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
    pub fn org_by_slug(&self, slug: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, slug, name, created_at FROM orgs
                 WHERE slug = ?1 AND deleted_at IS NULL",
                &vals![slug],
            )
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
    pub fn org_by_slug_including_deleted(&self, slug: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, slug, name, created_at FROM orgs WHERE slug = ?1",
                &vals![slug],
            )
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
    pub fn create_project(&self, org_id: i64, path: &str, name: &str) -> Result<i64> {
        self.backend.execute_insert(
            "INSERT INTO projects (org_id, path, name, created_at) VALUES (?1, ?2, ?3, ?4)",
            &vals![org_id, path, name, unix_now()],
        )
    }

    /// List an org's projects, ordered by materialized path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_projects(&self, org_id: i64) -> Result<Vec<ProjectRecord>> {
        let rows = self.backend.query(
            "SELECT id, org_id, path, name, created_at FROM projects
             WHERE org_id = ?1 ORDER BY path",
            &vals![org_id],
        )?;
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

    // -- tenancy: principals -------------------------------------------------

    /// Create a user; returns the new user id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a unique-constraint
    /// violation when `email` is already registered.
    pub fn create_user(&self, email: &str, display_name: Option<&str>) -> Result<i64> {
        self.backend.execute_insert(
            "INSERT INTO users (email, display_name, created_at) VALUES (?1, ?2, ?3)",
            &vals![email, display_name, unix_now()],
        )
    }

    /// Look up a non-deleted user's id by email.
    ///
    /// Soft-deleted users (those with `deleted_at` set) are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn user_by_email(&self, email: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT id FROM users WHERE email = ?1 AND deleted_at IS NULL",
                &vals![email],
            )
            .context("loading user by email")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Look up a non-deleted user's email by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn user_email(&self, user_id: i64) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT email FROM users WHERE id = ?1 AND deleted_at IS NULL",
                &vals![user_id],
            )
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
    pub fn find_or_create_user(&self, email: &str) -> Result<i64> {
        if let Some(id) = self.user_by_email(email)? {
            return Ok(id);
        }
        self.backend.execute(
            "INSERT INTO users (email, display_name, created_at) VALUES (?1, NULL, ?2)
             ON CONFLICT(email) DO NOTHING",
            &vals![email, unix_now()],
        )?;
        self.backend
            .query_opt("SELECT id FROM users WHERE email = ?1", &vals![email])?
            .context("resolving user id after insert")?
            .get(0)
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
    pub fn pending_device_request(&self, user_code: &str) -> Result<Option<(String, Vec<String>)>> {
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT scope, permissions FROM device_codes
                 WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
                   AND expires_at > ?2",
                &vals![user_code, now],
            )
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
    pub fn create_service_account(&self, org_id: i64, name: &str) -> Result<i64> {
        self.backend.execute_insert(
            "INSERT INTO service_accounts (org_id, name, created_at) VALUES (?1, ?2, ?3)",
            &vals![org_id, name, unix_now()],
        )
    }

    /// Look up a service account's id by `(org_id, name)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn service_account_by_name(&self, org_id: i64, name: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT id FROM service_accounts WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
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
        self.backend.execute(
            "INSERT INTO memberships
             (principal_kind, principal_id, scope, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(principal_kind, principal_id, scope)
             DO UPDATE SET role = excluded.role",
            &vals![principal_kind, principal_id, scope, role, unix_now()],
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
        self.backend.execute(
            "DELETE FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 AND scope = ?3",
            &vals![principal_kind, principal_id, scope],
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
        let rows = self.backend.query(
            "SELECT scope, role FROM memberships
             WHERE principal_kind = ?1 AND principal_id = ?2 ORDER BY scope",
            &vals![principal_kind, principal_id],
        )?;
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
    pub fn list_members_of_scope(&self, scope: &str) -> Result<Vec<(String, i64, String)>> {
        let rows = self.backend.query(
            "SELECT principal_kind, principal_id, role FROM memberships
             WHERE scope = ?1 ORDER BY principal_kind, principal_id",
            &vals![scope],
        )?;
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
        self.backend.execute(
            "UPDATE registries
             SET org_id = ?2, project_path = ?3, visibility = ?4
             WHERE id = ?1",
            &vals![registry_id, org_id, project_path, visibility],
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
        // Per-org registry-count quota (NULL/unset = unlimited).
        if let Some(max_registries) = self.org_quota(org_id)?.max_registries {
            if self.org_registry_count(org_id)? >= max_registries {
                bail!("org registry quota of {max_registries} reached");
            }
        }
        let id = self.backend.execute_insert(
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
        )?;
        self.backend.execute(
            "INSERT INTO registry_index (registry_id, state)
             VALUES (?1, 'indexing')
             ON CONFLICT(registry_id) DO NOTHING",
            &vals![id],
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
        self.backend.execute_insert(
            "INSERT INTO storage_bindings (org_id, name, kind, root, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &vals![org_id, name, kind, root, unix_now()],
        )
    }

    /// Look up a storage binding by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn storage_binding(&self, id: i64) -> Result<Option<StorageBindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, root, created_at
                 FROM storage_bindings WHERE id = ?1",
                &vals![id],
            )
            .context("loading storage binding by id")?
            .map(|row| row_to_storage_binding(&row))
            .transpose()
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
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, root, created_at
                 FROM storage_bindings WHERE org_id = ?1 AND name = ?2",
                &vals![org_id, name],
            )
            .context("loading storage binding by name")?
            .map(|row| row_to_storage_binding(&row))
            .transpose()
    }

    /// List an org's storage bindings, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_storage_bindings(&self, org_id: i64) -> Result<Vec<StorageBindingRecord>> {
        let rows = self.backend.query(
            "SELECT id, org_id, name, kind, root, created_at
             FROM storage_bindings WHERE org_id = ?1 ORDER BY name",
            &vals![org_id],
        )?;
        rows.iter().map(row_to_storage_binding).collect()
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
        self.backend.execute(
            "UPDATE registries SET storage_binding_id = ?2, prefix = ?3 WHERE id = ?1",
            &vals![registry_id, binding_id, prefix],
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
        let registry = self
            .backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE id = ?1"),
                &vals![registry_id],
            )
            .context("loading registry for surface resolution")?
            .map(|row| row_to_registry(&row))
            .transpose()?;
        let Some(registry) = registry else {
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
    pub fn create_hosted_key(
        &self,
        sealer: &dyn crate::auth::oidc::SecretSealer,
        org_id: i64,
        key_id: &str,
    ) -> Result<String> {
        use rand::Rng as _;

        let seed: [u8; 32] = rand::rng().random();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key =
            crate::surface::sshsig::trusted_key_line(key_id, &signing_key.verifying_key());
        // Seal the seed as a hex string so the placeholder XOR sealer (which
        // operates on UTF-8 plaintext) round-trips it losslessly.
        let secret_enc = sealer.seal(&hex::encode(seed))?;
        self.backend
            .execute(
                "INSERT INTO hosted_keys (org_id, key_id, public_key, secret_enc, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &vals![org_id, key_id, public_key, secret_enc, unix_now()],
            )
            .with_context(|| format!("enrolling hosted key '{key_id}' in org {org_id}"))?;
        Ok(public_key)
    }

    /// Load one hosted-key row by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn hosted_key(&self, id: i64) -> Result<Option<HostedKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, key_id, public_key, secret_enc, created_at
                 FROM hosted_keys WHERE id = ?1",
                &vals![id],
            )
            .context("loading hosted key by id")?
            .map(|row| row_to_hosted_key(&row))
            .transpose()
    }

    /// Look up a hosted key by its org and key id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn hosted_key_by_name(&self, org_id: i64, key_id: &str) -> Result<Option<HostedKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, key_id, public_key, secret_enc, created_at
                 FROM hosted_keys WHERE org_id = ?1 AND key_id = ?2",
                &vals![org_id, key_id],
            )
            .context("loading hosted key by name")?
            .map(|row| row_to_hosted_key(&row))
            .transpose()
    }

    /// List an org's hosted signing keys, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_hosted_keys(&self, org_id: i64) -> Result<Vec<HostedKeyRecord>> {
        let rows = self.backend.query(
            "SELECT id, org_id, key_id, public_key, secret_enc, created_at
             FROM hosted_keys WHERE org_id = ?1 ORDER BY created_at, id",
            &vals![org_id],
        )?;
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
    pub fn load_hosted_signing_key(
        &self,
        sealer: &dyn crate::auth::oidc::SecretSealer,
        id: i64,
    ) -> Result<(String, ed25519_dalek::SigningKey, String)> {
        let record = self
            .hosted_key(id)?
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
    pub fn set_registry_hosted_key(
        &self,
        registry_id: i64,
        hosted_key_id: Option<i64>,
    ) -> Result<()> {
        self.backend.execute(
            "UPDATE registries SET hosted_key_id = ?2 WHERE id = ?1",
            &vals![registry_id, hosted_key_id],
        )?;
        Ok(())
    }

    /// Look up an organization by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn org_by_id(&self, id: i64) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, slug, name, created_at FROM orgs WHERE id = ?1",
                &vals![id],
            )
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
    pub fn list_orgs(&self) -> Result<Vec<OrgRecord>> {
        let rows = self.backend.query(
            "SELECT id, slug, name, created_at FROM orgs
             WHERE deleted_at IS NULL ORDER BY slug",
            &[],
        )?;
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
    pub fn set_org_quota(&self, org_id: i64, quota: &OrgQuota) -> Result<()> {
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
        )?;
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
    pub fn org_quota(&self, org_id: i64) -> Result<OrgQuota> {
        let row = self.backend.query_opt(
            "SELECT max_bytes, max_objects, max_registries, max_tokens
             FROM org_quotas WHERE org_id = ?1",
            &vals![org_id],
        )?;
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
    pub fn org_usage(&self, org_id: i64) -> Result<OrgUsage> {
        let row = self.backend.query_opt(
            "SELECT used_bytes, object_count, updated_at FROM org_usage WHERE org_id = ?1",
            &vals![org_id],
        )?;
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
    pub fn add_org_usage(&self, org_id: i64, delta_bytes: i64, delta_objects: i64) -> Result<()> {
        self.backend.execute(
            "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(org_id) DO UPDATE SET
                 used_bytes = org_usage.used_bytes + excluded.used_bytes,
                 object_count = org_usage.object_count + excluded.object_count,
                 updated_at = excluded.updated_at",
            &vals![org_id, delta_bytes, delta_objects, unix_now()],
        )?;
        Ok(())
    }

    /// Whether writing `additional_bytes` more would exceed an org's byte quota.
    ///
    /// Returns `true` only when the org has a `max_bytes` cap *and*
    /// `used_bytes + additional_bytes` would exceed it. An org with no cap (or
    /// no quota row) never exceeds. The object-count cap is checked separately
    /// by the caller against [`Database::org_quota`]/[`Database::org_usage`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn would_exceed_quota(&self, org_id: i64, additional_bytes: i64) -> Result<bool> {
        let quota = self.org_quota(org_id)?;
        let Some(max_bytes) = quota.max_bytes else {
            return Ok(false);
        };
        let used = self.org_usage(org_id)?.used_bytes;
        Ok(used.saturating_add(additional_bytes) > max_bytes)
    }

    /// Read an instance-config value by key.
    ///
    /// Returns `None` when the key is unset.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn instance_config_get(&self, key: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT value FROM instance_config WHERE config_key = ?1",
                &vals![key],
            )?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Set an instance-config value, upserting the key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn instance_config_set(&self, key: &str, value: &str) -> Result<()> {
        self.backend.execute(
            "INSERT INTO instance_config (config_key, value) VALUES (?1, ?2)
             ON CONFLICT(config_key) DO UPDATE SET value = excluded.value",
            &vals![key, value],
        )?;
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
    /// The seed is sealed at rest with the instance [`SecretSealer`] exactly as
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
    pub fn get_or_create_draft_signing_key(
        &self,
        sealer: &dyn crate::auth::oidc::SecretSealer,
    ) -> Result<(ed25519_dalek::SigningKey, String)> {
        let seed: [u8; 32] = match self.instance_config_get(Self::DRAFT_SIGNING_KEY)? {
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
                self.instance_config_set(Self::DRAFT_SIGNING_KEY, &sealed)?;
                seed
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_line =
            crate::surface::sshsig::trusted_key_line("aos-hub-draft", &signing_key.verifying_key());
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
    pub fn signup_policy(&self) -> Result<SignupPolicy> {
        Ok(self
            .instance_config_get("signup_policy")?
            .map(|v| SignupPolicy::parse(&v))
            .unwrap_or(SignupPolicy::InviteOnly))
    }

    /// Set the instance signup policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_signup_policy(&self, policy: SignupPolicy) -> Result<()> {
        self.instance_config_set("signup_policy", policy.as_str())
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
    pub fn org_active_token_count(&self, org_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM tokens
                 WHERE owner_kind = 'service_account'
                   AND revoked_at IS NULL
                   AND owner_id IN (SELECT id FROM service_accounts WHERE org_id = ?1)",
                &vals![org_id],
            )?
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
    pub fn export_org_token_metadata(
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
        let rows = self.backend.query(
            "SELECT id, owner_kind, owner_id, scope, permissions, created_at, expires_at,
                    last_used_at
             FROM tokens
             WHERE owner_kind = 'service_account'
               AND owner_id IN (SELECT id FROM service_accounts WHERE org_id = ?1)
             ORDER BY created_at, id",
            &vals![org_id],
        )?;
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
    pub fn list_memberships_under(
        &self,
        scope_prefix: &str,
    ) -> Result<Vec<(String, i64, String, String)>> {
        let prefix = crate::domain::Scope::parse(scope_prefix);
        let rows = self.backend.query(
            "SELECT principal_kind, principal_id, scope, role FROM memberships
             ORDER BY scope, principal_kind, principal_id",
            &[],
        )?;
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
    pub fn user_has_any_membership(&self, user_id: i64) -> Result<bool> {
        let count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1",
                &vals![user_id],
            )?
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
    pub fn has_pending_invitation(&self, email: &str) -> Result<bool> {
        let now = unix_now();
        let count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM invitations
                 WHERE email = ?1 AND accepted_at IS NULL AND expires_at > ?2",
                &vals![email, now],
            )?
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
    pub fn org_registry_count(&self, org_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM registries WHERE org_id = ?1",
                &vals![org_id],
            )?
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
    pub fn org_is_active(&self, org_id: i64) -> Result<bool> {
        let row = self.backend.query_opt(
            "SELECT 1 FROM orgs WHERE id = ?1 AND deleted_at IS NULL",
            &vals![org_id],
        )?;
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
    pub fn soft_delete_org(&self, org_id: i64, grace_secs: i64) -> Result<bool> {
        let now = unix_now();
        let n = self.backend.execute(
            "UPDATE orgs SET deleted_at = ?2, purge_after = ?3
             WHERE id = ?1 AND deleted_at IS NULL",
            &vals![org_id, now, now + grace_secs],
        )?;
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
    pub fn restore_org(&self, org_id: i64) -> Result<bool> {
        let n = self.backend.execute(
            "UPDATE orgs SET deleted_at = NULL, purge_after = NULL
             WHERE id = ?1 AND deleted_at IS NOT NULL",
            &vals![org_id],
        )?;
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
    pub fn list_purgeable_orgs(&self, now: i64) -> Result<Vec<OrgRecord>> {
        let rows = self.backend.query(
            "SELECT id, slug, name, created_at FROM orgs
             WHERE deleted_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after <= ?1
             ORDER BY slug",
            &vals![now],
        )?;
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
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn hard_purge_org(&self, org_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute("DELETE FROM orgs WHERE id = ?1", &vals![org_id])?;
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
    pub fn create_invitation(
        &self,
        org_id: i64,
        email: &str,
        scope: &str,
        role: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<i64> {
        self.backend.execute_insert(
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
        let now = unix_now();
        let record = self
            .backend
            .query_opt(
                "SELECT id, org_id, email, scope, role FROM invitations
                 WHERE token_hash = ?1 AND accepted_at IS NULL AND expires_at > ?2",
                &vals![token_hash, now],
            )
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
            self.backend.execute(
                "UPDATE invitations SET accepted_at = ?2 WHERE id = ?1",
                &vals![record.id, now],
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
        self.backend.execute(
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
        let row = self
            .backend
            .query_opt(
                "SELECT id, owner_kind, owner_id, scope, permissions, expires_at,
                        revoked_at, rotated_at
                 FROM tokens WHERE hash = ?1",
                &vals![hash],
            )
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
        self.backend.execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
            &vals![id, now],
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
        self.backend.execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            &vals![token_id, unix_now()],
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
        let rows = self.backend.query(
            "SELECT id, scope, permissions FROM tokens
             WHERE owner_kind = ?1 AND owner_id = ?2 AND revoked_at IS NULL
             ORDER BY created_at",
            &vals![owner.kind.as_str(), owner.id],
        )?;
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
        let mut result: Option<(String, String)> = None;
        self.backend.with_tx(&mut |tx| {
            let old = tx.query_opt(
                "SELECT owner_kind, owner_id, scope, permissions, comment, expires_at
                 FROM tokens WHERE id = ?1 AND revoked_at IS NULL",
                &vals![token_id],
            )?;
            let Some(old) = old else {
                return Ok(());
            };
            let owner_kind: String = old.get(0)?;
            let owner_id: i64 = old.get(1)?;
            let scope: String = old.get(2)?;
            let perms_json: String = old.get(3)?;
            let comment: Option<String> = old.get(4)?;
            let expires_at: Option<i64> = old.get(5)?;
            tx.execute(
                "UPDATE tokens SET rotated_at = ?2 WHERE id = ?1",
                &vals![token_id, now],
            )?;
            let (secret, hash) = crate::auth::token::generate_token();
            let new_id = uuid::Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO tokens
                 (id, hash, owner_kind, owner_id, scope, permissions, comment, created_at,
                  expires_at, revoked_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
                &vals![
                    new_id, hash, owner_kind, owner_id, scope, perms_json, comment, now,
                    expires_at,
                ],
            )?;
            result = Some((new_id, secret));
            Ok(())
        })?;
        Ok(result)
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
        self.backend.execute(
            "INSERT INTO sessions
             (id_hash, user_id, created_at, last_seen_at, expires_at, auth_level,
              last_authenticated_at)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?3)",
            &vals![hash, user_id, now, now + ttl_secs, auth_level],
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
        let row = self
            .backend
            .query_opt(
                "SELECT user_id, auth_level, last_authenticated_at, expires_at
                 FROM sessions WHERE id_hash = ?1",
                &vals![hash],
            )
            .context("loading session by hash")?
            .map(|row| -> Result<SessionAuth> {
                Ok(SessionAuth {
                    user_id: row.get(0)?,
                    auth_level: row.get(1)?,
                    last_authenticated_at: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            })
            .transpose()?;
        let Some(session) = row else {
            return Ok(None);
        };
        if now >= session.expires_at {
            return Ok(None);
        }
        self.backend.execute(
            "UPDATE sessions SET last_seen_at = ?2 WHERE id_hash = ?1",
            &vals![hash, now],
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
        self.backend
            .execute("DELETE FROM sessions WHERE id_hash = ?1", &vals![hash])?;
        Ok(())
    }

    /// Revoke every session belonging to a user ("sign out everywhere").
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn revoke_all_user_sessions(&self, user_id: i64) -> Result<()> {
        self.backend
            .execute("DELETE FROM sessions WHERE user_id = ?1", &vals![user_id])?;
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
    pub fn sole_owned_orgs(&self, user_id: i64) -> Result<Vec<String>> {
        // Orgs where the user is an owner at the org scope.
        let rows = self.backend.query(
            "SELECT o.id, o.slug FROM orgs o
             JOIN memberships m
               ON m.scope = o.slug
              AND m.principal_kind = 'user'
              AND m.principal_id = ?1
              AND m.role = 'owner'
             WHERE o.deleted_at IS NULL",
            &vals![user_id],
        )?;
        let mut sole = Vec::new();
        for row in &rows {
            let org_slug: String = row.get(1)?;
            let owner_count: i64 = self
                .backend
                .query_opt(
                    "SELECT COUNT(*) FROM memberships
                     WHERE scope = ?1 AND principal_kind = 'user' AND role = 'owner'",
                    &vals![org_slug],
                )?
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
    pub fn transfer_org_ownership(&self, org_id: i64, from_user: i64, to_user: i64) -> Result<()> {
        let org = self
            .org_by_id(org_id)?
            .with_context(|| format!("no org with id {org_id}"))?;
        let now = unix_now();
        self.backend.with_tx(&mut |tx| {
            tx.execute(
                "INSERT INTO memberships
                 (principal_kind, principal_id, scope, role, created_at)
                 VALUES ('user', ?1, ?2, 'owner', ?3)
                 ON CONFLICT(principal_kind, principal_id, scope)
                 DO UPDATE SET role = excluded.role",
                &vals![to_user, org.slug, now],
            )?;
            tx.execute(
                "DELETE FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1 AND scope = ?2",
                &vals![from_user, org.slug],
            )?;
            Ok(())
        })?;
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
    pub fn delete_user(&self, user_id: i64) -> Result<bool> {
        let blocking = self.sole_owned_orgs(user_id)?;
        if !blocking.is_empty() {
            bail!(
                "user {user_id} is the sole owner of: {} — transfer ownership before deleting",
                blocking.join(", ")
            );
        }
        let now = unix_now();
        let mut deleted = false;
        self.backend.with_tx(&mut |tx| {
            let n = tx.execute(
                "UPDATE users SET deleted_at = ?2 WHERE id = ?1 AND deleted_at IS NULL",
                &vals![user_id, now],
            )?;
            if n == 0 {
                return Ok(());
            }
            deleted = true;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", &vals![user_id])?;
            tx.execute(
                "UPDATE tokens SET revoked_at = ?2
                 WHERE owner_kind = 'user' AND owner_id = ?1 AND revoked_at IS NULL",
                &vals![user_id, now],
            )?;
            Ok(())
        })?;
        Ok(deleted)
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
        self.backend.execute(
            "UPDATE sessions SET auth_level = 1, last_authenticated_at = ?2 WHERE id_hash = ?1",
            &vals![hash, unix_now()],
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
        self.backend.execute(
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
        let row = self
            .backend
            .query_opt(
                "SELECT scope, permissions FROM device_codes
                 WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
                   AND expires_at > ?2",
                &vals![user_code, now],
            )
            .context("loading device code for approval")?;
        let Some(row) = row else {
            return Ok(false);
        };
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
        let (token_id, secret) =
            self.create_token(approver, requested_scope.as_str(), &granted, None, None)?;
        // Stow the minted secret on the device row: it is delivered exactly
        // once to the polling CLI by `poll_device`, never persisted in the
        // clear anywhere a human session can read it.
        self.backend.execute(
            "UPDATE device_codes
             SET approved_by_user = ?2, issued_token_id = ?3, issued_token_secret = ?4
             WHERE user_code = ?1",
            &vals![user_code, approver.id, token_id, secret],
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
        let n = self.backend.execute(
            "UPDATE device_codes SET denied = 1
             WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0",
            &vals![user_code],
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
        let row = self
            .backend
            .query_opt(
                "SELECT denied, approved_by_user, issued_token_secret
                 FROM device_codes WHERE device_code_hash = ?1",
                &vals![hash],
            )
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
    pub fn create_magic_link(&self, email: &str) -> Result<String> {
        let secret = crate::auth::magic::new_magic_secret();
        let hash = crate::auth::token::sha256_hex(&secret);
        let now = unix_now();
        self.backend.execute(
            "INSERT INTO magic_links (token_hash, email, created_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            &vals![
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
        // Claim-then-read: the conditional UPDATE is the single-use gate, so
        // two concurrent consumptions of the same link cannot both succeed
        // (the second stamps zero rows). On sqlite/postgres a single
        // `UPDATE … RETURNING email` ties the claim to the email atomically;
        // MySQL has no `UPDATE … RETURNING`, so a transactional
        // select-claim-then-read preserves the same single-use guarantee.
        if self.dialect() == Dialect::Mysql {
            let mut email: Option<String> = None;
            self.backend.with_tx(&mut |tx| {
                let n = tx.execute(
                    "UPDATE magic_links SET consumed_at = ?2
                     WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                    &vals![hash, now],
                )?;
                if n > 0 {
                    let row = tx.query_opt(
                        "SELECT email FROM magic_links WHERE token_hash = ?1",
                        &vals![hash],
                    )?;
                    email = row.map(|r| r.get(0)).transpose()?;
                }
                Ok(())
            })?;
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
    /// must already be **sealed** by a [`crate::auth::oidc::SecretSealer`] —
    /// this method stores the value verbatim and never sees the plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, including a foreign-key
    /// violation when `org_id` does not reference an org.
    pub fn upsert_idp_config(&self, config: &IdpConfigRecord) -> Result<()> {
        let now = unix_now();
        self.backend.execute(
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
        )?;
        Ok(())
    }

    /// Load an org's OIDC identity-provider configuration, if configured.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn idp_config(&self, org_id: i64) -> Result<Option<IdpConfigRecord>> {
        self.backend
            .query_opt(
                "SELECT org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
                        client_id, client_secret_enc, scopes, groups_claim, role_map_json,
                        allow_jit, enforce_sso, default_role
                 FROM org_idp_configs WHERE org_id = ?1",
                &vals![org_id],
            )
            .context("loading idp config by org id")?
            .map(|row| row_to_idp_config(&row))
            .transpose()
    }

    /// Claim a domain for an org with a fresh DNS-TXT challenge.
    ///
    /// Returns the generated `txt_challenge` value the org must publish as a
    /// TXT record at the domain to prove control; the domain starts
    /// **unverified** (`verified_at` NULL) until [`Database::verify_org_domain`]
    /// stamps it. Re-claiming a domain rotates its challenge and resets it to
    /// unverified.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn add_org_domain(&self, org_id: i64, domain: &str) -> Result<String> {
        let domain = domain.trim().to_lowercase();
        let challenge = format!(
            "aos-domain-verify={}",
            crate::auth::session::new_session_secret()
        );
        self.backend.execute(
            "INSERT INTO org_domains (domain, org_id, txt_challenge, verified_at)
             VALUES (?1, ?2, ?3, NULL)
             ON CONFLICT(domain) DO UPDATE SET
                 org_id = excluded.org_id,
                 txt_challenge = excluded.txt_challenge,
                 verified_at = NULL",
            &vals![domain, org_id, challenge],
        )?;
        Ok(challenge)
    }

    /// Look up a claimed domain (verified or not).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn org_domain(&self, domain: &str) -> Result<Option<OrgDomainRecord>> {
        let domain = domain.trim().to_lowercase();
        self.backend
            .query_opt(
                "SELECT domain, org_id, txt_challenge, verified_at FROM org_domains WHERE domain = ?1",
                &vals![domain],
            )
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
    pub fn verify_org_domain(&self, domain: &str) -> Result<bool> {
        let domain = domain.trim().to_lowercase();
        let n = self.backend.execute(
            "UPDATE org_domains SET verified_at = ?2 WHERE domain = ?1",
            &vals![domain, unix_now()],
        )?;
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
    pub fn org_for_domain(&self, domain: &str) -> Result<Option<i64>> {
        let domain = domain.trim().to_lowercase();
        self.backend
            .query_opt(
                "SELECT org_id FROM org_domains WHERE domain = ?1 AND verified_at IS NOT NULL",
                &vals![domain],
            )
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
    pub fn create_oidc_flow(
        &self,
        state: &str,
        org_id: i64,
        nonce: &str,
        code_verifier: &str,
        redirect_after: Option<&str>,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = unix_now();
        self.backend.execute(
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
        )?;
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
    pub fn take_oidc_flow(&self, state: &str) -> Result<Option<OidcFlowRecord>> {
        let now = unix_now();
        // sqlite/postgres do the delete-and-read in one `DELETE … RETURNING`;
        // MySQL lacks it, so select-then-delete inside a transaction keeps the
        // single-use, CSRF-defeating gate (the delete claims the state).
        let row: Option<OidcFlowRecord> = if self.dialect() == Dialect::Mysql {
            let mut found = None;
            self.backend.with_tx(&mut |tx| {
                let selected = tx.query_opt(
                    "SELECT state, org_id, nonce, code_verifier, redirect_after, expires_at
                     FROM oidc_flows WHERE state = ?1",
                    &vals![state],
                )?;
                if let Some(r) = selected {
                    let n = tx.execute("DELETE FROM oidc_flows WHERE state = ?1", &vals![state])?;
                    if n > 0 {
                        found = Some(row_to_oidc_flow(&r)?);
                    }
                }
                Ok(())
            })?;
            found
        } else {
            self.backend
                .query_opt(
                    "DELETE FROM oidc_flows WHERE state = ?1
                     RETURNING state, org_id, nonce, code_verifier, redirect_after, expires_at",
                    &vals![state],
                )
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
    pub fn create_webauthn_challenge(
        &self,
        challenge: &str,
        user_id: Option<i64>,
        kind: &str,
        ttl_secs: i64,
    ) -> Result<()> {
        let now = unix_now();
        self.backend.execute(
            "INSERT INTO webauthn_challenges (challenge, user_id, kind, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &vals![challenge, user_id, kind, now, now + ttl_secs],
        )?;
        Ok(())
    }

    /// Consume a WebAuthn challenge by value, returning it exactly once.
    ///
    /// Deletes the row and returns it (`DELETE … RETURNING` on sqlite/postgres,
    /// a select-then-delete transaction on MySQL), so a replayed challenge finds
    /// nothing — the single-use, anti-replay gate. Returns `Ok(None)` for an
    /// unknown, already-consumed, expired, or wrong-`kind` challenge.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn take_webauthn_challenge(
        &self,
        challenge: &str,
        kind: &str,
    ) -> Result<Option<WebauthnChallengeRecord>> {
        let now = unix_now();
        let row: Option<WebauthnChallengeRecord> = if self.dialect() == Dialect::Mysql {
            let mut found = None;
            self.backend.with_tx(&mut |tx| {
                let selected = tx.query_opt(
                    "SELECT challenge, user_id, kind, expires_at
                     FROM webauthn_challenges WHERE challenge = ?1",
                    &vals![challenge],
                )?;
                if let Some(r) = selected {
                    let n = tx.execute(
                        "DELETE FROM webauthn_challenges WHERE challenge = ?1",
                        &vals![challenge],
                    )?;
                    if n > 0 {
                        found = Some(row_to_webauthn_challenge(&r)?);
                    }
                }
                Ok(())
            })?;
            found
        } else {
            self.backend
                .query_opt(
                    "DELETE FROM webauthn_challenges WHERE challenge = ?1
                     RETURNING challenge, user_id, kind, expires_at",
                    &vals![challenge],
                )
                .context("consuming webauthn challenge")?
                .map(|row| row_to_webauthn_challenge(&row))
                .transpose()?
        };
        // The row is deleted, but an expired or mismatched-kind challenge must
        // not authenticate.
        match row {
            Some(rec) if now < rec.expires_at && rec.kind == kind => Ok(Some(rec)),
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
    pub fn add_webauthn_credential(
        &self,
        user_id: i64,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
        transports: Option<&str>,
        label: Option<&str>,
    ) -> Result<i64> {
        self.backend.execute_insert(
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
    }

    /// Look up a WebAuthn credential by its base64url credential id.
    ///
    /// Returns `Ok(None)` when no credential with that id is registered (the
    /// assertion is for an unknown or de-registered passkey).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn webauthn_credential_by_id(
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
            .context("loading webauthn credential by id")?
            .map(|row| row_to_webauthn_credential(&row))
            .transpose()
    }

    /// List a user's registered WebAuthn credentials, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_user_credentials(&self, user_id: i64) -> Result<Vec<WebauthnCredentialRecord>> {
        self.backend
            .query(
                "SELECT id, user_id, credential_id, public_key, sign_count, transports,
                        label, created_at, last_used_at
                 FROM webauthn_credentials WHERE user_id = ?1
                 ORDER BY created_at DESC, id DESC",
                &vals![user_id],
            )
            .context("listing user webauthn credentials")?
            .iter()
            .map(row_to_webauthn_credential)
            .collect()
    }

    /// Update a credential's stored signature counter.
    ///
    /// Called after a successful assertion to advance the monotonic counter the
    /// next assertion is checked against.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn update_credential_sign_count(&self, id: i64, sign_count: i64) -> Result<()> {
        self.backend.execute(
            "UPDATE webauthn_credentials SET sign_count = ?2 WHERE id = ?1",
            &vals![id, sign_count],
        )?;
        Ok(())
    }

    /// Stamp a credential's `last_used_at` to now.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn touch_credential(&self, id: i64) -> Result<()> {
        self.backend.execute(
            "UPDATE webauthn_credentials SET last_used_at = ?2 WHERE id = ?1",
            &vals![id, unix_now()],
        )?;
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
    /// 3. Otherwise, when `allow_jit`, a fresh user and identity are created
    ///    ([`IdentityLink::Created`]).
    ///
    /// Returns `Ok(None)` when no identity exists, no auto-link applies, and
    /// `allow_jit` is false — the caller rejects the login.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn link_or_create_identity(
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
        if let Some(user_id) = self.identity_user(issuer, subject)? {
            self.backend.execute(
                "UPDATE user_identities SET email = ?3, last_login = ?4
                 WHERE issuer = ?1 AND subject = ?2",
                &vals![issuer, subject, email, now],
            )?;
            return Ok(Some(IdentityLink::Existing(user_id)));
        }
        // 2. Auto-link a verified email on a captured domain to an existing user.
        if email_verified {
            if let Some(addr) = email {
                let domain = addr.rsplit_once('@').map(|(_, d)| d.to_lowercase());
                let captured = match &domain {
                    Some(d) => self.org_for_domain(d)? == Some(org_id),
                    None => false,
                };
                if captured {
                    if let Some(user_id) = self.user_by_email(addr)? {
                        self.insert_identity(issuer, subject, user_id, email, now)?;
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
        let user_id = self.find_or_create_user(&user_email)?;
        self.insert_identity(issuer, subject, user_id, email, now)?;
        Ok(Some(IdentityLink::Created(user_id)))
    }

    /// The user id linked to an `(issuer, subject)` identity, if any.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn identity_user(&self, issuer: &str, subject: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT user_id FROM user_identities WHERE issuer = ?1 AND subject = ?2",
                &vals![issuer, subject],
            )
            .context("loading identity user")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Insert a new `(issuer, subject)` identity for a user.
    fn insert_identity(
        &self,
        issuer: &str,
        subject: &str,
        user_id: i64,
        email: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.backend.execute(
            "INSERT INTO user_identities (user_id, issuer, subject, email, last_login)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &vals![user_id, issuer, subject, email, now],
        )?;
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
    pub fn set_registry_visibility(&self, registry_id: i64, visibility: &str) -> Result<()> {
        self.backend.execute(
            "UPDATE registries SET visibility = ?2 WHERE id = ?1",
            &vals![registry_id, visibility],
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
        self.backend.execute_insert(
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
        let rows = self.backend.query(
            "SELECT id, change_id, actor_kind, actor_label, action, scope,
                    result_commit, result_tag, detail, created_at
             FROM audit_log ORDER BY id DESC",
            &[],
        )?;
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
    pub fn create_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
    ) -> Result<()> {
        self.backend.execute(
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
        )?;
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
    pub fn create_git_changeset(
        &self,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        scope: &str,
        summary: Option<&str>,
        git_ref: &str,
        git_commit: &str,
    ) -> Result<()> {
        self.backend.execute(
            "INSERT INTO config_changesets
             (change_id, actor_kind, actor_id, actor_label, scope, status,
              summary, created_at, applied_at, reverted_by_change_id, git_ref, git_commit)
             VALUES (?1, ?2, ?3, ?4, ?5, 'draft', ?6, ?7, NULL, NULL, ?8, ?9)",
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
        let seq: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM config_revisions WHERE change_id = ?1",
                &vals![change_id],
            )?
            .context("count query returned no row")?
            .get(0)?;
        self.backend.execute(
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
        )?;
        Ok(seq)
    }

    /// Load one change-set summary by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn changeset(&self, change_id: &str) -> Result<Option<ChangesetRow>> {
        self.backend
            .query_opt(
                &format!("SELECT {CHANGESET_COLUMNS} FROM config_changesets WHERE change_id = ?1"),
                &vals![change_id],
            )
            .context("loading changeset by id")?
            .map(|row| row_to_changeset(&row))
            .transpose()
    }

    /// List a change-set's revisions in `seq` order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_revisions(&self, change_id: &str) -> Result<Vec<RevisionRow>> {
        let rows = self.backend.query(
            "SELECT id, change_id, object_type, object_id, op, old_json, new_json, seq
             FROM config_revisions WHERE change_id = ?1 ORDER BY seq",
            &vals![change_id],
        )?;
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
        self.backend.execute(
            "UPDATE config_changesets
             SET status = ?2,
                 applied_at = COALESCE(?3, applied_at),
                 reverted_by_change_id = COALESCE(?4, reverted_by_change_id)
             WHERE change_id = ?1",
            &vals![change_id, status, applied_at, reverted_by],
        )?;
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
    pub fn mark_changeset_applied_commit(&self, change_id: &str, commit_oid: &str) -> Result<()> {
        self.backend.execute(
            "UPDATE config_changesets
             SET status = 'applied', applied_at = ?2, git_commit = ?3
             WHERE change_id = ?1 AND status = 'draft'",
            &vals![change_id, unix_now(), commit_oid],
        )?;
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
    pub fn audit_exists_for_commit(&self, action: &str, result_commit: &str) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM audit_log WHERE action = ?1 AND result_commit = ?2 LIMIT 1",
                &vals![action, result_commit],
            )?
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
    pub fn apply_changeset<F>(&self, change_id: &str, mut apply_fn: F) -> Result<()>
    where
        F: FnMut(&RevisionRow) -> Result<()>,
    {
        let revisions = self.list_revisions(change_id)?;
        for revision in &revisions {
            apply_fn(revision)?;
        }
        self.backend.with_tx(&mut |tx| {
            tx.execute(
                "UPDATE config_changesets SET status = 'applied', applied_at = ?2
                 WHERE change_id = ?1",
                &vals![change_id, unix_now()],
            )?;
            Ok(())
        })
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
        let rows = self.backend.query(
            &format!(
                "SELECT {CHANGESET_COLUMNS} FROM config_changesets \
                 ORDER BY created_at DESC, change_id DESC"
            ),
            &[],
        )?;
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
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn create_webhook(
        &self,
        org_id: i64,
        url: &str,
        secret: &str,
        events: &[String],
    ) -> Result<i64> {
        self.backend.execute_insert(
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
    }

    /// List an org's webhook subscriptions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn list_webhooks(&self, org_id: i64) -> Result<Vec<WebhookRecord>> {
        let rows = self.backend.query(
            "SELECT id, org_id, url, secret, events, active, created_at
             FROM webhooks WHERE org_id = ?1 ORDER BY id",
            &vals![org_id],
        )?;
        rows.iter().map(row_to_webhook).collect()
    }

    /// Load one webhook by id, regardless of org.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn webhook(&self, id: i64) -> Result<Option<WebhookRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, url, secret, events, active, created_at
                 FROM webhooks WHERE id = ?1",
                &vals![id],
            )
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
    pub fn delete_webhook(&self, id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute("DELETE FROM webhooks WHERE id = ?1", &vals![id])?;
        Ok(n > 0)
    }

    /// Enable or disable a webhook; returns whether a row was updated.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub fn set_webhook_active(&self, id: i64, active: bool) -> Result<bool> {
        let n = self.backend.execute(
            "UPDATE webhooks SET active = ?2 WHERE id = ?1",
            &vals![id, active],
        )?;
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
    pub fn enqueue_delivery(&self, webhook_id: i64, event: &str, payload: &str) -> Result<i64> {
        let now = unix_now();
        self.backend.execute_insert(
            "INSERT INTO webhook_deliveries
             (webhook_id, event, payload, status, attempts, created_at, next_attempt_at)
             VALUES (?1, ?2, ?3, 'pending', 0, ?4, ?4)",
            &vals![webhook_id, event, payload, now],
        )
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
    pub fn due_deliveries(&self, now: i64) -> Result<Vec<DueDelivery>> {
        let rows = self.backend.query(
            "SELECT d.id, d.webhook_id, d.event, d.payload, d.attempts, w.url, w.secret
             FROM webhook_deliveries d
             JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 AND w.active = 1
             ORDER BY d.id",
            &vals![now],
        )?;
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
    pub fn mark_delivery(
        &self,
        id: i64,
        status: &str,
        response_code: Option<i64>,
        attempts: i64,
        next_attempt_at: Option<i64>,
    ) -> Result<()> {
        let delivered_at = (status == "delivered").then(unix_now);
        self.backend.execute(
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
        )?;
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
    pub fn delivery_status_counts(&self) -> Result<(u64, u64, u64)> {
        let count = |status: &str| -> Result<u64> {
            self.backend
                .query_opt(
                    "SELECT COUNT(*) FROM webhook_deliveries WHERE status = ?1",
                    &vals![status],
                )?
                .context("count query returned no row")?
                .get::<u64>(0)
        };
        Ok((count("pending")?, count("delivered")?, count("failed")?))
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
     org_id, project_path, visibility, storage_binding_id, prefix, hosted_key_id";

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

/// Map a `frontends` row into a [`FrontendRecord`] (columns in the order
/// [`Database::list_frontends`] selects).
fn row_to_frontend(row: &Row) -> Result<FrontendRecord> {
    Ok(FrontendRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        domain: row.get(2)?,
        base_path: row.get(3)?,
        mode: row.get(4)?,
        serves_git: row.get(5)?,
        serves_cache: row.get(6)?,
        serves_web: row.get(7)?,
        consumer_priority: row.get(8)?,
        advertised: row.get(9)?,
        created_at: row.get(10)?,
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
     summary, created_at, applied_at, reverted_by_change_id, git_ref, git_commit";

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
    // The in-module migration tests exercise raw `rusqlite` access through the
    // sqlite-only `lock()` helper, so they bind parameters with rusqlite's own
    // `params!` macro.
    use rusqlite::params;

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
            cache_stack: None,
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
    fn v7_database_migrates_to_v8_and_stores_cache_stack() {
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
        let db = Database::open(&path).unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        assert!(db.registry_cache_stack(id).unwrap().is_none());

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
        .unwrap();
        assert_eq!(db.registry_cache_stack(id).unwrap(), Some(stack));
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
    fn draft_signing_key_is_generated_once_and_persists() {
        let db = Database::open_in_memory().unwrap();
        let sealer = crate::auth::oidc::dev_sealer();
        let (key1, line1) = db.get_or_create_draft_signing_key(sealer.as_ref()).unwrap();
        // A second call returns the same key (persisted seed), not a fresh one.
        let (key2, line2) = db.get_or_create_draft_signing_key(sealer.as_ref()).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        assert_eq!(line1, line2);
        assert!(line1.starts_with("aos-hub-draft:Ed25519:"));
        // The stored value is sealed, not the raw seed.
        let stored = db
            .instance_config_get("draft_signing_key")
            .unwrap()
            .unwrap();
        assert_ne!(stored, hex::encode(key1.to_bytes()));
    }

    #[test]
    fn git_changeset_records_ref_and_commit() {
        let db = Database::open_in_memory().unwrap();
        db.create_git_changeset(
            "ch-1",
            "user",
            Some(7),
            "alice@acme.com",
            "acme/cdn",
            Some("edit registry.toml"),
            "refs/hub/changes/ch-1",
            "abc123",
        )
        .unwrap();
        let cs = db.changeset("ch-1").unwrap().unwrap();
        assert_eq!(cs.status, "draft");
        assert_eq!(cs.git_ref.as_deref(), Some("refs/hub/changes/ch-1"));
        assert_eq!(cs.git_commit.as_deref(), Some("abc123"));
        // A plain change-set leaves both columns NULL.
        db.create_changeset("ch-2", "user", Some(7), "alice@acme.com", "acme", None)
            .unwrap();
        let plain = db.changeset("ch-2").unwrap().unwrap();
        assert!(plain.git_ref.is_none());
        assert!(plain.git_commit.is_none());
    }

    #[test]
    fn mark_changeset_applied_commit_links_promoting_commit() {
        let db = Database::open_in_memory().unwrap();
        db.create_git_changeset(
            "ch-3",
            "user",
            Some(7),
            "alice@acme.com",
            "acme/cdn",
            Some("edit"),
            "refs/hub/changes/ch-3",
            "draftoid",
        )
        .unwrap();
        db.mark_changeset_applied_commit("ch-3", "rosteroid")
            .unwrap();
        let cs = db.changeset("ch-3").unwrap().unwrap();
        assert_eq!(cs.status, "applied");
        assert!(cs.applied_at.is_some());
        assert_eq!(cs.git_commit.as_deref(), Some("rosteroid"));
        // Re-marking an applied row is a no-op (status-guarded UPDATE).
        db.mark_changeset_applied_commit("ch-3", "otheroid")
            .unwrap();
        let again = db.changeset("ch-3").unwrap().unwrap();
        assert_eq!(again.git_commit.as_deref(), Some("rosteroid"));
    }

    #[test]
    fn audit_exists_for_commit_is_specific_to_action_and_commit() {
        let db = Database::open_in_memory().unwrap();
        assert!(!db
            .audit_exists_for_commit("index.external_commit", "oid-1")
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
        .unwrap();
        assert!(db
            .audit_exists_for_commit("index.external_commit", "oid-1")
            .unwrap());
        // A different commit, or a different action, does not match.
        assert!(!db
            .audit_exists_for_commit("index.external_commit", "oid-2")
            .unwrap());
        assert!(!db.audit_exists_for_commit("index", "oid-1").unwrap());
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

    // -- operations: quotas, usage, signup policy, offboarding (v13) --------

    #[test]
    fn quota_defaults_to_unlimited_and_round_trips() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        // No quota row: every dimension unlimited.
        assert_eq!(db.org_quota(org).unwrap(), OrgQuota::default());
        assert!(!db.would_exceed_quota(org, i64::MAX / 2).unwrap());

        let quota = OrgQuota {
            max_bytes: Some(1000),
            max_objects: Some(10),
            max_registries: Some(2),
            max_tokens: Some(5),
        };
        db.set_org_quota(org, &quota).unwrap();
        assert_eq!(db.org_quota(org).unwrap(), quota);
    }

    #[test]
    fn usage_accumulates_and_drives_would_exceed_quota() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        db.set_org_quota(
            org,
            &OrgQuota {
                max_bytes: Some(100),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(db.org_usage(org).unwrap(), OrgUsage::default());
        // 60 more fits under 100.
        assert!(!db.would_exceed_quota(org, 60).unwrap());
        db.add_org_usage(org, 60, 1).unwrap();
        assert_eq!(db.org_usage(org).unwrap().used_bytes, 60);
        assert_eq!(db.org_usage(org).unwrap().object_count, 1);
        // 60 + 50 = 110 > 100: would exceed.
        assert!(db.would_exceed_quota(org, 50).unwrap());
        // 60 + 40 = 100 is not *over* 100.
        assert!(!db.would_exceed_quota(org, 40).unwrap());
    }

    #[test]
    fn signup_policy_defaults_invite_only_and_round_trips() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.signup_policy().unwrap(), SignupPolicy::InviteOnly);
        db.set_signup_policy(SignupPolicy::Open).unwrap();
        assert_eq!(db.signup_policy().unwrap(), SignupPolicy::Open);
        // An unknown stored value falls closed to invite-only.
        db.instance_config_set("signup_policy", "garbage").unwrap();
        assert_eq!(db.signup_policy().unwrap(), SignupPolicy::InviteOnly);
    }

    #[test]
    fn soft_delete_excludes_from_serving_then_restore() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        db.register_owned(org, "acme/cdn");
        assert!(db.org_by_slug("acme").unwrap().is_some());
        assert_eq!(db.list_orgs().unwrap().len(), 1);
        assert_eq!(db.list_registries().unwrap().len(), 1);

        assert!(db.soft_delete_org(org, 30 * 86_400).unwrap());
        // Excluded from active serving queries...
        assert!(db.org_by_slug("acme").unwrap().is_none());
        assert!(db.list_orgs().unwrap().is_empty());
        assert!(db.list_registries().unwrap().is_empty());
        assert!(!db.org_is_active(org).unwrap());
        // ...but still visible to the admin/restore path.
        assert!(db.org_by_slug_including_deleted("acme").unwrap().is_some());

        assert!(db.restore_org(org).unwrap());
        assert!(db.org_by_slug("acme").unwrap().is_some());
        assert_eq!(db.list_registries().unwrap().len(), 1);
    }

    #[test]
    fn purge_only_after_grace_window() {
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        let now = unix_now();
        db.soft_delete_org(org, 100).unwrap();
        // Not yet purgeable just after deletion.
        assert!(db.list_purgeable_orgs(now).unwrap().is_empty());
        // Past the grace window it is listed and can be purged.
        let purgeable = db.list_purgeable_orgs(now + 200).unwrap();
        assert_eq!(purgeable.len(), 1);
        assert!(db.hard_purge_org(org).unwrap());
        assert!(db.org_by_slug_including_deleted("acme").unwrap().is_none());
    }

    #[test]
    fn sole_owner_delete_blocked_then_transfer_succeeds() {
        use crate::domain::{Permission, Principal, Role};
        let db = Database::open_in_memory().unwrap();
        let org = db.create_org("acme", "Acme").unwrap();
        let alice = db.create_user("alice@acme.com", None).unwrap();
        let bob = db.create_user("bob@acme.com", None).unwrap();
        db.grant_membership("user", alice, "acme", "owner").unwrap();
        // Alice has a token + a session, to confirm they deaden on deletion.
        let (token_id, secret) = db
            .create_token(
                Principal::user(alice),
                "acme",
                &[Permission::Read],
                None,
                None,
            )
            .unwrap();
        let session = db.create_session(alice, 3600, 1).unwrap();

        // Alice is the sole owner: deletion is blocked.
        assert_eq!(db.sole_owned_orgs(alice).unwrap(), vec!["acme".to_string()]);
        assert!(db.delete_user(alice).is_err());
        // The token and session are untouched by the failed delete.
        assert!(db.validate_token(&secret).unwrap().is_some());
        assert!(db.validate_session(&session).unwrap().is_some());

        // Transfer ownership to Bob, then Alice is deletable.
        db.transfer_org_ownership(org, alice, bob).unwrap();
        assert!(db.sole_owned_orgs(alice).unwrap().is_empty());
        assert!(db.delete_user(alice).unwrap());
        // Alice's credentials deaden immediately.
        assert!(db.validate_token(&secret).unwrap().is_none());
        assert!(db.validate_session(&session).unwrap().is_none());
        assert!(db.user_email(alice).unwrap().is_none());
        let _ = token_id;
        // Bob now owns acme.
        let grants = db.effective_scopes(Principal::user(bob)).unwrap();
        assert!(grants
            .iter()
            .any(|(s, r)| s.as_str() == "acme" && *r == Role::Owner));
    }

    /// Test helper: register a managed registry owned by `org` at `slug` with a
    /// local_fs binding, so serving queries can exclude it on soft-delete.
    impl Database {
        fn register_owned(&self, org_id: i64, slug: &str) {
            let binding = self
                .create_storage_binding(org_id, "primary", "local_fs", "/tmp/aos-hub-test")
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
            .unwrap();
        }
    }
}
