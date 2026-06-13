//! Hub storage: the registry system of record plus the rebuildable index.
//!
//! Three kinds of tables live in one sqlite database, with sharply
//! different contracts (RFC-0004 "Stance"):
//!
//! - **System of record** — `registries`, `channel_floors`, and the
//!   phase-2 tenancy tables `orgs`, `projects`, `users`,
//!   `user_identities`, `service_accounts`, `memberships`, and
//!   `invitations`: facts that exist nowhere on the surface (slug, source
//!   URL, trust anchors, the anti-rollback floor each channel has reached,
//!   plus the org → project → registry hierarchy and who may act on it).
//!   Losing these loses real state; floors in particular survive every
//!   re-index, and ownership/grants are never rebuildable from the
//!   surface.
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

use std::path::Path;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

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
];

/// A registered registry (system-of-record row).
#[derive(Debug, Clone)]
pub struct RegistryRecord {
    /// Database id.
    pub id: i64,
    /// URL path slug the registry is served under.
    pub slug: String,
    /// Surface source: `file://` path or `http(s)://` base URL.
    pub source_url: String,
    /// Pinned trust anchors in `name:Ed25519:<base64>` form.
    pub trust_keys: Vec<String>,
    /// Whether indexing fails closed on missing/invalid signatures.
    pub require_signatures: bool,
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
            "SELECT id, slug, source_url, trust_keys, require_signatures
             FROM registries WHERE slug = ?1",
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
        let mut stmt = conn.prepare(
            "SELECT id, slug, source_url, trust_keys, require_signatures
             FROM registries ORDER BY slug",
        )?;
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
}

fn row_to_registry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RegistryRecord> {
    let trust_json: String = row.get(3)?;
    Ok(RegistryRecord {
        id: row.get(0)?,
        slug: row.get(1)?,
        source_url: row.get(2)?,
        trust_keys: serde_json::from_str(&trust_json).unwrap_or_default(),
        require_signatures: row.get::<_, i64>(4)? != 0,
    })
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
