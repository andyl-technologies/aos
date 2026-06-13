//! Hub storage: the registry system of record plus the rebuildable index.
//!
//! Two kinds of tables live in one sqlite database, with sharply different
//! contracts (RFC-0004 "Stance"):
//!
//! - **System of record** — `registries`: registration facts that exist
//!   nowhere on the surface (slug, source URL, trust anchors). Losing
//!   these loses real state.
//! - **Rebuildable index** — everything else (`registry_index`,
//!   `packages`, `package_versions`, `version_platforms`, `channels`,
//!   `channel_partitions`, `releases`, `key_rosters`, `caches`): derived
//!   from the verified surface by the indexer and safely droppable; a
//!   re-index reconstructs it.
//!
//! Migrations are ordered SQL statements tracked in `schema_version`,
//!  applied at open. The connection is wrapped in a `Mutex` following the
//! pattern of `aos-server`'s token store; hub queries are short and
//! page-shaped, so a single writer is ample for phase 1.

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

    /// Open an in-memory database (tests and `--dev` ephemeral mode).
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
                 (registry_id, semver, tag_oid, commit_oid, signer, tagged_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    registry_id,
                    release.semver,
                    release.tag_oid,
                    release.commit_oid,
                    release.signer,
                    release.tagged_at,
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
             (registry_id, state, error, last_indexed_commit, name, description, indexed_at)
             VALUES (?1, 'fresh', NULL, ?2, ?3, ?4, ?5)
             ON CONFLICT(registry_id) DO UPDATE SET
                 state = 'fresh', error = NULL,
                 last_indexed_commit = excluded.last_indexed_commit,
                 name = excluded.name, description = excluded.description,
                 indexed_at = excluded.indexed_at",
            params![
                registry_id,
                snapshot.commit,
                snapshot.name,
                snapshot.description,
                unix_now(),
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
            "SELECT platform, store_path, nar_hash, nar_size, closure_size
             FROM version_platforms WHERE version_id = ?1 ORDER BY platform",
        )?;
        for (version_id, version, previous) in versions {
            let platforms = platform_stmt
                .query_map([version_id], |row| {
                    Ok(PlatformDetail {
                        platform: row.get(0)?,
                        store_path: row.get(1)?,
                        nar_hash: row.get(2)?,
                        nar_size: row.get::<_, i64>(3)? as u64,
                        closure_size: row.get::<_, i64>(4)? as u64,
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
            "SELECT semver, tag_oid, commit_oid, signer, tagged_at
             FROM releases WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC",
        )?;
        let rows = stmt.query_map([registry_id], |row| {
            Ok(ReleaseRow {
                semver: row.get(0)?,
                tag_oid: row.get(1)?,
                commit_oid: row.get(2)?,
                signer: row.get(3)?,
                tagged_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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
            }],
            channels: vec![ChannelSummary {
                name: "stable".into(),
                frontier: Some("1.0.0".into()),
                partitions: vec![Some("1.0.0".into()); 256],
            }],
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
    }
}
