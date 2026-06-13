//! Portable SQL for the Worker's D1 backend: schema and read queries.
//!
//! D1 *is* sqlite — the same dialect the native hub treats as its source form
//! ([`aos_registry_hub::db::dialect::Dialect::Sqlite`] is the identity
//! translation). So the read path reuses the native hub's sqlite-flavored SQL
//! verbatim; the only divergence is the driver (async D1 prepared statements
//! instead of sync `rusqlite`). Keeping the strings here, pure and free of any
//! `worker` types, lets the native test suite run them through a real sqlite
//! engine ([`tests`]) — the read schema and queries are validated offline even
//! though the D1 execution path can only run on the Workers runtime.
//!
//! # Schema subset
//!
//! The Worker serves the **read path** (RFC-0004 phase-1 Cloudflare
//! deployment: read index + facade), so [`SCHEMA`] is the read-relevant subset
//! of the native hub's `MIGRATIONS` — the indexer's output tables and the
//! registry-identity rows the indexer reads. The tenancy/IAM, token, session,
//! audit, and config-changeset tables are native-only (the write/console/auth
//! path is not ported) and are intentionally omitted. Every statement here is
//! copied from a native migration so the two schemas cannot drift on the
//! columns the read path touches:
//!
//! ```text
//! registries          — registry identity + pinned trust anchors
//! registry_index       — index freshness/state + surface metadata
//! packages             — package metadata (one row per package)
//! package_versions     — versions of a package
//! version_platforms    — per-platform store paths, sizes, refs, images
//! channels             — channels and their observed frontier
//! channel_partitions   — the 256-bucket → release map per channel
//! releases             — verified signed release tags
//! key_rosters          — the trust roster mirror (public data)
//! caches               — committed [[caches]] entries
//! channel_floors       — per-channel anti-rollback floors (indexer state)
//! ```
//!
//! `channel_floors` is the one *write*-side table the indexer needs on the
//! Worker: it is the native hub's anti-rollback "system of record" for
//! channels (a monotonic floor the frontier may never drop below). The read
//! path never queries it; it exists so the Cron indexer's fail-closed rollback
//! guard ([`crate::indexer`]) matches the native hub.
//!
//! The `INTEGER PRIMARY KEY` rows are sqlite rowid aliases (D1 supports them),
//! and every placeholder is sqlite's numbered `?N` form, which D1 binds
//! positionally from the `bind` slice.

/// The Worker's D1 schema, as one executable batch of `CREATE TABLE`
/// statements.
///
/// Applied by `wrangler d1 migrations apply` (the file in `migrations/`) or by
/// the Worker's init path. This is the read-relevant subset of the native
/// hub's `MIGRATIONS`, copied verbatim so the column shapes match what the
/// indexer writes and the read queries expect.
pub const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS registries (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    source_url  TEXT NOT NULL,
    trust_keys  TEXT NOT NULL DEFAULT '[]',
    require_signatures INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    visibility  TEXT NOT NULL DEFAULT 'public',
    prefix      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS registry_index (
    registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
    state       TEXT NOT NULL,
    error       TEXT,
    last_indexed_commit TEXT,
    name        TEXT,
    description TEXT,
    indexed_at  INTEGER,
    refs_digest TEXT
);
CREATE TABLE IF NOT EXISTS packages (
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
CREATE TABLE IF NOT EXISTS package_versions (
    id          INTEGER PRIMARY KEY,
    package_id  INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version     TEXT NOT NULL,
    previous    TEXT,
    UNIQUE (package_id, version)
);
CREATE TABLE IF NOT EXISTS version_platforms (
    id          INTEGER PRIMARY KEY,
    version_id  INTEGER NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    platform    TEXT NOT NULL,
    store_path  TEXT NOT NULL,
    nar_hash    TEXT NOT NULL,
    nar_size    INTEGER NOT NULL,
    closure_size INTEGER NOT NULL,
    refs        TEXT NOT NULL,
    images      TEXT NOT NULL,
    UNIQUE (version_id, platform)
);
CREATE TABLE IF NOT EXISTS channels (
    id          INTEGER PRIMARY KEY,
    registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    frontier    TEXT,
    UNIQUE (registry_id, name)
);
CREATE TABLE IF NOT EXISTS channel_partitions (
    channel_id  INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    bucket      INTEGER NOT NULL,
    release     TEXT NOT NULL,
    PRIMARY KEY (channel_id, bucket)
);
CREATE TABLE IF NOT EXISTS releases (
    id          INTEGER PRIMARY KEY,
    registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    semver      TEXT NOT NULL,
    tag_oid     TEXT NOT NULL,
    commit_oid  TEXT NOT NULL,
    signer      TEXT,
    tagged_at   INTEGER,
    pack_present INTEGER NOT NULL DEFAULT 0,
    UNIQUE (registry_id, semver)
);
CREATE TABLE IF NOT EXISTS key_rosters (
    registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    status      TEXT NOT NULL,
    PRIMARY KEY (registry_id, key_id)
);
CREATE TABLE IF NOT EXISTS caches (
    registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    priority    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channel_floors (
    registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    channel     TEXT NOT NULL,
    floor       TEXT NOT NULL,
    PRIMARY KEY (registry_id, channel)
);
";

/// Look up one public registry by slug.
///
/// Mirrors the native `registry_by_slug` projection (restricted to the columns
/// the read path needs). The Worker serves public registries anonymously; the
/// caller filters on `visibility = 'public'` so private/internal registries are
/// never exposed without the (native-only) auth path.
pub const REGISTRY_BY_SLUG: &str = "\
SELECT id, slug, source_url, trust_keys, require_signatures, visibility, prefix \
FROM registries WHERE slug = ?1 AND visibility = 'public'";

/// List every public registry, slug-ordered (the hub home page).
pub const LIST_PUBLIC_REGISTRIES: &str = "\
SELECT id, slug, source_url, trust_keys, require_signatures, visibility, prefix \
FROM registries WHERE visibility = 'public' ORDER BY slug";

/// The index freshness row for a registry.
pub const REGISTRY_INDEX: &str = "\
SELECT state, error, last_indexed_commit, name, description, indexed_at \
FROM registry_index WHERE registry_id = ?1";

/// List a registry's packages with their latest version.
///
/// Identical to the native `list_packages` query (RFC-0004 read path); the
/// correlated subquery picks the newest version by descending rowid.
pub const LIST_PACKAGES: &str = "\
SELECT p.name, p.description, p.license, \
       (SELECT v.version FROM package_versions v \
        WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1) AS latest \
FROM packages p WHERE p.registry_id = ?1 ORDER BY p.name";

/// Load one package's header (the native `package_detail` first query).
pub const PACKAGE_HEADER: &str = "\
SELECT id, name, description, homepage, license, maintainer, sysroot \
FROM packages WHERE registry_id = ?1 AND name = ?2";

/// Versions of one package, newest first.
pub const PACKAGE_VERSIONS: &str = "\
SELECT id, version, previous FROM package_versions \
WHERE package_id = ?1 ORDER BY id DESC";

/// Per-platform rows for one package version.
pub const VERSION_PLATFORMS: &str = "\
SELECT platform, store_path, nar_hash, nar_size, closure_size, refs, images \
FROM version_platforms WHERE version_id = ?1 ORDER BY platform";

/// List a registry's channels (the native `list_channels` header query).
pub const LIST_CHANNELS: &str = "\
SELECT id, name, frontier FROM channels WHERE registry_id = ?1 ORDER BY name";

/// The 256-bucket partition map for one channel.
pub const CHANNEL_PARTITIONS: &str = "\
SELECT bucket, release FROM channel_partitions WHERE channel_id = ?1";

/// List a registry's verified releases, newest first (native `list_releases`).
pub const LIST_RELEASES: &str = "\
SELECT semver, tag_oid, commit_oid, signer, tagged_at, pack_present \
FROM releases WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC";

/// The trust roster mirror as `(key_id, public_key, status)` rows.
pub const LIST_ROSTER: &str = "\
SELECT key_id, public_key, status FROM key_rosters \
WHERE registry_id = ?1 ORDER BY status, key_id";

/// Committed `[[caches]]` entries, highest priority first.
pub const LIST_CACHES: &str = "\
SELECT url, priority FROM caches WHERE registry_id = ?1 ORDER BY priority DESC";

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// The schema applies on a real sqlite engine — D1 *is* sqlite, so a clean
    /// `execute_batch` here proves the Worker's DDL is valid D1 DDL.
    #[test]
    fn schema_applies_on_sqlite() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA)
            .expect("worker schema is valid sqlite/D1 DDL");
        // Idempotent: re-applying the `IF NOT EXISTS` batch is a no-op.
        conn.execute_batch(SCHEMA).expect("schema is idempotent");
    }

    /// Every read query prepares against the schema — column names and table
    /// references all resolve, so a binding/column typo is caught offline.
    #[test]
    fn read_queries_prepare_against_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        for sql in [
            REGISTRY_BY_SLUG,
            LIST_PUBLIC_REGISTRIES,
            REGISTRY_INDEX,
            LIST_PACKAGES,
            PACKAGE_HEADER,
            PACKAGE_VERSIONS,
            VERSION_PLATFORMS,
            LIST_CHANNELS,
            CHANNEL_PARTITIONS,
            LIST_RELEASES,
            LIST_ROSTER,
            LIST_CACHES,
        ] {
            conn.prepare(sql)
                .unwrap_or_else(|e| panic!("read query failed to prepare: {e}\n{sql}"));
        }
    }

    /// The read path is end-to-end consistent: seed a registry, a package with
    /// a version + platform, a channel partition, a release, a roster key, and
    /// a cache, then run every read query and confirm it returns the rows.
    #[test]
    fn read_queries_return_seeded_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch(
            "
            INSERT INTO registries (id, slug, source_url, trust_keys, require_signatures, created_at)
                VALUES (1, 'demo', 'https://cdn.example/demo', '[]', 1, 100);
            INSERT INTO registry_index (registry_id, state, last_indexed_commit, name, description, indexed_at)
                VALUES (1, 'fresh', 'abcd', 'Demo', 'A demo registry', 200);
            INSERT INTO packages (id, registry_id, name, description, license, maintainer, sysroot)
                VALUES (1, 1, 'curl', 'A client', 'MIT', 'alice', 0);
            INSERT INTO package_versions (id, package_id, version, previous) VALUES (1, 1, '8.0.0', NULL);
            INSERT INTO version_platforms (id, version_id, platform, store_path, nar_hash, nar_size, closure_size, refs, images)
                VALUES (1, 1, 'x86_64-linux', '/nix/store/x-curl', 'sha256:ab', 100, 200, '[]', '[]');
            INSERT INTO channels (id, registry_id, name, frontier) VALUES (1, 1, 'stable', '8.0.0');
            INSERT INTO channel_partitions (channel_id, bucket, release) VALUES (1, 0, '8.0.0');
            INSERT INTO releases (registry_id, semver, tag_oid, commit_oid, signer, tagged_at, pack_present)
                VALUES (1, '8.0.0', 'tag1', 'commit1', 'alice', 300, 1);
            INSERT INTO key_rosters (registry_id, key_id, public_key, status) VALUES (1, 'k1', 'AAAA', 'active');
            INSERT INTO caches (registry_id, url, priority) VALUES (1, 'https://cdn.example/demo', 100);
            ",
        )
        .unwrap();

        let slug: String = conn
            .query_row(REGISTRY_BY_SLUG, ["demo"], |r| r.get(1))
            .unwrap();
        assert_eq!(slug, "demo");

        let pkg: String = conn.query_row(LIST_PACKAGES, [1i64], |r| r.get(0)).unwrap();
        assert_eq!(pkg, "curl");

        let latest: String = conn.query_row(LIST_PACKAGES, [1i64], |r| r.get(3)).unwrap();
        assert_eq!(latest, "8.0.0");

        let chan: String = conn.query_row(LIST_CHANNELS, [1i64], |r| r.get(1)).unwrap();
        assert_eq!(chan, "stable");

        let semver: String = conn.query_row(LIST_RELEASES, [1i64], |r| r.get(0)).unwrap();
        assert_eq!(semver, "8.0.0");

        let key_id: String = conn.query_row(LIST_ROSTER, [1i64], |r| r.get(0)).unwrap();
        assert_eq!(key_id, "k1");

        let cache_url: String = conn.query_row(LIST_CACHES, [1i64], |r| r.get(0)).unwrap();
        assert_eq!(cache_url, "https://cdn.example/demo");
    }

    /// The wrangler migration file and the in-crate [`SCHEMA`] constant carry
    /// the same DDL, so `wrangler d1 migrations apply` and the `/_init` handler
    /// build an identical schema. Compared after stripping SQL comments and
    /// collapsing whitespace, so cosmetic formatting differences don't matter.
    #[test]
    fn migration_file_matches_schema() {
        let file = include_str!("../migrations/0001_schema.sql");
        assert_eq!(
            normalize_ddl(file),
            normalize_ddl(SCHEMA),
            "migrations/0001_schema.sql drifted from sql::SCHEMA"
        );
    }

    /// Strip `--` comment lines and collapse all runs of whitespace to a single
    /// space, for a formatting-insensitive DDL comparison.
    fn normalize_ddl(sql: &str) -> String {
        let no_comments: String = sql
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");
        no_comments.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The Worker's read/indexer tables expose exactly the column set the
    /// native hub schema gives them, so a future edit to either schema that
    /// changes a shared column is caught offline.
    ///
    /// # Why a pinned contract rather than a direct cross-link
    ///
    /// The native hub's applied schema lives in `aos_registry_hub::db`'s
    /// `MIGRATIONS` constant, which is **private** (not `pub`), so the Worker
    /// cannot reference it even with a native dev-dependency on the hub crate —
    /// and that crate pulls axum/tokio/rusqlite, a heavy tree to add to the
    /// Worker's native test build for one constant. Instead the expected column
    /// set for every shared table is pinned here, transcribed from the native
    /// `MIGRATIONS` (its v1 base plus the `ALTER … ADD COLUMN` migrations that
    /// add `releases.pack_present`, `registry_index.refs_digest`,
    /// `registries.visibility`, and `registries.prefix`). The Worker keeps a
    /// strict *subset* of the native columns (the read path never needs the
    /// tenancy/IAM columns), so each entry below is asserted to be present and
    /// the Worker's tables must not introduce a column the native schema lacks.
    /// If the native schema gains or renames a read-path column, update this
    /// contract in the same change — the test then enforces the two stay
    /// consistent.
    #[test]
    fn read_tables_match_native_column_contract() {
        use std::collections::BTreeSet;

        // (table, the native columns the Worker mirrors). These are transcribed
        // from `aos_registry_hub::db::MIGRATIONS`; see the doc above.
        let expected: &[(&str, &[&str])] = &[
            (
                "registries",
                &[
                    "id",
                    "slug",
                    "source_url",
                    "trust_keys",
                    "require_signatures",
                    "created_at",
                    "visibility",
                    "prefix",
                ],
            ),
            (
                "registry_index",
                &[
                    "registry_id",
                    "state",
                    "error",
                    "last_indexed_commit",
                    "name",
                    "description",
                    "indexed_at",
                    "refs_digest",
                ],
            ),
            (
                "packages",
                &[
                    "id",
                    "registry_id",
                    "name",
                    "description",
                    "homepage",
                    "license",
                    "maintainer",
                    "sysroot",
                ],
            ),
            (
                "package_versions",
                &["id", "package_id", "version", "previous"],
            ),
            (
                "version_platforms",
                &[
                    "id",
                    "version_id",
                    "platform",
                    "store_path",
                    "nar_hash",
                    "nar_size",
                    "closure_size",
                    "refs",
                    "images",
                ],
            ),
            ("channels", &["id", "registry_id", "name", "frontier"]),
            ("channel_partitions", &["channel_id", "bucket", "release"]),
            (
                "releases",
                &[
                    "id",
                    "registry_id",
                    "semver",
                    "tag_oid",
                    "commit_oid",
                    "signer",
                    "tagged_at",
                    "pack_present",
                ],
            ),
            (
                "key_rosters",
                &["registry_id", "key_id", "public_key", "status"],
            ),
            ("caches", &["registry_id", "url", "priority"]),
            ("channel_floors", &["registry_id", "channel", "floor"]),
        ];

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        for (table, native_cols) in expected {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let actual: BTreeSet<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let native: BTreeSet<String> = native_cols.iter().map(|c| (*c).to_string()).collect();
            assert_eq!(
                actual, native,
                "table `{table}` columns drifted from the native hub contract"
            );
        }
    }

    /// Private/internal registries are invisible to the public read path: the
    /// slug lookup filters on `visibility = 'public'`.
    #[test]
    fn private_registries_are_not_publicly_visible() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch(
            "INSERT INTO registries (id, slug, source_url, require_signatures, created_at, visibility)
             VALUES (1, 'secret', 'file:///x', 1, 0, 'private')",
        )
        .unwrap();
        let found: Option<String> = conn
            .query_row(REGISTRY_BY_SLUG, ["secret"], |r| r.get(1))
            .ok();
        assert!(
            found.is_none(),
            "private registry must not resolve publicly"
        );
    }
}
