-- AOS registry hub Worker — D1 read schema (RFC-0004).
--
-- Applied with `wrangler d1 migrations apply aos-registry-hub`. This is the
-- read-relevant subset of the native hub's MIGRATIONS, copied verbatim from
-- `src/sql.rs::SCHEMA` (D1 *is* sqlite, so the native sqlite DDL applies
-- directly). The `sql::tests::migration_file_matches_schema` test asserts this
-- file and the in-crate `SCHEMA` constant stay byte-identical, so the wrangler
-- migration and the optional `/_init` handler can never drift.

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
