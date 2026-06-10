//! Read-only access to the Nix store SQLite database.
//!
//! The Nix daemon owns the store database (`var/nix/db/db.sqlite` under the
//! AOS root) and is its only writer. [`NixStore`] opens that database in
//! read-only mode and answers the queries the server needs: full path
//! metadata for narinfo responses ([`NixStore::path_info`]) and validity
//! checks for `query-missing` and build preflight
//! ([`NixStore::is_valid_path`], [`NixStore::is_valid_path_or_hash`]).

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

/// Metadata about a store path from the Nix SQLite DB.
///
/// This is distinct from `aos_core::nix::PathInfo` — it includes
/// `id` (DB primary key) and uses `sigs`/`refs` field names.
#[derive(Debug, Clone)]
pub struct DbPathInfo {
    /// Primary key of the row in the `ValidPaths` table.
    pub id: i64,
    /// Full store path (e.g. `/var/lib/aos/store/{hash}-{name}`).
    pub path: String,
    /// NAR hash of the uncompressed archive, stored as `sha256:{base16}`.
    pub nar_hash: String,
    /// Size of the uncompressed NAR in bytes.
    pub nar_size: i64,
    /// Store path of the deriver (`.drv`), if recorded.
    pub deriver: Option<String>,
    /// Narinfo signatures (`key-name:base64`) attached to this path.
    pub sigs: Vec<String>,
    /// Store paths this path references at runtime.
    pub refs: Vec<String>,
}

impl DbPathInfo {
    /// Converts to the canonical `aos_core::nix::PathInfo` type, dropping
    /// the DB-specific `id`.
    pub fn to_path_info(&self) -> aos_core::nix::PathInfo {
        aos_core::nix::PathInfo {
            path: self.path.clone(),
            nar_hash: self.nar_hash.clone(),
            nar_size: self.nar_size as u64,
            references: self.refs.clone(),
            deriver: self.deriver.clone(),
            signatures: self.sigs.clone(),
        }
    }
}

/// Read-only handle to the Nix store SQLite database.
///
/// The connection is wrapped in a `Mutex` because `rusqlite::Connection` is
/// not `Sync`; queries serialize on that lock.
pub struct NixStore {
    conn: Mutex<Connection>,
}

impl NixStore {
    /// Opens the Nix SQLite DB in read-only mode.
    ///
    /// The writer side (the Nix daemon) creates the database in WAL mode;
    /// this handle merely reads the `journal_mode` pragma and never
    /// attempts to change it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened (e.g. the file
    /// does not exist or is not readable) or the journal-mode pragma query
    /// fails.
    pub fn open(db_path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening Nix DB at {}", db_path.display()))?;

        // The writer side creates the DB in WAL mode. This handle is read-only,
        // so do not try to mutate `journal_mode` here.
        let _journal_mode: String =
            conn.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Looks up a store path by its full path string.
    ///
    /// Returns `Ok(None)` if the path is not registered. On a hit, the
    /// `refs` list is populated with a second query against the `Refs`
    /// table.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection lock is poisoned or either SQL
    /// query fails.
    pub fn path_info(&self, store_path: &str) -> Result<Option<DbPathInfo>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let mut stmt = conn.prepare_cached(
            "SELECT id, path, hash, narSize, deriver, sigs FROM ValidPaths WHERE path = ?1",
        )?;

        let info = stmt
            .query_row(params![store_path], |row| {
                let id: i64 = row.get(0)?;
                let path: String = row.get(1)?;
                let nar_hash: String = row.get(2)?;
                let nar_size: i64 = row.get(3)?;
                let deriver: Option<String> = row.get(4)?;
                let sigs_str: Option<String> = row.get(5)?;

                let sigs = sigs_str
                    .map(|s| s.split(' ').map(String::from).collect())
                    .unwrap_or_default();

                Ok(DbPathInfo {
                    id,
                    path,
                    nar_hash,
                    nar_size,
                    deriver,
                    sigs,
                    refs: Vec::new(), // filled below
                })
            })
            .optional()?;

        let Some(mut info) = info else {
            return Ok(None);
        };

        // Query references.
        let mut refs_stmt = conn.prepare_cached(
            "SELECT v.path FROM Refs r JOIN ValidPaths v ON r.reference = v.id WHERE r.referrer = ?1",
        )?;
        let refs = refs_stmt
            .query_map(params![info.id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        info.refs = refs;

        Ok(Some(info))
    }

    /// Checks if a store path is valid (registered in the database).
    ///
    /// Matches on the exact full path string only; see
    /// [`is_valid_path_or_hash`](Self::is_valid_path_or_hash) for the more
    /// forgiving variant used by cache clients.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection lock is poisoned or the SQL query
    /// fails.
    pub fn is_valid_path(&self, store_path: &str) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        let mut stmt = conn.prepare_cached("SELECT 1 FROM ValidPaths WHERE path = ?1 LIMIT 1")?;
        let exists = stmt
            .query_row(params![store_path], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Checks if a store path or store-path hash is valid locally.
    ///
    /// Cache clients identify paths by the hash prefix in narinfo and mass-query
    /// requests. A client and server may use different store roots, so accepting
    /// only an exact full path would make already-imported paths look missing
    /// whenever the root differs. This first tries an exact path match, then
    /// falls back to matching any registered path whose basename starts with
    /// the same store hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection lock is poisoned or a SQL query
    /// fails.
    pub fn is_valid_path_or_hash(&self, path_or_hash: &str) -> Result<bool> {
        if self.is_valid_path(path_or_hash)? {
            return Ok(true);
        }

        let Some(store_hash) = store_hash_from_path_or_hash(path_or_hash) else {
            return Ok(false);
        };

        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        let pattern = format!("%/{store_hash}-%");
        let mut stmt =
            conn.prepare_cached("SELECT 1 FROM ValidPaths WHERE path LIKE ?1 LIMIT 1")?;
        let exists = stmt
            .query_row(params![pattern], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }
}

/// Extracts the store hash from either a full store path or a bare hash.
///
/// Takes the basename (after the last `/`) and the leading segment before
/// the first `-`, so `/root/store/abc-foo-1.0`, `abc-foo-1.0`, and `abc`
/// all yield `abc`. Returns `None` for empty input.
fn store_hash_from_path_or_hash(path_or_hash: &str) -> Option<&str> {
    let basename = path_or_hash.rsplit('/').next()?;
    let hash = basename.split('-').next().unwrap_or(basename);
    if hash.is_empty() { None } else { Some(hash) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_path_or_hash_accepts_exact_paths_and_hash_identities() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let db_path = temp.path().join("db.sqlite");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "
            CREATE TABLE ValidPaths (
              id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              path TEXT UNIQUE NOT NULL,
              hash TEXT NOT NULL,
              registrationTime INTEGER NOT NULL,
              deriver TEXT,
              narSize INTEGER,
              ultimate INTEGER,
              sigs TEXT,
              ca TEXT
            );
            CREATE TABLE Refs (
              referrer INTEGER NOT NULL,
              reference INTEGER NOT NULL,
              PRIMARY KEY (referrer, reference)
            );
            INSERT INTO ValidPaths
              (path, hash, registrationTime, narSize, ultimate, sigs)
            VALUES
              (
                '/var/lib/aos/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo-1.0',
                'sha256:abc',
                1000000,
                123,
                1,
                ''
              );
            ",
        )?;
        drop(conn);

        let store = NixStore::open(&db_path)?;

        assert!(store.is_valid_path_or_hash(
            "/var/lib/aos/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo-1.0"
        )?);
        assert!(store.is_valid_path_or_hash(
            "/tmp/client-root/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo-1.0"
        )?);
        assert!(store.is_valid_path_or_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?);
        assert!(!store.is_valid_path_or_hash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?);

        Ok(())
    }
}
