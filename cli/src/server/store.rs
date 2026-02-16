use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

/// Metadata about a store path from the Nix SQLite DB.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub id: i64,
    pub path: String,
    pub nar_hash: String,
    pub nar_size: i64,
    pub deriver: Option<String>,
    pub sigs: Vec<String>,
    pub refs: Vec<String>,
}

/// Read-only handle to the Nix store SQLite database.
/// Wrapped in a Mutex because rusqlite::Connection is not Sync.
pub struct NixStore {
    conn: Mutex<Connection>,
}

impl NixStore {
    /// Open the Nix SQLite DB in read-only WAL mode.
    pub fn open(db_path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening Nix DB at {}", db_path.display()))?;

        // Enable WAL mode for concurrent reads.
        conn.pragma_update(None, "journal_mode", "wal")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Look up a store path by its full path string.
    pub fn path_info(&self, store_path: &str) -> Result<Option<PathInfo>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

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

                Ok(PathInfo {
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

    /// Check if a store path is valid (exists in the DB).
    pub fn is_valid_path(&self, store_path: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM ValidPaths WHERE path = ?1 LIMIT 1",
        )?;
        let exists = stmt
            .query_row(params![store_path], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }
}
