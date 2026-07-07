//! In-process Nix store path validity checks backed by a read-only SQLite read.
//!
//! Forcing a `fetchurl`/`fetchTarball` that already resolved to a `/nix/store`
//! path asks the store one question: *is this path valid?* C++ Nix answers it
//! with a single indexed row lookup (`LocalStore::isValidPath`) against its path
//! metadata database. The native evaluator historically answered it by spawning
//! `nix-store --store daemon --check-validity <path>`, and cold evaluation pays
//! that subprocess — dynamic linker load plus a daemon round-trip — once per
//! forced fetch. Profiling attributed the single largest slice of cold-eval wall
//! time to those spawns.
//!
//! [`StoreValidityChecker`] replaces the subprocess with the same read C++ Nix
//! performs: an `SQLITE_OPEN_READ_ONLY` connection to the path database and the
//! query
//!
//! ```sql
//! SELECT 1 FROM ValidPaths WHERE path = ?1 LIMIT 1
//! ```
//!
//! The database lives at `<state>/db/db.sqlite`, where `<state>` is
//! `<store-prefix>/var/nix` and `<store-prefix>` is the parent of the store
//! directory (`/nix/store` -> `/nix` -> `/nix/var/nix/db/db.sqlite`). Results are
//! memoized per run so a repeated question never re-reads the database.
//!
//! # Fallback and correctness
//!
//! The fast path is strictly an optimization. If the database cannot be opened
//! (it is missing, unreadable, or `rusqlite` errors on open) or a query itself
//! errors, the checker falls back to the caller-supplied subprocess probe and
//! never fails evaluation because the read is unavailable. Both the database
//! answer and the fallback answer are memoized.
//!
//! Reading the database directly reproduces exactly the time-of-check/time-of-use
//! race that the subprocess already had: a concurrent `nix-store --gc` may
//! invalidate a path between the check and its use. C++ Nix tolerates this same
//! race, and the evaluator re-validates the NAR digest of any reused path, so a
//! stale "valid" answer is caught downstream rather than trusted blindly.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

/// The `isValidPath` lookup, byte-for-byte C++ Nix's `LocalStore::isValidPath`
/// query so a path deemed valid by the daemon is deemed valid by this read.
const IS_VALID_PATH_QUERY: &str = "SELECT 1 FROM ValidPaths WHERE path = ?1 LIMIT 1";

/// How long a query waits for a writer's lock (a concurrent `nix-store` build or
/// GC) before giving up and letting the caller fall back. Kept short: the read
/// is advisory, so blocking eval on it defeats the purpose.
const BUSY_TIMEOUT: Duration = Duration::from_millis(100);

/// Lazily-opened state of the read-only connection to the Nix path database.
enum DbState {
    /// The database has not been opened yet; the first query attempts to open it.
    Unopened,
    /// The database is open and queryable.
    Ready(Connection),
    /// Opening the database failed once; every query falls back without retrying.
    Unavailable,
}

impl fmt::Debug for DbState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rusqlite::Connection` is not `Debug`; report only the state variant.
        let variant = match self {
            Self::Unopened => "Unopened",
            Self::Ready(_) => "Ready",
            Self::Unavailable => "Unavailable",
        };
        f.debug_tuple("DbState").field(&variant).finish()
    }
}

/// A per-run, in-process checker for Nix store path validity.
///
/// Owns a lazily-opened read-only connection to the store's SQLite path database
/// and a memo of previously answered paths. Construct one with
/// [`StoreValidityChecker::for_store_dir`] and query it with
/// [`StoreValidityChecker::is_valid`].
#[derive(Debug)]
pub(crate) struct StoreValidityChecker {
    /// Path to the store's `db.sqlite`, derived once from the store directory.
    db_path: PathBuf,
    /// Lazily-opened connection state; opened on the first query that needs it.
    state: DbState,
    /// Memo of answered paths, caching both valid (`true`) and invalid (`false`)
    /// results — including results produced by the subprocess fallback.
    memo: HashMap<Vec<u8>, bool>,
}

impl StoreValidityChecker {
    /// Creates a checker for the store rooted at `store_dir`.
    ///
    /// The path database location is computed once from `store_dir` (see the
    /// module documentation); the database itself is not opened until the first
    /// query that consults it.
    pub(crate) fn for_store_dir(store_dir: &[u8]) -> Self {
        Self::with_db_path(Self::db_path_for_store_dir(store_dir))
    }

    /// Creates a checker that reads the path database at `db_path`.
    fn with_db_path(db_path: PathBuf) -> Self {
        Self {
            db_path,
            state: DbState::Unopened,
            memo: HashMap::new(),
        }
    }

    /// Returns whether `store_path` is a valid path in the store.
    ///
    /// Answers from the per-run memo when possible. Otherwise it consults the
    /// read-only path database; if the database is unavailable or the query
    /// errors, it calls `fallback` (the existing subprocess probe) and caches
    /// whatever answer it produces. The result — from either source — is
    /// memoized before returning.
    ///
    /// This carries the same time-of-check/time-of-use race as the subprocess it
    /// replaces: a concurrent garbage collection may invalidate `store_path`
    /// after this returns `true`. Callers re-validate the reused path's NAR
    /// digest, so a stale answer is caught rather than trusted.
    pub(crate) fn is_valid<F>(&mut self, store_path: &[u8], fallback: F) -> bool
    where
        F: FnOnce(&[u8]) -> bool,
    {
        if let Some(&cached) = self.memo.get(store_path) {
            return cached;
        }
        let result = match self.query_db(store_path) {
            Some(valid) => valid,
            None => fallback(store_path),
        };
        self.memo.insert(store_path.to_vec(), result);
        result
    }

    /// Queries the path database for `store_path`.
    ///
    /// Returns `Some(true)`/`Some(false)` when the database produced a definitive
    /// answer, or `None` when the database is unavailable or the query errored —
    /// signalling the caller to fall back to the subprocess probe.
    fn query_db(&mut self, store_path: &[u8]) -> Option<bool> {
        let path = std::str::from_utf8(store_path).ok()?;
        let connection = self.connection()?;
        match connection.query_row(IS_VALID_PATH_QUERY, [path], |_row| Ok(())) {
            Ok(()) => Some(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Some(false),
            Err(_) => None,
        }
    }

    /// Returns the open connection, opening it lazily on first use.
    ///
    /// Returns `None` if the database could not be opened; the failure is latched
    /// so subsequent calls do not retry the open.
    fn connection(&mut self) -> Option<&Connection> {
        if matches!(self.state, DbState::Unopened) {
            self.state = match Self::open(&self.db_path) {
                Some(connection) => DbState::Ready(connection),
                None => DbState::Unavailable,
            };
        }
        match &self.state {
            DbState::Ready(connection) => Some(connection),
            DbState::Unopened | DbState::Unavailable => None,
        }
    }

    /// Opens `db_path` read-only with a short busy timeout, or returns `None` on
    /// any error (missing file, permissions, or a `rusqlite` failure).
    fn open(db_path: &Path) -> Option<Connection> {
        let connection =
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        connection.busy_timeout(BUSY_TIMEOUT).ok()?;
        Some(connection)
    }

    /// Computes the path database location for a store rooted at `store_dir`.
    ///
    /// Mirrors C++ Nix: the state directory is `<prefix>/var/nix`, where
    /// `<prefix>` is the parent of the store directory, and the database is
    /// `<state>/db/db.sqlite`. For the default `/nix/store` this yields
    /// `/nix/var/nix/db/db.sqlite`. A store directory without a parent falls back
    /// to a `/nix` prefix.
    fn db_path_for_store_dir(store_dir: &[u8]) -> PathBuf {
        let store = Path::new(OsStr::from_bytes(store_dir));
        let prefix = store.parent().unwrap_or_else(|| Path::new("/nix"));
        prefix.join("var/nix/db/db.sqlite")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a temporary path database with the minimal `ValidPaths` schema and
    /// the given valid `paths`, returning the connection's file path.
    fn seed_db(paths: &[&str]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aos-nix-store-validity-{}-{}",
            std::process::id(),
            NEXT_DB_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let db_path = dir.join("db.sqlite");
        let connection = Connection::open(&db_path).expect("open writable db");
        connection
            .execute_batch(
                "CREATE TABLE ValidPaths (\
                     id INTEGER PRIMARY KEY AUTOINCREMENT, \
                     path TEXT UNIQUE NOT NULL\
                 );",
            )
            .expect("create ValidPaths");
        for path in paths {
            connection
                .execute("INSERT INTO ValidPaths (path) VALUES (?1)", [path])
                .expect("insert path");
        }
        db_path
    }

    static NEXT_DB_INDEX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fallback that panics if invoked, asserting the database answered.
    fn no_fallback(_path: &[u8]) -> bool {
        panic!("fallback must not run when the database answers");
    }

    #[test]
    fn db_path_is_derived_from_store_prefix() {
        assert_eq!(
            StoreValidityChecker::db_path_for_store_dir(b"/nix/store"),
            PathBuf::from("/nix/var/nix/db/db.sqlite"),
        );
        assert_eq!(
            StoreValidityChecker::db_path_for_store_dir(b"/custom/root/store"),
            PathBuf::from("/custom/root/var/nix/db/db.sqlite"),
        );
    }

    #[test]
    fn reports_valid_and_invalid_paths_from_database() {
        let valid = "/nix/store/00000000000000000000000000000000-valid";
        let missing = "/nix/store/11111111111111111111111111111111-missing";
        let db_path = seed_db(&[valid]);
        let mut checker = StoreValidityChecker::with_db_path(db_path.clone());

        assert!(checker.is_valid(valid.as_bytes(), no_fallback));
        assert!(!checker.is_valid(missing.as_bytes(), no_fallback));

        std::fs::remove_dir_all(db_path.parent().expect("db parent")).expect("cleanup");
    }

    #[test]
    fn memoizes_answers_even_after_the_row_is_deleted() {
        let valid = "/nix/store/22222222222222222222222222222222-cached";
        let db_path = seed_db(&[valid]);
        let mut checker = StoreValidityChecker::with_db_path(db_path.clone());

        // First query reads the database and caches `true`.
        assert!(checker.is_valid(valid.as_bytes(), no_fallback));

        // Delete the row out from under the open read-only connection.
        {
            let writer = Connection::open(&db_path).expect("reopen writable");
            writer
                .execute("DELETE FROM ValidPaths WHERE path = ?1", [valid])
                .expect("delete row");
        }

        // The cached answer is returned without re-reading the database.
        assert!(checker.is_valid(valid.as_bytes(), no_fallback));

        std::fs::remove_dir_all(db_path.parent().expect("db parent")).expect("cleanup");
    }

    #[test]
    fn falls_back_when_database_path_does_not_exist() {
        let db_path = std::env::temp_dir().join(format!(
            "aos-nix-store-validity-absent-{}-{}/db.sqlite",
            std::process::id(),
            NEXT_DB_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        assert!(!db_path.exists());
        let mut checker = StoreValidityChecker::with_db_path(db_path);
        let path = b"/nix/store/33333333333333333333333333333333-fallback";

        let mut fallback_calls = 0usize;
        let valid = checker.is_valid(path, |_p| {
            fallback_calls += 1;
            true
        });
        assert!(valid);
        assert_eq!(fallback_calls, 1, "fallback answers when the db is absent");

        // The fallback's answer is memoized: a second query does not re-run it.
        let valid_again = checker.is_valid(path, no_fallback);
        assert!(valid_again);
    }
}
