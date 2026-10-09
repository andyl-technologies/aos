//! Durable SQLite leaf for immutable, authenticated campaign objects.
//!
//! ```text
//! <root>/objects.sqlite3       WAL database, or private DELETE-journal catalog
//! <root>/objects.sqlite3-wal   Generic leaf transaction log when present
//! <root>/objects.sqlite3-journal Private catalog's quota-contained rollback log
//! <root>/inventory.lock        Interprocess put and inventory fence
//! ```
//!
//! Each successful put or planned delete commits with `synchronous=FULL` before
//! returning. The lock spans administrative inventory and deletion, including
//! the separate commits needed to make each deletion independently durable.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::blob::ZeroBlob;
use rusqlite::{Connection, DatabaseName, OpenFlags, OptionalExtension, params};
use rustix::fs::{FlockOperation, OFlags, flock};

use super::admin::{
    InventoryCounter, PhysicalRepairAuthority, persistent_inventory_generation,
    physical_storage_identity,
};
use super::*;

mod admin_batch;
mod batch;
mod bounded_read;
pub(crate) use bounded_read::SqliteRamReadSession;
mod checked_reader;
mod process_heap;
pub(super) use batch::busy::Accepted;
pub use process_heap::{
    SqliteConnection, SqliteHeapAuthority, SqliteHeapError, SqliteHeapIssuer,
    SqliteProcessBootstrapAuthority, SqliteProcessHeap,
};
mod catalog;
#[cfg(feature = "test-support")]
pub use batch::busy::SqliteScopeFaultObservation;
pub use batch::busy::{SqliteCommitOutcome, SqliteScopeError};
pub use batch::diagnostic::SqliteDiagnosticError;
pub use catalog::{
    SqliteCatalogOperation, SqliteCatalogOperationKind, SqliteCatalogSupervisor,
    minimum_sqlite_catalog_staging_bytes,
};

const DATABASE_FILE: &str = "objects.sqlite3";
const LOCK_FILE: &str = "inventory.lock";
const METADATA_DOMAIN: &[u8] = b"crucible.content-store.sqlite-metadata.v1";
const MAX_CHUNK_BYTES: usize = 64 * 1024;
const MAX_BATCH_OBJECTS: usize = 64;
const MAX_BATCH_BYTES: u64 = 4 * 1024 * 1024;
const READ_STATEMENT_CACHE_CAPACITY: usize = 2;

// Every SQLite leaf contains temporary work in memory, including graph leaves
// wrapped by a physical disk quota. Connection caches never mmap blob files.
fn configure_sqlite_temporary_storage(connection: &Connection) -> Result<(), StoreError> {
    connection
        .execute_batch("PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0;")
        .map_err(|source| database_error("bound-sqlite-temporary-storage", source))?;
    let temp_store: i64 = connection
        .query_row("PRAGMA temp_store", [], |row| row.get(0))
        .map_err(|source| database_error("verify-sqlite-temporary-storage", source))?;
    let mmap_size: i64 = connection
        .query_row("PRAGMA mmap_size", [], |row| row.get(0))
        .map_err(|source| database_error("verify-sqlite-mapping-limit", source))?;
    if temp_store != 2 || mmap_size != 0 {
        return Err(StoreError::InvalidComposition {
            reason: "SQLite temporary work or database mappings escape the allocator entitlement",
        });
    }
    Ok(())
}

/// Paired object and administrative views of one quota-bound SQLite facade.
///
/// The two trait references share the same final `Arc`, retained original
/// resources and physical storage identity.
pub type SqliteBlobAuthorities = (Arc<dyn ImmutableBlobBackend>, Arc<dyn BlobStoreAdmin>);

/// SQLite-backed durable immutable object leaf.
///
/// The constructor initializes one database and an interprocess inventory
/// lock. Clones share the same connection while separate processes coordinate
/// their writes and administrative scans through the lock file. Temporary
/// SQLite work uses memory rather than files outside the store root; database
/// page mappings are disabled. WAL-index mappings remain separately charged
/// file-backed resident memory. Physical disk quotas contain database sidecars;
/// ordinary stores must separately admit their process memory.
#[derive(Clone)]
pub struct SqliteBlobBackend {
    name: String,
    root: PathBuf,
    connection: SqliteConnection,
    read_connection: SqliteConnection,
    catalog_supervisor: Option<Arc<dyn SqliteCatalogSupervisor>>,
    quarantined: Arc<std::sync::atomic::AtomicBool>,
    resident_lease: crate::owned_decode::ResourceLoanSlot,
    maximum_sqlite_heap_bytes: Option<u64>,
}

/// Bounds cached private SQLite backend and quota-facade Rust allocations.
///
/// This excludes SQLite's separately capped allocator, provider cache keys and
/// authority receipts, and independently reserved deferred source/reader loans.
/// Private catalogs disable the Rust prepared-statement cache. An owner reserves
/// its own containers separately before opening the backend.
///
/// # Errors
/// Refuses oversized backend names or overflow in actual retained path storage.
pub fn minimum_sqlite_catalog_resident_bytes(name: &str, root: &Path) -> Result<u64, StoreError> {
    if name.len() > catalog::MAX_BACKEND_NAME_BYTES {
        return Err(StoreError::Quota);
    }
    let fixed = std::mem::size_of::<SqliteBlobBackend>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<(usize, usize, std::sync::atomic::AtomicBool)>()
        + super::physical_quota::facade_metadata_bytes()
        + 2 * catalog::MAX_BACKEND_NAME_BYTES;
    (fixed as u64)
        .checked_add(root.as_os_str().len() as u64)
        .ok_or(StoreError::Quota)
}

impl SqliteBlobBackend {
    /// Opens or creates a durable SQLite object database at `root`.
    ///
    /// # Errors
    ///
    /// Returns an I/O, SQLite, or metadata error if the database cannot be
    /// initialized or its persisted inventory identity is malformed.
    pub fn open(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        heap: &SqliteProcessHeap,
    ) -> Result<Self, StoreError> {
        // Ordinary graphs retain this same finite process heap as well.
        // Checked diagnostics need its actual native message bound; losing
        // that identity here must not turn a capped connection into None.
        Self::open_inner(
            name.into(),
            root.into(),
            Some(heap.maximum_heap_bytes()),
            None,
            heap,
        )
    }

    /// Opens a physically quota-bound catalog with a hard SQLite heap ceiling.
    ///
    /// The guard must be bound before this call and cover `root` and every
    /// database sidecar. All backend operations retain and revalidate it.
    /// SQLite temporary work stays in its capped allocator rather than an
    /// uncharged temporary directory. Every connection borrows the same original
    /// process heap, which must fit this catalog's upper bound. Private
    /// catalogs use verified DELETE journals to avoid WAL-index mappings and
    /// refuse WAL/SHM predecessors before SQLite opens them. Sources are bounded
    /// by 4 MiB and authenticated before a write transaction; staging waits retain
    /// their original supervised scope.
    ///
    /// # Errors
    /// Refuses unavailable quota authority, zero or unrepresentable heap limits,
    /// unavailable SQLite hard-heap enforcement, or database initialization errors.
    pub fn open_with_physical_quota(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        guard: Arc<dyn StorePhysicalQuotaGuard>,
        maximum_sqlite_heap_bytes: u64,
        supervisor: Arc<dyn SqliteCatalogSupervisor>,
        heap: &SqliteProcessHeap,
    ) -> Result<Arc<dyn ImmutableBlobBackend>, StoreError> {
        let (backend, _) = Self::open_with_physical_quota_and_admin(
            name,
            root,
            guard,
            maximum_sqlite_heap_bytes,
            supervisor,
            heap,
        )?;
        Ok(backend)
    }

    /// Opens one quota-bound catalog with paired object and administration views.
    ///
    /// Both views share the same final physical-quota facade, connection and
    /// original resident lease. Dropping either view does not release ownership
    /// while the other remains live.
    ///
    /// # Errors
    /// Refuses the same quota, heap, supervision and initialization failures as
    /// [`Self::open_with_physical_quota`].
    pub fn open_with_physical_quota_and_admin(
        name: impl Into<String>,
        root: impl Into<PathBuf>,
        guard: Arc<dyn StorePhysicalQuotaGuard>,
        maximum_sqlite_heap_bytes: u64,
        supervisor: Arc<dyn SqliteCatalogSupervisor>,
        heap: &SqliteProcessHeap,
    ) -> Result<SqliteBlobAuthorities, StoreError> {
        guard.verify()?;
        let name = name.into();
        if name.len() > catalog::MAX_BACKEND_NAME_BYTES
            || name.capacity() > catalog::MAX_BACKEND_NAME_BYTES
        {
            return Err(StoreError::Quota);
        }
        let operation = supervisor.begin(SqliteCatalogOperationKind::Write)?;
        let _staging = catalog::write_gate(operation.as_ref())?;
        let root = root.into();
        let required = minimum_sqlite_catalog_resident_bytes(&name, &root)?
            .checked_add((root.capacity() - root.as_os_str().len()) as u64)
            .ok_or(StoreError::Quota)?;
        let resident_lease = supervisor.reserve_resident_bytes(required)?;
        let mut backend = Self::open_inner(
            name.clone(),
            root,
            Some(maximum_sqlite_heap_bytes),
            Some(supervisor),
            heap,
        )?;
        backend.resident_lease = resident_lease.into();
        let backend = Arc::new(backend);
        let store =
            super::physical_quota::PhysicalQuotaStore::new(name, backend.clone(), backend, guard)?;
        operation.complete()?;
        let store = Arc::new(store);
        Ok((store.clone(), store))
    }

    fn open_inner(
        name: String,
        root: PathBuf,
        maximum_sqlite_heap_bytes: Option<u64>,
        catalog_supervisor: Option<Arc<dyn SqliteCatalogSupervisor>>,
        heap: &SqliteProcessHeap,
    ) -> Result<Self, StoreError> {
        heap.verify_live()?;
        if let Some(maximum) = maximum_sqlite_heap_bytes {
            let representable = i64::try_from(maximum).ok().filter(|limit| *limit > 0);
            if representable.is_none() || heap.maximum_heap_bytes() > maximum {
                return Err(StoreError::InvalidComposition {
                    reason: "SQLite process heap exceeds this catalog entitlement",
                });
            }
        }
        super::directory::create_dir_all_durable(&root)?;

        let database_path = root.join(DATABASE_FILE);
        if catalog_supervisor.is_some() {
            // WAL predecessors need an offline checkpoint. Opening them here
            // could map an unbounded wal-index before resource admission.
            for sidecar in [
                format!("{DATABASE_FILE}-wal"),
                format!("{DATABASE_FILE}-shm"),
            ] {
                match fs::symlink_metadata(root.join(sidecar)) {
                    Ok(_) => {
                        return Err(StoreError::InvalidComposition {
                            reason: "private SQLite catalogs require offline WAL retirement",
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(StoreError::Io {
                            operation: "inspect-private-sqlite-journal-predecessor",
                            path: root.clone(),
                            source,
                        });
                    }
                }
            }
        }
        for name in [
            DATABASE_FILE.to_owned(),
            format!("{DATABASE_FILE}-wal"),
            format!("{DATABASE_FILE}-shm"),
            format!("{DATABASE_FILE}-journal"),
            LOCK_FILE.to_owned(),
        ] {
            reject_nonregular_existing(&root.join(name))?;
        }
        if catalog_supervisor.is_some() {
            reject_wal_database_header(&database_path)?;
        }
        let managed_connection = heap.open_connection_for(
            &database_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            "open-sqlite-blob-database",
        )?;
        let connection = managed_connection.lock()?;
        configure_sqlite_temporary_storage(&connection)?;
        connection
            .execute_batch("PRAGMA auto_vacuum=FULL;")
            .map_err(|source| database_error("configure-sqlite-auto-vacuum", source))?;
        let auto_vacuum: i64 = connection
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .map_err(|source| database_error("read-sqlite-auto-vacuum-mode", source))?;
        if auto_vacuum != 1 {
            return Err(StoreError::InvalidComposition {
                reason: "SQLite blob database requires FULL auto-vacuum",
            });
        }

        let journal = if catalog_supervisor.is_some() {
            "DELETE"
        } else {
            "WAL"
        };
        let actual_journal: String = connection
            .query_row(&format!("PRAGMA journal_mode={journal}"), [], |row| {
                row.get(0)
            })
            .map_err(|source| database_error("configure-sqlite-journal-mode", source))?;
        if !actual_journal.eq_ignore_ascii_case(journal) {
            return Err(StoreError::InvalidComposition {
                reason: "SQLite journal mode does not match catalog resource ownership",
            });
        }
        connection
            .execute_batch(
                "PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS objects (
                     id TEXT PRIMARY KEY NOT NULL,
                     body BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS metadata (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     instance BLOB NOT NULL,
                     generation INTEGER NOT NULL,
                     checksum BLOB NOT NULL
                 );",
            )
            .map_err(|source| database_error("initialize-sqlite-blob-schema", source))?;

        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(|source| database_error("verify-sqlite-durability-mode", source))?;
        if synchronous != 2 {
            return Err(StoreError::InvalidComposition {
                reason: "SQLite requires FULL synchronization",
            });
        }
        let instance = random_instance()?;
        let checksum = metadata_checksum(instance, 1);
        connection
            .execute(
                "INSERT OR IGNORE INTO metadata (singleton, instance, generation, checksum)
                 VALUES (1, ?1, 1, ?2)",
                params![instance.as_slice(), checksum.as_slice()],
            )
            .map_err(|source| database_error("initialize-sqlite-blob-metadata", source))?;
        load_metadata(&connection)?;

        // SQLite syncs its database and WAL; the containing directory must
        // also persist the initial database and lock names before publication.
        let lock_path = root.join(LOCK_FILE);
        open_inventory_lock(&lock_path, true)?;
        File::open(&root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| StoreError::Io {
                operation: "sync-sqlite-blob-root",
                path: root.clone(),
                source,
            })?;

        // A source handle may be read while the writer holds its connection
        // through a conditional put or fenced repair. WAL readers need a
        // separate connection so that same-store publication cannot deadlock.
        let managed_read_connection = heap.open_connection_for(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            "open-sqlite-blob-reader",
        )?;
        let read_connection = managed_read_connection.lock()?;
        configure_sqlite_temporary_storage(&read_connection)?;
        // Retain only the two read query plans. Every execution still reads
        // current rows and authenticates their bytes; no object data is cached.
        read_connection.set_prepared_statement_cache_capacity(if catalog_supervisor.is_some() {
            0
        } else {
            READ_STATEMENT_CACHE_CAPACITY
        });

        drop(read_connection);
        drop(connection);

        Ok(Self {
            name,
            root,
            connection: managed_connection,
            read_connection: managed_read_connection,
            catalog_supervisor,
            resident_lease: Default::default(),
            maximum_sqlite_heap_bytes,
            quarantined: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Returns the physical SQLite database directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock_connection(&self) -> Result<process_heap::SqliteConnectionGuard<'_>, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let connection = self.connection.lock_for("lock-sqlite-blob-connection")?;
        batch::busy::healthy(&self.quarantined)?;
        Ok(connection)
    }

    fn acquire_inventory_lock(&self) -> Result<File, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let path = self.root.join(LOCK_FILE);
        let file = open_inventory_lock(&path, false)?;
        flock(&file, FlockOperation::LockExclusive).map_err(|source| StoreError::Io {
            operation: "lock-sqlite-inventory",
            path,
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        batch::busy::healthy(&self.quarantined)?;
        Ok(file)
    }

    fn read_handle(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Read))
            .transpose()?;
        let _staging = operation.as_deref().map(catalog::read_gate).transpose()?;
        let connection = self
            .read_connection
            .lock()
            .map_err(|_| StoreError::Poisoned {
                operation: "lock-sqlite-blob-reader",
            })?;
        batch::busy::healthy(&self.quarantined)?;
        let mut statement = connection
            .prepare_cached("SELECT length(body) FROM objects WHERE id = ?1")
            .map_err(|source| database_error("read-sqlite-blob-length", source))?;
        let length: Option<i64> = statement
            .query_row([id.encode()], |row| row.get(0))
            .optional()
            .map_err(|source| database_error("read-sqlite-blob-length", source))?;
        let length = length.ok_or(StoreError::NotFound { id })?;
        let logical_length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
        let range = range.unwrap_or(ByteRange {
            offset: 0,
            length: logical_length,
        });
        validate_range(logical_length, range)?;

        let source_lease = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| {
                supervisor.reserve_resident_bytes(
                    (std::mem::size_of::<SqliteBlobSource>()
                        + 2 * std::mem::size_of::<usize>()
                        + super::physical_quota::deferred_source_metadata_bytes())
                        as u64,
                )
            })
            .transpose()?;
        let source = SqliteBlobSource {
            connection: self.read_connection.clone(),
            id,
            logical_length,
            range,
            catalog_supervisor: self.catalog_supervisor.clone(),
            resident_lease: self.resident_lease.clone(),
            maximum_sqlite_heap_bytes: self.maximum_sqlite_heap_bytes,
            quarantined: self.quarantined.clone(),
            original: crate::owned_decode::DecodeBudgetSlot::default(),
            _source_lease: source_lease.into(),
            _source_credit: None,
        };
        let handle = if range.offset == 0 && range.length == logical_length {
            BlobHandle::authenticated(id, source)
        } else {
            BlobHandle::integrity_checked(id, source)
        };
        if let Some(operation) = operation {
            operation.complete()?;
        }
        batch::busy::healthy(&self.quarantined)?;
        Ok(handle)
    }
}

fn open_inventory_lock(path: &Path, create: bool) -> Result<File, StoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|source| StoreError::Io {
            operation: "open-sqlite-inventory-lock",
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspect-sqlite-inventory-lock",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::InvalidComposition {
            reason: "SQLite inventory lock is not a regular file",
        });
    }
    Ok(file)
}

fn reject_nonregular_existing(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(StoreError::InvalidComposition {
            reason: "SQLite blob root contains a non-regular storage entry",
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StoreError::Io {
            operation: "inspect-sqlite-blob-entry",
            path: path.to_path_buf(),
            source,
        }),
    }
}

// A clean WAL database can retain its journal selection after its sidecars
// disappear. Reject that persisted selection before SQLite can map a new index.
fn reject_wal_database_header(path: &Path) -> Result<(), StoreError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(StoreError::Io {
                operation: "open-private-sqlite-header",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let length = file
        .metadata()
        .map_err(|source| StoreError::Io {
            operation: "inspect-private-sqlite-header",
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if length == 0 {
        return Ok(());
    }
    let mut header = [0_u8; 20];
    file.read_exact(&mut header)
        .map_err(|source| StoreError::Io {
            operation: "read-private-sqlite-header",
            path: path.to_path_buf(),
            source,
        })?;
    if &header[..16] != b"SQLite format 3\0" || header[18] != 1 || header[19] != 1 {
        return Err(StoreError::InvalidComposition {
            reason: "private SQLite catalogs require an authenticated rollback-journal predecessor",
        });
    }
    Ok(())
}

impl ImmutableBlobBackend for SqliteBlobBackend {
    fn read_bounded_with_boundary(
        &self,
        request: &mut crate::ram::BoundedReadRequest<'_, '_>,
    ) -> Result<(), StoreError> {
        request.execute_sqlite(self)
    }

    fn checked_publication_metadata(
        &self,
        _kind: ObjectKind,
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        Ok(CheckedPublicationMetadata {
            maximum_placements: 1,
            maximum_backend_name_bytes: self.name.len(),
        })
    }

    fn put_many_if_absent_with_boundary(
        &self,
        account: &crate::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.put_batch_with_boundary(account, objects, boundary)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: true,
            planned_delete: true,
        }
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        graph_object_count(objects)?;
        Ok(())
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_handle(id, None) {
            Ok(handle) => {
                validate_source(id, &handle)?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read_with_boundary(
        &self,
        account: &crate::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        checked_reader::lookup(self, account, id, range, boundary)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.read_handle(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Write))
            .transpose()?;
        let _staging = operation.as_deref().map(catalog::write_gate).transpose()?;
        let _inventory_lock = self.acquire_inventory_lock()?;
        let logical_length = source.logical_length();
        let blob_length = i32::try_from(logical_length).map_err(|_| StoreError::Quota)?;

        {
            let connection = self.lock_connection()?;
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM objects WHERE id = ?1)",
                    [id.encode()],
                    |row| row.get(0),
                )
                .map_err(|source| database_error("test-sqlite-blob-presence", source))?;
            if exists {
                drop(connection);
                source.verified_as(id)?;
                if !self.contains(id)? {
                    return Err(StoreError::NotFound { id });
                }
                if let Some(operation) = operation {
                    operation.complete()?;
                }
                batch::busy::healthy(&self.quarantined)?;
                return Ok(sqlite_receipt(&self.name, id, logical_length));
            }
        }

        let mut connection = self.lock_connection()?;
        let staged = if operation.is_some() {
            let bytes = source.read_all(MAX_BATCH_BYTES)?;
            validate_bytes(id, &bytes)?;
            operation
                .as_deref()
                .map(|operation| operation.check())
                .transpose()?;
            Some(bytes)
        } else {
            None
        };
        let transaction = connection
            .transaction()
            .map_err(|source| database_error("begin-sqlite-blob-put", source))?;
        transaction
            .execute(
                "INSERT INTO objects (id, body) VALUES (?1, ?2)",
                params![id.encode(), ZeroBlob(blob_length)],
            )
            .map_err(|source| database_error("stage-sqlite-blob", source))?;
        let row_id = transaction.last_insert_rowid();
        {
            let mut blob = transaction
                .blob_open(DatabaseName::Main, "objects", "body", row_id, false)
                .map_err(|source| database_error("open-sqlite-blob-staging", source))?;
            if let Some(bytes) = &staged {
                std::io::Write::write_all(&mut blob, bytes).map_err(|source| StoreError::Io {
                    operation: "write-private-sqlite-staging",
                    path: self.root.clone(),
                    source,
                })?;
            } else {
                copy_source(id, source, &mut blob)?;
            }
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-put", source))?;
        if let Some(operation) = operation {
            operation.complete()?;
        }
        batch::busy::healthy(&self.quarantined)?;
        Ok(sqlite_receipt(&self.name, id, logical_length))
    }

    fn put_many_if_absent(
        &self,
        objects: &[(ContentId, BlobHandle)],
    ) -> Result<Vec<PutReceipt>, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Write))
            .transpose()?;
        let _staging = operation.as_deref().map(catalog::write_gate).transpose()?;
        if objects.len() > MAX_BATCH_OBJECTS {
            return Err(StoreError::Quota);
        }

        // Authentication must finish before taking the connection lock: a
        // source may itself read through this backend's SQLite connection.
        let mut total_bytes = 0_u64;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(objects.len())
            .map_err(|_| StoreError::Quota)?;
        for (id, source) in objects {
            operation
                .as_deref()
                .map(|operation| operation.check())
                .transpose()?;
            let length = source.logical_length();
            total_bytes = total_bytes.checked_add(length).ok_or(StoreError::Quota)?;
            if total_bytes > MAX_BATCH_BYTES {
                return Err(StoreError::Quota);
            }
            let bytes = source
                .read_all(MAX_BATCH_BYTES)
                .map_err(|error| match error {
                    StoreError::InvalidSourceLength { .. } => StoreError::Corrupt { id: *id },
                    other => other,
                })?;
            validate_bytes(*id, &bytes)?;
            staged.push((*id, bytes));
        }

        let _inventory_lock = self.acquire_inventory_lock()?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction()
            .map_err(|source| database_error("begin-sqlite-blob-batch", source))?;
        let mut inserted = false;
        for (id, bytes) in &staged {
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM objects WHERE id = ?1)",
                    [id.encode()],
                    |row| row.get(0),
                )
                .map_err(|source| database_error("test-sqlite-batch-presence", source))?;
            if exists {
                authenticate_stored(&transaction, *id)?;
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO objects (id, body) VALUES (?1, ?2)",
                    params![id.encode(), bytes],
                )
                .map_err(|source| database_error("stage-sqlite-batch-object", source))?;
            inserted = true;
        }
        if inserted {
            advance_metadata(&transaction)?;
        }
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-batch", source))?;

        if let Some(operation) = operation {
            operation.complete()?;
        }
        batch::busy::healthy(&self.quarantined)?;
        Ok(staged
            .into_iter()
            .map(|(id, bytes)| sqlite_receipt(&self.name, id, bytes.len() as u64))
            .collect())
    }
}

impl BlobStoreAdmin for SqliteBlobBackend {
    fn acquire_inventory_fence_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<CheckedInventoryFence<'_>, StoreError> {
        admin_batch::acquire(self, boundary)
    }

    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Write))
            .transpose()?;
        let staging = operation.as_deref().map(catalog::write_gate).transpose()?;
        let lock = self.acquire_inventory_lock()?;
        let connection = self.lock_connection()?;
        let (instance, generation) = load_metadata(&connection)?;
        Ok(Box::new(SqliteInventoryFence {
            backend: self,
            connection,
            _lock: lock,
            instance,
            generation,
            operation,
            _staging: staging,
        }))
    }
}

struct SqliteInventoryFence<'a> {
    backend: &'a SqliteBlobBackend,
    operation: Option<Box<dyn SqliteCatalogOperation>>,
    _staging: Option<catalog::WriteStagingGuard>,
    connection: process_heap::SqliteConnectionGuard<'a>,
    _lock: File,
    instance: [u8; 32],
    generation: u64,
}

impl BlobInventoryFence for SqliteInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        batch::busy::healthy(&self.backend.quarantined)?;
        let generation =
            persistent_inventory_generation(&self.backend.name, self.instance, self.generation)?;
        let mut inventory =
            InventoryCounter::new(physical_storage_identity(self.instance), generation);
        let mut statement = self
            .connection
            .prepare("SELECT id, length(body) FROM objects ORDER BY id")
            .map_err(|source| database_error("prepare-sqlite-blob-inventory", source))?;
        let mut rows = statement
            .query([])
            .map_err(|source| database_error("query-sqlite-blob-inventory", source))?;
        while let Some(row) = rows
            .next()
            .map_err(|source| database_error("visit-sqlite-blob-inventory", source))?
        {
            self.operation
                .as_deref()
                .map(|operation| operation.check())
                .transpose()?;
            let id_text: String = row
                .get(0)
                .map_err(|source| database_error("decode-sqlite-blob-id", source))?;
            let id = ContentId::parse(&id_text)?;
            let length: i64 = row
                .get(1)
                .map_err(|source| database_error("decode-sqlite-blob-length", source))?;
            let logical_length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
            let record = BlobInventoryRecord::new(id, logical_length);
            batch::busy::healthy(&self.backend.quarantined)?;
            visitor(record)?;
            inventory.push(record)?;
        }
        batch::busy::healthy(&self.backend.quarantined)?;
        Ok(inventory.finish(self.backend.name.clone()))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        batch::busy::healthy(&self.backend.quarantined)?;
        self.operation
            .as_deref()
            .map(|operation| operation.check())
            .transpose()?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| database_error("begin-sqlite-blob-delete", source))?;
        let removed = transaction
            .execute("DELETE FROM objects WHERE id = ?1", [id.encode()])
            .map_err(|source| database_error("delete-sqlite-blob-candidate", source))?;
        if removed == 0 {
            drop(transaction);
            if self.backend.catalog_supervisor.is_none() {
                checkpoint_reclaimed_pages(&self.connection)?;
            }
            batch::busy::healthy(&self.backend.quarantined)?;
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-delete", source))?;
        self.generation = self.generation.checked_add(1).ok_or(StoreError::Quota)?;
        if self.backend.catalog_supervisor.is_none() {
            checkpoint_reclaimed_pages(&self.connection)?;
        }
        batch::busy::healthy(&self.backend.quarantined)?;
        Ok(PlannedDeleteDisposition::Deleted)
    }

    fn repair_put_if_absent(
        &mut self,
        _authority: &PhysicalRepairAuthority,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        batch::busy::healthy(&self.backend.quarantined)?;
        self.operation
            .as_deref()
            .map(|operation| operation.check())
            .transpose()?;
        let staged = if self.operation.is_some() {
            let bytes = source.read_all(MAX_BATCH_BYTES)?;
            validate_bytes(id, &bytes)?;
            Some(bytes)
        } else {
            source.verified_as(id)?;
            None
        };
        let logical_length = source.logical_length();
        let blob_length = i32::try_from(logical_length).map_err(|_| StoreError::Quota)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| database_error("begin-sqlite-blob-repair", source))?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM objects WHERE id = ?1)",
                [id.encode()],
                |row| row.get(0),
            )
            .map_err(|source| database_error("test-sqlite-repair-presence", source))?;
        if exists {
            authenticate_stored(&transaction, id)?;
            batch::busy::healthy(&self.backend.quarantined)?;
            return Ok(sqlite_receipt(&self.backend.name, id, logical_length));
        }

        transaction
            .execute(
                "INSERT INTO objects (id, body) VALUES (?1, ?2)",
                params![id.encode(), ZeroBlob(blob_length)],
            )
            .map_err(|source| database_error("stage-sqlite-blob-repair", source))?;
        let row_id = transaction.last_insert_rowid();
        {
            let mut blob = transaction
                .blob_open(DatabaseName::Main, "objects", "body", row_id, false)
                .map_err(|source| database_error("open-sqlite-blob-repair", source))?;
            if let Some(bytes) = &staged {
                std::io::Write::write_all(&mut blob, bytes).map_err(|source| StoreError::Io {
                    operation: "write-private-sqlite-repair",
                    path: self.backend.root.clone(),
                    source,
                })?;
            } else {
                copy_source(id, source, &mut blob)?;
            }
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-repair", source))?;
        self.generation = self.generation.checked_add(1).ok_or(StoreError::Quota)?;
        batch::busy::healthy(&self.backend.quarantined)?;
        Ok(sqlite_receipt(&self.backend.name, id, logical_length))
    }
}

struct SqliteBlobSource {
    connection: SqliteConnection,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
    catalog_supervisor: Option<Arc<dyn SqliteCatalogSupervisor>>,
    quarantined: Arc<std::sync::atomic::AtomicBool>,
    resident_lease: crate::owned_decode::ResourceLoanSlot,
    maximum_sqlite_heap_bytes: Option<u64>,
    original: crate::owned_decode::DecodeBudgetSlot,
    _source_lease: crate::owned_decode::ResourceLoanSlot,
    _source_credit: Option<crate::owned_decode::DecodeScratch>,
}

impl BlobSource for SqliteBlobSource {
    fn checked_read_access(&self) -> super::CheckedReadAccess {
        super::CheckedReadAccess::Owning
    }

    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(self.reader()?))
    }

    fn open_with_boundary(
        &self,
        caller: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<super::CheckedReader, StoreError> {
        checked_reader::open(self, caller, boundary)
    }
}

impl SqliteBlobSource {
    fn reader(&self) -> Result<AuthenticatingSqliteReader, StoreError> {
        batch::busy::healthy(&self.quarantined)?;
        let reader_lease = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| {
                supervisor.reserve_resident_bytes(
                    (std::mem::size_of::<AuthenticatingSqliteReader>()
                        + super::physical_quota::deferred_reader_metadata_bytes())
                        as u64,
                )
            })
            .transpose()?;
        Ok(AuthenticatingSqliteReader {
            connection: self.connection.clone(),
            id: self.id,
            logical_length: self.logical_length,
            range: self.range,
            scan_offset: 0,
            output_offset: 0,
            hasher: content_hasher(
                self.id.kind(),
                self.id.schema_version(),
                self.logical_length,
            ),
            finalized: false,
            catalog_supervisor: self.catalog_supervisor.clone(),
            quarantined: self.quarantined.clone(),
            _catalog_lease: self.resident_lease.clone(),
            _reader_lease: reader_lease.into(),
        })
    }
}

struct AuthenticatingSqliteReader {
    connection: SqliteConnection,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    finalized: bool,
    catalog_supervisor: Option<Arc<dyn SqliteCatalogSupervisor>>,
    quarantined: Arc<std::sync::atomic::AtomicBool>,
    _catalog_lease: crate::owned_decode::ResourceLoanSlot,
    _reader_lease: crate::owned_decode::ResourceLoanSlot,
}

impl AuthenticatingSqliteReader {
    fn read_chunk(&self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let offset = i64::try_from(offset)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(invalid_object_data)?;
        let connection = self.connection.lock().map_err(io::Error::other)?;
        batch::busy::healthy(&self.quarantined).map_err(io::Error::other)?;
        let mut statement = connection
            .prepare_cached("SELECT substr(body, ?2, ?3) FROM objects WHERE id = ?1")
            .map_err(io::Error::other)?;
        let bytes: Option<Vec<u8>> = statement
            .query_row(params![self.id.encode(), offset, length as i64], |row| {
                row.get(0)
            })
            .optional()
            .map_err(io::Error::other)?;
        let bytes = bytes.ok_or_else(invalid_object_data)?;
        if bytes.len() != length {
            return Err(invalid_object_data());
        }
        Ok(bytes)
    }

    fn scan_until(
        &mut self,
        target: u64,
        operation: Option<&dyn SqliteCatalogOperation>,
    ) -> io::Result<()> {
        while self.scan_offset < target {
            if let Some(operation) = operation {
                operation.check().map_err(io::Error::other)?;
            }
            let length = usize::try_from((target - self.scan_offset).min(MAX_CHUNK_BYTES as u64))
                .map_err(|_| invalid_object_data())?;
            let bytes = self.read_chunk(self.scan_offset, length)?;
            self.hasher.update(&bytes);
            self.scan_offset += length as u64;
        }
        Ok(())
    }
}

impl Read for AuthenticatingSqliteReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        batch::busy::healthy(&self.quarantined).map_err(io::Error::other)?;
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Read))
            .transpose()
            .map_err(io::Error::other)?;
        let _staging = operation
            .as_deref()
            .map(catalog::read_gate)
            .transpose()
            .map_err(io::Error::other)?;
        let result = self.read_authenticated(output, operation.as_deref());
        if result.is_ok()
            && let Some(operation) = operation
        {
            operation.complete().map_err(io::Error::other)?;
        }
        batch::busy::healthy(&self.quarantined).map_err(io::Error::other)?;
        result
    }
}

impl AuthenticatingSqliteReader {
    fn read_authenticated(
        &mut self,
        output: &mut [u8],
        operation: Option<&dyn SqliteCatalogOperation>,
    ) -> io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset, operation)?;
        if self.output_offset < self.range.length {
            let length = usize::try_from(
                (self.range.length - self.output_offset)
                    .min(output.len() as u64)
                    .min(MAX_CHUNK_BYTES as u64),
            )
            .map_err(|_| invalid_object_data())?;
            let bytes = self.read_chunk(self.scan_offset, length)?;
            output[..length].copy_from_slice(&bytes);
            self.hasher.update(&bytes);
            self.scan_offset += length as u64;
            self.output_offset += length as u64;
            return Ok(length);
        }

        self.scan_until(self.logical_length, operation)?;
        if *self.hasher.finalize().as_bytes() != self.id.digest() {
            return Err(invalid_object_data());
        }
        self.finalized = true;
        Ok(0)
    }
}

fn authenticate_stored(connection: &Connection, id: ContentId) -> Result<(), StoreError> {
    authenticate_stored_with_boundary(connection, id, &mut || Ok(()), None, None)
}

fn authenticate_stored_with_boundary(
    connection: &Connection,
    id: ContentId,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    account: Option<&crate::owned_decode::DecodeBudget>,
    quarantined: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(), StoreError> {
    if account.is_some() != quarantined.is_some() {
        return Err(StoreError::InvalidComposition {
            reason: "checked SQLite authentication requires its original quarantine marker",
        });
    }
    boundary()?;
    let length: Option<i64> =
        query_stored_with_boundary(connection, quarantined, boundary, || {
            with_stored_id_text(id, account.is_some(), |encoded| {
                connection
                    .query_row(
                        "SELECT length(body) FROM objects WHERE id = ?1",
                        [encoded],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|source| database_error("read-sqlite-repair-length", source))
            })
        })?;
    let length = length.ok_or(StoreError::NotFound { id })?;
    let logical_length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
    let mut hasher = content_hasher(id.kind(), id.schema_version(), logical_length);
    let mut offset = 0_u64;
    while offset < logical_length {
        boundary()?;
        let chunk_length = usize::try_from((logical_length - offset).min(MAX_CHUNK_BYTES as u64))
            .map_err(|_| StoreError::Quota)?;
        let _credit = account
            .map(|account| {
                account
                    .reserve_scratch_array::<u8>(chunk_length)
                    .map_err(|error| super::batch::admission_under(account, error))
            })
            .transpose()?;
        let sqlite_offset = i64::try_from(offset + 1).map_err(|_| StoreError::Quota)?;
        let chunk: Vec<u8> = query_stored_with_boundary(connection, quarantined, boundary, || {
            with_stored_id_text(id, account.is_some(), |encoded| {
                connection
                    .query_row(
                        "SELECT substr(body, ?2, ?3) FROM objects WHERE id = ?1",
                        params![encoded, sqlite_offset, chunk_length as i64],
                        |row| row.get(0),
                    )
                    .map_err(|source| database_error("read-sqlite-repair-body", source))
            })
        })?;
        boundary()?;
        if chunk.len() != chunk_length {
            return Err(StoreError::Corrupt { id });
        }
        hasher.update(&chunk);
        offset += chunk_length as u64;
    }
    if *hasher.finalize().as_bytes() != id.digest() {
        return Err(StoreError::Corrupt { id });
    }
    boundary()?;
    Ok(())
}

// Only actual SQL-step errors reach retry. Original callback failures cannot
// be mistaken for BUSY or cause an already completed mutation to run again.
fn query_stored_with_boundary<T>(
    connection: &Connection,
    quarantined: Option<&std::sync::atomic::AtomicBool>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    mut query: impl FnMut() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    match quarantined {
        Some(marker) => batch::busy::retry(connection, true, marker, boundary, |_| query()),
        None => query(),
    }
}

fn with_stored_id_text<T>(
    id: ContentId,
    checked: bool,
    consume: impl FnOnce(&str) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    if checked {
        super::batch::with_id_text(id, consume)
    } else {
        consume(&id.encode())
    }
}

fn load_metadata(connection: &Connection) -> Result<([u8; 32], u64), StoreError> {
    let (instance, generation, checksum): (Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            "SELECT instance, generation, checksum FROM metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|source| database_error("read-sqlite-blob-metadata", source))?;
    let instance: [u8; 32] = instance.try_into().map_err(|_| invalid_metadata())?;
    let generation = u64::try_from(generation).map_err(|_| invalid_metadata())?;
    if generation == 0 || checksum != metadata_checksum(instance, generation) {
        return Err(invalid_metadata());
    }
    Ok((instance, generation))
}

fn advance_metadata(connection: &Connection) -> Result<(), StoreError> {
    let (instance, generation) = load_metadata(connection)?;
    let next = generation.checked_add(1).ok_or(StoreError::Quota)?;
    let next_sql = i64::try_from(next).map_err(|_| StoreError::Quota)?;
    let checksum = metadata_checksum(instance, next);
    connection
        .execute(
            "UPDATE metadata SET generation = ?1, checksum = ?2 WHERE singleton = 1",
            params![next_sql, checksum.as_slice()],
        )
        .map_err(|source| database_error("advance-sqlite-blob-generation", source))?;
    Ok(())
}

fn checkpoint_reclaimed_pages(connection: &Connection) -> Result<(), StoreError> {
    // A long-running WAL connection otherwise retains deleted bytes until a
    // later checkpoint. Retry of an already absent candidate can finish a
    // checkpoint that was busy after the durable delete committed.
    let blocked: i64 = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(|source| database_error("checkpoint-sqlite-blob-delete", source))?;
    if blocked != 0 {
        return Err(StoreError::StreamIo {
            operation: "checkpoint-sqlite-blob-delete",
            source: io::Error::new(io::ErrorKind::WouldBlock, "SQLite checkpoint is busy"),
        });
    }
    Ok(())
}

fn metadata_checksum(instance: [u8; 32], generation: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(METADATA_DOMAIN);
    hasher.update(&instance);
    hasher.update(&generation.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn random_instance() -> Result<[u8; 32], StoreError> {
    let path = PathBuf::from("/dev/urandom");
    let mut random = [0_u8; 32];
    File::open(&path)
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|source| StoreError::Io {
            operation: "read-sqlite-blob-instance-randomness",
            path,
            source,
        })?;
    Ok(random)
}

fn sqlite_receipt(name: &str, id: ContentId, logical_length: u64) -> PutReceipt {
    PutReceipt::one(
        id,
        PlacementReceipt {
            backend: name.to_owned(),
            durable: true,
            logical_length,
        },
    )
}

fn database_error(operation: &'static str, source: rusqlite::Error) -> StoreError {
    StoreError::StreamIo {
        operation,
        source: io::Error::other(source),
    }
}

fn invalid_metadata() -> StoreError {
    StoreError::InvalidComposition {
        reason: "SQLite blob inventory metadata is malformed",
    }
}

fn invalid_object_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "SQLite blob bytes failed authentication",
    )
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::content_store::fixture_sqlite_connection;

    struct TestCatalogSupervisor;
    struct TestCatalogOperation;

    impl SqliteCatalogSupervisor for TestCatalogSupervisor {
        fn reserve_resident_bytes(
            &self,
            _bytes: u64,
        ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
            Ok(crate::owned_decode::ResourceLoan::new(()))
        }

        fn begin(
            &self,
            _kind: SqliteCatalogOperationKind,
        ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
            Ok(Box::new(TestCatalogOperation))
        }
    }

    impl SqliteCatalogOperation for TestCatalogOperation {
        fn check(&self) -> Result<(), StoreError> {
            Ok(())
        }
        fn complete(self: Box<Self>) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct TestQuotaGuard {
        refused: std::sync::atomic::AtomicBool,
        resources: crate::content_store::test_resources::FixtureResourceBudget,
    }

    impl Default for TestQuotaGuard {
        fn default() -> Self {
            Self {
                refused: std::sync::atomic::AtomicBool::new(false),
                resources: crate::content_store::test_resources::FixtureResourceBudget::new(
                    128,
                    256 * 1024 * 1024,
                ),
            }
        }
    }

    impl StorePhysicalQuotaGuard for TestQuotaGuard {
        fn reserve_resources(
            &self,
            descriptors: u64,
            resident_bytes: u64,
        ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
            self.verify()?;
            self.resources.reserve(descriptors, resident_bytes)
        }

        fn verify(&self) -> Result<(), StoreError> {
            if self.refused.load(std::sync::atomic::Ordering::SeqCst) {
                Err(StoreError::Quota)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn physical_quota_covers_initialization_and_deferred_handles() {
        if std::env::var_os("CRUCIBLE_SQLITE_QUOTA_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", "content_store::sqlite::tests::physical_quota_covers_initialization_and_deferred_handles", "--nocapture"])
                .env("CRUCIBLE_SQLITE_QUOTA_CHILD", "1")
                .status()
                .expect("isolated quota test");
            assert!(status.success());
            return;
        }
        let root = tempfile::tempdir().expect("quota test root");
        let unopened = root.path().join("refused");
        let guard = Arc::new(TestQuotaGuard::default());
        guard
            .refused
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            SqliteBlobBackend::open_with_physical_quota(
                "refused",
                &unopened,
                guard.clone(),
                128 << 20,
                Arc::new(TestCatalogSupervisor),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            ),
            Err(StoreError::Quota)
        ));
        assert!(!unopened.exists());

        guard
            .refused
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let backend = SqliteBlobBackend::open_with_physical_quota(
            "guarded",
            root.path(),
            guard.clone(),
            128 << 20,
            Arc::new(TestCatalogSupervisor),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("quota-bound catalog");
        assert!(!root.path().join("objects.sqlite3-wal").exists());
        assert!(!root.path().join("objects.sqlite3-shm").exists());
        let bytes = b"retained authenticated bytes";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("put");
        let handle = backend.read(id, None).expect("retained handle");
        let mut reader = handle.open().expect("retained reader");
        drop(backend);
        guard
            .refused
            .store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(matches!(handle.open(), Err(StoreError::Quota)));
        assert!(reader.read(&mut [0; 8]).is_err());
    }

    #[test]
    fn private_catalog_refuses_clean_wal_header_before_sqlite_opens() {
        let root = tempfile::tempdir().expect("clean WAL predecessor root");
        let generic = SqliteBlobBackend::open(
            "generic",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("generic WAL leaf");
        drop(generic);
        let database = root.path().join(DATABASE_FILE);
        let before = fs::read(&database).expect("persisted WAL database");
        assert_eq!(&before[18..20], &[2, 2]);
        assert!(!root.path().join("objects.sqlite3-wal").exists());
        assert!(!root.path().join("objects.sqlite3-shm").exists());

        let result = SqliteBlobBackend::open_with_physical_quota(
            "private",
            root.path(),
            Arc::new(TestQuotaGuard::default()),
            i64::MAX as u64,
            Arc::new(TestCatalogSupervisor),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        );

        assert!(matches!(result, Err(StoreError::InvalidComposition { .. })));
        assert_eq!(
            fs::read(&database).expect("unchanged WAL predecessor"),
            before
        );
        assert!(!root.path().join("objects.sqlite3-wal").exists());
        assert!(!root.path().join("objects.sqlite3-shm").exists());
    }

    #[test]
    fn private_delete_catalog_rekeys_large_sources_before_transaction() {
        if std::env::var_os("CRUCIBLE_SQLITE_DELETE_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", "content_store::sqlite::tests::private_delete_catalog_rekeys_large_sources_before_transaction", "--nocapture"])
                .env("CRUCIBLE_SQLITE_DELETE_CHILD", "1").status().expect("isolated DELETE test");
            assert!(status.success());
            return;
        }
        let root = tempfile::tempdir().expect("private catalog root");
        let backend = SqliteBlobBackend::open_inner(
            "private".into(),
            root.path().into(),
            Some(128 << 20),
            Some(Arc::new(TestCatalogSupervisor)),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("private DELETE catalog");
        backend
            .lock_connection()
            .expect("writer")
            .pragma_update(None, "cache_size", -64)
            .expect("force cache spill");
        let bytes = vec![0x5b; 3 << 20];
        let original = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
        let republished = ContentId::for_bytes(ObjectKind::CampaignFact, 2, &bytes);
        let repaired = ContentId::for_bytes(ObjectKind::CampaignFact, 3, &bytes);
        backend
            .put_if_absent(original, &BlobHandle::from_bytes(bytes.clone()))
            .expect("seed object");
        let source = backend.read(original, None).expect("same-backend source");
        backend
            .put_if_absent(republished, &source)
            .expect("rekey above cache threshold");
        let mut fence = backend.acquire_inventory_fence().expect("repair fence");
        fence
            .repair_put_if_absent(&PhysicalRepairAuthority::new(), repaired, &source)
            .expect("repair above cache threshold");
        drop(fence);
        for id in [original, republished, repaired] {
            assert_eq!(
                backend
                    .read(id, None)
                    .expect("handle")
                    .read_all(4 << 20)
                    .expect("authenticate"),
                bytes
            );
        }
        let mode: String = backend
            .lock_connection()
            .expect("writer")
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        assert_eq!(mode, "delete");
        assert!(!root.path().join("objects.sqlite3-wal").exists());
        assert!(!root.path().join("objects.sqlite3-shm").exists());
        let legacy = root.path().join("legacy");
        std::fs::create_dir(&legacy).expect("legacy directory");
        std::fs::write(legacy.join("objects.sqlite3-wal"), b"predecessor").expect("legacy WAL");
        assert!(matches!(
            SqliteBlobBackend::open_inner(
                "refused".into(),
                legacy.clone(),
                Some(128 << 20),
                Some(Arc::new(TestCatalogSupervisor)),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            ),
            Err(StoreError::InvalidComposition { .. })
        ));
        assert!(!legacy.join("objects.sqlite3").exists());
    }

    #[test]
    fn bounded_sqlite_allocator_exhaustion_isolated_subprocess() {
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "content_store::sqlite::tests::bounded_sqlite_allocator_child",
                "--nocapture",
            ])
            .env("CRUCIBLE_SQLITE_HEAP_CHILD", "1")
            .status()
            .expect("isolated allocator test");
        assert!(status.success());
    }

    #[test]
    fn bounded_sqlite_allocator_child() {
        if std::env::var_os("CRUCIBLE_SQLITE_HEAP_CHILD").is_none() {
            return;
        }
        let root = tempfile::tempdir().expect("isolated SQLite root");
        let backend = SqliteBlobBackend::open_inner(
            "bounded-memory".into(),
            root.path().into(),
            Some(8 << 20),
            Some(Arc::new(TestCatalogSupervisor)),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("bounded catalog");
        let connection = backend.lock_connection().expect("writer");
        let error = connection
            .query_row("SELECT length(randomblob(32 * 1024 * 1024))", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect_err("real SQLite allocation must fail at the hard heap limit");
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::OutOfMemory)
        );
        let limit: i64 = connection
            .query_row("PRAGMA hard_heap_limit", [], |row| row.get(0))
            .expect("heap limit");
        assert!(limit > 0 && limit <= 8 << 20);
    }

    fn sqlite_file_census(root: &Path) -> (u64, u64) {
        let mut allocated_blocks = 0;
        let mut conservative_bytes = 0;
        for entry in std::fs::read_dir(root).expect("read SQLite root") {
            let entry = entry.expect("SQLite root entry");
            File::open(entry.path())
                .expect("open SQLite file")
                .sync_all()
                .expect("sync SQLite file before census");
            let metadata = entry.metadata().expect("SQLite file metadata");
            let blocks = metadata.blocks() * 512;
            allocated_blocks += blocks;
            conservative_bytes += blocks.max(metadata.len());
        }
        File::open(root)
            .expect("open SQLite root")
            .sync_all()
            .expect("sync SQLite root before census");
        (allocated_blocks, conservative_bytes)
    }

    #[test]
    fn durable_put_reopens_with_authenticated_range_and_stable_inventory() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"authenticated SQLite campaign object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        assert!(backend.capabilities().repair_inventory);
        assert!(backend.capabilities().planned_delete);

        let receipt = backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("durable put");
        assert!(receipt.is_durable());
        let mut fence = backend.acquire_inventory_fence().expect("inventory fence");
        let before = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("complete inventory");
        assert_eq!(before.objects(), 1);
        drop(fence);
        drop(backend);

        let reopened = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen");
        assert_eq!(
            reopened
                .read(id, None)
                .expect("whole-object handle")
                .read_all(1024)
                .expect("authenticated whole object"),
            bytes
        );
        assert_eq!(
            reopened
                .read(
                    id,
                    Some(ByteRange {
                        offset: 14,
                        length: 6,
                    }),
                )
                .expect("range handle")
                .read_all(6)
                .expect("authenticated range"),
            &bytes[14..20]
        );
        let mut fence = reopened
            .acquire_inventory_fence()
            .expect("cold inventory fence");
        let after = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("cold complete inventory");
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.storage_identity(), before.storage_identity());
        drop(fence);

        let other_schema = ContentId::parse(&format!(
            "{}.{}.{}",
            id.kind().as_str(),
            id.schema_version() + 1,
            id.encode().rsplit('.').next().expect("digest field"),
        ))
        .expect("same digest with different schema");
        assert!(!reopened.contains(other_schema).expect("distinct ID absent"));
    }

    #[test]
    fn same_backend_source_can_publish_another_schema_and_fenced_repair() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"same bytes, distinct authenticated schemas";
        let original = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let republished = ContentId::for_bytes(ObjectKind::CampaignFact, 2, bytes);
        let repaired = ContentId::for_bytes(ObjectKind::CampaignFact, 3, bytes);
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        backend
            .put_if_absent(original, &BlobHandle::from_bytes(bytes))
            .expect("publish source object");

        let source = backend.read(original, None).expect("same-backend source");
        backend
            .put_if_absent(republished, &source)
            .expect("re-key same-backend source");
        let mut fence = backend.acquire_inventory_fence().expect("repair fence");
        fence
            .repair_put_if_absent(&PhysicalRepairAuthority::new(), repaired, &source)
            .expect("repair from same-backend source");
        drop(fence);

        for id in [original, republished, repaired] {
            assert_eq!(
                backend
                    .read(id, None)
                    .expect("published object handle")
                    .read_all(1024)
                    .expect("authenticated bytes"),
                bytes
            );
        }
    }

    #[test]
    fn batch_rekeys_same_backend_source_and_reopens_atomically() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let first_bytes = b"first committed source";
        let first = ContentId::for_bytes(ObjectKind::CampaignFact, 1, first_bytes);
        backend
            .put_if_absent(first, &BlobHandle::from_bytes(first_bytes))
            .expect("publish source");

        let rekeyed = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
        let second_bytes = b"second batch object";
        let second = ContentId::for_bytes(ObjectKind::CampaignFact, 1, second_bytes);
        let objects = [
            (
                rekeyed,
                backend.read(first, None).expect("same-backend source"),
            ),
            (second, BlobHandle::from_bytes(second_bytes)),
        ];
        let receipts = backend
            .put_many_if_absent(&objects)
            .expect("durable batch publication");
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(PutReceipt::is_durable));
        assert_eq!(receipts[0].id, rekeyed);
        assert_eq!(receipts[1].id, second);

        let invalid = ContentId::for_bytes(ObjectKind::Trace, 1, b"different bytes");
        let rejected = [
            (
                ContentId::for_bytes(ObjectKind::Trace, 1, b"would be orphaned"),
                BlobHandle::from_bytes(b"would be orphaned"),
            ),
            (invalid, BlobHandle::from_bytes(b"wrong bytes")),
        ];
        assert!(matches!(
            backend.put_many_if_absent(&rejected),
            Err(StoreError::Corrupt { id }) if id == invalid
        ));
        assert!(!backend.contains(rejected[0].0).expect("no partial batch"));
        drop(backend);

        let reopened = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen");
        for (id, expected) in [
            (rekeyed, first_bytes.as_slice()),
            (second, second_bytes.as_slice()),
        ] {
            assert_eq!(
                reopened
                    .read(id, None)
                    .expect("reopened batch object")
                    .read_all(1024)
                    .expect("authenticated body"),
                expected
            );
        }
    }

    #[test]
    fn graph_forwards_admitted_batch_as_one_durable_mutation() {
        let root = tempfile::tempdir().expect("temporary graph root");
        let leaf = StoreNodeId::new("sqlite-batch-leaf").expect("leaf ID");
        let database_root = root.path().join("blobs");
        let (graph, _) = StoreGraph::build_with_admin_and_original_resources(
            StoreGraphConfig {
                gc_mark_root: None,
                root: leaf.clone(),
                admitted_kinds: BTreeSet::from([ObjectKind::CampaignFact]),
                nodes: BTreeMap::from([(
                    leaf,
                    StoreNodeSpec::Sqlite {
                        root: database_root.clone(),
                    },
                )]),
            },
            crate::content_store::StoreGraphOriginalResources {
                memory_namespaces: None,
                sqlite_heap: Some(
                    &crate::content_store::fixture_sqlite_heap()
                        .expect("authored SQLite fixture process"),
                ),
            },
        )
        .expect("build SQLite graph");
        let first_bytes = b"first graph object";
        let second_bytes = b"second graph object";
        let first = ContentId::for_bytes(ObjectKind::CampaignFact, 1, first_bytes);
        let second = ContentId::for_bytes(ObjectKind::CampaignFact, 1, second_bytes);
        let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, b"rejected kind");
        let objects = [
            (first, BlobHandle::from_bytes(first_bytes)),
            (second, BlobHandle::from_bytes(second_bytes)),
        ];

        assert!(
            graph
                .put_many_if_absent(&[
                    objects[0].clone(),
                    (rejected, BlobHandle::from_bytes(b"rejected kind")),
                ])
                .is_err()
        );
        assert!(
            !graph
                .contains(first)
                .expect("rejected batch left no object")
        );

        let before = {
            let connection = fixture_sqlite_connection(database_root.join(DATABASE_FILE))
                .expect("inspect database generation");
            load_metadata(&connection.lock().expect("managed metadata connection"))
                .expect("valid metadata")
                .1
        };
        let receipts = graph
            .put_many_if_absent(&objects)
            .expect("publish graph batch");
        assert_eq!(receipts.len(), objects.len());
        assert!(receipts.iter().all(PutReceipt::is_durable));
        let after = {
            let connection = fixture_sqlite_connection(database_root.join(DATABASE_FILE))
                .expect("inspect committed generation");
            load_metadata(&connection.lock().expect("managed metadata connection"))
                .expect("valid committed metadata")
                .1
        };
        assert_eq!(after, before + 1);

        drop(graph);
        let reopened = SqliteBlobBackend::open(
            "sqlite-batch-leaf",
            &database_root,
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen batch");
        for (id, expected) in [
            (first, first_bytes.as_slice()),
            (second, second_bytes.as_slice()),
        ] {
            assert_eq!(
                reopened
                    .read(id, None)
                    .expect("batch object")
                    .read_all(1024)
                    .expect("authenticated batch object"),
                expected
            );
        }
    }

    #[test]
    fn duplicate_id_within_one_batch_has_one_durable_placement() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let bytes = b"one object listed twice";
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        let source = BlobHandle::from_bytes(bytes);
        let objects = [(id, source.clone()), (id, source)];

        let receipts = backend
            .put_many_if_absent(&objects)
            .expect("publish duplicate ID batch");
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(PutReceipt::is_durable));
        let mut fence = backend.acquire_inventory_fence().expect("inventory fence");
        assert_eq!(
            fence
                .visit_inventory(&mut |_| Ok(()))
                .expect("inventory after batch")
                .objects(),
            1
        );
    }

    #[test]
    fn failed_batch_commit_rolls_back_every_staged_object() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let fault =
            fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("open fault writer");
        fault
            .execute_batch(
                "CREATE TABLE required_parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE deferred_child (
                     parent INTEGER REFERENCES required_parent(id)
                         DEFERRABLE INITIALLY DEFERRED
                 );
                 CREATE TRIGGER fail_object_commit AFTER INSERT ON objects BEGIN
                     INSERT INTO deferred_child(parent) VALUES (1);
                 END;",
            )
            .expect("install deferred commit failure");
        drop(fault);

        let objects = (0..MAX_BATCH_OBJECTS)
            .map(|index| {
                let bytes = format!("staged object {index}").into_bytes();
                (
                    ContentId::for_bytes(ObjectKind::Trace, 1, &bytes),
                    BlobHandle::from_bytes(bytes),
                )
            })
            .collect::<Vec<_>>();
        assert!(backend.put_many_if_absent(&objects).is_err());
        assert!(
            backend
                .lock_connection()
                .expect("writer lock")
                .is_autocommit()
        );
        for (id, _) in &objects {
            assert!(!backend.contains(*id).expect("failed commit is invisible"));
        }
        drop(backend);

        let reopened = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen");
        for (id, _) in &objects {
            assert!(!reopened.contains(*id).expect("failed commit stayed absent"));
        }
    }

    #[test]
    fn concurrent_reader_sees_entire_batch_or_none() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let reader = crate::content_store::fixture_sqlite_heap()
            .expect("authored SQLite fixture process")
            .open_connection(
                root.path().join(DATABASE_FILE),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("open independent reader");
        let objects = (0..MAX_BATCH_OBJECTS)
            .map(|index| {
                let bytes = vec![index as u8; MAX_CHUNK_BYTES];
                let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
                (id, BlobHandle::from_bytes(bytes))
            })
            .collect::<Vec<_>>();
        let ready = Arc::new(Barrier::new(2));
        let writer_ready = ready.clone();
        let writer_backend = backend.clone();
        let writer = std::thread::spawn(move || {
            writer_ready.wait();
            writer_backend.put_many_if_absent(&objects)
        });

        let count = || -> i64 {
            reader
                .query_row("SELECT count(*) FROM objects", [], |row| row.get(0))
                .expect("read committed object count")
        };
        assert_eq!(count(), 0);
        ready.wait();
        while !writer.is_finished() {
            let observed = count();
            assert!(observed == 0 || observed == MAX_BATCH_OBJECTS as i64);
            std::thread::yield_now();
        }
        let receipts = writer
            .join()
            .expect("writer thread")
            .expect("durable batch");
        assert_eq!(receipts.len(), MAX_BATCH_OBJECTS);
        assert_eq!(count(), MAX_BATCH_OBJECTS as i64);
    }

    #[test]
    fn batch_rolls_back_new_objects_when_an_existing_id_is_corrupt() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let existing_bytes = b"existing immutable object";
        let existing = ContentId::for_bytes(ObjectKind::Trace, 1, existing_bytes);
        backend
            .put_if_absent(existing, &BlobHandle::from_bytes(existing_bytes))
            .expect("publish existing object");

        let fault =
            fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("open for fault");
        fault
            .execute(
                "UPDATE objects SET body = ?1 WHERE id = ?2",
                params![b"corrupt", existing.encode()],
            )
            .expect("inject corrupt existing object");
        drop(fault);

        let new_bytes = b"new object before corruption check";
        let new = ContentId::for_bytes(ObjectKind::Trace, 1, new_bytes);
        let objects = [
            (new, BlobHandle::from_bytes(new_bytes)),
            (existing, BlobHandle::from_bytes(existing_bytes)),
        ];
        assert!(matches!(
            backend.put_many_if_absent(&objects),
            Err(StoreError::Corrupt { id }) if id == existing
        ));
        assert!(!backend.contains(new).expect("first insert rolled back"));
        drop(backend);

        let reopened = SqliteBlobBackend::open(
            "sqlite-batch",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen");
        assert!(!reopened.contains(new).expect("rollback remains durable"));
    }

    #[test]
    fn warmed_read_statements_observe_external_corruption_delete_and_repair() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"immutable campaign object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("durable put");
        assert!(backend.contains(id).expect("warm authenticated reader"));

        // A separate writer changes the same-length body after both cached
        // statements have run. Cached query plans must never cache row data.
        let connection =
            fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("open for fault");
        connection
            .execute(
                "UPDATE objects SET body = ?1 WHERE id = ?2",
                params![vec![b'x'; bytes.len()], id.encode()],
            )
            .expect("inject same-length corruption");
        assert!(matches!(
            backend.contains(id),
            Err(StoreError::Corrupt { .. })
        ));

        connection
            .execute("DELETE FROM objects WHERE id = ?1", [id.encode()])
            .expect("remove corrupt object");
        assert!(!backend.contains(id).expect("observe external deletion"));
        assert!(matches!(
            backend.read(id, None),
            Err(StoreError::NotFound { .. })
        ));

        connection
            .execute(
                "INSERT INTO objects (id, body) VALUES (?1, ?2)",
                params![id.encode(), bytes],
            )
            .expect("restore authentic bytes");
        assert_eq!(
            backend
                .read(id, None)
                .expect("restored handle")
                .read_all(1024)
                .expect("restored bytes"),
            bytes
        );
    }

    #[test]
    fn corruption_fails_closed_and_planned_delete_survives_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"immutable campaign object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("durable put");
        drop(backend);

        let connection =
            fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("open for fault");
        connection
            .execute(
                "UPDATE objects SET body = ?1 WHERE id = ?2",
                params![b"broken", id.encode()],
            )
            .expect("inject corrupt object");
        drop(connection);

        let reopened = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen");
        assert!(matches!(
            reopened.contains(id),
            Err(StoreError::Corrupt { .. })
        ));
        let mut fence = reopened.acquire_inventory_fence().expect("inventory fence");
        let summary = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("inventory reads placement metadata");
        assert_eq!(summary.objects(), 1);
        let initial_generation = summary.generation();
        assert!(matches!(
            fence.repair_put_if_absent(
                &PhysicalRepairAuthority::new(),
                id,
                &BlobHandle::from_bytes(bytes),
            ),
            Err(StoreError::Corrupt { .. })
        ));
        assert_eq!(
            fence.delete_candidate(id).expect("durable planned delete"),
            PlannedDeleteDisposition::Deleted
        );
        let deleted = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("inventory after delete");
        assert_eq!(deleted.objects(), 0);
        assert_ne!(deleted.generation(), initial_generation);
        let repair = fence
            .repair_put_if_absent(
                &PhysicalRepairAuthority::new(),
                id,
                &BlobHandle::from_bytes(bytes),
            )
            .expect("fenced absent-object repair");
        assert!(repair.is_durable());
        let repaired = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("inventory after repair");
        assert_eq!(repaired.objects(), 1);
        assert_ne!(repaired.generation(), deleted.generation());
        drop(fence);
        assert!(reopened.contains(id).expect("repair authenticates"));
        drop(reopened);

        let reopened = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("reopen after fenced repair");
        let mut fence = reopened
            .acquire_inventory_fence()
            .expect("repaired inventory fence");
        let cold_repaired = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("cold repaired inventory");
        assert_eq!(cold_repaired.generation(), repaired.generation());
        drop(fence);
        assert!(reopened.contains(id).expect("cold repair authenticates"));

        let mut fence = reopened.acquire_inventory_fence().expect("delete fence");
        assert_eq!(
            fence.delete_candidate(id).expect("durable planned delete"),
            PlannedDeleteDisposition::Deleted
        );
        let final_generation = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("inventory after final delete")
            .generation();
        drop(fence);
        drop(reopened);

        let final_backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("reopen after delete");
        assert!(!final_backend.contains(id).expect("candidate absent"));
        let mut fence = final_backend
            .acquire_inventory_fence()
            .expect("final inventory fence");
        let final_inventory = fence
            .visit_inventory(&mut |_| Ok(()))
            .expect("complete final inventory");
        assert_eq!(final_inventory.objects(), 0);
        assert_eq!(final_inventory.generation(), final_generation);
    }

    #[test]
    fn uncommitted_object_is_not_visible_after_connection_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"uncommitted campaign object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        drop(backend);

        let connection =
            fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("open writer");
        let mut native = connection.lock().expect("managed interrupted writer");
        let transaction = native.transaction().expect("begin interrupted write");
        transaction
            .execute(
                "INSERT INTO objects (id, body) VALUES (?1, ?2)",
                params![id.encode(), bytes],
            )
            .expect("stage uncommitted object");
        drop(transaction);
        drop(native);
        drop(connection);

        let reopened = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("cold reopen");
        assert!(!reopened.contains(id).expect("uncommitted object absent"));
    }

    #[test]
    fn corrupt_inventory_generation_fails_closed_on_cold_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        drop(backend);

        let connection =
            fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("open for fault");
        connection
            .execute("UPDATE metadata SET generation = generation + 1", [])
            .expect("inject metadata corruption");
        drop(connection);

        assert!(matches!(
            SqliteBlobBackend::open(
                "sqlite-test",
                root.path(),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            ),
            Err(StoreError::InvalidComposition { .. })
        ));
    }

    #[test]
    fn non_reclaiming_database_layout_fails_closed_on_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let connection = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
            .expect("create non-reclaiming database");
        connection
            .execute_batch("PRAGMA auto_vacuum=NONE; CREATE TABLE legacy (id INTEGER);")
            .expect("persist non-reclaiming layout");
        drop(connection);

        assert!(matches!(
            SqliteBlobBackend::open(
                "sqlite-test",
                root.path(),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            ),
            Err(StoreError::InvalidComposition { .. })
        ));
    }

    #[test]
    fn symlinked_database_sidecar_lock_and_root_fail_closed() {
        let root = tempfile::tempdir().expect("temporary database root");
        let external = tempfile::tempdir().expect("external sentinel root");
        let sentinel = external.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").expect("write sentinel");

        let database = root.path().join(DATABASE_FILE);
        symlink(&sentinel, &database).expect("symlink database");
        assert!(
            SqliteBlobBackend::open(
                "sqlite-test",
                root.path(),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            )
            .is_err()
        );
        std::fs::remove_file(&database).expect("remove database symlink");

        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = root.path().join(format!("{DATABASE_FILE}{suffix}"));
            symlink(&sentinel, &sidecar).expect("symlink sidecar");
            assert!(
                SqliteBlobBackend::open(
                    "sqlite-test",
                    root.path(),
                    &crate::content_store::fixture_sqlite_heap()
                        .expect("authored SQLite fixture process")
                )
                .is_err()
            );
            std::fs::remove_file(sidecar).expect("remove sidecar symlink");
        }

        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let lock = root.path().join(LOCK_FILE);
        std::fs::remove_file(&lock).expect("remove inventory lock");
        symlink(&sentinel, &lock).expect("symlink inventory lock");
        assert!(backend.acquire_inventory_fence().is_err());
        assert!(
            SqliteBlobBackend::open(
                "sqlite-test",
                root.path(),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            )
            .is_err()
        );
        drop(backend);
        std::fs::remove_file(&lock).expect("remove inventory lock symlink");

        let alias = external.path().join("aliased-root");
        symlink(root.path(), &alias).expect("symlink database root");
        assert!(
            SqliteBlobBackend::open(
                "sqlite-test",
                &alias,
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process")
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(sentinel).expect("read sentinel"),
            b"unchanged"
        );
    }

    #[test]
    fn planned_deletes_reclaim_database_pages_after_cold_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("open database");
        let mut ids = Vec::new();
        for ordinal in 0_u64..128 {
            let mut bytes = vec![0_u8; 64 * 1024];
            let mut hasher = blake3::Hasher::new();
            hasher.update(&ordinal.to_le_bytes());
            hasher.finalize_xof().fill(&mut bytes);
            let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
            backend
                .put_if_absent(id, &BlobHandle::from_bytes(bytes))
                .expect("seed durable object");
            ids.push(id);
        }
        drop(backend);
        let seeded_database_bytes = std::fs::metadata(root.path().join(DATABASE_FILE))
            .expect("seeded database metadata")
            .len();
        let (seeded_cold_blocks, seeded_cold_conservative) = sqlite_file_census(root.path());

        let reopened = SqliteBlobBackend::open(
            "sqlite-test",
            root.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .expect("reopen seeded database");
        let (before_live_blocks, before_live_conservative) = sqlite_file_census(root.path());
        let mut fence = reopened.acquire_inventory_fence().expect("delete fence");
        for id in ids {
            assert_eq!(
                fence.delete_candidate(id).expect("planned delete"),
                PlannedDeleteDisposition::Deleted
            );
        }
        assert_eq!(
            fence
                .visit_inventory(&mut |_| Ok(()))
                .expect("empty inventory")
                .objects(),
            0
        );
        let after_live_database_bytes = std::fs::metadata(root.path().join(DATABASE_FILE))
            .expect("database metadata after planned deletes")
            .len();
        let after_live_wal_bytes =
            std::fs::metadata(root.path().join(format!("{DATABASE_FILE}-wal")))
                .expect("WAL metadata after truncate checkpoint")
                .len();
        let (after_live_blocks, after_live_conservative) = sqlite_file_census(root.path());
        drop(fence);
        drop(reopened);

        let after_cold_database_bytes = std::fs::metadata(root.path().join(DATABASE_FILE))
            .expect("cold database metadata")
            .len();
        let (after_cold_blocks, after_cold_conservative) = sqlite_file_census(root.path());
        println!(
            "sqlite_gc_reclaim seeded_database_bytes={seeded_database_bytes} after_live_database_bytes={after_live_database_bytes} after_live_wal_bytes={after_live_wal_bytes} after_cold_database_bytes={after_cold_database_bytes} seeded_cold_blocks={seeded_cold_blocks} seeded_cold_conservative={seeded_cold_conservative} before_live_blocks={before_live_blocks} before_live_conservative={before_live_conservative} after_live_blocks={after_live_blocks} after_live_conservative={after_live_conservative} after_cold_blocks={after_cold_blocks} after_cold_conservative={after_cold_conservative}"
        );
        assert!(seeded_database_bytes > 8 * 1024 * 1024);
        assert!(after_live_database_bytes < seeded_database_bytes / 2);
        assert_eq!(after_live_wal_bytes, 0);
        assert_eq!(after_cold_database_bytes, after_live_database_bytes);
    }
}
