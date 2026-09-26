//! Durable SQLite leaf for immutable, authenticated campaign objects.
//!
//! ```text
//! <root>/objects.sqlite3       SQLite database in WAL mode
//! <root>/objects.sqlite3-wal   SQLite's durable transaction log when present
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
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::blob::ZeroBlob;
use rusqlite::{Connection, DatabaseName, OpenFlags, OptionalExtension, params};
use rustix::fs::{FlockOperation, OFlags, flock};

use super::admin::{
    InventoryCounter, PhysicalRepairAuthority, persistent_inventory_generation,
    physical_storage_identity,
};
use super::*;

const DATABASE_FILE: &str = "objects.sqlite3";
const LOCK_FILE: &str = "inventory.lock";
const METADATA_DOMAIN: &[u8] = b"crucible.content-store.sqlite-metadata.v1";
const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// SQLite-backed durable immutable object leaf.
///
/// The constructor initializes one database and an interprocess inventory
/// lock. Clones share the same connection while separate processes coordinate
/// their writes and administrative scans through the lock file.
#[derive(Clone)]
pub struct SqliteBlobBackend {
    name: String,
    root: PathBuf,
    connection: Arc<Mutex<Connection>>,
    read_connection: Arc<Mutex<Connection>>,
}

impl SqliteBlobBackend {
    /// Opens or creates a durable SQLite object database at `root`.
    ///
    /// # Errors
    ///
    /// Returns an I/O, SQLite, or metadata error if the database cannot be
    /// initialized or its persisted inventory identity is malformed.
    pub fn open(name: impl Into<String>, root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        super::directory::create_dir_all_durable(&root)?;

        let database_path = root.join(DATABASE_FILE);
        for name in [
            DATABASE_FILE.to_owned(),
            format!("{DATABASE_FILE}-wal"),
            format!("{DATABASE_FILE}-shm"),
            format!("{DATABASE_FILE}-journal"),
            LOCK_FILE.to_owned(),
        ] {
            reject_nonregular_existing(&root.join(name))?;
        }
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|source| database_error("open-sqlite-blob-database", source))?;
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

        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
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
        let read_connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|source| database_error("open-sqlite-blob-reader", source))?;

        Ok(Self {
            name: name.into(),
            root,
            connection: Arc::new(Mutex::new(connection)),
            read_connection: Arc::new(Mutex::new(read_connection)),
        })
    }

    /// Returns the physical SQLite database directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection.lock().map_err(|_| StoreError::Poisoned {
            operation: "lock-sqlite-blob-connection",
        })
    }

    fn acquire_inventory_lock(&self) -> Result<File, StoreError> {
        let path = self.root.join(LOCK_FILE);
        let file = open_inventory_lock(&path, false)?;
        flock(&file, FlockOperation::LockExclusive).map_err(|source| StoreError::Io {
            operation: "lock-sqlite-inventory",
            path,
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        Ok(file)
    }

    fn read_handle(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let connection = self
            .read_connection
            .lock()
            .map_err(|_| StoreError::Poisoned {
                operation: "lock-sqlite-blob-reader",
            })?;
        let length: Option<i64> = connection
            .query_row(
                "SELECT length(body) FROM objects WHERE id = ?1",
                [id.encode()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| database_error("read-sqlite-blob-length", source))?;
        let length = length.ok_or(StoreError::NotFound { id })?;
        let logical_length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
        let range = range.unwrap_or(ByteRange {
            offset: 0,
            length: logical_length,
        });
        validate_range(logical_length, range)?;

        let source: Arc<dyn BlobSource> = Arc::new(SqliteBlobSource {
            connection: self.read_connection.clone(),
            id,
            logical_length,
            range,
        });
        if range.offset == 0 && range.length == logical_length {
            Ok(BlobHandle::authenticated(id, source))
        } else {
            Ok(BlobHandle::integrity_checked(id, source))
        }
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

impl ImmutableBlobBackend for SqliteBlobBackend {
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

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.read_handle(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
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
                return Ok(sqlite_receipt(&self.name, id, logical_length));
            }
        }

        let mut connection = self.lock_connection()?;
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
            copy_source(id, source, &mut blob)?;
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-put", source))?;
        Ok(sqlite_receipt(&self.name, id, logical_length))
    }
}

impl BlobStoreAdmin for SqliteBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lock = self.acquire_inventory_lock()?;
        let connection = self.lock_connection()?;
        let (instance, generation) = load_metadata(&connection)?;
        Ok(Box::new(SqliteInventoryFence {
            backend: self,
            connection,
            _lock: lock,
            instance,
            generation,
        }))
    }
}

struct SqliteInventoryFence<'a> {
    backend: &'a SqliteBlobBackend,
    connection: MutexGuard<'a, Connection>,
    _lock: File,
    instance: [u8; 32],
    generation: u64,
}

impl BlobInventoryFence for SqliteInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
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
            let id_text: String = row
                .get(0)
                .map_err(|source| database_error("decode-sqlite-blob-id", source))?;
            let id = ContentId::parse(&id_text)?;
            let length: i64 = row
                .get(1)
                .map_err(|source| database_error("decode-sqlite-blob-length", source))?;
            let logical_length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
            let record = BlobInventoryRecord::new(id, logical_length);
            visitor(record)?;
            inventory.push(record)?;
        }
        Ok(inventory.finish(self.backend.name.clone()))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| database_error("begin-sqlite-blob-delete", source))?;
        let removed = transaction
            .execute("DELETE FROM objects WHERE id = ?1", [id.encode()])
            .map_err(|source| database_error("delete-sqlite-blob-candidate", source))?;
        if removed == 0 {
            drop(transaction);
            checkpoint_reclaimed_pages(&self.connection)?;
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-delete", source))?;
        self.generation = self.generation.checked_add(1).ok_or(StoreError::Quota)?;
        checkpoint_reclaimed_pages(&self.connection)?;
        Ok(PlannedDeleteDisposition::Deleted)
    }

    fn repair_put_if_absent(
        &mut self,
        _authority: &PhysicalRepairAuthority,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        source.verified_as(id)?;
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
            copy_source(id, source, &mut blob)?;
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-repair", source))?;
        self.generation = self.generation.checked_add(1).ok_or(StoreError::Quota)?;
        Ok(sqlite_receipt(&self.backend.name, id, logical_length))
    }
}

struct SqliteBlobSource {
    connection: Arc<Mutex<Connection>>,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
}

impl BlobSource for SqliteBlobSource {
    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(AuthenticatingSqliteReader {
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
        }))
    }
}

struct AuthenticatingSqliteReader {
    connection: Arc<Mutex<Connection>>,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    finalized: bool,
}

impl AuthenticatingSqliteReader {
    fn read_chunk(&self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let offset = i64::try_from(offset)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(invalid_object_data)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("SQLite blob connection lock poisoned"))?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT substr(body, ?2, ?3) FROM objects WHERE id = ?1",
                params![self.id.encode(), offset, length as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        let bytes = bytes.ok_or_else(invalid_object_data)?;
        if bytes.len() != length {
            return Err(invalid_object_data());
        }
        Ok(bytes)
    }

    fn scan_until(&mut self, target: u64) -> io::Result<()> {
        while self.scan_offset < target {
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
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset)?;
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

        self.scan_until(self.logical_length)?;
        if *self.hasher.finalize().as_bytes() != self.id.digest() {
            return Err(invalid_object_data());
        }
        self.finalized = true;
        Ok(0)
    }
}

fn authenticate_stored(connection: &Connection, id: ContentId) -> Result<(), StoreError> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(body) FROM objects WHERE id = ?1",
            [id.encode()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| database_error("read-sqlite-repair-length", source))?;
    let length = length.ok_or(StoreError::NotFound { id })?;
    let logical_length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
    let mut hasher = content_hasher(id.kind(), id.schema_version(), logical_length);
    let mut offset = 0_u64;
    while offset < logical_length {
        let chunk_length = usize::try_from((logical_length - offset).min(MAX_CHUNK_BYTES as u64))
            .map_err(|_| StoreError::Quota)?;
        let sqlite_offset = i64::try_from(offset + 1).map_err(|_| StoreError::Quota)?;
        let chunk: Vec<u8> = connection
            .query_row(
                "SELECT substr(body, ?2, ?3) FROM objects WHERE id = ?1",
                params![id.encode(), sqlite_offset, chunk_length as i64],
                |row| row.get(0),
            )
            .map_err(|source| database_error("read-sqlite-repair-body", source))?;
        if chunk.len() != chunk_length {
            return Err(StoreError::Corrupt { id });
        }
        hasher.update(&chunk);
        offset += chunk_length as u64;
    }
    if *hasher.finalize().as_bytes() != id.digest() {
        return Err(StoreError::Corrupt { id });
    }
    Ok(())
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

    use std::os::unix::fs::{MetadataExt, symlink};

    use super::*;

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
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
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

        let reopened = SqliteBlobBackend::open("sqlite-test", root.path()).expect("cold reopen");
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
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
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
    fn corruption_fails_closed_and_planned_delete_survives_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"immutable campaign object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("durable put");
        drop(backend);

        let connection = Connection::open(root.path().join(DATABASE_FILE)).expect("open for fault");
        connection
            .execute(
                "UPDATE objects SET body = ?1 WHERE id = ?2",
                params![b"broken", id.encode()],
            )
            .expect("inject corrupt object");
        drop(connection);

        let reopened = SqliteBlobBackend::open("sqlite-test", root.path()).expect("cold reopen");
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

        let reopened = SqliteBlobBackend::open("sqlite-test", root.path())
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

        let final_backend =
            SqliteBlobBackend::open("sqlite-test", root.path()).expect("reopen after delete");
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
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
        drop(backend);

        let mut connection =
            Connection::open(root.path().join(DATABASE_FILE)).expect("open writer");
        let transaction = connection.transaction().expect("begin interrupted write");
        transaction
            .execute(
                "INSERT INTO objects (id, body) VALUES (?1, ?2)",
                params![id.encode(), bytes],
            )
            .expect("stage uncommitted object");
        drop(transaction);
        drop(connection);

        let reopened = SqliteBlobBackend::open("sqlite-test", root.path()).expect("cold reopen");
        assert!(!reopened.contains(id).expect("uncommitted object absent"));
    }

    #[test]
    fn corrupt_inventory_generation_fails_closed_on_cold_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
        drop(backend);

        let connection = Connection::open(root.path().join(DATABASE_FILE)).expect("open for fault");
        connection
            .execute("UPDATE metadata SET generation = generation + 1", [])
            .expect("inject metadata corruption");
        drop(connection);

        assert!(matches!(
            SqliteBlobBackend::open("sqlite-test", root.path()),
            Err(StoreError::InvalidComposition { .. })
        ));
    }

    #[test]
    fn non_reclaiming_database_layout_fails_closed_on_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let connection = Connection::open(root.path().join(DATABASE_FILE))
            .expect("create non-reclaiming database");
        connection
            .execute_batch("PRAGMA auto_vacuum=NONE; CREATE TABLE legacy (id INTEGER);")
            .expect("persist non-reclaiming layout");
        drop(connection);

        assert!(matches!(
            SqliteBlobBackend::open("sqlite-test", root.path()),
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
        assert!(SqliteBlobBackend::open("sqlite-test", root.path()).is_err());
        std::fs::remove_file(&database).expect("remove database symlink");

        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = root.path().join(format!("{DATABASE_FILE}{suffix}"));
            symlink(&sentinel, &sidecar).expect("symlink sidecar");
            assert!(SqliteBlobBackend::open("sqlite-test", root.path()).is_err());
            std::fs::remove_file(sidecar).expect("remove sidecar symlink");
        }

        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
        let lock = root.path().join(LOCK_FILE);
        std::fs::remove_file(&lock).expect("remove inventory lock");
        symlink(&sentinel, &lock).expect("symlink inventory lock");
        assert!(backend.acquire_inventory_fence().is_err());
        assert!(SqliteBlobBackend::open("sqlite-test", root.path()).is_err());
        drop(backend);
        std::fs::remove_file(&lock).expect("remove inventory lock symlink");

        let alias = external.path().join("aliased-root");
        symlink(root.path(), &alias).expect("symlink database root");
        assert!(SqliteBlobBackend::open("sqlite-test", &alias).is_err());
        assert_eq!(
            std::fs::read(sentinel).expect("read sentinel"),
            b"unchanged"
        );
    }

    #[test]
    fn planned_deletes_reclaim_database_pages_after_cold_reopen() {
        let root = tempfile::tempdir().expect("temporary database root");
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");
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

        let reopened =
            SqliteBlobBackend::open("sqlite-test", root.path()).expect("reopen seeded database");
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
