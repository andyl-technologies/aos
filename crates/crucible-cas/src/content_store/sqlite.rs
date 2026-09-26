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

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::blob::ZeroBlob;
use rusqlite::{Connection, DatabaseName, OptionalExtension, params};
use rustix::fs::{FlockOperation, flock};

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
        let connection = Connection::open(&database_path)
            .map_err(|source| database_error("open-sqlite-blob-database", source))?;
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
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| StoreError::Io {
                operation: "create-sqlite-inventory-lock",
                path: lock_path,
                source,
            })?;
        File::open(&root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| StoreError::Io {
                operation: "sync-sqlite-blob-root",
                path: root.clone(),
                source,
            })?;

        Ok(Self {
            name: name.into(),
            root,
            connection: Arc::new(Mutex::new(connection)),
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open-sqlite-inventory-lock",
                path: path.clone(),
                source,
            })?;
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
        let connection = self.lock_connection()?;
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
            connection: self.connection.clone(),
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
            repair_inventory: false,
            planned_delete: false,
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
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        }
        advance_metadata(&transaction)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit-sqlite-blob-delete", source))?;
        self.generation = self.generation.checked_add(1).ok_or(StoreError::Quota)?;
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
    use super::*;

    #[test]
    fn durable_put_reopens_with_authenticated_range_and_stable_inventory() {
        let root = tempfile::tempdir().expect("temporary database root");
        let bytes = b"authenticated SQLite campaign object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        let backend = SqliteBlobBackend::open("sqlite-test", root.path()).expect("open database");

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
            &id.encode().rsplit('.').next().expect("digest field"),
        ))
        .expect("same digest with different schema");
        assert!(!reopened.contains(other_schema).expect("distinct ID absent"));
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
        let repair = fence
            .repair_put_if_absent(
                &PhysicalRepairAuthority::new(),
                id,
                &BlobHandle::from_bytes(bytes),
            )
            .expect("fenced absent-object repair");
        assert!(repair.is_durable());
        drop(fence);
        assert!(reopened.contains(id).expect("repair authenticates"));

        let mut fence = reopened.acquire_inventory_fence().expect("delete fence");
        assert_eq!(
            fence.delete_candidate(id).expect("durable planned delete"),
            PlannedDeleteDisposition::Deleted
        );
        drop(fence);
        drop(reopened);

        let final_backend =
            SqliteBlobBackend::open("sqlite-test", root.path()).expect("reopen after delete");
        assert!(!final_backend.contains(id).expect("candidate absent"));
        let mut fence = final_backend
            .acquire_inventory_fence()
            .expect("final inventory fence");
        assert_eq!(
            fence
                .visit_inventory(&mut |_| Ok(()))
                .expect("complete final inventory")
                .objects(),
            0
        );
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
}
