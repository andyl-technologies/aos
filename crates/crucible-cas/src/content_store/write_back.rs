//! Durable write-back transfer ownership for composed immutable stores.
//!
//! One write-back node acknowledges a logical put only after a durable staging
//! placement and a durable pending-transfer journal record both exist. The
//! journal's shared lifecycle fence spans that children-before-journal window;
//! its exclusive side exposes the exact pending IDs as garbage-collection
//! roots and excludes transfer-set changes until a collector releases it.
//!
//! The journal is an append-only checksummed v1 log. Complete records remove
//! pending IDs, and bounded compaction rewrites only the current pending set.
//! A torn trailing record is discarded under the state lock; malformed complete
//! records fail closed.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustix::fs::{FlockOperation, flock};

use super::directory::create_dir_all_durable;
use super::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, PutReceipt,
    StoreError, StoreNamespaceAuthorizer, StoreNamespaceOperation,
};

const JOURNAL_MAGIC: &[u8] = b"crucible.content-store.write-back-transfer.v1\0";
const JOURNAL_RECORD_DOMAIN: &[u8] = b"crucible.content-store.write-back-transfer-record.v1";
const JOURNAL_BINDING_DOMAIN: &[u8] = b"crucible.content-store.write-back-transfer-binding.v1";
const RETENTION_GENERATION_DOMAIN: &[u8] =
    b"crucible.content-store.write-back-retention-generation.v1";
const JOURNAL_FILE: &str = "transfers-v1.log";
const LIFECYCLE_LOCK_FILE: &str = "lifecycle.lock";
const STATE_LOCK_FILE: &str = "state.lock";
const MAX_JOURNAL_RECORD_BYTES: usize = 256;
const COMPACT_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PENDING_OBJECTS: u64 = 65_536;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Exact generation digest of one fenced write-back root inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriteBackRetentionGeneration([u8; 32]);

impl WriteBackRetentionGeneration {
    /// Returns the raw generation digest.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One pending transfer retained as a logical garbage-collection root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteBackRetentionRoot {
    node: String,
    id: ContentId,
    logical_length: u64,
}

impl WriteBackRetentionRoot {
    pub(crate) fn new(node: String, id: ContentId, logical_length: u64) -> Self {
        Self {
            node,
            id,
            logical_length,
        }
    }

    /// Returns the admitted store-graph node that owns the transfer.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the exact pending logical object.
    #[must_use]
    pub const fn id(&self) -> ContentId {
        self.id
    }

    /// Returns the authenticated logical byte length.
    #[must_use]
    pub const fn logical_length(&self) -> u64 {
        self.logical_length
    }
}

/// Terminal evidence for one complete fenced write-back root inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteBackRetentionSummary {
    generation: WriteBackRetentionGeneration,
    roots: u64,
    logical_bytes: u64,
}

impl WriteBackRetentionSummary {
    /// Returns the exact active-set generation digest.
    #[must_use]
    pub const fn generation(self) -> WriteBackRetentionGeneration {
        self.generation
    }

    /// Returns the number of pending logical roots.
    #[must_use]
    pub const fn roots(self) -> u64 {
        self.roots
    }

    /// Returns the checked sum of pending logical bytes.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }
}

/// Exclusive inventory authority over pending write-back roots.
pub trait WriteBackRetentionFence {
    /// Visits every exact pending transfer and returns terminal evidence.
    ///
    /// Visited roots are tentative until this method returns successfully.
    ///
    /// # Errors
    ///
    /// Returns a store or visitor error when the exact active set cannot be
    /// read completely. The visitor may already have observed a prefix.
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(WriteBackRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<WriteBackRetentionSummary, StoreError>;
}

/// Separate capability for inventorying pending write-back roots.
pub trait WriteBackRetentionAdmin: Send + Sync {
    /// Acquires exclusive transfer-set authority.
    ///
    /// The returned fence blocks acknowledged puts and transfer completion
    /// until it is dropped.
    ///
    /// # Errors
    ///
    /// Returns a store error when any journal lifecycle cannot be fenced.
    fn acquire_write_back_retention_fence(
        &self,
    ) -> Result<Box<dyn WriteBackRetentionFence + '_>, StoreError>;
}

#[derive(Clone, Copy)]
enum JournalOperation {
    Pending,
    Complete,
}

struct JournalRecord {
    operation: JournalOperation,
    id: ContentId,
    logical_length: u64,
}

#[derive(Default)]
struct JournalCache {
    device: u64,
    inode: u64,
    offset: u64,
    active: BTreeMap<ContentId, u64>,
    active_bytes: u64,
}

pub(crate) struct WriteBackJournal {
    node: String,
    root: PathBuf,
    maximum_pending_objects: u64,
    maximum_pending_bytes: u64,
    binding: [u8; 32],
    cache: Mutex<JournalCache>,
}

impl WriteBackJournal {
    pub(crate) fn open(
        node: impl Into<String>,
        root: PathBuf,
        maximum_pending_objects: u64,
        maximum_pending_bytes: u64,
        binding: [u8; 32],
    ) -> Result<Arc<Self>, StoreError> {
        if maximum_pending_objects == 0
            || maximum_pending_objects > MAX_PENDING_OBJECTS
            || maximum_pending_bytes == 0
        {
            return Err(StoreError::InvalidComposition {
                reason: "write-back journal bounds are invalid",
            });
        }
        create_dir_all_durable(&root)?;
        let journal = Arc::new(Self {
            node: node.into(),
            root,
            maximum_pending_objects,
            maximum_pending_bytes,
            binding,
            cache: Mutex::new(JournalCache::default()),
        });
        journal.initialize()?;
        Ok(journal)
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let state_lock = self.lock_state()?;
        let path = self.log_path();
        let mut log = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| io_error("open write-back journal", &path, source))?;
        if log
            .metadata()
            .map_err(|source| io_error("stat write-back journal", &path, source))?
            .len()
            == 0
        {
            write_journal_header(&mut log, self.binding)
                .map_err(|source| io_error("initialize write-back journal", &path, source))?;
            log.sync_all()
                .map_err(|source| io_error("sync write-back journal", &path, source))?;
            sync_directory(&self.root)?;
        }
        drop(log);
        let mut cache = self.cache.lock().map_err(|_| StoreError::Poisoned {
            operation: "initialize write-back journal cache",
        })?;
        self.synchronize_cache(&mut cache)?;
        drop(state_lock);
        Ok(())
    }

    pub(crate) fn acquire_shared_lifecycle(&self) -> Result<File, StoreError> {
        self.lock_file(LIFECYCLE_LOCK_FILE, FlockOperation::LockShared)
    }

    pub(crate) fn acquire_exclusive_lifecycle(&self) -> Result<File, StoreError> {
        self.lock_file(LIFECYCLE_LOCK_FILE, FlockOperation::LockExclusive)
    }

    fn lock_state(&self) -> Result<File, StoreError> {
        self.lock_file(STATE_LOCK_FILE, FlockOperation::LockExclusive)
    }

    fn lock_file(&self, name: &str, operation: FlockOperation) -> Result<File, StoreError> {
        let path = self.root.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| io_error("open write-back journal lock", &path, source))?;
        flock(&file, operation)
            .map_err(|source| io_error("lock write-back journal", &path, source.into()))?;
        Ok(file)
    }

    pub(crate) fn stage_pending<T, F>(
        &self,
        id: ContentId,
        logical_length: u64,
        stage: F,
    ) -> Result<T, StoreError>
    where
        F: FnOnce() -> Result<T, StoreError>,
    {
        let _state_lock = self.lock_state()?;
        let mut cache = self.cache.lock().map_err(|_| StoreError::Poisoned {
            operation: "reserve write-back journal capacity",
        })?;
        self.synchronize_cache(&mut cache)?;
        let record = JournalRecord {
            operation: JournalOperation::Pending,
            id,
            logical_length,
        };
        let append = self.validate_record(&cache, &record)?;

        let value = stage()?;
        if append {
            self.append_record(&mut cache, record)?;
        }
        Ok(value)
    }

    pub(crate) fn record_complete(
        &self,
        id: ContentId,
        logical_length: u64,
    ) -> Result<(), StoreError> {
        self.append_if_needed(JournalRecord {
            operation: JournalOperation::Complete,
            id,
            logical_length,
        })
    }

    fn append_if_needed(&self, record: JournalRecord) -> Result<(), StoreError> {
        let _state_lock = self.lock_state()?;
        let mut cache = self.cache.lock().map_err(|_| StoreError::Poisoned {
            operation: "update write-back journal cache",
        })?;
        self.synchronize_cache(&mut cache)?;
        if !self.validate_record(&cache, &record)? {
            return Ok(());
        }
        self.append_record(&mut cache, record)
    }

    fn validate_record(
        &self,
        cache: &JournalCache,
        record: &JournalRecord,
    ) -> Result<bool, StoreError> {
        match record.operation {
            JournalOperation::Pending => {
                if let Some(existing) = cache.active.get(&record.id) {
                    if *existing != record.logical_length {
                        return Err(StoreError::Incompatible);
                    }
                    return Ok(false);
                }
                let next_objects = u64::try_from(cache.active.len())
                    .map_err(|_| StoreError::Quota)?
                    .checked_add(1)
                    .ok_or(StoreError::Quota)?;
                let next_bytes = cache
                    .active_bytes
                    .checked_add(record.logical_length)
                    .ok_or(StoreError::Quota)?;
                if next_objects > self.maximum_pending_objects
                    || next_bytes > self.maximum_pending_bytes
                {
                    return Err(StoreError::Quota);
                }
            }
            JournalOperation::Complete => match cache.active.get(&record.id) {
                None => return Ok(false),
                Some(existing) if *existing == record.logical_length => {}
                Some(_) => return Err(StoreError::Incompatible),
            },
        }
        Ok(true)
    }

    fn append_record(
        &self,
        cache: &mut JournalCache,
        record: JournalRecord,
    ) -> Result<(), StoreError> {
        let frame = encode_record(&record)?;
        if cache
            .offset
            .checked_add(frame.len() as u64)
            .ok_or(StoreError::Quota)?
            > COMPACT_JOURNAL_BYTES
        {
            self.compact(cache)?;
        }
        if cache
            .offset
            .checked_add(frame.len() as u64)
            .ok_or(StoreError::Quota)?
            > MAX_JOURNAL_BYTES
        {
            return Err(StoreError::Quota);
        }

        let path = self.log_path();
        let mut log = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|source| io_error("append write-back journal", &path, source))?;
        log.write_all(&frame)
            .map_err(|source| io_error("append write-back journal", &path, source))?;
        log.sync_all()
            .map_err(|source| io_error("sync write-back journal", &path, source))?;
        apply_record(cache, record)?;
        cache.offset = cache
            .offset
            .checked_add(frame.len() as u64)
            .ok_or(StoreError::Quota)?;
        Ok(())
    }

    pub(crate) fn next_pending(&self) -> Result<Option<(ContentId, u64)>, StoreError> {
        let _state_lock = self.lock_state()?;
        let mut cache = self.cache.lock().map_err(|_| StoreError::Poisoned {
            operation: "read write-back journal cache",
        })?;
        self.synchronize_cache(&mut cache)?;
        Ok(cache
            .active
            .first_key_value()
            .map(|(id, length)| (*id, *length)))
    }

    pub(crate) fn inventory(
        &self,
        visitor: &mut dyn FnMut(WriteBackRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<(u64, u64), StoreError> {
        let _state_lock = self.lock_state()?;
        let mut cache = self.cache.lock().map_err(|_| StoreError::Poisoned {
            operation: "inventory write-back journal cache",
        })?;
        self.synchronize_cache(&mut cache)?;
        for (id, logical_length) in &cache.active {
            visitor(WriteBackRetentionRoot::new(
                self.node.clone(),
                *id,
                *logical_length,
            ))?;
        }
        Ok((cache.active.len() as u64, cache.active_bytes))
    }

    fn synchronize_cache(&self, cache: &mut JournalCache) -> Result<(), StoreError> {
        let path = self.log_path();
        let mut log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| io_error("open write-back journal", &path, source))?;
        let metadata = log
            .metadata()
            .map_err(|source| io_error("stat write-back journal", &path, source))?;
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(StoreError::Quota);
        }
        if cache.device != metadata.dev()
            || cache.inode != metadata.ino()
            || cache.offset < journal_header_length()
            || cache.offset > metadata.len()
        {
            *cache = JournalCache::default();
            let mut header = vec![
                0_u8;
                usize::try_from(journal_header_length())
                    .map_err(|_| StoreError::Quota)?
            ];
            if let Err(source) = log.read_exact(&mut header) {
                if source.kind() == io::ErrorKind::UnexpectedEof {
                    return Err(StoreError::Incompatible);
                }
                return Err(io_error("read write-back journal magic", &path, source));
            }
            if header[..JOURNAL_MAGIC.len()] != *JOURNAL_MAGIC
                || header[JOURNAL_MAGIC.len()..] != self.binding
            {
                return Err(StoreError::Incompatible);
            }
            cache.device = metadata.dev();
            cache.inode = metadata.ino();
            cache.offset = journal_header_length();
        }
        log.seek(SeekFrom::Start(cache.offset))
            .map_err(|source| io_error("seek write-back journal", &path, source))?;
        loop {
            let record_offset = cache.offset;
            let mut length = [0_u8; 4];
            match read_prefix(&mut log, &mut length)
                .map_err(|source| io_error("read write-back journal frame", &path, source))?
            {
                PrefixRead::Eof => break,
                PrefixRead::Partial => {
                    truncate_torn_tail(&mut log, &path, record_offset)?;
                    break;
                }
                PrefixRead::Complete => {}
            }
            let length =
                usize::try_from(u32::from_be_bytes(length)).map_err(|_| StoreError::Quota)?;
            if length == 0 || length > MAX_JOURNAL_RECORD_BYTES {
                return Err(StoreError::Incompatible);
            }
            let mut encoded = vec![0_u8; length];
            if let Err(source) = log.read_exact(&mut encoded) {
                if source.kind() == io::ErrorKind::UnexpectedEof {
                    truncate_torn_tail(&mut log, &path, record_offset)?;
                    break;
                }
                return Err(io_error("read write-back journal record", &path, source));
            }
            let record = decode_record(&encoded)?;
            apply_record(cache, record)?;
            cache.offset = record_offset
                .checked_add(4)
                .and_then(|value| value.checked_add(length as u64))
                .ok_or(StoreError::Quota)?;
            if cache.active.len() as u64 > self.maximum_pending_objects
                || cache.active_bytes > self.maximum_pending_bytes
            {
                return Err(StoreError::Incompatible);
            }
        }
        Ok(())
    }

    fn compact(&self, cache: &mut JournalCache) -> Result<(), StoreError> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self.root.join(format!(
            ".{JOURNAL_FILE}.tmp-{}-{sequence}",
            std::process::id()
        ));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| {
                io_error("create compacted write-back journal", &temporary, source)
            })?;
        write_journal_header(&mut output, self.binding)
            .map_err(|source| io_error("write compacted write-back journal", &temporary, source))?;
        for (id, logical_length) in &cache.active {
            output
                .write_all(&encode_record(&JournalRecord {
                    operation: JournalOperation::Pending,
                    id: *id,
                    logical_length: *logical_length,
                })?)
                .map_err(|source| {
                    io_error("write compacted write-back journal", &temporary, source)
                })?;
        }
        output
            .sync_all()
            .map_err(|source| io_error("sync compacted write-back journal", &temporary, source))?;
        let path = self.log_path();
        fs::rename(&temporary, &path)
            .map_err(|source| io_error("publish compacted write-back journal", &path, source))?;
        sync_directory(&self.root)?;
        *cache = JournalCache::default();
        self.synchronize_cache(cache)
    }

    fn log_path(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE)
    }
}

pub(crate) struct WriteBackStore {
    name: String,
    staging: Arc<dyn ImmutableBlobBackend>,
    destination: Arc<dyn ImmutableBlobBackend>,
    journal: Arc<WriteBackJournal>,
}

impl WriteBackStore {
    pub(crate) fn new(
        name: impl Into<String>,
        staging: Arc<dyn ImmutableBlobBackend>,
        destination: Arc<dyn ImmutableBlobBackend>,
        journal_root: PathBuf,
        maximum_pending_objects: u64,
        maximum_pending_bytes: u64,
    ) -> Result<Self, StoreError> {
        let name = name.into();
        let staging_capabilities = staging.capabilities();
        let destination_capabilities = destination.capabilities();
        if !staging_capabilities.durable
            || staging_capabilities.deferred_write
            || !staging_capabilities.conditional_create
            || !staging_capabilities.streaming_read
            || !staging_capabilities.streaming_put
            || !destination_capabilities.durable
            || destination_capabilities.deferred_write
            || !destination_capabilities.conditional_create
            || !destination_capabilities.streaming_put
        {
            return Err(StoreError::InvalidComposition {
                reason: "write-back children lack durable streaming capabilities",
            });
        }
        let binding = write_back_binding(
            &name,
            staging.name(),
            destination.name(),
            maximum_pending_objects,
            maximum_pending_bytes,
        );
        let journal = WriteBackJournal::open(
            name.clone(),
            journal_root,
            maximum_pending_objects,
            maximum_pending_bytes,
            binding,
        )?;
        Ok(Self {
            name,
            staging,
            destination,
            journal,
        })
    }

    pub(crate) fn journal(&self) -> Arc<WriteBackJournal> {
        Arc::clone(&self.journal)
    }

    pub(crate) fn flush_one(
        &self,
        authorize: &mut dyn FnMut(ContentId) -> Result<(), StoreError>,
    ) -> Result<bool, StoreError> {
        let _lifecycle = self.journal.acquire_shared_lifecycle()?;
        let Some((id, logical_length)) = self.journal.next_pending()? else {
            return Ok(false);
        };
        authorize(id)?;
        let source = match self.staging.read(id, None) {
            Ok(source) => source,
            Err(StoreError::NotFound { .. }) => self.destination.read(id, None)?,
            Err(error) => return Err(error),
        };
        if source.logical_length() != logical_length {
            return Err(StoreError::Corrupt { id });
        }
        let receipt = self.destination.put_if_absent(id, &source)?;
        if !receipt.is_durable() {
            return Err(StoreError::Unsupported {
                capability: "durable write-back destination receipt",
            });
        }
        self.journal.record_complete(id, logical_length)?;
        Ok(true)
    }
}

impl ImmutableBlobBackend for WriteBackStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.staging.capabilities();
        let destination = self.destination.capabilities();
        capabilities.durable = true;
        capabilities.deferred_write = true;
        capabilities.range_read &= destination.range_read;
        capabilities.streaming_read &= destination.streaming_read;
        capabilities.repair_inventory = false;
        capabilities.planned_delete = false;
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.staging.contains(id) {
            Ok(true) => Ok(true),
            Ok(false) | Err(StoreError::NotFound { .. }) => self.destination.contains(id),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        match self.staging.read(id, range) {
            Ok(blob) => Ok(blob),
            Err(StoreError::NotFound { .. }) => self.destination.read(id, range),
            Err(error) => Err(error),
        }
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let logical_length = source.logical_length();
        let _lifecycle = self.journal.acquire_shared_lifecycle()?;
        self.journal.stage_pending(id, logical_length, || {
            let receipt = self.staging.put_if_absent(id, source)?;
            if !receipt.is_durable() {
                return Err(StoreError::Unsupported {
                    capability: "durable write-back staging receipt",
                });
            }
            Ok(receipt)
        })
    }
}

pub(crate) struct StoreGraphWriteBackFence {
    journals: Vec<(String, Arc<WriteBackJournal>, File)>,
    namespace_authorizer: Option<Arc<dyn StoreNamespaceAuthorizer>>,
    profile_validation_root: Option<Arc<dyn ImmutableBlobBackend>>,
}

impl StoreGraphWriteBackFence {
    pub(crate) fn acquire(
        journals: &BTreeMap<String, Arc<WriteBackJournal>>,
        namespace_authorizer: Option<Arc<dyn StoreNamespaceAuthorizer>>,
        profile_validation_root: Option<Arc<dyn ImmutableBlobBackend>>,
    ) -> Result<Self, StoreError> {
        let mut held = Vec::with_capacity(journals.len());
        for (node, journal) in journals {
            let lock = journal.acquire_exclusive_lifecycle()?;
            held.push((node.clone(), Arc::clone(journal), lock));
        }
        Ok(Self {
            journals: held,
            namespace_authorizer,
            profile_validation_root,
        })
    }
}

impl WriteBackRetentionFence for StoreGraphWriteBackFence {
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(WriteBackRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<WriteBackRetentionSummary, StoreError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RETENTION_GENERATION_DOMAIN);
        let mut roots = 0_u64;
        let mut logical_bytes = 0_u64;
        for (node, journal, _lock) in &self.journals {
            let (node_roots, node_bytes) = journal.inventory(&mut |root| {
                if let Some(authorizer) = &self.namespace_authorizer {
                    authorizer.authorize(StoreNamespaceOperation::Read, root.id())?;
                }
                if let Some(profile_root) = &self.profile_validation_root {
                    profile_root.read(root.id(), None)?;
                }
                hasher.update(&(node.len() as u64).to_be_bytes());
                hasher.update(node.as_bytes());
                hasher.update(root.id().to_string().as_bytes());
                hasher.update(&root.logical_length().to_be_bytes());
                visitor(root)
            })?;
            roots = roots.checked_add(node_roots).ok_or(StoreError::Quota)?;
            logical_bytes = logical_bytes
                .checked_add(node_bytes)
                .ok_or(StoreError::Quota)?;
        }
        Ok(WriteBackRetentionSummary {
            generation: WriteBackRetentionGeneration(*hasher.finalize().as_bytes()),
            roots,
            logical_bytes,
        })
    }
}

fn encode_record(record: &JournalRecord) -> Result<Vec<u8>, StoreError> {
    let id = record.id.to_string();
    let id_length = u16::try_from(id.len()).map_err(|_| StoreError::Quota)?;
    let mut payload = Vec::with_capacity(1 + 2 + id.len() + 8 + 32);
    payload.push(match record.operation {
        JournalOperation::Pending => 0,
        JournalOperation::Complete => 1,
    });
    payload.extend_from_slice(&id_length.to_be_bytes());
    payload.extend_from_slice(id.as_bytes());
    payload.extend_from_slice(&record.logical_length.to_be_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_RECORD_DOMAIN);
    hasher.update(&payload);
    payload.extend_from_slice(hasher.finalize().as_bytes());
    if payload.len() > MAX_JOURNAL_RECORD_BYTES {
        return Err(StoreError::Quota);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn write_back_binding(
    node: &str,
    staging: &str,
    destination: &str,
    maximum_pending_objects: u64,
    maximum_pending_bytes: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_BINDING_DOMAIN);
    for value in [node, staging, destination] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(&maximum_pending_objects.to_be_bytes());
    hasher.update(&maximum_pending_bytes.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn journal_header_length() -> u64 {
    JOURNAL_MAGIC.len() as u64 + 32
}

fn write_journal_header(output: &mut File, binding: [u8; 32]) -> io::Result<()> {
    output.write_all(JOURNAL_MAGIC)?;
    output.write_all(&binding)
}

fn decode_record(encoded: &[u8]) -> Result<JournalRecord, StoreError> {
    if encoded.len() < 1 + 2 + 8 + 32 {
        return Err(StoreError::Incompatible);
    }
    let payload_length = encoded.len() - 32;
    let (payload, checksum) = encoded.split_at(payload_length);
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_RECORD_DOMAIN);
    hasher.update(payload);
    if hasher.finalize().as_bytes() != checksum {
        return Err(StoreError::Incompatible);
    }
    let operation = match payload[0] {
        0 => JournalOperation::Pending,
        1 => JournalOperation::Complete,
        _ => return Err(StoreError::Incompatible),
    };
    let id_length = usize::from(u16::from_be_bytes([payload[1], payload[2]]));
    let expected_length = 1_usize
        .checked_add(2)
        .and_then(|value| value.checked_add(id_length))
        .and_then(|value| value.checked_add(8))
        .ok_or(StoreError::Quota)?;
    if payload.len() != expected_length {
        return Err(StoreError::Incompatible);
    }
    let id_end = 3 + id_length;
    let id = std::str::from_utf8(&payload[3..id_end])
        .map_err(|_| StoreError::Incompatible)
        .and_then(|id| ContentId::parse(id).map_err(|_| StoreError::Incompatible))?;
    let logical_length = u64::from_be_bytes(
        payload[id_end..]
            .try_into()
            .map_err(|_| StoreError::Incompatible)?,
    );
    Ok(JournalRecord {
        operation,
        id,
        logical_length,
    })
}

fn apply_record(cache: &mut JournalCache, record: JournalRecord) -> Result<(), StoreError> {
    match record.operation {
        JournalOperation::Pending => match cache.active.get(&record.id) {
            Some(existing) if *existing == record.logical_length => {}
            Some(_) => return Err(StoreError::Incompatible),
            None => {
                cache.active_bytes = cache
                    .active_bytes
                    .checked_add(record.logical_length)
                    .ok_or(StoreError::Quota)?;
                cache.active.insert(record.id, record.logical_length);
            }
        },
        JournalOperation::Complete => {
            let existing = cache
                .active
                .get(&record.id)
                .ok_or(StoreError::Incompatible)?;
            if *existing != record.logical_length {
                return Err(StoreError::Incompatible);
            }
            cache.active.remove(&record.id);
            cache.active_bytes = cache
                .active_bytes
                .checked_sub(record.logical_length)
                .ok_or(StoreError::Incompatible)?;
        }
    }
    Ok(())
}

enum PrefixRead {
    Eof,
    Partial,
    Complete,
}

fn read_prefix(reader: &mut File, output: &mut [u8; 4]) -> io::Result<PrefixRead> {
    let mut filled = 0;
    while filled < output.len() {
        match reader.read(&mut output[filled..]) {
            Ok(0) if filled == 0 => return Ok(PrefixRead::Eof),
            Ok(0) => return Ok(PrefixRead::Partial),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(PrefixRead::Complete)
}

fn truncate_torn_tail(log: &mut File, path: &Path, offset: u64) -> Result<(), StoreError> {
    log.set_len(offset)
        .map_err(|source| io_error("truncate torn write-back journal", path, source))?;
    log.sync_all()
        .map_err(|source| io_error("sync truncated write-back journal", path, source))
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync write-back journal directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}
