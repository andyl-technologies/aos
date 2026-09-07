//! Durable bounded roots for exact/thin hot-checkpoint fallbacks.
//!
//! A retained QEMU source may be released only while its exact or thin fallback
//! remains protected from concurrent garbage collection. This module owns a
//! fixed 65,536-slot operational catalog, independent of campaign refs. Each
//! directory record is checksummed, atomically replaced or removed, and fsynced.
//! An inventory fence blocks mutations while GC streams the complete root set.
//!
//! The directory layout is:
//!
//! ```text
//! <catalog>/
//!   writer.lock
//!   records/<four-lowercase-hex-slot>
//! ```

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};

use crucible::ContentHash;
use crucible_campaign::{
    CampaignCodecError, CampaignHash, CampaignLineageId, ConfigurationArtifactId, ExactCheckpointId,
};
use crucible_cas::content_store::ContentId;
use rustix::fs::{FlockOperation, flock};
use thiserror::Error;

use crate::{HotCheckpointFallback, QemuHotForkTemplateKey};

/// Maximum durable fallback records retained by one daemon catalog.
pub const MAX_HOT_CHECKPOINT_FALLBACK_ROOTS: usize = 65_536;

const RECORD_MAGIC: &[u8] = b"crucible.executor.hot-checkpoint-fallback.v1\0";
const RECORD_CHECKSUM_DOMAIN: &str = "crucible.executor.hot-checkpoint-fallback.v1";
const SUMMARY_DOMAIN: &str = "crucible.executor.hot-checkpoint-fallback-summary.v1";
const MAX_RECORD_BYTES: u64 = 1_024;

/// Stable bounded slot in the operational fallback catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HotCheckpointFallbackSlot(u16);

impl HotCheckpointFallbackSlot {
    /// Builds one slot from its zero-based catalog index.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointFallbackRetentionError::SlotOutOfRange`] when
    /// `index` is outside the fixed catalog namespace.
    pub fn new(index: usize) -> Result<Self, HotCheckpointFallbackRetentionError> {
        let slot = u16::try_from(index)
            .map_err(|_| HotCheckpointFallbackRetentionError::SlotOutOfRange { index })?;
        Ok(Self(slot))
    }

    /// Returns the zero-based catalog index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Exact source key and fallback identity retained in one catalog slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointFallbackRecord {
    key: QemuHotForkTemplateKey,
    fallback: HotCheckpointFallback,
}

impl HotCheckpointFallbackRecord {
    /// Binds one exact source identity to its durable fallback.
    #[must_use]
    pub const fn new(key: QemuHotForkTemplateKey, fallback: HotCheckpointFallback) -> Self {
        Self { key, fallback }
    }

    /// Returns the source lineage/configuration identity.
    #[must_use]
    pub const fn template_key(self) -> QemuHotForkTemplateKey {
        self.key
    }

    /// Returns the exact retained fallback identity.
    #[must_use]
    pub const fn fallback(self) -> HotCheckpointFallback {
        self.fallback
    }

    /// Returns the immutable content root protected from GC.
    #[must_use]
    pub const fn root(self) -> ContentId {
        match self.fallback {
            HotCheckpointFallback::Exact(checkpoint) => checkpoint.content_id(),
            HotCheckpointFallback::Thin(configuration) => configuration.content_id(),
        }
    }
}

/// Result of conditionally replacing one fallback slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointFallbackRetentionCas {
    /// The requested record or absence became durable.
    Advanced,
    /// The expected slot value differed from durable state.
    Conflict {
        /// Current durable value observed by the failed comparison.
        current: Option<HotCheckpointFallbackRecord>,
    },
}

/// Terminal evidence for one stable fallback-root inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointFallbackRetentionSummary {
    digest: CampaignHash,
    roots: u64,
}

impl HotCheckpointFallbackRetentionSummary {
    /// Returns the digest of every ordered slot and record.
    #[must_use]
    pub const fn digest(self) -> CampaignHash {
        self.digest
    }

    /// Returns the number of roots visited.
    #[must_use]
    pub const fn roots(self) -> u64 {
        self.roots
    }
}

/// Stable inventory guard for destructive-GC coordination.
pub trait HotCheckpointFallbackRetentionFence {
    /// Streams every durable fallback record in exact slot order.
    ///
    /// Visited records are tentative until terminal success. This inventory is
    /// the restart authority used by the managed hot/cold owner; callers must
    /// not infer absence until the returned summary authenticates the complete
    /// bounded catalog.
    ///
    /// # Errors
    ///
    /// Returns a catalog error when a record cannot be authenticated or the
    /// visitor rejects an entry.
    fn visit_fallbacks(
        &mut self,
        visitor: &mut dyn FnMut(
            HotCheckpointFallbackSlot,
            HotCheckpointFallbackRecord,
        ) -> Result<(), HotCheckpointFallbackRetentionError>,
    ) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError>;

    /// Streams every durable fallback root exactly once.
    ///
    /// Visited roots are tentative until terminal success.
    ///
    /// # Errors
    ///
    /// Returns a catalog error when a record cannot be authenticated or the
    /// visitor rejects a root.
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(ContentId) -> Result<(), HotCheckpointFallbackRetentionError>,
    ) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError> {
        self.visit_fallbacks(&mut |_slot, record| visitor(record.root()))
    }
}

/// Separate maintenance capability for hot-checkpoint fallback roots.
pub trait HotCheckpointFallbackRetentionAdmin: Send + Sync {
    /// Acquires a stable complete root inventory.
    ///
    /// # Errors
    ///
    /// Returns a catalog error when the lifecycle lock is poisoned or durable
    /// records cannot be authenticated.
    fn acquire_hot_checkpoint_retention_fence(
        &self,
    ) -> Result<
        Box<dyn HotCheckpointFallbackRetentionFence + '_>,
        HotCheckpointFallbackRetentionError,
    >;
}

/// Mutable capability for one bounded operational fallback catalog.
pub trait HotCheckpointFallbackRetentionStore: HotCheckpointFallbackRetentionAdmin {
    /// Loads one exact slot.
    ///
    /// # Errors
    ///
    /// Returns a catalog error when the slot record is unavailable or corrupt.
    fn load_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
    ) -> Result<Option<HotCheckpointFallbackRecord>, HotCheckpointFallbackRetentionError>;

    /// Conditionally replaces or removes one exact slot.
    ///
    /// `None` removes the record durably. A stale expected value returns
    /// [`HotCheckpointFallbackRetentionCas::Conflict`] without mutation.
    ///
    /// # Errors
    ///
    /// Returns a catalog error when durable replacement/removal fails.
    fn compare_exchange_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
        expected: Option<HotCheckpointFallbackRecord>,
        next: Option<HotCheckpointFallbackRecord>,
    ) -> Result<HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError>;
}

/// In-memory fallback catalog for bounded composition tests.
#[derive(Clone, Default)]
pub struct MemoryHotCheckpointFallbackRetentionStore {
    records: Arc<RwLock<BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>>>,
}

impl MemoryHotCheckpointFallbackRetentionStore {
    /// Creates an empty bounded catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl HotCheckpointFallbackRetentionStore for MemoryHotCheckpointFallbackRetentionStore {
    fn load_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
    ) -> Result<Option<HotCheckpointFallbackRecord>, HotCheckpointFallbackRetentionError> {
        Ok(self
            .records
            .read()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?
            .get(&slot)
            .copied())
    }

    fn compare_exchange_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
        expected: Option<HotCheckpointFallbackRecord>,
        next: Option<HotCheckpointFallbackRecord>,
    ) -> Result<HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError> {
        let mut records = self
            .records
            .write()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?;
        let current = records.get(&slot).copied();
        if current != expected {
            return Ok(HotCheckpointFallbackRetentionCas::Conflict { current });
        }
        match next {
            Some(next) => {
                records.insert(slot, next);
            }
            None => {
                records.remove(&slot);
            }
        }
        Ok(HotCheckpointFallbackRetentionCas::Advanced)
    }
}

impl HotCheckpointFallbackRetentionAdmin for MemoryHotCheckpointFallbackRetentionStore {
    fn acquire_hot_checkpoint_retention_fence(
        &self,
    ) -> Result<
        Box<dyn HotCheckpointFallbackRetentionFence + '_>,
        HotCheckpointFallbackRetentionError,
    > {
        Ok(Box::new(MemoryHotCheckpointFallbackRetentionFence {
            records: self
                .records
                .read()
                .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?,
        }))
    }
}

struct MemoryHotCheckpointFallbackRetentionFence<'a> {
    records: RwLockReadGuard<'a, BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>>,
}

impl HotCheckpointFallbackRetentionFence for MemoryHotCheckpointFallbackRetentionFence<'_> {
    fn visit_fallbacks(
        &mut self,
        visitor: &mut dyn FnMut(
            HotCheckpointFallbackSlot,
            HotCheckpointFallbackRecord,
        ) -> Result<(), HotCheckpointFallbackRetentionError>,
    ) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError> {
        visit_records(&self.records, visitor)
    }
}

/// Crash-safe directory fallback catalog with one process writer.
#[derive(Clone)]
pub struct DirectoryHotCheckpointFallbackRetentionStore {
    inner: Arc<DirectoryHotCheckpointFallbackRetentionInner>,
}

struct DirectoryHotCheckpointFallbackRetentionInner {
    root: PathBuf,
    _writer_lock: File,
    lifecycle: RwLock<()>,
    records: Mutex<BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>>,
}

impl DirectoryHotCheckpointFallbackRetentionStore {
    /// Opens a durable catalog and authenticates every existing record.
    ///
    /// # Errors
    ///
    /// Returns a catalog error when the directory cannot be created, another
    /// writer owns it, or any durable record is malformed or inconsistent with
    /// its fixed slot name.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, HotCheckpointFallbackRetentionError> {
        let root = root.into();
        create_directory_durable(&root)?;
        let lock_path = root.join("writer.lock");
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_error("open-writer-lock", &lock_path, source))?;
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            io_error(
                "lock-writer",
                &lock_path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        recover_staging_records(&root)?;
        let records = load_directory_records(&root)?;
        Ok(Self {
            inner: Arc::new(DirectoryHotCheckpointFallbackRetentionInner {
                root,
                _writer_lock: writer_lock,
                lifecycle: RwLock::new(()),
                records: Mutex::new(records),
            }),
        })
    }

    /// Returns the physical catalog root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    fn record_path(&self, slot: HotCheckpointFallbackSlot) -> PathBuf {
        self.inner
            .root
            .join("records")
            .join(format!("{:04x}", slot.0))
    }
}

impl HotCheckpointFallbackRetentionStore for DirectoryHotCheckpointFallbackRetentionStore {
    fn load_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
    ) -> Result<Option<HotCheckpointFallbackRecord>, HotCheckpointFallbackRetentionError> {
        let _lifecycle = self
            .inner
            .lifecycle
            .read()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?;
        let path = self.record_path(slot);
        let loaded = read_record(&path, slot)?;
        sync_parent_if_present(&path)?;
        let mut records = self
            .inner
            .records
            .lock()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?;
        match loaded {
            Some(record) => {
                records.insert(slot, record);
            }
            None => {
                records.remove(&slot);
            }
        }
        Ok(loaded)
    }

    fn compare_exchange_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
        expected: Option<HotCheckpointFallbackRecord>,
        next: Option<HotCheckpointFallbackRecord>,
    ) -> Result<HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError> {
        let _lifecycle = self
            .inner
            .lifecycle
            .write()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?;
        let path = self.record_path(slot);
        let current = read_record(&path, slot)?;
        sync_parent_if_present(&path)?;
        let mut records = self
            .inner
            .records
            .lock()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?;
        match current {
            Some(current) => {
                records.insert(slot, current);
            }
            None => {
                records.remove(&slot);
            }
        }
        if current != expected {
            return Ok(HotCheckpointFallbackRetentionCas::Conflict { current });
        }

        match next {
            Some(next) => replace_record(&path, &encode_record(slot, next))?,
            None => remove_record(&path)?,
        }
        match next {
            Some(next) => {
                records.insert(slot, next);
            }
            None => {
                records.remove(&slot);
            }
        }
        Ok(HotCheckpointFallbackRetentionCas::Advanced)
    }
}

impl HotCheckpointFallbackRetentionAdmin for DirectoryHotCheckpointFallbackRetentionStore {
    fn acquire_hot_checkpoint_retention_fence(
        &self,
    ) -> Result<
        Box<dyn HotCheckpointFallbackRetentionFence + '_>,
        HotCheckpointFallbackRetentionError,
    > {
        let lifecycle = self
            .inner
            .lifecycle
            .read()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)?;
        let records = load_directory_records(&self.inner.root)?;
        *self
            .inner
            .records
            .lock()
            .map_err(|_| HotCheckpointFallbackRetentionError::Poisoned)? = records.clone();
        Ok(Box::new(DirectoryHotCheckpointFallbackRetentionFence {
            _lifecycle: lifecycle,
            records,
        }))
    }
}

struct DirectoryHotCheckpointFallbackRetentionFence<'a> {
    _lifecycle: RwLockReadGuard<'a, ()>,
    records: BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
}

impl HotCheckpointFallbackRetentionFence for DirectoryHotCheckpointFallbackRetentionFence<'_> {
    fn visit_fallbacks(
        &mut self,
        visitor: &mut dyn FnMut(
            HotCheckpointFallbackSlot,
            HotCheckpointFallbackRecord,
        ) -> Result<(), HotCheckpointFallbackRetentionError>,
    ) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError> {
        visit_records(&self.records, visitor)
    }
}

/// Durable fallback-catalog failure.
#[derive(Debug, Error)]
pub enum HotCheckpointFallbackRetentionError {
    /// A catalog slot was outside the fixed 16-bit namespace.
    #[error("hot-checkpoint fallback slot {index} is outside the fixed catalog")]
    SlotOutOfRange {
        /// Rejected zero-based slot index.
        index: usize,
    },
    /// An operating-system operation failed.
    #[error("hot-checkpoint fallback catalog {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact affected path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A durable record was malformed or stored under the wrong slot.
    #[error("hot-checkpoint fallback catalog is corrupt: {reason}")]
    Corrupt {
        /// Stable corruption category.
        reason: &'static str,
    },
    /// A typed campaign identity was invalid.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// An in-process catalog lock was poisoned.
    #[error("hot-checkpoint fallback catalog lock is poisoned")]
    Poisoned,
    /// The caller stopped a tentative root inventory.
    #[error("hot-checkpoint fallback root visitor rejected an entry")]
    Visitor,
}

fn visit_records(
    records: &BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
    visitor: &mut dyn FnMut(
        HotCheckpointFallbackSlot,
        HotCheckpointFallbackRecord,
    ) -> Result<(), HotCheckpointFallbackRetentionError>,
) -> Result<HotCheckpointFallbackRetentionSummary, HotCheckpointFallbackRetentionError> {
    let mut material = Vec::with_capacity(records.len().saturating_mul(128));
    for (&slot, &record) in records {
        visitor(slot, record)?;
        material.extend_from_slice(&slot.0.to_be_bytes());
        material.extend_from_slice(
            &CampaignHash::derive(RECORD_CHECKSUM_DOMAIN, &encode_record(slot, record)).as_bytes(),
        );
    }
    let roots =
        u64::try_from(records.len()).map_err(|_| corrupt("fallback-root-count-overflow"))?;
    Ok(HotCheckpointFallbackRetentionSummary {
        digest: CampaignHash::derive(SUMMARY_DOMAIN, &material),
        roots,
    })
}

fn encode_record(slot: HotCheckpointFallbackSlot, record: HotCheckpointFallbackRecord) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(RECORD_MAGIC);
    payload.extend_from_slice(&slot.0.to_be_bytes());
    push_bytes(&mut payload, record.key.lineage().to_text().as_bytes());
    payload.extend_from_slice(&record.key.configuration().bytes);
    match record.fallback {
        HotCheckpointFallback::Exact(checkpoint) => {
            payload.push(0);
            push_bytes(&mut payload, checkpoint.to_text().as_bytes());
        }
        HotCheckpointFallback::Thin(configuration) => {
            payload.push(1);
            push_bytes(&mut payload, configuration.to_text().as_bytes());
        }
    }
    let checksum = CampaignHash::derive(RECORD_CHECKSUM_DOMAIN, &payload);
    payload.extend_from_slice(&checksum.as_bytes());
    payload
}

fn decode_record(
    bytes: &[u8],
    expected_slot: HotCheckpointFallbackSlot,
) -> Result<HotCheckpointFallbackRecord, HotCheckpointFallbackRetentionError> {
    if bytes.len() < 32 || bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(corrupt("record-size"));
    }
    let payload_length = bytes.len() - 32;
    let (payload, checksum) = bytes.split_at(payload_length);
    if checksum != CampaignHash::derive(RECORD_CHECKSUM_DOMAIN, payload).as_bytes() {
        return Err(corrupt("record-checksum"));
    }
    let mut cursor = RecordCursor::new(payload);
    cursor.require(RECORD_MAGIC)?;
    let slot = HotCheckpointFallbackSlot(u16::from_be_bytes(cursor.fixed()?));
    if slot != expected_slot {
        return Err(corrupt("record-slot-mismatch"));
    }
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let configuration = ContentHash {
        bytes: cursor.fixed()?,
    };
    let fallback = match cursor.byte()? {
        0 => HotCheckpointFallback::Exact(parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?),
        1 => HotCheckpointFallback::Thin(parse_typed(
            cursor.bytes()?,
            ConfigurationArtifactId::parse,
        )?),
        _ => return Err(corrupt("record-fallback-tag")),
    };
    cursor.finish()?;
    Ok(HotCheckpointFallbackRecord::new(
        QemuHotForkTemplateKey::new(lineage, configuration),
        fallback,
    ))
}

fn load_directory_records(
    root: &Path,
) -> Result<
    BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
    HotCheckpointFallbackRetentionError,
> {
    let records_root = root.join("records");
    let entries = match fs::read_dir(&records_root) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => return Err(io_error("read-record-directory", &records_root, source)),
    };
    let mut records = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read-record-entry", &records_root, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| corrupt("record-name-not-utf8"))?;
        if name.starts_with(".staging-") {
            continue;
        }
        if name.len() != 4
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(corrupt("record-name"));
        }
        if !entry
            .file_type()
            .map_err(|source| io_error("stat-record-entry", &entry.path(), source))?
            .is_file()
        {
            return Err(corrupt("record-not-file"));
        }
        let index = u16::from_str_radix(&name, 16).map_err(|_| corrupt("record-name"))?;
        let slot = HotCheckpointFallbackSlot(index);
        let record =
            read_record(&entry.path(), slot)?.ok_or_else(|| corrupt("record-disappeared"))?;
        if records.insert(slot, record).is_some() {
            return Err(corrupt("duplicate-record-slot"));
        }
        if records.len() > MAX_HOT_CHECKPOINT_FALLBACK_ROOTS {
            return Err(corrupt("record-count"));
        }
    }
    Ok(records)
}

fn read_record(
    path: &Path,
    slot: HotCheckpointFallbackSlot,
) -> Result<Option<HotCheckpointFallbackRecord>, HotCheckpointFallbackRetentionError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open-record", path, source)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-record", path, source))?;
    decode_record(&bytes, slot).map(Some)
}

fn replace_record(path: &Path, bytes: &[u8]) -> Result<(), HotCheckpointFallbackRetentionError> {
    let directory = path.parent().ok_or_else(|| corrupt("record-path-parent"))?;
    create_directory_durable(directory)?;
    let record_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt("record-path-name"))?;
    let staging_path = directory.join(format!(".staging-{record_name}"));
    let mut staging = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging_path)
        .map_err(|source| io_error("create-record-staging", &staging_path, source))?;
    if let Err(source) = staging.write_all(bytes).and_then(|()| staging.sync_all()) {
        drop(staging);
        remove_staging_record(&staging_path)?;
        return Err(io_error("write-record-staging", &staging_path, source));
    }
    drop(staging);
    if let Err(source) = fs::rename(&staging_path, path) {
        remove_staging_record(&staging_path)?;
        return Err(io_error("replace-record", path, source));
    }
    sync_directory(directory)
}

fn recover_staging_records(root: &Path) -> Result<(), HotCheckpointFallbackRetentionError> {
    let records_root = root.join("records");
    let entries = match fs::read_dir(&records_root) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(io_error("read-record-directory", &records_root, source)),
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read-record-entry", &records_root, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| corrupt("record-name-not-utf8"))?;
        if !name.starts_with(".staging-") {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|source| io_error("stat-record-entry", &entry.path(), source))?
            .is_file()
        {
            return Err(corrupt("staging-record-not-file"));
        }
        fs::remove_file(entry.path())
            .map_err(|source| io_error("remove-staging-record", &entry.path(), source))?;
        removed = true;
    }
    if removed {
        sync_directory(&records_root)?;
    }
    Ok(())
}

fn remove_staging_record(path: &Path) -> Result<(), HotCheckpointFallbackRetentionError> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent_if_present(path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove-staging-record", path, source)),
    }
}

fn remove_record(path: &Path) -> Result<(), HotCheckpointFallbackRetentionError> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent_if_present(path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove-record", path, source)),
    }
}

fn sync_parent_if_present(path: &Path) -> Result<(), HotCheckpointFallbackRetentionError> {
    let parent = path.parent().ok_or_else(|| corrupt("record-path-parent"))?;
    if parent.is_dir() {
        sync_directory(parent)
    } else {
        Ok(())
    }
}

fn create_directory_durable(path: &Path) -> Result<(), HotCheckpointFallbackRetentionError> {
    if path.is_dir() {
        sync_directory(path)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|source| io_error("create-directory", path, source))?;
    let mut current = path;
    loop {
        sync_directory(current)?;
        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current || !parent.exists() {
            break;
        }
        current = parent;
        if current == Path::new("/") {
            break;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), HotCheckpointFallbackRetentionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync-directory", path, source))
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

fn parse_typed<T>(
    bytes: &[u8],
    parse: impl FnOnce(&str) -> Result<T, CampaignCodecError>,
) -> Result<T, HotCheckpointFallbackRetentionError> {
    if bytes.len() > 256 {
        return Err(corrupt("typed-id-size"));
    }
    let value = std::str::from_utf8(bytes).map_err(|_| corrupt("typed-id-utf8"))?;
    parse(value).map_err(Into::into)
}

struct RecordCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> RecordCursor<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HotCheckpointFallbackRetentionError> {
        if self.remaining.len() < length {
            return Err(corrupt("record-truncated"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], HotCheckpointFallbackRetentionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| corrupt("record-fixed-width"))
    }

    fn byte(&mut self) -> Result<u8, HotCheckpointFallbackRetentionError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn bytes(&mut self) -> Result<&'a [u8], HotCheckpointFallbackRetentionError> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        self.take(length)
    }

    fn require(&mut self, expected: &[u8]) -> Result<(), HotCheckpointFallbackRetentionError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(corrupt("record-magic"))
        }
    }

    fn finish(self) -> Result<(), HotCheckpointFallbackRetentionError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(corrupt("record-trailing-bytes"))
        }
    }
}

fn corrupt(reason: &'static str) -> HotCheckpointFallbackRetentionError {
    HotCheckpointFallbackRetentionError::Corrupt { reason }
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> HotCheckpointFallbackRetentionError {
    HotCheckpointFallbackRetentionError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests;
