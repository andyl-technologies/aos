//! Restart-safe campaign archive transfer ownership and orchestration.
//!
//! Source and destination journals retain the same direct object inventory
//! before copying starts. The records are independent, so no operation holds
//! both repositories' GC fences or journal mutations at once.
//!
//! ```text
//! <root>/writer.lock
//! <root>/records/<operation-id>/page-<index:08x>
//!   TransferPageV2(operation, index, [(object, length)...])  <= 4,096 entries
//! <root>/records/<operation-id>/header
//!   TransferHeaderV2(operation, source|destination, manifest, pages, objects,
//!                    pages digest)
//! <root>/staging/<operation-id>.staging
//! ```
//!
//! A record is paged like the archive inventory it protects, in canonical
//! 4,096-entry pages, so one record admits every archive the campaign format
//! admits and no journal file grows with the archive. Pages are fsynced
//! before the header, and the header becomes visible by file sync, rename,
//! and directory sync, so only complete records are visible. GC holds the
//! journal fence while streaming every recorded object as a direct root.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard};

#[cfg(test)]
use std::cell::Cell;

use crucible_campaign::{
    CampaignArchiveCheckpointResolver, CampaignArchiveManifestId, CampaignArchivePlan,
    CampaignArchiveTransferReport, CampaignFactId, CampaignName, CampaignRepository,
    CampaignRepositoryError, ConfigurationId,
};
use crucible_store::content_store::{ContentId, DurabilityRequirement, StoreError};
use rustix::fs::{FlockOperation, flock};
use thiserror::Error;

use crate::exact_pin_retention::authenticate_archive_checkpoint;
use crate::{
    DirectoryExactPinMaterializationStore, ExactCheckpointStore, ExactCheckpointStoreError,
    ExactPinMaterializationSelection, ExactPinRetentionAdmin, ExactPinRetentionError,
    ExactPinRetentionFence,
};

#[cfg(test)]
mod tests;

mod journal_io;
use journal_io::{
    cleanup_staging, create_child_directory, create_journal_directory, hash_field, io_error,
    read_bounded_file, sync_directory, write_atomic, write_new_file,
};
#[cfg(test)]
use journal_io::{fail_directory_sync_after, fail_next_directory_sync};

mod record;
use record::{TransferHeader, TransferPage, TransferPagesDigest, encode_record};

const WRITER_LOCK: &str = "writer.lock";
const RECORDS_DIRECTORY: &str = "records";
const STAGING_DIRECTORY: &str = "staging";
const HEADER_FILE: &str = "header";
const PAGE_FILE_PREFIX: &str = "page-";
// Incomplete operations one journal retains at once; each record is paged.
const MAX_TRANSFER_RECORDS: usize = 65_536;
// Bound on one header or page file. A full page of 4,096 entries encodes to
// a few hundred KiB, so this frames a file without limiting archive size.
const MAX_TRANSFER_RECORD_BYTES: u64 = 16 * 1024 * 1024;

// Directory syncs to let pass before the next one fails; `None` fails none.
#[cfg(test)]
thread_local! {
    static FAIL_DIRECTORY_SYNC_AFTER: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Identity of one destination- and publication-bound transfer operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignTransferOperationId([u8; 32]);

impl CampaignTransferOperationId {
    /// Derives an operation identity from immutable content and destination intent.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError::InvalidOperation`] when any
    /// operational name is empty or exceeds 1,024 bytes.
    pub fn for_archive(
        manifest: CampaignArchiveManifestId,
        destination_identity: &str,
        archive_name: &str,
        campaign_name: Option<&str>,
        destination_durability: DurabilityRequirement,
    ) -> Result<Self, CampaignTransferJournalError> {
        if destination_identity.is_empty()
            || destination_identity.len() > 1_024
            || archive_name.is_empty()
            || archive_name.len() > 1_024
            || campaign_name.is_some_and(|name| name.is_empty() || name.len() > 1_024)
        {
            return Err(CampaignTransferJournalError::InvalidOperation);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.campaign.transfer-operation.v1");
        hash_field(&mut hasher, manifest.content_id().encode().as_bytes());
        hash_field(&mut hasher, destination_identity.as_bytes());
        hash_field(&mut hasher, archive_name.as_bytes());
        hash_field(&mut hasher, campaign_name.unwrap_or("").as_bytes());
        hasher.update(
            &destination_durability
                .minimum_durable_placements()
                .to_be_bytes(),
        );
        hasher.update(&[u8::from(destination_durability.allows_deferred_write())]);
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    /// Renders the canonical lowercase operation identity.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}

/// Terminal authenticated durability receipt for one archive publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignArchiveDurabilityReceipt {
    operation: CampaignTransferOperationId,
    manifest: CampaignArchiveManifestId,
    requirement: DurabilityRequirement,
    transfer: CampaignArchiveTransferReport,
}

impl CampaignArchiveDurabilityReceipt {
    /// Returns the destination- and publication-bound transfer identity.
    #[must_use]
    pub const fn operation(self) -> CampaignTransferOperationId {
        self.operation
    }

    /// Returns the authenticated archive manifest published by the transfer.
    #[must_use]
    pub const fn manifest(self) -> CampaignArchiveManifestId {
        self.manifest
    }

    /// Returns the exact destination durability requirement.
    #[must_use]
    pub const fn requirement(self) -> DurabilityRequirement {
        self.requirement
    }

    /// Returns the verified missing-object transfer counters and placement floor.
    #[must_use]
    pub const fn transfer(self) -> CampaignArchiveTransferReport {
        self.transfer
    }
}

/// Direct object root protected by an incomplete archive transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CampaignTransferRetentionRoot {
    id: ContentId,
    logical_length: u64,
}

impl CampaignTransferRetentionRoot {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(id: ContentId, logical_length: u64) -> Self {
        Self { id, logical_length }
    }

    /// Returns the protected logical object identity.
    #[must_use]
    pub const fn id(self) -> ContentId {
        self.id
    }

    /// Returns its authenticated source logical length.
    #[must_use]
    pub const fn logical_length(self) -> u64 {
        self.logical_length
    }
}

/// Digest of one complete transfer-journal inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignTransferRetentionGeneration([u8; 32]);

impl CampaignTransferRetentionGeneration {
    #[cfg(test)]
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Terminal summary of one transfer-root inventory pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignTransferRetentionSummary {
    generation: CampaignTransferRetentionGeneration,
    records: u64,
    roots: u64,
}

impl CampaignTransferRetentionSummary {
    #[cfg(test)]
    pub(crate) const fn new(
        generation: CampaignTransferRetentionGeneration,
        records: u64,
        roots: u64,
    ) -> Self {
        Self {
            generation,
            records,
            roots,
        }
    }

    /// Returns the digest of exact record bytes in canonical filename order.
    #[must_use]
    pub const fn generation(self) -> CampaignTransferRetentionGeneration {
        self.generation
    }

    /// Returns the number of incomplete transfer records.
    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }

    /// Returns the number of direct root visits, including duplicates.
    #[must_use]
    pub const fn roots(self) -> u64 {
        self.roots
    }
}

/// Exclusive stable view of incomplete transfer roots.
pub trait CampaignTransferRetentionFence {
    /// Visits every direct retained object and returns a terminal generation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] for corrupt inventory, a
    /// visitor failure, bounds exhaustion, or filesystem I/O failure.
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(CampaignTransferRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<CampaignTransferRetentionSummary, CampaignTransferJournalError>;
}

/// Maintenance capability for incomplete archive-transfer roots.
pub trait CampaignTransferRetentionAdmin: Send + Sync {
    /// Acquires a stable transfer-root inventory fence.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] when inventory authority or
    /// journal validation fails.
    fn acquire_campaign_transfer_retention_fence(
        &self,
    ) -> Result<Box<dyn CampaignTransferRetentionFence + '_>, CampaignTransferJournalError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferJournalRole {
    Source,
    Destination,
}

/// Restart-safe single-writer transfer-root journal namespace.
#[derive(Clone)]
pub struct DirectoryCampaignTransferJournal {
    inner: Arc<DirectoryCampaignTransferJournalInner>,
}

struct DirectoryCampaignTransferJournalInner {
    root: PathBuf,
    writer_lock: File,
    lifecycle: RwLock<()>,
}

impl Drop for DirectoryCampaignTransferJournalInner {
    fn drop(&mut self) {
        let _ = flock(&self.writer_lock, FlockOperation::Unlock);
    }
}

impl DirectoryCampaignTransferJournal {
    /// Opens or creates one durable transfer-journal namespace.
    ///
    /// Opening removes staging files and incomplete records left by an
    /// interrupted writer, then validates every complete record's header.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] when the namespace cannot be
    /// created, exclusively locked, fsynced, or validated within bounds.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CampaignTransferJournalError> {
        let root = root.into();
        create_journal_directory(&root)?;
        create_child_directory(&root, RECORDS_DIRECTORY)?;
        create_child_directory(&root, STAGING_DIRECTORY)?;
        let lock_path = root.join(WRITER_LOCK);
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_error("open-transfer-journal-lock", &lock_path, source))?;
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            io_error("lock-transfer-journal", &lock_path, io::Error::from(source))
        })?;
        let journal = Self {
            inner: Arc::new(DirectoryCampaignTransferJournalInner {
                root,
                writer_lock,
                lifecycle: RwLock::new(()),
            }),
        };
        cleanup_staging(&journal.inner.root.join(STAGING_DIRECTORY))?;
        let mut removed_incomplete = false;
        for (_, directory) in journal.record_directories()? {
            if read_record_header(&directory, None)?.is_none() {
                removed_incomplete |= remove_record_directory(&directory)?;
            }
        }
        if removed_incomplete {
            sync_directory(&journal.inner.root.join(RECORDS_DIRECTORY))?;
        }
        journal.validate_records()?;
        Ok(journal)
    }

    /// Durably records the plan's direct objects before copying starts.
    ///
    /// Pages are written and fsynced first; the header is renamed into place
    /// last, so a record is visible only when complete. Repeating a visible
    /// record rebuilds it from the plan and requires identical files.
    fn begin(
        &self,
        operation: CampaignTransferOperationId,
        role: TransferJournalRole,
        plan: &CampaignArchivePlan,
    ) -> Result<(), CampaignTransferJournalError> {
        let _lifecycle = self
            .inner
            .lifecycle
            .write()
            .map_err(|_| CampaignTransferJournalError::Poisoned)?;
        let directory = self.record_directory(operation);
        let header_path = directory.join(HEADER_FILE);
        match read_bounded_file(&header_path) {
            Ok(existing) => {
                let header = encode_record(operation, role, plan, &mut |index, bytes| {
                    if read_bounded_file(&directory.join(page_file_name(index)))? != bytes {
                        return Err(CampaignTransferJournalError::RecordMismatch);
                    }
                    Ok(())
                })?;
                if header.canonical_bytes()? != existing {
                    return Err(CampaignTransferJournalError::RecordMismatch);
                }
                sync_directory(&directory)?;
                return sync_directory(&self.inner.root.join(RECORDS_DIRECTORY));
            }
            Err(CampaignTransferJournalError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(source),
        }

        let operation_name = operation.to_hex();
        let other_records = self
            .record_directories()?
            .iter()
            .filter(|(name, _)| *name != operation_name)
            .count();
        if other_records >= MAX_TRANSFER_RECORDS {
            return Err(CampaignTransferJournalError::RecordLimit);
        }
        // An earlier attempt may have left pages without a header; the
        // records-directory sync below also makes that removal durable.
        remove_record_directory(&directory)?;
        fs::create_dir(&directory)
            .map_err(|source| io_error("create-transfer-record", &directory, source))?;
        sync_directory(&self.inner.root.join(RECORDS_DIRECTORY))?;
        let header = encode_record(operation, role, plan, &mut |index, bytes| {
            write_new_file(&directory.join(page_file_name(index)), bytes)
        })?;
        sync_directory(&directory)?;
        write_atomic(
            &self.inner.root.join(STAGING_DIRECTORY),
            &operation_name,
            &header_path,
            &header.canonical_bytes()?,
        )
    }

    /// Returns whether a manifest retains incomplete transfer ownership.
    ///
    /// Only the record header is read.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] if the header is malformed or unreadable.
    pub fn contains(
        &self,
        operation: CampaignTransferOperationId,
    ) -> Result<bool, CampaignTransferJournalError> {
        let _lifecycle = self
            .inner
            .lifecycle
            .read()
            .map_err(|_| CampaignTransferJournalError::Poisoned)?;
        Ok(read_record_header(&self.record_directory(operation), Some(operation))?.is_some())
    }

    /// Removes one completed transfer root after destination publication.
    ///
    /// The header is removed first, so the record stops protecting its
    /// objects before its pages are deleted.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] when an existing header is
    /// corrupt or durable removal cannot complete.
    pub fn complete(
        &self,
        operation: CampaignTransferOperationId,
    ) -> Result<(), CampaignTransferJournalError> {
        let _lifecycle = self
            .inner
            .lifecycle
            .write()
            .map_err(|_| CampaignTransferJournalError::Poisoned)?;
        let directory = self.record_directory(operation);
        if read_record_header(&directory, Some(operation))?.is_some() {
            let header_path = directory.join(HEADER_FILE);
            fs::remove_file(&header_path)
                .map_err(|source| io_error("remove-transfer-record", &header_path, source))?;
            sync_directory(&directory)?;
        }
        // Syncing even when nothing remains re-establishes the durability of
        // a removal whose earlier sync failed.
        remove_record_directory(&directory)?;
        sync_directory(&self.inner.root.join(RECORDS_DIRECTORY))
    }

    fn record_directory(&self, operation: CampaignTransferOperationId) -> PathBuf {
        self.inner
            .root
            .join(RECORDS_DIRECTORY)
            .join(operation.to_hex())
    }

    /// Lists record directories, complete or not, in canonical name order.
    fn record_directories(&self) -> Result<Vec<(String, PathBuf)>, CampaignTransferJournalError> {
        let records = self.inner.root.join(RECORDS_DIRECTORY);
        let mut result = Vec::new();
        for entry in fs::read_dir(&records)
            .map_err(|source| io_error("read-transfer-records", &records, source))?
        {
            if result.len() >= MAX_TRANSFER_RECORDS {
                return Err(CampaignTransferJournalError::RecordLimit);
            }
            let entry =
                entry.map_err(|source| io_error("read-transfer-record", &records, source))?;
            let file_type = entry
                .file_type()
                .map_err(|source| io_error("stat-transfer-record", &entry.path(), source))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CampaignTransferJournalError::UnexpectedEntry)?;
            if !file_type.is_dir() || !is_operation_name(&name) {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
            result.push((name, entry.path()));
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(result)
    }

    /// Validates every complete record's header and file set.
    ///
    /// Page contents are authenticated when a GC fence visits them or a
    /// retried `begin` compares them, not here, so validation reads one
    /// header per record.
    fn validate_records(&self) -> Result<(), CampaignTransferJournalError> {
        for (name, directory) in self.record_directories()? {
            let Some(header) = read_record_header(&directory, None)? else {
                continue;
            };
            if header.operation.to_hex() != name {
                return Err(CampaignTransferJournalError::RecordMismatch);
            }
            validate_record_files(&directory, header.page_count)?;
        }
        Ok(())
    }
}

impl CampaignTransferRetentionAdmin for DirectoryCampaignTransferJournal {
    fn acquire_campaign_transfer_retention_fence(
        &self,
    ) -> Result<Box<dyn CampaignTransferRetentionFence + '_>, CampaignTransferJournalError> {
        let lifecycle = self
            .inner
            .lifecycle
            .read()
            .map_err(|_| CampaignTransferJournalError::Poisoned)?;
        self.validate_records()?;
        Ok(Box::new(DirectoryTransferRetentionFence {
            journal: self,
            _lifecycle: lifecycle,
        }))
    }
}

struct DirectoryTransferRetentionFence<'a> {
    journal: &'a DirectoryCampaignTransferJournal,
    _lifecycle: RwLockReadGuard<'a, ()>,
}

impl CampaignTransferRetentionFence for DirectoryTransferRetentionFence<'_> {
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(CampaignTransferRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<CampaignTransferRetentionSummary, CampaignTransferJournalError> {
        let mut generation = blake3::Hasher::new();
        let mut records = 0_u64;
        let mut roots = 0_u64;
        for (name, directory) in self.journal.record_directories()? {
            // The fence excludes writers, so a headerless directory is an
            // interrupted removal that protects nothing.
            let Some(header) = read_record_header(&directory, None)? else {
                continue;
            };
            if header.operation.to_hex() != name {
                return Err(CampaignTransferJournalError::RecordMismatch);
            }
            hash_field(&mut generation, name.as_bytes());
            hash_field(&mut generation, &header.canonical_bytes()?);

            // Pages are read, authenticated, and visited one at a time.
            let mut pages_digest = TransferPagesDigest::new();
            for index in 0..header.page_count {
                let bytes = read_bounded_file(&directory.join(page_file_name(index)))?;
                let page = TransferPage::from_canonical_bytes(&bytes, &header, index)?;
                hash_field(&mut generation, &bytes);
                pages_digest.update(&bytes);
                for root in page.objects {
                    visitor(root).map_err(CampaignTransferJournalError::Visitor)?;
                    roots = roots
                        .checked_add(1)
                        .ok_or(CampaignTransferJournalError::ObjectLimit)?;
                }
            }
            if pages_digest.finish() != header.pages_digest {
                return Err(CampaignTransferJournalError::Corrupt);
            }
            records += 1;
        }
        Ok(CampaignTransferRetentionSummary {
            generation: CampaignTransferRetentionGeneration(*generation.finalize().as_bytes()),
            records,
            roots,
        })
    }
}

/// Reads a record's header, or `None` when the record has no header.
fn read_record_header(
    directory: &Path,
    expected: Option<CampaignTransferOperationId>,
) -> Result<Option<TransferHeader>, CampaignTransferJournalError> {
    match read_bounded_file(&directory.join(HEADER_FILE)) {
        Ok(bytes) => TransferHeader::from_canonical_bytes(&bytes, expected).map(Some),
        Err(CampaignTransferJournalError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(source) => Err(source),
    }
}

/// Requires exactly the header and pages `0..page_count` in a record.
fn validate_record_files(
    directory: &Path,
    page_count: u32,
) -> Result<(), CampaignTransferJournalError> {
    let mut entries = 0_u64;
    for entry in fs::read_dir(directory)
        .map_err(|source| io_error("read-transfer-record", directory, source))?
    {
        let entry = entry.map_err(|source| io_error("read-transfer-record", directory, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CampaignTransferJournalError::UnexpectedEntry)?;
        let is_file = entry
            .file_type()
            .map_err(|source| io_error("stat-transfer-record", &entry.path(), source))?
            .is_file();
        let expected =
            name == HEADER_FILE || page_file_index(&name).is_some_and(|index| index < page_count);
        if !is_file || !expected {
            return Err(CampaignTransferJournalError::UnexpectedEntry);
        }
        entries += 1;
    }
    if entries != u64::from(page_count) + 1 {
        return Err(CampaignTransferJournalError::Corrupt);
    }
    Ok(())
}

/// Removes a record directory and its files, returning whether it existed.
///
/// The caller syncs the records directory to make the removal durable.
fn remove_record_directory(directory: &Path) -> Result<bool, CampaignTransferJournalError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error("read-transfer-record", directory, source)),
    };
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read-transfer-record", directory, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CampaignTransferJournalError::UnexpectedEntry)?;
        if name != HEADER_FILE && page_file_index(&name).is_none() {
            return Err(CampaignTransferJournalError::UnexpectedEntry);
        }
        fs::remove_file(entry.path())
            .map_err(|source| io_error("remove-transfer-page", &entry.path(), source))?;
    }
    fs::remove_dir(directory)
        .map_err(|source| io_error("remove-transfer-record", directory, source))?;
    Ok(true)
}

fn page_file_name(index: u32) -> String {
    format!("{PAGE_FILE_PREFIX}{index:08x}")
}

fn page_file_index(name: &str) -> Option<u32> {
    let digits = name.strip_prefix(PAGE_FILE_PREFIX)?;
    if digits.len() != 8
        || !digits
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

fn is_operation_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Prepared-service capability for one GC-registered archive transfer endpoint.
///
/// Construction is restricted to the managed campaign-service owner. This
/// binds every durable transfer to the same journal that its ordinary GC path
/// inventories, so an incomplete copy cannot be made invisible to GC by
/// supplying an unrelated journal directory.
pub struct CampaignArchiveTransferEndpoint<'a> {
    repository: &'a CampaignRepository,
    journal: &'a mut DirectoryCampaignTransferJournal,
    identity: &'a str,
    writable: bool,
    checkpoints: Option<&'a ExactCheckpointStore>,
    exact_pins: Option<&'a mut DirectoryExactPinMaterializationStore>,
}

impl<'a> CampaignArchiveTransferEndpoint<'a> {
    pub(crate) fn new(
        repository: &'a CampaignRepository,
        journal: &'a mut DirectoryCampaignTransferJournal,
        identity: &'a str,
        writable: bool,
    ) -> Self {
        Self {
            repository,
            journal,
            identity,
            writable,
            checkpoints: None,
            exact_pins: None,
        }
    }

    pub(crate) fn new_with_operational_checkpoints(
        repository: &'a CampaignRepository,
        journal: &'a mut DirectoryCampaignTransferJournal,
        identity: &'a str,
        writable: bool,
        checkpoints: &'a ExactCheckpointStore,
        exact_pins: &'a mut DirectoryExactPinMaterializationStore,
    ) -> Self {
        Self {
            repository,
            journal,
            identity,
            writable,
            checkpoints: Some(checkpoints),
            exact_pins: Some(exact_pins),
        }
    }
}

/// Exact-pin resolver backed by the durable selection catalog and checkpoint store.
pub struct ExactPinCampaignArchiveCheckpointResolver<'a> {
    repository: &'a CampaignRepository,
    checkpoints: &'a ExactCheckpointStore,
    campaign: CampaignName,
    fence: Box<dyn ExactPinRetentionFence + 'a>,
}

impl<'a> ExactPinCampaignArchiveCheckpointResolver<'a> {
    /// Acquires exact selection authority for one source campaign.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when the catalog cannot be fenced.
    pub fn new(
        repository: &'a CampaignRepository,
        checkpoints: &'a ExactCheckpointStore,
        campaign: CampaignName,
        selections: &'a mut dyn ExactPinRetentionAdmin,
    ) -> Result<Self, ExactPinRetentionError> {
        let fence = selections.acquire_exact_pin_retention_fence()?;
        Ok(Self {
            repository,
            checkpoints,
            campaign,
            fence,
        })
    }
}

impl CampaignArchiveCheckpointResolver for ExactPinCampaignArchiveCheckpointResolver<'_> {
    fn resolve_checkpoint(
        &mut self,
        configuration: ConfigurationId,
        pin_fact: CampaignFactId,
    ) -> Result<crucible_campaign::ExactCheckpointId, CampaignRepositoryError> {
        let selection = self
            .fence
            .selection(&self.campaign, configuration)
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "campaign-archive-exact-pin-selection-unavailable",
            })?
            .ok_or(CampaignRepositoryError::Integrity {
                reason: "campaign-archive-exact-pin-materialization-missing",
            })?;
        if selection.campaign() != &self.campaign
            || selection.configuration() != configuration
            || selection.pin_fact() != pin_fact
        {
            return Err(CampaignRepositoryError::Integrity {
                reason: "campaign-archive-exact-pin-selection-mismatch",
            });
        }
        selection
            .authenticate_current(self.repository, self.checkpoints)
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "campaign-archive-exact-checkpoint-invalid",
            })?;
        Ok(selection.checkpoint())
    }
}

/// Executes one restart-safe archive copy and transfers retention to destination refs.
///
/// The source journal is durable before the destination journal. No repository
/// or journal fence spans both sides. The destination archive ref is published
/// only after every object and direct inventory authenticate there. An optional
/// ordinary campaign ref is accepted only for an executable or mirror archive.
///
/// # Errors
///
/// Returns [`CampaignArchiveTransferError`] when journaling, copying,
/// inspection, ref publication, or durable ownership removal fails.
pub fn transfer_campaign_archive_durably(
    source: &mut CampaignArchiveTransferEndpoint<'_>,
    destination: &mut CampaignArchiveTransferEndpoint<'_>,
    plan: &CampaignArchivePlan,
    archive_name: &str,
    campaign_name: Option<&str>,
    destination_durability: DurabilityRequirement,
) -> Result<CampaignArchiveDurabilityReceipt, CampaignArchiveTransferError> {
    if !source.writable {
        return Err(CampaignArchiveTransferError::SourceReadOnly);
    }
    if !destination.writable {
        return Err(CampaignArchiveTransferError::DestinationReadOnly);
    }
    destination
        .repository
        .validate_campaign_archive_publication_intent(
            archive_name,
            campaign_name,
            plan.manifest().policy(),
        )?;
    if let Some(campaign_name) = campaign_name {
        match destination.repository.head(campaign_name) {
            Ok(current) if current.snapshot_id() == plan.manifest().source_snapshot() => {}
            Ok(current) => {
                return Err(CampaignArchiveTransferError::DestinationCampaignConflict {
                    current: current.snapshot_id(),
                    imported: plan.manifest().source_snapshot(),
                });
            }
            Err(CampaignRepositoryError::NotFound) => {}
            Err(source) => return Err(source.into()),
        }
    }
    let checkpoint_selections = plan.manifest().checkpoint_selections();
    if !checkpoint_selections.is_empty() && destination.checkpoints.is_none() {
        return Err(CampaignArchiveTransferError::CheckpointStoreUnavailable);
    }
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        destination.identity,
        archive_name,
        campaign_name,
        destination_durability,
    )?;
    {
        let _source_gc = source.repository.acquire_gc_exclusion_guard()?;
        source
            .journal
            .begin(operation, TransferJournalRole::Source, plan)?;
        source.repository.stage_campaign_archive_metadata(plan)?;
    }
    {
        let _destination_gc = destination.repository.acquire_gc_exclusion_guard()?;
        destination
            .journal
            .begin(operation, TransferJournalRole::Destination, plan)?;
    }

    let report = source.repository.transfer_campaign_archive_objects(
        destination.repository,
        plan,
        destination_durability,
    )?;
    if let Some(checkpoints) = destination.checkpoints {
        let destination_campaign = campaign_name
            .map(CampaignName::new)
            .transpose()
            .map_err(ExactPinRetentionError::from)?;
        let mut prepared = Vec::with_capacity(checkpoint_selections.len());
        for selection in checkpoint_selections {
            if let Some(campaign) = destination_campaign.as_ref() {
                prepared.push(
                    ExactPinMaterializationSelection::prepare_at_snapshot(
                        destination.repository,
                        checkpoints,
                        campaign,
                        plan.manifest().source_snapshot(),
                        selection.configuration(),
                        selection.pin_fact(),
                        selection.checkpoint(),
                    )
                    .map_err(map_archive_exact_pin_error)?,
                );
            } else {
                authenticate_archive_checkpoint(
                    destination.repository,
                    checkpoints,
                    plan.manifest().source_snapshot(),
                    selection.configuration(),
                    selection.pin_fact(),
                    selection.checkpoint(),
                )
                .map_err(map_archive_exact_pin_error)?;
            }
        }
        if !prepared.is_empty() && destination.exact_pins.is_none() {
            return Err(CampaignArchiveTransferError::ExactPinStoreUnavailable);
        }
        if let Some(exact_pins) = destination.exact_pins.as_deref_mut() {
            for selection in prepared {
                exact_pins.select_import_if_absent(selection)?;
            }
        }
    }
    destination
        .repository
        .publish_campaign_archive(archive_name, None, plan)?;
    if let Some(campaign_name) = campaign_name {
        destination.repository.publish_transferred_campaign(
            campaign_name,
            None,
            plan.manifest_id(),
        )?;
    }
    destination.journal.complete(operation)?;
    source.journal.complete(operation)?;
    Ok(CampaignArchiveDurabilityReceipt {
        operation,
        manifest: plan.manifest_id(),
        requirement: destination_durability,
        transfer: report,
    })
}

fn map_archive_exact_pin_error(error: ExactPinRetentionError) -> CampaignArchiveTransferError {
    match error {
        ExactPinRetentionError::CheckpointConfigurationMismatch { .. } => {
            CampaignArchiveTransferError::CheckpointConfigurationMismatch
        }
        error => CampaignArchiveTransferError::ExactPin(error),
    }
}

/// Failure to journal, transfer, publish, or retire one campaign archive.
#[derive(Debug, Error)]
pub enum CampaignArchiveTransferError {
    /// The selected source deployment does not permit journal or metadata mutation.
    #[error("campaign archive transfer source is read-only")]
    SourceReadOnly,
    /// The selected destination deployment does not permit mutation.
    #[error("campaign archive transfer destination is read-only")]
    DestinationReadOnly,
    /// The destination campaign name already belongs to another snapshot.
    #[error("destination campaign already names {current}, cannot import {imported}")]
    DestinationCampaignConflict {
        /// Existing destination campaign snapshot preserved by the preflight.
        current: crucible_campaign::CampaignSnapshotId,
        /// Source snapshot requested by this transfer.
        imported: crucible_campaign::CampaignSnapshotId,
    },
    /// An executable archive has exact selections but no destination checkpoint verifier.
    #[error("campaign archive transfer destination has no exact-checkpoint store")]
    CheckpointStoreUnavailable,
    /// An ordinary executable import cannot persist its exact-pin selections.
    #[error("campaign archive transfer destination has no exact-pin materialization store")]
    ExactPinStoreUnavailable,
    /// A destination checkpoint materializes another configuration than its manifest selection.
    #[error("campaign archive transfer checkpoint configuration does not match its manifest")]
    CheckpointConfigurationMismatch,
    /// Imported exact-pin materialization or production resume validation failed.
    #[error(transparent)]
    ExactPin(#[from] ExactPinRetentionError),
    /// Destination exact-checkpoint authentication failed.
    #[error(transparent)]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// Campaign repository validation, storage, or ref publication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Durable transfer-root ownership failed.
    #[error(transparent)]
    Journal(#[from] CampaignTransferJournalError),
}

/// Failure to persist or inventory transfer-root ownership.
#[derive(Debug, Error)]
pub enum CampaignTransferJournalError {
    /// A journal filesystem operation failed.
    #[error("campaign transfer journal operation {operation} failed for {path}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying failure.
        #[source]
        source: io::Error,
    },
    /// A record failed checksum or canonical decoding.
    #[error("campaign transfer journal record is corrupt")]
    Corrupt,
    /// A record filename or preexisting manifest binding disagreed.
    #[error("campaign transfer journal record binding is inconsistent")]
    RecordMismatch,
    /// The record namespace exceeds its bounded file count.
    #[error("campaign transfer journal record limit exceeded")]
    RecordLimit,
    /// A plan protects no object, or a record or one of its files exceeds
    /// its format bound.
    #[error("campaign transfer journal object limit exceeded")]
    ObjectLimit,
    /// The record directory contains an unexpected entry.
    #[error("campaign transfer journal contains an unexpected entry")]
    UnexpectedEntry,
    /// Transfer destination identity or intended ref name is invalid.
    #[error("campaign transfer operation identity input is invalid")]
    InvalidOperation,
    /// A GC retention visitor rejected one root.
    #[error("campaign transfer retention visitor failed")]
    Visitor(#[source] StoreError),
    /// The archive plan's spooled inventory could not be replayed.
    #[error("campaign transfer plan inventory could not be replayed")]
    Plan(#[from] CampaignRepositoryError),
    /// The shared in-process journal lifecycle lock was poisoned.
    #[error("campaign transfer journal lifecycle lock is poisoned")]
    Poisoned,
}
