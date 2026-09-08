//! Restart-safe campaign archive transfer ownership and orchestration.
//!
//! Source and destination journals retain the same direct object inventory
//! before copying starts. The records are independent, so no operation holds
//! both repositories' GC fences or journal mutations at once.
//!
//! ```text
//! <root>/writer.lock
//! <root>/records/<operation-id>.transfer
//!   TransferRecordV1(operation, source|destination, manifest, [(object, length)...])
//! <root>/staging/<operation-id>.staging
//! ```
//!
//! A record becomes visible by file sync, rename, and directory sync. GC holds
//! the journal fence while treating every recorded object as a direct root.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::cell::Cell;

use crucible_campaign::{
    CampaignArchiveCheckpointResolver, CampaignArchiveManifestId, CampaignArchivePlan,
    CampaignArchiveTransferReport, CampaignFactId, CampaignName, CampaignRepository,
    CampaignRepositoryError, ConfigurationId,
};
use crucible_cas::content_store::{ContentId, DurabilityRequirement, StoreError};
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

const JOURNAL_MAGIC: &[u8; 32] = b"CRUCIBLE-CAMPAIGN-TRANSFER-V1!!!";
const JOURNAL_VERSION: u32 = 1;
const WRITER_LOCK: &str = "writer.lock";
const RECORDS_DIRECTORY: &str = "records";
const STAGING_DIRECTORY: &str = "staging";
const MAX_TRANSFER_OBJECTS: usize = 65_536;
const MAX_TRANSFER_RECORDS: usize = 65_536;
const MAX_TRANSFER_RECORD_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_DIRECTORY_SYNC: Cell<bool> = const { Cell::new(false) };
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
pub struct DirectoryCampaignTransferJournal {
    root: PathBuf,
    writer_lock: File,
}

impl Drop for DirectoryCampaignTransferJournal {
    fn drop(&mut self) {
        let _ = flock(&self.writer_lock, FlockOperation::Unlock);
    }
}

impl DirectoryCampaignTransferJournal {
    /// Opens or creates one durable transfer-journal namespace.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] when the namespace cannot be
    /// created, exclusively locked, fsynced, or fully validated within bounds.
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
        let journal = Self { root, writer_lock };
        cleanup_staging(&journal.root.join(STAGING_DIRECTORY))?;
        journal.visit_records(&mut |_, _| Ok(()))?;
        Ok(journal)
    }

    fn begin(
        &mut self,
        operation: CampaignTransferOperationId,
        role: TransferJournalRole,
        plan: &CampaignArchivePlan,
    ) -> Result<(), CampaignTransferJournalError> {
        let objects = plan.transfer_objects();
        if objects.is_empty() || objects.len() > MAX_TRANSFER_OBJECTS {
            return Err(CampaignTransferJournalError::ObjectLimit);
        }
        let record = TransferRecord::new(operation, role, plan.manifest_id(), objects)?;
        let bytes = record.canonical_bytes()?;
        let path = self.record_path(operation);
        match read_bounded_file(&path) {
            Ok(existing) if existing == bytes => {
                return sync_directory(&self.root.join(RECORDS_DIRECTORY));
            }
            Ok(_) => return Err(CampaignTransferJournalError::RecordMismatch),
            Err(CampaignTransferJournalError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(source),
        }
        if self.record_paths()?.len() >= MAX_TRANSFER_RECORDS {
            return Err(CampaignTransferJournalError::RecordLimit);
        }
        write_atomic(&path, &bytes)
    }

    /// Returns whether a manifest retains incomplete transfer ownership.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] if the record is malformed or unreadable.
    pub fn contains(
        &self,
        operation: CampaignTransferOperationId,
    ) -> Result<bool, CampaignTransferJournalError> {
        let path = self.record_path(operation);
        match read_bounded_file(&path) {
            Ok(bytes) => {
                TransferRecord::from_canonical_bytes(&bytes, operation)?;
                Ok(true)
            }
            Err(CampaignTransferJournalError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(source) => Err(source),
        }
    }

    /// Removes one completed transfer root after destination publication.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignTransferJournalError`] when an existing record is
    /// corrupt or durable removal cannot complete.
    pub fn complete(
        &mut self,
        operation: CampaignTransferOperationId,
    ) -> Result<(), CampaignTransferJournalError> {
        let path = self.record_path(operation);
        match read_bounded_file(&path) {
            Ok(bytes) => {
                TransferRecord::from_canonical_bytes(&bytes, operation)?;
                fs::remove_file(&path)
                    .map_err(|source| io_error("remove-transfer-record", &path, source))?;
                sync_directory(&self.root.join(RECORDS_DIRECTORY))
            }
            Err(CampaignTransferJournalError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                sync_directory(&self.root.join(RECORDS_DIRECTORY))
            }
            Err(source) => Err(source),
        }
    }

    fn record_path(&self, operation: CampaignTransferOperationId) -> PathBuf {
        self.root
            .join(RECORDS_DIRECTORY)
            .join(format!("{}.transfer", operation.to_hex()))
    }

    fn record_paths(&self) -> Result<Vec<(String, PathBuf)>, CampaignTransferJournalError> {
        let records = self.root.join(RECORDS_DIRECTORY);
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
            if !file_type.is_file() {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CampaignTransferJournalError::UnexpectedEntry)?;
            if !name.ends_with(".transfer") {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
            result.push((name, entry.path()));
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(result)
    }

    fn visit_records(
        &self,
        visitor: &mut dyn FnMut(&str, &TransferRecord) -> Result<(), CampaignTransferJournalError>,
    ) -> Result<(), CampaignTransferJournalError> {
        for (name, path) in self.record_paths()? {
            let bytes = read_bounded_file(&path)?;
            let record = TransferRecord::from_canonical_bytes_unbound(&bytes)?;
            let expected = format!("{}.transfer", record.operation.to_hex());
            if name != expected {
                return Err(CampaignTransferJournalError::RecordMismatch);
            }
            visitor(&name, &record)?;
        }
        Ok(())
    }
}

impl CampaignTransferRetentionAdmin for DirectoryCampaignTransferJournal {
    fn acquire_campaign_transfer_retention_fence(
        &self,
    ) -> Result<Box<dyn CampaignTransferRetentionFence + '_>, CampaignTransferJournalError> {
        self.visit_records(&mut |_, _| Ok(()))?;
        Ok(Box::new(DirectoryTransferRetentionFence { journal: self }))
    }
}

struct DirectoryTransferRetentionFence<'a> {
    journal: &'a DirectoryCampaignTransferJournal,
}

impl CampaignTransferRetentionFence for DirectoryTransferRetentionFence<'_> {
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(CampaignTransferRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<CampaignTransferRetentionSummary, CampaignTransferJournalError> {
        let paths = self.journal.record_paths()?;
        let mut hasher = blake3::Hasher::new();
        let mut roots = 0_u64;
        for (name, path) in &paths {
            let bytes = read_bounded_file(path)?;
            hasher.update(&(name.len() as u64).to_be_bytes());
            hasher.update(name.as_bytes());
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
            let record = TransferRecord::from_canonical_bytes_unbound(&bytes)?;
            if *name != format!("{}.transfer", record.operation.to_hex()) {
                return Err(CampaignTransferJournalError::RecordMismatch);
            }
            for root in record.objects {
                visitor(root).map_err(CampaignTransferJournalError::Visitor)?;
                roots = roots
                    .checked_add(1)
                    .ok_or(CampaignTransferJournalError::ObjectLimit)?;
            }
        }
        Ok(CampaignTransferRetentionSummary {
            generation: CampaignTransferRetentionGeneration(*hasher.finalize().as_bytes()),
            records: paths.len() as u64,
            roots,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransferRecord {
    operation: CampaignTransferOperationId,
    role: TransferJournalRole,
    manifest: CampaignArchiveManifestId,
    objects: Vec<CampaignTransferRetentionRoot>,
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

    pub(crate) fn new_with_checkpoints(
        repository: &'a CampaignRepository,
        journal: &'a mut DirectoryCampaignTransferJournal,
        identity: &'a str,
        writable: bool,
        checkpoints: &'a ExactCheckpointStore,
    ) -> Self {
        Self {
            repository,
            journal,
            identity,
            writable,
            checkpoints: Some(checkpoints),
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

impl TransferRecord {
    fn new(
        operation: CampaignTransferOperationId,
        role: TransferJournalRole,
        manifest: CampaignArchiveManifestId,
        objects: Vec<(ContentId, u64)>,
    ) -> Result<Self, CampaignTransferJournalError> {
        let objects = objects
            .into_iter()
            .map(|(id, logical_length)| CampaignTransferRetentionRoot { id, logical_length })
            .collect::<Vec<_>>();
        if objects.is_empty()
            || objects.len() > MAX_TRANSFER_OBJECTS
            || objects.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(CampaignTransferJournalError::ObjectLimit);
        }
        Ok(Self {
            operation,
            role,
            manifest,
            objects,
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CampaignTransferJournalError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JOURNAL_MAGIC);
        bytes.extend_from_slice(&JOURNAL_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.operation.0);
        bytes.push(match self.role {
            TransferJournalRole::Source => 0,
            TransferJournalRole::Destination => 1,
        });
        encode_content_id(self.manifest.content_id(), &mut bytes)?;
        bytes.extend_from_slice(&(self.objects.len() as u32).to_be_bytes());
        for object in &self.objects {
            encode_content_id(object.id, &mut bytes)?;
            bytes.extend_from_slice(&object.logical_length.to_be_bytes());
        }
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        if bytes.len() as u64 > MAX_TRANSFER_RECORD_BYTES {
            return Err(CampaignTransferJournalError::ObjectLimit);
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(
        bytes: &[u8],
        expected: CampaignTransferOperationId,
    ) -> Result<Self, CampaignTransferJournalError> {
        let record = Self::from_canonical_bytes_unbound(bytes)?;
        if record.operation != expected {
            return Err(CampaignTransferJournalError::RecordMismatch);
        }
        Ok(record)
    }

    fn from_canonical_bytes_unbound(bytes: &[u8]) -> Result<Self, CampaignTransferJournalError> {
        if bytes.len() < JOURNAL_MAGIC.len() + 4 + 32 + 1 + 4 + 4 + 32
            || bytes.len() as u64 > MAX_TRANSFER_RECORD_BYTES
        {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if blake3::hash(payload).as_bytes() != checksum {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let mut cursor = Cursor::new(payload);
        if cursor.take(JOURNAL_MAGIC.len())? != JOURNAL_MAGIC {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        if cursor.u32()? != JOURNAL_VERSION {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let operation = CampaignTransferOperationId(
            cursor
                .take(32)?
                .try_into()
                .map_err(|_| CampaignTransferJournalError::Corrupt)?,
        );
        let role = match cursor.u8()? {
            0 => TransferJournalRole::Source,
            1 => TransferJournalRole::Destination,
            _ => return Err(CampaignTransferJournalError::Corrupt),
        };
        let manifest_content = cursor.content_id()?;
        let manifest = CampaignArchiveManifestId::parse(&format!(
            "crucible.campaign.archive-manifest@{}",
            manifest_content
        ))
        .map_err(|_| CampaignTransferJournalError::Corrupt)?;
        let count = cursor.u32()? as usize;
        if count == 0 || count > MAX_TRANSFER_OBJECTS {
            return Err(CampaignTransferJournalError::ObjectLimit);
        }
        let mut objects = Vec::with_capacity(count);
        for _ in 0..count {
            objects.push(CampaignTransferRetentionRoot {
                id: cursor.content_id()?,
                logical_length: cursor.u64()?,
            });
        }
        if !cursor.is_eof() || objects.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let record = Self {
            operation,
            role,
            manifest,
            objects,
        };
        if record.canonical_bytes()? != bytes {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        Ok(record)
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
) -> Result<CampaignArchiveTransferReport, CampaignArchiveTransferError> {
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
    Ok(report)
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
    /// One transfer exceeds its bounded direct-object inventory.
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
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CampaignTransferJournalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CampaignTransferJournalError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignTransferJournalError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CampaignTransferJournalError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CampaignTransferJournalError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    fn u64(&mut self) -> Result<u64, CampaignTransferJournalError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    fn content_id(&mut self) -> Result<ContentId, CampaignTransferJournalError> {
        let length = self.u32()? as usize;
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| CampaignTransferJournalError::Corrupt)?;
        ContentId::parse(text).map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    const fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn encode_content_id(
    id: ContentId,
    bytes: &mut Vec<u8>,
) -> Result<(), CampaignTransferJournalError> {
    let encoded = id.encode();
    let length = u32::try_from(encoded.len()).map_err(|_| CampaignTransferJournalError::Corrupt)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(encoded.as_bytes());
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, CampaignTransferJournalError> {
    let file = File::open(path).map_err(|source| io_error("open-transfer-record", path, source))?;
    let length = file
        .metadata()
        .map_err(|source| io_error("stat-transfer-record", path, source))?
        .len();
    if length > MAX_TRANSFER_RECORD_BYTES {
        return Err(CampaignTransferJournalError::ObjectLimit);
    }
    let read_limit = MAX_TRANSFER_RECORD_BYTES
        .checked_add(1)
        .ok_or(CampaignTransferJournalError::ObjectLimit)?;
    let capacity = usize::try_from(length.min(read_limit))
        .map_err(|_| CampaignTransferJournalError::ObjectLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-transfer-record", path, source))?;
    if bytes.len() as u64 > MAX_TRANSFER_RECORD_BYTES {
        return Err(CampaignTransferJournalError::ObjectLimit);
    }
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CampaignTransferJournalError> {
    let root = path
        .parent()
        .and_then(Path::parent)
        .ok_or(CampaignTransferJournalError::Corrupt)?;
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or(CampaignTransferJournalError::Corrupt)?;
    let temporary = root.join(STAGING_DIRECTORY).join(format!("{stem}.staging"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| io_error("create-transfer-staging", &temporary, source))?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(io_error("write-transfer-staging", &temporary, source));
    }
    fs::rename(&temporary, path)
        .map_err(|source| io_error("rename-transfer-record", path, source))?;
    sync_directory(path.parent().ok_or(CampaignTransferJournalError::Corrupt)?)?;
    sync_directory(&root.join(STAGING_DIRECTORY))
}

fn create_journal_directory(path: &Path) -> Result<(), CampaignTransferJournalError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::metadata(path)
                .map_err(|source| io_error("stat-transfer-journal", path, source))?
                .is_dir()
            {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
        }
        Err(source) => return Err(io_error("create-transfer-journal", path, source)),
    }
    let parent = path.parent().ok_or(CampaignTransferJournalError::Corrupt)?;
    sync_directory(parent)
}

fn create_child_directory(root: &Path, name: &str) -> Result<(), CampaignTransferJournalError> {
    let path = root.join(name);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::metadata(&path)
                .map_err(|source| io_error("stat-transfer-directory", &path, source))?
                .is_dir()
            {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
        }
        Err(source) => return Err(io_error("create-transfer-directory", &path, source)),
    }
    sync_directory(root)
}

fn cleanup_staging(path: &Path) -> Result<(), CampaignTransferJournalError> {
    let mut entries = 0_usize;
    for entry in
        fs::read_dir(path).map_err(|source| io_error("read-transfer-staging", path, source))?
    {
        entries = entries
            .checked_add(1)
            .ok_or(CampaignTransferJournalError::RecordLimit)?;
        if entries > MAX_TRANSFER_RECORDS {
            return Err(CampaignTransferJournalError::RecordLimit);
        }
        let entry = entry.map_err(|source| io_error("read-transfer-staging", path, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CampaignTransferJournalError::UnexpectedEntry)?;
        let valid_name = name.strip_suffix(".staging").is_some_and(|stem| {
            stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        if !valid_name
            || !entry
                .file_type()
                .map_err(|source| io_error("stat-transfer-staging", &entry.path(), source))?
                .is_file()
        {
            return Err(CampaignTransferJournalError::UnexpectedEntry);
        }
        fs::remove_file(entry.path())
            .map_err(|source| io_error("remove-transfer-staging", path, source))?;
    }
    if entries != 0 {
        sync_directory(path)?;
    }
    Ok(())
}

fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn sync_directory(path: &Path) -> Result<(), CampaignTransferJournalError> {
    #[cfg(test)]
    if FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
        return Err(io_error(
            "sync-transfer-directory",
            path,
            io::Error::other("injected directory sync failure"),
        ));
    }
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync-transfer-directory", path, source))
}

#[cfg(test)]
fn fail_next_directory_sync() {
    FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.set(true));
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> CampaignTransferJournalError {
    CampaignTransferJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
