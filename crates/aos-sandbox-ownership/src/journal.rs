//! Private Ownership journal admission around shared native DATA mechanics.
//!
//! Only this issuer owns the fixed Ownership writer, currentness, history and
//! semantic publication. Broker's canonical/native machinery cannot construct
//! a signing owner or enter a paid operation. No raw journal is exported.

use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::{CanonicalNativeJournalV1, CanonicalReplayOriginalV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{ProtectedJournalLocation, ProtectedWriterNameWitness};
use aos_sandbox_journal::protected_storage::{
    WriterAcquisitionRetentionV1, WriterAcquisitionSlotsV1, acquire_writer_originals_v1,
};
use aos_sandbox_journal::recovery::{RecoveryTailMode, TailResultSlots, finish_replayed_tail};

pub use aos_sandbox_broker::canonical_journal::{CommitResult, RecoveryReport,
    NativeJournalDataErrorV1 as JournalError, JournalLimits, JournalRecord, JournalTransaction};
pub use aos_sandbox_core::RecordNamespace;
pub use aos_sandbox_protocol::domain_ledger::transaction::IdempotencyKey;

pub(crate) type ProtectedJournalCurrentnessOriginalsV1 =
    aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1<JournalError>;
pub(crate) type ProtectedJournalPreopenReplayExtentV1 =
    aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;

pub(crate) fn protected_journal_preopen_replay_extent_for_prefix_v1(
    limits: JournalLimits, bytes: u64,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    ProtectedJournalPreopenReplayExtentV1::new(limits, bytes)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum JournalAppendReceivingDemandErrorV1 {
    #[error(transparent)] Journal(#[from] JournalError),
    #[error(transparent)] Accounting(#[from] aos_sandbox_core::AccountingError),
}

struct AuthorityInstance;

pub(crate) struct Journal {
    data: CanonicalNativeJournalV1,
    protected: Option<ProtectedJournalLocation<()>>,
    authority: Arc<AuthorityInstance>,
    durable_bytes: u64,
}

pub(crate) struct JournalShape {
    pub(crate) native_bytes: u64,
    pub(crate) retained_bytes: usize,
    pub(crate) cells: usize,
}

impl Journal {
    fn from_original_parts(path: PathBuf, file: File, lock: File, limits: JournalLimits,
        protected: Option<ProtectedJournalLocation<()>>, replay: &mut CanonicalReplayOriginalV1,
    ) -> Result<Self, JournalError> {
        let durable_bytes = replay.report().ok_or(JournalError::ProtectedBoundary)?.0;
        let prefix = replay.take_prefix().ok_or(JournalError::ProtectedBoundary)?;
        Ok(Self { data: CanonicalNativeJournalV1::from_owned_parts(path, file, lock, limits, prefix),
            protected, authority: Arc::new(AuthorityInstance), durable_bytes })
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.data.native().is_poisoned() { Err(JournalError::Poisoned) } else { Ok(()) }
    }

    pub(crate) fn ownership_namespaces_are_exact_v1(&self) -> bool {
        self.data.native().committed_namespaces().iter().all(|namespace|
            matches!(namespace, RecordNamespace::Operation | RecordNamespace::DesiredState))
    }

    pub(crate) fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.data.native().state().iter().filter_map(move |((actual, key), value)|
            (*actual == namespace).then_some((key.as_slice(), value.as_slice())))
    }

    pub(crate) fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.records(namespace).find_map(|(actual, value)| (actual == key).then_some(value))
    }

    pub(crate) fn snapshot_sequence(&self) -> u64 { self.data.native().next_sequence() }

    pub(crate) fn first_global_allocation_shape_v1(&self) -> Result<JournalShape, JournalError> {
        self.ensure_healthy()?;
        let native_bytes = self.data.native().file().metadata()?.len();
        if native_bytes != self.durable_bytes { return Err(JournalError::StaleAuthoritySnapshot); }
        let retained_bytes = self.data.native().state().iter().try_fold(0usize, |bytes, ((_, key), value)| {
            bytes.checked_add(key.capacity()).and_then(|bytes| bytes.checked_add(value.capacity()))
                .ok_or(JournalError::LimitExceeded("retained Ownership map"))
        })?;
        Ok(JournalShape { native_bytes, retained_bytes, cells: self.data.native().state().len() })
    }

    fn require_owned_names(&self, sink: &mut ProtectedJournalCurrentnessOriginalsV1) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        self.observe_owned_names(sink)
    }

    // Only fresh entry checks health. Already-entered intervals owe this same
    // physical observation even when their append poisoned the native writer.
    fn observe_owned_names(&self, sink: &mut ProtectedJournalCurrentnessOriginalsV1) -> Result<(), JournalError> {
        let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        sink.observe_names(location, location.name(), location.expected_uid(),
            self.data.native().lock_file(), self.data.native().file())
    }

    fn finish_owed_names(&self, sink: &mut ProtectedJournalCurrentnessOriginalsV1) -> Result<(), JournalError> {
        sink.begin(true)?;
        let result = self.observe_owned_names(sink);
        sink.finish(result)
    }

    pub(crate) fn validate_held_protected_names_retaining(&self,
        sink: &mut ProtectedJournalCurrentnessOriginalsV1) -> Result<(), JournalError> {
        sink.begin(true)?;
        let result = self.require_owned_names(sink);
        sink.finish(result)
    }

    pub(crate) fn observe_local_ownership_native_history_v1(&self,
        names: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), LocalOwnershipNativeHistoryErrorV1> {
        if let Err(first) = self.ensure_healthy() {
            return Err(LocalOwnershipNativeHistoryErrorV1 { first, bookend: None,
                replay: None, metadata_after: None, named_first: false });
        }
        self.observe_entered_local_history(names)
    }

    fn observe_entered_local_history(&self,
        names: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), LocalOwnershipNativeHistoryErrorV1> {
        let mut replay = CanonicalReplayOriginalV1::new();
        let mut witness: Option<ProtectedWriterNameWitness> = None;
        let mut metadata_after = None;
        let first = (|| {
            let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            witness = Some(location.writer_witness::<JournalError>(self.data.native().file(), self.data.native().lock_file())?);
            // The shared captured cursor uses positional reads on the SAME
            // file and bounded actual prefix, with no duplicate FD or seek.
            replay.capture_prefix_once(self.data.native().file(), self.data.native().limits(), self.durable_bytes)?;
            if !replay.matches_native(self.data.native()) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            let (end, _) = replay.report().ok_or(JournalError::ProtectedBoundary)?;
            metadata_after = Some(self.data.native().file().metadata());
            if metadata_after.as_ref().and_then(|result| result.as_ref().ok())
                .is_none_or(|metadata| metadata.len() != end)
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })();
        // Replay failure does not suppress the independent held-name post.
        // As before, witness comparison depends on successful names and an
        // available initial witness; it is not a separately owed observation.
        let post = (|| {
            self.finish_owed_names(names)?;
            if let Some(witness) = witness.as_ref() {
                self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?
                    .require_writer_witness::<JournalError>(self.data.native().file(), self.data.native().lock_file(), witness)?;
            }
            Ok(())
        })();
        match (first, post) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), bookend) => Err(LocalOwnershipNativeHistoryErrorV1 { first,
                bookend: bookend.err(), replay: Some(replay), metadata_after, named_first: false }),
            (Ok(()), Err(first)) => Err(LocalOwnershipNativeHistoryErrorV1 { first,
                bookend: None, replay: Some(replay), metadata_after, named_first: true }),
        }
    }

    // This private borrow is created only by the actual paid local append
    // caller. It cannot outlive or swap the same Journal; it exposes no reset,
    // generic health bypass, raw native handle or independent admission.
    pub(crate) fn begin_local_append_interval_v1(&mut self)
        -> Result<LocalAppendObservationV1<'_>, JournalError> {
        self.ensure_healthy()?;
        Ok(LocalAppendObservationV1 { journal: self })
    }

    pub(crate) fn commit(&mut self, transaction: &JournalTransaction) -> Result<CommitResult, JournalError> {
        if self.protected.is_some() {
            let mut names = ProtectedJournalCurrentnessOriginalsV1::new();
            self.validate_held_protected_names_retaining(&mut names)?;
        }
        self.commit_local_v1(transaction)
    }

    // The selected caller retains the before/prehistory/history/readback/post
    // name reservoirs under its exact paid funding loan. This private method
    // adds no unpriced hidden observation or public admission shortcut.
    pub(crate) fn commit_local_v1(&mut self, transaction: &JournalTransaction) -> Result<CommitResult, JournalError> {
        self.ensure_healthy()?;
        if self.protected.is_some() && transaction.records().iter().any(|record|
            !matches!(record.namespace(), RecordNamespace::Operation | RecordNamespace::DesiredState)) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let result = self.data.append_data(transaction)?;
        self.durable_bytes = result.durable_bytes;
        Ok(result)
    }

    pub(crate) fn append_receiving_demand_v1(&self,
        records: impl ExactSizeIterator<Item = aos_sandbox_journal::geometry::RecordShape>,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        let append = aos_sandbox_journal::geometry::encoded_transaction_append_bytes(records)
            .map_err(JournalError::from)?;
        let shape = self.first_global_allocation_shape_v1()?;
        let future = shape.native_bytes.checked_add(append).ok_or(JournalError::JournalTooLarge)?;
        let extent = protected_journal_preopen_replay_extent_for_prefix_v1(self.data.native().limits(), future)?;
        let invalid = || JournalError::LimitExceeded("Ownership append receiving geometry");
        // Retained live map + readback/audit/prospective map carrier overlaps
        // are distinct from the actual canonical native parser/encoder extent.
        let retained = shape.retained_bytes.checked_mul(4)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<LocalAppendObservationV1<'_>>()))
            .ok_or_else(invalid)?;
        // The same-Journal borrowed interval and its returned constructor
        // carrier are separate control metadata, not live-map entry slack.
        let cells = shape.cells.checked_mul(4)
            .and_then(|cells| cells.checked_add(2)).ok_or_else(invalid)?;
        Ok(extent.dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(retained).map_err(|_| invalid())?)
                .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?)
                .with(D::StorageBytes, future))?)
    }

    pub(crate) fn open_protected_at(directory: impl AsRef<Path>, name: &str, limits: JournalLimits)
        -> Result<(Self, RecoveryReport), JournalError> {
        let mut original = OwnershipCapturedJournalOpenV1::new_at(directory.as_ref(), name);
        original.prepare_once(limits, CapturedJournalOpenModeV1::CreateAndRepair);
        original.replay_once();
        original.take_opened().ok_or(JournalError::ProtectedBoundary)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn open(path: impl AsRef<Path>, limits: JournalLimits) -> Result<(Self, RecoveryReport), JournalError> {
        use rustix::fs::{FlockOperation, flock};
        let path = path.as_ref();
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path.with_extension("lock"))?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(io_error)?;
        let mut replay = CanonicalReplayOriginalV1::new();
        let mut file = file;
        replay.capture_once(&mut file, limits)?;
        let (end, mut report) = replay.report().ok_or(JournalError::ProtectedBoundary)?;
        let observed_length = file.metadata()?.len();
        report.truncated_bytes = finish_replayed_tail(&mut file, observed_length, end,
            RecoveryTailMode::RepairIncomplete, None).map_err(|_| JournalError::ProtectedBoundary)?;
        let journal = Self::from_original_parts(path.to_owned(), file, lock, limits, None, &mut replay)?;
        Ok((journal, report))
    }
}

/// Continuously holds the healthy-entered paid local append's actual writer.
pub(crate) struct LocalAppendObservationV1<'journal> {
    journal: &'journal mut Journal,
}

impl LocalAppendObservationV1<'_> {
    pub(crate) fn observe_names(&self, sink: &mut ProtectedJournalCurrentnessOriginalsV1)
        -> Result<(), JournalError> {
        self.journal.finish_owed_names(sink)
    }

    pub(crate) fn observe_history(&self, names: &mut ProtectedJournalCurrentnessOriginalsV1)
        -> Result<(), LocalOwnershipNativeHistoryErrorV1> {
        self.journal.observe_entered_local_history(names)
    }

    pub(crate) fn append(&mut self, transaction: &JournalTransaction) -> Result<CommitResult, JournalError> {
        self.journal.commit_local_v1(transaction)
    }

    pub(crate) fn require_readback(&self, transaction: &JournalTransaction, native: Option<&CommitResult>)
        -> Result<(), JournalError> {
        let native = native.ok_or(JournalError::ProtectedBoundary)?;
        let shape = self.journal.first_global_allocation_shape_v1()?;
        if self.journal.snapshot_sequence() != native.commit_sequence.checked_add(1)
            .ok_or(JournalError::ProtectedBoundary)?
            || shape.native_bytes != native.durable_bytes
            || transaction.records().iter().any(|record| {
                self.journal.get(record.namespace(), record.key()) != record.value()
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn io_error(error: rustix::io::Errno) -> JournalError { std::io::Error::from_raw_os_error(error.raw_os_error()).into() }

#[derive(Debug, thiserror::Error)]
#[error("original Ownership native history failed: {first}")]
pub(crate) struct LocalOwnershipNativeHistoryErrorV1 {
    #[source] first: JournalError,
    bookend: Option<JournalError>,
    replay: Option<CanonicalReplayOriginalV1>,
    metadata_after: Option<std::io::Result<std::fs::Metadata>>,
    named_first: bool,
}

impl LocalOwnershipNativeHistoryErrorV1 {
    pub(crate) fn first_cause<'a>(&'a self, names: &'a ProtectedJournalCurrentnessOriginalsV1) -> &'a (dyn Error + 'static) {
        if self.named_first { names.failure().unwrap_or(&self.first) }
        else {
            self.replay.as_ref().and_then(CanonicalReplayOriginalV1::failure)
                .or_else(|| self.metadata_after.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static)))
                .unwrap_or(&self.first)
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CapturedJournalOpenModeV1 { CreateAndRepair }

#[derive(Clone)]
pub(crate) struct OpeningOwnerLinkV1(Arc<AuthorityInstance>);
impl OpeningOwnerLinkV1 {
    pub(crate) fn matches_journal_v1(&self, journal: &Journal) -> bool { Arc::ptr_eq(&self.0, &journal.authority) }
}

pub(crate) struct OwnershipCapturedJournalOpenV1 {
    recipe: JournalRecipe,
    attempted: bool,
    replay_entered: bool,
    taken: bool,
    limits: Option<JournalLimits>,
    ancestors: Vec<File>,
    directory: Option<File>,
    lock: Option<File>,
    file: Option<File>,
    protected: Option<ProtectedJournalLocation<()>>,
    directory_error: Option<JournalError>,
    directory_native_error: Option<rustix::io::Errno>,
    lock_native_error: Option<rustix::io::Errno>,
    lock_claim_native_error: Option<rustix::io::Errno>,
    file_native_error: Option<rustix::io::Errno>,
    lock_open: Option<Result<(), JournalError>>,
    lock_claim: Option<Result<(), JournalError>>,
    compaction: Option<Result<(), JournalError>>,
    file_open: Option<Result<(), JournalError>>,
    directory_sync: Option<Result<(), JournalError>>,
    preparation: Option<Result<(), JournalError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    before: ProtectedJournalCurrentnessOriginalsV1,
    replay: CanonicalReplayOriginalV1,
    truncate: Option<std::io::Result<()>>,
    sync: Option<std::io::Result<()>>,
    seek: Option<std::io::Result<u64>>,
    after: ProtectedJournalCurrentnessOriginalsV1,
    final_names: ProtectedJournalCurrentnessOriginalsV1,
    metadata_after: Option<std::io::Result<std::fs::Metadata>>,
    replay_result: Option<Result<(), JournalError>>,
    opened: Option<(Journal, RecoveryReport)>,
    owner_link: Option<OpeningOwnerLinkV1>,
}

impl OwnershipCapturedJournalOpenV1 {
    pub(crate) fn new() -> Self {
        Self::from_recipe(JournalRecipe::Fixed)
    }

    fn new_at(path: &Path, name: &str) -> Self {
        Self::from_recipe(JournalRecipe::Ordinary(path.to_owned(), name.to_owned()))
    }

    fn from_recipe(recipe: JournalRecipe) -> Self {
        Self { recipe, attempted: false,
            replay_entered: false, taken: false, limits: None, ancestors: Vec::new(), directory: None,
            lock: None, file: None, protected: None, directory_error: None,
            directory_native_error: None, lock_native_error: None, lock_claim_native_error: None,
            file_native_error: None, lock_open: None, lock_claim: None, compaction: None,
            file_open: None, directory_sync: None, preparation: None, metadata: None, extent: None,
            before: Default::default(), replay: CanonicalReplayOriginalV1::new(),
            truncate: None, sync: None, seek: None, after: Default::default(),
            final_names: Default::default(), metadata_after: None, replay_result: None, opened: None, owner_link: None }
    }

    pub(crate) fn prepare_once(&mut self, limits: JournalLimits, _mode: CapturedJournalOpenModeV1) {
        if self.attempted { return; }
        self.attempted = true;
        self.limits = Some(limits);
        let (path, name) = self.recipe.parts();
        self.preparation = Some((|| {
            acquire_writer_originals_v1(WriterAcquisitionSlotsV1 {
                ancestors: &mut self.ancestors, directory: &mut self.directory, lock: &mut self.lock,
                file: &mut self.file, lock_open: &mut self.lock_open, lock_claim: &mut self.lock_claim,
                compaction: &mut self.compaction, file_open: &mut self.file_open,
                directory_sync: &mut self.directory_sync,
            }, path, name, limits.into(), 0, true, JournalError::AlreadyLocked,
            Some(WriterAcquisitionRetentionV1 {
                directory_error: &mut self.directory_error, directory_native_error: &mut self.directory_native_error,
                lock_native_error: &mut self.lock_native_error, lock_claim_native_error: &mut self.lock_claim_native_error,
                file_native_error: &mut self.file_native_error,
            }))?;
            let directory = self.directory.take().ok_or(JournalError::ProtectedBoundary)?;
            self.protected = Some(ProtectedJournalLocation::from_original_parts((directory, name.to_owned(), 0, ())));
            self.metadata = Some(self.file.as_ref().ok_or(JournalError::ProtectedBoundary)?.metadata());
            let bytes = self.metadata.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?.len();
            self.extent = Some(protected_journal_preopen_replay_extent_for_prefix_v1(limits, bytes));
            if !matches!(self.extent, Some(Ok(_))) { return Err(JournalError::ProtectedBoundary); }
            Ok(())
        })());
    }

    pub(crate) fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if !matches!(self.preparation, Some(Ok(()))) { return None; }
        self.extent.as_ref()?.as_ref().ok()
    }

    pub(crate) fn replay_once(&mut self) {
        if self.replay_entered || self.captured_extent().is_none() { return; }
        self.replay_entered = true;
        self.replay_result = Some(self.replay_inner());
    }

    fn replay_inner(&mut self) -> Result<(), JournalError> {
        let (path, name) = self.recipe.parts();
        let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let file = self.file.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let lock = self.lock.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.before.begin(true)?;
        let before = self.before.observe_names(location, name, 0, lock, file);
        self.before.finish(before)?;
        let limits = self.limits.ok_or(JournalError::ProtectedBoundary)?;
        let captured_length = self.extent.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.native_bytes();
        let replay_result = self.replay.capture_prefix_once(file, limits, captured_length);
        // Both readback metadata and actual held names are owed independently
        // after the parser returns, including on its first native/schema Err.
        self.metadata_after = Some(file.metadata());
        self.after.begin(true)?;
        let after = self.after.observe_names(location, name, 0, lock, file);
        let post = self.after.finish(after);
        replay_result?;
        post?;
        let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let metadata_after = self.metadata_after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if metadata_tuple(metadata) != metadata_tuple(metadata_after) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let (end, mut report) = self.replay.report().ok_or(JournalError::ProtectedBoundary)?;
        let tail = finish_replayed_tail(file, metadata.len(), end, RecoveryTailMode::RepairIncomplete,
            Some(TailResultSlots::new(&mut self.truncate, &mut self.sync, &mut self.seek)))
            .map_err(|_| JournalError::ProtectedBoundary);
        self.final_names.begin(true)?;
        let names = self.final_names.observe_names(location, name, 0, lock, file);
        let final_post = self.final_names.finish(names);
        report.truncated_bytes = tail?;
        final_post?;
        let (file, lock, protected) = (self.file.take(), self.lock.take(), self.protected.take());
        let (file, lock, protected) = match (file, lock, protected) {
            (Some(file), Some(lock), Some(protected)) => (file, lock, protected),
            (file, lock, protected) => { self.file = file; self.lock = lock; self.protected = protected;
                return Err(JournalError::ProtectedBoundary); }
        };
        let journal = Journal::from_original_parts(path.join(name), file, lock, limits, Some(protected), &mut self.replay)?;
        self.owner_link = Some(OpeningOwnerLinkV1(Arc::clone(&journal.authority)));
        self.opened = Some((journal, report));
        Ok(())
    }

    pub(crate) fn replay_ready(&self) -> bool { matches!(self.replay_result, Some(Ok(()))) && self.opened.is_some() }
    pub(crate) fn take_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
        if self.taken || !self.replay_ready() { return None; }
        self.taken = true;
        self.opened.take()
    }
    pub(crate) fn was_taken_positive_v1(&self) -> bool { self.taken && matches!(self.replay_result, Some(Ok(()))) }
    pub(crate) fn opening_owner_link_v1(&self) -> Option<&OpeningOwnerLinkV1> { self.owner_link.as_ref() }

    pub(crate) fn fixed_preparation_demand() -> ResourceVector {
        let bytes = std::mem::size_of::<Self>()
            + 6 * std::mem::size_of::<File>()
            + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
            + std::mem::size_of::<AuthorityInstance>() + std::mem::align_of::<AuthorityInstance>()
            + 4 * ("/var/lib/aos/sandbox/multi-node".len() + "coordinator-ownership-v1.journal".len() + 32)
            // Three names-only reservoirs coexist through startup posts. Their
            // inline fields are already in Self; count only dynamic strings
            // and bounded native error backing here, plus all six actual FDs.
            + 3 * (2 * ("coordinator-ownership-v1.journal".len() + 5) + 8 * 256);
        ResourceVector::ZERO.with(D::MemoryBytes, bytes as u64)
            .with(D::OpenFiles, 6 + 2 + 3 * 2).with(D::MetadataEntries, 12 + 3 * 6)
    }

    pub(crate) fn named_currentness_demand_v1() -> Result<ResourceVector, JournalError> {
        ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("coordinator-ownership-v1.journal")
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn failed<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
        }
        self.directory_native_error.as_ref().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.directory_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.lock_native_error.as_ref().map(|cause| cause as _))
            .or_else(|| failed(&self.lock_open)).or_else(|| self.lock_claim_native_error.as_ref().map(|cause| cause as _))
            .or_else(|| failed(&self.lock_claim)).or_else(|| failed(&self.compaction))
            .or_else(|| self.file_native_error.as_ref().map(|cause| cause as _))
            .or_else(|| failed(&self.file_open)).or_else(|| failed(&self.directory_sync))
            .or_else(|| failed(&self.metadata)).or_else(|| failed(&self.extent)).or_else(|| failed(&self.preparation))
            .or_else(|| self.before.failure()).or_else(|| self.replay.failure())
            .or_else(|| failed(&self.metadata_after)).or_else(|| self.after.failure()).or_else(|| failed(&self.truncate))
            .or_else(|| failed(&self.sync)).or_else(|| failed(&self.seek))
            .or_else(|| self.final_names.failure()).or_else(|| failed(&self.replay_result))
    }
}

enum JournalRecipe {
    Fixed,
    Ordinary(PathBuf, String),
}

impl JournalRecipe {
    fn parts(&self) -> (&Path, &str) {
        match self {
            Self::Fixed => (Path::new("/var/lib/aos/sandbox/multi-node"), "coordinator-ownership-v1.journal"),
            Self::Ordinary(path, name) => (path, name),
        }
    }
}

fn metadata_tuple(value: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (value.dev(), value.ino(), value.len(), value.mtime(), value.mtime_nsec(), value.ctime(), value.ctime_nsec())
}

#[cfg(test)]
impl Journal {
    // This preserves the existing ordinary compaction/recovery regression. The
    // protected issuer exports no compaction entry or unfunded fixed-writer API.
    pub(crate) fn compact(&mut self) -> Result<(), JournalError> {
        use std::io::Seek as _;
        self.ensure_healthy()?;
        if self.protected.is_some() { return Err(JournalError::ProtectedBoundary); }
        let mut temporary = self.data.native().path().as_os_str().to_os_string();
        temporary.push(".compact.tmp");
        let temporary = PathBuf::from(temporary);
        let mut replacement = std::fs::OpenOptions::new().read(true).write(true)
            .create(true).truncate(true).open(&temporary)?;
        aos_sandbox_broker::canonical_journal::write_compacted_data(&mut replacement,
            self.data.native().state(), self.data.native().limits())?;
        replacement.sync_all()?;
        if replacement.metadata()?.len() > self.data.native().limits().maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        drop(replacement);
        std::fs::rename(&temporary, self.data.native().path())?;
        File::open(self.data.native().path().parent().ok_or(JournalError::ProtectedBoundary)?)?.sync_all()?;
        let mut replacement = std::fs::OpenOptions::new().read(true).write(true).open(self.data.native().path())?;
        let mut replay = CanonicalReplayOriginalV1::new();
        replay.capture_once(&replacement, self.data.native().limits())?;
        let length = replacement.metadata()?.len();
        let (end, _) = replay.report().ok_or(JournalError::ProtectedBoundary)?;
        if length != end { return Err(JournalError::MalformedTransaction("compacted journal has an uncommitted tail")); }
        replacement.seek(std::io::SeekFrom::End(0))?;
        self.data.native_mut().replace_replayed_file(replacement,
            replay.take_prefix().ok_or(JournalError::ProtectedBoundary)?);
        self.durable_bytes = length;
        self.authority = Arc::new(AuthorityInstance);
        Ok(())
    }
}

#[cfg(test)]
mod owed_names_tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("ownership-owed-names-{}-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn journal(&self) -> Journal {
            let path = self.0.join("authority");
            let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
            let lock = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
                .open(self.0.join("authority.lock")).unwrap();
            let mut replay = CanonicalReplayOriginalV1::new();
            replay.capture_once(&file, JournalLimits::default()).unwrap();
            let uid = file.metadata().unwrap().uid();
            let location = ProtectedJournalLocation::from_original_parts((File::open(&self.0).unwrap(), "authority".to_owned(), uid, ()));
            Journal::from_original_parts(path, file, lock, JournalLimits::default(), Some(location), &mut replay).unwrap()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn entered_interval_observes_real_names_after_poison_but_fresh_entry_stays_closed() {
        let directory = TestDirectory::new();
        let mut journal = directory.journal();
        let interval = journal.begin_local_append_interval_v1().unwrap();
        // Actual native append comparison failure permanently poisons this
        // same owner without replacing its file or changing either name.
        let mut interval = interval;
        let cause = interval.journal.data.native_mut().append_exact(&[], 1).unwrap_err();
        let mut post = ProtectedJournalCurrentnessOriginalsV1::new();

        interval.observe_names(&mut post).unwrap();

        assert!(matches!(cause, aos_sandbox_journal::framing::FrameError::Io(_)));
        assert!(interval.journal.data.native().is_poisoned());
        assert!(post.is_complete());
        assert_eq!(post.retained_file_count(), 2);
        drop(interval);
        let mut fresh = ProtectedJournalCurrentnessOriginalsV1::new();
        assert!(journal.validate_held_protected_names_retaining(&mut fresh).is_err());
        assert_eq!(fresh.retained_file_count(), 0);
        assert!(journal.begin_local_append_interval_v1().is_err());
    }

    #[test]
    fn poisoned_interval_keeps_partial_named_lock_and_native_primary_on_later_name_error() {
        let directory = TestDirectory::new();
        let mut journal = directory.journal();
        let mut interval = journal.begin_local_append_interval_v1().unwrap();
        let primary = interval.journal.data.native_mut().append_exact(&[], 1).unwrap_err();
        std::fs::remove_file(directory.0.join("authority")).unwrap();
        let mut post = ProtectedJournalCurrentnessOriginalsV1::new();

        assert!(interval.observe_names(&mut post).is_err());

        assert!(matches!(primary, aos_sandbox_journal::framing::FrameError::Io(_)));
        assert!(post.failure().is_some());
        assert_eq!(post.retained_file_count(), 1);
        assert!(interval.journal.data.native().is_poisoned());
    }
}
