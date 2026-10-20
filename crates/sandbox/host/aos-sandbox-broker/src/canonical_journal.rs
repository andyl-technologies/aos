//! Mechanical canonical journal DATA over the existing generic native owner.
//!
//! This layer shares framing, transaction decoding, exact native bookkeeping,
//! materialization and append IO. It never validates a role's semantic history,
//! supplies funding, signs, or constructs a protected operation handler. Role
//! adapters retain their private admission, namespaces, keys and currentness.

/// Shares retained native append stages without role admission or payment.
pub mod append_stages;

/// Retains actual captured append DATA and independent native observations.
pub mod captured;

/// Retains fixed Network native openings without semantic or financial authority.
pub mod network_opening;

mod writer_custody;
pub use writer_custody::CanonicalWriterCustodyDataV1;

mod error;
mod reread_geometry;
pub use reread_geometry::{CanonicalRereadWireWorkDataV1, ordinary_reread_wire_work_data_v1};
pub use error::CanonicalJournalMechanicalErrorV1;

/// Names sealed mechanical ports for genuine trusted coordinators.
pub mod coordinator;

mod opening;
pub use opening::{
    CanonicalJournalInstanceDataV1, CanonicalJournalInstanceWeakDataV1,
    CanonicalOpenedWriterDataV1, CanonicalOrdinaryAppendStageV1,
    CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryOpeningOriginalsV1,
    CanonicalWriterOpeningOriginalsV1, CanonicalOrdinaryReadonlyOpeningV1,
    CanonicalOrdinaryReadonlyReplayDataV1, CanonicalOrdinaryReplacementV1,
    CanonicalOrdinaryReplacementReadyV1, CanonicalOrdinaryReplacementInstalledV1,
    CanonicalOrdinaryRereadDataV1, CanonicalOrdinaryRereadOriginalV1,
};

#[cfg(target_os = "linux")]
pub use opening::{
    CanonicalOrdinaryNixOfflineOpeningV1, CanonicalNixOfflineAcquisitionErrorV1,
    CanonicalNixOfflineDirectoryOperationsV1, CanonicalNixOfflineFileOperationsV1,
};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::{framing, materialized, transaction};
use aos_sandbox_journal::framing::{Frame, FrameError, FrameKind, ReadOnlyFrameScratchV1};
use aos_sandbox_journal::owner::{NativeJournal, NativeJournalState};
use aos_sandbox_journal::replay::{NativeReplayBookkeeping, NativeReplayError};
use aos_sandbox_journal::transaction::NativePendingTransaction;
use aos_sandbox_protocol::domain_ledger::{JournalTransactionDataError, transaction as data};

pub use data::{JournalLimits, JournalRecord, JournalTransaction};

/// Preserves native or canonical journal DATA failures without role authority.
#[derive(Debug, thiserror::Error)]
pub enum NativeJournalDataErrorV1 {
    /// Preserves the actual IO error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Preserves the shared frame/geometry error.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Preserves the sole canonical transaction validator's error.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
    /// Preserves native sequence/count/identity bookkeeping errors.
    #[error(transparent)]
    ReplayCoordinate(#[from] NativeReplayError),
    /// Retains failed prepared frames beside the actual append/preparation cause.
    #[error("native append failed: {0}")]
    Append(Box<NativeAppendFailureV1>),
    /// Denies reuse of an ambiguous native append.
    #[error("native journal is poisoned")]
    Poisoned,
    /// Refuses physical or upper-private admission without issuing authority.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// Refuses a changed original physical name.
    #[error("protected journal original changed")]
    StaleAuthoritySnapshot,
    /// Refuses an unsupported protected opening primitive.
    #[error("protected opening is unavailable")]
    UnsupportedProtectedOpen,
    /// Refuses a second holder of the actual flock.
    #[error("journal is already locked")]
    AlreadyLocked,
    /// Refuses a repeated transaction identity.
    #[error("transaction identity was already committed")]
    DuplicateTransaction,
    /// Refuses exhausted sequence space.
    #[error("journal sequence exhausted")]
    SequenceExhausted,
    /// Refuses a journal exceeding its actual configured byte bound.
    #[error("journal is too large")]
    JournalTooLarge,
    /// Refuses a role-private record namespace.
    #[error("foreign authority namespace")]
    ForeignAuthorityNamespace,
    /// Preserves a static configured or representation bound.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Refuses malformed transaction shape in a role-private adapter.
    #[error("malformed transaction: {0}")]
    MalformedTransaction(&'static str),
}

impl aos_sandbox_journal::protected_storage::ProtectedFailure for NativeJournalDataErrorV1 {
    const BOUNDARY: Self = Self::ProtectedBoundary;
    const UNSUPPORTED_OPEN: Self = Self::UnsupportedProtectedOpen;
    const STALE_NAME: Self = Self::StaleAuthoritySnapshot;
}

/// Carries native recovery coordinates as DATA, never a current-cut receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Counts committed transactions replayed from the actual file.
    pub committed_transactions: usize,
    /// Counts actual committed record frames.
    pub committed_records: usize,
    /// Counts incomplete tail bytes removed by the separately selected repair.
    pub truncated_bytes: u64,
}

/// Carries returned native append coordinates without role admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitResult {
    /// Names the actual synced COMMIT frame.
    pub commit_sequence: u64,
    /// Records the actual resulting file byte length.
    pub durable_bytes: u64,
}

struct Pending {
    native: NativePendingTransaction,
    records: Vec<JournalRecord>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommitPhase {
    Decoded,
    CompactionValidated,
    Registered,
    Prepared,
    Accounted,
}

struct ReplayWork {
    retaining_validation: bool,
    ordinary_disposal_phase: u8,
    commit_phase: Option<CommitPhase>,
    applied_records: usize,
    native: NativeReplayBookkeeping,
    namespaces: BTreeSet<RecordNamespace>,
    state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    materialized: usize,
    pending: Option<Pending>,
    reached_pending: Option<Pending>,
    transaction: Option<JournalTransaction>,
    validation: data::TransactionValidationCaptureV1,
    frame: Option<Frame>,
    partial: Option<ReadOnlyFrameScratchV1>,
    compaction_prefix: bool,
    compaction_index: u64,
    compaction_last: Option<(RecordNamespace, Vec<u8>)>,
    compaction_current: Option<(RecordNamespace, Vec<u8>)>,
}

impl ReplayWork {
    fn new() -> Self {
        Self {
            retaining_validation: true,
            ordinary_disposal_phase: 0,
            commit_phase: None,
            applied_records: 0,
            native: NativeReplayBookkeeping::new(),
            namespaces: BTreeSet::new(),
            state: BTreeMap::new(),
            materialized: 0,
            pending: None,
            reached_pending: None,
            transaction: None,
            validation: data::TransactionValidationCaptureV1::new(),
            frame: None,
            partial: None,
            compaction_prefix: true,
            compaction_index: 1,
            compaction_last: None,
            compaction_current: None,
        }
    }

    fn observe(&mut self, file: &mut (impl Read + Seek), limits: JournalLimits) -> Result<(), NativeJournalDataErrorV1> {
        file.seek(SeekFrom::Start(0))?;
        while self.advance_to_commit(file, limits)? {
            self.apply_current_commit(limits)?;
        }
        Ok(())
    }

    fn advance_to_commit(
        &mut self,
        file: &mut (impl Read + Seek),
        limits: JournalLimits,
    ) -> Result<bool, NativeJournalDataErrorV1> {
        loop {
            let Some((frame, width)) = framing::read_frame_retained(
                file, self.native.coordinates().offset, limits.maximum_record_bytes,
                self.retaining_validation.then_some(&mut self.partial),
            )? else { return Ok(false); };
            self.frame = Some(frame);
            let frame = self.frame.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
            self.native.observe_frame(frame, width)?;
            if self.native.coordinates().offset > limits.maximum_journal_bytes {
                return Err(NativeJournalDataErrorV1::JournalTooLarge);
            }
            match frame.kind {
                FrameKind::Begin => {
                    if self.pending.is_some() {
                        return Err(NativeJournalDataErrorV1::MalformedTransaction("nested begin frame"));
                    }
                    let count = transaction::decode_begin_count(&frame.payload, limits.maximum_records_per_transaction)?;
                    self.pending = Some(Pending {
                        records: Vec::with_capacity(count),
                        native: NativePendingTransaction::begin(frame, count, self.native.coordinates().offset, width)?,
                    });
                }
                FrameKind::Record => {
                    let pending = self.pending.as_mut().ok_or(
                        NativeJournalDataErrorV1::MalformedTransaction("record outside transaction"))?;
                    pending.native.observe_record(frame, pending.records.len())?;
                    pending.records.push(data::decode_record(&frame.payload, limits)?);
                }
                FrameKind::Commit => {
                    self.reached_pending = self.pending.take();
                    let pending = self.reached_pending.as_mut().ok_or(
                        NativeJournalDataErrorV1::MalformedTransaction("commit outside transaction"))?;
                    pending.native.validate_commit(frame, pending.records.len())?;
                    self.transaction = Some(JournalTransaction::from_unvalidated_data(
                        pending.native.transaction_id(), std::mem::take(&mut pending.records)));
                    let transaction = self.transaction.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
                    if self.retaining_validation {
                        data::validate_transaction_retaining_v1(transaction, limits, &mut self.validation)?;
                    } else {
                        // The existing immediate adapter moves its precise error and
                        // disposes the ordinary validator's key scratch before return.
                        data::validate_transaction(transaction, limits)?;
                    }
                    self.commit_phase = Some(CommitPhase::Decoded);
                    return Ok(true);
                }
            }
            self.frame = None;
        }
    }

    fn validate_current_compaction(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.commit_phase != Some(CommitPhase::Decoded) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let transaction = self.transaction.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let mut compact_id = [0u8; 16];
        compact_id[..8].copy_from_slice(&self.compaction_index.to_le_bytes());
        compact_id[8..].copy_from_slice(b"compact1");
        if self.compaction_prefix && *transaction.id() == compact_id {
            for record in transaction.records() {
                self.compaction_current = Some((record.namespace(), record.key().to_vec()));
                let key = self.compaction_current.as_ref()
                    .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
                if record.value().is_none()
                    || self.compaction_last.as_ref().is_some_and(|last| last >= key)
                    || self.state.contains_key(key) {
                    return Err(NativeJournalDataErrorV1::MalformedTransaction("invalid compaction snapshot"));
                }
                self.compaction_last = self.compaction_current.take();
            }
            self.compaction_index = self.compaction_index.checked_add(1)
                .ok_or(NativeJournalDataErrorV1::SequenceExhausted)?;
        } else {
            self.compaction_prefix = false;
        }
        self.commit_phase = Some(CommitPhase::CompactionValidated);
        Ok(())
    }

    fn register_current_commit(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.commit_phase != Some(CommitPhase::CompactionValidated) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let transaction = self.transaction.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        self.native.register_transaction(*transaction.id())?;
        self.commit_phase = Some(CommitPhase::Registered);
        Ok(())
    }

    fn prepare_current_change(&mut self, limits: JournalLimits) -> Result<(), NativeJournalDataErrorV1> {
        if self.commit_phase != Some(CommitPhase::Registered) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let transaction = self.transaction.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        require_new_finality_admissions_v1(&self.state, transaction)?;
        self.materialized = materialized::validate_change(
            &self.state, self.materialized,
            transaction.records().iter().map(materialized::RecordMutationRef::from),
            limits.maximum_materialized_bytes, limits.maximum_materialized_records,
        )?;
        self.commit_phase = Some(CommitPhase::Prepared);
        Ok(())
    }

    fn apply_current_commit(&mut self, limits: JournalLimits) -> Result<(), NativeJournalDataErrorV1> {
        if self.commit_phase == Some(CommitPhase::Decoded) {
            self.validate_current_compaction()?;
        }
        if self.commit_phase == Some(CommitPhase::CompactionValidated) {
            self.register_current_commit()?;
        }
        if self.commit_phase == Some(CommitPhase::Registered) {
            self.prepare_current_change(limits)?;
        }
        if self.commit_phase != Some(CommitPhase::Prepared) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        while self.apply_next_record()? {}
        self.finish_current_commit(limits)
    }

    fn apply_next_record(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        if self.commit_phase != Some(CommitPhase::Prepared) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let transaction = self.transaction.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let Some(record) = transaction.records().get(self.applied_records) else {
            return Ok(false);
        };
        self.namespaces.insert(record.namespace());
        materialized::apply_mutation(&mut self.state, record.into());
        self.applied_records += 1;
        Ok(true)
    }

    fn finish_current_commit(&mut self, limits: JournalLimits) -> Result<(), NativeJournalDataErrorV1> {
        self.finish_current_accounting(limits)?;
        self.dispose_completed_commit()
    }

    fn finish_current_accounting(&mut self, limits: JournalLimits) -> Result<(), NativeJournalDataErrorV1> {
        let transaction = self.transaction.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        if self.commit_phase != Some(CommitPhase::Prepared)
            || self.applied_records != transaction.records().len()
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.native.finish_commit(transaction.records().len(), limits.maximum_transactions)?;
        self.commit_phase = Some(CommitPhase::Accounted);
        Ok(())
    }

    fn dispose_completed_commit(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.commit_phase != Some(CommitPhase::Accounted) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        // Only full COMMIT completion disposes this actual positive
        // index before the next transaction reuses its prepaid peak.
        self.validation = data::TransactionValidationCaptureV1::new();
        self.transaction = None;
        self.reached_pending = None;
        self.frame = None;
        self.commit_phase = None;
        self.applied_records = 0;
        Ok(())
    }

    fn dispose_ordinary_current(&mut self) -> bool {
        if self.retaining_validation || self.ordinary_disposal_phase != 0 { return false; }
        drop(self.compaction_current.take());
        drop(self.transaction.take());
        drop(self.reached_pending.take());
        drop(self.frame.take());
        drop(self.partial.take());
        self.ordinary_disposal_phase = 1;
        true
    }

    fn dispose_ordinary_pending(&mut self) -> bool {
        if self.retaining_validation || self.ordinary_disposal_phase != 1 { return false; }
        drop(self.compaction_last.take());
        drop(self.pending.take());
        self.ordinary_disposal_phase = 2;
        true
    }

    fn dispose_ordinary(mut self) {
        if self.ordinary_disposal_phase == 0 { self.dispose_ordinary_current(); }
        if self.ordinary_disposal_phase == 1 { self.dispose_ordinary_pending(); }
        drop(self.validation);
        drop(self.state);
        drop(self.namespaces);
        drop(self.native);
    }

    fn into_prefix(mut self) -> NativeJournalState<RecordNamespace> {
        let coordinates = self.native.coordinates();
        NativeJournalState::from_owned_parts(
            coordinates.durable_next_sequence, coordinates.committed_transactions,
            self.native.take_transaction_ids(), self.namespaces, self.state, self.materialized,
        )
    }
}

/// Retains prepared frame bytes beside the actual native refusal.
pub struct NativeAppendFailureV1 {
    frames: Vec<Vec<u8>>,
    cause: NativeJournalDataErrorV1,
}

impl NativeAppendFailureV1 {
    /// Disposes ordinary encoded backings before moving the precise native cause.
    ///
    /// Selected failures must retain this whole owner; this consuming adapter
    /// cannot prove positive disposal, native completion or paid settlement.
    #[must_use]
    pub fn into_ordinary_cause_v1(self) -> NativeJournalDataErrorV1 {
        let Self { frames, cause } = self;
        drop(frames);
        cause
    }
}

impl std::fmt::Debug for NativeAppendFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("NativeAppendFailureV1").field("frames", &self.frames.len())
            .field("cause", &self.cause).finish_non_exhaustive()
    }
}

impl std::fmt::Display for NativeAppendFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, output)
    }
}

impl Error for NativeAppendFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.cause) }
}

/// Owns replayed native DATA without constructing a protected role journal.
///
/// The role retains the actual File and lock until it has completed repair,
/// physical posts and its own model authentication.
pub struct CanonicalReplayOriginalV1 {
    work: Option<ReplayWork>,
    outcome: Option<Result<(), NativeJournalDataErrorV1>>,
    metadata: Option<io::Result<std::fs::Metadata>>,
    cursor_started: bool,
    cursor_preparation: Option<Result<(), NativeJournalDataErrorV1>>,
    cursor_step: Option<Result<(), NativeJournalDataErrorV1>>,
}

impl CanonicalReplayOriginalV1 {
    /// Creates empty replay destinations without IO or allocation.
    pub const fn new() -> Self {
        Self {
            work: None,
            outcome: None,
            metadata: None,
            cursor_started: false,
            cursor_preparation: None,
            cursor_step: None,
        }
    }

    /// Replays the supplied actual file with the sole canonical codecs once.
    ///
    /// # Errors
    /// Retains native partials, decoded transaction and first returned error.
    pub fn capture_once(&mut self, file: &File, limits: JournalLimits) -> Result<(), NativeJournalDataErrorV1> {
        self.capture_inner(file, limits, None)
    }

    /// Replays only the independently admitted same-original captured length.
    ///
    /// # Errors
    /// Parks metadata before comparing the exact length; a changed file refuses
    /// before parser growth. The bounded cursor cannot read beyond this prefix.
    pub fn capture_prefix_once(&mut self, file: &File, limits: JournalLimits, captured_length: u64)
        -> Result<(), NativeJournalDataErrorV1> {
        self.capture_inner(file, limits, Some(captured_length))
    }

    fn capture_inner(&mut self, file: &File, limits: JournalLimits, expected: Option<u64>)
        -> Result<(), NativeJournalDataErrorV1> {
        if self.outcome.is_some() || self.cursor_started {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.work = Some(ReplayWork::new());
        self.outcome = Some((|| {
            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())?;
            self.metadata = Some(file.metadata());
            let length = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.len();
            if expected.is_some_and(|expected| expected != length) {
                return Err(NativeJournalDataErrorV1::StaleAuthoritySnapshot);
            }
            if length > limits.maximum_journal_bytes { return Err(NativeJournalDataErrorV1::JournalTooLarge); }
            let mut cursor = aos_sandbox_journal::storage::CapturedFileCursor::new(file, length);
            self.work.as_mut().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.observe(&mut cursor, limits)
        })());
        if matches!(self.outcome, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    /// Borrows original replay failure DATA without resampling the file.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.metadata.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.work.as_ref().and_then(|work| work.validation.failure())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.cursor_preparation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.cursor_step.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    /// Disposes only the ordinary current commit and frame temporaries.
    ///
    /// This performs no IO and supplies no admission or completion. A private
    /// role adapter next drops its older replay-semantic locals, before the
    /// separate pending-prefix disposal window. Retained mode refuses.
    #[must_use]
    pub fn dispose_ordinary_current_once(&mut self) -> bool {
        self.work.as_mut().is_some_and(ReplayWork::dispose_ordinary_current)
    }

    /// Disposes ordinary compaction and pending locals after current disposal.
    ///
    /// The role drops its actual idempotency index after this window and before
    /// `into_ordinary_error` disposes the native state/namespaces/ID prefix.
    /// Retained mode and an out-of-order or repeated call refuse without IO.
    #[must_use]
    pub fn dispose_ordinary_pending_once(&mut self) -> bool {
        self.work.as_mut().is_some_and(ReplayWork::dispose_ordinary_pending)
    }

    /// Moves the immediate cursor's original error before ordinary cleanup.
    ///
    /// This consuming adapter belongs to `begin_ordinary_semantic_cursor_once`.
    /// Retained role callers keep this owner and use `failure` instead. It does
    /// not clone IO errors. Retained-mode owners have no transferable error
    /// through this adapter; consuming one only disposes it.
    #[must_use]
    pub fn into_ordinary_error(mut self) -> Option<NativeJournalDataErrorV1> {
        if self.work.as_ref().is_none_or(|work| work.retaining_validation) {
            return None;
        }
        let cause = self.metadata.take().and_then(Result::err)
            .map(NativeJournalDataErrorV1::Io)
            .or_else(|| self.cursor_preparation.take().and_then(Result::err))
            .or_else(|| self.cursor_step.take().and_then(Result::err))
            .or_else(|| self.outcome.take().and_then(Result::err));
        if let Some(work) = self.work.take() {
            work.dispose_ordinary();
        }
        cause
    }

    /// Copies the actual successfully replayed prefix coordinates.
    pub fn report(&self) -> Option<(u64, RecoveryReport)> {
        if !matches!(self.outcome, Some(Ok(()))) {
            return None;
        }
        let coordinates = self.work.as_ref()?.native.coordinates();
        Some((coordinates.durable_end, RecoveryReport {
            committed_transactions: coordinates.committed_transactions,
            committed_records: coordinates.committed_records, truncated_bytes: 0,
        }))
    }

    /// Borrows replayed materialized DATA without admitting any namespace.
    pub fn state(&self) -> Option<&BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>> {
        self.report()?;
        Some(&self.work.as_ref()?.state)
    }

    /// Borrows complete committed namespace provenance as nonauthorizing DATA.
    pub fn committed_namespaces(&self) -> Option<&BTreeSet<RecordNamespace>> {
        self.report()?;
        Some(&self.work.as_ref()?.namespaces)
    }

    /// Borrows completed canonical transaction identities as comparison DATA.
    ///
    /// Absence denotes an incomplete or failed native replay. This supplies no
    /// semantic validation, protected read authority or currentness permission.
    #[doc(hidden)]
    pub fn transaction_ids_data_v1(&self) -> Option<&BTreeSet<[u8; 16]>> {
        self.report()?;
        Some(self.work.as_ref()?.native.transaction_ids())
    }

    /// Compares all retained native coordinates, identities and materialized DATA.
    pub fn matches_native(&self, native: &NativeJournal<RecordNamespace, JournalLimits>) -> bool {
        self.matches_native_fields(
            native.state(), native.next_sequence(), native.committed_transactions(),
            native.transaction_ids(), native.committed_namespaces(), native.materialized_bytes(),
        )
    }

    /// Compares the SAME native prefix through an opaque selected-owner view.
    ///
    /// This comparison DATA cannot install a prefix or construct currentness.
    #[must_use]
    pub fn matches_coordinator_view_v1<P>(
        &self, view: coordinator::CanonicalWriterReadViewV1<'_, P>,
    ) -> bool {
        self.matches_native_fields(
            view.state(), view.next_sequence(), view.committed_transactions(),
            view.transaction_ids(), view.committed_namespaces(), view.materialized_bytes(),
        )
    }

    fn matches_native_fields(
        &self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        next_sequence: u64,
        committed_transactions: usize,
        transaction_ids: &BTreeSet<[u8; 16]>,
        committed_namespaces: &BTreeSet<RecordNamespace>,
        materialized_bytes: usize,
    ) -> bool {
        let Some(work) = self.work.as_ref() else { return false; };
        self.report().is_some_and(|(_, report)| {
            work.state == *state
                && work.native.coordinates().durable_next_sequence == next_sequence
                && report.committed_transactions == committed_transactions
                && work.native.transaction_ids() == transaction_ids
                && work.namespaces == *committed_namespaces
                && work.materialized == materialized_bytes
        })
    }

    /// Moves only a complete native DATA prefix; this cannot open a journal.
    pub fn take_prefix(&mut self) -> Option<NativeJournalState<RecordNamespace>> {
        self.report()?;
        Some(self.work.take()?.into_prefix())
    }
}

/// Owns ordinary native DATA storage without semantic admission or a role key.
pub struct CanonicalNativeJournalV1 {
    native: NativeJournal<RecordNamespace, JournalLimits>,
}

impl CanonicalNativeJournalV1 {
    /// Adopts actual supplied originals and replay DATA without protected admission.
    pub fn from_owned_parts(path: PathBuf, file: File, lock: File, limits: JournalLimits,
        prefix: NativeJournalState<RecordNamespace>) -> Self {
        Self { native: NativeJournal::from_owned_parts(path, file, lock, limits, prefix) }
    }

    /// Moves this same native data into its existing private role facade.
    ///
    /// No file, identity, semantic result or authority is supplied by this move.
    pub fn into_native_data_v1(self) -> NativeJournal<RecordNamespace, JournalLimits> { self.native }

    /// Borrows native DATA mechanics; the caller retains all semantic gates.
    pub const fn native(&self) -> &NativeJournal<RecordNamespace, JournalLimits> { &self.native }

    /// Borrows mutable native DATA mechanics without granting role authority.
    pub fn native_mut(&mut self) -> &mut NativeJournal<RecordNamespace, JournalLimits> { &mut self.native }

    /// Applies an already role-admitted canonical DATA transaction mechanically.
    ///
    /// # Errors
    /// Preserves canonical shape, duplicate/count, native encode, write/sync and
    /// length refusals. Ambiguous append results poison the same original.
    pub fn append_data(&mut self, transaction: &JournalTransaction) -> Result<CommitResult, NativeJournalDataErrorV1> {
        if self.native.is_poisoned() {
            return Err(NativeJournalDataErrorV1::Poisoned);
        }
        let limits = self.native.limits();
        data::validate_transaction(transaction, limits)?;
        require_new_finality_admissions_v1(self.native.state(), transaction)?;
        if self.native.transaction_ids().contains(transaction.id()) {
            return Err(NativeJournalDataErrorV1::DuplicateTransaction);
        }
        if self.native.committed_transactions() >= limits.maximum_transactions {
            return Err(NativeJournalDataErrorV1::LimitExceeded("committed transaction count"));
        }
        let materialized = self.native.projected_change(transaction.records().iter().map(Into::into))?;
        let following = self.native.next_sequence().checked_add(transaction.records().len() as u64)
            .and_then(|sequence| sequence.checked_add(2)).ok_or(NativeJournalDataErrorV1::SequenceExhausted)?;
        let frames = data::encode_transaction(transaction, self.native.next_sequence())?;
        let result = (|| {
            let expected = self.native.expected_append_length(&frames)?;
            let durable_bytes = self.native.append_exact(&frames, expected)?;
            for record in transaction.records() { self.native.apply_mutation(record.into()); }
            self.native.publish_append(materialized, following, *transaction.id(), transaction.records().iter().map(|record| record.namespace()));
            Ok::<_, NativeJournalDataErrorV1>(CommitResult { commit_sequence: following - 1, durable_bytes })
        })();
        match result {
            Ok(result) => Ok(result),
            Err(cause) => Err(NativeJournalDataErrorV1::Append(Box::new(NativeAppendFailureV1 { frames, cause }))),
        }
    }
}

// A compaction snapshot inserts each immutable admission into an empty prefix.
// Both ordinary append and every cold/native replay then use this same reducer
// guard. Looking up borrowed keys adds no transient map or copied key.
fn require_new_finality_admissions_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalTransactionDataError> {
    use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::CreateFinalityObservationAdmissionDataV1 as Admission;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::OperatorRecovery
            || !Admission::is_admission_key_v1(record.key()) { continue; }
        let before = state.iter().find_map(|((namespace, key), value)|
            (*namespace == record.namespace() && key.as_slice() == record.key()).then_some(value.as_slice()));
        Admission::require_new_record_v1(record.key(), before, record.value())
            .map_err(|_|JournalTransactionDataError::MalformedRecord("immutable finality observation admission"))?;
    }
    Ok(())
}

/// Prices native replay's actual bounded-prefix and declared-BEGIN carriers.
///
/// The recipe accepts only DATA and creates no account or replay permission.
#[derive(Clone, Copy)]
pub struct CanonicalReplayExtentDataV1 { limits: JournalLimits, bytes: u64 }

impl CanonicalReplayExtentDataV1 {
    /// Copies the same actual configured limits as passive geometry DATA.
    #[must_use]
    pub const fn limits(self) -> JournalLimits { self.limits }

    /// Validates native bounds and actual prefix width without allocating.
    ///
    /// # Errors
    /// Rejects invalid native bounds or an excessive/overflowing prefix.
    pub fn new(limits: JournalLimits, bytes: u64) -> Result<Self, NativeJournalDataErrorV1> {
        aos_sandbox_journal::geometry::validate_native_bounds(limits.into())?;
        if bytes > limits.maximum_journal_bytes { return Err(NativeJournalDataErrorV1::JournalTooLarge); }
        usize::try_from(bytes).map_err(|_| NativeJournalDataErrorV1::JournalTooLarge)?;
        Ok(Self { limits, bytes })
    }

    /// Copies the exact captured native length as passive representation DATA.
    pub const fn native_bytes(self) -> u64 { self.bytes }

    /// Prices the actual parser/map/identity/native encoder dominant peak.
    ///
    /// # Errors
    /// Rejects checked representation overflow before parser allocation.
    pub fn dominant_native_receiving_demand_v1(self) -> Result<ResourceVector, NativeJournalDataErrorV1> {
        let overflow = || NativeJournalDataErrorV1::LimitExceeded("native replay representation");
        let bytes = usize::try_from(self.bytes).map_err(|_| overflow())?;
        let frames = bytes / framing::HEADER_BYTES;
        let map_cell = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();
        // One full 11-cell B-tree node plus its 12 links per reached record
        // dominates each map/ID entry independently of amortized occupancy.
        let cells = frames.checked_mul(11).and_then(|count| count.checked_mul(
            map_cell + std::mem::size_of::<[u8; 16]>() + 12 * std::mem::size_of::<usize>()))
            .ok_or_else(overflow)?;
        let declared = self.limits.maximum_records_per_transaction
            .checked_mul(std::mem::size_of::<JournalRecord>()).ok_or_else(overflow)?;
        // Resident map, decoded records, native frame growth, append encoder,
        // independently replayed map and three old/new Vec growth overlaps.
        let memory = bytes.checked_mul(12).and_then(|value| value.checked_add(cells.checked_mul(2)?))
            .and_then(|value| value.checked_add(declared.checked_mul(3)?))
            .and_then(|value| value.checked_add(self.limits.maximum_record_bytes.checked_add(7)?))
            .and_then(|value| value.checked_add(2 * framing::FRAME_READ_SCRATCH_BYTES))
            .and_then(|value| value.checked_add(std::mem::size_of::<ReplayWork>() * 2))
            // The selected staged adapter reaches these actual stack carriers
            // outside its parent owner's inline sizeof term.
            .and_then(|value| value.checked_add(std::mem::size_of::<CanonicalReplayCursorV1<'_, '_>>()))
            .and_then(|value| value.checked_add(std::mem::size_of::<CanonicalCommitReadViewV1<'_>>()))
            .ok_or_else(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| overflow())?)
            .with(D::MetadataEntries, (frames as u64).checked_mul(4).ok_or_else(overflow)?))
    }

    /// Prices the sole canonical record/transaction validator's retained keys.
    ///
    /// # Errors
    /// Rejects checked representation overflow before validation.
    pub fn dominant_semantic_receiving_demand_v1(self) -> Result<ResourceVector, NativeJournalDataErrorV1> {
        let invalid = || NativeJournalDataErrorV1::JournalTooLarge;
        let prefix = usize::try_from(self.bytes).map_err(|_| invalid())?;
        let count = self.limits.maximum_records_per_transaction.min(prefix / framing::HEADER_BYTES);
        let key_bytes = self.limits.maximum_transaction_bytes.min(prefix);
        let current = self.limits.maximum_key_bytes.min(prefix);
        let bytes = aos_sandbox_journal::transaction::NativeRecordKeyIndexV1::dynamic_bytes_v1(
            count, key_bytes, current).and_then(|bytes| bytes.checked_add(current.checked_mul(3)?))
            .ok_or_else(invalid)?;
        // The retained key index has at most one resident entry per reached
        // record. Rust fields and control destinations are representation bytes,
        // not additional resident namespace entries.
        let cells = count;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?))
    }
}

impl std::fmt::Debug for CanonicalReplayOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("CanonicalReplayOriginalV1").field("complete", &self.report().is_some()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek as _, Write as _};

    fn append(file: &mut File, id: u8, sequence: u64) -> u64 {
        let transaction = JournalTransaction::new([id; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, vec![id], vec![id + 1])]).unwrap();
        let frames = data::encode_transaction(&transaction, sequence).unwrap();
        for frame in frames { file.write_all(&frame).unwrap(); }
        file.metadata().unwrap().len()
    }

    #[test]
    fn failed_later_frame_keeps_the_earlier_native_map_and_reached_payload() {
        let mut file = tempfile::tempfile().unwrap();
        append(&mut file, 1, 1);
        let transaction = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, vec![2], vec![3])]).unwrap();
        let mut frames = data::encode_transaction(&transaction, 4).unwrap();
        *frames[1].last_mut().unwrap() ^= 1;
        for frame in frames { file.write_all(&frame).unwrap(); }
        let mut original = CanonicalReplayOriginalV1::new();

        assert!(original.capture_once(&file, JournalLimits::default()).is_err());

        assert!(original.failure().is_some());
        assert!(original.take_prefix().is_none());
        let work = original.work.as_ref().unwrap();
        assert_eq!(work.state.len(), 1);
        assert_eq!(work.native.coordinates().committed_transactions, 1);
        assert!(work.partial.is_some());
        assert!(work.pending.is_some());
    }

    #[test]
    fn changed_captured_length_refuses_before_any_parser_or_map_growth() {
        let mut file = tempfile::tempfile().unwrap();
        let admitted = append(&mut file, 1, 1);
        file.write_all(&[0]).unwrap();
        let mut original = CanonicalReplayOriginalV1::new();

        assert!(original.capture_prefix_once(&file, JournalLimits::default(), admitted).is_err());

        let work = original.work.as_ref().unwrap();
        assert_eq!(work.native.coordinates().offset, 0);
        assert!(work.state.is_empty());
        assert!(work.pending.is_none());
        assert!(work.partial.is_none());
        assert_eq!(original.metadata.as_ref().unwrap().as_ref().unwrap().len(), admitted + 1);
    }

    #[test]
    fn shared_positional_replay_preserves_actual_file_cursor_and_exact_native_ids() {
        let mut file = tempfile::tempfile().unwrap();
        let length = append(&mut file, 1, 1);
        file.seek(SeekFrom::Start(17)).unwrap();
        let mut original = CanonicalReplayOriginalV1::new();
        original.capture_prefix_once(&file, JournalLimits::default(), length).unwrap();
        assert_eq!(file.stream_position().unwrap(), 17);

        let mut impostor = CanonicalReplayOriginalV1::new();
        impostor.capture_prefix_once(&file, JournalLimits::default(), length).unwrap();
        let work = impostor.work.as_mut().unwrap();
        work.native.take_transaction_ids();
        work.native.register_transaction([9; 16]).unwrap();
        let prefix = impostor.take_prefix().unwrap();
        let native = NativeJournal::from_owned_parts(PathBuf::new(), file,
            tempfile::tempfile().unwrap(), JournalLimits::default(), prefix);

        assert_eq!(original.state(), Some(native.state()));
        assert!(!original.matches_native(&native));
    }
}

mod compaction;
pub use compaction::{CanonicalCompactionErrorV1, write_compacted_data};

impl From<CanonicalCompactionErrorV1> for NativeJournalDataErrorV1 {
    fn from(error: CanonicalCompactionErrorV1) -> Self {
        match error {
            CanonicalCompactionErrorV1::Io(error) => Self::Io(error),
            CanonicalCompactionErrorV1::Frame(error) => Self::Frame(error),
            CanonicalCompactionErrorV1::Transaction(error) => Self::Transaction(error),
            CanonicalCompactionErrorV1::LimitExceeded(message) => Self::LimitExceeded(message),
            CanonicalCompactionErrorV1::SequenceExhausted => Self::SequenceExhausted,
        }
    }
}

#[cfg(test)]
mod retained_commit_tests {
    use super::*;
    use std::io::Write as _;

    fn write_transaction(file: &mut File, transaction: &JournalTransaction) {
        for frame in data::encode_transaction(transaction, 1).unwrap() {
            file.write_all(&frame).unwrap();
        }
    }

    #[test]
    fn commit_duplicate_keeps_actual_transaction_and_original_index() {
        let mut file = tempfile::tempfile().unwrap();
        let transaction = JournalTransaction::from_unvalidated_data([3; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![4], vec![1]),
            JournalRecord::put(RecordNamespace::Operation, vec![4], vec![2]),
        ]);
        write_transaction(&mut file, &transaction);
        let mut replay = CanonicalReplayOriginalV1::new();

        assert!(replay.capture_once(&file, JournalLimits::default()).is_err());

        let work = replay.work.as_ref().unwrap();
        assert_eq!(work.transaction.as_ref().unwrap().records().len(), 2);
        assert_eq!(work.validation.index_v1().retained_key_count_v1(), 1);
        assert!(matches!(replay.failure().unwrap().downcast_ref::<JournalTransactionDataError>(),
            Some(JournalTransactionDataError::DuplicateRecordKey)));
        assert!(replay.take_prefix().is_none());
    }

    #[test]
    fn rejected_compaction_delete_keeps_current_comparison_key() {
        let mut file = tempfile::tempfile().unwrap();
        let mut id = [0; 16];
        id[..8].copy_from_slice(&1u64.to_le_bytes());
        id[8..].copy_from_slice(b"compact1");
        let transaction = JournalTransaction::from_unvalidated_data(id, vec![
            JournalRecord::delete(RecordNamespace::Operation, vec![8, 9]),
        ]);
        write_transaction(&mut file, &transaction);
        let mut replay = CanonicalReplayOriginalV1::new();

        assert!(replay.capture_once(&file, JournalLimits::default()).is_err());

        let work = replay.work.as_ref().unwrap();
        assert_eq!(work.compaction_current.as_ref(), Some(&(RecordNamespace::Operation, vec![8, 9])));
        assert!(work.compaction_last.is_none());
        assert!(work.state.is_empty());
        assert!(work.transaction.is_some());
        assert!(replay.take_prefix().is_none());
    }
}

mod semantic_cursor;
pub use semantic_cursor::{CanonicalCommitReadViewV1, CanonicalReplayCursorV1, CanonicalReplayPrefixReadViewV1};
