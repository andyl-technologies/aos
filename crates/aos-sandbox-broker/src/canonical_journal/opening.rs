//! Retains the shared writable acquisition, canonical replay and tail originals.
//!
//! This is native custody DATA. Role-private callers select fixed storage,
//! retain actual paid originals, run semantic checks at the shared cursor's
//! frontiers, and keep their accepted constructors private. No method here
//! authenticates a role, supplies capacity, or creates an effect permission.

mod ordinary_held;

pub use ordinary_held::{
    CanonicalJournalInstanceDataV1, CanonicalJournalInstanceWeakDataV1,
    CanonicalOrdinaryAppendStageV1, CanonicalOrdinaryHeldJournalV1,
    CanonicalOrdinaryOpeningOriginalsV1, CanonicalOrdinaryReadonlyOpeningV1,
    CanonicalOrdinaryReadonlyReplayDataV1, CanonicalOrdinaryReplacementV1,
    CanonicalOrdinaryReplacementReadyV1, CanonicalOrdinaryReplacementInstalledV1,
    CanonicalOrdinaryRereadDataV1, CanonicalOrdinaryRereadOriginalV1,
};

#[cfg(target_os = "linux")]
pub use ordinary_held::{
    CanonicalOrdinaryNixOfflineOpeningV1, CanonicalNixOfflineAcquisitionErrorV1,
    CanonicalNixOfflineDirectoryOperationsV1, CanonicalNixOfflineFileOperationsV1,
};

use super::*;
use std::path::Path;
use aos_sandbox_journal::protected_storage::{FileIdentity, FileIdentityOriginalsV1, ProtectedJournalLocation};
use aos_sandbox_journal::protected_storage::{
    WriterAcquisitionRetentionV1, WriterAcquisitionSlotsV1, acquire_writer_originals_v1, acquire_writer_originals_ordinary_v1,
    writer_acquisition_temporary_shape_v1,
};
use aos_sandbox_journal::recovery::{
    RecoveryTailError, RecoveryTailMode, TailResultSlots, finish_replayed_tail,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum AcquisitionAccess {
    ReadOnly,
    ReadWrite,
}

struct Configuration {
    path: PathBuf,
    name: String,
    limits: JournalLimits,
    uid: u32,
}

/// Retains every actual reached native writer acquisition and replay partial.
///
/// Creating this carrier performs no IO or allocation. Callers pay the actual
/// inline owner and additional fixed geometry before preparation, then its
/// actual captured replay geometry before entering the parser. It is not a
/// selected-role factory and cannot replace a genuine paid construction loan.
#[must_use]
pub struct CanonicalWriterOpeningOriginalsV1 {
    ancestors: Vec<File>,
    traversal_retired: bool,
    directory: Option<File>,
    lock: Option<File>,
    file: Option<File>,
    lock_open: Option<Result<(), NativeJournalDataErrorV1>>,
    lock_claim: Option<Result<(), NativeJournalDataErrorV1>>,
    compaction: Option<Result<(), NativeJournalDataErrorV1>>,
    file_open: Option<Result<(), NativeJournalDataErrorV1>>,
    directory_sync: Option<Result<(), NativeJournalDataErrorV1>>,
    directory_error: Option<NativeJournalDataErrorV1>,
    directory_native_error: Option<rustix::io::Errno>,
    lock_native_error: Option<rustix::io::Errno>,
    lock_claim_native_error: Option<rustix::io::Errno>,
    file_native_error: Option<rustix::io::Errno>,
    configuration: Option<Configuration>,
    preparation: Option<Result<(), NativeJournalDataErrorV1>>,
    metadata: Option<io::Result<std::fs::Metadata>>,
    replay: CanonicalReplayOriginalV1,
    truncate: Option<io::Result<()>>,
    sync: Option<io::Result<()>>,
    seek: Option<io::Result<u64>>,
    tail: Option<Result<u64, RecoveryTailError>>,
    native_prefix: Option<NativeJournalState<RecordNamespace>>,
    report: Option<RecoveryReport>,
    ordinary: bool,
    access: AcquisitionAccess,
    recovery_started: bool,
    ordinary_lock_name: Option<String>,
    ordinary_parser_seek: Option<io::Result<u64>>,
    ordinary_parser_identity: Option<Result<FileIdentity, NativeJournalDataErrorV1>>,
    selected_parser_identity: FileIdentityOriginalsV1<NativeJournalDataErrorV1>,
    selected_parser_identity_result: Option<Result<(), NativeJournalDataErrorV1>>,
    attempted: bool,
    taken: bool,
    closed: Option<NativeJournalDataErrorV1>,
}

impl CanonicalWriterOpeningOriginalsV1 {
    /// Creates empty once-only destinations without acquiring an original.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ancestors: Vec::new(),
            traversal_retired: false,
            directory: None,
            lock: None,
            file: None,
            lock_open: None,
            lock_claim: None,
            compaction: None,
            file_open: None,
            directory_sync: None,
            directory_error: None,
            directory_native_error: None,
            lock_native_error: None,
            lock_claim_native_error: None,
            file_native_error: None,
            configuration: None,
            preparation: None,
            metadata: None,
            replay: CanonicalReplayOriginalV1::new(),
            truncate: None,
            sync: None,
            seek: None,
            tail: None,
            native_prefix: None,
            report: None,
            ordinary: false,
            access: AcquisitionAccess::ReadWrite,
            recovery_started: false,
            ordinary_lock_name: None,
            ordinary_parser_seek: None,
            ordinary_parser_identity: None,
            selected_parser_identity: FileIdentityOriginalsV1::new(),
            selected_parser_identity_result: None,
            attempted: false,
            taken: false,
            closed: None,
        }
    }

    /// Prices additional native preparation before the first directory open.
    ///
    /// The parent separately pays its actual inline opening owner. This bound
    /// covers the actual rooted Vec, native path buffers, construction/output
    /// temporaries and borrowed acquisition/tail slots. Replay demand is added
    /// from the actual captured extent before its parser begins.
    ///
    /// # Errors
    /// Refuses invalid fixed-name DATA or checked geometry overflow.
    pub fn additional_fixed_receiving_demand_v1(path: &Path, name: &str)
        -> Result<aos_sandbox_core::ResourceVector, NativeJournalDataErrorV1>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        let invalid = || NativeJournalDataErrorV1::LimitExceeded("native writer opening geometry");
        if !path.is_absolute() {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        aos_sandbox_journal::protected_storage::validate_basename::<NativeJournalDataErrorV1>(name)?;
        let depth = path.components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count().checked_add(1).ok_or_else(invalid)?;
        let paths = path.as_os_str().as_encoded_bytes().len()
            .checked_add(name.len()).and_then(|bytes| bytes.checked_add(32))
            .and_then(|bytes| bytes.checked_mul(4)).ok_or_else(invalid)?;
        let (native_temporaries, _representation_controls) = writer_acquisition_temporary_shape_v1(path)
            .ok_or_else(invalid)?;
        let identity = FileIdentityOriginalsV1::<NativeJournalDataErrorV1>::receiving_footprint_v1()
            .ok_or_else(invalid)?;
        let memory = depth.checked_mul(std::mem::size_of::<File>())
            .and_then(|bytes| bytes.checked_add(paths))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CanonicalOpenedWriterDataV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CompletedNativeOpening>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<CompletedNativeOpening>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<WriterAcquisitionSlotsV1<'_, NativeJournalDataErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<WriterAcquisitionRetentionV1<'_, NativeJournalDataErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<TailResultSlots<'_>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::fs::Metadata>() * 2))
            .and_then(|bytes| bytes.checked_add(8 * 256))
            .and_then(|bytes| bytes.checked_add(native_temporaries))
            .and_then(|bytes| bytes.checked_add(identity.memory_bytes)).ok_or_else(invalid)?;
        // Only resident path namespace entries consume this dimension:
        // rooted ancestors plus the journal, lock and compaction basenames.
        // Rust fields and retained Metadata objects are paid as bytes above.
        let cells = depth.checked_add(3).ok_or_else(invalid)?;
        let files = depth.checked_add(2).ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?))
    }

    /// Runs the existing native acquisition once into these resident slots.
    ///
    /// This mechanical entry accepts storage DATA, not a protected-purpose
    /// grant. Actual role constructors choose their fixed path, name, UID,
    /// limits and create policy after their own same-original fixed admission.
    ///
    /// # Errors
    /// Retains the original traversal, lock, flock, compaction, open, directory
    /// sync or metadata failure before returning its boundary classification.
    pub fn prepare_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.prepare_inner(path, name, limits, uid, allow_create, false, false)
    }

    /// Runs the immediate ordinary ownership adapter of the same acquisition.
    ///
    /// # Errors
    /// Preserves actual errors for `into_ordinary_error`; no selected role uses
    /// this adapter or gains receiving authority from its native DATA.
    pub fn prepare_ordinary_once(
        &mut self, path: &Path, name: &str, limits: JournalLimits,
        uid: u32, allow_create: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.prepare_inner(path, name, limits, uid, allow_create, true, false)
    }

    /// Enters the same immediate native recipe with empty-history refusal.
    ///
    /// # Errors
    /// Retains actual physical errors; preexisting history is never repaired.
    pub fn prepare_empty_ordinary_once(
        &mut self, path: &Path, name: &str, limits: JournalLimits, uid: u32,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.prepare_inner(path, name, limits, uid, true, true, true)
    }

    fn prepare_inner(
        &mut self, path: &Path, name: &str, limits: JournalLimits,
        uid: u32, allow_create: bool, ordinary: bool, empty_history: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        if self.attempted {
            return Err(self.refuse_order());
        }
        self.attempted = true;
        self.ordinary = ordinary;
        self.preparation = Some((|| {
            let slots = WriterAcquisitionSlotsV1 {
                ancestors: &mut self.ancestors,
                directory: &mut self.directory,
                lock: &mut self.lock,
                file: &mut self.file,
                lock_open: &mut self.lock_open,
                lock_claim: &mut self.lock_claim,
                compaction: &mut self.compaction,
                file_open: &mut self.file_open,
                directory_sync: &mut self.directory_sync,
            };
            if empty_history {
                aos_sandbox_journal::protected_storage::acquire_empty_writer_originals_ordinary_v1(
                    slots, path, name, limits.into(), uid,
                    NativeJournalDataErrorV1::AlreadyLocked, &mut self.ordinary_lock_name,
                )?;
            } else if ordinary {
                acquire_writer_originals_ordinary_v1(slots, path, name, limits.into(),
                    uid, allow_create, NativeJournalDataErrorV1::AlreadyLocked,
                    &mut self.ordinary_lock_name)?;
            } else {
                acquire_writer_originals_v1(slots, path, name, limits.into(),
                    uid, allow_create, NativeJournalDataErrorV1::AlreadyLocked,
                    Some(WriterAcquisitionRetentionV1 {
                        directory_error: &mut self.directory_error,
                        directory_native_error: &mut self.directory_native_error,
                        lock_native_error: &mut self.lock_native_error,
                        lock_claim_native_error: &mut self.lock_claim_native_error,
                        file_native_error: &mut self.file_native_error,
                    }))?;
            }
            self.record_prepared_configuration(path, name, limits, uid)
        })());
        if matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    fn record_prepared_configuration(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.recovery_started = true;
        self.configuration = Some(Configuration {
            path: PathBuf::from(name),
            name: name.to_owned(),
            limits,
            uid,
        });
        self.metadata = Some(
            self.file
                .as_ref()
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
                .metadata(),
        );
        let length = self
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .len();
        if length > limits.maximum_journal_bytes {
            return Err(NativeJournalDataErrorV1::JournalTooLarge);
        }
        Ok(())
    }

    /// Describes only this actual fixed-paid file's captured native extent.
    ///
    /// # Errors
    /// Refuses failed preparation, missing metadata or configured overflow.
    pub fn prepared_extent(&self) -> Result<CanonicalReplayExtentDataV1, NativeJournalDataErrorV1> {
        if !matches!(self.preparation, Some(Ok(()))) || self.taken || self.closed.is_some() {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let configuration = self.configuration.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let bytes = self.metadata.as_ref().or(self.replay.metadata.as_ref())
            .and_then(|result| result.as_ref().ok())
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.len();
        CanonicalReplayExtentDataV1::new(configuration.limits, bytes)
    }

    /// Observes the original rooted path and held writer names in one sink.
    ///
    /// This mechanical stage adds no healthy-entry check: a genuine caller may
    /// owe its independent post after parser refusal. It neither opens a new
    /// writer nor changes the held file, lock or configured pathname.
    ///
    /// # Errors
    /// Retains the reached rooted traversal, directory binding and names in the
    /// supplied original; missing custody or repeated observation refuses.
    pub fn observe_names_retaining_v1<E>(
        &self,
        directory_path: &Path,
        name: &str,
        uid: u32,
        originals: &mut crate::writer_currentness::WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where
        E: aos_sandbox_journal::protected_storage::ProtectedFailure
            + From<aos_sandbox_journal::framing::FrameError>
            + Error + 'static,
    {
        originals.begin(false)?;
        let result = (|| {
            let directory = self.directory.as_ref()
                .ok_or(E::BOUNDARY)?;
            originals.observe_directory(directory_path, uid)?;
            originals.bind_directory(directory)?;
            let lock = self.lock.as_ref().ok_or(E::BOUNDARY)?;
            let file = self.file.as_ref().ok_or(E::BOUNDARY)?;
            originals.observe_names_at(directory, name, uid, lock, file)
        })();
        originals.finish(result)
    }

    /// Observes only the same rooted directory binding at its existing frontier.
    ///
    /// # Errors
    /// Retains the actual traversal/binding refusal without opening data names.
    pub fn observe_directory_retaining_v1<E>(
        &self,
        directory_path: &Path,
        uid: u32,
        originals: &mut crate::writer_currentness::WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where
        E: aos_sandbox_journal::protected_storage::ProtectedFailure
            + From<aos_sandbox_journal::framing::FrameError>
            + Error + 'static,
    {
        originals.begin(false)?;
        let result = (|| {
            let directory = self.directory.as_ref()
                .ok_or(E::BOUNDARY)?;
            originals.observe_directory(directory_path, uid)?;
            originals.bind_directory(directory)
        })();
        originals.finish(result)
    }

    /// Borrows the completed parser identity of this same native original.
    #[must_use]
    pub fn selected_parser_identity_data_v1(&self) -> Option<FileIdentity> {
        if !matches!(self.selected_parser_identity_result, Some(Ok(()))) { return None; }
        self.selected_parser_identity.completed_identity().copied()
    }

    /// Borrows the actual first metadata without sampling or replacing it.
    #[must_use]
    pub fn initial_metadata_data_v1(&self) -> Option<&std::fs::Metadata> {
        self.metadata.as_ref()?.as_ref().ok()
    }

    /// Parks the actual owed post against this original's first metadata once.
    ///
    /// No health gate suppresses the post after entered parser/semantic failure.
    /// The supplied slot retains the actual native result and comparison.
    ///
    /// # Errors
    /// Refuses a repeated slot or absent original file/metadata before IO.
    pub fn observe_captured_prefix_post_once_v1<E>(
        &self,
        slot: &mut Option<aos_sandbox_journal::protected_storage::CapturedReplayPrefixPostV1<E>>,
    ) -> Result<(), E>
    where
        E: aos_sandbox_journal::protected_storage::ProtectedFailure,
    {
        if slot.is_some() {
            return Err(E::BOUNDARY);
        }
        let file = self.file.as_ref().ok_or(E::BOUNDARY)?;
        let before = self.initial_metadata_data_v1().ok_or(E::BOUNDARY)?;
        *slot = Some(aos_sandbox_journal::protected_storage::CapturedReplayPrefixPostV1::observe(file, before));
        Ok(())
    }

    /// Enters the same staged parser after actual role replay admission.
    ///
    /// The caller retains its semantic destinations separately and runs their
    /// existing checks between the cursor's exact native COMMIT stages.
    ///
    /// # Errors
    /// Retains a changed physical extent or the original parser's refusal.
    pub fn begin_semantic_replay_once(&mut self)
        -> Result<CanonicalReplayCursorV1<'_, '_>, NativeJournalDataErrorV1>
    {
        if self.ordinary { return Err(self.refuse_order()); }
        let extent = self.prepared_extent()?;
        if self.tail.is_some() {
            return Err(self.refuse_order());
        }
        let configuration = self.configuration.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let file = self.file.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        self.replay.begin_semantic_cursor_once(file, configuration.limits, extent.native_bytes())
    }

    /// Begins captured replay using this original's actual parser identity metadata.
    ///
    /// This explicit route preserves legacy initial-metadata, one parser identity,
    /// parser and independently owed prefix-post order without another fstat.
    /// Existing selected callers keep their separate established entry unchanged.
    ///
    /// # Errors
    /// Refuses ordinary, repeated, failed or missing identity before parsing.
    pub fn begin_captured_replay_with_parser_metadata_once_v1(&mut self)
        -> Result<CanonicalReplayCursorV1<'_, '_>, NativeJournalDataErrorV1>
    {
        if self.ordinary || self.tail.is_some() || self.replay.cursor_started {
            return Err(self.refuse_order());
        }
        let extent = self.prepared_extent()?;
        if !matches!(self.selected_parser_identity_result, Some(Ok(()))) {
            return Err(self.refuse_order());
        }
        let metadata = self.selected_parser_identity.completed_metadata()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.clone();
        let limits = self.configuration.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.limits;
        let file = self.file.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        self.replay.begin_semantic_cursor_with_metadata_once(
            file, limits, extent.native_bytes(), metadata,
        )
    }

    /// Captures the same held file identity before selected semantic parsing.
    ///
    /// This one probe retains its actual Metadata and projection until the
    /// enclosing real role disposes the whole opening. It opens no descriptor,
    /// changes no file offset and produces comparison DATA, never admission.
    ///
    /// # Errors
    /// Retains actual metadata/projection refusal; repeat or ordinary entry
    /// refuses without another probe. The caller prepays fixed identity shape.
    pub fn prepare_selected_parser_identity_once(&mut self) -> Result<FileIdentity, NativeJournalDataErrorV1> {
        if self.ordinary || self.selected_parser_identity_result.is_some() || self.replay.cursor_started {
            return Err(self.refuse_order());
        }
        self.prepared_extent()?;
        let file = self.file.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        self.selected_parser_identity_result = Some(FileIdentity::of_retaining_v1(
            file, &mut self.selected_parser_identity,
        ));
        if !matches!(self.selected_parser_identity_result, Some(Ok(()))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.selected_parser_identity.completed_identity().copied()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)
    }

    /// Enters the immediate ordinary parser without a second metadata probe.
    ///
    /// # Errors
    /// Preserves the original metadata or parser failure until owned extraction;
    /// retained entry, repeated replay and a missing original refuse.
    pub fn begin_ordinary_semantic_replay_once(&mut self)
        -> Result<CanonicalReplayCursorV1<'_, '_>, NativeJournalDataErrorV1>
    {
        if !self.ordinary || self.tail.is_some() || self.replay.cursor_started {
            return Err(self.refuse_order());
        }
        self.prepared_extent()?;
        let limits = self.configuration.as_ref()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.limits;
        if self.ordinary_parser_seek.is_none() {
            self.prepare_ordinary_parser_once()?;
        }
        if !matches!(self.ordinary_parser_identity, Some(Ok(_))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let metadata = match self.metadata.take() {
            Some(Ok(metadata)) => metadata,
            other => { self.metadata = other; return Err(NativeJournalDataErrorV1::ProtectedBoundary); }
        };
        let file = self.file.as_mut().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        self.replay.begin_ordinary_semantic_cursor_on_original_once(file, limits, metadata)
    }

    /// Performs the original ordinary seek and identity sample before parsing.
    ///
    /// The role may copy the resulting physical identity before lending this
    /// owner to the cursor. Beginning the parser then reuses these same Results.
    /// This native DATA establishes no selected original or role provenance.
    ///
    /// # Errors
    /// Retains the actual seek or metadata failure; repeat entry refuses before IO.
    pub fn prepare_ordinary_parser_once(&mut self) -> Result<FileIdentity, NativeJournalDataErrorV1> {
        if !self.ordinary || self.ordinary_parser_seek.is_some() || self.replay.cursor_started {
            return Err(self.refuse_order());
        }
        self.prepared_extent()?;
        self.ordinary_parser_seek = Some(self.file.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.seek(SeekFrom::Start(0)));
        if !matches!(self.ordinary_parser_seek, Some(Ok(_))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.ordinary_parser_identity = Some(FileIdentity::of::<NativeJournalDataErrorV1>(
            self.file.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?,
        ));
        if !matches!(self.ordinary_parser_identity, Some(Ok(_))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.ordinary_parser_file_identity().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)
    }

    /// Borrows the actual ordinary parser's seven-field identity observation.
    #[must_use]
    pub fn ordinary_parser_file_identity(&self) -> Option<FileIdentity> {
        self.ordinary_parser_identity.as_ref()?.as_ref().ok().copied()
    }

    /// Disposes ordinary current commit/frame locals before older role scratch.
    #[must_use]
    pub fn dispose_ordinary_current_once(&mut self) -> bool {
        self.ordinary && self.replay.dispose_ordinary_current_once()
    }

    /// Disposes ordinary pending locals before the role's idempotency index.
    #[must_use]
    pub fn dispose_ordinary_pending_once(&mut self) -> bool {
        self.ordinary && self.replay.dispose_ordinary_pending_once()
    }

    /// Finalizes the same already replayed file with the existing tail engine.
    ///
    /// Actual role-private callers invoke this only after their complete final
    /// semantic checks. This entry supplies no permission to repair storage.
    ///
    /// # Errors
    /// Retains the exact truncate, sync and seek Results or the uncommitted-tail
    /// refusal. Incomplete native replay and repeated finalization refuse.
    pub fn finish_replayed_tail_once(&mut self, mode: RecoveryTailMode)
        -> Result<(), NativeJournalDataErrorV1>
    {
        if self.tail.is_some() || self.taken || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        let (durable_end, _) = self.replay.report()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let length = self.prepared_extent()?.native_bytes();
        let file = self.file.as_mut().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let slots = if self.ordinary { None } else {
            Some(TailResultSlots::new(&mut self.truncate, &mut self.sync, &mut self.seek))
        };
        self.tail = Some(finish_replayed_tail(file, length, durable_end, mode, slots));
        if matches!(self.tail, Some(Ok(_))) {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    /// Moves complete native originals without constructing a role journal.
    ///
    /// The actual private role adapter first checks its retained semantic Result
    /// and owed currentness posts. This method's success certifies only native
    /// replay/tail DATA, never those independent role conditions.
    pub fn take_opened_parts_once(&mut self) -> Option<CanonicalOpenedWriterDataV1> {
        // Selected existing callers require a real protected directory before
        // any prefix is taken. The ordinary internal route also supports its
        // genuine unprotected opener without weakening this public boundary.
        self.directory.as_ref()?;
        if self.access != AcquisitionAccess::ReadWrite {
            return None;
        }
        let parts = self.take_completed_native_parts_once()?;
        let CompletedNativeOpening {
            configuration,
            directory,
            file,
            lock,
            prefix,
            report,
            access: _,
        } = parts;
        match directory {
            Some(directory) => Some(CanonicalOpenedWriterDataV1 {
                configuration,
                directory,
                file,
                lock,
                prefix,
                report,
            }),
            None => {
                self.configuration = Some(configuration);
                self.file = Some(file);
                self.lock = Some(lock);
                self.native_prefix = Some(prefix);
                self.report = Some(report);
                self.taken = false;
                None
            }
        }
    }

    // The only ordinary/native transfer constructor consumes this SAME opened
    // original's completed parser prefix. Its fields and constructor are private;
    // no supplied file, prefix, map or replay-success value can enter here.
    fn take_completed_native_parts_once(&mut self) -> Option<CompletedNativeOpening> {
        if self.taken
            || self.failure().is_some()
            || self.configuration.is_none()
            || self.file.is_none()
            || self.lock.is_none()
        {
            return None;
        }
        if self.native_prefix.is_none() {
            let (_, mut report) = self.replay.report()?;
            report.truncated_bytes = *self.tail.as_ref()?.as_ref().ok()?;
            self.native_prefix = self.replay.take_prefix();
            self.report = Some(report);
        }
        let originals = (
            self.configuration.take(),
            self.file.take(),
            self.lock.take(),
            self.native_prefix.take(),
            self.report.take(),
        );
        let (configuration, file, lock, prefix, report) = match originals {
            (Some(configuration), Some(file), Some(lock), Some(prefix), Some(report)) => {
                (configuration, file, lock, prefix, report)
            }
            (configuration, file, lock, prefix, report) => {
                self.configuration = configuration;
                self.file = file;
                self.lock = lock;
                self.native_prefix = prefix;
                self.report = report;
                return None;
            }
        };
        self.taken = true;
        Some(CompletedNativeOpening {
            configuration,
            directory: self.directory.take(),
            file,
            lock,
            prefix,
            report,
            access: self.access,
        })
    }

    // Closed role adapters invoke this only after their actual semantic and
    // independently owed native/profile posts. The common owner additionally
    // verifies that its own whole positive replay/tail and native move occurred.
    // Ordinary disposal keeps its original lexical route below.
    pub(crate) fn retire_completed_traversal_once_v1(&mut self)
        -> Result<(), NativeJournalDataErrorV1>
    {
        if self.ordinary || !self.taken || self.traversal_retired || self.failure().is_some()
            || !matches!(self.tail, Some(Ok(_))) || self.configuration.is_some()
            || self.directory.is_some() || self.file.is_some() || self.lock.is_some()
            || self.native_prefix.is_some() || self.report.is_some()
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        // Actual Directory/Journal/Lock custody already moved intact. No later
        // opening method borrows this completed traversal's ancestor vector.
        drop(std::mem::take(&mut self.ancestors));
        self.traversal_retired = true;
        Ok(())
    }

    /// Moves the first ordinary native error and closes its actual originals.
    ///
    /// The role first disposes its own semantic/recovery locals at their old
    /// boundary. This adapter then closes the native subset explicitly: after
    /// recovery entry, directory/name, lock, file, path, outer lock name; before
    /// recovery entry, file, lock, outer lock name, directory. Selected callers
    /// keep this carrier and use its borrowed `failure` instead.
    #[must_use]
    pub fn into_ordinary_error(mut self) -> Option<NativeJournalDataErrorV1> {
        if !self.ordinary { return None; }
        let cause = self.directory_error.take()
            .or_else(|| self.lock_open.take().and_then(Result::err))
            .or_else(|| self.lock_claim.take().and_then(Result::err))
            .or_else(|| self.compaction.take().and_then(Result::err))
            .or_else(|| self.file_open.take().and_then(Result::err))
            .or_else(|| self.directory_sync.take().and_then(Result::err))
            .or_else(|| self.metadata.take().and_then(Result::err).map(NativeJournalDataErrorV1::Io))
            .or_else(|| self.preparation.take().and_then(Result::err))
            .or_else(|| self.ordinary_parser_seek.take().and_then(Result::err).map(NativeJournalDataErrorV1::Io))
            .or_else(|| self.ordinary_parser_identity.take().and_then(Result::err))
            .or_else(|| std::mem::replace(&mut self.replay, CanonicalReplayOriginalV1::new()).into_ordinary_error())
            .or_else(|| self.tail.take().and_then(Result::err).map(|cause| match cause {
                RecoveryTailError::Io(cause) => NativeJournalDataErrorV1::Io(cause),
                RecoveryTailError::UncommittedTail => NativeJournalDataErrorV1::MalformedTransaction(
                    "read-only journal has an uncommitted tail"),
                RecoveryTailError::RetainedNativeFailure => NativeJournalDataErrorV1::ProtectedBoundary,
            }))
            .or_else(|| self.closed.take());

        // Even a role semantic error has no native cause to extract, but its
        // completed or failed native parser locals still precede these FDs.
        let replay = std::mem::replace(&mut self.replay, CanonicalReplayOriginalV1::new());
        let _ = replay.into_ordinary_error();
        if self.recovery_started {
            drop(self.directory.take());
            let path = self.configuration.take().map(|configuration| {
                drop(configuration.name);
                configuration.path
            });
            drop(self.lock.take());
            drop(self.file.take());
            drop(path);
            drop(self.ordinary_lock_name.take());
        } else {
            drop(self.file.take());
            drop(self.lock.take());
            drop(self.ordinary_lock_name.take());
            drop(self.directory.take());
        }
        drop(std::mem::take(&mut self.ancestors));
        cause
    }

    fn refuse_order(&mut self) -> NativeJournalDataErrorV1 {
        self.closed.get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        NativeJournalDataErrorV1::ProtectedBoundary
    }

    /// Borrows the first actual native failure without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.directory_error)
            .or_else(|| errno(&self.directory_native_error))
            .or_else(|| errno(&self.lock_native_error))
            .or_else(|| step_error(&self.lock_open))
            .or_else(|| errno(&self.lock_claim_native_error))
            .or_else(|| step_error(&self.lock_claim))
            .or_else(|| step_error(&self.compaction))
            .or_else(|| errno(&self.file_native_error))
            .or_else(|| step_error(&self.file_open))
            .or_else(|| step_error(&self.directory_sync))
            .or_else(|| step_error(&self.metadata))
            .or_else(|| step_error(&self.preparation))
            .or_else(|| step_error(&self.ordinary_parser_seek))
            .or_else(|| step_error(&self.ordinary_parser_identity))
            .or_else(|| self.selected_parser_identity.failure())
            .or_else(|| step_error(&self.selected_parser_identity_result))
            .or_else(|| self.replay.failure())
            .or_else(|| step_error(&self.truncate))
            .or_else(|| step_error(&self.sync))
            .or_else(|| step_error(&self.seek))
            .or_else(|| step_error(&self.tail))
            .or_else(|| error(&self.closed))
    }
}

impl Default for CanonicalWriterOpeningOriginalsV1 {
    fn default() -> Self { Self::new() }
}

// This bundle has no public constructor or field projection. Protected and
// unprotected ordinary routes can form it only through their actual acquisition
// and canonical parser; selected callers still require a protected directory.
struct CompletedNativeOpening {
    configuration: Configuration,
    directory: Option<File>,
    file: File,
    lock: File,
    prefix: NativeJournalState<RecordNamespace>,
    report: RecoveryReport,
    access: AcquisitionAccess,
}

/// Owns complete native writable parts as mechanical comparison/custody DATA.
///
/// No public field or constructor can fabricate a successful acquisition here.
/// The resulting generic native owner still has no protected role admission.
pub struct CanonicalOpenedWriterDataV1 {
    configuration: Configuration,
    directory: File,
    file: File,
    lock: File,
    prefix: NativeJournalState<RecordNamespace>,
    report: RecoveryReport,
}

impl CanonicalOpenedWriterDataV1 {
    /// Returns the actual acquisition/replay report as comparison DATA.
    #[must_use]
    pub fn recovery_report(&self) -> RecoveryReport {
        self.report
    }

    /// Moves the actual native originals into their role-private adapter fields.
    ///
    /// The supplied compaction selection remains uninterpreted DATA. A caller
    /// cannot turn it into a semantic grant through this mechanical conversion.
    pub fn into_native_parts<P>(self, compaction_selection: P)
        -> (CanonicalNativeJournalV1, ProtectedJournalLocation<P>, RecoveryReport)
    {
        let native = CanonicalNativeJournalV1::from_owned_parts(
            self.configuration.path, self.file, self.lock,
            self.configuration.limits, self.prefix,
        );
        let location = ProtectedJournalLocation::from_original_parts((
            self.directory, self.configuration.name, self.configuration.uid, compaction_selection,
        ));
        (native, location, self.report)
    }
}

fn step_error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn errno(value: &Option<rustix::io::Errno>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().map(|cause| cause as _)
}

fn error(value: &Option<NativeJournalDataErrorV1>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    fn root_owner_uid() -> u32 {
        File::open("/").unwrap().metadata().unwrap().uid()
    }

    fn absent_root_child() -> PathBuf {
        PathBuf::from(format!("/aos-canonical-opening-test-{}-absent", std::process::id()))
    }

    #[test]
    fn selected_failed_root_preserves_original_errno_root_file_and_first_result() {
        let mut opening = CanonicalWriterOpeningOriginalsV1::new();
        let path = absent_root_child();

        assert!(opening.prepare_once(&path, "history", JournalLimits::default(), root_owner_uid(), false).is_err());
        let first = opening.failure().unwrap() as *const dyn Error as *const ();
        assert_eq!(opening.ancestors.len(), 1);
        assert_eq!(opening.directory_native_error, Some(rustix::io::Errno::NOENT));
        let root = opening.ancestors[0].metadata().unwrap();
        assert_eq!((root.dev(), root.ino()), {
            let root = File::open("/").unwrap().metadata().unwrap();
            (root.dev(), root.ino())
        });

        assert!(opening.prepare_once(&path, "other", JournalLimits::default(), root_owner_uid(), false).is_err());
        assert_eq!(opening.failure().unwrap() as *const dyn Error as *const (), first);
        assert_eq!(opening.ancestors.len(), 1);
        assert!(opening.closed.is_some());
        assert!(opening.retire_completed_traversal_once_v1().is_err());
        assert_eq!(opening.failure().unwrap() as *const dyn Error as *const (), first);
        assert_eq!(opening.ancestors.len(), 1);
        assert!(opening.ancestors[0].metadata().is_ok());
        assert!(opening.prepared_extent().is_err());
        assert!(opening.take_opened_parts_once().is_none());
    }

    #[test]
    fn completed_native_move_retires_only_real_traversal_files() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;

        // /tmp's shared writable ancestry intentionally fails protected
        // traversal. Use a private leaf beside this actual test executable.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new().prefix("writer-traversal-")
            .tempdir_in(executable.parent().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mut opening = CanonicalWriterOpeningOriginalsV1::new();
        // This fixture begins empty: the genuine creation path must create
        // both private native files before replay and positive handoff.
        opening.prepare_once(directory.path(), "history", JournalLimits::default(), uid, true)
            .unwrap_or_else(|cause| panic!("native preparation: {cause}; original: {:?}", opening.failure()));
        opening.prepare_selected_parser_identity_once().unwrap();
        {
            let mut cursor = opening.begin_semantic_replay_once().unwrap();
            assert!(!cursor.advance_once().unwrap());
            assert!(cursor.completed_prefix().is_some());
        }
        opening.finish_replayed_tail_once(RecoveryTailMode::RejectIncomplete).unwrap();
        let ancestors: Vec<_> = opening.ancestors.iter().map(|file| file.as_raw_fd()).collect();
        assert!(!ancestors.is_empty());
        assert!(opening.retire_completed_traversal_once_v1().is_err());
        assert_eq!(opening.ancestors.len(), ancestors.len());

        let opened = opening.take_opened_parts_once().unwrap();
        let directory_identity = opened.directory.metadata().unwrap();
        let journal_identity = opened.file.metadata().unwrap();
        let lock_identity = opened.lock.metadata().unwrap();
        opening.retire_completed_traversal_once_v1().unwrap();

        assert!(opening.ancestors.is_empty());
        for fd in ancestors {
            assert_eq!(std::fs::symlink_metadata(format!("/proc/self/fd/{fd}"))
                .unwrap_err().kind(), std::io::ErrorKind::NotFound);
        }
        for (file, expected) in [
            (&opened.directory, directory_identity), (&opened.file, journal_identity),
            (&opened.lock, lock_identity),
        ] {
            let actual = file.metadata().unwrap();
            assert_eq!((actual.dev(), actual.ino()), (expected.dev(), expected.ino()));
        }
        assert!(opening.retire_completed_traversal_once_v1().is_err());
        assert!(opening.failure().is_none());
    }

    #[test]
    fn ordinary_failed_root_moves_precise_io_error_and_keeps_no_ancestor_archive() {
        let mut opening = CanonicalWriterOpeningOriginalsV1::new();

        assert!(opening.prepare_ordinary_once(&absent_root_child(), "history",
            JournalLimits::default(), root_owner_uid(), false).is_err());
        assert!(opening.ancestors.is_empty());
        assert!(opening.directory.is_none());
        assert!(opening.directory_native_error.is_none());
        assert!(opening.take_opened_parts_once().is_none());
        assert!(matches!(opening.into_ordinary_error(),
            Some(NativeJournalDataErrorV1::Io(error))
                if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error())));
    }
}

#[cfg(test)]
mod writer_custody_tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    use aos_sandbox_core::OperationId;
    use aos_sandbox_protocol::domain_ledger::readonly::{
        IdempotencyDecisionV1, IdempotencyOutcome,
    };
    use aos_sandbox_protocol::domain_ledger::transaction::IdempotencyKey;

    // Mechanical native DATA only. No role constructor, original Root/C,
    // financial permit or protected semantic admission is fabricated here.
    fn opened_data(directory: &Path) -> CanonicalOpenedWriterDataV1 {
        let mut file = OpenOptions::new().read(true).write(true).create_new(true)
            .mode(0o600).open(directory.join("history")).unwrap();
        file.write_all(b"native").unwrap();
        let lock = OpenOptions::new().read(true).write(true).create_new(true)
            .mode(0o600).open(directory.join("history.lock")).unwrap();
        let uid = file.metadata().unwrap().uid();
        let state = BTreeMap::from([((RecordNamespace::DesiredState, vec![1]), vec![2, 3])]);
        let prefix = NativeJournalState::from_owned_parts(
            4, 1, BTreeSet::from([[1; 16]]),
            BTreeSet::from([RecordNamespace::DesiredState]), state, 3,
        );
        CanonicalOpenedWriterDataV1 {
            configuration: Configuration {
                path: PathBuf::from("history"),
                name: "history".to_owned(),
                limits: JournalLimits::default(),
                uid,
            },
            directory: File::open(directory).unwrap(),
            file,
            lock,
            prefix,
            report: RecoveryReport {
                committed_transactions: 1,
                committed_records: 1,
                truncated_bytes: 0,
            },
        }
    }

    #[test]
    fn physical_prefix_moves_original_allocations_and_lends_the_same_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let opened = opened_data(directory.path());
        let original_file = opened.file.metadata().unwrap();
        let key = vec![4];
        let operation = OperationId::from_bytes([5; 16]);
        let index = BTreeMap::from([(key.clone(), IdempotencyDecisionV1 {
            request_digest: [6; 32], operation_id: operation,
        })]);
        let index_key = index.first_key_value().unwrap().0.as_ptr();
        let compaction = vec![7, 8];
        let compaction_bytes = compaction.as_ptr();

        let (custody, report) = CanonicalWriterCustodyDataV1::from_opened_data_v1(
            opened, index, compaction,
        );
        let actual_file = custody.metadata().unwrap();
        let view = custody.historical_view();
        let (_, _, value) = view.all_records().next().unwrap();
        let native_value = custody.native.native().state().first_key_value().unwrap().1;
        let mut cursor = custody.captured_reader(6);
        let mut bytes = [0; 6];
        cursor.read_exact(&mut bytes).unwrap();

        assert_eq!((actual_file.dev(), actual_file.ino()),
            (original_file.dev(), original_file.ino()));
        assert_eq!(value.as_ptr(), native_value.as_ptr());
        assert_eq!(custody.index.first_key_value().unwrap().0.as_ptr(), index_key);
        assert_eq!(custody.compaction_selection().as_ptr(), compaction_bytes);
        assert_eq!(view.check_idempotency(&IdempotencyKey::new(key).unwrap(), [6; 32]),
            IdempotencyOutcome::Replay(operation));
        assert_eq!(&bytes, b"native");
        assert_eq!(custody.next_sequence(), 4);
        assert_eq!(report.committed_records, 1);
        let _same_location_view = custody.runtime_history();
    }

    #[test]
    fn entered_mechanical_name_observation_uses_same_files_after_native_poison() {
        let directory = tempfile::tempdir().unwrap();
        let opened = opened_data(directory.path());
        let (mut custody, _) = CanonicalWriterCustodyDataV1::from_opened_data_v1(
            opened, BTreeMap::new(), (),
        );
        let mut names = crate::writer_currentness::WriterCurrentnessOriginalsV1::<
            NativeJournalDataErrorV1,
        >::new();
        names.begin(true).unwrap();
        custody.native.native_mut().poison();

        let result = custody.observe_names_into(&mut names);
        assert!(names.finish(result).is_ok());
        let witness = custody.writer_witness::<NativeJournalDataErrorV1>().unwrap();
        custody.require_writer_witness::<NativeJournalDataErrorV1>(&witness).unwrap();

        assert!(custody.historical_view().is_poisoned());
        assert!(names.is_complete());
        assert!(names.retained_file_count() > 0);
        // Complete native names do not settle a whole C/R interval or clear
        // its poison/negative custody; only the real closed owner can do that.
    }

    #[test]
    fn replaced_name_keeps_the_actual_failed_sampler_after_later_native_reads() {
        let directory = tempfile::tempdir().unwrap();
        let opened = opened_data(directory.path());
        let (custody, _) = CanonicalWriterCustodyDataV1::from_opened_data_v1(
            opened, BTreeMap::new(), (),
        );
        std::fs::rename(directory.path().join("history"),
            directory.path().join("retired-history")).unwrap();
        OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(directory.path().join("history")).unwrap();
        let mut names = crate::writer_currentness::WriterCurrentnessOriginalsV1::<
            NativeJournalDataErrorV1,
        >::new();
        names.begin(true).unwrap();

        let result = custody.observe_names_into(&mut names);
        assert!(names.finish(result).is_err());
        let first = names.failure().unwrap() as *const dyn Error as *const ();
        let _same_held_file = custody.metadata().unwrap();

        assert!(!names.is_complete());
        assert!(names.retained_file_count() > 0);
        assert_eq!(first, names.failure().unwrap() as *const dyn Error as *const ());
    }
    #[test]
    fn selected_parser_identity_samples_same_file_once_without_changing_offset() {
        use std::io::Seek as _;

        let directory = tempfile::tempdir().unwrap();
        let opened = opened_data(directory.path());
        let expected = FileIdentity::of::<NativeJournalDataErrorV1>(&opened.file).unwrap();
        let mut opening = CanonicalWriterOpeningOriginalsV1::new();
        opening.metadata = Some(opened.file.metadata());
        opening.configuration = Some(opened.configuration);
        opening.file = Some(opened.file);
        opening.preparation = Some(Ok(()));
        let before_offset = opening.file.as_ref().unwrap().stream_position().unwrap();

        let identity = opening.prepare_selected_parser_identity_once().unwrap();
        let after_offset = opening.file.as_ref().unwrap().stream_position().unwrap();

        assert!(identity == expected);
        assert_eq!(before_offset, after_offset);
        assert!(opening.selected_parser_identity.completed_identity() == Some(&expected));
        assert!(opening.prepare_selected_parser_identity_once().is_err());
        assert!(opening.selected_parser_identity.completed_identity() == Some(&expected));
        assert!(matches!(opening.selected_parser_identity_result, Some(Ok(()))));
        assert!(opening.closed.is_some());
    }

    #[test]
    fn unprepared_selected_identity_refuses_without_sampling_or_entering_parser() {
        let mut opening = CanonicalWriterOpeningOriginalsV1::new();

        assert!(opening.prepare_selected_parser_identity_once().is_err());

        assert!(opening.selected_parser_identity_result.is_none());
        assert!(opening.selected_parser_identity.completed_identity().is_none());
        assert!(!opening.replay.cursor_started);
        assert!(opening.take_opened_parts_once().is_none());
    }

}
