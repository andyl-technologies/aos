//! Pauses the same native parser at ordered role-semantic COMMIT frontiers.
//!
//! The cursor exposes borrowed comparison DATA only. A role retains its genuine
//! original, pays the captured extent before entry, and performs its own semantic
//! checks between the native steps. Completing this cursor cannot open a role
//! journal, issue a receiving loan, or authenticate a record.

use super::*;
use aos_sandbox_journal::replay::NativeReplayCoordinates;
use aos_sandbox_journal::storage::CapturedFileCursor;

/// Borrows the actual decoded COMMIT and its preceding materialized DATA.
///
/// This view has no public constructor and does not certify role semantics.
pub struct CanonicalCommitReadViewV1<'work> {
    work: &'work ReplayWork,
    transaction: &'work JournalTransaction,
    pending: &'work Pending,
    frame: &'work Frame,
}

impl CanonicalCommitReadViewV1<'_> {
    /// Borrows the actual canonical transaction without copying its records.
    pub fn transaction(&self) -> &JournalTransaction {
        self.transaction
    }

    /// Borrows the materialized prefix at the currently reached native stage.
    ///
    /// This is the preceding prefix until record application begins; each actual
    /// per-record apply then updates the same map before its role index step.
    pub fn prior_state(&self) -> &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        &self.work.state
    }

    /// Copies the actual reached frame and preceding durable coordinates.
    pub fn coordinates(&self) -> NativeReplayCoordinates {
        self.work.native.coordinates()
    }

    /// Copies the actual BEGIN sequence and byte offset.
    pub fn begin_position(&self) -> (u64, u64) {
        self.pending.native.begin_position()
    }

    /// Copies the actual COMMIT sequence.
    pub fn commit_sequence(&self) -> u64 {
        self.frame.sequence
    }

    /// Borrows the actual COMMIT payload used by existing history validators.
    pub fn commit_payload(&self) -> &[u8] {
        &self.frame.payload
    }

    /// Borrows the ordered-record digest from the actual validated COMMIT.
    ///
    /// The native payload is record-count:u32le followed by digest32. This
    /// accessor preserves that distinction when a passive native64 formatter
    /// needs only the digest. The sole transaction parser has already checked
    /// the count and ordered payload hash before lending this COMMIT view.
    ///
    /// # Errors
    /// Refuses a payload whose established native width is not36 bytes. No
    /// field is skipped in native validation and no digest is recomputed.
    pub fn commit_digest_data_v4(&self) -> Result<&[u8; 32], NativeJournalDataErrorV1> {
        if self.frame.payload.len() != 36 {
            return Err(NativeJournalDataErrorV1::MalformedTransaction("invalid commit payload"));
        }
        self.frame.payload[4..].try_into()
            .map_err(|_| NativeJournalDataErrorV1::MalformedTransaction("invalid commit digest"))
    }

    /// Copies the currently reached native materialized-byte accounting.
    ///
    /// Before change preparation this describes the preceding prefix; after
    /// preparation it describes the proposed change, matching the native engine.
    pub fn materialized_bytes(&self) -> usize {
        self.work.materialized
    }

    /// Compares the compaction identity only at the decoded frontier.
    ///
    /// Returns `None` after native compaction validation advances its index.
    /// This comparison never exempts a transaction from the role's own checks.
    pub fn compaction_candidate_before_validation(&self) -> Option<bool> {
        if self.work.commit_phase != Some(CommitPhase::Decoded) {
            return None;
        }
        let mut expected = [0u8; 16];
        expected[..8].copy_from_slice(&self.work.compaction_index.to_le_bytes());
        expected[8..].copy_from_slice(b"compact1");
        Some(self.work.compaction_prefix && *self.transaction.id() == expected)
    }
}

/// Borrows the actual complete structural prefix for final semantic checks.
///
/// This DATA view owns no file, native mutation or role completion. Structural
/// completion does not certify the caller's final semantic/pending/capacity cut.
#[derive(Clone, Copy)]
pub struct CanonicalReplayPrefixReadViewV1<'work> {
    work: &'work ReplayWork,
}

impl CanonicalReplayPrefixReadViewV1<'_> {
    /// Borrows the actual materialized prefix without cloning its map.
    #[must_use]
    pub fn state(&self) -> &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
        &self.work.state
    }

    /// Copies the actual parser's reached and durable coordinates as DATA.
    #[must_use]
    pub fn coordinates(&self) -> NativeReplayCoordinates {
        self.work.native.coordinates()
    }

    /// Returns actual native materialized-byte accounting as DATA.
    #[must_use]
    pub fn materialized_bytes(&self) -> usize {
        self.work.materialized
    }
}

enum ReplayReader<'file> {
    Captured(&'file File),
    Ordinary(&'file File),
    Coordinator(super::coordinator::CanonicalCoordinatorReadCursorV1<'file>),
    Bytes(std::io::Cursor<&'file [u8]>),
    #[cfg(test)]
    Fault(&'file mut tests::FailAfterPrefix),
}

impl ReplayReader<'_> {
    fn file(&self) -> Option<&File> {
        match self {
            Self::Captured(file) => Some(file),
            Self::Ordinary(file) => Some(file),
            Self::Coordinator(_) | Self::Bytes(_) => None,
            #[cfg(test)]
            Self::Fault(reader) => Some(&reader.file),
        }
    }
}

/// Borrows one actual file and its continuously retained replay destinations.
///
/// Dropping an unfinished cursor leaves its original permanently attempted and
/// unavailable as a successful prefix. Neither the file offset nor its ownership
/// changes for selected replay: the existing bounded positional reader supplies
/// each parser step. The ordinary original-description adapter keeps its old
/// actual seek/read schedule instead.
pub struct CanonicalReplayCursorV1<'file, 'original> {
    reader: ReplayReader<'file>,
    original: &'original mut CanonicalReplayOriginalV1,
    limits: JournalLimits,
    captured_length: u64,
    position: u64,
    finished: bool,
}

impl CanonicalReplayOriginalV1 {
    /// Begins a once-only staged replay of the independently paid actual extent.
    ///
    /// # Errors
    /// Retains the original metadata and bounds/length failure before returning
    /// a boundary classification. A prior attempt or changed length refuses
    /// before parser growth. The caller retains its role's actual paid original.
    pub fn begin_semantic_cursor_once<'file, 'original>(
        &'original mut self,
        file: &'file File,
        limits: JournalLimits,
        captured_length: u64,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        self.begin_cursor_inner(ReplayReader::Captured(file), limits, captured_length, true, None)
    }

    /// Begins retained replay with the owner's actual parser-entry metadata.
    ///
    /// The role keeps the original native Result. This moved metadata DATA copy
    /// avoids a second fstat while using the same bounds and captured-length
    /// checks; neither the copy nor this cursor establishes role admission.
    ///
    /// # Errors
    /// Retains native bounds, captured-length, repeated-entry or parser refusal.
    pub fn begin_semantic_cursor_with_metadata_once<'file, 'original>(
        &'original mut self,
        file: &'file File,
        limits: JournalLimits,
        captured_length: u64,
        metadata: std::fs::Metadata,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        self.begin_cursor_inner(
            ReplayReader::Captured(file), limits, captured_length, true, Some(metadata),
        )
    }

    /// Begins the same parser for an ordinary immediate role adapter.
    ///
    /// Its canonical validator uses the existing immediate error vocabulary
    /// and temporary-disposal boundary. Selected roles use the retained entry.
    ///
    /// # Errors
    /// Retains preparation/parser failure until `into_ordinary_error` moves the
    /// actual error and disposes the ordinary replay locals at the caller's
    /// original return boundary. Repeated or changed-extent entry refuses.
    pub fn begin_ordinary_semantic_cursor_once<'file, 'original>(
        &'original mut self,
        file: &'file File,
        limits: JournalLimits,
        captured_length: u64,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        self.begin_cursor_inner(ReplayReader::Captured(file), limits, captured_length, false, None)
    }

    /// Moves the ordinary opener's already observed metadata into this replay.
    ///
    /// This immediate adapter avoids a second metadata syscall. Metadata is
    /// comparison DATA; it authenticates no path, file, original or role.
    ///
    /// # Errors
    /// Preserves the ordinary cursor's first bounds, parser or order failure.
    pub fn begin_ordinary_semantic_cursor_with_metadata_once<'file, 'original>(
        &'original mut self,
        file: &'file File,
        limits: JournalLimits,
        metadata: std::fs::Metadata,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        let length = metadata.len();
        self.begin_cursor_inner(ReplayReader::Captured(file), limits, length, false, Some(metadata))
    }

    /// Borrows the original ordinary File description after its old preflight.
    ///
    /// Unlike the selected captured reader, this adapter advances the actual
    /// original offset. The caller performs the old seek-to-zero and file
    /// identity sample before entry, retaining their actual Results itself.
    ///
    /// # Errors
    /// Preserves the same ordinary cursor's bounds, parser and order failure.
    pub fn begin_ordinary_semantic_cursor_on_original_once<'file, 'original>(
        &'original mut self,
        file: &'file mut File,
        limits: JournalLimits,
        metadata: std::fs::Metadata,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        let length = metadata.len();
        self.begin_cursor_inner(ReplayReader::Ordinary(file), limits, length, false, Some(metadata))
    }

    // Only actual common owners can borrow their own File here. Shared File
    // references implement Read/Seek on the same OFD; no positional substitute,
    // native projection or extra metadata probe is introduced. Native scratch
    // retention is independent of the upper Source-family retention policy.
    pub(crate) fn begin_shared_original_cursor_once<'file, 'original>(
        &'original mut self,
        file: &'file File,
        limits: JournalLimits,
        metadata: std::fs::Metadata,
        retaining_validation: bool,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        self.begin_cursor_inner(
            ReplayReader::Ordinary(file), limits, metadata.len(),
            retaining_validation, Some(metadata),
        )
    }

    /// Begins ordinary replay through an existing opaque coordinator reader.
    ///
    /// The reader retains its actual bounded/OFD behavior and any selected Root
    /// invocation fence on every IO. This consumes no File, map, native owner or
    /// role receipt. It preserves the caller's old seek-to-zero and single
    /// identity probe without adding a metadata/length race comparison.
    ///
    /// # Errors
    /// Retains the actual seek or identity failure and refuses repeated entry.
    /// Parser and index failures remain in the same existing staged originals.
    pub fn begin_coordinator_ordinary_cursor_once<'file, 'original>(
        &'original mut self,
        mut reader: super::coordinator::CanonicalCoordinatorReadCursorV1<'file>,
        limits: JournalLimits,
    ) -> Result<
        (aos_sandbox_journal::protected_storage::FileIdentity,
         CanonicalReplayCursorV1<'file, 'original>),
        NativeJournalDataErrorV1,
    > {
        use aos_sandbox_journal::storage::JournalReadIdentityDataV1 as _;

        if self.cursor_started || self.outcome.is_some() {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.cursor_started = true;
        let mut work = ReplayWork::new();
        work.retaining_validation = false;
        self.work = Some(work);
        self.cursor_preparation = Some(reader.seek(SeekFrom::Start(0))
            .map(|_| ()).map_err(NativeJournalDataErrorV1::Io));
        if !matches!(self.cursor_preparation, Some(Ok(()))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }

        let identity = match reader.sample_file_identity_v1() {
            Ok(identity) => identity,
            Err(cause) => {
                self.cursor_preparation = Some(Err(NativeJournalDataErrorV1::Io(cause)));
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
        };
        Ok((identity, CanonicalReplayCursorV1 {
            reader: ReplayReader::Coordinator(reader),
            original: self,
            limits,
            captured_length: 0,
            position: 0,
            finished: false,
        }))
    }

    /// Parses borrowed readback bytes as ordinary untrusted comparison DATA.
    ///
    /// This creates no native observation. The actual owner must perform its
    /// published-readback and identity operations first and independently compare
    /// the result afterward. Neither bytes nor identity grant a role, current
    /// cut, financial allowance or native writer. The same sole parser runs on
    /// this bounded in-memory input without opening, probing or copying a file.
    ///
    /// # Errors
    /// Refuses repeated entry and retains the actual parser's typed error.
    pub fn begin_readback_bytes_ordinary_cursor_once<'bytes, 'original>(
        &'original mut self,
        bytes: &'bytes [u8],
        limits: JournalLimits,
    ) -> Result<CanonicalReplayCursorV1<'bytes, 'original>, NativeJournalDataErrorV1> {
        if self.cursor_started || self.outcome.is_some() {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.cursor_started = true;
        let mut work = ReplayWork::new();
        work.retaining_validation = false;
        self.work = Some(work);
        self.cursor_preparation = Some(Ok(()));
        Ok(CanonicalReplayCursorV1 {
            reader: ReplayReader::Bytes(std::io::Cursor::new(bytes)),
            original: self,
            limits,
            captured_length: 0,
            position: 0,
            finished: false,
        })
    }

    fn begin_cursor_inner<'file, 'original>(
        &'original mut self,
        reader: ReplayReader<'file>,
        limits: JournalLimits,
        captured_length: u64,
        retaining_validation: bool,
        metadata: Option<std::fs::Metadata>,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        if self.cursor_started || self.outcome.is_some() {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.cursor_started = true;
        let mut work = ReplayWork::new();
        work.retaining_validation = retaining_validation;
        self.work = Some(work);
        self.metadata = metadata.map(Ok);
        self.cursor_preparation = Some((|| {
            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())?;
            if self.metadata.is_none() {
                self.metadata = Some(
                    reader.file().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.metadata(),
                );
            }
            let actual_length = self.metadata.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?.len();
            if actual_length != captured_length {
                return Err(NativeJournalDataErrorV1::StaleAuthoritySnapshot);
            }
            if actual_length > limits.maximum_journal_bytes {
                return Err(NativeJournalDataErrorV1::JournalTooLarge);
            }
            Ok(())
        })());
        if !matches!(self.cursor_preparation, Some(Ok(()))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }

        Ok(CanonicalReplayCursorV1 {
            reader,
            original: self,
            limits,
            captured_length,
            position: 0,
            finished: false,
        })
    }
}

impl CanonicalReplayCursorV1<'_, '_> {
    /// Advances the existing parser to its next canonical decoded COMMIT.
    ///
    /// Returns `false` only at the existing complete replay boundary. A reached
    /// COMMIT remains resident until all four ordered native steps complete.
    ///
    /// # Errors
    /// Retains any native frame, decoder, bounds or out-of-order refusal. An
    /// unfinished COMMIT cannot be skipped and a failed cursor cannot resume.
    pub fn advance_once(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        self.require_active()?;
        if self.original.work.as_ref().is_none_or(|work| work.commit_phase.is_some()) {
            return self.refuse_order();
        }

        let result = (|| {
            let work = self.original.work.as_mut()
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
            let reached = match &mut self.reader {
                ReplayReader::Captured(file) => {
                    let mut reader = CapturedFileCursor::new(file, self.captured_length);
                    reader.seek(SeekFrom::Start(self.position))?;
                    work.advance_to_commit(&mut reader, self.limits)?
                }
                ReplayReader::Ordinary(file) => work.advance_to_commit(file, self.limits)?,
                ReplayReader::Coordinator(reader) => work.advance_to_commit(reader, self.limits)?,
                ReplayReader::Bytes(reader) => work.advance_to_commit(reader, self.limits)?,
                #[cfg(test)]
                ReplayReader::Fault(reader) => work.advance_to_commit(*reader, self.limits)?,
            };
            self.position = work.native.coordinates().offset;
            Ok(reached)
        })();
        match result {
            Ok(reached) => {
                self.original.cursor_step = Some(Ok(()));
                if !reached {
                    self.original.outcome = Some(Ok(()));
                    self.finished = true;
                }
                Ok(reached)
            }
            Err(cause) => {
                self.original.cursor_step = Some(Err(cause));
                Err(NativeJournalDataErrorV1::ProtectedBoundary)
            }
        }
    }

    /// Lends a completed structural prefix to the existing final semantic checks.
    ///
    /// A failed or incomplete cursor lends none. This passive view cannot move
    /// the native owner, finish a role or issue successful opening authority.
    #[must_use]
    pub fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        if !self.finished || !matches!(self.original.outcome, Some(Ok(()))) {
            return None;
        }
        Some(CanonicalReplayPrefixReadViewV1 { work: self.original.work.as_ref()? })
    }

    /// Borrows the current actual COMMIT without manufacturing a transaction.
    pub fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.require_active().ok()?;
        let work = self.original.work.as_ref()?;
        work.commit_phase?;
        Some(CanonicalCommitReadViewV1 {
            transaction: work.transaction.as_ref()?,
            pending: work.reached_pending.as_ref()?,
            frame: work.frame.as_ref()?,
            work,
        })
    }

    /// Runs the existing native compaction-key check after earlier role hooks.
    ///
    /// # Errors
    /// Retains the actual compaction failure or an out-of-order refusal.
    pub fn validate_compaction_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .validate_current_compaction();
        self.park_step(result)
    }

    /// Registers the actual transaction identity after role-semantic checks.
    ///
    /// # Errors
    /// Retains the actual duplicate identity or out-of-order refusal.
    pub fn register_transaction_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .register_current_commit();
        self.park_step(result)
    }

    /// Prepares native materialization after the role's idempotency check.
    ///
    /// # Errors
    /// Retains the same native materialization error or out-of-order refusal.
    pub fn prepare_change_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .prepare_current_change(self.limits);
        self.park_step(result)
    }

    /// Applies the actual prepared transaction after the role's final checks.
    ///
    /// # Errors
    /// Retains native commit-accounting failures. This method cannot implicitly
    /// skip compaction, registration or materialization stages.
    pub fn apply_commit_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        if self.original.work.as_ref().and_then(|work| work.commit_phase)
            != Some(CommitPhase::Prepared)
        {
            return self.refuse_order();
        }
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .apply_current_commit(self.limits);
        self.park_step(result)
    }

    /// Applies the next actual record before its role-owned index update.
    ///
    /// Returns `false` after the last record. While the returned step is
    /// positive, `last_applied_record` lends that same transaction record to the
    /// existing idempotency adapter without copying its key or value.
    ///
    /// # Errors
    /// Retains an out-of-order or missing-original refusal. The role must still
    /// finish commit accounting after every required record/index step.
    pub fn apply_next_record_once(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .apply_next_record();
        match result {
            Ok(applied) => {
                self.park_step(Ok(()))?;
                Ok(applied)
            }
            Err(cause) => {
                self.park_step(Err(cause))?;
                Err(NativeJournalDataErrorV1::ProtectedBoundary)
            }
        }
    }

    /// Borrows the last actually applied transaction record for its index step.
    pub fn last_applied_record(&self) -> Option<&JournalRecord> {
        self.require_active().ok()?;
        let work = self.original.work.as_ref()?;
        if work.commit_phase != Some(CommitPhase::Prepared) {
            return None;
        }
        work.transaction.as_ref()?.records().get(work.applied_records.checked_sub(1)?)
    }

    /// Completes native accounting after the role's last record/index update.
    ///
    /// # Errors
    /// Retains native count/sequence failures or refusal of unapplied records.
    pub fn finish_commit_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .finish_current_commit(self.limits);
        self.park_step(result)
    }

    /// Advances actual COMMIT accounting while retaining its transaction prefix.
    ///
    /// The upper semantic owner performs its existing final COMMIT checks
    /// before calling [`Self::dispose_completed_commit_once`]. No completion
    /// DATA or success flag can substitute for this actual parser phase.
    ///
    /// # Errors
    /// Retains original count/sequence or unfinished-record refusal.
    pub fn finish_commit_accounting_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .finish_current_accounting(self.limits);
        self.park_step(result)
    }

    /// Disposes the actual accounted COMMIT at the caller's positive boundary.
    ///
    /// # Errors
    /// Refuses a foreign phase, failed accounting or repeated disposal. An
    /// unfinished upper interval leaves all native transaction fields resident.
    pub fn dispose_completed_commit_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.require_active()?;
        let result = self.original.work.as_mut()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?
            .dispose_completed_commit();
        self.park_step(result)
    }

    /// Borrows the retained original failure without repeating native work.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }

    fn require_active(&self) -> Result<(), NativeJournalDataErrorV1> {
        if self.finished
            || !matches!(self.original.cursor_preparation, Some(Ok(())))
            || matches!(self.original.cursor_step, Some(Err(_)))
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        Ok(())
    }

    fn refuse_order<T>(&mut self) -> Result<T, NativeJournalDataErrorV1> {
        self.park_step(Err(NativeJournalDataErrorV1::ProtectedBoundary))?;
        Err(NativeJournalDataErrorV1::ProtectedBoundary)
    }

    fn park_step(&mut self, result: Result<(), NativeJournalDataErrorV1>)
        -> Result<(), NativeJournalDataErrorV1>
    {
        let positive = result.is_ok();
        self.original.cursor_step = Some(result);
        if positive { Ok(()) } else { Err(NativeJournalDataErrorV1::ProtectedBoundary) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_transaction(file: &mut File, transaction: &JournalTransaction, sequence: u64) {
        for frame in data::encode_transaction(transaction, sequence).unwrap() {
            file.write_all(&frame).unwrap();
        }
    }

    pub(super) struct FailAfterPrefix {
        pub(super) file: File,
        prefix_bytes: usize,
        read_bytes: usize,
        attempted_later_read: bool,
    }

    impl Read for FailAfterPrefix {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.read_bytes >= self.prefix_bytes {
                self.attempted_later_read = true;
                return Err(io::Error::other("later frame read must not occur"));
            }
            let read = self.file.read(bytes)?;
            self.read_bytes += read;
            Ok(read)
        }
    }

    impl Seek for FailAfterPrefix {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            let position = self.file.seek(position)?;
            self.read_bytes = usize::try_from(position).map_err(io::Error::other)?;
            Ok(position)
        }
    }

    #[test]
    fn replay_rejects_unknown_namespace_before_attempting_later_frame_io() {
        let frames = aos_sandbox_journal::transaction::encode_transaction(
            [7; 16], 1,
            [aos_sandbox_journal::transaction::NativeRecordRef {
                namespace_byte: 255, key: b"key", value: None,
            }].into_iter(),
        ).unwrap();
        let prefix = [&frames[0][..], &frames[1][..]].concat();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&prefix).unwrap();
        let mut reader = FailAfterPrefix {
            file, prefix_bytes: prefix.len(), read_bytes: 0, attempted_later_read: false,
        };
        reader.seek(SeekFrom::Start(0)).unwrap();
        let metadata = reader.file.metadata().unwrap();
        let mut original = CanonicalReplayOriginalV1::new();
        let mut cursor = original.begin_cursor_inner(
            ReplayReader::Fault(&mut reader), JournalLimits::default(),
            metadata.len(), false, Some(metadata),
        ).unwrap();

        assert!(cursor.advance_once().is_err());
        drop(cursor);
        assert!(matches!(original.into_ordinary_error(), Some(
            NativeJournalDataErrorV1::Transaction(
                JournalTransactionDataError::MalformedRecord("unknown record namespace")
            )
        )));
        assert_eq!(reader.read_bytes, prefix.len());
        assert!(!reader.attempted_later_read);
    }

    #[test]
    fn coordinator_replay_keeps_its_original_bound_and_description_offset() {
        use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;
        use super::super::coordinator::CanonicalCoordinatorReadCursorV1;

        let mut file = tempfile::tempfile().unwrap();
        let transaction = JournalTransaction::new([7; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![2], vec![3]),
        ]).unwrap();
        write_transaction(&mut file, &transaction, 1);
        let end = file.stream_position().unwrap();
        file.write_all(b"later uncommitted bytes").unwrap();
        let outside_offset = file.stream_position().unwrap();
        let reader = CanonicalCoordinatorReadCursorV1::from_parts(
            ReadOnlyCapturedFileCursorV1::new(&file, end), None,
        );
        let mut original = CanonicalReplayOriginalV1::new();
        let (identity, mut cursor) = original.begin_coordinator_ordinary_cursor_once(
            reader, JournalLimits::default(),
        ).unwrap();

        assert_eq!(identity.byte_len(), outside_offset);
        assert!(cursor.advance_once().unwrap());
        assert_eq!(cursor.current_commit().unwrap().transaction(), &transaction);
        cursor.validate_compaction_once().unwrap();
        cursor.register_transaction_once().unwrap();
        cursor.prepare_change_once().unwrap();
        cursor.apply_commit_once().unwrap();
        assert!(!cursor.advance_once().unwrap());
        drop(cursor);
        assert_eq!(file.stream_position().unwrap(), outside_offset);
        assert_eq!(original.report().unwrap().0, end);

        let mut actual_original = CanonicalReplayOriginalV1::new();
        let reader = CanonicalCoordinatorReadCursorV1::from_original(&file, None);
        let (_, mut cursor) = actual_original.begin_coordinator_ordinary_cursor_once(
            reader, JournalLimits::default(),
        ).unwrap();
        assert_eq!((&file).stream_position().unwrap(), 0);
        assert!(cursor.advance_once().unwrap());
        assert_eq!((&file).stream_position().unwrap(), end);
        drop(cursor);
        let prior = actual_original.failure().map(|cause| cause.to_string());
        let reader = CanonicalCoordinatorReadCursorV1::from_original(&file, None);
        assert!(actual_original.begin_coordinator_ordinary_cursor_once(
            reader, JournalLimits::default(),
        ).is_err());
        assert_eq!((&file).stream_position().unwrap(), end);
        assert_eq!(actual_original.failure().map(|cause| cause.to_string()), prior);
    }

    #[test]
    fn semantic_frontier_precedes_invalid_compaction_and_retains_the_actual_commit() {
        let mut file = tempfile::tempfile().unwrap();
        let mut id = [0; 16];
        id[..8].copy_from_slice(&1u64.to_le_bytes());
        id[8..].copy_from_slice(b"compact1");
        let transaction = JournalTransaction::from_unvalidated_data(id, vec![
            JournalRecord::delete(RecordNamespace::Operation, vec![8, 9]),
        ]);
        write_transaction(&mut file, &transaction, 1);
        let length = file.metadata().unwrap().len();
        let mut original = CanonicalReplayOriginalV1::new();
        let mut cursor = original.begin_semantic_cursor_once(
            &file, JournalLimits::default(), length,
        ).unwrap();

        assert!(cursor.advance_once().unwrap());
        let decoded = cursor.current_commit().unwrap();
        assert_eq!(decoded.transaction(), &transaction);
        assert_eq!(decoded.compaction_candidate_before_validation(), Some(true));
        assert!(decoded.prior_state().is_empty());
        assert_eq!(decoded.begin_position(), (1, 0));
        assert_eq!(decoded.commit_sequence(), 3);
        assert_eq!(decoded.coordinates().committed_transactions, 0);
        let actual_key = decoded.transaction().records()[0].key().as_ptr();

        assert!(cursor.validate_compaction_once().is_err());
        let first_cause = cursor.failure().unwrap() as *const dyn Error as *const ();
        assert!(cursor.advance_once().is_err());
        assert_eq!(cursor.failure().unwrap() as *const dyn Error as *const (), first_cause);
        drop(cursor);

        let work = original.work.as_ref().unwrap();
        assert_eq!(work.transaction.as_ref().unwrap().records()[0].key().as_ptr(), actual_key);
        assert_eq!(work.compaction_current.as_ref(), Some(&(RecordNamespace::Operation, vec![8, 9])));
        assert_eq!(work.native.coordinates().committed_transactions, 0);
        assert!(work.state.is_empty());
        assert!(original.take_prefix().is_none());
    }

    #[test]
    fn staged_real_frames_match_ordinary_replay_with_each_record_index_frontier() {
        let mut file = tempfile::tempfile().unwrap();
        let transaction = JournalTransaction::new([7; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![2], vec![3]),
            JournalRecord::put(RecordNamespace::Operation, vec![4], vec![5]),
        ]).unwrap();
        write_transaction(&mut file, &transaction, 1);
        let length = file.metadata().unwrap().len();
        let mut ordinary = CanonicalReplayOriginalV1::new();
        ordinary.capture_prefix_once(&file, JournalLimits::default(), length).unwrap();
        let mut staged = CanonicalReplayOriginalV1::new();
        let mut cursor = staged.begin_semantic_cursor_once(
            &file, JournalLimits::default(), length,
        ).unwrap();

        assert!(cursor.advance_once().unwrap());
        let commit = cursor.current_commit().unwrap();
        assert_eq!(commit.commit_payload().len(), 36);
        assert_eq!(&commit.commit_payload()[..4], &2_u32.to_le_bytes());
        assert_eq!(commit.commit_digest_data_v4().unwrap().as_slice(), &commit.commit_payload()[4..]);
        cursor.validate_compaction_once().unwrap();
        cursor.register_transaction_once().unwrap();
        assert_eq!(cursor.current_commit().unwrap().coordinates().committed_transactions, 0);
        cursor.prepare_change_once().unwrap();
        for expected in transaction.records() {
            assert!(cursor.apply_next_record_once().unwrap());
            assert_eq!(cursor.last_applied_record(), Some(expected));
            let reached = cursor.current_commit().unwrap();
            assert_eq!(reached.prior_state().get(&(expected.namespace(), expected.key().to_vec()))
                .map(Vec::as_slice), expected.value());
        }
        assert!(!cursor.apply_next_record_once().unwrap());
        cursor.finish_commit_once().unwrap();
        assert!(!cursor.advance_once().unwrap());
        drop(cursor);

        assert_eq!(staged.report(), ordinary.report());
        assert_eq!(staged.state(), ordinary.state());
        let staged_work = staged.work.as_ref().unwrap();
        let ordinary_work = ordinary.work.as_ref().unwrap();
        assert_eq!(staged_work.native.transaction_ids(), ordinary_work.native.transaction_ids());
        assert_eq!(staged_work.namespaces, ordinary_work.namespaces);
        assert_eq!(staged_work.materialized, ordinary_work.materialized);
    }

    #[test]
    fn accounted_commit_keeps_actual_transaction_until_semantic_disposal() {
        let mut file = tempfile::tempfile().unwrap();
        let transaction = JournalTransaction::new([23; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![2], vec![3]),
        ]).unwrap();
        write_transaction(&mut file, &transaction, 1);
        let length = file.metadata().unwrap().len();
        let mut original = CanonicalReplayOriginalV1::new();
        let mut cursor = original.begin_semantic_cursor_once(
            &file, JournalLimits::default(), length,
        ).unwrap();

        assert!(cursor.advance_once().unwrap());
        cursor.validate_compaction_once().unwrap();
        cursor.register_transaction_once().unwrap();
        cursor.prepare_change_once().unwrap();
        assert!(cursor.apply_next_record_once().unwrap());
        let original_key = cursor.current_commit().unwrap().transaction().records()[0].key().as_ptr();
        cursor.finish_commit_accounting_once().unwrap();

        let reached = cursor.current_commit().unwrap();
        assert_eq!(reached.transaction(), &transaction);
        assert_eq!(reached.transaction().records()[0].key().as_ptr(), original_key);
        assert_eq!(reached.coordinates().committed_transactions, 1);
        assert_eq!(reached.coordinates().durable_end, length);
        assert!(cursor.completed_prefix().is_none());

        cursor.dispose_completed_commit_once().unwrap();
        assert!(cursor.current_commit().is_none());
        assert!(!cursor.advance_once().unwrap());
        let prefix = cursor.completed_prefix().unwrap();
        assert_eq!(prefix.coordinates().durable_end, length);
        assert_eq!(prefix.state().get(&(RecordNamespace::Operation, vec![2])), Some(&vec![3]));
    }

    #[test]
    fn failed_commit_accounting_retains_actual_second_transaction_and_old_boundary() {
        let mut file = tempfile::tempfile().unwrap();
        let first = JournalTransaction::new([24; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![2], vec![3]),
        ]).unwrap();
        let second = JournalTransaction::new([25; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![4], vec![5]),
        ]).unwrap();
        write_transaction(&mut file, &first, 1);
        let first_end = file.metadata().unwrap().len();
        write_transaction(&mut file, &second, 4);
        let length = file.metadata().unwrap().len();
        let mut limits = JournalLimits::default();
        limits.maximum_transactions = 1;
        let mut original = CanonicalReplayOriginalV1::new();
        let mut cursor = original.begin_semantic_cursor_once(&file, limits, length).unwrap();

        assert!(cursor.advance_once().unwrap());
        cursor.validate_compaction_once().unwrap();
        cursor.register_transaction_once().unwrap();
        cursor.prepare_change_once().unwrap();
        assert!(cursor.apply_next_record_once().unwrap());
        cursor.finish_commit_once().unwrap();
        assert!(cursor.advance_once().unwrap());
        cursor.validate_compaction_once().unwrap();
        cursor.register_transaction_once().unwrap();
        cursor.prepare_change_once().unwrap();
        assert!(cursor.apply_next_record_once().unwrap());
        assert!(cursor.finish_commit_accounting_once().is_err());
        assert!(cursor.dispose_completed_commit_once().is_err());
        assert!(cursor.completed_prefix().is_none());
        drop(cursor);

        let work = original.work.as_ref().unwrap();
        assert_eq!(work.transaction.as_ref(), Some(&second));
        assert!(work.reached_pending.is_some());
        assert!(work.frame.is_some());
        assert_eq!(work.native.coordinates().committed_transactions, 2);
        assert_eq!(work.native.coordinates().durable_end, first_end);
        assert!(original.take_prefix().is_none());
    }

    #[test]
    fn ordinary_cursor_moves_precise_duplicate_key_error_without_selected_projection() {
        let mut file = tempfile::tempfile().unwrap();
        let transaction = JournalTransaction::from_unvalidated_data([12; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![3], vec![4]),
            JournalRecord::put(RecordNamespace::Operation, vec![3], vec![5]),
        ]);
        write_transaction(&mut file, &transaction, 1);
        let length = file.metadata().unwrap().len();
        let mut ordinary = CanonicalReplayOriginalV1::new();
        let mut cursor = ordinary.begin_ordinary_semantic_cursor_once(
            &file, JournalLimits::default(), length,
        ).unwrap();

        assert!(cursor.advance_once().is_err());
        drop(cursor);
        assert!(matches!(ordinary.into_ordinary_error(), Some(
            NativeJournalDataErrorV1::Transaction(JournalTransactionDataError::DuplicateRecordKey)
        )));

        let mut selected = CanonicalReplayOriginalV1::new();
        let mut cursor = selected.begin_semantic_cursor_once(
            &file, JournalLimits::default(), length,
        ).unwrap();
        assert!(cursor.advance_once().is_err());
        drop(cursor);
        assert!(matches!(selected.work.as_ref().unwrap().validation.failure(),
            Some(JournalTransactionDataError::DuplicateRecordKey)));
        assert!(selected.work.as_ref().unwrap().transaction.is_some());
    }

    #[test]
    fn ordinary_cursor_moves_the_actual_native_read_error() {
        let file = File::open(std::env::temp_dir()).unwrap();
        let length = file.metadata().unwrap().len();
        let mut ordinary = CanonicalReplayOriginalV1::new();
        let mut cursor = ordinary.begin_ordinary_semantic_cursor_once(
            &file, JournalLimits::default(), length,
        ).unwrap();

        assert!(cursor.advance_once().is_err());
        drop(cursor);
        assert!(matches!(ordinary.into_ordinary_error(),
            Some(NativeJournalDataErrorV1::Frame(FrameError::Io(error)))
                if error.raw_os_error() == Some(rustix::io::Errno::ISDIR.raw_os_error())));
    }


    #[test]
    fn ordinary_original_reader_advances_real_offset_and_disposes_in_role_windows() {
        let mut file = tempfile::tempfile().unwrap();
        let transaction = JournalTransaction::new([19; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![8]),
        ]).unwrap();
        write_transaction(&mut file, &transaction, 1);
        let length = file.metadata().unwrap().len();
        let metadata = file.metadata().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut original = CanonicalReplayOriginalV1::new();
        let mut cursor = original.begin_ordinary_semantic_cursor_on_original_once(
            &mut file, JournalLimits::default(), metadata,
        ).unwrap();

        assert!(cursor.advance_once().unwrap());
        cursor.validate_compaction_once().unwrap();
        cursor.register_transaction_once().unwrap();
        cursor.prepare_change_once().unwrap();
        cursor.apply_commit_once().unwrap();
        assert!(!cursor.advance_once().unwrap());
        drop(cursor);
        assert_eq!(file.stream_position().unwrap(), length);
        assert!(!original.dispose_ordinary_pending_once());
        assert!(original.dispose_ordinary_current_once());
        assert!(!original.dispose_ordinary_current_once());
        assert!(original.work.as_ref().unwrap().state.contains_key(&(RecordNamespace::Operation, vec![7])));
        assert!(original.dispose_ordinary_pending_once());
        assert!(original.work.as_ref().unwrap().state.contains_key(&(RecordNamespace::Operation, vec![7])));
        assert!(original.into_ordinary_error().is_none());
    }

}
