//! Replays an already-held file through the same canonical cursor and index.
//!
//! The ordinary entry advances its original description; the captured entry
//! leaves that description's offset unchanged. Both borrow the actual holder.
//! This module creates no writer, role, challenge, financial account or semantic
//! completion, and accepts no file, resident map, index or replay-success input.

use std::error::Error;
use std::fs::Metadata;
use std::io::{self, Seek as _, SeekFrom};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1;

use super::{CanonicalOrdinaryHeldJournalV1, Index};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::{
    CanonicalReplayExtentDataV1, CanonicalReplayOriginalV1, NativeJournalDataErrorV1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Ordinary,
    CapturedOrdinary,
    CoordinatorOrdinary,
    PublishedBytesOrdinary,
}

/// Retains one actual same-file parser, private index and native observations.
///
/// The original remains inert until a held journal lends its own file. Upper
/// Source/Root semantics and independently owed native posts remain with their
/// real owner; successful structural replay supplies comparison DATA only.
pub struct CanonicalOrdinaryRereadOriginalV1 {
    replay: CanonicalReplayOriginalV1,
    index: Index,
    index_originals: CanonicalReplayIndexOriginalsV1,
    seek: Option<io::Result<u64>>,
    metadata: Option<io::Result<Metadata>>,
    identity: Option<FileIdentity>,
    preparation: Option<Result<(), NativeJournalDataErrorV1>>,
    mode: Option<Mode>,
    disposition: u8,
    reentry: Option<NativeJournalDataErrorV1>,
}

/// Owns one completed parser/index result for upper comparison only.
///
/// There is no public constructor, file, lock, location, mutable map or native
/// writer projection. Neither an ordinary nor selected opening accepts this
/// result as input. Its sole producer consumes the same actual reread original
/// after indexed EOF and the caller's ordinary scratch-disposal windows.
pub struct CanonicalOrdinaryRereadDataV1 {
    work: crate::canonical_journal::ReplayWork,
    index: Index,
}

impl CanonicalOrdinaryRereadDataV1 {
    /// Copies the actual reached and durable parser coordinates.
    #[must_use]
    pub fn coordinates_data_v1(&self) -> aos_sandbox_journal::replay::NativeReplayCoordinates {
        self.work.native.coordinates()
    }

    /// Borrows the actual complete materialized comparison map.
    #[must_use]
    pub fn state_data_v1(&self) -> &std::collections::BTreeMap<
        (aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>,
    > {
        &self.work.state
    }

    /// Borrows the actual committed transaction identities as DATA.
    #[must_use]
    pub fn transaction_ids_data_v1(&self) -> &std::collections::BTreeSet<[u8; 16]> {
        self.work.native.transaction_ids()
    }

    /// Borrows all actual committed namespace provenance as DATA.
    #[must_use]
    pub fn committed_namespaces_data_v1(&self) -> &std::collections::BTreeSet<
        aos_sandbox_model::RecordNamespace,
    > {
        &self.work.namespaces
    }

    /// Borrows this same replay's complete private idempotency index.
    #[must_use]
    pub fn idempotency_data_v1(&self) -> &Index {
        &self.index
    }

    /// Copies actual materialized-byte accounting without a currentness claim.
    #[must_use]
    pub fn materialized_bytes_data_v1(&self) -> usize {
        self.work.materialized
    }
}

impl CanonicalOrdinaryRereadOriginalV1 {
    /// Creates vacant native-result and index storage without IO or allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            replay: CanonicalReplayOriginalV1::new(),
            index: Index::new(),
            index_originals: CanonicalReplayIndexOriginalsV1::new(),
            seek: None,
            metadata: None,
            identity: None,
            preparation: None,
            mode: None,
            disposition: 0,
            reentry: None,
        }
    }

    /// Prices only compiled reread/control and outgoing comparison carriers.
    ///
    /// The actual native/index/semantic payload suppliers stay separate. This
    /// passive byte recipe creates no account, allowance, role or parser entry.
    /// Checked overflow returns None; Rust carriers add no namespace entries.
    #[must_use]
    pub fn receiving_control_bytes_data_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Metadata>().checked_mul(2)?))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<FileIdentity>().checked_mul(3)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<CanonicalIndexedReplayV1<'_, '_>>().checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    crate::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1<'_>
                >().checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<Result<
                    (FileIdentity, CanonicalIndexedReplayV1<'_, '_>), NativeJournalDataErrorV1
                >>())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<CanonicalOrdinaryRereadDataV1>()
                    .checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<Result<
                    CanonicalOrdinaryRereadDataV1, Self,
                >>())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<&[u8]>().checked_mul(2)?)
            })

    }

    /// Bounds the actual canonical parser, validator, index and new carriers.
    ///
    /// This passive quote grants no funding. Funded callers admit it before
    /// parser growth; ordinary callers retain their existing allocation policy.
    /// Source challenge/cache and other role models remain separate.
    ///
    /// # Errors
    /// Refuses overflow in these compiled carriers or the canonical suppliers.
    pub fn receiving_demand_v1(
        extent: CanonicalReplayExtentDataV1,
    ) -> Result<ResourceVector, NativeJournalDataErrorV1> {
        let overflow = || NativeJournalDataErrorV1::LimitExceeded("held reread representation");
        let fixed = u64::try_from(Self::receiving_control_bytes_data_v1()
            .ok_or_else(overflow)?)
            .map_err(|_| overflow())?;
        let index =
            CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent).map_err(|_| overflow())?;
        extent
            .dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(index))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed)))
            .map_err(|_| overflow())
    }

    /// Replays an actual opaque coordinator reader without changing its fence.
    ///
    /// Ordinary and selected callers keep their existing role, original native
    /// borrow and bounded/OFD behavior. In particular the selected Root cursor
    /// continues to acquire its native invocation guard for every read, seek and
    /// identity probe. No supplied file, map, prefix or role receipt is accepted.
    ///
    /// # Errors
    /// Retains actual native/index errors for ordered ordinary disposal; a
    /// repeated entry refuses before seek, metadata or parser work.
    pub fn begin_coordinator_ordinary_once_v1<'file, 'original>(
        &'original mut self,
        reader: crate::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1<'file>,
        limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'file, 'original>), NativeJournalDataErrorV1> {
        self.begin(Mode::CoordinatorOrdinary)?;
        // The canonical original retains the actual native preparation cause;
        // this slot only records entry, so its marker cannot mask that cause.
        self.preparation = Some(Ok(()));
        let (identity, cursor) = self.replay
            .begin_coordinator_ordinary_cursor_once(reader, limits)?;
        self.identity = Some(identity);
        Ok((identity, CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut self.index, &mut self.index_originals,
        )))
    }

    /// Parses a role's borrowed published readback as untrusted DATA only.
    ///
    /// The caller retains the real native readback Result, its actual identity,
    /// full semantic original, and independently owed native posts. Supplying
    /// bytes/identity cannot create a native journal or establish currentness.
    /// This method neither copies the buffer nor performs native IO.
    ///
    /// # Errors
    /// Retains actual parser/index errors and refuses reentry before parsing.
    pub fn begin_readback_bytes_ordinary_once_v1<'bytes, 'original>(
        &'original mut self,
        bytes: &'bytes [u8],
        identity: FileIdentity,
        limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'bytes, 'original>), NativeJournalDataErrorV1> {
        self.begin(Mode::PublishedBytesOrdinary)?;
        self.preparation = Some(Ok(()));
        self.identity = Some(identity);
        let cursor = self.replay.begin_readback_bytes_ordinary_cursor_once(bytes, limits)?;
        Ok((identity, CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut self.index, &mut self.index_originals,
        )))
    }

    /// Borrows the identity from this actual single parser-entry metadata probe.
    #[must_use]
    pub fn identity_data_v1(&self) -> Option<FileIdentity> {
        if self.reentry.is_some() || !matches!(self.preparation, Some(Ok(()))) {
            return None;
        }
        self.identity
    }

    /// Compares the complete actual native prefix and private index with a holder.
    ///
    /// This performs no IO and cannot install its replay into that holder. The
    /// caller still owes exact semantic completion and native currentness posts.
    #[must_use]
    pub fn matches_held_data_v1<P, I>(&self, held: &CanonicalOrdinaryHeldJournalV1<P, I>) -> bool {
        self.reentry.is_none()
            && matches!(self.preparation, Some(Ok(())))
            && self.index_originals.is_complete()
            && self.index == held.index
            && self.replay.matches_coordinator_view_v1(held.read_view_v1())
    }

    /// Reports the actually completed durable end without a currentness claim.
    #[must_use]
    pub fn completed_end_data_v1(&self) -> Option<u64> {
        if self.reentry.is_some() || !self.index_originals.is_complete() {
            return None;
        }
        Some(self.replay.report()?.0)
    }

    /// Borrows the earliest original native or reached index failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.seek
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.metadata
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.preparation
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.replay.failure())
            .or_else(|| self.index_originals.failure())
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    /// Disposes ordinary current native locals after the upper prospective map.
    ///
    /// # Errors
    /// Refuses unentered or repeated/out-of-order disposition without IO.
    pub fn dispose_ordinary_current_once_v1(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.mode.is_none() || self.disposition != 0 {
            return Err(self.refuse());
        }
        self.disposition = 1;
        let _ = self.replay.dispose_ordinary_current_once();
        Ok(())
    }

    /// Disposes ordinary pending locals after actual upper semantic scratch.
    ///
    /// # Errors
    /// Refuses unentered or repeated/out-of-order disposition without IO.
    pub fn dispose_ordinary_pending_once_v1(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.mode.is_none() || self.disposition != 1 {
            return Err(self.refuse());
        }
        self.disposition = 2;
        let _ = self.replay.dispose_ordinary_pending_once();
        Ok(())
    }

    /// Moves actual ordinary causes after current, upper and pending disposal.
    ///
    /// The index drops before the canonical native prefix. The upper role keeps
    /// its semantic/cursor error selection; a boundary marker never replaces a
    /// deeper actual stored cause. The real role retains its selected returned error.
    ///
    /// # Errors
    /// Returns this whole unchanged original unless the ordered disposal completed.
    #[allow(clippy::result_large_err)]
    pub fn into_ordinary_errors_v1(
        mut self,
    ) -> Result<
        (
            Option<IdempotencyRecordDataErrorV1>,
            Option<NativeJournalDataErrorV1>,
        ),
        Self,
    > {
        if self.mode.is_none() || self.disposition != 2 {
            return Err(self);
        }
        let index_cause = self.index_originals.into_ordinary_error();
        drop(self.index);
        let native_cause = self
            .seek
            .take()
            .and_then(Result::err)
            .map(NativeJournalDataErrorV1::Io)
            .or_else(|| {
                self.metadata
                    .take()
                    .and_then(Result::err)
                    .map(NativeJournalDataErrorV1::Io)
            })
            .or_else(|| self.preparation.take().and_then(Result::err))
            .or_else(|| self.replay.into_ordinary_error())
            .or(self.reentry);
        Ok((index_cause, native_cause))
    }

    /// Moves only this same completed reread's immutable comparison backing.
    ///
    /// No successful state can be supplied by a caller. The real upper owner
    /// first completes its full semantic recipe and ordinary current, upper and
    /// pending scratch disposal; its independently owed native posts remain
    /// upper. The returned data cannot install a prefix or open a writer.
    ///
    /// # Errors
    /// Returns this unchanged original on incomplete replay or wrong disposition.
    #[allow(clippy::result_large_err)]
    pub fn into_completed_comparison_data_v1(
        mut self,
    ) -> Result<CanonicalOrdinaryRereadDataV1, Self> {
        if self.reentry.is_some() || self.disposition != 2
            || !self.index_originals.is_complete() || self.replay.report().is_none()
        {
            return Err(self);
        }
        let Some(work) = self.replay.work.take() else {
            return Err(self);
        };
        Ok(CanonicalOrdinaryRereadDataV1 { work, index: self.index })
    }

    fn begin(&mut self, mode: Mode) -> Result<(), NativeJournalDataErrorV1> {
        if self.mode.is_some() {
            return Err(self.refuse());
        }
        self.mode = Some(mode);
        Ok(())
    }

    fn refuse(&mut self) -> NativeJournalDataErrorV1 {
        self.reentry
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        NativeJournalDataErrorV1::ProtectedBoundary
    }
}

impl Default for CanonicalOrdinaryRereadOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl<P, I> CanonicalOrdinaryHeldJournalV1<P, I> {
    /// Lends the same original file description to one ordinary indexed reread.
    ///
    /// The existing seek-to-zero and single identity probe precede all parser
    /// growth. This changes only the original read offset, not writer custody.
    /// Source role and complete challenge checks remain with the actual caller.
    /// The returned identity copies this entry's single metadata projection,
    /// so semantic replay needs neither another probe nor an overlapping borrow.
    ///
    /// # Errors
    /// Retains seek, metadata, bounds, parser or reentry refusal in the original.
    pub fn begin_ordinary_reread_once_v1<'file, 'original>(
        &'file mut self,
        original: &'original mut CanonicalOrdinaryRereadOriginalV1,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'file, 'original>), NativeJournalDataErrorV1>
    {
        original.begin(Mode::Ordinary)?;
        let (file, limits) = self.native.native_mut().file_with_limits_mut();
        original.seek = Some(file.seek(SeekFrom::Start(0)));
        if !matches!(original.seek, Some(Ok(_))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        original.metadata = Some(file.metadata());
        let metadata = original
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let identity = FileIdentity::from_metadata_data_v1(metadata);
        original.identity = Some(identity);
        original.preparation =
            Some(CanonicalReplayExtentDataV1::new(limits, metadata.len()).map(|_| ()));
        if !matches!(original.preparation, Some(Ok(()))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let cursor = original
            .replay
            .begin_ordinary_semantic_cursor_on_original_once(file, limits, metadata.clone())?;
        Ok((
            identity,
            CanonicalIndexedReplayV1::from_supplied_data_v1(
                cursor,
                &mut original.index,
                &mut original.index_originals,
            ),
        ))
    }

    /// Lends the same positional parser with ordinary validation and disposal.
    ///
    /// Original Release uses this existing immediate policy while its actual
    /// returned Result and independent native posts stay in the role owner.
    /// An unsuccessful parser does not acquire a new retained-graph policy.
    /// The original append description's offset remains unchanged.
    /// The returned identity copies this entry's actual metadata projection.
    ///
    /// # Errors
    /// Retains metadata, changed-length, native bounds, parser or reentry refusal
    /// until the actual ordinary current/upper/pending/index/native disposition.
    pub fn begin_captured_ordinary_reread_once_v1<'file, 'original>(
        &'file self,
        original: &'original mut CanonicalOrdinaryRereadOriginalV1,
        captured_length: u64,
    ) -> Result<(FileIdentity, CanonicalIndexedReplayV1<'file, 'original>), NativeJournalDataErrorV1>
    {
        original.begin(Mode::CapturedOrdinary)?;
        let native = self.native.native();
        let file = native.file();
        original.metadata = Some(file.metadata());
        let metadata = original
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        let identity = FileIdentity::from_metadata_data_v1(metadata);
        original.identity = Some(identity);
        original.preparation = Some((|| {
            CanonicalReplayExtentDataV1::new(native.limits(), captured_length)?;
            if metadata.len() != captured_length {
                return Err(NativeJournalDataErrorV1::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
        if !matches!(original.preparation, Some(Ok(()))) {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let cursor = original
            .replay
            .begin_ordinary_semantic_cursor_with_metadata_once(
                file,
                native.limits(),
                metadata.clone(),
            )?;
        Ok((
            identity,
            CanonicalIndexedReplayV1::from_supplied_data_v1(
                cursor,
                &mut original.index,
                &mut original.index_originals,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_journal::recovery::RecoveryTailMode;
    use aos_sandbox_protocol::domain_ledger::transaction::{
        JournalLimits, JournalRecord, JournalTransaction, encode_transaction,
    };

    use super::super::CanonicalOrdinaryOpeningOriginalsV1;
    use super::*;

    fn transaction(id: u8) -> JournalTransaction {
        let mut decision = vec![3; 32];
        decision.extend_from_slice(&[4; 16]);
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::Idempotency,
                vec![id],
                decision,
            )],
        )
        .unwrap()
    }

    fn held(path: &std::path::Path) -> CanonicalOrdinaryHeldJournalV1<()> {
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_unprotected_ordinary_once_v1(path, JournalLimits::default())
            .unwrap();
        opening.prepare_parser_identity_once_v1().unwrap();
        super::super::tests::finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RepairIncomplete)
            .unwrap();
        opening.take_held_without_instance_once_v1(()).unwrap().0
    }

    fn finish(
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
    ) -> Result<
        (),
        crate::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1,
    > {
        while cursor.advance_once()? {
            cursor.validate_compaction_once()?;
            cursor.register_and_compare_index_once()?;
            cursor.prepare_change_once()?;
            while cursor.apply_next_record_once()? {}
            cursor.finish_commit_accounting_once()?;
            cursor.finish_commit_once()?;
        }
        Ok(())
    }

    #[test]
    fn actual_ordinary_and_captured_rereads_preserve_their_distinct_offsets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history");
        let mut file = std::fs::File::create(&path).unwrap();
        for frame in encode_transaction(&transaction(1), 1).unwrap() {
            file.write_all(&frame).unwrap();
        }
        drop(file);
        let mut held = held(&path);
        let length = held.native.native().file().metadata().unwrap().len();
        held.native
            .native_mut()
            .file_with_limits_mut()
            .0
            .seek(SeekFrom::Start(9))
            .unwrap();

        let mut captured = CanonicalOrdinaryRereadOriginalV1::new();
        finish(
            &mut held
                .begin_captured_ordinary_reread_once_v1(&mut captured, length)
                .unwrap()
                .1,
        )
        .unwrap();
        assert!(captured.matches_held_data_v1(&held));
        let mut original_file = held.native.native().file();
        assert_eq!(original_file.stream_position().unwrap(), 9);
        assert_eq!(captured.completed_end_data_v1(), Some(length));

        let mut ordinary = CanonicalOrdinaryRereadOriginalV1::new();
        finish(&mut held.begin_ordinary_reread_once_v1(&mut ordinary).unwrap().1).unwrap();
        assert!(ordinary.matches_held_data_v1(&held));
        let mut original_file = held.native.native().file();
        assert_eq!(original_file.stream_position().unwrap(), length);
        let actual_state = ordinary.replay.state().unwrap()
            .values().next().unwrap().as_ptr();
        let mut ordinary = ordinary.into_completed_comparison_data_v1().err().unwrap();
        assert!(ordinary.matches_held_data_v1(&held));
        ordinary.dispose_ordinary_current_once_v1().unwrap();
        ordinary.dispose_ordinary_pending_once_v1().unwrap();
        let data = ordinary.into_completed_comparison_data_v1().ok().unwrap();

        assert_eq!(data.state_data_v1(), held.read_view_v1().state());
        assert_eq!(data.state_data_v1().values().next().unwrap().as_ptr(), actual_state);
        assert_eq!(data.transaction_ids_data_v1(), held.read_view_v1().transaction_ids());
        assert_eq!(data.idempotency_data_v1(), held.read_view_v1().idempotency_index());
    }

    #[test]
    fn corrupt_later_commit_keeps_actual_prior_index_and_cause_across_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history");
        let mut held = held(&path);
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        for frame in encode_transaction(&transaction(1), 1).unwrap() {
            writer.write_all(&frame).unwrap();
        }
        let mut frames = encode_transaction(&transaction(2), 4).unwrap();
        let last = frames.last_mut().unwrap();
        let end = last.len() - 1;
        last[end] ^= 1;
        for frame in frames {
            writer.write_all(&frame).unwrap();
        }
        drop(writer);
        let length = held.native.native().file().metadata().unwrap().len();

        let mut original = CanonicalOrdinaryRereadOriginalV1::new();
        assert!(
            finish(
                &mut held
                    .begin_captured_ordinary_reread_once_v1(&mut original, length)
                    .unwrap()
                    .1
            )
            .is_err()
        );
        assert_eq!(original.index.len(), 1);
        assert!(original.failure().unwrap().to_string().contains("checksum"));
        assert!(!original.matches_held_data_v1(&held));
        assert!(held.begin_ordinary_reread_once_v1(&mut original).is_err());
        assert_eq!(original.index.len(), 1);
        assert!(original.failure().unwrap().to_string().contains("checksum"));
        original.dispose_ordinary_current_once_v1().unwrap();
        assert_eq!(original.index.len(), 1);
        original.dispose_ordinary_pending_once_v1().unwrap();
        let (index_cause, native_cause) = original.into_ordinary_errors_v1().ok().unwrap();
        assert!(index_cause.is_none());
        assert!(native_cause.unwrap().to_string().contains("checksum"));
    }
}
