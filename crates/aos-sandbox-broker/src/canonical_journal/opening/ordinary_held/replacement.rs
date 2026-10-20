//! Keeps ordinary replacement replay and installation on the same actual bundle.
//!
//! The existing physical adapter owns the replacement File and cleanup loan.
//! This composition supplies its sole canonical cursor and private replay index.
//! Completion ends the old immutable borrow before same-instance installation;
//! the upper role installs its semantic remainder before one late marker change.

use std::error::Error;
use std::io;

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_journal::owner::NativeJournalState;
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1;

use super::{CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1, Index};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::coordinator::replacement::{
    CanonicalReplacementErrorV1, OrdinaryCoordinatorReplacementV1, OrdinaryReplacementFileDataV1,
};
use crate::canonical_journal::{CanonicalReplayOriginalV1, NativeJournalDataErrorV1};

/// Borrows one actual ordinary replacement through its own parser and index.
///
/// Neither supplied replay state nor a comparison handle can construct this
/// owner. Upper semantics run between the existing indexed cursor's steps.
/// The returned borrow prevents another replacement of the same holder:
///
/// ```compile_fail
/// use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryHeldJournalV1;
/// fn parallel<P, I>(held: &mut CanonicalOrdinaryHeldJournalV1<P, I>) {
///     let first = held.prepare_replacement_once_v1().unwrap();
///     let second = held.prepare_replacement_once_v1().unwrap();
///     drop(first);
///     drop(second);
/// }
/// ```
#[must_use]
pub struct CanonicalOrdinaryReplacementV1<'old, P, I> {
    physical: Option<OrdinaryCoordinatorReplacementV1<'old, P>>,
    replay: CanonicalReplayOriginalV1,
    index: Index,
    indexed: CanonicalReplayIndexOriginalsV1,
    parser_seek: Option<io::Result<u64>>,
    parser_metadata: Option<io::Result<std::fs::Metadata>>,
    parser_identity: Option<FileIdentity>,
    instance: CanonicalJournalInstanceDataV1<I>,
    previous_next: u64,
    replay_started: bool,
    ordinary_disposition: u8,
    closed: Option<NativeJournalDataErrorV1>,
}

/// Owns only a completed replacement's actual file, canonical prefix and index.
///
/// Its private constructor consumes the same parser and physical tail check.
/// No caller-supplied File, prefix, index, Arc or completion DATA is accepted.
#[must_use]
pub struct CanonicalOrdinaryReplacementReadyV1<I> {
    physical: OrdinaryReplacementFileDataV1,
    prefix: Option<NativeJournalState<RecordNamespace>>,
    index: Option<Index>,
    instance: CanonicalJournalInstanceDataV1<I>,
    previous_next: u64,
}

/// Retains the reached native/index install until the upper semantic frontier.
///
/// The actual upper caller installs its full semantic remainder before using
/// this single-use token to rotate the existing intrinsic comparison marker.
/// This token certifies no role semantics, funding, currentness or permission.
#[must_use]
pub struct CanonicalOrdinaryReplacementInstalledV1<I> {
    // Its file has moved; the old ordinary temporary-name carrier still lives
    // through the upper semantic and marker frontiers as it did in compact.
    _physical: OrdinaryReplacementFileDataV1,
    instance: CanonicalJournalInstanceDataV1<I>,
    installed_next: u64,
}

impl<P, I> CanonicalOrdinaryHeldJournalV1<P, I> {
    /// Prepares replacement from this same healthy native and protected location.
    ///
    /// The existing marker is cloned without allocation. No-instance holders
    /// refuse before IO; replacement never creates a missing old identity.
    ///
    /// # Errors
    /// Preserves ordinary physical/encoder errors and refuses a missing marker
    /// or poisoned native before constructing a replacement.
    pub fn prepare_replacement_once_v1(
        &mut self,
    ) -> Result<CanonicalOrdinaryReplacementV1<'_, P, I>, CanonicalReplacementErrorV1> {
        if self.is_read_only_v1() || self.native.native().is_poisoned() {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let instance = self
            .instance
            .as_ref()
            .ok_or(CanonicalReplacementErrorV1::Closed)?
            .clone();
        let previous_next = self.native.native().next_sequence();
        let physical = OrdinaryCoordinatorReplacementV1::prepare_once(
            self.native.native(),
            self.location.as_ref(),
        )?;
        Ok(CanonicalOrdinaryReplacementV1 {
            physical: Some(physical),
            replay: CanonicalReplayOriginalV1::new(),
            index: Index::new(),
            indexed: CanonicalReplayIndexOriginalsV1::new(),
            parser_seek: None,
            parser_metadata: None,
            parser_identity: None,
            instance,
            previous_next,
            replay_started: false,
            ordinary_disposition: 0,
            closed: None,
        })
    }
}

impl<P, I> CanonicalOrdinaryReplacementV1<'_, P, I> {
    /// Bounds actual preparing, completion, installation and return carriers.
    ///
    /// Three preparing and ready planes conservatively cover resident, caller
    /// and returned construction; the installed token and typed return lanes
    /// remain separately counted. Dynamic encoded/index/native/semantic backing
    /// and the final I allocation keep their existing additional suppliers.
    /// This passive byte bound provides no payment or namespace entries.
    /// Returns `None` on checked representation overflow.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(
                std::mem::size_of::<CanonicalOrdinaryReplacementReadyV1<I>>().checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<CanonicalOrdinaryReplacementInstalledV1<I>>().checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<Self, CanonicalReplacementErrorV1>>().checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<CanonicalOrdinaryReplacementReadyV1<I>, CanonicalReplacementErrorV1>,
                >()
                .checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<CanonicalOrdinaryReplacementInstalledV1<I>, CanonicalReplacementErrorV1>,
                >()
                .checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<CanonicalJournalInstanceDataV1<I>, CanonicalReplacementErrorV1>,
                >()
                .checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<CanonicalIndexedReplayV1<'_, '_>>().checked_mul(3)?)?
            .checked_add(
                std::mem::size_of::<Result<FileIdentity, CanonicalReplacementErrorV1>>()
                    .checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<std::fs::Metadata>().checked_mul(2)?)?
            .checked_add(
                std::mem::size_of::<
                    Result<
                        (
                            Option<IdempotencyRecordDataErrorV1>,
                            Option<NativeJournalDataErrorV1>,
                        ),
                        Self,
                    >,
                >()
                .checked_mul(2)?,
            )
    }

    /// Seeks and samples the actual replacement once at the old parser entry.
    ///
    /// The same metadata supplies both comparison DATA and the existing cursor;
    /// a second native identity observation is not performed.
    ///
    /// # Errors
    /// Retains the actual seek/metadata cause and refuses reentry or closed work.
    pub fn prepare_parser_identity_once_v1(
        &mut self,
    ) -> Result<FileIdentity, CanonicalReplacementErrorV1> {
        if self.parser_seek.is_some() || self.replay_started || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        let identity = self
            .physical
            .as_mut()
            .ok_or(CanonicalReplacementErrorV1::Closed)?
            .prepare_indexed_parser_once_v1(&mut self.parser_seek, &mut self.parser_metadata)?;
        self.parser_identity = Some(identity);
        Ok(identity)
    }

    /// Lends the same installed file and private index to the existing cursor.
    ///
    /// The upper owner retains its actual semantic checks between the cursor's
    /// original stages. This method does not validate or adopt role semantics.
    ///
    /// # Errors
    /// Retains original parser-entry/canonical failures and refuses repeat entry.
    pub fn begin_indexed_replay_once_v1(
        &mut self,
    ) -> Result<CanonicalIndexedReplayV1<'_, '_>, CanonicalReplacementErrorV1> {
        if self.replay_started || self.closed.is_some() || self.ordinary_disposition != 0 {
            return Err(self.refuse_order());
        }
        if self.parser_seek.is_none() {
            self.prepare_parser_identity_once_v1()?;
        }
        if self.parser_identity.is_none() {
            return Err(self.refuse_order());
        }
        self.replay_started = true;
        self.physical
            .as_mut()
            .ok_or(CanonicalReplacementErrorV1::Closed)?
            .begin_indexed_replay_once_v1(
                &mut self.replay,
                &mut self.index,
                &mut self.indexed,
                &mut self.parser_metadata,
            )
    }

    /// Consumes completed replay and the original exact-tail/final-seek check.
    ///
    /// The returned private bundle no longer borrows the old native/location.
    /// Upper final semantic checks must finish before this mechanical transfer.
    ///
    /// # Errors
    /// Refuses incomplete/failed replay or disposition and preserves the actual
    /// physical metadata, uncommitted-tail or final-seek error.
    pub fn finish_replayed_once_v1(
        mut self,
    ) -> Result<CanonicalOrdinaryReplacementReadyV1<I>, CanonicalReplacementErrorV1> {
        if self.closed.is_some() || self.ordinary_disposition != 0 || !self.indexed.is_complete() {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let (durable_end, _) = self
            .replay
            .report()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        // The upper replay-semantic locals have ended before this consuming
        // frontier. Retire ordinary parser scratch before the physical tail
        // metadata/seek, while preserving the completed prefix and index.
        if !self.replay.dispose_ordinary_current_once()
            || !self.replay.dispose_ordinary_pending_once()
        {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let physical = self
            .physical
            .take()
            .ok_or(CanonicalReplacementErrorV1::Closed)?
            .finish_once(durable_end)?;
        let prefix = self
            .replay
            .take_prefix()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        Ok(CanonicalOrdinaryReplacementReadyV1 {
            physical,
            prefix: Some(prefix),
            index: Some(std::mem::take(&mut self.index)),
            instance: self.instance.clone(),
            previous_next: self.previous_next,
        })
    }

    /// Borrows the actual parser-entry or native replay stopping cause.
    #[must_use]
    pub fn native_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.parser_seek
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.parser_metadata
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.replay.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Borrows the original private index comparison or application cause.
    #[must_use]
    pub fn index_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.indexed.failure()
    }

    /// Disposes current parser temporaries before the upper semantic scratch.
    ///
    /// # Errors
    /// Refuses repeated or out-of-order disposition without another native step.
    pub fn dispose_ordinary_current_once_v1(
        &mut self,
    ) -> Result<bool, CanonicalReplacementErrorV1> {
        if self.ordinary_disposition != 0 {
            return Err(self.refuse_order());
        }
        self.ordinary_disposition = 1;
        Ok(self.replay.dispose_ordinary_current_once())
    }

    /// Disposes pending parser locals after the actual upper semantic scratch.
    ///
    /// # Errors
    /// Refuses repeated or out-of-order disposition without another native step.
    pub fn dispose_ordinary_pending_once_v1(
        &mut self,
    ) -> Result<bool, CanonicalReplacementErrorV1> {
        if self.ordinary_disposition != 1 {
            return Err(self.refuse_order());
        }
        self.ordinary_disposition = 2;
        Ok(self.replay.dispose_ordinary_pending_once())
    }

    /// Moves exact ordinary index/native errors after their explicit windows.
    ///
    /// The actual upper selector chooses chronology between its own semantic
    /// cause and these unchanged typed causes. No owning error is cloned.
    ///
    /// # Errors
    /// Returns this whole owner unchanged until both disposal windows finish.
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
        if self.ordinary_disposition != 2 {
            return Err(self);
        }
        let indexed = std::mem::replace(&mut self.indexed, CanonicalReplayIndexOriginalsV1::new());
        let index = indexed.into_ordinary_error();
        drop(std::mem::take(&mut self.index));
        let replay = std::mem::replace(&mut self.replay, CanonicalReplayOriginalV1::new());
        let native = self
            .parser_seek
            .take()
            .and_then(Result::err)
            .map(NativeJournalDataErrorV1::Io)
            .or_else(|| {
                self.parser_metadata
                    .take()
                    .and_then(Result::err)
                    .map(NativeJournalDataErrorV1::Io)
            })
            .or_else(|| replay.into_ordinary_error())
            .or_else(|| self.closed.take());
        Ok((index, native))
    }

    fn refuse_order(&mut self) -> CanonicalReplacementErrorV1 {
        self.closed
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        CanonicalReplacementErrorV1::Closed
    }
}

impl<P, I> Drop for CanonicalOrdinaryReplacementV1<'_, P, I> {
    fn drop(&mut self) {
        // The returned-error adapter exposes the upper scratch window. On an
        // abandoned ordinary path, keep all parser/index locals before the
        // physical replacement/cleanup loan, without inventing positive work.
        self.replay.dispose_ordinary_current_once();
        self.replay.dispose_ordinary_pending_once();
        drop(std::mem::replace(
            &mut self.indexed,
            CanonicalReplayIndexOriginalsV1::new(),
        ));
        drop(std::mem::take(&mut self.index));
        drop(
            std::mem::replace(&mut self.replay, CanonicalReplayOriginalV1::new())
                .into_ordinary_error(),
        );
        drop(self.physical.take());
    }
}

impl<I> CanonicalOrdinaryReplacementReadyV1<I> {
    /// Installs this private completed bundle into only its unchanged old owner.
    ///
    /// # Errors
    /// Refuses another marker, poisoned native or advanced old sequence before
    /// changing that destination. No caller-projected state can be installed.
    pub fn install_once_v1<P>(
        mut self,
        held: &mut CanonicalOrdinaryHeldJournalV1<P, I>,
    ) -> Result<CanonicalOrdinaryReplacementInstalledV1<I>, CanonicalReplacementErrorV1> {
        if held.is_read_only_v1()
            || held.native.native().is_poisoned()
            || held.native.native().next_sequence() != self.previous_next
            || held
                .instance
                .as_ref()
                .is_none_or(|instance| !instance.same_original_v1(&self.instance))
        {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let prefix = self
            .prefix
            .take()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        let index = self
            .index
            .take()
            .ok_or(CanonicalReplacementErrorV1::Closed)?;
        self.physical
            .install_once(held.native.native_mut(), prefix)?;
        held.index = index;
        Ok(CanonicalOrdinaryReplacementInstalledV1 {
            _physical: self.physical,
            instance: self.instance,
            installed_next: held.native.native().next_sequence(),
        })
    }
}

impl<I> CanonicalOrdinaryReplacementInstalledV1<I> {
    /// Rotates one late marker at the caller's reached post-semantic frontier.
    ///
    /// The role must first install its actual full semantic remainder. The new
    /// payload is comparison DATA, not a supplied Arc or authority original.
    /// The returned alias and held alias share exactly one new allocation.
    ///
    /// # Errors
    /// Refuses another or changed owner, poisoned native or advanced installed
    /// head before allocating or replacing any marker.
    pub fn finish_after_semantic_once_v1<P>(
        self,
        held: &mut CanonicalOrdinaryHeldJournalV1<P, I>,
        payload: I,
    ) -> Result<CanonicalJournalInstanceDataV1<I>, CanonicalReplacementErrorV1> {
        if held.is_read_only_v1()
            || held.native.native().is_poisoned()
            || held.native.native().next_sequence() != self.installed_next
            || held
                .instance
                .as_ref()
                .is_none_or(|instance| !instance.same_original_v1(&self.instance))
        {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        let instance = CanonicalJournalInstanceDataV1::from_payload(payload);
        held.instance = Some(instance.clone());
        Ok(instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::sync::Arc;

    use crate::canonical_journal::coordinator::CanonicalCoordinatorAppendV1;
    use crate::canonical_journal::opening::ordinary_held::{
        CanonicalOrdinaryOpeningOriginalsV1, tests as opening_tests,
    };
    use aos_sandbox_journal::recovery::RecoveryTailMode;
    use aos_sandbox_protocol::domain_ledger::transaction::{
        JournalLimits, JournalRecord, JournalTransaction,
    };

    struct Marker(u8);

    fn held() -> (
        tempfile::TempDir,
        CanonicalOrdinaryHeldJournalV1<(), Marker>,
    ) {
        let directory = opening_tests::protected_directory();
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        opening_tests::finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, _) = opening
            .take_held_with_late_payload_once_v1((), Marker(1))
            .unwrap();
        (directory, held)
    }

    fn append(held: &mut CanonicalOrdinaryHeldJournalV1<(), Marker>, id: u8) {
        let mut value = vec![id; 32];
        value.extend_from_slice(&[id; 16]);
        let transaction = JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::Idempotency,
                vec![id],
                value,
            )],
        )
        .unwrap();
        let mut stage = held.prepare_append_once(&transaction).unwrap();
        held.append_coordinates_once(&mut stage).unwrap();
        held.expected_append_length_once(&mut stage).unwrap();
        held.append_prepared_once(&mut stage).unwrap();
        while held.apply_next_record_once(&mut stage).unwrap() {}
        held.publish_append_once(&mut stage).unwrap();
        held.finish_append_after_posts_once(&mut stage).unwrap();
    }

    fn replay(stage: &mut CanonicalOrdinaryReplacementV1<'_, (), Marker>) {
        let mut cursor = stage.begin_indexed_replay_once_v1().unwrap();
        while cursor.advance_once().unwrap() {
            cursor.validate_compaction_once().unwrap();
            cursor.register_and_compare_index_once().unwrap();
            cursor.prepare_change_once().unwrap();
            while cursor.apply_next_record_once().unwrap() {}
            cursor.finish_commit_accounting_once().unwrap();
            cursor.finish_commit_once().unwrap();
        }
        assert!(cursor.completed_prefix().is_some());
    }

    #[test]
    fn real_bundle_installs_before_one_late_same_alias_rotation() {
        let (_directory, mut held) = held();
        append(&mut held, 1);
        let old = held.instance_data_v1().unwrap().clone();
        let weak = old.comparison_stamp_v1();
        let expected = held.read_view_v1().state().clone();
        let namespaces = held.read_view_v1().committed_namespaces().clone();
        let next = held.read_view_v1().next_sequence();

        let mut stage = held.prepare_replacement_once_v1().unwrap();
        let identity = stage.prepare_parser_identity_once_v1().unwrap();
        assert!(identity.byte_len() > 0);
        replay(&mut stage);
        let ready = stage.finish_replayed_once_v1().unwrap();
        let installed = ready.install_once_v1(&mut held).unwrap();

        // Mechanical install has not claimed the upper semantic/marker cut.
        assert!(held.instance_data_v1().unwrap().same_original_v1(&old));
        assert_eq!(held.read_view_v1().state(), &expected);
        assert_eq!(held.read_view_v1().committed_namespaces(), &namespaces);
        assert_eq!(held.read_view_v1().next_sequence(), next);
        assert_eq!(held.read_view_v1().idempotency_index().len(), 1);
        let marker = installed
            .finish_after_semantic_once_v1(&mut held, Marker(2))
            .unwrap();

        assert_eq!(marker.comparison_arc_v1().as_ref().0, 2);
        assert!(held.instance_data_v1().unwrap().same_original_v1(&marker));
        assert!(!marker.same_original_v1(&old));
        assert!(!marker.matches_stamp_v1(&weak));
        assert_eq!(Arc::strong_count(marker.comparison_arc_v1()), 2);
        assert_eq!(Arc::strong_count(old.comparison_arc_v1()), 1);
    }

    #[test]
    fn different_instance_and_advanced_old_head_cannot_install_the_bundle() {
        let (_directory, mut origin) = held();
        let (_foreign_directory, mut foreign) = held();
        append(&mut origin, 1);
        let foreign_instance = foreign.instance_data_v1().unwrap().clone();
        let foreign_next = foreign.read_view_v1().next_sequence();
        let mut stage = origin.prepare_replacement_once_v1().unwrap();
        replay(&mut stage);
        let ready = stage.finish_replayed_once_v1().unwrap();

        assert!(ready.install_once_v1(&mut foreign).is_err());
        assert_eq!(foreign.read_view_v1().next_sequence(), foreign_next);
        assert!(foreign.read_view_v1().state().is_empty());
        assert!(
            foreign
                .instance_data_v1()
                .unwrap()
                .same_original_v1(&foreign_instance)
        );

        let mut stage = origin.prepare_replacement_once_v1().unwrap();
        replay(&mut stage);
        let ready = stage.finish_replayed_once_v1().unwrap();
        append(&mut origin, 2);
        let advanced = origin.read_view_v1().next_sequence();
        assert!(ready.install_once_v1(&mut origin).is_err());
        assert_eq!(origin.read_view_v1().next_sequence(), advanced);
        assert_eq!(origin.read_view_v1().idempotency_index().len(), 2);
    }

    #[test]
    fn unfinished_cursor_and_actual_late_tail_cannot_transfer() {
        let (directory, mut held) = held();
        append(&mut held, 1);
        let mut stage = held.prepare_replacement_once_v1().unwrap();
        {
            let mut cursor = stage.begin_indexed_replay_once_v1().unwrap();
            assert!(cursor.advance_once().unwrap());
        }
        assert!(stage.finish_replayed_once_v1().is_err());

        let mut stage = held.prepare_replacement_once_v1().unwrap();
        replay(&mut stage);
        OpenOptions::new()
            .append(true)
            .open(directory.path().join("history"))
            .unwrap()
            .write_all(&[0x7f])
            .unwrap();
        let failed = stage.finish_replayed_once_v1();
        assert!(matches!(
            failed,
            Err(CanonicalReplacementErrorV1::Native(
                NativeJournalDataErrorV1::MalformedTransaction(
                    "compacted journal has an uncommitted tail"
                ),
            ))
        ));
        assert!(!directory.path().join("history.compact.tmp").exists());
    }

    #[test]
    fn advanced_installed_head_refuses_late_marker_without_another_allocation() {
        let (_directory, mut held) = held();
        append(&mut held, 1);
        let old = held.instance_data_v1().unwrap().clone();
        let mut stage = held.prepare_replacement_once_v1().unwrap();
        replay(&mut stage);
        let ready = stage.finish_replayed_once_v1().unwrap();
        let installed = ready.install_once_v1(&mut held).unwrap();
        append(&mut held, 2);

        assert!(
            installed
                .finish_after_semantic_once_v1(&mut held, Marker(2))
                .is_err()
        );
        assert!(held.instance_data_v1().unwrap().same_original_v1(&old));
        assert_eq!(old.comparison_arc_v1().as_ref().0, 1);
        assert_eq!(Arc::strong_count(old.comparison_arc_v1()), 2);
    }

    #[test]
    fn actual_parser_error_survives_the_explicit_ordinary_disposal_windows() {
        use aos_sandbox_journal::framing::HEADER_BYTES;

        let (directory, mut held) = held();
        append(&mut held, 1);
        let mut stage = held.prepare_replacement_once_v1().unwrap();
        OpenOptions::new()
            .write(true)
            .open(directory.path().join("history"))
            .unwrap()
            .write_all(&vec![0; HEADER_BYTES])
            .unwrap();
        {
            let mut cursor = stage.begin_indexed_replay_once_v1().unwrap();
            assert!(cursor.advance_once().is_err());
        }
        let cause = stage.native_failure_v1().unwrap().to_string();

        stage.dispose_ordinary_current_once_v1().unwrap();
        // The actual role disposes its own semantic scratch at this window.
        stage.dispose_ordinary_pending_once_v1().unwrap();
        let (index, native) = match stage.into_ordinary_errors_v1() {
            Ok(errors) => errors,
            Err(_) => panic!("completed ordinary windows were rejected"),
        };

        assert!(index.is_none());
        assert_eq!(native.unwrap().to_string(), cause);
        assert!(!directory.path().join("history.compact.tmp").exists());
    }

    #[test]
    fn genuine_no_instance_opening_refuses_replacement_before_io() {
        let directory = opening_tests::protected_directory();
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        opening_tests::finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (mut held, _) = opening.take_held_without_instance_once_v1(()).unwrap();

        assert!(held.prepare_replacement_once_v1().is_err());
        assert!(held.instance_data_v1().is_none());
        assert!(!directory.path().join("history.compact.tmp").exists());
    }

    #[test]
    fn actual_unprotected_opener_replaces_its_private_file_and_index() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history");
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_unprotected_ordinary_once_v1(&path, JournalLimits::default())
            .unwrap();
        opening_tests::finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (mut held, _) = opening
            .take_held_with_late_payload_once_v1((), Marker(1))
            .unwrap();
        assert!(!held.read_view_v1().is_protected());
        append(&mut held, 1);

        let mut stage = held.prepare_replacement_once_v1().unwrap();
        replay(&mut stage);
        let ready = stage.finish_replayed_once_v1().unwrap();
        let installed = ready.install_once_v1(&mut held).unwrap();
        let marker = installed
            .finish_after_semantic_once_v1(&mut held, Marker(2))
            .unwrap();

        assert!(held.instance_data_v1().unwrap().same_original_v1(&marker));
        assert_eq!(held.read_view_v1().idempotency_index().len(), 1);
        assert!(held.read_view_v1().metadata().unwrap().len() > 0);
        assert!(!directory.path().join("history.compact.tmp").exists());
    }
}
