//! Original Release capture, comparison, first-cause parking and copy budgets.
//!
//! Resident fields, shared COMMIT observation and the replay parser stay in Journal.

use std::path::Path;

use super::{
    DeploymentHistoryObserverV1, HEADER_BYTES, IdempotencyDecision, Journal, JournalError,
    JournalLimits, JournalRecord, JournalTransaction, NativeReleaseReplayWorkV1,
    OriginalReleaseControllerCutCaptureV1, OriginalReleaseControllerCutFailureV1,
    OriginalReleaseControllerNativeHistoryV1, OriginalReleaseNativeCutPurposeV1,
    RecordNamespace, ObservedReplayStateV1, encoded_transaction_append_bytes, replay_coordinator_observed_v1,
    runtime_deployment_history,
};

pub(super) fn native_release_replay_work_v1(
    physical: usize,
    limits: JournalLimits,
) -> Result<NativeReleaseReplayWorkV1, JournalError> {
    let work = aos_sandbox_broker::canonical_journal::ordinary_reread_wire_work_data_v1(
        physical, limits,
    ).ok_or(JournalError::LimitExceeded("original Release replay copy"))?;
    Ok(NativeReleaseReplayWorkV1 {
        replay_indexes: work.replay_indexes,
        pending_records: work.pending_records,
        frame_payload: work.frame_payload,
    })
}

// The private union descriptor has these fields. Preserve the existing four
// alignment allowances instead of exposing or duplicating that private type.

impl OriginalReleaseControllerNativeHistoryV1 {
    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
        native_digest: &[u8],
    ) -> Result<(), JournalError> {
        let next = commit_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let frames = u64::try_from(transaction.records().len())
            .map_err(|_| JournalError::LimitExceeded("original Release native frames"))?
            .checked_add(2)
            .ok_or(JournalError::SequenceExhausted)?;
        if begin_sequence != self.next_sequence.unwrap_or(1)
            || next.checked_sub(begin_sequence) != Some(frames)
            || begin_offset != self.durable_end
            || end_offset.checked_sub(begin_offset)
                != Some(encoded_transaction_append_bytes(transaction)?)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let head = native_digest
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.next_sequence = Some(next);
        self.durable_end = end_offset;
        self.head = Some(head);
        Ok(())
    }
}

#[cfg(test)]
mod reached_frame_memory_tests {
    use super::*;
    use aos_sandbox_journal::framing::FRAME_READ_SCRATCH_BYTES;

    #[test]
    fn release_replay_charges_growth_peak_and_scratch_on_tiny_physical_prefixes() {
        let limits = JournalLimits::default();
        let empty = native_release_replay_work_v1(0, limits).unwrap();
        let reached = native_release_replay_work_v1(10, limits).unwrap();

        assert_eq!(empty.frame_payload, FRAME_READ_SCRATCH_BYTES);
        // Ten reached bytes can hold a new20-byte and old10-byte allocation.
        assert_eq!(reached.frame_payload, FRAME_READ_SCRATCH_BYTES + 30);
        assert_eq!(empty.pending_records, 0);
        assert_eq!(reached.pending_records, 0);
    }

    #[test]
    fn release_replay_caps_each_growth_buffer_at_the_declared_payload_limit() {
        let limits = JournalLimits {
            maximum_record_bytes: 1024,
            ..JournalLimits::default()
        };
        let advertised = limits.maximum_record_bytes + 7;
        let physical = advertised * 4;

        let work = native_release_replay_work_v1(physical, limits).unwrap();

        assert_eq!(
            work.frame_payload,
            FRAME_READ_SCRATCH_BYTES + 2 * advertised
        );
        assert_eq!(
            work.pending_records,
            (physical / HEADER_BYTES).min(limits.maximum_records_per_transaction)
                * std::mem::size_of::<JournalRecord>()
        );
    }
}


impl OriginalReleaseControllerCutCaptureV1 {
    // Move only a proven parked first Err into the containing selected action
    // Result. The attempted cut, site, native Ok and all other debt stay here;
    // a vacated Err slot neither makes this reusable nor enables a write.
    pub(crate) fn transfer_first_error(&mut self) -> Option<JournalError> {
        if self.error_transferred {
            return None;
        }
        let site = self.first?;
        let error = match site {
            OriginalReleaseControllerCutFailureV1::Protection
                if matches!(self.protection, Some(Err(_))) =>
            {
                self.protection.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::CopyBound
                if matches!(self.copy_bound, Some(Err(_))) =>
            {
                self.copy_bound.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::Native
                if matches!(self.native, Some(Err(_))) =>
            {
                self.native.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::Comparison
                if matches!(self.comparison, Some(Err(_))) =>
            {
                self.comparison.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::NamedPost
                if matches!(self.named_post, Some(Err(_))) =>
            {
                self.named_post.take().and_then(Result::err)
            }
            _ => None,
        };
        self.error_transferred = error.is_some();
        error
    }

    pub(crate) fn recheck(&self, journal: &Journal) -> Result<(), JournalError> {
        if self.first.is_some() || self.error_transferred {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let witness = self
            .protection
            .as_ref()
            .and_then(|returned| returned.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let replayed = self
            .native
            .as_ref()
            .and_then(|returned| returned.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        journal.require_original_release_cut_location_v1(self.purpose)?;
        journal.require_original_release_controller_replay_v1(
            replayed,
            &self.history,
            witness.file().byte_len(),
        )?;
        journal.validate_protected_writer_name_witness(witness)
    }

    // Retained for Root readback after a full graph/snapshot comparison; this
    // recipe has no current caller. No scalar head is accepted as input.
    pub(super) fn copy_root_native_cut_into_v1(
        &self,
        journal: &Journal,
        destination: &mut [u8; 40],
    ) -> Result<(), JournalError> {
        if !matches!(self.purpose, OriginalReleaseNativeCutPurposeV1::Root) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.recheck(journal)?;
        let head = self.history.head.ok_or(JournalError::ProtectedBoundary)?;
        let next = self
            .history
            .next_sequence
            .ok_or(JournalError::ProtectedBoundary)?;
        destination[..32].copy_from_slice(&head);
        destination[32..].copy_from_slice(&next.to_be_bytes());
        Ok(())
    }
}

impl Journal {
    pub(crate) fn capture_original_release_controller_cut_v1(
        &self,
    ) -> OriginalReleaseControllerCutCaptureV1 {
        self.capture_original_release_native_cut_v1(OriginalReleaseNativeCutPurposeV1::Controller)
    }

    pub(super) fn capture_original_release_root_cut_v1(
        &self,
    ) -> OriginalReleaseControllerCutCaptureV1 {
        self.capture_original_release_native_cut_v1(OriginalReleaseNativeCutPurposeV1::Root)
    }

    pub(super) fn require_original_release_cut_location_v1(
        &self,
        purpose: OriginalReleaseNativeCutPurposeV1,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        match purpose {
            OriginalReleaseNativeCutPurposeV1::Controller => self.require_protected_named_location(
                Path::new("/var/lib/aos/sandboxd"),
                "controller.journal",
                self.protected_owner_uid()?,
                crate::journal::controller::production_journal_limits(),
            ),
            OriginalReleaseNativeCutPurposeV1::Root => self.require_protected_named_location(
                Path::new("/var/lib/aos/sandbox-mount"),
                "mount.journal",
                0,
                self.native.limits(),
            ),
        }
    }

    pub(super) fn capture_original_release_native_cut_v1(
        &self,
        purpose: OriginalReleaseNativeCutPurposeV1,
    ) -> OriginalReleaseControllerCutCaptureV1 {
        let mut captured = OriginalReleaseControllerCutCaptureV1 {
            purpose,
            protection: None,
            copy_bound: None,
            native: None,
            comparison: None,
            named_post: None,
            history: OriginalReleaseControllerNativeHistoryV1::default(),
            first: None,
            error_transferred: false,
        };
        captured.protection = Some((|| {
            self.require_original_release_cut_location_v1(purpose)?;
            self.protected_writer_name_witness()
        })());
        if matches!(captured.protection, Some(Err(_))) {
            captured.first = Some(OriginalReleaseControllerCutFailureV1::Protection);
        }

        // The original and returned indexes, decoded record containers and
        // bounded parser payload coexist. Price their logical storage before
        // replay; allocator nodes and nested validator work remain separate
        // funding obligations, not implied by this native headroom check.
        captured.copy_bound = Some((|| {
            let witness = captured
                .protection
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let bytes =
                self.original_release_controller_replay_copy_bytes_v1(witness.file().byte_len())?;
            if bytes > self.native.limits().maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("original Release replay copy"));
            }
            Ok(())
        })());
        if matches!(captured.copy_bound, Some(Err(_))) {
            captured
                .first
                .get_or_insert(OriginalReleaseControllerCutFailureV1::CopyBound);
        }

        self.observe_original_release_native_cut_v1(&mut captured);
        captured
    }

    // These non-Provider routes use the same native read and result parking.
    pub(super) fn observe_original_release_native_cut_v1(
        &self,
        captured: &mut OriginalReleaseControllerCutCaptureV1,
    ) {
        if captured.first.is_none() {
            if let Some(Ok(witness)) = captured.protection.as_ref() {
                let reader = self.native.captured_reader(witness.file().byte_len());
                // The original native Result is parked before projecting its
                // full-map comparison, including partial-replay failure.
                let observer = DeploymentHistoryObserverV1::OriginalRelease(&mut captured.history);
                captured.native = Some(replay_coordinator_observed_v1(
                    reader,
                    self.native.limits(),
                    None,
                    Some(observer),
                ));
                if matches!(captured.native, Some(Err(_))) {
                    captured.first = Some(OriginalReleaseControllerCutFailureV1::Native);
                }
                if let Some(Ok(replayed)) = captured.native.as_ref() {
                    captured.comparison = Some(self.require_original_release_controller_replay_v1(
                        replayed,
                        &captured.history,
                        witness.file().byte_len(),
                    ));
                    if matches!(captured.comparison, Some(Err(_))) {
                        captured
                            .first
                            .get_or_insert(OriginalReleaseControllerCutFailureV1::Comparison);
                    }
                }
            }
        }

        // The same original names are observed even after native/copy failure.
        // No append descriptor seek, reopen, duplicate, recovery or new parser.
        if let Some(Ok(witness)) = captured.protection.as_ref() {
            captured.named_post = Some(self.validate_protected_writer_name_witness(witness));
            if matches!(captured.named_post, Some(Err(_))) {
                captured
                    .first
                    .get_or_insert(OriginalReleaseControllerCutFailureV1::NamedPost);
            }
        }
    }


    // The captured physical prefix bounds all historical payloads, including
    // rows larger than today's materialized map. It is not a second quota or
    // a claim that per-record ceilings fund the whole caller's owner graph.
    pub(super) fn original_release_controller_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
    ) -> Result<usize, JournalError> {
        if !self.source_challenge_history.is_empty()
            || self.source_original_replay.has_dependencies()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.original_release_native_replay_copy_bytes_v1(physical_end)
    }

    pub(super) fn original_release_native_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
    ) -> Result<usize, JournalError> {
        let limit = || JournalError::LimitExceeded("original Release replay copy");
        let physical = usize::try_from(physical_end).map_err(|_| limit())?;
        let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();
        let idempotency_entry = std::mem::size_of::<(Vec<u8>, IdempotencyDecision)>();

        let original_indexes = self
            .native
            .state()
            .len()
            .checked_mul(map_entry)
            .and_then(|bytes| bytes.checked_add(self.native.materialized_bytes()))
            .and_then(|bytes| {
                bytes.checked_add(self.native.transaction_ids().len().checked_mul(16)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    self.native
                        .committed_namespaces()
                        .len()
                        .checked_mul(std::mem::size_of::<RecordNamespace>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(self.native.idempotency().len().checked_mul(idempotency_entry)?)
            })
            .ok_or_else(limit)?;
        let original_indexes = self.native.idempotency()
            .keys()
            .try_fold(original_indexes, |bytes, key| {
                bytes.checked_add(key.len()).ok_or_else(limit)
            })?;

        let NativeReleaseReplayWorkV1 {
            replay_indexes,
            pending_records,
            frame_payload,
        } = native_release_replay_work_v1(physical, self.native.limits())?;

        original_indexes
            .checked_add(replay_indexes)
            .and_then(|bytes| bytes.checked_add(pending_records))
            .and_then(|bytes| bytes.checked_add(frame_payload))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ObservedReplayStateV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(Vec<JournalRecord>, aos_sandbox_journal::transaction::NativePendingTransaction)>()))
            .and_then(|bytes| bytes.checked_add(super::ordinary_reread::receiving_control_bytes_v1()?))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>())
            })
            .ok_or_else(limit)
    }


    pub(super) fn require_original_release_controller_replay_v1(
        &self,
        replayed: &ObservedReplayStateV1,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
    ) -> Result<(), JournalError> {
        self.require_original_release_native_replay_v1(
            replayed,
            history,
            physical_end,
            OriginalReleaseNativeCutPurposeV1::Controller,
        )
    }


    pub(super) fn require_original_release_native_replay_v1(
        &self,
        replayed: &ObservedReplayStateV1,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
        _purpose: OriginalReleaseNativeCutPurposeV1,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        if history.head.is_none_or(|head| head == [0; 32])
            || self.native.next_sequence() == 0
            || self.native.next_sequence() == u64::MAX
            || history.durable_end != physical_end
            || history.next_sequence != Some(self.native.next_sequence())
            || replayed.durable_end != physical_end
            || replayed.next_sequence != self.native.next_sequence()
            || replayed.committed_transactions != self.native.committed_transactions()
            || replayed.native.transaction_ids_data_v1() != self.native.transaction_ids()
            || replayed.native.committed_namespaces_data_v1() != self.native.committed_namespaces()
            || replayed.native.state_data_v1() != self.native.state()
            || replayed.native.materialized_bytes_data_v1() != self.native.materialized_bytes()
            || replayed.native.idempotency_data_v1() != self.native.idempotency()
            || !replayed.source_challenge_history.is_empty()
            || !self.source_challenge_history.is_empty()
            || replayed.source_original_replay.has_dependencies()
            || self.source_original_replay.has_dependencies()
            || replayed.source_history_compacted != self.source_history_compacted
            || replayed.q04_lower_history_present != self.q04_lower_history_present
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}
