//! Original Release capture, comparison, first-cause parking and copy budgets.
//!
//! Resident fields, shared COMMIT observation and the replay parser stay in Journal.

use std::path::Path;

use super::{
    DeploymentHistoryObserverV1, HEADER_BYTES, IdempotencyDecision, Journal, JournalError,
    JournalLimits, JournalRecord, JournalTransaction, NativeReleaseReplayWorkV1,
    OriginalReleaseControllerCutCaptureV1, OriginalReleaseControllerCutFailureV1,
    OriginalReleaseControllerNativeHistoryV1, OriginalReleaseNativeCutPurposeV1,
    OriginalReleaseSourceCutCaptureV1, OriginalReleaseSourceCutFailureV1, PendingTransaction,
    RecordNamespace, ReplayState, encoded_transaction_append_bytes, replay_original_observed,
    runtime_deployment_history, source_original_native,
};

pub(super) fn native_release_replay_work_v1(
    physical: usize,
    limits: JournalLimits,
) -> Result<NativeReleaseReplayWorkV1, JournalError> {
    let limit = || JournalError::LimitExceeded("original Release replay copy");
    let historical_frames = physical / HEADER_BYTES;
    let historical_rows = historical_frames.min(limits.maximum_materialized_records);
    let historical_transactions = historical_frames.min(limits.maximum_transactions);
    let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();
    let idempotency_entry = std::mem::size_of::<(Vec<u8>, IdempotencyDecision)>();

    // Two native maps cover the replay and its prospective materialization;
    // the third payload allowance covers idempotency and pending records.
    let replay_indexes = physical
        .checked_mul(3)
        .and_then(|bytes| {
            bytes.checked_add(historical_rows.checked_mul(map_entry)?.checked_mul(2)?)
        })
        .and_then(|bytes| bytes.checked_add(historical_rows.checked_mul(idempotency_entry)?))
        .and_then(|bytes| bytes.checked_add(historical_transactions.checked_mul(16)?))
        .and_then(|bytes| {
            bytes
                .checked_add(historical_frames.checked_mul(std::mem::size_of::<RecordNamespace>())?)
        })
        .ok_or_else(limit)?;
    let pending_records = historical_frames
        .min(limits.maximum_records_per_transaction)
        .checked_mul(std::mem::size_of::<JournalRecord>())
        .ok_or_else(limit)?;
    let advertised_payload = limits
        .maximum_record_bytes
        .checked_add(7)
        .ok_or_else(limit)?;
    // The shared frame reader grows only after bytes are actually read. The
    // same capacity/scratch bound must cover direct Release-copy callers and
    // initial captured-prefix receiving, not only the latter's correction.
    let frame_payload = aos_sandbox_journal::framing::reached_frame_read_memory_bound_v1(
        advertised_payload,
        physical,
    )
    .map_err(|_| limit())?;

    Ok(NativeReleaseReplayWorkV1 {
        replay_indexes,
        pending_records,
        frame_payload,
    })
}

// The private union descriptor has these fields. Preserve the existing four
// alignment allowances instead of exposing or duplicating that private type.
pub(super) fn source_release_historical_descriptor_bytes_v1() -> Result<usize, JournalError> {
    use aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceRetirementComparisonV5;
    use source_original_native::SourceOriginalAdmissionDataV5;

    std::mem::size_of::<[u8; 16]>()
        .checked_add(std::mem::size_of::<bool>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_core::ObjectDigest>()))
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                std::sync::Arc<OriginalSourceRetirementComparisonV5>,
            >())
        })
        .and_then(|bytes| {
            bytes.checked_add(4 * std::mem::align_of::<SourceOriginalAdmissionDataV5>())
        })
        .ok_or(JournalError::LimitExceeded(
            "Source original Release replay copy",
        ))
}

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

impl OriginalReleaseSourceCutCaptureV1 {
    pub(super) fn postcheck_debt(&self) -> Option<&JournalError> {
        self.native
            .named_post
            .as_ref()
            .and_then(|returned| returned.as_ref().err())
            .or_else(|| {
                self.challenge_post
                    .as_ref()
                    .and_then(|returned| returned.as_ref().err())
            })
    }

    pub(super) fn transfer_first_error(&mut self) -> Option<JournalError> {
        if self.error_transferred {
            return None;
        }
        let error = match self.first? {
            OriginalReleaseSourceCutFailureV1::Readback
                if matches!(self.readback, Some(Err(_))) =>
            {
                self.readback.take().and_then(Result::err)
            }
            OriginalReleaseSourceCutFailureV1::Native => self.native.transfer_first_error(),
            OriginalReleaseSourceCutFailureV1::ChallengePost
                if matches!(self.challenge_post, Some(Err(_))) =>
            {
                self.challenge_post.take().and_then(Result::err)
            }
            _ => None,
        };
        self.error_transferred = error.is_some();
        error
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
            OriginalReleaseNativeCutPurposeV1::Source => {
                source_original_native::writer::require_fixed(self)
            }
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

        self.observe_original_release_native_cut_v1(&mut captured, None, None);
        captured
    }

    // Both routes use this exact ReadAt/parser/result-parking sequence. The
    // Source route supplies its real held challenge view, never another witness.
    pub(super) fn observe_original_release_native_cut_v1(
        &self,
        captured: &mut OriginalReleaseControllerCutCaptureV1,
        challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
        readback: Option<&Result<(), JournalError>>,
    ) {
        if captured.first.is_none() && readback.is_none_or(Result::is_ok) {
            if let Some(Ok(witness)) = captured.protection.as_ref() {
                let mut reader = runtime_deployment_history::ReadAtCursorV1::new(
                    self.native.file(),
                    witness.file().byte_len(),
                );
                // The original native Result is parked before projecting its
                // full-map comparison, including partial-replay failure.
                let observer = match challenges {
                    Some(_) => DeploymentHistoryObserverV1::OriginalReleaseSource {
                        history: &mut captured.history,
                        remaining: self.native.committed_transactions(),
                    },
                    None => DeploymentHistoryObserverV1::OriginalRelease(&mut captured.history),
                };
                captured.native = Some(replay_original_observed(
                    &mut reader,
                    self.native.limits(),
                    challenges,
                    Some(observer),
                ));
                if matches!(captured.native, Some(Err(_))) {
                    captured.first = Some(OriginalReleaseControllerCutFailureV1::Native);
                }
                if let Some(Ok(replayed)) = captured.native.as_ref() {
                    captured.comparison = Some(match challenges {
                        Some(challenges) => self.require_original_release_source_replay_v1(
                            replayed,
                            &captured.history,
                            witness.file().byte_len(),
                            challenges,
                        ),
                        None => self.require_original_release_controller_replay_v1(
                            replayed,
                            &captured.history,
                            witness.file().byte_len(),
                        ),
                    });
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

    pub(super) fn observe_original_release_source_cut_into_v1(
        &self,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
        readback: Result<(), JournalError>,
        destination: &mut Option<OriginalReleaseSourceCutCaptureV1>,
    ) -> Result<(), JournalError> {
        if destination.is_some() {
            std::process::abort();
        }
        let captured = OriginalReleaseControllerCutCaptureV1 {
            purpose: OriginalReleaseNativeCutPurposeV1::Source,
            protection: None,
            copy_bound: None,
            native: None,
            comparison: None,
            named_post: None,
            history: OriginalReleaseControllerNativeHistoryV1::default(),
            first: None,
            error_transferred: false,
        };
        *destination = Some(OriginalReleaseSourceCutCaptureV1 {
            readback: Some(readback),
            native: captured,
            challenge_post: None,
            first: None,
            error_transferred: false,
        });
        let Some(source) = destination.as_mut() else {
            std::process::abort();
        };
        if matches!(source.readback, Some(Err(_))) {
            source.first = Some(OriginalReleaseSourceCutFailureV1::Readback);
        }
        let captured = &mut source.native;
        captured.protection = Some((|| {
            self.require_original_release_cut_location_v1(captured.purpose)?;
            self.source_original_replay
                .validate_challenges(challenges)?;
            self.protected_writer_name_witness()
        })());
        if matches!(captured.protection, Some(Err(_))) {
            captured
                .first
                .get_or_insert(OriginalReleaseControllerCutFailureV1::Protection);
        }

        captured.copy_bound = Some((|| {
            let witness = captured
                .protection
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let bytes = self.original_release_source_replay_copy_bytes_v1(
                witness.file().byte_len(),
                challenges,
            )?;
            if bytes > self.native.limits().maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded(
                    "Source original Release replay copy",
                ));
            }
            Ok(())
        })());
        if matches!(captured.copy_bound, Some(Err(_))) {
            captured
                .first
                .get_or_insert(OriginalReleaseControllerCutFailureV1::CopyBound);
        }

        self.observe_original_release_native_cut_v1(
            &mut source.native,
            Some(challenges),
            source.readback.as_ref(),
        );
        if source.native.named_post.is_none() {
            source.native.named_post = Some(self.require_original_release_cut_location_v1(
                OriginalReleaseNativeCutPurposeV1::Source,
            ));
            if matches!(source.native.named_post, Some(Err(_))) {
                source
                    .native
                    .first
                    .get_or_insert(OriginalReleaseControllerCutFailureV1::NamedPost);
            }
        }
        if source.native.first.is_some() {
            source
                .first
                .get_or_insert(OriginalReleaseSourceCutFailureV1::Native);
        }
        source.challenge_post = Some(challenges.validate_current());
        if matches!(source.challenge_post, Some(Err(_))) {
            source
                .first
                .get_or_insert(OriginalReleaseSourceCutFailureV1::ChallengePost);
        }
        if source.first.is_some() {
            return match source.transfer_first_error() {
                Some(cause) => Err(cause),
                None => std::process::abort(),
            };
        }
        Ok(())
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
                bytes.checked_add(self.idempotency.len().checked_mul(idempotency_entry)?)
            })
            .ok_or_else(limit)?;
        let original_indexes = self
            .idempotency
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
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ReplayState>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PendingTransaction>()))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>())
            })
            .ok_or_else(limit)
    }

    pub(super) fn original_release_source_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<usize, JournalError> {
        use source_original_native::{SourceOriginalAdmissionDataV5, SourceOriginalPhysicalCutV5};

        let limit = || JournalError::LimitExceeded("Source original Release replay copy");
        let physical = usize::try_from(physical_end).map_err(|_| limit())?;
        // The fixed Source observer rejects an extra COMMIT before any Source
        // retention. Price actual original metadata, not a guessed count from
        // the serialized width of today's large carriers.
        let transactions = self.native.committed_transactions();
        if transactions == 0 || transactions > self.native.limits().maximum_transactions {
            return Err(JournalError::ProtectedBoundary);
        }
        let pairs = transactions.checked_mul(transactions).ok_or_else(limit)?;
        // A historical reference contains these four fields. Four maximum
        // alignment allowances conservatively cover its padding without
        // exposing that private representation outside its owning module.
        let historical_descriptor = source_release_historical_descriptor_bytes_v1()?;

        // Each physical transaction can retain two cut maps, one four-payload
        // Applying seed and one three-payload current retirement. Historical
        // retirements contribute at most one three-payload copy per origin pair.
        // This bounds the existing retained_bytes charge, not allocator RAM.
        let source_payload = transactions
            .checked_mul(9)
            .and_then(|linear| {
                pairs
                    .checked_mul(3)
                    .and_then(|square| linear.checked_add(square))
            })
            .and_then(|factor| physical.checked_mul(factor))
            .and_then(|bytes| {
                bytes.checked_add(
                    transactions.checked_mul(
                        std::mem::size_of::<SourceOriginalAdmissionDataV5>()
                            .checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>())?,
                    )?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(pairs.checked_mul(2)?.checked_mul(historical_descriptor)?)
            })
            .ok_or_else(limit)?
            .min(self.native.limits().maximum_materialized_bytes);
        let resident = self
            .source_original_replay
            .original_release_resident_copy_bytes_v1()?;
        let representation = std::mem::size_of::<Option<OriginalReleaseSourceCutCaptureV1>>()
            .checked_sub(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::cell::Cell<bool>>()))
            .ok_or_else(limit)?;
        // The live challenge Journal's original Vec and the cached Arc witness
        // coexist. Charge both payloads independently; borrowing does not
        // eliminate the original Vec's residence or its separate native owner.
        let challenge_resident = challenges.checkpoints()?.try_fold(0_usize, |bytes, row| {
            bytes
                .checked_add(std::mem::size_of::<
                    source_original_native::SourceOriginalChallengeCheckpointV5,
                >())
                .and_then(|bytes| bytes.checked_add(row.key().len()))
                .and_then(|bytes| bytes.checked_add(row.value().len()))
                .ok_or_else(limit)
        })?;

        // Retain the fresh independent cache AND guard an additional logical
        // comparison allowance. The shared parser's original limits stay
        // unchanged; nested allocator/validator peaks remain funding debt.
        self.original_release_native_replay_copy_bytes_v1(physical_end)?
            .checked_add(resident)
            .and_then(|bytes| bytes.checked_add(challenge_resident))
            .and_then(|bytes| bytes.checked_add(source_payload.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(physical.checked_mul(6)?))
            .and_then(|bytes| bytes.checked_add(representation))
            .ok_or_else(limit)
    }

    pub(super) fn require_original_release_controller_replay_v1(
        &self,
        replayed: &ReplayState,
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

    pub(super) fn require_original_release_source_replay_v1(
        &self,
        replayed: &ReplayState,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        self.require_original_release_native_replay_v1(
            replayed,
            history,
            physical_end,
            OriginalReleaseNativeCutPurposeV1::Source,
        )?;
        source_original_native::writer::require_original_release_source_replay_v1(
            self, replayed, challenges,
        )
    }

    pub(super) fn require_original_release_native_replay_v1(
        &self,
        replayed: &ReplayState,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
        purpose: OriginalReleaseNativeCutPurposeV1,
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
            || replayed.transaction_ids != *self.native.transaction_ids()
            || replayed.committed_namespaces != *self.native.committed_namespaces()
            || replayed.state != *self.native.state()
            || replayed.materialized_bytes != self.native.materialized_bytes()
            || replayed.idempotency != self.idempotency
            || (!matches!(purpose, OriginalReleaseNativeCutPurposeV1::Source)
                && (!replayed.source_challenge_history.is_empty()
                    || !self.source_challenge_history.is_empty()
                    || replayed.source_original_replay.has_dependencies()
                    || self.source_original_replay.has_dependencies()))
            || replayed.source_history_compacted != self.source_history_compacted
            || replayed.q04_lower_history_present != self.q04_lower_history_present
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}
