//! Retains the actual paid Cache readonly constructor through its full replay.
//!
//! The same common native opener owns captured metadata, parser, index, tail,
//! prefix post and late instance transfer. Cache's concrete financial context
//! pays before named entry and every semantic growth frontier. Failed partial
//! owners and their independently owed name posts remain resident.

use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalJournalMechanicalErrorV1,
    CanonicalOrdinaryOpeningOriginalsV1, CanonicalOrdinaryReadonlyOpeningV1,
    NativeJournalDataErrorV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::readonly::{ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal, ReadonlyNameArchiveV1};
use super::readonly_receiving::CacheReadonlyReceivingContextV1;
use super::semantics::{self, CacheSemanticOriginalV1, CacheSemanticRemainderV1};
use super::{
    CacheCompactionSelectionV1, CacheJournalInstanceV1, HeldCacheJournalV1,
    Journal, JournalError, JournalLimits, ProtectedJournalPreopenReplayExtentV1,
    RecoveryReport,
};

type Native = CanonicalOrdinaryReadonlyOpeningV1<JournalError>;

#[derive(Debug, thiserror::Error)]
#[error("captured Cache readonly opening is closed")]
struct Closed;

static CLOSED: Closed = Closed;

struct CapturedPreparationV1 {
    binding: Option<(String, JournalLimits)>,
    named_admission: Option<Result<(), JournalError>>,
    native: Option<Result<(), JournalError>>,
    names: Option<Result<(), JournalError>>,
    replay_entered: bool,
    closed: bool,
}

impl CapturedPreparationV1 {
    const fn new() -> Self {
        Self {
            binding: None,
            named_admission: None,
            native: None,
            names: None,
            replay_entered: false,
            closed: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.named_admission.as_ref().and_then(|value| value.as_ref().err())
            .or_else(|| self.native.as_ref().and_then(|value| value.as_ref().err()))
            .or_else(|| self.names.as_ref().and_then(|value| value.as_ref().err()))
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.closed.then_some(&CLOSED as _))
    }
}

pub(crate) struct ReadOnlyJournalOpenOriginalsV1 {
    native: Native,
    semantic: Option<CacheSemanticOriginalV1>,
    remainder: Option<CacheSemanticRemainderV1>,
    opened: Option<(HeldCacheJournalV1, RecoveryReport)>,
    replay_result: Option<Result<(), JournalError>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    returned: Option<Result<RecoveryReport, JournalError>>,
    readback: Option<ReadOnlyProtectedJournal>,
    witness: Option<ReadOnlyJournalNameWitness>,
    initial_name: Option<Result<(), JournalError>>,
    post_name: Option<Result<(), JournalError>>,
    attempted: bool,
    post_attempted: bool,
    closed: bool,
    captured: CapturedPreparationV1,
    named_receiving: Option<ReadonlyNameArchiveV1>,
}

impl ReadOnlyJournalOpenOriginalsV1 {
    pub(crate) const fn new() -> Self {
        Self {
            native: Native::new(),
            semantic: None,
            remainder: None,
            opened: None,
            replay_result: None,
            extent: None,
            returned: None,
            readback: None,
            witness: None,
            initial_name: None,
            post_name: None,
            attempted: false,
            post_attempted: false,
            closed: false,
            captured: CapturedPreparationV1::new(),
            named_receiving: None,
        }
    }

    pub(crate) fn prepare_captured_cache_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: (u64, u64),
        receiving: &mut CacheReadonlyReceivingContextV1<'_, '_, '_, '_>,
    ) {
        if self.attempted || self.closed || self.captured.named_admission.is_some() {
            self.captured.closed = true;
            return;
        }
        self.captured.named_admission = Some(receiving.require_fixed_named_preparation());
        if !matches!(self.captured.named_admission, Some(Ok(()))) {
            self.attempted = true;
            return;
        }
        self.named_receiving = Some(ReadonlyNameArchiveV1::new());
        self.attempted = true;
        self.captured.binding = Some((name.to_owned(), limits));
        self.captured.native = Some((|| {
            self.native.prepare_bound_directory_once_v1(
                path, name, limits, uid, expected_directory,
            )?;
            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())
                .map_err(CanonicalJournalMechanicalErrorV1::from)
                .map_err(JournalError::from)?;
            self.native.prepare_bound_files_once_v1(None)?;
            let (directory, journal, lock) = self.native.identities_data_v1()
                .ok_or_else(JournalError::boundary)?;
            self.witness = Some(ReadOnlyJournalNameWitness {
                physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness::
                    from_original_parts((path.to_owned(), name.to_owned(), uid, directory, journal, lock)),
            });
            let length = self.native.capture_metadata_once_v1()?;
            if length > limits.maximum_journal_bytes {
                return Err(CanonicalJournalMechanicalErrorV1::JournalTooLarge.into());
            }
            self.extent = Some(super::protected_journal_preopen_replay_extent_for_prefix_v1(
                limits, length,
            ));
            if !matches!(self.extent, Some(Ok(_))) {
                return Err(JournalError::boundary());
            }
            Ok(())
        })());
        // Actual physical-name entry still owes this post after capture error.
        self.captured.names = self.observe_names();
    }

    pub(crate) fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.closed || self.captured.replay_entered || self.captured.failure().is_some()
            || !matches!(self.captured.native, Some(Ok(())))
            || !matches!(self.captured.names, Some(Ok(())))
        {
            return None;
        }
        self.extent.as_ref()?.as_ref().ok()
    }

    pub(crate) fn replay_captured_cache_once(
        &mut self,
        receiving: &mut CacheReadonlyReceivingContextV1<'_, '_, '_, '_>,
    ) {
        if self.closed || self.captured.replay_entered || self.captured.failure().is_some()
            || !matches!(self.captured.native, Some(Ok(())))
            || !matches!(self.captured.names, Some(Ok(())))
            || self.returned.is_some()
        {
            self.captured.closed = true;
            return;
        }
        self.captured.replay_entered = true;
        let Some((name, limits)) = self.captured.binding.take() else {
            self.captured.closed = true;
            return;
        };
        self.returned = Some(self.finish_captured_inner(limits, receiving));
        self.captured.binding = Some((name, limits));
        self.initial_name = self.observe_names();
    }

    fn finish_captured_inner(
        &mut self,
        limits: JournalLimits,
        receiving: &mut CacheReadonlyReceivingContextV1<'_, '_, '_, '_>,
    ) -> Result<RecoveryReport, JournalError> {
        let length = self.native.captured_length_data_v1().ok_or_else(JournalError::boundary)?;
        self.replay_result = Some((|| {
            receiving.require_captured_file_end(length)?;
            self.semantic = Some(CacheSemanticOriginalV1::new());
            let (identity, mut cursor) = self.native.begin_retained_captured_replay_once_v1()
                .map_err(JournalError::from_ordinary_native_v1)?;
            semantics::observe_readonly_once(
                self.semantic.as_mut().ok_or_else(JournalError::boundary)?,
                &mut cursor, identity, limits, receiving,
            ).map_err(|_| JournalError::boundary())
        })());
        // The entered prefix always receives its independently owed post.
        self.native.observe_retained_prefix_post_once_v1();
        if !matches!(self.replay_result, Some(Ok(()))) {
            return Err(JournalError::boundary());
        }
        if self.native.retained_prefix_post_v1().is_none_or(|post| post.failure().is_some()) {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        let truncated_bytes = self.native.finish_retained_tail_once_v1()?;
        self.remainder = self.semantic.as_mut().and_then(semantics::take_remainder_once);
        self.remainder.as_ref().ok_or_else(JournalError::boundary)?;
        self.witness.as_ref().ok_or_else(JournalError::boundary)?;
        self.opened = self.native.take_held_with_late_payload_once_v1(
            CacheCompactionSelectionV1::Other, CacheJournalInstanceV1,
        );
        let witness = self.witness.take().ok_or_else(JournalError::boundary)?;
        match Journal::from_opening_originals_v1(&mut self.opened, &mut self.remainder) {
            Some((journal, mut report)) => {
                report.truncated_bytes = truncated_bytes;
                self.readback = Some(ReadOnlyProtectedJournal {
                    journal,
                    witness,
                    named_receiving: self.named_receiving.take(),
                });
                Ok(report)
            }
            None => {
                self.witness = Some(witness);
                Err(JournalError::boundary())
            }
        }
    }

    fn observe_names(&self) -> Option<Result<(), JournalError>> {
        if let Some(readback) = &self.readback {
            return Some(readback.check_named_currentness());
        }
        let witness = self.witness.as_ref()?;
        if !self.native.has_native_file_data_v1() {
            return None;
        }
        Some(match &self.named_receiving {
            Some(archive) => archive.observe_opening_v1(witness, &self.native),
            None => self.native.require_temporary_names_current_v1::<JournalError>(&witness.physical),
        })
    }

    pub(crate) fn recheck_named_once(&mut self) {
        if self.post_attempted || !self.attempted {
            self.closed = true;
            return;
        }
        self.post_attempted = true;
        self.post_name = self.observe_names();
    }

    pub(crate) fn observe_named_currentness(&self) -> Option<Result<(), JournalError>> {
        self.observe_names()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self.native.acquisition_failure_v1()
            .or_else(|| self.extent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.semantic.as_ref()?.source_failure_cause_v1())
            .or_else(|| self.native.retained_parser_preparation_failure_v1())
            .or_else(|| {
                let cause = self.native.replay_failure_v1()?;
                // Keep the cursor's owning wrapper resident while exposing
                // the same typed frame diagnostic as the original Cache path.
                match cause.downcast_ref::<NativeJournalDataErrorV1>() {
                    Some(NativeJournalDataErrorV1::Frame(frame)) => Some(frame as _),
                    _ => Some(cause),
                }
            })
            .or_else(|| self.native.index_failure_v1())
            .or_else(|| self.semantic.as_ref()?.failure())
            .or_else(|| self.replay_result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.native.retained_prefix_post_v1()?.failure())
            .or_else(|| self.native.retained_tail_failure_v1())
            .or_else(|| self.captured.failure())
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.initial_name.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.post_name.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.native.order_failure_v1())
            .or_else(|| self.closed.then_some(&CLOSED as _))?;
        match cause.downcast_ref::<JournalError>() {
            Some(JournalError::ReadOnlyNameReceivingFailure(index)) => {
                self.named_receiving_failure(*index).map(|cause| cause as _).or(Some(cause))
            }
            _ => Some(cause),
        }
    }

    pub(crate) fn named_receiving_failure(&self, index: u8) -> Option<&JournalError> {
        match &self.readback {
            Some(readback) => readback.named_receiving_failure(index),
            None => self.named_receiving.as_ref()?.failure_at(index),
        }
    }

    pub(crate) fn readback_mut(&mut self) -> Option<&mut ReadOnlyProtectedJournal> {
        if self.closed || self.failure().is_some()
            || !matches!(self.returned, Some(Ok(_)))
            || !matches!(self.initial_name, Some(Ok(())))
        {
            return None;
        }
        self.readback.as_mut()
    }

    pub(crate) fn fixed_preparation_demand_v1<T>(
        directory_descriptors: u16,
        path_name_bytes: u16,
    ) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::limit_exceeded("Cache captured readonly construction");
        let base = CanonicalOrdinaryOpeningOriginalsV1::<()>::fixed_preparation_demand_v1::<T>(
            directory_descriptors, path_name_bytes,
        )?;
        let semantic = semantics::receiving_demand_v1().map_err(JournalError::from)?;
        let bytes = Native::receiving_construction_bytes_v1::<
            CacheCompactionSelectionV1, CacheJournalInstanceV1,
        >().ok_or_else(invalid)?
            .checked_add(Journal::opening_materialization_bytes_v1().ok_or_else(invalid)?)
            .and_then(|bytes| bytes.checked_add(
                CanonicalJournalInstanceDataV1::<CacheJournalInstanceV1>::
                    payload_allocation_receiving_bytes_v1()?,
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>().checked_mul(4)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        base.checked_add(semantic)
            .and_then(|value| value.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| invalid())
    }

    pub(crate) fn cache_named_receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        ReadonlyNameArchiveV1::receiving_demand_v1()
    }
}


impl ReadOnlyJournalOpenOriginalsV1 {
    pub(crate) const fn cache_held_attempted_v1(&self) -> bool {
        self.attempted
    }

    pub(crate) fn cache_held_report_data_v1(&self) -> Option<RecoveryReport> {
        if self.failure().is_some() {
            return None;
        }
        self.returned.as_ref().and_then(|result| result.as_ref().ok()).copied()
    }

    #[cfg(test)]
    pub(crate) fn prepare_absent_cache_fixture_once_v1(&mut self) {
        if self.attempted {
            self.closed = true;
            return;
        }
        self.attempted = true;
        let path = Path::new("/rfc21-cache-held-absent-native-fixture");
        self.captured.native = Some(
            self.native.prepare_bound_directory_once_v1(
                path, "state.journal", JournalLimits::default(), 0, (1, 2),
            ).and_then(|()| {
                // This fixture intentionally has no payer and never enters a
                // positive file/replay path, even if the external path exists.
                Err(JournalError::boundary())
            }),
        );
    }
}
