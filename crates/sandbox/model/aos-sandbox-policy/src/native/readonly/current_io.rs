//! Stages the genuine Current Controller reader on the same fixed opening.
//!
//! Current metadata precedes its captured-name post. The independent prefix
//! post runs after every entered replay outcome, before tail classification.
//! The same finite name archive follows the genuine opening into its late
//! model; no ordinary fallback or replacement parser/model is selected here.

use std::error::Error;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, NativeJournalDataErrorV1,
};
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_journal::protected_storage::{FileIdentity, ReadonlyNameArchiveV1};
use aos_sandbox_journal::recovery::RecoveryTailError;
use aos_sandbox_ledger_replay::cold::ColdReplayClosedV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use crate::native::root_current::readonly_receiving::RootCurrentReadonlyReceivingContextV1;
use super::error::RootReadonlyErrorV1 as ReadError;
use super::model::RootReadonlyModelOriginalsV1;
use super::{RootFixedNativeReadOriginalsV1, RootFixedNativeTargetV1};

const CURRENT_NAME_OBSERVATIONS: usize = 6;
type Slot<T> = Option<Result<T, ReadError>>;
type Names = ReadonlyNameArchiveV1<ReadError>;

pub(super) struct CurrentIoOriginalV1 {
    purpose_uid: Option<u32>,
    named_admission: Slot<()>,
    prepared: Slot<()>,
    name_error: Option<ReadError>,
    captured_names: Option<Result<(), u8>>,
    initial_names: Option<Result<(), u8>>,
    after_names: Option<Result<(), u8>>,
    after_names_attempted: bool,
    file_end_admission: Slot<()>,
    replay: Slot<()>,
    tail: Slot<u64>,
    archive: Option<Names>,
    expected_directory: Option<(u64, u64)>,
    replay_entered: bool,
    model_finished: bool,
}

impl CurrentIoOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            purpose_uid: None,
            named_admission: None,
            prepared: None,
            name_error: None,
            captured_names: None,
            initial_names: None,
            after_names: None,
            after_names_attempted: false,
            file_end_admission: None,
            replay: None,
            tail: None,
            archive: None,
            expected_directory: None,
            replay_entered: false,
            model_finished: false,
        }
    }

    // This is a supplier only. Its genuine purpose constructor must consume
    // the bound before these additional concrete controls are constructed.
    pub(super) fn additional_control_bytes_v1() -> Option<usize> {
        // The outer purpose entry is distinct from captured-file entry. It
        // retains only the actual old mount-after UID on early body refusal.
        let outer_scope = size_of::<(&mut RootFixedNativeReadOriginalsV1, u32)>().checked_mul(3)?
            .checked_add(size_of::<Option<u32>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<(&Option<u32>, u32)>().checked_mul(3)?)?;
        let replay_loan = size_of::<RootCurrentReplayFieldsBorrowV1<'_>>().checked_mul(2)?
            .checked_add(size_of::<(RootCurrentReplayFieldsBorrowV1<'_>, &super::audit::RootControllerReadonlyGeometryAuditV1)>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(6)?)?
            .checked_add(size_of::<(&mut RootCurrentReplayFieldsBorrowV1<'_>, &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>)>().checked_mul(6)?)?
            .checked_add(size_of::<(&mut RootFixedNativeReadOriginalsV1, &mut RootReadonlyModelOriginalsV1)>().checked_mul(3)?)?;
        let mount_split = size_of::<(&mut RootFixedNativeReadOriginalsV1, u32, (u64, u64))>().checked_mul(3)?
            .checked_add(size_of::<(&mut RootFixedNativeReadOriginalsV1, &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>)>().checked_mul(6)?)?
            .checked_add(size_of::<Option<(u64, u64)>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(6)?)?;
        let forwarded = size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<(&RootFixedNativeReadOriginalsV1, bool)>().checked_mul(3)?)?
            .checked_add(size_of::<&bool>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(6)?)?
            .checked_add(size_of::<&RootFixedNativeReadOriginalsV1>().checked_mul(3)?)?
            .checked_add(size_of::<&super::audit::RootControllerReadonlyGeometryAuditV1>().checked_mul(3)?)?
            .checked_add(mount_split)?
            .checked_add(replay_loan)?
            .checked_add(outer_scope)?
            .checked_add(size_of::<(
                Result<(), ReadError>,
                Result<(), ColdReplayClosedV1>,
                Option<Result<(), u8>>,
                Result<u64, RecoveryTailError>,
                Result<u64, ReadError>,
                Result<(FileIdentity, CanonicalIndexedReplayV1<'_, '_>), NativeJournalDataErrorV1>,
                CanonicalIndexedReplayErrorV1,
                CanonicalJournalMechanicalErrorV1,
                ReadError,
                Option<&Names>,
                Option<&(dyn Error + 'static)>,
                Option<std::io::Result<std::fs::Metadata>>,
                Option<Result<(), u8>>,
                Result<super::model::RootReadonlyModelInputsV1, ReadError>,
            )>().checked_mul(2)?)?;

        let arguments = size_of::<(
            &mut RootFixedNativeReadOriginalsV1,
            &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
        )>().checked_mul(6)?
            .checked_add(size_of::<(u32, (u64, u64))>().checked_mul(2)?)?
            .checked_add(size_of::<(&mut RootFixedNativeReadOriginalsV1, &mut RootReadonlyModelOriginalsV1)>()
                .checked_mul(2)?)?
            .checked_add(size_of::<(&RootFixedNativeReadOriginalsV1, &RootReadonlyModelOriginalsV1)>()
                .checked_mul(2)?)?
            .checked_add(size_of::<(&mut Self, Option<Result<(), u8>>)>().checked_mul(6)?)?
            .checked_add(size_of::<(&Self, &Option<Result<(), u8>>)>().checked_mul(6)?)?
            .checked_add(size_of::<(&Names, u8)>().checked_mul(6)?)?
            .checked_add(size_of::<&RootFixedNativeReadOriginalsV1>().checked_mul(6)?)?;

        // Preparation/replay closures hold their actual mutable receiver and
        // receiving-context references; the replay also borrows captured EOF.
        let body_closures = size_of::<(
            &mut &mut RootFixedNativeReadOriginalsV1,
            &mut &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
        )>().checked_mul(3)?
            .checked_add(size_of::<(
                &mut &mut RootFixedNativeReadOriginalsV1,
                &mut &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
                &u64,
            )>().checked_mul(3)?)?
            .checked_add(size_of::<&u8>().checked_mul(3)?)?
            .checked_add(size_of::<&&Self>().checked_mul(3)?)?;

        // The first-cause chain contains 21 distinct borrowed
        // closure environments. Both receiver kinds are bounded per closure;
        // no helper's argument bytes are reused to pay these environments.
        let selector_closures = size_of::<(&RootFixedNativeReadOriginalsV1, &Self)>()
            .checked_mul(63)?;

        let borrowed_failures = size_of::<(
            &aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<ReadError>,
            &super::ColdReplayOriginalV1,
            &Option<Result<(), ColdReplayClosedV1>>,
            &CurrentIoOriginalV1,
        )>().checked_mul(6)?
            .checked_add(size_of::<&RootCurrentReplayFieldsBorrowV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(9)?)?
            .checked_add(size_of::<(
                &aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<ReadError>,
                &super::ColdReplayOriginalV1,
                &Option<Result<(), ColdReplayClosedV1>>,
                &CurrentIoOriginalV1,
            )>().checked_mul(33)?)?;
        let construction = size_of::<RootFixedNativeReadOriginalsV1>()
            .checked_add(size_of::<super::role_replay::RootReadonlySemanticOriginalV1>()
                .checked_mul(2)?)?
            .checked_add(size_of::<Option<Names>>().checked_mul(2)?)?;

        let quote_interfaces = size_of::<Result<ResourceVector, ReadError>>().checked_mul(8)?
            // Names and Audit are separate captured vectors in the Current
            // donor's two checked-add closures, beyond their call arguments.
            .checked_add(size_of::<&ResourceVector>().checked_mul(6)?)?
            // The Current transfer directly calls its retained failure and
            // indexed-EOF checkers after the Common readback was removed.
            .checked_add(size_of::<&RootFixedNativeReadOriginalsV1>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(2)?)?
            .checked_add(size_of::<&Option<&(dyn Error + 'static)>>())?
            .checked_add(size_of::<&aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<ReadError>>())?
            .checked_add(size_of::<bool>().checked_mul(2)?)?
            .checked_add(size_of::<Option<aos_sandbox_journal::protected_storage::ReadonlyNameArchiveGeometryV1>>()
                .checked_mul(2)?)?
            .checked_add(size_of::<(usize, &str)>().checked_mul(2)?)?
            .checked_add(size_of::<(ResourceVector, ResourceVector)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                .checked_mul(6)?)?
            .checked_add(size_of::<Result<u64, std::num::TryFromIntError>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<u64>>().checked_mul(2)?)?
            .checked_add(size_of::<ReadError>().checked_mul(4)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(4)?)?;

        forwarded.checked_add(arguments)?.checked_add(body_closures)?
            .checked_add(selector_closures)?.checked_add(borrowed_failures)?.checked_add(construction)?
            .checked_add(quote_interfaces)
    }

    pub(super) fn name_receiving_demand_v1() -> Result<ResourceVector, ReadError> {
        use aos_sandbox_model::ResourceDimension as D;
        let geometry = Names::receiving_geometry_v1(CURRENT_NAME_OBSERVATIONS,
            RootFixedNativeTargetV1::ControllerCurrent.recipe().0)
            .ok_or(ReadError::LimitExceeded("readonly name receiving geometry"))?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, geometry.memory_bytes)
            .with(D::OpenFiles, geometry.open_files)
            .with(D::MetadataEntries, geometry.namespace_entries))
    }

    // Preserve the original typed marker when a finite archive reports its
    // exhaustion sentinel rather than a stored per-entry native cause.
    fn retain_first_name_error(&mut self, result: Option<Result<(), u8>>) {
        if let Some(Err(index)) = result {
            if self.name_error.is_none() {
                self.name_error = Some(ReadError::ReadOnlyNameReceivingFailure(index));
            }
        }
    }

    fn name_failure(&self, slot: &Option<Result<(), u8>>)
        -> Option<&(dyn Error + 'static)>
    {
        let index = *slot.as_ref()?.as_ref().err()?;
        self.archive.as_ref().and_then(|archive| archive.failure_at(index))
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.name_error.as_ref().map(|cause| cause as _))
    }
}

impl RootFixedNativeReadOriginalsV1 {
    // This fixed selection creates only inert destinations. It never completes
    // a role or receives a caller-provided success/financial/physical original.
    pub(in crate::native) fn controller_role_current_v1() -> Self {
        let mut original = Self::with_semantic_v1(
            super::role_replay::RootReadonlySemanticOriginalV1::current_v1(),
        );
        original.target = RootFixedNativeTargetV1::ControllerCurrent;
        original.current_io = Some(CurrentIoOriginalV1::new());
        original
    }

    // This is consumed by the genuine incoming constructor before the inert
    // reader exists. It quotes no native file, family allocation or role grant.
    pub(crate) fn current_construction_control_bytes_v1() -> Option<usize> {
        let reader = size_of::<RootFixedNativeReadOriginalsV1>().checked_mul(2)?;
        let semantic = super::role_replay::RootReadonlySemanticOriginalV1::receiving_construction_bytes_v1()?;
        let io = CurrentIoOriginalV1::additional_control_bytes_v1()?;
        let forwarding = size_of::<Option<usize>>().checked_mul(6)?;

        reader.checked_add(semantic)?.checked_add(io)?.checked_add(forwarding)
    }

    // This is only custody of the old outer purpose entry/UID. Actual fixed
    // admission and the concrete receiving context remain mandatory before any
    // opening. It issues neither a role, captured file nor successful replay.
    pub(crate) fn begin_current_purpose_once_v1(
        &mut self,
        original_uid: u32,
    ) -> Result<(), ReadError> {
        let io = self.current_io.as_mut().ok_or(ReadError::ProtectedBoundary)?;
        if self.entered || self.closed || io.purpose_uid.is_some() {
            self.closed = true;
            return Err(ReadError::ProtectedBoundary);
        }
        io.purpose_uid = Some(original_uid);
        Ok(())
    }

    pub(crate) fn prepare_current_once(
        &mut self,
        original_uid: u32,
        expected_directory: (u64, u64),
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) {
        self.prepare_current_mount_once_v1(original_uid, expected_directory);
        if matches!(self.mount_before_result, Some(Ok(()))) && self.primary.is_none() {
            self.prepare_current_files_once_v1(receiving);
        }
    }

    // Only the genuine Current purpose invokes this split. The mount is still
    // observed before the actual short live receiving check, with the exact
    // receipt directory retained for the SAME subsequent bound opening.
    pub(crate) fn prepare_current_mount_once_v1(
        &mut self,
        original_uid: u32,
        expected_directory: (u64, u64),
    ) {
        if self.entered || self.closed || self.current_io.is_none() {
            self.closed = true;
            return;
        }
        if let Some(io) = &mut self.current_io {
            if io.purpose_uid.is_none() {
                io.purpose_uid = Some(original_uid);
            }
            io.expected_directory = Some(expected_directory);
        }
        self.entered = true;
        self.original_uid = original_uid;
        self.mount_before_result = Some(self.mount_before.observe_root_readonly_once(
            self.target.view_v1(), self.original_uid, rustix::process::getegid().as_raw(),
            Some(expected_directory),
        ));
        if super::positive(&self.mount_before_result).is_err() {
            self.primary = Some(Err(ReadError::ProtectedBoundary));
        }
    }

    pub(crate) fn prepare_current_files_once_v1(
        &mut self,
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) {
        if !self.entered || self.closed || self.primary.is_some()
            || !matches!(self.mount_before_result, Some(Ok(())))
        {
            self.closed = true;
            return;
        }
        self.primary = Some(self.prepare_current_files_inner(receiving));
    }

    fn prepare_current_files_inner(
        &mut self,
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) -> Result<(), ReadError> {
        let expected_directory = self.current_io.as_ref()
            .and_then(|io| io.expected_directory).ok_or(ReadError::ProtectedBoundary)?;
        let admission = receiving.require_fixed_named_preparation();
        self.current_io.as_mut().ok_or(ReadError::ProtectedBoundary)?.named_admission = Some(admission);
        super::positive(&self.current_io.as_ref().ok_or(ReadError::ProtectedBoundary)?.named_admission)?;
        self.current_io.as_mut().ok_or(ReadError::ProtectedBoundary)?.archive =
            Some(Names::new(CURRENT_NAME_OBSERVATIONS));

        let prepared = (|| {
            let (root, name, limits) = self.target.recipe();
            self.opening.prepare_bound_directory_once_v1(
                Path::new(root), name, limits, 0, expected_directory,
            )?;
            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())
                .map_err(|cause| ReadError::from(CanonicalJournalMechanicalErrorV1::from(cause)))?;
            self.opening.prepare_bound_files_once_v1(
                Some(receiving.retained_lock_name_destination_v1()),
            )?;
            let (directory, file, lock) = self.opening.identities_data_v1()
                .ok_or(ReadError::ProtectedBoundary)?;
            self.capture_fixed_witness_once_v1(root, name, 0, directory, file, lock);
            let bytes = self.opening.capture_metadata_once_v1()?;
            if bytes > limits.maximum_journal_bytes {
                return Err(ReadError::JournalTooLarge);
            }
            self.extent = Some(super::preopen_geometry::protected_journal_preopen_replay_extent_for_prefix_v1(
                limits, bytes,
            ));
            super::positive(&self.extent).map(|_| ())
        })();
        // Park the whole primary before the independent name IO, including
        // on refusal; it must remain owned through that observer and unwind.
        self.current_io.as_mut().ok_or(ReadError::ProtectedBoundary)?.prepared = Some(prepared);
        // The captured-name post is owed even if metadata or extent refused.
        let names = self.observe_current_opening_names_v1();
        let io = self.current_io.as_mut().ok_or(ReadError::ProtectedBoundary)?;
        io.captured_names = names;
        io.retain_first_name_error(names);
        super::positive(&io.prepared)?;
        if !matches!(self.current_io.as_ref().and_then(|io| io.captured_names), Some(Ok(()))) {
            return Err(ReadError::ProtectedBoundary);
        }
        Ok(())
    }

    fn observe_current_opening_names_v1(&self) -> Option<Result<(), u8>> {
        if !self.opening.has_native_file_data_v1() {
            return None;
        }
        let io = self.current_io.as_ref()?;
        let witness = self.witness.as_ref()?;
        Some(self.opening.observe_archived_names_v1(io.archive.as_ref()?, witness))
    }

    pub(crate) fn replay_current_once(
        &mut self,
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
        model: &mut RootReadonlyModelOriginalsV1,
    ) {
        let entered = {
            let (mut replay, _audit) = self.borrow_current_replay_fields_v1();
            replay.replay_once_v1(receiving)
        };
        if entered {
            self.finish_current_replay_model_once_v1(model);
        }
    }

    // This is a lexical split of the SAME owner, never a file, Audit or replay
    // adopter. The capture check is passive; its protected fields remain under
    // this exclusive loan until the unchanged replay guard consumes the check.
    pub(crate) fn borrow_current_replay_fields_v1(
        &mut self,
    ) -> (RootCurrentReplayFieldsBorrowV1<'_>, &super::audit::RootControllerReadonlyGeometryAuditV1) {
        let captured = self.require_captured_v1();
        let replay = RootCurrentReplayFieldsBorrowV1 {
            captured,
            target: self.target,
            opening: &mut self.opening,
            cold: &mut self.cold,
            cold_result: &mut self.cold_result,
            current_io: &mut self.current_io,
            replay_result: &mut self.replay_result,
            replay_position: &mut self.replay_position,
            closed: &mut self.closed,
        };
        (replay, &self.audit)
    }

    // Initial archive observation still follows the SAME late model transfer.
    // This separate private entry is reached only after the replay loan ends.
    pub(crate) fn finish_current_replay_model_once_v1(
        &mut self,
        model: &mut RootReadonlyModelOriginalsV1,
    ) -> bool {
        let Some(io) = &mut self.current_io else {
            self.closed = true;
            return false;
        };
        if io.model_finished || io.replay.is_none() {
            self.closed = true;
            return false;
        }
        io.model_finished = true;
        let positive = matches!(io.replay, Some(Ok(())));
        if positive {
            model.adopt_current_once(self);
            // Model owns the SAME archive/opening after the actual transfer,
            // even when its saved-challenge or late-identity stage refuses.
            model.observe_initial_current_names_once_v1();
        } else {
            let names = self.observe_current_opening_names_v1();
            if let Some(io) = &mut self.current_io {
                io.initial_names = names;
                io.retain_first_name_error(names);
            }
        }
        true
    }

    // The genuine purpose retains this SAME first-pass owner, including its
    // negative state, across funding, replay and all independent posts.
    pub(crate) fn current_audit_original_v1(&self) -> &super::audit::RootControllerReadonlyGeometryAuditV1 {
        &self.audit
    }

    // This private transfer is the original Current materialization frontier:
    // full role EOF, owed prefix post and rejecting tail have completed; later
    // names/mount/Storage/peer/clock posts remain owed on these SAME originals.
    pub(super) fn take_current_model_inputs_once_v1(
        &mut self,
    ) -> Result<super::model::RootReadonlyModelInputsV1, ReadError> {
        if self.model_transferred || self.current_io.is_none() || self.closed
            || !matches!(self.primary, Some(Ok(())))
            || !matches!(self.extent, Some(Ok(_)))
            || !matches!(self.replay_result, Some(Ok(())))
            || !self.opening.indexed_replay_complete_data_v1()
            || self.replay_position.is_none()
            || self.current_failure_v1().is_some()
            || !matches!(self.target, RootFixedNativeTargetV1::ControllerCurrent)
            || !matches!(self.cold_result, Some(Ok(())))
            || !matches!(self.current_io.as_ref().and_then(|io| io.replay.as_ref()), Some(Ok(())))
            || !matches!(self.current_io.as_ref().and_then(|io| io.tail.as_ref()), Some(Ok(_)))
            || self.opening.retained_prefix_post_v1().is_none_or(|post| post.failure().is_some())
            || self.current_io.as_ref().is_none_or(|io| io.archive.is_none())
            || self.witness.is_none()
        {
            return Err(ReadError::ProtectedBoundary);
        }
        let report = self.opening.replay_data_v1().report()
            .ok_or(ReadError::ProtectedBoundary)?.1;
        let remainder = self.cold.take_remainder_once().ok_or(ReadError::ProtectedBoundary)?;
        let current_names = self.take_current_name_archive_once_v1();
        self.model_transferred = true;
        Ok(super::model::RootReadonlyModelInputsV1 {
            target: self.target,
            view: self.target.view_v1(),
            original_uid: self.original_uid,
            witness: self.witness.take(),
            report,
            opening: Some(std::mem::replace(&mut self.opening,
                aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1::new())),
            remainder: Some(remainder),
            current_names,
        })
    }

    // This named observation precedes the separate mount-after and Storage
    // posts. It must not use Common's combined mount/names/metadata method.
    pub(crate) fn observe_current_names_after_once_v1(
        &mut self,
        model: &mut RootReadonlyModelOriginalsV1,
    ) {
        let Some(io) = &mut self.current_io else { self.closed = true; return; };
        if !self.entered || io.after_names_attempted { self.closed = true; return; }
        io.after_names_attempted = true;
        if self.model_transferred {
            model.observe_current_names_after_once_v1();
        } else {
            let result = self.observe_current_opening_names_v1();
            if let Some(io) = &mut self.current_io {
                io.after_names = result;
                io.retain_first_name_error(result);
            }
        }
    }

    pub(crate) fn observe_current_mount_after_once_v1(&mut self) {
        let original_uid = self.current_io.as_ref().and_then(|io| io.purpose_uid);
        let Some(original_uid) = original_uid else {
            self.closed = true;
            return;
        };
        if self.mount_after_result.is_some() {
            self.closed = true;
            return;
        }
        self.mount_after_result = Some(self.mount_after.observe_root_readonly_once(
            self.target.view_v1(), original_uid, rustix::process::getegid().as_raw(), None,
        ));
        self.mount_binding = Some(match (self.mount_before.witness(), self.mount_after.witness()) {
            (Some(before), Some(after)) if before == after => Ok(()),
            _ => Err(ReadError::ProtectedBoundary),
        });
    }

    // The containing purpose observes this only AFTER its Storage posts. A
    // failed primary still observes the actual remaining file without health.
    pub(crate) fn observe_current_file_metadata_v1(
        &self,
        model: &RootReadonlyModelOriginalsV1,
    ) -> Option<std::io::Result<std::fs::Metadata>> {
        if self.model_transferred {
            model.observe_current_file_metadata_v1()
        } else if self.opening.has_native_file_data_v1() {
            Some(self.opening.observe_metadata_v1())
        } else {
            None
        }
    }

    // Only the actual native model transfer takes this private same-owner
    // archive. No public constructor can supply one or mark names successful.
    pub(super) fn take_current_name_archive_once_v1(&mut self) -> Option<Names> {
        self.current_io.as_mut()?.archive.take()
    }

    pub(super) fn current_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.current_failure_inner(true)
    }

    // The old containing purpose checks primary failure before considering its
    // independently owed named post. Both views retain one actual cause recipe.
    pub(crate) fn current_primary_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.current_failure_inner(false)
    }

    fn current_failure_inner(&self, include_post: bool) -> Option<&(dyn Error + 'static)> {
        let io = self.current_io.as_ref()?;
        self.mount_before.failure().or_else(|| super::cause(&self.mount_before_result))
            .or_else(|| self.opening.acquisition_failure_v1())
            .or_else(|| super::cause(&self.extent))
            .or_else(|| current_cursor_failure_v1(&self.opening, &self.cold, &self.cold_result, io))
            .or_else(|| super::cause(&io.named_admission))
            .or_else(|| super::cause(&io.prepared))
            .or_else(|| io.name_failure(&io.captured_names))
            .or_else(|| super::cause(&self.primary))
            .or_else(|| super::cause(&io.replay))
            .or_else(|| io.name_failure(&io.initial_names))
            .or_else(|| if include_post { io.name_failure(&io.after_names) } else { None })
            .or_else(|| self.opening.order_failure_v1())
            .or_else(|| self.closed.then_some(&super::READ_CLOSED as &(dyn Error + 'static)))
    }
}


// The immutable Audit is deliberately absent. Its first-pass state can be
// borrowed by the real COMMIT/EOF context while only these disjoint fields move
// through the same retained cursor and semantic engine.
pub(in crate::native) struct RootCurrentReplayFieldsBorrowV1<'reader> {
    captured: Result<(), ReadError>,
    target: RootFixedNativeTargetV1,
    opening: &'reader mut aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<ReadError>,
    cold: &'reader mut super::ColdReplayOriginalV1,
    cold_result: &'reader mut Option<Result<(), ColdReplayClosedV1>>,
    current_io: &'reader mut Option<CurrentIoOriginalV1>,
    replay_result: &'reader mut Option<Result<(), CanonicalIndexedReplayErrorV1>>,
    replay_position: &'reader mut Option<(u64, u64)>,
    closed: &'reader mut bool,
}

impl RootCurrentReplayFieldsBorrowV1<'_> {
    pub(in crate::native) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let io = self.current_io.as_ref()?;
        current_cursor_failure_v1(self.opening, self.cold, self.cold_result, io)
            .or_else(|| super::cause(&io.replay))
            .or_else(|| (*self.closed).then_some(&super::READ_CLOSED as &(dyn Error + 'static)))
    }

    pub(in crate::native) fn refuse_reentry_once_v1(&mut self) {
        *self.closed = true;
    }

    pub(in crate::native) fn require_complete_v1(&self) -> Result<(), ReadError> {
        if *self.closed
            || !matches!(self.replay_result, Some(Ok(())))
            || !matches!(self.current_io.as_ref().and_then(|io| io.replay.as_ref()), Some(Ok(())))
        {
            return Err(ReadError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(in crate::native) fn replay_once_v1(
        &mut self,
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) -> bool {
        if self.captured.is_err()
            || self.current_io.as_ref().is_none_or(|io| io.replay_entered)
            || self.replay_result.is_some()
        {
            *self.closed = true;
            return false;
        }
        if let Some(io) = self.current_io.as_mut() {
            io.replay_entered = true;
        }
        let result = self.replay_inner(receiving);
        let positive = result.is_ok();
        if let Some(io) = self.current_io.as_mut() {
            io.replay = Some(result);
        }
        *self.replay_result = Some(if positive {
            Ok(())
        } else {
            Err(CanonicalIndexedReplayErrorV1::Closed)
        });
        true
    }

    fn replay_inner(
        &mut self,
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) -> Result<(), ReadError> {
        let bytes = self.opening.captured_length_data_v1().ok_or(ReadError::ProtectedBoundary)?;
        *self.cold_result = Some((|| {
            let admission = receiving.require_captured_file_end(bytes);
            self.current_io.as_mut().ok_or(ColdReplayClosedV1)?.file_end_admission = Some(admission);
            super::positive(&self.current_io.as_ref().ok_or(ColdReplayClosedV1)?.file_end_admission)
                .map_err(|_| ColdReplayClosedV1)?;
            let (identity, mut cursor) = self.opening.begin_retained_captured_replay_once_v1()
                .map_err(|_| ColdReplayClosedV1)?;
            self.cold.observe_current_once(&mut cursor, identity, self.target.recipe().2, receiving)?;
            let position = cursor.completed_prefix().ok_or(ColdReplayClosedV1)?.coordinates();
            *self.replay_position = Some((position.durable_next_sequence, position.durable_end));
            Ok(())
        })());
        // This SAME real metadata comparison is unconditional after body entry;
        // a prior context/parser/semantic refusal still owns the first cause.
        self.opening.observe_retained_prefix_post_once_v1();
        if !matches!(self.cold_result, Some(Ok(()))) {
            return Err(ReadError::ProtectedBoundary);
        }
        if self.opening.retained_prefix_post_v1().is_none_or(|post| post.failure().is_some()) {
            return Err(ReadError::StaleAuthoritySnapshot);
        }
        let tail = self.opening.finish_retained_tail_once_v1()
            .map_err(|cause| ReadError::from(CanonicalJournalMechanicalErrorV1::from(cause)));
        if let Some(io) = &mut self.current_io { io.tail = Some(tail); }
        super::positive(&self.current_io.as_ref().ok_or(ReadError::ProtectedBoundary)?.tail)?;
        Ok(())
    }
}

// Both views borrow the SAME cursor, Cold and prefix/tail results. This is one
// diagnostic recipe, not a saved success marker or an alternate replay engine.
fn current_cursor_failure_v1<'cause>(
    opening: &'cause aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<ReadError>,
    cold: &'cause super::ColdReplayOriginalV1,
    cold_result: &'cause Option<Result<(), ColdReplayClosedV1>>,
    io: &'cause CurrentIoOriginalV1,
) -> Option<&'cause (dyn Error + 'static)> {
    cold.source_failure_cause_v1()
            .or_else(|| opening.retained_parser_preparation_failure_v1())
            .or_else(|| opening.replay_failure_v1().map(|cause| {
                match cause.downcast_ref::<NativeJournalDataErrorV1>() {
                    Some(NativeJournalDataErrorV1::Frame(frame)) => frame as &(dyn Error + 'static),
                    _ => cause,
                }
            }))
            .or_else(|| opening.index_failure_v1())
            .or_else(|| cold.failure())
            .or_else(|| super::cause(&io.file_end_admission))
            .or_else(|| super::cause(&cold_result))
            .or_else(|| opening.retained_prefix_post_v1()?.failure())
            .or_else(|| opening.retained_tail_failure_v1())
}
