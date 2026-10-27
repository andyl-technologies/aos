//! Keeps the initial Storage floor's distinct phases on the same original B.
//!
//! Main and sidecar charges remain cumulative. No decoded width, matching name
//! or main-prefix payment creates another writer or resets a spent phase.

use super::*;
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::{
    FloorSidecarDecodeShapeV1, sidecar_limits_v1,
};
use aos_sandbox_journal::framing::FrameError;
use crate::journal::{
    ControllerStorageFloorCapturedJournalOpenV1, Journal, JournalLimits,
    ProtectedJournalPreopenReplayExtentV1, StorageNativeOpeningOwnerLinkV1,
};

#[derive(Clone, Copy)]
enum FloorFirstV1 {
    Fixed,
    FixedOperation,
    Preparation,
    Prefix,
    PrefixOperation,
    Replay,
    Take,
    Reentry,
}

pub(super) struct InitialStorageFloorReceivingV1 {
    main: Option<StorageNativeOpeningOwnerLinkV1>,
    fixed_shape: Option<ControllerInitialBrokerSessionCaptureShapeV1>,
    fixed: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed_operation: Option<ComponentReceivingOwnedOperationV1>,
    extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    decode_shape: Option<FloorSidecarDecodeShapeV1>,
    limits: Option<Result<JournalLimits, FrameError>>,
    prefix: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    prefix_operation: Option<ComponentReceivingOwnedOperationV1>,
    opening: Option<StorageNativeOpeningOwnerLinkV1>,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    replay: Option<Result<(), ResourceReservationErrorV1>>,
    take: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<FloorFirstV1>,
}

impl InitialStorageFloorReceivingV1 {
    pub(super) const fn new() -> Self {
        Self {
            main: None,
            fixed_shape: None,
            fixed: None,
            fixed_operation: None,
            extent: None,
            decode_shape: None,
            limits: None,
            prefix: None,
            prefix_operation: None,
            opening: None,
            preparation: None,
            replay: None,
            take: None,
            first: None,
        }
    }

    // The enclosing initial receiver's sizeof already includes this resident
    // field. This names its additional constructor and actual stage temporaries.
    pub(super) fn receiving_temporary_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let overflow = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let (current_bytes, _) = ControllerInitialSessionReceivingOriginalV1::current_temporary_shape_v1();
        let bytes = size_of::<Self>()
            .checked_add(size_of::<ComponentReceivingOwnedOperationV1>().checked_mul(2).ok_or_else(overflow)?)
            .and_then(|bytes| bytes.checked_add(size_of::<ResourceVector>().checked_mul(10)?))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<ResourceVector, ResourceReservationErrorV1>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<ProtectedJournalPreopenReplayExtentV1>()))
            .and_then(|bytes| bytes.checked_add(size_of::<FloorSidecarDecodeShapeV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<ControllerInitialBrokerSessionCaptureShapeV1>()))
            .and_then(|bytes| bytes.checked_add(size_of::<ControllerInitialBrokerSessionOwnerLinkV1>()))
            .and_then(|bytes| bytes.checked_add(size_of::<JournalLimits>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(current_bytes))
            .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(size_of::<&ControllerInitialBrokerSessionReceivingLoanV1<'static>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<&Journal>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<&ControllerStorageFloorCapturedJournalOpenV1>()))
            .and_then(|bytes| bytes.checked_add(size_of::<&ControllerInitialBrokerSessionCaptureShapeV1>()))
            .ok_or_else(overflow)?;
        // The concrete temporary layouts above occupy bytes. They create no
        // namespace entries; the actual main/sidecar native names are priced
        // separately by their unchanged fixed/captured-prefix suppliers.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
        }
        match self.first? {
            FloorFirstV1::Fixed => cause(&self.fixed),
            FloorFirstV1::FixedOperation => self.fixed_operation.as_ref()?.failure().map(|cause| cause as _),
            FloorFirstV1::Preparation => cause(&self.preparation),
            FloorFirstV1::Prefix => cause(&self.limits).or_else(|| cause(&self.prefix)),
            FloorFirstV1::PrefixOperation => self.prefix_operation.as_ref()?.failure().map(|cause| cause as _),
            FloorFirstV1::Replay => cause(&self.replay),
            FloorFirstV1::Take => cause(&self.take),
            FloorFirstV1::Reentry => Some(&ControllerInitialBrokerSessionClosedV1),
        }
    }
}

impl ControllerInitialBrokerSessionReceivingLoanV1<'_> {
    fn require_storage_main_v1(&self, main: &Journal) -> Result<(), ResourceReservationErrorV1> {
        self.owner.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .require_storage_floor_current_v1().map_err(ResourceReservationErrorV1::from)?;
        self.require_fixed_capture_current_v1(ControllerInitialBrokerSessionRoleV1::Storage)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.require_opened_journal_v1(main).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if !self.owner.prefix_operation.as_ref().is_some_and(|phase| phase.is_consumed_current()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let before = self.owner.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.owner.require_recipient_v1(before.0, before.1)
    }

    fn require_storage_floor_main_v1(&self, main: &Journal) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_main_v1(main)?;
        if !self.owner.storage_floor.main.as_ref().is_some_and(|saved| saved.same_journal(main)) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    fn main_complete_bound_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let fixed = self.owner.fixed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        let prefix = self.owner.prefix.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(fixed.checked_add(prefix)?)
    }

    fn close_storage_floor_v1(&mut self, first: FloorFirstV1) -> ControllerInitialBrokerSessionClosedV1 {
        self.owner.storage_floor.first.get_or_insert(first);
        self.owner.first.get_or_insert(FirstV1::StorageFloor);
        ControllerInitialBrokerSessionClosedV1
    }

    /// Pays distinct sidecar custody before constructing its upper or native owner.
    ///
    /// The closed Security producer supplies its actual type/path/result widths.
    /// Native derives the fixed facade recipe itself under the SAME Storage B.
    ///
    /// # Errors
    /// Retains a foreign main, repeated entry, overflow or original B refusal.
    pub fn require_storage_floor_fixed_preparation_once_v1(
        &mut self,
        main: &Journal,
        actual: &ControllerInitialBrokerSessionCaptureShapeV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || self.owner.storage_floor.fixed.is_some() {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Reentry));
        }
        self.owner.storage_floor.fixed_shape = Some(*actual);
        let result = (|| {
            self.require_storage_main_v1(main)?;
            self.owner.storage_floor.main = Some(main.held_session_owner_link_v1());
            let native = ControllerStorageFloorCapturedJournalOpenV1::fixed_preparation_demand()?;
            let fixed = native.checked_add(actual.demand()?)?;
            let complete = self.main_complete_bound_v1()?.checked_add(fixed)?;
            self.owner.receiving.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .debit_storage_floor_representation_v1(complete).map_err(ResourceReservationErrorV1::from)?;
            Ok(fixed)
        })();
        self.owner.storage_floor.fixed = Some(result);
        let Some(Ok(fixed)) = self.owner.storage_floor.fixed.as_ref() else {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Fixed));
        };
        self.owner.storage_floor.fixed_operation = Some(ComponentReceivingOwnedOperationV1::preflight(*fixed, *fixed));
        if !self.owner.storage_floor.fixed_operation.as_mut().is_some_and(|phase| phase.consume_once().is_ok()) {
            return Err(self.close_storage_floor_v1(FloorFirstV1::FixedOperation));
        }
        Ok(())
    }

    /// Consumes the distinct paid fixed phase before rooted acquisition.
    ///
    /// # Errors
    /// Retains a foreign main, absent payment, closure or repeated entry.
    pub(crate) fn enter_storage_floor_preparation_once_v1(
        &mut self,
        main: &Journal,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || self.owner.storage_floor.preparation.is_some() {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Reentry));
        }
        let result = (|| {
            self.require_storage_floor_main_v1(main)?;
            if !self.owner.storage_floor.fixed_operation.as_ref().is_some_and(|phase| phase.is_consumed_current()) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        self.owner.storage_floor.preparation = Some(result);
        if matches!(self.owner.storage_floor.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(self.close_storage_floor_v1(FloorFirstV1::Preparation))
        }
    }

    /// Pays the exact held sidecar prefix and its distinct typed read reservoir.
    ///
    /// Saved B/main identities are checked before accessing its native extent.
    /// Native replay and generic semantics remain separate from the actual
    /// Security typed shape. No initializer or physical TPM work is included.
    ///
    /// # Errors
    /// Retains mismatched origins/bounds, overflow, repeated entry or B refusal.
    pub fn admit_storage_floor_captured_prefix_once_v1(
        &mut self,
        main: &Journal,
        opening: &ControllerStorageFloorCapturedJournalOpenV1,
        actual: FloorSidecarDecodeShapeV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || self.owner.storage_floor.prefix.is_some() {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Reentry));
        }
        self.owner.storage_floor.decode_shape = Some(actual);
        let expected_owner = self.owner_link_v1();
        let result = (|| {
            self.require_storage_floor_main_v1(main)?;
            if !matches!(self.owner.storage_floor.preparation, Some(Ok(())))
                || !opening.receiving_owner_link_v1().is_some_and(|saved| saved.same_owner_v1(&expected_owner))
                || !opening.main_owner_link_v1().is_some_and(|saved| saved.same_journal(main))
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let extent = opening.captured_extent().copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            self.owner.storage_floor.extent = Some(extent);
            self.owner.storage_floor.limits = Some(sidecar_limits_v1(main.configured_limits()));
            let expected = self.owner.storage_floor.limits.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let typed = require_decode_shape_v1(main.configured_limits(), expected, &extent, actual)?;
            let native = extent.dominant_native_receiving_demand_v1()?;
            let semantic = extent.dominant_semantic_receiving_demand_v1()?;
            let variable = native.checked_add(semantic)?.checked_add(typed)?;
            let fixed = self.owner.storage_floor.fixed.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = self.main_complete_bound_v1()?.checked_add(fixed)?.checked_add(variable)?;
            self.owner.receiving.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .debit_storage_floor_representation_v1(complete).map_err(ResourceReservationErrorV1::from)?;
            Ok(variable)
        })();
        self.owner.storage_floor.prefix = Some(result);
        let Some(Ok(variable)) = self.owner.storage_floor.prefix.as_ref() else {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Prefix));
        };
        self.owner.storage_floor.prefix_operation = Some(ComponentReceivingOwnedOperationV1::preflight(*variable, *variable));
        if !self.owner.storage_floor.prefix_operation.as_mut().is_some_and(|phase| phase.consume_once().is_ok()) {
            return Err(self.close_storage_floor_v1(FloorFirstV1::PrefixOperation));
        }
        Ok(())
    }

    /// Enters the same sidecar's replay after its own captured-prefix payment.
    ///
    /// # Errors
    /// Retains another main, missing prefix consumption or repeated replay.
    pub(crate) fn enter_storage_floor_replay_once_v1(
        &mut self,
        main: &Journal,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || self.owner.storage_floor.replay.is_some() {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Reentry));
        }
        self.owner.storage_floor.replay = Some((|| {
            self.require_storage_floor_main_v1(main)?;
            if !matches!(self.owner.storage_floor.preparation, Some(Ok(())))
                || !self.owner.storage_floor.prefix_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if matches!(self.owner.storage_floor.replay, Some(Ok(()))) {
            Ok(())
        } else {
            Err(self.close_storage_floor_v1(FloorFirstV1::Replay))
        }
    }

    /// Binds the actual distinct sidecar opening before final native transfer.
    ///
    /// # Errors
    /// Retains incomplete replay, repeated take or a main/sidecar substitution.
    pub(crate) fn enter_storage_floor_take_once_v1(
        &mut self,
        main: &Journal,
        opening: &StorageNativeOpeningOwnerLinkV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || self.owner.storage_floor.take.is_some() {
            return Err(self.close_storage_floor_v1(FloorFirstV1::Reentry));
        }
        self.owner.storage_floor.take = Some((|| {
            self.require_storage_floor_main_v1(main)?;
            if !matches!(self.owner.storage_floor.replay, Some(Ok(())))
                || self.owner.storage_floor.opening.is_some() || opening.same_journal(main)
                || !self.owner.storage_floor.prefix_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.owner.storage_floor.opening = Some(opening.clone());
            Ok(())
        })());
        if matches!(self.owner.storage_floor.take, Some(Ok(()))) {
            Ok(())
        } else {
            Err(self.close_storage_floor_v1(FloorFirstV1::Take))
        }
    }

    /// Joins the actual taken sidecar before constructing its private typed store.
    ///
    /// # Errors
    /// Refuses another main/sidecar, incomplete phase, or any earlier failure.
    pub fn require_storage_floor_journal_v1(
        &self,
        main: &Journal,
        sidecar: &Journal,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        self.require_storage_floor_main_v1(main).map_err(|_| ControllerInitialBrokerSessionClosedV1)?;
        if !matches!(self.owner.storage_floor.take, Some(Ok(())))
            || !self.owner.storage_floor.opening.as_ref().is_some_and(|saved| saved.same_journal(sidecar))
            || !self.owner.storage_floor.prefix_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        Ok(())
    }
}

fn require_decode_shape_v1(
    main: JournalLimits,
    expected: JournalLimits,
    extent: &ProtectedJournalPreopenReplayExtentV1,
    actual: FloorSidecarDecodeShapeV1,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    if actual.main_limits != main || actual.sidecar_limits != expected
        || extent.limits != expected || actual.native_bytes != extent.native_bytes
    {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    ControllerInitialBrokerSessionCaptureShapeV1 {
        inline_bytes: actual.inline_bytes,
        heap_bytes: actual.heap_bytes,
        open_files: actual.open_files,
        metadata_cells: actual.named_entries,
    }.demand()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(main: JournalLimits, extent: &ProtectedJournalPreopenReplayExtentV1) -> FloorSidecarDecodeShapeV1 {
        FloorSidecarDecodeShapeV1 {
            main_limits: main,
            sidecar_limits: extent.limits,
            native_bytes: extent.native_bytes,
            inline_bytes: 128,
            heap_bytes: 256,
            open_files: 36,
            named_entries: 64,
        }
    }

    #[test]
    fn typed_floor_shape_cannot_substitute_main_limits_or_native_prefix() {
        let main = JournalLimits::default();
        let expected = sidecar_limits_v1(main).unwrap();
        let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(expected, 0).unwrap();
        let actual = shape(main, &extent);
        let accepted = require_decode_shape_v1(main, expected, &extent, actual).unwrap();
        assert_eq!(accepted.get(D::OpenFiles), 36);
        assert_eq!(accepted.get(D::MemoryBytes), 384);

        let mut wrong_main = actual;
        wrong_main.main_limits.maximum_transactions += 1;
        assert!(require_decode_shape_v1(main, expected, &extent, wrong_main).is_err());
        let mut wrong_prefix = actual;
        wrong_prefix.native_bytes = 1;
        assert!(require_decode_shape_v1(main, expected, &extent, wrong_prefix).is_err());
        let mut wrong_sidecar = actual;
        wrong_sidecar.sidecar_limits.maximum_records_per_transaction += 1;
        assert!(require_decode_shape_v1(main, expected, &extent, wrong_sidecar).is_err());
        let mut foreign_extent = extent;
        foreign_extent.limits.maximum_transactions += 1;
        assert!(require_decode_shape_v1(main, expected, &foreign_extent, actual).is_err());
    }

    #[test]
    fn typed_floor_actual_width_overflow_refuses_without_allocation() {
        let main = JournalLimits::default();
        let expected = sidecar_limits_v1(main).unwrap();
        let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(expected, 0).unwrap();
        let mut actual = shape(main, &extent);
        actual.inline_bytes = usize::MAX;
        actual.heap_bytes = 1;

        assert!(require_decode_shape_v1(main, expected, &extent, actual).is_err());
        assert!(InitialStorageFloorReceivingV1::receiving_temporary_demand_v1().is_ok());
    }

    #[test]
    fn distinct_sidecar_requires_the_actual_opening_arc_even_at_the_same_name() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session-floor.journal");
        let (old, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let old_link = old.held_session_owner_link_v1();
        drop(old);
        let (actual, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let actual_link = actual.held_session_owner_link_v1();

        assert!(!old_link.same_journal(&actual));
        assert!(actual_link.same_journal(&actual));
        assert!(!old_link.same_owner(&actual_link));
        // These ordinary native objects test identity mechanics only. No B
        // original, paid loan, protected sidecar or positive role is fabricated.
    }
}
