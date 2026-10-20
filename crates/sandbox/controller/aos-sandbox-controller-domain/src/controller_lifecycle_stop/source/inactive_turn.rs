//! Parks each ordinary Stop Source destination only after its funded entry.
//!
//! The six headers are resident from construction. Their full backing and
//! construction planes remain explicit in the startup and Stop suppliers.
//! Cleanup retains these headers without allocating or replaying the turns.

use super::*;

pub(in crate::controller_lifecycle_stop) struct StopSourceTurnSlotV4 {
    purpose: StopSourcePurposeV4,
    entered: bool,
    reentered: bool,
    entry: Option<Result<()>>,
    entry_original: bool,
    controller_entered: bool,
    controller_after: Option<Result<()>>,
    turn: Option<Box<StopSourceTurnOriginalV4>>,
}

impl StopSourceTurnSlotV4 {
    pub(in crate::controller_lifecycle_stop) fn new(purpose: StopSourcePurposeV4) -> Self {
        Self {
            purpose,
            entered: false,
            reentered: false,
            entry: None,
            entry_original: false,
            controller_entered: false,
            controller_after: None,
            turn: None,
        }
    }

    fn claim_once_v4(&mut self) -> Result<()> {
        if self.entered {
            self.reentered = true;
            if let Some(turn) = self.turn.as_mut() {
                turn.first.get_or_insert(First::Reentry);
            }
            return Err(CLOSED);
        }
        self.entered = true;
        Ok(())
    }

    pub(in crate::controller_lifecycle_stop) fn run_once_v4(
        &mut self,
        operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        self.claim_once_v4()?;
        self.entry = Some(begin_controller_turn_v4(
            bank,
            profile,
            controller_native,
            resident,
            controller,
            StopSourceEntryV5::Ordinary,
            &mut self.controller_entered,
        ));
        if !matches!(self.entry, Some(Ok(()))) {
            self.entry_original = controller_native.failure().is_some();
            // No Source/native/clock destination has entered. The independently
            // owed Controller after still runs even when entry refused.
            if self.controller_entered {
                self.controller_after = Some(finish_controller_turn_v4(
                    bank,
                    profile,
                    controller_native,
                    controller,
                ));
            }
            return Err(CLOSED);
        }

        // All constructors below are inert and infallible. The actual native
        // entry has already paid the resident six-turn construction/backing
        // supplier plus fixed_demand_v4. No entered turn is taken or moved to
        // change its layout.
        self.turn = Some(Box::new(StopSourceTurnOriginalV4::new(self.purpose)));
        let Some(turn) = self.turn.as_mut() else {
            std::process::abort();
        };
        turn.entered = true;
        turn.entry = Some(Ok(()));
        turn.controller_entered = self.controller_entered;
        self.controller_entered = false;

        let _ = turn.enter_source_after_controller_v4(
            operation,
            bank,
            profile,
            controller_native,
            resident,
            controller,
            source,
        );
        turn.prepare_metadata_once_v4(
            operation,
            bank,
            profile,
            controller_native,
            controller,
            source,
        );
        turn.finish_once_v4(bank, profile, controller_native, controller, source)
    }

    pub(in crate::controller_lifecycle_stop) fn resident_bytes_v4(&self) -> Result<usize> {
        self.turn.as_ref().ok_or(CLOSED)?.resident_bytes_v4()
    }

    pub(in crate::controller_lifecycle_stop) fn failure_v4<'owner>(
        &'owner self,
        controller: &'owner ControllerCreateProvisioningReceivingV1,
    ) -> Option<&'owner (dyn Error + 'static)> {
        if let Some(turn) = self.turn.as_ref() {
            return turn.failure_v4(controller);
        }
        if matches!(self.entry, Some(Err(_))) {
            return selected_error(self.entry_original, controller, &self.entry);
        }
        error(&self.controller_after).or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_slots_neither_construct_nor_forge_completed_turns() {
        let slot = StopSourceTurnSlotV4::new(StopSourcePurposeV4::Admission);

        assert!(!slot.entered);
        assert!(slot.turn.is_none());
        assert!(slot.entry.is_none());
        assert!(!slot.controller_entered);
        assert!(slot.controller_after.is_none());
        assert!(slot.resident_bytes_v4().is_err());
    }

    #[test]
    fn repeated_entry_preserves_the_unallocated_refusal_and_owed_after() {
        let mut slot = StopSourceTurnSlotV4::new(StopSourcePurposeV4::Admission);
        assert!(slot.claim_once_v4().is_ok());
        slot.entry = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        slot.controller_after = Some(Err(CLOSED));

        assert!(slot.claim_once_v4().is_err());

        assert!(slot.reentered);
        assert!(slot.turn.is_none());
        assert!(matches!(
            slot.entry,
            Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable))
        ));
        assert!(matches!(slot.controller_after, Some(Err(_))));
    }

    #[test]
    fn compiled_backing_keeps_all_six_construction_and_destination_planes() {
        let (bytes, metadata) =
            ControllerLifecycleStopOriginalV4::inactive_receiving_footprint_v4()
                .expect("compiled Source destinations fit the receiving supplier");

        assert_eq!(
            bytes,
            6 * (3 * std::mem::size_of::<StopSourceTurnOriginalV4>()
                + std::mem::size_of::<std::alloc::Layout>())
        );
        assert_eq!(metadata, 0);
        assert!(
            6 * std::mem::size_of::<StopSourceTurnSlotV4>()
                < std::mem::size_of::<StopSourceTurnOriginalV4>()
        );

        let retained_header = std::mem::size_of::<ControllerLifecycleStopOriginalV4>();
        let former_inline_header = retained_header
            - 6 * std::mem::size_of::<StopSourceTurnSlotV4>()
            + 6 * std::mem::size_of::<StopSourceTurnOriginalV4>();
        assert!(2 * retained_header + bytes >= 2 * former_inline_header);
    }
}
