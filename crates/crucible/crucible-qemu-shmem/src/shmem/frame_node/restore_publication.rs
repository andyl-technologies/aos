//! A stopped restore's native-readable fields precede both original requests.
//!
//! The common host claim excludes speculative control writers. This local
//! publication does not prove that QEMU loaded a checkpoint or stopped: the
//! caller retains those owners, and the native consumer must authenticate them.

use super::runtime::ControlBoundaryPublicationClaim;
use super::*;

impl NodeSlot {
    /// Publishes one stopped restore with prepared fields before either request.
    ///
    /// The caller holds the executor stopped after a successful authenticated
    /// load. All fallible body checks and storage reservations precede this
    /// call. `fields` receives the actual proposed control request, physical
    /// restore generation and original even advance while the common claim excludes every other host
    /// request publisher. Neither value supplies a native phase owner.
    ///
    /// The fields effect retains local custody before claim release and wake. A wake failure
    /// preserves both requests and local custody. Native readers must refuse a
    /// held claim and validate the exact full pair after release.
    ///
    /// # Errors
    ///
    /// Refuses a busy publisher, pending restore/control request, unexpected
    /// control transition, or failed wake. Refusal before `fields` changes no
    /// body or request. A competing native transition after `fields` leaves an
    /// unaccepted pair that must fail closed in the native reader.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic. The common claim is released on unwind;
    /// a fields panic publishes neither request. Prepared storage can remain
    /// committed and must not be mistaken for an accepted restore.
    pub fn request_logical_time_restore_with_prepared_fields(
        &self,
        target_icount: u64,
        fault_command_frontier: u64,
        expected_ceiling: u64,
        fields: impl FnOnce(PreparedControlBoundaryRequest, u32, SchedulerAdvanceSequence),
    ) -> Result<(u32, u32), NodeSlotError> {
        self.request_logical_time_restore_with_fields_and_wake(
            target_icount,
            fault_command_frontier,
            expected_ceiling,
            fields,
            || self.wake_after_signal_increment(),
        )
    }

    pub(super) fn request_logical_time_restore_with_fields_and_wake(
        &self,
        target_icount: u64,
        fault_command_frontier: u64,
        expected_ceiling: u64,
        fields: impl FnOnce(PreparedControlBoundaryRequest, u32, SchedulerAdvanceSequence),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<(u32, u32), NodeSlotError> {
        self.control_boundary_publication_claim
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NodeSlotError::ControlBoundaryPublicationBusy)?;
        let publication = ControlBoundaryPublicationClaim(&self.control_boundary_publication_claim);
        let restore_request = self.logical_time_restore_request.load(Ordering::Acquire);
        let restore_ack = self.logical_time_restore_ack.load(Ordering::Acquire);
        if restore_request != restore_ack {
            return Err(NodeSlotError::LogicalTimeRestoreAlreadyPending {
                request: restore_request,
                ack: restore_ack,
            });
        }
        let observed = self.control_boundary_ack.load(Ordering::Acquire);
        if observed & 1 == 0 {
            return Err(NodeSlotError::RestoreControlBoundaryAlreadyPending { request: observed });
        }
        let request = observed.wrapping_add(1);
        let generation = match restore_request.wrapping_add(1) {
            0 => 1,
            generation => generation,
        };

        let (ceiling, stop, _) = self
            .try_load_scheduler_advance_raw()
            .ok_or(NodeSlotError::ControlBoundaryPublicationBusy)?;
        if stop != ADVANCE_STOP_CONDITION_CEILING || ceiling != expected_ceiling {
            return Err(NodeSlotError::RestoreCeilingChanged {
                expected: expected_ceiling,
                observed: ceiling,
            });
        }
        // The stopped restore keeps the original external ceiling, which may
        // exceed its logical target. AUTH obtains this exact writer receipt;
        // neither a later getter nor target equality substitutes for it.
        self.publish_scheduler_advance_fields_with_effect(
            ceiling,
            AdvanceStopCondition::Ceiling,
            |advance| fields(PreparedControlBoundaryRequest(request), generation, advance),
        );
        self.control_boundary_fault_command_frontier
            .store(fault_command_frontier, Ordering::Relaxed);
        self.control_boundary_capture_request
            .store(0, Ordering::Relaxed);
        self.logical_time_restore_target
            .store(target_icount, Ordering::Relaxed);
        self.logical_time_restore_request
            .store(generation, Ordering::Release);
        self.control_boundary_ack
            .compare_exchange(observed, request, Ordering::Release, Ordering::Acquire)
            .map_err(|observed| NodeSlotError::ControlBoundaryPublicationRaced {
                expected: request,
                observed,
            })?;

        drop(publication);
        wake().map_err(|source| NodeSlotError::FutexWake { source })?;
        Ok((generation, request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn restore_fields_precede_both_requests_and_claim_closes_before_wake()
    -> Result<(), NodeSlotError> {
        for refuse_wake in [false, true] {
            let slot = NodeSlot::new(KIND_VM);
            slot.arm_external_state_restore_ceiling(200)?;
            let custody = Cell::new(None);
            let source = FutexError::Syscall {
                operation: "modeled restore wake refusal",
                errno: 22,
            };
            let result = slot.request_logical_time_restore_with_fields_and_wake(
                100,
                7,
                200,
                |request, generation, advance| {
                    assert_eq!(slot.control_boundary_token(), 1);
                    assert!(slot.pending_logical_time_restore().is_none());
                    assert!(slot.try_snapshot().is_none());
                    assert_eq!(advance.get(), 4);
                    custody.set(Some((generation, request.get(), advance.get())));
                },
                || {
                    let live = slot
                        .try_snapshot()
                        .unwrap_or_else(|| panic!("claim held at wake"));
                    assert_eq!(
                        custody.get(),
                        Some((1, 2, live.advance_publication_sequence))
                    );
                    assert_eq!(live.logical_time_restore_request, 1);
                    assert_eq!(live.logical_time_restore_target, 100);
                    assert_eq!(live.control_boundary_ack, 2);
                    assert_eq!(live.control_boundary_fault_command_frontier, 7);
                    assert_eq!(live.max_advance_icount, 200);
                    if refuse_wake {
                        Err(source.clone())
                    } else {
                        slot.wake_after_signal_increment()
                    }
                },
            );
            if refuse_wake {
                assert!(
                    matches!(result, Err(NodeSlotError::FutexWake { source: actual }) if actual == source)
                );
            } else {
                assert_eq!(result?, (1, 2));
            }
            assert_eq!(custody.get(), Some((1, 2, 4)));
            assert_eq!(
                slot.pending_logical_time_restore().map(|r| r.generation),
                Some(1)
            );
        }
        Ok(())
    }

    #[test]
    fn restore_claim_excludes_other_requests_and_unwind_releases_without_publishing() {
        let slot = NodeSlot::new(KIND_VM);
        let result = std::panic::catch_unwind(|| {
            slot.request_logical_time_restore_with_prepared_fields(0, 0, 0, |_, _, _| {
                assert!(matches!(
                    slot.request_control_boundary(0, None),
                    Err(NodeSlotError::ControlBoundaryPublicationBusy)
                ));
                panic!("modeled prepared-field failure");
            })
        });
        assert!(result.is_err());
        assert!(slot.try_snapshot().is_some());
        assert!(slot.pending_logical_time_restore().is_none());
        assert_eq!(slot.control_boundary_token(), 1);
        assert_eq!(slot.request_control_boundary(0, None).ok(), Some(2));
    }

    #[test]
    fn pending_control_or_changed_ceiling_refuses_before_restore_fields()
    -> Result<(), NodeSlotError> {
        let slot = NodeSlot::new(KIND_VM);
        let fields = Cell::new(false);
        assert!(matches!(
            slot.request_logical_time_restore_with_prepared_fields(0, 0, 1, |_, _, _| fields
                .set(true)),
            Err(NodeSlotError::RestoreCeilingChanged { .. })
        ));
        assert!(!fields.get());
        slot.request_control_boundary(0, None)?;
        assert!(matches!(
            slot.request_logical_time_restore_with_prepared_fields(0, 0, 0, |_, _, _| fields
                .set(true)),
            Err(NodeSlotError::RestoreControlBoundaryAlreadyPending { .. })
        ));
        assert!(!fields.get());
        assert!(slot.pending_logical_time_restore().is_none());
        Ok(())
    }
}
