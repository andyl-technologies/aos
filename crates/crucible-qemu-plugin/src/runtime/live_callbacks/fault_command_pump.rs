//! Exclusive fault-command pumping and control-boundary settlement.
//!
//! Live callbacks own the fault-command bridge through one pump flag. A nested
//! QEMU ceiling query made while a mutation is applied observes the flag and
//! reuses already published scheduling state instead of dequeuing again.

use super::*;

/// Releases exclusive fault-command pump ownership on every return path.
struct FaultCommandPumpGuard<'a>(&'a AtomicBool);

impl Drop for FaultCommandPumpGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl LiveVcpuTimeCallbackState {
    pub(super) fn pump_fault_commands(
        &self,
        raw_icount: u64,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        if self
            .fault_command_pump_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Applying a QEMU mutation may synchronously make QEMU query the
            // simulator ceiling. The outer pump still owns the command and
            // result transports, so the nested query must use the already
            // published scheduling state without trying to dequeue again.
            return Ok(true);
        }
        let _pump_active = FaultCommandPumpGuard(&self.fault_command_pump_active);
        let mut bridge = match self.fault_commands.try_lock() {
            Ok(bridge) => bridge,
            Err(TryLockError::WouldBlock) => {
                return Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed);
            }
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        let bridge = &mut *bridge;
        let drained = bridge
            .pump_with_offset_reader(raw_icount, &|| self.fault_offset_for_raw(raw_icount))
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
        self.logical_icount_for_raw(raw_icount)?;
        Ok(drained)
    }

    pub(super) fn settle_fault_commands_at_control_boundary(
        &self,
        raw_icount: u64,
        control_request: u32,
        fault_command_frontier: u64,
        settlement: Option<control_callback_witness::SettlementContext>,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        if self
            .fault_command_pump_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.control_callback_witness.retain_settlement(
                settlement,
                control_callback_witness::SettlementReason::PumpActive,
            );
            return Ok(false);
        }
        let _pump_active = FaultCommandPumpGuard(&self.fault_command_pump_active);
        let mut bridge = match self.fault_commands.try_lock() {
            Ok(bridge) => bridge,
            Err(TryLockError::WouldBlock) => {
                return Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed);
            }
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        let bridge = &mut *bridge;

        if !bridge
            .pump_through_frontier_with_offset_reader(raw_icount, fault_command_frontier, &|| {
                self.fault_offset_for_raw(raw_icount)
            })
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?
        {
            self.control_callback_witness.retain_settlement(
                settlement,
                control_callback_witness::SettlementReason::FrontierPending,
            );
            return Ok(false);
        }
        if self
            .control_boundary_dispatch_generation
            .load(Ordering::Acquire)
            != control_request
        {
            bridge
                .dispatch_node_boundary(raw_icount)
                .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?;
            self.control_boundary_dispatch_generation
                .store(control_request, Ordering::Release);
        }
        self.logical_icount_for_raw(raw_icount)?;
        let refreshed_offset = self.logical_icount_offset.load(Ordering::Acquire);
        if !bridge
            .drain_publications(refreshed_offset)
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })?
        {
            self.control_callback_witness.retain_settlement(
                settlement,
                control_callback_witness::SettlementReason::PublicationBackpressure,
            );
            return Ok(false);
        }
        let settled = bridge.command_frontier_is_settled(fault_command_frontier);
        if !settled {
            self.control_callback_witness.retain_settlement(
                settlement,
                control_callback_witness::SettlementReason::FrontierUnsettled,
            );
        }
        if settled {
            self.control_callback_witness.retain_settlement(
                settlement,
                control_callback_witness::SettlementReason::Settled,
            );
        }
        Ok(settled)
    }

    pub(super) fn initialize_fault_commands(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut bridge = match self.fault_commands.try_lock() {
            Ok(bridge) => bridge,
            Err(TryLockError::WouldBlock) => {
                return Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed);
            }
            Err(TryLockError::Poisoned(_error)) => {
                return Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned);
            }
        };
        let bridge = &mut *bridge;
        bridge
            .initialize()
            .map_err(|source| LiveVcpuTimeCallbackError::FaultCommands { source })
    }

    /// Processes setup-time capability admission before the ready ACK.
    pub(crate) fn admit_fault_capabilities(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        self.initialize_fault_commands()?;
        self.pump_fault_commands((self.icount_raw)()).map(|_| ())
    }
}
