//! QEMU commanded-preemption capability wrapper.

use super::*;

impl PluginPreemptionInjector {
    /// Requires the patched QEMU preemption-injection export.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionError::CapabilityUnavailable`] when the
    /// `qemu_plugin_inject_preemption` export was not resolved.
    pub fn require(
        inject_preemption: Option<QemuInjectPreemptionFn>,
    ) -> Result<Self, PreemptionError> {
        let Some(inject_preemption) = inject_preemption else {
            return Err(PreemptionError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL,
            });
        };
        Ok(Self { inject_preemption })
    }

    /// Applies a scheduler-commanded preemption exactly at the requested icount.
    ///
    /// The command is rejected before calling QEMU if it is outside `window`, if
    /// its vCPU operands are malformed, or if a vCPU-switch command does not
    /// match the current round-robin cursor. The round-robin cursor is advanced
    /// only after QEMU accepts a vCPU-switch command.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionError`] when validation fails, when QEMU rejects the
    /// command, or when the local round-robin cursor rejects a commanded switch.
    pub fn apply_decision(
        &self,
        decision: PluginPreemptionDecision,
        window: PreemptionWindow,
        run_state: &mut RoundRobinRunState,
    ) -> Result<PluginPreemptionApplication, PreemptionError> {
        let command = decision.to_qemu_command(window, run_state.vcpu_count())?;
        if let PluginPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } = decision.kind() {
            run_state
                .validate_commanded_switch(from_vcpu, to_vcpu)
                .map_err(PreemptionError::RoundRobin)?;
        }

        let status = (self.inject_preemption)(
            command.at_icount,
            command.deadline_icount,
            command.ceiling_icount,
            command.raw_kind,
            command.arg0,
            command.arg1,
            command.arg2,
        );
        if status != 0 {
            return Err(PreemptionError::CapabilityRejected {
                at_icount: command.at_icount,
                raw_kind: command.raw_kind,
                status,
            });
        }

        let round_robin_turn = match decision.kind() {
            PluginPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                Some(run_state.force_commanded_switch(from_vcpu, to_vcpu)?)
            }
            PluginPreemptionKind::InterruptAt { .. } => None,
        };

        Ok(PluginPreemptionApplication {
            decision,
            command,
            round_robin_turn,
        })
    }

    /// Enqueues a scheduler-commanded preemption in QEMU's live RR loop.
    ///
    /// Unlike [`Self::apply_decision`], this method does not mutate a
    /// plugin-local round-robin cursor. Production commands may target a future
    /// turn, so patched QEMU remains the authoritative cursor and validates the
    /// source vCPU when the command becomes due.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionError`] when the command or window is invalid for
    /// `vcpu_count`, or when QEMU rejects the command.
    pub fn enqueue_decision(
        &self,
        decision: PluginPreemptionDecision,
        window: PreemptionWindow,
        vcpu_count: u32,
    ) -> Result<QemuPreemptionCommand, PreemptionError> {
        let command = decision.to_qemu_command(window, vcpu_count)?;
        let status = (self.inject_preemption)(
            command.at_icount,
            command.deadline_icount,
            command.ceiling_icount,
            command.raw_kind,
            command.arg0,
            command.arg1,
            command.arg2,
        );
        if status != 0 {
            return Err(PreemptionError::CapabilityRejected {
                at_icount: command.at_icount,
                raw_kind: command.raw_kind,
                status,
            });
        }
        Ok(command)
    }
}
