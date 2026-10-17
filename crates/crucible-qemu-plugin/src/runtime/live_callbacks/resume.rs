//! Original vCPU resume, pending-reply delivery and halt-tracking order.
//!
//! The optional pending-selectable witness reports original dispositions only;
//! it neither owns reply writes nor changes control or idle-return predicates.

use std::sync::atomic::Ordering;

use crate::PluginShmemOrdering;

use super::super::live_whitebox::{
    deliver_selectable_reply_on_vcpu_resume, observe_selectable_resume,
    selectable_resume_witness::Phase as SelectableResumePhase,
};
use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};

impl LiveVcpuTimeCallbackState {
    /// Delivers a pending reply before the original control/halt resume path.
    ///
    /// # Errors
    /// Returns the original initialization, pause, idle, reply, halt-tracking or
    /// progress-publication failure without altering its ordering.
    pub(super) fn on_vcpu_resume(
        &self,
        vcpu_index: u32,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.require_initialized_vcpu(vcpu_index)?;
        observe_selectable_resume(
            SelectableResumePhase::RustEntry,
            vcpu_index,
            Some(raw_icount),
            None,
        );
        if self.publish_pause_for_boundary(raw_icount, true, false, None, "vcpu-resume")? {
            observe_selectable_resume(
                SelectableResumePhase::PauseReturn,
                vcpu_index,
                Some(raw_icount),
                None,
            );
            return Ok(());
        }
        if self.preserve_network_output_stop(raw_icount, "vcpu-resume")? {
            observe_selectable_resume(
                SelectableResumePhase::NetworkReturn,
                vcpu_index,
                Some(raw_icount),
                None,
            );
            return Ok(());
        }
        let control_boundary_requested =
            PluginShmemOrdering::control_boundary_is_requested(self.slot.get());
        if self.idle_advance_is_pending() {
            if control_boundary_requested {
                observe_selectable_resume(
                    SelectableResumePhase::IdleControlReturn,
                    vcpu_index,
                    Some(raw_icount),
                    None,
                );
                return Ok(());
            }
            observe_selectable_resume(
                SelectableResumePhase::IdleError,
                vcpu_index,
                Some(raw_icount),
                None,
            );
            return Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending);
        }
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        observe_selectable_resume(
            SelectableResumePhase::ReplyEnter,
            vcpu_index,
            Some(raw_icount),
            Some(current_icount),
        );
        deliver_selectable_reply_on_vcpu_resume(vcpu_index, current_icount).map_err(|source| {
            LiveVcpuTimeCallbackError::WhiteboxCallback {
                message: source.to_string(),
            }
        })?;
        observe_selectable_resume(
            SelectableResumePhase::ReplyReturn,
            vcpu_index,
            Some(raw_icount),
            Some(current_icount),
        );
        if control_boundary_requested {
            // The exact resume callback remains the sole authority for a
            // host-selected guest-memory write. Settle that reply before the
            // control boundary, but retain halt tracking and the published
            // future idle deadline until the control callback acknowledges it.
            observe_selectable_resume(
                SelectableResumePhase::ControlReturn,
                vcpu_index,
                Some(raw_icount),
                Some(current_icount),
            );
            return Ok(());
        }
        let was_halted = {
            let mut halted_vcpus = self.try_halted_vcpus()?;
            let was_halted = halted_vcpus
                .is_halted(vcpu_index)
                .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?;
            halted_vcpus
                .mark_running(vcpu_index)
                .map_err(|source| LiveVcpuTimeCallbackError::VcpuHaltTracking { source })?;
            was_halted
        };
        if !was_halted {
            observe_selectable_resume(
                SelectableResumePhase::AlreadyRunningReturn,
                vcpu_index,
                Some(raw_icount),
                Some(current_icount),
            );
            return Ok(());
        }
        self.all_halted_idle_handled.store(false, Ordering::Release);
        // A resume from the all-halted idle path precedes RR-owner selection,
        // so cross-vCPU capture is no safer here than in the matching idle
        // callback. Publish progress now and let the host's BQL-held terminal
        // boundary own the fingerprint.
        self.publish_current_icount_for_boundary(raw_icount, true, "vcpu-resume")?;
        PluginShmemOrdering::mark_running_after_wake(self.slot.get());
        observe_selectable_resume(
            SelectableResumePhase::RunningReturn,
            vcpu_index,
            Some(raw_icount),
            Some(current_icount),
        );
        Ok(())
    }
}
