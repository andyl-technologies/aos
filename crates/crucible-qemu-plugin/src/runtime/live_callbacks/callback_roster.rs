//! Exact function and userdata tuples retained at actual registration seams.
//!
//! Native source must compare these process-private observations with its own
//! tables. The original runtime owns the allocations and callback code; this
//! record grants no callback, FIFO, continuation, capture or device authority.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::c_void;
use std::sync::OnceLock;

use super::LiveVcpuTimeCallbackError;

/// Copies one native-private callback identity without dereferencing its addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(in crate::runtime) struct CallbackTuple {
    /// Selects the closed source callback field independently of a family mask.
    pub kind: u32,
    /// Remains zero in version one.
    pub reserved: u32,
    /// Retains the literal function supplied to the actual native registrar.
    pub function: usize,
    /// Retains the literal userdata supplied to that registrar.
    pub userdata: usize,
}

impl CallbackTuple {
    fn new(kind: u32, function: usize, userdata: *mut c_void) -> Self {
        Self {
            kind,
            reserved: 0,
            function,
            userdata: userdata as usize,
        }
    }
}

/// Keeps the first live and hot-fork registrations in their original pinned runtime.
#[derive(Default)]
pub(in crate::runtime) struct RetainedCallbackRoster {
    live: OnceLock<[CallbackTuple; 28]>,
    hot_fork: OnceLock<[CallbackTuple; 2]>,
    complete: OnceLock<[CallbackTuple; 30]>,
}

impl RetainedCallbackRoster {
    /// Retains the selected init function and all actual live callback tuples.
    ///
    /// # Errors
    /// Rejects changed original functions or userdata while preserving the first tuples.
    pub(in crate::runtime) fn retain_live(
        &self,
        vcpu_init: crate::QemuVcpuSimpleCbFn,
        userdata: *mut c_void,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let original = live_rows(vcpu_init, userdata);
        retain_original(&self.live, original)?;
        self.complete_original().map(|_| ())
    }

    /// Retains hot-fork tuples after both actual native registrations succeed.
    ///
    /// # Errors
    /// Rejects changed original runtime userdata while preserving the first tuples.
    pub(in crate::runtime) fn retain_hot_fork(
        &self,
        userdata: *mut c_void,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let original = [
            CallbackTuple::new(
                29,
                super::super::crucible_qemu_plugin_hot_fork_barrier as *const () as usize,
                userdata,
            ),
            CallbackTuple::new(
                30,
                super::super::crucible_qemu_plugin_hot_fork_child_runtime as *const () as usize,
                userdata,
            ),
        ];
        retain_original(&self.hot_fork, original)?;
        self.complete_original().map(|_| ())
    }

    /// Borrows the stable complete roster only after both original seams returned.
    ///
    /// Native source must independently compare these tuples with its actual
    /// tables. Missing registrations stay absent; an array of requested kinds
    /// cannot stand in for successful native registration.
    ///
    /// # Errors
    /// Rejects a changed original complete image without replacing its first array.
    pub(in crate::runtime) fn complete_original(
        &self,
    ) -> Result<Option<&[CallbackTuple; 30]>, LiveVcpuTimeCallbackError> {
        let (Some(live), Some(hot_fork)) = (self.live.get(), self.hot_fork.get()) else {
            return Ok(None);
        };
        let original = std::array::from_fn(|index| {
            if index < live.len() {
                live[index]
            } else {
                hot_fork[index - live.len()]
            }
        });

        retain_original(&self.complete, original)?;
        Ok(self.complete.get())
    }
}

fn retain_original<const N: usize>(
    retained: &OnceLock<[CallbackTuple; N]>,
    original: [CallbackTuple; N],
) -> Result<(), LiveVcpuTimeCallbackError> {
    if original
        .iter()
        .any(|row| row.function == 0 || row.userdata == 0)
    {
        return Err(LiveVcpuTimeCallbackError::CallbackRosterChanged);
    }

    // Actual installation serializes registration. A conflicting observation
    // preserves the first tuple instead of rewriting its original identity.
    let _already_retained = retained.set(original);
    if retained.get() != Some(&original) {
        return Err(LiveVcpuTimeCallbackError::CallbackRosterChanged);
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Original tuple tests intentionally fail on changed registration identities.
// crucible-lint: allow rust-allow -- These test-only unwraps expose missing retained original tuples.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "callback_roster_tests.rs"]
mod tests;

fn live_rows(vcpu_init: crate::QemuVcpuSimpleCbFn, userdata: *mut c_void) -> [CallbackTuple; 28] {
    [
        CallbackTuple::new(1, vcpu_init as *const () as usize, userdata),
        CallbackTuple::new(
            2,
            super::crucible_qemu_plugin_live_vcpu_idle_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            3,
            super::crucible_qemu_plugin_live_vcpu_resume_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            4,
            super::crucible_qemu_plugin_live_control_boundary_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            5,
            super::crucible_qemu_plugin_live_publish_icount_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            6,
            super::crucible_qemu_plugin_live_max_advance_icount_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            7,
            super::crucible_qemu_plugin_live_logical_ceiling_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            8,
            super::crucible_qemu_plugin_live_time_advance_completion_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            9,
            super::crucible_qemu_plugin_live_network_tx_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            10,
            super::devices::crucible_qemu_plugin_live_block_submit_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            11,
            super::devices::crucible_qemu_plugin_live_block_poll_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            12,
            super::devices::crucible_qemu_plugin_live_block_event_poll_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            13,
            super::devices::crucible_qemu_plugin_live_block_event_commit_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            14,
            super::devices::crucible_qemu_plugin_live_block_transport_save_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            15,
            super::devices::crucible_qemu_plugin_live_block_transport_restore_cb as *const ()
                as usize,
            userdata,
        ),
        CallbackTuple::new(
            16,
            super::crucible_qemu_plugin_live_block_wait_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            17,
            super::devices::crucible_qemu_plugin_live_ninep_burst_start_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            18,
            super::devices::crucible_qemu_plugin_live_ninep_submit_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            19,
            super::devices::crucible_qemu_plugin_live_ninep_poll_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            20,
            super::devices::crucible_qemu_plugin_live_ninep_burst_done_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            21,
            super::devices::crucible_qemu_plugin_live_accelerator_submit_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            22,
            super::devices::crucible_qemu_plugin_live_accelerator_poll_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            23,
            super::devices::crucible_qemu_plugin_live_accelerator_wait_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            24,
            super::devices::crucible_qemu_plugin_live_accelerator_restore_begin_cb as *const ()
                as usize,
            userdata,
        ),
        CallbackTuple::new(
            25,
            super::devices::crucible_qemu_plugin_live_accelerator_restore_cb as *const () as usize,
            userdata,
        ),
        CallbackTuple::new(
            26,
            super::devices::crucible_qemu_plugin_live_accelerator_restore_commit_cb as *const ()
                as usize,
            userdata,
        ),
        CallbackTuple::new(
            27,
            super::devices::crucible_qemu_plugin_live_accelerator_restore_abort_cb as *const ()
                as usize,
            userdata,
        ),
        CallbackTuple::new(
            28,
            super::devices::crucible_qemu_plugin_live_accelerator_cancel_cb as *const () as usize,
            userdata,
        ),
    ]
}
