//! Retains device workspace ownership across the private fork transition.
//!
//! Early disarm touches only the parent's directly held owner. Fresh-child
//! reconstruction remains closed until its separate native startup Source is
//! issued; neither the copied parent Source nor pager operations can supply it.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;

impl OwnedCallbackRuntimeState {
    pub(super) fn child_startup_source_unavailable() -> HotForkChildRuntimeError {
        HotForkChildRuntimeError::Workspace {
            source: crate::DeviceDigestWorkspaceError::StartupSource {
                source: crate::StartupSourceError::Ownership {
                    reason: "separately issued child startup Source is unavailable",
                },
            },
        }
    }

    pub(super) fn disarm_child_device_workspace(
        &mut self,
        plan: &crate::QemuPluginHotForkChildPlan,
    ) -> Result<crate::QemuPluginHotForkChildStatus, i32> {
        if plan.schema_version != crate::QEMU_PLUGIN_HOT_FORK_CHILD_PLAN_VERSION
            || plan.struct_size as usize != std::mem::size_of::<crate::QemuPluginHotForkChildPlan>()
            || !hot_fork_child_process_generation_matches(plan, self.process_generation)
            || self.owner_process == std::process::id()
            || self.workspace_disarmed
        {
            return Err(-libc::EPROTO);
        }
        // Source's VMA is DONTFORK. Disarm only the child's copied local
        // metadata before any inherited lock, callback or descriptor reuse.
        self.workspace_mapping
            .disarm_inherited()
            .map_err(|_| -libc::EIO)?;
        if let Some(live) = self.live_vcpu_time.as_mut()
            && live
                .as_mut()
                .get_mut()
                .disarm_fingerprint_workspace()
                .is_err()
        {
            return Err(-libc::EIO);
        }
        self.workspace_disarmed = true;
        // This path must not query inherited worker/registry Mutex state. It
        // precedes child contracts, descriptor transactions and reconstruction.
        let disarmed = crate::QemuPluginHotForkChildStatus {
            schema_version: crate::QEMU_PLUGIN_HOT_FORK_CHILD_STATUS_VERSION,
            struct_size: std::mem::size_of::<crate::QemuPluginHotForkChildStatus>() as u32,
            flags: crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_WORKSPACE_DISARMED,
            phase: u32::from(CHILD_RUNTIME_TEMPLATE),
            parent_process_generation: plan.parent_process_generation,
            child_process_generation: plan.child_process_generation,
            template_generation: plan.template_generation,
            private_ring_generation: 0,
            plugin_endpoint_generation: 0,
            plugin_barrier_generation: plan.plugin_barrier_generation,
            control_socket_cookie: 0,
            wake_eventfd_id: 0,
            source_mapping_start: 0,
            source_mapping_length: 0,
            source_mapping_offset: 0,
            worker_mask: 0,
            parked_worker_mask: 0,
            pending_worker_mask: 0,
            worker_operations_in_flight: 0,
            account_generation: 0,
            workspace_generation: 0,
            workspace_device: 0,
            workspace_inode: 0,
            workspace_length: 0,
            workspace_fd: -1,
            workspace_reserved: 0,
        };

        Ok(disarmed)
    }
}

pub(super) fn child_workspace_matches(
    plan: &crate::QemuPluginHotForkChildPlan,
    state: &OwnedCallbackRuntimeState,
) -> bool {
    if plan.workspace_reserved != 0 {
        return false;
    }
    if state
        .live_vcpu_time
        .as_ref()
        .is_some_and(|live| live.fingerprint_enabled())
    {
        plan.account_generation != 0
            && plan.workspace_generation != 0
            && plan.workspace_length == crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES
            && plan.workspace_fd >= 0
            && plan.workspace_fd != plan.control_fd
            && plan.workspace_fd != plan.wake_fd
            && plan.workspace_fd != plan.private_ring_fd
    } else {
        plan.account_generation == 0
            && plan.workspace_generation == 0
            && plan.workspace_device == 0
            && plan.workspace_inode == 0
            && plan.workspace_length == 0
            && plan.workspace_fd == -1
    }
}
