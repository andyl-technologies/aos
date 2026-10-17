//! Publishes each actual physical callback group through its owning entered span.
//!
//! Group receipts precede span return; callback activation and independently
//! allocated optional children remain distinct unsupported cuts.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime::registration_groups::Kind;

impl LiveVcpuTimeCallbackRegistrar {
    #[cfg(not(test))]
    pub(super) fn register_physical_groups(
        &self,
        args: &PluginArgs,
        capabilities: &RequiredLiveVcpuTimeCapabilities,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        check_installing_callback_owner(state.as_ref())?;
        claim_live_callback_registration().map_err(live_callback_registration_error)?;
        macro_rules! install {
            ($kind:ident, $registrar:expr) => {
                state
                    .as_mut()
                    .install_registration_group(self.plugin_id, Kind::$kind, $registrar)
                    .map_err(live_callback_registration_error)?
            };
        }

        install!(IdleResume, |child| {
            (capabilities.register_vcpu_idle_resume)(
                Some(crucible_qemu_plugin_live_vcpu_idle_cb),
                Some(crucible_qemu_plugin_live_vcpu_resume_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(Control, |child| {
            (capabilities.register_control_boundary)(
                Some(crucible_qemu_plugin_live_control_boundary_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        state
            .as_mut()
            .verify_control_component()
            .map_err(|source| {
                live_callback_registration_error(LiveVcpuTimeCallbackError::ControlComponent {
                    source,
                })
            })?;
        install!(Dispatch, |child| {
            (capabilities.register_sim_shmem_dispatch)(
                Some(crucible_qemu_plugin_live_publish_icount_cb),
                Some(crucible_qemu_plugin_live_max_advance_icount_cb),
                Some(crucible_qemu_plugin_live_logical_ceiling_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(TimeAdvance, |child| {
            let status = (capabilities.register_time_advance_cb)(
                Some(crucible_qemu_plugin_live_time_advance_completion_cb),
                std::ptr::from_mut(child).cast(),
            );
            if status == 0 {
                Ok(())
            } else {
                Err(LiveVcpuTimeCallbackError::TimeAdvanceCompletionRegistrationRejected { status })
            }
        });
        install!(NetTx, |child| {
            (capabilities.register_net_tx)(
                Some(crucible_qemu_plugin_live_network_tx_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(Block, |child| {
            (capabilities.register_block)(
                Some(devices::crucible_qemu_plugin_live_block_submit_cb),
                Some(devices::crucible_qemu_plugin_live_block_poll_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(BlockEvent, |child| {
            (capabilities.register_block_event)(
                Some(devices::crucible_qemu_plugin_live_block_event_poll_cb),
                Some(devices::crucible_qemu_plugin_live_block_event_commit_cb),
                Some(devices::crucible_qemu_plugin_live_block_transport_save_cb),
                Some(devices::crucible_qemu_plugin_live_block_transport_restore_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(BlockWait, |child| {
            (capabilities.register_block_wait)(
                Some(crucible_qemu_plugin_live_block_wait_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(NineP, |child| {
            (capabilities.register_ninep)(
                Some(devices::crucible_qemu_plugin_live_ninep_burst_start_cb),
                Some(devices::crucible_qemu_plugin_live_ninep_submit_cb),
                Some(devices::crucible_qemu_plugin_live_ninep_poll_cb),
                Some(devices::crucible_qemu_plugin_live_ninep_burst_done_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        install!(Accelerator, |child| {
            (capabilities.register_accelerator)(
                Some(devices::crucible_qemu_plugin_live_accelerator_submit_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_poll_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_wait_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_restore_begin_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_restore_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_restore_commit_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_restore_abort_cb),
                Some(devices::crucible_qemu_plugin_live_accelerator_cancel_cb),
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        // Independent optional children cannot borrow this complete group's
        // credit or primary userdata. Refuse before their Box/global effects.
        if args.whitebox().is_on() {
            return Err(live_callback_registration_error(
                LiveVcpuTimeCallbackError::CallbackRegistrationGroup {
                    source: crate::StartupSourceError::Ownership {
                        reason: "whitebox callback child and complete registration owner are not issued",
                    },
                },
            ));
        }
        install!(VcpuInit, |child| {
            (capabilities.register_vcpu_init)(
                self.plugin_id,
                crucible_qemu_plugin_live_vcpu_init_cb,
                std::ptr::from_mut(child).cast(),
            );
            Ok(())
        });
        // Native's physical finish keeps its members inactive. Actual CPU use,
        // action Original and callback activation must join before startup can
        // publish a success proof; complete receipts alone cannot supply them.
        Err(live_callback_registration_error(
            crate::runtime::callback_child::CallbackChild::activation_unavailable(),
        ))
    }
}
