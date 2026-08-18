//! Capability-preflight regression cases for live callback registration.

use super::*;

extern "C" fn test_request_shutdown(_failure: std::os::raw::c_int) {}

#[test]
fn live_registrar_preflight_names_each_missing_capability() {
    let execution_model =
        QemuPluginExecutionModel::validate(2, crate::QemuTcgThreading::SingleThreadedRoundRobin)
            .unwrap_or_else(|error| panic!("test model should validate: {error}"));
    let args = PluginArgs::parse("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0")
        .unwrap_or_else(|error| panic!("test arguments should parse: {error}"));
    let missing_preemption = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        crate::QemuPluginTargetArchitecture::X86_64,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            force_vcpu_exit: test_force_vcpu_exit,
            request_vmstop: test_request_vmstop,
            inject_preemption: None,
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_control_boundary: Some(test_register_control_boundary),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_event: Some(test_register_block_event),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
            register_accelerator: Some(test_register_accelerator),
            fault_commands: crate::fault_command::QemuFaultCommandApis::test_stub(),
            request_shutdown: test_request_shutdown,
        },
    );
    assert!(matches!(
        missing_preemption.preflight(&args),
        Err(OwnedCallbackRegistrationError::LiveVcpuTime {
            source: LiveVcpuTimeCallbackError::Preemption {
                source: PreemptionError::CapabilityUnavailable {
                    symbol,
                },
            },
        }) if symbol == crate::QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL
    ));

    let missing_init = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        crate::QemuPluginTargetArchitecture::X86_64,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            force_vcpu_exit: test_force_vcpu_exit,
            request_vmstop: test_request_vmstop,
            inject_preemption: Some(super::super::test_support::accept_preemption),
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: None,
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_control_boundary: Some(test_register_control_boundary),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_event: Some(test_register_block_event),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
            register_accelerator: Some(test_register_accelerator),
            fault_commands: crate::fault_command::QemuFaultCommandApis::test_stub(),
            request_shutdown: test_request_shutdown,
        },
    );
    assert!(matches!(
        missing_init.preflight(&args),
        Err(OwnedCallbackRegistrationError::LiveVcpuTime {
            source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL,
            }
        })
    ));

    let mut missing_control_capabilities = missing_init.capabilities;
    missing_control_capabilities.register_vcpu_init = Some(test_register_vcpu_init);
    missing_control_capabilities.register_control_boundary = None;
    let missing_control_boundary = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        crate::QemuPluginTargetArchitecture::X86_64,
        missing_control_capabilities,
    );
    assert!(matches!(
        missing_control_boundary.preflight(&args),
        Err(OwnedCallbackRegistrationError::LiveVcpuTime {
            source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_CONTROL_BOUNDARY_CB_SYMBOL,
            }
        })
    ));

    let missing_sim_dispatch = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        crate::QemuPluginTargetArchitecture::X86_64,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            force_vcpu_exit: test_force_vcpu_exit,
            request_vmstop: test_request_vmstop,
            inject_preemption: Some(super::super::test_support::accept_preemption),
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_control_boundary: Some(test_register_control_boundary),
            register_sim_shmem_dispatch: None,
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_event: Some(test_register_block_event),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
            register_accelerator: Some(test_register_accelerator),
            fault_commands: crate::fault_command::QemuFaultCommandApis::test_stub(),
            request_shutdown: test_request_shutdown,
        },
    );
    assert!(matches!(
        missing_sim_dispatch.preflight(&args),
        Err(OwnedCallbackRegistrationError::LiveVcpuTime {
            source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
            },
        })
    ));

    let missing_time_advance_completion = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        crate::QemuPluginTargetArchitecture::X86_64,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            force_vcpu_exit: test_force_vcpu_exit,
            request_vmstop: test_request_vmstop,
            inject_preemption: Some(super::super::test_support::accept_preemption),
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_control_boundary: Some(test_register_control_boundary),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: None,
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_event: Some(test_register_block_event),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
            register_accelerator: Some(test_register_accelerator),
            fault_commands: crate::fault_command::QemuFaultCommandApis::test_stub(),
            request_shutdown: test_request_shutdown,
        },
    );
    assert!(matches!(
        missing_time_advance_completion.preflight(&args),
        Err(OwnedCallbackRegistrationError::LiveVcpuTime {
            source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL,
            },
        })
    ));

    let missing_block_wait = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        crate::QemuPluginTargetArchitecture::X86_64,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            force_vcpu_exit: test_force_vcpu_exit,
            request_vmstop: test_request_vmstop,
            inject_preemption: Some(super::super::test_support::accept_preemption),
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_control_boundary: Some(test_register_control_boundary),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_event: Some(test_register_block_event),
            register_block_wait: None,
            register_ninep: Some(test_register_ninep),
            register_accelerator: Some(test_register_accelerator),
            fault_commands: crate::fault_command::QemuFaultCommandApis::test_stub(),
            request_shutdown: test_request_shutdown,
        },
    );
    assert!(matches!(
        missing_block_wait.preflight(&args),
        Err(OwnedCallbackRegistrationError::LiveVcpuTime {
            source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL,
            },
        })
    ));
}
