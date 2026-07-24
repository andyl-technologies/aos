//! Capability-preflight regression cases for live callback registration.

use super::*;

#[test]
fn live_registrar_preflight_names_each_missing_capability() {
    let execution_model =
        QemuPluginExecutionModel::validate(2, crate::QemuTcgThreading::SingleThreadedRoundRobin)
            .unwrap_or_else(|error| panic!("test model should validate: {error}"));
    let args = PluginArgs::parse("simfd=3,slot=0")
        .unwrap_or_else(|error| panic!("test arguments should parse: {error}"));
    let missing_init = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: None,
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
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

    let missing_sim_dispatch = LiveVcpuTimeCallbackRegistrar::new(
        1,
        execution_model,
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_sim_shmem_dispatch: None,
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
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
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: None,
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_wait: Some(test_register_block_wait),
            register_ninep: Some(test_register_ninep),
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
        LiveVcpuTimeCallbackCapabilities {
            icount_raw: test_icount_raw,
            clock_deadline_ns: Some(test_clock_deadline_ns),
            advance_time_ns: Some(test_queue_idle_advance),
            register_vcpu_init: Some(test_register_vcpu_init),
            register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
            register_sim_shmem_dispatch: Some(test_register_sim_dispatch),
            register_time_advance_cb: Some(test_register_time_advance_cb),
            register_net_tx: Some(test_register_net_tx),
            net_send: Some(test_net_send),
            net_flush: Some(test_net_flush),
            register_block: Some(test_register_block),
            register_block_wait: None,
            register_ninep: Some(test_register_ninep),
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
