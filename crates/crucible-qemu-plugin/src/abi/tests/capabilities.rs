//! Fail-closed QEMU capability discovery tests.

use super::*;

#[test]
fn abi_install_entrypoint_fails_closed_without_required_runtime_symbols() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

    assert!(resolve_qemu_clock_deadline_symbol().is_none());
    assert!(resolve_qemu_advance_time_ticks_symbol().is_none());
    assert_eq!(
        call_qemu_plugin_install_with_valid_args(&valid_info),
        QEMU_PLUGIN_INSTALL_ERROR
    );
}

#[test]
fn runtime_install_retains_required_apis() {
    let runtime_apis = admit_required_runtime_apis(required_runtime_api_symbols())
        .unwrap_or_else(|error| panic!("runtime API set should install: {error}"));

    assert_eq!((runtime_apis.icount_raw())(), 17);
    (runtime_apis.force_vcpu_exit())();
    assert_eq!((runtime_apis.register_wake_fd())(42), 0);
}

#[test]
fn runtime_install_rejects_each_missing_capability_family() {
    let mut symbols = required_runtime_api_symbols();
    symbols.clock_deadline_ns = None;
    assert_eq!(
        admit_required_runtime_apis(symbols).map(|_apis| ()),
        Err(QemuPluginAbiError::ExactDeadlineCapability {
            source: ExactDeadlineError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            },
        })
    );

    let mut symbols = required_runtime_api_symbols();
    symbols.advance_time_ticks = None;
    assert_eq!(
        admit_required_runtime_apis(symbols).map(|_apis| ()),
        Err(QemuPluginAbiError::QueuedIdleAdvanceCapability {
            source: QueuedIdleAdvanceError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_ADVANCE_TIME_TICKS_SYMBOL,
            },
        })
    );

    let mut symbols = required_runtime_api_symbols();
    symbols.inject_preemption = None;
    assert_eq!(
        admit_required_runtime_apis(symbols).map(|_apis| ()),
        Err(QemuPluginAbiError::PreemptionInjectionCapability {
            source: PreemptionError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL,
            },
        })
    );

    let mut symbols = required_runtime_api_symbols();
    symbols.read_vcpu_regs = None;
    assert_eq!(
        admit_required_runtime_apis(symbols).map(|_apis| ()),
        Err(QemuPluginAbiError::VcpuIntrospectionCapability {
            source: VcpuIntrospectionError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
            },
        })
    );

    let mut symbols = required_runtime_api_symbols();
    symbols.read_rr_cursor = None;
    assert_eq!(
        admit_required_runtime_apis(symbols).map(|_apis| ()),
        Err(QemuPluginAbiError::VcpuIntrospectionCapability {
            source: VcpuIntrospectionError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_RR_CURSOR_SYMBOL,
            },
        })
    );

    let mut symbols = required_runtime_api_symbols();
    symbols.icount_raw = None;
    assert_eq!(
        admit_required_runtime_apis(symbols).map(|_apis| ()),
        Err(QemuPluginAbiError::RuntimeApiCapability {
            symbol: QEMU_PLUGIN_ICOUNT_RAW_SYMBOL,
        })
    );
}
