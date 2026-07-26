//! Fail-closed QEMU capability discovery tests.

use super::*;

#[test]
fn abi_install_entrypoint_fails_closed_without_exact_deadline_or_queued_advance_symbols() {
    let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

    assert!(resolve_qemu_advance_time_ns_symbol().is_none());
    assert!(resolve_qemu_register_time_advance_cb_symbol().is_none());
    assert_eq!(
        call_qemu_plugin_install_with_valid_args(&valid_info),
        QEMU_PLUGIN_INSTALL_ERROR
    );
    assert_eq!(
        install_required_deadline_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            None,
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::ExactDeadlineCapability {
            source: ExactDeadlineError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            },
        })
    );
}

#[test]
fn abi_install_entrypoint_requires_queued_advance_after_deadline_resolution() {
    let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
    let _deadline_guard = TestClockDeadlineSymbolGuard::install(abi_test_deadline);
    let Some(deadline) = resolve_qemu_clock_deadline_symbol() else {
        panic!("test exported exact-deadline symbol should resolve");
    };

    assert_eq!(deadline(), 4096);
    assert!(resolve_qemu_advance_time_ns_symbol().is_none());
    assert_eq!(
        call_qemu_plugin_install_with_valid_args(&valid_info),
        QEMU_PLUGIN_INSTALL_ERROR
    );
}

#[test]
fn abi_install_requires_queued_idle_advance_symbol() {
    let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

    assert_eq!(
        install_required_time_capability_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
        )
        .map(|state| {
            (
                state.exact_deadline_reader().is_some(),
                state.queued_idle_advance().is_some(),
            )
        }),
        Ok((true, true))
    );
    assert_eq!(
        install_required_time_capability_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            None,
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::QueuedIdleAdvanceCapability {
            source: QueuedIdleAdvanceError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL,
            },
        })
    );
}

#[test]
fn abi_install_requires_preemption_injection_symbol() {
    let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

    assert!(resolve_qemu_inject_preemption_symbol().is_none());
    assert_eq!(
        install_required_preemption_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
        )
        .map(|state| {
            (
                state.exact_deadline_reader().is_some(),
                state.queued_idle_advance().is_some(),
                state.preemption_injector().is_some(),
            )
        }),
        Ok((true, true, true))
    );
    assert_eq!(
        install_required_preemption_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            None,
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::PreemptionInjectionCapability {
            source: PreemptionError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL,
            },
        })
    );
}

#[test]
fn abi_install_requires_vcpu_introspection_symbols() {
    let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

    assert!(resolve_qemu_read_vcpu_regs_symbol().is_none());
    assert!(resolve_qemu_rr_cursor_symbol().is_none());
    assert_eq!(
        install_required_vcpu_introspection_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            Some(abi_test_read_vcpu_regs),
            Some(abi_test_rr_cursor),
        )
        .map(|state| {
            (
                state.exact_deadline_reader().is_some(),
                state.queued_idle_advance().is_some(),
                state.preemption_injector().is_some(),
                state.vcpu_introspector().is_some(),
            )
        }),
        Ok((true, true, true, true))
    );
    assert_eq!(
        install_required_vcpu_introspection_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            None,
            Some(abi_test_rr_cursor),
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::VcpuIntrospectionCapability {
            source: VcpuIntrospectionError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
            },
        })
    );
    assert_eq!(
        install_required_vcpu_introspection_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            Some(abi_test_read_vcpu_regs),
            None,
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::VcpuIntrospectionCapability {
            source: VcpuIntrospectionError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_RR_CURSOR_SYMBOL,
            },
        })
    );
}

#[test]
fn abi_install_requires_t_patch_11_runtime_api_symbols() {
    let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

    let state = install_required_runtime_api_scaffold_from_qemu_info(
        &valid_info,
        QemuTcgThreading::SingleThreadedRoundRobin,
        Some(abi_test_deadline),
        Some(abi_test_direct_advance),
        Some(abi_test_inject_preemption),
        Some(abi_test_read_vcpu_regs),
        Some(abi_test_rr_cursor),
        Some(abi_test_icount_raw),
        Some(abi_test_force_vcpu_exit),
        Some(abi_test_register_wake_fd),
        Some(abi_test_register_tcg_exec_cb),
    )
    .unwrap_or_else(|error| panic!("runtime API scaffold should install: {error}"));
    let runtime_apis = state
        .runtime_apis()
        .unwrap_or_else(|| panic!("runtime API handles should be retained"));

    assert_eq!((runtime_apis.icount_raw())(), 17);
    (runtime_apis.force_vcpu_exit())();
    assert_eq!((runtime_apis.register_wake_fd())(42), 0);
    (runtime_apis.register_tcg_exec_cb())(None, std::ptr::null_mut());
    assert!(state.exact_deadline_reader().is_some());
    assert!(state.queued_idle_advance().is_some());
    assert!(state.preemption_injector().is_some());
    assert!(state.vcpu_introspector().is_some());

    assert_eq!(
        install_required_runtime_api_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            Some(abi_test_read_vcpu_regs),
            Some(abi_test_rr_cursor),
            None,
            Some(abi_test_force_vcpu_exit),
            Some(abi_test_register_wake_fd),
            Some(abi_test_register_tcg_exec_cb),
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::RuntimeApiCapability {
            symbol: QEMU_PLUGIN_ICOUNT_RAW_SYMBOL,
        })
    );
    assert_eq!(
        install_required_runtime_api_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            Some(abi_test_read_vcpu_regs),
            Some(abi_test_rr_cursor),
            Some(abi_test_icount_raw),
            Some(abi_test_force_vcpu_exit),
            Some(abi_test_register_wake_fd),
            None,
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::RuntimeApiCapability {
            symbol: crate::QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL,
        })
    );
}

#[test]
fn abi_install_full_capability_scaffold_fails_closed_without_exact_deadline() {
    let valid_info = qemu_info_fixture(2, 1, QEMU_PLUGIN_API_VERSION);

    assert_eq!(
        install_required_vcpu_introspection_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin,
            None,
            Some(abi_test_direct_advance),
            Some(abi_test_inject_preemption),
            Some(abi_test_read_vcpu_regs),
            Some(abi_test_rr_cursor),
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::ExactDeadlineCapability {
            source: ExactDeadlineError::CapabilityUnavailable {
                symbol: crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
            },
        })
    );
}
