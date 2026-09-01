//! Shared capability fixtures for live callback unit tests.

pub(super) extern "C" fn accept_preemption(
    _at_icount: u64,
    _deadline_icount: u64,
    _ceiling_icount: u64,
    _kind: std::os::raw::c_uint,
    _arg0: u32,
    _arg1: u32,
    _arg2: u32,
) -> std::os::raw::c_int {
    0
}

pub(super) fn test_preemption_injector() -> crate::PluginPreemptionInjector {
    crate::PluginPreemptionInjector::require(Some(accept_preemption))
        .unwrap_or_else(|error| panic!("test preemption capability should bind: {error}"))
}

pub(super) extern "C" fn test_force_vcpu_exit() {}

pub(super) extern "C" fn test_request_vmstop() -> std::os::raw::c_int {
    0
}
