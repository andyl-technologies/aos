//! Shared capability fixtures for live callback unit tests.

use std::cell::Cell;

thread_local! {
    static TIMER_WITNESS: Cell<(u64, i64, u64)> = const { Cell::new((0, 0, 0)) };
}

pub(crate) extern "C" fn arm_timer_witness(
    deadline_ns: i64,
    deadline_icount: u64,
    generation: *mut u64,
) -> std::os::raw::c_int {
    let next = TIMER_WITNESS.with(|witness| witness.get().0.wrapping_add(1).max(1));
    TIMER_WITNESS.with(|witness| witness.set((next, deadline_ns, deadline_icount)));
    // SAFETY: the test exercises the same non-null output-pointer contract as QEMU.
    unsafe { generation.write(next) };
    0
}

pub(crate) extern "C" fn query_timer_witness(
    generation: u64,
    out: *mut crate::QemuVirtualTimerWitnessRecord,
) -> std::os::raw::c_int {
    let (armed_generation, deadline_ns, deadline_icount) = TIMER_WITNESS.with(Cell::get);
    if generation != armed_generation {
        return -libc::ENOENT;
    }
    let raw_icount = super::tests::test_icount_raw();
    // SAFETY: the test exercises the same non-null output-pointer contract as QEMU.
    unsafe {
        out.write(crate::QemuVirtualTimerWitnessRecord {
            generation,
            deadline_ns,
            deadline_icount,
            armed_raw_icount: raw_icount,
            fired_expire_ns: deadline_ns,
            fired_virtual_ns: deadline_ns,
            fired_raw_icount: raw_icount,
            completed: 1,
            reserved: 0,
        });
    }
    0
}

pub(super) fn test_virtual_timer_witness() -> crate::QemuVirtualTimerWitness {
    crate::QemuVirtualTimerWitness::test_stub(arm_timer_witness, query_timer_witness)
}

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

pub(super) extern "C" fn test_wait_idle_wake(
    _vcpu_index: u32,
    _wake_signal: *mut u32,
    _expected: u32,
) -> std::os::raw::c_int {
    1
}

pub(super) const fn test_idle_wake_wait() -> crate::QemuIdleWakeWait {
    crate::QemuIdleWakeWait::test_stub(test_wait_idle_wake)
}

pub(super) extern "C" fn test_request_vmstop() -> std::os::raw::c_int {
    0
}
