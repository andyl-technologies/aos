//! Invalid deterministic launch-profile candidates.

use super::*;

#[test]
fn compact_vmstate_baseline_does_not_reserve_another_full_guest_ram_copy() {
    let small = QemuLaunchResourceRequirements::from_vm_shape(128, 1, true);
    let large = QemuLaunchResourceRequirements::from_vm_shape(4096, 4, true);
    let trace_bytes = 32 * 1024 * 1024;

    assert_eq!(small.minimum_writable_bytes(), 512 * 1024 * 1024);
    assert_eq!(
        large.minimum_writable_bytes(),
        small.minimum_writable_bytes()
    );
    assert_eq!(small.guest_memory_bytes(), 128 * 1024 * 1024);
    assert_eq!(large.guest_memory_bytes(), 4096 * 1024 * 1024);
    assert_eq!(
        large
            .with_diagnostic_trace_bytes(trace_bytes)
            .minimum_writable_bytes(),
        small.minimum_writable_bytes() + trace_bytes,
    );
}

#[test]
fn host_provided_machine_reset_is_rejected() {
    let candidate = LaunchProfileCandidate {
        machine_reset: MachineResetMode::HostProvided,
        ..LaunchProfileCandidate::default()
    };

    assert_eq!(
        candidate.try_into_deterministic(),
        Err(LaunchProfileError::MachineResetNotDeterministic {
            mode: MachineResetMode::HostProvided,
        })
    );
}
