//! Invalid deterministic launch-profile candidates.

use super::*;

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
