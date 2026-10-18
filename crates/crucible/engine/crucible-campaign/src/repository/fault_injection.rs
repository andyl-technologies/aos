//! Production-disabled destructive recovery fault boundaries.

const TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
const FAULT_EXIT_CODE: i32 = 86;

pub(super) enum DestructiveRecoveryFault {
    CoordinatorBeforeObservationCommit,
    DaemonDuringSnapshotPublication,
}

impl DestructiveRecoveryFault {
    const fn trigger(&self) -> &'static str {
        match self {
            Self::CoordinatorBeforeObservationCommit => {
                "crucible.destructive-recovery.coordinator-before-observation-commit"
            }
            Self::DaemonDuringSnapshotPublication => {
                "crucible.destructive-recovery.daemon-during-snapshot-publication"
            }
        }
    }
}

pub(super) fn terminate_if_requested(fault: DestructiveRecoveryFault) {
    let requested = std::env::var_os(TRIGGER_ENVIRONMENT);
    if requested.as_deref() == Some(std::ffi::OsStr::new(fault.trigger())) {
        // Exiting without unwinding models loss of process-local reservations
        // at an exact boundary after durable writes and before ref publication.
        std::process::exit(FAULT_EXIT_CODE);
    }
}
