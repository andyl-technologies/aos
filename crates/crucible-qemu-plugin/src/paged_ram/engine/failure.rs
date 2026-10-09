//! Retains the first concrete operational cause before failed authority is exposed.
//!
//! The immutable slot owns the original typed error. Later cleanup failures and
//! generic native dispatch statuses cannot replace a backing errno or its cut.

use super::*;

/// The original failure of this actual owner, independent of guest fault evidence.
#[derive(Clone, Debug)]
pub(crate) struct RetainedOperationalFailure {
    pub(crate) class: SourceOperationClass,
    pub(crate) policy_revision: u64,
    pub(crate) topology_generation: u64,
    pub(crate) error: RamError,
}

impl PausedPagingOwner {
    /// Returns the retained typed cause without guest access or backing I/O.
    pub(crate) fn operational_failure(&self) -> Option<RetainedOperationalFailure> {
        self.first_operational_failure.get().cloned()
    }

    /// Publishes failure custody before any observer can see failed authority.
    pub(super) fn retain_operational_failure(&self, class: SourceOperationClass, error: &RamError) {
        let _ = self
            .first_operational_failure
            .set(RetainedOperationalFailure {
                class,
                policy_revision: self.requested_policy_revision.load(Ordering::Acquire),
                topology_generation: self.topology_generation.load(Ordering::Acquire),
                error: error.clone(),
            });
        self.failed.store(true, Ordering::Release);
    }

    /// Moves a root-reader cause before returning its generic native status.
    ///
    /// Logical causes already live by value in `RamError::Core`; moving them
    /// into this existing slot neither formats them nor creates shared custody.
    pub(super) fn retain_operational_failure_owned(
        &self,
        class: SourceOperationClass,
        error: RamError,
    ) {
        let _ = self
            .first_operational_failure
            .set(RetainedOperationalFailure {
                class,
                policy_revision: self.requested_policy_revision.load(Ordering::Acquire),
                topology_generation: self.topology_generation.load(Ordering::Acquire),
                error,
            });
        self.failed.store(true, Ordering::Release);
    }

    pub(super) fn writeback_failure(&self, error: RamError) -> RamError {
        self.retain_operational_failure(SourceOperationClass::Writeback, &error);
        error
    }
}

impl RetainedOperationalFailure {
    /// Projects only portable scalar causes; the concrete source stays retained.
    pub(crate) fn to_wire(&self) -> crucible_protocol::ram_control::RamControlOperationFailure {
        use crate::ram_error::SupervisionFailure;
        use crucible_protocol::ram_control::{
            RamControlFailureCause, RamControlFailureOperation, RamControlOperationFailure,
            RamControlSupervisionFailure,
        };
        let operation = match self.class {
            SourceOperationClass::ControlSetup => RamControlFailureOperation::ControlSetup,
            SourceOperationClass::Cleanup => RamControlFailureOperation::Cleanup,
            SourceOperationClass::Quiescence => RamControlFailureOperation::Quiescence,
            SourceOperationClass::ForkRearm => RamControlFailureOperation::ForkRearm,
            SourceOperationClass::PageIn => RamControlFailureOperation::PageIn,
            SourceOperationClass::Writeback => RamControlFailureOperation::Writeback,
            SourceOperationClass::FingerprintUpdate => {
                RamControlFailureOperation::FingerprintUpdate
            }
        };
        let cause = match &self.error {
            RamError::Io(error) => RamControlFailureCause::Io {
                errno: error.raw_os_error().filter(|errno| *errno > 0).unwrap_or(0),
            },
            RamError::Native { status, .. } if *status != 0 => {
                RamControlFailureCause::Native { status: *status }
            }
            RamError::Supervision { failure, .. } => RamControlFailureCause::Supervision {
                kind: match failure {
                    SupervisionFailure::Expired => RamControlSupervisionFailure::Expired,
                    SupervisionFailure::Canceled => RamControlSupervisionFailure::Canceled,
                    SupervisionFailure::MissingPolicy => {
                        RamControlSupervisionFailure::MissingPolicy
                    }
                    SupervisionFailure::Capacity => RamControlSupervisionFailure::Capacity,
                    SupervisionFailure::Uncertain => RamControlSupervisionFailure::Uncertain,
                },
            },
            _ => RamControlFailureCause::Other,
        };
        RamControlOperationFailure {
            operation,
            policy_revision: self.policy_revision,
            topology_generation: self.topology_generation,
            cause,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_protocol::ram_control::{RamControlFailureCause, RamControlFailureOperation};

    struct NoOperations;

    impl SourceOperationFactory for NoOperations {
        fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
            Err(io::Error::other("this observation must not start work"))
        }
    }

    #[test]
    fn zero_native_status_keeps_the_original_cause_without_claiming_failed_errno() {
        let failure = RetainedOperationalFailure {
            class: SourceOperationClass::Quiescence,
            policy_revision: 0,
            topology_generation: 0,
            error: RamError::Native {
                operation: "uncertain disposition",
                status: 0,
            },
        };
        assert_eq!(failure.to_wire().cause, RamControlFailureCause::Other);
        assert!(matches!(failure.error, RamError::Native { status: 0, .. }));
    }

    #[test]
    fn owned_root_logical_failure_keeps_its_original_cut_and_first_cause() {
        let resources = PluginRamResources {
            resident_peak_bytes: 8192,
            backing_peak_bytes: 16384,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 3,
        };
        let owner = PausedPagingOwner::new(resources, Arc::new(NoOperations))
            .unwrap_or_else(|error| panic!("test owner admission: {error}"));
        owner
            .seal_geometry(7, 8192)
            .unwrap_or_else(|error| panic!("test geometry admission: {error}"));
        owner.requested_policy_revision.store(3, Ordering::Release);
        let message = String::from("original logical root failure");
        let pointer = message.as_ptr();

        owner.retain_operational_failure_owned(
            SourceOperationClass::FingerprintUpdate,
            RamError::Core(crucible_ram::RamError::Read(message)),
        );
        owner.requested_policy_revision.store(4, Ordering::Release);
        owner.retain_operational_failure_owned(
            SourceOperationClass::Cleanup,
            RamError::Invariant("later cleanup refusal"),
        );

        let retained = owner
            .first_operational_failure
            .get()
            .unwrap_or_else(|| panic!("original logical failure must stay retained"));
        let RamError::Core(crucible_ram::RamError::Read(message)) = &retained.error else {
            panic!("retained cause must remain the original logical error")
        };
        assert_eq!(message.as_ptr(), pointer);
        assert_eq!(retained.policy_revision, 3);
        assert_eq!(retained.topology_generation, 7);
        assert_eq!(retained.class, SourceOperationClass::FingerprintUpdate);
        assert!(owner.failed.load(Ordering::Acquire));
        assert_eq!(
            retained.to_wire().operation,
            RamControlFailureOperation::FingerprintUpdate
        );
        assert_eq!(retained.to_wire().cause, RamControlFailureCause::Other);
    }

    #[test]
    fn first_backing_errno_and_cut_survive_later_dispatch_failure() {
        let resources = PluginRamResources {
            resident_peak_bytes: 8192,
            backing_peak_bytes: 16384,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 3,
        };
        let owner = PausedPagingOwner::new(resources, Arc::new(NoOperations))
            .unwrap_or_else(|error| panic!("test owner admission: {error}"));
        owner
            .seal_geometry(7, 8192)
            .unwrap_or_else(|error| panic!("test geometry admission: {error}"));
        owner.requested_policy_revision.store(3, Ordering::Release);
        let original = RamError::from(io::Error::from_raw_os_error(libc::EIO));
        assert!(owner.operational_failure().is_none());

        owner.retain_operational_failure(SourceOperationClass::Writeback, &original);
        owner.requested_policy_revision.store(4, Ordering::Release);
        owner.retain_operational_failure(
            SourceOperationClass::Quiescence,
            &RamError::Native {
                operation: "dispatch",
                status: -libc::EIO,
            },
        );

        let retained = owner
            .operational_failure()
            .unwrap_or_else(|| panic!("original failure must remain retained"));
        assert_eq!(retained.error, original);
        assert!(owner.failed.load(Ordering::Acquire));
        let report = retained.to_wire();
        assert_eq!(report.operation, RamControlFailureOperation::Writeback);
        assert_eq!(report.policy_revision, 3);
        assert_eq!(report.topology_generation, 7);
        assert_eq!(
            report.cause,
            RamControlFailureCause::Io { errno: libc::EIO }
        );
    }
}
