//! Retains the first concrete operational cause before failed authority is exposed.
//!
//! The immutable slot owns the original typed error. Later cleanup failures and
//! generic native dispatch statuses cannot replace a backing errno or its cut.

use super::super::source::{RootSourceFailure, SourceDiagnostic};
use super::*;

/// A cause retained without adding shared ownership during a root read.
pub(super) enum RetainedCause {
    Ram(RamError),
    Io(io::Error),
    Source(SourceDiagnostic),
}

impl std::fmt::Debug for RetainedCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Inspection formats the retained payload; callback retention only moves it.
        match self {
            Self::Ram(error) => formatter.debug_tuple("Ram").field(error).finish(),
            Self::Io(error) => formatter.debug_tuple("Io").field(error).finish(),
            Self::Source(error) => formatter.debug_tuple("Source").field(error).finish(),
        }
    }
}

/// The original failure of this actual owner, independent of guest fault evidence.
#[derive(Debug)]
pub(crate) struct RetainedOperationalFailure {
    pub(crate) class: SourceOperationClass,
    pub(crate) policy_revision: u64,
    pub(crate) topology_generation: u64,
    pub(super) error: RetainedCause,
}

impl PausedPagingOwner {
    /// Returns the retained typed cause without guest access or backing I/O.
    pub(crate) fn operational_failure(&self) -> Option<&RetainedOperationalFailure> {
        self.first_operational_failure.get()
    }

    /// Publishes failure custody before any observer can see failed authority.
    pub(super) fn retain_operational_failure(&self, class: SourceOperationClass, error: &RamError) {
        let _ = self
            .first_operational_failure
            .set(RetainedOperationalFailure {
                class,
                policy_revision: self.requested_policy_revision.load(Ordering::Acquire),
                topology_generation: self.topology_generation.load(Ordering::Acquire),
                error: RetainedCause::Ram(error.clone()),
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
                error: RetainedCause::Ram(error),
            });
        self.failed.store(true, Ordering::Release);
    }

    /// Moves original source I/O into the existing slot before native refusal.
    ///
    /// The source operation and mutex have already closed. Keeping this value
    /// avoids constructing shared error custody while the native hash is live.
    pub(super) fn retain_operational_io_failure(
        &self,
        class: SourceOperationClass,
        error: io::Error,
    ) {
        let _ = self
            .first_operational_failure
            .set(RetainedOperationalFailure {
                class,
                policy_revision: self.requested_policy_revision.load(Ordering::Acquire),
                topology_generation: self.topology_generation.load(Ordering::Acquire),
                error: RetainedCause::Io(error),
            });
        self.failed.store(true, Ordering::Release);
    }

    /// Retains a borrowed source cause after its operation and mutex have closed.
    ///
    /// Diagnostics remain typed until the owner is inspected outside native
    /// hashing. The immutable slot preserves the initiating message and cut.
    pub(super) fn retain_operational_source_failure(
        &self,
        class: SourceOperationClass,
        error: RootSourceFailure,
    ) {
        match error {
            RootSourceFailure::Io(error) => self.retain_operational_io_failure(class, error),
            RootSourceFailure::Diagnostic(error) => {
                let _ = self
                    .first_operational_failure
                    .set(RetainedOperationalFailure {
                        class,
                        policy_revision: self.requested_policy_revision.load(Ordering::Acquire),
                        topology_generation: self.topology_generation.load(Ordering::Acquire),
                        error: RetainedCause::Source(error),
                    });
                self.failed.store(true, Ordering::Release);
            }
        }
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
            RetainedCause::Source(_) => RamControlFailureCause::Io { errno: 0 },
            RetainedCause::Io(error) => RamControlFailureCause::Io {
                errno: error.raw_os_error().filter(|errno| *errno > 0).unwrap_or(0),
            },
            RetainedCause::Ram(RamError::Io(error)) => RamControlFailureCause::Io {
                errno: error.raw_os_error().filter(|errno| *errno > 0).unwrap_or(0),
            },
            RetainedCause::Ram(RamError::Native { status, .. }) if *status != 0 => {
                RamControlFailureCause::Native { status: *status }
            }
            RetainedCause::Ram(RamError::Supervision { failure, .. }) => {
                RamControlFailureCause::Supervision {
                    kind: match failure {
                        SupervisionFailure::Expired => RamControlSupervisionFailure::Expired,
                        SupervisionFailure::Canceled => RamControlSupervisionFailure::Canceled,
                        SupervisionFailure::MissingPolicy => {
                            RamControlSupervisionFailure::MissingPolicy
                        }
                        SupervisionFailure::Capacity => RamControlSupervisionFailure::Capacity,
                        SupervisionFailure::Uncertain => RamControlSupervisionFailure::Uncertain,
                    },
                }
            }
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

    fn observation_owner() -> Arc<PausedPagingOwner> {
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
        owner
    }

    #[test]
    fn root_io_relay_keeps_errno_and_original_first_failure_cut() {
        let owner = observation_owner();
        let mut root_io = None;
        let dispatch_error = super::super::service::source_read_failure(
            super::super::super::source::SourceFetchError::Io(io::Error::from_raw_os_error(
                libc::EPIPE,
            )),
            Some(&mut root_io),
        );
        assert!(matches!(dispatch_error, RamError::Invariant(_)));
        let original = root_io
            .take()
            .unwrap_or_else(|| panic!("root I/O must stay owned before callback retention"));
        owner.retain_operational_source_failure(SourceOperationClass::FingerprintUpdate, original);
        owner.requested_policy_revision.store(4, Ordering::Release);
        owner.retain_operational_failure_owned(
            SourceOperationClass::Cleanup,
            RamError::Invariant("later cleanup refusal"),
        );

        let retained = owner
            .operational_failure()
            .unwrap_or_else(|| panic!("root I/O must remain retained"));
        let RetainedCause::Io(original) = &retained.error else {
            panic!("root source I/O must not acquire an Arc wrapper")
        };
        assert_eq!(original.raw_os_error(), Some(libc::EPIPE));
        assert_eq!(retained.policy_revision, 3);
        assert_eq!(retained.topology_generation, 7);
        assert!(owner.failed.load(Ordering::Acquire));
        let report = retained.to_wire();
        assert_eq!(
            report.operation,
            RamControlFailureOperation::FingerprintUpdate
        );
        assert_eq!(
            report.cause,
            RamControlFailureCause::Io { errno: libc::EPIPE }
        );
    }

    #[test]
    fn root_source_diagnostic_relay_keeps_display_projection_and_first_cut() {
        const MESSAGE: &str = "source response namespace, status, or length mismatch";
        for diagnostic in [
            SourceDiagnostic::Invalid(MESSAGE),
            SourceDiagnostic::Protocol(crucible_protocol::ram_page::RamPageProtocolError::Invalid(
                "bad response magic",
            )),
            SourceDiagnostic::Protocol(
                crucible_protocol::ram_page::RamPageProtocolError::Allocation,
            ),
            SourceDiagnostic::Unavailable("restore source ownership uncertain"),
            SourceDiagnostic::Transport {
                kind: io::ErrorKind::ConnectionAborted,
                message: "RAM page source canceled",
            },
        ] {
            let expected = diagnostic.to_string();
            let owner = observation_owner();
            let mut slot = None;

            let dispatch = super::super::service::source_read_failure(
                super::super::super::source::SourceFetchError::Diagnostic(diagnostic),
                Some(&mut slot),
            );
            assert!(matches!(dispatch, RamError::Invariant(_)));
            owner.retain_operational_source_failure(
                SourceOperationClass::FingerprintUpdate,
                slot.take()
                    .unwrap_or_else(|| panic!("source diagnostic must stay owned")),
            );
            owner.requested_policy_revision.store(4, Ordering::Release);
            owner.retain_operational_io_failure(
                SourceOperationClass::Cleanup,
                io::Error::from_raw_os_error(libc::EPIPE),
            );

            let retained = owner
                .operational_failure()
                .unwrap_or_else(|| panic!("initiating source failure must remain retained"));
            let RetainedCause::Source(original) = &retained.error else {
                panic!("root source diagnostic must not become a custom I/O allocation")
            };
            assert_eq!(original.to_string(), expected);
            assert_eq!(retained.policy_revision, 3);
            assert_eq!(retained.topology_generation, 7);
            assert_eq!(
                retained.to_wire().cause,
                RamControlFailureCause::Io { errno: 0 }
            );
            assert_eq!(
                retained.to_wire().operation,
                RamControlFailureOperation::FingerprintUpdate
            );
            assert!(owner.failed.load(Ordering::Acquire));
        }
    }

    #[test]
    fn root_io_keeps_arbitrary_payload_and_projection_borrows_the_original() {
        #[derive(Debug)]
        struct OriginalPayload(&'static str);

        impl std::fmt::Display for OriginalPayload {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.0)
            }
        }

        impl std::error::Error for OriginalPayload {}

        let owner = observation_owner();
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            OriginalPayload("actual source cause"),
        );
        let payload = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<OriginalPayload>())
            .unwrap_or_else(|| panic!("original fixture payload must exist"))
            as *const OriginalPayload;
        owner.retain_operational_io_failure(SourceOperationClass::FingerprintUpdate, error);

        let first = owner
            .operational_failure()
            .unwrap_or_else(|| panic!("original source payload must stay retained"));
        let again = owner
            .operational_failure()
            .unwrap_or_else(|| panic!("projection must borrow the same immutable slot"));
        assert!(std::ptr::eq(first, again));
        let RetainedCause::Io(error) = &first.error else {
            panic!("owned I/O cause must remain unwrapped")
        };
        let retained_payload = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<OriginalPayload>())
            .unwrap_or_else(|| panic!("original arbitrary payload type must survive"));
        assert!(std::ptr::eq(payload, retained_payload));
        assert_eq!(retained_payload.0, "actual source cause");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            first.to_wire().cause,
            RamControlFailureCause::Io { errno: 0 }
        );
    }

    #[test]
    fn ordinary_io_conversion_retains_public_shared_error_identity() {
        let error = super::super::service::source_read_failure(
            super::super::super::source::SourceFetchError::Io(io::Error::from_raw_os_error(
                libc::EPIPE,
            )),
            None,
        );
        let RamError::Io(original) = &error else {
            panic!("ordinary I/O conversion must retain its public Arc representation")
        };
        assert_eq!(original.raw_os_error(), Some(libc::EPIPE));
        let clone = error.clone();
        let RamError::Io(clone) = clone else {
            panic!("public RamError cloning must keep its existing representation")
        };
        assert!(Arc::ptr_eq(original, &clone));
    }

    #[test]
    fn owned_io_uses_the_previous_record_and_slot_extent() {
        struct PreviousFailure {
            class: SourceOperationClass,
            policy_revision: u64,
            topology_generation: u64,
            error: RamError,
        }

        let previous = PreviousFailure {
            class: SourceOperationClass::FingerprintUpdate,
            policy_revision: 3,
            topology_generation: 7,
            error: RamError::Invariant("previous inline failure geometry"),
        };
        assert_eq!(previous.class, SourceOperationClass::FingerprintUpdate);
        assert_eq!(previous.policy_revision, 3);
        assert_eq!(previous.topology_generation, 7);
        assert!(matches!(previous.error, RamError::Invariant(_)));
        assert_eq!(
            std::mem::size_of::<RetainedOperationalFailure>(),
            std::mem::size_of::<PreviousFailure>()
        );
        assert_eq!(
            std::mem::align_of::<RetainedOperationalFailure>(),
            std::mem::align_of::<PreviousFailure>()
        );
        assert_eq!(
            std::mem::size_of::<std::sync::OnceLock<RetainedOperationalFailure>>(),
            std::mem::size_of::<std::sync::OnceLock<PreviousFailure>>()
        );
        println!(
            "OWNED_IO_LAYOUT cause={} record={} slot={} owner={} align={}",
            std::mem::size_of::<RetainedCause>(),
            std::mem::size_of::<RetainedOperationalFailure>(),
            std::mem::size_of::<std::sync::OnceLock<RetainedOperationalFailure>>(),
            std::mem::size_of::<PausedPagingOwner>(),
            std::mem::align_of::<RetainedOperationalFailure>()
        );
    }

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
            error: RetainedCause::Ram(RamError::Native {
                operation: "uncertain disposition",
                status: 0,
            }),
        };
        assert_eq!(failure.to_wire().cause, RamControlFailureCause::Other);
        assert!(matches!(
            failure.error,
            RetainedCause::Ram(RamError::Native { status: 0, .. })
        ));
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
        let RetainedCause::Ram(RamError::Core(crucible_ram::RamError::Read(message))) =
            &retained.error
        else {
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
        assert!(matches!(&retained.error, RetainedCause::Ram(error) if error == &original));
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
