//! Streams concrete retained history without exposing generic resource owners.
//!
//! Each record borrows the original causes and immutable status in its paid
//! body. Callbacks cannot retain these records beyond a protected observation.
//! Construction status and panic presence never establish physical return.

use std::any::Any;
use std::fmt;

use super::LifecycleFailureRef;

/// Borrows an original Rust panic payload without consuming its owning body.
#[derive(Clone, Copy)]
pub struct LifecyclePanicRef<'a> {
    // Arbitrary payloads can own resources; public observation exposes only text.
    pub(crate) payload: &'a (dyn Any + Send),
}

impl<'a> LifecyclePanicRef<'a> {
    /// Borrows the original message of a string panic payload.
    ///
    /// Other payloads remain retained and return `None`, independently of their
    /// eventual destruction. This accessor does not expose their owning value.
    #[must_use]
    pub fn message(&self) -> Option<&'a str> {
        self.payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| self.payload.downcast_ref::<&'static str>().copied())
    }
}

impl fmt::Debug for LifecyclePanicRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanicPayload")
            .field("message", &self.message())
            .finish_non_exhaustive()
    }
}

/// Borrows complete, concrete diagnostic data from a retained lifecycle body.
///
/// Records carry neither cleanup authority nor a certificate of native return.
/// Their order follows the containing history, independently of first-failure
/// selection and caller-specific retry classification.
#[derive(Clone, Copy, Debug)]
pub enum LifecycleHistoryRef<'a> {
    /// An original typed cause remains in its original owner.
    Failure(LifecycleFailureRef<'a>),
    /// A prepared Source retains its independent construction and cleanup causes.
    SourcePreparation {
        /// The original shared-admission first refusal, before constructor entry.
        admission_first: Option<LifecycleFailureRef<'a>>,
        /// The independent postcheck of the same World Preparation at acquisition.
        admission_post: Option<&'a crucible_host_resources::host_supervision::HostSupervisionError>,
        /// The initiating constructor cause, before supplemental capture history.
        first: Option<LifecycleFailureRef<'a>>,
        /// The original native cleanup refusal.
        native: Option<&'a crucible_qemu_host::QemuVmRealizationError>,
        /// The first containing-body cleanup refusal.
        cleanup_first:
            Option<&'a crucible_host_resources::host_services::process_birth::ServiceBirthError>,
        /// The independent postcheck of that same cleanup operation.
        cleanup_post: Option<&'a crucible_host_resources::host_supervision::HostSupervisionError>,
        /// The original context restoration refusal.
        context_restore: Option<&'a crate::qemu_lifecycle_launcher::CanonicalContextError>,
        /// The original external-body acceptance refusal.
        body_acceptance: Option<&'a super::ServiceMainPreclaimError>,
        /// The complete original capture history, including its independent postcheck.
        capture: Option<&'a crate::vm_lifecycle::ProductionVmHotForkSourcePreparationHistory>,
    },
    /// A Target constructor retains aggregate failures and observed body state.
    TargetConstruction {
        /// The original Main admission refusal.
        first_main: Option<&'a crate::TargetMainAdmissionError>,
        /// The original setup refusal.
        first_setup: Option<&'a crate::TargetSetupFailure>,
        /// The original Source preparation refusal.
        first_preparation: Option<&'a crate::TargetPreparationFailure>,
        /// The original aggregate native admission report.
        first_begin: Option<&'a crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport>,
        /// The original aggregate reconciliation refusal.
        first_reconciliation: Option<&'a crucible_control_api::LifecycleApiError>,
        /// The original aggregate cleanup report.
        first_aggregate: Option<&'a crate::QemuAttemptResourceGuardCleanupFailure>,
        /// The original release-readiness refusal.
        first_readiness: Option<&'a crate::QemuHotForkWorldReleaseReadinessError>,
        /// Whether the constructor retains its original selected member storage.
        members_present: bool,
        /// Whether the constructor retains its original selected launch rows.
        launch_rows_present: bool,
        /// Whether the original constructor observed body destruction.
        body_destroyed: bool,
        /// Whether the original constructor observed physical return.
        physically_returned: bool,
    },
    /// A selected Target member retains all of its independent native reports.
    #[cfg(target_os = "linux")]
    TargetMember {
        /// The original selected node identity.
        node: &'a crucible_engine::NodeId,
        /// The original native admission refusal.
        admission:
            Option<&'a crucible_host_resources::host_services::process_birth::NativePoolRefusal>,
        /// The original native construction cleanup refusal.
        cleanup: Option<&'a crucible_qemu_host::QemuForkTargetConstructionError>,
        /// The original child's reconciliation refusal.
        reconciliation: Option<
            &'a crate::QemuHotForkAttemptReconciliationError<
                crate::LinuxQemuHotForkReconciliationError,
            >,
        >,
    },
    /// A selected launch row retains its errors and actual worker panic payload.
    #[cfg(target_os = "linux")]
    TargetLaunch {
        /// The original selected node identity.
        node: &'a crucible_engine::NodeId,
        /// The original launch refusal.
        launch: Option<&'a crate::LinuxQemuHotForkWorldAttemptLaunchFailure>,
        /// The independent rollback refusal.
        rollback: Option<&'a crucible_qemu_host::QemuVmRealizationError>,
        /// The actual panic payload, including payloads without a string message.
        worker_panic: Option<LifecyclePanicRef<'a>>,
    },
}

impl<'a> From<LifecycleFailureRef<'a>> for LifecycleHistoryRef<'a> {
    fn from(first: LifecycleFailureRef<'a>) -> Self {
        Self::Failure(first)
    }
}

impl fmt::Display for LifecycleHistoryRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(first) => fmt::Display::fmt(first, formatter),
            _ => fmt::Debug::fmt(self, formatter),
        }
    }
}
