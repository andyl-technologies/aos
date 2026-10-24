//! Borrows concrete lifecycle failures without moving their original custody.
//!
//! Protected observations lend these views only while their exact Main role is
//! locked. Terminal bodies lend them for the lifetime of the retained body.
//! A view is diagnostic data, not cleanup, retry or native-return authority.

use std::fmt;

use crucible_control_api::LifecycleApiError;
use crucible_control_api::host_operational::HostOperationalError;
use crucible_engine::{BackendError, EngineError, SchedulerError};
use crucible_host_resources::host_services::process_birth::{
    NativePoolRefusal, NativePoolReturnError, ServiceBirthError,
};
use crucible_host_resources::host_supervision::HostSupervisionError;
use crucible_qemu_host::QemuVmRealizationError;

/// Borrows an actual concrete failure from its retained lifecycle owner.
#[derive(Clone, Copy, Debug)]
pub enum LifecycleFailureRef<'a> {
    /// The original Service startup failed.
    Service(&'a crate::packaged_qemu_executor::RetainedServiceStartCause),
    /// Production lifecycle construction failed.
    Lifecycle(&'a crate::QemuAttemptProductionVmLifecycleError),
    /// The original Main role refused access.
    Role(&'a super::ServiceMainPreclaimError),
    /// The original checkpoint selection slot refused access.
    Selection(&'a crate::executor_worker::SelectedCheckpointSlotError),
    /// An operational registry or resource action failed.
    Operational(&'a HostOperationalError),
    /// The original operation's supervision refused.
    Supervision(&'a HostSupervisionError),
    /// Source preparation retained a concrete refusal.
    Preparation(&'a crate::vm_lifecycle::ProductionVmHotForkSourcePreparationError),
    /// A backend operation failed.
    Backend(&'a BackendError),
    /// A scheduler operation failed.
    Scheduler(&'a SchedulerError),
    /// An admitted allocation could not be reserved.
    Allocation(&'a std::collections::TryReserveError),
    /// Semantic identity or model work failed.
    Engine(&'a EngineError),
    /// Actual QEMU realization or native cleanup failed.
    Realization(&'a QemuVmRealizationError),
    /// The original host I/O operation failed.
    Io(&'a std::io::Error),
    /// The canonical retained Service context could not be restored.
    Context(&'a crate::qemu_lifecycle_launcher::CanonicalContextError),
    /// The selected Target's Main admission failed.
    TargetMain(&'a crate::qemu_hot_fork_world_factory::TargetMainAdmissionError),
    /// The selected Target's setup failed.
    TargetSetup(&'a crate::qemu_hot_fork_world_factory::TargetSetupFailure),
    /// The original Source could not prepare a Target.
    TargetPreparation(&'a crate::TargetPreparationFailure),
    /// Actual native Target admission refused.
    #[cfg(target_os = "linux")]
    NativeAdmission(&'a NativePoolRefusal),
    /// The exact native Target construction loan could not retire.
    #[cfg(target_os = "linux")]
    NativeTargetCleanup(&'a crucible_qemu_host::QemuForkTargetConstructionError),
    /// The actual child's native reconciliation failed.
    #[cfg(target_os = "linux")]
    NativeReconciliation(
        &'a crate::QemuHotForkAttemptReconciliationError<
            crate::LinuxQemuHotForkReconciliationError,
        >,
    ),
    /// The selected native child could not launch.
    #[cfg(target_os = "linux")]
    TargetLaunch(&'a crate::LinuxQemuHotForkWorldAttemptLaunchFailure),
    /// Native guard admission retained its original report.
    GuardBegin(&'a crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport),
    /// Native guard cleanup retained its original report.
    GuardCleanup(&'a crate::QemuAttemptResourceGuardCleanupFailure),
    /// The complete child world was not ready for release.
    WorldReadiness(&'a crate::qemu_hot_fork_world_resource::QemuHotForkWorldReleaseReadinessError),
    /// Source retirement retained independent phase history.
    #[cfg(target_os = "linux")]
    SourceRetirement(&'a crate::vm_lifecycle::ProductionVmHotForkSourceRetirementHistory),
    /// Source cleanup retained its original complete history.
    SourceCleanup(&'a crate::SourceCleanupHistory),
    /// Lifecycle control or its same-work postcheck refused.
    Control(&'a LifecycleApiError),
    /// The original body could not finish construction cleanup.
    BodyCleanup(&'a crate::ProductionVmConstructionCleanupError),
    /// The actual native world could not return its memberships.
    NativeReturn(&'a NativePoolReturnError),
    /// The actual Service admission or return operation refused.
    ServiceBirth(&'a ServiceBirthError),
}

impl fmt::Display for LifecycleFailureRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(error) => fmt::Display::fmt(error, formatter),
            Self::Lifecycle(error) => fmt::Display::fmt(error, formatter),
            Self::Role(error) => fmt::Display::fmt(error, formatter),
            Self::Selection(error) => fmt::Display::fmt(error, formatter),
            Self::Operational(error) => fmt::Display::fmt(error, formatter),
            Self::Supervision(error) => fmt::Display::fmt(error, formatter),
            Self::Preparation(error) => fmt::Display::fmt(error, formatter),
            Self::Backend(error) => fmt::Display::fmt(error, formatter),
            Self::Scheduler(error) => fmt::Display::fmt(error, formatter),
            Self::Allocation(error) => fmt::Display::fmt(error, formatter),
            Self::Engine(error) => fmt::Display::fmt(error, formatter),
            Self::Realization(error) => fmt::Display::fmt(error, formatter),
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Context(error) => fmt::Display::fmt(error, formatter),
            Self::TargetMain(error) => fmt::Display::fmt(error, formatter),
            Self::TargetSetup(error) => fmt::Display::fmt(error, formatter),
            Self::TargetPreparation(error) => fmt::Display::fmt(error, formatter),
            #[cfg(target_os = "linux")]
            Self::NativeAdmission(error) => fmt::Display::fmt(error, formatter),
            #[cfg(target_os = "linux")]
            Self::NativeTargetCleanup(error) => fmt::Display::fmt(error, formatter),
            #[cfg(target_os = "linux")]
            Self::NativeReconciliation(error) => fmt::Display::fmt(error, formatter),
            #[cfg(target_os = "linux")]
            Self::TargetLaunch(error) => fmt::Display::fmt(error, formatter),
            Self::GuardBegin(error) => fmt::Display::fmt(error, formatter),
            Self::GuardCleanup(error) => fmt::Display::fmt(error, formatter),
            Self::WorldReadiness(error) => fmt::Display::fmt(error, formatter),
            #[cfg(target_os = "linux")]
            Self::SourceRetirement(error) => fmt::Display::fmt(error, formatter),
            Self::SourceCleanup(error) => fmt::Display::fmt(error, formatter),
            Self::Control(error) => fmt::Display::fmt(error, formatter),
            Self::BodyCleanup(error) => fmt::Display::fmt(error, formatter),
            Self::NativeReturn(error) => fmt::Display::fmt(error, formatter),
            Self::ServiceBirth(error) => fmt::Display::fmt(error, formatter),
        }
    }
}
