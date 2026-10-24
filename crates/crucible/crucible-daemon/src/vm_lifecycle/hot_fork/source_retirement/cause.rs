//! Borrows concrete Source retirement failures from their original history.
//!
//! Views grant no cleanup, native return or retry authority. Their references
//! remain tied to the retained owner that already stores each phase's cause.

use std::fmt;

use crucible_engine::{BackendError, SchedulerError};
use crucible_host_resources::host_services::process_birth::ServiceBirthError;
use crucible_host_resources::host_supervision::HostSupervisionError;

use super::super::rearm_return::SourceRearmHistory;

/// Borrows a concrete phase failure without copying its original allocation.
#[derive(Clone, Copy, Debug)]
pub enum SourceRetirementCause<'a> {
    /// The managed parent Park operation refused.
    #[cfg(feature = "private-measurement-domain")]
    ManagedPark(&'a crate::ProductionVmParentParkDrainRefusal),
    /// The managed Park caller's independent postcheck refused.
    #[cfg(feature = "private-measurement-domain")]
    ManagedParkCallerPost(&'a HostSupervisionError),
    /// The managed Park membership-return postcheck refused.
    #[cfg(feature = "private-measurement-domain")]
    ManagedParkMembershipPost(&'a HostSupervisionError),
    /// The managed Park Cleanup postcheck refused.
    #[cfg(feature = "private-measurement-domain")]
    ManagedParkCleanupPost(&'a HostSupervisionError),
    /// The original Source rearm retained its cause or rollback diagnostics.
    Rearm(&'a SourceRearmHistory),
    /// The Source's Cleanup operation could not be admitted.
    Admission(&'a ServiceBirthError),
    /// The original Cleanup precheck refused before rollback.
    Original(&'a HostSupervisionError),
    /// The backend could not roll back its prepared Source.
    Rollback(&'a BackendError),
    /// The independent rollback postcheck refused.
    RollbackPost(&'a HostSupervisionError),
    /// The scheduler could not shut down its Source.
    Shutdown(&'a SchedulerError),
    /// The independent scheduler shutdown postcheck refused.
    ShutdownPost(&'a HostSupervisionError),
    /// The original physical body could not retire.
    Body(&'a crate::ProductionVmConstructionCleanupError),
    /// The independent physical-body postcheck refused.
    BodyPost(&'a HostSupervisionError),
}

impl fmt::Display for SourceRetirementCause<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "private-measurement-domain")]
            Self::ManagedPark(error) => fmt::Display::fmt(error, formatter),
            #[cfg(feature = "private-measurement-domain")]
            Self::ManagedParkCallerPost(error)
            | Self::ManagedParkMembershipPost(error)
            | Self::ManagedParkCleanupPost(error) => fmt::Display::fmt(error, formatter),
            Self::Rearm(error) => fmt::Display::fmt(error, formatter),
            Self::Admission(error) => fmt::Display::fmt(error, formatter),
            Self::Original(error)
            | Self::RollbackPost(error)
            | Self::ShutdownPost(error)
            | Self::BodyPost(error) => fmt::Display::fmt(error, formatter),
            Self::Rollback(error) => fmt::Display::fmt(error, formatter),
            Self::Shutdown(error) => fmt::Display::fmt(error, formatter),
            Self::Body(error) => fmt::Display::fmt(error, formatter),
        }
    }
}
