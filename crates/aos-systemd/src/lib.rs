//! `aos-systemd` — a typed, async client for `org.freedesktop.systemd1` over
//! D-Bus (zbus 5).
//!
//! This crate is the *transport* layer: it speaks to systemd directly so apm
//! can propagate job results, classify outcomes, and read unit properties
//! without shelling out to `systemctl`. It has no apm- or apr-specific
//! knowledge and deliberately does not depend on `aos-core`.
//! [`fd_store`] provides bounded, read-only inspection of a service's manager
//! descriptor store for callers that validate the returned metadata.
//!
//! Entry point: [`SystemdClient::connect`].

mod client;
mod error;
pub mod fd_store;
mod manager_proxy;
mod sandbox;

pub use client::{
    FailedUnit, FailedUnitsReport, JobOutcome, JobResult, RestartPolicy,
    ServiceControlGroupObservation, SettleOutcome, SystemdClient,
};
pub use client::GitSourceSocketObservationV1;
pub use client::NixOfflineAbsenceObservationV5;
pub use error::{Error, Result};
pub use manager_proxy::ListUnitsEntry;
pub use sandbox::{
    CpuWeight, DiscoveredSandboxUnit, ExactStartError, ExactStopError, ExactStopOutcome,
    ExactUnitClient, ExactUnitObservation, ExactUnitRole, ExactUnitState, ExactUnitTarget,
    FreezerState, GuardianCredentialDescriptors, GuardianCredentialRole,
    GuardianExecutableDescriptor, GuardianExecutableSnapshot, GuardianStartError,
    GuardianUnitObservation, GuardianUnitSpec, PayloadRootContinuityPolicyV1,
    PostUnrefUnitObservation, SandboxCgroupPath, SandboxDescriptorPath, SandboxDevice,
    SandboxDiscoveryComparison, SandboxDiscoveryConflict, SandboxDiscoveryIndeterminate,
    SandboxDiscoveryOutcome, SandboxNspawnCommand, SandboxQuarantineEvidence, SandboxResolvedPaths,
    SandboxResources, SandboxUnitDiscoverySnapshot, SandboxUnitName, SandboxUnitObservation,
    SandboxUnitSpec,
};
#[cfg(target_os = "linux")]
pub use sandbox::{
    FixedFuseWorkerPid1ClientV1, FuseWorkerDescriptorRoleV1, FuseWorkerUnitNameV1,
    FuseWorkerUnitObservationV1, FuseWorkerUnitSpecV1,
};

// `unit_property` returns a `zbus::zvariant::OwnedValue` in its public
// signature. Re-export it (and `Value`, needed to inspect the variant) so
// downstream consumers can name and destructure the result without taking a
// direct zbus dependency of their own.
pub use zbus::zvariant::{OwnedValue, Value};
