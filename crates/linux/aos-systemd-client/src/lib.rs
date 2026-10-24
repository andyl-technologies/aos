//! `aos-systemd-client` — a typed, async client for `org.freedesktop.systemd1` over
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
#[cfg(target_os = "linux")]
mod pid1_property_read;
mod sandbox;
mod sandbox_resource_recipe;
pub use sandbox_resource_recipe::{SandboxResourceRecipeV1, SandboxResourceRecipeErrorV1};

pub use client::{ServicePropertiesReadOriginalV2, ServicePropertiesReadClosedV2,
    ServiceControlGroupReadOriginalV2};

pub use client::{
    FailedUnit, FailedUnitsReport, JobOutcome, JobResult, ManagerIncarnation, PinnedSystemdManager,
    RestartPolicy, ServiceControlGroupObservation, SettleOutcome, SystemdClient,
    SystemdManagerConnection, UnitActiveState,
};
pub use client::GitSourceSocketObservationV1;
pub use client::NixOfflineAbsenceObservationV5;
#[cfg(target_os = "linux")]
pub use client::{
    CompletedOwnUnitPid1ImageV1, OwnUnitPid1ImageAttemptV1,
    OwnUnitPid1ImageEndedV1, OwnUnitPid1ImageFailureV1,
};
#[cfg(target_os = "linux")]
pub use client::{
    ControllerAttachmentServiceV1, ControllerPropertyObserverAttemptV1,
    ReadonlyPropertyManagerOriginalV2, ReadonlyPropertyReceiveScheduleV2,
};
pub use error::{Error, Result};
pub use manager_proxy::ListUnitsEntry;
pub use sandbox::{
    CpuWeight, DiscoveredSandboxUnit, ExactStartError, ExactStopError, ExactStopOutcome,
    ExactUnitClient, ExactUnitObservation, ExactUnitRole, ExactUnitState, ExactUnitTarget,
    FreezerState, GuardianUnitPropertyOriginalV2, GuardianCredentialAcquisitionOriginalV2, GuardianCredentialDescriptors, GuardianCredentialRole,
    GuardianExecutableDescriptor, GuardianExecutableSnapshot, GuardianStartError,
    GuardianUnitObservation, GuardianUnitSpec, PayloadRootContinuityPolicyV1,
    PostUnrefUnitObservation, SandboxCgroupPath, SandboxDescriptorPath, SandboxGuestAgentPinOriginalV2, SandboxDevice,
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

/// Borrows the original selected transport's native, protocol or ended cause.
#[cfg(target_os = "linux")]
pub use zbus::connection::socket::LauncherImageFailureRefV1 as HostSystemdNativeFailureRefV2;


/// Preserves the original typed property clone or conversion failure.
pub use zbus::zvariant::Error as PropertyValueErrorV1;

#[cfg(target_os = "linux")]
pub use client::{
    SharedFixedPid1PropertyProviderV1,
    FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1, FixedPid1PropertyGrowthErrorV1,
    FixedPid1PropertyGeometryV1, FixedPid1PropertyValuesV1, FixedPid1PropertyActionOutcomeV1,
    FixedPid1PropertyFailureViewV1, FixedPid1PropertyJoinOutcomeV1, FixedPid1PropertyWorkerSlotV1,
};

#[cfg(target_os = "linux")]
pub use pid1_property_read::{
    Pid1PropertyReadErrorV1, Pid1PropertyReadRecipeV1, read_pid1_startup_properties_v1,
};

#[cfg(target_os = "linux")]
pub use client::{
    HostRuntimeDiscoveryOriginalV5, HostRuntimeDiscoveryRefusalV5, NetworkWorkerCensusOriginalV4, NetworkWorkerCensusRefusalV4,
    HostSystemdCallV2, HostLaunchEffectWriteGateV3, HostLaunchReceiveScheduleV2, HostSystemdConnectionFootprintV2,
    HostSystemdConnectionOriginalV2, HostSystemdDispositionFailureLoanV2,
    HostSystemdDispositionUnavailableV2,
};

/// Retains the original payload property and native descriptor preparation.
pub use sandbox::PayloadUnitPropertyOriginalV2;

#[cfg(target_os = "linux")]
pub use client::{HostSystemdNativeDisposalV2, HostSystemdNativeDisposedV2, HostSystemdStorageCompactedV2};

#[cfg(target_os = "linux")]
pub use sandbox::GuardianExecutableValidationOriginalV2;
