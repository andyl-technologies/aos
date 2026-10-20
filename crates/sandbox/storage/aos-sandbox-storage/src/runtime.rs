//! Protected construction and startup recovery for the Storage broker.
//!
//! Runtime construction reads authority and state authentication together,
//! opens the sole transaction-store lock, anchors a separately protected
//! complete genesis snapshot, and performs observation-only recovery before
//! reporting readiness. The static genesis is never compared to an evolved
//! current head; it identifies only the authenticated chain root. A separate
//! protected minimum generation supplies the monotonic rollback floor.
//!
//! The complete-bootstrap property is a contract of the privileged publisher
//! that creates this directory. This module enforces root ownership, fixed
//! filenames, bounded canonical records, and exact genesis identity; it does
//! not accept a caller-provided boolean as proof of completeness.
//! Repair worker admission closes before the final pin/ZFS and guest-root
//! cgroup scans; it does not itself authorize a Repair commit.
//! The explicit operator-listener constructor acquires four existing writers
//! before startup mutation, retaining a genuine sidecar debt token until exact
//! settlement. Its terminal-only observation never materializes catalog rows.

mod native_acquire;
mod daemon_prefix;
mod startup_assembly;
mod transaction_recovery;
mod startup_reconciliation;
mod inventory_catalog;
mod guest_root_publication;
mod guest_root_health;
mod root_mount_export;
mod root_export_original;
mod bootstrap_open;
use startup_assembly::StorageRuntimeAssemblyV1;
use daemon_prefix::{DaemonPrefixProfileV1, StorageDaemonPrefixV1};
pub(crate) mod capture_candidate;
#[cfg(target_os = "linux")]
pub(crate) mod git_coverage;
pub(crate) mod original_held_settlement;
pub(crate) mod original_held_measurement;
mod operator_terminal_hold;
mod native_readback;
mod original_output;
mod repair_worker_drain;
mod operator_startup;
mod canary_export_held;
pub(crate) use canary_export_held::CanaryBootstrapOriginalLoanV2;
pub(crate) use native_acquire::{
    StorageNativeDeliveryOutcomeV2, original_fail_stop_deadline,
    validate_native_request_clock, validate_original_clock,
};
pub(crate) use original_held_measurement::StoredOriginalHeldSigningLoanV1;

use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyStorageRequest, BrokerMethod, InventoryStorageResourcesResponse,
    StorageOperatorRepairCommitRecordV1,
};
use aos_sandbox_guest_protocol::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_model::model::{IdentityProfile, SandboxSpec, UnmappableIdentityPolicy};
use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, ObjectDigest, ProtocolVersion, RawClockProvenance,
    RawPairedClockSample,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::semantics::storage::{CanonicalStorageSemanticsV1, StorageOperation};
use aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES, PeerCredentials, PeerPolicy, ValidatedStorageWorkspace,
    decode_storage_resource_inventory_response,
};
use aos_sandbox_source_provider_protocol::{StorageLiveExportSourceV1, ZfsHeldSnapshotProofV1};
use buffa::Message as _;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};

use crate::authorization::StorageProtectedConfigurationV1;
use crate::broker::{
    AuthenticatedWorkspaceCatalogPhysicalPlanV1, AuthorizedWorkspacePinRepairAttemptV1,
    StorageHeldSnapshotCatalogCutV1, StorageHeldSnapshotSelectorV1, WorkspacePinExecutionOutcomeV1,
    WorkspaceRemovePinRequirementV1,
};
use crate::guest_root_inventory::{
    ProtectedGuestRootTemplateV1, attach_guest_root_publication_readback_v1,
};
use crate::pin_worker_runtime::SystemdGuestRootPublisherClientV1;
use crate::helper::{
    StorageMutationHelper, SystemdZfsProcessBackend, ZfsHelperOutcome, ZfsProcessBackend,
};
use crate::live_export_origin::StorageLiveExportOriginV1;
use crate::native_issuance::StorageNativeIssuanceLedgerV1;
use crate::observation_protocol::{
    WorkspaceCatalogObservationBindingsV1, WorkspaceCatalogObservationExpectationV1,
    WorkspaceCatalogObservationRequestV1, encode_request,
};
use crate::pin_observer::WorkspacePinHostCustody;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::pin_worker_runtime::{
    SystemdWorkspacePinExecutor, SystemdWorkspacePinObserver, SystemdWorkspacePinRuntimeIo,
    WorkspacePinRuntimeIo,
};
use crate::process::{
    HeldSnapshotPhysicalObservationV1, HeldSnapshotWorkerBindingV1, open_cgroup_root,
};
use crate::resolver::protected_catalog::ProtectedStorageResolverPolicyDirectoryV1;
use crate::resolver::protected_catalog::StorageResolverPolicyCatalogBindingV1;
use crate::root_policy::PortableRootAttributesV1;
use crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1;
use crate::workspace_catalog::{
    PendingStorageWorkspaceCatalogV1, StorageWorkspaceCatalogActivationCandidateV1,
    ValidatedPendingStorageWorkspaceCatalogV1,
};
use crate::workspace_repair_observer::random_challenge;
use crate::{
    CommittedStorageResultV1, DurableStoragePhase, ResolvedCatalogCommitmentV1,
    StorageAdmissionCoordinator, StorageAdmissionError, StorageAdmissionOutcome,
    StorageBrokerError, StorageCatalogPreparationOutcomeV1, StorageIdentityPoolV1,
    StorageStateError, StorageTransactionStore, StorageWorkspaceCatalogError, SystemdZfsExecutor,
    ZfsHelperContract, ZfsTransactionError, ZfsWorkerError,
};
use repair_worker_drain::{RepairWorkerDispatchGate, close_and_drain_worker_scopes};

const BOOTSTRAP_FILE: &str = "storage-genesis.catalog";
const MINIMUM_GENERATION_FILE: &str = "storage-minimum-generation";
const BOOTSTRAP_MAGIC: &[u8; 8] = b"AOSSBT01";
const BOOTSTRAP_VERSION: u16 = 1;
const BOOTSTRAP_HEADER_BYTES: usize = 24;
const MAXIMUM_BOOTSTRAP_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_BOOTSTRAP_CATALOGS: usize = 256;
const RUNTIME_BINDING_DOMAIN: &[u8] = b"aos.sandbox.storage.runtime-composition.v1\0";
const WORKSPACE_PIN_WORKER_SOCKET: &str = "/run/aos/sandbox-workspace-pin-worker/control.sock";
const WORKSPACE_PIN_OBSERVER_SOCKET: &str = "/run/aos/sandbox-workspace-pin-observer/control.sock";
const GUEST_ROOT_PUBLISHER_SOCKET: &str = "/run/aos/sandbox-guest-root-publisher/control.sock";
const STARTUP_CATALOG_OBSERVATION_NANOSECONDS: u64 = 10_000_000_000;
const STARTUP_CATALOG_WORKER_NANOSECONDS: u64 = 9_000_000_000;
pub(crate) const KERNEL_CLOCK_PROVENANCE: [u8; 16] = *b"aos-kernel-clock";

/// Rejects a retained Repair hold before startup observation can dispatch.
///
/// # Errors
///
/// Returns [`StorageRuntimeError::Recovery`] while the authenticated journal
/// retains an unresolved held guard.
pub(crate) fn reject_held_repair_guard_after_quiescence(
    transactions: &StorageTransactionStore,
) -> Result<(), StorageRuntimeError> {
    // A persisted hold is not a new dispatch grant. A future resolver must
    // authenticate the Controller terminal outcome before opening this gate.
    if transactions.has_held_repair_guard() {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}

fn live_export_origin_matches_source(
    origin: &StorageLiveExportOriginV1,
    source: StorageLiveExportSourceV1,
) -> bool {
    origin.source_assignment_digest() == source.source_assignment_digest()
        && origin.owner() == (source.owner_sandbox(), source.source_incarnation())
        && origin.workspace() == (source.workspace_id(), source.workspace_digest())
        && origin.physical_identity()
            == (
                source.origin_boot_id(),
                source.origin_device(),
                source.origin_inode(),
                source.origin_mount_id(),
            )
}

pub(crate) fn guest_root_inventory_cutoff(
    now: u64,
    deadline: u64,
) -> Result<u64, StorageRuntimeError> {
    let latest = deadline
        .checked_sub(1)
        .ok_or(StorageRuntimeError::Recovery)?;
    let cutoff = now
        .checked_add(9_000_000_000)
        .ok_or(StorageRuntimeError::Recovery)?
        .min(latest);
    if cutoff <= now {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(cutoff)
}

/// Reports protected Storage runtime construction or recovery failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageRuntimeError {
    /// The actual contacted receiving original or its retained shape is closed.
    #[error("the original Storage receiving interval is closed")]
    Receiving,

    /// Protected authority configuration was rejected.
    #[error("protected Storage authority configuration was rejected: {0}")]
    Configuration(#[from] crate::StorageAuthorityConfigError),
    /// Protected bootstrap provenance or canonical bytes were rejected.
    #[error("protected Storage bootstrap was rejected")]
    Bootstrap,
    /// Authenticated transaction state failed closed.
    #[error("Storage runtime state was rejected: {0}")]
    State(#[from] StorageStateError),
    /// The fixed worker boundary could not be constructed.
    #[error("fixed Storage worker was rejected: {0}")]
    Worker(#[from] ZfsWorkerError),
    /// The fixed ZFS executable contract was invalid.
    #[error("fixed Storage transaction contract was rejected: {0}")]
    Transaction(#[from] ZfsTransactionError),
    /// Observation-only recovery or authorized execution failed closed.
    #[error("Storage observation or execution failed closed")]
    Recovery,
    /// In-process journal custody is ambiguous and must be reopened.
    #[error("Storage state requires process restart and protected reopen")]
    ReopenRequired,
    /// Protected workspace publication state or root-pin identity failed closed.
    #[error("Storage workspace publication failed closed: {0}")]
    WorkspaceCatalog(#[from] StorageWorkspaceCatalogError),
    /// The initial host mount namespace or fixed pin root could not be retained.
    #[error("initial Storage workspace pin scope failed closed")]
    WorkspacePinScope,
    /// Signed Apply admission or its durable authority links failed closed.
    #[error("Storage admission failed closed: {0}")]
    Admission(#[from] StorageBrokerError),
    /// The explicit empty operator sidecar could not be provisioned or rechecked.
    #[error("Storage operator receipt provisioning failed: {0}")]
    OperatorProvision(#[from] crate::operator_recovery::StorageOperatorRecoveryErrorV1),
    /// Actual fixed role credentials changed during explicit provisioning.
    #[error("Storage operator provisioning credentials failed: {0}")]
    OperatorProvisionCredentials(#[source] Box<crate::service::StorageServiceError>),
}

/// Describes core mutation recovery and authoritative-catalog readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRuntimeReadiness {
    /// Mutation recovery, mandatory root pins, and publication have converged.
    ///
    /// This state permits inventory and otherwise-authorized Prepare. It does
    /// not imply generic Apply readiness; [`StorageApplyReadiness`] is an
    /// independent production-backend gate.
    Ready,
    /// Authenticated current-format effects still require observation.
    RecoveryPending {
        /// Count of bounded pending or ambiguous operations.
        operations: usize,
    },
    /// An ambiguous commit consumed trusted in-process journal custody.
    ///
    /// No RPC remains available in this state. The service must exit so its
    /// supervisor can construct a new runtime and replay the durable prefix.
    ReopenRequired,
}

impl StorageRuntimeReadiness {
    const fn permits_catalog_methods(self) -> bool {
        matches!(self, Self::Ready)
    }

    const fn permits_repair(self) -> bool {
        matches!(self, Self::Ready | Self::RecoveryPending { .. })
    }

    const fn requires_reopen(self) -> bool {
        matches!(self, Self::ReopenRequired)
    }
}

/// Describes whether the complete generic Apply backend exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageApplyReadiness {
    /// Apply remains closed until every advertised action, including Snapshot,
    /// has a dedicated worker and complete MAC and platform qualification.
    WorkspaceBackendUnavailable,
    /// The explicit dormant constructor retained the fixed ZFS worker and
    /// protected AOSSMT01 Snapshot metadata owner.
    ProtectedWorkerReady,
}

#[derive(Clone, Copy)]
enum StorageApplyConstructionV1 {
    Closed,
    DormantProtectedWorker,
}

enum StorageStartupOutcomeV4 {
    Runtime(
        StorageBrokerRuntime,
        Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
    ),
    OperatorProvisioned,
}

// The request owner lives outside the runtime loan. A return or unwind that
// did not establish complete readback permanently ends this one attempt.
struct OriginalOutputRegistrationBoundaryV1<'attempt> {
    attempt: &'attempt mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
}

impl Drop for OriginalOutputRegistrationBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.attempt.completed && self.attempt.failure().is_none() && self.attempt.postcheck_debt().is_none() {
            self.attempt.first_cause = Some(
                crate::execution_output_credential::OriginalOutputRegistrationErrorV1::NotCurrent,
            );
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalNativeConstructionPhaseV1 {
    Captured,
    Opening,
    NativeOpening,
    Ready,
    Failed,
}

#[derive(Clone, Copy)]
pub(crate) enum OriginalStartupProfileV1<'key> {
    Ordinary,
    Held(&'key crate::storage_zfs_hold_key::StorageZfsHoldKeyV1),
}

impl OriginalStartupProfileV1<'_> {
    fn receiving_profile(self) -> DaemonPrefixProfileV1 {
        match self {
            Self::Ordinary => DaemonPrefixProfileV1::Ordinary,
            Self::Held(_) => DaemonPrefixProfileV1::HeldNative,
        }
    }
}

// The selected daemon's actual executor stays in its outer resident slot until
// every earlier startup check and fixed Snapshot owner has succeeded.
enum StorageStartupExecutorV1<'owner> {
    Legacy(&'owner mut Option<SystemdZfsExecutor>),
    Receiving(&'owner mut Option<SystemdZfsExecutor>),
}

impl StorageStartupExecutorV1<'_> {
    fn take(&mut self) -> Option<SystemdZfsExecutor> {
        match self {
            Self::Legacy(executor) => executor.take(),
            Self::Receiving(executor) => executor.take(),
        }
    }
}

enum OriginalNativeConstructionCauseV1 {
    Startup(crate::activation::StorageOriginalWorkerStartupCauseV3),
    Native(crate::native_issuance::StorageNativeIssuanceErrorV1),
    Runtime(StorageRuntimeError),
    Service(crate::service::StorageServiceError),
}

impl OriginalNativeConstructionCauseV1 {
    fn source(&self) -> &(dyn std::error::Error + 'static) {
        match self {
            Self::Startup(cause) => cause,
            Self::Native(cause) => cause,
            Self::Runtime(cause) => cause,
            Self::Service(cause) => cause,
        }
    }
}

/// Retains the genuine original startup and the selected first-offer construction.
///
/// It is begun immediately after real capture, before later caller gates. Its
/// private partial slots keep the same returned native writer and optional
/// Repair owner. Ready lends the composition; it never extracts a replacement
/// writer or converts absence into admission. An armed destructor aborts before
/// these originals can be discarded. Lower pre-return custody remains separate.
pub struct StorageOriginalNativeConstructionV1 {
    daemon_prefix: StorageDaemonPrefixV1,
    assembly: Option<StorageRuntimeAssemblyV1>,
    template_open: crate::guest_root_inventory::ProtectedGuestRootTemplateOpenV1,
    selected_template: Option<ProtectedGuestRootTemplateV1>,
    startup_configuration_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    catalog_observer_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    snapshot_metadata: crate::helper::StorageSnapshotMetadataStartupV1,
    snapshot_capture_result: Option<Result<(), ()>>,
    snapshot_current_result: Option<Result<(), StorageOriginalNativeConstructionClosedV1>>,
    startup_reconciliation: Option<Result<StorageRuntimeReadiness, StorageRuntimeError>>,
    startup_reconciliation_post: Option<Result<(), crate::activation::StorageOriginalWorkerStartupCauseV3>>,
    phase: OriginalNativeConstructionPhaseV1,
    startup: Option<crate::activation::StorageOriginalWorkerStartupV3>,
    legacy_executor: Option<SystemdZfsExecutor>,
    native_writer: Option<aos_sandbox_controller_domain::Journal>,
    native_trust: Option<crate::live_export_request_trust::StorageLiveExportRequestTrustV1>,
    native_ledger: Option<StorageNativeIssuanceLedgerV1>,
    operator_owner: Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
    runtime: Option<StorageBrokerRuntime>,
    composition: Option<crate::DormantStorageApplyCompositionV1>,
    first_cause: Option<OriginalNativeConstructionCauseV1>,
}

/// Reports that the original construction is closed; its real cause stays resident.
#[derive(Debug, thiserror::Error)]
#[error("original Storage native construction is closed; its cause and custody remain resident")]
pub struct StorageOriginalNativeConstructionClosedV1;

/// Borrows the same independently held request-trust owner from original construction.
///
/// This nonClone, private-field loan contains no caller pins or descriptor
/// selector. It supplies cryptographic provenance only; the concrete offer must
/// also rejoin its original writer, startup, peer, clock and measured root.
pub struct StorageOriginalNativeTrustLoanV1<'owner> {
    pub(crate) owner: &'owner crate::live_export_request_trust::StorageLiveExportRequestTrustV1,
}

/// Fences selected crossings before parent-held originals can unwind.
#[must_use]
pub struct StorageOriginalNativeUnwindFenceV1 {
    _private: (),
}

impl Drop for StorageOriginalNativeUnwindFenceV1 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

impl StorageOriginalNativeConstructionV1 {
    /// Parks the actual returned original startup without performing another observation.
    #[must_use]
    pub fn begin(startup: crate::activation::StorageOriginalWorkerStartupV3) -> Self {
        Self {
            phase: OriginalNativeConstructionPhaseV1::Captured,
            daemon_prefix: StorageDaemonPrefixV1::new(),
            assembly: Some(StorageRuntimeAssemblyV1::new()),
            template_open: crate::guest_root_inventory::ProtectedGuestRootTemplateOpenV1::new(),
            selected_template: None,
            startup_configuration_demand: None,
            catalog_observer_demand: None,
            snapshot_metadata: crate::helper::StorageSnapshotMetadataStartupV1::new(),
            snapshot_capture_result: None,
            snapshot_current_result: None,
            startup_reconciliation: None,
            startup_reconciliation_post: None,
            startup: Some(startup),
            legacy_executor: None,
            native_writer: None,
            native_trust: None,
            native_ledger: None,
            operator_owner: None,
            runtime: None,
            composition: None,
            first_cause: None,
        }
    }

    /// Reports whether this actual startup owns the distinct service envelope.
    #[must_use]
    pub fn has_storage_service_receiving_original_v1(&self) -> bool {
        self.startup.as_ref().is_some_and(|startup|
            startup.has_storage_service_receiving_original_v1())
    }

    /// Returns a nonauthorizing unwind fence for this already-held owner.
    pub fn unwind_fence(&self) -> StorageOriginalNativeUnwindFenceV1 {
        StorageOriginalNativeUnwindFenceV1 { _private: () }
    }

    /// Borrows the first concrete failure without cloning or formatting its cause.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let receiving_failure = || self.startup.as_ref()
            .and_then(|startup| startup.storage_receiving_failure_v1());
        let template_failure = self.template_open.failure().map(|cause| {
            let receiving_marker = cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>()
                || matches!(
                    cause.downcast_ref::<crate::guest_root_inventory::GuestRootInventoryErrorV1>(),
                    Some(crate::guest_root_inventory::GuestRootInventoryErrorV1::Receiving),
                );
            if receiving_marker {
                receiving_failure().unwrap_or(cause)
            } else {
                cause
            }
        });

        self.daemon_prefix.failure()
            .map(|cause| if cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>() {
                receiving_failure().unwrap_or(cause)
            } else {
                cause
            })
            .or_else(|| self.assembly.as_ref().and_then(|assembly| {
                assembly.configuration_before.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)
                    .or_else(|| assembly.broker_configuration_open.failure())
                    .or_else(|| assembly.configuration_capture.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.configuration_conversion.failure())
                    .or_else(|| assembly.configuration_conversion_result.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.configuration_post.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.bootstrap_before.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.bootstrap_open.failure())
                    .or_else(|| assembly.bootstrap_capture.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.bootstrap_post.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.state_startup.failure())
                    .or_else(|| assembly.initial_pin_failure_v1())
            })
                .map(|cause| if cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>() {
                    receiving_failure().unwrap_or(cause)
                } else { cause }))
            .or_else(|| self.assembly.as_ref().and_then(|assembly| {
                assembly.coordinator.as_ref().and_then(StorageAdmissionCoordinator::startup_mutation_primary_failure_v1)
                    .or_else(|| assembly.startup_mutation_entry.as_ref()
                        .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.resolver_configuration.as_ref()
                        .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.startup_authority.as_ref()
                        .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.startup_retirement.as_ref()
                        .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.coordinator.as_ref()
                        .and_then(StorageAdmissionCoordinator::startup_mutation_post_failure_v1))
                    .or_else(|| assembly.workspace_plan.as_ref()
                        .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
                    .or_else(|| assembly.workspace_startup.failure())
                    .or_else(|| assembly.issuance_startup.failure())
                    .or_else(|| assembly.trust_startup.failure())
            }).map(|cause| if cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>() {
                receiving_failure().unwrap_or(cause)
            } else { cause }))
            .or_else(|| self.runtime.as_ref().and_then(Self::runtime_startup_failure_v1))
            .or_else(|| self.startup_reconciliation.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.startup_reconciliation_post.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.snapshot_metadata.failure())
            .or(template_failure)
            .or_else(|| self.startup_configuration_demand.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.catalog_observer_demand.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(receiving_failure)
            .or_else(|| self.first_cause.as_ref().map(OriginalNativeConstructionCauseV1::source))
            .or_else(|| self.composition.as_ref().and_then(|composition|
                composition.runtime().original_held_first_cause()))
    }

    fn runtime_startup_failure_v1(runtime: &StorageBrokerRuntime) -> Option<&(dyn std::error::Error + 'static)> {
        runtime.startup_reconciliation.operator_policy_error.as_ref().map(|cause| {
            runtime.resolver_policy_directory_original.failure()
                .or_else(|| runtime.resolver_policy_read_original.failure())
                .unwrap_or(cause as &dyn std::error::Error)
        }).or_else(|| runtime.startup_reconciliation.failure(&runtime.coordinator, &runtime.helper))
            .map(|cause| {
                if cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>()
                    || matches!(cause.downcast_ref::<StorageRuntimeError>(), Some(StorageRuntimeError::Receiving))
                {
                    runtime.original_worker_startup.as_ref()
                        .and_then(crate::activation::StorageOriginalWorkerStartupV3::storage_receiving_failure_v1)
                        .unwrap_or(cause)
                } else { cause }
            })
            .or_else(|| runtime.coordinator.startup_mutation_failure_v1())
            .or_else(|| runtime.workspaces.as_ref()
                .and_then(ValidatedPendingStorageWorkspaceCatalogV1::startup_native_failure_v1))
            .or_else(|| runtime.receiving_inventory_worker_failure_v1())
            .or_else(|| runtime.original_held_first_cause())
    }

    /// Permanently closes the owner around a returned installed-caller failure.
    pub fn retain_service_failure(&mut self, cause: crate::service::StorageServiceError) {
        self.phase = OriginalNativeConstructionPhaseV1::Failed;
        if self.first_cause.is_none()
            && !self.composition.as_ref().is_some_and(|composition|
                composition.runtime().original_held_first_cause().is_some())
        {
            self.first_cause = Some(OriginalNativeConstructionCauseV1::Service(cause));
        }
    }

    /// Permanently closes a resident negative without replacing its real cause.
    pub fn close_resident(&mut self) {
        self.phase = OriginalNativeConstructionPhaseV1::Failed;
    }

    /// Loads the actual selected package before later construction effects.
    ///
    /// The actual receiving original joins argv9 and lends its SAME ledger to
    /// the shared scanner. Supported nonresource original callers retain their
    /// existing protected-template scope. Both keep the actual load on this
    /// already resident outer owner until the complete positive transfer.
    ///
    /// # Errors
    /// Refuses reentry or any original, template or accounting failure. Its
    /// original cause remains on this owner and the genuine Native original.
    pub fn observe_guest_root_template_once_v1(
        &mut self,
        package: &Path,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Captured {
            self.phase = OriginalNativeConstructionPhaseV1::Failed;
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let _crossing = self.unwind_fence();
        let result = (|| {
            let startup = self.startup.as_mut().ok_or(StorageOriginalNativeConstructionClosedV1)?;
            if startup.has_storage_service_receiving_original_v1() {
                let mut receiving = startup.borrow_storage_prepare_receiving_v1()
                    .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
                self.template_open.open_receiving_once_v1(&mut receiving, package)
                    .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            } else {
                self.template_open.open_legacy_once_v1(package)
                    .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.phase = OriginalNativeConstructionPhaseV1::Failed;
        }
        result
    }

    /// Borrows the actual observed template while later daemon gates run.
    ///
    /// # Errors
    /// Refuses absent positive observation, transfer or a closed construction.
    pub fn observed_guest_root_template_v1(
        &self,
    ) -> Result<&ProtectedGuestRootTemplateV1, StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Captured {
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        self.template_open.template().ok_or(StorageOriginalNativeConstructionClosedV1)
    }

    /// Moves the actually observed template after intervening gates succeeded.
    ///
    /// The attempt keeps its actual template through a later executor refusal.
    /// Runtime construction immediately parks it again before fallible startup.
    ///
    /// # Errors
    /// Refuses absent positive observation, reentry or a failed construction.
    pub fn take_observed_guest_root_template_once_v1(
        &mut self,
    ) -> Result<ProtectedGuestRootTemplateV1, StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Captured {
            self.phase = OriginalNativeConstructionPhaseV1::Failed;
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        match self.template_open.take_template_once_v1() {
            Some(template) => Ok(template),
            None => {
                self.phase = OriginalNativeConstructionPhaseV1::Failed;
                Err(StorageOriginalNativeConstructionClosedV1)
            }
        }
    }

    /// Constructs the same selected runtime once, retaining every returned native cut.
    ///
    /// # Errors
    ///
    /// Refuses reentry, absent provisioned names, changed genuine startup, role
    /// archives, history, active holds or any runtime gate. The original cause
    /// remains in this owner; failure does not drop or reopen its writer.
    #[allow(clippy::too_many_arguments)]
    pub fn open_once(
        &mut self,
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
        operator_credentials: Option<&crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1>,
        template: ProtectedGuestRootTemplateV1,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if self.legacy_executor.is_some() {
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let _crossing = self.unwind_fence();
        let mut executor = Some(executor);
        let outcome = self.open_for_once_v1(authority_directory, bootstrap_directory, state_directory,
            resolver_policy_directory, identity_pool, zfs_executable,
            StorageStartupExecutorV1::Legacy(&mut executor), OriginalStartupProfileV1::Held(key),
            operator_credentials, template);
        self.legacy_executor = executor;
        outcome
    }

    /// Opens the measured ordinary receiver using its actual resident executor.
    ///
    /// # Errors
    /// Retains first startup/native failures and refuses absent prefix payment.
    #[allow(clippy::too_many_arguments)]
    pub fn open_observed_ordinary_once_v1(
        &mut self, authority_directory: &Path, bootstrap_directory: &Path,
        state_directory: &Path, resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1, zfs_executable: PathBuf,
        executor: &mut Option<SystemdZfsExecutor>,
        operator_credentials: Option<&crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1>,
        template: ProtectedGuestRootTemplateV1,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        self.open_for_once_v1(authority_directory, bootstrap_directory, state_directory,
            resolver_policy_directory, identity_pool, zfs_executable,
            StorageStartupExecutorV1::Receiving(executor), OriginalStartupProfileV1::Ordinary,
            operator_credentials, template)
    }

    /// Opens the measured held receiver using its actual resident executor/key.
    ///
    /// # Errors
    /// Retains first startup/native failures and refuses a different paid profile.
    #[allow(clippy::too_many_arguments)]
    pub fn open_observed_held_once_v1(
        &mut self, authority_directory: &Path, bootstrap_directory: &Path,
        state_directory: &Path, resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1, zfs_executable: PathBuf,
        executor: &mut Option<SystemdZfsExecutor>,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
        operator_credentials: Option<&crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1>,
        template: ProtectedGuestRootTemplateV1,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        self.open_for_once_v1(authority_directory, bootstrap_directory, state_directory,
            resolver_policy_directory, identity_pool, zfs_executable,
            StorageStartupExecutorV1::Receiving(executor), OriginalStartupProfileV1::Held(key),
            operator_credentials, template)
    }

    fn open_for_once_v1(
        &mut self,
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: StorageStartupExecutorV1<'_>,
        profile: OriginalStartupProfileV1<'_>,
        operator_credentials: Option<&crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1>,
        template: ProtectedGuestRootTemplateV1,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Captured {
            self.phase = OriginalNativeConstructionPhaseV1::Failed;
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        self.phase = OriginalNativeConstructionPhaseV1::Opening;
        self.selected_template = Some(template);
        let _crossing = self.unwind_fence();
        let result = (|| {
            if matches!(&executor, StorageStartupExecutorV1::Receiving(slot) if slot.is_none()) {
                return Err(StorageRuntimeError::Receiving);
            }
            self.startup.as_mut().ok_or(StorageRuntimeError::Recovery)?
                .recheck().map_err(|cause| {
                    self.first_cause = Some(OriginalNativeConstructionCauseV1::Startup(cause));
                    StorageRuntimeError::Recovery
                })?;
            if self.has_storage_service_receiving_original_v1() {
                if !self.daemon_prefix.matches(profile.receiving_profile()) {
                    return Err(StorageRuntimeError::Receiving);
                }
                self.require_daemon_prefix_paid_current_v1()
                    .map_err(|_| StorageRuntimeError::Receiving)?;
                if state_directory != Path::new("/var/lib/aos/sandbox-storage") {
                    return Err(StorageRuntimeError::Receiving);
                }
                let template = self.selected_template.as_ref().ok_or(StorageRuntimeError::Receiving)?;
                let mut receiving = self.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?
                    .borrow_storage_prepare_receiving_v1().map_err(|_| StorageRuntimeError::Receiving)?;
                receiving.require_storage_authority_directory_v1(authority_directory)
                    .map_err(|_| StorageRuntimeError::Receiving)?;
                receiving.require_storage_startup_directories_v1(bootstrap_directory, resolver_policy_directory)
                    .map_err(|_| StorageRuntimeError::Receiving)?;
                receiving.require_guest_root_template_v1(template.root(), template.root_tree_digest())
                    .map_err(|_| StorageRuntimeError::Receiving)?;
            }
            let selection = match operator_credentials {
                Some(credentials) => operator_startup::OperatorStartupSelectionV4::Existing(credentials),
                None => operator_startup::OperatorStartupSelectionV4::Ordinary,
            };
            let mut assembly = self.assembly.take().ok_or(StorageRuntimeError::Receiving)?;
            // Declared after the actual assembly: unwind aborts before any of
            // these retained native owners can be destroyed as closure locals.
            let _assembly_crossing = self.unwind_fence();
            let outcome = StorageBrokerRuntime::open_root_owned_selected_native_v4(
                authority_directory, bootstrap_directory, state_directory,
                resolver_policy_directory, identity_pool, zfs_executable, executor,
                StorageApplyConstructionV1::DormantProtectedWorker, selection,
                &mut assembly, Some((&mut *self, profile)),
            );
            self.assembly = Some(assembly);
            let outcome = outcome?;
            let StorageStartupOutcomeV4::Runtime(runtime, owner) = outcome else {
                return Err(StorageRuntimeError::Recovery);
            };
            self.operator_owner = owner;
            self.composition = Some(crate::DormantStorageApplyCompositionV1::from_runtime(runtime)
                .with_guest_root_template(match self.selected_template.take() {
                    Some(template) => template,
                    None => std::process::abort(),
                }));
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.phase = OriginalNativeConstructionPhaseV1::Ready;
                Ok(())
            }
            Err(cause) => {
                self.phase = OriginalNativeConstructionPhaseV1::Failed;
                if self.first_cause.is_none() {
                    self.first_cause = Some(OriginalNativeConstructionCauseV1::Runtime(cause));
                }
                Err(StorageOriginalNativeConstructionClosedV1)
            }
        }
    }

    /// Lends the same completed composition and optional fourth writer.
    ///
    /// # Errors
    ///
    /// Refuses a partial, failed or reentered owner. No field is taken on refusal.
    pub fn ready_parts(&mut self) -> Result<(
        &mut crate::DormantStorageApplyCompositionV1,
        &mut Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
        StorageOriginalNativeTrustLoanV1<'_>,
    ), StorageOriginalNativeConstructionClosedV1> {
        let (composition, owner, trust, _service) = self.ready_service_parts_v1()?;
        Ok((composition, owner, trust))
    }

    /// Lends the completed ordinary owner without weakening native interests.
    ///
    /// # Errors
    /// Refuses a partial/failed construction or held profile with required Trust.
    pub fn ordinary_ready_parts_v1(&mut self) -> Result<(
        &mut crate::DormantStorageApplyCompositionV1,
        &mut Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
    ), StorageOriginalNativeConstructionClosedV1> {
        let (composition, owner, _service) = self.ordinary_ready_service_parts_v1()?;
        Ok((composition, owner))
    }

    /// Lends the completed held composition and its genuine service destination.
    ///
    /// # Errors
    /// Refuses failed/partial owners or a missing required Trust writer.
    pub fn ready_service_parts_v1(&mut self) -> Result<(
        &mut crate::DormantStorageApplyCompositionV1,
        &mut Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
        StorageOriginalNativeTrustLoanV1<'_>,
        StorageOriginalServiceSlotV1<'_>,
    ), StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Ready || self.first_cause.is_some()
            || self.startup.is_some()
            || self.composition.as_ref().is_some_and(|composition| composition.runtime().requires_reopen())
        {
            self.phase = OriginalNativeConstructionPhaseV1::Failed;
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let composition = self.composition.as_mut().ok_or(StorageOriginalNativeConstructionClosedV1)?;
        let owner = self.native_trust.as_ref().ok_or(StorageOriginalNativeConstructionClosedV1)?;
        Ok((composition, &mut self.operator_owner, StorageOriginalNativeTrustLoanV1 { owner },
            StorageOriginalServiceSlotV1 { startup: &mut self.startup }))
    }

    /// Lends the completed ordinary composition and its genuine destination.
    ///
    /// # Errors
    /// Refuses failed/partial owners, occupied destination or a held Trust route.
    pub fn ordinary_ready_service_parts_v1(&mut self) -> Result<(
        &mut crate::DormantStorageApplyCompositionV1,
        &mut Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
        StorageOriginalServiceSlotV1<'_>,
    ), StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Ready || self.first_cause.is_some()
            || self.native_trust.is_some() || self.startup.is_some()
            || self.composition.as_ref().is_some_and(|composition| composition.runtime().requires_reopen())
        {
            self.phase = OriginalNativeConstructionPhaseV1::Failed;
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let composition = self.composition.as_mut().ok_or(StorageOriginalNativeConstructionClosedV1)?;
        Ok((composition, &mut self.operator_owner,
            StorageOriginalServiceSlotV1 { startup: &mut self.startup }))
    }

    pub(crate) fn require_native_open(&mut self) -> Result<(), crate::native_issuance::StorageNativeIssuanceErrorV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Opening
            || self.native_writer.is_some() || self.native_trust.is_some() || self.native_ledger.is_some()
        {
            return Err(crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict);
        }
        self.phase = OriginalNativeConstructionPhaseV1::NativeOpening;
        self.startup.as_mut().ok_or(crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict)?
            .recheck().map_err(|cause| {
                self.first_cause = Some(OriginalNativeConstructionCauseV1::Startup(cause));
                crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict
            })
    }

    pub(crate) fn park_native_writer(&mut self, journal: aos_sandbox_controller_domain::Journal) {
        self.native_writer = Some(journal);
    }

    pub(crate) fn park_native_trust(&mut self, trust: crate::live_export_request_trust::StorageLiveExportRequestTrustV1) {
        self.native_trust = Some(trust);
    }

    pub(crate) fn take_native_writer(&mut self) -> Result<aos_sandbox_controller_domain::Journal,
        crate::native_issuance::StorageNativeIssuanceErrorV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::NativeOpening
            || self.native_writer.is_none() || self.native_trust.is_none()
        {
            return Err(crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict);
        }
        match self.native_writer.take() {
            Some(journal) => Ok(journal),
            None => std::process::abort(),
        }
    }

    pub(crate) fn park_native_ledger(&mut self, ledger: StorageNativeIssuanceLedgerV1) {
        self.native_ledger = Some(ledger);
    }
}

impl Drop for StorageOriginalNativeConstructionV1 {
    fn drop(&mut self) {
        // Even Ready retains original session/interest debt. There is no local
        // completion, loss-of-FD, timeout or empty-population discharge here.
        std::process::abort();
    }
}

/// Describes whether protected policy permits production catalog preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePrepareReadiness {
    /// Deployment intentionally omitted the external resolver-policy catalog.
    Unconfigured,
    /// Configured policy was missing, insecure, malformed, or rolled back.
    PolicyInvalid,
    /// A complete trusted policy publication was durably admitted.
    Ready,
}

/// Retains one nonauthorizing physical sample joined to an unchanged protected cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageHeldSnapshotReadbackV1 {
    /// The unchanged independently recovered protected catalog cut.
    pub(crate) cut: StorageHeldSnapshotCatalogCutV1,
    /// The protected-policy-constrained pool GUID observed on both sides of the hold readback.
    pub(crate) pool_guid: u64,
    /// The exact complete protected policy publication bracketing this sample.
    pub(crate) policy_head: StorageResolverPolicyCatalogBindingV1,
    /// The digest of exact worker request, ZFS output, and both pool rows.
    pub(crate) physical_observation_digest: ObjectDigest,
    /// Exact physical portable bytes measured in the confined reader.
    pub(crate) measured_tree: crate::process::HeldSnapshotReaderObservationV1,
    /// Fresh ZFS hold/GUID readback after the detached measurement quiesced.
    pub(crate) post_measurement_observation_digest: ObjectDigest,
}

/// Pins the original measured detached mount for readback and live Storage escrow.
pub(crate) struct StorageHeldSnapshotReadbackWithMountV1 {
    pub(crate) readback: StorageHeldSnapshotReadbackV1,
    mount: OwnedFd,
    #[cfg(test)]
    synthetic_fixture: Option<[u8; 16]>,
}

impl StorageHeldSnapshotReadbackWithMountV1 {
    /// Rechecks that the retained mount is the exact read-only measured root.
    pub(crate) fn verify_mount(&self) -> Result<(), StorageRuntimeError> {
        #[cfg(test)]
        if self.synthetic_fixture.is_some() {
            let observed = fstat(self.mount.as_fd()).map_err(|_| StorageRuntimeError::Recovery)?;
            if observed.st_dev != self.readback.measured_tree.root_device
                || observed.st_ino != self.readback.measured_tree.root_inode
                || MountId::from_fd(self.mount.as_fd())
                    .map_err(|_| StorageRuntimeError::Recovery)?
                    .get()
                    != self.readback.measured_tree.mount_id
            {
                return Err(StorageRuntimeError::Recovery);
            }
            return Ok(());
        }
        crate::process::verify_received_mount_fd(
            self.mount.as_fd(),
            &self.readback.measured_tree,
            self.readback.pool_guid,
        )
        .map_err(|_| StorageRuntimeError::Recovery)
    }

    /// Observes this retained FD, rather than reopening or reconstructing its root.
    ///
    /// # Errors
    ///
    /// Rejects changed measured mount identity/flags, non-O_PATH semantics, or invalid boot.
    pub(crate) fn observe_root(
        &self,
    ) -> Result<aos_sandbox_source_provider_protocol::SourceRootObservationV1, StorageRuntimeError>
    {
        self.verify_mount()?;
        let flags = rustix::fs::fcntl_getfl(self.mount.as_fd())
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !flags.contains(OFlags::PATH) {
            return Err(StorageRuntimeError::Recovery);
        }
        let stat = fstat(self.mount.as_fd()).map_err(|_| StorageRuntimeError::Recovery)?;
        let mount_id =
            MountId::from_fd(self.mount.as_fd()).map_err(|_| StorageRuntimeError::Recovery)?;
        let boot_id = KernelBootId::current()
            .map_err(|_| StorageRuntimeError::Recovery)?
            .into_bytes();
        #[cfg(test)]
        let boot_id = self.synthetic_fixture.unwrap_or(boot_id);
        aos_sandbox_source_provider_protocol::SourceRootObservationV1::new(
            boot_id,
            stat.st_dev,
            stat.st_ino,
            mount_id.get(),
            true,
            true,
            true,
        )
        .map_err(|_| StorageRuntimeError::Recovery)
    }
}

fn identity_observation_matches_snapshot_metadata(
    observed: crate::held_snapshot_tree::HeldSnapshotIdentityObservationV1,
    metadata: CheckedSnapshotMetadataRecordV1,
) -> bool {
    observed.root_attributes == metadata.root_attributes()
        && observed.maximum_portable_uid == metadata.maximum_portable_uid()
        && observed.maximum_portable_gid == metadata.maximum_portable_gid()
        && observed.distinct_inode_count == metadata.distinct_inode_count()
        && observed.directory_entry_count == metadata.directory_entry_count()
        && observed.identity_tree_digest == metadata.identity_tree_digest()
}

/// Reports one synchronous authorized mutation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRuntimeMutationOutcome {
    /// Exact postcondition evidence and physical catalog state were committed.
    Committed(CommittedStorageResultV1),
    /// The exact expired or strictly superseded intent was retired before mutation.
    Aborted {
        /// Deterministic identity of the retired mutation intent.
        mutation_digest: ObjectDigest,
    },
    /// No mutation was retried; later observation is still required.
    ObservationRequired {
        /// Current durable crash phase.
        phase: DurableStoragePhase,
        /// Exact pending mutation commitment.
        mutation_digest: ObjectDigest,
    },
}

/// Reports durable progress of one coordinated lifecycle dataset snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicDatasetSnapshotMutationOutcomeV1 {
    /// The exact whole-group readback was durably committed.
    Committed {
        /// Protected grouped-program commitment.
        program: ObjectDigest,
        /// Whole-group physical GUID observation commitment.
        observation: ObjectDigest,
    },
    /// The effect may have occurred and recovery must only observe the group.
    ObservationRequired {
        /// Protected grouped-program commitment retained in durable custody.
        program: ObjectDigest,
    },
    /// A durable Prepared record exists but no effect was dispatched.
    PreparedBeforeEffect {
        /// Protected grouped-program commitment retained before mutation.
        program: ObjectDigest,
    },
}

/// Reports one authorized workspace root-pin repair request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspacePinRepairExecutionOutcomeV1 {
    /// Exact worker postcondition evidence satisfied the fresh repair attempt.
    Satisfied,
    /// The exact operation is already durable and remains observation-only.
    ObservationRequired,
}

fn operator_sidecar_failure(
    error: crate::operator_recovery::StorageOperatorRecoveryErrorV1,
) -> StorageRuntimeError {
    match error {
        crate::operator_recovery::StorageOperatorRecoveryErrorV1::Journal(_) => {
            StorageRuntimeError::ReopenRequired
        }
        crate::operator_recovery::StorageOperatorRecoveryErrorV1::Binding
        | crate::operator_recovery::StorageOperatorRecoveryErrorV1::Pending => {
            StorageRuntimeError::Recovery
        }
    }
}

/// Owns the sole Storage coordinator and fixed worker helper.
pub struct StorageBrokerRuntime {
    // Negative effect/health reservoirs abort before ordinary Runtime fields
    // can release their entered failed native prefixes.
    guest_root_publication: Option<Box<guest_root_publication::GuestRootPublicationOriginalV2>>,
    guest_root_health: Option<Box<guest_root_health::GuestRootStartupHealthOriginalV2>>,
    guest_root_health_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    guest_root_health_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    guest_root_publication_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    guest_root_publication_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    root_export_original: Option<Box<root_export_original::RootExportOriginalV2>>,
    root_export_geometry: Option<Result<root_export_original::RootExportRepresentationV2, aos_sandbox_model::AccountingError>>,
    coordinator: StorageAdmissionCoordinator,
    workspaces: Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    configuration_binding: ObjectDigest,
    broker_instance_id: [u8; 16],
    held_reader_state_directory: Option<PathBuf>,
    native_issuance: Option<StorageNativeIssuanceLedgerV1>,
    native_escrow: native_acquire::StorageNativeEscrowV2,
    original_worker_startup: Option<crate::activation::StorageOriginalWorkerStartupV3>,
    original_service_lent: bool,
    startup_reconciliation: startup_reconciliation::StartupReconciliationOriginalV1,
    receiving_inventory_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    receiving_prepare_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    receiving_prepare_result: Option<Result<StorageCatalogPreparationOutcomeV1, StorageRuntimeError>>,
    receiving_prepare_clocks: [Option<Result<RawPairedClockSample, aos_sandbox_controller_domain::hierarchy::genesis_profile::SourceGenesisErrorV1>>; 2],
    receiving_prepare_policy_read: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1,
    receiving_inventory_catalog: Option<Box<inventory_catalog::InventoryCatalogOriginalV1>>,
    original_measurements: original_held_measurement::ResidentOriginalMeasurementsV3,
    #[cfg(target_os = "linux")]
    git_coverage: Option<git_coverage::StorageGitCoverageV1>,
    #[cfg(test)]
    native_fixture: Option<native_acquire::SyntheticNativeRuntimeV2>,
    #[cfg(test)]
    native_readback_fixture_uid: Option<u32>,
    pin_contract: ZfsHelperContract,
    pin_io: Box<dyn WorkspacePinRuntimeIo + Send>,
    helper: StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>,
    readiness: StorageRuntimeReadiness,
    apply_readiness: StorageApplyReadiness,
    resolver_policies: Option<ProtectedStorageResolverPolicyDirectoryV1>,
    resolver_policy_directory_original: crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1,
    resolver_policy_read_original: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1,
    prepare_readiness: StoragePrepareReadiness,
    worker_dispatch: RepairWorkerDispatchGate,
    operator_startup: Option<operator_startup::DeferredOperatorStartupV4>,
    #[cfg(test)]
    fail_repair_completion_commit_for_test: bool,
    canary_export: canary_export_held::CanaryExportHeldV1,
}

/// Borrows the parent destination for one original service interval.
///
/// The constructor is private to a completed original Construction. The same
/// startup owner moves out of Runtime before I/O and stays in the parent slot
/// through all failures. Positive handback moves it into the same Runtime; this
/// exposes neither an account nor a constructor for receiving authority.
#[must_use]
pub struct StorageOriginalServiceSlotV1<'owner> {
    startup: &'owner mut Option<crate::activation::StorageOriginalWorkerStartupV3>,
}

impl Drop for StorageOriginalServiceSlotV1<'_> {
    fn drop(&mut self) {
        if self.startup.is_some() {
            // A failure or unwind cannot destroy the same genuine original.
            std::process::abort();
        }
    }
}

impl StorageOriginalServiceSlotV1<'_> {
    /// Moves the same original into its resident parent destination before I/O.
    ///
    /// # Errors
    /// Refuses an occupied destination, a loaned/legacy Runtime, incomplete
    /// disposal or actual original currentness failure. No owner drops on Err.
    pub fn lend_original_v1(
        &mut self,
        composition: &mut crate::DormantStorageApplyCompositionV1,
    ) -> Result<(), StorageRuntimeError> {
        let runtime = composition.runtime_mut_for_service_handoff_v1();
        if self.startup.is_some() || runtime.original_service_lent {
            return Err(StorageRuntimeError::Receiving);
        }
        let startup = runtime.original_worker_startup.as_mut().ok_or(StorageRuntimeError::Receiving)?;
        startup.require_service_handoff_v1().map_err(|_| StorageRuntimeError::Receiving)?;
        startup.recheck().map_err(|_| StorageRuntimeError::Receiving)?;
        *self.startup = runtime.original_worker_startup.take();
        runtime.original_service_lent = true;
        Ok(())
    }

    /// Borrows only the actual original already moved into this parent slot.
    ///
    /// # Errors
    /// Refuses an absent or failed receiving original; no replacement is built.
    pub fn borrow_receiving_v1(&mut self)
        -> Result<aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>, aos_sandbox_controller_domain::StorageReceivingClosedV1>
    {
        self.startup.as_mut().ok_or(aos_sandbox_controller_domain::StorageReceivingClosedV1)?
            .borrow_storage_prepare_receiving_v1()
    }

    /// Borrows the retained original cause while the actual owner is lent.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.startup.as_ref().and_then(
            crate::activation::StorageOriginalWorkerStartupV3::storage_receiving_failure_v1,
        )
    }

    /// Borrows the actual original cause before or after its owning move.
    #[must_use]
    pub fn failure_with_composition<'owner>(
        &'owner self,
        composition: &'owner crate::DormantStorageApplyCompositionV1,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        self.failure().or_else(|| composition.runtime().original_worker_startup.as_ref()
            .and_then(crate::activation::StorageOriginalWorkerStartupV3::storage_receiving_failure_v1))
    }

    /// Returns the same owner after real positive disposal and pure parking.
    ///
    /// This is an infallible owning handoff, with no late observation or new
    /// admission. Calling it without the actual positive boundary aborts while
    /// both the Runtime and original remain resident.
    pub fn return_after_positive_v1(&mut self, composition: &mut crate::DormantStorageApplyCompositionV1) {
        let runtime = composition.runtime_mut_for_service_handoff_v1();
        if !runtime.original_service_lent || runtime.original_worker_startup.is_some()
            || !self.startup.as_ref().is_some_and(|startup| startup.require_service_handoff_v1().is_ok())
        {
            std::process::abort();
        }
        runtime.original_worker_startup = self.startup.take();
        runtime.original_service_lent = false;
    }
}

/// Holds one checked Runtime reconciliation and its actual Native Sent token.
///
/// The caller keeps its remaining Session/request/response owners through all
/// fallible posts, then disposes those positive carriers before completion.
/// The same State/Workspace journals and domain effects remain resident.
#[must_use]
pub struct StorageRuntimeLifecycleDisposalV1<'runtime, 'phase, 'cut, 'original> {
    runtime: &'runtime mut StorageBrokerRuntime,
    native: aos_sandbox_controller_domain::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
}

impl StorageRuntimeLifecycleDisposalV1<'_, '_, '_, '_> {
    /// Disposes checked upper carriers before completing their Native operation.
    ///
    /// No I/O, allocation, fallible check or authority decision follows the
    /// first actual disposal. Persistent journal/history accounting is kept.
    pub fn complete_after_disposal_v1(self) {
        self.runtime.startup_reconciliation.transactions.complete_positive_disposal();
        self.runtime.helper.complete_recovery_disposition_v1();
        self.runtime.coordinator.complete_recovery_disposition_v1();
        self.runtime.startup_reconciliation = startup_reconciliation::StartupReconciliationOriginalV1::new();
        if let Some(mut publication) = self.runtime.guest_root_publication.take() {
            publication.dispose_after_positive_posts_v2();
            drop(publication);
        }
        self.runtime.guest_root_publication_demand = None;
        self.runtime.guest_root_publication_payment = None;
        self.native.complete_after_disposal_v1();
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn recheck_execution_output_receiving_v1(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<(), StorageRuntimeError> {
        let startup = self.original_worker_startup.as_mut().ok_or(StorageRuntimeError::Receiving)?;
        let mut receiving = startup.borrow_storage_prepare_receiving_v1()
            .map_err(|_| StorageRuntimeError::Receiving)?;
        output.recheck_receiving_v1(&mut receiving).map_err(|_| StorageRuntimeError::Receiving)
    }


    fn require_git_coverage_new_admission_v1(&self) -> Result<(), StorageRuntimeError> {
        #[cfg(target_os = "linux")]
        if self.git_coverage.is_some() || self.coordinator.git_coverage_denies_new_v1() {
            return Err(StorageRuntimeError::Recovery);
        }
        Ok(())
    }

    /// Retains selected prefix DATA but never authorizes creation or dispatch.
    pub(crate) fn observe_canary_export_original(
        &mut self,
        connection: aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        verifier: &crate::peer::HostRootExportPeerVerifier,
    ) {
        if !self.canary_export.is_unused() {
            // An additional connection cannot replace the resident originals.
            return;
        }
        self.canary_export.park_original(connection, record);
        self.canary_export.observe_original(
            &self.coordinator,
            self.native_issuance.as_mut(),
            &self.worker_dispatch,
            &self.broker_instance_id,
            verifier,
        );
    }

    /// Runs only the admitted, resident canary association producer.
    ///
    /// The root-export caller selects this before its Legacy accept/receive.
    /// A selected refusal cannot fall back or substitute packet DATA for the
    /// original startup. Completion still sends no gen0, ACK or root permit.
    pub(crate) fn serve_canary_export_selected_v2(
        &mut self,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        verifier: &crate::peer::HostRootExportPeerVerifier,
        template: &ProtectedGuestRootTemplateV1,
    ) {
        if !self.canary_export.receive_selected_original_v2(
            listener, self.original_worker_startup.as_mut(), verifier,
        ) {
            return;
        }
        let inventory = (|| {
            let deadline = self.canary_export.selected_deadline_v2()
                .ok_or(StorageRuntimeError::Recovery)?;
            let now = boottime_now_nanoseconds()?;
            let cutoff = guest_root_inventory_cutoff(now, deadline)?;
            self.inventory_resources(deadline, cutoff)
        })();
        if !self.canary_export.park_selected_inventory_v2(inventory, template, &self.broker_instance_id) {
            self.canary_export.finish_selected_runtime_observations_v2(
                &self.coordinator, self.native_issuance.as_mut(),
                self.original_worker_startup.as_mut(), &self.worker_dispatch, verifier,
            );
            return;
        }
        if !self.canary_export.prepare_selected_cut_v2(
            &self.coordinator, self.native_issuance.as_mut(),
            &self.worker_dispatch, &self.broker_instance_id,
        ) {
            self.canary_export.finish_selected_runtime_observations_v2(
                &self.coordinator, self.native_issuance.as_mut(),
                self.original_worker_startup.as_mut(), &self.worker_dispatch, verifier,
            );
            return;
        }
        self.canary_export.complete_selected_bootstrap_v2(
            &mut self.coordinator, self.native_issuance.as_mut(),
            self.original_worker_startup.as_mut(), &self.worker_dispatch, verifier,
        );
    }

    pub(crate) fn install_original_worker_startup(
        &mut self,
        mut startup: crate::activation::StorageOriginalWorkerStartupV3,
    ) -> Result<(), crate::activation::StorageOriginalWorkerStartupErrorV3> {
        use crate::activation::{
            StorageOriginalWorkerStartupCauseV3, StorageOriginalWorkerStartupErrorV3,
        };

        if self.original_worker_startup.is_some() || self.original_service_lent {
            return Err(StorageOriginalWorkerStartupErrorV3::retain_closed(
                StorageOriginalWorkerStartupCauseV3::Closed,
                startup,
            ));
        }
        if let Err(cause) = startup.recheck() {
            return Err(StorageOriginalWorkerStartupErrorV3::retain_closed(
                cause,
                startup,
            ));
        }
        self.original_worker_startup = Some(startup);
        Ok(())
    }

    /// Reobserves one catalogued hold and measures its immutable bytes.
    ///
    /// Both workers must quiesce while Storage retains its journal cut. A
    /// failed or lost reply is never replayed. Neither worker has signing
    /// authority; this result must not be interpreted as a SourceRoot receipt.
    ///
    /// # Errors
    ///
    /// Rejects stale catalog custody, changed protected heads,
    /// physical mismatch, worker faults, and unproven worker quiescence.
    pub(crate) fn observe_held_snapshot_readback(
        &mut self,
        selector: StorageHeldSnapshotSelectorV1,
    ) -> Result<StorageHeldSnapshotReadbackV1, StorageRuntimeError> {
        let (readback, mount) = self.observe_held_snapshot_readback_inner(selector, false)?;
        if mount.is_some() {
            return Err(StorageRuntimeError::Recovery);
        }
        Ok(readback)
    }

    fn observe_held_snapshot_readback_inner(
        &mut self,
        selector: StorageHeldSnapshotSelectorV1,
        retain_mount: bool,
    ) -> Result<(StorageHeldSnapshotReadbackV1, Option<OwnedFd>), StorageRuntimeError> {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !self.readiness.permits_catalog_methods() {
            return Err(StorageRuntimeError::Recovery);
        }
        let initial = self
            .coordinator
            .held_snapshot_catalog_cut(selector)
            .map_err(StorageRuntimeError::Admission)?;
        // The worker's physical pool must be chosen by protected Storage policy,
        // never by the request that selected the catalogued hold.
        let policies = self
            .resolver_policies
            .as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        let current_policy = policies.load().map_err(|_| StorageRuntimeError::Recovery)?;
        let policy_head = current_policy
            .binding()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let expected_pool_guid = current_policy
            .expected_pool_guid_for_root(initial.snapshot.dataset().root())
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let binding = HeldSnapshotWorkerBindingV1 {
            pool_guid: expected_pool_guid,
            catalog: initial.catalog,
            authority_sequence: initial.authority_sequence,
            nonce: random_challenge()?,
        };
        let (pool_guid, digest) = classify_held_snapshot_worker_result(
            &mut self.readiness,
            self.helper
                .observe_held_snapshot(&initial.snapshot, selector.hold_id, binding),
        )?;
        if pool_guid != expected_pool_guid {
            return Err(StorageRuntimeError::Recovery);
        }

        // The reader must exit before Storage accepts the second hold and
        // final protected cut. The versioned path keeps only its verified
        // read-only mount FD alive across those checks.
        let mut reader = crate::process::SystemdHeldSnapshotReaderV1::new(
            crate::process::open_cgroup_root().map_err(|_| StorageRuntimeError::Recovery)?,
            self.held_reader_state_directory
                .as_deref()
                .ok_or(StorageRuntimeError::Recovery)?,
        )
        .map_err(|_| StorageRuntimeError::Recovery)?;
        let nonce = random_challenge()?;
        let measurement = if retain_mount {
            reader
                .measure_with_mount(
                    &initial.snapshot,
                    expected_pool_guid,
                    initial.materialized_state_digest,
                    nonce,
                )
                .map(|(measured, mount)| (measured, Some(mount)))
        } else {
            reader
                .measure(
                    &initial.snapshot,
                    expected_pool_guid,
                    initial.materialized_state_digest,
                    nonce,
                )
                .map(|measured| (measured, None))
        };
        let (measured_tree, mount) = match measurement {
            Ok(measured) => measured,
            Err(ZfsWorkerError::Quiescence(_)) => {
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
                return Err(StorageRuntimeError::ReopenRequired);
            }
            Err(_) => return Err(StorageRuntimeError::Recovery),
        };
        let post_binding = HeldSnapshotWorkerBindingV1 {
            nonce: random_challenge()?,
            ..binding
        };
        let (post_pool_guid, post_measurement_observation_digest) =
            classify_held_snapshot_worker_result(
                &mut self.readiness,
                self.helper.observe_held_snapshot(
                    &initial.snapshot,
                    selector.hold_id,
                    post_binding,
                ),
            )?;
        if post_pool_guid != expected_pool_guid {
            return Err(StorageRuntimeError::Recovery);
        }

        let final_cut = self
            .coordinator
            .held_snapshot_catalog_cut(selector)
            .map_err(StorageRuntimeError::Admission)?;
        initial
            .ensure_unchanged(&final_cut)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let final_policy = policies.load().map_err(|_| StorageRuntimeError::Recovery)?;
        if final_policy
            .binding()
            .map_err(|_| StorageRuntimeError::Recovery)?
            != policy_head
            || final_policy
                .expected_pool_guid_for_root(final_cut.snapshot.dataset().root())
                .map_err(|_| StorageRuntimeError::Recovery)?
                != expected_pool_guid
        {
            return Err(StorageRuntimeError::Recovery);
        }
        if !identity_observation_matches_snapshot_metadata(
            measured_tree.identity,
            final_cut.metadata,
        ) {
            return Err(StorageRuntimeError::Recovery);
        }
        if let Some(descriptor) = mount.as_ref() {
            crate::process::verify_received_mount_fd(
                descriptor.as_fd(),
                &measured_tree,
                expected_pool_guid,
            )
            .map_err(|_| StorageRuntimeError::Recovery)?;
        }
        Ok((
            StorageHeldSnapshotReadbackV1 {
                cut: final_cut,
                pool_guid,
                policy_head,
                physical_observation_digest: digest,
                measured_tree,
                post_measurement_observation_digest,
            },
            mount,
        ))
    }

    /// Checks a native Provider row against Storage's unchanged protected cut and measured bytes.
    ///
    /// This private result carries no root descriptor or signing authority. A
    /// future authenticated Storage carrier may use it only as input to a
    /// separate receipt and descriptor-custody protocol; it cannot open Acquire.
    ///
    /// # Errors
    ///
    /// Rejects a stale or mismatched claim, or any held-snapshot readback failure.
    pub(crate) fn observe_native_held_snapshot_claim(
        &mut self,
        claim: &ZfsHeldSnapshotProofV1,
    ) -> Result<StorageHeldSnapshotReadbackV1, StorageRuntimeError> {
        let selector = StorageHeldSnapshotSelectorV1::from_native_claim(claim)?;
        let readback = self.observe_held_snapshot_readback(selector)?;
        if !readback.cut.matches_native_claim(
            claim,
            readback.pool_guid,
            readback.measured_tree.content_digest,
            readback.measured_tree.mounted_snapshot_guid,
        ) {
            return Err(StorageRuntimeError::Admission(StorageBrokerError::Request));
        }
        Ok(readback)
    }

    /// Retains one read-only mount while joining a native claim to Storage's final cut.
    pub(crate) fn observe_native_held_snapshot_claim_with_mount(
        &mut self,
        claim: &ZfsHeldSnapshotProofV1,
    ) -> Result<StorageHeldSnapshotReadbackWithMountV1, StorageRuntimeError> {
        let selector = StorageHeldSnapshotSelectorV1::from_native_claim(claim)?;
        let (readback, mount) = self.observe_held_snapshot_readback_inner(selector, true)?;
        if !readback.cut.matches_native_claim(
            claim,
            readback.pool_guid,
            readback.measured_tree.content_digest,
            readback.measured_tree.mounted_snapshot_guid,
        ) {
            return Err(StorageRuntimeError::Admission(StorageBrokerError::Request));
        }
        let mount = mount.ok_or(StorageRuntimeError::Recovery)?;
        let held = StorageHeldSnapshotReadbackWithMountV1 {
            readback,
            mount,
            #[cfg(test)]
            synthetic_fixture: None,
        };
        held.verify_mount()?;
        Ok(held)
    }

    pub(crate) fn prepare_lifecycle_atomic_snapshot(
        &self,
        plan: &aos_sandbox_controller_domain::lifecycle::LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<crate::DormantAtomicDatasetSnapshotV1, aos_sandbox_controller_domain::lifecycle::LifecyclePhase6ErrorV1>
    {
        crate::lifecycle_atomic_snapshot::prepare_atomic_dataset_snapshot(&self.coordinator, plan)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_authenticated_atomic_snapshot<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<AtomicDatasetSnapshotMutationOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if self.apply_readiness != StorageApplyReadiness::ProtectedWorkerReady {
            return Err(StorageRuntimeError::Recovery);
        }
        let initial_clock = trusted_clock().map_err(|_| StorageRuntimeError::Recovery)?;
        let request = aos_sandbox_protocol::decode_atomic_storage_snapshot_request(
            request_body,
            peer,
            policy,
            0,
        )
        .map_err(|_| StorageRuntimeError::Recovery)?;
        let existing = self
            .coordinator
            .existing_atomic_dataset_snapshot(request.operation())?;
        if existing.as_ref().is_none_or(|(phase, _, _)| {
            *phase == crate::state::AtomicDatasetSnapshotPhaseV1::Prepared
        }) {
            self.require_git_coverage_new_admission_v1()?;
        }
        if existing.is_none() && !self.readiness.permits_catalog_methods() {
            return Err(StorageRuntimeError::Recovery);
        }
        if existing.as_ref().is_some_and(|(phase, _, _)| {
            *phase == crate::state::AtomicDatasetSnapshotPhaseV1::Prepared
        }) && !self.readiness.permits_catalog_methods()
            && self.readiness != (StorageRuntimeReadiness::RecoveryPending { operations: 1 })
        {
            return Err(StorageRuntimeError::Recovery);
        }
        let admission = self.coordinator.admit_new_atomic_dataset_snapshot(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            &initial_clock,
        );
        let program =
            self.finish_live_transaction_mutation(admission, StorageRuntimeError::Admission)?;
        match self
            .coordinator
            .atomic_dataset_snapshot_recovery(request.operation())?
            .0
        {
            crate::state::AtomicDatasetSnapshotPhaseV1::Committed => {
                return self.recover_lifecycle_atomic_snapshot(request.operation());
            }
            crate::state::AtomicDatasetSnapshotPhaseV1::Ambiguous => {
                return self.recover_lifecycle_atomic_snapshot(request.operation());
            }
            crate::state::AtomicDatasetSnapshotPhaseV1::Prepared => {}
        }
        self.coordinator.authorize_atomic_snapshot_dispatch(
            &request,
            request_body,
            &program,
            trusted_clock,
        )?;
        self.dispatch_prepared_atomic_snapshot(program.operation(), program.commitment())
    }

    fn dispatch_prepared_atomic_snapshot(
        &mut self,
        operation: [u8; 16],
        commitment: ObjectDigest,
    ) -> Result<AtomicDatasetSnapshotMutationOutcomeV1, StorageRuntimeError> {
        self.require_git_coverage_new_admission_v1()?;
        let marked = self
            .coordinator
            .mark_atomic_dataset_snapshot_ambiguous(operation, commitment);
        let program =
            self.finish_live_transaction_mutation(marked, StorageRuntimeError::Admission)?;
        self.latch_recovery_required();
        let evidence = match self.helper.atomic_snapshot_once(&program, true) {
            Ok(evidence) => evidence,
            Err(_) => {
                return Ok(
                    AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                        program: commitment,
                    },
                );
            }
        };
        let observation = evidence.digest();
        if self
            .coordinator
            .commit_atomic_dataset_snapshot_with_evidence(
                operation,
                commitment,
                observation,
                evidence.member_guids(),
            )
            .is_err()
        {
            if self.coordinator.transaction_journal_requires_reopen() {
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
                return Err(StorageRuntimeError::ReopenRequired);
            }
            return Ok(
                AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                    program: commitment,
                },
            );
        }
        self.readiness = self.reconcile_startup()?;
        Ok(AtomicDatasetSnapshotMutationOutcomeV1::Committed {
            program: commitment,
            observation,
        })
    }

    pub(crate) fn recover_lifecycle_atomic_snapshot(
        &mut self,
        operation: [u8; 16],
    ) -> Result<AtomicDatasetSnapshotMutationOutcomeV1, StorageRuntimeError> {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if self.apply_readiness != StorageApplyReadiness::ProtectedWorkerReady {
            return Err(StorageRuntimeError::Recovery);
        }
        let (phase, program, retained) = self
            .coordinator
            .atomic_dataset_snapshot_recovery(operation)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let commitment = program.commitment();
        match phase {
            crate::state::AtomicDatasetSnapshotPhaseV1::Prepared => Ok(
                AtomicDatasetSnapshotMutationOutcomeV1::PreparedBeforeEffect {
                    program: commitment,
                },
            ),
            crate::state::AtomicDatasetSnapshotPhaseV1::Committed => {
                Ok(AtomicDatasetSnapshotMutationOutcomeV1::Committed {
                    program: commitment,
                    observation: retained.ok_or(StorageRuntimeError::Recovery)?,
                })
            }
            crate::state::AtomicDatasetSnapshotPhaseV1::Ambiguous => {
                let evidence = match self.helper.atomic_snapshot_once(&program, false) {
                    Ok(evidence) => evidence,
                    Err(_) => {
                        return Ok(
                            AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                                program: commitment,
                            },
                        );
                    }
                };
                let observation = evidence.digest();
                let committed = if program.format_version() == 1 {
                    self.coordinator.commit_atomic_dataset_snapshot(
                        operation,
                        commitment,
                        observation,
                    )
                } else {
                    self.coordinator
                        .commit_atomic_dataset_snapshot_with_evidence(
                            operation,
                            commitment,
                            observation,
                            evidence.member_guids(),
                        )
                };
                if committed.is_err() {
                    if self.coordinator.transaction_journal_requires_reopen() {
                        self.readiness = StorageRuntimeReadiness::ReopenRequired;
                        return Err(StorageRuntimeError::ReopenRequired);
                    }
                    return Ok(
                        AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                            program: commitment,
                        },
                    );
                }
                self.readiness = self.reconcile_startup()?;
                Ok(AtomicDatasetSnapshotMutationOutcomeV1::Committed {
                    program: commitment,
                    observation,
                })
            }
        }
    }

    /// Opens protected state, anchors genesis, and performs startup retirement and observation.
    ///
    /// `bootstrap_directory` is a root-owned fixed-file publication, not a
    /// request or controller-provided raw catalog. A truly unused journal is
    /// initialized atomically with the protected authority binding and genesis
    /// head. An initialized journal instead authenticates its current head and
    /// compares only its immutable genesis identity to the static publication.
    /// Before workspace inventory opens, authenticated expired or strictly
    /// superseded Prepared operations are durably retired. A clock sample that
    /// is discontinuous with the authenticated effect leaves exact-current work
    /// pending for observation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for insecure or malformed protected
    /// inputs, rollback, authority/genesis substitution, worker construction,
    /// corrupt state, or failed observation-only recovery. An indeterminate
    /// startup retirement returns [`StorageRuntimeError::ReopenRequired`]; a
    /// later open must replay the durable journal prefix before serving.
    pub fn open_root_owned(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        Self::open_root_owned_inner(
            authority_directory,
            bootstrap_directory,
            state_directory,
            None,
            identity_pool,
            zfs_executable,
            executor,
            StorageApplyConstructionV1::Closed,
            None,
        )
        .map(|(runtime, _)| runtime)
    }

    /// Opens the runtime with an optional external resolver-policy publication.
    ///
    /// An omitted policy leaves repair and inventory available but disables
    /// Prepare. A configured invalid or rolled-back publication is classified
    /// as [`StoragePrepareReadiness::PolicyInvalid`] without manufacturing a
    /// fallback policy. Journal I/O or authenticated-state corruption remains
    /// fatal to the whole runtime. Durable Prepared retirement follows the same
    /// pre-inventory ordering as [`Self::open_root_owned`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] under the same protected authority,
    /// bootstrap, journal, worker, and recovery failures as
    /// [`Self::open_root_owned`]. A policy rollback is classified rather than
    /// returned, while an uncertain policy-floor or startup-retirement commit
    /// is fatal and requires protected reopen.
    #[allow(clippy::too_many_arguments)]
    pub fn open_root_owned_with_resolver_policy(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        Self::open_root_owned_inner(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            StorageApplyConstructionV1::Closed,
            None,
        )
        .map(|(runtime, _)| runtime)
    }

    /// Opens the source-only protected Apply and Snapshot worker composition.
    ///
    /// Unlike the production constructors, this explicitly retains the fixed
    /// root-owned Snapshot metadata directory alongside the existing ZFS
    /// worker, protected transaction catalog, and workspace catalog. It does
    /// not register or advertise Apply, install a unit, or dispatch an effect;
    /// callers must still invoke admission and execution explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for every ordinary protected runtime
    /// failure and when the fixed Snapshot metadata owner is unavailable or
    /// insecure.
    #[allow(clippy::too_many_arguments)]
    pub fn open_root_owned_dormant_apply_worker(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        Self::open_root_owned_inner(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            StorageApplyConstructionV1::DormantProtectedWorker,
            None,
        )
        .map(|(runtime, _)| runtime)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_root_owned_inner(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        apply_construction: StorageApplyConstructionV1,
        operator_credentials: Option<
            &crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1,
        >,
    ) -> Result<
        (Self, Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>),
        StorageRuntimeError,
    > {
        let selection = match operator_credentials {
            Some(credentials) => operator_startup::OperatorStartupSelectionV4::Existing(credentials),
            None => operator_startup::OperatorStartupSelectionV4::Ordinary,
        };
        match Self::open_root_owned_selected_v4(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            apply_construction,
            selection,
        )? {
            StorageStartupOutcomeV4::Runtime(runtime, owner) => Ok((runtime, owner)),
            StorageStartupOutcomeV4::OperatorProvisioned => Err(StorageRuntimeError::Recovery),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn open_root_owned_selected_v4(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        apply_construction: StorageApplyConstructionV1,
        selection: operator_startup::OperatorStartupSelectionV4<'_>,
    ) -> Result<StorageStartupOutcomeV4, StorageRuntimeError> {
        let mut executor = Some(executor);
        let mut assembly = StorageRuntimeAssemblyV1::new();
        Self::open_root_owned_selected_native_v4(
            authority_directory, bootstrap_directory, state_directory,
            resolver_policy_directory, identity_pool, zfs_executable,
            StorageStartupExecutorV1::Legacy(&mut executor),
            apply_construction, selection, &mut assembly, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_root_owned_selected_native_v4(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        mut executor: StorageStartupExecutorV1<'_>,
        apply_construction: StorageApplyConstructionV1,
        selection: operator_startup::OperatorStartupSelectionV4<'_>,
        assembly: &mut StorageRuntimeAssemblyV1,
        mut original: Option<(&mut StorageOriginalNativeConstructionV1, OriginalStartupProfileV1<'_>)>,
    ) -> Result<StorageStartupOutcomeV4, StorageRuntimeError> {
        let operator_credentials = selection.credentials();
        // Retain the host mount namespace before constructing any subsystem
        // that may later acquire a namespace-scoped helper.
        assembly.pin_custody = Some(WorkspacePinHostCustody::retain_initial_root_owned()
            .map_err(|_| StorageRuntimeError::WorkspacePinScope)?);
        let selected_receiver = original.as_ref().is_some_and(|(attempt, _)|
            attempt.has_storage_service_receiving_original_v1());
        let protected_configuration = if selected_receiver {
            let attempt = original.as_mut().map(|(attempt, _)| &mut **attempt)
                .ok_or(StorageRuntimeError::Receiving)?;
            let startup = attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?;
            assembly.configuration_before = Some(startup.borrow_storage_prepare_receiving_v1()
                .and_then(|mut receiving| receiving.require_startup_current_v1()));
            if !matches!(assembly.configuration_before, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            // The actual argv6 join and updated Broker9FD receiving demand
            // were admitted by the original prefix before this first read.
            assembly.configuration_capture = Some(
                assembly.broker_configuration_open.capture_storage_once(authority_directory),
            );
            if matches!(assembly.configuration_capture, Some(Ok(()))) {
                assembly.broker_configuration = assembly.broker_configuration_open.take_configuration_once();
                assembly.configuration_conversion_result = Some(
                    assembly.configuration_conversion.capture_once_v1(&mut assembly.broker_configuration),
                );
            }
            // Actual public pins and all split authority/secret parts stay
            // resident through this independent post even on conversion Err.
            assembly.configuration_post = Some(startup.borrow_storage_prepare_receiving_v1()
                .and_then(|mut receiving| receiving.require_startup_current_v1()));
            if !matches!(assembly.configuration_capture, Some(Ok(())))
                || !matches!(assembly.configuration_conversion_result, Some(Ok(())))
                || !matches!(assembly.configuration_post, Some(Ok(())))
            {
                return Err(StorageRuntimeError::Receiving);
            }
            assembly.configuration_conversion.take_configuration_once_v1()
                .ok_or(StorageRuntimeError::Receiving)?
        } else {
            StorageProtectedConfigurationV1::from_protected_directory(authority_directory)?
        };
        let configuration_binding =
            runtime_configuration_binding(protected_configuration.public_binding(), identity_pool);
        let authority_binding = protected_configuration.public_binding();
        let (authority, state_key, _) = protected_configuration.into_parts();
        assembly.authority = Some(authority);
        assembly.state_key = Some(state_key);
        if selected_receiver {
            assembly.configuration_conversion.dispose_positive_pins_v1();
            // The actual original already joined argv7 and paid the full
            // configuration prefix before entering this shared startup engine.
            let attempt = original.as_mut().map(|(attempt, _)| &mut **attempt)
                .ok_or(StorageRuntimeError::Receiving)?;
            let startup = attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?;
            assembly.bootstrap_before = Some(startup.borrow_storage_prepare_receiving_v1()
                .and_then(|mut receiving| receiving.require_startup_current_v1()));
            if !matches!(assembly.bootstrap_before, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            assembly.bootstrap_capture = Some(
                assembly.bootstrap_open.capture_once_v1(bootstrap_directory, 0),
            );
            // Run the independent original post even after a read/decode error;
            // the actual earlier prefix failure remains resident and first.
            assembly.bootstrap_post = Some(startup.borrow_storage_prepare_receiving_v1()
                .and_then(|mut receiving| receiving.require_startup_current_v1()));
            if !matches!(assembly.bootstrap_capture, Some(Ok(()))) {
                return Err(StorageRuntimeError::Bootstrap);
            }
            if !matches!(assembly.bootstrap_post, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            assembly.bootstrap = assembly.bootstrap_open.take_success_v1();
        } else {
            assembly.bootstrap = Some(ProtectedStorageBootstrap::open_root_owned(bootstrap_directory)?);
        }
        let bootstrap = assembly.bootstrap.as_ref().ok_or(StorageRuntimeError::Receiving)?;
        if selected_receiver {
            let attempt = original.as_mut().map(|(attempt, _)| &mut **attempt)
                .ok_or(StorageRuntimeError::Receiving)?;
            let mut receiving = attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?
                .borrow_storage_prepare_receiving_v1().map_err(|_| StorageRuntimeError::Receiving)?;
            assembly.state_startup.open_once_v1(
                &mut receiving,
                if operator_credentials.is_some() {
                    aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1::ExistingOnly
                } else {
                    aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1::CreateAndRepair
                },
                &mut assembly.state_key, bootstrap.minimum_generation, configuration_binding,
                bootstrap.genesis_generation, &bootstrap.catalogs,
            )?;
        } else {
            let state_key = assembly.state_key.take().ok_or(StorageRuntimeError::Receiving)?;
            assembly.transactions = Some(match operator_credentials {
            Some(_) => StorageTransactionStore::open_existing_root_owned_runtime(
                state_directory,
                state_key,
                bootstrap.minimum_generation,
                configuration_binding,
                bootstrap.genesis_generation,
                &bootstrap.catalogs,
            )?,
            None => StorageTransactionStore::open_root_owned_runtime(
                state_directory,
                state_key,
                bootstrap.minimum_generation,
                configuration_binding,
                bootstrap.genesis_generation,
                &bootstrap.catalogs,
            )?,
            });
        }
        let contract = ZfsHelperContract::new(zfs_executable)?;
        assembly.pin_executor = Some(SystemdWorkspacePinExecutor::new(
            PathBuf::from(WORKSPACE_PIN_WORKER_SOCKET),
            open_cgroup_root()?,
        )?);
        assembly.pin_observer = Some(SystemdWorkspacePinObserver::new(
            PathBuf::from(WORKSPACE_PIN_OBSERVER_SOCKET),
            open_cgroup_root()?,
        )?);
        assembly.pin_io = Some(SystemdWorkspacePinRuntimeIo::new(
            assembly.pin_custody.take().ok_or(StorageRuntimeError::Receiving)?,
            assembly.pin_executor.take().ok_or(StorageRuntimeError::Receiving)?,
            assembly.pin_observer.take().ok_or(StorageRuntimeError::Receiving)?,
        ));
        let pin_io = assembly.pin_io.as_mut().ok_or(StorageRuntimeError::Receiving)?;
        // The transaction journal lock is already held. Prove the complete
        // reserved pin-worker cgroup scope empty before opening or observing
        // workspace state and before generic mutation recovery.
        if selected_receiver {
            let attempt = original.as_mut().map(|(attempt, _)| &mut **attempt)
                .ok_or(StorageRuntimeError::Receiving)?;
            let mut receiving = attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?
                .borrow_storage_prepare_receiving_v1()
                .map_err(|_| StorageRuntimeError::Receiving)?;
            let transactions = assembly.state_startup.store()
                .ok_or(StorageRuntimeError::Receiving)?;
            let borrowed = receiving.borrow_initial_pin_quiescence_once_v1(
                transactions.recovery_encoding_journal_v1(),
            );
            let mut stage = match borrowed {
                Ok(stage) => {
                    assembly.initial_pin_borrow = Some(Ok(()));
                    stage
                }
                Err(cause) => {
                    assembly.initial_pin_borrow = Some(Err(cause));
                    return Err(StorageRuntimeError::Receiving);
                }
            };
            assembly.initial_pin_scan = Some(pin_io.recover_initial_quiescence_receiving_v1(
                &mut stage,
            ));
            if !matches!(assembly.initial_pin_scan, Some(Ok(()))) {
                // The same guard parks all raw scan/native/post owners before
                // projecting this error; the whole IO result remains resident.
                drop(stage);
                return Err(StorageRuntimeError::Receiving);
            }
            assembly.initial_pin_disposal = Some(stage.complete_after_quiescence_v1());
            if !matches!(assembly.initial_pin_disposal, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
        } else {
            pin_io.recover_quiescence()?;
        }
        if !selected_receiver {
            assembly.guest_root_publisher = Some(SystemdGuestRootPublisherClientV1::new(
                PathBuf::from(GUEST_ROOT_PUBLISHER_SOCKET), open_cgroup_root()?,
            )?);
            assembly.guest_root_publisher.as_mut().ok_or(StorageRuntimeError::Receiving)?
                .recover_quiescence()?;
        }
        // The selected initial scan already completed the same closed roster,
        // including GuestRoot31; it must not enter another unpriced observer.
        let transactions = if selected_receiver {
            assembly.state_startup.store()
        } else {
            assembly.transactions.as_ref()
        }.ok_or(StorageRuntimeError::Receiving)?;

        // This runs after both cgroup scans and before any startup observer.
        reject_held_repair_guard_after_quiescence(transactions)?;

        transactions.validate_runtime_restart(
            configuration_binding,
            bootstrap.genesis_generation,
            &bootstrap.catalogs,
        )?;
        let transactions = if selected_receiver {
            let attempt = original.as_mut().map(|(attempt, _)| &mut **attempt)
                .ok_or(StorageRuntimeError::Receiving)?;
            let mut receiving = attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?
                .borrow_storage_prepare_receiving_v1().map_err(|_| StorageRuntimeError::Receiving)?;
            assembly.state_startup.settle_native_once_v1(&mut receiving)?;
            assembly.state_startup.take_store_once_v1()
        } else {
            assembly.transactions.take()
        }.ok_or(StorageRuntimeError::Receiving)?;
        assembly.coordinator = Some(StorageAdmissionCoordinator::new(
            assembly.authority.take().ok_or(StorageRuntimeError::Receiving)?, transactions,
        ));
        let coordinator = assembly.coordinator.as_mut().ok_or(StorageRuntimeError::Receiving)?;
        // Existing records must authenticate against the preexisting floor;
        // a current policy publication cannot heal missing rollback evidence.
        coordinator
            .authenticate_catalog_preparations()
            .map_err(StorageRuntimeError::Admission)?;
        // Keep the actual mutable receiving loan continuously through the
        // interval. A refused work reservation must not require reborrowing a
        // now-closed ordinary admission merely to perform its prepaid post.
        let mut retirement_receiving = if selected_receiver {
            let attempt = original.as_mut().map(|(attempt, _)| &mut **attempt)
                .ok_or(StorageRuntimeError::Receiving)?;
            Some(attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?
                .borrow_storage_prepare_receiving_v1().map_err(|_| StorageRuntimeError::Receiving)?)
        } else {
            None
        };
        if let Some(receiving) = retirement_receiving.as_mut() {
            assembly.startup_mutation_entry = Some(coordinator.prepare_startup_mutations_v1(receiving));
            if !matches!(assembly.startup_mutation_entry, Some(Ok(()))) {
                assembly.startup_mutation_posts = Some(coordinator.finish_startup_mutations_v1(receiving));
                return Err(StorageRuntimeError::Receiving);
            }
        }
        assembly.resolver_configuration = Some(if operator_credentials.is_some() {
            // The actual sidecar is not held yet; policy admission can write.
            Ok((None, StoragePrepareReadiness::Unconfigured))
        } else {
            configure_resolver_policy_with_originals_v1(
                coordinator, resolver_policy_directory, authority_binding,
                selected_receiver.then_some((
                    &mut assembly.resolver_policy_directory_original,
                    &mut assembly.resolver_policy_read_original,
                )),
                None,
            )
        });
        if matches!(assembly.resolver_configuration, Some(Err(_))) {
            if selected_receiver {
                let receiving = retirement_receiving.as_mut().ok_or(StorageRuntimeError::Receiving)?;
                assembly.startup_mutation_posts = Some(coordinator.finish_startup_mutations_v1(receiving));
                // Preserve the actual error in the resident assembly. This
                // outer status is only a projection; first_cause borrows it.
                return Err(StorageRuntimeError::Recovery);
            }
            let Some(Err(cause)) = assembly.resolver_configuration.take() else {
                std::process::abort();
            };
            return Err(cause);
        }
        let Some(Ok((policies, prepare_readiness))) = assembly.resolver_configuration.take() else {
            std::process::abort();
        };
        assembly.resolver_policies = policies;
        // Historical repair authority must authenticate before either ordinary
        // effect histories or the workspace inventory becomes an input.
        // Keep both exclusive journals for the runtime lifetime. Acquiring the
        // transaction journal first is the only permitted cross-journal order.
        let mut startup_clock = || {
            trusted_paired_clock_sample()
                .map_err(|_| crate::StorageAdmissionError::VerificationFailed)
        };
        if selected_receiver {
            assembly.startup_authority = Some(authenticate_startup_authority(coordinator));
            if matches!(assembly.startup_authority, Some(Ok(()))) && operator_credentials.is_none() {
                assembly.startup_retirement = Some(
                    coordinator.retire_inactive_prepared_at_startup(&mut startup_clock),
                );
            }
            // The real retirement Result stays parked while both independent
            // posts run, even after an authenticated retirement/native error.
            let mut receiving = retirement_receiving.take().ok_or(StorageRuntimeError::Receiving)?;
            assembly.startup_mutation_posts = Some(coordinator.finish_startup_mutations_v1(&mut receiving));
            if !matches!(assembly.startup_authority, Some(Ok(()))) {
                return Err(StorageRuntimeError::Recovery);
            }
            if matches!(assembly.startup_retirement, Some(Err(_))) {
                return Err(if coordinator.transaction_journal_requires_reopen() {
                    StorageRuntimeError::ReopenRequired
                } else {
                    StorageRuntimeError::Recovery
                });
            }
            if !matches!(assembly.startup_mutation_posts, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            authenticate_startup_authority(coordinator)?;
            assembly.workspace_plan = Some(coordinator.workspace_catalog_activation_plan());
            let Some(Ok(_)) = assembly.workspace_plan.as_ref() else {
                return Err(StorageRuntimeError::Recovery);
            };
            let Some(Ok((plan, physical))) = assembly.workspace_plan.take() else {
                std::process::abort();
            };
            assembly.selected_workspace_plan = Some(plan);
            assembly.physical_workspace_plan = physical;
            assembly.workspace_startup.open_once_v1(
                &mut receiving,
                if operator_credentials.is_some() {
                    aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1::ExistingOnly
                } else {
                    aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1::CreateAndRepair
                },
                identity_pool,
                &mut assembly.selected_workspace_plan,
            )?;
            assembly.workspaces = assembly.workspace_startup.take_validated_once_v1();
        } else {
        assembly.workspaces = Some(if operator_credentials.is_some() {
            authenticate_startup_authority(coordinator)?;
            let pending = PendingStorageWorkspaceCatalogV1::open_existing_root_owned(
                state_directory,
                identity_pool,
            )?;
            let (plan, _) = coordinator.workspace_catalog_activation_plan()?;
            pending.validate_plan(plan)?
        } else {
            open_validated_workspace_catalog_after_startup(
                coordinator,
                &mut startup_clock,
                || {
                    PendingStorageWorkspaceCatalogV1::open_root_owned(state_directory, identity_pool)
                        .map_err(Into::into)
                },
            )?
        });
        }
        drop(retirement_receiving);
        let workspaces = assembly.workspaces.as_ref().ok_or(StorageRuntimeError::Receiving)?;
        // Preserve one lifetime writer order: primary transaction, workspace,
        // then separate native issuance. Neither acceptance nor ReleaseHold
        // may observe a separately reopened/unheld consumer-interest snapshot.
        if selected_receiver {
            let (attempt, profile) = original.as_mut().ok_or(StorageRuntimeError::Receiving)?;
            attempt.require_native_open().map_err(|_| StorageRuntimeError::Recovery)?;
            let startup = attempt.startup.as_mut().ok_or(StorageRuntimeError::Receiving)?;
            let mut receiving = startup.borrow_storage_prepare_receiving_v1()
                .map_err(|_| StorageRuntimeError::Receiving)?;
            assembly.issuance_startup.open_once_v1(
                &mut receiving,
                if operator_credentials.is_some() {
                    aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1::ExistingOnly
                } else {
                    aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1::CreateAndRepair
                },
                state_directory,
                profile,
                coordinator,
            ).map_err(|_| StorageRuntimeError::Recovery)?;
            attempt.native_ledger = assembly.issuance_startup.take_owner_once_v1();
            if let OriginalStartupProfileV1::Held(key) = profile {
                assembly.trust_startup.open_once_v1(&mut receiving, authority_directory)
                    .map_err(|_| StorageRuntimeError::Recovery)?;
                assembly.trust_startup.settle_native_once_v1(&mut receiving)
                    .map_err(|_| StorageRuntimeError::Recovery)?;
                attempt.native_trust = assembly.trust_startup.take_trust_once_v1();
                // The same normal owners remain parked on Construction before
                // this independently required Trust/key/current-interest join.
                let ledger = attempt.native_ledger.as_mut().ok_or(StorageRuntimeError::Recovery)?;
                let trust = attempt.native_trust.as_ref().ok_or(StorageRuntimeError::Recovery)?;
                if let Err(cause) = ledger.validate_original_held_cold(coordinator, trust, key) {
                    attempt.first_cause.get_or_insert(OriginalNativeConstructionCauseV1::Native(cause));
                    return Err(StorageRuntimeError::Recovery);
                }
            }
        } else {
        assembly.native_issuance = if let Some((attempt, profile)) = original.as_mut() {
            match profile {
                OriginalStartupProfileV1::Held(key) => {
                    let _crossing = attempt.unwind_fence();
                    let result = StorageNativeIssuanceLedgerV1::park_original_held_writer(
                        attempt, state_directory, authority_directory, key,
                    ).and_then(|()| {
                        attempt.native_ledger.as_mut()
                            .ok_or(crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict)?
                            .validate_original_held_cold(coordinator,
                                attempt.native_trust.as_ref()
                                    .ok_or(crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict)?, key)
                    });
                    if let Err(cause) = result {
                        attempt.phase = OriginalNativeConstructionPhaseV1::Failed;
                        if attempt.first_cause.is_none() {
                            attempt.first_cause = Some(OriginalNativeConstructionCauseV1::Native(cause));
                        }
                        return Err(StorageRuntimeError::Recovery);
                    }
                }
                OriginalStartupProfileV1::Ordinary => {
                    attempt.require_native_open().map_err(|_| StorageRuntimeError::Recovery)?;
                    attempt.native_ledger = Some(match operator_credentials {
                        Some(_) => StorageNativeIssuanceLedgerV1::open_existing_root_owned(state_directory),
                        None => StorageNativeIssuanceLedgerV1::open_root_owned(state_directory),
                    }.map_err(|cause| {
                        attempt.first_cause = Some(OriginalNativeConstructionCauseV1::Native(cause));
                        StorageRuntimeError::Recovery
                    })?);
                    attempt.native_ledger.as_mut().ok_or(StorageRuntimeError::Recovery)?
                        .validate_active_holds(coordinator).map_err(|cause| {
                            attempt.first_cause = Some(OriginalNativeConstructionCauseV1::Native(cause));
                            StorageRuntimeError::Recovery
                        })?;
                }
            }
            None
        } else {
            let mut native_issuance = match operator_credentials {
                Some(_) => StorageNativeIssuanceLedgerV1::open_existing_root_owned(state_directory),
                None => StorageNativeIssuanceLedgerV1::open_root_owned(state_directory),
            }.map_err(|_| StorageRuntimeError::Recovery)?;
            native_issuance.validate_active_holds(coordinator)
                .map_err(|_| StorageRuntimeError::Recovery)?;
            Some(native_issuance)
        };

        }

        if let operator_startup::OperatorStartupSelectionV4::ProvisionEmpty(credentials) = selection {
            // All lower writers and physical roots remain held. Provisioning
            // exits before random runtime IDs, backend construction, or any
            // ordinary startup/policy/recovery mutation.
            operator_startup::provision_empty_operator_sidecar_v4(
                coordinator,
                workspaces,
                assembly.native_issuance.as_mut().ok_or(StorageRuntimeError::Recovery)?,
                pin_io,
                state_directory,
                credentials,
            )?;
            // Match the runtime's primary/workspace/native field-drop order;
            // the fourth writer has already been checked and released.
            drop(assembly.coordinator.take());
            drop(assembly.workspaces.take());
            drop(assembly.native_issuance.take());
            return Ok(StorageStartupOutcomeV4::OperatorProvisioned);
        }

        // The fourth writer is acquired only after all three lower cuts authenticate.
        assembly.operator_owner = match operator_credentials {
            Some(credentials) => {
                let owner = credentials.open_existing_owner(state_directory).map_err(|cause| {
                    if let Some((attempt, _)) = original.as_mut() {
                        if attempt.first_cause.is_none() {
                            attempt.first_cause = Some(OriginalNativeConstructionCauseV1::Service(cause));
                        }
                    }
                    StorageRuntimeError::Recovery
                })?;
                Some(owner)
            }
            None => None,
        };
        // The returned fourth writer parks before its first capture/readback.
        if let Some((attempt, _)) = original.as_mut() {
            attempt.operator_owner = assembly.operator_owner.take();
        }
        let operator_owner_loan = match original.as_mut() {
            Some((attempt, _)) => attempt.operator_owner.as_mut(),
            None => assembly.operator_owner.as_mut(),
        };
        let operator_startup = match operator_owner_loan {
            Some(owner) => Some(operator_startup::DeferredOperatorStartupV4::capture(
                owner,
                resolver_policy_directory,
                authority_binding,
            )?),
            None => None,
        };
        let broker_instance_id = random_challenge()?;

        // Every fallible presence check precedes the actual positive executor/
        // Snapshot handoff. The following checked moves cannot discard a
        // previously moved writer because a later Option is unexpectedly empty.
        if assembly.coordinator.is_none() || assembly.workspaces.is_none()
            || assembly.pin_io.is_none()
        {
            return Err(StorageRuntimeError::Receiving);
        }
        let (backend, apply_readiness) = match apply_construction {
            StorageApplyConstructionV1::Closed => (
                SystemdZfsProcessBackend::new(executor.take().ok_or(StorageRuntimeError::Receiving)?),
                StorageApplyReadiness::WorkspaceBackendUnavailable,
            ),
            StorageApplyConstructionV1::DormantProtectedWorker => {
                let backend = if let Some((attempt, _)) = original.as_mut()
                    .filter(|(attempt, _)| attempt.has_storage_service_receiving_original_v1())
                {
                    attempt.snapshot_capture_result = Some(attempt.snapshot_metadata.capture_once());
                    attempt.snapshot_current_result = Some(attempt.require_daemon_prefix_paid_current_v1());
                    if !matches!(attempt.snapshot_capture_result, Some(Ok(())))
                        || !matches!(attempt.snapshot_current_result, Some(Ok(())))
                    {
                        return Err(StorageRuntimeError::Recovery);
                    }
                    let handoff = attempt.snapshot_metadata.prepare_backend_once()
                        .map_err(|_| StorageRuntimeError::Recovery)?;
                    let executor = executor.take().ok_or(StorageRuntimeError::Receiving)?;
                    handoff.complete(executor)
                } else {
                    SystemdZfsProcessBackend::with_protected_snapshot_metadata(
                        executor.take().ok_or(StorageRuntimeError::Receiving)?,
                    ).map_err(|_| StorageRuntimeError::Recovery)?
                };
                (backend, StorageApplyReadiness::ProtectedWorkerReady)
            }
        };
        let mut runtime = Self {
            coordinator: assembly.take_coordinator(),
            workspaces: Some(assembly.take_workspaces()),
            configuration_binding,
            broker_instance_id,
            held_reader_state_directory: Some(state_directory.to_path_buf()),
            native_issuance: match original.as_mut() {
                Some((attempt, _)) => attempt.native_ledger.take(),
                None => assembly.native_issuance.take(),
            },
            native_escrow: native_acquire::StorageNativeEscrowV2::default(),
            original_service_lent: false,
            original_worker_startup: match original.as_mut() {
                Some((attempt, _)) => attempt.startup.take(),
                None => None,
            },
            receiving_inventory_demand: None,
            receiving_prepare_demand: None,
            receiving_prepare_result: None,
            receiving_prepare_clocks: [None, None],
            receiving_prepare_policy_read: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            receiving_inventory_catalog: None,
            startup_reconciliation: startup_reconciliation::StartupReconciliationOriginalV1::new(),
            original_measurements: original_held_measurement::ResidentOriginalMeasurementsV3::default(),
            #[cfg(target_os = "linux")]
            git_coverage: None,
            #[cfg(test)]
            native_fixture: None,
            #[cfg(test)]
            native_readback_fixture_uid: None,
            pin_contract: contract.clone(),
            pin_io: Box::new(assembly.take_pin_io()),
            helper: StorageMutationHelper::new(
                contract,
                Box::new(backend) as Box<dyn ZfsProcessBackend + Send>,
            ),
            readiness: StorageRuntimeReadiness::RecoveryPending { operations: 1 },
            apply_readiness,
            resolver_policies: assembly.resolver_policies.take(),
            resolver_policy_directory_original: std::mem::replace(
                &mut assembly.resolver_policy_directory_original,
                crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1::new(),
            ),
            resolver_policy_read_original: std::mem::replace(
                &mut assembly.resolver_policy_read_original,
                crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            ),
            prepare_readiness,
            worker_dispatch: RepairWorkerDispatchGate::new(),
            operator_startup,
            #[cfg(test)]
            fail_repair_completion_commit_for_test: false,
            guest_root_publication: None,
            guest_root_health: None, guest_root_health_demand: None, guest_root_health_payment: None,
            guest_root_publication_demand: None,
            guest_root_publication_payment: None,
            root_export_original: None,
            root_export_geometry: None,
            canary_export: canary_export_held::CanaryExportHeldV1::new(),
        };
        if let Some((attempt, profile)) = original.as_mut() {
            attempt.runtime = Some(runtime);
            let _crossing = attempt.unwind_fence();
            let runtime = attempt.runtime.as_mut().ok_or(StorageRuntimeError::Recovery)?;
            if selected_receiver {
                attempt.startup_reconciliation = Some(if let Some(owner) = attempt.operator_owner.as_mut() {
                    runtime.finish_operator_construction_v4(owner).map(|()| runtime.readiness)
                } else {
                    runtime.reconcile_initial_receiving_v1()
                });
                // Keep the entire reconciliation Result and normal Runtime
                // resident while the independent same-original post runs.
                attempt.startup_reconciliation_post = Some(runtime.original_worker_startup.as_mut()
                    .ok_or(StorageRuntimeError::Recovery)?.recheck());
                let Some(Ok(readiness)) = attempt.startup_reconciliation.as_ref() else {
                    return Err(StorageRuntimeError::Recovery);
                };
                if !matches!(attempt.startup_reconciliation_post, Some(Ok(()))) {
                    return Err(StorageRuntimeError::Recovery);
                }
                runtime.readiness = *readiness;
            } else {
            if let Some(owner) = attempt.operator_owner.as_mut() {
                runtime.finish_operator_construction_v4(owner)?;
            } else {
                runtime.readiness = runtime.reconcile_startup()?;
            }
            runtime.original_worker_startup.as_mut().ok_or(StorageRuntimeError::Recovery)?
                .recheck().map_err(|cause| {
                    attempt.first_cause = Some(OriginalNativeConstructionCauseV1::Startup(cause));
                    StorageRuntimeError::Recovery
                })?;
            }
            if let OriginalStartupProfileV1::Held(key) = profile {
                key.recheck().map_err(|cause| {
                    attempt.first_cause = Some(OriginalNativeConstructionCauseV1::Service(cause));
                    StorageRuntimeError::Recovery
                })?;
            }
            if selected_receiver && !runtime.has_deferred_operator_debt_v4() {
                runtime.complete_initial_reconciliation_disposal_v1()?;
            }
            // All checks precede these infallible checked moves. The caller
            // immediately parks the same composition; the fence stays armed.
            let runtime = match attempt.runtime.take() {
                Some(runtime) => runtime,
                None => std::process::abort(),
            };
            return Ok(StorageStartupOutcomeV4::Runtime(runtime, attempt.operator_owner.take()));
        } else if let Some(owner) = assembly.operator_owner.as_mut() {
            runtime.finish_operator_construction_v4(owner)?;
        } else {
            runtime.readiness = runtime.reconcile_startup()?;
        }

        Ok(StorageStartupOutcomeV4::Runtime(runtime, assembly.operator_owner.take()))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_protected_components_for_test<F, C>(
        mut coordinator: StorageAdmissionCoordinator,
        open_workspaces: F,
        trusted_clock: &mut C,
        configuration_binding: ObjectDigest,
        pin_custody: WorkspacePinHostCustody,
        pin_contract: ZfsHelperContract,
        pin_executor: SystemdWorkspacePinExecutor,
        pin_observer: SystemdWorkspacePinObserver,
        helper: StorageMutationHelper<SystemdZfsProcessBackend>,
    ) -> Result<Self, StorageRuntimeError>
    where
        F: FnOnce() -> Result<PendingStorageWorkspaceCatalogV1, StorageRuntimeError>,
        C: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        // Preserve the production construction order: prove the complete
        // mutator cgroup empty, authenticate the transaction journal, and only
        // then open the workspace journal under the already-held first lock.
        let mut pin_io = SystemdWorkspacePinRuntimeIo::new(pin_custody, pin_executor, pin_observer);
        pin_io.recover_quiescence()?;
        if coordinator.has_held_repair_guard() {
            return Err(StorageRuntimeError::Recovery);
        }
        let workspaces = open_validated_workspace_catalog_after_startup(
            &mut coordinator,
            trusted_clock,
            open_workspaces,
        )?;

        let mut runtime = Self {
            coordinator,
            workspaces: Some(workspaces),
            configuration_binding,
            broker_instance_id: random_challenge()?,
            held_reader_state_directory: None,
            native_issuance: None,
            native_escrow: native_acquire::StorageNativeEscrowV2::default(),
            original_worker_startup: None,
            original_service_lent: false,
            original_measurements: original_held_measurement::ResidentOriginalMeasurementsV3::default(),
            #[cfg(target_os = "linux")]
            git_coverage: None,
            native_fixture: None,
            native_readback_fixture_uid: None,
            pin_contract,
            pin_io: Box::new(pin_io),
            helper: helper.into_boxed(),
            readiness: StorageRuntimeReadiness::RecoveryPending { operations: 1 },
            apply_readiness: StorageApplyReadiness::WorkspaceBackendUnavailable,
            resolver_policies: None,
            resolver_policy_directory_original: crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1::new(),
            resolver_policy_read_original: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            prepare_readiness: StoragePrepareReadiness::Unconfigured,
            worker_dispatch: RepairWorkerDispatchGate::new(),
            operator_startup: None,
            fail_repair_completion_commit_for_test: false,
            guest_root_publication: None,
            guest_root_health: None, guest_root_health_demand: None, guest_root_health_payment: None,
            guest_root_publication_demand: None,
            guest_root_publication_payment: None,
            root_export_original: None,
            root_export_geometry: None,
            canary_export: canary_export_held::CanaryExportHeldV1::new(),
            receiving_inventory_demand: None,
            receiving_prepare_demand: None,
            receiving_prepare_result: None,
            receiving_prepare_clocks: [None, None],
            receiving_prepare_policy_read: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            receiving_inventory_catalog: None,
            startup_reconciliation: startup_reconciliation::StartupReconciliationOriginalV1::new(),
        };
        runtime.readiness = runtime.reconcile_startup()?;

        Ok(runtime)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_runtime_interfaces_for_test<F, C>(
        mut coordinator: StorageAdmissionCoordinator,
        open_workspaces: F,
        trusted_clock: &mut C,
        configuration_binding: ObjectDigest,
        pin_contract: ZfsHelperContract,
        mut pin_io: Box<dyn WorkspacePinRuntimeIo + Send>,
        helper: StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>,
    ) -> Result<Self, StorageRuntimeError>
    where
        F: FnOnce() -> Result<PendingStorageWorkspaceCatalogV1, StorageRuntimeError>,
        C: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        pin_io.recover_quiescence()?;
        if coordinator.has_held_repair_guard() {
            return Err(StorageRuntimeError::Recovery);
        }
        let workspaces = open_validated_workspace_catalog_after_startup(
            &mut coordinator,
            trusted_clock,
            open_workspaces,
        )?;
        let mut runtime = Self {
            coordinator,
            workspaces: Some(workspaces),
            configuration_binding,
            broker_instance_id: random_challenge()?,
            held_reader_state_directory: None,
            native_issuance: None,
            native_escrow: native_acquire::StorageNativeEscrowV2::default(),
            original_worker_startup: None,
            original_service_lent: false,
            original_measurements: original_held_measurement::ResidentOriginalMeasurementsV3::default(),
            #[cfg(target_os = "linux")]
            git_coverage: None,
            native_fixture: None,
            native_readback_fixture_uid: None,
            pin_contract,
            pin_io,
            helper,
            readiness: StorageRuntimeReadiness::RecoveryPending { operations: 1 },
            apply_readiness: StorageApplyReadiness::WorkspaceBackendUnavailable,
            resolver_policies: None,
            resolver_policy_directory_original: crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1::new(),
            resolver_policy_read_original: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            prepare_readiness: StoragePrepareReadiness::Unconfigured,
            worker_dispatch: RepairWorkerDispatchGate::new(),
            operator_startup: None,
            fail_repair_completion_commit_for_test: false,
            guest_root_publication: None,
            guest_root_health: None, guest_root_health_demand: None, guest_root_health_payment: None,
            guest_root_publication_demand: None,
            guest_root_publication_payment: None,
            root_export_original: None,
            root_export_geometry: None,
            canary_export: canary_export_held::CanaryExportHeldV1::new(),
            receiving_inventory_demand: None,
            receiving_prepare_demand: None,
            receiving_prepare_result: None,
            receiving_prepare_clocks: [None, None],
            receiving_prepare_policy_read: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            receiving_inventory_catalog: None,
            startup_reconciliation: startup_reconciliation::StartupReconciliationOriginalV1::new(),
        };
        runtime.readiness = runtime.reconcile_startup()?;
        Ok(runtime)
    }

    #[cfg(test)]
    pub(crate) const fn coordinator_for_test(&self) -> &StorageAdmissionCoordinator {
        &self.coordinator
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_transaction_journal_commit_for_test(&mut self) {
        self.coordinator.fail_after_next_journal_commit_for_test();
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_repair_completion_commit_for_test(&mut self) {
        self.fail_repair_completion_commit_for_test = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_workspace_catalog_commit_for_test(&mut self) -> bool {
        let Some(workspaces) = self.workspaces.as_mut() else {
            return false;
        };
        workspaces.fail_after_next_materialization_commit_for_test();
        true
    }

    #[cfg(test)]
    pub(crate) fn into_journals_for_test(
        self,
    ) -> (
        StorageAdmissionCoordinator,
        ValidatedPendingStorageWorkspaceCatalogV1,
    ) {
        (
            self.coordinator,
            self.workspaces
                .unwrap_or_else(|| unreachable!("workspace catalog custody escaped runtime")),
        )
    }

    #[cfg(test)]
    pub(crate) fn into_reopen_components_for_test(
        self,
    ) -> (
        StorageAdmissionCoordinator,
        Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    ) {
        (self.coordinator, self.workspaces)
    }

    /// Returns the fail-closed startup readiness classification.
    #[must_use]
    pub const fn readiness(&self) -> StorageRuntimeReadiness {
        self.readiness
    }

    /// Returns the protected resolver-policy startup classification.
    #[must_use]
    pub const fn prepare_readiness(&self) -> StoragePrepareReadiness {
        self.prepare_readiness
    }

    /// Returns the independent generic Apply backend classification.
    #[must_use]
    pub const fn apply_readiness(&self) -> StorageApplyReadiness {
        self.apply_readiness
    }

    /// Reports whether this process must exit and reopen protected journals.
    #[must_use]
    pub const fn requires_reopen(&self) -> bool {
        self.readiness.requires_reopen()
    }

    /// Reports whether production Prepare is safe in the current runtime state.
    #[must_use]
    pub fn is_prepare_ready(&self) -> bool {
        matches!(self.prepare_readiness, StoragePrepareReadiness::Ready)
            && self.readiness.permits_catalog_methods()
            && self.worker_dispatch.is_open()
    }

    fn operation_permits_apply(
        &mut self,
        operation_id: [u8; 16],
    ) -> Result<bool, StorageRuntimeError> {
        if self.apply_readiness != StorageApplyReadiness::ProtectedWorkerReady
            || !self.readiness.permits_catalog_methods()
            || !self.worker_dispatch.is_open()
        {
            return Ok(false);
        }
        let catalog = self.coordinator.prepared_catalog_for_apply(operation_id)?;
        if let Some(issuance) = &mut self.native_issuance {
            issuance
                .validate_active_holds(&self.coordinator)
                .and_then(|()| issuance.check_release(catalog.plan()))
                .map_err(|_| StorageRuntimeError::Recovery)?;
        }
        Ok(true)
    }

    /// Reports whether the isolated repair path may accept a fresh request.
    ///
    /// Repair readiness never implies generic Apply readiness. The repair
    /// method re-observes its exact precondition and rechecks all authority on
    /// every call, including while another recovered operation remains pending.
    #[must_use]
    pub fn is_repair_ready(&self) -> bool {
        self.readiness.permits_repair() && self.worker_dispatch.is_open()
    }

    /// Reports whether authenticated authoritative inventory may be exposed.
    ///
    /// Every admitted state has authenticated repair history before the
    /// workspace catalog is opened.
    #[must_use]
    pub fn is_inventory_ready(&self) -> bool {
        if !self.readiness.permits_catalog_methods() || !self.worker_dispatch.is_open() {
            return false;
        }
        let Some(workspaces) = self.workspaces.as_ref() else {
            return false;
        };
        workspaces.is_terminally_materialized()
    }

    /// Proves the fixed protected publisher is live before a static method profile is served.
    ///
    /// # Errors
    ///
    /// Returns an error when current Storage inventory is closed, or the
    /// socket-activated publisher cannot authenticate and exit cleanly.
    pub fn probe_guest_root_publisher(&self) -> Result<(), StorageRuntimeError> {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !self.is_inventory_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let mut publisher = SystemdGuestRootPublisherClientV1::new(
            PathBuf::from(GUEST_ROOT_PUBLISHER_SOCKET),
            open_cgroup_root()?,
        )?;
        publisher.probe().map_err(Into::into)
    }

    /// Encodes the current physically revalidated complete Storage inventory.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError::Recovery`] when the method gate or
    /// deadline is invalid, or protected workspace/resolver catalog evidence
    /// rejects the retained launch or lifecycle resources. Returns
    /// [`StorageRuntimeError::ReopenRequired`] when post-observation
    /// materialization reports an ambiguous journal commit; all method gates
    /// remain closed until the process reopens protected state.
    pub fn inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let now = boottime_now_nanoseconds()?;
        if !self.is_inventory_ready()
            || now >= worker_cutoff_boottime_nanoseconds
            || worker_cutoff_boottime_nanoseconds >= activation_deadline_boottime_nanoseconds
        {
            return Err(StorageRuntimeError::Recovery);
        }

        self.reobserve_workspace_inventory(
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )
    }

    fn reobserve_workspace_inventory(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let validated = self
            .workspaces
            .take()
            .ok_or(StorageRuntimeError::Recovery)?;
        let result = self.inventory_from_validated(
            validated,
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        );
        match result {
            Ok((validated, inventory)) => {
                self.workspaces = Some(validated);
                Ok(inventory)
            }
            Err((Some(validated), error)) => {
                self.workspaces = Some(validated);
                Err(error)
            }
            Err((None, error)) => {
                let _ = error;
                self.latch_reopen_required();
                Err(StorageRuntimeError::ReopenRequired)
            }
        }
    }

    /// Retains one detached workspace mount only after fresh Storage inventory.
    ///
    /// The returned descriptor is not Host launch authority. A separate
    /// authenticated Host handoff must recheck the same live assignment and
    /// publication proof before transferring it onward.
    pub(crate) fn export_guest_root_mount(
        &mut self,
        expected_proof: GuestRootPublicationProofV1,
        template: &ProtectedGuestRootTemplateV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<OwnedFd, StorageRuntimeError> {
        root_mount_export::export_ordinary_v2(
            self, expected_proof, template, deadline_boottime_nanoseconds,
        )
    }

    pub(crate) fn live_export_origin_mount_id(
        &self,
        workspace: &ValidatedStorageWorkspace,
    ) -> Result<u64, StorageRuntimeError> {
        let (_, physical) = self.coordinator.workspace_catalog_activation_plan()?;
        let physical = physical.ok_or(StorageRuntimeError::Recovery)?;
        physical
            .targets()
            .iter()
            .find(|target| target.workspace_handle() == *workspace.workspace_handle())
            .and_then(|target| match target.expectation() {
                WorkspaceCatalogObservationExpectationV1::Present {
                    mount_id,
                    root_device,
                    root_inode,
                } if root_device == workspace.root_device()
                    && root_inode == workspace.root_inode()
                    && target.dataset_guid() == workspace.dataset_guid()
                    && target.creation_operation_id() == *workspace.creation_operation_id() =>
                {
                    Some(mount_id)
                }
                _ => None,
            })
            .ok_or(StorageRuntimeError::Recovery)
    }

    /// Obtains one private read-only clone from the authenticated pin observer.
    ///
    /// This is not an export or a grant. The worker is the only process with
    /// mount privilege; the broker retains its returned FD and never sends it
    /// to the Provider transport. Both physical observations must still name
    /// the exact current Storage source selected by the protected catalog.
    pub(crate) fn clone_live_export_mount(
        &mut self,
        source: StorageLiveExportSourceV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<OwnedFd, StorageRuntimeError> {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let before =
            self.observe_live_export_origin(source.workspace_id(), deadline_boottime_nanoseconds)?;
        if !live_export_origin_matches_source(&before, source) {
            return Err(StorageRuntimeError::Recovery);
        }

        let now = boottime_now_nanoseconds()?;
        let cutoff = guest_root_inventory_cutoff(now, deadline_boottime_nanoseconds)?;
        let validated = self
            .workspaces
            .as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        let (plan, physical) = self.coordinator.workspace_catalog_activation_plan()?;
        let physical = physical.ok_or(StorageRuntimeError::Recovery)?;
        let request = self
            .catalog_observation_request(
                validated,
                &plan,
                &physical,
                catalog_observation_nonce()?,
                deadline_boottime_nanoseconds,
            )?
            .with_live_export(source.workspace_id())?;
        let encoded = encode_request(&request)?;
        let (_, mount) = self
            .pin_io
            .export_catalog_root(&encoded, &request, cutoff)?;

        let cloned_stat = fstat(&mount).map_err(|_| StorageRuntimeError::Recovery)?;
        let cloned_mount_id = MountId::from_fd(mount.as_fd())
            .map_err(|_| StorageRuntimeError::Recovery)?
            .get();
        let mount_flags = rustix::fs::fstatvfs(&mount)
            .map_err(|_| StorageRuntimeError::Recovery)?
            .f_flag;
        if cloned_stat.st_dev != source.origin_device()
            || cloned_stat.st_ino != source.origin_inode()
            || cloned_mount_id == source.origin_mount_id()
            || !mount_flags.contains(
                rustix::fs::StatVfsMountFlags::RDONLY
                    | rustix::fs::StatVfsMountFlags::NOSUID
                    | rustix::fs::StatVfsMountFlags::NODEV,
            )
        {
            return Err(StorageRuntimeError::Recovery);
        }

        let after =
            self.observe_live_export_origin(source.workspace_id(), deadline_boottime_nanoseconds)?;
        if !live_export_origin_matches_source(&after, source) {
            return Err(StorageRuntimeError::Recovery);
        }
        Ok(mount)
    }

    /// Debits actual owned Inventory source geometry before worker/model growth.
    pub(crate) fn reserve_inventory_receiving_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageRuntimeError> {
        if self.receiving_inventory_demand.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        let demand = self.inventory_retention_demand_v1();
        // The real whole arithmetic result precedes the actual original debit.
        self.receiving_inventory_demand = Some(demand);
        let Some(Ok(demand)) = self.receiving_inventory_demand.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        receiving.reserve_inventory_retention_once_v1(*demand)
            .map_err(|_| StorageRuntimeError::Receiving)
    }

    /// Counts actual retained workspace rows through the existing shape suppliers.
    fn inventory_workspace_rows_v2(&self) -> Result<u64, aos_sandbox_model::AccountingError> {
        let mut geometry = self.coordinator.receiving_inventory_geometry_v1()?;
        if let Some(workspaces) = self.workspaces.as_ref() {
            geometry.include(workspaces.receiving_inventory_geometry_v1()?)?;
        }
        Ok(geometry.workspace_rows)
    }

    fn inventory_retention_demand_v1(&self)
        -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>
    {
        let mut geometry = self.coordinator.receiving_inventory_geometry_v1()?;
        if let Some(workspaces) = self.workspaces.as_ref() {
            geometry.include(workspaces.receiving_inventory_geometry_v1()?)?;
        }
        geometry.retained_model_demand_v1()?
            .checked_add(inventory_catalog::InventoryCatalogOriginalV1::fixed_demand_v1()?)?
            .checked_add(crate::guest_root_inventory::marker_readback_retained_demand_v1(
                geometry.workspace_rows,
            )?)
    }

    pub(crate) fn retain_refused_inventory_body_v1(&mut self, body: Vec<u8>) {
        if let Some(original) = self.receiving_inventory_catalog.as_mut() {
            original.retain_refused_body(body);
        }
    }

    /// Borrows the actual pre-Inventory arithmetic failure retained on this owner.
    pub(crate) fn receiving_inventory_demand_failure_v1(&self)
        -> Option<&aos_sandbox_model::AccountingError>
    {
        self.receiving_inventory_demand.as_ref().and_then(|result| result.as_ref().err())
    }

    pub(crate) fn receiving_inventory_worker_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.receiving_inventory_catalog.as_ref()
            .and_then(|original| original.failure())
            .or_else(|| self.pin_io.catalog_observation_failure_v1())
    }

    /// Encodes the complete lifecycle inventory for authenticated broker readback.
    ///
    /// It first runs the existing physical workspace observation, then rereads
    /// the protected resolver journal and appends all five lifecycle object
    /// families before the caller submits the exact body to broker-session
    /// signing.
    pub(crate) fn complete_lifecycle_inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let inventory = self.inventory_resources(
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )?;
        self.complete_inventory_from_workspace_bytes(inventory)
    }

    fn complete_inventory_from_workspace_bytes(
        &self,
        inventory: Vec<u8>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.complete_inventory_from_workspace_bytes_borrowed(&inventory)
    }

    fn complete_inventory_from_workspace_bytes_borrowed(
        &self,
        inventory: &[u8],
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        inventory_catalog::complete_lifecycle_body_v1(&self.coordinator, inventory)
    }

    fn inventory_from_validated(
        &mut self,
        validated: ValidatedPendingStorageWorkspaceCatalogV1,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<
        (ValidatedPendingStorageWorkspaceCatalogV1, Vec<u8>),
        (
            Option<ValidatedPendingStorageWorkspaceCatalogV1>,
            StorageRuntimeError,
        ),
    > {
        self.inventory_from_validated_shared_v1(
            validated,
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )
    }

    fn catalog_observation_request(
        &self,
        validated: &ValidatedPendingStorageWorkspaceCatalogV1,
        plan: &crate::workspace_catalog::StorageWorkspaceCatalogPlanV1,
        physical_plan: &AuthenticatedWorkspaceCatalogPhysicalPlanV1,
        nonce: [u8; 32],
        deadline_boottime_nanoseconds: u64,
    ) -> Result<WorkspaceCatalogObservationRequestV1, StorageRuntimeError> {
        build_catalog_observation_request(
            self.configuration_binding, self.broker_instance_id, self.pin_io.as_ref(),
            validated, plan, physical_plan, nonce, deadline_boottime_nanoseconds,
        )
    }

    /// Resolves and retains one non-authorizing production catalog preparation.
    ///
    /// Apply remains unavailable. This path uses only the root-owned policy
    /// directory retained at startup and a fresh authenticated transaction
    /// projection; callers cannot supply a resolver or inventory snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when Prepare readiness is unavailable,
    /// request authority fails, policy or durable state is stale, resolution is
    /// denied, either protected clock sample fails, or atomic retention fails.
    /// An uncertain transaction-journal commit returns
    /// [`StorageRuntimeError::ReopenRequired`] and closes every method gate.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_catalog<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.require_git_coverage_new_admission_v1()?;
        if !self.is_prepare_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let resolver_policies = self
            .resolver_policies
            .as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        let result = self.coordinator.prepare_catalog_from_protected_policy(
            request_body,
            artifacts,
            resolver_policies,
            protocol_version,
            peer,
            policy,
            trusted_clock,
        );
        self.finish_live_transaction_mutation(result, StorageRuntimeError::Admission)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_catalog_state_receiving_v1<F>(
        &mut self,
        request_body: &[u8],
        expected_request_id: [u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageRuntimeError>
    where F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.reserve_lifecycle_preparation_models_v1(request_body, artifacts, receiving)?;
        self.require_git_coverage_new_admission_v1()?;
        if !self.is_prepare_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let resolver_policies = self.resolver_policies.as_ref().ok_or(StorageRuntimeError::Recovery)?;
        let result = self.coordinator.prepare_catalog_state_from_protected_policy_v1(
            request_body, expected_request_id, artifacts, resolver_policies,
            protocol_version, peer, policy, trusted_clock, receiving,
            &mut self.startup_reconciliation.prepare_policy_read,
        );
        let result = self.finish_live_transaction_mutation(result, StorageRuntimeError::Admission);
        self.startup_reconciliation.preparation_complete = result.is_ok();
        result
    }

    /// Retains ordinary Prepare through the same actual paid Storage original.
    ///
    /// # Errors
    /// Preserves Prepare readiness, protected policy/resolver and authority
    /// failures, and closes runtime gates after actual Native uncertainty.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_catalog_receiving_v1(
        &mut self,
        request_body: &[u8],
        expected_request_id: [u8; 16],
        protected_boot_id: [u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageRuntimeError>
    {
        receiving.require_prepare_retention_v1().map_err(|_| StorageRuntimeError::Receiving)?;
        if self.receiving_prepare_demand.is_some() || self.receiving_prepare_result.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        let demand = self.coordinator.receiving_inventory_geometry_v1()
            .and_then(|geometry| geometry.retained_model_demand_v1())
            .and_then(|state| ProtectedStorageResolverPolicyDirectoryV1::receiving_demand_v1()
                .and_then(|policy| state.checked_add(policy)))
            .and_then(|current| crate::catalog_preparation::receiving_preparation_demand_v1(request_body.len(), artifacts)
                .and_then(|prepare| current.checked_add(prepare)));
        self.receiving_prepare_demand = Some(demand);
        let Some(Ok(demand)) = self.receiving_prepare_demand.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        receiving.reserve_catalog_retention_once_v1(*demand)
            .map_err(|_| StorageRuntimeError::Receiving)?;
        let result = (|| {
            self.require_git_coverage_new_admission_v1()?;
            if !self.is_prepare_ready() {
                return Err(StorageRuntimeError::Recovery);
            }
            let resolver_policies = self.resolver_policies.as_ref()
                .ok_or(StorageRuntimeError::Recovery)?;
            let clocks = &mut self.receiving_prepare_clocks;
            let mut next = 0;
            let mut trusted_clock = || {
                let Some(slot) = clocks.get_mut(next) else {
                    return Err(StorageAdmissionError::FenceRejected);
                };
                next += 1;
                *slot = Some(aos_sandbox_controller_domain::policy_compiler::observe_root_first_source_successor_clock_v2(None));
                match slot.as_ref() {
                    Some(Ok(sample)) if sample.host_boot_id() == protected_boot_id => Ok(*sample),
                    _ => Err(StorageAdmissionError::FenceRejected),
                }
            };
            let result = self.coordinator.prepare_catalog_receiving_from_protected_policy(
                request_body, expected_request_id, artifacts, resolver_policies, protocol_version,
                peer, policy, &mut trusted_clock, receiving, &mut self.receiving_prepare_policy_read,
            );
            self.finish_live_transaction_mutation(result, StorageRuntimeError::Admission)
        })();
        // Park the complete actual admission/resolution/native Result before
        // projecting status through the selected Session execution boundary.
        self.receiving_prepare_result = Some(result);
        match self.receiving_prepare_result.as_ref() {
            Some(Ok(outcome)) => Ok(outcome.clone()),
            _ => Err(StorageRuntimeError::Receiving),
        }
    }

    pub(crate) fn receiving_prepare_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receiving_prepare_demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.receiving_prepare_clocks.iter().find_map(|slot|
                slot.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)))
            .or_else(|| self.receiving_prepare_policy_read.failure())
            .or_else(|| self.coordinator.receiving_preparation_append_failure_v1())
            .or_else(|| self.receiving_prepare_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }

    /// Retains one selected Nix generation Prepare in its original reservoir.
    ///
    /// The request is parked before cohort, readiness or policy observations.
    /// This is existing-only Prepare, not Clone Apply or completed Start.
    ///
    /// # Errors
    /// Refuses reused custody, an enrolled cohort, unavailable originals,
    /// failed admission/commit/readback or expired original clock. Actual
    /// errors and any native commit remain in `original` before late checks.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_nix_generation_into<F>(
        &mut self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request_id: [u8; 16],
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
        original: &mut crate::StorageGenerationAttemptV1,
    ) -> Result<(), crate::StorageGenerationStoppedV1>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        use crate::nix_generation::StorageGenerationCauseV1;

        if original.entered || original.request.is_none() || original.first.is_some() {
            original.first.get_or_insert(StorageGenerationCauseV1::Occupied);
            return Err(crate::StorageGenerationStoppedV1);
        }
        original.entered = true;

        let prerequisites = self.require_git_coverage_new_admission_v1().and_then(|()| {
            if !self.is_prepare_ready() || self.resolver_policies.is_none() {
                return Err(StorageRuntimeError::Recovery);
            }
            Ok(())
        });
        if let Err(error) = prerequisites {
            original.retain_runtime_error(error);
            if let Err(error) = trusted_clock() {
                original.clock_debt.get_or_insert(error);
            }
            return Err(crate::StorageGenerationStoppedV1);
        }

        let resolver_policies = match self.resolver_policies.as_ref() {
            Some(policies) => policies,
            None => return Err(crate::StorageGenerationStoppedV1),
        };
        let result = self.coordinator.prepare_nix_generation_into(
            artifacts, request_id, resolver_policies, protocol_version, peer, policy,
            trusted_clock, original,
        );
        if self.coordinator.transaction_journal_requires_reopen() {
            self.latch_reopen_required();
            original.retain_runtime_error(StorageRuntimeError::ReopenRequired);
            original.finished = false;
        }

        // This independent clock observation also runs after a native Err.
        // It never replaces the original cause with a coarse runtime marker.
        let late = trusted_clock().and_then(|later| {
            if let Some(Ok(initial)) = original.initial.as_ref() {
                initial.validate_later_sample(later)
                    .map_err(|_| StorageAdmissionError::FenceRejected)?;
            }
            if let Some(Ok(selected)) = original.checked.as_ref() {
                if later.host_boot_id() != selected.prefix().host_boot_id
                    || later.boottime_nanoseconds() >= selected.prefix().deadline_boottime_nanoseconds
                {
                    return Err(StorageAdmissionError::FenceRejected);
                }
            }
            Ok(())
        });
        if let Err(error) = late {
            original.clock_debt.get_or_insert(error);
            original.finished = false;
        }
        if result.is_err() || original.first.is_some() || original.clock_debt.is_some() {
            return Err(crate::StorageGenerationStoppedV1);
        }
        Ok(())
    }

    /// Repairs one existing workspace root pin through fresh observation.
    ///
    /// The caller supplies only the raw Storage 1.0 request and standard
    /// authorization artifacts. Dataset identity, catalog, attempt ordinal,
    /// mount observation, and host scope are derived from authenticated state
    /// and retained descriptors while the runtime holds its exclusive journals.
    /// An exact durable retry is observation-only and never reaches a mutator.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when repair is unavailable, authority or
    /// retained history fails closed, exact dataset/pin absence is not freshly
    /// proved, worker dispatch fails, or the exact postcondition is not
    /// observed. An uncertain transaction-journal admission returns
    /// [`StorageRuntimeError::ReopenRequired`] and closes every method gate.
    #[allow(clippy::too_many_arguments)]
    pub fn repair_workspace_pin<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
    ) -> Result<WorkspacePinRepairExecutionOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.repair_workspace_pin_inner(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            trusted_clock,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn repair_workspace_pin_state_receiving_v1<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
        cutoff: u64,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<WorkspacePinRepairExecutionOutcomeV1, StorageRuntimeError>
    where F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.repair_workspace_pin_inner(
            request_body, artifacts, protocol_version, peer, policy,
            trusted_clock, None, None, Some(receiving), Some(cutoff),
        )
    }

    /// Reserves and retains a signed exact admission probe without dispatching repair.
    ///
    /// # Errors
    ///
    /// Rejects a replayed effect, failed fresh observation, changed signed
    /// authority, or uncertain protected sidecar custody.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_workspace_pin_repair_for_operator<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        signed_intent: &[u8],
        owner: &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
        trusted_clock: &mut F,
    ) -> Result<Vec<u8>, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.require_git_coverage_new_admission_v1()?;
        if !self.is_repair_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let clock = trusted_clock().map_err(|_| StorageRuntimeError::Recovery)?;
        if self
            .coordinator
            .workspace_pin_repair_replay(
                request_body,
                artifacts,
                protocol_version,
                peer,
                policy,
                &clock,
            )
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            return Err(StorageRuntimeError::Recovery);
        }
        let host_scope = self
            .pin_io
            .host_scope()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let dispatch = self
            .coordinator
            .plan_workspace_pin_repair_admission_observation(
                request_body,
                artifacts,
                protocol_version,
                peer,
                policy,
                &clock,
                &self.pin_contract,
                host_scope,
            )
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let observation_request = dispatch
            .request_bytes()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let fresh = self
            .pin_io
            .observe_repair_admission(&observation_request, dispatch.probe())
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let semantics = aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1::decode(
            request_body, peer, policy, clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageRuntimeError::Recovery)?;
        if !matches!(
            owner
                .reserve(
                    signed_intent,
                    request_body,
                    &semantics,
                    dispatch.probe(),
                    &fresh
                )
                .map_err(operator_sidecar_failure)?,
            crate::operator_recovery::StorageOperatorRecoveryReservationV2::Pending
        ) {
            return Err(StorageRuntimeError::Recovery);
        }
        owner
            .sign_reserved_probe_attestation_v1(signed_intent, dispatch.probe())
            .map_err(operator_sidecar_failure)
    }

    /// Executes only the previously attested probe after a separate controller call.
    ///
    /// # Errors
    ///
    /// Rejects changed physical state or authority before durable attempt
    /// admission; uncertain post-admission state requires recovery.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_prepared_workspace_pin_repair_for_operator<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        signed_intent: &[u8],
        expected_attestation_digest: [u8; 32],
        owner: &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
        trusted_clock: &mut F,
    ) -> Result<
        Option<crate::operator_recovery::StorageOperatorRecoveryCompletionV2>,
        StorageRuntimeError,
    >
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.repair_workspace_pin_inner(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            trusted_clock,
            Some((&mut *owner, signed_intent)),
            Some(expected_attestation_digest),
            None,
            None,
        )?;
        let effect_id = owner
            .effect_id_for_request(signed_intent, request_body)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        self.recover_operator_workspace_pin_receipt(owner, effect_id)
    }

    /// Reconciles a pending operator receipt from durable Storage repair state.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for failed inventory readback, invalid
    /// physical owner evidence, or an uncertain sidecar commit.
    #[allow(
        dead_code,
        reason = "operator repair controller mapping is not installed"
    )]
    pub(crate) fn recover_operator_workspace_pin_receipt(
        &mut self,
        owner: &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
        effect_id: [u8; 32],
    ) -> Result<
        Option<crate::operator_recovery::StorageOperatorRecoveryCompletionV2>,
        StorageRuntimeError,
    > {
        if !self.is_inventory_ready() {
            return Ok(None);
        }
        let now = boottime_now_nanoseconds()?;
        let deadline = now
            .checked_add(10_000_000_000)
            .ok_or(StorageRuntimeError::Recovery)?;
        let cutoff = now
            .checked_add(9_000_000_000)
            .ok_or(StorageRuntimeError::Recovery)?;
        let inventory = self.complete_lifecycle_inventory_resources(deadline, cutoff)?;
        match owner.complete(effect_id, &self.coordinator, &inventory) {
            Ok(receipt) => Ok(Some(receipt)),
            Err(crate::operator_recovery::StorageOperatorRecoveryErrorV1::Pending) => Ok(None),
            Err(error) => Err(operator_sidecar_failure(error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn repair_workspace_pin_inner<F>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: &mut F,
        mut operator_owner: Option<(
            &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
            &[u8],
        )>,
        expected_attestation_digest: Option<[u8; 32]>,
        mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
        worker_cutoff: Option<u64>,
    ) -> Result<WorkspacePinRepairExecutionOutcomeV1, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        let selected = receiving.is_some();
        if selected {
            let demand = self.coordinator.receiving_inventory_geometry_v1()
                .and_then(|shape| shape.retained_model_demand_v1());
            let demand = match demand {
                Ok(demand) => demand,
                Err(cause) => {
                    self.startup_reconciliation.arithmetic = Some(cause);
                    return Err(StorageRuntimeError::Receiving);
                }
            };
            self.startup_reconciliation.capacity = Some(receiving.as_deref_mut()
                .ok_or(StorageRuntimeError::Receiving)?.reserve_inventory_readback_v1(
                    self.coordinator.recovery_encoding_journal_v1(), demand,
                ));
            if !matches!(self.startup_reconciliation.capacity, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
        }
        if !self.is_repair_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if let Some(expected) = expected_attestation_digest {
            let Some((owner, signed_intent)) = operator_owner.as_mut() else {
                return Err(StorageRuntimeError::Recovery);
            };
            let packet = owner
                .recover_reserved_probe_attestation_v1(signed_intent)
                .map_err(operator_sidecar_failure)?;
            if Sha256::digest(&packet).as_slice() != expected {
                return Err(StorageRuntimeError::Recovery);
            }
        }
        let preliminary_clock = trusted_clock().map_err(|_| StorageRuntimeError::Recovery)?;
        if self
            .coordinator
            .workspace_pin_repair_replay(
                request_body,
                artifacts,
                protocol_version,
                peer,
                policy,
                &preliminary_clock,
            )
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            return Ok(WorkspacePinRepairExecutionOutcomeV1::ObservationRequired);
        }

        self.require_git_coverage_new_admission_v1()?;
        let host_scope = self.pin_io.host_scope();
        let current_host_scope = self.startup_reconciliation.worker_result_v1(host_scope, selected)?;
        let retained = match (operator_owner.as_mut(), expected_attestation_digest) {
            (Some((owner, intent)), Some(expected)) => {
                let packet = owner
                    .recover_reserved_probe_attestation_v1(intent)
                    .map_err(operator_sidecar_failure)?;
                if Sha256::digest(&packet).as_slice() != expected {
                    return Err(StorageRuntimeError::Recovery);
                }
                let challenge: [u8; 16] = packet
                    .get(72..88)
                    .ok_or(StorageRuntimeError::Recovery)?
                    .try_into()
                    .map_err(|_| StorageRuntimeError::Recovery)?;
                Some(challenge)
            }
            (None, None) | (Some(_), None) => None,
            (None, Some(_)) => return Err(StorageRuntimeError::Recovery),
        };
        let observation_dispatch = match retained {
            Some(challenge) => self
                .coordinator
                .plan_workspace_pin_repair_admission_observation_with_challenge(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    &preliminary_clock,
                    &self.pin_contract,
                    current_host_scope,
                    challenge,
                ),
            None => self
                .coordinator
                .plan_workspace_pin_repair_admission_observation(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    &preliminary_clock,
                    &self.pin_contract,
                    current_host_scope,
                ),
        }
        .map_err(|_| StorageRuntimeError::Recovery)?;
        let request = match receiving.as_deref_mut() {
            Some(receiving) => observation_dispatch.request_bytes_receiving_v1(receiving),
            None => observation_dispatch.request_bytes(),
        };
        let observation_request = self.startup_reconciliation.operation_result_v1(request, selected)?;
        let observation = match receiving.as_deref_mut() {
            Some(receiving) => {
                startup_reconciliation::reserve_pin_result_v1(receiving)?;
                let cutoff = worker_cutoff.ok_or(StorageRuntimeError::Receiving)?;
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(
                    receiving, self.coordinator.recovery_encoding_journal_v1(),
                );
                self.pin_io.observe_repair_admission_receiving_v1(
                    &observation_request, observation_dispatch.probe(), cutoff, &mut stage,
                )
            }
            None => self.pin_io.observe_repair_admission(&observation_request, observation_dispatch.probe()),
        };
        let fresh_observation = self.startup_reconciliation.worker_result_v1(observation, selected)?;
        if let Some((owner, signed_intent)) = operator_owner {
            if expected_attestation_digest.is_none() {
                return Err(StorageRuntimeError::Recovery);
            }
            owner
                .sign_reserved_probe_attestation_v1(signed_intent, observation_dispatch.probe())
                .map_err(operator_sidecar_failure)?;
        }
        let result = match receiving.as_deref_mut() {
            Some(receiving) => self.coordinator.begin_workspace_pin_repair_receiving_v1(
                observation_dispatch,
                fresh_observation,
                request_body,
                artifacts,
                protocol_version,
                peer,
                policy,
                &self.pin_contract,
                trusted_clock,
                receiving,
            ),
            None => self.coordinator.begin_workspace_pin_repair(
                observation_dispatch,
                fresh_observation,
                request_body,
                artifacts,
                protocol_version,
                peer,
                policy,
                &self.pin_contract,
                trusted_clock,
            ),
        };
        let result = match result {
            Ok(admitted) => Ok(admitted),
            Err(cause) if selected => {
                self.startup_reconciliation.operation_error = Some(cause);
                Err(StorageRuntimeError::Receiving)
            }
            Err(_) => Err(StorageRuntimeError::Recovery),
        };
        let admitted = self.finish_live_transaction_mutation(result, |cause| cause)?;
        let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(dispatch) = admitted else {
            return Ok(WorkspacePinRepairExecutionOutcomeV1::ObservationRequired);
        };

        let request = match receiving.as_deref_mut() {
            Some(receiving) => dispatch.worker_request_bytes_receiving_v1(receiving),
            None => dispatch.worker_request_bytes(),
        };
        let worker_request = self.startup_reconciliation.operation_result_v1(request, selected)?;
        let execution = match receiving.as_deref_mut() {
            Some(receiving) => {
                startup_reconciliation::reserve_pin_result_v1(receiving)?;
                let cutoff = worker_cutoff.ok_or(StorageRuntimeError::Receiving)?;
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(
                    receiving, self.coordinator.recovery_encoding_journal_v1(),
                );
                self.pin_io.execute_receiving_v1(&worker_request, dispatch.attempt(), cutoff, &mut stage)
            }
            None => self.pin_io.execute(&worker_request, dispatch.attempt()),
        };
        let result = match self.startup_reconciliation.worker_result_v1(execution, selected) {
            Ok(result) => result,
            Err(cause) => {
                self.latch_recovery_required();
                return Err(cause);
            }
        };
        // The worker may have changed the pin. From this point until every
        // durable completion and catalog projection succeeds, no other RPC may
        // use the old Ready classification.
        self.latch_reopen_required();
        #[cfg(test)]
        if std::mem::take(&mut self.fail_repair_completion_commit_for_test) {
            self.coordinator.fail_after_next_journal_commit_for_test();
        }
        let completed = match receiving.as_deref_mut() {
            Some(receiving) => self.coordinator.complete_workspace_pin_repair_execution_receiving_v1(
                dispatch.attempt(), &result, receiving,
            ),
            None => self.coordinator.complete_workspace_pin_repair_execution(dispatch.attempt(), &result),
        };
        let disposition = match completed {
            Ok(disposition) => disposition,
            Err(cause) => {
                if selected { self.startup_reconciliation.operation_error = Some(cause); }
                return Err(StorageRuntimeError::ReopenRequired);
            }
        };
        if disposition
            != crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication
        {
            self.latch_recovery_required();
            return Err(StorageRuntimeError::Recovery);
        }
        let reconciliation = match receiving {
            Some(receiving) => self.reconcile_entered_state_v1(receiving),
            None => self.reconcile_startup(),
        };
        finish_reopen_required_reconciliation(&mut self.readiness, reconciliation)?;
        Ok(WorkspacePinRepairExecutionOutcomeV1::Satisfied)
    }

    /// Admits one workspace-creating effect with an exact retained identity range.
    ///
    /// The runtime holds both journals in transaction-then-workspace order,
    /// chooses first-fit against every retained transaction intent and catalog
    /// tombstone, then commits that exact range with the signed operation.
    /// Rejected or interrupted intents remain reserved and are never silently
    /// reused. This path remains unavailable while
    /// [`Self::apply_readiness`] reports that the complete backend is held.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when Apply is not ready, the sandbox is
    /// not a private-userns workspace, the range pool is exhausted or
    /// inconsistent, signed authority fails, or the durable admission fails.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_workspace_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        manifest: &CanonicalAssignmentManifestV1,
        sandbox_spec: &SandboxSpec,
    ) -> Result<StorageAdmissionOutcome, StorageRuntimeError> {
        self.admit_workspace_apply_intent_inner_v1(request_body, artifacts, catalog,
            protocol_version, peer, policy, current_clock, manifest, sandbox_spec, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_workspace_apply_intent_inner_v1(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        manifest: &CanonicalAssignmentManifestV1,
        sandbox_spec: &SandboxSpec,
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<StorageAdmissionOutcome, StorageRuntimeError> {
        if self.original_service_lent && receiving.is_none() {
            return Err(StorageRuntimeError::Receiving);
        }
        self.require_git_coverage_new_admission_v1()?;
        if self.apply_readiness == StorageApplyReadiness::WorkspaceBackendUnavailable
            || protocol_version != ProtocolVersion::new(1, 0)
        {
            return Err(StorageRuntimeError::Recovery);
        }
        let semantics = CanonicalStorageSemanticsV1::decode(
            request_body,
            catalog.binding(),
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageRuntimeError::Recovery)?;
        if semantics.header().protocol_version() != protocol_version {
            return Err(StorageRuntimeError::Recovery);
        }
        if !self.operation_permits_apply(*semantics.operation_id())? {
            return Err(StorageRuntimeError::Recovery);
        }
        let metadata = semantics
            .workspace_metadata()
            .ok_or(StorageRuntimeError::Recovery)?;
        if metadata.manifest() != manifest || metadata.sandbox_spec() != sandbox_spec {
            return Err(StorageRuntimeError::Recovery);
        }

        let prepared = self
            .coordinator
            .prepared_catalog_for_apply(*semantics.operation_id())?;
        if &prepared != catalog {
            return Err(StorageRuntimeError::Recovery);
        }
        let IdentityProfile::PrivateUserns {
            id_range_size,
            unmappable_policy,
            ..
        } = sandbox_spec.identity_profile()
        else {
            return Err(StorageRuntimeError::Recovery);
        };
        let root_attributes = catalog
            .root_policy()
            .ok_or(StorageRuntimeError::Recovery)?
            .root_attributes();
        let identity_range_size = id_range_size.get();
        let root_is_representable = private_identity_profile_supports_root(
            *unmappable_policy,
            root_attributes,
            identity_range_size,
        );
        let tree_is_representable = match catalog.plan() {
            crate::CatalogPlanV1::CreateWorkspace { .. } => catalog.clone_identity().is_none(),
            crate::CatalogPlanV1::Clone { .. } => {
                catalog.clone_identity().is_some_and(|requirement| {
                    requirement.maximum_portable_uid() < identity_range_size
                        && requirement.maximum_portable_gid() < identity_range_size
                })
            }
            _ => false,
        };
        if !root_is_representable || !tree_is_representable {
            return Err(StorageRuntimeError::Recovery);
        }
        let transaction_ranges = self.coordinator.workspace_identity_ranges()?;
        let pool = self
            .workspaces
            .as_ref()
            .ok_or(StorageRuntimeError::Recovery)?
            .snapshot()
            .identity_pool();
        let retained_range = self
            .coordinator
            .workspace_identity_range(*semantics.operation_id())?;
        let identity_range_start = select_identity_range_for_apply(
            pool,
            &transaction_ranges,
            retained_range,
            identity_range_size,
        )?;
        let result = match receiving {
            Some(receiving) => self.coordinator.admit_apply_intent_receiving_v1(
                request_body, artifacts, catalog, protocol_version, peer, policy, current_clock,
                Some((identity_range_start, manifest, sandbox_spec)), receiving,
            ),
            None => self.coordinator.admit_workspace_apply_intent(
                request_body, artifacts, catalog, protocol_version, peer, policy, current_clock,
                identity_range_start, manifest, sandbox_spec,
            ),
        };
        self.finish_live_transaction_mutation(result, StorageRuntimeError::Admission)
    }

    /// Admits Storage 1.0 Apply using only signed bytes and protected preparation state.
    ///
    /// Create and Clone consume their exact canonical portable metadata and
    /// reserve an identity range. Snapshot and the remaining operations use
    /// generic admission; Snapshot execution additionally requires the exact
    /// protected AOSSMT01 record retained by the dormant worker constructor.
    /// The Apply surface remains structurally absent from advertisement.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when Apply is unavailable, the request
    /// version differs from the negotiated version, preparation or signed
    /// authority is invalid, workspace metadata is absent or inconsistent, or
    /// durable admission fails.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_signed_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<([u8; 16], StorageOperation, StorageAdmissionOutcome), StorageRuntimeError> {
        self.admit_signed_apply_intent_inner(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            current_clock,
            None,
            None,
        )
        .map(|(_, operation_id, operation, outcome)| (operation_id, operation, outcome))
    }

    /// Admits a signed Apply after checking its authenticated request identity.
    ///
    /// The header request identity remains distinct from the operation key
    /// used for catalog lookup and execution.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched header or any admission failure
    /// reported by [`Self::admit_signed_apply_intent`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_authenticated_signed_apply_intent(
        &mut self,
        request_body: &[u8],
        authenticated_request_id: &[u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<([u8; 16], [u8; 16], StorageOperation, StorageAdmissionOutcome), StorageRuntimeError> {
        self.admit_signed_apply_intent_inner(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            current_clock,
            Some(authenticated_request_id),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_authenticated_signed_apply_receiving_v1(
        &mut self,
        request_body: &[u8],
        authenticated_request_id: &[u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<([u8; 16], [u8; 16], StorageOperation, StorageAdmissionOutcome), StorageRuntimeError> {
        receiving.require_models_current_v1(self.coordinator.recovery_encoding_journal_v1())
            .map_err(|_| StorageRuntimeError::Receiving)?;
        self.admit_signed_apply_intent_inner(request_body, artifacts, protocol_version,
            peer, policy, current_clock, Some(authenticated_request_id), Some(receiving))
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_signed_apply_intent_inner(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        authenticated_request_id: Option<&[u8; 16]>,
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<([u8; 16], [u8; 16], StorageOperation, StorageAdmissionOutcome), StorageRuntimeError> {
        if self.original_service_lent && receiving.is_none() {
            return Err(StorageRuntimeError::Receiving);
        }
        self.require_git_coverage_new_admission_v1()?;
        if self.apply_readiness == StorageApplyReadiness::WorkspaceBackendUnavailable
            || protocol_version != ProtocolVersion::new(1, 0)
        {
            return Err(StorageRuntimeError::Recovery);
        }
        let request = ApplyStorageRequest::decode_from_slice(request_body)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(StorageRuntimeError::Recovery);
        }
        let operation_id: [u8; 16] = request
            .operation_id
            .as_slice()
            .try_into()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !self.operation_permits_apply(operation_id)? {
            return Err(StorageRuntimeError::Recovery);
        }
        let catalog = self.coordinator.prepared_catalog_for_apply(operation_id)?;
        let semantics = CanonicalStorageSemanticsV1::decode(
            request_body,
            catalog.binding(),
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageRuntimeError::Recovery)?;
        if semantics.header().protocol_version() != protocol_version {
            return Err(StorageRuntimeError::Recovery);
        }
        let request_id = *semantics.header().request_id();
        if authenticated_request_id.is_some_and(|expected| expected != &request_id) {
            return Err(StorageRuntimeError::Recovery);
        }
        let operation = semantics.operation();
        let result = match apply_admission_route(operation) {
            StorageApplyAdmissionRoute::Workspace => {
                let metadata = semantics
                    .workspace_metadata()
                    .ok_or(StorageRuntimeError::Recovery)?;
                let manifest = metadata.manifest().clone();
                let sandbox_spec = metadata.sandbox_spec().clone();
                return self
                    .admit_workspace_apply_intent_inner_v1(
                        request_body,
                        artifacts,
                        &catalog,
                        protocol_version,
                        peer,
                        policy,
                        current_clock,
                        &manifest,
                        &sandbox_spec,
                        receiving,
                    )
                    .map(|outcome| (request_id, operation_id, operation, outcome));
            }
            StorageApplyAdmissionRoute::Generic => match receiving {
                Some(receiving) => self.coordinator.admit_apply_intent_receiving_v1(
                    request_body, artifacts, &catalog, protocol_version, peer, policy,
                    current_clock, None, receiving,
                ),
                None => self.coordinator.admit_apply_intent(
                    request_body, artifacts, &catalog, protocol_version, peer, policy, current_clock,
                ),
            },
        };
        let outcome =
            self.finish_live_transaction_mutation(result, StorageRuntimeError::Admission)?;
        Ok((request_id, operation_id, operation, outcome))
    }

    /// Executes one already-admitted Prepared effect under fresh authority.
    ///
    /// This method performs pre-observation and reopens current durable
    /// authority. Strict authenticated supersession aborts without sampling.
    /// An exact-current intent is sampled before Ambiguous; authenticated expiry
    /// aborts at that sample. Only Fresh authority crosses Ambiguous, consumes
    /// the one-shot proof with a second sample, and dispatches exactly once.
    /// Service code must not call it while [`Self::apply_readiness`] reports a
    /// held backend.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError::Recovery`] when persisted authority, an
    /// invalid clock sample, physical preconditions, dispatch, or postcondition
    /// observation fails. Strict supersession or authenticated expiry returns
    /// [`StorageRuntimeMutationOutcome::Aborted`] under the ordering above. A
    /// failure after the durable Ambiguous transition remains observation-only
    /// and is never retried here.
    pub fn execute_admitted<F>(
        &mut self,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.execute_admitted_inner_v1(operation_id, trusted_clock, None)
    }

    pub(crate) fn lifecycle_apply_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.startup_reconciliation.failure_with_guest_root_v2(
            &self.coordinator, &self.helper, self.guest_root_publication_failure_v2(),
        ).map(|cause| match cause.downcast_ref::<ZfsWorkerError>()
                .and_then(ZfsWorkerError::physical_native_refusal_v1)
            {
                Some(marker) => marker as &dyn std::error::Error,
                None => cause,
            })
    }

    pub(crate) fn lifecycle_state_journal_v1(&self) -> &aos_sandbox_controller_domain::Journal {
        self.coordinator.recovery_encoding_journal_v1()
    }

    pub(crate) fn execute_admitted_receiving_v1<F>(
        &mut self,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        receiving.require_models_current_v1(self.coordinator.recovery_encoding_journal_v1())
            .map_err(|_| StorageRuntimeError::Receiving)?;
        self.execute_admitted_inner_v1(operation_id, trusted_clock, Some(receiving))
    }

    fn execute_admitted_inner_v1<F>(
        &mut self,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
        mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        if self.original_service_lent && receiving.is_none() {
            return Err(StorageRuntimeError::Receiving);
        }
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !self.operation_permits_apply(operation_id)? {
            return Err(StorageRuntimeError::Recovery);
        }
        let prepared = match receiving.as_deref_mut() {
            Some(receiving) => {
                let result = self.coordinator.preobserve_receiving_v1(
                    &mut self.helper, operation_id, receiving,
                );
                self.startup_reconciliation.operation_result_v1(result, true)?
            }
            None => self.coordinator.preobserve(&mut self.helper, operation_id)
                .map_err(|_| StorageRuntimeError::Recovery)?,
        };
        let mutation_digest = prepared.entry().mutation_digest();
        let creates_workspace = matches!(
            prepared.catalog().plan(),
            crate::CatalogPlanV1::CreateWorkspace { .. } | crate::CatalogPlanV1::Clone { .. }
        );
        if !matches!(prepared.catalog().plan(),
            crate::CatalogPlanV1::ReleaseHold { .. }
                | crate::CatalogPlanV1::DestroyDataset { .. }
                | crate::CatalogPlanV1::DestroySnapshot { .. })
        {
            self.require_git_coverage_new_admission_v1()?;
        }
        let removal = self
            .coordinator
            .workspace_remove_pin_requirement(&prepared)
            .map_err(|_| StorageRuntimeError::Recovery)?;

        // Every path below can cross a physical-effect boundary. Close all
        // public gates until exact postconditions and catalog activation agree.
        self.latch_recovery_required();
        let committed = match removal {
            WorkspaceRemovePinRequirementV1::Required(expected_pin) => {
                let result = match receiving.as_deref_mut() {
                    Some(receiving) => self.coordinator.execute_workspace_remove_and_destroy_with_io_receiving_v1(
                        self.pin_io.as_mut(), &self.pin_contract, prepared, expected_pin, trusted_clock,
                        receiving, &mut self.startup_reconciliation.pin_remove_result,
                    ),
                    None => self.coordinator.execute_workspace_remove_and_destroy_with_io(
                        self.pin_io.as_mut(), &self.pin_contract, prepared, expected_pin, trusted_clock,
                    ),
                };
                let result = match receiving.as_ref() {
                    Some(_) => self.startup_reconciliation.operation_result_v1(result, true),
                    None => result.map_err(|_| StorageRuntimeError::Recovery),
                };
                let (pin_outcome, committed) = self
                    .finish_live_transaction_mutation(result, |_| StorageRuntimeError::Recovery)?;
                match pin_outcome {
                    WorkspacePinExecutionOutcomeV1::Satisfied => {}
                    WorkspacePinExecutionOutcomeV1::ObservationRequired => {
                        return Ok(StorageRuntimeMutationOutcome::ObservationRequired {
                            phase: DurableStoragePhase::Ambiguous,
                            mutation_digest,
                        });
                    }
                    WorkspacePinExecutionOutcomeV1::Aborted { mutation_digest } => {
                        return self.finish_aborted_mutation_inner_v1(mutation_digest, receiving.as_deref_mut());
                    }
                }
                committed.ok_or(StorageRuntimeError::Recovery)?
            }
            WorkspaceRemovePinRequirementV1::Missing => {
                return Err(StorageRuntimeError::Recovery);
            }
            WorkspaceRemovePinRequirementV1::NotWorkspace => {
                let execution = match receiving.as_deref_mut() {
                    Some(receiving) => self.coordinator.execute_preobserved_receiving_v1(
                        &mut self.helper, prepared, trusted_clock, receiving,
                    ),
                    None => self.coordinator.execute_preobserved(&mut self.helper, prepared, trusted_clock),
                };
                let execution = match receiving.as_ref() {
                    Some(_) => self.startup_reconciliation.operation_result_v1(execution, true),
                    None => execution.map_err(|_| StorageRuntimeError::Recovery),
                };
                match self.finish_live_transaction_mutation(execution, |error| error)? {
                    ZfsHelperOutcome::Committed(committed) => committed,
                    ZfsHelperOutcome::Aborted { mutation_digest } => {
                        return self.finish_aborted_mutation_inner_v1(mutation_digest, receiving.as_deref_mut());
                    }
                    ZfsHelperOutcome::ObservationRequired {
                        phase,
                        mutation_digest,
                    } => {
                        return Ok(StorageRuntimeMutationOutcome::ObservationRequired {
                            phase,
                            mutation_digest,
                        });
                    }
                }
            }
        };

        if creates_workspace {
            let result = match receiving.as_deref_mut() {
                Some(receiving) => self.coordinator.execute_workspace_pin_ensure_with_io_receiving_v1(
                    self.pin_io.as_mut(), &self.pin_contract, committed, trusted_clock, receiving,
                    &mut self.startup_reconciliation.pin_ensure_result,
                ),
                None => self.coordinator.execute_workspace_pin_ensure_with_io(
                    self.pin_io.as_mut(), &self.pin_contract, committed, trusted_clock,
                ),
            };
            let result = match receiving.as_ref() {
                Some(_) => self.startup_reconciliation.operation_result_v1(result, true),
                None => result.map_err(|_| StorageRuntimeError::Recovery),
            };
            let pin_outcome =
                self.finish_live_transaction_mutation(result, |_| StorageRuntimeError::Recovery)?;
            match pin_outcome {
                WorkspacePinExecutionOutcomeV1::Satisfied => {}
                WorkspacePinExecutionOutcomeV1::ObservationRequired => {
                    return Ok(StorageRuntimeMutationOutcome::ObservationRequired {
                        phase: DurableStoragePhase::Committed,
                        mutation_digest,
                    });
                }
                WorkspacePinExecutionOutcomeV1::Aborted { .. } => {
                    return Err(StorageRuntimeError::Recovery);
                }
            }
        }

        let readiness = match receiving {
            Some(receiving) => self.reconcile_entered_state_v1(receiving)?,
            None => self.reconcile_startup()?,
        };
        self.readiness = readiness;
        if !self.readiness.permits_catalog_methods() {
            return Ok(StorageRuntimeMutationOutcome::ObservationRequired {
                phase: DurableStoragePhase::Committed,
                mutation_digest,
            });
        }
        Ok(StorageRuntimeMutationOutcome::Committed(committed))
    }

    /// Closes every new worker launch before the final global cgroup drain.
    ///
    /// This is deliberately not an acquisition proof: no caller may yet hold
    /// this process and its protected journals across live physical readback,
    /// the Controller transaction, and ambiguous-outcome recovery.
    ///
    /// # Errors
    ///
    /// Rejects nonterminal or poisoned journal custody, an in-flight dispatch,
    /// or either global worker-scope scan failing to prove quiescence. Once
    /// admission closes, failure cannot reopen it in this process.
    #[allow(dead_code, reason = "Repair guard acquisition remains closed")]
    pub(crate) fn drain_repair_worker_dispatch(&mut self) -> Result<(), StorageRuntimeError> {
        if !self.is_inventory_ready() || self.coordinator.transaction_journal_requires_reopen() {
            return Err(StorageRuntimeError::Recovery);
        }

        close_and_drain_worker_scopes(
            &self.worker_dispatch,
            || self.pin_io.recover_quiescence().map_err(Into::into),
            || {
                let mut publisher = SystemdGuestRootPublisherClientV1::new(
                    PathBuf::from(GUEST_ROOT_PUBLISHER_SOCKET),
                    open_cgroup_root()?,
                )?;
                publisher.recover_quiescence().map_err(Into::into)
            },
        )
    }


    fn latch_recovery_required(&mut self) {
        let operations = match self.readiness {
            StorageRuntimeReadiness::RecoveryPending { operations } => operations.max(1),
            _ => 1,
        };
        self.readiness = StorageRuntimeReadiness::RecoveryPending { operations };
    }

    fn finish_aborted_mutation(
        &mut self,
        mutation_digest: ObjectDigest,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError> {
        self.finish_aborted_mutation_inner_v1(mutation_digest, None)
    }

    fn finish_aborted_mutation_inner_v1(
        &mut self,
        mutation_digest: ObjectDigest,
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError> {
        let readiness = match receiving {
            Some(receiving) => self.reconcile_entered_state_v1(receiving)?,
            None => self.reconcile_startup()?,
        };
        self.readiness = readiness;
        Ok(StorageRuntimeMutationOutcome::Aborted { mutation_digest })
    }

    fn latch_reopen_required(&mut self) {
        self.readiness = StorageRuntimeReadiness::ReopenRequired;
    }

    fn finish_live_transaction_mutation<T, E>(
        &mut self,
        result: Result<T, E>,
        ordinary_error: impl FnOnce(E) -> StorageRuntimeError,
    ) -> Result<T, StorageRuntimeError> {
        finish_live_transaction_mutation(
            &mut self.readiness,
            self.coordinator.transaction_journal_requires_reopen(),
            result,
            ordinary_error,
        )
    }
}

fn classify_held_snapshot_worker_result(
    readiness: &mut StorageRuntimeReadiness,
    result: Result<HeldSnapshotPhysicalObservationV1, crate::helper::ZfsHelperError>,
) -> Result<(u64, ObjectDigest), StorageRuntimeError> {
    match result {
        Ok(HeldSnapshotPhysicalObservationV1::Matched { pool_guid, digest }) => {
            Ok((pool_guid, digest))
        }
        Ok(HeldSnapshotPhysicalObservationV1::Mismatch)
        | Err(crate::helper::ZfsHelperError::ProcessContract) => Err(StorageRuntimeError::Recovery),
        Err(crate::helper::ZfsHelperError::Backend(ZfsWorkerError::Quiescence(_))) => {
            *readiness = StorageRuntimeReadiness::ReopenRequired;
            Err(StorageRuntimeError::ReopenRequired)
        }
        Err(_) => Err(StorageRuntimeError::Recovery),
    }
}

const fn private_identity_profile_supports_root(
    unmappable_policy: UnmappableIdentityPolicy,
    attributes: PortableRootAttributesV1,
    range_size: u32,
) -> bool {
    matches!(unmappable_policy, UnmappableIdentityPolicy::Reject)
        && attributes.uid() < range_size
        && attributes.gid() < range_size
}

fn finish_live_transaction_mutation<T, E>(
    readiness: &mut StorageRuntimeReadiness,
    transaction_journal_requires_reopen: bool,
    result: Result<T, E>,
    ordinary_error: impl FnOnce(E) -> StorageRuntimeError,
) -> Result<T, StorageRuntimeError> {
    // Only the store's explicit poison bit proves that a journal error may
    // have crossed durability without updating the in-memory projection.
    // Semantic State errors remain ordinary request failures.
    if transaction_journal_requires_reopen {
        *readiness = StorageRuntimeReadiness::ReopenRequired;
        return Err(StorageRuntimeError::ReopenRequired);
    }

    result.map_err(ordinary_error)
}

/// Samples the production kernel wall and boot clocks with the current boot identity.
///
/// BOOTTIME precedes the integer wall observation so sampling delays cannot
/// extend an expiry derived from the pair. Both reads share one boot identity.
/// This adapter does not alter the paired-clock continuity policy.
///
/// # Errors
///
/// Returns [`StorageRuntimeError::Recovery`] when the kernel boot identity or
/// either clock cannot form a valid paired sample, including a changed boot.
pub(crate) fn trusted_paired_clock_sample() -> Result<RawPairedClockSample, StorageRuntimeError> {
    paired_clock_sample_from_kernel_readers(
        || {
            KernelBootId::current()
                .map(KernelBootId::into_bytes)
                .map_err(|_| StorageRuntimeError::Recovery)
        },
        || boottime_now_nanoseconds().map_err(|_| StorageRuntimeError::Recovery),
        || rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec,
    )
}

// Kept private so only the fixed kernel adapter can provide production samples;
// injected readers exercise its exact ordering and failure paths in unit tests.
pub(crate) fn paired_clock_sample_from_kernel_readers(
    mut boot_identity: impl FnMut() -> Result<[u8; 16], StorageRuntimeError>,
    boottime: impl FnOnce() -> Result<u64, StorageRuntimeError>,
    wall_seconds: impl FnOnce() -> i64,
) -> Result<RawPairedClockSample, StorageRuntimeError> {
    let boot_before = boot_identity()?;
    let boottime_nanoseconds = boottime()?;
    let wall_seconds = wall_seconds();
    let boot_after = boot_identity()?;
    if boot_before != boot_after {
        return Err(StorageRuntimeError::Recovery);
    }

    let provenance = RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
        .map_err(|_| StorageRuntimeError::Recovery)?;
    RawPairedClockSample::new_untrusted(provenance, boot_before, wall_seconds, boottime_nanoseconds)
        .map_err(|_| StorageRuntimeError::Recovery)
}

fn finish_reopen_required_reconciliation(
    readiness: &mut StorageRuntimeReadiness,
    reconciliation: Result<StorageRuntimeReadiness, StorageRuntimeError>,
) -> Result<(), StorageRuntimeError> {
    debug_assert!(readiness.requires_reopen());
    match reconciliation {
        Ok(next) => {
            *readiness = next;
            Ok(())
        }
        Err(_) => Err(StorageRuntimeError::ReopenRequired),
    }
}

#[cfg(test)]
fn prepare_catalog_candidate_before_observation<T>(
    validated: ValidatedPendingStorageWorkspaceCatalogV1,
    physical_plan: AuthenticatedWorkspaceCatalogPhysicalPlanV1,
    request: WorkspaceCatalogObservationRequestV1,
    observe: impl FnOnce(&[u8], &WorkspaceCatalogObservationRequestV1) -> Result<T, StorageRuntimeError>,
) -> Result<
    (StorageWorkspaceCatalogActivationCandidateV1, T),
    (
        ValidatedPendingStorageWorkspaceCatalogV1,
        StorageRuntimeError,
    ),
> {
    let candidate = match StorageWorkspaceCatalogActivationCandidateV1::new(
        validated,
        physical_plan,
        request,
    ) {
        Ok(candidate) => candidate,
        Err(failure) => {
            let (validated, error) = failure.into_parts();
            return Err((validated, error.into()));
        }
    };
    let request_bytes = match encode_request(candidate.request()) {
        Ok(bytes) => bytes,
        Err(error) => return Err((candidate.into_validated(), error.into())),
    };
    match observe(&request_bytes, candidate.request()) {
        Ok(observation) => Ok((candidate, observation)),
        Err(error) => Err((candidate.into_validated(), error)),
    }
}

fn build_catalog_observation_request(
    configuration_binding: ObjectDigest,
    broker_instance_id: [u8; 16],
    pin_io: &dyn WorkspacePinRuntimeIo,
    validated: &ValidatedPendingStorageWorkspaceCatalogV1,
    plan: &crate::workspace_catalog::StorageWorkspaceCatalogPlanV1,
    physical_plan: &AuthenticatedWorkspaceCatalogPhysicalPlanV1,
    nonce: [u8; 32],
    deadline_boottime_nanoseconds: u64,
) -> Result<WorkspaceCatalogObservationRequestV1, StorageRuntimeError> {
    let snapshot = validated.snapshot();
    let catalog_generation = snapshot.catalog_generation().unwrap_or(1);
    let identity_pool = snapshot.identity_pool();
    let bindings = WorkspaceCatalogObservationBindingsV1::new(
        configuration_binding,
        broker_instance_id,
        plan.transaction_sequence(),
        plan.transaction_snapshot_digest(),
        plan.plan_digest(),
        plan.physical_head().0,
        plan.physical_head().1,
        snapshot.journal_sequence(),
        snapshot.digest(),
        catalog_generation,
        identity_pool.range_start(),
        identity_pool.range_size(),
    )?;
    let custody = pin_io
        .catalog_binding()
        .map_err(|_| StorageRuntimeError::WorkspacePinScope)?;
    WorkspaceCatalogObservationRequestV1::new(
        nonce,
        deadline_boottime_nanoseconds,
        bindings,
        custody,
        physical_plan.roots().to_vec(),
        physical_plan.allowed_objects().to_vec(),
        physical_plan.targets().to_vec(),
    )
    .map_err(Into::into)
}

pub(crate) fn authenticate_startup_authority(
    coordinator: &StorageAdmissionCoordinator,
) -> Result<(), StorageRuntimeError> {
    coordinator
        .authenticate_workspace_pin_attempts()
        .map_err(|_| StorageRuntimeError::Recovery)?;
    coordinator
        .authenticate_catalog_preparations()
        .map_err(|_| StorageRuntimeError::Recovery)?;
    coordinator
        .authenticate_atomic_snapshot_records()
        .map_err(|_| StorageRuntimeError::Recovery)
}

fn configure_resolver_policy(
    coordinator: &mut StorageAdmissionCoordinator,
    policy_directory: Option<&Path>,
    authority_binding: ObjectDigest,
) -> Result<
    (
        Option<ProtectedStorageResolverPolicyDirectoryV1>,
        StoragePrepareReadiness,
    ),
    StorageRuntimeError,
> {
    configure_resolver_policy_with_originals_v1(coordinator, policy_directory, authority_binding, None, None)
}

fn configure_resolver_policy_with_originals_v1(
    coordinator: &mut StorageAdmissionCoordinator,
    policy_directory: Option<&Path>,
    authority_binding: ObjectDigest,
    mut originals: Option<(
        &mut crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1,
        &mut crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1,
    )>,
    mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
) -> Result<(Option<ProtectedStorageResolverPolicyDirectoryV1>, StoragePrepareReadiness), StorageRuntimeError> {
    let Some(policy_directory) = policy_directory else {
        return Ok((None, StoragePrepareReadiness::Unconfigured));
    };
    let opened = match originals.as_mut() {
        Some((directory, _)) => ProtectedStorageResolverPolicyDirectoryV1::open_root_owned_retaining_v1(
            policy_directory, authority_binding, directory,
        ),
        None => ProtectedStorageResolverPolicyDirectoryV1::open_root_owned(policy_directory, authority_binding),
    };
    let protected = match opened {
        Ok(protected) => protected,
        Err(_) => return Ok((None, StoragePrepareReadiness::PolicyInvalid)),
    };
    classify_resolver_policy_publication_with_original_v1(protected, |binding| {
        match receiving.as_deref_mut() {
            Some(receiving) => coordinator.admit_recovery_resolver_policy_v1(binding, receiving),
            None => coordinator.admit_trusted_resolver_policy(binding),
        }
    }, originals.map(|(_, reader)| reader))
}

fn classify_resolver_policy_publication<F>(
    protected: ProtectedStorageResolverPolicyDirectoryV1,
    admit: F,
) -> Result<
    (
        Option<ProtectedStorageResolverPolicyDirectoryV1>,
        StoragePrepareReadiness,
    ),
    StorageRuntimeError,
>
where
    F: FnMut(
        crate::resolver::protected_catalog::StorageResolverPolicyCatalogBindingV1,
    )
        -> Result<crate::state::StorageResolverPolicyAdmissionOutcomeV1, StorageBrokerError>,
{
    classify_resolver_policy_publication_with_original_v1(protected, admit, None)
}

fn classify_resolver_policy_publication_with_original_v1<F>(
    protected: ProtectedStorageResolverPolicyDirectoryV1,
    mut admit: F,
    original: Option<&mut crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1>,
) -> Result<(Option<ProtectedStorageResolverPolicyDirectoryV1>, StoragePrepareReadiness), StorageRuntimeError>
where
    F: FnMut(crate::resolver::protected_catalog::StorageResolverPolicyCatalogBindingV1)
        -> Result<crate::state::StorageResolverPolicyAdmissionOutcomeV1, StorageBrokerError>,
{
    let loaded = match original {
        Some(original) => protected.load_retaining_v1(original),
        None => protected.load(),
    };
    let binding = match loaded.and_then(|catalog| catalog.binding()) {
        Ok(binding) => binding,
        Err(_) => return Ok((Some(protected), StoragePrepareReadiness::PolicyInvalid)),
    };
    let readiness = match admit(binding) {
        Ok(_) => StoragePrepareReadiness::Ready,
        Err(StorageBrokerError::State(StorageStateError::Rollback)) => {
            StoragePrepareReadiness::PolicyInvalid
        }
        Err(error) => return Err(StorageRuntimeError::Admission(error)),
    };
    Ok((Some(protected), readiness))
}

fn authenticate_before_workspace_inventory<T>(
    authenticate: impl FnOnce() -> Result<(), StorageRuntimeError>,
    open_inventory: impl FnOnce() -> Result<T, StorageRuntimeError>,
) -> Result<T, StorageRuntimeError> {
    authenticate()?;
    open_inventory()
}

/// Retires inactive transactions before opening and validating workspace state.
///
/// # Errors
///
/// Returns [`StorageRuntimeError`] for unauthenticated transaction authority,
/// failed clock acquisition, retirement publication, workspace open, or plan
/// validation. An indeterminate retirement commit requires protected reopen.
pub(crate) fn open_validated_workspace_catalog_after_startup<F, O>(
    coordinator: &mut StorageAdmissionCoordinator,
    trusted_clock: &mut F,
    open_inventory: O,
) -> Result<ValidatedPendingStorageWorkspaceCatalogV1, StorageRuntimeError>
where
    F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    O: FnOnce() -> Result<PendingStorageWorkspaceCatalogV1, StorageRuntimeError>,
{
    authenticate_startup_authority(coordinator)?;
    coordinator
        .retire_inactive_prepared_at_startup(trusted_clock)
        .map_err(|_| {
            if coordinator.transaction_journal_requires_reopen() {
                StorageRuntimeError::ReopenRequired
            } else {
                StorageRuntimeError::Recovery
            }
        })?;
    let pending = authenticate_before_workspace_inventory(
        || authenticate_startup_authority(coordinator),
        open_inventory,
    )?;
    let (workspace_plan, _) = coordinator.workspace_catalog_activation_plan()?;
    pending.validate_plan(workspace_plan).map_err(Into::into)
}

/// Reconciles nonterminal transaction entries through observation only.
///
/// # Errors
///
/// Returns [`StorageRuntimeError::Recovery`] when authenticated recovery or
/// postcondition observation fails closed.
pub(crate) fn reconcile_transaction_recovery<B: crate::helper::ZfsProcessBackend>(
    coordinator: &mut StorageAdmissionCoordinator,
    helper: &mut StorageMutationHelper<B>,
) -> Result<usize, StorageRuntimeError> {
    let mut original = transaction_recovery::TransactionRecoveryOriginalV1::new();
    original.run(coordinator, helper, None)
}

/// Classifies whether startup recovery must remain pending.
pub(crate) const fn pending_startup_readiness(
    pending_operations: usize,
    has_physical_plan: bool,
) -> Option<StorageRuntimeReadiness> {
    if pending_operations != 0 || !has_physical_plan {
        let operations = if pending_operations == 0 {
            1
        } else {
            pending_operations
        };
        Some(StorageRuntimeReadiness::RecoveryPending { operations })
    } else {
        None
    }
}

pub(crate) fn runtime_configuration_binding(
    authority_binding: ObjectDigest,
    identity_pool: StorageIdentityPoolV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RUNTIME_BINDING_DOMAIN);
    digest.update(authority_binding.as_bytes());
    digest.update(identity_pool.range_start().to_be_bytes());
    digest.update(identity_pool.range_size().to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn catalog_observation_nonce() -> Result<[u8; 32], ZfsWorkerError> {
    let first = random_challenge()?;
    let second = random_challenge()?;
    let mut nonce = [0_u8; 32];
    nonce[..16].copy_from_slice(&first);
    nonce[16..].copy_from_slice(&second);
    Ok(nonce)
}

fn reserve_identity_range(
    pool: StorageIdentityPoolV1,
    transaction_ranges: &[(u32, u32)],
    requested_size: u32,
) -> Result<u32, StorageWorkspaceCatalogError> {
    let (pool_end, ranges) = validate_identity_ranges(pool, transaction_ranges)?;
    let mut candidate = pool.range_start();
    for (start, end) in ranges {
        let candidate_end = candidate
            .checked_add(requested_size)
            .ok_or(StorageWorkspaceCatalogError::IdentityExhausted)?;
        if candidate_end <= start {
            return Ok(candidate);
        }
        candidate = candidate.max(end);
    }
    candidate
        .checked_add(requested_size)
        .filter(|end| *end <= pool_end)
        .map(|_| candidate)
        .ok_or(StorageWorkspaceCatalogError::IdentityExhausted)
}

fn select_identity_range_for_apply(
    pool: StorageIdentityPoolV1,
    transaction_ranges: &[(u32, u32)],
    retained_range: Option<(u32, u32)>,
    requested_size: u32,
) -> Result<u32, StorageWorkspaceCatalogError> {
    let Some((range_start, range_size)) = retained_range else {
        return reserve_identity_range(pool, transaction_ranges, requested_size);
    };
    let (_, validated_ranges) = validate_identity_ranges(pool, transaction_ranges)?;
    let range_end = range_start
        .checked_add(range_size)
        .ok_or(StorageWorkspaceCatalogError::IdentityConflict)?;
    if range_size != requested_size
        || validated_ranges
            .binary_search(&(range_start, range_end))
            .is_err()
    {
        return Err(StorageWorkspaceCatalogError::IdentityConflict);
    }
    Ok(range_start)
}

fn validate_identity_ranges(
    pool: StorageIdentityPoolV1,
    transaction_ranges: &[(u32, u32)],
) -> Result<(u32, Vec<(u32, u32)>), StorageWorkspaceCatalogError> {
    let pool_end = pool
        .range_start()
        .checked_add(pool.range_size())
        .ok_or(StorageWorkspaceCatalogError::InvalidCandidate)?;
    let mut ranges = transaction_ranges
        .iter()
        .map(|(start, size)| {
            let end = start
                .checked_add(*size)
                .ok_or(StorageWorkspaceCatalogError::IdentityConflict)?;
            if *start < pool.range_start() || end > pool_end {
                return Err(StorageWorkspaceCatalogError::IdentityConflict);
            }
            Ok((*start, end))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(StorageWorkspaceCatalogError::IdentityConflict);
    }
    Ok((pool_end, ranges))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageApplyAdmissionRoute {
    Workspace,
    Generic,
}

const fn apply_admission_route(operation: StorageOperation) -> StorageApplyAdmissionRoute {
    if operation.requires_workspace_metadata() {
        StorageApplyAdmissionRoute::Workspace
    } else {
        StorageApplyAdmissionRoute::Generic
    }
}

impl From<ZfsHelperOutcome> for StorageRuntimeMutationOutcome {
    fn from(value: ZfsHelperOutcome) -> Self {
        match value {
            ZfsHelperOutcome::Committed(result) => Self::Committed(result),
            ZfsHelperOutcome::Aborted { mutation_digest } => Self::Aborted { mutation_digest },
            ZfsHelperOutcome::ObservationRequired {
                phase,
                mutation_digest,
            } => Self::ObservationRequired {
                phase,
                mutation_digest,
            },
        }
    }
}

// These are the actual fixed Runtime owners, distinct from each contacted
// worker's prepaid receipt peak: four manager/worker-parent cgroup pairs,
// the initial host namespace and pin-root pair, and Snapshot metadata directory.
// The genuine construction debits this set before creating its Runtime owners.
fn storage_runtime_fixed_receiving_demand_v1() -> aos_sandbox_model::ResourceVector {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    ResourceVector::ZERO.with(D::OpenFiles, 11)
}

struct ProtectedStorageBootstrap {
    minimum_generation: u64,
    genesis_generation: u64,
    catalogs: Vec<ResolvedCatalogCommitmentV1>,
}

impl ProtectedStorageBootstrap {
    /// Prices the unchanged binary bootstrap limits before its first read.
    fn receiving_demand_v1()
        -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        // Catalogs use the strict16KiB typed binary codec, not an arbitrary
        // JSON/union model. The header may claim256 catalogs before their
        // bodies arrive. Price those actual carriers independently of bytes.
        let cell = (std::mem::size_of::<ResolvedCatalogCommitmentV1>()
            + std::mem::size_of::<crate::ResolvedSnapshot>() + 8 * 255) as u64;
        let models = cell.checked_mul(MAXIMUM_BOOTSTRAP_CATALOGS as u64)
            .and_then(|value| value.checked_mul(32))
            .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        // Includes full bounded read/growth even on changed or truncated files,
        // typed/canonical catalog copies, and the separately retained8-byte floor.
        let memory = models.checked_add((16 * MAXIMUM_BOOTSTRAP_BYTES) as u64)
            .and_then(|value| value.checked_add(std::mem::size_of::<bootstrap_open::ProtectedStorageBootstrapOpenV1>() as u64
                + std::mem::size_of::<Self>() as u64 + 64 * 1024))
            .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, 32 * MAXIMUM_BOOTSTRAP_CATALOGS as u64)
            .with(D::OpenFiles, 4))
    }

    fn open_root_owned(directory: &Path) -> Result<Self, StorageRuntimeError> {
        Self::open_with_owner(directory, 0)
    }

    fn open_with_owner(directory: &Path, expected_uid: u32) -> Result<Self, StorageRuntimeError> {
        let directory = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageRuntimeError::Bootstrap)?;
        validate_directory(&directory, expected_uid)?;
        let minimum_bytes = read_protected(&directory, MINIMUM_GENERATION_FILE, 8, expected_uid)?;
        let minimum_generation = decode_bootstrap_minimum_v1(&minimum_bytes)?;
        let bytes = read_protected(
            &directory,
            BOOTSTRAP_FILE,
            MAXIMUM_BOOTSTRAP_BYTES,
            expected_uid,
        )?;
        let (genesis_generation, catalogs) = decode_bootstrap(&bytes)?;
        Ok(Self {
            minimum_generation,
            genesis_generation,
            catalogs,
        })
    }
}

fn validate_directory(directory: &OwnedFd, expected_uid: u32) -> Result<(), StorageRuntimeError> {
    let metadata = fstat(directory).map_err(|_| StorageRuntimeError::Bootstrap)?;
    validate_bootstrap_directory_metadata_v1(&metadata, expected_uid)
}

fn validate_bootstrap_directory_metadata_v1(
    metadata: &rustix::fs::Stat,
    expected_uid: u32,
) -> Result<(), StorageRuntimeError> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != expected_uid
        || !matches!(metadata.st_mode & 0o7777, 0o500 | 0o700)
    {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok(())
}

fn read_protected(
    directory: &OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
    expected_uid: u32,
) -> Result<Vec<u8>, StorageRuntimeError> {
    let mut read = bootstrap_open::ProtectedBootstrapFileReadV1::new();
    read.read_once_v1(directory, name, maximum_bytes, expected_uid)?;
    read.dispose_positive_file_v1();
    read.require_length_v1(maximum_bytes)?;
    Ok(std::mem::take(&mut read.bytes))
}

fn decode_bootstrap_minimum_v1(minimum_bytes: &[u8]) -> Result<u64, StorageRuntimeError> {
    if minimum_bytes.len() != 8 {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let minimum_generation = u64::from_be_bytes(
        minimum_bytes.try_into().map_err(|_| StorageRuntimeError::Bootstrap)?,
    );
    if minimum_generation == 0 {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok(minimum_generation)
}

fn decode_bootstrap(
    bytes: &[u8],
) -> Result<(u64, Vec<ResolvedCatalogCommitmentV1>), StorageRuntimeError> {
    if bytes.len() < BOOTSTRAP_HEADER_BYTES
        || &bytes[..8] != BOOTSTRAP_MAGIC
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| StorageRuntimeError::Bootstrap)?,
        ) != BOOTSTRAP_VERSION
        || bytes[10..12] != [0; 2]
    {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let generation = u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| StorageRuntimeError::Bootstrap)?,
    );
    let count = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| StorageRuntimeError::Bootstrap)?,
    ) as usize;
    if generation == 0 || count == 0 || count > MAXIMUM_BOOTSTRAP_CATALOGS {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let mut offset = BOOTSTRAP_HEADER_BYTES;
    let mut catalogs = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = offset
            .checked_add(4)
            .ok_or(StorageRuntimeError::Bootstrap)?;
        let length = u32::from_be_bytes(
            bytes
                .get(offset..length_end)
                .ok_or(StorageRuntimeError::Bootstrap)?
                .try_into()
                .map_err(|_| StorageRuntimeError::Bootstrap)?,
        ) as usize;
        offset = length_end;
        let end = offset
            .checked_add(length)
            .ok_or(StorageRuntimeError::Bootstrap)?;
        let catalog_bytes = bytes
            .get(offset..end)
            .ok_or(StorageRuntimeError::Bootstrap)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(catalog_bytes)
            .map_err(|_| StorageRuntimeError::Bootstrap)?;
        catalogs.push(catalog);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok((generation, catalogs))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;
    use crate::held_snapshot_tree::HeldSnapshotIdentityObservationV1;
    use crate::resolver::protected_catalog::{
        ProtectedStorageResolverPolicyDirectoryV1, encode_catalog_for_test,
    };
    use crate::state::StorageResolverPolicyAdmissionOutcomeV1;
    use crate::workspace_catalog::StorageWorkspaceCatalogPlanV1;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    #[test]
    fn operator_provisioning_preserves_the_original_journal_cause() {
        let cause = crate::operator_recovery::StorageOperatorRecoveryErrorV1::Journal(
            aos_sandbox_controller_domain::JournalError::AlreadyLocked,
        );
        let error = StorageRuntimeError::from(cause);

        assert!(matches!(
            error,
            StorageRuntimeError::OperatorProvision(
                crate::operator_recovery::StorageOperatorRecoveryErrorV1::Journal(
                    aos_sandbox_controller_domain::JournalError::AlreadyLocked,
                ),
            ),
        ));
    }

    #[test]
    fn operator_provisioning_preserves_the_original_credential_cause() {
        let cause = crate::service::StorageServiceError::Activation("original role cause".to_owned());
        let error = StorageRuntimeError::OperatorProvisionCredentials(Box::new(cause));
        let StorageRuntimeError::OperatorProvisionCredentials(cause) = error else {
            panic!("the provisioning source must remain typed");
        };

        assert!(matches!(
            *cause,
            crate::service::StorageServiceError::Activation(ref message)
                if message == "original role cause",
        ));
    }

    #[test]
    fn kernel_paired_clock_sampling_brackets_boot_and_reads_boot_time_before_wall() {
        let calls = RefCell::new(Vec::new());
        let sample = paired_clock_sample_from_kernel_readers(
            || {
                calls.borrow_mut().push("boot identity");
                Ok([1; 16])
            },
            || {
                calls.borrow_mut().push("BOOTTIME");
                Ok(123)
            },
            || {
                calls.borrow_mut().push("REALTIME");
                100
            },
        )
        .unwrap();

        assert_eq!(
            *calls.borrow(),
            ["boot identity", "BOOTTIME", "REALTIME", "boot identity"]
        );
        assert_eq!(sample.host_boot_id(), [1; 16]);
        assert_eq!(sample.boottime_nanoseconds(), 123);
        assert_eq!(sample.wall_seconds(), 100);
    }

    #[test]
    fn kernel_paired_clock_sampling_rejects_changed_boot_and_read_errors() {
        let boot_reads = Cell::new(0);
        let changed_boot = paired_clock_sample_from_kernel_readers(
            || {
                boot_reads.set(boot_reads.get() + 1);
                Ok([boot_reads.get(); 16])
            },
            || Ok(123),
            || 100,
        );
        assert!(matches!(changed_boot, Err(StorageRuntimeError::Recovery)));

        let failed_boot = paired_clock_sample_from_kernel_readers(
            || Err(StorageRuntimeError::Recovery),
            || panic!("failed boot read must stop before either clock"),
            || panic!("failed boot read must stop before either clock"),
        );
        assert!(matches!(failed_boot, Err(StorageRuntimeError::Recovery)));

        let failed_clock = paired_clock_sample_from_kernel_readers(
            || Ok([1; 16]),
            || Err(StorageRuntimeError::Recovery),
            || panic!("failed BOOTTIME read must stop before REALTIME"),
        );
        assert!(matches!(failed_clock, Err(StorageRuntimeError::Recovery)));
    }

    #[test]
    fn held_snapshot_identity_must_match_the_unchanged_protected_metadata() {
        let root = PortableRootAttributesV1::new(0, 0, 0o755).unwrap();
        let observed = HeldSnapshotIdentityObservationV1 {
            root_attributes: root,
            maximum_portable_uid: 17,
            maximum_portable_gid: 23,
            distinct_inode_count: 3,
            directory_entry_count: 2,
            identity_tree_digest: ObjectDigest::from_bytes([11; 32]),
        };
        let metadata = |maximum_uid, digest| {
            CheckedSnapshotMetadataRecordV1::new_for_test(
                [1; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                aos_sandbox_protocol::semantics::CatalogBindingV1::from_publisher(
                    1,
                    ObjectDigest::from_bytes([4; 32]),
                )
                .unwrap(),
                5,
                6,
                [7; 32],
                ObjectDigest::from_bytes([8; 32]),
                root,
                maximum_uid,
                23,
                3,
                2,
                digest,
            )
            .unwrap()
        };

        assert!(identity_observation_matches_snapshot_metadata(
            observed,
            metadata(17, ObjectDigest::from_bytes([11; 32])),
        ));
        assert!(!identity_observation_matches_snapshot_metadata(
            observed,
            metadata(18, ObjectDigest::from_bytes([11; 32])),
        ));
        assert!(!identity_observation_matches_snapshot_metadata(
            observed,
            metadata(17, ObjectDigest::from_bytes([12; 32])),
        ));
        assert!(!identity_observation_matches_snapshot_metadata(
            HeldSnapshotIdentityObservationV1 {
                directory_entry_count: 1,
                ..observed
            },
            metadata(17, ObjectDigest::from_bytes([11; 32])),
        ));
        assert!(!identity_observation_matches_snapshot_metadata(
            HeldSnapshotIdentityObservationV1 {
                root_attributes: PortableRootAttributesV1::new(1, 0, 0o755).unwrap(),
                ..observed
            },
            metadata(17, ObjectDigest::from_bytes([11; 32])),
        ));
    }

    fn catalog(generation: u64) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 11, [5; 32], domains)
                .unwrap();
        let destination =
            PlannedDataset::from_catalog(root, "tank/aos/project/work", domains).unwrap();
        ResolvedCatalogCommitmentV1::new_for_test(
            generation,
            domains,
            CatalogPlanV1::CreateWorkspace {
                destination,
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor, 65_536, 8, 16).unwrap(),
            },
        )
        .unwrap()
    }

    fn empty_workspace_plan() -> StorageWorkspaceCatalogPlanV1 {
        StorageWorkspaceCatalogPlanV1::new(
            31,
            ObjectDigest::from_bytes([32; 32]),
            ObjectDigest::from_bytes([33; 32]),
            34,
            ObjectDigest::from_bytes([35; 32]),
            Vec::new(),
        )
        .unwrap()
    }

    fn empty_observation_request(
        validated: &ValidatedPendingStorageWorkspaceCatalogV1,
    ) -> WorkspaceCatalogObservationRequestV1 {
        let plan = validated.plan();
        let snapshot = validated.snapshot();
        let identity_pool = snapshot.identity_pool();
        let generation = snapshot.catalog_generation().unwrap_or(1);
        WorkspaceCatalogObservationRequestV1::new(
            [36; 32],
            37,
            WorkspaceCatalogObservationBindingsV1::new(
                ObjectDigest::from_bytes([38; 32]),
                [39; 16],
                plan.transaction_sequence(),
                plan.transaction_snapshot_digest(),
                plan.plan_digest(),
                plan.physical_head().0,
                plan.physical_head().1,
                snapshot.journal_sequence(),
                snapshot.digest(),
                generation,
                identity_pool.range_start(),
                identity_pool.range_size(),
            )
            .unwrap(),
            crate::observation_protocol::WorkspaceCatalogCustodyBindingV1::new(
                [40; 16], 41, 42, 43, 44, 45,
            )
            .unwrap(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    fn encode_bootstrap(generation: u64, catalogs: &[ResolvedCatalogCommitmentV1]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BOOTSTRAP_MAGIC);
        bytes.extend_from_slice(&BOOTSTRAP_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&(catalogs.len() as u32).to_be_bytes());
        for catalog in catalogs {
            bytes.extend_from_slice(&(catalog.canonical_bytes().len() as u32).to_be_bytes());
            bytes.extend_from_slice(catalog.canonical_bytes());
        }
        bytes
    }

    #[test]
    fn bootstrap_decoder_requires_exact_canonical_bounded_sequence() {
        let catalog = catalog(7);
        let bytes = encode_bootstrap(6, std::slice::from_ref(&catalog));
        let (generation, decoded) = decode_bootstrap(&bytes).unwrap();
        assert_eq!(generation, 6);
        assert_eq!(decoded, vec![catalog]);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_bootstrap(&trailing).is_err());
        assert!(decode_bootstrap(&encode_bootstrap(6, &[])).is_err());
    }

    #[test]
    fn reopen_required_closes_catalog_repair_and_apply_readiness() {
        let mut readiness = StorageRuntimeReadiness::Ready;
        assert!(readiness.permits_catalog_methods());
        assert!(readiness.permits_repair());

        // A completed repair latches fail-stop before catalog reconciliation.
        readiness = StorageRuntimeReadiness::ReopenRequired;
        let error = finish_reopen_required_reconciliation(
            &mut readiness,
            Err(StorageRuntimeError::ReopenRequired),
        )
        .unwrap_err();

        assert!(matches!(error, StorageRuntimeError::ReopenRequired));
        assert!(readiness.requires_reopen());
        assert!(!readiness.permits_catalog_methods());
        assert!(!readiness.permits_repair());
        assert!(!matches!(readiness, StorageRuntimeReadiness::Ready));
    }

    #[test]
    fn held_snapshot_worker_quiescence_failure_latches_reopen() {
        let mut readiness = StorageRuntimeReadiness::Ready;
        let result = classify_held_snapshot_worker_result(
            &mut readiness,
            Err(crate::helper::ZfsHelperError::Backend(
                ZfsWorkerError::Quiescence("worker escaped cgroup".to_owned()),
            )),
        );

        assert!(matches!(result, Err(StorageRuntimeError::ReopenRequired)));
        assert_eq!(readiness, StorageRuntimeReadiness::ReopenRequired);
        assert!(!readiness.permits_catalog_methods());
        assert!(!readiness.permits_repair());
    }

    #[test]
    fn held_snapshot_mismatch_and_lost_reply_never_return_a_sample() {
        let mut readiness = StorageRuntimeReadiness::Ready;
        for result in [
            Ok(HeldSnapshotPhysicalObservationV1::Mismatch),
            Err(crate::helper::ZfsHelperError::Backend(
                ZfsWorkerError::Transport(
                    aos_sandbox_linux::seqpacket::SeqpacketError::EmptyRecord,
                ),
            )),
        ] {
            assert!(matches!(
                classify_held_snapshot_worker_result(&mut readiness, result),
                Err(StorageRuntimeError::Recovery)
            ));
            assert_eq!(readiness, StorageRuntimeReadiness::Ready);
        }
    }

    #[test]
    fn runtime_keeps_send_across_private_effect_adapters() {
        fn require_send<T: Send>() {}

        require_send::<StorageBrokerRuntime>();
    }

    #[test]
    fn only_explicit_transaction_poison_latches_reopen_required() {
        let mut readiness = StorageRuntimeReadiness::Ready;
        let ordinary = finish_live_transaction_mutation(
            &mut readiness,
            false,
            Err::<(), _>(StorageBrokerError::State(StorageStateError::InvalidValue)),
            StorageRuntimeError::Admission,
        )
        .unwrap_err();
        assert!(matches!(
            ordinary,
            StorageRuntimeError::Admission(StorageBrokerError::State(
                StorageStateError::InvalidValue
            ))
        ));
        assert_eq!(readiness, StorageRuntimeReadiness::Ready);

        let poisoned = finish_live_transaction_mutation(
            &mut readiness,
            true,
            Err::<(), _>(StorageBrokerError::State(StorageStateError::Journal(
                aos_sandbox_controller_domain::JournalError::Poisoned,
            ))),
            StorageRuntimeError::Admission,
        )
        .unwrap_err();
        assert!(matches!(poisoned, StorageRuntimeError::ReopenRequired));
        assert!(readiness.requires_reopen());
        assert!(!readiness.permits_catalog_methods());
        assert!(!readiness.permits_repair());
    }

    #[test]
    fn startup_readiness_requires_both_pin_and_catalog_reconciliation() {
        let catalog_current_but_pin_pending = pending_startup_readiness(1, true);
        assert_eq!(
            catalog_current_but_pin_pending,
            Some(StorageRuntimeReadiness::RecoveryPending { operations: 1 })
        );
        let repaired_pin_but_catalog_pending = pending_startup_readiness(0, false);
        assert_eq!(
            repaired_pin_but_catalog_pending,
            Some(StorageRuntimeReadiness::RecoveryPending { operations: 1 })
        );
        assert_eq!(pending_startup_readiness(0, true), None);
    }

    #[test]
    fn headless_catalog_observes_before_any_materialization() {
        let directory = TempDir::new().unwrap();
        let identity_pool = StorageIdentityPoolV1::new(65_536, 65_536).unwrap();
        let pending =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        let validated = pending.validate_plan(empty_workspace_plan()).unwrap();
        let request = empty_observation_request(&validated);
        let observer_called = Cell::new(false);

        let (candidate, ()) = prepare_catalog_candidate_before_observation(
            validated,
            AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            request,
            |_, _| {
                observer_called.set(true);
                Ok(())
            },
        )
        .ok()
        .unwrap();

        assert!(observer_called.get());
        let validated = candidate.into_validated();
        assert!(!validated.is_initialized());
        assert_eq!(validated.plan(), &empty_workspace_plan());
    }

    #[test]
    fn observer_failure_restores_validated_catalog_custody() {
        let directory = TempDir::new().unwrap();
        let identity_pool = StorageIdentityPoolV1::new(65_536, 65_536).unwrap();
        let pending =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        let validated = pending.validate_plan(empty_workspace_plan()).unwrap();
        let snapshot = validated.snapshot();
        let request = empty_observation_request(&validated);
        let observer_called = Cell::new(false);

        let failure = prepare_catalog_candidate_before_observation::<()>(
            validated,
            AuthenticatedWorkspaceCatalogPhysicalPlanV1::new_for_test(
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            request,
            |_, _| {
                observer_called.set(true);
                Err(StorageRuntimeError::Recovery)
            },
        )
        .err()
        .unwrap();

        assert!(observer_called.get());
        assert_eq!(failure.0.snapshot(), snapshot);
        assert!(!failure.0.is_initialized());
        assert!(!failure.0.is_terminally_materialized());
    }

    #[test]
    fn runtime_configuration_binding_covers_authority_and_identity_pool() {
        let range = aos_sandbox_protocol::MINIMUM_HOST_IDENTITY_RANGE;
        let authority = ObjectDigest::from_bytes([21; 32]);
        let pool = StorageIdentityPoolV1::new(range, range * 4).unwrap();
        let binding = runtime_configuration_binding(authority, pool);

        assert_eq!(binding, runtime_configuration_binding(authority, pool));
        assert_ne!(
            binding,
            runtime_configuration_binding(ObjectDigest::from_bytes([22; 32]), pool)
        );
        assert_ne!(
            binding,
            runtime_configuration_binding(
                authority,
                StorageIdentityPoolV1::new(range * 2, range * 4).unwrap(),
            )
        );
        assert_ne!(
            binding,
            runtime_configuration_binding(
                authority,
                StorageIdentityPoolV1::new(range, range * 5).unwrap(),
            )
        );
    }

    #[test]
    fn protected_bootstrap_defers_generation_floor_to_locked_state_open() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("bootstrap");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_uid = fs::metadata(&directory).unwrap().uid();
        let catalog = catalog(7);

        let minimum_path = directory.join(MINIMUM_GENERATION_FILE);
        fs::write(&minimum_path, 5_u64.to_be_bytes()).unwrap();
        fs::set_permissions(&minimum_path, fs::Permissions::from_mode(0o600)).unwrap();
        let bootstrap_path = directory.join(BOOTSTRAP_FILE);
        fs::write(&bootstrap_path, encode_bootstrap(6, &[catalog])).unwrap();
        fs::set_permissions(&bootstrap_path, fs::Permissions::from_mode(0o600)).unwrap();

        let below_genesis =
            ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).unwrap();
        assert_eq!(below_genesis.minimum_generation, 5);
        assert_eq!(below_genesis.genesis_generation, 6);

        // An evolved journal may have advanced beyond both values. Only the
        // locked state opener can distinguish that restart from first boot.
        fs::write(&minimum_path, 8_u64.to_be_bytes()).unwrap();
        let above_genesis =
            ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).unwrap();
        assert_eq!(above_genesis.minimum_generation, 8);
        assert_eq!(above_genesis.genesis_generation, 6);

        fs::set_permissions(&minimum_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).is_err());
    }

    #[test]
    fn selected_bootstrap_keeps_native_reads_after_decode_refusal() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("bootstrap");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_uid = fs::metadata(&directory).unwrap().uid();
        let minimum_path = directory.join(MINIMUM_GENERATION_FILE);
        fs::write(&minimum_path, 5_u64.to_be_bytes()).unwrap();
        fs::set_permissions(&minimum_path, fs::Permissions::from_mode(0o600)).unwrap();
        let bootstrap_path = directory.join(BOOTSTRAP_FILE);
        fs::write(&bootstrap_path, b"malformed canonical bootstrap").unwrap();
        fs::set_permissions(&bootstrap_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut selected = bootstrap_open::ProtectedStorageBootstrapOpenV1::new();

        assert!(matches!(selected.capture_once_v1(&directory, expected_uid),
            Err(StorageRuntimeError::Bootstrap)));
        assert_eq!(selected.retained_file_count_v1(), 3);
        let first = selected.failure().unwrap().downcast_ref::<StorageRuntimeError>()
            .unwrap() as *const StorageRuntimeError;
        assert!(selected.take_success_v1().is_none());

        fs::write(&bootstrap_path, encode_bootstrap(6, &[catalog(7)])).unwrap();
        assert!(selected.capture_once_v1(&directory, expected_uid).is_err());
        assert_eq!(selected.retained_file_count_v1(), 3);
        assert_eq!(selected.failure().unwrap().downcast_ref::<StorageRuntimeError>()
            .unwrap() as *const StorageRuntimeError, first);
        assert!(selected.take_success_v1().is_none());
        assert!(ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).is_ok());
    }

    #[test]
    fn selected_bootstrap_handoff_keeps_originals_and_matches_ordinary_decoder() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("bootstrap");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_uid = fs::metadata(&directory).unwrap().uid();
        let minimum_path = directory.join(MINIMUM_GENERATION_FILE);
        fs::write(&minimum_path, 5_u64.to_be_bytes()).unwrap();
        fs::set_permissions(&minimum_path, fs::Permissions::from_mode(0o600)).unwrap();
        let bootstrap_path = directory.join(BOOTSTRAP_FILE);
        fs::write(&bootstrap_path, encode_bootstrap(6, &[catalog(7)])).unwrap();
        fs::set_permissions(&bootstrap_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut selected = bootstrap_open::ProtectedStorageBootstrapOpenV1::new();

        selected.capture_once_v1(&directory, expected_uid).unwrap();
        let owner = selected.take_success_v1().unwrap();
        let ordinary = ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).unwrap();
        assert_eq!(owner.minimum_generation, ordinary.minimum_generation);
        assert_eq!(owner.genesis_generation, ordinary.genesis_generation);
        assert_eq!(owner.catalogs, ordinary.catalogs);
        assert_eq!(selected.retained_file_count_v1(), 3);
        assert!(selected.failure().is_none());
        assert!(selected.take_success_v1().is_none());
    }

    #[test]
    fn repair_authority_precedes_workspace_inventory_and_failure_stops_open() {
        let order = RefCell::new(Vec::new());
        let inventory = authenticate_before_workspace_inventory(
            || {
                order.borrow_mut().push("authority");
                Ok(())
            },
            || {
                order.borrow_mut().push("inventory");
                Ok(7)
            },
        )
        .unwrap();
        assert_eq!(inventory, 7);
        assert_eq!(*order.borrow(), ["authority", "inventory"]);

        let inventory_opened = std::cell::Cell::new(false);
        let rejected = authenticate_before_workspace_inventory::<()>(
            || Err(StorageRuntimeError::Recovery),
            || {
                inventory_opened.set(true);
                Ok(())
            },
        );
        assert!(matches!(rejected, Err(StorageRuntimeError::Recovery)));
        assert!(!inventory_opened.get());
    }

    #[test]
    fn resolver_policy_publication_has_bounded_ready_invalid_and_rollback_states() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("policy");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_uid = fs::metadata(&directory).unwrap().uid();
        let authority = ObjectDigest::from_bytes([21; 32]);
        let catalog_path = directory.join("storage-resolver-policy.catalog");
        fs::write(&catalog_path, encode_catalog_for_test(7, authority, &[])).unwrap();
        fs::set_permissions(&catalog_path, fs::Permissions::from_mode(0o600)).unwrap();

        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_for_test(
            &directory,
            authority,
            expected_uid,
        )
        .unwrap();
        let admissions = std::cell::Cell::new(0);
        let (retained, readiness) = classify_resolver_policy_publication(protected, |binding| {
            admissions.set(admissions.get() + 1);
            assert_eq!(binding.generation(), 7);
            Ok(StorageResolverPolicyAdmissionOutcomeV1::Advanced)
        })
        .unwrap();
        assert!(retained.is_some());
        assert_eq!(readiness, StoragePrepareReadiness::Ready);
        assert_eq!(admissions.get(), 1);

        fs::write(&catalog_path, b"malformed").unwrap();
        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_for_test(
            &directory,
            authority,
            expected_uid,
        )
        .unwrap();
        let (retained, readiness) = classify_resolver_policy_publication(protected, |_| {
            panic!("invalid publication reached policy-floor admission")
        })
        .unwrap();
        assert!(retained.is_some());
        assert_eq!(readiness, StoragePrepareReadiness::PolicyInvalid);

        fs::write(&catalog_path, encode_catalog_for_test(7, authority, &[])).unwrap();
        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_for_test(
            &directory,
            authority,
            expected_uid,
        )
        .unwrap();
        let (retained, readiness) = classify_resolver_policy_publication(protected, |_| {
            Err(StorageBrokerError::State(StorageStateError::Rollback))
        })
        .unwrap();
        assert!(retained.is_some());
        assert_eq!(readiness, StoragePrepareReadiness::PolicyInvalid);

        let protected = ProtectedStorageResolverPolicyDirectoryV1::open_for_test(
            &directory,
            authority,
            expected_uid,
        )
        .unwrap();
        let failure = classify_resolver_policy_publication(protected, |_| {
            Err(StorageBrokerError::State(StorageStateError::CorruptRecord))
        });
        assert!(matches!(
            failure,
            Err(StorageRuntimeError::Admission(StorageBrokerError::State(
                StorageStateError::CorruptRecord
            )))
        ));
    }

    #[test]
    fn apply_router_holds_snapshot_and_covers_every_other_action() {
        let storage_handle = [1; 32];
        let version_handle = [2; 32];
        let routes = [
            (
                StorageOperation::CreateWorkspace { quota_bytes: 1 },
                StorageApplyAdmissionRoute::Workspace,
            ),
            (
                StorageOperation::Snapshot { storage_handle },
                StorageApplyAdmissionRoute::Generic,
            ),
            (
                StorageOperation::HoldSnapshot {
                    storage_handle,
                    version_handle,
                },
                StorageApplyAdmissionRoute::Generic,
            ),
            (
                StorageOperation::ReleaseHold {
                    storage_handle,
                    version_handle,
                },
                StorageApplyAdmissionRoute::Generic,
            ),
            (
                StorageOperation::Clone {
                    storage_handle,
                    version_handle,
                    quota_bytes: 1,
                },
                StorageApplyAdmissionRoute::Workspace,
            ),
            (
                StorageOperation::SetQuota {
                    storage_handle,
                    quota_bytes: 1,
                },
                StorageApplyAdmissionRoute::Generic,
            ),
            (
                StorageOperation::Destroy {
                    storage_handle,
                    version_handle: None,
                },
                StorageApplyAdmissionRoute::Generic,
            ),
        ];

        for (operation, expected) in routes {
            assert_eq!(apply_admission_route(operation), expected);
        }
    }

    #[test]
    fn identity_selector_reuses_retained_range_and_rejects_conflicts() {
        let range = aos_sandbox_protocol::MINIMUM_HOST_IDENTITY_RANGE;
        let pool = StorageIdentityPoolV1::new(range, range * 2).unwrap();
        let retained = (range, range);
        let all_ranges = [retained, (range * 2, range)];

        let live =
            select_identity_range_for_apply(pool, &all_ranges, Some(retained), range).unwrap();
        let reopened =
            select_identity_range_for_apply(pool, &all_ranges, Some(retained), range).unwrap();

        assert_eq!(live, range);
        assert_eq!(reopened, live);
        assert!(matches!(
            select_identity_range_for_apply(pool, &all_ranges, None, range),
            Err(StorageWorkspaceCatalogError::IdentityExhausted)
        ));
        assert!(matches!(
            select_identity_range_for_apply(pool, &all_ranges, Some((range, range - 1)), range),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));
        assert!(matches!(
            select_identity_range_for_apply(pool, &all_ranges, Some((range * 3, range)), range),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));
    }

    #[test]
    fn snapshot_apply_route_uses_the_generic_admission_path() {
        assert_eq!(
            apply_admission_route(StorageOperation::Snapshot {
                storage_handle: [1; 32],
            }),
            StorageApplyAdmissionRoute::Generic
        );
    }

    #[test]
    fn clone_root_must_fit_the_rejecting_private_identity_map() {
        let range = aos_sandbox_protocol::MINIMUM_HOST_IDENTITY_RANGE;
        let upper = PortableRootAttributesV1::new(range - 1, range - 1, 0).unwrap();
        let uid_outside = PortableRootAttributesV1::new(range, 0, 0o755).unwrap();
        let gid_outside = PortableRootAttributesV1::new(0, range, 0o755).unwrap();

        assert!(private_identity_profile_supports_root(
            UnmappableIdentityPolicy::Reject,
            upper,
            range,
        ));
        assert!(!private_identity_profile_supports_root(
            UnmappableIdentityPolicy::Reject,
            uid_outside,
            range,
        ));
        assert!(!private_identity_profile_supports_root(
            UnmappableIdentityPolicy::Reject,
            gid_outside,
            range,
        ));
        assert!(!private_identity_profile_supports_root(
            UnmappableIdentityPolicy::IsolatedSynthesizedPresentation,
            upper,
            range,
        ));
    }
}

pub(crate) mod capture_query;
pub(crate) mod original_capture;
