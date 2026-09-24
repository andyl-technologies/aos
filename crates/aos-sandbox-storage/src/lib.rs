//! Fixed-function storage-broker request and OpenZFS execution primitives.
//!
//! This crate owns the narrow boundary between hostile local storage requests
//! and an AOS-built OpenZFS executable. [`request`] performs bounded protobuf
//! decoding, common peer/header checks, closed action-shape validation, and
//! canonical broker-authority commitment. [`catalog`] binds every node-local
//! effect input into a versioned resolved-catalog commitment while exposing
//! only an opaque digest/generation binding to portable authority. [`zfs`]
//! accepts only those catalog plans and compiles a non-runnable transaction
//! program whose GUID/hold checks, mutation, and typed postcondition must remain
//! coupled under a catalog lock. It never accepts command fragments, property
//! names, shell text, or `PATH` lookup.
//!
//! [`state`] owns the bounded, authenticated durable intent/result state
//! machine and its exclusive catalog lock. [`workspace_catalog`] binds an exact
//! committed creation to its operation-scoped authority fence and fixed root
//! pin, retains non-recycled dataset and subordinate-identity allocations, and
//! emits the bounded authoritative inventory. Postcondition observation and
//! the long-running storage service remain intentionally separate layers.
//! `execution_output` retains bounded logical execution-capture reservations
//! and authenticated deletion tombstones; physical capture backing is not yet
//! connected to the ZFS catalog.
//! [`process`] reaches ZFS only through a fixed, systemd-contained one-shot
//! worker that recompiles typed catalog input. [`runtime`] also exposes an
//! explicit dormant Apply constructor which retains protected Snapshot
//! metadata; the production service continues to omit Apply advertisement.

pub mod activation;
pub mod authorization;
pub mod broker;
pub mod catalog;
mod catalog_decode;
pub mod catalog_preparation;
mod catalog_transition;
mod clone_identity;
mod dormant_broker_session;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "capture file effects await authenticated worker mount custody"
)]
mod execution_capture_files;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "capture ZFS effect awaits a signed Storage grant and durable attempt issuer"
)]
mod execution_capture_zfs_worker;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "capture writer awaits exclusive ZFS mount custody and signed Controller grant"
)]
mod execution_capture_writer;
#[cfg(target_os = "linux")]
pub mod execution_output;
mod guest_root_attempt;
pub mod guest_root_inventory;
pub mod guest_root_worker;
#[allow(
    dead_code,
    reason = "sealed helper boundary is not wired until Apply readiness exists"
)]
mod helper;
mod lifecycle_atomic_snapshot;
mod lifecycle_inventory;
mod live_export_catalog;
#[allow(
    dead_code,
    reason = "private RO clone remains unreachable until independent grant authority is complete"
)]
mod live_export_clone;
#[allow(
    dead_code,
    reason = "named consumer comparison awaits current Attachment and Host-to-Storage handoff"
)]
mod live_export_consumer_claim;
#[allow(
    dead_code,
    reason = "private deny-stage handoff awaits Host-to-Storage carrier and kernel owner"
)]
mod live_export_grant_handoff;
mod live_export_key;
pub mod live_export_origin;
#[allow(
    dead_code,
    reason = "LocalLive intake remains closed until Provider selected-row proof is available"
)]
mod live_export_request_readback;
pub use live_export_request_readback::StorageLiveExportReadbackV1;
mod live_export_request_replay;
#[allow(
    dead_code,
    reason = "LocalLive intake remains closed until Provider selected-row proof is available"
)]
mod live_export_request_trust;
pub mod live_export_transport;
mod observation;
#[allow(
    dead_code,
    reason = "catalog observation protocol is wired with the activation typestate"
)]
mod observation_protocol;
#[allow(
    dead_code,
    reason = "public operator Repair completion remains closed pending independent evidence"
)]
pub mod operator_recovery;
pub mod operator_recovery_credentials;
pub mod operator_repair_transport;
pub mod peer;
mod pin_observer;
mod pin_worker;
mod pin_worker_runtime;
pub mod process;
pub mod request;
pub mod root_export;
#[allow(
    dead_code,
    reason = "protected catalog resolution is not wired until Storage Apply readiness exists"
)]
mod resolver;
#[allow(
    dead_code,
    reason = "root initialization is not wired until Storage Apply readiness exists"
)]
mod root_policy;
pub mod runtime;
pub mod service;
mod snapshot_metadata;
pub mod state;
pub mod transport;
pub mod workspace_catalog;
mod workspace_pin;
mod workspace_repair;
mod workspace_repair_admission;
mod workspace_repair_observer;
mod workspace_repair_worker;
mod worker_wire;
pub mod zfs;

pub use authorization::{
    AuthorizedStorageResolutionV1, StorageAdmissionError, StorageAuthorityConfigError,
    StorageAuthorityV1, StorageProtectedConfigurationV1,
};
pub use broker::{
    StorageAdmissionCoordinator, StorageAdmissionOutcome, StorageBrokerError,
    advertised_storage_methods,
};
pub use catalog::{
    ActiveHoldEvidence, CatalogObjectKind, CatalogPlanV1, CatalogSemanticError, HoldId,
    ManagedDatasetRoot, PlannedDataset, PlannedSnapshot, PostconditionPolicyV1,
    ProjectAncestorPolicyV1, ReservationPolicy, ResolvedCatalogCommitmentV1, ResolvedDataset,
    ResolvedSnapshot, StorageDomainsV1, WorkspaceSpacePolicyV1,
};
pub use catalog_preparation::{
    ProtectedStorageCatalogResolverV1, StorageCatalogPreparationError,
    StorageCatalogPreparationOutcomeV1,
};
pub use dormant_broker_session::{
    DormantStorageApplyCompositionV1, DormantStorageBrokerCallErrorV1,
    DormantStorageBrokerCallsiteV1, DormantStorageBrokerObservationV1,
};
pub use lifecycle_atomic_snapshot::DormantAtomicDatasetSnapshotV1;
pub use live_export_origin::StorageLiveExportOriginV1;
pub use live_export_transport::StorageLiveExportTransportOutcomeV1;
pub use pin_worker_runtime::{
    run_inherited_workspace_pin_observer, run_inherited_workspace_pin_worker,
};
pub use process::{
    SystemdZfsExecutor, WorkerProcessOutput, ZfsWorkerError, process_timeout, run_inherited_worker,
};
pub use request::{
    CanonicalStorageSemanticsV1, CatalogBindingV1, StorageOperation, StorageRequestError,
    StorageSemanticsError, decode_resolved,
};
pub use runtime::{
    AtomicDatasetSnapshotMutationOutcomeV1, StorageApplyReadiness, StorageBrokerRuntime,
    StoragePrepareReadiness, StorageRuntimeError, StorageRuntimeMutationOutcome,
    StorageRuntimeReadiness, WorkspacePinRepairExecutionOutcomeV1,
};
pub use service::{
    StorageConnectionOutcome, StorageRpcRuntime, StorageService, StorageServiceError,
};
pub use state::{
    BeginStorageTransaction, CommittedStorageResultV1, DurableStoragePhase, StorageRecoveryEntry,
    StorageStateError, StorageStateKey, StorageTransactionStore, VerifiedStorageResultV1,
};
pub use workspace_catalog::{
    StorageIdentityPoolV1, StorageWorkspaceCatalogError, StorageWorkspaceCatalogOutcomeV1,
    StorageWorkspaceCatalogV1, StorageWorkspacePublicationV1, StorageWorkspaceRetirementV1,
};
pub use zfs::{
    AncestorPolicyTransaction, ZfsHelperContract, ZfsPrecondition, ZfsTransaction,
    ZfsTransactionError,
};
