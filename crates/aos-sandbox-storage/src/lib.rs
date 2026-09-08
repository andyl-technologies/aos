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
//! [`process`] reaches ZFS only through a fixed, systemd-contained one-shot
//! worker that recompiles typed catalog input.

pub mod authorization;
pub mod broker;
pub mod catalog;
mod catalog_decode;
mod catalog_transition;
#[allow(
    dead_code,
    reason = "sealed helper boundary is not wired until Apply readiness exists"
)]
mod helper;
mod observation;
pub mod process;
pub mod request;
pub mod state;
pub mod workspace_catalog;
pub mod zfs;

pub use authorization::{StorageAdmissionError, StorageAuthorityConfigError, StorageAuthorityV1};
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
pub use process::{
    SystemdZfsExecutor, WorkerProcessOutput, ZfsWorkerError, process_timeout, run_inherited_worker,
};
pub use request::{
    CanonicalStorageSemanticsV1, CatalogBindingV1, StorageOperation, StorageRequestError,
    StorageSemanticsError, decode_resolved,
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
