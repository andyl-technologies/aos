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

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use aos_proto::aos::sandbox::local::v1::ApplyStorageRequest;
use aos_sandbox_core::model::{IdentityProfile, SandboxSpec, UnmappableIdentityPolicy};
use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, ObjectDigest, ProtocolVersion, RawClockProvenance,
    RawPairedClockSample,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::semantics::storage::{CanonicalStorageSemanticsV1, StorageOperation};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use buffa::Message as _;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};

use crate::authorization::StorageProtectedConfigurationV1;
use crate::broker::{
    AuthenticatedWorkspaceCatalogPhysicalPlanV1, AuthorizedWorkspacePinRepairAttemptV1,
    WorkspacePinExecutionOutcomeV1, WorkspaceRemovePinRequirementV1,
};
use crate::helper::{
    StorageMutationHelper, SystemdZfsProcessBackend, ZfsHelperOutcome, ZfsProcessBackend,
};
use crate::observation_protocol::{
    WorkspaceCatalogObservationBindingsV1, WorkspaceCatalogObservationRequestV1, encode_request,
};
use crate::pin_observer::WorkspacePinHostCustody;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::pin_worker_runtime::{
    SystemdWorkspacePinExecutor, SystemdWorkspacePinObserver, SystemdWorkspacePinRuntimeIo,
    WorkspacePinRuntimeIo,
};
use crate::process::open_cgroup_root;
use crate::resolver::protected_catalog::ProtectedStorageResolverPolicyDirectoryV1;
use crate::root_policy::PortableRootAttributesV1;
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
const STARTUP_CATALOG_OBSERVATION_NANOSECONDS: u64 = 10_000_000_000;
const STARTUP_CATALOG_WORKER_NANOSECONDS: u64 = 9_000_000_000;
const KERNEL_CLOCK_PROVENANCE: [u8; 16] = *b"aos-kernel-clock";

/// Reports protected Storage runtime construction or recovery failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageRuntimeError {
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

/// Owns the sole Storage coordinator and fixed worker helper.
pub struct StorageBrokerRuntime {
    coordinator: StorageAdmissionCoordinator,
    workspaces: Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    configuration_binding: ObjectDigest,
    broker_instance_id: [u8; 16],
    pin_contract: ZfsHelperContract,
    pin_io: Box<dyn WorkspacePinRuntimeIo + Send>,
    helper: StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>,
    readiness: StorageRuntimeReadiness,
    apply_readiness: StorageApplyReadiness,
    resolver_policies: Option<ProtectedStorageResolverPolicyDirectoryV1>,
    prepare_readiness: StoragePrepareReadiness,
    #[cfg(test)]
    fail_repair_completion_commit_for_test: bool,
}

impl StorageBrokerRuntime {
    pub(crate) fn prepare_lifecycle_atomic_snapshot(
        &self,
        plan: &aos_sandbox::lifecycle::LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<crate::DormantAtomicDatasetSnapshotV1, aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>
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
        let marked = self
            .coordinator
            .mark_atomic_dataset_snapshot_ambiguous(operation, commitment);
        let program =
            self.finish_live_transaction_mutation(marked, StorageRuntimeError::Admission)?;
        self.latch_recovery_required();
        let observation = match self.helper.atomic_snapshot_once(&program, true) {
            Ok(observation) => observation,
            Err(_) => {
                return Ok(
                    AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                        program: commitment,
                    },
                );
            }
        };
        if self
            .coordinator
            .commit_atomic_dataset_snapshot(operation, commitment, observation)
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
                let observation = match self.helper.atomic_snapshot_once(&program, false) {
                    Ok(observation) => observation,
                    Err(_) => {
                        return Ok(
                            AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                                program: commitment,
                            },
                        );
                    }
                };
                if self
                    .coordinator
                    .commit_atomic_dataset_snapshot(operation, commitment, observation)
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
        )
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
        )
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
        )
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
    ) -> Result<Self, StorageRuntimeError> {
        // Retain the host mount namespace before constructing any subsystem
        // that may later acquire a namespace-scoped helper.
        let pin_custody = WorkspacePinHostCustody::retain_initial_root_owned()
            .map_err(|_| StorageRuntimeError::WorkspacePinScope)?;
        let protected_configuration =
            StorageProtectedConfigurationV1::from_protected_directory(authority_directory)?;
        let configuration_binding =
            runtime_configuration_binding(protected_configuration.public_binding(), identity_pool);
        let authority_binding = protected_configuration.public_binding();
        let (authority, state_key, _) = protected_configuration.into_parts();
        let bootstrap = ProtectedStorageBootstrap::open_root_owned(bootstrap_directory)?;
        let transactions = StorageTransactionStore::open_root_owned_runtime(
            state_directory,
            state_key,
            bootstrap.minimum_generation,
            configuration_binding,
            bootstrap.genesis_generation,
            &bootstrap.catalogs,
        )?;
        let contract = ZfsHelperContract::new(zfs_executable)?;
        let pin_executor = SystemdWorkspacePinExecutor::new(
            PathBuf::from(WORKSPACE_PIN_WORKER_SOCKET),
            open_cgroup_root()?,
        )?;
        let pin_observer = SystemdWorkspacePinObserver::new(
            PathBuf::from(WORKSPACE_PIN_OBSERVER_SOCKET),
            open_cgroup_root()?,
        )?;
        let mut pin_io = SystemdWorkspacePinRuntimeIo::new(pin_custody, pin_executor, pin_observer);
        // The transaction journal lock is already held. Prove the complete
        // reserved pin-worker cgroup scope empty before opening or observing
        // workspace state and before generic mutation recovery.
        pin_io.recover_quiescence()?;

        transactions.validate_runtime_restart(
            configuration_binding,
            bootstrap.genesis_generation,
            &bootstrap.catalogs,
        )?;
        let mut coordinator = StorageAdmissionCoordinator::new(authority, transactions);
        // Existing records must authenticate against the preexisting floor;
        // a current policy publication cannot heal missing rollback evidence.
        coordinator
            .authenticate_catalog_preparations()
            .map_err(StorageRuntimeError::Admission)?;
        let (resolver_policies, prepare_readiness) = configure_resolver_policy(
            &mut coordinator,
            resolver_policy_directory,
            authority_binding,
        )?;
        // Historical repair authority must authenticate before either ordinary
        // effect histories or the workspace inventory becomes an input.
        // Keep both exclusive journals for the runtime lifetime. Acquiring the
        // transaction journal first is the only permitted cross-journal order.
        let mut startup_clock = || {
            trusted_paired_clock_sample()
                .map_err(|_| crate::StorageAdmissionError::VerificationFailed)
        };
        let workspaces = open_validated_workspace_catalog_after_startup(
            &mut coordinator,
            &mut startup_clock,
            || {
                PendingStorageWorkspaceCatalogV1::open_root_owned(state_directory, identity_pool)
                    .map_err(Into::into)
            },
        )?;
        let broker_instance_id = random_challenge()?;

        let (backend, apply_readiness) = match apply_construction {
            StorageApplyConstructionV1::Closed => (
                SystemdZfsProcessBackend::new(executor),
                StorageApplyReadiness::WorkspaceBackendUnavailable,
            ),
            StorageApplyConstructionV1::DormantProtectedWorker => (
                SystemdZfsProcessBackend::with_protected_snapshot_metadata(executor)
                    .map_err(|_| StorageRuntimeError::Recovery)?,
                StorageApplyReadiness::ProtectedWorkerReady,
            ),
        };
        let mut runtime = Self {
            coordinator,
            workspaces: Some(workspaces),
            configuration_binding,
            broker_instance_id,
            pin_contract: contract.clone(),
            pin_io: Box::new(pin_io),
            helper: StorageMutationHelper::new(
                contract,
                Box::new(backend) as Box<dyn ZfsProcessBackend + Send>,
            ),
            readiness: StorageRuntimeReadiness::RecoveryPending { operations: 1 },
            apply_readiness,
            resolver_policies,
            prepare_readiness,
            #[cfg(test)]
            fail_repair_completion_commit_for_test: false,
        };
        runtime.readiness = runtime.reconcile_startup()?;
        Ok(runtime)
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
            pin_contract,
            pin_io: Box::new(pin_io),
            helper: helper.into_boxed(),
            readiness: StorageRuntimeReadiness::RecoveryPending { operations: 1 },
            apply_readiness: StorageApplyReadiness::WorkspaceBackendUnavailable,
            resolver_policies: None,
            prepare_readiness: StoragePrepareReadiness::Unconfigured,
            fail_repair_completion_commit_for_test: false,
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
            pin_contract,
            pin_io,
            helper,
            readiness: StorageRuntimeReadiness::RecoveryPending { operations: 1 },
            apply_readiness: StorageApplyReadiness::WorkspaceBackendUnavailable,
            resolver_policies: None,
            prepare_readiness: StoragePrepareReadiness::Unconfigured,
            fail_repair_completion_commit_for_test: false,
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
    pub const fn is_prepare_ready(&self) -> bool {
        matches!(self.prepare_readiness, StoragePrepareReadiness::Ready)
            && self.readiness.permits_catalog_methods()
    }

    fn operation_permits_apply(&self, operation_id: [u8; 16]) -> Result<bool, StorageRuntimeError> {
        if self.apply_readiness != StorageApplyReadiness::ProtectedWorkerReady
            || !self.readiness.permits_catalog_methods()
        {
            return Ok(false);
        }
        let _ = self.coordinator.prepared_catalog_for_apply(operation_id)?;
        Ok(true)
    }

    /// Reports whether the isolated repair path may accept a fresh request.
    ///
    /// Repair readiness never implies generic Apply readiness. The repair
    /// method re-observes its exact precondition and rechecks all authority on
    /// every call, including while another recovered operation remains pending.
    #[must_use]
    pub const fn is_repair_ready(&self) -> bool {
        self.readiness.permits_repair()
    }

    /// Reports whether authenticated authoritative inventory may be exposed.
    ///
    /// Every admitted state has authenticated repair history before the
    /// workspace catalog is opened.
    #[must_use]
    pub fn is_inventory_ready(&self) -> bool {
        if !self.readiness.permits_catalog_methods() {
            return false;
        }
        let Some(workspaces) = self.workspaces.as_ref() else {
            return false;
        };
        workspaces.is_terminally_materialized()
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
        let now = boottime_now_nanoseconds()?;
        if !self.is_inventory_ready()
            || now >= worker_cutoff_boottime_nanoseconds
            || worker_cutoff_boottime_nanoseconds >= activation_deadline_boottime_nanoseconds
        {
            return Err(StorageRuntimeError::Recovery);
        }

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

    /// Encodes the additive complete lifecycle inventory for dormant composition.
    ///
    /// This method is not used by the installed Storage service. It first runs
    /// the existing physical workspace observation, then rereads the protected
    /// resolver journal and appends all five lifecycle object families before
    /// the caller submits the exact body to broker-session signing.
    pub(crate) fn dormant_lifecycle_inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let inventory = self.inventory_resources(
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )?;
        crate::lifecycle_inventory::attach_complete_lifecycle_inventory(
            &self.coordinator,
            &inventory,
        )
        .map_err(|_| StorageRuntimeError::Recovery)
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
        let (plan, physical_plan) = match self.coordinator.workspace_catalog_activation_plan() {
            Ok(composition) => composition,
            Err(error) => return Err((Some(validated), error.into())),
        };
        let Some(physical_plan) = physical_plan else {
            return Err((Some(validated), StorageRuntimeError::Recovery));
        };
        let nonce = match catalog_observation_nonce() {
            Ok(nonce) => nonce,
            Err(error) => return Err((Some(validated), error.into())),
        };
        let request = match self.catalog_observation_request(
            &validated,
            &plan,
            &physical_plan,
            nonce,
            activation_deadline_boottime_nanoseconds,
        ) {
            Ok(request) => request,
            Err(error) => return Err((Some(validated), error)),
        };
        let (candidate, fresh) = match prepare_catalog_candidate_before_observation(
            validated,
            physical_plan,
            request,
            |request_bytes, request| {
                self.pin_io
                    .observe_catalog(request_bytes, request, worker_cutoff_boottime_nanoseconds)
                    .map_err(Into::into)
            },
        ) {
            Ok(prepared) => prepared,
            Err((validated, error)) => return Err((Some(validated), error)),
        };

        let original_request = candidate.request();
        let nonce = original_request.nonce();
        let bindings = original_request.bindings();
        let deadline = original_request.deadline_boottime_nanoseconds();
        let (recomposed_plan, recomposed_physical_plan) =
            match self.coordinator.workspace_catalog_activation_plan() {
                Ok(composition) => composition,
                Err(error) => return Err((Some(candidate.into_validated()), error.into())),
            };
        let Some(recomposed_physical_plan) = recomposed_physical_plan else {
            return Err((
                Some(candidate.into_validated()),
                StorageRuntimeError::Recovery,
            ));
        };
        let custody = match self.pin_io.catalog_binding() {
            Ok(custody) => custody,
            Err(_) => {
                return Err((
                    Some(candidate.into_validated()),
                    StorageRuntimeError::WorkspacePinScope,
                ));
            }
        };
        let recomposed_request = match WorkspaceCatalogObservationRequestV1::new(
            nonce,
            deadline,
            bindings,
            custody,
            recomposed_physical_plan.roots().to_vec(),
            recomposed_physical_plan.allowed_objects().to_vec(),
            recomposed_physical_plan.targets().to_vec(),
        ) {
            Ok(request) => request,
            Err(error) => return Err((Some(candidate.into_validated()), error.into())),
        };
        let now = match boottime_now_nanoseconds() {
            Ok(now) => now,
            Err(error) => return Err((Some(candidate.into_validated()), error.into())),
        };
        let activated = match candidate.activate(
            recomposed_plan,
            recomposed_physical_plan,
            recomposed_request,
            fresh,
            now,
        ) {
            Ok(activated) => activated,
            Err(failure) => {
                let (validated, error) = failure.into_parts();
                return Err((validated, error.into()));
            }
        };
        let (validated, inventory) = activated.into_inventory();
        Ok((validated, inventory))
    }

    fn catalog_observation_request(
        &self,
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
            self.configuration_binding,
            self.broker_instance_id,
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
        let custody = self
            .pin_io
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
        if !self.is_repair_ready() {
            return Err(StorageRuntimeError::Recovery);
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

        let current_host_scope = self
            .pin_io
            .host_scope()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let observation_dispatch = self
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
            )
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let observation_request = observation_dispatch
            .request_bytes()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let fresh_observation = self
            .pin_io
            .observe_repair_admission(&observation_request, observation_dispatch.probe())
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let result = self.coordinator.begin_workspace_pin_repair(
            observation_dispatch,
            fresh_observation,
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            &self.pin_contract,
            trusted_clock,
        );
        let admitted =
            self.finish_live_transaction_mutation(result, |_| StorageRuntimeError::Recovery)?;
        let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(dispatch) = admitted else {
            return Ok(WorkspacePinRepairExecutionOutcomeV1::ObservationRequired);
        };

        let worker_request = dispatch
            .worker_request_bytes()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let result = match self.pin_io.execute(&worker_request, dispatch.attempt()) {
            Ok(result) => result,
            Err(_) => {
                self.latch_recovery_required();
                return Err(StorageRuntimeError::Recovery);
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
        let disposition = match self
            .coordinator
            .complete_workspace_pin_repair_execution(dispatch.attempt(), &result)
        {
            Ok(disposition) => disposition,
            Err(_) => {
                return Err(StorageRuntimeError::ReopenRequired);
            }
        };
        if disposition
            != crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication
        {
            self.latch_recovery_required();
            return Err(StorageRuntimeError::Recovery);
        }
        let reconciliation = self.reconcile_startup();
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
        let result = self.coordinator.admit_workspace_apply_intent(
            request_body,
            artifacts,
            catalog,
            protocol_version,
            peer,
            policy,
            current_clock,
            identity_range_start,
            manifest,
            sandbox_spec,
        );
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
        let operation = semantics.operation();
        let result = match apply_admission_route(operation) {
            StorageApplyAdmissionRoute::Workspace => {
                let metadata = semantics
                    .workspace_metadata()
                    .ok_or(StorageRuntimeError::Recovery)?;
                let manifest = metadata.manifest().clone();
                let sandbox_spec = metadata.sandbox_spec().clone();
                return self
                    .admit_workspace_apply_intent(
                        request_body,
                        artifacts,
                        &catalog,
                        protocol_version,
                        peer,
                        policy,
                        current_clock,
                        &manifest,
                        &sandbox_spec,
                    )
                    .map(|outcome| (operation_id, operation, outcome));
            }
            StorageApplyAdmissionRoute::Generic => self.coordinator.admit_apply_intent(
                request_body,
                artifacts,
                &catalog,
                protocol_version,
                peer,
                policy,
                current_clock,
            ),
        };
        let outcome =
            self.finish_live_transaction_mutation(result, StorageRuntimeError::Admission)?;
        Ok((operation_id, operation, outcome))
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
        if !self.operation_permits_apply(operation_id)? {
            return Err(StorageRuntimeError::Recovery);
        }
        let prepared = self
            .coordinator
            .preobserve(&mut self.helper, operation_id)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let mutation_digest = prepared.entry().mutation_digest();
        let creates_workspace = matches!(
            prepared.catalog().plan(),
            crate::CatalogPlanV1::CreateWorkspace { .. } | crate::CatalogPlanV1::Clone { .. }
        );
        let removal = self
            .coordinator
            .workspace_remove_pin_requirement(&prepared)
            .map_err(|_| StorageRuntimeError::Recovery)?;

        // Every path below can cross a physical-effect boundary. Close all
        // public gates until exact postconditions and catalog activation agree.
        self.latch_recovery_required();
        let committed = match removal {
            WorkspaceRemovePinRequirementV1::Required(expected_pin) => {
                let result = self
                    .coordinator
                    .execute_workspace_remove_and_destroy_with_io(
                        self.pin_io.as_mut(),
                        &self.pin_contract,
                        prepared,
                        expected_pin,
                        trusted_clock,
                    );
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
                        return self.finish_aborted_mutation(mutation_digest);
                    }
                }
                committed.ok_or(StorageRuntimeError::Recovery)?
            }
            WorkspaceRemovePinRequirementV1::Missing => {
                return Err(StorageRuntimeError::Recovery);
            }
            WorkspaceRemovePinRequirementV1::NotWorkspace => {
                let execution = self
                    .coordinator
                    .execute_preobserved(&mut self.helper, prepared, trusted_clock)
                    .map_err(|_| StorageRuntimeError::Recovery);
                match self.finish_live_transaction_mutation(execution, |error| error)? {
                    ZfsHelperOutcome::Committed(committed) => committed,
                    ZfsHelperOutcome::Aborted { mutation_digest } => {
                        return self.finish_aborted_mutation(mutation_digest);
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
            let result = self.coordinator.execute_workspace_pin_ensure_with_io(
                self.pin_io.as_mut(),
                &self.pin_contract,
                committed,
                trusted_clock,
            );
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

        let readiness = self.reconcile_startup()?;
        self.readiness = readiness;
        if !self.readiness.permits_catalog_methods() {
            return Ok(StorageRuntimeMutationOutcome::ObservationRequired {
                phase: DurableStoragePhase::Committed,
                mutation_digest,
            });
        }
        Ok(StorageRuntimeMutationOutcome::Committed(committed))
    }

    fn reconcile_startup(&mut self) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let mut pending = reconcile_transaction_recovery(&mut self.coordinator, &mut self.helper)?;
        for dispatch in self
            .coordinator
            .workspace_pin_observation_dispatches()
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            let request = dispatch
                .request_bytes(&self.pin_contract)
                .map_err(|_| StorageRuntimeError::Recovery)?;
            let result = self
                .pin_io
                .observe(&request, dispatch.attempt())
                .map_err(|_| StorageRuntimeError::Recovery)?;
            match self
                .coordinator
                .complete_workspace_pin_observation(dispatch.attempt(), &result)
                .map_err(|_| StorageRuntimeError::Recovery)?
            {
                crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication
                | crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompleteRetirement => {}
                _ => pending += 1,
            }
        }
        let current_host_scope = self
            .pin_io
            .host_scope()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        for dispatch in self
            .coordinator
            .workspace_pin_repair_observation_dispatches(&self.pin_contract, current_host_scope)
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            let request = dispatch
                .request_bytes()
                .map_err(|_| StorageRuntimeError::Recovery)?;
            let result = self
                .pin_io
                .observe_repair(
                    &request,
                    dispatch.attempt().attempt_id(),
                    dispatch.probe().digest(),
                )
                .map_err(|_| StorageRuntimeError::Recovery)?;
            match self
                .coordinator
                .complete_workspace_pin_repair_observation(dispatch, result)
                .map_err(|_| StorageRuntimeError::Recovery)?
            {
                crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication => {}
                crate::workspace_pin::WorkspacePinRecoveryDispositionV1::AwaitFreshRepair => {
                    pending += 1;
                }
                _ => return Err(StorageRuntimeError::Recovery),
            }
        }
        let (workspace_plan, physical_plan) =
            self.coordinator.workspace_catalog_activation_plan()?;
        self.workspaces
            .as_mut()
            .ok_or(StorageRuntimeError::Recovery)?
            .revalidate_plan(workspace_plan)?;
        if let Some(readiness) = pending_startup_readiness(pending, physical_plan.is_some()) {
            return Ok(readiness);
        }

        let now = boottime_now_nanoseconds()?;
        let activation_deadline = now
            .checked_add(STARTUP_CATALOG_OBSERVATION_NANOSECONDS)
            .ok_or(StorageRuntimeError::Recovery)?;
        let worker_cutoff = now
            .checked_add(STARTUP_CATALOG_WORKER_NANOSECONDS)
            .ok_or(StorageRuntimeError::Recovery)?;
        let validated = self
            .workspaces
            .take()
            .ok_or(StorageRuntimeError::Recovery)?;
        match self.inventory_from_validated(validated, activation_deadline, worker_cutoff) {
            Ok((validated, _)) => {
                self.workspaces = Some(validated);
                Ok(StorageRuntimeReadiness::Ready)
            }
            Err((Some(validated), error)) => {
                self.workspaces = Some(validated);
                Err(error)
            }
            Err((None, _)) => {
                self.latch_reopen_required();
                Err(StorageRuntimeError::ReopenRequired)
            }
        }
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
        let readiness = self.reconcile_startup()?;
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
/// # Errors
///
/// Returns [`StorageRuntimeError::Recovery`] when the kernel boot identity or
/// either clock cannot form a valid paired sample.
pub(crate) fn trusted_paired_clock_sample() -> Result<RawPairedClockSample, StorageRuntimeError> {
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let provenance = RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
        .map_err(|_| StorageRuntimeError::Recovery)?;
    let boot_id = KernelBootId::current()
        .map_err(|_| StorageRuntimeError::Recovery)?
        .into_bytes();
    RawPairedClockSample::new_untrusted(
        provenance,
        boot_id,
        wall.tv_sec,
        boottime_now_nanoseconds().map_err(|_| StorageRuntimeError::Recovery)?,
    )
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
    let Some(policy_directory) = policy_directory else {
        return Ok((None, StoragePrepareReadiness::Unconfigured));
    };
    let protected = match ProtectedStorageResolverPolicyDirectoryV1::open_root_owned(
        policy_directory,
        authority_binding,
    ) {
        Ok(protected) => protected,
        Err(_) => return Ok((None, StoragePrepareReadiness::PolicyInvalid)),
    };
    classify_resolver_policy_publication(protected, |binding| {
        coordinator.admit_trusted_resolver_policy(binding)
    })
}

fn classify_resolver_policy_publication<F>(
    protected: ProtectedStorageResolverPolicyDirectoryV1,
    mut admit: F,
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
    let binding = match protected.load().and_then(|catalog| catalog.binding()) {
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
    let entries = coordinator
        .recovery_entries()
        .map_err(|_| StorageRuntimeError::Recovery)?;
    let mut pending = 0;

    for entry in entries {
        if matches!(
            entry.phase(),
            DurableStoragePhase::Committed | DurableStoragePhase::Aborted
        ) {
            continue;
        }
        match coordinator
            .reconcile_recovery(helper, entry)
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            ZfsHelperOutcome::Committed(_) => {}
            ZfsHelperOutcome::Aborted { .. } => return Err(StorageRuntimeError::Recovery),
            ZfsHelperOutcome::ObservationRequired { .. } => pending += 1,
        }
    }

    for record in coordinator
        .atomic_dataset_snapshot_inventory()
        .map_err(|_| StorageRuntimeError::Recovery)?
    {
        match record.phase() {
            crate::state::AtomicDatasetSnapshotPhaseV1::Prepared => pending += 1,
            crate::state::AtomicDatasetSnapshotPhaseV1::Committed => {}
            crate::state::AtomicDatasetSnapshotPhaseV1::Ambiguous => {
                let program = record.program();
                let observation = match helper.atomic_snapshot_once(program, false) {
                    Ok(observation) => observation,
                    Err(_) => {
                        pending += 1;
                        continue;
                    }
                };
                coordinator
                    .commit_atomic_dataset_snapshot(
                        program.operation(),
                        program.commitment(),
                        observation,
                    )
                    .map_err(|_| StorageRuntimeError::Recovery)?;
            }
        }
    }

    Ok(pending)
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

struct ProtectedStorageBootstrap {
    minimum_generation: u64,
    genesis_generation: u64,
    catalogs: Vec<ResolvedCatalogCommitmentV1>,
}

impl ProtectedStorageBootstrap {
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
        if minimum_bytes.len() != 8 {
            return Err(StorageRuntimeError::Bootstrap);
        }
        let minimum_generation = u64::from_be_bytes(
            minimum_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StorageRuntimeError::Bootstrap)?,
        );
        if minimum_generation == 0 {
            return Err(StorageRuntimeError::Bootstrap);
        }
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
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StorageRuntimeError::Bootstrap)?;
    let metadata = fstat(&fd).map_err(|_| StorageRuntimeError::Bootstrap)?;
    let declared_size =
        usize::try_from(metadata.st_size).map_err(|_| StorageRuntimeError::Bootstrap)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != expected_uid
        || metadata.st_nlink != 1
        || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
        || declared_size == 0
        || declared_size > maximum_bytes
    {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let mut bytes = Vec::with_capacity(declared_size);
    std::fs::File::from(fd)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| StorageRuntimeError::Bootstrap)?;
    if bytes.len() != declared_size || bytes.len() > maximum_bytes {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok(bytes)
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
    use crate::resolver::protected_catalog::{
        ProtectedStorageResolverPolicyDirectoryV1, encode_catalog_for_test,
    };
    use crate::state::StorageResolverPolicyAdmissionOutcomeV1;
    use crate::workspace_catalog::StorageWorkspaceCatalogPlanV1;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

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
                aos_sandbox::JournalError::Poisoned,
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
