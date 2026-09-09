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

use aos_sandbox_core::model::{IdentityProfile, SandboxSpec};
use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, ObjectDigest, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};

use crate::authorization::StorageProtectedConfigurationV1;
use crate::broker::{
    AuthorizedWorkspacePinRepairAttemptV1, WorkspacePinExecutionOutcomeV1,
    WorkspaceRemovePinRequirementV1,
};
use crate::helper::{StorageMutationHelper, SystemdZfsProcessBackend, ZfsHelperOutcome};
use crate::pin_observer::WorkspacePinHostCustody;
use crate::pin_worker_runtime::{SystemdWorkspacePinExecutor, SystemdWorkspacePinObserver};
use crate::process::open_cgroup_root;
use crate::{
    CommittedStorageResultV1, DurableStoragePhase, ResolvedCatalogCommitmentV1,
    StorageAdmissionCoordinator, StorageAdmissionError, StorageAdmissionOutcome,
    StorageBrokerError, StorageIdentityPoolV1, StorageStateError, StorageTransactionStore,
    StorageWorkspaceCatalogError, StorageWorkspaceCatalogV1, SystemdZfsExecutor, ZfsHelperContract,
    ZfsTransactionError, ZfsWorkerError, decode_resolved,
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

/// Describes whether the composed runtime may accept a new live effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRuntimeReadiness {
    /// Mutation recovery, mandatory root pins, and publication have converged.
    ///
    /// Construction in this increment never returns this state because root-pin
    /// materialization and workspace publication are not composed yet.
    Ready,
    /// Mutation recovery converged, but mandatory publication is not composed.
    IntegrationIncomplete,
    /// Authenticated current-format effects still require observation.
    RecoveryPending {
        /// Count of bounded pending or ambiguous operations.
        operations: usize,
    },
    /// Pre-runtime-binding state is retained strictly for non-dispatch recovery.
    LegacyRecoveryOnly {
        /// Count of retained operations, including already committed history.
        operations: usize,
    },
}

/// Reports one synchronous authorized mutation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRuntimeMutationOutcome {
    /// Exact postcondition evidence and physical catalog state were committed.
    Committed(CommittedStorageResultV1),
    /// No mutation was retried; later observation is still required.
    ObservationRequired {
        /// Current durable crash phase.
        phase: DurableStoragePhase,
        /// Exact pending mutation commitment.
        mutation_digest: ObjectDigest,
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
    workspaces: StorageWorkspaceCatalogV1,
    pin_custody: WorkspacePinHostCustody,
    pin_contract: ZfsHelperContract,
    pin_executor: SystemdWorkspacePinExecutor,
    pin_observer: SystemdWorkspacePinObserver,
    helper: StorageMutationHelper<SystemdZfsProcessBackend>,
    readiness: StorageRuntimeReadiness,
}

impl StorageBrokerRuntime {
    /// Opens protected state, anchors genesis, and performs startup observation.
    ///
    /// `bootstrap_directory` is a root-owned fixed-file publication, not a
    /// request or controller-provided raw catalog. A truly unused journal is
    /// initialized atomically with the protected authority binding and genesis
    /// head. An initialized journal instead authenticates its current head and
    /// compares only its immutable genesis identity to the static publication.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for insecure or malformed protected
    /// inputs, rollback, authority/genesis substitution, worker construction,
    /// corrupt state, or failed observation-only recovery.
    pub fn open_root_owned(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        // Retain the host mount namespace before constructing any subsystem
        // that may later acquire a namespace-scoped helper.
        let pin_custody = WorkspacePinHostCustody::retain_initial_root_owned()
            .map_err(|_| StorageRuntimeError::WorkspacePinScope)?;
        let protected_configuration =
            StorageProtectedConfigurationV1::from_protected_directory(authority_directory)?;
        let configuration_binding =
            runtime_configuration_binding(protected_configuration.public_binding(), identity_pool);
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
        let mut pin_executor = SystemdWorkspacePinExecutor::new(
            PathBuf::from(WORKSPACE_PIN_WORKER_SOCKET),
            open_cgroup_root()?,
        )?;
        // The transaction journal lock is already held. Prove the complete
        // reserved pin-worker cgroup scope empty before opening or observing
        // workspace state and before generic mutation recovery.
        pin_executor.recover_quiescence()?;
        let pin_observer = SystemdWorkspacePinObserver::new(
            PathBuf::from(WORKSPACE_PIN_OBSERVER_SOCKET),
            open_cgroup_root()?,
        )?;

        let legacy_recovery = transactions.requires_legacy_recovery()?;
        if !legacy_recovery {
            transactions.validate_runtime_restart(
                configuration_binding,
                bootstrap.genesis_generation,
                &bootstrap.catalogs,
            )?;
        }
        let coordinator = StorageAdmissionCoordinator::new(authority, transactions);
        // Historical repair authority must authenticate before either ordinary
        // effect histories or the workspace inventory becomes an input.
        // Keep both exclusive journals for the runtime lifetime. Acquiring the
        // transaction journal first is the only permitted cross-journal order.
        let workspaces = authenticate_before_workspace_inventory(
            || authenticate_startup_authority(&coordinator),
            || {
                StorageWorkspaceCatalogV1::open_root_owned(state_directory, identity_pool)
                    .map_err(Into::into)
            },
        )?;

        let backend = SystemdZfsProcessBackend::new(executor);
        let mut runtime = Self {
            coordinator,
            workspaces,
            pin_custody,
            pin_contract: contract.clone(),
            pin_executor,
            pin_observer,
            helper: StorageMutationHelper::new(contract, backend),
            readiness: StorageRuntimeReadiness::IntegrationIncomplete,
        };
        runtime.readiness = if legacy_recovery {
            StorageRuntimeReadiness::LegacyRecoveryOnly {
                operations: runtime
                    .coordinator
                    .recovery_entries()
                    .map_err(|_| StorageRuntimeError::Recovery)?
                    .len(),
            }
        } else {
            runtime.reconcile_startup()?
        };
        Ok(runtime)
    }

    #[cfg(test)]
    pub(crate) fn from_protected_components_for_test<F>(
        coordinator: StorageAdmissionCoordinator,
        open_workspaces: F,
        pin_custody: WorkspacePinHostCustody,
        pin_contract: ZfsHelperContract,
        mut pin_executor: SystemdWorkspacePinExecutor,
        pin_observer: SystemdWorkspacePinObserver,
        helper: StorageMutationHelper<SystemdZfsProcessBackend>,
    ) -> Result<Self, StorageRuntimeError>
    where
        F: FnOnce() -> Result<StorageWorkspaceCatalogV1, StorageRuntimeError>,
    {
        // Preserve the production construction order: prove the complete
        // mutator cgroup empty, authenticate the transaction journal, and only
        // then open the workspace journal under the already-held first lock.
        pin_executor.recover_quiescence()?;
        let workspaces = authenticate_before_workspace_inventory(
            || authenticate_startup_authority(&coordinator),
            open_workspaces,
        )?;

        let mut runtime = Self {
            coordinator,
            workspaces,
            pin_custody,
            pin_contract,
            pin_executor,
            pin_observer,
            helper,
            readiness: StorageRuntimeReadiness::IntegrationIncomplete,
        };
        runtime.readiness = runtime.reconcile_startup()?;

        Ok(runtime)
    }

    #[cfg(test)]
    pub(crate) const fn coordinator_for_test(&self) -> &StorageAdmissionCoordinator {
        &self.coordinator
    }

    #[cfg(test)]
    pub(crate) const fn workspace_catalog_for_test(&self) -> &StorageWorkspaceCatalogV1 {
        &self.workspaces
    }

    #[cfg(test)]
    pub(crate) fn into_journals_for_test(
        self,
    ) -> (StorageAdmissionCoordinator, StorageWorkspaceCatalogV1) {
        (self.coordinator, self.workspaces)
    }

    /// Returns the fail-closed startup readiness classification.
    #[must_use]
    pub const fn readiness(&self) -> StorageRuntimeReadiness {
        self.readiness
    }

    /// Reports whether the complete Apply composition has converged.
    ///
    /// This remains false until root-pin materialization and workspace
    /// publication are integrated with mutation recovery.
    #[must_use]
    pub const fn is_apply_ready(&self) -> bool {
        matches!(self.readiness, StorageRuntimeReadiness::Ready)
    }

    /// Reports whether the isolated repair path may accept a fresh request.
    ///
    /// Repair readiness never implies generic Apply readiness. The repair
    /// method re-observes its exact precondition and rechecks all authority on
    /// every call, including while another recovered operation remains pending.
    #[must_use]
    pub const fn is_repair_ready(&self) -> bool {
        matches!(
            self.readiness,
            StorageRuntimeReadiness::Ready
                | StorageRuntimeReadiness::IntegrationIncomplete
                | StorageRuntimeReadiness::RecoveryPending { .. }
        )
    }

    /// Repairs one existing workspace root pin through fresh observation.
    ///
    /// The caller supplies only the raw Storage 1.4 request and standard
    /// authorization artifacts. Dataset identity, catalog, attempt ordinal,
    /// mount observation, and host scope are derived from authenticated state
    /// and retained descriptors while the runtime holds its exclusive journals.
    /// An exact durable retry is observation-only and never reaches a mutator.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when repair is unavailable, authority or
    /// retained history fails closed, exact dataset/pin absence is not freshly
    /// proved, the atomic admission is uncertain, worker dispatch fails, or
    /// the exact postcondition is not observed.
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
            .pin_custody
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
            .pin_observer
            .observe_repair_admission(
                &observation_request,
                observation_dispatch.probe(),
                &self.pin_custody,
            )
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let admitted = self
            .coordinator
            .begin_workspace_pin_repair(
                observation_dispatch,
                fresh_observation,
                request_body,
                artifacts,
                protocol_version,
                peer,
                policy,
                &self.pin_contract,
                trusted_clock,
            )
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let AuthorizedWorkspacePinRepairAttemptV1::Dispatch(dispatch) = admitted else {
            return Ok(WorkspacePinRepairExecutionOutcomeV1::ObservationRequired);
        };

        let worker_request = dispatch
            .worker_request_bytes()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let result =
            match self
                .pin_executor
                .execute(&worker_request, dispatch.attempt(), &self.pin_custody)
            {
                Ok(result) => result,
                Err(_) => {
                    self.latch_recovery_required();
                    return Err(StorageRuntimeError::Recovery);
                }
            };
        let disposition = match self
            .coordinator
            .complete_workspace_pin_repair_execution(dispatch.attempt(), &result)
        {
            Ok(disposition) => disposition,
            Err(_) => {
                self.latch_recovery_required();
                return Err(StorageRuntimeError::Recovery);
            }
        };
        if disposition
            != crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication
        {
            self.latch_recovery_required();
            return Err(StorageRuntimeError::Recovery);
        }
        self.readiness = self.reconcile_startup()?;
        Ok(WorkspacePinRepairExecutionOutcomeV1::Satisfied)
    }

    /// Admits one workspace-creating effect with an exact retained identity range.
    ///
    /// The runtime holds both journals in transaction-then-workspace order,
    /// chooses first-fit against every retained transaction intent and catalog
    /// tombstone, then commits that exact range with the signed operation.
    /// Rejected or interrupted intents remain reserved and are never silently
    /// reused. This path remains unavailable until the complete Apply runtime
    /// reports [`StorageRuntimeReadiness::Ready`].
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
        if !self.is_apply_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let IdentityProfile::PrivateUserns { id_range_size, .. } = sandbox_spec.identity_profile()
        else {
            return Err(StorageRuntimeError::Recovery);
        };
        let semantics = decode_resolved(
            request_body,
            catalog,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageRuntimeError::Admission(StorageBrokerError::Request))?;
        let range_start = match self
            .coordinator
            .workspace_identity_range(*semantics.operation_id())?
        {
            Some((range_start, range_size)) if range_size == id_range_size.get() => range_start,
            Some(_) => {
                return Err(StorageRuntimeError::Admission(
                    StorageBrokerError::WorkspaceCatalog(
                        StorageWorkspaceCatalogError::IdentityConflict,
                    ),
                ));
            }
            None => {
                let retained_ranges = self.coordinator.workspace_identity_ranges()?;
                self.workspaces
                    .reserve_identity_range(&retained_ranges, id_range_size.get())?
            }
        };
        self.coordinator
            .admit_workspace_apply_intent(
                request_body,
                artifacts,
                catalog,
                protocol_version,
                peer,
                policy,
                current_clock,
                range_start,
                manifest,
                sandbox_spec,
            )
            .map_err(Into::into)
    }

    /// Executes one already-admitted Prepared effect under fresh authority.
    ///
    /// This method performs pre-observation, reopens current durable authority,
    /// samples the supplied protected clock before Ambiguous, durably crosses
    /// Ambiguous, samples again, and dispatches exactly once. Service code must
    /// not call it unless [`Self::is_apply_ready`] is true.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError::Recovery`] when persisted authority,
    /// either fresh clock sample, physical preconditions, dispatch, or
    /// postcondition observation fails. A failure after the durable Ambiguous
    /// transition remains observation-only and is never retried here.
    pub fn execute_admitted<F>(
        &mut self,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        if !self.is_apply_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let outcome = match self.execute_composed(operation_id, trusted_clock) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.latch_recovery_required();
                return Err(StorageRuntimeError::Recovery);
            }
        };
        if matches!(outcome, ZfsHelperOutcome::ObservationRequired { .. }) {
            self.latch_recovery_required();
        }
        Ok(outcome.into())
    }

    fn execute_composed<F>(
        &mut self,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
    ) -> Result<ZfsHelperOutcome, crate::helper::ZfsHelperError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        let prepared = self
            .coordinator
            .preobserve(&mut self.helper, operation_id)?;
        let remove_requirement = self
            .coordinator
            .workspace_remove_pin_requirement(&prepared)?;
        match remove_requirement {
            WorkspaceRemovePinRequirementV1::Required(expected_pin) => {
                let entry = prepared.entry();
                let (pin_outcome, committed) =
                    self.coordinator.execute_workspace_remove_and_destroy(
                        &mut self.pin_executor,
                        &self.pin_contract,
                        &self.pin_custody,
                        prepared,
                        expected_pin,
                        trusted_clock,
                    )?;
                return match (pin_outcome, committed) {
                    (WorkspacePinExecutionOutcomeV1::Satisfied, Some(result)) => {
                        let retirement = self
                            .coordinator
                            .workspace_retirement(result)
                            .map_err(|_| crate::helper::ZfsHelperError::PostconditionMismatch)?;
                        self.workspaces
                            .retire(retirement)
                            .map_err(|_| crate::helper::ZfsHelperError::PostconditionMismatch)?;
                        Ok(ZfsHelperOutcome::Committed(result))
                    }
                    _ => Ok(ZfsHelperOutcome::ObservationRequired {
                        phase: DurableStoragePhase::Ambiguous,
                        mutation_digest: entry.mutation_digest(),
                    }),
                };
            }
            WorkspaceRemovePinRequirementV1::Missing => {
                return Err(crate::helper::ZfsHelperError::PostconditionMismatch);
            }
            WorkspaceRemovePinRequirementV1::NotWorkspace => {}
        }

        let outcome =
            self.coordinator
                .execute_preobserved(&mut self.helper, prepared, trusted_clock)?;
        let ZfsHelperOutcome::Committed(result) = outcome else {
            return Ok(outcome);
        };
        if self
            .coordinator
            .workspace_identity_range(result.operation_id())
            .map_err(|_| crate::helper::ZfsHelperError::PostconditionMismatch)?
            .is_none()
        {
            return Ok(ZfsHelperOutcome::Committed(result));
        }

        let pin_outcome = self.coordinator.execute_workspace_pin_ensure(
            &mut self.pin_executor,
            &self.pin_contract,
            &self.pin_custody,
            result,
            trusted_clock,
        )?;
        if pin_outcome != WorkspacePinExecutionOutcomeV1::Satisfied {
            return Err(crate::helper::ZfsHelperError::PostconditionMismatch);
        }
        let publication = self
            .coordinator
            .workspace_publication(result)
            .map_err(|_| crate::helper::ZfsHelperError::PostconditionMismatch)?;
        self.workspaces
            .publish(publication)
            .map_err(|_| crate::helper::ZfsHelperError::PostconditionMismatch)?;
        Ok(ZfsHelperOutcome::Committed(result))
    }

    fn reconcile_startup(&mut self) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let entries = self
            .coordinator
            .recovery_entries()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let mut pending = 0;
        for entry in entries {
            if entry.phase() == DurableStoragePhase::Committed {
                continue;
            }
            match self
                .coordinator
                .reconcile_recovery(&mut self.helper, entry)
                .map_err(|_| StorageRuntimeError::Recovery)?
            {
                ZfsHelperOutcome::Committed(_) => {}
                ZfsHelperOutcome::ObservationRequired { .. } => pending += 1,
            }
        }
        for dispatch in self
            .coordinator
            .workspace_pin_observation_dispatches()
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            let request = dispatch
                .request_bytes(&self.pin_contract)
                .map_err(|_| StorageRuntimeError::Recovery)?;
            let result = self
                .pin_observer
                .observe(&request, dispatch.attempt(), &self.pin_custody)
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
            .pin_custody
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
                .pin_observer
                .observe_repair(
                    &request,
                    dispatch.attempt().attempt_id(),
                    dispatch.probe().digest(),
                    &self.pin_custody,
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
        let identity_ranges = self
            .coordinator
            .workspace_identity_ranges()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        self.workspaces
            .validate_transaction_identity_ranges(&identity_ranges)?;
        let projection = self
            .coordinator
            .workspace_projection()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        self.workspaces.converge(projection)?;
        Ok(if pending == 0 {
            StorageRuntimeReadiness::IntegrationIncomplete
        } else {
            StorageRuntimeReadiness::RecoveryPending {
                operations: pending,
            }
        })
    }

    fn latch_recovery_required(&mut self) {
        let operations = match self.readiness {
            StorageRuntimeReadiness::RecoveryPending { operations } => operations.max(1),
            _ => 1,
        };
        self.readiness = StorageRuntimeReadiness::RecoveryPending { operations };
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
        .map_err(|_| StorageRuntimeError::Recovery)
}

fn authenticate_before_workspace_inventory<T>(
    authenticate: impl FnOnce() -> Result<(), StorageRuntimeError>,
    open_inventory: impl FnOnce() -> Result<T, StorageRuntimeError>,
) -> Result<T, StorageRuntimeError> {
    authenticate()?;
    open_inventory()
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

impl From<ZfsHelperOutcome> for StorageRuntimeMutationOutcome {
    fn from(value: ZfsHelperOutcome) -> Self {
        match value {
            ZfsHelperOutcome::Committed(result) => Self::Committed(result),
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

    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;
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
        ResolvedCatalogCommitmentV1::new(
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
}
