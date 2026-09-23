//! Authenticated-session callsite for Storage effects.
//!
//! This module deliberately has no service registration. It joins the
//! constructible protected Storage runtime to the existing signed admission and
//! one-shot execution paths only when an external protected-session owner
//! supplies the exact already-authenticated body and kernel identity evidence.

use std::path::{Path, PathBuf};

use aos_proto::aos::sandbox::local::v1::{
    AtomicStorageSnapshotResponse, BrokerMethod, StorageResult,
};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::semantics::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    StorageAdmissionError, StorageAdmissionOutcome, StorageBrokerRuntime, StorageIdentityPoolV1,
    StorageOperation, StorageRuntimeError, StorageRuntimeMutationOutcome, SystemdZfsExecutor,
};

mod sealed {
    pub trait Sealed {}
}

/// Reports rejection at the dormant broker-session-to-Storage boundary.
#[derive(Debug, thiserror::Error)]
pub enum DormantStorageBrokerCallErrorV1 {
    /// The protected session and live kernel boot identities differ.
    #[error("authenticated Storage handoff has stale kernel evidence")]
    StaleKernel,
    /// Storage admission or execution rejected the exact request.
    #[error("authenticated Storage Apply failed: {0}")]
    Runtime(#[from] StorageRuntimeError),
}

/// Seals the result produced by the real Storage admission/execution path.
///
/// Its private fields prevent callers from manufacturing a successful domain
/// observation for the broker-session owner.
pub struct DormantStorageBrokerObservationV1 {
    operation_id: [u8; 16],
    operation: StorageOperation,
    admission: StorageAdmissionOutcome,
    execution: Option<StorageRuntimeMutationOutcome>,
    commitment: ObjectDigest,
}

impl DormantStorageBrokerObservationV1 {
    /// Returns the exact successful Storage result derived from committed state.
    ///
    /// # Errors
    ///
    /// Returns an error while the durable mutation is absent, aborted, or
    /// observation-only and therefore cannot truthfully produce success.
    pub fn response(&self) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        let committed = self
            .execution
            .and_then(|execution| match execution {
                StorageRuntimeMutationOutcome::Committed(result) => Some(result),
                StorageRuntimeMutationOutcome::Aborted { .. }
                | StorageRuntimeMutationOutcome::ObservationRequired { .. } => None,
            })
            .or_else(|| match self.admission {
                StorageAdmissionOutcome::Replay(result) => Some(result),
                _ => None,
            })
            .ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        Ok(StorageResult {
            storage_handle: committed
                .storage_handle()
                .map_or_else(Vec::new, |handle| handle.to_vec()),
            immutable_version_handle: committed
                .immutable_version_handle()
                .map_or_else(Vec::new, |handle| handle.to_vec()),
            non_secret_receipt: committed.result_digest().as_bytes().to_vec(),
            ..Default::default()
        }
        .encode_to_vec())
    }

    /// Returns the exact Storage operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the closed Storage operation.
    #[must_use]
    pub const fn operation(&self) -> StorageOperation {
        self.operation
    }

    /// Returns the durable admission classification.
    #[must_use]
    pub const fn admission(&self) -> &StorageAdmissionOutcome {
        &self.admission
    }

    /// Returns execution evidence when a newly prepared effect was consumed.
    #[must_use]
    pub const fn execution(&self) -> Option<&StorageRuntimeMutationOutcome> {
        self.execution.as_ref()
    }

    /// Returns the domain-separated observation commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Defines the closed call surface accepted by broker-session security.
///
/// The private supertrait restricts implementations to this crate, so a
/// public caller cannot replace Storage execution with fabricated success.
#[doc(hidden)]
pub trait DormantStorageBrokerCallsiteV1: sealed::Sealed {
    /// Admits and, for a fresh Prepared row, executes one exact Apply body.
    ///
    /// # Errors
    ///
    /// Returns an error when request or kernel evidence is stale, or when the
    /// durable Storage admission or execution path rejects the call.
    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantStorageBrokerObservationV1, DormantStorageBrokerCallErrorV1>;

    /// Executes one exact authenticated Storage prepare, repair, or grouped
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for any other method, stale kernel/request evidence,
    /// or a result that still requires authoritative recovery observation.
    fn consume_authenticated_operation(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1>;
}

/// Owns the complete source-only protected Storage Apply composition.
///
/// Construction opens the same protected catalogs and worker custody as the
/// explicit dormant runtime constructor. It does not advertise Apply or
/// install a listener; consumption remains an explicit broker-session call.
pub struct DormantStorageApplyCompositionV1 {
    runtime: StorageBrokerRuntime,
}

impl DormantStorageApplyCompositionV1 {
    /// Opens the complete dormant protected Storage Apply composition.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when protected state, worker custody,
    /// Snapshot metadata, or startup recovery cannot be established.
    #[allow(clippy::too_many_arguments)]
    pub fn open_root_owned(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        let runtime = StorageBrokerRuntime::open_root_owned_dormant_apply_worker(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
        )?;
        Ok(Self { runtime })
    }

    /// Wraps an already-open explicit dormant Apply runtime.
    #[must_use]
    pub const fn from_runtime(runtime: StorageBrokerRuntime) -> Self {
        Self { runtime }
    }

    /// Returns the retained runtime for explicit recovery coordination.
    #[must_use]
    pub const fn runtime(&self) -> &StorageBrokerRuntime {
        &self.runtime
    }

    /// Produces one complete post-observation Storage inventory body.
    ///
    /// The caller must submit these exact bytes through the authenticated
    /// Storage inventory broker-session outcome path. This method performs no
    /// service registration or advertisement.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when either live workspace observation
    /// or the subsequent protected five-family resolver reread fails.
    pub fn lifecycle_inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.runtime.dormant_lifecycle_inventory_resources(
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )
    }

    /// Resolves an atomic lifecycle dataset snapshot against protected Storage state.
    ///
    /// This performs no mutation. The returned opaque program includes every
    /// currently owned Dataset row selected by the lifecycle closure, and only
    /// the Storage-owned grouped backend path may consume it.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`](aos_sandbox::lifecycle::LifecyclePhase6ErrorV1)
    /// for a stale inventory head, omitted owned dataset, substituted
    /// SnapshotId, or mismatched protected catalog.
    pub fn prepare_atomic_dataset_snapshot(
        &self,
        plan: &aos_sandbox::lifecycle::LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<crate::DormantAtomicDatasetSnapshotV1, aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>
    {
        self.runtime.prepare_lifecycle_atomic_snapshot(plan)
    }

    /// Recovers one retained coordinated snapshot without redispatching it.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for corrupt protected custody or a
    /// worker/projection failure. Ambiguous work is only physically observed.
    pub fn recover_atomic_dataset_snapshot(
        &mut self,
        operation: [u8; 16],
    ) -> Result<crate::AtomicDatasetSnapshotMutationOutcomeV1, StorageRuntimeError> {
        self.runtime.recover_lifecycle_atomic_snapshot(operation)
    }
}

impl sealed::Sealed for DormantStorageApplyCompositionV1 {}

impl DormantStorageBrokerCallsiteV1 for DormantStorageApplyCompositionV1 {
    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantStorageBrokerObservationV1, DormantStorageBrokerCallErrorV1> {
        let current_boot_id = KernelBootId::current()
            .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?
            .into_bytes();
        if current_boot_id != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let current_clock = super::runtime::trusted_paired_clock_sample()?;
        if current_clock.host_boot_id() != protected_boot_id {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        let (admitted_id, operation, admission) = self.runtime.admit_signed_apply_intent(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            &current_clock,
        )?;
        if admitted_id != request_id {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let execution = if matches!(admission, StorageAdmissionOutcome::Prepared { .. }) {
            let mut clock = || {
                let sample = super::runtime::trusted_paired_clock_sample()
                    .map_err(|_| StorageAdmissionError::FenceRejected)?;
                if sample.host_boot_id() != protected_boot_id {
                    return Err(StorageAdmissionError::FenceRejected);
                }
                Ok(sample)
            };
            Some(self.runtime.execute_admitted(request_id, &mut clock)?)
        } else {
            None
        };
        let commitment = storage_observation_commitment(
            request_id,
            request_body_digest,
            operation,
            &admission,
            execution.as_ref(),
        );
        Ok(DormantStorageBrokerObservationV1 {
            operation_id: request_id,
            operation,
            admission,
            execution,
            commitment,
        })
    }

    fn consume_authenticated_operation(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        let current_boot_id = KernelBootId::current()
            .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?
            .into_bytes();
        if current_boot_id != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let mut clock = || {
            let sample = super::runtime::trusted_paired_clock_sample()
                .map_err(|_| StorageAdmissionError::FenceRejected)?;
            if sample.host_boot_id() != protected_boot_id {
                return Err(StorageAdmissionError::FenceRejected);
            }
            Ok(sample)
        };
        match method {
            BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
                let request = aos_sandbox_protocol::decode_atomic_storage_snapshot_request(
                    request_body,
                    peer,
                    policy,
                    0,
                )
                .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?;
                if request.header().request_id() != &request_id
                    || request.header().protocol_version() != protocol_version
                {
                    return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
                }
                match self.runtime.execute_authenticated_atomic_snapshot(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    &mut clock,
                )? {
                    crate::AtomicDatasetSnapshotMutationOutcomeV1::Committed {
                        program,
                        observation,
                    } => Ok(AtomicStorageSnapshotResponse {
                        program_digest: program.as_bytes().to_vec(),
                        observation_digest: observation.as_bytes().to_vec(),
                        observation_required: false,
                        ..Default::default()
                    }
                    .encode_to_vec()),
                    crate::AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                        ..
                    }
                    | crate::AtomicDatasetSnapshotMutationOutcomeV1::PreparedBeforeEffect {
                        ..
                    } => Err(DormantStorageBrokerCallErrorV1::StaleKernel),
                }
            }
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => self
                .runtime
                .prepare_catalog(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    &mut clock,
                )
                .map(|outcome| outcome.response().encode_to_vec())
                .map_err(Into::into),
            BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
                let initial = super::runtime::trusted_paired_clock_sample()?;
                let semantics = CanonicalStorageRepairSemanticsV1::decode(
                    request_body,
                    peer,
                    policy,
                    initial.boottime_nanoseconds(),
                )
                .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?;
                if semantics.header().request_id() != &request_id
                    || semantics.header().protocol_version() != protocol_version
                {
                    return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
                }
                match self.runtime.repair_workspace_pin(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    &mut clock,
                )? {
                    crate::WorkspacePinRepairExecutionOutcomeV1::Satisfied => Ok(StorageResult {
                        storage_handle: semantics.storage_handle().as_bytes().to_vec(),
                        ..Default::default()
                    }
                    .encode_to_vec()),
                    crate::WorkspacePinRepairExecutionOutcomeV1::ObservationRequired => {
                        Err(DormantStorageBrokerCallErrorV1::StaleKernel)
                    }
                }
            }
            _ => Err(DormantStorageBrokerCallErrorV1::StaleKernel),
        }
    }
}

fn storage_observation_commitment(
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    operation: StorageOperation,
    admission: &StorageAdmissionOutcome,
    execution: Option<&StorageRuntimeMutationOutcome>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-storage-broker-observation-v1\0");
    digest.update(request_id);
    digest.update(request_body_digest.as_bytes());
    digest.update([match operation {
        StorageOperation::CreateWorkspace { .. } => 1,
        StorageOperation::Snapshot { .. } => 2,
        StorageOperation::HoldSnapshot { .. } => 3,
        StorageOperation::ReleaseHold { .. } => 4,
        StorageOperation::Clone { .. } => 5,
        StorageOperation::SetQuota { .. } => 6,
        StorageOperation::Destroy { .. } => 7,
    }]);
    match admission {
        StorageAdmissionOutcome::Prepared { mutation_digest } => {
            digest.update([1]);
            digest.update(mutation_digest.as_bytes());
        }
        StorageAdmissionOutcome::ObservationRequired {
            mutation_digest, ..
        } => {
            digest.update([2]);
            digest.update(mutation_digest.as_bytes());
        }
        StorageAdmissionOutcome::Replay(result) => {
            digest.update([3]);
            digest.update(result.result_digest().as_bytes());
        }
        StorageAdmissionOutcome::Aborted { mutation_digest } => {
            digest.update([4]);
            digest.update(mutation_digest.as_bytes());
        }
    }
    match execution {
        Some(StorageRuntimeMutationOutcome::Committed(result)) => {
            digest.update([1]);
            digest.update(result.result_digest().as_bytes());
        }
        Some(StorageRuntimeMutationOutcome::Aborted { mutation_digest }) => {
            digest.update([2]);
            digest.update(mutation_digest.as_bytes());
        }
        Some(StorageRuntimeMutationOutcome::ObservationRequired {
            mutation_digest, ..
        }) => {
            digest.update([3]);
            digest.update(mutation_digest.as_bytes());
        }
        None => digest.update([0]),
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}
