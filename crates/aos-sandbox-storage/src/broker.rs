//! Non-executing storage admission coordinator.
//!
//! The coordinator is the sole owner of the storage journal lock. It verifies
//! portable signed authority against an exact node-local catalog resolution,
//! then commits the authenticated assignment fence, non-authorizing admission
//! intent, and storage transaction intent in one journal transaction. It does
//! not cross the ambiguous-mutation boundary and exposes no ZFS invocation.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::journal::RecordNamespace;
use aos_sandbox_broker::{BrokerAuthorizationFenceV1, BrokerEffectIntentV2, BrokerEffectStatusV2};
use aos_sandbox_core::model::SandboxSpec;
use aos_sandbox_core::{
    BrokerAssignment, BrokerGrantTarget, BrokerVerb, CanonicalAssignmentManifestV1, NodeId,
    ObjectDigest, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::semantics::storage_prepare::CanonicalStoragePreparationSemanticsV1;
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use sha2::{Digest as _, Sha256};

use crate::authorization::{StorageAuthorityV1, decode_assignment};
use crate::catalog_preparation::{
    RetainedStorageCatalogPreparationV1, StoragePreparationAuthorityRecordsV1,
};
use crate::helper::{
    PreobservedZfsMutation, StorageMutationHelper, ZfsHelperError, ZfsHelperOutcome,
    ZfsProcessBackend,
};
use crate::pin_observer::WorkspacePinHostCustody;
use crate::pin_worker::{
    WorkspacePinWorkerAuthorityV1, encode_request as encode_pin_worker_request,
};
use crate::pin_worker_runtime::{
    FreshWorkspacePinRepairObservationV1, SystemdWorkspacePinExecutor,
};
use crate::state::{CatalogPreparationConsumption, StorageWorkspaceProjection};
use crate::workspace_catalog::{
    StorageWorkspaceCatalogActionV1, StorageWorkspacePublicationV1, StorageWorkspaceRetirementV1,
};
use crate::workspace_pin::{
    BeginWorkspacePinAttemptV1, WorkspacePinActionV1, WorkspacePinAttemptPhaseV1,
    WorkspacePinAttemptV1, WorkspacePinHostScopeV1, WorkspacePinRecoveryDispositionV1,
    WorkspaceRootPinProofV1,
};
use crate::workspace_repair::WorkspacePinRepairProbeV1;
use crate::workspace_repair_admission::{
    WorkspacePinRepairAdmissionProbeV1, WorkspacePinRepairAdmissionRequestV1,
    bind_probe as bind_repair_admission_probe, classify_predecessor as classify_repair_predecessor,
    encode_request as encode_repair_admission_request,
};
use crate::workspace_repair_observer::{
    WorkspacePinRepairObserverRequestV1, WorkspacePinRepairObserverResultV1,
    bind_probe as bind_repair_probe, encode_request as encode_repair_observer_request,
    random_challenge as random_repair_challenge,
};
use crate::workspace_repair_worker::{
    WorkspacePinRepairWorkerRequestV1, encode_request as encode_repair_worker_request,
};
use crate::{
    BeginStorageTransaction, CatalogPlanV1, CommittedStorageResultV1, DurableStoragePhase,
    ProtectedStorageCatalogResolverV1, ResolvedCatalogCommitmentV1, StorageCatalogPreparationError,
    StorageCatalogPreparationOutcomeV1, StorageTransactionStore, StorageWorkspaceCatalogError,
    ZfsHelperContract, ZfsTransaction, decode_resolved,
};

/// Reports fail-closed storage admission failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageBrokerError {
    /// Hostile request bytes or local catalog association failed.
    #[error("storage request or catalog resolution was rejected")]
    Request,
    /// Protected signed plan, lease, or fence validation failed.
    #[error("storage authority was rejected")]
    Authority,
    /// Signed catalog preparation resolution or replay failed closed.
    #[error("storage catalog preparation failed: {0}")]
    Preparation(#[from] StorageCatalogPreparationError),
    /// Durable admission state was corrupt, conflicting, or unavailable.
    #[error("storage durable admission failed: {0}")]
    State(#[from] crate::StorageStateError),
    /// Workspace publication inputs failed closed validation.
    #[error("storage workspace catalog input was rejected: {0}")]
    WorkspaceCatalog(#[from] StorageWorkspaceCatalogError),
}

/// Classifies a durable admission without implying that mutation is runnable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAdmissionOutcome {
    /// Exact authority and intent were durably prepared for future observation.
    Prepared {
        /// Deterministic identity of the non-executing mutation intent.
        mutation_digest: ObjectDigest,
    },
    /// Recovery must only re-observe; it must never blindly reapply mutation.
    ObservationRequired {
        /// Durable crash phase requiring reconciliation.
        phase: DurableStoragePhase,
        /// Deterministic identity of the pending mutation.
        mutation_digest: ObjectDigest,
    },
    /// A future observer previously committed an exact result.
    Replay(crate::CommittedStorageResultV1),
}

/// Serializes protected storage authority and durable transaction admission.
pub struct StorageAdmissionCoordinator {
    authority: StorageAuthorityV1,
    transactions: StorageTransactionStore,
}

struct AuthenticatedCatalogPreparation {
    record: RetainedStorageCatalogPreparationV1,
    preparation_fence: BrokerAuthorizationFenceV1,
    sealed_record: Vec<u8>,
}

/// Proves that one exact persisted effect passed the final authority check.
///
/// Only [`StorageAdmissionCoordinator`] constructs this non-clone value. The
/// coordinator consumes it synchronously rather than returning it to callers.
pub(crate) struct FreshStorageEffectAuthority {
    entry: crate::StorageRecoveryEntry,
}

/// Proves a fresh authority check covered one exact root-pin attempt.
///
/// The attempt ID is the consumed grant identity persisted atomically with the
/// attempt record. The digest binds its action, parent result, fence,
/// assignment, dataset, proof precondition, and retained identity range.
pub(crate) struct FreshWorkspacePinAuthority {
    attempt_id: [u8; 16],
    attempt_digest: ObjectDigest,
    sealed_receipt: Vec<u8>,
}

impl FreshWorkspacePinAuthority {
    pub(crate) const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    pub(crate) const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }

    pub(crate) fn into_sealed_receipt(self) -> Vec<u8> {
        self.sealed_receipt
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(attempt_id: [u8; 16], attempt_digest: ObjectDigest) -> Self {
        Self {
            attempt_id,
            attempt_digest,
            sealed_receipt: vec![0xa5],
        }
    }
}

pub(crate) enum AuthorizedWorkspacePinAttemptV1 {
    Dispatch(Box<FreshWorkspacePinDispatchV1>),
    ObserveOnly,
    Satisfied,
}

/// Carries one non-clone, freshly checked pin attempt into immediate dispatch.
pub(crate) struct FreshWorkspacePinDispatchV1 {
    attempt: WorkspacePinAttemptV1,
    catalog: ResolvedCatalogCommitmentV1,
    worker_authority: WorkspacePinWorkerAuthorityV1,
}

/// Carries one authenticated historical attempt into the read-only helper.
pub(crate) struct WorkspacePinObservationDispatchV1 {
    attempt: WorkspacePinAttemptV1,
    catalog: ResolvedCatalogCommitmentV1,
    observer_authority: WorkspacePinWorkerAuthorityV1,
}

/// Carries one fresh observation challenge for the latest retained repair.
pub(crate) struct WorkspacePinRepairObservationDispatchV1 {
    attempt: WorkspacePinAttemptV1,
    request: WorkspacePinRepairObserverRequestV1,
    probe: WorkspacePinRepairProbeV1,
}

/// Carries one fresh, non-authorizing observation challenge before admission.
pub(crate) struct WorkspacePinRepairAdmissionDispatchV1 {
    latest_attempt: WorkspacePinAttemptV1,
    request: WorkspacePinRepairAdmissionRequestV1,
    probe: WorkspacePinRepairAdmissionProbeV1,
}

/// Classifies a freshly admitted repair without permitting replay dispatch.
pub(crate) enum AuthorizedWorkspacePinRepairAttemptV1 {
    /// A newly committed attempt may be handed to the fixed repair worker once.
    Dispatch(Box<FreshWorkspacePinRepairDispatchV1>),
    /// The exact repair operation was already durable and is observation-only.
    ObserveOnly,
}

/// Carries one newly committed repair attempt into immediate worker encoding.
pub(crate) struct FreshWorkspacePinRepairDispatchV1 {
    attempt: WorkspacePinAttemptV1,
    request: WorkspacePinRepairWorkerRequestV1,
}

impl FreshWorkspacePinRepairDispatchV1 {
    pub(crate) const fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) fn worker_request_bytes(&self) -> Result<Vec<u8>, ZfsHelperError> {
        encode_repair_worker_request(&self.request).map_err(ZfsHelperError::Backend)
    }
}

impl WorkspacePinRepairAdmissionDispatchV1 {
    pub(crate) const fn probe(&self) -> &WorkspacePinRepairAdmissionProbeV1 {
        &self.probe
    }

    pub(crate) fn request_bytes(&self) -> Result<Vec<u8>, ZfsHelperError> {
        encode_repair_admission_request(&self.request).map_err(ZfsHelperError::Backend)
    }
}

impl WorkspacePinRepairObservationDispatchV1 {
    pub(crate) const fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn probe(&self) -> &WorkspacePinRepairProbeV1 {
        &self.probe
    }

    pub(crate) fn request_bytes(&self) -> Result<Vec<u8>, ZfsHelperError> {
        encode_repair_observer_request(&self.request).map_err(ZfsHelperError::Backend)
    }
}

impl WorkspacePinObservationDispatchV1 {
    pub(crate) fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) fn request_bytes(
        &self,
        contract: &crate::ZfsHelperContract,
    ) -> Result<Vec<u8>, ZfsHelperError> {
        encode_pin_worker_request(contract, &self.catalog, &self.observer_authority)
            .map_err(ZfsHelperError::Backend)
    }
}

impl FreshWorkspacePinDispatchV1 {
    pub(crate) fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) fn worker_request_bytes(
        &self,
        contract: &crate::ZfsHelperContract,
    ) -> Result<Vec<u8>, ZfsHelperError> {
        encode_pin_worker_request(contract, &self.catalog, &self.worker_authority)
            .map_err(ZfsHelperError::Backend)
    }
}

pub(crate) enum AuthorizedWorkspaceRemoveAttemptV1 {
    Dispatch(Box<FreshWorkspaceRemoveDispatchV1>),
    ObserveOnly,
    Satisfied,
}

/// Classifies whether synchronous pin coordination reached durable satisfaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinExecutionOutcomeV1 {
    /// The exact worker result was durably accepted.
    Satisfied,
    /// A prior ambiguous attempt forbids another dispatch.
    ObservationRequired,
}

pub(crate) enum WorkspaceRemovePinRequirementV1 {
    NotWorkspace,
    Required(WorkspaceRootPinProofV1),
    Missing,
}

/// Couples the consumed pin grant to the pre-observed ZFS destruction.
pub(crate) struct FreshWorkspaceRemoveDispatchV1 {
    attempt: WorkspacePinAttemptV1,
    prepared: PreobservedZfsMutation,
    catalog: ResolvedCatalogCommitmentV1,
    worker_authority: WorkspacePinWorkerAuthorityV1,
}

impl FreshWorkspaceRemoveDispatchV1 {
    pub(crate) fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) fn into_parts(self) -> (WorkspacePinAttemptV1, PreobservedZfsMutation) {
        (self.attempt, self.prepared)
    }

    pub(crate) fn worker_request_bytes(
        &self,
        contract: &crate::ZfsHelperContract,
    ) -> Result<Vec<u8>, ZfsHelperError> {
        encode_pin_worker_request(contract, &self.catalog, &self.worker_authority)
            .map_err(ZfsHelperError::Backend)
    }
}

impl FreshStorageEffectAuthority {
    pub(crate) const fn entry(&self) -> crate::StorageRecoveryEntry {
        self.entry
    }

    #[cfg(test)]
    pub(crate) const fn new_for_test(entry: crate::StorageRecoveryEntry) -> Self {
        Self { entry }
    }
}

impl StorageAdmissionCoordinator {
    /// Constructs a coordinator from complete protected authority and state.
    #[must_use]
    pub const fn new(authority: StorageAuthorityV1, transactions: StorageTransactionStore) -> Self {
        Self {
            authority,
            transactions,
        }
    }

    /// Resolves and durably retains one independently authorized catalog preparation.
    ///
    /// The returned receipt is authenticated replay evidence only. It cannot
    /// authorize Apply, and successful preparation performs no physical or
    /// catalog-head mutation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] for hostile request bytes, stale trusted
    /// inventory or catalog head, rejected signed authority, unsafe protected
    /// resolution, operation equivocation, corrupt replay links, or failure to
    /// retain the preparation and its authority records atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_catalog<R: ProtectedStorageCatalogResolverV1>(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        current_inventory: crate::CatalogBindingV1,
        resolver: &R,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<StorageCatalogPreparationOutcomeV1, StorageBrokerError> {
        self.transactions.ensure_authority_readable()?;
        let semantics = CanonicalStoragePreparationSemanticsV1::decode(
            request_body,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageBrokerError::Request)?;
        let operation_id = semantics.operation_id();
        let sandbox_id = *semantics.fence().sandbox_id();
        let request_id = *semantics.header().request_id();
        let retained = self
            .transactions
            .catalog_preparation_record(&operation_id)?
            .map(<[u8]>::to_vec);
        let prior_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .map(<[u8]>::to_vec);
        let admission = self
            .authority
            .admit_preparation(
                artifacts,
                &semantics,
                request_body,
                protocol_version,
                current_clock,
                prior_fence.as_deref(),
            )
            .map_err(|_| StorageBrokerError::Authority)?;

        if let Some(sealed_record) = retained {
            let retained = self.authenticate_catalog_preparation(operation_id, sealed_record)?;
            retained.record.replay_matches(
                &semantics,
                admission.effect.plan_digest(),
                admission.effect.lease_digest(),
                current_clock.host_boot_id(),
                current_clock.boottime_nanoseconds(),
            )?;
            if retained.preparation_fence != admission.fence
                || admission.effect.transport_request_digest()
                    != ObjectDigest::from_bytes(Sha256::digest(request_body).into())
            {
                return Err(StorageCatalogPreparationError::Equivocation.into());
            }
            if retained.record.consumption().is_some() {
                self.authenticate_consumed_preparation(&retained)?;
            }
            return retained.record.outcome().map_err(Into::into);
        }

        if semantics.inventory_binding() != current_inventory {
            return Err(StorageCatalogPreparationError::InventoryMismatch.into());
        }
        let current_head = self.transactions.catalog_head_binding()?;
        if semantics.expected_catalog_head() != current_head {
            return Err(StorageCatalogPreparationError::StaleCatalogHead.into());
        }
        let catalog = resolver.resolve(&semantics, current_head)?;
        let sealed = self
            .authority
            .seal(&sandbox_id, &request_id, &operation_id, &admission)
            .map_err(|_| StorageBrokerError::Authority)?;
        let prepared = RetainedStorageCatalogPreparationV1::prepare(
            &semantics,
            catalog,
            request_id,
            current_clock.host_boot_id(),
            admission.effect.effect_deadline_boottime_nanoseconds(),
            admission.effect.plan_digest(),
            admission.effect.lease_digest(),
            StoragePreparationAuthorityRecordsV1 {
                sealed_fence: &sealed.current_fence,
                sealed_effect: &sealed.effect,
                sealed_operation_fence: &sealed.operation_fence,
            },
        )?;
        let receipt = self
            .authority
            .seal_catalog_preparation_receipt(&operation_id, &prepared.receipt_payload)
            .map_err(|_| StorageBrokerError::Authority)?;
        let record = prepared.record.with_receipt(receipt)?;
        let sealed_record = self
            .authority
            .seal_catalog_preparation_record(&operation_id, &record.encode_payload()?)
            .map_err(|_| StorageBrokerError::Authority)?;

        // The store rechecks the head while committing all four records. No
        // resolver output becomes durable if that compare-and-swap fails.
        self.transactions.retain_catalog_preparation(
            operation_id,
            sandbox_id,
            request_id,
            current_head,
            sealed.current_fence,
            sealed.effect,
            sealed.operation_fence,
            sealed_record,
        )?;
        record.outcome().map_err(Into::into)
    }

    /// Authenticates every retained preparation and its durable cross-links.
    ///
    /// This startup check accepts both unconsumed preparations and preparations
    /// atomically consumed by an admitted Apply in any durable mutation phase.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] when any record is malformed, relocated,
    /// tampered, missing an authority link, or inconsistent with its admitted
    /// Apply operation.
    pub fn authenticate_catalog_preparations(&self) -> Result<(), StorageBrokerError> {
        for (operation_id, sealed_record) in self.transactions.catalog_preparation_records()? {
            let retained = self.authenticate_catalog_preparation(operation_id, sealed_record)?;
            if retained.record.consumption().is_some() {
                self.authenticate_consumed_preparation(&retained)?;
            } else if self.transactions.phase(operation_id)?.is_some() {
                return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
            }
        }
        Ok(())
    }

    pub(crate) fn recovery_entries(
        &self,
    ) -> Result<Vec<crate::StorageRecoveryEntry>, ZfsHelperError> {
        Ok(self.transactions.recovery_entries()?.collect())
    }

    pub(crate) fn authenticate_workspace_pin_attempts(&self) -> Result<(), ZfsHelperError> {
        let attempts = self.transactions.workspace_pin_attempts()?;

        // Repair grants are retained history, not current dispatch authority.
        // Authenticate every such history before reading ordinary effect state.
        for attempt in attempts.iter().filter(|attempt| {
            attempt.action() == WorkspacePinActionV1::Ensure
                && attempt.effect_operation_id() != attempt.creation_operation_id()
        }) {
            let effect = self.authenticate_workspace_pin_repair(attempt)?;
            self.authority
                .verify_pin_attempt_receipt(attempt, &effect, attempt.effect_operation_id())
                .map_err(|_| ZfsHelperError::Authority)?;
        }

        for attempt in attempts.iter().filter(|attempt| {
            attempt.action() != WorkspacePinActionV1::Ensure
                || attempt.effect_operation_id() == attempt.creation_operation_id()
        }) {
            let entry = self
                .transactions
                .current_recovery_entry(attempt.effect_operation_id())?;
            let (_, effect) = self.persisted_effect_context(entry)?;
            self.authority
                .verify_pin_attempt_receipt(attempt, &effect, attempt.effect_operation_id())
                .map_err(|_| ZfsHelperError::Authority)?;
        }
        Ok(())
    }

    fn authenticate_workspace_pin_repair(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<BrokerEffectIntentV2, ZfsHelperError> {
        let operation_id = attempt.effect_operation_id();
        let intent = self
            .transactions
            .workspace_pin_repair_intent(operation_id)?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let sealed_operation_fence = self
            .transactions
            .authority_record(RecordNamespace::AuthorityPublication, &operation_id)?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let live_effect = self
            .transactions
            .authority_record(RecordNamespace::Effect, &intent.request_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let (_, admitted_effect) = self
            .authority
            .authenticate_workspace_pin_repair_intent(&intent, sealed_operation_fence, live_effect)
            .map_err(|_| ZfsHelperError::Authority)?;
        let opened_live_effect = self
            .authority
            .open_admission_intent(&intent.request_id(), live_effect)
            .map_err(|_| ZfsHelperError::Authority)?;
        match (attempt.phase(), opened_live_effect.status()) {
            (WorkspacePinAttemptPhaseV1::Ambiguous, BrokerEffectStatusV2::Pending) => {}
            (WorkspacePinAttemptPhaseV1::Satisfied, BrokerEffectStatusV2::Complete) => {
                let expected_completed_effect = self
                    .authority
                    .seal_workspace_pin_repair_completion(&admitted_effect, attempt)
                    .map_err(|_| ZfsHelperError::Authority)?;
                if expected_completed_effect.as_slice() != live_effect {
                    return Err(ZfsHelperError::Authority);
                }
            }
            _ => return Err(ZfsHelperError::Authority),
        }
        Ok(admitted_effect)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_workspace_pin_repair_admission_observation(
        &self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        contract: &ZfsHelperContract,
        current_host_scope: WorkspacePinHostScopeV1,
    ) -> Result<WorkspacePinRepairAdmissionDispatchV1, ZfsHelperError> {
        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            request_body,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| ZfsHelperError::Authority)?;
        let sandbox_id = *semantics.fence().sandbox_id();
        let prior_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .map(<[u8]>::to_vec);
        let admission = self
            .authority
            .admit_workspace_pin_repair(
                artifacts,
                &semantics,
                request_body,
                protocol_version,
                current_clock,
                prior_fence.as_deref(),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        if self.transactions.phase(semantics.operation_id())?.is_some()
            || self
                .transactions
                .workspace_pin_repair_intent(semantics.operation_id())?
                .is_some()
        {
            return Err(ZfsHelperError::Authority);
        }

        let workspace_handle = *semantics.storage_handle().as_bytes();
        let latest_attempt = self
            .transactions
            .workspace_pin_attempts()?
            .into_iter()
            .filter(|attempt| attempt.workspace_handle() == workspace_handle)
            .max_by_key(WorkspacePinAttemptV1::attempt_ordinal)
            .ok_or(ZfsHelperError::Authority)?;
        let creation_is_active = self.transactions.workspace_creation_is_active(
            latest_attempt.creation_operation_id(),
            workspace_handle,
        )?;
        let predecessor_repair = self
            .transactions
            .workspace_pin_repair_intent(latest_attempt.effect_operation_id())?;
        let predecessor_kind = classify_repair_predecessor(
            &latest_attempt,
            predecessor_repair.as_ref(),
            creation_is_active,
        )?;

        let creation_intent = self
            .transactions
            .workspace_publication_intent(latest_attempt.creation_operation_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        if latest_attempt.workspace_assignment_digest() != creation_intent.assignment_digest() {
            return Err(ZfsHelperError::Authority);
        }
        let catalog = self
            .transactions
            .workspace_creation_catalog_for_attempt(&latest_attempt)?;
        let latest_attempt_record = self
            .transactions
            .workspace_pin_attempt_record(&latest_attempt)?;
        let publication_intent_record = self
            .transactions
            .workspace_publication_intent_record(latest_attempt.creation_operation_id())?;
        let predecessor_repair_intent_record = match predecessor_repair.as_ref() {
            Some(intent) => self
                .transactions
                .workspace_pin_repair_intent_record(intent)?,
            None => Vec::new(),
        };
        let request = WorkspacePinRepairAdmissionRequestV1::new(
            contract.executable().to_path_buf(),
            random_repair_challenge()?,
            *semantics.header().request_id(),
            semantics.operation_id(),
            admission.effect.transport_request_digest(),
            admission.effect.request_digest(),
            admission.fence.assignment().digest(),
            workspace_handle,
            predecessor_kind,
            catalog,
            latest_attempt_record,
            publication_intent_record,
            predecessor_repair_intent_record,
        )?;
        let probe = bind_repair_admission_probe(
            &request,
            &latest_attempt,
            predecessor_repair.as_ref(),
            current_host_scope,
        )?;

        Ok(WorkspacePinRepairAdmissionDispatchV1 {
            latest_attempt,
            request,
            probe,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn workspace_pin_repair_replay(
        &self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<bool, ZfsHelperError> {
        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            request_body,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| ZfsHelperError::Authority)?;
        let Some(intent) = self
            .transactions
            .workspace_pin_repair_intent(semantics.operation_id())?
        else {
            return Ok(false);
        };
        let sandbox_id = *semantics.fence().sandbox_id();
        let prior_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let admission = self
            .authority
            .admit_workspace_pin_repair(
                artifacts,
                &semantics,
                request_body,
                protocol_version,
                current_clock,
                Some(prior_fence),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        let attempt = self
            .transactions
            .workspace_pin_attempts()?
            .into_iter()
            .find(|attempt| attempt.attempt_id() == intent.repair_attempt_id())
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        if intent.request_id() != *semantics.header().request_id()
            || intent.request_digest()
                != ObjectDigest::from_bytes(Sha256::digest(request_body).into())
            || intent.semantic_commitment() != semantics.argument_commitment().digest()
            || intent.repair_assignment_digest() != admission.fence.assignment().digest()
            || intent.workspace_handle() != *semantics.storage_handle().as_bytes()
            || attempt.effect_operation_id() != intent.repair_operation_id()
        {
            return Err(ZfsHelperError::Authority);
        }
        self.authenticate_workspace_pin_repair(&attempt)?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_workspace_pin_repair<F>(
        &mut self,
        dispatch: WorkspacePinRepairAdmissionDispatchV1,
        fresh_observation: FreshWorkspacePinRepairObservationV1,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        contract: &ZfsHelperContract,
        trusted_clock: &mut F,
    ) -> Result<AuthorizedWorkspacePinRepairAttemptV1, ZfsHelperError>
    where
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        if !fresh_observation.matches_probe(&dispatch.probe) {
            return Err(ZfsHelperError::Authority);
        }
        let current_latest = self
            .transactions
            .workspace_pin_attempts()?
            .into_iter()
            .filter(|attempt| {
                attempt.workspace_handle() == dispatch.latest_attempt.workspace_handle()
            })
            .max_by_key(WorkspacePinAttemptV1::attempt_ordinal)
            .ok_or(ZfsHelperError::Authority)?;
        if current_latest != dispatch.latest_attempt
            || !self.transactions.workspace_creation_is_active(
                current_latest.creation_operation_id(),
                current_latest.workspace_handle(),
            )?
        {
            return Err(ZfsHelperError::Authority);
        }
        let predecessor_repair = self
            .transactions
            .workspace_pin_repair_intent(current_latest.effect_operation_id())?;
        classify_repair_predecessor(&current_latest, predecessor_repair.as_ref(), true)?;
        let current_attempt_record = self
            .transactions
            .workspace_pin_attempt_record(&current_latest)?;
        let current_publication_record = self
            .transactions
            .workspace_publication_intent_record(current_latest.creation_operation_id())?;
        let current_repair_record = match predecessor_repair.as_ref() {
            Some(intent) => self
                .transactions
                .workspace_pin_repair_intent_record(intent)?,
            None => Vec::new(),
        };
        if !dispatch.request.matches_current_records(
            &current_attempt_record,
            &current_publication_record,
            &current_repair_record,
        ) {
            return Err(ZfsHelperError::Authority);
        }

        let current_clock = trusted_clock().map_err(|_| ZfsHelperError::Authority)?;
        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            request_body,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| ZfsHelperError::Authority)?;
        let sandbox_id = *semantics.fence().sandbox_id();
        let prior_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .map(<[u8]>::to_vec);
        let admission = self
            .authority
            .admit_workspace_pin_repair(
                artifacts,
                &semantics,
                request_body,
                protocol_version,
                &current_clock,
                prior_fence.as_deref(),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        if !dispatch.request.matches_semantics(
            *semantics.header().request_id(),
            semantics.operation_id(),
            admission.effect.transport_request_digest(),
            admission.effect.request_digest(),
            admission.fence.assignment().digest(),
            *semantics.storage_handle().as_bytes(),
        ) {
            return Err(ZfsHelperError::Authority);
        }
        self.authority
            .check_before_effect(&admission.effect, trusted_clock)
            .map_err(|_| ZfsHelperError::Authority)?;

        let sealed = self
            .authority
            .seal(
                &sandbox_id,
                semantics.header().request_id(),
                &semantics.operation_id(),
                &admission,
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        let operation_fence_digest =
            ObjectDigest::from_bytes(Sha256::digest(&sealed.operation_fence).into());
        let attempt = self.transactions.plan_workspace_pin_repair(
            &current_latest,
            semantics.operation_id(),
            operation_fence_digest,
            admission.fence.assignment().digest(),
            dispatch.probe.current_host_scope(),
            *admission.effect.clock_provenance(),
            admission.effect.effect_deadline_boottime_nanoseconds(),
        )?;
        let sealed_receipt = self
            .authority
            .seal_pin_attempt_receipt(
                &attempt,
                &admission.effect,
                &admission.fence,
                semantics.operation_id(),
                *semantics.header().request_id(),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        let authority = FreshWorkspacePinAuthority {
            attempt_id: attempt.attempt_id(),
            attempt_digest: attempt.authority_digest()?,
            sealed_receipt,
        };
        let repair_intent =
            crate::workspace_repair::StorageWorkspacePinRepairIntentV1::new_ambiguous(
                semantics.operation_id(),
                &admission.effect,
                sealed.effect.clone(),
                admission.fence.assignment().digest(),
                operation_fence_digest,
                current_latest.creation_operation_id(),
                current_latest.creation_result_catalog(),
                current_latest.creation_result_digest(),
                ObjectDigest::from_bytes(Sha256::digest(&current_publication_record).into()),
                current_latest.workspace_handle(),
                current_latest.attempt_id(),
                current_latest.phase(),
                ObjectDigest::from_bytes(Sha256::digest(&current_attempt_record).into()),
                attempt.attempt_id(),
                attempt.attempt_ordinal(),
            )?;
        let sealed_completed_effect = self
            .authority
            .seal_workspace_pin_repair_completion(&admission.effect, &attempt)
            .map_err(|_| ZfsHelperError::Authority)?;
        let outcome = self.transactions.begin_workspace_pin_repair(
            sandbox_id,
            &current_latest,
            repair_intent,
            attempt,
            sealed.current_fence,
            sealed.effect,
            sealed_completed_effect,
            sealed.operation_fence,
            authority,
        )?;
        let BeginWorkspacePinAttemptV1::Dispatch(attempt) = outcome else {
            return Ok(AuthorizedWorkspacePinRepairAttemptV1::ObserveOnly);
        };

        let postcommit = (|| {
            let effect = self.authenticate_workspace_pin_repair(&attempt)?;
            let current_fence_bytes = self
                .transactions
                .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
                .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
            let operation_fence_bytes = self
                .transactions
                .authority_record(
                    RecordNamespace::AuthorityPublication,
                    &attempt.effect_operation_id(),
                )?
                .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
            let current_fence = self
                .authority
                .open_fence(&sandbox_id, current_fence_bytes)
                .map_err(|_| ZfsHelperError::Authority)?;
            let operation_fence = self
                .authority
                .open_operation_fence(&attempt.effect_operation_id(), operation_fence_bytes)
                .map_err(|_| ZfsHelperError::Authority)?;
            if current_fence != operation_fence {
                return Err(ZfsHelperError::Authority);
            }
            self.authority
                .check_before_effect(&effect, trusted_clock)
                .map_err(|_| ZfsHelperError::Authority)?;
            self.authority
                .verify_pin_attempt_receipt(&attempt, &effect, attempt.effect_operation_id())
                .map_err(|_| ZfsHelperError::Authority)?;
            let catalog = self
                .transactions
                .workspace_creation_catalog_for_attempt(&attempt)?;
            let intent = self
                .transactions
                .workspace_pin_repair_intent(attempt.effect_operation_id())?
                .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
            let repair_intent_record = self
                .transactions
                .workspace_pin_repair_intent_record(&intent)?;
            let attempt_record = self.transactions.workspace_pin_attempt_record(&attempt)?;
            let publication_intent_record = self
                .transactions
                .workspace_publication_intent_record(attempt.creation_operation_id())?;
            let worker_authority = WorkspacePinWorkerAuthorityV1::new(
                intent.request_id(),
                attempt_record,
                current_fence_bytes.to_vec(),
                intent.admitted_effect_record().to_vec(),
                operation_fence_bytes.to_vec(),
            )?;
            let request = WorkspacePinRepairWorkerRequestV1::new(
                contract.executable().to_path_buf(),
                catalog,
                worker_authority,
                repair_intent_record,
                publication_intent_record,
            )?;
            Ok(FreshWorkspacePinRepairDispatchV1 { attempt, request })
        })();
        match postcommit {
            Ok(dispatch) => Ok(AuthorizedWorkspacePinRepairAttemptV1::Dispatch(Box::new(
                dispatch,
            ))),
            Err(error) => {
                self.transactions.poison_after_committed_repair_failure();
                Err(error)
            }
        }
    }

    pub(crate) fn workspace_pin_observation_dispatches(
        &self,
    ) -> Result<Vec<WorkspacePinObservationDispatchV1>, ZfsHelperError> {
        let mut dispatches = Vec::new();
        for attempt in self.transactions.workspace_pin_attempts()? {
            let latest = self
                .transactions
                .latest_workspace_pin_attempt(attempt.creation_operation_id())?;
            if latest.as_ref() != Some(&attempt)
                || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
                || (attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.effect_operation_id() != attempt.creation_operation_id())
            {
                continue;
            }
            let entry = self
                .transactions
                .current_recovery_entry(attempt.effect_operation_id())?;
            let (_, effect) = self.persisted_effect_context(entry)?;
            self.authority
                .verify_pin_attempt_receipt(&attempt, &effect, entry.operation_id())
                .map_err(|_| ZfsHelperError::Authority)?;
            dispatches.push(WorkspacePinObservationDispatchV1 {
                catalog: self.transactions.recover_catalog(entry)?,
                observer_authority: self.pin_worker_authority(entry, &attempt)?,
                attempt,
            });
        }
        Ok(dispatches)
    }

    pub(crate) fn workspace_pin_repair_observation_dispatches(
        &self,
        contract: &ZfsHelperContract,
        current_host_scope: WorkspacePinHostScopeV1,
    ) -> Result<Vec<WorkspacePinRepairObservationDispatchV1>, ZfsHelperError> {
        let mut dispatches = Vec::new();
        for intent in self.transactions.workspace_pin_repair_intents()? {
            let Some(attempt) = self
                .transactions
                .latest_workspace_pin_attempt(intent.creation_operation_id())?
            else {
                return Err(crate::StorageStateError::MissingAuthorityLink.into());
            };
            if attempt.attempt_id() != intent.repair_attempt_id()
                || attempt.action() != WorkspacePinActionV1::Ensure
                || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
                || !self.transactions.workspace_creation_is_active(
                    intent.creation_operation_id(),
                    intent.workspace_handle(),
                )?
            {
                continue;
            }

            let catalog = self.transactions.workspace_creation_catalog(&intent)?;
            let repair_intent_record = self
                .transactions
                .workspace_pin_repair_intent_record(&intent)?;
            let repair_attempt_record = self.transactions.workspace_pin_attempt_record(&attempt)?;
            let publication_intent_record = self
                .transactions
                .workspace_publication_intent_record(intent.creation_operation_id())?;
            let historical_attempt_host_scope = WorkspacePinHostScopeV1::new(
                attempt.host_boot_id(),
                attempt.host_mount_namespace_device(),
                attempt.host_mount_namespace_inode(),
            )?;
            let generated_challenge = random_repair_challenge()?;
            let probe = bind_repair_probe(
                &intent,
                &attempt,
                generated_challenge,
                ObjectDigest::from_bytes(Sha256::digest(&repair_intent_record).into()),
                ObjectDigest::from_bytes(Sha256::digest(&publication_intent_record).into()),
                ObjectDigest::from_bytes(Sha256::digest(&repair_attempt_record).into()),
                historical_attempt_host_scope,
                current_host_scope,
            )?;
            let request = WorkspacePinRepairObserverRequestV1::new(
                contract.executable().to_path_buf(),
                generated_challenge,
                catalog,
                repair_intent_record,
                repair_attempt_record,
                publication_intent_record,
            )?;
            dispatches.push(WorkspacePinRepairObservationDispatchV1 {
                attempt,
                request,
                probe,
            });
        }
        Ok(dispatches)
    }

    pub(crate) fn complete_workspace_pin_repair_observation(
        &mut self,
        dispatch: WorkspacePinRepairObservationDispatchV1,
        result: WorkspacePinRepairObserverResultV1,
    ) -> Result<WorkspacePinRecoveryDispositionV1, ZfsHelperError> {
        if result.probe_digest() != dispatch.probe.digest()
            || result.observation().attempt_id() != dispatch.attempt.attempt_id()
            || self
                .transactions
                .latest_workspace_pin_attempt(dispatch.attempt.creation_operation_id())?
                .as_ref()
                != Some(&dispatch.attempt)
            || !self.transactions.workspace_creation_is_active(
                dispatch.attempt.creation_operation_id(),
                dispatch.attempt.workspace_handle(),
            )?
        {
            return Err(ZfsHelperError::Authority);
        }

        let intent = self
            .transactions
            .workspace_pin_repair_intent(dispatch.probe.repair_operation_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let repair_intent_record = self
            .transactions
            .workspace_pin_repair_intent_record(&intent)?;
        let repair_attempt_record = self
            .transactions
            .workspace_pin_attempt_record(&dispatch.attempt)?;
        let publication_intent_record = self
            .transactions
            .workspace_publication_intent_record(dispatch.attempt.creation_operation_id())?;
        if result.probe_digest() != dispatch.probe.digest()
            || ObjectDigest::from_bytes(Sha256::digest(repair_intent_record).into())
                != dispatch.probe.repair_intent_record_digest()
            || ObjectDigest::from_bytes(Sha256::digest(repair_attempt_record).into())
                != dispatch.probe.latest_ensure_attempt_record_digest()
            || ObjectDigest::from_bytes(Sha256::digest(publication_intent_record).into())
                != dispatch.probe.publication_intent_record_digest()
        {
            return Err(ZfsHelperError::Authority);
        }
        if dispatch.probe.historical_attempt_host_scope() != dispatch.probe.current_host_scope()
            && matches!(
                result.observation().pin(),
                crate::workspace_pin::WorkspacePinObservationV1::Present(_)
            )
        {
            return Err(ZfsHelperError::Authority);
        }

        let observation = result.into_observation();
        let disposition = self.complete_workspace_pin_repair_attempt(
            &dispatch.attempt,
            observation.dataset(),
            observation.pin(),
        )?;
        if disposition == WorkspacePinRecoveryDispositionV1::Mismatch {
            return Err(ZfsHelperError::Authority);
        }
        Ok(disposition)
    }

    pub(crate) fn complete_workspace_pin_repair_execution(
        &mut self,
        attempt: &WorkspacePinAttemptV1,
        result: &crate::pin_worker::WorkspacePinWorkerResultV1,
    ) -> Result<WorkspacePinRecoveryDispositionV1, ZfsHelperError> {
        if result.attempt_id() != attempt.attempt_id()
            || self
                .transactions
                .workspace_pin_attempts()?
                .into_iter()
                .find(|candidate| candidate.attempt_id() == attempt.attempt_id())
                .as_ref()
                != Some(attempt)
        {
            return Err(ZfsHelperError::Authority);
        }
        self.complete_workspace_pin_repair_attempt(attempt, result.dataset(), result.pin())
    }

    fn complete_workspace_pin_repair_attempt(
        &mut self,
        attempt: &WorkspacePinAttemptV1,
        dataset: &crate::workspace_pin::WorkspaceDatasetObservationV1,
        pin: &crate::workspace_pin::WorkspacePinObservationV1,
    ) -> Result<WorkspacePinRecoveryDispositionV1, ZfsHelperError> {
        let admitted_effect = self.authenticate_workspace_pin_repair(attempt)?;
        self.authority
            .verify_pin_attempt_receipt(attempt, &admitted_effect, attempt.effect_operation_id())
            .map_err(|_| ZfsHelperError::Authority)?;
        let sealed_completed_effect = self
            .authority
            .seal_workspace_pin_repair_completion(&admitted_effect, attempt)
            .map_err(|_| ZfsHelperError::Authority)?;
        let disposition = self.transactions.complete_workspace_pin_repair_attempt(
            attempt.attempt_id(),
            dataset,
            pin,
            sealed_completed_effect,
        )?;
        if disposition != WorkspacePinRecoveryDispositionV1::CompletePublication {
            return Ok(disposition);
        }

        let satisfied = self
            .transactions
            .workspace_pin_attempts()?
            .into_iter()
            .find(|candidate| candidate.attempt_id() == attempt.attempt_id())
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        if satisfied.phase() != WorkspacePinAttemptPhaseV1::Satisfied
            || !satisfied.same_authorized_effect(attempt)
        {
            self.transactions.poison_after_committed_repair_failure();
            return Err(ZfsHelperError::Authority);
        }
        if self.authenticate_workspace_pin_repair(&satisfied).is_err() {
            self.transactions.poison_after_committed_repair_failure();
            return Err(ZfsHelperError::Authority);
        }
        Ok(disposition)
    }

    pub(crate) fn complete_workspace_pin_observation(
        &mut self,
        attempt: &WorkspacePinAttemptV1,
        result: &crate::pin_worker::WorkspacePinWorkerResultV1,
    ) -> Result<WorkspacePinRecoveryDispositionV1, ZfsHelperError> {
        if result.attempt_id() != attempt.attempt_id()
            || self
                .transactions
                .workspace_pin_attempts()?
                .into_iter()
                .find(|candidate| candidate.attempt_id() == attempt.attempt_id())
                .as_ref()
                != Some(attempt)
        {
            return Err(ZfsHelperError::Authority);
        }
        self.transactions
            .complete_workspace_pin_attempt(attempt.attempt_id(), result.dataset(), result.pin())
            .map_err(Into::into)
    }

    pub(crate) fn reconcile_recovery<B: ZfsProcessBackend>(
        &mut self,
        helper: &mut StorageMutationHelper<B>,
        entry: crate::StorageRecoveryEntry,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        self.authenticate_recovery_entry(entry)?;
        helper.observe_only(&mut self.transactions, entry.operation_id())
    }

    #[cfg(test)]
    pub(crate) fn preobserve_and_execute<B, F>(
        &mut self,
        helper: &mut StorageMutationHelper<B>,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError>
    where
        B: ZfsProcessBackend,
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        let prepared = self.preobserve(helper, operation_id)?;
        self.execute_preobserved(helper, prepared, trusted_clock)
    }

    pub(crate) fn preobserve<B: ZfsProcessBackend>(
        &self,
        helper: &mut StorageMutationHelper<B>,
        operation_id: [u8; 16],
    ) -> Result<PreobservedZfsMutation, ZfsHelperError> {
        helper.preobserve(&self.transactions, operation_id)
    }

    pub(crate) fn begin_workspace_pin_ensure<F>(
        &mut self,
        result: CommittedStorageResultV1,
        host_scope: WorkspacePinHostScopeV1,
        trusted_clock: &mut F,
    ) -> Result<AuthorizedWorkspacePinAttemptV1, ZfsHelperError>
    where
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        let entry = self.transactions.committed_recovery_entry(result)?;
        let current_fence_bytes = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &entry.sandbox_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let current_fence = self
            .authority
            .open_fence(&entry.sandbox_id(), &current_fence_bytes)
            .map_err(|_| ZfsHelperError::Authority)?;
        let (operation_fence, effect) = self.persisted_effect_context(entry)?;
        if current_fence != operation_fence {
            return Err(ZfsHelperError::Authority);
        }
        self.authority
            .check_before_effect(&effect, trusted_clock)
            .map_err(|_| ZfsHelperError::Authority)?;

        let attempt = self.transactions.plan_workspace_pin_ensure(
            result,
            operation_fence.assignment().digest(),
            host_scope,
            *effect.clock_provenance(),
            effect.effect_deadline_boottime_nanoseconds(),
        )?;
        let sealed_receipt = self
            .authority
            .seal_pin_attempt_receipt(
                &attempt,
                &effect,
                &operation_fence,
                entry.operation_id(),
                entry.request_id(),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        let authority = FreshWorkspacePinAuthority {
            attempt_id: attempt.attempt_id(),
            attempt_digest: attempt.authority_digest()?,
            sealed_receipt,
        };
        let outcome = self
            .transactions
            .begin_workspace_pin_attempt(attempt, authority)?;
        match outcome {
            BeginWorkspacePinAttemptV1::Dispatch(attempt) => {
                // The distinct attempt grant is already durably consumed. A
                // second protected clock sample immediately gates handing it
                // to the fixed worker; failure leaves observation-only state.
                self.authority
                    .check_before_effect(&effect, trusted_clock)
                    .map_err(|_| ZfsHelperError::Authority)?;
                self.authority
                    .verify_pin_attempt_receipt(&attempt, &effect, entry.operation_id())
                    .map_err(|_| ZfsHelperError::Authority)?;
                let catalog = self.transactions.recover_catalog(entry)?;
                let worker_authority = self.pin_worker_authority(entry, &attempt)?;
                Ok(AuthorizedWorkspacePinAttemptV1::Dispatch(Box::new(
                    FreshWorkspacePinDispatchV1 {
                        attempt,
                        catalog,
                        worker_authority,
                    },
                )))
            }
            BeginWorkspacePinAttemptV1::ObserveOnly(_) => {
                Ok(AuthorizedWorkspacePinAttemptV1::ObserveOnly)
            }
            BeginWorkspacePinAttemptV1::Satisfied(_) => {
                Ok(AuthorizedWorkspacePinAttemptV1::Satisfied)
            }
        }
    }

    pub(crate) fn begin_workspace_pin_remove_and_destroy<F>(
        &mut self,
        prepared: PreobservedZfsMutation,
        host_scope: WorkspacePinHostScopeV1,
        expected_pin: WorkspaceRootPinProofV1,
        trusted_clock: &mut F,
    ) -> Result<AuthorizedWorkspaceRemoveAttemptV1, ZfsHelperError>
    where
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        let entry = prepared.entry();
        let current_entry = self
            .transactions
            .current_recovery_entry(entry.operation_id())?;
        if current_entry != entry || entry.phase() != DurableStoragePhase::Prepared {
            return Err(crate::StorageStateError::InvalidTransition.into());
        }
        let current_fence_bytes = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &entry.sandbox_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let current_fence = self
            .authority
            .open_fence(&entry.sandbox_id(), &current_fence_bytes)
            .map_err(|_| ZfsHelperError::Authority)?;
        let (operation_fence, effect) = self.persisted_effect_context(entry)?;
        if current_fence != operation_fence {
            return Err(ZfsHelperError::Authority);
        }
        self.authority
            .check_before_effect(&effect, trusted_clock)
            .map_err(|_| ZfsHelperError::Authority)?;
        let catalog = self.transactions.recover_catalog(entry)?;

        let attempt = self.transactions.plan_workspace_pin_remove_and_destroy(
            entry.operation_id(),
            operation_fence.assignment().digest(),
            host_scope,
            *effect.clock_provenance(),
            effect.effect_deadline_boottime_nanoseconds(),
            expected_pin,
        )?;
        let sealed_receipt = self
            .authority
            .seal_pin_attempt_receipt(
                &attempt,
                &effect,
                &operation_fence,
                entry.operation_id(),
                entry.request_id(),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        let authority = FreshWorkspacePinAuthority {
            attempt_id: attempt.attempt_id(),
            attempt_digest: attempt.authority_digest()?,
            sealed_receipt,
        };
        let outcome = self.transactions.begin_workspace_pin_remove_and_destroy(
            attempt,
            entry.mutation_digest(),
            authority,
        )?;
        match outcome {
            BeginWorkspacePinAttemptV1::Dispatch(attempt) => {
                self.authority
                    .check_before_effect(&effect, trusted_clock)
                    .map_err(|_| ZfsHelperError::Authority)?;
                self.authority
                    .verify_pin_attempt_receipt(&attempt, &effect, entry.operation_id())
                    .map_err(|_| ZfsHelperError::Authority)?;
                let worker_authority = self.pin_worker_authority(entry, &attempt)?;
                Ok(AuthorizedWorkspaceRemoveAttemptV1::Dispatch(Box::new(
                    FreshWorkspaceRemoveDispatchV1 {
                        attempt,
                        prepared,
                        catalog,
                        worker_authority,
                    },
                )))
            }
            BeginWorkspacePinAttemptV1::ObserveOnly(_) => {
                Ok(AuthorizedWorkspaceRemoveAttemptV1::ObserveOnly)
            }
            BeginWorkspacePinAttemptV1::Satisfied(_) => {
                Ok(AuthorizedWorkspaceRemoveAttemptV1::Satisfied)
            }
        }
    }

    pub(crate) fn execute_workspace_pin_ensure<F>(
        &mut self,
        executor: &mut SystemdWorkspacePinExecutor,
        contract: &ZfsHelperContract,
        custody: &WorkspacePinHostCustody,
        result: CommittedStorageResultV1,
        trusted_clock: &mut F,
    ) -> Result<WorkspacePinExecutionOutcomeV1, ZfsHelperError>
    where
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        let host_scope = custody.host_scope()?;
        match self.begin_workspace_pin_ensure(result, host_scope, trusted_clock)? {
            AuthorizedWorkspacePinAttemptV1::Dispatch(dispatch) => {
                let request = dispatch.worker_request_bytes(contract)?;
                let result = executor.execute(&request, dispatch.attempt(), custody)?;
                let disposition = self.transactions.complete_workspace_pin_attempt(
                    result.attempt_id(),
                    result.dataset(),
                    result.pin(),
                )?;
                if disposition != WorkspacePinRecoveryDispositionV1::CompletePublication {
                    return Err(ZfsHelperError::PostconditionMismatch);
                }
                Ok(WorkspacePinExecutionOutcomeV1::Satisfied)
            }
            AuthorizedWorkspacePinAttemptV1::Satisfied => {
                Ok(WorkspacePinExecutionOutcomeV1::Satisfied)
            }
            AuthorizedWorkspacePinAttemptV1::ObserveOnly => {
                Ok(WorkspacePinExecutionOutcomeV1::ObservationRequired)
            }
        }
    }

    pub(crate) fn workspace_remove_pin_requirement(
        &self,
        prepared: &PreobservedZfsMutation,
    ) -> Result<WorkspaceRemovePinRequirementV1, ZfsHelperError> {
        let CatalogPlanV1::DestroyDataset { dataset } = prepared.catalog().plan() else {
            return Ok(WorkspaceRemovePinRequirementV1::NotWorkspace);
        };
        let Some(creation) = self
            .transactions
            .managed_workspace_creation(dataset.guid())?
        else {
            return Ok(WorkspaceRemovePinRequirementV1::NotWorkspace);
        };
        if creation.storage_handle() != Some(dataset.storage_handle()) {
            return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
        }
        let latest = self
            .transactions
            .workspace_pin_attempts()?
            .into_iter()
            .filter(|attempt| {
                attempt.workspace_handle() == dataset.storage_handle()
                    && attempt.dataset_name() == dataset.name()
                    && attempt.dataset_guid() == dataset.guid()
                    && attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.phase() == WorkspacePinAttemptPhaseV1::Satisfied
            })
            .max_by_key(WorkspacePinAttemptV1::attempt_ordinal);
        Ok(
            match latest.and_then(|attempt| attempt.satisfied_pin().cloned()) {
                Some(proof) => WorkspaceRemovePinRequirementV1::Required(proof),
                None => WorkspaceRemovePinRequirementV1::Missing,
            },
        )
    }

    pub(crate) fn execute_workspace_remove_and_destroy<F>(
        &mut self,
        executor: &mut SystemdWorkspacePinExecutor,
        contract: &ZfsHelperContract,
        custody: &WorkspacePinHostCustody,
        prepared: PreobservedZfsMutation,
        expected_pin: WorkspaceRootPinProofV1,
        trusted_clock: &mut F,
    ) -> Result<
        (
            WorkspacePinExecutionOutcomeV1,
            Option<CommittedStorageResultV1>,
        ),
        ZfsHelperError,
    >
    where
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        let host_scope = custody.host_scope()?;
        match self.begin_workspace_pin_remove_and_destroy(
            prepared,
            host_scope,
            expected_pin,
            trusted_clock,
        )? {
            AuthorizedWorkspaceRemoveAttemptV1::Dispatch(dispatch) => {
                let request = dispatch.worker_request_bytes(contract)?;
                let result = executor.execute(&request, dispatch.attempt(), custody)?;
                if dispatch.attempt().classify(result.dataset(), result.pin())
                    != WorkspacePinRecoveryDispositionV1::CompleteRetirement
                {
                    return Err(ZfsHelperError::PostconditionMismatch);
                }

                let (attempt, prepared) = (*dispatch).into_parts();
                let transaction =
                    ZfsTransaction::from_catalog(prepared.operation(), prepared.catalog())?;
                let entry = prepared.entry();
                let committed = self.transactions.commit_observed(
                    entry.operation_id(),
                    entry.mutation_digest(),
                    prepared.catalog(),
                    transaction.postcondition(),
                    None,
                    result.observation_digest(),
                )?;
                let disposition = self.transactions.complete_workspace_pin_attempt(
                    attempt.attempt_id(),
                    result.dataset(),
                    result.pin(),
                )?;
                if disposition != WorkspacePinRecoveryDispositionV1::CompleteRetirement {
                    return Err(ZfsHelperError::PostconditionMismatch);
                }
                Ok((WorkspacePinExecutionOutcomeV1::Satisfied, Some(committed)))
            }
            AuthorizedWorkspaceRemoveAttemptV1::Satisfied => {
                Ok((WorkspacePinExecutionOutcomeV1::Satisfied, None))
            }
            AuthorizedWorkspaceRemoveAttemptV1::ObserveOnly => {
                Ok((WorkspacePinExecutionOutcomeV1::ObservationRequired, None))
            }
        }
    }

    /// Verifies and durably records an unadvertised Apply admission intent.
    ///
    /// This method deliberately does not make StorageApply service-ready. A
    /// future privileged observer/helper must reconcile the typed transaction
    /// under this same lock before any service may advertise Apply.
    /// `CreateWorkspace` and `Clone` are rejected because they require the
    /// composed runtime's workspace-publication admission path.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] for hostile bytes, catalog substitution,
    /// signed-authority failure, fencing conflict, or durable-state failure.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<StorageAdmissionOutcome, StorageBrokerError> {
        self.admit_apply_intent_inner(
            request_body,
            artifacts,
            catalog,
            protocol_version,
            peer,
            policy,
            current_clock,
            None,
        )
    }

    /// Verifies and durably records a workspace-creating Apply admission.
    ///
    /// The canonical assignment manifest and sandbox specification are checked
    /// against the admitted assignment. Only their exact assignment digest,
    /// root descriptor, and private-userns range are retained as an
    /// authenticated, operation-bound intent in the same initial transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] for every failure documented by
    /// [`Self::admit_apply_intent`], or when the portable publication inputs do
    /// not exactly match the admitted workspace creation or clone.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_workspace_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        identity_range_start: u32,
        manifest: &CanonicalAssignmentManifestV1,
        sandbox_spec: &SandboxSpec,
    ) -> Result<StorageAdmissionOutcome, StorageBrokerError> {
        self.admit_apply_intent_inner(
            request_body,
            artifacts,
            catalog,
            protocol_version,
            peer,
            policy,
            current_clock,
            Some((identity_range_start, manifest, sandbox_spec)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_apply_intent_inner(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        publication_inputs: Option<(u32, &CanonicalAssignmentManifestV1, &SandboxSpec)>,
    ) -> Result<StorageAdmissionOutcome, StorageBrokerError> {
        self.transactions.ensure_authority_readable()?;
        let semantics = decode_resolved(
            request_body,
            catalog,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageBrokerError::Request)?;
        let assignment =
            decode_assignment(request_body).map_err(|_| StorageBrokerError::Request)?;
        let sandbox_id = *assignment.sandbox().as_bytes();
        let request_id = *semantics.header().request_id();
        let operation_id = *semantics.operation_id();
        let sealed_preparation = self
            .transactions
            .catalog_preparation_record(&operation_id)?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let preparation =
            self.authenticate_catalog_preparation(operation_id, sealed_preparation)?;
        let existing = self.transactions.phase(operation_id)?.is_some();
        if preparation.record.catalog() != catalog
            || preparation.record.sandbox_id() != sandbox_id
            || preparation.preparation_fence.assignment() != assignment
        {
            return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
        }
        match (existing, preparation.record.consumption()) {
            (false, None) => {
                if preparation.record.host_boot_id() != current_clock.host_boot_id() {
                    return Err(StorageCatalogPreparationError::HostBootMismatch.into());
                }
                if current_clock.boottime_nanoseconds()
                    >= preparation.record.expires_boottime_nanoseconds()
                {
                    return Err(StorageCatalogPreparationError::Expired.into());
                }
                if self.transactions.catalog_head_binding()? != preparation.record.expected_head() {
                    return Err(StorageCatalogPreparationError::StaleCatalogHead.into());
                }
            }
            (true, Some(_)) => self.authenticate_consumed_preparation(&preparation)?,
            _ => return Err(crate::StorageStateError::AuthorityLinkMismatch.into()),
        }
        let prior_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .map(<[u8]>::to_vec);
        let prior_admission_intent = self
            .transactions
            .authority_record(RecordNamespace::Effect, &request_id)?
            .map(<[u8]>::to_vec);
        if !existing
            && (request_id == preparation.record.request_id() || prior_admission_intent.is_some())
        {
            return Err(crate::StorageStateError::Equivocation.into());
        }
        if existing && (prior_fence.is_none() || prior_admission_intent.is_none()) {
            return Err(StorageBrokerError::State(
                crate::StorageStateError::MissingAuthorityLink,
            ));
        }
        let admission = self
            .authority
            .admit(
                artifacts,
                &semantics,
                request_body,
                protocol_version,
                current_clock,
                prior_fence.as_deref(),
            )
            .map_err(|_| StorageBrokerError::Authority)?;
        let publication_intent = publication_inputs
            .map(|(identity_range_start, manifest, sandbox_spec)| {
                crate::workspace_catalog::StorageWorkspacePublicationIntentV1::from_portable(
                    *semantics.operation_id(),
                    catalog,
                    assignment,
                    admission.fence.node(),
                    manifest,
                    sandbox_spec,
                    identity_range_start,
                )
            })
            .transpose()?;
        if existing {
            let persisted_fence = self
                .authority
                .open_fence(
                    &sandbox_id,
                    prior_fence
                        .as_deref()
                        .ok_or(crate::StorageStateError::MissingAuthorityLink)?,
                )
                .map_err(|_| StorageBrokerError::Authority)?;
            let persisted_intent = self
                .authority
                .open_admission_intent(
                    &request_id,
                    prior_admission_intent
                        .as_deref()
                        .ok_or(crate::StorageStateError::MissingAuthorityLink)?,
                )
                .map_err(|_| StorageBrokerError::Authority)?;
            let transport_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
            if persisted_fence.assignment() != assignment
                || persisted_intent.transport_request_digest() != transport_digest
                || persisted_intent.request_digest() != semantics.argument_commitment().digest()
                || persisted_intent.verb() != semantics.broker_verb()
                || persisted_intent.target() != semantics.grant_target()
                || persisted_intent.plan_digest() != admission.effect.plan_digest()
                || persisted_intent.lease_digest() != admission.effect.lease_digest()
            {
                return Err(StorageBrokerError::State(
                    crate::StorageStateError::AuthorityLinkMismatch,
                ));
            }
        }
        let sealed = self
            .authority
            .seal(&sandbox_id, &request_id, &operation_id, &admission)
            .map_err(|_| StorageBrokerError::Authority)?;
        let request_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
        let outcome = if existing {
            let consumption = preparation
                .record
                .consumption()
                .ok_or(crate::StorageStateError::AuthorityLinkMismatch)?;
            if consumption.apply_request_id() != request_id
                || consumption.apply_transport_digest() != request_digest
                || consumption.apply_semantic_digest() != semantics.argument_commitment().digest()
                || consumption.apply_plan_digest() != admission.effect.plan_digest()
                || consumption.apply_lease_digest() != admission.effect.lease_digest()
            {
                return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
            }
            self.transactions.begin_authorized_with_publication(
                operation_id,
                request_digest,
                catalog,
                sandbox_id,
                request_id,
                sealed.current_fence,
                sealed.effect,
                sealed.operation_fence,
                publication_intent,
            )?
        } else {
            let consumed = preparation.record.consume(
                request_id,
                request_digest,
                semantics.argument_commitment().digest(),
                admission.effect.plan_digest(),
                admission.effect.lease_digest(),
            )?;
            let sealed_consumed = self
                .authority
                .seal_catalog_preparation_record(&operation_id, &consumed.encode_payload()?)
                .map_err(|_| StorageBrokerError::Authority)?;
            let transition = CatalogPreparationConsumption::new(
                preparation.record.expected_head(),
                preparation.sealed_record,
                sealed_consumed,
            )?;
            self.transactions
                .begin_authorized_with_consumed_preparation(
                    operation_id,
                    request_digest,
                    catalog,
                    sandbox_id,
                    request_id,
                    sealed.current_fence,
                    sealed.effect,
                    sealed.operation_fence,
                    publication_intent,
                    transition,
                )?
        };
        Ok(match outcome {
            BeginStorageTransaction::Prepared { mutation_digest } => {
                StorageAdmissionOutcome::Prepared { mutation_digest }
            }
            BeginStorageTransaction::ObserveOnly {
                phase,
                mutation_digest,
            } => StorageAdmissionOutcome::ObservationRequired {
                phase,
                mutation_digest,
            },
            BeginStorageTransaction::Replay(result) => StorageAdmissionOutcome::Replay(result),
        })
    }

    /// Revalidates current authority and synchronously consumes one mutation.
    ///
    /// The slow physical pre-observation has already completed. This method
    /// reopens the exact durable effect, operation fence, and current sandbox
    /// fence; rejects superseded authority; samples trusted time; and consumes
    /// the one-shot proof in the helper call made before returning.
    pub(crate) fn execute_preobserved<B, F>(
        &mut self,
        helper: &mut StorageMutationHelper<B>,
        prepared: PreobservedZfsMutation,
        trusted_clock: &mut F,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError>
    where
        B: ZfsProcessBackend,
        F: FnMut() -> Result<RawPairedClockSample, crate::StorageAdmissionError>,
    {
        let entry = prepared.entry();
        let current_entry = self
            .transactions
            .current_recovery_entry(entry.operation_id())?;
        if current_entry != entry || entry.phase() != DurableStoragePhase::Prepared {
            return Err(crate::StorageStateError::InvalidTransition.into());
        }
        let current_fence_bytes = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &entry.sandbox_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let current_fence = self
            .authority
            .open_fence(&entry.sandbox_id(), &current_fence_bytes)
            .map_err(|_| ZfsHelperError::Authority)?;
        let (operation_fence, effect) = self.persisted_effect_context(entry)?;
        if current_fence != operation_fence {
            return Err(ZfsHelperError::Authority);
        }
        self.authority
            .check_before_effect(&effect, trusted_clock)
            .map_err(|_| ZfsHelperError::Authority)?;

        let authority = FreshStorageEffectAuthority { entry };
        let protected_authority = &self.authority;
        helper.execute_preobserved(&mut self.transactions, prepared, authority, || {
            protected_authority
                .check_before_effect(&effect, trusted_clock)
                .map_err(|_| ZfsHelperError::Authority)
        })
    }

    pub(crate) fn authenticate_recovery_entry(
        &self,
        entry: crate::StorageRecoveryEntry,
    ) -> Result<(), ZfsHelperError> {
        self.persisted_effect_context(entry).map(|_| ())
    }

    fn authenticate_catalog_preparation(
        &self,
        operation_id: [u8; 16],
        sealed_record: Vec<u8>,
    ) -> Result<AuthenticatedCatalogPreparation, StorageBrokerError> {
        let payload = self
            .authority
            .open_catalog_preparation_record(&operation_id, &sealed_record)
            .map_err(|_| StorageBrokerError::Authority)?;
        let record = RetainedStorageCatalogPreparationV1::decode_payload(payload)?;
        if record.operation_id() != operation_id {
            return Err(StorageCatalogPreparationError::CorruptRecord.into());
        }

        let receipt_payload = self
            .authority
            .open_catalog_preparation_receipt(&operation_id, record.receipt())
            .map_err(|_| StorageBrokerError::Authority)?;
        if receipt_payload != record.expected_receipt_payload() {
            return Err(StorageCatalogPreparationError::CorruptRecord.into());
        }

        // These historical copies remain inside the preparation record after
        // Apply atomically replaces their journal locations with Apply links.
        let current_fence = self
            .authority
            .open_fence(&record.sandbox_id(), record.sealed_fence())
            .map_err(|_| StorageBrokerError::Authority)?;
        let operation_fence = self
            .authority
            .open_operation_fence(&operation_id, record.sealed_operation_fence())
            .map_err(|_| StorageBrokerError::Authority)?;
        let effect = self
            .authority
            .open_admission_intent(&record.request_id(), record.sealed_effect())
            .map_err(|_| StorageBrokerError::Authority)?;
        let live_fence_bytes = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &record.sandbox_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let live_fence = self
            .authority
            .open_fence(&record.sandbox_id(), live_fence_bytes)
            .map_err(|_| StorageBrokerError::Authority)?;
        let live_effect = self
            .transactions
            .authority_record(RecordNamespace::Effect, &record.request_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        self.authority
            .check_current_fence(&operation_fence)
            .map_err(|_| StorageBrokerError::Authority)?;
        self.authority
            .check_current_fence(&live_fence)
            .map_err(|_| StorageBrokerError::Authority)?;
        if current_fence != operation_fence
            || !fence_is_same_or_successor(&operation_fence, &live_fence)
            || live_effect != record.sealed_effect()
            || operation_fence.assignment().sandbox().as_bytes() != &record.sandbox_id()
            || operation_fence.assignment().digest() != record.assignment_digest()
            || operation_fence.plan_digest() != record.plan_digest()
            || operation_fence.local_lease_record().lease_digest() != record.lease_digest()
            || effect.status() != BrokerEffectStatusV2::Pending
            || effect.request_id() != &record.request_id()
            || effect.request_digest() != record.preparation_digest()
            || effect.verb() != BrokerVerb::StoragePrepareCatalog
            || effect.target() != BrokerGrantTarget::Assignment
            || effect.plan_digest() != record.plan_digest()
            || effect.lease_digest() != record.lease_digest()
            || effect.plan_expires_seconds() != operation_fence.plan_expires_seconds()
            || effect.local_lease_record() != operation_fence.local_lease_record()
            || effect.host_boot_id() != &record.host_boot_id()
            || record.expires_boottime_nanoseconds() > effect.effect_deadline_boottime_nanoseconds()
        {
            return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
        }
        if record.consumption().is_none() {
            let live_operation_fence = self
                .transactions
                .authority_record(RecordNamespace::AuthorityPublication, &operation_id)?
                .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
            if live_operation_fence != record.sealed_operation_fence() {
                return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
            }
        }

        Ok(AuthenticatedCatalogPreparation {
            record,
            preparation_fence: operation_fence,
            sealed_record,
        })
    }

    fn authenticate_consumed_preparation(
        &self,
        preparation: &AuthenticatedCatalogPreparation,
    ) -> Result<(), StorageBrokerError> {
        let consumption = preparation
            .record
            .consumption()
            .ok_or(crate::StorageStateError::AuthorityLinkMismatch)?;
        let entry = self
            .transactions
            .current_recovery_entry(preparation.record.operation_id())?;
        let catalog = self.transactions.recover_catalog(entry)?;
        let (apply_fence, effect) = self
            .persisted_effect_context(entry)
            .map_err(|_| StorageBrokerError::Authority)?;
        if entry.sandbox_id() != preparation.record.sandbox_id()
            || entry.request_id() != consumption.apply_request_id()
            || entry.request_digest() != consumption.apply_transport_digest()
            || catalog != *preparation.record.catalog()
            || apply_fence.assignment() != preparation.preparation_fence.assignment()
            || effect.request_digest() != consumption.apply_semantic_digest()
            || effect.plan_digest() != consumption.apply_plan_digest()
            || effect.lease_digest() != consumption.apply_lease_digest()
        {
            return Err(crate::StorageStateError::AuthorityLinkMismatch.into());
        }
        Ok(())
    }

    fn persisted_effect_context(
        &self,
        entry: crate::StorageRecoveryEntry,
    ) -> Result<(BrokerAuthorizationFenceV1, BrokerEffectIntentV2), ZfsHelperError> {
        if self
            .transactions
            .current_recovery_entry(entry.operation_id())?
            != entry
        {
            return Err(crate::StorageStateError::InvalidTransition.into());
        }
        let catalog = self.transactions.recover_catalog(entry)?;
        let operation = catalog.plan().operation();
        let operation_fence_bytes = self
            .transactions
            .authority_record(RecordNamespace::AuthorityPublication, &entry.operation_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let effect_bytes = self
            .transactions
            .authority_record(RecordNamespace::Effect, &entry.request_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let operation_fence = self
            .authority
            .open_operation_fence(&entry.operation_id(), &operation_fence_bytes)
            .map_err(|_| ZfsHelperError::Authority)?;
        self.authority
            .check_current_fence(&operation_fence)
            .map_err(|_| ZfsHelperError::Authority)?;
        let effect = self
            .authority
            .open_admission_intent(&entry.request_id(), &effect_bytes)
            .map_err(|_| ZfsHelperError::Authority)?;
        let semantic_commitment = operation
            .persisted_argument_commitment(
                operation_fence.assignment(),
                entry.operation_id(),
                catalog.binding(),
            )
            .map_err(|_| ZfsHelperError::Authority)?;
        let grant_target = operation
            .grant_target()
            .map_err(|_| ZfsHelperError::Authority)?;
        if operation_fence.assignment().sandbox().as_bytes() != &entry.sandbox_id()
            || effect.status() != aos_sandbox_broker::BrokerEffectStatusV2::Pending
            || effect.request_id() != &entry.request_id()
            || effect.transport_request_digest() != entry.request_digest()
            || effect.request_digest() != semantic_commitment.digest()
            || effect.verb() != operation.broker_verb()
            || effect.target() != grant_target
            || effect.plan_digest() != operation_fence.plan_digest()
            || effect.plan_expires_seconds() != operation_fence.plan_expires_seconds()
            || effect.local_lease_record() != operation_fence.local_lease_record()
            || effect.lease_digest() != operation_fence.local_lease_record().lease_digest()
        {
            return Err(ZfsHelperError::Authority);
        }
        Ok((operation_fence, effect))
    }

    fn pin_worker_authority(
        &self,
        entry: crate::StorageRecoveryEntry,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<WorkspacePinWorkerAuthorityV1, ZfsHelperError> {
        let attempt_record = self.transactions.workspace_pin_attempt_record(attempt)?;
        let current_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &entry.sandbox_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let effect = self
            .transactions
            .authority_record(RecordNamespace::Effect, &entry.request_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        let operation_fence = self
            .transactions
            .authority_record(RecordNamespace::AuthorityPublication, &entry.operation_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?
            .to_vec();
        WorkspacePinWorkerAuthorityV1::new(
            entry.request_id(),
            attempt_record,
            current_fence,
            effect,
            operation_fence,
        )
        .map_err(ZfsHelperError::Backend)
    }

    /// Reconstructs one launchable workspace publication from committed state.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] when the result is not the exact current
    /// committed record, its catalog cannot be recovered, its authority fence
    /// is missing or invalid, or its authenticated publication intent does not
    /// match that fence. The latest durable pin attempt for the workspace must
    /// be a satisfied Ensure attempt for this creation.
    pub fn workspace_publication(
        &self,
        result: CommittedStorageResultV1,
    ) -> Result<StorageWorkspacePublicationV1, StorageBrokerError> {
        let workspace_handle = result
            .storage_handle()
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let pin_proof = self
            .transactions
            .require_satisfied_workspace_ensure_pin_effect(
                result.operation_id(),
                workspace_handle,
            )?;
        self.workspace_publication_from_committed(result, pin_proof)
    }

    fn workspace_publication_from_committed(
        &self,
        result: CommittedStorageResultV1,
        pin_proof: WorkspaceRootPinProofV1,
    ) -> Result<StorageWorkspacePublicationV1, StorageBrokerError> {
        let (catalog, assignment, _) = self.committed_context(result)?;
        let intent = self
            .transactions
            .workspace_publication_intent(result.operation_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        StorageWorkspacePublicationV1::from_intent(result, &catalog, assignment, intent, pin_proof)
            .map_err(Into::into)
    }

    /// Reconstructs one workspace retirement from an exact committed destroy.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] when the result is not the exact current
    /// committed record, its catalog cannot be recovered, its operation-scoped
    /// authority fence is missing or invalid, or the operation is not a dataset
    /// destruction. The latest durable pin attempt for the workspace must be a
    /// satisfied RemoveAndDestroy attempt for this destruction.
    pub fn workspace_retirement(
        &self,
        result: CommittedStorageResultV1,
    ) -> Result<StorageWorkspaceRetirementV1, StorageBrokerError> {
        let workspace_handle = result
            .storage_handle()
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        self.transactions.require_satisfied_workspace_pin_effect(
            result.operation_id(),
            workspace_handle,
            WorkspacePinActionV1::RemoveAndDestroy,
        )?;
        let (catalog, _, _) = self.committed_context(result)?;
        StorageWorkspaceRetirementV1::from_committed(result, &catalog).map_err(Into::into)
    }

    pub(crate) fn workspace_projection(
        &self,
    ) -> Result<Vec<StorageWorkspaceCatalogActionV1>, StorageBrokerError> {
        self.transactions
            .workspace_projection()?
            .into_iter()
            .map(|projection| match projection {
                StorageWorkspaceProjection::Active(result) => self
                    .workspace_publication(result)
                    .map(StorageWorkspaceCatalogActionV1::Publish),
                StorageWorkspaceProjection::Retired {
                    creation,
                    retirement,
                } => Ok(StorageWorkspaceCatalogActionV1::Retire {
                    // State projection admits retirement only after the latest
                    // pin attempt is a satisfied RemoveAndDestroy. Reconstruct
                    // historical creation identity without demanding that the
                    // now-retired workspace still have a launchable Ensure.
                    creation: self.workspace_publication_from_committed(
                        creation,
                        self.transactions.satisfied_workspace_pin_proof_for_effect(
                            creation.operation_id(),
                            creation
                                .storage_handle()
                                .ok_or(crate::StorageStateError::MissingAuthorityLink)?,
                            WorkspacePinActionV1::Ensure,
                        )?,
                    )?,
                    retirement: self.workspace_retirement(retirement)?,
                }),
            })
            .collect()
    }

    pub(crate) fn workspace_identity_ranges(&self) -> Result<Vec<(u32, u32)>, StorageBrokerError> {
        self.transactions
            .workspace_identity_ranges()
            .map_err(Into::into)
    }

    pub(crate) fn workspace_identity_range(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<(u32, u32)>, StorageBrokerError> {
        self.transactions
            .workspace_identity_range(operation_id)
            .map_err(Into::into)
    }

    fn committed_context(
        &self,
        result: CommittedStorageResultV1,
    ) -> Result<(ResolvedCatalogCommitmentV1, BrokerAssignment, NodeId), StorageBrokerError> {
        let entry = self.transactions.committed_recovery_entry(result)?;
        let catalog = self.transactions.recover_catalog(entry)?;
        let sandbox_id = entry.sandbox_id();
        let sealed_fence = self
            .transactions
            .authority_record(RecordNamespace::AuthorityPublication, &entry.operation_id())?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let fence = self
            .authority
            .open_operation_fence(&entry.operation_id(), sealed_fence)
            .map_err(|_| StorageBrokerError::Authority)?;
        let assignment = fence.assignment();
        if assignment.sandbox().as_bytes() != &sandbox_id {
            return Err(StorageBrokerError::Authority);
        }
        Ok((catalog, assignment, fence.node()))
    }
}

fn fence_is_same_or_successor(
    historical: &BrokerAuthorizationFenceV1,
    current: &BrokerAuthorizationFenceV1,
) -> bool {
    let historical_assignment = historical.assignment();
    let current_assignment = current.assignment();
    if historical.node() != current.node()
        || current_assignment.epoch() < historical_assignment.epoch()
    {
        return false;
    }
    if current_assignment.epoch() > historical_assignment.epoch() {
        return true;
    }
    if current.ownership_authority() != historical.ownership_authority()
        || current_assignment.incarnation() != historical_assignment.incarnation()
        || current_assignment.desired_generation() < historical_assignment.desired_generation()
    {
        return false;
    }
    current_assignment.desired_generation() > historical_assignment.desired_generation()
        || (current_assignment.digest() == historical_assignment.digest()
            && current.plan_digest() == historical.plan_digest())
}

/// Returns the closed method set safe for the incomplete storage service.
///
/// Apply is intentionally absent until catalog publication, key provisioning,
/// privileged observation, and helper readiness form one complete startup
/// proof. Inventory is included only when a caller has a complete bounded
/// catalog inventory implementation.
#[must_use]
pub fn advertised_storage_methods(inventory_ready: bool) -> Vec<BrokerMethod> {
    if inventory_ready {
        vec![BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::fs;
    use std::num::NonZeroU32;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use aos_proto::aos::sandbox::local::v1::{
        ApplyStorageRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerRequestEnvelope,
        PrepareStorageCatalogRequest, RepairStorageWorkspacePinRequest, StorageAction,
    };
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        AssignmentManifestV1, IdentityProfile, KeyReference, KeyUsage, NetworkKind, NetworkProfile,
        ResourceProfile, SandboxAncestry, SignaturePurpose, SignatureStatement, StableKeyId,
        TrustPolicy, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget,
        BrokerVerb, CanonicalAssignmentManifestV1, DecodeLimits, DesiredGeneration, FeatureRef,
        IncarnationId, LeaseAssignment, MediaType, NamespaceGeneration, NodeId, ObjectDescriptor,
        OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, ProjectId, ProtocolId,
        RawClockProvenance, ResourceVector, RevocationScopeId, SandboxId, TrustScopeId,
        descriptor_for_bytes, encode_sandbox_spec, sign_statement,
    };
    use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
    use aos_sandbox_protocol::{
        MINIMUM_HOST_IDENTITY_RANGE, decode_request_envelope,
        decode_storage_resource_inventory_response,
    };
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;
    use crate::helper::{
        SealedZfsProgram, SystemdZfsProcessBackend, ZfsHelperError, ZfsPostconditionObservation,
        ZfsProcessOutput,
    };
    use crate::workspace_pin::derive_attempt_id;
    use crate::workspace_repair::StorageWorkspacePinRepairIntentV1;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageAdmissionError, StorageDomainsV1,
        StorageStateKey, WorkspaceSpacePolicyV1, ZfsHelperContract,
    };

    fn private_tempdir_in(parent: &Path) -> std::io::Result<TempDir> {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
    }

    const NODE: NodeId = NodeId::from_bytes([31; 16]);

    struct Fixture {
        plan_key: SigningKey,
        lease_key: SigningKey,
        plan_signer: KeyReference,
        lease_signer: KeyReference,
        plan_policy: Vec<u8>,
        plan_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_policy: Vec<u8>,
        lease_descriptor: aos_sandbox_core::ObjectDescriptor,
        plan_scope: TrustScopeId,
        lease_scope: TrustScopeId,
        revocation: RevocationScopeId,
    }

    impl Fixture {
        fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let plan_signer = key_ref("storage-plan", 3, KeyUsage::BrokerAuthorization, &plan_key);
            let lease_signer = key_ref("storage-lease", 7, KeyUsage::OwnershipLease, &lease_key);
            let plan_scope = TrustScopeId::from_bytes([43; 16]);
            let lease_scope = TrustScopeId::from_bytes([44; 16]);
            let (plan_policy, plan_descriptor) = policy(
                plan_scope,
                SignaturePurpose::BrokerAuthorization,
                plan_signer.clone(),
            );
            let (lease_policy, lease_descriptor) = policy(
                lease_scope,
                SignaturePurpose::OwnershipLease,
                lease_signer.clone(),
            );
            Self {
                plan_key,
                lease_key,
                plan_signer,
                lease_signer,
                plan_policy,
                plan_descriptor,
                lease_policy,
                lease_descriptor,
                plan_scope,
                lease_scope,
                revocation: RevocationScopeId::from_bytes([45; 16]),
            }
        }

        fn authority(&self) -> StorageAuthorityV1 {
            let plan = aos_sandbox_core::BrokerPlanTrustAnchor::from_trusted_configuration(
                self.plan_policy.clone(),
                self.plan_descriptor.clone(),
                self.plan_scope,
                self.plan_signer.clone(),
                self.plan_key.verifying_key().to_bytes(),
                self.revocation,
                DecodeLimits::default(),
            )
            .unwrap();
            let lease = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                self.lease_policy.clone(),
                self.lease_descriptor.clone(),
                self.lease_scope,
                self.lease_signer.clone(),
                self.lease_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            StorageAuthorityV1::new(plan, lease, NODE, [51; 16], [52; 32]).unwrap()
        }

        fn protected_authority_binding(&self) -> ObjectDigest {
            let mut hash = Sha256::new();
            hash.update(b"aos.sandbox.broker.protected-configuration.v1\0");
            hash.update([3]);
            hash.update((self.plan_policy.len() as u64).to_be_bytes());
            hash.update(&self.plan_policy);
            hash.update(self.plan_key.verifying_key().as_bytes());
            hash.update(self.revocation.as_bytes());
            hash.update((self.lease_policy.len() as u64).to_be_bytes());
            hash.update(&self.lease_policy);
            hash.update(self.lease_key.verifying_key().as_bytes());
            hash.update(NODE.as_bytes());
            hash.update([51; 16]);
            ObjectDigest::from_bytes(hash.finalize().into())
        }

        fn provision_protected(&self, directory: &Path) {
            fs::create_dir_all(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();

            self.write_protected(directory, "broker-plan-policy.cbor", &self.plan_policy);
            self.write_protected(
                directory,
                "broker-plan-public-key",
                &self.plan_key.verifying_key().to_bytes(),
            );
            self.write_protected(
                directory,
                "broker-revocation-scope",
                self.revocation.as_bytes(),
            );
            self.write_protected(directory, "ownership-lease-policy.cbor", &self.lease_policy);
            self.write_protected(
                directory,
                "ownership-lease-public-key",
                &self.lease_key.verifying_key().to_bytes(),
            );
            self.write_protected(directory, "node-id", NODE.as_bytes());

            let mut journal_key = Vec::with_capacity(48);
            journal_key.extend_from_slice(&[51; 16]);
            journal_key.extend_from_slice(&[52; 32]);
            self.write_protected(directory, "journal-mac-key", &journal_key);
        }

        fn write_protected(&self, directory: &Path, name: &str, bytes: &[u8]) {
            let path = directory.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn artifacts(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing(request, catalog, &[request], expires, audience, protocol)
        }

        fn artifacts_at_head(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            expected_head: crate::CatalogBindingV1,
            expires: i64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_between_at_head(
                request,
                catalog,
                &[request],
                Some(expected_head),
                true,
                true,
                100,
                expires,
                300,
                BrokerAudience::Storage,
                ProtocolId::StorageBroker,
            )
        }

        fn artifacts_authorizing(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            authorized: &[&[u8]],
            expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_between(
                request, catalog, authorized, 100, expires, 300, audience, protocol,
            )
        }

        fn artifacts_for_kernel_clock(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            current_wall_seconds: i64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            // Whole-second wall expiry must comfortably cover the request's
            // nanosecond-precision boottime deadline after clock conversion.
            self.artifacts_authorizing_between(
                request,
                catalog,
                &[request],
                current_wall_seconds - 30,
                current_wall_seconds + 300,
                current_wall_seconds + 300,
                BrokerAudience::Storage,
                ProtocolId::StorageBroker,
            )
        }

        fn artifacts_for_kernel_clock_at_head(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            expected_head: crate::CatalogBindingV1,
            current_wall_seconds: i64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            // Later operations must authorize the exact preparation bytes,
            // including the catalog head advanced by earlier operations.
            self.artifacts_authorizing_between_at_head(
                request,
                catalog,
                &[request],
                Some(expected_head),
                true,
                true,
                current_wall_seconds - 30,
                current_wall_seconds + 300,
                current_wall_seconds + 300,
                BrokerAudience::Storage,
                ProtocolId::StorageBroker,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn artifacts_authorizing_between(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            authorized: &[&[u8]],
            valid_after: i64,
            expires: i64,
            lease_expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_between_at_head(
                request,
                catalog,
                authorized,
                None,
                true,
                true,
                valid_after,
                expires,
                lease_expires,
                audience,
                protocol,
            )
        }

        fn artifacts_with_grants(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            include_apply: bool,
            include_prepare: bool,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_between_at_head(
                request,
                catalog,
                &[request],
                None,
                include_apply,
                include_prepare,
                100,
                300,
                300,
                BrokerAudience::Storage,
                ProtocolId::StorageBroker,
            )
        }

        fn repair_artifacts(&self, request: &[u8]) -> ValidatedUntrustedAuthorizationArtifacts {
            let semantics = CanonicalStorageRepairSemanticsV1::decode(
                request,
                peer(),
                peer_policy(),
                clock().boottime_nanoseconds(),
            )
            .unwrap();
            let fence = semantics.fence();
            let assignment = BrokerAssignment::new(
                SandboxId::from_bytes(*fence.sandbox_id()),
                IncarnationId::from_bytes(*fence.incarnation_id()),
                AssignmentEpoch::new(fence.assignment_epoch()),
                DesiredGeneration::new(fence.desired_generation()),
                ObjectDigest::from_bytes(*fence.assignment_digest()),
            )
            .unwrap();
            let grant = BrokerGrant::new(
                semantics.broker_verb(),
                semantics.grant_target(),
                semantics.argument_commitment(),
                request.len() as u32,
                0,
            )
            .unwrap();
            self.signed_artifacts(
                assignment,
                vec![grant],
                100,
                300,
                300,
                BrokerAudience::Storage,
                ProtocolId::StorageBroker,
                ProtocolVersion::new(1, 4),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn artifacts_authorizing_between_at_head(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            authorized: &[&[u8]],
            expected_head: Option<crate::CatalogBindingV1>,
            include_apply: bool,
            include_prepare: bool,
            valid_after: i64,
            expires: i64,
            lease_expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let semantics = decode_resolved(request, catalog, peer(), peer_policy(), 100).unwrap();
            let assignment = decode_assignment(request).unwrap();
            let mut grants = if audience == BrokerAudience::Storage {
                authorized
                    .iter()
                    .flat_map(|bytes| {
                        let candidate =
                            decode_resolved(bytes, catalog, peer(), peer_policy(), 100).unwrap();
                        let (preparation_bytes, _, _) = match expected_head {
                            Some(head) => preparation_request_at_head(bytes, catalog, head),
                            None => preparation_request(bytes, catalog),
                        };
                        let preparation = CanonicalStoragePreparationSemanticsV1::decode(
                            &preparation_bytes,
                            peer(),
                            peer_policy(),
                            100,
                        )
                        .unwrap();
                        let mut grants = Vec::with_capacity(2);
                        if include_apply {
                            grants.push(
                                BrokerGrant::new(
                                    candidate.broker_verb(),
                                    candidate.grant_target(),
                                    candidate.argument_commitment(),
                                    bytes.len() as u32,
                                    0,
                                )
                                .unwrap(),
                            );
                        }
                        if include_prepare {
                            grants.push(
                                BrokerGrant::new(
                                    preparation.broker_verb(),
                                    preparation.grant_target(),
                                    preparation.argument_commitment(),
                                    preparation_bytes.len() as u32,
                                    0,
                                )
                                .unwrap(),
                            );
                        }
                        grants
                    })
                    .collect()
            } else {
                vec![
                    BrokerGrant::new(
                        BrokerVerb::MountInventorySummary,
                        BrokerGrantTarget::Assignment,
                        semantics.argument_commitment(),
                        request.len() as u32,
                        0,
                    )
                    .unwrap(),
                ]
            };
            grants.sort_by_key(|grant| (grant.verb(), grant.target(), grant.argument_commitment()));
            grants.dedup();
            self.signed_artifacts(
                assignment,
                grants,
                valid_after,
                expires,
                lease_expires,
                audience,
                protocol,
                ProtocolVersion::new(1, 3),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn signed_artifacts(
            &self,
            assignment: BrokerAssignment,
            grants: Vec<BrokerGrant>,
            valid_after: i64,
            expires: i64,
            lease_expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
            protocol_version: ProtocolVersion,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let plan = BrokerAuthorizationPlan::new(
                audience,
                protocol,
                protocol_version,
                assignment,
                NODE,
                self.lease_signer.clone(),
                grants,
                ObjectDigest::from_bytes([48; 32]),
                self.revocation,
                valid_after,
                expires,
                Vec::new(),
            )
            .unwrap();
            let plan_bytes = encode_broker_authorization_plan(&plan);
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                NODE,
                1,
                valid_after,
                lease_expires,
                10,
                [49; 16],
            )
            .unwrap();
            let lease_bytes = encode_ownership_lease(&lease);
            validated(
                BrokerAuthorizationArtifactsV1 {
                    broker_plan_signature: signed(
                        &plan_bytes,
                        PortableMediaType::BrokerAuthorizationPlan,
                        self.plan_scope,
                        self.plan_signer.clone(),
                        SignaturePurpose::BrokerAuthorization,
                        valid_after,
                        expires,
                        &self.plan_descriptor,
                        &self.plan_key,
                    ),
                    broker_plan: plan_bytes,
                    ownership_lease_signature: signed(
                        &lease_bytes,
                        PortableMediaType::OwnershipLease,
                        self.lease_scope,
                        self.lease_signer.clone(),
                        SignaturePurpose::OwnershipLease,
                        valid_after,
                        lease_expires,
                        &self.lease_descriptor,
                        &self.lease_key,
                    ),
                    ownership_lease: lease_bytes,
                    ..Default::default()
                },
                protocol,
            )
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }
    fn peer_policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }
    fn clock() -> RawPairedClockSample {
        clock_at([50; 16], 150, 100)
    }

    fn clock_at(
        host_boot_id: [u8; 16],
        wall_seconds: i64,
        boottime_nanoseconds: u64,
    ) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            host_boot_id,
            wall_seconds,
            boottime_nanoseconds,
        )
        .unwrap()
    }

    fn workspace_pin_proof(
        workspace_handle: [u8; 32],
        dataset_name: &str,
        dataset_guid: u64,
    ) -> WorkspaceRootPinProofV1 {
        use std::fmt::Write as _;

        let mut mount_point = "/run/aos/sandbox-pins/workspaces/".to_owned();
        for byte in workspace_handle {
            write!(mount_point, "{byte:02x}").unwrap();
        }

        WorkspaceRootPinProofV1::new(
            [50; 16],
            51,
            52,
            53,
            "/".to_owned(),
            mount_point,
            "zfs".to_owned(),
            dataset_name.to_owned(),
            dataset_guid,
            54,
            55,
        )
        .unwrap()
    }

    fn request(operation: u8, handle: u8) -> Vec<u8> {
        request_with_generation(operation, handle, 5)
    }

    fn with_request_id(request: &[u8], request_id: [u8; 16]) -> Vec<u8> {
        let mut decoded = ApplyStorageRequest::decode_from_slice(request).unwrap();
        decoded.header.get_or_insert_default().request_id = request_id.to_vec();
        decoded.encode_to_vec()
    }

    fn with_deadline(request: &[u8], deadline_boottime_nanoseconds: u64) -> Vec<u8> {
        let mut decoded = ApplyStorageRequest::decode_from_slice(request).unwrap();
        decoded
            .header
            .get_or_insert_default()
            .deadline_boottime_nanoseconds = deadline_boottime_nanoseconds;
        decoded.encode_to_vec()
    }

    fn preparation_request(
        apply_bytes: &[u8],
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> (Vec<u8>, crate::CatalogBindingV1, crate::CatalogBindingV1) {
        let expected_head =
            crate::catalog_transition::StorageCatalogTransitionProvider::bootstrap_binding(
                catalog.generation() - 1,
                std::slice::from_ref(catalog),
            )
            .unwrap();
        preparation_request_at_head(apply_bytes, catalog, expected_head)
    }

    fn preparation_request_at_head(
        apply_bytes: &[u8],
        catalog: &ResolvedCatalogCommitmentV1,
        expected_head: crate::CatalogBindingV1,
    ) -> (Vec<u8>, crate::CatalogBindingV1, crate::CatalogBindingV1) {
        let apply = ApplyStorageRequest::decode_from_slice(apply_bytes).unwrap();
        let inventory = catalog.binding();
        let mut request = PrepareStorageCatalogRequest {
            header: apply.header.clone(),
            ..Default::default()
        };
        let header = request.header.get_or_insert_default();
        header.protocol_minor = 3;
        let operation_marker = apply.operation_id.first().copied().unwrap();
        header.request_id = vec![operation_marker.wrapping_add(128); 16];
        request.fence = apply.fence.clone();
        request.action = apply.action;
        request.operation_id = apply.operation_id;
        request.storage_handle = apply.storage_handle;
        request.source_version_handle = apply.source_version_handle;
        request.requested_quota_bytes = apply.quota_bytes;
        request.requested_reservation_bytes = match catalog.plan() {
            CatalogPlanV1::CreateWorkspace { space, .. }
            | CatalogPlanV1::Clone { space, .. }
            | CatalogPlanV1::SetQuota { space, .. } => match space.reservation() {
                ReservationPolicy::None => 0,
                ReservationPolicy::Exact(bytes) => bytes,
            },
            _ => 0,
        };
        request.requested_hold_id = match catalog.plan() {
            CatalogPlanV1::HoldSnapshot { hold_id, .. }
            | CatalogPlanV1::ReleaseHold { hold_id, .. } => hold_id.as_bytes().to_vec(),
            CatalogPlanV1::Clone { origin_hold, .. } => origin_hold.hold_id().as_bytes().to_vec(),
            _ => Vec::new(),
        };
        request.inventory_generation = inventory.generation();
        request.inventory_digest = inventory.digest().as_bytes().to_vec();
        request.expected_catalog_generation = expected_head.generation();
        request.expected_catalog_digest = expected_head.digest().as_bytes().to_vec();
        request.preparation_expires_boottime_nanoseconds =
            header.deadline_boottime_nanoseconds.checked_sub(1).unwrap();
        (request.encode_to_vec(), inventory, expected_head)
    }

    struct StaticCatalogResolver<'a> {
        catalog: &'a ResolvedCatalogCommitmentV1,
    }

    impl ProtectedStorageCatalogResolverV1 for StaticCatalogResolver<'_> {
        fn resolve(
            &self,
            _semantics: &CanonicalStoragePreparationSemanticsV1,
            _current_head: crate::CatalogBindingV1,
        ) -> Result<ResolvedCatalogCommitmentV1, StorageCatalogPreparationError> {
            Ok(self.catalog.clone())
        }
    }

    fn prepare_for_apply(
        coordinator: &mut StorageAdmissionCoordinator,
        request: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        current_clock: &RawPairedClockSample,
    ) -> StorageCatalogPreparationOutcomeV1 {
        let expected_head = coordinator.transactions.catalog_head_binding().unwrap();
        let (preparation, inventory, _) =
            preparation_request_at_head(request, catalog, expected_head);
        coordinator
            .prepare_catalog(
                &preparation,
                artifacts,
                inventory,
                &StaticCatalogResolver { catalog },
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                current_clock,
            )
            .unwrap()
    }

    fn request_with_generation(operation: u8, handle: u8, desired_generation: u64) -> Vec<u8> {
        let mut value = ApplyStorageRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 3;
        header.request_id = vec![operation; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = desired_generation;
        fence.assignment_digest = vec![6; 32];
        value.action = StorageAction::STORAGE_ACTION_SET_QUOTA.into();
        value.operation_id = vec![operation; 16];
        value.storage_handle = vec![handle; 32];
        value.quota_bytes = 4096;
        value.encode_to_vec()
    }

    fn repair_request(
        request_id: u8,
        operation_id: u8,
        workspace_handle: [u8; 32],
        desired_generation: u64,
        assignment_digest: ObjectDigest,
    ) -> Vec<u8> {
        let mut value = RepairStorageWorkspacePinRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 4;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = desired_generation;
        fence.assignment_digest = assignment_digest.as_bytes().to_vec();
        value.operation_id = vec![operation_id; 16];
        value.storage_handle = workspace_handle.to_vec();
        value.encode_to_vec()
    }

    fn reverse_length_delimited_fields(bytes: &[u8]) -> Vec<u8> {
        let mut fields = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let start = offset;
            let tag = bytes[offset];
            assert_eq!(tag & 0x07, 2);
            offset += 1;

            let mut length = 0_usize;
            let mut shift = 0_u32;
            loop {
                let byte = bytes[offset];
                offset += 1;
                length |= usize::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            offset += length;
            fields.push(bytes[start..offset].to_vec());
        }
        fields.reverse();
        fields.concat()
    }

    fn destroy_request(
        operation: u8,
        workspace_handle: [u8; 32],
        assignment_digest: ObjectDigest,
    ) -> Vec<u8> {
        let mut value = ApplyStorageRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 3;
        header.request_id = vec![operation; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 6;
        fence.assignment_digest = assignment_digest.as_bytes().to_vec();
        value.action = StorageAction::STORAGE_ACTION_DESTROY.into();
        value.operation_id = vec![operation; 16];
        value.storage_handle = workspace_handle.to_vec();
        value.encode_to_vec()
    }

    fn create_request(operation: u8, assignment_digest: ObjectDigest) -> Vec<u8> {
        let mut value = ApplyStorageRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 3;
        header.request_id = vec![operation; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = assignment_digest.as_bytes().to_vec();
        value.action = StorageAction::STORAGE_ACTION_CREATE_WORKSPACE.into();
        value.operation_id = vec![operation; 16];
        value.quota_bytes = 4096;
        value.encode_to_vec()
    }

    fn catalog(handle: u8, generation: u64) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [9; 32], domains)
                .unwrap();
        let dataset =
            ResolvedDataset::from_catalog(root, "tank/aos/project/work", 11, [handle; 32], domains)
                .unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains,
            CatalogPlanV1::SetQuota {
                dataset,
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor, 65_536, 8, 16).unwrap(),
            },
        )
        .unwrap()
    }

    fn destroy_catalog(workspace_handle: [u8; 32], generation: u64) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let dataset = ResolvedDataset::from_catalog(
            ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap(),
            "tank/aos/project/work",
            11,
            workspace_handle,
            domains,
        )
        .unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains,
            CatalogPlanV1::DestroyDataset { dataset },
        )
        .unwrap()
    }

    fn create_catalog(generation: u64) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [9; 32], domains)
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

    fn vm_clock() -> RawPairedClockSample {
        let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            aos_sandbox_linux::boot::KernelBootId::current()
                .unwrap()
                .into_bytes(),
            realtime.tv_sec,
            crate::pin_worker::boottime_now_nanoseconds().unwrap(),
        )
        .unwrap()
    }

    fn vm_create_request(
        assignment_digest: ObjectDigest,
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Vec<u8> {
        let mut value = ApplyStorageRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 3;
        header.request_id = vec![7; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = effect_deadline_boottime_nanoseconds;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = assignment_digest.as_bytes().to_vec();
        value.action = StorageAction::STORAGE_ACTION_CREATE_WORKSPACE.into();
        value.operation_id = vec![7; 16];
        value.quota_bytes = 67_108_864;
        value.encode_to_vec()
    }

    fn vm_destroy_request(
        workspace_handle: [u8; 32],
        assignment_digest: ObjectDigest,
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Vec<u8> {
        let mut value = ApplyStorageRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 3;
        header.request_id = vec![8; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = effect_deadline_boottime_nanoseconds;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 6;
        fence.assignment_digest = assignment_digest.as_bytes().to_vec();
        value.action = StorageAction::STORAGE_ACTION_DESTROY.into();
        value.operation_id = vec![8; 16];
        value.storage_handle = workspace_handle.to_vec();
        value.encode_to_vec()
    }

    fn vm_create_catalog(
        root_guid: u64,
        ancestor_guid: u64,
        dataset_name: &str,
    ) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("aosproof", "aosproof/aos", root_guid).unwrap();
        let ancestor = ResolvedDataset::from_catalog(
            root.clone(),
            "aosproof/aos/project",
            ancestor_guid,
            [9; 32],
            domains,
        )
        .unwrap();
        let destination = PlannedDataset::from_catalog(root, dataset_name, domains).unwrap();

        ResolvedCatalogCommitmentV1::new(
            9,
            domains,
            CatalogPlanV1::CreateWorkspace {
                destination,
                space: WorkspaceSpacePolicyV1::new(67_108_864, ReservationPolicy::Exact(1_048_576))
                    .unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor, 268_435_456, 8, 16).unwrap(),
            },
        )
        .unwrap()
    }

    fn vm_destroy_catalog(
        root_guid: u64,
        dataset_guid: u64,
        workspace_handle: [u8; 32],
        dataset_name: &str,
    ) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("aosproof", "aosproof/aos", root_guid).unwrap();
        let dataset = ResolvedDataset::from_catalog(
            root,
            dataset_name,
            dataset_guid,
            workspace_handle,
            domains,
        )
        .unwrap();

        ResolvedCatalogCommitmentV1::new(11, domains, CatalogPlanV1::DestroyDataset { dataset })
            .unwrap()
    }

    fn object_descriptor(kind: PortableMediaType, marker: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([marker; 32]),
            1,
        )
    }

    fn sandbox_spec(root_marker: u8) -> SandboxSpec {
        SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(Vec::new()).unwrap(),
            object_descriptor(PortableMediaType::Environment, 71),
            object_descriptor(PortableMediaType::View, root_marker),
            Vec::new(),
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    fn assignment_manifest(spec: &SandboxSpec) -> CanonicalAssignmentManifestV1 {
        assignment_manifest_at(spec, 5)
    }

    fn assignment_manifest_at(
        spec: &SandboxSpec,
        desired_generation: u64,
    ) -> CanonicalAssignmentManifestV1 {
        let spec_bytes = encode_sandbox_spec(spec);
        let spec_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &spec_bytes,
        );
        let manifest = AssignmentManifestV1::new(
            SandboxId::from_bytes([2; 16]),
            ProjectId::from_bytes([4; 16]),
            SandboxAncestry::new(SandboxId::from_bytes([2; 16]), Vec::new()).unwrap(),
            IncarnationId::from_bytes([3; 16]),
            NODE,
            AssignmentEpoch::new(4),
            DesiredGeneration::new(desired_generation),
            NamespaceGeneration::new(6),
            spec_descriptor,
            object_descriptor(PortableMediaType::Policy, 70),
            spec.environment().clone(),
            spec.root_view().clone(),
            Vec::new(),
            ObjectDigest::from_bytes([73; 32]),
            ResourceVector::ZERO,
            Vec::new(),
        )
        .unwrap();
        CanonicalAssignmentManifestV1::new(manifest)
    }
    fn key_ref(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }
    fn policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        signer: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        let bytes = encode_trust_policy(
            &TrustPolicy::new(scope, purpose, vec![signer], Vec::new()).unwrap(),
        );
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }
    #[allow(clippy::too_many_arguments)]
    fn signed(
        bytes: &[u8],
        media: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        issued_seconds: i64,
        expires_seconds: i64,
        policy: &aos_sandbox_core::ObjectDescriptor,
        key: &SigningKey,
    ) -> Vec<u8> {
        let subject =
            descriptor_for_bytes(MediaType::new(media.as_str().to_owned()).unwrap(), bytes);
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            issued_seconds,
            Some(expires_seconds),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }
    fn validated(
        artifacts: BrokerAuthorizationArtifactsV1,
        protocol: ProtocolId,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: if protocol == ProtocolId::StorageBroker {
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY.into()
            } else {
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into()
            },
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), protocol, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }
    fn coordinator(directory: &TempDir, fixture: &Fixture) -> StorageAdmissionCoordinator {
        let store = StorageTransactionStore::open_for_test(
            directory.path(),
            StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            0,
        )
        .unwrap();
        StorageAdmissionCoordinator::new(fixture.authority(), store)
    }

    fn initialized_coordinator(
        directory: &TempDir,
        fixture: &Fixture,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> StorageAdmissionCoordinator {
        let mut coordinator = coordinator(directory, fixture);
        coordinator
            .transactions
            .initialize_catalog_from_protected_snapshot(
                catalog.generation() - 1,
                std::slice::from_ref(catalog),
            )
            .unwrap();
        coordinator
    }

    fn runtime_coordinator(
        directory: &TempDir,
        fixture: &Fixture,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<StorageAdmissionCoordinator, crate::StorageStateError> {
        let range = aos_sandbox_protocol::MINIMUM_HOST_IDENTITY_RANGE;
        let identity_pool = crate::StorageIdentityPoolV1::new(range, range * 4).unwrap();
        let configuration_binding = crate::runtime::runtime_configuration_binding(
            fixture.protected_authority_binding(),
            identity_pool,
        );
        let store = StorageTransactionStore::open_runtime_for_test(
            directory.path(),
            StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            catalog.generation() - 1,
            configuration_binding,
            catalog.generation() - 1,
            std::slice::from_ref(catalog),
        )?;
        store.validate_runtime_restart(
            configuration_binding,
            catalog.generation() - 1,
            std::slice::from_ref(catalog),
        )?;
        Ok(StorageAdmissionCoordinator::new(fixture.authority(), store))
    }

    fn workspace_pin_ensure_dispatch(
        directory: &TempDir,
        fixture: &Fixture,
    ) -> (
        StorageAdmissionCoordinator,
        FreshWorkspacePinDispatchV1,
        CommittedStorageResultV1,
    ) {
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest(&spec);
        let request = create_request(7, manifest.digest());
        let catalog = create_catalog(9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut coordinator = initialized_coordinator(directory, fixture, &catalog);
        prepare_for_apply(&mut coordinator, &request, &artifacts, &catalog, &clock());
        let StorageAdmissionOutcome::Prepared { mutation_digest } = coordinator
            .admit_workspace_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
                65_536,
                &manifest,
                &spec,
            )
            .unwrap()
        else {
            panic!("workspace pin worker fixture was not prepared")
        };
        coordinator
            .transactions
            .mark_mutation_ambiguous([7; 16], mutation_digest)
            .unwrap();
        let result = coordinator
            .transactions
            .commit_observed(
                [7; 16],
                mutation_digest,
                &catalog,
                &catalog.plan().postcondition(),
                Some(11),
                ObjectDigest::from_bytes([62; 32]),
            )
            .unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
        let AuthorizedWorkspacePinAttemptV1::Dispatch(dispatch) = coordinator
            .begin_workspace_pin_ensure(result, host_scope, &mut || Ok(clock()))
            .unwrap()
        else {
            panic!("workspace pin worker fixture was not dispatched")
        };

        (coordinator, *dispatch, result)
    }

    fn workspace_pin_remove_dispatch(
        directory: &TempDir,
        fixture: &Fixture,
    ) -> (
        StorageAdmissionCoordinator,
        FreshWorkspaceRemoveDispatchV1,
        CommittedStorageResultV1,
    ) {
        let (mut coordinator, ensure, creation) = workspace_pin_ensure_dispatch(directory, fixture);
        let workspace_handle = creation.storage_handle().unwrap();
        let proof = workspace_pin_proof(workspace_handle, "tank/aos/project/work", 11);
        coordinator
            .transactions
            .complete_workspace_pin_attempt(
                ensure.attempt().attempt_id(),
                &crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 11,
                },
                &crate::workspace_pin::WorkspacePinObservationV1::Present(proof.clone()),
            )
            .unwrap();

        let spec = sandbox_spec(72);
        let manifest = assignment_manifest_at(&spec, 6);
        let request = destroy_request(8, workspace_handle, manifest.digest());
        let catalog = destroy_catalog(workspace_handle, 11);
        let expected_head = coordinator.transactions.catalog_head_binding().unwrap();
        let artifacts = fixture.artifacts_at_head(&request, &catalog, expected_head, 300);
        prepare_for_apply(&mut coordinator, &request, &artifacts, &catalog, &clock());
        let StorageAdmissionOutcome::Prepared { .. } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("workspace pin removal fixture was not prepared")
        };
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            CountingBackend {
                executions: Rc::new(Cell::new(0)),
            },
        );
        let prepared = helper
            .preobserve(&coordinator.transactions, [8; 16])
            .unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
        let AuthorizedWorkspaceRemoveAttemptV1::Dispatch(dispatch) =
            coordinator
                .begin_workspace_pin_remove_and_destroy(prepared, host_scope, proof, &mut || {
                    Ok(clock())
                })
                .unwrap()
        else {
            panic!("workspace pin removal fixture was not dispatched")
        };

        (coordinator, *dispatch, creation)
    }

    struct CountingBackend {
        executions: Rc<Cell<usize>>,
    }

    impl ZfsProcessBackend for CountingBackend {
        fn observe_preconditions(
            &mut self,
            _program: &SealedZfsProgram<'_>,
            expected: &[crate::ZfsPrecondition],
        ) -> Result<Vec<crate::ZfsPrecondition>, ZfsHelperError> {
            Ok(expected.to_vec())
        }

        fn execute_once(
            &mut self,
            _program: &SealedZfsProgram<'_>,
        ) -> Result<ZfsProcessOutput, ZfsHelperError> {
            self.executions.set(self.executions.get() + 1);
            Err(ZfsHelperError::ProcessContract)
        }

        fn observe_postcondition(
            &mut self,
            _program: &SealedZfsProgram<'_>,
            _expected: &crate::PostconditionPolicyV1,
            _expected_ancestor: Option<&ProjectAncestorPolicyV1>,
        ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
            Ok(None)
        }
    }

    #[test]
    fn kernel_clock_authorization_signatures_match_plan_and_lease_validity() {
        let fixture = Fixture::new();
        let state = TempDir::new().unwrap();
        let catalog = vm_create_catalog(41, 42, "aosproof/aos/project/pinned-workspace");
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest(&spec);
        let admission_clock = vm_clock();
        let effect_deadline = admission_clock
            .boottime_nanoseconds()
            .checked_add(120_000_000_000)
            .unwrap();
        let request = vm_create_request(manifest.digest(), effect_deadline);
        let artifacts =
            fixture.artifacts_for_kernel_clock(&request, &catalog, admission_clock.wall_seconds());
        let mut coordinator = initialized_coordinator(&state, &fixture, &catalog);

        prepare_for_apply(
            &mut coordinator,
            &request,
            &artifacts,
            &catalog,
            &admission_clock,
        );
    }

    #[test]
    #[ignore = "requires the installed generic and root-pin systemd workers"]
    fn systemd_workspace_pin_vm_client() {
        let executable = std::env::var_os("AOS_ZFS_EXECUTABLE")
            .map(PathBuf::from)
            .unwrap();
        let authority_directory = std::env::var_os("AOS_STORAGE_AUTHORITY_DIRECTORY")
            .map(PathBuf::from)
            .unwrap();
        let root_guid = std::env::var("AOS_STORAGE_ROOT_GUID")
            .unwrap()
            .parse()
            .unwrap();
        let ancestor_guid = std::env::var("AOS_STORAGE_ANCESTOR_GUID")
            .unwrap()
            .parse()
            .unwrap();

        let fixture = Fixture::new();
        fixture.provision_protected(&authority_directory);
        let state = TempDir::new().unwrap();
        let catalog = vm_create_catalog(
            root_guid,
            ancestor_guid,
            "aosproof/aos/project/pinned-workspace",
        );
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest(&spec);
        let admission_clock = vm_clock();
        let effect_deadline = admission_clock
            .boottime_nanoseconds()
            .checked_add(120_000_000_000)
            .unwrap();
        let request = vm_create_request(manifest.digest(), effect_deadline);
        let artifacts =
            fixture.artifacts_for_kernel_clock(&request, &catalog, admission_clock.wall_seconds());
        let mut coordinator = initialized_coordinator(&state, &fixture, &catalog);
        prepare_for_apply(
            &mut coordinator,
            &request,
            &artifacts,
            &catalog,
            &admission_clock,
        );
        let StorageAdmissionOutcome::Prepared { .. } = coordinator
            .admit_workspace_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &admission_clock,
                65_536,
                &manifest,
                &spec,
            )
            .unwrap()
        else {
            panic!("installed-worker create was not prepared")
        };

        let contract = ZfsHelperContract::new(executable).unwrap();
        let generic_executor = crate::SystemdZfsExecutor::new(
            PathBuf::from("/run/aos/sandbox-zfs-worker/control.sock"),
            crate::process::open_cgroup_root().unwrap(),
        )
        .unwrap();
        let mut helper = StorageMutationHelper::new(
            contract.clone(),
            SystemdZfsProcessBackend::new(generic_executor),
        );
        let ZfsHelperOutcome::Committed(creation) = coordinator
            .preobserve_and_execute(&mut helper, [7; 16], &mut || Ok(vm_clock()))
            .unwrap()
        else {
            panic!("installed generic worker did not commit create")
        };
        let dataset_guid = creation.object_guid().unwrap();
        let workspace_handle = creation.storage_handle().unwrap();

        let custody = WorkspacePinHostCustody::retain_initial_root_owned().unwrap();
        let mut pin_executor = SystemdWorkspacePinExecutor::new(
            PathBuf::from("/run/aos/sandbox-workspace-pin-worker/control.sock"),
            crate::process::open_cgroup_root().unwrap(),
        )
        .unwrap();
        assert_eq!(
            coordinator
                .execute_workspace_pin_ensure(
                    &mut pin_executor,
                    &contract,
                    &custody,
                    creation,
                    &mut || Ok(vm_clock()),
                )
                .unwrap(),
            WorkspacePinExecutionOutcomeV1::Satisfied
        );
        let pin_path = PathBuf::from(crate::workspace_pin::workspace_pin_path(&workspace_handle));
        assert!(pin_path.is_dir());
        let expected_pin = coordinator
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .into_iter()
            .find(|attempt| {
                attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.phase() == WorkspacePinAttemptPhaseV1::Satisfied
            })
            .and_then(|attempt| attempt.satisfied_pin().cloned())
            .unwrap();

        // Exercise the root-owned production catalog against the real pinned
        // ZFS mount, including live inventory validation and restart recovery.
        // The production opener requires root-owned, non-writable ancestry;
        // `/tmp` is intentionally outside that protected boundary.
        let protected_parent = fs::symlink_metadata("/run/aos").unwrap();
        assert!(protected_parent.file_type().is_dir());
        assert_eq!(protected_parent.uid(), 0);
        assert_eq!(protected_parent.permissions().mode() & 0o022, 0);
        let workspace_catalog_state = private_tempdir_in(Path::new("/run/aos")).unwrap();
        let catalog_state_metadata = fs::symlink_metadata(workspace_catalog_state.path()).unwrap();
        assert!(catalog_state_metadata.file_type().is_dir());
        assert_eq!(catalog_state_metadata.uid(), 0);
        assert_eq!(catalog_state_metadata.permissions().mode() & 0o777, 0o700);
        let identity_pool = crate::StorageIdentityPoolV1::new(
            MINIMUM_HOST_IDENTITY_RANGE,
            MINIMUM_HOST_IDENTITY_RANGE * 4,
        )
        .unwrap();
        let publication = coordinator.workspace_publication(creation).unwrap();
        let mut workspace_catalog = crate::StorageWorkspaceCatalogV1::open_root_owned(
            workspace_catalog_state.path(),
            identity_pool,
        )
        .unwrap();
        assert_eq!(
            workspace_catalog.publish(publication.clone()).unwrap(),
            crate::StorageWorkspaceCatalogOutcomeV1::Published
        );
        let inventory = decode_storage_resource_inventory_response(
            &workspace_catalog.inventory_resources().unwrap(),
            1_048_576,
        )
        .unwrap();
        assert_eq!(inventory.workspaces().len(), 1);
        drop(workspace_catalog);

        let mut workspace_catalog = crate::StorageWorkspaceCatalogV1::open_root_owned(
            workspace_catalog_state.path(),
            identity_pool,
        )
        .unwrap();
        assert_eq!(
            workspace_catalog.publish(publication).unwrap(),
            crate::StorageWorkspaceCatalogOutcomeV1::Replay
        );
        assert_eq!(
            decode_storage_resource_inventory_response(
                &workspace_catalog.inventory_resources().unwrap(),
                1_048_576,
            )
            .unwrap()
            .workspaces()
            .len(),
            1
        );

        let destroy_spec = sandbox_spec(72);
        let destroy_manifest = assignment_manifest_at(&destroy_spec, 6);
        let destroy_clock = vm_clock();
        let destroy_deadline = destroy_clock
            .boottime_nanoseconds()
            .checked_add(120_000_000_000)
            .unwrap();
        let destroy_request = vm_destroy_request(
            workspace_handle,
            destroy_manifest.digest(),
            destroy_deadline,
        );
        let destroy_catalog = vm_destroy_catalog(
            root_guid,
            dataset_guid,
            workspace_handle,
            "aosproof/aos/project/pinned-workspace",
        );
        let destroy_artifacts = fixture.artifacts_for_kernel_clock_at_head(
            &destroy_request,
            &destroy_catalog,
            coordinator.transactions.catalog_head_binding().unwrap(),
            destroy_clock.wall_seconds(),
        );
        prepare_for_apply(
            &mut coordinator,
            &destroy_request,
            &destroy_artifacts,
            &destroy_catalog,
            &destroy_clock,
        );
        let StorageAdmissionOutcome::Prepared { .. } = coordinator
            .admit_apply_intent(
                &destroy_request,
                &destroy_artifacts,
                &destroy_catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &destroy_clock,
            )
            .unwrap()
        else {
            panic!("installed-worker destroy was not prepared")
        };
        let prepared = coordinator.preobserve(&mut helper, [8; 16]).unwrap();
        let (pin_outcome, committed) = coordinator
            .execute_workspace_remove_and_destroy(
                &mut pin_executor,
                &contract,
                &custody,
                prepared,
                expected_pin,
                &mut || Ok(vm_clock()),
            )
            .unwrap();
        assert_eq!(pin_outcome, WorkspacePinExecutionOutcomeV1::Satisfied);
        let committed = committed.unwrap();
        assert!(!pin_path.exists());
        let retirement = coordinator.workspace_retirement(committed).unwrap();
        assert_eq!(
            workspace_catalog.retire(retirement).unwrap(),
            crate::StorageWorkspaceCatalogOutcomeV1::Retired
        );
        assert!(
            decode_storage_resource_inventory_response(
                &workspace_catalog.inventory_resources().unwrap(),
                1_048_576,
            )
            .unwrap()
            .workspaces()
            .is_empty()
        );
        drop(workspace_catalog);

        let workspace_catalog = crate::StorageWorkspaceCatalogV1::open_root_owned(
            workspace_catalog_state.path(),
            identity_pool,
        )
        .unwrap();
        assert!(
            decode_storage_resource_inventory_response(
                &workspace_catalog.inventory_resources().unwrap(),
                1_048_576,
            )
            .unwrap()
            .workspaces()
            .is_empty()
        );

        // A second workspace leaves its Ensure attempt Ambiguous, advances the
        // desired fence, and proves the installed effect worker rejects that
        // stale fence without a replay claim or mount. The distinct observer
        // then authenticates the historical operation under current
        // same-sandbox authority and returns read-only absence evidence.
        let observation_state = TempDir::new().unwrap();
        let observation_catalog = vm_create_catalog(
            root_guid,
            ancestor_guid,
            "aosproof/aos/project/observed-workspace",
        );
        let observation_spec = sandbox_spec(74);
        let observation_manifest = assignment_manifest(&observation_spec);
        let observation_clock = vm_clock();
        let observation_deadline = observation_clock
            .boottime_nanoseconds()
            .checked_add(120_000_000_000)
            .unwrap();
        let observation_request =
            vm_create_request(observation_manifest.digest(), observation_deadline);
        let observation_artifacts = fixture.artifacts_for_kernel_clock(
            &observation_request,
            &observation_catalog,
            observation_clock.wall_seconds(),
        );
        let mut observer_coordinator =
            initialized_coordinator(&observation_state, &fixture, &observation_catalog);
        prepare_for_apply(
            &mut observer_coordinator,
            &observation_request,
            &observation_artifacts,
            &observation_catalog,
            &observation_clock,
        );
        let StorageAdmissionOutcome::Prepared { .. } = observer_coordinator
            .admit_workspace_apply_intent(
                &observation_request,
                &observation_artifacts,
                &observation_catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &observation_clock,
                131_072,
                &observation_manifest,
                &observation_spec,
            )
            .unwrap()
        else {
            panic!("observer fixture create was not prepared")
        };
        let ZfsHelperOutcome::Committed(observation_creation) = observer_coordinator
            .preobserve_and_execute(&mut helper, [7; 16], &mut || Ok(vm_clock()))
            .unwrap()
        else {
            panic!("observer fixture dataset was not created")
        };
        let observation_guid = observation_creation.object_guid().unwrap();
        let observation_handle = observation_creation.storage_handle().unwrap();
        let AuthorizedWorkspacePinAttemptV1::Dispatch(observation_dispatch) = observer_coordinator
            .begin_workspace_pin_ensure(
                observation_creation,
                custody.host_scope().unwrap(),
                &mut || Ok(vm_clock()),
            )
            .unwrap()
        else {
            panic!("observer fixture Ensure was not dispatched")
        };

        let advanced_spec = sandbox_spec(74);
        let advanced_manifest = assignment_manifest_at(&advanced_spec, 6);
        let advanced_clock = vm_clock();
        let advanced_deadline = advanced_clock
            .boottime_nanoseconds()
            .checked_add(120_000_000_000)
            .unwrap();
        let advanced_request = vm_destroy_request(
            observation_handle,
            advanced_manifest.digest(),
            advanced_deadline,
        );
        let advanced_catalog = vm_destroy_catalog(
            root_guid,
            observation_guid,
            observation_handle,
            "aosproof/aos/project/observed-workspace",
        );
        let advanced_artifacts = fixture.artifacts_for_kernel_clock_at_head(
            &advanced_request,
            &advanced_catalog,
            observer_coordinator
                .transactions
                .catalog_head_binding()
                .unwrap(),
            advanced_clock.wall_seconds(),
        );
        prepare_for_apply(
            &mut observer_coordinator,
            &advanced_request,
            &advanced_artifacts,
            &advanced_catalog,
            &advanced_clock,
        );
        let StorageAdmissionOutcome::Prepared { .. } = observer_coordinator
            .admit_apply_intent(
                &advanced_request,
                &advanced_artifacts,
                &advanced_catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &advanced_clock,
            )
            .unwrap()
        else {
            panic!("observer fixture fence was not advanced")
        };

        use crate::pin_worker::WorkspacePinWorkerAuthorityRecord;

        let current_fence = observer_coordinator
            .transactions
            .authority_record(RecordNamespace::DesiredState, &[2; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        let valid_request = observation_dispatch
            .worker_request_bytes(&contract)
            .unwrap();
        let mut stale_request = crate::pin_worker::decode_request(&valid_request).unwrap();
        let current_fence_donor = crate::pin_worker::WorkspacePinWorkerAuthorityV1::new(
            [1; 16],
            vec![1],
            current_fence,
            vec![1],
            vec![1],
        )
        .unwrap();
        stale_request.authority.substitute_record_from(
            WorkspacePinWorkerAuthorityRecord::CurrentFence,
            &current_fence_donor,
        );
        let stale_request = crate::pin_worker::encode_request(
            &contract,
            &stale_request.catalog,
            &stale_request.authority,
        )
        .unwrap();
        assert!(
            pin_executor
                .execute(&stale_request, observation_dispatch.attempt(), &custody,)
                .is_err()
        );
        let observation_pin_path = PathBuf::from(crate::workspace_pin::workspace_pin_path(
            &observation_handle,
        ));
        assert!(!observation_pin_path.exists());

        let replay_claims_before = fs::read_dir("/var/lib/aos-sandbox-workspace-pin-worker")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("attempt-"))
            .count();
        assert_eq!(replay_claims_before, 2);
        let mut observations = observer_coordinator
            .workspace_pin_observation_dispatches()
            .unwrap();
        assert_eq!(observations.len(), 1);
        let observation = observations.remove(0);
        let mut pin_observer = crate::pin_worker_runtime::SystemdWorkspacePinObserver::new(
            PathBuf::from("/run/aos/sandbox-workspace-pin-observer/control.sock"),
            crate::process::open_cgroup_root().unwrap(),
        )
        .unwrap();
        let observer_request = observation.request_bytes(&contract).unwrap();
        let observer_result = pin_observer
            .observe(&observer_request, observation.attempt(), &custody)
            .unwrap();
        assert_eq!(
            observer_result.dataset(),
            &crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: "aosproof/aos/project/observed-workspace".to_owned(),
                guid: observation_guid,
            }
        );
        assert_eq!(
            observer_result.pin(),
            &crate::workspace_pin::WorkspacePinObservationV1::Absent
        );
        assert_eq!(
            observer_coordinator
                .complete_workspace_pin_observation(observation.attempt(), &observer_result)
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
        );
        assert!(!observation_pin_path.exists());
        let replay_claims_after = fs::read_dir("/var/lib/aos-sandbox-workspace-pin-worker")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("attempt-"))
            .count();
        assert_eq!(replay_claims_after, replay_claims_before);
    }

    #[test]
    fn private_tempdir_builder_does_not_inherit_permissive_parent_mode() {
        let parent = TempDir::new().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).unwrap();

        let directory = private_tempdir_in(parent.path()).unwrap();
        let metadata = fs::symlink_metadata(directory.path()).unwrap();

        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn real_authority_prepares_and_exact_replay_is_observation_only() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let original_request = request(7, 8);
        let original_catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &original_request,
            &original_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &original_catalog);
        prepare_for_apply(
            &mut broker,
            &original_request,
            &artifacts,
            &original_catalog,
            &clock(),
        );
        assert!(matches!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &artifacts,
                    &original_catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .unwrap(),
            StorageAdmissionOutcome::Prepared { .. }
        ));
        assert!(matches!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &artifacts,
                    &original_catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .unwrap(),
            StorageAdmissionOutcome::ObservationRequired {
                phase: DurableStoragePhase::Prepared,
                ..
            }
        ));
    }

    #[test]
    fn signed_preparation_and_apply_replay_exactly_across_reopen() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        let prepared = prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        drop(broker);

        let mut broker = coordinator(&directory, &fixture);
        crate::runtime::authenticate_startup_authority(&broker).unwrap();
        let replayed = prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        assert_eq!(replayed, prepared);
        assert!(matches!(
            broker
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            StorageAdmissionOutcome::Prepared { .. }
        ));
        drop(broker);

        let mut broker = coordinator(&directory, &fixture);
        crate::runtime::authenticate_startup_authority(&broker).unwrap();
        assert!(matches!(
            broker
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            StorageAdmissionOutcome::ObservationRequired {
                phase: DurableStoragePhase::Prepared,
                ..
            }
        ));
    }

    #[test]
    fn preparation_and_apply_require_independent_signed_grants() {
        let apply_only_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let apply_only = fixture.artifacts_with_grants(&request, &catalog, true, false);
        let mut apply_only_broker =
            initialized_coordinator(&apply_only_directory, &fixture, &catalog);
        let before = apply_only_broker.transactions.journal_sequence_for_test();
        let (preparation, inventory, _) = preparation_request(&request, &catalog);

        assert!(matches!(
            apply_only_broker.prepare_catalog(
                &preparation,
                &apply_only,
                inventory,
                &StaticCatalogResolver { catalog: &catalog },
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::Authority)
        ));
        assert_eq!(
            apply_only_broker.transactions.journal_sequence_for_test(),
            before
        );
        assert!(
            apply_only_broker
                .transactions
                .catalog_preparation_record(&[7; 16])
                .unwrap()
                .is_none()
        );

        let prepare_only_directory = TempDir::new().unwrap();
        let prepare_only = fixture.artifacts_with_grants(&request, &catalog, false, true);
        let mut prepare_only_broker =
            initialized_coordinator(&prepare_only_directory, &fixture, &catalog);
        prepare_for_apply(
            &mut prepare_only_broker,
            &request,
            &prepare_only,
            &catalog,
            &clock(),
        );
        let before = prepare_only_broker.transactions.journal_sequence_for_test();

        assert!(matches!(
            prepare_only_broker.admit_apply_intent(
                &request,
                &prepare_only,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::Authority)
        ));
        assert_eq!(
            prepare_only_broker.transactions.journal_sequence_for_test(),
            before
        );
        assert_eq!(
            prepare_only_broker.transactions.phase([7; 16]).unwrap(),
            None
        );
    }

    #[test]
    fn stale_catalog_head_rejects_preparation_without_journal_mutation() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let current_catalog = catalog(8, 9);
        let stale_catalog = catalog(8, 10);
        let request = request(7, 8);
        let artifacts = fixture.artifacts(
            &request,
            &stale_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &current_catalog);
        let before = broker.transactions.journal_sequence_for_test();
        let (preparation, inventory, _) = preparation_request(&request, &stale_catalog);

        assert!(matches!(
            broker.prepare_catalog(
                &preparation,
                &artifacts,
                inventory,
                &StaticCatalogResolver {
                    catalog: &stale_catalog,
                },
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::Preparation(
                StorageCatalogPreparationError::StaleCatalogHead
            ))
        ));
        assert_eq!(broker.transactions.journal_sequence_for_test(), before);
        assert!(
            broker
                .transactions
                .catalog_preparation_record(&[7; 16])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn apply_rechecks_preparation_expiry_boot_and_revocation_without_mutation() {
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );

        let expired_directory = TempDir::new().unwrap();
        let mut expired = initialized_coordinator(&expired_directory, &fixture, &catalog);
        prepare_for_apply(&mut expired, &request, &artifacts, &catalog, &clock());
        let before = expired.transactions.journal_sequence_for_test();
        assert!(matches!(
            expired.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock_at([50; 16], 150, 199),
            ),
            Err(StorageBrokerError::Preparation(
                StorageCatalogPreparationError::Expired
            ))
        ));
        assert_eq!(expired.transactions.journal_sequence_for_test(), before);
        assert_eq!(expired.transactions.phase([7; 16]).unwrap(), None);

        let rebooted_directory = TempDir::new().unwrap();
        let mut rebooted = initialized_coordinator(&rebooted_directory, &fixture, &catalog);
        prepare_for_apply(&mut rebooted, &request, &artifacts, &catalog, &clock());
        let before = rebooted.transactions.journal_sequence_for_test();
        assert!(matches!(
            rebooted.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock_at([60; 16], 150, 100),
            ),
            Err(StorageBrokerError::Preparation(
                StorageCatalogPreparationError::HostBootMismatch
            ))
        ));
        assert_eq!(rebooted.transactions.journal_sequence_for_test(), before);
        assert_eq!(rebooted.transactions.phase([7; 16]).unwrap(), None);

        let revoked_directory = TempDir::new().unwrap();
        let mut revoked = initialized_coordinator(&revoked_directory, &fixture, &catalog);
        prepare_for_apply(&mut revoked, &request, &artifacts, &catalog, &clock());
        let mut revoked_fixture = Fixture::new();
        revoked_fixture.revocation = RevocationScopeId::from_bytes([46; 16]);
        let revoked_artifacts = revoked_fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let before = revoked.transactions.journal_sequence_for_test();
        assert!(matches!(
            revoked.admit_apply_intent(
                &request,
                &revoked_artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::Authority)
        ));
        assert_eq!(revoked.transactions.journal_sequence_for_test(), before);
        assert_eq!(revoked.transactions.phase([7; 16]).unwrap(), None);

        let authority_change_directory = TempDir::new().unwrap();
        let mut before_change =
            runtime_coordinator(&authority_change_directory, &fixture, &catalog).unwrap();
        prepare_for_apply(&mut before_change, &request, &artifacts, &catalog, &clock());
        let before = before_change.transactions.journal_sequence_for_test();
        drop(before_change);

        assert!(
            runtime_coordinator(&authority_change_directory, &revoked_fixture, &catalog).is_err()
        );
        let mut after_change = coordinator(&authority_change_directory, &revoked_fixture);
        assert_eq!(
            after_change.transactions.journal_sequence_for_test(),
            before
        );
        assert!(matches!(
            after_change.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::Authority)
        ));
        assert_eq!(
            after_change.transactions.journal_sequence_for_test(),
            before
        );
        assert_eq!(after_change.transactions.phase([7; 16]).unwrap(), None);
    }

    #[test]
    fn retained_preparation_rejects_same_operation_equivocation() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let conflicting = with_deadline(&request, 201);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts_authorizing(
            &request,
            &catalog,
            &[&request, &conflicting],
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        let before = broker.transactions.journal_sequence_for_test();
        let retained = broker
            .transactions
            .catalog_preparation_record(&[7; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        let (conflicting_preparation, inventory, _) = preparation_request(&conflicting, &catalog);

        assert!(matches!(
            broker.prepare_catalog(
                &conflicting_preparation,
                &artifacts,
                inventory,
                &StaticCatalogResolver { catalog: &catalog },
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::Preparation(
                StorageCatalogPreparationError::Equivocation
            ))
        ));
        assert_eq!(broker.transactions.journal_sequence_for_test(), before);
        assert_eq!(
            broker
                .transactions
                .catalog_preparation_record(&[7; 16])
                .unwrap(),
            Some(retained.as_slice())
        );
    }

    #[test]
    fn occupied_apply_request_ids_never_consume_preparation() {
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let occupied_directory = TempDir::new().unwrap();
        let mut occupied = initialized_coordinator(&occupied_directory, &fixture, &catalog);
        prepare_for_apply(&mut occupied, &request, &artifacts, &catalog, &clock());
        let preparation_effect = occupied
            .transactions
            .authority_record(RecordNamespace::Effect, &[135; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        occupied.transactions.put_authority_record_for_test(
            RecordNamespace::Effect,
            &[7; 16],
            preparation_effect,
        );
        let before = occupied.transactions.journal_sequence_for_test();
        assert!(matches!(
            occupied.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::State(
                crate::StorageStateError::Equivocation
            ))
        ));
        assert_eq!(occupied.transactions.journal_sequence_for_test(), before);
        assert_eq!(occupied.transactions.phase([7; 16]).unwrap(), None);

        let same_id_directory = TempDir::new().unwrap();
        let same_id_request = with_request_id(&request, [135; 16]);
        let same_id_artifacts = fixture.artifacts(
            &same_id_request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut same_id = initialized_coordinator(&same_id_directory, &fixture, &catalog);
        prepare_for_apply(
            &mut same_id,
            &same_id_request,
            &same_id_artifacts,
            &catalog,
            &clock(),
        );
        let before = same_id.transactions.journal_sequence_for_test();
        assert!(matches!(
            same_id.admit_apply_intent(
                &same_id_request,
                &same_id_artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::State(
                crate::StorageStateError::Equivocation
            ))
        ));
        assert_eq!(same_id.transactions.journal_sequence_for_test(), before);
        assert_eq!(same_id.transactions.phase([7; 16]).unwrap(), None);
    }

    #[test]
    fn crash_after_atomic_apply_consumption_reopens_observation_only() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        broker
            .transactions
            .fail_after_next_journal_commit_for_test();

        assert!(
            broker
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .is_err()
        );
        drop(broker);

        let mut recovered = coordinator(&directory, &fixture);
        crate::runtime::authenticate_startup_authority(&recovered).unwrap();
        assert_eq!(
            recovered.transactions.phase([7; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
        assert!(matches!(
            recovered
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            StorageAdmissionOutcome::ObservationRequired {
                phase: DurableStoragePhase::Prepared,
                ..
            }
        ));
    }

    #[test]
    fn startup_rejects_each_missing_or_substituted_preparation_authority_link() {
        for case in 0..4 {
            let directory = TempDir::new().unwrap();
            let fixture = Fixture::new();
            let request = request(7, 8);
            let catalog = catalog(8, 9);
            let artifacts = fixture.artifacts(
                &request,
                &catalog,
                300,
                BrokerAudience::Storage,
                ProtocolId::StorageBroker,
            );
            let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
            prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
            let effect = broker
                .transactions
                .authority_record(RecordNamespace::Effect, &[135; 16])
                .unwrap()
                .unwrap()
                .to_vec();
            let operation_fence = broker
                .transactions
                .authority_record(RecordNamespace::AuthorityPublication, &[7; 16])
                .unwrap()
                .unwrap()
                .to_vec();

            match case {
                0 => broker
                    .transactions
                    .remove_authority_record_for_test(RecordNamespace::Effect, &[135; 16]),
                1 => broker.transactions.put_authority_record_for_test(
                    RecordNamespace::Effect,
                    &[135; 16],
                    operation_fence,
                ),
                2 => broker.transactions.remove_authority_record_for_test(
                    RecordNamespace::AuthorityPublication,
                    &[7; 16],
                ),
                3 => broker.transactions.put_authority_record_for_test(
                    RecordNamespace::AuthorityPublication,
                    &[7; 16],
                    effect,
                ),
                _ => unreachable!(),
            }
            drop(broker);

            let recovered = coordinator(&directory, &fixture);
            assert!(matches!(
                crate::runtime::authenticate_startup_authority(&recovered),
                Err(crate::StorageRuntimeError::Recovery)
            ));
        }
    }

    #[test]
    fn startup_rejects_prepared_apply_inconsistency_and_missing_historical_effect() {
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );

        let inconsistent_directory = TempDir::new().unwrap();
        let mut inconsistent = initialized_coordinator(&inconsistent_directory, &fixture, &catalog);
        prepare_for_apply(&mut inconsistent, &request, &artifacts, &catalog, &clock());
        let prepared_record = inconsistent
            .transactions
            .catalog_preparation_record(&[7; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        inconsistent
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        inconsistent.transactions.put_authority_record_for_test(
            RecordNamespace::StorageCatalogPreparation,
            &[7; 16],
            prepared_record,
        );
        drop(inconsistent);

        let recovered = coordinator(&inconsistent_directory, &fixture);
        assert!(matches!(
            crate::runtime::authenticate_startup_authority(&recovered),
            Err(crate::StorageRuntimeError::Recovery)
        ));

        let missing_history_directory = TempDir::new().unwrap();
        let mut missing_history =
            initialized_coordinator(&missing_history_directory, &fixture, &catalog);
        prepare_for_apply(
            &mut missing_history,
            &request,
            &artifacts,
            &catalog,
            &clock(),
        );
        missing_history
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        missing_history
            .transactions
            .remove_authority_record_for_test(RecordNamespace::Effect, &[135; 16]);
        drop(missing_history);

        let recovered = coordinator(&missing_history_directory, &fixture);
        assert!(matches!(
            crate::runtime::authenticate_startup_authority(&recovered),
            Err(crate::StorageRuntimeError::Recovery)
        ));
    }

    fn assert_second_clock_rejection(
        second_sample: Result<RawPairedClockSample, StorageAdmissionError>,
    ) {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        broker
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();

        let executions = Rc::new(Cell::new(0));
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            CountingBackend {
                executions: Rc::clone(&executions),
            },
        );
        let mut samples = 0;
        let result = broker.preobserve_and_execute(&mut helper, [7; 16], &mut || {
            samples += 1;
            if samples == 1 {
                Ok(clock())
            } else {
                second_sample
            }
        });

        assert!(matches!(result, Err(ZfsHelperError::Authority)));
        assert_eq!(samples, 2);
        assert_eq!(executions.get(), 0);
        assert_eq!(
            broker.transactions.phase([7; 16]).unwrap(),
            Some(DurableStoragePhase::Ambiguous)
        );
        drop(helper);
        drop(broker);

        let mut recovered = coordinator(&directory, &fixture);
        let entry = recovered
            .recovery_entries()
            .unwrap()
            .into_iter()
            .find(|entry| entry.operation_id() == [7; 16])
            .unwrap();
        let recovery_executions = Rc::new(Cell::new(0));
        let mut observer = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            CountingBackend {
                executions: Rc::clone(&recovery_executions),
            },
        );
        assert!(matches!(
            recovered.reconcile_recovery(&mut observer, entry).unwrap(),
            ZfsHelperOutcome::ObservationRequired {
                phase: DurableStoragePhase::Ambiguous,
                ..
            }
        ));
        assert_eq!(recovery_executions.get(), 0);
    }

    #[test]
    fn failed_second_clock_sample_leaves_ambiguous_without_dispatch() {
        assert_second_clock_rejection(Err(StorageAdmissionError::VerificationFailed));
    }

    #[test]
    fn expired_second_clock_sample_leaves_ambiguous_without_dispatch() {
        let expired = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            200,
        )
        .unwrap();
        assert_second_clock_rejection(Ok(expired));
    }

    #[test]
    fn superseded_current_fence_after_preobservation_prevents_dispatch() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let catalog = catalog(8, 9);
        let original_request = request_with_generation(7, 8, 5);
        let original_artifacts = fixture.artifacts(
            &original_request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(
            &mut broker,
            &original_request,
            &original_artifacts,
            &catalog,
            &clock(),
        );
        broker
            .admit_apply_intent(
                &original_request,
                &original_artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();

        let executions = Rc::new(Cell::new(0));
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            CountingBackend {
                executions: Rc::clone(&executions),
            },
        );
        let prepared = helper.preobserve(&broker.transactions, [7; 16]).unwrap();

        let superseding_request = request_with_generation(9, 8, 6);
        let superseding_artifacts = fixture.artifacts(
            &superseding_request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let superseding_semantics =
            decode_resolved(&superseding_request, &catalog, peer(), peer_policy(), 100).unwrap();
        let prior_fence = broker
            .transactions
            .authority_record(RecordNamespace::DesiredState, &[2; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        let superseding_admission = broker
            .authority
            .admit(
                &superseding_artifacts,
                &superseding_semantics,
                &superseding_request,
                ProtocolVersion::new(1, 3),
                &clock(),
                Some(&prior_fence),
            )
            .unwrap();
        let superseding_sealed = broker
            .authority
            .seal(&[2; 16], &[9; 16], &[9; 16], &superseding_admission)
            .unwrap();
        broker.transactions.put_authority_record_for_test(
            RecordNamespace::DesiredState,
            &[2; 16],
            superseding_sealed.current_fence,
        );

        assert!(matches!(
            broker.execute_preobserved(&mut helper, prepared, &mut || Ok(clock())),
            Err(ZfsHelperError::Authority)
        ));
        assert_eq!(executions.get(), 0);
        assert_eq!(
            broker.transactions.phase([7; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
    }

    #[test]
    fn exact_committed_destroy_reconstructs_an_authenticated_retirement() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest(&spec);
        let create_request = create_request(7, manifest.digest());
        let create_catalog = create_catalog(9);
        let create_artifacts = fixture.artifacts(
            &create_request,
            &create_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &create_catalog);
        prepare_for_apply(
            &mut broker,
            &create_request,
            &create_artifacts,
            &create_catalog,
            &clock(),
        );
        let StorageAdmissionOutcome::Prepared { mutation_digest } = broker
            .admit_workspace_apply_intent(
                &create_request,
                &create_artifacts,
                &create_catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
                65_536,
                &manifest,
                &spec,
            )
            .unwrap()
        else {
            panic!("managed workspace creation was not prepared")
        };
        broker
            .transactions
            .mark_mutation_ambiguous([7; 16], mutation_digest)
            .unwrap();
        let creation = broker
            .transactions
            .commit_observed(
                [7; 16],
                mutation_digest,
                &create_catalog,
                &create_catalog.plan().postcondition(),
                Some(11),
                ObjectDigest::from_bytes([62; 32]),
            )
            .unwrap();
        let workspace_handle = creation.storage_handle().unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
        let AuthorizedWorkspacePinAttemptV1::Dispatch(ensure_dispatch) = broker
            .begin_workspace_pin_ensure(creation, host_scope, &mut || Ok(clock()))
            .unwrap()
        else {
            panic!("workspace pin Ensure was not dispatched")
        };
        let proof = workspace_pin_proof(workspace_handle, "tank/aos/project/work", 11);
        broker
            .transactions
            .complete_workspace_pin_attempt(
                ensure_dispatch.attempt().attempt_id(),
                &crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 11,
                },
                &crate::workspace_pin::WorkspacePinObservationV1::Present(proof.clone()),
            )
            .unwrap();
        assert!(broker.workspace_publication(creation).is_ok());

        let destroy_manifest = assignment_manifest_at(&spec, 6);
        let request = destroy_request(8, workspace_handle, destroy_manifest.digest());
        let catalog = destroy_catalog(workspace_handle, 11);
        let expected_head = broker.transactions.catalog_head_binding().unwrap();
        let current_clock = clock();

        // A later operation's preparation grant must bind the head advanced by
        // the creation. Reusing genesis-head fixture artifacts is outside the
        // signed plan even when its assignment generation advances correctly.
        let wrong_head_artifacts =
            fixture.artifacts_for_kernel_clock(&request, &catalog, current_clock.wall_seconds());
        let (preparation_bytes, _, _) =
            preparation_request_at_head(&request, &catalog, expected_head);
        let preparation = CanonicalStoragePreparationSemanticsV1::decode(
            &preparation_bytes,
            peer(),
            peer_policy(),
            current_clock.boottime_nanoseconds(),
        )
        .unwrap();
        let prior_fence = broker
            .transactions
            .authority_record(RecordNamespace::DesiredState, &[2; 16])
            .unwrap();
        assert_eq!(
            broker
                .authority
                .admit_preparation(
                    &wrong_head_artifacts,
                    &preparation,
                    &preparation_bytes,
                    ProtocolVersion::new(1, 3),
                    &current_clock,
                    prior_fence,
                )
                .unwrap_err(),
            StorageAdmissionError::RequestMismatch
        );

        let artifacts = fixture.artifacts_at_head(&request, &catalog, expected_head, 300);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &current_clock);
        let StorageAdmissionOutcome::Prepared { mutation_digest } = broker
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &current_clock,
            )
            .unwrap()
        else {
            panic!("managed workspace destruction was not prepared")
        };
        let executions = Rc::new(Cell::new(0));
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            CountingBackend {
                executions: Rc::clone(&executions),
            },
        );
        let prepared = helper.preobserve(&broker.transactions, [8; 16]).unwrap();
        assert_eq!(prepared.entry().mutation_digest(), mutation_digest);
        let AuthorizedWorkspaceRemoveAttemptV1::Dispatch(remove_dispatch) =
            broker
                .begin_workspace_pin_remove_and_destroy(prepared, host_scope, proof, &mut || {
                    Ok(clock())
                })
                .unwrap()
        else {
            panic!("workspace pin RemoveAndDestroy was not dispatched")
        };
        let (remove_attempt, prepared) = (*remove_dispatch).into_parts();
        assert_eq!(remove_attempt.attempt_ordinal(), 2);
        assert_eq!(executions.get(), 0);
        let result = broker
            .transactions
            .commit_observed(
                [8; 16],
                prepared.entry().mutation_digest(),
                &catalog,
                &catalog.plan().postcondition(),
                None,
                ObjectDigest::from_bytes([63; 32]),
            )
            .unwrap();
        assert!(broker.workspace_retirement(result).is_err());
        broker
            .transactions
            .complete_workspace_pin_attempt(
                remove_attempt.attempt_id(),
                &crate::workspace_pin::WorkspaceDatasetObservationV1::Absent,
                &crate::workspace_pin::WorkspacePinObservationV1::Absent,
            )
            .unwrap();
        assert!(broker.workspace_publication(creation).is_err());
        assert!(broker.workspace_retirement(result).is_ok());
        assert!(matches!(
            broker.workspace_projection().unwrap().as_slice(),
            [StorageWorkspaceCatalogActionV1::Retire { .. }]
        ));

        drop(broker);
        let mut broker = coordinator(&directory, &fixture);
        broker.authenticate_workspace_pin_attempts().unwrap();
        assert!(broker.workspace_retirement(result).is_ok());

        let operation_fence = broker
            .transactions
            .authority_record(RecordNamespace::AuthorityPublication, &[8; 16])
            .unwrap()
            .unwrap();
        assert!(
            broker
                .authority
                .open_operation_fence(&[9; 16], operation_fence)
                .is_err()
        );
        broker
            .transactions
            .remove_authority_record_for_test(RecordNamespace::DesiredState, &[2; 16]);
        assert!(broker.workspace_retirement(result).is_ok());
        broker
            .transactions
            .remove_authority_record_for_test(RecordNamespace::AuthorityPublication, &[8; 16]);
        assert!(matches!(
            broker.workspace_retirement(result),
            Err(StorageBrokerError::State(
                crate::StorageStateError::MissingAuthorityLink
            ))
        ));
    }

    #[test]
    fn exact_committed_creation_requires_the_canonical_manifest_and_specification() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest(&spec);
        let request = create_request(7, manifest.digest());
        let catalog = create_catalog(9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        assert!(matches!(
            broker.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(StorageBrokerError::State(
                crate::StorageStateError::MissingAuthorityLink
            ))
        ));
        let StorageAdmissionOutcome::Prepared { mutation_digest } = broker
            .admit_workspace_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
                65_536,
                &manifest,
                &spec,
            )
            .unwrap()
        else {
            panic!("new workspace creation was not prepared")
        };
        broker
            .transactions
            .mark_mutation_ambiguous([7; 16], mutation_digest)
            .unwrap();
        let result = broker
            .transactions
            .commit_observed(
                [7; 16],
                mutation_digest,
                &catalog,
                &catalog.plan().postcondition(),
                Some(91),
                ObjectDigest::from_bytes([62; 32]),
            )
            .unwrap();

        let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
        let AuthorizedWorkspacePinAttemptV1::Dispatch(dispatch) = broker
            .begin_workspace_pin_ensure(result, host_scope, &mut || Ok(clock()))
            .unwrap()
        else {
            panic!("workspace pin Ensure was not dispatched")
        };
        let attempt_id = dispatch.attempt().attempt_id();
        let proof = workspace_pin_proof(
            result.storage_handle().unwrap(),
            "tank/aos/project/work",
            91,
        );
        broker
            .transactions
            .complete_workspace_pin_attempt(
                attempt_id,
                &crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 91,
                },
                &crate::workspace_pin::WorkspacePinObservationV1::Present(proof),
            )
            .unwrap();

        assert!(broker.workspace_publication(result).is_ok());
        drop(broker);
        let mut broker = coordinator(&directory, &fixture);
        broker.authenticate_workspace_pin_attempts().unwrap();
        assert!(broker.workspace_publication(result).is_ok());
        assert!(matches!(
            broker.admit_workspace_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
                65_536,
                &manifest,
                &sandbox_spec(74),
            ),
            Err(StorageBrokerError::WorkspaceCatalog(
                StorageWorkspaceCatalogError::InvalidCandidate
            ))
        ));
    }

    #[test]
    fn repair_history_reopen_authenticates_pending_effect_and_rejects_resealed_drift() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (mut broker, initial_dispatch, creation) =
            workspace_pin_ensure_dispatch(&directory, &fixture);
        let initial_attempt = initial_dispatch.attempt().clone();
        let workspace_handle = creation.storage_handle().unwrap();
        let repair_assignment_digest = assignment_manifest_at(&sandbox_spec(72), 6).digest();
        let repair_request_bytes =
            repair_request(80, 81, workspace_handle, 6, repair_assignment_digest);
        let repair_semantics = CanonicalStorageRepairSemanticsV1::decode(
            &repair_request_bytes,
            peer(),
            peer_policy(),
            clock().boottime_nanoseconds(),
        )
        .unwrap();
        let repair_artifacts = fixture.repair_artifacts(&repair_request_bytes);
        let prior_fence = broker
            .transactions
            .authority_record(RecordNamespace::DesiredState, &[2; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        let admission = broker
            .authority
            .admit_workspace_pin_repair(
                &repair_artifacts,
                &repair_semantics,
                &repair_request_bytes,
                ProtocolVersion::new(1, 4),
                &clock(),
                Some(&prior_fence),
            )
            .unwrap();
        let sealed = broker
            .authority
            .seal(
                &[2; 16],
                repair_semantics.header().request_id(),
                &repair_semantics.operation_id(),
                &admission,
            )
            .unwrap();
        let operation_fence_digest =
            ObjectDigest::from_bytes(Sha256::digest(&sealed.operation_fence).into());
        let repair_attempt_id = derive_attempt_id(
            &[52; 32],
            repair_semantics.operation_id(),
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            2,
        )
        .unwrap();
        let repair_attempt = WorkspacePinAttemptV1::new_ambiguous(
            repair_attempt_id,
            2,
            WorkspacePinActionV1::Ensure,
            repair_semantics.operation_id(),
            creation.operation_id(),
            operation_fence_digest,
            admission.fence.assignment().digest(),
            initial_attempt.workspace_assignment_digest(),
            creation.catalog(),
            creation.result_digest(),
            workspace_handle,
            initial_attempt.host_boot_id(),
            initial_attempt.host_mount_namespace_device(),
            initial_attempt.host_mount_namespace_inode(),
            *admission.effect.clock_provenance(),
            admission.effect.effect_deadline_boottime_nanoseconds(),
            initial_attempt.dataset_name().to_owned(),
            initial_attempt.dataset_guid(),
            initial_attempt.identity_range_start(),
            initial_attempt.identity_range_size(),
            None,
        )
        .unwrap();
        let receipt = broker
            .authority
            .seal_pin_attempt_receipt(
                &repair_attempt,
                &admission.effect,
                &admission.fence,
                repair_semantics.operation_id(),
                *repair_semantics.header().request_id(),
            )
            .unwrap();
        let repair_attempt = repair_attempt.with_authority_receipt(receipt).unwrap();
        let publication_record = broker
            .transactions
            .authority_record(
                RecordNamespace::StorageWorkspacePublicationIntent,
                &creation.operation_id(),
            )
            .unwrap()
            .unwrap();
        let initial_attempt_record = broker
            .transactions
            .workspace_pin_attempt_record(&initial_attempt)
            .unwrap();
        let repair_intent = StorageWorkspacePinRepairIntentV1::new_ambiguous(
            repair_semantics.operation_id(),
            &admission.effect,
            sealed.effect.clone(),
            admission.fence.assignment().digest(),
            operation_fence_digest,
            creation.operation_id(),
            creation.catalog(),
            creation.result_digest(),
            ObjectDigest::from_bytes(Sha256::digest(publication_record).into()),
            workspace_handle,
            initial_attempt.attempt_id(),
            initial_attempt.phase(),
            ObjectDigest::from_bytes(Sha256::digest(&initial_attempt_record).into()),
            repair_attempt.attempt_id(),
            repair_attempt.attempt_ordinal(),
        )
        .unwrap();
        let valid_pending_effect = sealed.effect.clone();
        broker
            .transactions
            .retain_workspace_pin_repair_for_test(
                [2; 16],
                repair_intent.clone(),
                repair_attempt.clone(),
                sealed.current_fence,
                sealed.effect,
                sealed.operation_fence,
            )
            .unwrap();
        drop(broker);

        let mut broker = coordinator(&directory, &fixture);
        broker.authenticate_workspace_pin_attempts().unwrap();
        let arbitrary_completed_effect = broker
            .authority
            .seal_effect_for_test(
                repair_semantics.header().request_id(),
                &admission.effect.clone().complete(vec![0xcc]).unwrap(),
            )
            .unwrap();
        let ambiguous_completed_directory = TempDir::new().unwrap();
        fs::copy(
            directory.path().join("storage-state.journal"),
            ambiguous_completed_directory
                .path()
                .join("storage-state.journal"),
        )
        .unwrap();
        let mut ambiguous_completed = coordinator(&ambiguous_completed_directory, &fixture);
        ambiguous_completed
            .transactions
            .put_authority_record_with_transaction_for_test(
                [0xbf; 16],
                RecordNamespace::Effect,
                repair_semantics.header().request_id(),
                arbitrary_completed_effect.clone(),
            );
        assert!(matches!(
            ambiguous_completed.authenticate_workspace_pin_attempts(),
            Err(ZfsHelperError::Authority)
        ));
        assert!(
            broker
                .workspace_pin_observation_dispatches()
                .unwrap()
                .is_empty()
        );
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let worker_catalog = broker
            .transactions
            .workspace_creation_catalog(&repair_intent)
            .unwrap();
        let repair_intent_record = broker
            .transactions
            .workspace_pin_repair_intent_record(&repair_intent)
            .unwrap();
        let repair_attempt_record = broker
            .transactions
            .workspace_pin_attempt_record(&repair_attempt)
            .unwrap();
        let publication_intent_record = broker
            .transactions
            .workspace_publication_intent_record(creation.operation_id())
            .unwrap();
        let current_fence = broker
            .transactions
            .authority_record(RecordNamespace::DesiredState, &[2; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        let operation_fence = broker
            .transactions
            .authority_record(
                RecordNamespace::AuthorityPublication,
                &repair_semantics.operation_id(),
            )
            .unwrap()
            .unwrap()
            .to_vec();
        let worker_authority = WorkspacePinWorkerAuthorityV1::new(
            *repair_semantics.header().request_id(),
            repair_attempt_record.clone(),
            current_fence.clone(),
            valid_pending_effect.clone(),
            operation_fence.clone(),
        )
        .unwrap();
        let worker_request =
            crate::workspace_repair_worker::WorkspacePinRepairWorkerRequestV1::new(
                contract.executable().to_path_buf(),
                worker_catalog.clone(),
                worker_authority,
                repair_intent_record.clone(),
                publication_intent_record.clone(),
            )
            .unwrap();
        let encoded_worker_request =
            crate::workspace_repair_worker::encode_request(&worker_request).unwrap();
        let authenticated_worker = crate::workspace_repair_worker::authenticate_request(
            &fixture.authority(),
            &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            &contract,
            crate::workspace_repair_worker::decode_request(&encoded_worker_request).unwrap(),
        )
        .unwrap();
        assert_eq!(authenticated_worker.attempt(), &repair_attempt);

        let stale_authority = WorkspacePinWorkerAuthorityV1::new(
            *repair_semantics.header().request_id(),
            repair_attempt_record.clone(),
            prior_fence.clone(),
            valid_pending_effect.clone(),
            operation_fence.clone(),
        )
        .unwrap();
        let stale_request = crate::workspace_repair_worker::WorkspacePinRepairWorkerRequestV1::new(
            contract.executable().to_path_buf(),
            worker_catalog.clone(),
            stale_authority,
            repair_intent_record.clone(),
            publication_intent_record.clone(),
        )
        .unwrap();
        assert!(
            crate::workspace_repair_worker::authenticate_request(
                &fixture.authority(),
                &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                &contract,
                stale_request,
            )
            .is_err()
        );

        let prior_attempt_authority = WorkspacePinWorkerAuthorityV1::new(
            *repair_semantics.header().request_id(),
            initial_attempt_record.clone(),
            current_fence.clone(),
            valid_pending_effect.clone(),
            operation_fence.clone(),
        )
        .unwrap();
        let prior_attempt_request =
            crate::workspace_repair_worker::WorkspacePinRepairWorkerRequestV1::new(
                contract.executable().to_path_buf(),
                worker_catalog.clone(),
                prior_attempt_authority,
                repair_intent_record.clone(),
                publication_intent_record.clone(),
            )
            .unwrap();
        assert!(
            crate::workspace_repair_worker::authenticate_request(
                &fixture.authority(),
                &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                &contract,
                prior_attempt_request,
            )
            .is_err()
        );

        let receipt_mismatched_attempt = repair_attempt
            .with_authority_receipt(vec![0xee; 32])
            .unwrap();
        let receipt_mismatched_attempt_record =
            crate::workspace_pin::attempt_record(&receipt_mismatched_attempt, [51; 16], &[52; 32])
                .unwrap()
                .value()
                .unwrap()
                .to_vec();
        let receipt_mismatched_authority = WorkspacePinWorkerAuthorityV1::new(
            *repair_semantics.header().request_id(),
            receipt_mismatched_attempt_record,
            current_fence.clone(),
            valid_pending_effect.clone(),
            operation_fence.clone(),
        )
        .unwrap();
        let receipt_mismatched_request =
            crate::workspace_repair_worker::WorkspacePinRepairWorkerRequestV1::new(
                contract.executable().to_path_buf(),
                worker_catalog.clone(),
                receipt_mismatched_authority,
                repair_intent_record.clone(),
                publication_intent_record.clone(),
            )
            .unwrap();
        assert!(
            crate::workspace_repair_worker::authenticate_request(
                &fixture.authority(),
                &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                &contract,
                receipt_mismatched_request,
            )
            .is_err()
        );

        let publication = broker
            .transactions
            .workspace_publication_intent(creation.operation_id())
            .unwrap()
            .unwrap();
        let substituted_publication =
            crate::workspace_catalog::StorageWorkspacePublicationIntentV1::from_authenticated_parts(
                publication.operation_id(),
                publication.request_catalog(),
                ObjectDigest::from_bytes([0xef; 32]),
                publication.root_image().clone(),
                publication.identity_range_start(),
                publication.identity_range_size(),
            )
            .unwrap();
        let substituted_publication = StorageStateKey::new([51; 16], [52; 32])
            .unwrap()
            .seal_workspace_publication_intent_for_test(&substituted_publication)
            .unwrap();
        let substituted_publication_authority = WorkspacePinWorkerAuthorityV1::new(
            *repair_semantics.header().request_id(),
            repair_attempt_record,
            current_fence,
            valid_pending_effect.clone(),
            operation_fence,
        )
        .unwrap();
        let substituted_publication_request =
            crate::workspace_repair_worker::WorkspacePinRepairWorkerRequestV1::new(
                contract.executable().to_path_buf(),
                worker_catalog,
                substituted_publication_authority,
                repair_intent_record,
                substituted_publication,
            )
            .unwrap();
        assert!(
            crate::workspace_repair_worker::authenticate_request(
                &fixture.authority(),
                &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                &contract,
                substituted_publication_request,
            )
            .is_err()
        );
        let cross_boot_scope = WorkspacePinHostScopeV1::new([0x91; 16], 0x92, 0x93).unwrap();
        let host_scope = WorkspacePinHostScopeV1::new(
            repair_attempt.host_boot_id(),
            repair_attempt.host_mount_namespace_device(),
            repair_attempt.host_mount_namespace_inode(),
        )
        .unwrap();
        let before_observation = broker.transactions.journal_sequence_for_test();
        let stale_dispatch = broker
            .workspace_pin_repair_observation_dispatches(&contract, cross_boot_scope)
            .unwrap()
            .pop()
            .unwrap();
        let stale_result = WorkspacePinRepairObserverResultV1::new(
            ObjectDigest::from_bytes([0xce; 32]),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_attempt.attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Absent,
                ObjectDigest::from_bytes([0xcd; 32]),
            ),
        );
        assert!(matches!(
            broker.complete_workspace_pin_repair_observation(stale_dispatch, stale_result),
            Err(ZfsHelperError::Authority)
        ));
        assert_eq!(
            broker.transactions.journal_sequence_for_test(),
            before_observation
        );

        let cross_boot_absent = broker
            .workspace_pin_repair_observation_dispatches(&contract, cross_boot_scope)
            .unwrap()
            .pop()
            .unwrap();
        let request_bytes = cross_boot_absent.request_bytes().unwrap();
        let authenticated_request = crate::workspace_repair_observer::authenticate_request(
            &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            &contract,
            crate::workspace_repair_observer::decode_request(&request_bytes).unwrap(),
            cross_boot_scope,
        )
        .unwrap();
        assert_eq!(
            authenticated_request.probe().digest(),
            cross_boot_absent.probe().digest()
        );
        for record in [
            crate::workspace_repair_observer::WorkspacePinRepairObserverRecordV1::RepairIntent,
            crate::workspace_repair_observer::WorkspacePinRepairObserverRecordV1::RepairAttempt,
            crate::workspace_repair_observer::WorkspacePinRepairObserverRecordV1::PublicationIntent,
        ] {
            let mut substituted =
                crate::workspace_repair_observer::decode_request(&request_bytes).unwrap();
            substituted.corrupt_record_for_test(record);
            assert!(matches!(
                crate::workspace_repair_observer::authenticate_request(
                    &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                    &contract,
                    substituted,
                    cross_boot_scope,
                ),
                Err(crate::ZfsWorkerError::Authority)
            ));
        }
        let mut wrong_catalog =
            crate::workspace_repair_observer::decode_request(&request_bytes).unwrap();
        wrong_catalog.replace_catalog_for_test(catalog(0x97, 30));
        assert!(matches!(
            crate::workspace_repair_observer::authenticate_request(
                &StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                &contract,
                wrong_catalog,
                cross_boot_scope,
            ),
            Err(crate::ZfsWorkerError::Authority)
        ));
        let cross_boot_absent_result = WorkspacePinRepairObserverResultV1::new(
            cross_boot_absent.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_attempt.attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Absent,
                ObjectDigest::from_bytes([0xcf; 32]),
            ),
        );
        assert_eq!(
            broker
                .complete_workspace_pin_repair_observation(
                    cross_boot_absent,
                    cross_boot_absent_result,
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
        );
        assert_eq!(
            broker.transactions.journal_sequence_for_test(),
            before_observation
        );

        let cross_boot_present = broker
            .workspace_pin_repair_observation_dispatches(&contract, cross_boot_scope)
            .unwrap()
            .pop()
            .unwrap();
        let cross_boot_proof = WorkspaceRootPinProofV1::new(
            cross_boot_scope.kernel_boot_id(),
            cross_boot_scope.mount_namespace_device(),
            cross_boot_scope.mount_namespace_inode(),
            0x94,
            "/".to_owned(),
            crate::workspace_pin::workspace_pin_path(&workspace_handle),
            "zfs".to_owned(),
            initial_attempt.dataset_name().to_owned(),
            11,
            0x95,
            0x96,
        )
        .unwrap();
        let cross_boot_present_result = WorkspacePinRepairObserverResultV1::new(
            cross_boot_present.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_attempt.attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Present(cross_boot_proof),
                ObjectDigest::from_bytes([0xd0; 32]),
            ),
        );
        assert!(matches!(
            broker.complete_workspace_pin_repair_observation(
                cross_boot_present,
                cross_boot_present_result,
            ),
            Err(ZfsHelperError::Authority)
        ));
        assert_eq!(
            broker.transactions.journal_sequence_for_test(),
            before_observation
        );

        let changed_directory = TempDir::new().unwrap();
        fs::copy(
            directory.path().join("storage-state.journal"),
            changed_directory.path().join("storage-state.journal"),
        )
        .unwrap();
        let mut changed = coordinator(&changed_directory, &fixture);
        let changed_dispatch = changed
            .workspace_pin_repair_observation_dispatches(&contract, host_scope)
            .unwrap()
            .pop()
            .unwrap();
        let changed_proof =
            workspace_pin_proof(workspace_handle, initial_attempt.dataset_name(), 11);
        changed
            .transactions
            .complete_workspace_pin_attempt(
                repair_attempt.attempt_id(),
                &crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                &crate::workspace_pin::WorkspacePinObservationV1::Present(changed_proof),
            )
            .unwrap();
        assert!(matches!(
            changed.authenticate_workspace_pin_attempts(),
            Err(ZfsHelperError::Authority)
        ));
        let after_history_change = changed.transactions.journal_sequence_for_test();
        let superseded_result = WorkspacePinRepairObserverResultV1::new(
            changed_dispatch.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_attempt.attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Absent,
                ObjectDigest::from_bytes([0xd1; 32]),
            ),
        );
        assert!(matches!(
            changed.complete_workspace_pin_repair_observation(changed_dispatch, superseded_result,),
            Err(ZfsHelperError::Authority)
        ));
        assert_eq!(
            changed.transactions.journal_sequence_for_test(),
            after_history_change
        );

        let completion_failure_directory = TempDir::new().unwrap();
        fs::copy(
            directory.path().join("storage-state.journal"),
            completion_failure_directory
                .path()
                .join("storage-state.journal"),
        )
        .unwrap();
        let mut completion_failure = coordinator(&completion_failure_directory, &fixture);
        let failure_dispatch = completion_failure
            .workspace_pin_repair_observation_dispatches(&contract, host_scope)
            .unwrap()
            .pop()
            .unwrap();
        let failure_result = WorkspacePinRepairObserverResultV1::new(
            failure_dispatch.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_attempt.attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Present(workspace_pin_proof(
                    workspace_handle,
                    initial_attempt.dataset_name(),
                    11,
                )),
                ObjectDigest::from_bytes([0xd2; 32]),
            ),
        );
        completion_failure
            .transactions
            .fail_after_next_journal_commit_for_test();
        assert!(
            completion_failure
                .complete_workspace_pin_repair_observation(failure_dispatch, failure_result)
                .is_err()
        );
        assert!(
            completion_failure
                .authenticate_workspace_pin_attempts()
                .is_err()
        );
        drop(completion_failure);
        let completion_failure = coordinator(&completion_failure_directory, &fixture);
        completion_failure
            .authenticate_workspace_pin_attempts()
            .unwrap();
        assert_eq!(
            completion_failure
                .transactions
                .latest_workspace_pin_attempt(creation.operation_id())
                .unwrap()
                .unwrap()
                .phase(),
            WorkspacePinAttemptPhaseV1::Satisfied
        );

        let mut dispatches = broker
            .workspace_pin_repair_observation_dispatches(&contract, host_scope)
            .unwrap();
        assert_eq!(dispatches.len(), 1);
        let dispatch = dispatches.pop().unwrap();
        let proof = workspace_pin_proof(workspace_handle, initial_attempt.dataset_name(), 11);
        let result = WorkspacePinRepairObserverResultV1::new(
            dispatch.probe().digest(),
            crate::pin_worker::WorkspacePinWorkerResultV1::new(
                repair_attempt.attempt_id(),
                crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                    name: initial_attempt.dataset_name().to_owned(),
                    guid: 11,
                },
                crate::workspace_pin::WorkspacePinObservationV1::Present(proof),
                ObjectDigest::from_bytes([0xd1; 32]),
            ),
        );
        assert_eq!(
            broker
                .complete_workspace_pin_repair_observation(dispatch, result)
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompletePublication
        );
        assert!(
            broker
                .workspace_pin_repair_observation_dispatches(&contract, host_scope)
                .unwrap()
                .is_empty()
        );
        let valid_completed_effect = broker
            .transactions
            .authority_record(
                RecordNamespace::Effect,
                repair_semantics.header().request_id(),
            )
            .unwrap()
            .unwrap()
            .to_vec();
        drop(broker);

        let mut broker = coordinator(&directory, &fixture);
        broker.authenticate_workspace_pin_attempts().unwrap();
        broker
            .transactions
            .put_authority_record_with_transaction_for_test(
                [0xc0; 16],
                RecordNamespace::Effect,
                repair_semantics.header().request_id(),
                arbitrary_completed_effect,
            );
        assert!(matches!(
            broker.authenticate_workspace_pin_attempts(),
            Err(ZfsHelperError::Authority)
        ));

        let alternate_transport = reverse_length_delimited_fields(&repair_request_bytes);
        assert_ne!(alternate_transport, repair_request_bytes);
        let alternate_semantics = CanonicalStorageRepairSemanticsV1::decode(
            &alternate_transport,
            peer(),
            peer_policy(),
            clock().boottime_nanoseconds(),
        )
        .unwrap();
        assert_eq!(
            alternate_semantics.argument_commitment(),
            repair_semantics.argument_commitment()
        );
        let wrong_semantic = repair_request(80, 82, workspace_handle, 6, repair_assignment_digest);
        let wrong_target = repair_request(80, 81, [0x83; 32], 6, repair_assignment_digest);
        let wrong_assignment = repair_request(
            80,
            81,
            workspace_handle,
            7,
            ObjectDigest::from_bytes([0x84; 32]),
        );
        let mut wrong_live_effects = Vec::new();
        for (case, wrong_request) in [
            ("transport", alternate_transport),
            ("semantic", wrong_semantic),
            ("target", wrong_target),
            ("assignment", wrong_assignment),
        ] {
            let wrong_semantics = CanonicalStorageRepairSemanticsV1::decode(
                &wrong_request,
                peer(),
                peer_policy(),
                clock().boottime_nanoseconds(),
            )
            .unwrap();
            let wrong_artifacts = fixture.repair_artifacts(&wrong_request);
            let wrong_admission = broker
                .authority
                .admit_workspace_pin_repair(
                    &wrong_artifacts,
                    &wrong_semantics,
                    &wrong_request,
                    ProtocolVersion::new(1, 4),
                    &clock(),
                    None,
                )
                .unwrap();
            let wrong_live_effect = broker
                .authority
                .seal(
                    &[2; 16],
                    repair_semantics.header().request_id(),
                    &repair_semantics.operation_id(),
                    &wrong_admission,
                )
                .unwrap()
                .effect;
            wrong_live_effects.push(wrong_live_effect.clone());
            let transaction_marker = 0xc1 + u8::try_from(wrong_live_effects.len()).unwrap();
            broker
                .transactions
                .put_authority_record_with_transaction_for_test(
                    [transaction_marker; 16],
                    RecordNamespace::Effect,
                    repair_semantics.header().request_id(),
                    wrong_live_effect,
                );
            assert!(
                matches!(
                    broker.authenticate_workspace_pin_attempts(),
                    Err(ZfsHelperError::Authority)
                ),
                "correctly resealed {case} drift was accepted"
            );
        }

        broker
            .transactions
            .put_authority_record_with_transaction_for_test(
                [0xc6; 16],
                RecordNamespace::Effect,
                repair_semantics.header().request_id(),
                valid_pending_effect,
            );
        assert!(matches!(
            broker.authenticate_workspace_pin_attempts(),
            Err(ZfsHelperError::Authority)
        ));
        broker
            .transactions
            .put_authority_record_with_transaction_for_test(
                [0xc7; 16],
                RecordNamespace::Effect,
                repair_semantics.header().request_id(),
                valid_completed_effect,
            );
        broker.authenticate_workspace_pin_attempts().unwrap();

        let retained_directory = TempDir::new().unwrap();
        fs::copy(
            directory.path().join("storage-state.journal"),
            retained_directory.path().join("storage-state.journal"),
        )
        .unwrap();
        let mut retained = coordinator(&retained_directory, &fixture);
        let wrong_retained_intent = StorageWorkspacePinRepairIntentV1::new_for_test(
            repair_intent.repair_operation_id(),
            repair_intent.request_id(),
            repair_intent.request_digest(),
            repair_intent.semantic_commitment(),
            repair_intent.repair_assignment_digest(),
            wrong_live_effects.remove(0),
            repair_intent.operation_fence_digest(),
            repair_intent.creation_operation_id(),
            repair_intent.creation_result_catalog(),
            repair_intent.creation_result_digest(),
            repair_intent.publication_intent_record_digest(),
            repair_intent.workspace_handle(),
            repair_intent.latest_ensure_attempt_id(),
            repair_intent.latest_ensure_phase(),
            repair_intent.latest_ensure_attempt_record_digest(),
            repair_intent.repair_attempt_id(),
            repair_intent.repair_attempt_ordinal(),
        )
        .unwrap();
        retained
            .transactions
            .replace_workspace_pin_repair_intent_for_test([0xd8; 16], wrong_retained_intent)
            .unwrap();
        drop(retained);

        let retained = coordinator(&retained_directory, &fixture);
        assert!(matches!(
            retained.authenticate_workspace_pin_attempts(),
            Err(ZfsHelperError::Authority)
        ));
    }

    #[test]
    fn fixed_worker_independently_authenticates_current_ensure_dispatch() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (_coordinator, dispatch, result) = workspace_pin_ensure_dispatch(&directory, &fixture);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let bytes = dispatch.worker_request_bytes(&contract).unwrap();
        let decoded = crate::pin_worker::decode_request(&bytes).unwrap();
        let state_key = StorageStateKey::new([51; 16], [52; 32]).unwrap();

        assert_eq!(decoded.catalog.generation(), 9);
        assert_eq!(
            dispatch.attempt().creation_result_catalog(),
            result.catalog()
        );
        assert_eq!(result.catalog().generation(), 10);
        assert_eq!(
            decoded.catalog.generation().checked_add(1),
            Some(result.catalog().generation())
        );
        assert_ne!(
            result.catalog().digest(),
            decoded.catalog.binding().digest()
        );

        let authenticated = crate::pin_worker::authenticate_request(
            &fixture.authority(),
            &state_key,
            &contract,
            decoded,
        )
        .unwrap();

        assert_eq!(authenticated.attempt(), dispatch.attempt());
        assert_eq!(
            authenticated.attempt().workspace_handle(),
            result.storage_handle().unwrap()
        );
        crate::pin_worker::check_before_effect(&fixture.authority(), &authenticated, &mut || {
            Ok(clock())
        })
        .unwrap();
    }

    #[test]
    fn historical_observer_authenticates_superseded_ambiguous_attempt_without_effect_authority() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (mut broker, _dispatch, _result) = workspace_pin_ensure_dispatch(&directory, &fixture);
        let superseding_catalog = catalog(8, 9);
        let superseding_request = request_with_generation(9, 8, 6);
        let superseding_artifacts = fixture.artifacts(
            &superseding_request,
            &superseding_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let superseding_semantics = decode_resolved(
            &superseding_request,
            &superseding_catalog,
            peer(),
            peer_policy(),
            100,
        )
        .unwrap();
        let prior_fence = broker
            .transactions
            .authority_record(RecordNamespace::DesiredState, &[2; 16])
            .unwrap()
            .unwrap()
            .to_vec();
        let superseding_admission = broker
            .authority
            .admit(
                &superseding_artifacts,
                &superseding_semantics,
                &superseding_request,
                ProtocolVersion::new(1, 3),
                &clock(),
                Some(&prior_fence),
            )
            .unwrap();
        let superseding_sealed = broker
            .authority
            .seal(&[2; 16], &[9; 16], &[9; 16], &superseding_admission)
            .unwrap();
        broker.transactions.put_authority_record_for_test(
            RecordNamespace::DesiredState,
            &[2; 16],
            superseding_sealed.current_fence,
        );

        let observations = broker.workspace_pin_observation_dispatches().unwrap();
        assert_eq!(observations.len(), 1);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let bytes = observations[0].request_bytes(&contract).unwrap();
        let state_key = StorageStateKey::new([51; 16], [52; 32]).unwrap();

        crate::pin_worker::authenticate_observation_request(
            &fixture.authority(),
            &state_key,
            &contract,
            crate::pin_worker::decode_request(&bytes).unwrap(),
        )
        .unwrap();
        assert!(
            crate::pin_worker::authenticate_request(
                &fixture.authority(),
                &state_key,
                &contract,
                crate::pin_worker::decode_request(&bytes).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_worker_independently_authenticates_current_remove_dispatch() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (_coordinator, dispatch, creation) =
            workspace_pin_remove_dispatch(&directory, &fixture);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let bytes = dispatch.worker_request_bytes(&contract).unwrap();
        let decoded = crate::pin_worker::decode_request(&bytes).unwrap();
        let state_key = StorageStateKey::new([51; 16], [52; 32]).unwrap();

        assert_eq!(decoded.catalog.generation(), 11);
        assert_eq!(
            dispatch.attempt().creation_result_catalog(),
            creation.catalog()
        );
        assert!(
            decoded.catalog.generation()
                > dispatch.attempt().creation_result_catalog().generation()
        );

        let authenticated = crate::pin_worker::authenticate_request(
            &fixture.authority(),
            &state_key,
            &contract,
            decoded,
        )
        .unwrap();

        assert_eq!(authenticated.attempt(), dispatch.attempt());
        assert_eq!(
            authenticated.attempt().workspace_handle(),
            creation.storage_handle().unwrap()
        );
        crate::pin_worker::check_before_effect(&fixture.authority(), &authenticated, &mut || {
            Ok(clock())
        })
        .unwrap();
    }

    #[test]
    fn managed_workspace_without_satisfied_pin_never_falls_through_to_generic_destroy() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (mut coordinator, _ensure, creation) =
            workspace_pin_ensure_dispatch(&directory, &fixture);
        let workspace_handle = creation.storage_handle().unwrap();
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest_at(&spec, 6);
        let request = destroy_request(8, workspace_handle, manifest.digest());
        let catalog = destroy_catalog(workspace_handle, 11);
        let expected_head = coordinator.transactions.catalog_head_binding().unwrap();
        let artifacts = fixture.artifacts_at_head(&request, &catalog, expected_head, 300);
        prepare_for_apply(&mut coordinator, &request, &artifacts, &catalog, &clock());
        let StorageAdmissionOutcome::Prepared { .. } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("workspace destruction was not prepared")
        };
        let executions = Rc::new(Cell::new(0));
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            CountingBackend {
                executions: Rc::clone(&executions),
            },
        );
        let prepared = coordinator.preobserve(&mut helper, [8; 16]).unwrap();

        assert!(matches!(
            coordinator
                .workspace_remove_pin_requirement(&prepared)
                .unwrap(),
            WorkspaceRemovePinRequirementV1::Missing
        ));
        assert_eq!(executions.get(), 0);
    }

    #[test]
    fn committed_destroy_with_ambiguous_pin_recovers_observation_only() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (mut broker, dispatch, _creation) = workspace_pin_remove_dispatch(&directory, &fixture);
        let attempt_id = dispatch.attempt().attempt_id();
        let (attempt, prepared) = dispatch.into_parts();
        let transaction =
            ZfsTransaction::from_catalog(prepared.operation(), prepared.catalog()).unwrap();
        let entry = prepared.entry();
        broker
            .transactions
            .commit_observed(
                entry.operation_id(),
                entry.mutation_digest(),
                prepared.catalog(),
                transaction.postcondition(),
                None,
                ObjectDigest::from_bytes([93; 32]),
            )
            .unwrap();
        assert_eq!(attempt.attempt_id(), attempt_id);
        drop(broker);

        let mut recovered = coordinator(&directory, &fixture);
        recovered.authenticate_workspace_pin_attempts().unwrap();
        assert_eq!(
            recovered.transactions.phase([8; 16]).unwrap(),
            Some(DurableStoragePhase::Committed)
        );
        let recovered_attempt = recovered
            .transactions
            .workspace_pin_attempts()
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.attempt_id() == attempt_id)
            .unwrap();
        assert_eq!(
            recovered_attempt.phase(),
            WorkspacePinAttemptPhaseV1::Ambiguous
        );
        let observation_dispatches = recovered.workspace_pin_observation_dispatches().unwrap();
        assert_eq!(observation_dispatches.len(), 1);
        assert_eq!(observation_dispatches[0].attempt(), &recovered_attempt);
        let observation = crate::pin_worker::WorkspacePinWorkerResultV1::new(
            attempt_id,
            crate::workspace_pin::WorkspaceDatasetObservationV1::Absent,
            crate::workspace_pin::WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([94; 32]),
        );
        assert_eq!(
            recovered
                .complete_workspace_pin_observation(&recovered_attempt, &observation)
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompleteRetirement
        );
        assert!(matches!(
            recovered.workspace_projection().unwrap().as_slice(),
            [StorageWorkspaceCatalogActionV1::Retire { .. }]
        ));
    }

    #[test]
    fn fixed_worker_rejects_each_substituted_authority_record_and_context() {
        use crate::pin_worker::WorkspacePinWorkerAuthorityRecord;

        let fixture = Fixture::new();
        let ensure_directory = TempDir::new().unwrap();
        let remove_directory = TempDir::new().unwrap();
        let (_ensure_coordinator, ensure, _) =
            workspace_pin_ensure_dispatch(&ensure_directory, &fixture);
        let (_remove_coordinator, remove, _) =
            workspace_pin_remove_dispatch(&remove_directory, &fixture);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let ensure_bytes = ensure.worker_request_bytes(&contract).unwrap();
        let remove_bytes = remove.worker_request_bytes(&contract).unwrap();
        let donor = crate::pin_worker::decode_request(&remove_bytes).unwrap();
        let state_key = StorageStateKey::new([51; 16], [52; 32]).unwrap();

        for record in [
            WorkspacePinWorkerAuthorityRecord::ParentRequest,
            WorkspacePinWorkerAuthorityRecord::Attempt,
            WorkspacePinWorkerAuthorityRecord::CurrentFence,
            WorkspacePinWorkerAuthorityRecord::Effect,
            WorkspacePinWorkerAuthorityRecord::OperationFence,
        ] {
            let mut substituted = crate::pin_worker::decode_request(&ensure_bytes).unwrap();
            substituted
                .authority
                .substitute_record_from(record, &donor.authority);

            assert!(matches!(
                crate::pin_worker::authenticate_request(
                    &fixture.authority(),
                    &state_key,
                    &contract,
                    substituted,
                ),
                Err(crate::ZfsWorkerError::Authority)
            ));
        }

        let mut substituted_catalog = crate::pin_worker::decode_request(&ensure_bytes).unwrap();
        substituted_catalog.catalog = donor.catalog;
        assert!(matches!(
            crate::pin_worker::authenticate_request(
                &fixture.authority(),
                &state_key,
                &contract,
                substituted_catalog,
            ),
            Err(crate::ZfsWorkerError::Authority)
        ));

        let mut substituted_executable = crate::pin_worker::decode_request(&ensure_bytes).unwrap();
        substituted_executable.executable = "/nix/store/substituted-zfs/sbin/zfs".into();
        assert!(matches!(
            crate::pin_worker::authenticate_request(
                &fixture.authority(),
                &state_key,
                &contract,
                substituted_executable,
            ),
            Err(crate::ZfsWorkerError::Authority)
        ));
    }

    #[test]
    fn fixed_worker_rechecks_the_protected_clock_immediately_before_effect() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (_coordinator, dispatch, _) = workspace_pin_ensure_dispatch(&directory, &fixture);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let request =
            crate::pin_worker::decode_request(&dispatch.worker_request_bytes(&contract).unwrap())
                .unwrap();
        let state_key = StorageStateKey::new([51; 16], [52; 32]).unwrap();
        let authenticated = crate::pin_worker::authenticate_request(
            &fixture.authority(),
            &state_key,
            &contract,
            request,
        )
        .unwrap();
        let expired = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            authenticated.effect_deadline_boottime_nanoseconds(),
        )
        .unwrap();

        assert!(matches!(
            crate::pin_worker::check_before_effect(
                &fixture.authority(),
                &authenticated,
                &mut || Ok(expired),
            ),
            Err(crate::ZfsWorkerError::Authority)
        ));
    }

    #[test]
    fn pin_attempt_receipt_round_trips_and_rejects_tamper_relocation_and_expiry() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let spec = sandbox_spec(72);
        let manifest = assignment_manifest(&spec);
        let request = create_request(7, manifest.digest());
        let catalog = create_catalog(9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        let StorageAdmissionOutcome::Prepared { mutation_digest } = broker
            .admit_workspace_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
                65_536,
                &manifest,
                &spec,
            )
            .unwrap()
        else {
            panic!("new workspace creation was not prepared")
        };
        broker
            .transactions
            .mark_mutation_ambiguous([7; 16], mutation_digest)
            .unwrap();
        let result = broker
            .transactions
            .commit_observed(
                [7; 16],
                mutation_digest,
                &catalog,
                &catalog.plan().postcondition(),
                Some(91),
                ObjectDigest::from_bytes([62; 32]),
            )
            .unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
        let AuthorizedWorkspacePinAttemptV1::Dispatch(dispatch) = broker
            .begin_workspace_pin_ensure(result, host_scope, &mut || Ok(clock()))
            .unwrap()
        else {
            panic!("fresh pin authority did not produce one dispatch")
        };
        let attempt = dispatch.attempt().clone();
        let entry = broker
            .transactions
            .committed_recovery_entry(result)
            .unwrap();
        let (_, effect) = broker.persisted_effect_context(entry).unwrap();
        broker
            .authority
            .verify_pin_attempt_receipt(&attempt, &effect, entry.operation_id())
            .unwrap();

        let mut tampered_receipt = attempt.authority_receipt().to_vec();
        tampered_receipt[0] ^= 0xff;
        let tampered = attempt.with_authority_receipt(tampered_receipt).unwrap();
        assert!(
            broker
                .authority
                .verify_pin_attempt_receipt(&tampered, &effect, entry.operation_id())
                .is_err()
        );
        assert!(
            broker
                .authority
                .verify_pin_attempt_receipt(&attempt, &effect, [99; 16])
                .is_err()
        );
        drop(broker);

        let recovered = coordinator(&directory, &fixture);
        recovered.authenticate_workspace_pin_attempts().unwrap();
        let recovered_attempts = recovered.transactions.workspace_pin_attempts().unwrap();
        assert_eq!(recovered_attempts, vec![attempt]);

        let expired_directory = TempDir::new().unwrap();
        let mut expired_broker = initialized_coordinator(&expired_directory, &fixture, &catalog);
        prepare_for_apply(
            &mut expired_broker,
            &request,
            &artifacts,
            &catalog,
            &clock(),
        );
        let StorageAdmissionOutcome::Prepared { mutation_digest } = expired_broker
            .admit_workspace_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
                65_536,
                &manifest,
                &spec,
            )
            .unwrap()
        else {
            panic!("expiry fixture was not prepared")
        };
        expired_broker
            .transactions
            .mark_mutation_ambiguous([7; 16], mutation_digest)
            .unwrap();
        let expired_result = expired_broker
            .transactions
            .commit_observed(
                [7; 16],
                mutation_digest,
                &catalog,
                &catalog.plan().postcondition(),
                Some(91),
                ObjectDigest::from_bytes([62; 32]),
            )
            .unwrap();
        let expired_sample = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            200,
        )
        .unwrap();
        let mut samples = 0;
        assert!(matches!(
            expired_broker.begin_workspace_pin_ensure(expired_result, host_scope, &mut || {
                samples += 1;
                if samples == 1 {
                    Ok(clock())
                } else {
                    Ok(expired_sample)
                }
            },),
            Err(ZfsHelperError::Authority)
        ));
        assert_eq!(samples, 2);
        let expired_attempts = expired_broker
            .transactions
            .workspace_pin_attempts()
            .unwrap();
        assert_eq!(expired_attempts.len(), 1);
        assert_eq!(
            expired_attempts[0].phase(),
            crate::workspace_pin::WorkspacePinAttemptPhaseV1::Ambiguous
        );
    }

    #[test]
    fn substitutions_and_invalid_authority_fail_closed() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let original_request = request(7, 8);
        let original_catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &original_request,
            &original_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &original_catalog);
        prepare_for_apply(
            &mut broker,
            &original_request,
            &artifacts,
            &original_catalog,
            &clock(),
        );
        broker
            .admit_apply_intent(
                &original_request,
                &artifacts,
                &original_catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(
            broker
                .admit_apply_intent(
                    &request(9, 8),
                    &artifacts,
                    &original_catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );
        assert!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &artifacts,
                    &catalog(9, 10),
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );

        let expired = fixture.artifacts(
            &original_request,
            &original_catalog,
            140,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        assert!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &expired,
                    &original_catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );
        let wrong = fixture.artifacts(
            &original_request,
            &original_catalog,
            300,
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
        );
        assert!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &wrong,
                    &original_catalog,
                    ProtocolVersion::new(1, 3),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );
    }

    #[test]
    fn missing_link_after_recovery_is_rejected() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &request, &artifacts, &catalog, &clock());
        broker
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        broker
            .transactions
            .remove_authority_record_for_test(RecordNamespace::Effect, &[7; 16]);
        drop(broker);
        let mut recovered = coordinator(&directory, &fixture);
        assert!(matches!(
            recovered.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock()
            ),
            Err(StorageBrokerError::Authority)
        ));
    }

    #[test]
    fn cross_linked_intent_cannot_be_sealed_for_another_request() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let original = request(7, 8);
        let substituted = request(9, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts_authorizing(
            &original,
            &catalog,
            &[&original, &substituted],
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = initialized_coordinator(&directory, &fixture, &catalog);
        prepare_for_apply(&mut broker, &original, &artifacts, &catalog, &clock());
        broker
            .admit_apply_intent(
                &original,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 3),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();

        let semantics =
            decode_resolved(&substituted, &catalog, peer(), peer_policy(), 100).unwrap();
        let admission = broker
            .authority
            .admit(
                &artifacts,
                &semantics,
                &substituted,
                ProtocolVersion::new(1, 3),
                &clock(),
                broker
                    .transactions
                    .authority_record(RecordNamespace::DesiredState, &[2; 16])
                    .unwrap(),
            )
            .unwrap();
        assert!(
            broker
                .authority
                .seal(&[2; 16], &[7; 16], &[9; 16], &admission)
                .is_err()
        );
    }

    #[test]
    fn apply_is_never_advertised_without_complete_effect_readiness() {
        assert!(advertised_storage_methods(false).is_empty());
        assert_eq!(
            advertised_storage_methods(true),
            [BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY]
        );
        assert!(
            !advertised_storage_methods(true).contains(&BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
        );
    }
}
