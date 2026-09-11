//! Crash-recoverable network preparation coordinator.
//!
//! The coordinator validates portable PREPARE semantics, requires an opaque
//! protected-catalog token, verifies signed Network authority, and atomically
//! journals linked operation records. An admitted preparation must cross the
//! durable Ambiguous boundary before the fixed one-shot worker attempts its
//! effect, and the preparation finalizer commits only after two matching typed
//! observations. This coordinator rejects existing-resource actions; the
//! separate lifecycle coordinator admits them but does not execute their
//! effects. Public Apply remains unadvertised, while authoritative inventory is
//! independently available through the read-only service.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::RecordNamespace;
use aos_sandbox_broker::BrokerEffectClockDispositionV1;
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use sha2::{Digest as _, Sha256};

use crate::NetworkKernelPlanV1;
use crate::authorization::{
    NetworkAdmissionError, NetworkAuthorityV1, decode_assignment, decode_request_id,
};
use crate::catalog::{AuthenticatedNetworkPreparationV1, ResolvedNetworkPreparationV1};
use crate::lifecycle_state::{
    AmbiguousNetworkLifecycleDispatchV1, CommittedNetworkLifecycleResultV1,
    DurableNetworkLifecyclePhase, NetworkLifecycleBeginOutcome, NetworkLifecycleStateError,
    NetworkLifecycleStateStore, PreparedNetworkLifecycleRecordInput, prepared_lifecycle_record,
};
use crate::lifecycle_worker_protocol::{
    NetworkLifecycleWorkerDispatchV1, issue_lifecycle_dispatch,
};
use crate::namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceLifecycleAuthorityV1, NetworkNamespaceLifecycleTransitionV1,
    NetworkNamespaceObservedStateKindV1, NetworkNamespaceObservedStateV1,
    NetworkNamespacePublicationV1,
};
use crate::preparation_catalog::{NetworkPreparationCatalogError, NetworkPreparationCatalogV1};
#[cfg(test)]
use crate::state::{AmbiguousNetworkDispatchV1, NetworkRecoveryEntry};
use crate::state::{
    CommittedNetworkResultV1, DurableNetworkPhase, NetworkBeginOutcome, NetworkNamespaceCustodyV1,
    NetworkStateError, NetworkStateStore, PreparedNetworkRecordInput, VerifiedNetworkResultV1,
    prepared_record,
};
#[cfg(test)]
use crate::worker_protocol::issue_prepare_dispatch;
use crate::worker_protocol::{
    NetworkPrepareWorkerDispatchV1, NetworkWorkerProtocolError, kernel_plan_matches_catalog,
    prevalidate_prepare_dispatch,
};
use crate::worker_runtime::RecoveredNetworkPreparationObservation;

/// Reports fail-closed network admission failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkBrokerError {
    /// Hostile request bytes or local catalog association failed.
    #[error("network request or catalog resolution was rejected")]
    Request,
    /// Protected signed plan, lease, or fence validation failed.
    #[error("network authority was rejected")]
    Authority,
    /// Durable admission state was corrupt, conflicting, or unavailable.
    #[error("network durable admission failed: {0}")]
    State(#[from] NetworkStateError),
    /// Existing-handle durable admission was corrupt, conflicting, or unavailable.
    #[error("network lifecycle durable admission failed: {0}")]
    LifecycleState(#[from] NetworkLifecycleStateError),
    /// Protected preparation history no longer reproduces committed state.
    #[error("network preparation catalog rejected committed state: {0}")]
    PreparationCatalog(#[from] NetworkPreparationCatalogError),
    /// A committed observation cannot form a current namespace publication.
    #[error("network namespace publication was rejected: {0}")]
    NamespaceCatalog(#[from] NetworkNamespaceCatalogError),
    /// The exact durable effect could not form an authenticated worker request.
    #[error("network worker dispatch was rejected: {0}")]
    WorkerProtocol(#[from] NetworkWorkerProtocolError),
}

/// Classifies durable admission without implying an executable effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAdmissionOutcome {
    /// Exact signed authority and intent were durably prepared.
    Prepared {
        /// Deterministic identity of the one-shot preparation effect.
        effect_digest: ObjectDigest,
    },
    /// The same effect is unfinished and must only be observed.
    ObserveOnly {
        /// Current durable crash phase.
        phase: DurableNetworkPhase,
        /// Deterministic identity of the one-shot preparation effect.
        effect_digest: ObjectDigest,
    },
    /// The exact expired intent was durably retired before effect authority.
    Aborted {
        /// Deterministic identity of the retired preparation effect.
        effect_digest: ObjectDigest,
    },
    /// The exact request already committed and returns its prior result.
    Replay(CommittedNetworkResultV1),
}

/// Classifies one fully prevalidated preparation execution decision.
#[derive(Debug, Eq, PartialEq)]
pub enum NetworkPrepareExecutionOutcomeV1 {
    /// The exact Prepared row became Ambiguous and released one worker request.
    Dispatch(Box<NetworkPrepareWorkerDispatchV1>),
    /// The exact expired Prepared row became an authenticated Aborted tombstone.
    Aborted {
        /// Deterministic identity of the retired preparation effect.
        effect_digest: ObjectDigest,
    },
}

/// Classifies durable existing-handle admission without executing an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkLifecycleAdmissionOutcome {
    /// Exact signed authority and current-resource intent were prepared.
    Prepared {
        /// Deterministic identity of the lifecycle effect.
        effect_digest: ObjectDigest,
    },
    /// The same lifecycle effect is unfinished and may only be observed.
    ObserveOnly {
        /// Current durable crash phase.
        phase: DurableNetworkLifecyclePhase,
        /// Deterministic identity of the lifecycle effect.
        effect_digest: ObjectDigest,
    },
    /// The exact request already committed and returns its prior result.
    Replay(CommittedNetworkLifecycleResultV1),
}

/// Authorizes construction of one first and only preparation-worker request.
///
/// This non-clone value exists only in memory after the exact synchronous
/// `Prepared -> Ambiguous` journal transition. Recovery deliberately cannot
/// reconstruct it, so an ambiguous operation is observation/cleanup-only.
#[cfg(test)]
#[must_use]
pub(crate) struct NetworkEffectDispatchPermitV1 {
    durable: AmbiguousNetworkDispatchV1,
}

/// Authorizes construction of one first lifecycle-worker request.
///
/// This value exists only after the synchronous `Prepared -> Ambiguous`
/// transition. Recovery exposes only observation data and cannot recreate it.
#[must_use]
pub struct NetworkLifecycleEffectDispatchPermitV1 {
    durable: AmbiguousNetworkLifecycleDispatchV1,
}

/// Serializes protected network authority and durable preparation state.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "focused creation-journal tests use subsets of this test harness"
)]
pub(crate) struct NetworkAdmissionCoordinator {
    authority: NetworkAuthorityV1,
    state: NetworkStateStore,
}

#[cfg(test)]
impl NetworkAdmissionCoordinator {
    /// Constructs a creation-only coordinator for focused in-crate tests.
    #[must_use]
    pub(crate) const fn new(authority: NetworkAuthorityV1, state: NetworkStateStore) -> Self {
        Self { authority, state }
    }

    /// Verifies and journals an unadvertised Apply intent without executing it.
    ///
    /// Preparation accepts only an opaque token from the protected preparation
    /// catalog. Existing-resource actions are categorically rejected, and this
    /// coordinator does not invoke a privileged kernel helper.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] for hostile bytes, resolution-shape or
    /// boot mismatch, signed authority failure, or durable-state conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &AuthenticatedNetworkPreparationV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
        let assignment =
            decode_assignment(request_body).map_err(|_| NetworkBrokerError::Request)?;
        let sandbox_id = *assignment.sandbox().as_bytes();
        let prior_fence = self
            .state
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .map(<[u8]>::to_vec);
        admit_apply_intent_with_prior(
            &self.authority,
            &mut self.state,
            request_body,
            artifacts,
            catalog,
            protocol_version,
            peer,
            policy,
            current_clock,
            prior_fence.as_deref(),
        )
    }

    /// Durably crosses the point after which a preparation may have run.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the exact prepared request
    /// and effect digest are current.
    pub fn mark_effect_ambiguous(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<NetworkEffectDispatchPermitV1, NetworkBrokerError> {
        let durable =
            self.state
                .mark_effect_ambiguous(&self.authority, request_id, effect_digest)?;
        Ok(NetworkEffectDispatchPermitV1 { durable })
    }

    /// Consumes a fresh ambiguity-transition permit into one worker request.
    ///
    /// The supplied canonical plan must reproduce the exact durable request,
    /// assignment, protected preparation, and effect identity. Losing either
    /// this permit or the resulting request never permits reconstruction from
    /// recovered ambiguous state.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::WorkerProtocol`] when any request, plan,
    /// catalog, fence, or effect relationship differs.
    pub fn issue_prepare_worker_dispatch(
        &self,
        permit: NetworkEffectDispatchPermitV1,
        request_body: &[u8],
        kernel_plan: NetworkKernelPlanV1,
    ) -> Result<NetworkPrepareWorkerDispatchV1, NetworkBrokerError> {
        issue_prepare_dispatch(&self.authority, permit.durable, request_body, kernel_plan)
            .map_err(Into::into)
    }

    /// Durably binds an ambiguous preparation to its READY namespace.
    ///
    /// The caller must complete this journal transition and then obtain an
    /// exact confirmed [`crate::SystemdNetworkNamespaceStore`] readback before
    /// transferring the first effect frame. Repeating the exact binding is
    /// idempotent; substituting any identity is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the request, effect,
    /// reserved handle, current boot, and physical namespace identify the
    /// exact current ambiguous operation.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_effect_namespace_custody(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        network_handle: [u8; 32],
        kernel_boot_id: [u8; 16],
        namespace_device: u64,
        namespace_inode: u64,
        kernel_plan_digest: ObjectDigest,
    ) -> Result<NetworkNamespaceCustodyV1, NetworkBrokerError> {
        self.state
            .bind_namespace_custody(
                &self.authority,
                request_id,
                effect_digest,
                network_handle,
                kernel_boot_id,
                namespace_device,
                namespace_inode,
                kernel_plan_digest,
            )
            .map_err(Into::into)
    }

    /// Commits one verified current-boot namespace observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the assertion exactly
    /// matches the ambiguous durable effect and a unique physical namespace.
    pub fn commit_verified(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        verified: VerifiedNetworkResultV1,
    ) -> Result<CommittedNetworkResultV1, NetworkBrokerError> {
        self.state
            .commit_verified(&self.authority, request_id, effect_digest, verified)
            .map_err(Into::into)
    }

    /// Reconstructs the exact protected preparation for a recovery entry.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] when the entry no longer names
    /// the exact current record.
    pub fn recover_preparation(
        &self,
        entry: &NetworkRecoveryEntry,
    ) -> Result<ResolvedNetworkPreparationV1, NetworkBrokerError> {
        self.state.recover_preparation(entry).map_err(Into::into)
    }

    /// Returns bounded authenticated durable history for recovery.
    ///
    /// This is not current kernel inventory or readiness evidence.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] when an indeterminate commit has
    /// poisoned the creation journal's authenticated materialized view.
    pub fn recovery_snapshot(
        &self,
    ) -> Result<crate::state::NetworkRecoverySnapshotV1, NetworkBrokerError> {
        self.state.recovery_snapshot().map_err(Into::into)
    }
}

#[allow(clippy::too_many_arguments)]
fn admit_apply_intent_with_prior(
    authority: &NetworkAuthorityV1,
    state: &mut NetworkStateStore,
    request_body: &[u8],
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    catalog: &AuthenticatedNetworkPreparationV1,
    protocol_version: ProtocolVersion,
    peer: PeerCredentials,
    policy: PeerPolicy,
    current_clock: &RawPairedClockSample,
    prior_fence: Option<&[u8]>,
) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
    let assignment = decode_assignment(request_body).map_err(|_| NetworkBrokerError::Request)?;
    let catalog = authority
        .validate_catalog(catalog, assignment)
        .map_err(|_| NetworkBrokerError::Authority)?;
    let sandbox_id = *assignment.sandbox().as_bytes();
    let request_id = decode_request_id(request_body).map_err(|_| NetworkBrokerError::Request)?;
    let transport_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
    if let Some(effect_digest) =
        state.replay_aborted(request_id, sandbox_id, transport_digest, catalog)?
    {
        return Ok(NetworkAdmissionOutcome::Aborted { effect_digest });
    }

    let semantics = CanonicalNetworkSemanticsV1::decode(
        request_body,
        peer,
        policy,
        current_clock.boottime_nanoseconds(),
    )
    .map_err(|_| NetworkBrokerError::Request)?;
    validate_catalog(&semantics, catalog)?;

    let admission = authority
        .admit(
            artifacts,
            &semantics,
            request_body,
            protocol_version,
            current_clock,
            prior_fence,
        )
        .map_err(|_| NetworkBrokerError::Authority)?;
    let current_fence = authority
        .seal_fence(&sandbox_id, &admission)
        .map_err(|_| NetworkBrokerError::Authority)?;
    let effect = authority
        .seal_effect(&request_id, &admission)
        .map_err(|_| NetworkBrokerError::Authority)?;
    let operation_fence = authority
        .seal_operation_fence(&request_id, &admission)
        .map_err(|_| NetworkBrokerError::Authority)?;
    let record = prepared_record(PreparedNetworkRecordInput {
        request_id,
        sandbox_id,
        transport_digest,
        semantic_digest: semantics.argument_commitment().digest(),
        verb: semantics.broker_verb(),
        catalog: catalog.clone(),
        current_fence,
        operation_fence,
        effect,
    });

    Ok(match state.begin_authorized(authority, record)? {
        NetworkBeginOutcome::Prepared { effect_digest } => {
            NetworkAdmissionOutcome::Prepared { effect_digest }
        }
        NetworkBeginOutcome::ObserveOnly {
            phase,
            effect_digest,
        } => NetworkAdmissionOutcome::ObserveOnly {
            phase,
            effect_digest,
        },
        NetworkBeginOutcome::Aborted { effect_digest } => {
            NetworkAdmissionOutcome::Aborted { effect_digest }
        }
        NetworkBeginOutcome::Replay(result) => NetworkAdmissionOutcome::Replay(result),
    })
}

/// Serializes signed authority and effects for existing namespace handles.
pub struct NetworkLifecycleAdmissionCoordinator {
    authority: NetworkAuthorityV1,
    creation_state: NetworkStateStore,
    lifecycle_state: NetworkLifecycleStateStore,
}

impl NetworkLifecycleAdmissionCoordinator {
    /// Constructs a coordinator from creation authority and separate lifecycle state.
    #[must_use]
    pub const fn new(
        authority: NetworkAuthorityV1,
        creation_state: NetworkStateStore,
        lifecycle_state: NetworkLifecycleStateStore,
    ) -> Self {
        Self {
            authority,
            creation_state,
            lifecycle_state,
        }
    }

    /// Verifies and journals one new-namespace intent against both journals.
    ///
    /// This is the production creation path once lifecycle state exists. It
    /// authenticates the current fence retained by each journal and admits the
    /// request only after selecting their unique monotonic successor. A
    /// creation request therefore cannot recreate from a fence that predates a
    /// committed or ambiguous lifecycle operation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] for hostile request bytes, incomparable
    /// journal fences, signed authority failure, or durable-state conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &AuthenticatedNetworkPreparationV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
        let assignment =
            decode_assignment(request_body).map_err(|_| NetworkBrokerError::Request)?;
        let sandbox_id = *assignment.sandbox().as_bytes();
        let creation_fence = self
            .creation_state
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?;
        let prior_fence = self
            .authority
            .latest_fence(
                &sandbox_id,
                [
                    creation_fence,
                    self.lifecycle_state.current_fence(&sandbox_id),
                ],
            )
            .map_err(|_| NetworkBrokerError::Authority)?;

        admit_apply_intent_with_prior(
            &self.authority,
            &mut self.creation_state,
            request_body,
            artifacts,
            catalog,
            protocol_version,
            peer,
            policy,
            current_clock,
            prior_fence.as_deref(),
        )
    }

    /// Fully validates and classifies one Prepared effect before releasing it.
    ///
    /// Request, plan, catalog, fence, effect, dispatch identity, and bounds are
    /// checked before the protected clock is sampled. An expired effect is
    /// durably aborted. A fresh effect synchronously crosses to Ambiguous and
    /// then releases the already-validated worker request without another
    /// caller-controlled validation step.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] when durable state is not the exact
    /// current Prepared row, prospective dispatch validation fails, the clock
    /// lacks authenticated continuity, or the terminal journal write fails.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_prepare_effect_once<F>(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        request_body: &[u8],
        kernel_plan: NetworkKernelPlanV1,
        trusted_clock: &mut F,
    ) -> Result<NetworkPrepareExecutionOutcomeV1, NetworkBrokerError>
    where
        F: FnMut() -> Result<RawPairedClockSample, NetworkAdmissionError>,
    {
        let prepared = self.creation_state.prepare_effect_dispatch(
            &self.authority,
            request_id,
            effect_digest,
        )?;
        let prospective =
            prevalidate_prepare_dispatch(&self.authority, &prepared, request_body, kernel_plan)?;
        let current_clock = trusted_clock().map_err(|_| NetworkBrokerError::Authority)?;
        match self
            .authority
            .classify_effect_clock(prepared.effect_intent(), &current_clock)
            .map_err(|_| NetworkBrokerError::Authority)?
        {
            BrokerEffectClockDispositionV1::Expired => {
                self.creation_state
                    .abort_prepared_exact(&self.authority, prepared)?;
                Ok(NetworkPrepareExecutionOutcomeV1::Aborted { effect_digest })
            }
            BrokerEffectClockDispositionV1::Fresh => {
                self.creation_state
                    .mark_prevalidated_effect_ambiguous(&self.authority, prepared)?;
                Ok(NetworkPrepareExecutionOutcomeV1::Dispatch(
                    prospective.release(),
                ))
            }
        }
    }

    /// Binds an ambiguous preparation to confirmed systemd namespace custody.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless every durable and physical
    /// namespace identity field matches the current preparation.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_effect_namespace_custody(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        network_handle: [u8; 32],
        kernel_boot_id: [u8; 16],
        namespace_device: u64,
        namespace_inode: u64,
        kernel_plan_digest: ObjectDigest,
    ) -> Result<NetworkNamespaceCustodyV1, NetworkBrokerError> {
        self.creation_state
            .bind_namespace_custody(
                &self.authority,
                request_id,
                effect_digest,
                network_handle,
                kernel_boot_id,
                namespace_device,
                namespace_inode,
                kernel_plan_digest,
            )
            .map_err(Into::into)
    }

    /// Commits one verified preparation observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the observation exactly
    /// matches the current ambiguous preparation.
    pub fn commit_verified_preparation(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        verified: VerifiedNetworkResultV1,
    ) -> Result<CommittedNetworkResultV1, NetworkBrokerError> {
        self.creation_state
            .commit_verified(&self.authority, request_id, effect_digest, verified)
            .map_err(Into::into)
    }

    /// Reconstructs a namespace publication from committed creation state.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] when committed state or its retained
    /// preparation no longer reproduces the exact publication.
    pub fn namespace_publication(
        &self,
        result: CommittedNetworkResultV1,
        preparations: &NetworkPreparationCatalogV1,
    ) -> Result<NetworkNamespacePublicationV1, NetworkBrokerError> {
        let entry = self.creation_state.committed_recovery_entry(result)?;
        let resolution = self.creation_state.recover_preparation(&entry)?;
        let assignment =
            preparations.assignment_for_resolution(result.network_handle(), &resolution)?;

        NetworkNamespacePublicationV1::from_committed(result, &resolution, assignment)
            .map_err(Into::into)
    }

    /// Recovers observation-only authority for one ambiguous preparation.
    ///
    /// The supplied descriptor must reproduce the exact systemd-custody boot,
    /// device, inode, and authenticated kernel-plan digest retained before the
    /// first effect frame. This method cannot reconstruct a dispatch permit.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the exact request and effect
    /// remain ambiguous with complete matching namespace custody.
    pub fn recover_ambiguous_preparation_observation<'a>(
        &self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        namespace: &'a NamespaceFd,
    ) -> Result<RecoveredNetworkPreparationObservation<'a>, NetworkBrokerError> {
        let entry = self
            .creation_state
            .recovery_entries()?
            .into_iter()
            .find(|entry| {
                entry.request_id() == request_id && entry.effect_digest() == effect_digest
            })
            .ok_or(NetworkStateError::InvalidTransition)?;
        let custody = entry
            .custody()
            .filter(|_| entry.phase() == DurableNetworkPhase::Ambiguous)
            .ok_or(NetworkStateError::InvalidTransition)?;
        let identity = namespace.identity();
        let kernel_plan_digest = custody.kernel_plan_digest();
        let current_boot_id = KernelBootId::current()
            .map_err(|_| NetworkStateError::InvalidTransition)?
            .into_bytes();
        if custody.kernel_boot_id() != current_boot_id
            || (custody.namespace_device(), custody.namespace_inode())
                != (identity.device, identity.inode)
        {
            return Err(NetworkStateError::InvalidTransition.into());
        }

        Ok(RecoveredNetworkPreparationObservation::new(
            namespace,
            request_id,
            effect_digest,
            kernel_plan_digest,
            custody.kernel_boot_id(),
        ))
    }

    /// Returns bounded authenticated creation history for observation recovery.
    ///
    /// The snapshot contains no effect-dispatch permit and makes no current
    /// kernel or namespace-catalog claim.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] when an indeterminate commit has
    /// poisoned the creation journal's authenticated materialized view.
    pub fn preparation_recovery_snapshot(
        &self,
    ) -> Result<crate::state::NetworkRecoverySnapshotV1, NetworkBrokerError> {
        self.creation_state.recovery_snapshot().map_err(Into::into)
    }

    /// Authenticates and journals one current-handle lifecycle intent.
    ///
    /// The authenticated preparation must own the exact requested handle and
    /// reproduce the namespace catalog's retained assignment and preparation.
    /// A live fixed pin, current resource digest, legal prior state, and lease
    /// high-water are captured in the atomic lifecycle admission record.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] for hostile request bytes, stale or
    /// mismatched catalog evidence, signed authority failure, illegal lifecycle
    /// order, or durable request/handle conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_lifecycle_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        preparation: &AuthenticatedNetworkPreparationV1,
        kernel_plan: &NetworkKernelPlanV1,
        namespaces: &NetworkNamespaceCatalogV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<NetworkLifecycleAdmissionOutcome, NetworkBrokerError> {
        let semantics = CanonicalNetworkSemanticsV1::decode(
            request_body,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| NetworkBrokerError::Request)?;
        let assignment =
            decode_assignment(request_body).map_err(|_| NetworkBrokerError::Request)?;
        let resolution = self
            .authority
            .validate_catalog(preparation, assignment)
            .map_err(|_| NetworkBrokerError::Authority)?;
        let handle = semantics
            .operation()
            .network_handle()
            .copied()
            .ok_or(NetworkBrokerError::Request)?;
        if resolution.reserved_network_handle() != &handle {
            return Err(NetworkBrokerError::Request);
        }
        let sandbox_id = *assignment.sandbox().as_bytes();
        let request_id = *semantics.header().request_id();
        let transport_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
        let semantic_digest = semantics.argument_commitment().digest();
        let creation_fence = self
            .creation_state
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?;
        let prior_fence = self
            .authority
            .latest_fence(
                &sandbox_id,
                [
                    creation_fence,
                    self.lifecycle_state.current_fence(&sandbox_id),
                ],
            )
            .map_err(|_| NetworkBrokerError::Authority)?;
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
            .map_err(|_| NetworkBrokerError::Authority)?;
        let current_fence = self
            .authority
            .seal_fence(&sandbox_id, &admission)
            .map_err(|_| NetworkBrokerError::Authority)?;
        let operation_fence = self
            .authority
            .seal_operation_fence(&request_id, &admission)
            .map_err(|_| NetworkBrokerError::Authority)?;
        let effect = self
            .authority
            .seal_effect(&request_id, &admission)
            .map_err(|_| NetworkBrokerError::Authority)?;
        if kernel_plan.assignment() != assignment
            || !kernel_plan_matches_catalog(kernel_plan, resolution)
        {
            return Err(NetworkBrokerError::Request);
        }
        if let Some(outcome) = self.lifecycle_state.existing_authorized_outcome(
            request_id,
            sandbox_id,
            transport_digest,
            semantic_digest,
            semantics.broker_verb(),
            resolution.binding().generation(),
            resolution.binding().digest(),
            handle,
            kernel_plan.digest(),
        )? {
            return Ok(map_lifecycle_outcome(outcome));
        }

        let namespace_authority =
            namespaces.authorize_current_lifecycle(handle, assignment, resolution.binding())?;
        if namespace_authority.kernel_plan_digest != kernel_plan.digest() {
            return Err(NetworkBrokerError::Request);
        }
        let (action, desired_state) =
            validate_lifecycle_operation(semantics.operation(), namespace_authority)?;
        let record = prepared_lifecycle_record(PreparedNetworkLifecycleRecordInput {
            request_id,
            sandbox_id,
            transport_digest,
            semantic_digest,
            verb: semantics.broker_verb(),
            action,
            preparation_generation: resolution.binding().generation(),
            preparation_digest: resolution.binding().digest(),
            authority: namespace_authority,
            desired_state,
            current_fence,
            operation_fence,
            effect,
        });

        Ok(map_lifecycle_outcome(
            self.lifecycle_state
                .begin_authorized(&self.authority, record)?,
        ))
    }

    /// Durably crosses the point after which a lifecycle effect may have run.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::LifecycleState`] unless the exact
    /// prepared request and effect identity are the current handle head.
    pub fn mark_effect_ambiguous(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<NetworkLifecycleEffectDispatchPermitV1, NetworkBrokerError> {
        let durable = self.lifecycle_state.mark_effect_ambiguous(
            &self.authority,
            request_id,
            effect_digest,
        )?;
        Ok(NetworkLifecycleEffectDispatchPermitV1 { durable })
    }

    /// Consumes a fresh lifecycle permit into one authenticated worker request.
    ///
    /// The raw request, protected preparation, and canonical kernel plan must
    /// reproduce every durable target, transition, fence, and effect field.
    /// No helper is launched and no kernel effect is performed.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::WorkerProtocol`] when any request, plan,
    /// catalog, target, state, fence, or effect relationship differs.
    pub fn issue_lifecycle_worker_dispatch(
        &self,
        permit: NetworkLifecycleEffectDispatchPermitV1,
        request_body: &[u8],
        catalog: AuthenticatedNetworkPreparationV1,
        kernel_plan: NetworkKernelPlanV1,
    ) -> Result<NetworkLifecycleWorkerDispatchV1, NetworkBrokerError> {
        issue_lifecycle_dispatch(
            &self.authority,
            permit.durable,
            request_body,
            catalog,
            kernel_plan,
        )
        .map_err(Into::into)
    }

    /// Applies and durably commits one exact helper-verified transition.
    ///
    /// Catalog application happens first. If the following lifecycle-journal
    /// commit is interrupted, recovery remains Ambiguous and repeating this
    /// exact transition is safe because the catalog compare-and-swap replays.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] unless the transition exactly matches
    /// the current ambiguous record and catalog head.
    pub fn commit_verified_transition(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        transition: NetworkNamespaceLifecycleTransitionV1,
        namespaces: &mut NetworkNamespaceCatalogV1,
    ) -> Result<CommittedNetworkLifecycleResultV1, NetworkBrokerError> {
        self.lifecycle_state
            .validate_verified_transition(request_id, effect_digest, transition)?;
        namespaces.apply_lifecycle_transition(transition)?;
        self.lifecycle_state
            .commit_verified(&self.authority, request_id, effect_digest, transition)
            .map_err(Into::into)
    }

    /// Returns deterministic authenticated lifecycle recovery history.
    pub fn recovery_entries(
        &self,
    ) -> impl Iterator<Item = crate::NetworkLifecycleRecoveryEntryV1> + '_ {
        self.lifecycle_state.recovery_entries()
    }

    #[cfg(test)]
    pub(crate) fn lifecycle_state_mut_for_test(&mut self) -> &mut NetworkLifecycleStateStore {
        &mut self.lifecycle_state
    }

    #[cfg(test)]
    pub(crate) fn corrupt_transport_link_for_test(
        &mut self,
        request_id: [u8; 16],
        digest: ObjectDigest,
    ) -> Result<(), NetworkLifecycleStateError> {
        self.lifecycle_state
            .rewrite_transport_digest_for_test(&self.authority, request_id, digest)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_current_fence_link_for_test(
        &mut self,
        request_id: [u8; 16],
        fence: Vec<u8>,
    ) -> Result<(), NetworkLifecycleStateError> {
        self.lifecycle_state
            .mislink_current_fence_for_test(&self.authority, request_id, fence)
    }

    #[cfg(test)]
    pub(crate) fn creation_fence_for_test(
        &self,
        sandbox_id: [u8; 16],
    ) -> Result<Vec<u8>, NetworkStateError> {
        Ok(self
            .creation_state
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?
            .map(<[u8]>::to_vec)
            .unwrap_or_default())
    }
}

fn map_lifecycle_outcome(
    outcome: NetworkLifecycleBeginOutcome,
) -> NetworkLifecycleAdmissionOutcome {
    match outcome {
        NetworkLifecycleBeginOutcome::Prepared { effect_digest } => {
            NetworkLifecycleAdmissionOutcome::Prepared { effect_digest }
        }
        NetworkLifecycleBeginOutcome::ObserveOnly {
            phase,
            effect_digest,
        } => NetworkLifecycleAdmissionOutcome::ObserveOnly {
            phase,
            effect_digest,
        },
        NetworkLifecycleBeginOutcome::Replay(result) => {
            NetworkLifecycleAdmissionOutcome::Replay(result)
        }
    }
}

fn validate_lifecycle_operation(
    operation: &NetworkOperation,
    authority: NetworkNamespaceLifecycleAuthorityV1,
) -> Result<
    (
        NetworkNamespaceLifecycleActionV1,
        NetworkNamespaceObservedStateV1,
    ),
    NetworkBrokerError,
> {
    let prior_kind = authority.observed_state.kind();
    match operation {
        NetworkOperation::ArmLease {
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            ..
        } if prior_kind == NetworkNamespaceObservedStateKindV1::DefaultDrop
            && *lease_generation > authority.highest_lease_generation =>
        {
            Ok((
                NetworkNamespaceLifecycleActionV1::Arm,
                NetworkNamespaceObservedStateV1::armed(
                    ObjectDigest::from_bytes(*ownership_lease_digest),
                    *lease_generation,
                    *fail_stop_boottime_nanoseconds,
                )?,
            ))
        }
        NetworkOperation::RenewLease {
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            ..
        } if prior_kind == NetworkNamespaceObservedStateKindV1::Armed
            && *lease_generation > authority.highest_lease_generation
            && authority
                .observed_state
                .lease()
                .is_some_and(|(_, _, deadline)| *fail_stop_boottime_nanoseconds > deadline) =>
        {
            Ok((
                NetworkNamespaceLifecycleActionV1::Renew,
                NetworkNamespaceObservedStateV1::armed(
                    ObjectDigest::from_bytes(*ownership_lease_digest),
                    *lease_generation,
                    *fail_stop_boottime_nanoseconds,
                )?,
            ))
        }
        NetworkOperation::Disarm { .. }
            if matches!(
                prior_kind,
                NetworkNamespaceObservedStateKindV1::Armed
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) =>
        {
            Ok((
                NetworkNamespaceLifecycleActionV1::Disarm,
                NetworkNamespaceObservedStateV1::default_drop(),
            ))
        }
        NetworkOperation::Destroy { .. }
            if matches!(
                prior_kind,
                NetworkNamespaceObservedStateKindV1::DefaultDrop
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) =>
        {
            Ok((
                NetworkNamespaceLifecycleActionV1::Destroy,
                NetworkNamespaceObservedStateV1::absent(),
            ))
        }
        _ => Err(NetworkBrokerError::Request),
    }
}

fn validate_catalog(
    semantics: &CanonicalNetworkSemanticsV1,
    catalog: &ResolvedNetworkPreparationV1,
) -> Result<(), NetworkBrokerError> {
    match semantics.operation() {
        NetworkOperation::Prepare { endpoint_ids }
            if endpoint_ids
                .iter()
                .eq(catalog.endpoints().iter().map(|item| item.id())) => {}
        // The preparation coordinator rejects existing-resource operations.
        // NetworkLifecycleAdmissionCoordinator validates those operations
        // against current-resource and durable lifecycle state, but does not
        // execute their effects.
        NetworkOperation::ArmLease { .. }
        | NetworkOperation::RenewLease { .. }
        | NetworkOperation::Disarm { .. }
        | NetworkOperation::Destroy { .. } => return Err(NetworkBrokerError::Request),
        _ => return Err(NetworkBrokerError::Request),
    }
    Ok(())
}

/// Returns the closed method set safe for the current network service.
///
/// Apply remains absent pending production broker/service/controller
/// composition, protected retention authorization, lifecycle effect execution
/// and teardown, and P0-06/MAC/VM qualification.
/// Inventory is read-only and is advertised only because service startup opens
/// and validates the complete protected namespace catalog and fixed pin root.
#[must_use]
pub fn advertised_network_methods() -> Vec<BrokerMethod> {
    vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES]
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    use aos_proto::aos::sandbox::local::v1::{
        ApplyNetworkRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerRequestEnvelope,
        NetworkAction,
    };
    use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
    use aos_sandbox_broker::BrokerLocalRecordDomain;
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, NetworkKind, SignaturePurpose, SignatureStatement, StableKeyId,
        TrustPolicy,
    };
    use aos_sandbox_core::{
        BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerPlanTrustAnchor, BrokerVerb,
        DecodeLimits, LeaseAssignment, MediaType, NetworkEndpointId, NodeId, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId, RawClockProvenance,
        RevocationScopeId, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_protocol::decode_request_envelope;
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;
    use crate::catalog::encode_authenticated_resolution;
    use crate::{
        NetworkAddressPoolV1, NetworkAdmissionError, NetworkAllocationPolicyV1,
        NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1,
        NetworkKernelPlanV1, NetworkLifecycleExecutionAuthorizationV1,
        NetworkLifecycleExecutionStepV1, NetworkLifecycleStateStore,
        NetworkLifecycleWorkerDispatchV1, NetworkNamespaceCatalogV1,
        NetworkNamespaceLifecycleObservationV1, NetworkNamespaceLifecycleTransitionV1,
        NetworkNamespacePlanV1, NetworkNamespacePublicationV1, NetworkPolicyProgramV1,
        NetworkPortRangeV1, NetworkPrepareWorkerDispatchV1, NetworkTransportProtocolV1,
        NetworkWorkerProtocolError, NetworkWorkerReplayLedger, ResolvedEndpointV1,
        ResolvedNetworkPreparationV1, VerifiedNetworkResultV1,
    };

    const NODE: NodeId = NodeId::from_bytes([31; 16]);

    pub(crate) struct Fixture {
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
        pub(crate) fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let plan_signer = key_ref("network-plan", 3, KeyUsage::BrokerAuthorization, &plan_key);
            let lease_signer = key_ref("network-lease", 7, KeyUsage::OwnershipLease, &lease_key);
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

        pub(crate) fn authority(&self) -> NetworkAuthorityV1 {
            self.authority_for(NODE)
        }

        fn authority_for(&self, node: NodeId) -> NetworkAuthorityV1 {
            let plan = BrokerPlanTrustAnchor::from_trusted_configuration(
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
            NetworkAuthorityV1::new(plan, lease, node, [46; 16], [47; 32]).unwrap()
        }

        pub(crate) fn artifacts(&self, request: &[u8]) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing(request, &[request])
        }

        fn artifacts_authorizing(
            &self,
            request: &[u8],
            authorized: &[&[u8]],
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_lease(request, authorized, 1, [49; 16])
        }

        fn lifecycle_artifacts(
            &self,
            request: &[u8],
            lease_generation: u64,
            renewal_nonce: [u8; 16],
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let (prepare, arm, disarm, destroy, _) = lifecycle_requests(self);
            let assignment = decode_assignment(&prepare).unwrap();
            let (_, renewal_digest, renewal_deadline) =
                self.ownership_lease_expiring(assignment, 3, [53; 16], 400);
            let renew = lifecycle_request_with_deadline(
                12,
                NetworkAction::NETWORK_ACTION_RENEW_LEASE,
                Some((renewal_digest, 3, renewal_deadline)),
                200_000_000_100,
            );
            self.artifacts_authorizing_lease_with_expiries(
                request,
                // Request IDs are correlation data rather than grant
                // semantics, so the original Prepare grant also authorizes
                // the stale-retry fixture without creating a duplicate grant.
                &[&prepare, &arm, &renew, &disarm, &destroy],
                lease_generation,
                renewal_nonce,
                300,
                500,
            )
        }

        fn ownership_lease(
            &self,
            assignment: aos_sandbox_core::BrokerAssignment,
            lease_generation: u64,
            renewal_nonce: [u8; 16],
        ) -> (Vec<u8>, ObjectDigest, u64) {
            self.ownership_lease_expiring(assignment, lease_generation, renewal_nonce, 300)
        }

        fn ownership_lease_expiring(
            &self,
            assignment: aos_sandbox_core::BrokerAssignment,
            lease_generation: u64,
            renewal_nonce: [u8; 16],
            authority_expires_seconds: i64,
        ) -> (Vec<u8>, ObjectDigest, u64) {
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                NODE,
                lease_generation,
                100,
                authority_expires_seconds,
                10,
                renewal_nonce,
            )
            .unwrap();
            let bytes = encode_ownership_lease(&lease);
            let descriptor = descriptor_for_bytes(
                MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
                &bytes,
            );
            // Fixture clock wall=150 and boot=100. Convert the guarded wall
            // interval back into the equivalent trusted BOOTTIME deadline.
            let remaining_seconds = authority_expires_seconds - 150 - 10 - 5;
            let deadline = u64::try_from(remaining_seconds)
                .unwrap()
                .checked_mul(1_000_000_000)
                .unwrap()
                .checked_add(100)
                .unwrap();
            (bytes, descriptor.digest(), deadline)
        }

        fn artifacts_authorizing_lease(
            &self,
            request: &[u8],
            authorized: &[&[u8]],
            lease_generation: u64,
            renewal_nonce: [u8; 16],
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_lease_expiring(
                request,
                authorized,
                lease_generation,
                renewal_nonce,
                300,
            )
        }

        fn artifacts_authorizing_lease_expiring(
            &self,
            request: &[u8],
            authorized: &[&[u8]],
            lease_generation: u64,
            renewal_nonce: [u8; 16],
            authority_expires_seconds: i64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing_lease_with_expiries(
                request,
                authorized,
                lease_generation,
                renewal_nonce,
                authority_expires_seconds,
                300,
            )
        }

        fn artifacts_authorizing_lease_with_expiries(
            &self,
            request: &[u8],
            authorized: &[&[u8]],
            lease_generation: u64,
            renewal_nonce: [u8; 16],
            authority_expires_seconds: i64,
            plan_expires_seconds: i64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let assignment = decode_assignment(request).unwrap();
            let mut grants = authorized
                .iter()
                .map(|bytes| {
                    let candidate =
                        CanonicalNetworkSemanticsV1::decode(bytes, peer(), peer_policy(), 100)
                            .unwrap();
                    BrokerGrant::new(
                        candidate.broker_verb(),
                        candidate.grant_target(),
                        candidate.argument_commitment(),
                        bytes.len() as u32,
                        0,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            grants.sort_by_key(|grant| (grant.verb(), grant.target(), grant.argument_commitment()));
            let plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Network,
                ProtocolId::NetworkBroker,
                ProtocolVersion::new(1, 0),
                assignment,
                NODE,
                self.lease_signer.clone(),
                grants,
                ObjectDigest::from_bytes([48; 32]),
                self.revocation,
                100,
                plan_expires_seconds,
                Vec::new(),
            )
            .unwrap();
            let plan_bytes = encode_broker_authorization_plan(&plan);
            let (lease_bytes, _, _) = self.ownership_lease_expiring(
                assignment,
                lease_generation,
                renewal_nonce,
                authority_expires_seconds,
            );
            validated(BrokerAuthorizationArtifactsV1 {
                broker_plan_signature: signed_expiring(
                    &plan_bytes,
                    PortableMediaType::BrokerAuthorizationPlan,
                    self.plan_scope,
                    self.plan_signer.clone(),
                    SignaturePurpose::BrokerAuthorization,
                    &self.plan_descriptor,
                    &self.plan_key,
                    plan_expires_seconds,
                ),
                broker_plan: plan_bytes,
                ownership_lease_signature: signed_expiring(
                    &lease_bytes,
                    PortableMediaType::OwnershipLease,
                    self.lease_scope,
                    self.lease_signer.clone(),
                    SignaturePurpose::OwnershipLease,
                    &self.lease_descriptor,
                    &self.lease_key,
                    authority_expires_seconds,
                ),
                ownership_lease: lease_bytes,
                ..Default::default()
            })
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
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            100,
        )
        .unwrap()
    }

    fn clock_at(boottime_nanoseconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            boottime_nanoseconds,
        )
        .unwrap()
    }

    fn expired_clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            151,
            1_000_000_100,
        )
        .unwrap()
    }

    fn advanced_clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            150,
        )
        .unwrap()
    }

    fn renewal_boundary_clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            285,
            135_000_000_100,
        )
        .unwrap()
    }

    fn renewal_preboundary_clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            284,
            134_000_000_100,
        )
        .unwrap()
    }

    fn request() -> Vec<u8> {
        request_for(7, 2, &[7, 8])
    }

    fn request_for(request_id: u8, sandbox_id: u8, endpoints: &[u8]) -> Vec<u8> {
        request_for_assignment(request_id, sandbox_id, 5, 6, endpoints)
    }

    fn request_for_assignment(
        request_id: u8,
        sandbox_id: u8,
        desired_generation: u64,
        assignment_digest: u8,
        endpoints: &[u8],
    ) -> Vec<u8> {
        request_for_complete_assignment(
            request_id,
            sandbox_id,
            3,
            4,
            desired_generation,
            assignment_digest,
            endpoints,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn request_for_complete_assignment(
        request_id: u8,
        sandbox_id: u8,
        incarnation_id: u8,
        assignment_epoch: u64,
        desired_generation: u64,
        assignment_digest: u8,
        endpoints: &[u8],
    ) -> Vec<u8> {
        let mut request = ApplyNetworkRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 180;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![sandbox_id; 16];
        fence.incarnation_id = vec![incarnation_id; 16];
        fence.assignment_epoch = assignment_epoch;
        fence.desired_generation = desired_generation;
        fence.assignment_digest = vec![assignment_digest; 32];
        request.action = NetworkAction::NETWORK_ACTION_PREPARE.into();
        request.endpoint_ids = endpoints.iter().map(|value| vec![*value; 16]).collect();
        request.encode_to_vec()
    }

    fn catalog() -> ResolvedNetworkPreparationV1 {
        catalog_for(9, 10, 11, &[(7, 12), (8, 13)])
    }

    fn catalog_for(
        generation: u64,
        handle: u8,
        profile: u8,
        endpoints: &[(u8, u8)],
    ) -> ResolvedNetworkPreparationV1 {
        ResolvedNetworkPreparationV1::new(
            generation,
            [handle; 32],
            ObjectDigest::from_bytes([profile; 32]),
            endpoints
                .iter()
                .map(|(id, policy)| {
                    ResolvedEndpointV1::new([*id; 16], ObjectDigest::from_bytes([*policy; 32]))
                        .unwrap()
                })
                .collect(),
        )
        .unwrap()
    }

    fn authenticated_catalog(
        authority: &NetworkAuthorityV1,
        resolution: ResolvedNetworkPreparationV1,
        request: &[u8],
    ) -> AuthenticatedNetworkPreparationV1 {
        authority
            .authenticate_protected_catalog_for_assignment(
                resolution,
                decode_assignment(request).unwrap(),
            )
            .unwrap()
    }

    fn lifecycle_request(
        request_id: u8,
        action: NetworkAction,
        ownership_lease: Option<(ObjectDigest, u64, u64)>,
    ) -> Vec<u8> {
        lifecycle_request_with_deadline(request_id, action, ownership_lease, 180)
    }

    fn lifecycle_request_with_deadline(
        request_id: u8,
        action: NetworkAction,
        ownership_lease: Option<(ObjectDigest, u64, u64)>,
        request_deadline_boottime_nanoseconds: u64,
    ) -> Vec<u8> {
        let mut request = ApplyNetworkRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = request_deadline_boottime_nanoseconds;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        request.action = action.into();
        request.network_handle = vec![10; 32];
        if let Some((digest, generation, deadline)) = ownership_lease {
            request.ownership_lease_digest = digest.as_bytes().to_vec();
            request.lease_generation = generation;
            request.fail_stop_boottime_nanoseconds = deadline;
        }
        request.encode_to_vec()
    }

    fn lifecycle_requests(fixture: &Fixture) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let prepare = request_for(7, 2, &[]);
        let assignment = decode_assignment(&prepare).unwrap();
        let (_, lease_digest, deadline) = fixture.ownership_lease(assignment, 2, [52; 16]);
        let arm = lifecycle_request(
            8,
            NetworkAction::NETWORK_ACTION_ARM_LEASE,
            Some((lease_digest, 2, deadline)),
        );
        let disarm = lifecycle_request(9, NetworkAction::NETWORK_ACTION_DISARM, None);
        let destroy = lifecycle_request(10, NetworkAction::NETWORK_ACTION_DESTROY, None);
        let stale_prepare = request_for(11, 2, &[]);
        (prepare, arm, disarm, destroy, stale_prepare)
    }

    fn encode_handle(handle: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in handle {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    struct LifecycleCase {
        _directory: TempDir,
        creation_directory: PathBuf,
        lifecycle_directory: PathBuf,
        namespace_directory: PathBuf,
        pin_directory: PathBuf,
        resolution: ResolvedNetworkPreparationV1,
        kernel_plan: NetworkKernelPlanV1,
        namespaces: NetworkNamespaceCatalogV1,
        coordinator: NetworkLifecycleAdmissionCoordinator,
    }

    struct PreparedExecutionCase {
        _directory: TempDir,
        creation_directory: PathBuf,
        lifecycle_directory: PathBuf,
        request: Vec<u8>,
        resolution: ResolvedNetworkPreparationV1,
        plan: NetworkKernelPlanV1,
        artifacts: ValidatedUntrustedAuthorizationArtifacts,
        preparation: AuthenticatedNetworkPreparationV1,
        effect_digest: ObjectDigest,
        coordinator: NetworkLifecycleAdmissionCoordinator,
    }

    fn prepared_execution_case(fixture: &Fixture) -> PreparedExecutionCase {
        let (request, resolution, plan) = isolated_worker_case();
        prepared_execution_case_from(fixture, request, resolution, plan)
    }

    fn prepared_execution_case_from(
        fixture: &Fixture,
        request: Vec<u8>,
        resolution: ResolvedNetworkPreparationV1,
        plan: NetworkKernelPlanV1,
    ) -> PreparedExecutionCase {
        let directory = TempDir::new().unwrap();
        let creation_directory = directory.path().join("creation");
        let lifecycle_directory = directory.path().join("lifecycle");
        fs::create_dir(&creation_directory).unwrap();
        fs::create_dir(&lifecycle_directory).unwrap();

        let authority = fixture.authority();
        let artifacts = fixture.artifacts(&request);
        let preparation = authenticated_catalog(&authority, resolution.clone(), &request);
        let creation_state =
            NetworkStateStore::open_for_test(&creation_directory, &authority, 0).unwrap();
        let lifecycle_state =
            NetworkLifecycleStateStore::open_for_test(&lifecycle_directory, &authority).unwrap();
        let mut coordinator =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation_state, lifecycle_state);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("execution case did not prepare");
        };

        PreparedExecutionCase {
            _directory: directory,
            creation_directory,
            lifecycle_directory,
            request,
            resolution,
            plan,
            artifacts,
            preparation,
            effect_digest,
            coordinator,
        }
    }

    fn lifecycle_case(fixture: &Fixture) -> LifecycleCase {
        let directory = TempDir::new().unwrap();
        let creation_directory = directory.path().join("creation");
        let lifecycle_directory = directory.path().join("lifecycle");
        let namespace_directory = directory.path().join("namespaces");
        let pin_directory = directory.path().join("pins");
        for path in [
            &creation_directory,
            &lifecycle_directory,
            &namespace_directory,
            &pin_directory,
        ] {
            fs::create_dir(path).unwrap();
        }

        let (prepare_request, _, _, _, _) = lifecycle_requests(fixture);
        let resolution = catalog_for(9, 10, 11, &[]);
        let (_, _, kernel_plan) = isolated_worker_case();
        let prepare_artifacts = fixture.lifecycle_artifacts(&prepare_request, 1, [49; 16]);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, resolution.clone(), &prepare_request);
        let creation_state =
            NetworkStateStore::open_for_test(&creation_directory, &authority, 0).unwrap();
        let mut creation = NetworkAdmissionCoordinator::new(authority, creation_state);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = creation
            .admit_apply_intent(
                &prepare_request,
                &prepare_artifacts,
                &preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("creation did not prepare");
        };
        drop(
            creation
                .mark_effect_ambiguous([7; 16], effect_digest)
                .unwrap(),
        );

        let pin = pin_directory.join(encode_handle(&[10; 32]));
        fs::File::create(&pin).unwrap();
        let metadata = fs::metadata(&pin).unwrap();
        creation
            .bind_effect_namespace_custody(
                [7; 16],
                effect_digest,
                [10; 32],
                [50; 16],
                metadata.dev(),
                metadata.ino(),
                kernel_plan.digest(),
            )
            .unwrap();
        let verified = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&prepare_request).into()),
            &resolution,
            [50; 16],
            metadata.dev(),
            metadata.ino(),
            kernel_plan.digest(),
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        let result = creation
            .commit_verified([7; 16], effect_digest, verified)
            .unwrap();

        let mut namespaces = NetworkNamespaceCatalogV1::open_for_test(
            &namespace_directory,
            &pin_directory,
            [50; 16],
            [91; 16],
        )
        .unwrap();
        let publication = NetworkNamespacePublicationV1::from_committed(
            result,
            &resolution,
            decode_assignment(&prepare_request).unwrap(),
        )
        .unwrap();
        namespaces.publish(publication).unwrap();
        drop(creation);

        let authority = fixture.authority();
        let creation_state =
            NetworkStateStore::open_for_test(&creation_directory, &authority, 0).unwrap();
        let lifecycle_state =
            NetworkLifecycleStateStore::open_for_test(&lifecycle_directory, &authority).unwrap();
        let coordinator =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation_state, lifecycle_state);

        LifecycleCase {
            _directory: directory,
            creation_directory,
            lifecycle_directory,
            namespace_directory,
            pin_directory,
            resolution,
            kernel_plan,
            namespaces,
            coordinator,
        }
    }

    fn arm_request(fixture: &Fixture) -> (Vec<u8>, ObjectDigest, u64) {
        let (prepare, request, _, _, _) = lifecycle_requests(fixture);
        let assignment = decode_assignment(&prepare).unwrap();
        let (_, lease_digest, deadline) = fixture.ownership_lease(assignment, 2, [52; 16]);
        (request, lease_digest, deadline)
    }

    fn substituted_lifecycle_kernel_plan() -> NetworkKernelPlanV1 {
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Isolated,
            ObjectDigest::from_bytes([55; 32]),
            None,
            Vec::new(),
        )
        .unwrap();
        let namespace = NetworkNamespacePlanV1::derive(
            [10; 32],
            2,
            ObjectDigest::from_bytes([11; 32]),
            &policy,
            &NetworkAllocationPolicyV1::isolated(),
        )
        .unwrap();
        NetworkKernelPlanV1::compile(
            decode_assignment(&request_for(7, 2, &[])).unwrap(),
            &namespace,
            &policy,
        )
        .unwrap()
    }

    fn lifecycle_veth_plan(
        allocation_generation: u64,
        include_ipv6: bool,
        include_route: bool,
    ) -> NetworkKernelPlanV1 {
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Project,
            ObjectDigest::from_bytes([55; 32]),
            Some(ObjectDigest::from_bytes([56; 32])),
            Vec::new(),
        )
        .unwrap();
        let mut pools = vec![
            NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 40, 0, 0], 17).unwrap())
                .unwrap(),
        ];
        if include_ipv6 {
            pools.push(
                NetworkAddressPoolV1::new(
                    NetworkIpPrefixV1::ipv6(
                        [0xfd, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        64,
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
        }
        let routes = if include_route {
            vec![NetworkIpPrefixV1::ipv4([198, 51, 100, 0], 24).unwrap()]
        } else {
            Vec::new()
        };
        let allocation =
            NetworkAllocationPolicyV1::veth(1_500, [0x02, 0xaa, 0xbb], pools, routes).unwrap();
        let namespace = NetworkNamespacePlanV1::derive(
            [10; 32],
            allocation_generation,
            ObjectDigest::from_bytes([11; 32]),
            &policy,
            &allocation,
        )
        .unwrap();

        NetworkKernelPlanV1::compile(
            decode_assignment(&request_for(7, 2, &[])).unwrap(),
            &namespace,
            &policy,
        )
        .unwrap()
    }

    fn admit_arm(
        case: &mut LifecycleCase,
        fixture: &Fixture,
    ) -> (Vec<u8>, ObjectDigest, u64, ObjectDigest) {
        let (request, lease_digest, deadline) = arm_request(fixture);
        let artifacts = fixture.lifecycle_artifacts(&request, 2, [52; 16]);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
        let NetworkLifecycleAdmissionOutcome::Prepared { effect_digest } = case
            .coordinator
            .admit_lifecycle_intent(
                &request,
                &artifacts,
                &preparation,
                &case.kernel_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("arm did not prepare");
        };
        (request, lease_digest, deadline, effect_digest)
    }

    fn issue_arm_lifecycle_dispatch(
        case: &mut LifecycleCase,
        fixture: &Fixture,
    ) -> (Vec<u8>, NetworkLifecycleWorkerDispatchV1) {
        let (request, _, _, effect_digest) = admit_arm(case, fixture);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
        let permit = case
            .coordinator
            .mark_effect_ambiguous([8; 16], effect_digest)
            .unwrap();
        let dispatch = case
            .coordinator
            .issue_lifecycle_worker_dispatch(
                permit,
                &request,
                preparation,
                case.kernel_plan.clone(),
            )
            .unwrap();

        (request, dispatch)
    }

    fn issue_destroy_lifecycle_dispatch(
        case: &mut LifecycleCase,
        fixture: &Fixture,
    ) -> NetworkLifecycleWorkerDispatchV1 {
        let (_, _, _, request, _) = lifecycle_requests(fixture);
        let artifacts = fixture.lifecycle_artifacts(&request, 4, [64; 16]);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
        let NetworkLifecycleAdmissionOutcome::Prepared { effect_digest } = case
            .coordinator
            .admit_lifecycle_intent(
                &request,
                &artifacts,
                &preparation,
                &case.kernel_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("destroy did not prepare");
        };
        let permit = case
            .coordinator
            .mark_effect_ambiguous([10; 16], effect_digest)
            .unwrap();
        case.coordinator
            .issue_lifecycle_worker_dispatch(
                permit,
                &request,
                preparation,
                case.kernel_plan.clone(),
            )
            .unwrap()
    }

    fn commit_arm_lifecycle(case: &mut LifecycleCase, fixture: &Fixture) {
        let (_, lease_digest, deadline, effect_digest) = admit_arm(case, fixture);
        drop(
            case.coordinator
                .mark_effect_ambiguous([8; 16], effect_digest)
                .unwrap(),
        );
        let observation = transition_for(
            case,
            [8; 16],
            NetworkNamespaceObservedStateV1::armed(lease_digest, 2, deadline).unwrap(),
            ObjectDigest::from_bytes([61; 32]),
        );
        let transition =
            NetworkNamespaceLifecycleTransitionV1::arm(observation, lease_digest, 2, deadline)
                .unwrap();
        case.coordinator
            .commit_verified_transition([8; 16], effect_digest, transition, &mut case.namespaces)
            .unwrap();
    }

    fn issue_disarm_lifecycle_dispatch(
        case: &mut LifecycleCase,
        fixture: &Fixture,
    ) -> NetworkLifecycleWorkerDispatchV1 {
        commit_arm_lifecycle(case, fixture);
        let (_, _, request, _, _) = lifecycle_requests(fixture);
        let artifacts = fixture.lifecycle_artifacts(&request, 3, [53; 16]);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
        let NetworkLifecycleAdmissionOutcome::Prepared { effect_digest } = case
            .coordinator
            .admit_lifecycle_intent(
                &request,
                &artifacts,
                &preparation,
                &case.kernel_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("disarm did not prepare");
        };
        let permit = case
            .coordinator
            .mark_effect_ambiguous([9; 16], effect_digest)
            .unwrap();
        case.coordinator
            .issue_lifecycle_worker_dispatch(
                permit,
                &request,
                preparation,
                case.kernel_plan.clone(),
            )
            .unwrap()
    }

    fn issue_renew_lifecycle_dispatch(
        case: &mut LifecycleCase,
        fixture: &Fixture,
    ) -> (NetworkLifecycleWorkerDispatchV1, u64) {
        commit_arm_lifecycle(case, fixture);
        let (prepare, arm, disarm, destroy, _) = lifecycle_requests(fixture);
        let assignment = decode_assignment(&prepare).unwrap();
        let (_, lease_digest, renewed_deadline) =
            fixture.ownership_lease_expiring(assignment, 3, [53; 16], 400);
        let request = lifecycle_request_with_deadline(
            12,
            NetworkAction::NETWORK_ACTION_RENEW_LEASE,
            Some((lease_digest, 3, renewed_deadline)),
            200_000_000_100,
        );
        let artifacts = fixture.artifacts_authorizing_lease_with_expiries(
            &request,
            &[&prepare, &arm, &request, &disarm, &destroy],
            3,
            [53; 16],
            400,
            500,
        );
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
        let NetworkLifecycleAdmissionOutcome::Prepared { effect_digest } = case
            .coordinator
            .admit_lifecycle_intent(
                &request,
                &artifacts,
                &preparation,
                &case.kernel_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("renew did not prepare");
        };
        let permit = case
            .coordinator
            .mark_effect_ambiguous([12; 16], effect_digest)
            .unwrap();
        let dispatch = case
            .coordinator
            .issue_lifecycle_worker_dispatch(
                permit,
                &request,
                preparation,
                case.kernel_plan.clone(),
            )
            .unwrap();
        let (_, _, prior_deadline) = fixture.ownership_lease(assignment, 2, [52; 16]);

        (dispatch, prior_deadline)
    }

    fn complete_lifecycle_step_order(
        fixture: &Fixture,
        dispatch: NetworkLifecycleWorkerDispatchV1,
    ) -> Vec<NetworkLifecycleExecutionStepV1> {
        let authority = fixture.authority();
        let current_fence = dispatch.claimed_current_fence().to_vec();
        let replay_directory = TempDir::new().unwrap();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut execution = dispatch
            .authenticate(&authority)
            .unwrap()
            .authorize_execution(
                &authority,
                &mut replay,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap();
        let mut steps = Vec::new();
        while let Some(step) = execution
            .authorize_next_step(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap()
        {
            steps.push(step.step());
            step.complete_success(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap();
        }
        assert!(execution.is_complete());
        steps
    }

    fn authorize_arm_execution(
        fixture: &Fixture,
    ) -> (
        NetworkAuthorityV1,
        Vec<u8>,
        NetworkLifecycleExecutionAuthorizationV1,
    ) {
        let mut case = lifecycle_case(fixture);
        let (_, dispatch) = issue_arm_lifecycle_dispatch(&mut case, fixture);
        let authority = fixture.authority();
        let current_fence = dispatch.claimed_current_fence().to_vec();
        let authenticated = dispatch.authenticate(&authority).unwrap();
        let replay_directory = TempDir::new().unwrap();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let execution = authenticated
            .authorize_execution(
                &authority,
                &mut replay,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap();

        (authority, current_fence, execution)
    }

    fn transition_for(
        case: &LifecycleCase,
        request_id: [u8; 16],
        observed_state: NetworkNamespaceObservedStateV1,
        observation_digest: ObjectDigest,
    ) -> NetworkNamespaceLifecycleObservationV1 {
        let assignment = decode_assignment(&request_for(7, 2, &[])).unwrap();
        let authority = case
            .namespaces
            .authorize_current_lifecycle([10; 32], assignment, case.resolution.binding())
            .unwrap();
        NetworkNamespaceLifecycleObservationV1::new(
            request_id,
            authority.resource_digest,
            authority.identity,
            observed_state,
            observation_digest,
        )
        .unwrap()
    }

    fn lifecycle_wire_field_offset(bytes: &[u8], field: usize) -> usize {
        assert!(field < 9);
        let length = |index: usize| {
            let start = 64 + index * 4;
            u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap()) as usize
        };
        (0..field).fold(100, |offset, index| offset + length(index))
    }

    fn lifecycle_wire_field(bytes: &[u8], field: usize) -> &[u8] {
        let offset = lifecycle_wire_field_offset(bytes, field);
        let length_offset = 64 + field * 4;
        let length = u32::from_be_bytes(bytes[length_offset..length_offset + 4].try_into().unwrap())
            as usize;
        &bytes[offset..offset + length]
    }

    fn replace_lifecycle_wire_field(bytes: &[u8], field: usize, replacement: &[u8]) -> Vec<u8> {
        let offset = lifecycle_wire_field_offset(bytes, field);
        let original_length = lifecycle_wire_field(bytes, field).len();
        let mut replaced = Vec::with_capacity(bytes.len() - original_length + replacement.len());
        replaced.extend_from_slice(&bytes[..offset]);
        replaced.extend_from_slice(replacement);
        replaced.extend_from_slice(&bytes[offset + original_length..]);
        replaced[64 + field * 4..68 + field * 4]
            .copy_from_slice(&(replacement.len() as u32).to_be_bytes());
        let total = replaced.len() as u32;
        replaced[12..16].copy_from_slice(&total.to_be_bytes());
        replaced
    }

    #[test]
    fn lifecycle_dispatch_round_trips_authenticates_and_rejects_every_wire_substitution() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let (request, dispatch) = issue_arm_lifecycle_dispatch(&mut case, &fixture);
        let bytes = dispatch.encode().unwrap();
        let authority = fixture.authority();

        let decoded = NetworkLifecycleWorkerDispatchV1::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert!(decoded.authenticate(&authority).is_ok());

        for role_offset in [10, 11] {
            let mut substituted = bytes.clone();
            substituted[role_offset] = 2;
            assert!(NetworkLifecycleWorkerDispatchV1::decode(&substituted).is_err());
        }

        for identity_offset in [16, 32] {
            let mut substituted = bytes.clone();
            substituted[identity_offset] ^= 1;
            let decoded = NetworkLifecycleWorkerDispatchV1::decode(&substituted).unwrap();
            assert!(matches!(
                decoded.authenticate(&authority),
                Err(NetworkWorkerProtocolError::Authority)
            ));
        }

        // Malformed changes fail either canonical decoding or authentication.
        for field in 0..9 {
            let mut substituted = bytes.clone();
            let offset = lifecycle_wire_field_offset(&substituted, field);
            substituted[offset] ^= 1;
            match NetworkLifecycleWorkerDispatchV1::decode(&substituted) {
                Ok(decoded) => assert!(decoded.authenticate(&authority).is_err()),
                Err(_) => {}
            }
        }

        // Independently valid records still cannot be substituted across any
        // semantic or protected association. These all decode canonically.
        let mut destroy_case = lifecycle_case(&fixture);
        let destroy_bytes = issue_destroy_lifecycle_dispatch(&mut destroy_case, &fixture)
            .encode()
            .unwrap();
        let alternate_plan = lifecycle_veth_plan(2, true, true);
        let alternate_resolution = catalog_for(10, 20, 21, &[]);
        let alternate_catalog = authenticated_catalog(&authority, alternate_resolution, &request);
        let encoded_alternate_catalog = encode_authenticated_resolution(
            alternate_catalog.assignment,
            &alternate_catalog.resolution,
        );
        let replacements = [
            (0, lifecycle_wire_field(&destroy_bytes, 0)),
            (1, alternate_plan.as_bytes()),
            (2, encoded_alternate_catalog.as_slice()),
            (3, alternate_catalog.sealed.as_slice()),
            (4, lifecycle_wire_field(&destroy_bytes, 4)),
            (5, lifecycle_wire_field(&destroy_bytes, 5)),
            (6, lifecycle_wire_field(&destroy_bytes, 6)),
            (7, lifecycle_wire_field(&destroy_bytes, 7)),
            (8, lifecycle_wire_field(&destroy_bytes, 8)),
        ];
        for (field, replacement) in replacements {
            assert_ne!(replacement, lifecycle_wire_field(&bytes, field));
            let substituted = replace_lifecycle_wire_field(&bytes, field, replacement);
            let decoded = NetworkLifecycleWorkerDispatchV1::decode(&substituted).unwrap();
            assert!(matches!(
                decoded.authenticate(&authority),
                Err(NetworkWorkerProtocolError::Authority)
            ));
        }
    }

    #[test]
    fn lifecycle_dispatch_issuance_rejects_exact_plan_substitutions() {
        let fixture = Fixture::new();
        let variants = [
            lifecycle_veth_plan(2, false, false),
            lifecycle_veth_plan(1, true, false),
            lifecycle_veth_plan(1, false, true),
        ];

        for substituted_plan in variants {
            let mut case = lifecycle_case(&fixture);
            let (request, _, _, effect_digest) = admit_arm(&mut case, &fixture);
            let authority = fixture.authority();
            let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
            let permit = case
                .coordinator
                .mark_effect_ambiguous([8; 16], effect_digest)
                .unwrap();
            assert_ne!(substituted_plan.digest(), case.kernel_plan.digest());
            assert!(matches!(
                case.coordinator.issue_lifecycle_worker_dispatch(
                    permit,
                    &request,
                    preparation,
                    substituted_plan,
                ),
                Err(NetworkBrokerError::WorkerProtocol(
                    NetworkWorkerProtocolError::Authority
                ))
            ));
        }
    }

    #[test]
    fn lifecycle_arm_steps_require_explicit_fresh_completion_and_replay_is_claimed_once() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let (_, dispatch) = issue_arm_lifecycle_dispatch(&mut case, &fixture);
        let bytes = dispatch.encode().unwrap();
        let current_fence = dispatch.claimed_current_fence().to_vec();
        let authority = fixture.authority();
        let replay_directory = TempDir::new().unwrap();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut execution = dispatch
            .authenticate(&authority)
            .unwrap()
            .authorize_execution(
                &authority,
                &mut replay,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap();
        let expected = [
            NetworkLifecycleExecutionStepV1::EnsureLinksDown,
            NetworkLifecycleExecutionStepV1::ArmLeaseGate,
            NetworkLifecycleExecutionStepV1::ConfigureExactAddressPairs,
            NetworkLifecycleExecutionStepV1::ConfigureExactRoutes,
            NetworkLifecycleExecutionStepV1::ConfigureExactPermanentNeighbors,
            NetworkLifecycleExecutionStepV1::VerifyExactPlanConfiguration,
            NetworkLifecycleExecutionStepV1::RaiseLinks,
        ];

        assert!(matches!(
            NetworkLifecycleWorkerDispatchV1::decode(&bytes)
                .unwrap()
                .authenticate(&authority)
                .unwrap()
                .authorize_execution(
                    &authority,
                    &mut replay,
                    &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                    &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
                ),
            Err(NetworkWorkerProtocolError::Replay)
        ));

        for expected_step in expected {
            let step = execution
                .authorize_next_step(
                    &authority,
                    &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                    &mut || Ok::<_, NetworkAdmissionError>(clock()),
                )
                .unwrap()
                .unwrap();
            assert_eq!(step.step(), expected_step);
            assert_eq!(step.kernel_plan().digest(), case.kernel_plan.digest());
            assert_eq!(step.target_namespace().network_handle(), [10; 32]);
            step.complete_success(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap();
        }
        assert!(
            execution
                .authorize_next_step(
                    &authority,
                    &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                    &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
                )
                .unwrap()
                .is_none()
        );
        assert!(execution.is_complete());
    }

    #[test]
    fn lifecycle_fence_provider_is_reloaded_after_claim_and_failed_claim_stays_consumed() {
        let fixture = Fixture::new();
        let mut arm_case = lifecycle_case(&fixture);
        let (_, dispatch) = issue_arm_lifecycle_dispatch(&mut arm_case, &fixture);
        let bytes = dispatch.encode().unwrap();
        let current_fence = dispatch.claimed_current_fence().to_vec();
        let mut later_case = lifecycle_case(&fixture);
        let later_fence = issue_destroy_lifecycle_dispatch(&mut later_case, &fixture)
            .claimed_current_fence()
            .to_vec();
        let authority = fixture.authority();
        let opened_current = authority.open_fence(&[2; 16], &current_fence).unwrap();
        let opened_later = authority.open_fence(&[2; 16], &later_fence).unwrap();
        assert_eq!(opened_later.assignment(), opened_current.assignment());
        assert!(
            opened_later.local_lease_record().lease_generation()
                > opened_current.local_lease_record().lease_generation()
        );

        let replay_directory = TempDir::new().unwrap();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut reads = 0;
        let mut advancing_fence = || {
            reads += 1;
            Ok::<_, NetworkAdmissionError>(if reads == 1 {
                current_fence.clone()
            } else {
                later_fence.clone()
            })
        };
        assert!(matches!(
            dispatch
                .authenticate(&authority)
                .unwrap()
                .authorize_execution(&authority, &mut replay, &mut advancing_fence, &mut || Ok::<
                    _,
                    NetworkAdmissionError,
                >(
                    clock()
                ),),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert_eq!(reads, 2);

        assert!(matches!(
            NetworkLifecycleWorkerDispatchV1::decode(&bytes)
                .unwrap()
                .authenticate(&authority)
                .unwrap()
                .authorize_execution(
                    &authority,
                    &mut replay,
                    &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                    &mut || Ok::<_, NetworkAdmissionError>(clock()),
                ),
            Err(NetworkWorkerProtocolError::Replay)
        ));
    }

    #[test]
    fn lifecycle_pending_step_drop_failure_and_forget_all_stop_the_attempt() {
        let fixture = Fixture::new();

        let (authority, current_fence, mut dropped) = authorize_arm_execution(&fixture);
        drop(
            dropped
                .authorize_next_step(
                    &authority,
                    &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                    &mut || Ok::<_, NetworkAdmissionError>(clock()),
                )
                .unwrap()
                .unwrap(),
        );
        assert!(dropped.is_poisoned());
        assert!(matches!(
            dropped.authorize_next_step(
                &authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
            ),
            Err(NetworkWorkerProtocolError::ExecutionPoisoned)
        ));

        let (authority, current_fence, mut failed) = authorize_arm_execution(&fixture);
        failed
            .authorize_next_step(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap()
            .unwrap()
            .fail();
        assert!(failed.is_poisoned());
        assert!(matches!(
            failed.authorize_next_step(
                &authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
            ),
            Err(NetworkWorkerProtocolError::ExecutionPoisoned)
        ));

        let (authority, current_fence, mut forgotten) = authorize_arm_execution(&fixture);
        let pending = forgotten
            .authorize_next_step(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap()
            .unwrap();
        std::mem::forget(pending);
        assert!(matches!(
            forgotten.authorize_next_step(
                &authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
            ),
            Err(NetworkWorkerProtocolError::ExecutionPoisoned)
        ));
        assert!(forgotten.is_poisoned());
    }

    #[test]
    fn lifecycle_disarm_restores_the_exact_plan_and_destroy_never_grants_broker_teardown() {
        let fixture = Fixture::new();
        let mut disarm_case = lifecycle_case(&fixture);
        let disarm = issue_disarm_lifecycle_dispatch(&mut disarm_case, &fixture);
        assert_eq!(
            complete_lifecycle_step_order(&fixture, disarm),
            vec![
                NetworkLifecycleExecutionStepV1::LowerLinks,
                NetworkLifecycleExecutionStepV1::DisarmLeaseGate,
                NetworkLifecycleExecutionStepV1::ConfigureExactAddressPairs,
                NetworkLifecycleExecutionStepV1::ConfigureExactRoutes,
                NetworkLifecycleExecutionStepV1::ConfigureExactPermanentNeighbors,
                NetworkLifecycleExecutionStepV1::VerifyExactPlanConfiguration,
            ]
        );

        let mut destroy_case = lifecycle_case(&fixture);
        let destroy = issue_destroy_lifecycle_dispatch(&mut destroy_case, &fixture);
        assert_eq!(
            complete_lifecycle_step_order(&fixture, destroy),
            vec![
                NetworkLifecycleExecutionStepV1::LowerLinks,
                NetworkLifecycleExecutionStepV1::RemoveOwnedNetworkObjects,
                NetworkLifecycleExecutionStepV1::VerifyKernelOwnedObjectsAbsent,
            ]
        );
    }

    #[test]
    fn lifecycle_renew_is_atomic_and_cannot_resurrect_an_expired_prior_gate() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let (dispatch, prior_deadline) = issue_renew_lifecycle_dispatch(&mut case, &fixture);
        assert_eq!(
            renewal_boundary_clock().boottime_nanoseconds(),
            prior_deadline
        );
        let bytes = dispatch.encode().unwrap();
        let current_fence = dispatch.claimed_current_fence().to_vec();
        let authority = fixture.authority();

        let valid_replay_directory = TempDir::new().unwrap();
        let mut valid_replay =
            NetworkWorkerReplayLedger::open_for_test(valid_replay_directory.path()).unwrap();
        let mut execution = NetworkLifecycleWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap()
            .authorize_execution(
                &authority,
                &mut valid_replay,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(renewal_preboundary_clock()),
            )
            .unwrap();
        let step = execution
            .authorize_next_step(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(renewal_preboundary_clock()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            step.step(),
            NetworkLifecycleExecutionStepV1::ReplaceLeaseGateAtomically
        );
        step.complete_success(
            &authority,
            &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
            &mut || Ok::<_, NetworkAdmissionError>(renewal_preboundary_clock()),
        )
        .unwrap();
        assert!(execution.is_complete());

        let expired_replay_directory = TempDir::new().unwrap();
        let mut expired_replay =
            NetworkWorkerReplayLedger::open_for_test(expired_replay_directory.path()).unwrap();
        assert!(matches!(
            dispatch
                .authenticate(&authority)
                .unwrap()
                .authorize_execution(
                    &authority,
                    &mut expired_replay,
                    &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                    &mut || Ok::<_, NetworkAdmissionError>(renewal_boundary_clock()),
                ),
            Err(NetworkWorkerProtocolError::Authority)
        ));
    }

    #[test]
    fn lifecycle_authority_or_time_changes_before_and_during_a_step_poison_execution() {
        let fixture = Fixture::new();

        let (authority, current_fence, mut advanced) = authorize_arm_execution(&fixture);
        let mut later_case = lifecycle_case(&fixture);
        let later_dispatch = issue_destroy_lifecycle_dispatch(&mut later_case, &fixture);
        let later_fence = later_dispatch.claimed_current_fence().to_vec();
        let opened_current = authority.open_fence(&[2; 16], &current_fence).unwrap();
        let opened_later = authority.open_fence(&[2; 16], &later_fence).unwrap();
        assert_ne!(later_fence, current_fence);
        assert_eq!(opened_later.assignment(), opened_current.assignment());
        assert!(
            opened_later.local_lease_record().lease_generation()
                > opened_current.local_lease_record().lease_generation()
        );
        assert!(matches!(
            advanced.authorize_next_step(
                &authority,
                &mut || { Ok::<_, NetworkAdmissionError>(later_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
            ),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert!(advanced.is_poisoned());

        let (_authority, current_fence, mut before) = authorize_arm_execution(&fixture);
        let wrong_authority = fixture.authority_for(NodeId::from_bytes([99; 16]));
        assert!(matches!(
            before.authorize_next_step(
                &wrong_authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
            ),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert!(before.is_poisoned());

        let (authority, current_fence, mut during) = authorize_arm_execution(&fixture);
        let pending = during
            .authorize_next_step(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            pending.complete_success(
                &wrong_authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(clock()) }
            ),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert!(during.is_poisoned());

        let (authority, current_fence, mut expired_before) = authorize_arm_execution(&fixture);
        assert!(matches!(
            expired_before.authorize_next_step(
                &authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(expired_clock()) }
            ),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert!(expired_before.is_poisoned());

        let (authority, current_fence, mut expired_during) = authorize_arm_execution(&fixture);
        let pending = expired_during
            .authorize_next_step(
                &authority,
                &mut || Ok::<_, NetworkAdmissionError>(current_fence.clone()),
                &mut || Ok::<_, NetworkAdmissionError>(clock()),
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            pending.complete_success(
                &authority,
                &mut || { Ok::<_, NetworkAdmissionError>(current_fence.clone()) },
                &mut || { Ok::<_, NetworkAdmissionError>(expired_clock()) }
            ),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert!(expired_during.is_poisoned());
    }

    #[test]
    fn lifecycle_recovery_is_observe_only_and_committed_arm_replays_at_later_clock() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let (request, lease_digest, deadline, effect_digest) = admit_arm(&mut case, &fixture);
        let artifacts = fixture.lifecycle_artifacts(&request, 2, [52; 16]);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, case.resolution.clone(), &request);
        let substituted_plan = substituted_lifecycle_kernel_plan();
        assert_ne!(substituted_plan.digest(), case.kernel_plan.digest());

        assert_eq!(
            case.coordinator
                .admit_lifecycle_intent(
                    &request,
                    &artifacts,
                    &preparation,
                    &case.kernel_plan,
                    &case.namespaces,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &advanced_clock(),
                )
                .unwrap(),
            NetworkLifecycleAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkLifecyclePhase::Prepared,
                effect_digest,
            }
        );
        assert!(matches!(
            case.coordinator.admit_lifecycle_intent(
                &request,
                &artifacts,
                &preparation,
                &substituted_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &advanced_clock(),
            ),
            Err(NetworkBrokerError::LifecycleState(
                NetworkLifecycleStateError::Equivocation
            ))
        ));
        drop(
            case.coordinator
                .mark_effect_ambiguous([8; 16], effect_digest)
                .unwrap(),
        );

        let wrong_observation = transition_for(
            &case,
            [99; 16],
            NetworkNamespaceObservedStateV1::armed(lease_digest, 2, deadline).unwrap(),
            ObjectDigest::from_bytes([60; 32]),
        );
        let wrong_transition = NetworkNamespaceLifecycleTransitionV1::arm(
            wrong_observation,
            lease_digest,
            2,
            deadline,
        )
        .unwrap();
        assert!(
            case.coordinator
                .commit_verified_transition(
                    [8; 16],
                    effect_digest,
                    wrong_transition,
                    &mut case.namespaces,
                )
                .is_err()
        );
        assert_eq!(
            case.namespaces
                .current_namespace_observed_state([10; 32])
                .unwrap()
                .kind(),
            NetworkNamespaceObservedStateKindV1::DefaultDrop
        );

        let observation = transition_for(
            &case,
            [8; 16],
            NetworkNamespaceObservedStateV1::armed(lease_digest, 2, deadline).unwrap(),
            ObjectDigest::from_bytes([61; 32]),
        );
        let transition =
            NetworkNamespaceLifecycleTransitionV1::arm(observation, lease_digest, 2, deadline)
                .unwrap();
        let result = case
            .coordinator
            .commit_verified_transition([8; 16], effect_digest, transition, &mut case.namespaces)
            .unwrap();
        assert_eq!(result.action(), NetworkNamespaceLifecycleActionV1::Arm);
        assert_eq!(
            case.coordinator
                .admit_lifecycle_intent(
                    &request,
                    &artifacts,
                    &preparation,
                    &case.kernel_plan,
                    &case.namespaces,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &advanced_clock(),
                )
                .unwrap(),
            NetworkLifecycleAdmissionOutcome::Replay(result)
        );
        assert!(
            case.coordinator
                .admit_lifecycle_intent(
                    &request,
                    &artifacts,
                    &preparation,
                    &substituted_plan,
                    &case.namespaces,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &advanced_clock(),
                )
                .is_err()
        );

        drop(case.coordinator);
        let authority = fixture.authority();
        let creation =
            NetworkStateStore::open_for_test(&case.creation_directory, &authority, 0).unwrap();
        let lifecycle =
            NetworkLifecycleStateStore::open_for_test(&case.lifecycle_directory, &authority)
                .unwrap();
        let recovered = NetworkLifecycleAdmissionCoordinator::new(authority, creation, lifecycle);
        let entries = recovered.recovery_entries().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].phase(), DurableNetworkLifecyclePhase::Committed);
        assert_eq!(entries[0].effect_digest(), effect_digest);
    }

    #[test]
    fn combined_creation_uses_lifecycle_fence_and_recreates_only_a_new_incarnation() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let (_, _, _, destroy_request, stale_prepare) = lifecycle_requests(&fixture);
        let destroy_artifacts = fixture.lifecycle_artifacts(&destroy_request, 4, [64; 16]);
        let authority = fixture.authority();
        let preparation =
            authenticated_catalog(&authority, case.resolution.clone(), &destroy_request);
        let NetworkLifecycleAdmissionOutcome::Prepared {
            effect_digest: destroy_effect,
        } = case
            .coordinator
            .admit_lifecycle_intent(
                &destroy_request,
                &destroy_artifacts,
                &preparation,
                &case.kernel_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("destroy did not prepare");
        };
        drop(
            case.coordinator
                .mark_effect_ambiguous([10; 16], destroy_effect)
                .unwrap(),
        );

        let destruction = transition_for(
            &case,
            [10; 16],
            NetworkNamespaceObservedStateV1::absent(),
            ObjectDigest::from_bytes([65; 32]),
        );
        fs::remove_file(case.pin_directory.join(encode_handle(&[10; 32]))).unwrap();
        case.coordinator
            .commit_verified_transition(
                [10; 16],
                destroy_effect,
                NetworkNamespaceLifecycleTransitionV1::destroy(destruction).unwrap(),
                &mut case.namespaces,
            )
            .unwrap();

        // This lease follows the creation journal's old lease generation, but
        // predates the destroy fence. The combined path must not resurrect it.
        let stale_resolution = catalog_for(10, 20, 21, &[]);
        let stale_artifacts = fixture.lifecycle_artifacts(&stale_prepare, 2, [66; 16]);
        let authority = fixture.authority();
        let stale_catalog =
            authenticated_catalog(&authority, stale_resolution.clone(), &stale_prepare);
        assert!(matches!(
            case.coordinator.admit_apply_intent(
                &stale_prepare,
                &stale_artifacts,
                &stale_catalog,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));

        let recreate = request_for_complete_assignment(12, 2, 19, 5, 1, 22, &[]);
        let recreate_artifacts =
            fixture.artifacts_authorizing_lease(&recreate, &[&recreate], 5, [67; 16]);
        let authority = fixture.authority();
        let recreate_catalog = authenticated_catalog(&authority, stale_resolution, &recreate);
        assert!(matches!(
            case.coordinator
                .admit_apply_intent(
                    &recreate,
                    &recreate_artifacts,
                    &recreate_catalog,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            NetworkAdmissionOutcome::Prepared { .. }
        ));

        // Once creation advances to epoch five, the old epoch-four lifecycle
        // fence can no longer authorize another mutation of the retired handle.
        assert!(matches!(
            case.coordinator.admit_lifecycle_intent(
                &destroy_request,
                &destroy_artifacts,
                &preparation,
                &case.kernel_plan,
                &case.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));
    }

    #[test]
    fn combined_creation_rejects_incomparable_authenticated_journal_heads() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let conflicting_request = request_for_assignment(13, 2, 5, 77, &[]);
        let conflicting_artifacts = fixture.artifacts(&conflicting_request);
        let authority = fixture.authority();
        let semantics = CanonicalNetworkSemanticsV1::decode(
            &conflicting_request,
            peer(),
            peer_policy(),
            clock().boottime_nanoseconds(),
        )
        .unwrap();
        let admission = authority
            .admit(
                &conflicting_artifacts,
                &semantics,
                &conflicting_request,
                ProtocolVersion::new(1, 0),
                &clock(),
                None,
            )
            .unwrap();
        let conflicting_fence = authority.seal_fence(&[2; 16], &admission).unwrap();
        let creation_fence = case.coordinator.creation_fence_for_test([2; 16]).unwrap();

        assert!(matches!(
            authority.latest_fence(
                &[2; 16],
                [
                    Some(creation_fence.as_slice()),
                    Some(conflicting_fence.as_slice())
                ]
            ),
            Err(NetworkAdmissionError::FenceRejected)
        ));
        assert!(matches!(
            authority.latest_fence(
                &[2; 16],
                [
                    Some(conflicting_fence.as_slice()),
                    Some(creation_fence.as_slice())
                ]
            ),
            Err(NetworkAdmissionError::FenceRejected)
        ));

        case.coordinator
            .lifecycle_state_mut_for_test()
            .replace_current_fence_for_test([2; 16], conflicting_fence)
            .unwrap();
        let candidate_request = request_for(14, 2, &[]);
        let candidate_artifacts = fixture.lifecycle_artifacts(&candidate_request, 2, [68; 16]);
        let authority = fixture.authority();
        let candidate_catalog =
            authenticated_catalog(&authority, catalog_for(10, 20, 21, &[]), &candidate_request);
        assert!(matches!(
            case.coordinator.admit_apply_intent(
                &candidate_request,
                &candidate_artifacts,
                &candidate_catalog,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));
    }

    #[test]
    fn lifecycle_recovery_rejects_missing_head_and_missing_or_stale_fence() {
        let fixture = Fixture::new();

        let mut missing_head = lifecycle_case(&fixture);
        admit_arm(&mut missing_head, &fixture);
        missing_head
            .coordinator
            .lifecycle_state_mut_for_test()
            .delete_handle_head_for_test([10; 32])
            .unwrap();
        drop(missing_head.coordinator);
        assert!(
            NetworkLifecycleStateStore::open_for_test(
                &missing_head.lifecycle_directory,
                &fixture.authority(),
            )
            .is_err()
        );

        let mut missing_fence = lifecycle_case(&fixture);
        admit_arm(&mut missing_fence, &fixture);
        missing_fence
            .coordinator
            .lifecycle_state_mut_for_test()
            .delete_desired_fence_for_test([2; 16])
            .unwrap();
        drop(missing_fence.coordinator);
        assert!(
            NetworkLifecycleStateStore::open_for_test(
                &missing_fence.lifecycle_directory,
                &fixture.authority(),
            )
            .is_err()
        );

        let mut stale_fence = lifecycle_case(&fixture);
        let (_, lease_digest, deadline, arm_effect) = admit_arm(&mut stale_fence, &fixture);
        drop(
            stale_fence
                .coordinator
                .mark_effect_ambiguous([8; 16], arm_effect)
                .unwrap(),
        );
        let arm_observation = transition_for(
            &stale_fence,
            [8; 16],
            NetworkNamespaceObservedStateV1::armed(lease_digest, 2, deadline).unwrap(),
            ObjectDigest::from_bytes([61; 32]),
        );
        let arm_transition =
            NetworkNamespaceLifecycleTransitionV1::arm(arm_observation, lease_digest, 2, deadline)
                .unwrap();
        stale_fence
            .coordinator
            .commit_verified_transition(
                [8; 16],
                arm_effect,
                arm_transition,
                &mut stale_fence.namespaces,
            )
            .unwrap();

        let (_, _, disarm_request, _, _) = lifecycle_requests(&fixture);
        let disarm_artifacts = fixture.lifecycle_artifacts(&disarm_request, 3, [53; 16]);
        let authority = fixture.authority();
        let preparation =
            authenticated_catalog(&authority, stale_fence.resolution.clone(), &disarm_request);
        let NetworkLifecycleAdmissionOutcome::Prepared {
            effect_digest: disarm_effect,
        } = stale_fence
            .coordinator
            .admit_lifecycle_intent(
                &disarm_request,
                &disarm_artifacts,
                &preparation,
                &stale_fence.kernel_plan,
                &stale_fence.namespaces,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("disarm did not prepare");
        };
        drop(
            stale_fence
                .coordinator
                .mark_effect_ambiguous([9; 16], disarm_effect)
                .unwrap(),
        );
        let disarm_observation = transition_for(
            &stale_fence,
            [9; 16],
            NetworkNamespaceObservedStateV1::default_drop(),
            ObjectDigest::from_bytes([62; 32]),
        );
        let disarm_transition =
            NetworkNamespaceLifecycleTransitionV1::disarm(disarm_observation).unwrap();
        stale_fence
            .coordinator
            .commit_verified_transition(
                [9; 16],
                disarm_effect,
                disarm_transition,
                &mut stale_fence.namespaces,
            )
            .unwrap();
        stale_fence
            .coordinator
            .lifecycle_state_mut_for_test()
            .restore_historical_fence_for_test([2; 16], [8; 16])
            .unwrap();
        drop(stale_fence.coordinator);
        assert!(
            NetworkLifecycleStateStore::open_for_test(
                &stale_fence.lifecycle_directory,
                &fixture.authority(),
            )
            .is_err()
        );
    }

    #[test]
    fn lifecycle_ambiguous_restart_preserves_effect_and_recovers_catalog_first_crash() {
        let fixture = Fixture::new();
        let mut case = lifecycle_case(&fixture);
        let (request, lease_digest, deadline, effect_digest) = admit_arm(&mut case, &fixture);
        drop(
            case.coordinator
                .mark_effect_ambiguous([8; 16], effect_digest)
                .unwrap(),
        );

        let LifecycleCase {
            _directory,
            creation_directory,
            lifecycle_directory,
            namespace_directory,
            pin_directory,
            resolution,
            kernel_plan,
            mut namespaces,
            coordinator,
        } = case;
        drop(coordinator);

        let authority = fixture.authority();
        let creation =
            NetworkStateStore::open_for_test(&creation_directory, &authority, 0).unwrap();
        let lifecycle =
            NetworkLifecycleStateStore::open_for_test(&lifecycle_directory, &authority).unwrap();
        let mut recovered =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation, lifecycle);
        let artifacts = fixture.lifecycle_artifacts(&request, 2, [52; 16]);
        let authority = fixture.authority();
        let preparation = authenticated_catalog(&authority, resolution.clone(), &request);
        assert_eq!(
            recovered
                .admit_lifecycle_intent(
                    &request,
                    &artifacts,
                    &preparation,
                    &kernel_plan,
                    &namespaces,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &advanced_clock(),
                )
                .unwrap(),
            NetworkLifecycleAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkLifecyclePhase::Ambiguous,
                effect_digest,
            }
        );

        let assignment = decode_assignment(&request).unwrap();
        let current = namespaces
            .authorize_current_lifecycle([10; 32], assignment, resolution.binding())
            .unwrap();
        let observation = NetworkNamespaceLifecycleObservationV1::new(
            [8; 16],
            current.resource_digest,
            current.identity,
            NetworkNamespaceObservedStateV1::armed(lease_digest, 2, deadline).unwrap(),
            ObjectDigest::from_bytes([63; 32]),
        )
        .unwrap();
        let transition =
            NetworkNamespaceLifecycleTransitionV1::arm(observation, lease_digest, 2, deadline)
                .unwrap();

        // Simulate a crash after the catalog CAS but before the lifecycle
        // journal can record Committed.
        assert_eq!(
            namespaces.apply_lifecycle_transition(transition).unwrap(),
            crate::NetworkNamespaceLifecycleOutcomeV1::Applied
        );
        let catalog_generation = namespaces.generation();
        let catalog_state = namespaces
            .current_namespace_observed_state([10; 32])
            .unwrap();
        drop(recovered);
        drop(namespaces);

        let mut namespaces = NetworkNamespaceCatalogV1::open_for_test(
            &namespace_directory,
            &pin_directory,
            [50; 16],
            [91; 16],
        )
        .unwrap();
        assert_eq!(namespaces.generation(), catalog_generation);
        assert_eq!(
            namespaces
                .current_namespace_observed_state([10; 32])
                .unwrap(),
            catalog_state
        );

        let authority = fixture.authority();
        let creation =
            NetworkStateStore::open_for_test(&creation_directory, &authority, 0).unwrap();
        let lifecycle =
            NetworkLifecycleStateStore::open_for_test(&lifecycle_directory, &authority).unwrap();
        let mut recovered =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation, lifecycle);
        assert_eq!(
            recovered
                .admit_lifecycle_intent(
                    &request,
                    &artifacts,
                    &preparation,
                    &kernel_plan,
                    &namespaces,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &advanced_clock(),
                )
                .unwrap(),
            NetworkLifecycleAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkLifecyclePhase::Ambiguous,
                effect_digest,
            }
        );
        let result = recovered
            .commit_verified_transition([8; 16], effect_digest, transition, &mut namespaces)
            .unwrap();
        assert_eq!(namespaces.generation(), catalog_generation);
        assert_eq!(
            recovered
                .admit_lifecycle_intent(
                    &request,
                    &artifacts,
                    &preparation,
                    &kernel_plan,
                    &namespaces,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &advanced_clock(),
                )
                .unwrap(),
            NetworkLifecycleAdmissionOutcome::Replay(result)
        );
    }

    #[test]
    fn lifecycle_recovery_rejects_authenticated_but_semantically_mislinked_records() {
        let fixture = Fixture::new();

        let mut transport_mislink = lifecycle_case(&fixture);
        admit_arm(&mut transport_mislink, &fixture);
        transport_mislink
            .coordinator
            .corrupt_transport_link_for_test([8; 16], ObjectDigest::from_bytes([99; 32]))
            .unwrap();
        drop(transport_mislink.coordinator);
        assert!(
            NetworkLifecycleStateStore::open_for_test(
                &transport_mislink.lifecycle_directory,
                &fixture.authority(),
            )
            .is_err()
        );

        let mut fence_mislink = lifecycle_case(&fixture);
        admit_arm(&mut fence_mislink, &fixture);
        let creation_fence = fence_mislink
            .coordinator
            .creation_fence_for_test([2; 16])
            .unwrap();
        assert!(!creation_fence.is_empty());
        fence_mislink
            .coordinator
            .corrupt_current_fence_link_for_test([8; 16], creation_fence)
            .unwrap();
        drop(fence_mislink.coordinator);
        assert!(
            NetworkLifecycleStateStore::open_for_test(
                &fence_mislink.lifecycle_directory,
                &fixture.authority(),
            )
            .is_err()
        );
    }

    fn isolated_worker_case() -> (Vec<u8>, ResolvedNetworkPreparationV1, NetworkKernelPlanV1) {
        let request = request_for(7, 2, &[]);
        let catalog = catalog_for(9, 10, 11, &[]);
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Isolated,
            ObjectDigest::from_bytes([55; 32]),
            None,
            Vec::new(),
        )
        .unwrap();
        let namespace = NetworkNamespacePlanV1::derive(
            [10; 32],
            1,
            ObjectDigest::from_bytes([11; 32]),
            &policy,
            &NetworkAllocationPolicyV1::isolated(),
        )
        .unwrap();
        let plan =
            NetworkKernelPlanV1::compile(decode_assignment(&request).unwrap(), &namespace, &policy)
                .unwrap();

        (request, catalog, plan)
    }

    fn nonempty_worker_case() -> (
        Vec<u8>,
        ResolvedNetworkPreparationV1,
        NetworkKernelPlanV1,
        NetworkKernelPlanV1,
    ) {
        let request = request_for(7, 2, &[7]);
        let first_flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Ingress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([198, 51, 100, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let substituted_flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Ingress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([203, 0, 113, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let endpoint_id = NetworkEndpointId::from_bytes([7; 16]);
        let endpoint = NetworkEndpointPolicyV1::new(endpoint_id, vec![first_flow]).unwrap();
        let substituted_endpoint =
            NetworkEndpointPolicyV1::new(endpoint_id, vec![substituted_flow]).unwrap();
        let catalog = ResolvedNetworkPreparationV1::new(
            9,
            [10; 32],
            ObjectDigest::from_bytes([11; 32]),
            vec![ResolvedEndpointV1::new([7; 16], endpoint.digest()).unwrap()],
        )
        .unwrap();
        let allocation = NetworkAllocationPolicyV1::veth(
            1_500,
            [0x02, 0xaa, 0xbb],
            vec![
                NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 40, 0, 0], 17).unwrap())
                    .unwrap(),
            ],
            Vec::new(),
        )
        .unwrap();
        let assignment = decode_assignment(&request).unwrap();
        let compile = |endpoint| {
            let policy = NetworkPolicyProgramV1::new(
                NetworkKind::Project,
                ObjectDigest::from_bytes([55; 32]),
                Some(ObjectDigest::from_bytes([56; 32])),
                vec![endpoint],
            )
            .unwrap();
            let namespace = NetworkNamespacePlanV1::derive(
                [10; 32],
                1,
                ObjectDigest::from_bytes([11; 32]),
                &policy,
                &allocation,
            )
            .unwrap();
            NetworkKernelPlanV1::compile(assignment, &namespace, &policy).unwrap()
        };

        (
            request,
            catalog,
            compile(endpoint),
            compile(substituted_endpoint),
        )
    }

    #[test]
    fn prevalidated_effect_clock_has_an_exact_boottime_boundary() {
        let fixture = Fixture::new();
        let mut fresh = prepared_execution_case(&fixture);
        let mut fresh_samples = 0;
        let fresh_outcome = fresh
            .coordinator
            .begin_prepare_effect_once(
                [7; 16],
                fresh.effect_digest,
                &fresh.request,
                fresh.plan,
                &mut || {
                    fresh_samples += 1;
                    Ok(clock_at(179))
                },
            )
            .unwrap();

        assert_eq!(fresh_samples, 1);
        assert!(matches!(
            fresh_outcome,
            NetworkPrepareExecutionOutcomeV1::Dispatch(_)
        ));
        assert_eq!(
            fresh.coordinator.creation_state.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Ambiguous)
        );

        let mut expired = prepared_execution_case(&fixture);
        let mut expired_samples = 0;
        let expired_outcome = expired
            .coordinator
            .begin_prepare_effect_once(
                [7; 16],
                expired.effect_digest,
                &expired.request,
                expired.plan,
                &mut || {
                    expired_samples += 1;
                    Ok(clock_at(180))
                },
            )
            .unwrap();

        assert_eq!(expired_samples, 1);
        assert!(matches!(
            expired_outcome,
            NetworkPrepareExecutionOutcomeV1::Aborted { effect_digest }
                if effect_digest == expired.effect_digest
        ));
        assert_eq!(
            expired.coordinator.creation_state.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Aborted)
        );
    }

    #[test]
    fn malformed_or_substituted_dispatch_is_rejected_before_clock_or_journal() {
        let fixture = Fixture::new();
        let mut malformed = prepared_execution_case(&fixture);
        let sequence = malformed
            .coordinator
            .creation_state
            .journal_sequence_for_test();
        let mut malformed_samples = 0;

        assert!(
            malformed
                .coordinator
                .begin_prepare_effect_once(
                    [7; 16],
                    malformed.effect_digest,
                    &[0xff],
                    malformed.plan,
                    &mut || {
                        malformed_samples += 1;
                        Ok(clock_at(179))
                    },
                )
                .is_err()
        );
        assert_eq!(malformed_samples, 0);
        assert_eq!(
            malformed
                .coordinator
                .creation_state
                .journal_sequence_for_test(),
            sequence
        );
        assert_eq!(
            malformed.coordinator.creation_state.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Prepared)
        );

        let (request, resolution, valid_plan, substituted_plan) = nonempty_worker_case();
        let mut substituted =
            prepared_execution_case_from(&fixture, request, resolution, valid_plan);
        let sequence = substituted
            .coordinator
            .creation_state
            .journal_sequence_for_test();
        let mut substituted_samples = 0;

        assert!(
            substituted
                .coordinator
                .begin_prepare_effect_once(
                    [7; 16],
                    substituted.effect_digest,
                    &substituted.request,
                    substituted_plan,
                    &mut || {
                        substituted_samples += 1;
                        Ok(clock_at(179))
                    },
                )
                .is_err()
        );
        assert_eq!(substituted_samples, 0);
        assert_eq!(
            substituted
                .coordinator
                .creation_state
                .journal_sequence_for_test(),
            sequence
        );
        assert_eq!(
            substituted
                .coordinator
                .creation_state
                .phase([7; 16])
                .unwrap(),
            Some(DurableNetworkPhase::Prepared)
        );
    }

    #[test]
    fn invalid_protected_clocks_leave_prepared_state_unchanged() {
        let fixture = Fixture::new();
        let wrong_boot = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [51; 16],
            150,
            179,
        )
        .unwrap();
        let wrong_provenance = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"bad-kernel-clock").unwrap(),
            [50; 16],
            150,
            179,
        )
        .unwrap();
        let backwards = clock_at(99);
        let wall_only_advance = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            200,
            100,
        )
        .unwrap();

        for invalid_clock in [wrong_boot, wrong_provenance, backwards, wall_only_advance] {
            let mut case = prepared_execution_case(&fixture);
            let sequence = case.coordinator.creation_state.journal_sequence_for_test();
            let mut samples = 0;

            assert!(
                case.coordinator
                    .begin_prepare_effect_once(
                        [7; 16],
                        case.effect_digest,
                        &case.request,
                        case.plan,
                        &mut || {
                            samples += 1;
                            Ok(invalid_clock)
                        },
                    )
                    .is_err()
            );
            assert_eq!(samples, 1);
            assert_eq!(
                case.coordinator.creation_state.journal_sequence_for_test(),
                sequence
            );
            assert_eq!(
                case.coordinator.creation_state.phase([7; 16]).unwrap(),
                Some(DurableNetworkPhase::Prepared)
            );
        }
    }

    #[test]
    fn terminal_transition_rechecks_every_persisted_authority_link() {
        let fixture = Fixture::new();
        for (namespace, key, marker) in [
            (RecordNamespace::DesiredState, [2; 16], 1),
            (RecordNamespace::AuthorityPublication, [7; 16], 2),
            (RecordNamespace::Effect, [7; 16], 3),
        ] {
            let mut case = prepared_execution_case(&fixture);
            let (authority, state) = (
                &case.coordinator.authority,
                &mut case.coordinator.creation_state,
            );
            let prepared = state
                .prepare_effect_dispatch(authority, [7; 16], case.effect_digest)
                .unwrap();
            state
                .put_authority_record_for_test(namespace, &key, vec![99; 32], marker)
                .unwrap();

            assert!(state.abort_prepared_exact(authority, prepared).is_err());
            assert_eq!(
                state.phase([7; 16]).unwrap(),
                Some(DurableNetworkPhase::Prepared)
            );
        }
    }

    #[test]
    fn expired_abort_is_durable_replayable_and_cannot_reach_downstream_phases() {
        let fixture = Fixture::new();
        let mut case = prepared_execution_case(&fixture);
        let crash_before_abort = copy_network_state_directory(&case.creation_directory);
        let sequence_before = case
            .coordinator
            .preparation_recovery_snapshot()
            .unwrap()
            .sequence();
        let outcome = case
            .coordinator
            .begin_prepare_effect_once(
                [7; 16],
                case.effect_digest,
                &case.request,
                case.plan.clone(),
                &mut || Ok(clock_at(180)),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            NetworkPrepareExecutionOutcomeV1::Aborted { .. }
        ));

        let sequence_after = case
            .coordinator
            .preparation_recovery_snapshot()
            .unwrap()
            .sequence();
        assert!(sequence_after > sequence_before);
        assert!(
            case.coordinator
                .bind_effect_namespace_custody(
                    [7; 16],
                    case.effect_digest,
                    [10; 32],
                    [50; 16],
                    51,
                    52,
                    case.plan.digest(),
                )
                .is_err()
        );
        let verified = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&case.request).into()),
            &case.resolution,
            [50; 16],
            51,
            52,
            case.plan.digest(),
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        assert!(
            case.coordinator
                .commit_verified_preparation([7; 16], case.effect_digest, verified)
                .is_err()
        );

        assert!(matches!(
            case.coordinator.admit_apply_intent(
                &case.request,
                &case.artifacts,
                &case.preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock_at(180),
            ),
            Ok(NetworkAdmissionOutcome::Aborted { effect_digest })
                if effect_digest == case.effect_digest
        ));
        assert_eq!(
            case.coordinator
                .preparation_recovery_snapshot()
                .unwrap()
                .sequence(),
            sequence_after
        );

        let mut substituted_request =
            ApplyNetworkRequest::decode_from_slice(&case.request).unwrap();
        substituted_request.endpoint_ids.push(vec![99; 16]);
        let substituted_request = substituted_request.encode_to_vec();
        assert!(matches!(
            case.coordinator.admit_apply_intent(
                &substituted_request,
                &case.artifacts,
                &case.preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
        let substituted_resolution = catalog_for(9, 10, 12, &[]);
        let substituted_preparation = authenticated_catalog(
            &case.coordinator.authority,
            substituted_resolution,
            &case.request,
        );
        assert!(matches!(
            case.coordinator.admit_apply_intent(
                &case.request,
                &case.artifacts,
                &substituted_preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
        assert_eq!(
            case.coordinator
                .preparation_recovery_snapshot()
                .unwrap()
                .sequence(),
            sequence_after
        );

        drop(case.coordinator);
        let authority = fixture.authority();
        let prepared_reopen =
            NetworkStateStore::open_for_test(crash_before_abort.path(), &authority, 0).unwrap();
        assert_eq!(
            prepared_reopen.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Prepared)
        );
        drop(prepared_reopen);

        let creation =
            NetworkStateStore::open_for_test(&case.creation_directory, &authority, 0).unwrap();
        let lifecycle =
            NetworkLifecycleStateStore::open_for_test(&case.lifecycle_directory, &authority)
                .unwrap();
        let recovered = NetworkLifecycleAdmissionCoordinator::new(authority, creation, lifecycle);
        let snapshot = recovered.preparation_recovery_snapshot().unwrap();
        let entry = &snapshot.entries()[0];
        assert_eq!(entry.phase(), DurableNetworkPhase::Aborted);
        assert_eq!(entry.catalog_resolution(), &case.resolution);

        let namespace = NamespaceFd::current_network().unwrap();
        assert!(
            recovered
                .recover_ambiguous_preparation_observation([7; 16], case.effect_digest, &namespace,)
                .is_err()
        );
    }

    #[test]
    fn abort_failure_poisons_authority_until_reopen() {
        let fixture = Fixture::new();
        let mut case = prepared_execution_case(&fixture);
        let sequence_before = case.coordinator.creation_state.journal_sequence_for_test();
        case.coordinator
            .creation_state
            .fail_after_next_journal_commit_for_test();

        assert!(
            case.coordinator
                .begin_prepare_effect_once(
                    [7; 16],
                    case.effect_digest,
                    &case.request,
                    case.plan.clone(),
                    &mut || Ok(clock_at(180)),
                )
                .is_err()
        );
        assert!(case.coordinator.creation_state.journal_sequence_for_test() > sequence_before);
        assert!(matches!(
            case.coordinator.creation_state.recovery_snapshot(),
            Err(NetworkStateError::Journal(
                aos_sandbox::JournalError::Poisoned
            ))
        ));
        assert!(matches!(
            case.coordinator.creation_state.recovery_entries(),
            Err(NetworkStateError::Journal(
                aos_sandbox::JournalError::Poisoned
            ))
        ));
        assert!(matches!(
            case.coordinator.creation_state.phase([7; 16]),
            Err(NetworkStateError::Journal(
                aos_sandbox::JournalError::Poisoned
            ))
        ));
        assert!(matches!(
            case.coordinator.preparation_recovery_snapshot(),
            Err(NetworkBrokerError::State(NetworkStateError::Journal(
                aos_sandbox::JournalError::Poisoned
            )))
        ));
        assert!(matches!(
            case.coordinator.begin_prepare_effect_once(
                [7; 16],
                case.effect_digest,
                &case.request,
                case.plan,
                &mut || Ok(clock_at(179)),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Journal(
                aos_sandbox::JournalError::Poisoned
            )))
        ));
        drop(case.coordinator);

        let authority = fixture.authority();
        let reopened_creation =
            NetworkStateStore::open_for_test(&case.creation_directory, &authority, 0).unwrap();
        assert_eq!(
            reopened_creation.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Aborted)
        );
        assert_eq!(
            reopened_creation.recovery_entries().unwrap()[0].phase(),
            DurableNetworkPhase::Aborted
        );
        assert_eq!(
            reopened_creation.recovery_snapshot().unwrap().entries()[0].phase(),
            DurableNetworkPhase::Aborted
        );

        let reopened_lifecycle =
            NetworkLifecycleStateStore::open_for_test(&case.lifecycle_directory, &authority)
                .unwrap();
        let reopened = NetworkLifecycleAdmissionCoordinator::new(
            authority,
            reopened_creation,
            reopened_lifecycle,
        );
        assert_eq!(
            reopened.preparation_recovery_snapshot().unwrap().entries()[0].phase(),
            DurableNetworkPhase::Aborted
        );
    }

    #[test]
    fn aborted_handle_lineage_allows_only_exact_resolution_replacement() {
        let fixture = Fixture::new();
        let mut exact = prepared_execution_case(&fixture);
        exact
            .coordinator
            .begin_prepare_effect_once(
                [7; 16],
                exact.effect_digest,
                &exact.request,
                exact.plan,
                &mut || Ok(clock_at(180)),
            )
            .unwrap();
        let replacement = request_for(8, 2, &[]);
        let replacement_artifacts = fixture.artifacts(&replacement);
        let replacement_preparation = authenticated_catalog(
            &exact.coordinator.authority,
            exact.resolution.clone(),
            &replacement,
        );
        assert!(matches!(
            exact.coordinator.admit_apply_intent(
                &replacement,
                &replacement_artifacts,
                &replacement_preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Ok(NetworkAdmissionOutcome::Prepared { .. })
        ));
        let phases = exact
            .coordinator
            .preparation_recovery_snapshot()
            .unwrap()
            .entries()
            .iter()
            .map(|entry| entry.phase())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![DurableNetworkPhase::Aborted, DurableNetworkPhase::Prepared]
        );

        let blocked = request_for(9, 2, &[]);
        let blocked_artifacts = fixture.artifacts(&blocked);
        let blocked_preparation = authenticated_catalog(
            &exact.coordinator.authority,
            exact.resolution.clone(),
            &blocked,
        );
        assert!(matches!(
            exact.coordinator.admit_apply_intent(
                &blocked,
                &blocked_artifacts,
                &blocked_preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(
                NetworkStateError::PendingConflict
            ))
        ));

        let mut changed_resolution = prepared_execution_case(&fixture);
        changed_resolution
            .coordinator
            .begin_prepare_effect_once(
                [7; 16],
                changed_resolution.effect_digest,
                &changed_resolution.request,
                changed_resolution.plan,
                &mut || Ok(clock_at(180)),
            )
            .unwrap();
        let replacement = request_for(8, 2, &[]);
        let changed = catalog_for(9, 10, 12, &[]);
        let changed_preparation = authenticated_catalog(
            &changed_resolution.coordinator.authority,
            changed,
            &replacement,
        );
        assert!(matches!(
            changed_resolution.coordinator.admit_apply_intent(
                &replacement,
                &fixture.artifacts(&replacement),
                &changed_preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));

        let mut changed_sandbox = prepared_execution_case(&fixture);
        changed_sandbox
            .coordinator
            .begin_prepare_effect_once(
                [7; 16],
                changed_sandbox.effect_digest,
                &changed_sandbox.request,
                changed_sandbox.plan,
                &mut || Ok(clock_at(180)),
            )
            .unwrap();
        let replacement = request_for(8, 3, &[]);
        let changed_preparation = authenticated_catalog(
            &changed_sandbox.coordinator.authority,
            changed_sandbox.resolution.clone(),
            &replacement,
        );
        assert!(matches!(
            changed_sandbox.coordinator.admit_apply_intent(
                &replacement,
                &fixture.artifacts(&replacement),
                &changed_preparation,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    fn issue_isolated_worker_dispatch(
        directory: &Path,
        fixture: &Fixture,
    ) -> (Vec<u8>, NetworkKernelPlanV1) {
        let (request, catalog, plan) = isolated_worker_case();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog, &request);
        let store = NetworkStateStore::open_for_test(directory, &authority, 0).unwrap();
        let lifecycle_directory = directory.join("lifecycle");
        fs::create_dir(&lifecycle_directory).unwrap();
        let lifecycle =
            NetworkLifecycleStateStore::open_for_test(&lifecycle_directory, &authority).unwrap();
        let mut coordinator =
            NetworkLifecycleAdmissionCoordinator::new(authority, store, lifecycle);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("worker request did not prepare the effect");
        };
        let outcome = crate::preparation_runtime::begin_network_preparation_once(
            &mut coordinator,
            [7; 16],
            effect_digest,
            &request,
            plan.clone(),
            &mut || Ok(clock()),
        )
        .unwrap();
        let NetworkPrepareExecutionOutcomeV1::Dispatch(dispatch) = outcome else {
            panic!("fresh worker request was unexpectedly aborted");
        };

        assert!(
            crate::preparation_runtime::begin_network_preparation_once(
                &mut coordinator,
                [7; 16],
                effect_digest,
                &request,
                plan.clone(),
                &mut || Ok(clock()),
            )
            .is_err()
        );

        let retained = NamespaceFd::current_network().unwrap();
        let identity = retained.identity();
        let kernel_boot_id = KernelBootId::current().unwrap().into_bytes();
        coordinator
            .bind_effect_namespace_custody(
                [7; 16],
                effect_digest,
                [10; 32],
                kernel_boot_id,
                identity.device,
                identity.inode,
                plan.digest(),
            )
            .unwrap();
        let recovery = coordinator
            .recover_ambiguous_preparation_observation([7; 16], effect_digest, &retained)
            .unwrap();
        assert_eq!(recovery.request_id(), [7; 16]);
        assert_eq!(recovery.effect_digest(), effect_digest);
        assert_eq!(recovery.kernel_plan_digest(), plan.digest());
        assert_eq!(recovery.namespace().identity(), identity);
        assert!(
            coordinator
                .recover_ambiguous_preparation_observation([8; 16], effect_digest, &retained,)
                .is_err()
        );
        assert!(
            coordinator
                .recover_ambiguous_preparation_observation(
                    [7; 16],
                    ObjectDigest::from_bytes([99; 32]),
                    &retained,
                )
                .is_err()
        );

        (dispatch.encode().unwrap(), plan)
    }

    fn key_ref(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn copy_network_state_directory(source: &Path) -> TempDir {
        let copy = TempDir::new().unwrap();
        fs::copy(
            source.join("network-state.journal"),
            copy.path().join("network-state.journal"),
        )
        .unwrap();
        copy
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
    fn signed_expiring(
        bytes: &[u8],
        media: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &aos_sandbox_core::ObjectDescriptor,
        key: &SigningKey,
        expires_seconds: i64,
    ) -> Vec<u8> {
        let subject =
            descriptor_for_bytes(MediaType::new(media.as_str().to_owned()).unwrap(), bytes);
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            100,
            Some(expires_seconds),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }

    fn validated(
        artifacts: BrokerAuthorizationArtifactsV1,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_NETWORK_APPLY.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::NetworkBroker, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }

    #[test]
    fn only_authoritative_inventory_is_advertised() {
        assert_eq!(
            advertised_network_methods(),
            [BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES]
        );
    }

    #[test]
    fn worker_dispatch_authenticates_and_rejects_replay_after_restart() {
        let state_directory = TempDir::new().unwrap();
        let replay_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (bytes, expected_plan) =
            issue_isolated_worker_dispatch(state_directory.path(), &fixture);

        let authority = fixture.authority();
        let dispatch = NetworkPrepareWorkerDispatchV1::decode(&bytes).unwrap();
        assert_eq!(dispatch.encode().unwrap(), bytes);
        let authenticated = dispatch.authenticate(&authority).unwrap();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut trusted_clock = || Ok(clock());
        let mutation = authenticated
            .authorize_mutation(&authority, &mut replay, &mut trusted_clock)
            .unwrap();
        assert_eq!(mutation.kernel_plan(), &expected_plan);
        assert_eq!(
            mutation
                .authorize_activation(&authority, &mut trusted_clock)
                .unwrap()
                .kernel_plan(),
            &expected_plan
        );
        drop(mutation);
        drop(replay);

        let replayed = NetworkPrepareWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap();
        let mut reopened =
            NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        assert!(matches!(
            replayed.authorize_mutation(&authority, &mut reopened, &mut trusted_clock),
            Err(NetworkWorkerProtocolError::Replay)
        ));
    }

    #[test]
    fn mutation_and_activation_recheck_current_authority() {
        let state_directory = TempDir::new().unwrap();
        let replay_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (bytes, _) = issue_isolated_worker_dispatch(state_directory.path(), &fixture);
        let authority = fixture.authority();
        let changed_authority = fixture.authority_for(NodeId::from_bytes([99; 16]));
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut trusted_clock = || Ok(clock());

        let before_mutation = NetworkPrepareWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap();
        assert!(matches!(
            before_mutation.authorize_mutation(&changed_authority, &mut replay, &mut trusted_clock),
            Err(NetworkWorkerProtocolError::Authority)
        ));

        // Rejection precedes the durable claim, so the unchanged authority may
        // still consume the one legitimate attempt.
        let authenticated = NetworkPrepareWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap();
        let mutation = authenticated
            .authorize_mutation(&authority, &mut replay, &mut trusted_clock)
            .unwrap();
        assert!(matches!(
            mutation.authorize_activation(&changed_authority, &mut trusted_clock),
            Err(NetworkWorkerProtocolError::Authority)
        ));
        assert!(
            mutation
                .authorize_activation(&authority, &mut trusted_clock)
                .is_ok()
        );
    }

    #[test]
    fn mutation_expiry_after_claim_consumes_the_attempt() {
        let state_directory = TempDir::new().unwrap();
        let replay_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (bytes, _) = issue_isolated_worker_dispatch(state_directory.path(), &fixture);
        let authority = fixture.authority();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut samples = [clock(), expired_clock()].into_iter();
        let mut advancing_clock = || samples.next().ok_or(NetworkAdmissionError::FenceRejected);

        let authenticated = NetworkPrepareWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap();
        assert!(matches!(
            authenticated.authorize_mutation(&authority, &mut replay, &mut advancing_clock),
            Err(NetworkWorkerProtocolError::Authority)
        ));

        let replayed = NetworkPrepareWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap();
        let mut trusted_clock = || Ok(clock());
        assert!(matches!(
            replayed.authorize_mutation(&authority, &mut replay, &mut trusted_clock),
            Err(NetworkWorkerProtocolError::Replay)
        ));
    }

    #[test]
    fn activation_rejects_expired_effect_time() {
        let state_directory = TempDir::new().unwrap();
        let replay_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (bytes, _) = issue_isolated_worker_dispatch(state_directory.path(), &fixture);
        let authority = fixture.authority();
        let mut replay = NetworkWorkerReplayLedger::open_for_test(replay_directory.path()).unwrap();
        let mut trusted_clock = || Ok(clock());
        let authenticated = NetworkPrepareWorkerDispatchV1::decode(&bytes)
            .unwrap()
            .authenticate(&authority)
            .unwrap();
        let mutation = authenticated
            .authorize_mutation(&authority, &mut replay, &mut trusted_clock)
            .unwrap();
        let mut expired = || Ok(expired_clock());

        assert!(matches!(
            mutation.authorize_activation(&authority, &mut expired),
            Err(NetworkWorkerProtocolError::Authority)
        ));
    }

    #[test]
    fn dispatch_rejects_substituted_nonempty_endpoint_policy() {
        let valid_state_directory = TempDir::new().unwrap();
        let substituted_state_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (request, catalog, valid_plan, substituted_plan) = nonempty_worker_case();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog.clone(), &request);
        let store =
            NetworkStateStore::open_for_test(valid_state_directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("nonempty request did not prepare the effect");
        };
        let permit = coordinator
            .mark_effect_ambiguous([7; 16], effect_digest)
            .unwrap();
        let dispatch = coordinator
            .issue_prepare_worker_dispatch(permit, &request, valid_plan.clone())
            .unwrap();

        dispatch.authenticate(&fixture.authority()).unwrap();

        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog, &request);
        let store =
            NetworkStateStore::open_for_test(substituted_state_directory.path(), &authority, 0)
                .unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("nonempty substituted request did not prepare the effect");
        };
        let permit = coordinator
            .mark_effect_ambiguous([7; 16], effect_digest)
            .unwrap();

        assert_ne!(
            valid_plan.policy_program_digest(),
            substituted_plan.policy_program_digest()
        );
        assert!(matches!(
            coordinator.issue_prepare_worker_dispatch(permit, &request, substituted_plan),
            Err(NetworkBrokerError::WorkerProtocol(
                NetworkWorkerProtocolError::Authority
            ))
        ));
    }

    #[test]
    fn recovered_ambiguous_state_cannot_reconstruct_dispatch_authority() {
        let state_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (bytes, _) = issue_isolated_worker_dispatch(state_directory.path(), &fixture);
        let (request, catalog, _) = isolated_worker_case();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog, &request);
        let store =
            NetworkStateStore::open_for_test(state_directory.path(), &authority, 0).unwrap();
        let mut recovered = NetworkAdmissionCoordinator::new(authority, store);

        let snapshot = recovered.recovery_snapshot().unwrap();
        assert_eq!(snapshot.entries().len(), 1);
        assert_eq!(
            snapshot.entries()[0].phase(),
            DurableNetworkPhase::Ambiguous
        );
        let outcome = recovered
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        let NetworkAdmissionOutcome::ObserveOnly {
            phase,
            effect_digest,
        } = outcome
        else {
            panic!("recovered ambiguity unexpectedly regained dispatch authority");
        };
        assert_eq!(phase, DurableNetworkPhase::Ambiguous);
        assert!(
            recovered
                .mark_effect_ambiguous([7; 16], effect_digest)
                .is_err()
        );

        // Previously issued bytes remain authenticated data, but no recovered
        // broker API can mint a second message or worker attempt from them.
        assert!(
            NetworkPrepareWorkerDispatchV1::decode(&bytes)
                .unwrap()
                .authenticate(&fixture.authority())
                .is_ok()
        );
    }

    #[test]
    fn worker_dispatch_rejects_a_tampered_local_seal() {
        let state_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (mut bytes, _) = issue_isolated_worker_dispatch(state_directory.path(), &fixture);
        let final_byte = bytes.last_mut().unwrap();
        *final_byte ^= 1;

        let decoded = NetworkPrepareWorkerDispatchV1::decode(&bytes).unwrap();
        assert!(matches!(
            decoded.authenticate(&fixture.authority()),
            Err(NetworkWorkerProtocolError::Authority)
        ));
    }

    #[test]
    fn real_signed_authority_cross_links_and_replays_prepared_intent() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let semantics =
            CanonicalNetworkSemanticsV1::decode(&request, peer(), peer_policy(), 100).unwrap();
        let admission = authority
            .admit(
                &artifacts,
                &semantics,
                &request,
                ProtocolVersion::new(1, 0),
                &clock(),
                None,
            )
            .unwrap();
        assert!(authority.seal_fence(&[99; 16], &admission).is_err());
        assert!(authority.seal_effect(&[98; 16], &admission).is_err());
        let catalog = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("first admission did not prepare the effect");
        };
        assert_ne!(effect_digest.as_bytes(), &[0; 32]);
        assert_eq!(coordinator.recovery_snapshot().unwrap().entries().len(), 1);
        assert_eq!(
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .unwrap(),
            NetworkAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkPhase::Prepared,
                effect_digest,
            }
        );
    }

    #[test]
    fn preparation_crosses_exact_crash_phases_and_replays_committed_result() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);

        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("first admission did not prepare the effect");
        };
        let premature = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&request).into()),
            &catalog(),
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([90; 32]),
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        assert!(
            coordinator
                .commit_verified([7; 16], effect_digest, premature)
                .is_err()
        );
        assert!(
            coordinator
                .mark_effect_ambiguous([7; 16], ObjectDigest::from_bytes([1; 32]))
                .is_err()
        );
        drop(
            coordinator
                .mark_effect_ambiguous([7; 16], effect_digest)
                .unwrap(),
        );
        assert!(
            coordinator
                .mark_effect_ambiguous([7; 16], effect_digest)
                .is_err()
        );
        coordinator
            .bind_effect_namespace_custody(
                [7; 16],
                effect_digest,
                [10; 32],
                [51; 16],
                52,
                53,
                ObjectDigest::from_bytes([90; 32]),
            )
            .unwrap();

        for (boot_id, device, inode) in [([50; 16], 52, 53), ([51; 16], 62, 53), ([51; 16], 52, 63)]
        {
            let stale = VerifiedNetworkResultV1::verify_preparation(
                [7; 16],
                ObjectDigest::from_bytes(Sha256::digest(&request).into()),
                &catalog(),
                boot_id,
                device,
                inode,
                ObjectDigest::from_bytes([90; 32]),
                ObjectDigest::from_bytes([54; 32]),
            )
            .unwrap();
            assert!(
                coordinator
                    .commit_verified([7; 16], effect_digest, stale)
                    .is_err()
            );
        }

        let verified = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&request).into()),
            &catalog(),
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([90; 32]),
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        let result = coordinator
            .commit_verified([7; 16], effect_digest, verified)
            .unwrap();
        assert_eq!(result.request_id(), [7; 16]);
        assert_eq!(result.network_handle(), [10; 32]);
        assert_eq!(result.kernel_boot_id(), [51; 16]);
        assert_eq!(result.namespace_device(), 52);
        assert_eq!(result.namespace_inode(), 53);
        assert_ne!(result.result_digest().as_bytes(), &[54; 32]);

        assert_eq!(
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            NetworkAdmissionOutcome::Replay(result)
        );
        let snapshot = coordinator.recovery_snapshot().unwrap();
        let entry = &snapshot.entries()[0];
        assert_eq!(entry.phase(), DurableNetworkPhase::Committed);
        assert_eq!(entry.effect_digest(), effect_digest);
        let custody = entry.custody().unwrap();
        assert_eq!(custody.kernel_boot_id(), [51; 16]);
        assert_eq!(custody.namespace_device(), 52);
        assert_eq!(custody.namespace_inode(), 53);
        assert_eq!(entry.result(), Some(result));
        assert_eq!(coordinator.recover_preparation(entry).unwrap(), catalog());

        drop(coordinator);
        let authority = fixture.authority();
        let recovered = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        assert_eq!(
            recovered.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Committed)
        );
        assert_eq!(
            recovered.committed_recovery_entry(result).unwrap().result(),
            Some(result)
        );
    }

    #[test]
    fn ambiguous_restart_is_observation_only() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let effect_digest;
        {
            let authority = fixture.authority();
            let token = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            effect_digest = match coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap()
            {
                NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
                _ => panic!("first admission did not prepare the effect"),
            };
            drop(
                coordinator
                    .mark_effect_ambiguous([7; 16], effect_digest)
                    .unwrap(),
            );
        }

        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert_eq!(
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            NetworkAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkPhase::Ambiguous,
                effect_digest,
            }
        );
    }

    #[test]
    fn mismatched_results_and_duplicate_physical_namespaces_fail_closed() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first_request = request_for(7, 2, &[7]);
        let second_request = request_for(8, 3, &[8]);
        let first_artifacts = fixture.artifacts(&first_request);
        let second_artifacts = fixture.artifacts(&second_request);
        let first_catalog = catalog_for(9, 10, 11, &[(7, 12)]);
        let second_catalog = catalog_for(10, 20, 21, &[(8, 22)]);
        let authority = fixture.authority();
        let first_token = authenticated_catalog(&authority, first_catalog.clone(), &first_request);
        let second_token =
            authenticated_catalog(&authority, second_catalog.clone(), &second_request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);

        let first_effect = match coordinator
            .admit_apply_intent(
                &first_request,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        {
            NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
            _ => panic!("first admission did not prepare the effect"),
        };
        drop(
            coordinator
                .mark_effect_ambiguous([7; 16], first_effect)
                .unwrap(),
        );
        coordinator
            .bind_effect_namespace_custody(
                [7; 16],
                first_effect,
                *first_catalog.reserved_network_handle(),
                [51; 16],
                52,
                53,
                ObjectDigest::from_bytes([90; 32]),
            )
            .unwrap();
        let mismatched = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&first_request).into()),
            &second_catalog,
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([90; 32]),
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        assert!(
            coordinator
                .commit_verified([7; 16], first_effect, mismatched)
                .is_err()
        );
        let first_verified = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&first_request).into()),
            &first_catalog,
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([90; 32]),
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        coordinator
            .commit_verified([7; 16], first_effect, first_verified)
            .unwrap();

        coordinator
            .state
            .rewrite_custody_plan_digest_for_test(
                &coordinator.authority,
                [7; 16],
                ObjectDigest::from_bytes([99; 32]),
            )
            .unwrap();
        let digest_mismatch = copy_network_state_directory(directory.path());
        assert!(matches!(
            NetworkStateStore::open_for_test(digest_mismatch.path(), &fixture.authority(), 0,),
            Err(NetworkStateError::CorruptRecord)
        ));
        coordinator
            .state
            .rewrite_custody_plan_digest_for_test(
                &coordinator.authority,
                [7; 16],
                ObjectDigest::from_bytes([90; 32]),
            )
            .unwrap();

        let second_effect = match coordinator
            .admit_apply_intent(
                &second_request,
                &second_artifacts,
                &second_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        {
            NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
            _ => panic!("second admission did not prepare the effect"),
        };
        drop(
            coordinator
                .mark_effect_ambiguous([8; 16], second_effect)
                .unwrap(),
        );
        coordinator
            .bind_effect_namespace_custody(
                [8; 16],
                second_effect,
                *second_catalog.reserved_network_handle(),
                [51; 16],
                62,
                63,
                ObjectDigest::from_bytes([91; 32]),
            )
            .unwrap();
        coordinator
            .state
            .rewrite_custody_identity_for_test(&coordinator.authority, [8; 16], [51; 16], 52, 53, 1)
            .unwrap();
        let ambiguous_collision = copy_network_state_directory(directory.path());
        assert!(matches!(
            NetworkStateStore::open_for_test(ambiguous_collision.path(), &fixture.authority(), 0,),
            Err(NetworkStateError::Equivocation)
        ));
        coordinator
            .state
            .rewrite_custody_identity_for_test(&coordinator.authority, [8; 16], [51; 16], 62, 63, 2)
            .unwrap();
        let collision = VerifiedNetworkResultV1::verify_preparation(
            [8; 16],
            ObjectDigest::from_bytes(Sha256::digest(&second_request).into()),
            &second_catalog,
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([91; 32]),
            ObjectDigest::from_bytes([55; 32]),
        )
        .unwrap();
        assert!(
            coordinator
                .commit_verified([8; 16], second_effect, collision)
                .is_err()
        );

        coordinator
            .state
            .rewrite_custody_identity_for_test(&coordinator.authority, [8; 16], [51; 16], 52, 53, 3)
            .unwrap();
        drop(coordinator);
        assert!(matches!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0),
            Err(NetworkStateError::Equivocation)
        ));
    }

    #[test]
    fn two_ambiguous_custodies_without_results_cannot_share_a_physical_namespace() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first_request = request_for(7, 2, &[7]);
        let second_request = request_for(8, 3, &[8]);
        let first_catalog = catalog_for(9, 10, 11, &[(7, 12)]);
        let second_catalog = catalog_for(10, 20, 21, &[(8, 22)]);
        let authority = fixture.authority();
        let first_token = authenticated_catalog(&authority, first_catalog.clone(), &first_request);
        let second_token =
            authenticated_catalog(&authority, second_catalog.clone(), &second_request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);

        let NetworkAdmissionOutcome::Prepared {
            effect_digest: first_effect,
        } = coordinator
            .admit_apply_intent(
                &first_request,
                &fixture.artifacts(&first_request),
                &first_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("first operation did not prepare");
        };
        drop(
            coordinator
                .mark_effect_ambiguous([7; 16], first_effect)
                .unwrap(),
        );
        coordinator
            .bind_effect_namespace_custody(
                [7; 16],
                first_effect,
                *first_catalog.reserved_network_handle(),
                [51; 16],
                52,
                53,
                ObjectDigest::from_bytes([90; 32]),
            )
            .unwrap();

        let NetworkAdmissionOutcome::Prepared {
            effect_digest: second_effect,
        } = coordinator
            .admit_apply_intent(
                &second_request,
                &fixture.artifacts(&second_request),
                &second_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("second operation did not prepare");
        };
        drop(
            coordinator
                .mark_effect_ambiguous([8; 16], second_effect)
                .unwrap(),
        );
        coordinator
            .bind_effect_namespace_custody(
                [8; 16],
                second_effect,
                *second_catalog.reserved_network_handle(),
                [51; 16],
                62,
                63,
                ObjectDigest::from_bytes([91; 32]),
            )
            .unwrap();

        // Model an authenticated on-disk collision that bypassed the live
        // uniqueness check. Neither operation has a committed result.
        coordinator
            .state
            .rewrite_custody_identity_for_test(&coordinator.authority, [8; 16], [51; 16], 52, 53, 4)
            .unwrap();
        assert_eq!(
            coordinator.state.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Ambiguous)
        );
        assert_eq!(
            coordinator.state.phase([8; 16]).unwrap(),
            Some(DurableNetworkPhase::Ambiguous)
        );
        drop(coordinator);

        assert!(matches!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0),
            Err(NetworkStateError::Equivocation)
        ));
    }

    #[test]
    fn later_current_fence_does_not_orphan_committed_operation_authority() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first_request = request_for(7, 2, &[7]);
        let second_request = request_for_assignment(8, 2, 6, 60, &[8]);
        let first_artifacts = fixture.artifacts(&first_request);
        let second_artifacts = fixture.artifacts(&second_request);
        let first_fence;
        {
            let authority = fixture.authority();
            let first_catalog = catalog_for(9, 10, 11, &[(7, 12)]);
            let second_catalog = catalog_for(10, 20, 21, &[(8, 22)]);
            let first_token =
                authenticated_catalog(&authority, first_catalog.clone(), &first_request);
            let second_token = authenticated_catalog(&authority, second_catalog, &second_request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            let first_effect = match coordinator
                .admit_apply_intent(
                    &first_request,
                    &first_artifacts,
                    &first_token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap()
            {
                NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
                _ => panic!("first admission did not prepare the effect"),
            };
            drop(
                coordinator
                    .mark_effect_ambiguous([7; 16], first_effect)
                    .unwrap(),
            );
            coordinator
                .bind_effect_namespace_custody(
                    [7; 16],
                    first_effect,
                    *first_catalog.reserved_network_handle(),
                    [51; 16],
                    52,
                    53,
                    ObjectDigest::from_bytes([90; 32]),
                )
                .unwrap();
            let verified = VerifiedNetworkResultV1::verify_preparation(
                [7; 16],
                ObjectDigest::from_bytes(Sha256::digest(&first_request).into()),
                &first_catalog,
                [51; 16],
                52,
                53,
                ObjectDigest::from_bytes([90; 32]),
                ObjectDigest::from_bytes([54; 32]),
            )
            .unwrap();
            coordinator
                .commit_verified([7; 16], first_effect, verified)
                .unwrap();
            first_fence = coordinator
                .state
                .authority_record(RecordNamespace::DesiredState, &[2; 16])
                .unwrap()
                .unwrap()
                .to_vec();
            assert!(matches!(
                coordinator
                    .admit_apply_intent(
                        &second_request,
                        &second_artifacts,
                        &second_token,
                        ProtocolVersion::new(1, 0),
                        peer(),
                        peer_policy(),
                        &clock(),
                    )
                    .unwrap(),
                NetworkAdmissionOutcome::Prepared { .. }
            ));
        }

        let authority = fixture.authority();
        let recovered = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        assert_eq!(recovered.recovery_snapshot().unwrap().entries().len(), 2);
        assert_eq!(
            recovered.phase([7; 16]).unwrap(),
            Some(DurableNetworkPhase::Committed)
        );
        assert_eq!(
            recovered.phase([8; 16]).unwrap(),
            Some(DurableNetworkPhase::Prepared)
        );
        drop(recovered);

        let (mut journal, _) = Journal::open(
            directory.path().join("network-state.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [89; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        vec![2; 16],
                        first_fence,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn relocated_authenticated_operation_fails_recovery() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        {
            let authority = fixture.authority();
            let catalog = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        {
            let (mut journal, _) = Journal::open(
                directory.path().join("network-state.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            let moved = journal
                .get(RecordNamespace::Operation, &[7; 16])
                .unwrap()
                .to_vec();
            journal
                .commit(
                    &JournalTransaction::new(
                        [90; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            vec![9; 16],
                            moved,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        assert!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn relocated_operation_fence_fails_recovery() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        {
            let authority = fixture.authority();
            let catalog = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        let (mut journal, _) = Journal::open(
            directory.path().join("network-state.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let moved = journal
            .get(RecordNamespace::AuthorityPublication, &[7; 16])
            .unwrap()
            .to_vec();
        journal
            .commit(
                &JournalTransaction::new(
                    [91; 16],
                    vec![
                        JournalRecord::delete(RecordNamespace::AuthorityPublication, vec![7; 16]),
                        JournalRecord::put(
                            RecordNamespace::AuthorityPublication,
                            vec![9; 16],
                            moved,
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn catalog_token_rejects_tamper_and_resolution_substitution() {
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        for substitute_resolution in [false, true] {
            let directory = TempDir::new().unwrap();
            let authority = fixture.authority();
            let mut token = authenticated_catalog(&authority, catalog(), &request);
            if substitute_resolution {
                token.resolution = catalog_for(10, 10, 11, &[(7, 12), (8, 13)]);
            } else {
                token.sealed[0] ^= 1;
            }
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            assert!(matches!(
                coordinator.admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                ),
                Err(NetworkBrokerError::Authority)
            ));
        }

        let directory = TempDir::new().unwrap();
        let relocated_request = request_for(7, 9, &[7, 8]);
        let relocated_artifacts = fixture.artifacts(&relocated_request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &relocated_request,
                &relocated_artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));

        let directory = TempDir::new().unwrap();
        let authority = fixture.authority();
        let resolution = catalog();
        let sealed = authority
            .0
            .seal_local_record(
                RecordNamespace::DesiredState,
                resolution.binding().digest().as_bytes(),
                BrokerLocalRecordDomain::new(*b"AOSNETCATALOG002").unwrap(),
                &crate::catalog::encode_resolution(&resolution),
            )
            .unwrap();
        let token = crate::AuthenticatedNetworkPreparationV1 {
            resolution,
            assignment: decode_assignment(&request).unwrap(),
            sealed,
        };
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));
    }

    #[test]
    fn missing_or_tampered_atomic_authority_links_fail_recovery() {
        for (namespace, key, tamper) in [
            (RecordNamespace::DesiredState, vec![2; 16], false),
            (RecordNamespace::Effect, vec![7; 16], false),
            (RecordNamespace::AuthorityPublication, vec![7; 16], false),
            (RecordNamespace::Operation, vec![7; 16], false),
            (RecordNamespace::DesiredState, vec![2; 16], true),
            (RecordNamespace::Effect, vec![7; 16], true),
            (RecordNamespace::AuthorityPublication, vec![7; 16], true),
            (RecordNamespace::Operation, vec![7; 16], true),
        ] {
            let directory = TempDir::new().unwrap();
            let fixture = Fixture::new();
            let request = request();
            let artifacts = fixture.artifacts(&request);
            {
                let authority = fixture.authority();
                let token = authenticated_catalog(&authority, catalog(), &request);
                let store =
                    NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
                let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
                coordinator
                    .admit_apply_intent(
                        &request,
                        &artifacts,
                        &token,
                        ProtocolVersion::new(1, 0),
                        peer(),
                        peer_policy(),
                        &clock(),
                    )
                    .unwrap();
            }
            {
                let recovered =
                    NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0)
                        .unwrap();
                assert_eq!(recovered.recovery_snapshot().unwrap().entries().len(), 1);
            }
            let (mut journal, _) = Journal::open(
                directory.path().join("network-state.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            let record = if tamper {
                let mut bytes = journal.get(namespace, &key).unwrap().to_vec();
                let middle = bytes.len() / 2;
                bytes[middle] ^= 1;
                JournalRecord::put(namespace, key, bytes)
            } else {
                JournalRecord::delete(namespace, key)
            };
            journal
                .commit(
                    &JournalTransaction::new(
                        [namespace as u8 + 70 + u8::from(tamper) * 10; 16],
                        vec![record],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);
            assert!(
                NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0)
                    .is_err()
            );
        }
    }

    #[test]
    fn exact_replay_accepts_only_exact_catalog_and_request_semantics() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        let changed = authenticated_catalog(
            &coordinator.authority,
            catalog_for(10, 10, 11, &[(7, 12), (8, 13)]),
            &request,
        );
        assert!(matches!(
            coordinator.admit_apply_intent(
                &request,
                &artifacts,
                &changed,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    #[test]
    fn request_semantic_and_sandbox_equivocation_fail_closed() {
        let fixture = Fixture::new();
        let first = request_for(7, 2, &[7]);
        let changed_semantics = request_for(7, 2, &[8]);
        let authorized = [&first[..], &changed_semantics[..]];
        let first_artifacts = fixture.artifacts_authorizing(&first, &authorized);
        let changed_artifacts = fixture.artifacts_authorizing(&changed_semantics, &authorized);
        let directory = TempDir::new().unwrap();
        let authority = fixture.authority();
        let first_token =
            authenticated_catalog(&authority, catalog_for(9, 10, 11, &[(7, 12)]), &first);
        let changed_token = authenticated_catalog(
            &authority,
            catalog_for(10, 20, 21, &[(8, 22)]),
            &changed_semantics,
        );
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &changed_semantics,
                &changed_artifacts,
                &changed_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));

        let directory = TempDir::new().unwrap();
        let changed_sandbox = request_for(7, 3, &[7]);
        let first_artifacts = fixture.artifacts(&first);
        let changed_artifacts = fixture.artifacts(&changed_sandbox);
        let authority = fixture.authority();
        let first_token =
            authenticated_catalog(&authority, catalog_for(9, 10, 11, &[(7, 12)]), &first);
        let changed_token = authenticated_catalog(
            &authority,
            catalog_for(10, 20, 21, &[(7, 22)]),
            &changed_sandbox,
        );
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &changed_sandbox,
                &changed_artifacts,
                &changed_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    #[test]
    fn one_pending_operation_per_sandbox_is_enforced() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first = request_for(7, 2, &[7, 8]);
        let second = request_for(8, 2, &[9, 10]);
        let authorized = [&first[..], &second[..]];
        let first_artifacts = fixture.artifacts_authorizing(&first, &authorized);
        let second_artifacts = fixture.artifacts_authorizing(&second, &authorized);
        let authority = fixture.authority();
        let first_token = authenticated_catalog(&authority, catalog(), &first);
        let second_catalog = catalog_for(10, 20, 21, &[(9, 22), (10, 23)]);
        let second_token = authenticated_catalog(&authority, second_catalog, &second);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &second,
                &second_artifacts,
                &second_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(
                NetworkStateError::PendingConflict
            ))
        ));
    }

    #[test]
    fn generation_rollback_is_rejected_on_open_and_each_begin() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        {
            let authority = fixture.authority();
            let token = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        assert!(matches!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 10),
            Err(NetworkStateError::Rollback)
        ));
        let lower_than_current = request_for(8, 3, &[9]);
        let lower_than_current_artifacts = fixture.artifacts(&lower_than_current);
        let authority = fixture.authority();
        let lower_than_current_token = authenticated_catalog(
            &authority,
            catalog_for(8, 20, 21, &[(9, 22)]),
            &lower_than_current,
        );
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &lower_than_current,
                &lower_than_current_artifacts,
                &lower_than_current_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Rollback))
        ));

        let empty = TempDir::new().unwrap();
        assert!(matches!(
            NetworkStateStore::open_for_test(empty.path(), &fixture.authority(), 10),
            Err(NetworkStateError::Rollback)
        ));
    }

    #[test]
    fn duplicate_reserved_handle_across_sandboxes_is_rejected() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first = request_for(7, 2, &[7]);
        let second = request_for(8, 3, &[8]);
        let first_artifacts = fixture.artifacts(&first);
        let second_artifacts = fixture.artifacts(&second);
        let authority = fixture.authority();
        let first_token =
            authenticated_catalog(&authority, catalog_for(9, 10, 11, &[(7, 12)]), &first);
        let second_token =
            authenticated_catalog(&authority, catalog_for(10, 10, 13, &[(8, 14)]), &second);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &second,
                &second_artifacts,
                &second_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    #[test]
    fn recovery_snapshot_is_lossless_and_bytewise_ordered() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let authority = fixture.authority();
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        let expected_catalog = catalog_for(10, 10, 11, &[(7, 12)]);
        for (request_id, sandbox_id, catalog) in [
            (9, 3, catalog_for(10, 20, 21, &[(8, 22)])),
            (7, 2, expected_catalog.clone()),
        ] {
            let request = request_for(
                request_id,
                sandbox_id,
                &[if request_id == 7 { 7 } else { 8 }],
            );
            let artifacts = fixture.artifacts(&request);
            let token = authenticated_catalog(&coordinator.authority, catalog, &request);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        let snapshot = coordinator.recovery_snapshot().unwrap();
        assert_eq!(snapshot.entries().len(), 2);
        assert_eq!(snapshot.entries()[0].request_id(), [7; 16]);
        assert_eq!(snapshot.entries()[1].request_id(), [9; 16]);
        assert_eq!(snapshot.entries()[0].verb(), BrokerVerb::NetworkPrepare);
        assert_eq!(
            snapshot.entries()[0].catalog_resolution(),
            &expected_catalog
        );
    }

    #[test]
    fn bounded_epoch_exhaustion_is_typed() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        coordinator.state.fill_epoch_for_test();
        let next = request_for(8, 3, &[9]);
        let next_artifacts = fixture.artifacts(&next);
        let next_token = authenticated_catalog(
            &coordinator.authority,
            catalog_for(10, 20, 21, &[(9, 22)]),
            &next,
        );
        assert!(matches!(
            coordinator.admit_apply_intent(
                &next,
                &next_artifacts,
                &next_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(
                NetworkStateError::ResourceExhausted
            ))
        ));
    }

    #[test]
    fn production_open_rejects_relative_and_unsafe_directories() {
        let fixture = Fixture::new();
        assert!(
            NetworkStateStore::open_root_owned(
                Path::new("relative-network-state"),
                &fixture.authority(),
                0,
            )
            .is_err()
        );
        assert!(
            NetworkStateStore::open_root_owned(Path::new("/tmp"), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn action_and_catalog_kinds_cannot_be_substituted() {
        let prepared = request();
        let prepared_semantics =
            CanonicalNetworkSemanticsV1::decode(&prepared, peer(), peer_policy(), 100).unwrap();
        assert!(validate_catalog(&prepared_semantics, &catalog()).is_ok());

        let mut destroy = ApplyNetworkRequest::decode_from_slice(&prepared).unwrap();
        destroy.action = NetworkAction::NETWORK_ACTION_DESTROY.into();
        destroy.endpoint_ids.clear();
        destroy.network_handle = vec![10; 32];
        let destroy_semantics = CanonicalNetworkSemanticsV1::decode(
            &destroy.encode_to_vec(),
            peer(),
            peer_policy(),
            100,
        )
        .unwrap();
        assert!(validate_catalog(&destroy_semantics, &catalog()).is_err());

        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let destroy_bytes = destroy.encode_to_vec();
        // Deliberately supply authority for a different action. Receiving a
        // request error proves the closed existing-action gate runs before
        // signed admission could inspect or accept these artifacts.
        let artifacts = fixture.artifacts(&request());
        let authority = fixture.authority();
        let preparation_token = authenticated_catalog(&authority, catalog(), &request());
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &destroy_bytes,
                &artifacts,
                &preparation_token,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Request)
        ));
    }
}
