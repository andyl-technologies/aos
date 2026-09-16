//! Dormant authenticated-session callsite for Network Apply.
//!
//! This adapter enters the real creation or existing-resource durable
//! admission coordinator after rechecking the live kernel boot. It registers
//! no route, listener, worker, or advertised method.

use aos_proto::aos::sandbox::local::v1::{NetworkResult, NetworkState};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::authorization::decode_assignment;
use crate::{
    ActivatedNetworkDescriptors, AuthenticatedNetworkPreparationV1,
    CommittedNetworkLifecycleResultV1, DurableNetworkLifecyclePhase, NetworkAdmissionError,
    NetworkAdmissionOutcome, NetworkBrokerError, NetworkKernelPlanV1,
    NetworkLifecycleAdmissionCoordinator, NetworkLifecycleAdmissionOutcome,
    NetworkLifecycleWorkerRuntimeError, NetworkNamespaceCatalogV1,
    NetworkNamespaceLifecycleActionV1, NetworkNamespaceLifecycleObservationV1,
    NetworkNamespaceLifecycleTransitionV1, NetworkNamespacePinWorkerError,
    NetworkNamespaceStoreError, NetworkNamespaceStoreName, NetworkNamespaceStoreOutcome,
    NetworkObservationWorkerError, NetworkPreparationCatalogV1,
    NetworkPreparationFinalizationInput, NetworkPreparationRecoveryInput,
    NetworkPreparationRuntimeError, NetworkPrepareExecutionOutcomeV1, NetworkWorkerRuntimeError,
    PreparedNetworkObservationV1, SystemdNetworkLifecycleExecutor,
    SystemdNetworkNamespacePinExecutor, SystemdNetworkNamespaceStore,
    SystemdNetworkObservationExecutor, SystemdNetworkPrepareExecutor,
    begin_network_preparation_once, finalize_observation_worker_preparation,
    finalize_recovered_observation_worker_preparation,
};

mod sealed {
    pub trait Sealed {}
}

/// Reports rejection at the dormant broker-session-to-Network boundary.
#[derive(Debug, thiserror::Error)]
pub enum DormantNetworkBrokerCallErrorV1 {
    /// The request or live kernel boot no longer matches the protected handoff.
    #[error("authenticated Network handoff has stale kernel evidence")]
    StaleKernel,
    /// The existing Network admission path rejected the exact request.
    #[error("authenticated Network Apply failed: {0}")]
    Broker(#[from] NetworkBrokerError),
    /// Preparation dispatch or durable finalization failed.
    #[error("authenticated Network preparation failed: {0}")]
    Preparation(#[from] NetworkPreparationRuntimeError),
    /// The privileged preparation worker failed or could not be quiesced.
    #[error("authenticated Network preparation worker failed: {0}")]
    Worker(#[from] NetworkWorkerRuntimeError),
    /// The separate read-only observation worker failed or could not be quiesced.
    #[error("authenticated Network observation worker failed: {0}")]
    ObservationWorker(#[from] NetworkObservationWorkerError),
    /// The privileged lifecycle worker failed or could not be quiesced.
    #[error("authenticated Network lifecycle worker failed: {0}")]
    LifecycleWorker(#[from] NetworkLifecycleWorkerRuntimeError),
    /// Live namespace descriptor custody could not be updated exactly.
    #[error("authenticated Network namespace custody failed: {0}")]
    NamespaceStore(#[from] NetworkNamespaceStoreError),
    /// Host-visible namespace-pin teardown failed or could not be quiesced.
    #[error("authenticated Network namespace pin teardown failed: {0}")]
    PinWorker(#[from] NetworkNamespacePinWorkerError),
}

/// Classifies the real Network coordinator entered by the dormant callsite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantNetworkBrokerAdmissionV1 {
    /// New-namespace preparation entered creation admission.
    Preparation(NetworkAdmissionOutcome),
    /// Existing-handle mutation entered lifecycle admission.
    Lifecycle(NetworkLifecycleAdmissionOutcome),
}

/// Seals one result produced by the real Network durable admission path.
pub struct DormantNetworkBrokerObservationV1 {
    request_id: [u8; 16],
    admission: DormantNetworkBrokerAdmissionV1,
    commitment: ObjectDigest,
    response_body: Option<Vec<u8>>,
}

impl DormantNetworkBrokerObservationV1 {
    /// Returns a success body only for an already committed preparation replay.
    ///
    /// # Errors
    ///
    /// Returns an error while Network admission has not produced a committed
    /// physical namespace observation; pending admission never becomes success.
    pub fn response(&self) -> Result<Vec<u8>, DormantNetworkBrokerCallErrorV1> {
        if let Some(response) = &self.response_body {
            return Ok(response.clone());
        }
        let DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Replay(
            committed,
        )) = self.admission
        else {
            return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
        };
        Ok(NetworkResult {
            network_handle: committed.network_handle().to_vec(),
            state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
            ..Default::default()
        }
        .encode_to_vec())
    }

    /// Returns the exact request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the durable Network admission classification.
    #[must_use]
    pub const fn admission(&self) -> DormantNetworkBrokerAdmissionV1 {
        self.admission
    }

    /// Returns the domain-separated observation commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Defines the closed Network call surface accepted by session security.
#[doc(hidden)]
pub trait DormantNetworkBrokerCallsiteV1: sealed::Sealed {
    /// Borrows the authoritative inventory owned by this exact callsite.
    fn namespace_catalog(&self) -> &NetworkNamespaceCatalogV1;

    /// Admits one exact authenticated Network Apply operation.
    ///
    /// # Errors
    ///
    /// Returns an error when request or kernel evidence is stale, or when the
    /// durable Network admission coordinator rejects the call.
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
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1>;
}

/// Retains the exact protected preparation, kernel plan, catalog, and clock.
pub struct DormantNetworkBrokerCompositionV1<'a> {
    coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
    preparation: &'a AuthenticatedNetworkPreparationV1,
    kernel_plan: &'a NetworkKernelPlanV1,
    namespaces: &'a NetworkNamespaceCatalogV1,
    last_boottime_nanoseconds: Option<u64>,
}

impl<'a> DormantNetworkBrokerCompositionV1<'a> {
    /// Constructs a dormant callsite with a fixed kernel clock owner.
    #[must_use]
    pub const fn new(
        coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
        preparation: &'a AuthenticatedNetworkPreparationV1,
        kernel_plan: &'a NetworkKernelPlanV1,
        namespaces: &'a NetworkNamespaceCatalogV1,
    ) -> Self {
        Self {
            coordinator,
            preparation,
            kernel_plan,
            namespaces,
            last_boottime_nanoseconds: None,
        }
    }
}

impl sealed::Sealed for DormantNetworkBrokerCompositionV1<'_> {}

impl DormantNetworkBrokerCallsiteV1 for DormantNetworkBrokerCompositionV1<'_> {
    fn namespace_catalog(&self) -> &NetworkNamespaceCatalogV1 {
        self.namespaces
    }

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
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
        let (semantics, current_clock) = validate_authenticated_request(
            request_body,
            request_id,
            request_body_digest,
            peer,
            policy,
            protocol_version,
            protected_boot_id,
            &mut self.last_boottime_nanoseconds,
        )?;
        admit_authenticated_request(
            self.coordinator,
            self.preparation,
            self.kernel_plan,
            self.namespaces,
            request_body,
            request_id,
            request_body_digest,
            artifacts,
            peer,
            policy,
            protocol_version,
            &semantics,
            &current_clock,
        )
    }
}

/// Resolves each authenticated request against protected preparation history.
///
/// Unlike [`DormantNetworkBrokerCompositionV1`], this composition does not pin
/// one assignment at construction. It derives the assignment and optional
/// handle from the authenticated body, then requires the protected preparation
/// catalog to reproduce one exact authenticated resolution and kernel plan.
pub struct DormantResolvedNetworkBrokerCompositionV1<'a> {
    coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
    preparations: &'a NetworkPreparationCatalogV1,
    namespaces: &'a NetworkNamespaceCatalogV1,
    last_boottime_nanoseconds: Option<u64>,
}

/// Executes authenticated Network preparation through separated systemd workers.
pub struct ProductionNetworkBrokerCompositionV1<'a> {
    coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
    preparations: &'a NetworkPreparationCatalogV1,
    namespaces: &'a mut NetworkNamespaceCatalogV1,
    activation: &'a mut ActivatedNetworkDescriptors,
    namespace_store: &'a SystemdNetworkNamespaceStore,
    prepare_executor: &'a mut SystemdNetworkPrepareExecutor,
    observation_executor: &'a mut SystemdNetworkObservationExecutor,
    lifecycle_executor: &'a mut SystemdNetworkLifecycleExecutor,
    pin_executor: &'a mut SystemdNetworkNamespacePinExecutor,
    last_boottime_nanoseconds: Option<u64>,
}

impl<'a> ProductionNetworkBrokerCompositionV1<'a> {
    /// Binds every durable catalog and fixed worker owner for one request cycle.
    #[must_use]
    pub const fn new(
        coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
        preparations: &'a NetworkPreparationCatalogV1,
        namespaces: &'a mut NetworkNamespaceCatalogV1,
        activation: &'a mut ActivatedNetworkDescriptors,
        namespace_store: &'a SystemdNetworkNamespaceStore,
        prepare_executor: &'a mut SystemdNetworkPrepareExecutor,
        observation_executor: &'a mut SystemdNetworkObservationExecutor,
        lifecycle_executor: &'a mut SystemdNetworkLifecycleExecutor,
        pin_executor: &'a mut SystemdNetworkNamespacePinExecutor,
    ) -> Self {
        Self {
            coordinator,
            preparations,
            namespaces,
            activation,
            namespace_store,
            prepare_executor,
            observation_executor,
            lifecycle_executor,
            pin_executor,
            last_boottime_nanoseconds: None,
        }
    }
}

impl sealed::Sealed for ProductionNetworkBrokerCompositionV1<'_> {}

impl DormantNetworkBrokerCallsiteV1 for ProductionNetworkBrokerCompositionV1<'_> {
    fn namespace_catalog(&self) -> &NetworkNamespaceCatalogV1 {
        self.namespaces
    }

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
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
        let (semantics, current_clock) = validate_authenticated_request(
            request_body,
            request_id,
            request_body_digest,
            peer,
            policy,
            protocol_version,
            protected_boot_id,
            &mut self.last_boottime_nanoseconds,
        )?;
        let assignment = decode_assignment(request_body)
            .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
        let (preparation, kernel_plan) = self.coordinator.resolve_session_request_preparation(
            self.preparations,
            assignment,
            None,
        )?;
        match semantics.operation() {
            NetworkOperation::Prepare { .. } => {
                let admission = self.coordinator.admit_apply_intent(
                    request_body,
                    artifacts,
                    &preparation,
                    protocol_version,
                    peer,
                    policy,
                    &current_clock,
                )?;
                let result = match admission {
                    NetworkAdmissionOutcome::Replay(committed) => committed,
                    NetworkAdmissionOutcome::Prepared { effect_digest } => {
                        let mut trusted_clock = || {
                            protected_paired_clock_sample()
                                .map_err(|_| NetworkAdmissionError::FenceRejected)
                        };
                        let execution = begin_network_preparation_once(
                            self.coordinator,
                            request_id,
                            effect_digest,
                            request_body,
                            kernel_plan.clone(),
                            &mut trusted_clock,
                        )?;
                        let NetworkPrepareExecutionOutcomeV1::Dispatch(dispatch) = execution else {
                            return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
                        };
                        let worker_output = self.prepare_executor.execute_once(
                            &dispatch,
                            self.coordinator,
                            self.namespace_store,
                        )?;
                        let proof = self
                            .observation_executor
                            .observe_once(&worker_output, &kernel_plan)?;
                        self.activation.retain_runtime_namespace(
                            *preparation.resolution().reserved_network_handle(),
                            worker_output.namespace(),
                        )?;
                        let input = NetworkPreparationFinalizationInput::new(
                            request_body,
                            preparation.resolution(),
                            &kernel_plan,
                            &worker_output,
                        );
                        finalize_observation_worker_preparation(
                            self.coordinator,
                            self.preparations,
                            self.namespaces,
                            input,
                            proof,
                        )?
                        .result()
                    }
                    NetworkAdmissionOutcome::ObserveOnly {
                        phase: crate::DurableNetworkPhase::Ambiguous,
                        effect_digest,
                    } => {
                        let target = self
                            .activation
                            .namespace_for_handle(
                                *preparation.resolution().reserved_network_handle(),
                            )
                            .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
                        let recovered =
                            self.coordinator.recover_ambiguous_preparation_observation(
                                request_id,
                                effect_digest,
                                target.namespace(),
                            )?;
                        let proof = self
                            .observation_executor
                            .observe_preparation_recovery_once(recovered, &kernel_plan)?;
                        let input = NetworkPreparationRecoveryInput::new(
                            request_id,
                            effect_digest,
                            request_body,
                            preparation.resolution(),
                            &kernel_plan,
                            target.namespace(),
                        );
                        finalize_recovered_observation_worker_preparation(
                            self.coordinator,
                            self.preparations,
                            self.namespaces,
                            input,
                            proof,
                        )?
                        .result()
                    }
                    NetworkAdmissionOutcome::ObserveOnly { .. }
                    | NetworkAdmissionOutcome::Aborted { .. } => {
                        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
                    }
                };
                let admission = DormantNetworkBrokerAdmissionV1::Preparation(
                    NetworkAdmissionOutcome::Replay(result),
                );
                let response_body = NetworkResult {
                    network_handle: result.network_handle().to_vec(),
                    state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
                    ..Default::default()
                }
                .encode_to_vec();
                let commitment =
                    network_observation_commitment(request_id, request_body_digest, admission);

                Ok(DormantNetworkBrokerObservationV1 {
                    request_id,
                    admission,
                    commitment,
                    response_body: Some(response_body),
                })
            }
            NetworkOperation::ArmLease { network_handle, .. }
            | NetworkOperation::RenewLease { network_handle, .. }
            | NetworkOperation::Disarm { network_handle }
            | NetworkOperation::Destroy { network_handle } => {
                let admission = self.coordinator.admit_lifecycle_intent(
                    request_body,
                    artifacts,
                    &preparation,
                    &kernel_plan,
                    self.namespaces,
                    protocol_version,
                    peer,
                    policy,
                    &current_clock,
                )?;
                let (result, released_identity) = match admission {
                    NetworkLifecycleAdmissionOutcome::Replay(committed) => (committed, None),
                    NetworkLifecycleAdmissionOutcome::Prepared { effect_digest } => {
                        let permit = self
                            .coordinator
                            .mark_effect_ambiguous(request_id, effect_digest)?;
                        let dispatch = self.coordinator.issue_lifecycle_worker_dispatch(
                            permit,
                            request_body,
                            preparation.clone(),
                            kernel_plan.clone(),
                        )?;
                        let target = self
                            .activation
                            .namespace_for_handle(*network_handle)
                            .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
                        let trusted_current_fence =
                            self.coordinator.trusted_lifecycle_fence(&dispatch)?;
                        let execution = self.lifecycle_executor.execute_once(
                            self.coordinator.authority(),
                            &dispatch,
                            &trusted_current_fence,
                            target,
                        )?;
                        let target_namespace_identity = target.identity();
                        let (proof, observation_digest) =
                            if execution.action() == NetworkNamespaceLifecycleActionV1::Destroy {
                                let proof = self.observation_executor.observe_destroyed_once(
                                    execution,
                                    &kernel_plan,
                                    target,
                                )?;
                                let pin_removal_digest = self.pin_executor.remove_once(
                                    execution.request_id(),
                                    execution.effect_digest(),
                                    execution.target_identity().network_handle(),
                                    target_namespace_identity,
                                )?;
                                let store_name = NetworkNamespaceStoreName::from_network_handle(
                                    execution.target_identity().network_handle(),
                                )?;
                                if self.namespace_store.remove(&store_name)?
                                    != NetworkNamespaceStoreOutcome::Removed
                                    || self
                                        .namespace_store
                                        .retained_identity(&store_name)?
                                        .is_some()
                                {
                                    return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
                                }
                                let observation_digest = destroyed_custody_observation_digest(
                                    execution.request_id(),
                                    execution.effect_digest(),
                                    execution.target_identity(),
                                    proof,
                                    pin_removal_digest,
                                )?;
                                (proof, observation_digest)
                            } else {
                                let proof = self.observation_executor.observe_lifecycle_once(
                                    execution,
                                    &kernel_plan,
                                    execution.target_identity().kernel_boot_id(),
                                    execution.desired_state(),
                                    target,
                                )?;
                                (proof, proof.observation_digest())
                            };
                        let observation = NetworkNamespaceLifecycleObservationV1::new(
                            execution.request_id(),
                            execution.prior_resource_digest(),
                            execution.target_identity(),
                            proof.observed_state(),
                            observation_digest,
                        )
                        .map_err(NetworkBrokerError::from)?;
                        let transition = lifecycle_transition(
                            execution.action(),
                            execution.desired_state(),
                            observation,
                        )?;
                        let committed = self.coordinator.commit_verified_transition(
                            execution.request_id(),
                            execution.effect_digest(),
                            transition,
                            self.namespaces,
                        )?;
                        let released_identity = (execution.action()
                            == NetworkNamespaceLifecycleActionV1::Destroy)
                            .then_some(target_namespace_identity);
                        (committed, released_identity)
                    }
                    NetworkLifecycleAdmissionOutcome::ObserveOnly {
                        phase: DurableNetworkLifecyclePhase::Ambiguous,
                        effect_digest,
                    } => {
                        let recovery = self
                            .coordinator
                            .recover_ambiguous_lifecycle(request_id, effect_digest)?;
                        let target = self
                            .activation
                            .namespace_for_handle(*network_handle)
                            .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
                        let target_namespace_identity = target.identity();

                        if matches!(
                            recovery.action(),
                            NetworkNamespaceLifecycleActionV1::Arm
                                | NetworkNamespaceLifecycleActionV1::Renew
                                | NetworkNamespaceLifecycleActionV1::Disarm
                        ) {
                            let permit = self
                                .coordinator
                                .recover_idempotent_lifecycle_effect(request_id, effect_digest)?;
                            let dispatch = self.coordinator.issue_lifecycle_worker_dispatch(
                                permit,
                                request_body,
                                preparation.clone(),
                                kernel_plan.clone(),
                            )?;
                            let trusted_current_fence =
                                self.coordinator.trusted_lifecycle_fence(&dispatch)?;
                            let execution = self.lifecycle_executor.execute_once(
                                self.coordinator.authority(),
                                &dispatch,
                                &trusted_current_fence,
                                target,
                            )?;
                            if execution.action() != recovery.action()
                                || execution.desired_state() != recovery.desired_state()
                            {
                                return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
                            }
                        }

                        let proof = self.observation_executor.observe_recovery_once(
                            recovery,
                            &kernel_plan,
                            target,
                        )?;
                        let observation_digest =
                            if recovery.action() == NetworkNamespaceLifecycleActionV1::Destroy {
                                let pin_removal_digest = self.pin_executor.reconcile_once(
                                    recovery.request_id(),
                                    recovery.effect_digest(),
                                    recovery.authority().identity.network_handle(),
                                    target_namespace_identity,
                                )?;
                                let store_name = NetworkNamespaceStoreName::from_network_handle(
                                    recovery.authority().identity.network_handle(),
                                )?;
                                if !matches!(
                                    self.namespace_store.remove(&store_name)?,
                                    NetworkNamespaceStoreOutcome::Removed
                                        | NetworkNamespaceStoreOutcome::Absent
                                ) || self
                                    .namespace_store
                                    .retained_identity(&store_name)?
                                    .is_some()
                                {
                                    return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
                                }
                                destroyed_custody_observation_digest(
                                    recovery.request_id(),
                                    recovery.effect_digest(),
                                    recovery.authority().identity,
                                    proof,
                                    pin_removal_digest,
                                )?
                            } else {
                                proof.observation_digest()
                            };
                        let observation = NetworkNamespaceLifecycleObservationV1::new(
                            recovery.request_id(),
                            recovery.authority().resource_digest,
                            recovery.authority().identity,
                            proof.observed_state(),
                            observation_digest,
                        )
                        .map_err(NetworkBrokerError::from)?;
                        let transition = lifecycle_transition(
                            recovery.action(),
                            recovery.desired_state(),
                            observation,
                        )?;
                        let committed = self.coordinator.commit_verified_transition(
                            recovery.request_id(),
                            recovery.effect_digest(),
                            transition,
                            self.namespaces,
                        )?;
                        let released_identity = (recovery.action()
                            == NetworkNamespaceLifecycleActionV1::Destroy)
                            .then_some(target_namespace_identity);
                        (committed, released_identity)
                    }
                    NetworkLifecycleAdmissionOutcome::ObserveOnly { .. } => {
                        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
                    }
                };
                if let Some(identity) = released_identity {
                    self.activation
                        .release_runtime_namespace(*network_handle, identity)?;
                }
                let admission = DormantNetworkBrokerAdmissionV1::Lifecycle(
                    NetworkLifecycleAdmissionOutcome::Replay(result),
                );
                let response_body = lifecycle_response(semantics.operation(), result)?;
                let commitment =
                    network_observation_commitment(request_id, request_body_digest, admission);

                Ok(DormantNetworkBrokerObservationV1 {
                    request_id,
                    admission,
                    commitment,
                    response_body: Some(response_body),
                })
            }
        }
    }
}

impl<'a> DormantResolvedNetworkBrokerCompositionV1<'a> {
    /// Constructs the multi-assignment Network broker-session callsite.
    #[must_use]
    pub const fn new(
        coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
        preparations: &'a NetworkPreparationCatalogV1,
        namespaces: &'a NetworkNamespaceCatalogV1,
    ) -> Self {
        Self {
            coordinator,
            preparations,
            namespaces,
            last_boottime_nanoseconds: None,
        }
    }
}

impl sealed::Sealed for DormantResolvedNetworkBrokerCompositionV1<'_> {}

impl DormantNetworkBrokerCallsiteV1 for DormantResolvedNetworkBrokerCompositionV1<'_> {
    fn namespace_catalog(&self) -> &NetworkNamespaceCatalogV1 {
        self.namespaces
    }

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
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
        let (semantics, current_clock) = validate_authenticated_request(
            request_body,
            request_id,
            request_body_digest,
            peer,
            policy,
            protocol_version,
            protected_boot_id,
            &mut self.last_boottime_nanoseconds,
        )?;
        let assignment = decode_assignment(request_body)
            .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
        let requested_handle = semantics.operation().network_handle().copied();
        let (preparation, kernel_plan) = self.coordinator.resolve_session_request_preparation(
            self.preparations,
            assignment,
            requested_handle,
        )?;

        admit_authenticated_request(
            self.coordinator,
            &preparation,
            &kernel_plan,
            self.namespaces,
            request_body,
            request_id,
            request_body_digest,
            artifacts,
            peer,
            policy,
            protocol_version,
            &semantics,
            &current_clock,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_authenticated_request(
    request_body: &[u8],
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol_version: ProtocolVersion,
    protected_boot_id: [u8; 16],
    last_boottime_nanoseconds: &mut Option<u64>,
) -> Result<(CanonicalNetworkSemanticsV1, RawPairedClockSample), DormantNetworkBrokerCallErrorV1> {
    let current_boot_id = KernelBootId::current()
        .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?
        .into_bytes();
    if current_boot_id != protected_boot_id
        || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }

    let current_clock = protected_paired_clock_sample()?;
    if current_clock.host_boot_id() != protected_boot_id
        || last_boottime_nanoseconds
            .is_some_and(|floor| current_clock.boottime_nanoseconds() < floor)
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }
    *last_boottime_nanoseconds = Some(current_clock.boottime_nanoseconds());
    let semantics = CanonicalNetworkSemanticsV1::decode(
        request_body,
        peer,
        policy,
        current_clock.boottime_nanoseconds(),
    )
    .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    if semantics.header().request_id() != &request_id
        || semantics.header().protocol_version() != protocol_version
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }

    Ok((semantics, current_clock))
}

#[allow(clippy::too_many_arguments)]
fn admit_authenticated_request(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    preparation: &AuthenticatedNetworkPreparationV1,
    kernel_plan: &NetworkKernelPlanV1,
    namespaces: &NetworkNamespaceCatalogV1,
    request_body: &[u8],
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol_version: ProtocolVersion,
    semantics: &CanonicalNetworkSemanticsV1,
    current_clock: &RawPairedClockSample,
) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
    let admission = match semantics.operation() {
        NetworkOperation::Prepare { .. } => {
            DormantNetworkBrokerAdmissionV1::Preparation(coordinator.admit_apply_intent(
                request_body,
                artifacts,
                preparation,
                protocol_version,
                peer,
                policy,
                current_clock,
            )?)
        }
        NetworkOperation::ArmLease { .. }
        | NetworkOperation::RenewLease { .. }
        | NetworkOperation::Disarm { .. }
        | NetworkOperation::Destroy { .. } => {
            DormantNetworkBrokerAdmissionV1::Lifecycle(coordinator.admit_lifecycle_intent(
                request_body,
                artifacts,
                preparation,
                kernel_plan,
                namespaces,
                protocol_version,
                peer,
                policy,
                current_clock,
            )?)
        }
    };
    let commitment = network_observation_commitment(request_id, request_body_digest, admission);
    Ok(DormantNetworkBrokerObservationV1 {
        request_id,
        admission,
        commitment,
        response_body: None,
    })
}

fn protected_paired_clock_sample() -> Result<RawPairedClockSample, DormantNetworkBrokerCallErrorV1>
{
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(boottime.tv_sec).map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    let nanoseconds = u64::try_from(boottime.tv_nsec)
        .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
        .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        KernelBootId::current()
            .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?
            .into_bytes(),
        wall.tv_sec,
        boottime_nanoseconds,
    )
    .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)
}

fn lifecycle_transition(
    action: NetworkNamespaceLifecycleActionV1,
    desired_state: crate::NetworkNamespaceObservedStateV1,
    observation: NetworkNamespaceLifecycleObservationV1,
) -> Result<NetworkNamespaceLifecycleTransitionV1, DormantNetworkBrokerCallErrorV1> {
    let transition = match action {
        NetworkNamespaceLifecycleActionV1::Arm => {
            let (lease_digest, generation, deadline) = desired_state
                .lease()
                .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
            NetworkNamespaceLifecycleTransitionV1::arm(
                observation,
                lease_digest,
                generation,
                deadline,
            )
        }
        NetworkNamespaceLifecycleActionV1::Renew => {
            let (lease_digest, generation, deadline) = desired_state
                .lease()
                .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
            NetworkNamespaceLifecycleTransitionV1::renew(
                observation,
                lease_digest,
                generation,
                deadline,
            )
        }
        NetworkNamespaceLifecycleActionV1::Disarm => {
            NetworkNamespaceLifecycleTransitionV1::disarm(observation)
        }
        NetworkNamespaceLifecycleActionV1::Destroy => {
            NetworkNamespaceLifecycleTransitionV1::destroy(observation)
        }
        NetworkNamespaceLifecycleActionV1::Fence => {
            return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
        }
    };
    transition
        .map_err(NetworkBrokerError::from)
        .map_err(Into::into)
}

fn destroyed_custody_observation_digest(
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    target: crate::NetworkNamespaceIdentityV1,
    proof: PreparedNetworkObservationV1,
    pin_removal_digest: ObjectDigest,
) -> Result<ObjectDigest, DormantNetworkBrokerCallErrorV1> {
    if proof.request_id() != request_id
        || proof.effect_digest() != effect_digest
        || proof.kernel_boot_id() != target.kernel_boot_id()
        || proof.namespace().device != target.namespace_device()
        || proof.namespace().inode != target.namespace_inode()
        || proof.observed_state().kind() != crate::NetworkNamespaceObservedStateKindV1::Absent
        || pin_removal_digest.as_bytes() == &[0; 32]
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }
    let namespace = proof.namespace();
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.destroyed-custody-observation.v1\0");
    digest.update(request_id);
    digest.update(effect_digest.as_bytes());
    digest.update(proof.kernel_plan_digest().as_bytes());
    digest.update(target.network_handle());
    digest.update(target.kernel_boot_id());
    digest.update(namespace.device.to_be_bytes());
    digest.update(namespace.inode.to_be_bytes());
    digest.update(proof.observation_digest().as_bytes());
    digest.update(pin_removal_digest.as_bytes());
    digest.update(b"systemd-descriptor-store-absent\0");
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn lifecycle_response(
    operation: &NetworkOperation,
    result: CommittedNetworkLifecycleResultV1,
) -> Result<Vec<u8>, DormantNetworkBrokerCallErrorV1> {
    let (expected_action, state, lease_generation) = match operation {
        NetworkOperation::ArmLease {
            lease_generation, ..
        } => (
            NetworkNamespaceLifecycleActionV1::Arm,
            NetworkState::NETWORK_STATE_ARMED,
            *lease_generation,
        ),
        NetworkOperation::RenewLease {
            lease_generation, ..
        } => (
            NetworkNamespaceLifecycleActionV1::Renew,
            NetworkState::NETWORK_STATE_ARMED,
            *lease_generation,
        ),
        NetworkOperation::Disarm { .. } => (
            NetworkNamespaceLifecycleActionV1::Disarm,
            NetworkState::NETWORK_STATE_DEFAULT_DROP,
            0,
        ),
        NetworkOperation::Destroy { .. } => (
            NetworkNamespaceLifecycleActionV1::Destroy,
            NetworkState::NETWORK_STATE_ABSENT,
            0,
        ),
        NetworkOperation::Prepare { .. } => {
            return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
        }
    };
    if result.action() != expected_action {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }

    Ok(NetworkResult {
        network_handle: result.network_handle().to_vec(),
        state: state.into(),
        lease_generation,
        ..Default::default()
    }
    .encode_to_vec())
}

fn network_observation_commitment(
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    admission: DormantNetworkBrokerAdmissionV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-network-broker-observation-v1\0");
    digest.update(request_id);
    digest.update(request_body_digest.as_bytes());
    let (tag, outcome_digest) = match admission {
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Prepared {
            effect_digest,
        }) => (1, effect_digest),
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::ObserveOnly {
            effect_digest,
            ..
        }) => (2, effect_digest),
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Aborted {
            effect_digest,
        }) => (3, effect_digest),
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Replay(result)) => {
            (4, result.result_digest())
        }
        DormantNetworkBrokerAdmissionV1::Lifecycle(
            NetworkLifecycleAdmissionOutcome::Prepared { effect_digest },
        ) => (5, effect_digest),
        DormantNetworkBrokerAdmissionV1::Lifecycle(
            NetworkLifecycleAdmissionOutcome::ObserveOnly { effect_digest, .. },
        ) => (6, effect_digest),
        DormantNetworkBrokerAdmissionV1::Lifecycle(NetworkLifecycleAdmissionOutcome::Replay(
            result,
        )) => (7, result.observation_digest()),
    };
    digest.update([tag]);
    digest.update(outcome_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
