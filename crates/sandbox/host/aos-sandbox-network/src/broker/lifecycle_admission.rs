//! Retains lifecycle signed admission beside the sole durable admission engine.
//!
//! Ordinary calls and the genuine Destroy9 source borrower share the complete
//! canonical catalog/fence/State predicates. Only the selected borrower lends
//! the prepaid exact-append gate; no callback signs or issues effect authority.

use super::*;
use aos_sandbox_broker::{BrokerSignedAdmissionOriginalV4, VerifiedBrokerAdmission};
use aos_sandbox_model::AccountingError;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::semantics::network::NetworkSemanticsError;

pub(super) type Gate<'held> = dyn FnMut(
        &NetworkAuthorityV1,
        &VerifiedBrokerAdmission,
        &crate::journal::Journal,
        &crate::journal::JournalTransaction,
    ) -> Result<(), NetworkLifecycleStateError>
    + 'held;

pub(crate) struct NetworkLifecycleAdmissionOriginalV4 {
    signed: BrokerSignedAdmissionOriginalV4,
    semantic: Option<Result<CanonicalNetworkSemanticsV1, NetworkSemanticsError>>,
    assignment: Option<Result<aos_sandbox_model::BrokerAssignment, NetworkAdmissionError>>,
    catalog: Option<Result<(), NetworkAdmissionError>>,
    prior: Option<Result<Option<Vec<u8>>, NetworkAdmissionError>>,
    admission: Option<Result<VerifiedBrokerAdmission, NetworkAdmissionError>>,
    current_fence: Option<Result<Vec<u8>, NetworkAdmissionError>>,
    operation_fence: Option<Result<Vec<u8>, NetworkAdmissionError>>,
    effect: Option<Result<Vec<u8>, NetworkAdmissionError>>,
    returned: Option<Result<NetworkLifecycleAdmissionOutcome, NetworkBrokerError>>,
    request_binding: Option<[u8; 32]>,
    entered: bool,
}

impl NetworkLifecycleAdmissionOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            signed: BrokerSignedAdmissionOriginalV4::new(),
            semantic: None,
            assignment: None,
            catalog: None,
            prior: None,
            admission: None,
            current_fence: None,
            operation_fence: None,
            effect: None,
            returned: None,
            request_binding: None,
            entered: false,
        }
    }

    pub(crate) fn run_selected_once_v4(
        &mut self,
        coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        request: &AuthenticatedBrokerMethodRequestV1,
        preparation: &AuthenticatedNetworkPreparationV1,
        kernel_plan: &NetworkKernelPlanV1,
        namespaces: &NetworkNamespaceCatalogV1,
        clock: &RawPairedClockSample,
        before_commit: &mut Gate<'_>,
    ) -> Result<NetworkLifecycleAdmissionOutcome, NetworkBrokerError> {
        if self.entered {
            return Err(NetworkBrokerError::Request);
        }
        self.entered = true;
        self.returned = Some((|| {
            if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive {
                return Err(NetworkBrokerError::Request);
            }
            let semantics = request
                .network_destroy_data_v4()
                .ok_or(NetworkBrokerError::Request)?;
            let artifacts = request
                .authorization()
                .ok_or(NetworkBrokerError::Authority)?;
            self.request_binding = Some(Sha256::digest(request.canonical_packet()).into());
            self.run_inner_v4(
                coordinator,
                request.exact_body(),
                artifacts,
                preparation,
                kernel_plan,
                namespaces,
                semantics.header().protocol_version(),
                request.peer(),
                request.peer_policy(),
                clock,
                Some(semantics),
                Some(before_commit),
            )
        })());
        self.returned
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(NetworkBrokerError::Authority)
    }

    pub(crate) fn verified_v4(&self) -> Option<&VerifiedBrokerAdmission> {
        if !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.admission.as_ref()?.as_ref().ok()
    }

    pub(crate) fn outcome_v4(&self) -> Option<NetworkLifecycleAdmissionOutcome> {
        self.returned.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn require_request_v4(&self, request: &AuthenticatedBrokerMethodRequestV1)
        -> Result<(), NetworkBrokerError> {
        if self.verified_v4().is_none() || request.network_destroy_data_v4().is_none()
            || self.request_binding != Some(Sha256::digest(request.canonical_packet()).into()) {
            return Err(NetworkBrokerError::Request);
        }
        Ok(())
    }

    pub(crate) fn receiving_demand_v4() -> Result<aos_sandbox_model::ResourceVector, AccountingError>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            slot: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        cause(&self.semantic)
            .or_else(|| cause(&self.assignment))
            .or_else(|| cause(&self.catalog))
            .or_else(|| cause(&self.prior))
            .or_else(|| self.signed.failure())
            .or_else(|| cause(&self.admission))
            .or_else(|| cause(&self.current_fence))
            .or_else(|| cause(&self.operation_fence))
            .or_else(|| cause(&self.effect))
            .or_else(|| cause(&self.returned))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_inner_v4(
        &mut self,
        coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        preparation: &AuthenticatedNetworkPreparationV1,
        kernel_plan: &NetworkKernelPlanV1,
        namespaces: &NetworkNamespaceCatalogV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
        selected: Option<&CanonicalNetworkSemanticsV1>,
        before_commit: Option<&mut Gate<'_>>,
    ) -> Result<NetworkLifecycleAdmissionOutcome, NetworkBrokerError> {
        self.semantic = Some(match selected {
            Some(semantic) => Ok(semantic.clone()),
            None => CanonicalNetworkSemanticsV1::decode(
                request_body,
                peer,
                policy,
                current_clock.boottime_nanoseconds(),
            ),
        });
        let semantics = self
            .semantic
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkBrokerError::Request)?;
        self.assignment = Some(decode_assignment(request_body));
        let assignment = self.assignment.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(NetworkBrokerError::Request)?;
        self.catalog = Some(coordinator.authority.validate_catalog(preparation, assignment)
            .map(|_| ()));
        if !matches!(self.catalog, Some(Ok(()))) {
            return Err(NetworkBrokerError::Authority);
        }
        // The positive check authenticated this exact protected owner. Reuse
        // its same resolution without re-verifying or reconstructing a token.
        let resolution = preparation.resolution();
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
        let creation_fence = coordinator
            .creation_state
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)?;
        self.prior = Some(coordinator.authority.latest_fence(
            &sandbox_id,
            [
                creation_fence,
                coordinator.lifecycle_state.current_fence(&sandbox_id),
            ],
        ));
        let prior_fence = self
            .prior
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkBrokerError::Authority)?;
        self.admission = Some(match selected {
            Some(_) => coordinator.authority.admit_retaining_v4(
                artifacts,
                semantics,
                request_body,
                protocol_version,
                current_clock,
                prior_fence.as_deref(),
                &mut self.signed,
            ),
            None => coordinator.authority.admit(
                artifacts,
                semantics,
                request_body,
                protocol_version,
                current_clock,
                prior_fence.as_deref(),
            ),
        });
        let admission = self
            .admission
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkBrokerError::Authority)?;
        self.current_fence = Some(coordinator.authority.seal_fence(&sandbox_id, admission));
        let current_fence = take_sealed_v4(&mut self.current_fence)?;
        self.operation_fence = Some(
            coordinator
                .authority
                .seal_operation_fence(&request_id, admission),
        );
        let operation_fence = take_sealed_v4(&mut self.operation_fence)?;
        self.effect = Some(coordinator.authority.seal_effect(&request_id, admission));
        let effect = take_sealed_v4(&mut self.effect)?;
        if kernel_plan.assignment() != assignment
            || !kernel_plan_matches_catalog(kernel_plan, resolution)
            || (kernel_plan.observation_expectation().veth().is_none()
                && matches!(
                    semantics.operation(),
                    NetworkOperation::ArmLease { .. } | NetworkOperation::RenewLease { .. }
                ))
        {
            return Err(NetworkBrokerError::Request);
        }
        if let Some(outcome) = coordinator.lifecycle_state.existing_authorized_outcome(
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

        let outcome = match before_commit {
            Some(before_commit) => {
                let mut gate =
                    |journal: &crate::journal::Journal,
                     transaction: &crate::journal::JournalTransaction| {
                        before_commit(&coordinator.authority, admission, journal, transaction)
                    };
                coordinator.lifecycle_state.begin_authorized_guarded_v4(
                    &coordinator.authority,
                    record,
                    Some(&mut gate),
                )
            }
            None => coordinator
                .lifecycle_state
                .begin_authorized(&coordinator.authority, record),
        }?;
        Ok(map_lifecycle_outcome(outcome))
    }
}

fn take_sealed_v4(
    slot: &mut Option<Result<Vec<u8>, NetworkAdmissionError>>,
) -> Result<Vec<u8>, NetworkBrokerError> {
    if !matches!(slot, Some(Ok(_))) {
        return Err(NetworkBrokerError::Authority);
    }
    match slot.take() {
        Some(Ok(bytes)) => Ok(bytes),
        _ => Err(NetworkBrokerError::Authority),
    }
}
