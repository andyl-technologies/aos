//! Retains the sole creation admission's actual typed projections and result.
//!
//! Ordinary entry keeps a local original and returns its unchanged actual
//! result. The fixed selected caller retains this same original through its
//! owed Session/F posts. Neither retained models nor coarse markers issue a
//! dispatch; the existing protected State transition remains the only issuer.

use super::*;
use aos_sandbox_broker::{BrokerSignedAdmissionOriginalV4, VerifiedBrokerAdmission};
use aos_sandbox_model::BrokerAssignment;
use aos_sandbox_protocol::semantics::network::NetworkSemanticsError;

pub(crate) struct NetworkCreationAdmissionOriginalV4 {
    pub(crate) signed: BrokerSignedAdmissionOriginalV4,
    assignment: Option<Result<BrokerAssignment, NetworkAdmissionError>>,
    request_id: Option<Result<[u8; 16], NetworkAdmissionError>>,
    semantic: Option<Result<CanonicalNetworkSemanticsV1, NetworkSemanticsError>>,
    catalog: Option<Result<(), NetworkAdmissionError>>,
    pub(crate) prior: Option<Result<Option<Vec<u8>>, NetworkAdmissionError>>,
    pub(crate) admission: Option<Result<VerifiedBrokerAdmission, NetworkAdmissionError>>,
    current_fence: Option<Result<Vec<u8>, NetworkAdmissionError>>,
    effect: Option<Result<Vec<u8>, NetworkAdmissionError>>,
    operation_fence: Option<Result<Vec<u8>, NetworkAdmissionError>>,
    returned: Option<Result<NetworkAdmissionOutcome, NetworkBrokerError>>,
    verified_body: Option<[u8; 32]>,
    verification_entered: bool,
    entered: bool,
}

impl NetworkCreationAdmissionOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { signed: BrokerSignedAdmissionOriginalV4::new(), assignment: None,
            request_id: None, semantic: None, catalog: None, prior: None,
            admission: None, current_fence: None, effect: None, operation_fence: None,
            returned: None, verified_body: None, verification_entered: false, entered: false }
    }

    pub(crate) fn verify_selected_once_v4(&mut self, authority: &NetworkAuthorityV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        clock: &RawPairedClockSample) -> Result<(), NetworkBrokerError> {
        if self.verification_entered || self.entered { return Err(NetworkBrokerError::Request); }
        self.verification_entered = true;
        let semantic = request.network_preparation_data_v2().ok_or(NetworkBrokerError::Request)?;
        let prior = self.prior.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(NetworkBrokerError::Authority)?.as_deref();
        let artifacts = request.authorization().ok_or(NetworkBrokerError::Authority)?;
        self.admission = Some(authority.admit_retaining_v4(artifacts, semantic,
            request.exact_body(), semantic.header().protocol_version(), clock, prior, &mut self.signed));
        if !matches!(self.admission, Some(Ok(_))) { return Err(NetworkBrokerError::Authority); }
        self.verified_body = Some(Sha256::digest(request.exact_body()).into());
        Ok(())
    }

    pub(crate) fn verified_v4(&self) -> Option<&VerifiedBrokerAdmission> {
        if !self.verification_entered || self.verified_body.is_none() { return None; }
        self.admission.as_ref()?.as_ref().ok()
    }

    pub(super) fn run_legacy_v4(&mut self, authority: &NetworkAuthorityV1,
        state: &mut NetworkStateStore, body: &[u8], artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &AuthenticatedNetworkPreparationV1, version: ProtocolVersion,
        peer: PeerCredentials, policy: PeerPolicy, clock: &RawPairedClockSample, prior: Option<&[u8]>) {
        self.returned = Some(self.run_inner_v4(authority, state, body, artifacts, catalog,
            version, peer, policy, clock, prior, None, None));
    }

    pub(crate) fn run_selected_v4(&mut self, authority: &NetworkAuthorityV1,
        state: &mut NetworkStateStore, body: &[u8], artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &AuthenticatedNetworkPreparationV1, semantic: &CanonicalNetworkSemanticsV1,
        peer: PeerCredentials, policy: PeerPolicy, clock: &RawPairedClockSample,
        before_commit: &mut dyn FnMut(&NetworkAuthorityV1, &VerifiedBrokerAdmission,
            &crate::journal::Journal, &crate::journal::JournalTransaction)
            -> Result<(), crate::state::NetworkStateError>) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
        if self.entered { return Err(NetworkBrokerError::Request); }
        self.entered = true;
        self.returned = Some(self.run_inner_v4(authority, state, body, artifacts, catalog,
            semantic.header().protocol_version(), peer, policy, clock, None, Some(semantic), Some(before_commit)));
        self.returned.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(NetworkBrokerError::Authority)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_inner_v4(&mut self, authority: &NetworkAuthorityV1,
        state: &mut NetworkStateStore, body: &[u8], artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &AuthenticatedNetworkPreparationV1, version: ProtocolVersion,
        peer: PeerCredentials, policy: PeerPolicy, clock: &RawPairedClockSample, legacy_prior: Option<&[u8]>,
        selected: Option<&CanonicalNetworkSemanticsV1>,
        before_commit: Option<&mut dyn FnMut(&NetworkAuthorityV1, &VerifiedBrokerAdmission,
            &crate::journal::Journal, &crate::journal::JournalTransaction)
            -> Result<(), crate::state::NetworkStateError>>) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
        self.assignment = Some(match selected {
            Some(semantic) => semantic.fence().broker_assignment().map_err(|_| NetworkAdmissionError::RequestMismatch),
            None => decode_assignment(body),
        });
        let assignment = self.assignment.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(NetworkBrokerError::Request)?;
        self.catalog = Some(authority.validate_catalog(catalog, assignment).map(|_| ()));
        if !matches!(self.catalog, Some(Ok(()))) { return Err(NetworkBrokerError::Authority); }
        let catalog = catalog.resolution();
        let sandbox_id = *assignment.sandbox().as_bytes();
        self.request_id = Some(match selected {
            Some(semantic) => Ok(*semantic.header().request_id()),
            None => decode_request_id(body),
        });
        let request_id = self.request_id.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(NetworkBrokerError::Request)?;
        let transport_digest = ObjectDigest::from_bytes(Sha256::digest(body).into());
        if let Some(effect_digest) = state.replay_aborted(request_id, sandbox_id, transport_digest, catalog)? {
            return Ok(NetworkAdmissionOutcome::Aborted { effect_digest });
        }
        self.semantic = Some(match selected {
            Some(semantic) => Ok(semantic.clone()),
            None => CanonicalNetworkSemanticsV1::decode(body, peer, policy, clock.boottime_nanoseconds()),
        });
        let semantic = self.semantic.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(NetworkBrokerError::Request)?;
        validate_catalog(semantic, catalog)?;
        let prior = if selected.is_some() {
            self.prior.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(NetworkBrokerError::Authority)?.as_deref()
        } else { legacy_prior };
        if selected.is_some() {
            // The actual signed admission preceded protected catalog growth.
            // Reuse only that same retained positive and exact original body;
            // a changed/failed/repeated source cannot invoke another verifier.
            if !self.verification_entered || self.verified_body != Some(Sha256::digest(body).into())
                || !matches!(self.admission, Some(Ok(_))) {
                return Err(NetworkBrokerError::Authority);
            }
        } else {
            self.admission = Some(authority.admit(artifacts, semantic, body, version, clock, prior));
        }
        let admission = self.admission.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(NetworkBrokerError::Authority)?;
        self.current_fence = Some(authority.seal_fence(&sandbox_id, admission));
        if !matches!(self.current_fence, Some(Ok(_))) { return Err(NetworkBrokerError::Authority); }
        self.effect = Some(authority.seal_effect(&request_id, admission));
        if !matches!(self.effect, Some(Ok(_))) { return Err(NetworkBrokerError::Authority); }
        self.operation_fence = Some(authority.seal_operation_fence(&request_id, admission));
        if !matches!(self.operation_fence, Some(Ok(_))) { return Err(NetworkBrokerError::Authority); }
        // Successful pure buffers move into the same State record; only
        // failures remain in their typed slots. No extra catalog/fence clone
        // or second retained semantic model is needed for native custody.
        let current_fence = take_success_v4(&mut self.current_fence)?;
        let effect = take_success_v4(&mut self.effect)?;
        let operation_fence = take_success_v4(&mut self.operation_fence)?;
        let record = prepared_record(PreparedNetworkRecordInput {
            request_id, sandbox_id, transport_digest, semantic_digest: semantic.argument_commitment().digest(),
            verb: semantic.broker_verb(), catalog: catalog.clone(), current_fence,
            operation_fence, effect,
        });
        let outcome = match before_commit {
            Some(before_commit) => {
                let mut gate = |journal: &crate::journal::Journal, transaction: &crate::journal::JournalTransaction| {
                    before_commit(authority, admission, journal, transaction)
                };
                state.begin_authorized_guarded_v4(authority, record, &mut gate)
            }
            None => state.begin_authorized(authority, record),
        }?;
        Ok(match outcome {
            NetworkBeginOutcome::Prepared { effect_digest } => NetworkAdmissionOutcome::Prepared { effect_digest },
            NetworkBeginOutcome::ObserveOnly { phase, effect_digest } => NetworkAdmissionOutcome::ObserveOnly { phase, effect_digest },
            NetworkBeginOutcome::Aborted { effect_digest } => NetworkAdmissionOutcome::Aborted { effect_digest },
            NetworkBeginOutcome::Replay(result) => NetworkAdmissionOutcome::Replay(result),
        })
    }

    pub(super) fn take_legacy_result_v4(&mut self) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
        self.returned.take().ok_or(NetworkBrokerError::Request)?
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        cause(&self.assignment).or_else(|| cause(&self.request_id)).or_else(|| cause(&self.catalog))
            .or_else(|| cause(&self.prior)).or_else(|| cause(&self.semantic)).or_else(|| self.signed.failure())
            .or_else(|| cause(&self.admission)).or_else(|| cause(&self.current_fence))
            .or_else(|| cause(&self.effect)).or_else(|| cause(&self.operation_fence))
            .or_else(|| cause(&self.returned))
    }
}

fn take_success_v4<T>(slot: &mut Option<Result<T, NetworkAdmissionError>>) -> Result<T, NetworkBrokerError> {
    if !matches!(slot, Some(Ok(_))) { return Err(NetworkBrokerError::Authority); }
    match slot.take() { Some(Ok(value)) => Ok(value), _ => std::process::abort() }
}
