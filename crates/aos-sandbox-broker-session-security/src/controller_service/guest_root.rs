//! Retained controller exchange for one separately admitted Storage root effect.
//!
//! The protected controller journal reserves the operation before this owner
//! sends method 31. Transport ambiguity retains exact session custody; after a
//! restart the same reserved operation is reconciled by fresh Storage inventory.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerAuthorizationArtifactsV1, BrokerMethod, BrokerRequestEnvelope,
    PopulateStorageGuestRootRequestV1, RequestHeader,
};
use aos_sandbox::guest_root_publication::GuestRootPublicationReservationV1;
use aos_sandbox::{EffectFailure, SignedBrokerPlan};
use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::semantics::decode_storage_guest_root_response_v1;
use buffa::Message as _;

use crate::DormantAuthenticatedBrokerSessionV1;
use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};

const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT;
const MAXIMUM_RESPONSE_BYTES: u32 = 4096;
const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "guest-root exchange custody is absent",
    retained: "guest-root exchange retains exact Storage session custody",
    unusable: "guest-root Storage session is unusable",
};

/// Retains one exact method-31 exchange until signed terminal result custody.
#[derive(Default)]
pub(super) struct ControllerGuestRootExchangeV1 {
    exchange: RetainedBrokerExchangeV1<GuestRootPublicationReservationV1>,
}

impl ControllerGuestRootExchangeV1 {
    pub(super) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    pub(super) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    pub(super) fn pending_reservation(&self) -> Option<GuestRootPublicationReservationV1> {
        self.exchange.context().copied()
    }

    pub(super) fn resume(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<Option<GuestRootPublicationProofV1>, EffectFailure> {
        if self.exchange.context().is_none() {
            return Ok(None);
        }
        let (reservation, outcome) = self.exchange.drive(session, &ERRORS)?;
        classify_outcome(&reservation, &outcome).map(Some)
    }

    pub(super) fn apply(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        reservation: GuestRootPublicationReservationV1,
        signed_plan: &SignedBrokerPlan,
        lease: Vec<u8>,
        lease_signature: Vec<u8>,
    ) -> Result<GuestRootPublicationProofV1, EffectFailure> {
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(
                "Storage guest-root session requires reconnect".to_owned(),
            ));
        }
        if self
            .exchange
            .context()
            .is_some_and(|pending| pending != &reservation)
        {
            return Err(EffectFailure::Retryable(
                "another guest-root exchange retains Storage session custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
            let authorization = BrokerAuthorizationArtifactsV1 {
                broker_plan: signed_plan.canonical_plan().to_vec(),
                broker_plan_signature: signed_plan.canonical_signature().to_vec(),
                ownership_lease: lease,
                ownership_lease_signature: lease_signature,
                ..Default::default()
            };
            let preparation = session
                .prepare_authenticated_request(METHOD, |coordinates| {
                    envelope(&reservation, coordinates, &authorization)
                })
                .map_err(|_| {
                    self.exchange.mark_failed();
                    EffectFailure::Retryable(
                        "guest-root effect could not enter protected Storage session custody"
                            .to_owned(),
                    )
                })?;
            self.exchange.start(reservation, preparation);
        }
        let (reservation, outcome) = self.exchange.drive(session, &ERRORS)?;
        let proof = classify_outcome(&reservation, &outcome);
        if matches!(&proof, Err(EffectFailure::Permanent(_))) {
            self.exchange.mark_failed();
        }
        proof
    }
}
fn envelope(
    reservation: &GuestRootPublicationReservationV1,
    coordinates: crate::DormantBrokerRequestCoordinatesV1,
    authorization: &BrokerAuthorizationArtifactsV1,
) -> BrokerRequestEnvelope {
    let header = RequestHeader {
        protocol_major: u32::from(coordinates.protocol_version().major()),
        protocol_minor: u32::from(coordinates.protocol_version().minor()),
        request_id: coordinates.request_id().to_vec(),
        audience: coordinates.audience().into(),
        deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
        maximum_response_bytes: coordinates.maximum_response_bytes(),
        ..Default::default()
    };
    let (incarnation, epoch, generation, assignment_digest) = reservation.assignment_fence();
    let fence = AssignmentFence {
        sandbox_id: reservation.sandbox().as_bytes().to_vec(),
        incarnation_id: incarnation.to_vec(),
        assignment_epoch: epoch,
        desired_generation: generation,
        assignment_digest: assignment_digest.to_vec(),
        ..Default::default()
    };
    let request = PopulateStorageGuestRootRequestV1 {
        header: Some(header).into(),
        fence: Some(fence).into(),
        operation_id: reservation.operation().as_bytes().to_vec(),
        workspace_handle: reservation.workspace_handle().to_vec(),
        creation_operation_id: reservation.creation_operation().to_vec(),
        ..Default::default()
    };
    BrokerRequestEnvelope {
        method: METHOD.into(),
        body: request.encode_to_vec(),
        authorization: Some(authorization.clone()).into(),
        ..Default::default()
    }
}

fn classify_outcome(
    reservation: &GuestRootPublicationReservationV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<GuestRootPublicationProofV1, EffectFailure> {
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != METHOD
    {
        return Err(EffectFailure::Permanent(
            "Storage guest-root outcome has the wrong signed method".to_owned(),
        ));
    }
    let exact_body = outcome.request().exact_body();
    let request =
        PopulateStorageGuestRootRequestV1::decode_from_slice(exact_body).map_err(|_| {
            EffectFailure::Permanent("Storage guest-root signed request is malformed".to_owned())
        })?;
    let (incarnation, epoch, generation, assignment_digest) = reservation.assignment_fence();
    let fence = request.fence.as_option().ok_or_else(|| {
        EffectFailure::Permanent("Storage guest-root signed request has no fence".to_owned())
    })?;
    if request.encode_to_vec() != exact_body
        || request.operation_id != reservation.operation().as_bytes()
        || request.workspace_handle != reservation.workspace_handle()
        || request.creation_operation_id != reservation.creation_operation()
        || fence.sandbox_id != reservation.sandbox().as_bytes()
        || fence.incarnation_id != incarnation
        || fence.assignment_epoch != epoch
        || fence.desired_generation != generation
        || fence.assignment_digest != assignment_digest
    {
        return Err(EffectFailure::Permanent(
            "Storage guest-root signed request differs from reservation".to_owned(),
        ));
    }
    let exact_body = match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
        AuthenticatedBrokerMethodResultV1::Error(error) if error.retryable() => {
            return Err(EffectFailure::Retryable(
                "Storage guest-root effect is temporarily unavailable".to_owned(),
            ));
        }
        AuthenticatedBrokerMethodResultV1::Error(_) => {
            return Err(EffectFailure::Permanent(
                "Storage guest-root effect was rejected before publication".to_owned(),
            ));
        }
    };
    let proof = decode_storage_guest_root_response_v1(exact_body, MAXIMUM_RESPONSE_BYTES).map_err(
        |_| EffectFailure::Permanent("Storage guest-root response proof is malformed".to_owned()),
    )?;
    reservation.verify_response_proof(proof).map_err(|_| {
        EffectFailure::Permanent("Storage guest-root response proof is foreign".to_owned())
    })?;
    Ok(proof)
}
