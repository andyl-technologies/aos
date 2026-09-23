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

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestPreparationV1,
    DormantBrokerRequestSendProgressV1, DormantBrokerResponseProgressV1,
    DormantOutstandingBrokerRequestV1, DormantPreparedBrokerRequestV1,
    DormantUnconfirmedBrokerRequestV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerSessionInitializationRecoveryV1,
};

const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT;
const MAXIMUM_RESPONSE_BYTES: u32 = 4096;

struct PendingGuestRootExchangeV1 {
    reservation: GuestRootPublicationReservationV1,
    stage: GuestRootExchangeStageV1,
}

enum GuestRootExchangeStageV1 {
    Initialization {
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Successor {
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Send(DormantPreparedBrokerRequestV1),
    Receive(DormantOutstandingBrokerRequestV1),
    Commit(ProtectedBrokerOutcomeCommitRecoveryV1),
}

/// Retains one exact method-31 exchange until signed terminal result custody.
#[derive(Default)]
pub(super) struct ControllerGuestRootExchangeV1 {
    pending: Option<PendingGuestRootExchangeV1>,
    failed: bool,
}

impl ControllerGuestRootExchangeV1 {
    pub(super) const fn has_pending(&self) -> bool {
        self.pending.is_some() || self.failed
    }

    pub(super) const fn requires_reconnect(&self) -> bool {
        self.failed
    }

    pub(super) fn pending_reservation(&self) -> Option<GuestRootPublicationReservationV1> {
        self.pending.as_ref().map(|pending| pending.reservation)
    }

    pub(super) fn resume(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<Option<GuestRootPublicationProofV1>, EffectFailure> {
        if self.pending.is_none() {
            return Ok(None);
        }
        let (reservation, outcome) = self.drive(session)?;
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
        if self.failed {
            return Err(EffectFailure::Retryable(
                "Storage guest-root session requires reconnect".to_owned(),
            ));
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.reservation != reservation)
        {
            return Err(EffectFailure::Retryable(
                "another guest-root exchange retains Storage session custody".to_owned(),
            ));
        }
        if self.pending.is_none() {
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
                    self.failed = true;
                    EffectFailure::Retryable(
                        "guest-root effect could not enter protected Storage session custody"
                            .to_owned(),
                    )
                })?;
            self.pending = Some(PendingGuestRootExchangeV1 {
                reservation,
                stage: preparation_stage(preparation),
            });
        }
        let (reservation, outcome) = self.drive(session)?;
        let proof = classify_outcome(&reservation, &outcome);
        if matches!(&proof, Err(EffectFailure::Permanent(_))) {
            self.failed = true;
        }
        proof
    }

    fn drive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<
        (
            GuestRootPublicationReservationV1,
            AuthenticatedBrokerMethodOutcomeV1,
        ),
        EffectFailure,
    > {
        let mut attempted_recovery = false;
        loop {
            let pending = self.pending.take().ok_or_else(|| {
                EffectFailure::Retryable("guest-root exchange custody is absent".to_owned())
            })?;
            let reservation = pending.reservation;
            let stage = match pending.stage {
                GuestRootExchangeStageV1::Initialization { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            reservation,
                            GuestRootExchangeStageV1::Initialization { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_initialization(recovery, request))
                }
                GuestRootExchangeStageV1::Successor { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            reservation,
                            GuestRootExchangeStageV1::Successor { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_successor(recovery, request))
                }
                GuestRootExchangeStageV1::Send(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_request(prepared) {
                        Ok(DormantBrokerRequestSendProgressV1::Sent(outstanding)) => {
                            GuestRootExchangeStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerRequestSendProgressV1::Pending(prepared)) => {
                            if wait(session, true, deadline).is_err() {
                                return self
                                    .retain(reservation, GuestRootExchangeStageV1::Send(prepared));
                            }
                            GuestRootExchangeStageV1::Send(prepared)
                        }
                        Err(_) => return self.fail(),
                    }
                }
                GuestRootExchangeStageV1::Receive(outstanding) => {
                    let deadline = outstanding.deadline_boottime_nanoseconds();
                    match session.receive_authenticated_response(outstanding) {
                        Ok(DormantBrokerResponseProgressV1::Pending(outstanding)) => {
                            if wait(session, false, deadline).is_err() {
                                return self.retain(
                                    reservation,
                                    GuestRootExchangeStageV1::Receive(outstanding),
                                );
                            }
                            GuestRootExchangeStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                        )) => return self.complete(session, reservation, committed),
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                                recovery, ..
                            },
                        )) => GuestRootExchangeStageV1::Commit(recovery),
                        Err(_) => return self.fail(),
                    }
                }
                GuestRootExchangeStageV1::Commit(recovery) => {
                    if attempted_recovery {
                        return self
                            .retain(reservation, GuestRootExchangeStageV1::Commit(recovery));
                    }
                    attempted_recovery = true;
                    match session.recover_broker_outcome_commit(recovery) {
                        ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                            return self.complete(session, reservation, committed);
                        }
                        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                            recovery, ..
                        } => GuestRootExchangeStageV1::Commit(recovery),
                    }
                }
            };
            self.pending = Some(PendingGuestRootExchangeV1 { reservation, stage });
        }
    }

    fn retain<T>(
        &mut self,
        reservation: GuestRootPublicationReservationV1,
        stage: GuestRootExchangeStageV1,
    ) -> Result<T, EffectFailure> {
        self.pending = Some(PendingGuestRootExchangeV1 { reservation, stage });
        Err(EffectFailure::Retryable(
            "guest-root exchange retains exact Storage session custody".to_owned(),
        ))
    }

    fn fail<T>(&mut self) -> Result<T, EffectFailure> {
        self.failed = true;
        Err(EffectFailure::Retryable(
            "guest-root Storage session is unusable".to_owned(),
        ))
    }

    fn complete(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        reservation: GuestRootPublicationReservationV1,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<
        (
            GuestRootPublicationReservationV1,
            AuthenticatedBrokerMethodOutcomeV1,
        ),
        EffectFailure,
    > {
        let (outcome, currentness) = committed.into_outcome_and_currentness();
        let Ok(mut current) = session.revalidate_broker_outcome(currentness) else {
            return self.fail();
        };
        if current.revalidate().is_err() {
            return self.fail();
        }
        Ok((reservation, outcome))
    }
}

fn preparation_stage(preparation: DormantBrokerRequestPreparationV1) -> GuestRootExchangeStageV1 {
    match preparation {
        DormantBrokerRequestPreparationV1::Prepared(prepared) => {
            GuestRootExchangeStageV1::Send(prepared)
        }
        DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
            recovery,
            request,
            ..
        } => GuestRootExchangeStageV1::Initialization { recovery, request },
        DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
            recovery, request, ..
        } => GuestRootExchangeStageV1::Successor { recovery, request },
    }
}

fn wait(
    session: &DormantAuthenticatedBrokerSessionV1,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ()> {
    let descriptor = session.as_fd().map_err(|_| ())?;
    crate::dormant_handshake::wait_for_handshake_readiness(
        descriptor,
        wants_write,
        deadline_boottime_nanoseconds,
    )
    .map_err(|_| ())
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
