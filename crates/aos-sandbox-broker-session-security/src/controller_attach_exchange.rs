//! Retained authenticated controller-to-Host attach-gate broker exchange.
//!
//! The exact method-28 request remains in protected broker-session custody
//! across send, response, and commit ambiguity. This owner never turns a Host
//! error or an unauthenticated body into attach route evidence.

use aos_proto::aos::sandbox::local::v1::{
    BrokerAuthorizationArtifactsV1, BrokerMethod, BrokerRequestEnvelope,
    InstallHostAttachGateRequestV1, RequestHeader,
};
use aos_sandbox::EffectFailure;
use aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use buffa::Message as _;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestCoordinatesV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1, DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerRequestV1, DormantUnconfirmedBrokerRequestV1,
    ProtectedBrokerOutcomeCommitRecoveryV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerSessionInitializationRecoveryV1,
};

const RETAINED_RECOVERY: &str = "attach gate request retains protected Host session recovery";
const SESSION_UNUSABLE: &str = "attach gate Host session is unusable";

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostAttachInstallIntentV1 {
    grant: [u8; PUBLIC_ATTACH_GRANT_BYTES],
}

impl HostAttachInstallIntentV1 {
    fn new(grant: &[u8]) -> Result<Self, EffectFailure> {
        let grant: [u8; PUBLIC_ATTACH_GRANT_BYTES] = grant.try_into().map_err(|_| {
            EffectFailure::Permanent("attach pending grant length is invalid".to_owned())
        })?;
        if &grant[..8] != b"AOSAPG01" {
            return Err(EffectFailure::Permanent(
                "attach pending grant magic is invalid".to_owned(),
            ));
        }
        Ok(Self { grant })
    }

    fn envelope(
        &self,
        coordinates: DormantBrokerRequestCoordinatesV1,
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
        let body = InstallHostAttachGateRequestV1 {
            header: Some(header).into(),
            pending_grant: self.grant.to_vec(),
            ..Default::default()
        };
        BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE.into(),
            body: body.encode_to_vec(),
            authorization: Some(authorization.clone()).into(),
            ..Default::default()
        }
    }
}

struct PendingHostAttachInstallV1 {
    intent: HostAttachInstallIntentV1,
    stage: HostAttachInstallStageV1,
}

enum HostAttachInstallStageV1 {
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

/// Retains one exact method-28 request until its signed outcome is committed.
#[derive(Default)]
pub(crate) struct ControllerHostAttachGateExchangeV1 {
    pending: Option<PendingHostAttachInstallV1>,
    failed: bool,
}

impl ControllerHostAttachGateExchangeV1 {
    /// Reports whether this exchange currently owns protected Host custody.
    pub(crate) const fn has_pending(&self) -> bool {
        self.pending.is_some() || self.failed
    }

    /// Reports whether the transport must be reopened before further work.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.failed
    }

    /// Installs one exact signed grant through the retained Host session.
    ///
    /// # Errors
    ///
    /// Returns a retryable error while exact protected recovery is retained or
    /// the authenticated transport is unavailable. It never interprets a Host
    /// success body as route evidence; the worker applies the shared decoder.
    pub(crate) fn install(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        grant: &[u8],
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if self.failed {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        let intent = HostAttachInstallIntentV1::new(grant)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.intent != intent)
        {
            return Err(EffectFailure::Retryable(
                "another exact attach request retains Host session custody".to_owned(),
            ));
        }
        if self.pending.is_none() {
            let authorization = authorization.ok_or_else(|| {
                EffectFailure::Retryable("current attach Host authorization is absent".to_owned())
            })?;
            let preparation = session
                .prepare_authenticated_request_checked(
                    BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE,
                    |coordinates| intent.envelope(coordinates, authorization),
                    |request| {
                        request.exact_body().len()
                            <= aos_sandbox_protocol::HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES
                    },
                )
                .map_err(|_| {
                    self.failed = true;
                    EffectFailure::Retryable(
                        "attach request could not enter protected Host custody".to_owned(),
                    )
                })?;
            self.pending = Some(PendingHostAttachInstallV1 {
                intent,
                stage: preparation_stage(preparation),
            });
        }
        self.drive(session)
    }

    fn drive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        let mut attempted_recovery = false;
        loop {
            let pending = self.pending.take().ok_or_else(|| {
                EffectFailure::Retryable("attach request custody is absent".to_owned())
            })?;
            let intent = pending.intent;
            let stage = match pending.stage {
                HostAttachInstallStageV1::Initialization { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            intent,
                            HostAttachInstallStageV1::Initialization { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_initialization(recovery, request))
                }
                HostAttachInstallStageV1::Successor { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            intent,
                            HostAttachInstallStageV1::Successor { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_successor(recovery, request))
                }
                HostAttachInstallStageV1::Send(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_request(prepared) {
                        Ok(DormantBrokerRequestSendProgressV1::Sent(outstanding)) => {
                            HostAttachInstallStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerRequestSendProgressV1::Pending(prepared)) => {
                            if wait(session, true, deadline).is_err() {
                                return self
                                    .retain(intent, HostAttachInstallStageV1::Send(prepared));
                            }
                            HostAttachInstallStageV1::Send(prepared)
                        }
                        Err(_) => return self.fail(),
                    }
                }
                HostAttachInstallStageV1::Receive(outstanding) => {
                    let deadline = outstanding.deadline_boottime_nanoseconds();
                    match session.receive_authenticated_response(outstanding) {
                        Ok(DormantBrokerResponseProgressV1::Pending(outstanding)) => {
                            if wait(session, false, deadline).is_err() {
                                return self.retain(
                                    intent,
                                    HostAttachInstallStageV1::Receive(outstanding),
                                );
                            }
                            HostAttachInstallStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                        )) => return self.complete(session, committed),
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                                recovery, ..
                            },
                        )) => HostAttachInstallStageV1::Commit(recovery),
                        Err(_) => return self.fail(),
                    }
                }
                HostAttachInstallStageV1::Commit(recovery) => {
                    if attempted_recovery {
                        return self.retain(intent, HostAttachInstallStageV1::Commit(recovery));
                    }
                    attempted_recovery = true;
                    match session.recover_broker_outcome_commit(recovery) {
                        ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                            return self.complete(session, committed);
                        }
                        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                            recovery, ..
                        } => HostAttachInstallStageV1::Commit(recovery),
                    }
                }
            };
            self.pending = Some(PendingHostAttachInstallV1 { intent, stage });
        }
    }

    fn retain<T>(
        &mut self,
        intent: HostAttachInstallIntentV1,
        stage: HostAttachInstallStageV1,
    ) -> Result<T, EffectFailure> {
        self.pending = Some(PendingHostAttachInstallV1 { intent, stage });
        Err(EffectFailure::Retryable(RETAINED_RECOVERY.to_owned()))
    }

    fn fail<T>(&mut self) -> Result<T, EffectFailure> {
        self.failed = true;
        Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()))
    }

    fn complete(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        let (outcome, currentness) = committed.into_outcome_and_currentness();
        let Ok(mut current) = session.revalidate_broker_outcome(currentness) else {
            return self.fail();
        };
        if current.revalidate().is_err() {
            return self.fail();
        }
        Ok(outcome)
    }
}

fn preparation_stage(preparation: DormantBrokerRequestPreparationV1) -> HostAttachInstallStageV1 {
    match preparation {
        DormantBrokerRequestPreparationV1::Prepared(prepared) => {
            HostAttachInstallStageV1::Send(prepared)
        }
        DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
            recovery,
            request,
            ..
        } => HostAttachInstallStageV1::Initialization { recovery, request },
        DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
            recovery, request, ..
        } => HostAttachInstallStageV1::Successor { recovery, request },
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
