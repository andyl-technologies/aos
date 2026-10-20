//! Owns the finite transport stages of an already-prepared inventory exchange.
//!
//! Each stage retains the genuine sealed request or recovery object and advances
//! through the same authenticated session. Controller keeps method context,
//! preparation, operation gates, readiness polling, and custody parking.
//! Native failures return immediately; an ambiguous receive commit returns its
//! error with recovery so Controller can park the cause before wrapping recovery.

use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1, DormantBrokerSessionHandshakeErrorV1,
    DormantOutstandingBrokerRequestV1, DormantPreparedBrokerRequestV1,
    DormantUnconfirmedBrokerRequestV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerSessionInitializationRecoveryV1,
};

/// Retains one sealed inventory exchange at its next transport transition.
pub(crate) enum InventoryTransportStageV1 {
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

/// Returns completion, retained transport custody, or an unparked native cause.
pub(crate) enum InventoryTransportProgressV1 {
    Complete {
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    },
    RecoveryRequired(InventoryTransportStageV1),
    ReceiveCommitRecovery {
        error: BrokerSessionSecurityError,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    },
}

/// Distinguishes a native transport failure from an impossible recovery stage.
pub(crate) enum InventoryTransportErrorV1 {
    Readiness(DormantBrokerSessionHandshakeErrorV1),
    Refused,
}

impl InventoryTransportStageV1 {
    /// Advances sealed custody without preparing, polling, or replacing a request.
    ///
    /// Matching durable recovery retains its original custody. A cross-stage
    /// preparation result is consumed on refusal, as at the original frontier.
    ///
    /// # Errors
    ///
    /// Returns the native handshake error immediately on send or receive failure,
    /// or refuses a preparation result from the other durable recovery stage.
    pub(crate) fn advance(
        self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<InventoryTransportProgressV1, InventoryTransportErrorV1> {
        match self {
            Self::Initialization { recovery, request } => {
                match session.recover_prepared_initialization(recovery, request) {
                    DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                        Self::send(session, prepared)
                    }
                    DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                        recovery,
                        request,
                        ..
                    } => Ok(InventoryTransportProgressV1::RecoveryRequired(
                        Self::Initialization { recovery, request },
                    )),
                    DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { .. } => {
                        Err(InventoryTransportErrorV1::Refused)
                    }
                }
            }
            Self::Successor { recovery, request } => {
                match session.recover_prepared_successor(recovery, request) {
                    DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                        Self::send(session, prepared)
                    }
                    DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                        recovery,
                        request,
                        ..
                    } => Ok(InventoryTransportProgressV1::RecoveryRequired(
                        Self::Successor { recovery, request },
                    )),
                    DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { .. } => {
                        Err(InventoryTransportErrorV1::Refused)
                    }
                }
            }
            Self::Send(prepared) => Self::send(session, prepared),
            Self::Receive(outstanding) => Self::receive(session, outstanding),
            Self::Commit(recovery) => {
                match session.recover_broker_outcome_commit(recovery) {
                    ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                        let (outcome, currentness) = committed.into_outcome_and_currentness();
                        Ok(InventoryTransportProgressV1::Complete {
                            outcome,
                            currentness,
                        })
                    }
                    ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                        Ok(InventoryTransportProgressV1::RecoveryRequired(Self::Commit(
                            recovery,
                        )))
                    }
                }
            }
        }
    }

    fn send(
        session: &mut DormantAuthenticatedBrokerSessionV1,
        prepared: DormantPreparedBrokerRequestV1,
    ) -> Result<InventoryTransportProgressV1, InventoryTransportErrorV1> {
        match session
            .send_authenticated_request(prepared)
            .map_err(InventoryTransportErrorV1::Readiness)?
        {
            DormantBrokerRequestSendProgressV1::Pending(prepared) => {
                Ok(InventoryTransportProgressV1::RecoveryRequired(Self::Send(
                    prepared,
                )))
            }
            DormantBrokerRequestSendProgressV1::Sent(outstanding) => {
                Self::receive(session, outstanding)
            }
        }
    }

    fn receive(
        session: &mut DormantAuthenticatedBrokerSessionV1,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<InventoryTransportProgressV1, InventoryTransportErrorV1> {
        match session
            .receive_authenticated_response(outstanding)
            .map_err(InventoryTransportErrorV1::Readiness)?
        {
            DormantBrokerResponseProgressV1::Pending(outstanding) => {
                Ok(InventoryTransportProgressV1::RecoveryRequired(Self::Receive(
                    outstanding,
                )))
            }
            DormantBrokerResponseProgressV1::Committed(
                ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
            ) => {
                let (outcome, currentness) = committed.into_outcome_and_currentness();
                Ok(InventoryTransportProgressV1::Complete {
                    outcome,
                    currentness,
                })
            }
            DormantBrokerResponseProgressV1::Committed(
                ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery },
            ) => Ok(InventoryTransportProgressV1::ReceiveCommitRecovery {
                error,
                recovery,
            }),
        }
    }
}
