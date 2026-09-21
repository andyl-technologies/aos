//! Bounded production receipt for authenticated broker requests.
//!
//! The public receipt methods consume the authenticated session. A successful
//! receipt returns that session beside one normalized request or replay event;
//! every error drops both transport and protected in-memory custody so the
//! service must reconnect and reopen the fixed journal.
//! Ready sockets and successful durable readbacks still require a live deadline
//! before a request is handed to the effect dispatcher. Expiry never erases an
//! admitted request; its protected record remains available for exact recovery.

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorInFlightReplayV1,
    DormantBrokerDescriptorRequestReceiveProgressV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantBrokerOutcomeUnknownV1, DormantBrokerRequestReceiveProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantBrokerTerminalReplayV1,
    DormantReceivedBrokerDescriptorRequestV1, DormantReceivedBrokerRequestV1,
};

/// Reports a fail-closed production request-receipt failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerReceiveErrorV1 {
    /// Protected request installation remained ambiguous after exact readback.
    #[error("broker request admission requires process restart and exact replay")]
    AdmissionRecovery,
    /// Protected currentness or request transport failed.
    #[error("broker request transport failed: {0}")]
    Transport(#[from] DormantBrokerSessionHandshakeErrorV1),
}

/// Retains one normalized descriptor-free production receipt.
#[must_use = "dispatch, recover, or replay the authenticated request event"]
pub enum ProductionBrokerRequestEventV1 {
    /// A new request is durably admitted and ready for method dispatch.
    Request(DormantReceivedBrokerRequestV1),
    /// The request exactly repeats an effect whose outcome remains unknown.
    InFlightReplay(DormantBrokerOutcomeUnknownV1),
    /// The request exactly repeats a protected descriptor-free terminal result.
    TerminalReplay(DormantBrokerTerminalReplayV1),
    /// The terminal result must reopen its Host-owned descriptors before resend.
    DescriptorTerminalReplay(DormantBrokerDescriptorTerminalReplayV1),
}

/// Retains one normalized Host production receipt.
#[must_use = "dispatch, recover, or replay the authenticated Host request event"]
pub enum ProductionHostBrokerRequestEventV1 {
    /// A new request and its authenticated method-selected FD table are admitted.
    Request(DormantReceivedBrokerDescriptorRequestV1),
    /// The request exactly repeats an effect whose outcome remains unknown.
    InFlightReplay(DormantBrokerDescriptorInFlightReplayV1),
    /// The request exactly repeats a protected descriptor-free terminal result.
    TerminalReplay(DormantBrokerTerminalReplayV1),
    /// The terminal result must reopen its Host-owned descriptors before resend.
    DescriptorTerminalReplay(DormantBrokerDescriptorTerminalReplayV1),
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Receives one descriptor-free production request before a boot-time deadline.
    ///
    /// Retryable socket backpressure waits on the same adopted socket. An
    /// ambiguous initial or successor admission receives one exact protected
    /// readback; continued ambiguity consumes the session and requires process
    /// restart so no later request can overtake uncertain durable state.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when transport,
    /// currentness, deadline, or exact protected readback fails.
    pub fn receive_production_request(
        mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(Self, ProductionBrokerRequestEventV1), ProductionBrokerReceiveErrorV1> {
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            let progress = self.receive_authenticated_request()?;
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            match progress {
                DormantBrokerRequestReceiveProgressV1::Pending => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        false,
                        deadline_boottime_nanoseconds,
                    )?;
                }
                DormantBrokerRequestReceiveProgressV1::Received(request) => {
                    return Ok((self, ProductionBrokerRequestEventV1::Request(request)));
                }
                DormantBrokerRequestReceiveProgressV1::InFlightReplay(custody) => {
                    return Ok((
                        self,
                        ProductionBrokerRequestEventV1::InFlightReplay(custody),
                    ));
                }
                DormantBrokerRequestReceiveProgressV1::TerminalReplay(replay) => {
                    return Ok((self, ProductionBrokerRequestEventV1::TerminalReplay(replay)));
                }
                DormantBrokerRequestReceiveProgressV1::DescriptorTerminalReplay(replay) => {
                    return Ok((
                        self,
                        ProductionBrokerRequestEventV1::DescriptorTerminalReplay(replay),
                    ));
                }
                DormantBrokerRequestReceiveProgressV1::InitializationRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered = self.recover_received_initialization(recovery, request);
                    return normalize_ordinary_recovery(
                        self,
                        recovered,
                        deadline_boottime_nanoseconds,
                    );
                }
                DormantBrokerRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered = self.recover_received_successor(recovery, request);
                    return normalize_ordinary_recovery(
                        self,
                        recovered,
                        deadline_boottime_nanoseconds,
                    );
                }
            }
        }
    }

    /// Receives one Host request and its method-selected descriptor table.
    ///
    /// The authenticated request decoder, rather than caller input or packet
    /// peeking, selects whether the exact table is empty or contains the sole
    /// catalog-publication descriptor. Durable ambiguity is read back once and
    /// otherwise fails closed as in [`Self::receive_production_request`].
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when transport,
    /// descriptor shape, currentness, deadline, or protected readback fails.
    pub fn receive_production_host_request(
        mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(Self, ProductionHostBrokerRequestEventV1), ProductionBrokerReceiveErrorV1> {
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            let progress = self.receive_authenticated_host_request()?;
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            match progress {
                DormantBrokerDescriptorRequestReceiveProgressV1::Pending => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        false,
                        deadline_boottime_nanoseconds,
                    )?;
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::Received(request) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::Request(request),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::InFlightReplay(custody) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::InFlightReplay(custody),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::TerminalReplay(replay) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::TerminalReplay(replay),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::DescriptorTerminalReplay(
                    replay,
                ) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::DescriptorTerminalReplay(replay),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::InitializationRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered =
                        self.recover_received_descriptor_initialization(recovery, request);
                    return normalize_host_recovery(self, recovered, deadline_boottime_nanoseconds);
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered = self.recover_received_descriptor_successor(recovery, request);
                    return normalize_host_recovery(self, recovered, deadline_boottime_nanoseconds);
                }
            }
        }
    }
}

fn normalize_ordinary_recovery(
    session: DormantAuthenticatedBrokerSessionV1,
    recovered: DormantBrokerRequestReceiveProgressV1,
    deadline_boottime_nanoseconds: u64,
) -> Result<
    (
        DormantAuthenticatedBrokerSessionV1,
        ProductionBrokerRequestEventV1,
    ),
    ProductionBrokerReceiveErrorV1,
> {
    crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
    match recovered {
        DormantBrokerRequestReceiveProgressV1::Received(request) => {
            Ok((session, ProductionBrokerRequestEventV1::Request(request)))
        }
        _ => Err(ProductionBrokerReceiveErrorV1::AdmissionRecovery),
    }
}

fn normalize_host_recovery(
    session: DormantAuthenticatedBrokerSessionV1,
    recovered: DormantBrokerDescriptorRequestReceiveProgressV1,
    deadline_boottime_nanoseconds: u64,
) -> Result<
    (
        DormantAuthenticatedBrokerSessionV1,
        ProductionHostBrokerRequestEventV1,
    ),
    ProductionBrokerReceiveErrorV1,
> {
    crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
    match recovered {
        DormantBrokerDescriptorRequestReceiveProgressV1::Received(request) => Ok((
            session,
            ProductionHostBrokerRequestEventV1::Request(request),
        )),
        _ => Err(ProductionBrokerReceiveErrorV1::AdmissionRecovery),
    }
}
