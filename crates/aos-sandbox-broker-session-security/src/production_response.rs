//! Bounded production completion for committed responses and exact replays.
//!
//! Every completion method consumes the authenticated session. Success returns
//! that same session for the next request. Failure drops the socket and all
//! in-memory custody, forcing reconnect/replay against the protected journal
//! instead of allowing a caller to continue after ambiguous transport.

use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorCommitResultV1,
    DormantBrokerDescriptorSendProgressV1, DormantBrokerDescriptorTerminalReplayRecoveryProgressV1,
    DormantBrokerDescriptorTerminalReplaySendProgressV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1,
    DormantBrokerTerminalReplaySendProgressV1, DormantBrokerTerminalReplayV1,
    DormantHostBrokerEffectAdapterV1, ProtectedBrokerOutcomeCommitResultV1,
};

/// Reports a fail-closed production response completion failure.
///
/// The associated completion method consumes and closes the authenticated
/// session on every error. A client may reconnect and replay its exact request;
/// the protected journal remains the sole recovery authority.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerResponseErrorV1 {
    /// A protected outcome commit remained ambiguous after exact readback.
    #[error("broker response commit requires process restart and exact replay")]
    CommitRecovery,
    /// Host descriptor receipt finalization remained ambiguous.
    #[error("Host descriptor response finalization requires exact replay")]
    HostFinalization,
    /// A protected Host descriptor replay could not be reopened exactly.
    #[error("Host descriptor terminal replay could not be reopened")]
    DescriptorReplay,
    /// Protected currentness or transport failed while sending a response.
    #[error("broker response transport failed: {0}")]
    Transport(#[from] DormantBrokerSessionHandshakeErrorV1),
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Completes protected readback and atomically sends an ordinary response.
    ///
    /// Backpressure is retried only with the identical committed packet and is
    /// bounded by `deadline_boottime_nanoseconds`. Any ambiguous commit,
    /// currentness failure, or fatal transport consumes the session so a caller
    /// cannot dispatch another request on uncertain state.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when exact commit readback
    /// remains ambiguous, transport currentness fails, or the boot-time
    /// deadline expires.
    pub fn finish_authenticated_response(
        mut self,
        committed: ProtectedBrokerOutcomeCommitResultV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let committed = match committed {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => committed,
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                match self.recover_broker_outcome_commit(recovery) {
                    ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => committed,
                    ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. } => {
                        return Err(ProductionBrokerResponseErrorV1::CommitRecovery);
                    }
                }
            }
        };

        let mut pending = committed;
        loop {
            match self.send_authenticated_response(pending)? {
                DormantBrokerResponseSendProgressV1::Sent(_) => return Ok(self),
                DormantBrokerResponseSendProgressV1::Pending(retained) => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        true,
                        deadline_boottime_nanoseconds,
                    )?;
                    pending = retained;
                }
                DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. } => {
                    return Err(error.into());
                }
            }
        }
    }

    /// Completes and sends one Host scope response with exact descriptors.
    ///
    /// The sealed Host callsite is used only when the terminal CAS committed
    /// but its Host receipt still needs finalization. Backpressure retains the
    /// committed packet and descriptor order exactly.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session for unresolved commit or
    /// Host receipt ambiguity, protected-currentness failure, fatal ancillary
    /// transport, or an expired boot-time deadline.
    pub fn finish_host_descriptor_response(
        mut self,
        committed: DormantBrokerDescriptorCommitResultV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let committed = match committed {
            DormantBrokerDescriptorCommitResultV1::Committed(committed) => committed,
            DormantBrokerDescriptorCommitResultV1::RecoveryRequired(recovery) => {
                match self.recover_descriptor_response_commit(recovery) {
                    DormantBrokerDescriptorCommitResultV1::Committed(committed) => committed,
                    DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(retained) => {
                        match self.recover_host_scope_terminal_finalization(
                            retained,
                            DormantHostBrokerEffectAdapterV1::new(host, artifacts),
                        ) {
                            DormantBrokerDescriptorCommitResultV1::Committed(committed) => {
                                committed
                            }
                            _ => return Err(ProductionBrokerResponseErrorV1::HostFinalization),
                        }
                    }
                    DormantBrokerDescriptorCommitResultV1::RecoveryRequired(_) => {
                        return Err(ProductionBrokerResponseErrorV1::CommitRecovery);
                    }
                }
            }
            DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(retained) => match self
                .recover_host_scope_terminal_finalization(
                    retained,
                    DormantHostBrokerEffectAdapterV1::new(host, artifacts),
                ) {
                DormantBrokerDescriptorCommitResultV1::Committed(committed) => committed,
                _ => return Err(ProductionBrokerResponseErrorV1::HostFinalization),
            },
        };

        let mut pending = committed;
        loop {
            match self.send_authenticated_descriptor_response(pending)? {
                DormantBrokerDescriptorSendProgressV1::Sent(_) => return Ok(self),
                DormantBrokerDescriptorSendProgressV1::Pending(retained) => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        true,
                        deadline_boottime_nanoseconds,
                    )?;
                    pending = retained;
                }
                DormantBrokerDescriptorSendProgressV1::RecoveryRequired(retained) => {
                    return Err(retained.into_error().into());
                }
            }
        }
    }

    /// Resends one descriptor-free protected terminal response byte-for-byte.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session for descriptor-bearing
    /// replay, changed currentness, fatal transport, or deadline expiry.
    pub fn finish_authenticated_terminal_replay(
        mut self,
        replay: DormantBrokerTerminalReplayV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let mut pending = replay;
        loop {
            match self.send_authenticated_terminal_replay(pending)? {
                DormantBrokerTerminalReplaySendProgressV1::Sent(_) => return Ok(self),
                DormantBrokerTerminalReplaySendProgressV1::Pending(retained) => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        true,
                        deadline_boottime_nanoseconds,
                    )?;
                    pending = retained;
                }
                DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired { error, .. } => {
                    return Err(error.into());
                }
                DormantBrokerTerminalReplaySendProgressV1::DescriptorRecoveryRequired(_) => {
                    return Err(ProductionBrokerResponseErrorV1::DescriptorReplay);
                }
            }
        }
    }

    /// Reopens and resends one Host descriptor terminal replay exactly.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when Host readback cannot
    /// reproduce the exact terminal body and descriptor roles, protected
    /// currentness fails, transport is fatal, or the deadline expires.
    pub async fn finish_host_descriptor_terminal_replay(
        mut self,
        replay: DormantBrokerDescriptorTerminalReplayV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let ready = match self
            .reopen_host_scope_terminal_replay(
                replay,
                DormantHostBrokerEffectAdapterV1::new(host, artifacts),
            )
            .await
        {
            DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::Ready(ready) => ready,
            DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                ..
            } => return Err(ProductionBrokerResponseErrorV1::DescriptorReplay),
        };

        let mut pending = ready;
        loop {
            match self.send_authenticated_descriptor_terminal_replay(pending) {
                DormantBrokerDescriptorTerminalReplaySendProgressV1::Sent(_) => return Ok(self),
                DormantBrokerDescriptorTerminalReplaySendProgressV1::Pending(retained) => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        true,
                        deadline_boottime_nanoseconds,
                    )?;
                    pending = retained;
                }
                DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                    error,
                    ..
                } => return Err(error.into()),
            }
        }
    }
}
