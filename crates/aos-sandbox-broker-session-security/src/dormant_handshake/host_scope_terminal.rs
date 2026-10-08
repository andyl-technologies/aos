//! Host scope descriptor-terminal custody, finalization, replay, and transport.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorEntry, BrokerMethod, BrokerResponseEnvelope,
};
use aos_sandbox_broker_session_protocol::decode_canonical_response_v1;
use aos_sandbox_core::ProtocolVersion;
use sha2::{Digest as _, Sha256};

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantBrokerExecutionErrorV1, DormantBrokerOutcomeUnknownV1,
    DormantBrokerSessionHandshakeErrorV1, DormantBrokerTerminalReplayV1,
    DormantOutstandingBrokerRequestV1, DormantReceivedBrokerRequestV1,
};
use crate::handshake;
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
};

/// Retains a revalidated terminal replay with its exact reopened descriptor order.
#[must_use = "send or retain the exact protected replay and every reopened descriptor"]
pub struct DormantReadyBrokerDescriptorTerminalReplayV1 {
    replay: DormantBrokerTerminalReplayV1,
    descriptors: Vec<OwnedFd>,
}

/// Retains a descriptor-producing observation after its domain dispatch began.
#[must_use = "retry protected response commit or retain every descriptor"]
pub enum DormantBrokerDescriptorOutcomeUnknownV1 {
    /// No exact descriptor response was produced; only opaque request custody remains.
    Unobserved(DormantBrokerOutcomeUnknownV1),
    /// Exact response bytes and descriptor order were observed but are not committed.
    Observed {
        request: DormantReceivedBrokerRequestV1,
        body: Vec<u8>,
        descriptors: Vec<OwnedFd>,
        replay_ticket: Option<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
    },
}

/// Retains plain request and descriptor custody across a scope execution failure.
#[must_use = "retain or explicitly resolve the returned descriptor custody"]
pub enum DormantBrokerDescriptorExecutionFailureV1<Domain> {
    /// No domain adapter was invoked; the request remains eligible for an error.
    BeforeEffect {
        error: BrokerSessionSecurityError,
        request: DormantReceivedBrokerRequestV1,
    },
    /// Domain dispatch began and descriptors, if produced, remain exact and opaque.
    OutcomeUnknown {
        error: DormantBrokerExecutionErrorV1<Domain>,
        custody: DormantBrokerDescriptorOutcomeUnknownV1,
    },
}

/// Reports descriptor-response backpressure or protected terminal custody.
#[must_use = "retain the outstanding request or exact response descriptors"]
pub enum DormantBrokerDescriptorResponseProgressV1 {
    /// No response was available; retain the outstanding request.
    Pending(DormantOutstandingBrokerRequestV1),
    /// The signed response and exact descriptors entered protected custody.
    Committed(DormantBrokerDescriptorCommitResultV1),
}

/// Retains the exact signed method-34 reply and its two physical descriptors.
#[must_use = "retain or recover the signed cgroup descriptor response"]
pub enum DormantHostConsumerCgroupResponseProgressV1 {
    /// No packet arrived; the original signed request remains outstanding.
    Pending(DormantOutstandingBrokerRequestV1),
    /// The signed result and same-session FD pair passed physical readback.
    Readback(crate::ProtectedHostConsumerCgroupTransferV1),
    /// Protected outcome commit is uncertain; FD custody remains sealed.
    RecoveryRequired(DormantBrokerDescriptorCommitRecoveryV1),
    /// Host finalization is uncertain; FD custody remains sealed.
    HostFinalizationRequired(DormantHostScopeTerminalFinalizationV1),
}

/// Retains a method-45 signed packet with its exact five received descriptors.
#[must_use = "retain or recover the signed Host namespace readback"]
pub enum DormantHostMountScopeIdentityResponseProgressV1 {
    /// No packet arrived; the same signed request remains outstanding.
    Pending(DormantOutstandingBrokerRequestV1),
    /// The signed result and same-record five FDs passed physical readback.
    Readback(crate::ProtectedHostMountScopeIdentityTransferV1),
    /// Protected outcome commit is uncertain; FD custody remains sealed.
    RecoveryRequired(DormantBrokerDescriptorCommitRecoveryV1),
    /// Host finalization is uncertain; FD custody remains sealed.
    HostFinalizationRequired(DormantHostScopeTerminalFinalizationV1),
}

/// Reports protected Host descriptor reopen progress for a terminal replay.
#[must_use = "send reopened descriptors or retain replay recovery custody"]
pub enum DormantBrokerDescriptorTerminalReplayRecoveryProgressV1 {
    /// The exact signed response body and descriptor count were reopened and revalidated.
    Ready(DormantReadyBrokerDescriptorTerminalReplayV1),
    /// Domain or protected currentness failed without losing replay authority.
    RecoveryRequired {
        /// Host reopen or protected-currentness failure.
        error: DormantBrokerExecutionErrorV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
        /// Exact descriptor-bearing replay retained for another reopen attempt.
        replay: DormantBrokerDescriptorTerminalReplayV1,
    },
}

/// Reports transport progress for an exact descriptor-bearing terminal replay.
#[must_use = "retry pending transport without dropping replay or descriptor custody"]
pub enum DormantBrokerDescriptorTerminalReplaySendProgressV1 {
    /// The exact signed packet and descriptors were resent atomically.
    Sent(DormantBrokerTerminalReplayV1),
    /// No packet or descriptor was sent.
    Pending(DormantReadyBrokerDescriptorTerminalReplayV1),
    /// Transport or protected currentness became ambiguous with all custody retained.
    RecoveryRequired {
        /// Currentness or ancillary transport failure.
        error: DormantBrokerSessionHandshakeErrorV1,
        /// Exact replay and reopened descriptors retained for recovery.
        replay: DormantReadyBrokerDescriptorTerminalReplayV1,
    },
}

/// Retains a descriptor response across protected commit ambiguity.
#[must_use = "recover or send while retaining every exact descriptor"]
pub enum DormantBrokerDescriptorCommitResultV1 {
    /// The signed response is durably committed and its descriptors are sendable.
    Committed(DormantCommittedBrokerDescriptorResponseV1),
    /// The response commit is ambiguous and descriptors remain in custody.
    RecoveryRequired(DormantBrokerDescriptorCommitRecoveryV1),
    /// Terminal CAS committed, while receipt signing or Host finalization remains ambiguous.
    HostFinalizationRequired(DormantHostScopeTerminalFinalizationV1),
}

/// Retains post-CAS terminal and descriptor custody until Host receipt finalization.
#[must_use = "finalize the Host receipt before sending the descriptor response"]
pub struct DormantHostScopeTerminalFinalizationV1 {
    error: DormantBrokerExecutionErrorV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    descriptors: Vec<OwnedFd>,
    replay_ticket: Option<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
}

impl DormantHostScopeTerminalFinalizationV1 {
    /// Returns the failure observed while finalizing the protected Host receipt.
    #[must_use]
    pub const fn error(
        &self,
    ) -> &DormantBrokerExecutionErrorV1<aos_sandbox_host::DormantHostBrokerCallErrorV1> {
        &self.error
    }
}

/// Seals one committed signed descriptor response to its exact FD custody.
#[must_use = "send or retain the inseparable signed response and descriptors"]
pub struct DormantCommittedBrokerDescriptorResponseV1 {
    committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    descriptors: Vec<OwnedFd>,
    host_observed: bool,
}

/// Retains an ambiguous descriptor commit without exposing replaceable FDs.
#[must_use = "recover the inseparable protected commit and descriptor custody"]
pub struct DormantBrokerDescriptorCommitRecoveryV1 {
    error: BrokerSessionSecurityError,
    recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    descriptors: Vec<OwnedFd>,
    host_observed: bool,
    scope_replay_ticket: Option<aos_sandbox_host::DormantHostScopeReplayTicketV1>,
}

/// Retains a committed descriptor response across send ambiguity.
#[must_use = "retry with the same signed response and descriptors"]
pub struct DormantBrokerDescriptorSendRecoveryV1 {
    error: DormantBrokerSessionHandshakeErrorV1,
    response: DormantCommittedBrokerDescriptorResponseV1,
}

impl DormantCommittedBrokerDescriptorResponseV1 {
    fn seal(
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        descriptors: Vec<OwnedFd>,
        host_observed: bool,
    ) -> Self {
        Self {
            committed,
            descriptors,
            host_observed,
        }
    }
}

impl DormantBrokerDescriptorCommitRecoveryV1 {
    /// Returns the protected commit failure without exposing separable custody.
    #[must_use]
    pub const fn error(&self) -> &BrokerSessionSecurityError {
        &self.error
    }
}

impl DormantBrokerDescriptorSendRecoveryV1 {
    /// Returns the send/currentness failure without exposing separable custody.
    #[must_use]
    pub const fn error(&self) -> &DormantBrokerSessionHandshakeErrorV1 {
        &self.error
    }

    /// Consumes failed transport custody into its redacted error.
    ///
    /// This deliberately drops the inseparable committed response and
    /// descriptors. It is suitable only when the owning authenticated session
    /// is also consumed so recovery must proceed by reconnect and exact replay.
    #[must_use]
    pub fn into_error(self) -> DormantBrokerSessionHandshakeErrorV1 {
        self.error
    }
}

/// Retains committed descriptor transport across retryable backpressure.
#[must_use = "retry or retain the exact signed packet and descriptors"]
pub enum DormantBrokerDescriptorSendProgressV1 {
    /// No bytes or descriptors were sent.
    Pending(DormantCommittedBrokerDescriptorResponseV1),
    /// The exact packet and descriptor table were atomically sent.
    Sent(ProtectedBrokerOutcomeCommittedAdvancementV1),
    /// Currentness or transport failed with terminal and descriptor custody retained.
    RecoveryRequired(DormantBrokerDescriptorSendRecoveryV1),
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Produces a Host payload or mount scope before signing descriptor roles.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without exposing the
    /// descriptors when the Host scope or either currentness sandwich fails.
    pub async fn execute_host_scope_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> Result<
        DormantBrokerDescriptorCommitResultV1,
        DormantBrokerDescriptorExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        let method_matches = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1
        ) && adapter.matches_request(&request.0);
        if !method_matches {
            return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let context = match self.0.reopen_broker_outcome(&request.0) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let terminal_verifier = match self.0.broker_outcome_verifier() {
            Ok(verifier) => verifier,
            Err(error) => {
                return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        if !matches!(
            adapter.fixed_terminal_verifier_commitment(),
            Ok(commitment) if commitment == terminal_verifier.commitment()
        ) {
            return Err(DormantBrokerDescriptorExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let observation = match adapter
            .execute_scope_before_outcome(&request.0, version, context.boot_id())
            .await
        {
            Ok(observation) => observation,
            Err(error) => {
                return Err(DormantBrokerDescriptorExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error),
                    custody: DormantBrokerDescriptorOutcomeUnknownV1::Unobserved(
                        DormantBrokerOutcomeUnknownV1 {
                            request,
                            observation: None,
                        },
                    ),
                });
            }
        };
        let (body, descriptors, replay_ticket) =
            observation.into_response_descriptors_and_replay_ticket();
        let custody = DormantBrokerDescriptorOutcomeUnknownV1::Observed {
            request,
            body,
            descriptors,
            replay_ticket,
        };
        self.retry_observed_host_scope_and_commit(custody, adapter)
            .map_err(
                |custody| DormantBrokerDescriptorExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    custody,
                },
            )
    }

    /// Retries protected commit for one exact observed Host scope response.
    ///
    /// This path never re-executes the Host effect. It retains the exact body,
    /// descriptor order, and replay ticket together until the terminal CAS and
    /// Host receipt finalization take ownership of them.
    ///
    /// # Errors
    ///
    /// Returns the unchanged custody when it is unobserved, lacks its replay
    /// ticket, has an inexact descriptor table, or protected currentness and
    /// response preparation cannot be re-established.
    pub fn retry_observed_host_scope_and_commit(
        &mut self,
        custody: DormantBrokerDescriptorOutcomeUnknownV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> Result<DormantBrokerDescriptorCommitResultV1, DormantBrokerDescriptorOutcomeUnknownV1>
    {
        let DormantBrokerDescriptorOutcomeUnknownV1::Observed {
            request,
            body,
            descriptors,
            replay_ticket,
        } = custody
        else {
            return Err(custody);
        };
        let Some(replay_ticket) = replay_ticket else {
            return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                request,
                body,
                descriptors,
                replay_ticket: None,
            });
        };
        let roles = match request.0.method() {
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
                aos_sandbox_protocol::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.as_slice()
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
                aos_sandbox_protocol::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES.as_slice()
            }
            _ => {
                return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                    request,
                    body,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                });
            }
        };
        if roles.len() != descriptors.len()
            || self.0.reopen_broker_outcome(&request.0).is_err()
            || !matches!(
                (adapter.fixed_terminal_verifier_commitment(), self.0.broker_outcome_verifier()),
                (Ok(adapter_commitment), Ok(verifier))
                    if adapter_commitment == verifier.commitment()
            )
        {
            return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                request,
                body,
                descriptors,
                replay_ticket: Some(replay_ticket),
            });
        }

        let response_descriptors = roles
            .iter()
            .enumerate()
            .map(|(index, role)| {
                u32::try_from(index).map(|index| BrokerDescriptorEntry {
                    index,
                    role: (*role).into(),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, _>>();
        let Ok(response_descriptors) = response_descriptors else {
            return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                request,
                body,
                descriptors,
                replay_ticket: Some(replay_ticket),
            });
        };
        let message = BrokerResponseEnvelope {
            request_id: request.0.request_id().to_vec(),
            method: request.0.method().into(),
            body: body.clone(),
            descriptors: response_descriptors,
            ..Default::default()
        };
        let pending = match self.0.prepare_broker_outcome(&request.0, message) {
            Ok(pending) => pending,
            Err(_) => {
                return Err(DormantBrokerDescriptorOutcomeUnknownV1::Observed {
                    request,
                    body,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                });
            }
        };

        Ok(match self.0.commit_broker_outcome(pending) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => self
                .finalize_host_scope_terminal(committed, descriptors, replay_ticket, &mut adapter),
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(
                    DormantBrokerDescriptorCommitRecoveryV1 {
                        error,
                        recovery,
                        descriptors,
                        host_observed: true,
                        scope_replay_ticket: Some(replay_ticket),
                    },
                )
            }
        })
    }

    fn finalize_host_scope_terminal(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        descriptors: Vec<OwnedFd>,
        mut replay_ticket: aos_sandbox_host::DormantHostScopeReplayTicketV1,
        adapter: &mut crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> DormantBrokerDescriptorCommitResultV1 {
        let receipt = self
            .0
            .sign_terminal_commit_receipt_for_committed(&replay_ticket, &committed);
        let Ok(receipt) = receipt else {
            return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                DormantHostScopeTerminalFinalizationV1 {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    committed,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                },
            );
        };
        if let Err(error) = adapter.bind_scope_terminal(Some(&mut replay_ticket), &receipt) {
            return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                DormantHostScopeTerminalFinalizationV1 {
                    error: DormantBrokerExecutionErrorV1::Domain(error),
                    committed,
                    descriptors,
                    replay_ticket: Some(replay_ticket),
                },
            );
        }
        self.1.push(replay_ticket);
        DormantBrokerDescriptorCommitResultV1::Committed(
            DormantCommittedBrokerDescriptorResponseV1::seal(committed, descriptors, true),
        )
    }

    /// Retries post-CAS Host receipt signing and durable finalization.
    #[must_use]
    pub fn recover_host_scope_terminal_finalization(
        &mut self,
        retained: DormantHostScopeTerminalFinalizationV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> DormantBrokerDescriptorCommitResultV1 {
        let DormantHostScopeTerminalFinalizationV1 {
            committed,
            descriptors,
            replay_ticket,
            ..
        } = retained;
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                    DormantHostScopeTerminalFinalizationV1 {
                        error: DormantBrokerExecutionErrorV1::Currentness(error),
                        committed,
                        descriptors,
                        replay_ticket,
                    },
                );
            }
        };
        let Some(replay_ticket) = replay_ticket else {
            return DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                DormantHostScopeTerminalFinalizationV1 {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    committed,
                    descriptors,
                    replay_ticket: None,
                },
            );
        };
        self.finalize_host_scope_terminal(committed, descriptors, replay_ticket, &mut adapter)
    }

    /// Reopens exact Host scope descriptors for a protected terminal replay.
    #[must_use]
    pub async fn reopen_host_scope_terminal_replay(
        &mut self,
        replay: DormantBrokerDescriptorTerminalReplayV1,
        mut adapter: crate::DormantHostBrokerEffectAdapterV1<'_>,
    ) -> DormantBrokerDescriptorTerminalReplayRecoveryProgressV1 {
        let replay = match self.0.revalidate_broker_replay(replay.0.0) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        let method = replay.method();
        let method_matches = matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1
        ) && adapter.matches_request(replay.request());
        if !method_matches {
            return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                    replay,
                )),
            };
        }
        let context = replay.verification_context();
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let expected_body = match replay.outcome().result() {
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success {
                exact_body,
                ..
            } => exact_body.as_slice(),
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Error(_) => &[],
        };
        let expected_response_body_digest: [u8; 32] = Sha256::digest(expected_body).into();
        let terminal_verifier = match self.0.broker_outcome_verifier() {
            Ok(verifier) => verifier,
            Err(error) => {
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        let terminal_verifier_commitment = terminal_verifier.commitment();
        if !matches!(
            adapter.fixed_terminal_verifier_commitment(),
            Ok(commitment) if commitment == terminal_verifier_commitment
        ) {
            return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                    replay,
                )),
            };
        }
        let replay_authorization = self.1.iter().find(|ticket| {
            ticket.matches_protected_replay(
                replay.method(),
                replay.request_id(),
                replay.signed_request_digest(),
                replay.session_binding(),
                expected_response_body_digest,
                replay.signed_outcome_digest(),
                replay.protected_generation(),
                replay.protected_head(),
            )
        });
        if replay_authorization.is_none() {
            if let Ok(reservation) = adapter.locate_scope_reservation(
                replay.request(),
                expected_response_body_digest,
                terminal_verifier_commitment,
                version,
                context.boot_id(),
            ) {
                let receipt = self
                    .0
                    .sign_terminal_commit_receipt_for_replay(&reservation, &replay);
                let finalized = receipt
                    .as_ref()
                    .is_ok_and(|receipt| adapter.bind_scope_terminal(None, receipt).is_ok());
                if !finalized {
                    return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                        error: DormantBrokerExecutionErrorV1::Currentness(
                            BrokerSessionSecurityError::Currentness,
                        ),
                        replay: DormantBrokerDescriptorTerminalReplayV1(
                            DormantBrokerTerminalReplayV1(replay),
                        ),
                    };
                }
            }
        }
        let observation = match adapter
            .execute_scope_replay_before_outcome(
                replay_authorization,
                replay.request(),
                expected_response_body_digest,
                replay.signed_outcome_digest(),
                replay.protected_generation(),
                replay.protected_head(),
                terminal_verifier_commitment,
                version,
                context.boot_id(),
            )
            .await
        {
            Ok(observation) => observation,
            Err(error) => {
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Domain(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        let (body, descriptors, _) = observation.into_response_descriptors_and_replay_ticket();
        let descriptor_count_matches = replay
            .response_descriptor_roles()
            .is_ok_and(|roles| roles.len() == descriptors.len());
        if body != expected_body || !descriptor_count_matches {
            drop(descriptors);
            return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                    replay,
                )),
            };
        }
        let replay = match self.0.revalidate_broker_replay(replay) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                drop(descriptors);
                return DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    replay: DormantBrokerDescriptorTerminalReplayV1(DormantBrokerTerminalReplayV1(
                        replay,
                    )),
                };
            }
        };
        DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::Ready(
            DormantReadyBrokerDescriptorTerminalReplayV1 {
                replay: DormantBrokerTerminalReplayV1(replay),
                descriptors,
            },
        )
    }

    /// Atomically resends a protected terminal response and its reopened descriptors.
    #[must_use]
    pub fn send_authenticated_descriptor_terminal_replay(
        &mut self,
        ready: DormantReadyBrokerDescriptorTerminalReplayV1,
    ) -> DormantBrokerDescriptorTerminalReplaySendProgressV1 {
        let DormantReadyBrokerDescriptorTerminalReplayV1 {
            replay,
            descriptors,
        } = ready;
        let replay = match self.0.revalidate_broker_replay(replay.0) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                return DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                    error: error.into(),
                    replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                        replay: DormantBrokerTerminalReplayV1(replay),
                        descriptors,
                    },
                };
            }
        };
        if !replay
            .response_descriptor_roles()
            .is_ok_and(|roles| roles.len() == descriptors.len())
        {
            return DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                error: DormantBrokerSessionHandshakeErrorV1::Protected(
                    BrokerSessionSecurityError::Currentness,
                ),
                replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                    replay: DormantBrokerTerminalReplayV1(replay),
                    descriptors,
                },
            };
        }
        let send = self
            .0
            .send_response_packet_with_descriptors(replay.exact_packet(), &descriptors);
        let replay = match self.0.revalidate_broker_replay(replay) {
            Ok(replay) => replay,
            Err((error, replay)) => {
                return DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                    error: error.into(),
                    replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                        replay: DormantBrokerTerminalReplayV1(replay),
                        descriptors,
                    },
                };
            }
        };
        match send {
            Ok(()) => DormantBrokerDescriptorTerminalReplaySendProgressV1::Sent(
                DormantBrokerTerminalReplayV1(replay),
            ),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerDescriptorTerminalReplaySendProgressV1::Pending(
                    DormantReadyBrokerDescriptorTerminalReplayV1 {
                        replay: DormantBrokerTerminalReplayV1(replay),
                        descriptors,
                    },
                )
            }
            Err(error) => DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                error: error.into(),
                replay: DormantReadyBrokerDescriptorTerminalReplayV1 {
                    replay: DormantBrokerTerminalReplayV1(replay),
                    descriptors,
                },
            },
        }
    }

    /// Recovers an ambiguous descriptor-response commit without dropping FDs.
    #[must_use]
    pub fn recover_descriptor_response_commit(
        &mut self,
        retained: DormantBrokerDescriptorCommitRecoveryV1,
    ) -> DormantBrokerDescriptorCommitResultV1 {
        let DormantBrokerDescriptorCommitRecoveryV1 {
            recovery,
            descriptors,
            host_observed,
            scope_replay_ticket,
            ..
        } = retained;
        match self.0.recover_broker_outcome_commit(recovery) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) if !host_observed => {
                DormantBrokerDescriptorCommitResultV1::Committed(
                    DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                )
            }
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(
                    DormantHostScopeTerminalFinalizationV1 {
                        error: DormantBrokerExecutionErrorV1::Currentness(
                            BrokerSessionSecurityError::Currentness,
                        ),
                        committed,
                        descriptors,
                        replay_ticket: scope_replay_ticket,
                    },
                )
            }
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(
                    DormantBrokerDescriptorCommitRecoveryV1 {
                        error,
                        recovery,
                        descriptors,
                        host_observed,
                        scope_replay_ticket,
                    },
                )
            }
        }
    }

    /// Atomically sends one committed signed response and its exact descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for changed protected transport currentness or a fatal
    /// ancillary send; retryable backpressure retains packet and descriptor custody.
    pub fn send_authenticated_descriptor_response(
        &mut self,
        response: DormantCommittedBrokerDescriptorResponseV1,
    ) -> Result<DormantBrokerDescriptorSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        let DormantCommittedBrokerDescriptorResponseV1 {
            committed,
            descriptors,
            host_observed,
        } = response;
        let roles_match = committed
            .response_descriptor_roles()
            .is_ok_and(|roles| roles.len() == descriptors.len());
        if !host_observed || !roles_match {
            return Ok(DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                DormantBrokerDescriptorSendRecoveryV1 {
                    error: DormantBrokerSessionHandshakeErrorV1::Protected(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    response: DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                },
            ));
        }
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                    DormantBrokerDescriptorSendRecoveryV1 {
                        error: error.into(),
                        response: DormantCommittedBrokerDescriptorResponseV1::seal(
                            committed,
                            descriptors,
                            host_observed,
                        ),
                    },
                ));
            }
        };
        let send = self
            .0
            .send_response_packet_with_descriptors(committed.exact_packet(), &descriptors);
        let committed = match self.0.revalidate_broker_committed(committed) {
            Ok(committed) => committed,
            Err((error, committed)) => {
                return Ok(DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                    DormantBrokerDescriptorSendRecoveryV1 {
                        error: error.into(),
                        response: DormantCommittedBrokerDescriptorResponseV1::seal(
                            committed,
                            descriptors,
                            host_observed,
                        ),
                    },
                ));
            }
        };
        Ok(match send {
            Ok(()) => DormantBrokerDescriptorSendProgressV1::Sent(committed),
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                DormantBrokerDescriptorSendProgressV1::Pending(
                    DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                )
            }
            Err(error) => DormantBrokerDescriptorSendProgressV1::RecoveryRequired(
                DormantBrokerDescriptorSendRecoveryV1 {
                    error: error.into(),
                    response: DormantCommittedBrokerDescriptorResponseV1::seal(
                        committed,
                        descriptors,
                        host_observed,
                    ),
                },
            ),
        })
    }

    /// Retries descriptor transport from inseparable ambiguity custody.
    ///
    /// # Errors
    ///
    /// Returns an error only for the same protected-currentness or transport
    /// failures reported by [`Self::send_authenticated_descriptor_response`].
    pub fn retry_authenticated_descriptor_response(
        &mut self,
        retained: DormantBrokerDescriptorSendRecoveryV1,
    ) -> Result<DormantBrokerDescriptorSendProgressV1, DormantBrokerSessionHandshakeErrorV1> {
        self.send_authenticated_descriptor_response(retained.response)
    }

    /// Receives and commits one Host scope response with its exact descriptors.
    ///
    /// The expected descriptor count is derived from the authenticated method,
    /// never supplied by the caller. Durable outcome ambiguity retains every
    /// received descriptor beside the exact recovery token.
    ///
    /// # Errors
    ///
    /// Returns an error for another method, invalid response bytes, an inexact
    /// descriptor table, changed peer/session evidence, or protected failure.
    pub fn receive_authenticated_scope_response(
        &mut self,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantBrokerDescriptorResponseProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        let expected_descriptors = match outstanding.0.method() {
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
                aos_sandbox_protocol::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.len()
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
                aos_sandbox_protocol::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES.len()
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => {
                aos_sandbox_protocol::host_consumer_cgroup::CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1
                    .len()
            }
            _ => return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        };
        let maximum = usize::try_from(outstanding.0.maximum_response_bytes())
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let (packet, descriptors) = match self
            .0
            .receive_response_packet_with_descriptors(maximum, expected_descriptors)
        {
            Ok(received) => received,
            Err(handshake::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Ok(DormantBrokerDescriptorResponseProgressV1::Pending(
                    outstanding,
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let outcome = decode_canonical_response_v1(&packet)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let (gate, _) = self.0.reopen_broker_outcome(&outstanding.0)?;
        let pending = match gate.admit_outcome_with_descriptor_count(&outcome, descriptors.len())? {
            crate::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => advancement,
            crate::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
        };
        let committed = match self.0.commit_broker_outcome(pending) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                DormantBrokerDescriptorCommitResultV1::Committed(
                    DormantCommittedBrokerDescriptorResponseV1::seal(committed, descriptors, false),
                )
            }
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(
                    DormantBrokerDescriptorCommitRecoveryV1 {
                        error,
                        recovery,
                        descriptors,
                        host_observed: false,
                        scope_replay_ticket: None,
                    },
                )
            }
        };
        Ok(DormantBrokerDescriptorResponseProgressV1::Committed(
            committed,
        ))
    }

    /// Receives and checks the Storage-only Host cgroup response atomically.
    ///
    /// The method remains absent from production advertisement. This closed
    /// adapter keeps the signed terminal and exact SCM_RIGHTS pair together,
    /// then checks Host service identity and current kernel objects without
    /// exposing either descriptor or constructing a Storage grant.
    ///
    /// # Errors
    ///
    /// Rejects a different method, unavailable authenticated peer pin, invalid
    /// signed response, noncanonical descriptors, or changed physical identity.
    pub fn receive_authenticated_consumer_cgroup_response(
        &mut self,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantHostConsumerCgroupResponseProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        if outstanding.0.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let host_peer_pidfd = self.0.retain_authenticated_peer_pidfd()?;
        let progress = self.receive_authenticated_scope_response(outstanding)?;
        match progress {
            DormantBrokerDescriptorResponseProgressV1::Pending(outstanding) => Ok(
                DormantHostConsumerCgroupResponseProgressV1::Pending(outstanding),
            ),
            DormantBrokerDescriptorResponseProgressV1::Committed(
                DormantBrokerDescriptorCommitResultV1::Committed(response),
            ) => {
                let DormantCommittedBrokerDescriptorResponseV1 {
                    committed,
                    descriptors,
                    ..
                } = response;
                let (outcome, currentness) = committed.into_outcome_and_currentness();
                let readback =
                    crate::ProtectedHostConsumerCgroupTransferV1::from_authenticated_response(
                        outcome,
                        currentness,
                        descriptors,
                        host_peer_pidfd,
                    )
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                Ok(DormantHostConsumerCgroupResponseProgressV1::Readback(
                    readback,
                ))
            }
            DormantBrokerDescriptorResponseProgressV1::Committed(
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(recovery),
            ) => Ok(DormantHostConsumerCgroupResponseProgressV1::RecoveryRequired(recovery)),
            DormantBrokerDescriptorResponseProgressV1::Committed(
                DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(recovery),
            ) => {
                Ok(DormantHostConsumerCgroupResponseProgressV1::HostFinalizationRequired(recovery))
            }
        }
    }

    /// Receives method 45 with its five FDs in one authenticated session record.
    ///
    /// Production hello excludes this method. The result retains the signed
    /// terminal and physical pins but cannot authorize a Mount effect.
    ///
    /// # Errors
    ///
    /// Rejects another method, changed session/peer, malformed signed body,
    /// inexact FD roles, or mismatched current namespace identities.
    pub fn receive_authenticated_mount_scope_identity_response(
        &mut self,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantHostMountScopeIdentityResponseProgressV1, DormantBrokerSessionHandshakeErrorV1>
    {
        if outstanding.0.method()
            != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let host_peer_pidfd = self.0.retain_authenticated_peer_pidfd()?;
        let progress = self.receive_authenticated_scope_response(outstanding)?;
        match progress {
            DormantBrokerDescriptorResponseProgressV1::Pending(outstanding) => Ok(
                DormantHostMountScopeIdentityResponseProgressV1::Pending(outstanding),
            ),
            DormantBrokerDescriptorResponseProgressV1::Committed(
                DormantBrokerDescriptorCommitResultV1::Committed(response),
            ) => {
                let DormantCommittedBrokerDescriptorResponseV1 {
                    committed,
                    descriptors,
                    ..
                } = response;
                let (outcome, currentness) = committed.into_outcome_and_currentness();
                let readback =
                    crate::ProtectedHostMountScopeIdentityTransferV1::from_authenticated_response(
                        outcome,
                        currentness,
                        descriptors,
                        host_peer_pidfd,
                    )
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::KernelEvidence)?;
                Ok(DormantHostMountScopeIdentityResponseProgressV1::Readback(
                    readback,
                ))
            }
            DormantBrokerDescriptorResponseProgressV1::Committed(
                DormantBrokerDescriptorCommitResultV1::RecoveryRequired(recovery),
            ) => Ok(DormantHostMountScopeIdentityResponseProgressV1::RecoveryRequired(recovery)),
            DormantBrokerDescriptorResponseProgressV1::Committed(
                DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(recovery),
            ) => Ok(
                DormantHostMountScopeIdentityResponseProgressV1::HostFinalizationRequired(recovery),
            ),
        }
    }
}
