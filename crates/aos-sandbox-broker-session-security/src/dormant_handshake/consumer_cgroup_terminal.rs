//! Closed signed terminal custody for Host method 34.
//!
//! A Storage audience session can prepare a signed, journaled read-only
//! response and reopen its exact physical descriptor pair after restart. This
//! module deliberately has no send or descriptor-extraction API: the Storage
//! client/catalog and Controller grant join have not authorized FD egress.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerDescriptorEntry, BrokerDescriptorRole, BrokerMethod, BrokerResponseEnvelope,
};
use aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1;
use aos_sandbox_core::{ObjectDigest, ProtocolVersion};
use aos_sandbox_host::{DormantHostBrokerCallsiteV1, DormantHostBrokerObservationV1};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::host_consumer_cgroup::{
    CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1, decode_consumer_cgroup_request_v1,
    decode_consumer_cgroup_response_v1,
};
use rustix::time::{ClockId, clock_gettime};
use sha2::{Digest as _, Sha256};

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantReceivedBrokerRequestV1,
};
use crate::production_activation::verify_storage_session_peer;
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeReplayV1,
};

/// Retains a signed read-only result and the exact two Host-minted FDs.
///
/// No method exposes either FD or sends this result. A future protected
/// Storage grant join must refresh Host currentness at its send edge.
#[must_use = "retain the signed outcome and descriptor pair together"]
pub(crate) struct DormantConsumerCgroupCommittedV1 {
    committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
    request: AuthenticatedBrokerMethodRequestV1,
    response_body: Vec<u8>,
    context: ProtectedBrokerSessionVerificationContextV1,
    descriptors: Vec<OwnedFd>,
}

/// Retains ambiguous signed-commit custody without permitting a second write.
#[must_use = "recover the exact signed commit before any descriptor send"]
pub(crate) struct DormantConsumerCgroupCommitRecoveryV1 {
    recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    request: AuthenticatedBrokerMethodRequestV1,
    response_body: Vec<u8>,
    context: ProtectedBrokerSessionVerificationContextV1,
    descriptors: Vec<OwnedFd>,
}

/// Distinguishes an exact signed terminal from an ambiguous journal commit.
#[must_use = "retain or recover the exact protected outcome"]
pub(crate) enum DormantConsumerCgroupCommitV1 {
    Committed(DormantConsumerCgroupCommittedV1),
    RecoveryRequired(DormantConsumerCgroupCommitRecoveryV1),
}

/// Keeps a protected terminal replay and freshly reopened physical FDs sealed.
#[must_use = "refresh currentness before a future authorized send"]
pub(crate) struct DormantReadyConsumerCgroupReplayV1 {
    replay: ProtectedBrokerOutcomeReplayV1,
    descriptors: Vec<OwnedFd>,
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Commits one read-only Host observation under the signed Storage session.
    ///
    /// This dormant method does not send the resulting FDs. Errors before the
    /// protected commit retain the original request for exact retry.
    pub(crate) async fn commit_consumer_cgroup_terminal(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        host: &mut dyn DormantHostBrokerCallsiteV1,
    ) -> Result<
        DormantConsumerCgroupCommitV1,
        (BrokerSessionSecurityError, DormantReceivedBrokerRequestV1),
    > {
        if !valid_consumer_request(&request.0) {
            return Err((BrokerSessionSecurityError::Currentness, request));
        }
        if verify_storage_session_peer(self).is_err() {
            return Err((BrokerSessionSecurityError::Currentness, request));
        }
        let context = match self.0.reopen_broker_outcome(&request.0) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => return Err((error, request)),
        };
        let observation = match observe_host_consumer(host, &request.0, &context).await {
            Ok(observation) => observation,
            Err(_) => return Err((BrokerSessionSecurityError::Currentness, request)),
        };
        let (body, descriptors) = match checked_observation(&request.0, &context, observation) {
            Ok(checked) => checked,
            Err(error) => return Err((error, request)),
        };
        if verify_storage_session_peer(self).is_err() {
            return Err((BrokerSessionSecurityError::Currentness, request));
        }

        let envelope = BrokerResponseEnvelope {
            request_id: request.0.request_id().to_vec(),
            method: BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP.into(),
            body: body.clone(),
            descriptors: CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1
                .iter()
                .enumerate()
                .map(|(index, role)| BrokerDescriptorEntry {
                    index: index as u32,
                    role: (*role).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let pending = match self.0.prepare_broker_outcome(&request.0, envelope) {
            Ok(pending) => pending,
            Err(error) => return Err((error, request)),
        };
        Ok(match self.0.commit_broker_outcome(pending) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                DormantConsumerCgroupCommitV1::Committed(DormantConsumerCgroupCommittedV1 {
                    committed,
                    request: request.0,
                    response_body: body,
                    context,
                    descriptors,
                })
            }
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                DormantConsumerCgroupCommitV1::RecoveryRequired(
                    DormantConsumerCgroupCommitRecoveryV1 {
                        recovery,
                        request: request.0,
                        response_body: body,
                        context,
                        descriptors,
                    },
                )
            }
        })
    }

    /// Resolves only the original ambiguous signed outcome, without new Host work.
    pub(crate) fn recover_consumer_cgroup_commit(
        &mut self,
        retained: DormantConsumerCgroupCommitRecoveryV1,
    ) -> DormantConsumerCgroupCommitV1 {
        match self.0.recover_broker_outcome_commit(retained.recovery) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                DormantConsumerCgroupCommitV1::Committed(DormantConsumerCgroupCommittedV1 {
                    committed,
                    request: retained.request,
                    response_body: retained.response_body,
                    context: retained.context,
                    descriptors: retained.descriptors,
                })
            }
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                DormantConsumerCgroupCommitV1::RecoveryRequired(
                    DormantConsumerCgroupCommitRecoveryV1 {
                        recovery,
                        request: retained.request,
                        response_body: retained.response_body,
                        context: retained.context,
                        descriptors: retained.descriptors,
                    },
                )
            }
        }
    }

    /// Renews the signed outcome, exact Storage peer, and Host physical FDs.
    ///
    /// This is the mandatory pre-send cut for an initial terminal response.
    /// It remains sealed and cannot itself transmit descriptors.
    pub(crate) async fn refresh_consumer_cgroup_commit_before_send(
        &mut self,
        retained: DormantConsumerCgroupCommittedV1,
        host: &mut dyn DormantHostBrokerCallsiteV1,
    ) -> Result<DormantConsumerCgroupCommittedV1, BrokerSessionSecurityError> {
        verify_storage_session_peer(self).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let committed = self
            .0
            .revalidate_broker_committed(retained.committed)
            .map_err(|(error, _)| error)?;
        if !valid_consumer_request(&retained.request)
            || committed.method() != retained.request.method()
            || committed.request_id() != retained.request.request_id()
            || committed.signed_request_digest() != retained.request.signed_request_digest()
            || committed.response_descriptor_roles()?
                != CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1.as_slice()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let observation = observe_host_consumer(host, &retained.request, &retained.context).await?;
        let (body, descriptors) =
            checked_observation(&retained.request, &retained.context, observation)?;
        if !consumer_terminal_matches(
            committed.method(),
            retained.request.authorization().is_some(),
            committed.response_descriptor_roles()?,
            descriptors.len(),
            &retained.response_body,
            &body,
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let committed = self
            .0
            .revalidate_broker_committed(committed)
            .map_err(|(error, _)| error)?;
        verify_storage_session_peer(self).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(DormantConsumerCgroupCommittedV1 {
            committed,
            request: retained.request,
            response_body: body,
            context: retained.context,
            descriptors,
        })
    }

    /// Reopens the exact signed terminal against current Host physical state.
    ///
    /// Replays after the original request deadline fail closed. A Storage
    /// client can submit a new read-only query, but cannot replace this signed
    /// response or reuse its descriptor table.
    pub(crate) async fn reopen_consumer_cgroup_terminal(
        &mut self,
        replay: DormantBrokerDescriptorTerminalReplayV1,
        host: &mut dyn DormantHostBrokerCallsiteV1,
    ) -> Result<DormantReadyConsumerCgroupReplayV1, BrokerSessionSecurityError> {
        self.reopen_consumer_cgroup_terminal_inner(replay.0.0, host)
            .await
    }

    /// Refreshes Host and Storage peer evidence at a future FD send edge.
    ///
    /// This deliberately returns another sealed token, not sendable FDs.
    pub(crate) async fn refresh_consumer_cgroup_before_send(
        &mut self,
        retained: DormantReadyConsumerCgroupReplayV1,
        host: &mut dyn DormantHostBrokerCallsiteV1,
    ) -> Result<DormantReadyConsumerCgroupReplayV1, BrokerSessionSecurityError> {
        let DormantReadyConsumerCgroupReplayV1 {
            replay,
            descriptors: previous_descriptors,
        } = retained;
        // The old O_PATH pin prevents kernfs ID reuse until the replacement
        // has been physically checked against the signed terminal body.
        let current = self
            .reopen_consumer_cgroup_terminal_inner(replay, host)
            .await?;
        drop(previous_descriptors);
        Ok(current)
    }

    async fn reopen_consumer_cgroup_terminal_inner(
        &mut self,
        replay: ProtectedBrokerOutcomeReplayV1,
        host: &mut dyn DormantHostBrokerCallsiteV1,
    ) -> Result<DormantReadyConsumerCgroupReplayV1, BrokerSessionSecurityError> {
        verify_storage_session_peer(self).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let replay = self
            .0
            .revalidate_broker_replay(replay)
            .map_err(|(error, _)| error)?;
        let expected_body = signed_consumer_body(&replay)?;
        let observation =
            observe_host_consumer(host, replay.request(), replay.verification_context())
                .await
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let (body, descriptors) =
            checked_observation(replay.request(), replay.verification_context(), observation)?;
        if !consumer_terminal_matches(
            replay.method(),
            replay.request().authorization().is_some(),
            replay.response_descriptor_roles()?,
            descriptors.len(),
            expected_body,
            &body,
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let replay = self
            .0
            .revalidate_broker_replay(replay)
            .map_err(|(error, _)| error)?;
        verify_storage_session_peer(self).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(DormantReadyConsumerCgroupReplayV1 {
            replay,
            descriptors,
        })
    }
}

fn valid_consumer_request(request: &AuthenticatedBrokerMethodRequestV1) -> bool {
    request.method() == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
        && request.authorization().is_none()
        && request.direction() == AuthenticatedBrokerRequestDirectionV1::ServerReceive
        && request.peer_policy().audience == Audience::AUDIENCE_STORAGE_BROKER
        && request.peer_policy().uid == 0
        && request.peer_policy().gid == Some(0)
        && request.peer().uid == 0
        && request.peer().gid == 0
}

fn consumer_terminal_matches(
    method: BrokerMethod,
    has_authorization: bool,
    roles: &[BrokerDescriptorRole],
    descriptor_count: usize,
    signed_body: &[u8],
    observed_body: &[u8],
) -> bool {
    method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
        && !has_authorization
        && roles == CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1.as_slice()
        && descriptor_count == CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1.len()
        && signed_body == observed_body
}

fn signed_consumer_body(
    replay: &ProtectedBrokerOutcomeReplayV1,
) -> Result<&[u8], BrokerSessionSecurityError> {
    if !valid_consumer_request(replay.request())
        || replay.response_descriptor_roles()? != CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1.as_slice()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    match replay.outcome().result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => Ok(exact_body),
        AuthenticatedBrokerMethodResultV1::Error(_) => Err(BrokerSessionSecurityError::Currentness),
    }
}

async fn observe_host_consumer(
    host: &mut dyn DormantHostBrokerCallsiteV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<DormantHostBrokerObservationV1, BrokerSessionSecurityError> {
    let digest = ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into());
    host.consume_authenticated_consumer_cgroup(
        request.exact_body(),
        request.request_id(),
        digest,
        request.peer(),
        request.peer_policy(),
        ProtocolVersion::new(context.protocol_major(), context.protocol_minor()),
        context.boot_id(),
    )
    .await
    .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn checked_observation(
    request: &AuthenticatedBrokerMethodRequestV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    observation: DormantHostBrokerObservationV1,
) -> Result<(Vec<u8>, Vec<OwnedFd>), BrokerSessionSecurityError> {
    if !valid_consumer_request(request)
        || observation.request_id() != request.request_id()
        || observation.commitment()
            != consumer_observation_commitment(
                request.request_id(),
                request.exact_body(),
                observation.response(),
            )
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let (body, descriptors, ticket) = observation.into_response_descriptors_and_replay_ticket();
    if ticket.is_some() || descriptors.len() != CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1.len() {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let now = current_boottime().ok_or(BrokerSessionSecurityError::Currentness)?;
    if !consumer_deadline_live(request.deadline_boottime_nanoseconds(), now) {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let query = decode_consumer_cgroup_request_v1(
        request.exact_body(),
        request.peer(),
        request.peer_policy(),
        now,
    )
    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let response = decode_consumer_cgroup_response_v1(&body, &query)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    if !consumer_boot_matches(context.boot_id(), response.boot_id()) {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok((body, descriptors))
}

fn consumer_observation_commitment(
    request_id: [u8; 16],
    request_body: &[u8],
    response_body: &[u8],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-host-broker-observation-v1\0");
    digest.update((BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP as i32).to_be_bytes());
    digest.update(request_id);
    digest.update(Sha256::digest(request_body));
    digest.update(Sha256::digest(response_body));
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn current_boottime() -> Option<u64> {
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanos = u64::try_from(now.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

fn consumer_deadline_live(deadline: u64, now: u64) -> bool {
    deadline != 0 && now < deadline
}

fn consumer_boot_matches(session_boot: [u8; 16], response_boot: [u8; 16]) -> bool {
    session_boot != [0; 16] && session_boot == response_boot
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker_session_protocol::{
        BrokerSessionProtocolV1, authenticated_broker_methods_for_role_v1,
    };

    #[test]
    fn signed_terminal_owner_does_not_advertise_method_34() {
        assert!(
            authenticated_broker_methods_for_role_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_STORAGE_BROKER,
            )
            .is_empty()
        );
    }

    #[test]
    fn terminal_match_rejects_substituted_method_roles_body_and_descriptor_count() {
        let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP;
        let roles = CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1;
        assert!(consumer_terminal_matches(
            method, false, &roles, 2, b"same", b"same"
        ));
        assert!(!consumer_terminal_matches(
            method, true, &roles, 2, b"same", b"same"
        ));
        assert!(!consumer_terminal_matches(
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE,
            false,
            &roles,
            2,
            b"same",
            b"same",
        ));
        assert!(!consumer_terminal_matches(
            method, false, &roles, 1, b"same", b"same"
        ));
        assert!(!consumer_terminal_matches(
            method, false, &roles, 2, b"same", b"changed"
        ));
        let reversed = [roles[1], roles[0]];
        assert!(!consumer_terminal_matches(
            method, false, &reversed, 2, b"same", b"same"
        ));
    }

    #[test]
    fn exact_deadline_edge_is_stale_for_terminal_reopen() {
        assert!(consumer_deadline_live(101, 100));
        assert!(!consumer_deadline_live(100, 100));
        assert!(!consumer_deadline_live(99, 100));
        assert!(!consumer_deadline_live(0, 100));
    }

    #[test]
    fn substituted_or_nil_host_boot_cannot_match_signed_session() {
        assert!(consumer_boot_matches([1; 16], [1; 16]));
        assert!(!consumer_boot_matches([1; 16], [2; 16]));
        assert!(!consumer_boot_matches([0; 16], [0; 16]));
    }

    #[test]
    fn host_observation_commitment_binds_request_and_response() {
        let original = consumer_observation_commitment([1; 16], b"request", b"response");
        assert_ne!(
            original,
            consumer_observation_commitment([2; 16], b"request", b"response")
        );
        assert_ne!(
            original,
            consumer_observation_commitment([1; 16], b"altered", b"response")
        );
        assert_ne!(
            original,
            consumer_observation_commitment([1; 16], b"request", b"altered")
        );
    }
}
