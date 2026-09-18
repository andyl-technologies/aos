//! Actual independent-channel joining with protected issuance and challenge state.

#![allow(
    clippy::unwrap_used,
    reason = "Integration fixture failures intentionally panic."
)]

use super::*;
use crate::local_provisioning::tests::provision_samples;
use crate::local_sessions::{LocalSessionId, LocalSessionLimits, LocalSessionRegistry};
use crate::publisher_authority::{PublisherAuthorityError, PublisherCapabilityRegistry};

pub(crate) struct JoinFixture {
    pub(crate) registered: RegisteredFixture,
    pub(crate) holders: LocalSessionRegistry,
    pub(crate) holder: SeqpacketSocket,
    pub(crate) holder_id: LocalSessionId,
    pub(crate) request: PublisherAdmissionRequestV1,
    pub(crate) join_policy: PublisherJoinPolicy,
}

pub(crate) fn join_fixture() -> JoinFixture {
    join_fixture_with_validity(60)
}

fn join_fixture_with_validity(validity_seconds: u32) -> JoinFixture {
    let mut registered = registered_fixture();
    registered.local.config.validity_seconds = validity_seconds;
    let mut holders = LocalSessionRegistry::new(LocalSessionLimits {
        maximum_sessions: 2,
    })
    .expect("holder session table");
    let endpoint = provision_samples(
        &mut registered.local,
        &mut holders,
        vec![Ok(sample(152, 3_000)), Ok(sample(153, 4_000))],
    )
    .expect("issue actual holder channel");
    let holder_id = endpoint.session_id();
    let mut draft = challenge_draft(
        &registered,
        0x91,
        1,
        0x93,
        registered.registration.fields().principal,
    );
    draft.capability = endpoint.capability_id();
    draft.claim.holder = registered.local.scope.holder;
    draft.claim.channel = endpoint.channel_binding();
    let request = PublisherAdmissionRequestV1::new(draft).expect("holder-bound request");
    register_challenge_samples(
        &mut registered,
        &request,
        vec![Ok(sample(154, 5_000)), Ok(sample(155, 6_000))],
    )
    .expect("register publisher's exact challenge");
    let holder = SeqpacketSocket::from_owned(endpoint.into_fd()).expect("holder sender");
    let join_policy = PublisherJoinPolicy {
        control: config(&registered.local),
        authority_limits: registered.local.config.authority_limits,
    };
    JoinFixture {
        registered,
        holders,
        holder,
        holder_id,
        request,
        join_policy,
    }
}

pub(crate) fn send_holder(holder: &mut SeqpacketSocket, request: &PublisherAdmissionRequestV1) {
    let mut frame = b"AOSLHI01\0\0".to_vec();
    frame.extend(encode_publisher_admission_request_v1(request));
    holder.send(&frame).expect("send actual holder record");
}

pub(crate) fn join_now(
    fixture: &mut JoinFixture,
) -> Result<JoinedPublisherRequest<'_>, PublisherJoinError> {
    join_holder_request(
        &mut fixture.registered.local.journal,
        &mut fixture.holders,
        &mut fixture.registered.sessions,
        fixture.holder_id,
        fixture.join_policy,
        &mut || Ok(sample(156, 7_000)),
    )
}

fn assert_holder_closed(fixture: &mut JoinFixture) {
    assert!(matches!(
        fixture.holders.receive(fixture.holder_id),
        Err(crate::local_sessions::LocalSessionError::Transport(
            SeqpacketError::Closed
        ))
    ));
    assert!(matches!(
        fixture.holders.capability_id(fixture.holder_id),
        Err(crate::local_sessions::LocalSessionError::UnknownSession)
    ));
}

#[test]
fn exact_holder_join_retains_channels_without_consuming_or_changing_audit() {
    let mut fixture = join_fixture();
    send_holder(&mut fixture.holder, &fixture.request);
    // A later queued publisher request is not consumed by the liveness probe.
    fixture
        .registered
        .client
        .send(b"next record")
        .expect("queue next publisher record");
    let before: Vec<_> = fixture
        .registered
        .local
        .journal
        .records(RecordNamespace::PublisherIngress)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    let request = fixture.request.clone();
    {
        let mut joined = join_now(&mut fixture).expect("join two real independent channels");
        assert_eq!(joined.request(), &request);
        assert_eq!(joined.capability_id(), request.capability());
        joined
            .recheck(&mut || Ok(sample(157, 8_000)))
            .expect("fresh join recheck");
    }
    let after: Vec<_> = fixture
        .registered
        .local
        .journal
        .records(RecordNamespace::PublisherIngress)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    assert_eq!(
        before, after,
        "joining must not consume or refresh a challenge"
    );
    let instance = fixture.registered.registration.fields().instance;
    assert_eq!(
        fixture
            .registered
            .sessions
            .receive(instance)
            .unwrap()
            .payload(),
        b"next record"
    );
}

#[test]
fn substituted_request_and_missing_challenge_close_holder_without_admission() {
    for missing in [false, true] {
        let mut fixture = join_fixture();
        let mut draft = challenge_draft(
            &fixture.registered,
            if missing { 0x92 } else { 0x91 },
            1,
            0x94,
            fixture.registered.registration.fields().principal,
        );
        draft.capability = fixture.request.capability();
        draft.claim.channel = fixture.request.plan().fields().request.channel;
        let substituted = PublisherAdmissionRequestV1::new(draft).expect("substituted request");
        send_holder(&mut fixture.holder, &substituted);
        assert!(matches!(
            join_now(&mut fixture),
            Err(PublisherJoinError::RequestMismatch)
        ));
        assert_holder_closed(&mut fixture);
    }
}

#[test]
fn identical_principal_on_another_holder_channel_cannot_forward_possession() {
    let mut fixture = join_fixture();
    let endpoint = provision_samples(
        &mut fixture.registered.local,
        &mut fixture.holders,
        vec![Ok(sample(154, 5_000)), Ok(sample(155, 6_000))],
    )
    .expect("issue distinct holder channel");
    let original_id = fixture.holder_id;
    fixture.holder_id = endpoint.session_id();
    let mut other = SeqpacketSocket::from_owned(endpoint.into_fd()).expect("other holder");
    send_holder(&mut other, &fixture.request);
    assert!(matches!(
        join_now(&mut fixture),
        Err(PublisherJoinError::HolderMismatch)
    ));
    assert_holder_closed(&mut fixture);
    fixture.holder_id = original_id;
    send_holder(&mut fixture.holder, &fixture.request);
    assert!(
        join_now(&mut fixture).is_ok(),
        "original channel remains usable"
    );
}

#[test]
fn revoked_capability_and_stale_controller_head_deny_registered_challenges() {
    for revoke in [true, false] {
        let mut fixture = join_fixture();
        if revoke {
            PublisherCapabilityRegistry::load(
                &mut fixture.registered.local.journal,
                fixture.join_policy.authority_limits,
            )
            .unwrap()
            .revoke_from_trusted_controller([0xa1; 16], fixture.request.capability())
            .unwrap();
        } else {
            let mut policy = PublisherPolicyStore::load(
                &mut fixture.registered.local.journal,
                fixture.join_policy.control.policy_limits,
            )
            .unwrap();
            let prior = policy.controller_head().unwrap().unwrap();
            policy
                .advance_controller_from_trusted_controller(
                    [0xa2; 16],
                    Some(prior.generation),
                    PublisherControllerHeadV1 {
                        generation: prior.generation + 1,
                        ..prior
                    },
                )
                .unwrap();
        }
        send_holder(&mut fixture.holder, &fixture.request);
        let result = join_now(&mut fixture);
        if revoke {
            assert!(matches!(
                result,
                Err(PublisherJoinError::Capability(
                    PublisherAuthorityError::Revoked
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(PublisherJoinError::Control(
                    PublisherControlError::PolicyDenied
                ))
            ));
        }
        assert_holder_closed(&mut fixture);
    }
}

#[test]
fn closed_publisher_connection_cannot_be_restored_from_live_process_and_audit() {
    let mut fixture = join_fixture();
    fixture.registered.client.close();
    send_holder(&mut fixture.holder, &fixture.request);
    assert!(matches!(
        join_now(&mut fixture),
        Err(PublisherJoinError::Publisher(_))
    ));
    assert_holder_closed(&mut fixture);
    let instance = fixture.registered.registration.fields().instance;
    assert!(matches!(
        fixture.registered.sessions.receive(instance),
        Err(PublisherSessionError::Retired)
    ));
    assert!(matches!(
        fixture
            .registered
            .sessions
            .release_retired_after_exit(instance),
        Err(PublisherSessionError::ExecutionAlive)
    ));
    fixture.registered.sessions = sessions(1);
    // A new process-local registry has no live execution to reconstruct.
    assert!(matches!(
        fixture.registered.sessions.retain_execution(instance),
        Err(PublisherSessionError::UnknownSession)
    ));
}

#[test]
fn frozen_wall_expiry_and_clock_regression_permanently_poison_join() {
    for failing in [sample(157, 36_000_005_000), sample(156, 8_000)] {
        let mut fixture = join_fixture();
        send_holder(&mut fixture.holder, &fixture.request);
        {
            let mut joined = join_now(&mut fixture).expect("initial join");
            joined
                .recheck(&mut || Ok(sample(157, 8_000)))
                .expect("advance observation");
            assert!(matches!(
                joined.recheck(&mut || Ok(failing)),
                Err(PublisherJoinError::Control(PublisherControlError::Clock))
            ));
            assert!(matches!(
                joined.recheck(&mut || Ok(sample(157, 8_000))),
                Err(PublisherJoinError::Invalidated)
            ));
        }
        assert_holder_closed(&mut fixture);
    }
}

#[test]
fn shorter_capability_deadline_remains_independent_of_pending_challenge() {
    for late in [sample(162, 8_000), sample(156, 10_000_003_000)] {
        let mut fixture = join_fixture_with_validity(10);
        send_holder(&mut fixture.holder, &fixture.request);
        {
            let mut joined = join_now(&mut fixture).expect("short-lived capability join");
            assert!(matches!(
                joined.recheck(&mut || Ok(late)),
                Err(PublisherJoinError::Control(PublisherControlError::Clock))
            ));
        }
        assert_holder_closed(&mut fixture);
    }
}

#[test]
fn final_clock_check_rejects_expiry_during_validation_and_changed_provenance() {
    let baseline = sample(156, 7_000);
    let wrong_provenance = RawPairedClockSample::new_untrusted(
        aos_sandbox_core::RawClockProvenance::new_untrusted([0xdd; 16]).unwrap(),
        baseline.host_boot_id(),
        156,
        8_000,
    )
    .unwrap();
    for final_sample in [sample(190, 8_000), wrong_provenance] {
        let mut fixture = join_fixture();
        send_holder(&mut fixture.holder, &fixture.request);
        {
            let mut joined = join_now(&mut fixture).expect("initial join");
            let mut reads = VecDeque::from([baseline, final_sample]);
            assert!(matches!(
                joined.recheck(&mut || Ok(reads.pop_front().expect("two clock checks"))),
                Err(PublisherJoinError::Control(PublisherControlError::Clock))
            ));
            assert!(reads.is_empty());
        }
        assert_holder_closed(&mut fixture);
    }
}

#[test]
fn later_publisher_shutdown_poisoning_closes_holder_ingress() {
    let mut fixture = join_fixture();
    send_holder(&mut fixture.holder, &fixture.request);
    let mut joined = join_holder_request(
        &mut fixture.registered.local.journal,
        &mut fixture.holders,
        &mut fixture.registered.sessions,
        fixture.holder_id,
        fixture.join_policy,
        &mut || Ok(sample(156, 7_000)),
    )
    .expect("initial join");
    fixture.registered.client.close();
    assert!(matches!(
        joined.recheck(&mut || Ok(sample(157, 8_000))),
        Err(PublisherJoinError::Publisher(_))
    ));
    assert!(matches!(
        joined.recheck(&mut || Ok(sample(157, 8_000))),
        Err(PublisherJoinError::Invalidated)
    ));
    drop(joined);
    assert_holder_closed(&mut fixture);
}

#[test]
fn holder_shutdown_before_join_rejects_its_previously_queued_record() {
    let mut fixture = join_fixture();
    send_holder(&mut fixture.holder, &fixture.request);
    fixture.holder.close();
    assert!(matches!(
        join_now(&mut fixture),
        Err(PublisherJoinError::Holder(_))
    ));
    assert_holder_closed(&mut fixture);
}

#[test]
fn holder_shutdown_after_join_permanently_invalidates_retained_possession() {
    let mut fixture = join_fixture();
    send_holder(&mut fixture.holder, &fixture.request);
    let mut joined = join_holder_request(
        &mut fixture.registered.local.journal,
        &mut fixture.holders,
        &mut fixture.registered.sessions,
        fixture.holder_id,
        fixture.join_policy,
        &mut || Ok(sample(156, 7_000)),
    )
    .expect("initial join");
    fixture.holder.close();
    assert!(matches!(
        joined.recheck(&mut || Ok(sample(157, 8_000))),
        Err(PublisherJoinError::Holder(_))
    ));
    assert!(matches!(
        joined.recheck(&mut || Ok(sample(157, 8_000))),
        Err(PublisherJoinError::Invalidated)
    ));
    drop(joined);
    assert_holder_closed(&mut fixture);
}

#[test]
fn equal_revocation_generation_in_another_scope_does_not_match_issuance() {
    let mut fixture = join_fixture();
    let other_scope = aos_sandbox_core::RevocationScopeId::from_bytes([0xb1; 16]);
    PublisherPolicyStore::load(
        &mut fixture.registered.local.journal,
        fixture.join_policy.control.policy_limits,
    )
    .unwrap()
    .advance_revocation_from_trusted_controller(
        [0xb2; 16],
        None,
        crate::publisher_policy::PublisherRevocationHeadV1 {
            scope: other_scope,
            generation: 1,
        },
    )
    .unwrap();
    let mut draft = challenge_draft(
        &fixture.registered,
        0xb3,
        1,
        0x93,
        fixture.registered.registration.fields().principal,
    );
    draft.capability = fixture.request.capability();
    draft.claim.channel = fixture.request.plan().fields().request.channel;
    draft.authority.revocation_scope = other_scope;
    fixture.request = PublisherAdmissionRequestV1::new(draft).unwrap();
    register_challenge_samples(
        &mut fixture.registered,
        &fixture.request,
        vec![Ok(sample(154, 5_000)), Ok(sample(155, 6_000))],
    )
    .expect("pending challenge does not authenticate holder capability scope");
    send_holder(&mut fixture.holder, &fixture.request);
    assert!(matches!(
        join_now(&mut fixture),
        Err(PublisherJoinError::IssuanceMismatch)
    ));
    assert_holder_closed(&mut fixture);
}

#[test]
fn bounded_capability_replay_cannot_be_bypassed_by_live_channel_state() {
    let mut fixture = join_fixture();
    fixture.join_policy.authority_limits =
        crate::publisher_authority::PublisherAuthorityLimits::new(1, 1, 1).unwrap();
    send_holder(&mut fixture.holder, &fixture.request);
    assert!(matches!(
        join_now(&mut fixture),
        Err(PublisherJoinError::Capability(
            PublisherAuthorityError::LimitExceeded(_)
        ))
    ));
    assert_holder_closed(&mut fixture);
}
