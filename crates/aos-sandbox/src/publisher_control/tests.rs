//! Real-kernel publisher registration through protected policy and audit state.

#![allow(
    clippy::expect_used,
    reason = "Integration fixture failures intentionally panic."
)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use aos_sandbox_core::format::encode_publisher_admission_request_v1;
use aos_sandbox_core::{
    CapabilityId, ChannelBinding, MediaType, NodeId, ObjectDigest, OperationId, PortableMediaType,
    PrincipalId, ProtocolVersion, PublicationReservationId, PublisherAdmissionClaimV1,
    PublisherAdmissionRequestDraftV1, PublisherAdmissionRequestV1, PublisherAuthorityBindings,
    PublisherChallengeV1, PublisherInstanceId, PublisherTarget, descriptor_for_bytes,
};
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError, SeqpacketSocket};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::*;
use crate::RecordNamespace;
use crate::local_provisioning::tests::{Fixture, anchor, fixture, open_journal, sample};
use crate::publisher_ingress::PublisherIngressWriteOutcome;
use crate::publisher_sessions::{PublisherSessionLimits, PublisherSessionRegistry};

fn scope(local: &Fixture) -> PublisherSessionScope {
    PublisherSessionScope {
        principal: local.scope.holder,
        node: NodeId::from_bytes([0x33; 16]),
        project: local.scope.project,
        cache_resource: local.scope.cache_resource,
    }
}

fn config(local: &Fixture) -> PublisherControlPolicy {
    PublisherControlPolicy {
        clock_provenance: local.config.clock_provenance,
        maximum_challenge_seconds: 60,
        policy_limits: local.config.policy_limits,
        ingress_limits: PublisherIngressLimits::default(),
    }
}

fn sessions(maximum_sessions: usize) -> PublisherSessionRegistry {
    PublisherSessionRegistry::new(PublisherSessionLimits { maximum_sessions })
        .expect("publisher session table")
}

struct ListenerFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    listener: RecordSubjectListener,
}

impl ListenerFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("socket directory");
        let path = directory.path().join("publisher-control.sock");
        let listener = RecordSubjectListener::bind(&path, 8).expect("publisher listener");
        Self {
            _directory: directory,
            path,
            listener,
        }
    }

    fn connect(&self) -> SeqpacketSocket {
        connect_sender(&self.path)
    }
}

fn connect_sender(path: &Path) -> SeqpacketSocket {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("publisher client socket");
    connect(
        &socket,
        &SocketAddrUnix::new(path).expect("publisher socket address"),
    )
    .expect("connect publisher client");
    let mut socket = SeqpacketSocket::from_owned(socket).expect("publisher client transport");
    socket
        .enable_record_subjects()
        .expect("client record subjects");
    socket
}

fn register_samples(
    local: &mut Fixture,
    sessions: &mut PublisherSessionRegistry,
    listener: &mut RecordSubjectListener,
    scope: PublisherSessionScope,
    observations: Vec<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
) -> Result<PublisherExecutionRegistrationV1, PublisherControlError> {
    let mut observations = VecDeque::from(observations);
    let config = config(local);
    register(
        &mut local.journal,
        sessions,
        listener,
        scope,
        anchor(),
        config,
        &mut || {
            observations
                .pop_front()
                .expect("unexpected extra clock observation")
        },
    )
}

fn only_execution_instance(journal: &Journal) -> PublisherInstanceId {
    let keys: Vec<_> = journal
        .records(RecordNamespace::PublisherIngress)
        .map(|(key, _)| key.to_vec())
        .collect();
    assert_eq!(keys.len(), 1, "expected one durable execution audit");
    let suffix = keys[0]
        .strip_prefix(b"execution/")
        .expect("execution record family");
    PublisherInstanceId::from_bytes(suffix.try_into().expect("instance key width"))
}

struct RegisteredFixture {
    local: Fixture,
    sessions: PublisherSessionRegistry,
    _transport: ListenerFixture,
    client: SeqpacketSocket,
    registration: PublisherExecutionRegistrationV1,
}

fn registered_fixture() -> RegisteredFixture {
    let mut local = fixture(true, true);
    let execution_scope = scope(&local);
    let mut sessions = sessions(1);
    let mut transport = ListenerFixture::new();
    let mut client = transport.connect();
    let registration = register_samples(
        &mut local,
        &mut sessions,
        &mut transport.listener,
        execution_scope,
        vec![Ok(sample(150, 1_000)), Ok(sample(151, 2_000))],
    )
    .expect("register challenge-test execution");
    client.receive(24).expect("consume execution greeting");
    RegisteredFixture {
        local,
        sessions,
        _transport: transport,
        client,
        registration,
    }
}

fn challenge_draft(
    registered: &RegisteredFixture,
    challenge: u8,
    holder: u8,
    operation: u8,
    target_principal: PrincipalId,
) -> PublisherAdmissionRequestDraftV1 {
    let facts = registered.registration.fields();
    PublisherAdmissionRequestDraftV1 {
        capability: CapabilityId::from_bytes([0x70; 16]),
        cache_resource: facts.cache_resource,
        challenge: PublisherChallengeV1::from_bytes([challenge; 32]).expect("nonzero challenge"),
        protocol_version: ProtocolVersion::new(1, 0),
        target: PublisherTarget {
            principal: target_principal,
            instance: facts.instance,
            node: facts.node,
            project: facts.project,
            cache_domain: facts.cache_domain,
            isolation_policy: facts.isolation_policy,
        },
        claim: PublisherAdmissionClaimV1 {
            holder: PrincipalId::from_bytes([holder; 16]),
            channel: ChannelBinding::new([0x72; 32]),
            operation: OperationId::from_bytes([operation; 16]),
            reservation: PublicationReservationId::from_bytes([0x74; 16]),
            content: descriptor_for_bytes(
                MediaType::new(PortableMediaType::Content.as_str()).expect("content media type"),
                b"publisher bytes",
            ),
            source_authorization: ObjectDigest::from_bytes([0x75; 32]),
            maximum_bytes: 1024,
        },
        authority: PublisherAuthorityBindings {
            policy: facts.policy_digest,
            policy_generation: facts.policy_generation,
            controller_generation: facts.controller_generation,
            revocation_scope: registered.local.config.revocation_scope,
            revocation_generation: 1,
            root_registry_generation: 1,
        },
        issued_seconds: 100,
        expires_seconds: 190,
        required_features: Vec::new(),
    }
}

fn challenge_request(
    registered: &RegisteredFixture,
    challenge: u8,
    holder: u8,
    operation: u8,
    target_principal: PrincipalId,
) -> PublisherAdmissionRequestV1 {
    PublisherAdmissionRequestV1::new(challenge_draft(
        registered,
        challenge,
        holder,
        operation,
        target_principal,
    ))
    .expect("publisher request")
}

fn register_challenge_samples(
    registered: &mut RegisteredFixture,
    request: &PublisherAdmissionRequestV1,
    observations: Vec<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
) -> Result<PendingPublisherChallengeReceipt, PublisherControlError> {
    let bytes = encode_publisher_admission_request_v1(request);
    registered
        .client
        .send(&bytes)
        .expect("send publisher challenge");
    let mut observations = VecDeque::from(observations);
    let config = config(&registered.local);
    register_challenge(
        &mut registered.local.journal,
        &mut registered.sessions,
        registered.registration.fields().instance,
        config,
        &mut || {
            observations
                .pop_front()
                .expect("unexpected extra challenge clock observation")
        },
    )
}

#[test]
fn registration_sends_only_postcommit_greeting_and_replays_durable_facts() {
    let mut local = fixture(true, true);
    let expected_scope = scope(&local);
    let control = config(&local);
    let mut sessions = sessions(1);
    let mut transport = ListenerFixture::new();
    let mut client = transport.connect();

    let registration = register_samples(
        &mut local,
        &mut sessions,
        &mut transport.listener,
        expected_scope,
        vec![Ok(sample(150, 1_000)), Ok(sample(151, 2_000))],
    )
    .expect("register publisher execution");
    let instance = registration.fields().instance;
    let greeting = client.receive(24).expect("registration greeting");
    assert_eq!(greeting.payload().len(), 24);
    assert_eq!(&greeting.payload()[..8], b"AOSPUBI1");
    assert_eq!(&greeting.payload()[8..], instance.as_bytes());

    let facts = registration.fields();
    assert_eq!(facts.principal, expected_scope.principal);
    assert_eq!(facts.node, expected_scope.node);
    assert_eq!(facts.project, expected_scope.project);
    assert_eq!(facts.cache_resource, expected_scope.cache_resource);
    assert_eq!(facts.policy_digest, local.policy.descriptor().digest());
    assert_eq!(facts.registered_wall_seconds, 150);
    assert_eq!(facts.registered_boottime_nanoseconds, 1_000);
    assert_eq!(facts.peer_pid, std::process::id());
    assert_eq!(facts.peer_tgid, std::process::id());

    let journal_path = local.directory.path().to_path_buf();
    drop(local.journal);
    let mut replay = open_journal(&journal_path);
    let store = PublisherIngressStore::load(&mut replay, control.ingress_limits)
        .expect("replay publisher ingress");
    assert_eq!(
        store.execution(instance).expect("read execution"),
        Some(registration)
    );
}

#[test]
fn missing_or_nonpublishing_policy_denies_before_audit_and_releases_slot() {
    for (install_policy, allow_publish) in [(false, true), (true, false)] {
        let mut local = fixture(install_policy, allow_publish);
        let expected_scope = scope(&local);
        let mut sessions = sessions(1);
        let mut transport = ListenerFixture::new();
        let mut first_client = transport.connect();

        assert!(matches!(
            register_samples(
                &mut local,
                &mut sessions,
                &mut transport.listener,
                expected_scope,
                vec![Ok(sample(150, 1_000))],
            ),
            Err(PublisherControlError::PolicyDenied)
        ));
        assert_eq!(
            local
                .journal
                .records(RecordNamespace::PublisherIngress)
                .count(),
            0
        );
        assert!(first_client.send(b"closed after denial").is_err());

        let _second_client = transport.connect();
        assert!(matches!(
            register_samples(
                &mut local,
                &mut sessions,
                &mut transport.listener,
                expected_scope,
                vec![Ok(sample(150, 2_000))],
            ),
            Err(PublisherControlError::PolicyDenied)
        ));
    }
}

#[test]
fn active_registration_reserves_capacity_before_accepting_another_peer() {
    let mut local = fixture(true, true);
    let first_scope = scope(&local);
    let mut sessions = sessions(1);
    let mut transport = ListenerFixture::new();
    let _first_client = transport.connect();
    register_samples(
        &mut local,
        &mut sessions,
        &mut transport.listener,
        first_scope,
        vec![Ok(sample(150, 1_000)), Ok(sample(151, 2_000))],
    )
    .expect("first registration");

    let second_scope = PublisherSessionScope {
        principal: PrincipalId::from_bytes([0x44; 16]),
        node: NodeId::from_bytes([0x55; 16]),
        ..first_scope
    };
    let _second_client = transport.connect();
    assert!(matches!(
        register_samples(
            &mut local,
            &mut sessions,
            &mut transport.listener,
            second_scope,
            Vec::new(),
        ),
        Err(PublisherControlError::Session(
            PublisherSessionError::Capacity
        ))
    ));
    assert!(
        transport.listener.accept().is_ok(),
        "capacity rejection must happen before accepting the queued peer"
    );
}

#[test]
fn postcommit_clock_failure_retains_audit_and_retires_execution_slot() {
    let mut local = fixture(true, true);
    let first_scope = scope(&local);
    let control = config(&local);
    let mut sessions = sessions(1);
    let mut transport = ListenerFixture::new();
    let mut client = transport.connect();

    assert!(matches!(
        register_samples(
            &mut local,
            &mut sessions,
            &mut transport.listener,
            first_scope,
            vec![Ok(sample(199, 1_000)), Ok(sample(199, 1_000_001_000)),],
        ),
        Err(PublisherControlError::Clock)
    ));
    let instance = only_execution_instance(&local.journal);
    assert!(
        PublisherIngressStore::load(&mut local.journal, control.ingress_limits)
            .expect("replay retained audit")
            .execution(instance)
            .expect("read retained execution")
            .is_some()
    );
    assert!(matches!(
        sessions.receive(instance),
        Err(PublisherSessionError::Retired)
    ));
    assert!(client.send(b"no greeting escaped").is_err());

    let second_scope = PublisherSessionScope {
        principal: PrincipalId::from_bytes([0x44; 16]),
        node: NodeId::from_bytes([0x55; 16]),
        ..first_scope
    };
    let _second_client = transport.connect();
    assert!(matches!(
        register_samples(
            &mut local,
            &mut sessions,
            &mut transport.listener,
            second_scope,
            Vec::new(),
        ),
        Err(PublisherControlError::Session(
            PublisherSessionError::Capacity
        ))
    ));
}

#[test]
fn challenge_registration_replays_exact_timestamps_and_rejects_reuse_or_stale_heads() {
    let mut registered = registered_fixture();
    let instance = registered.registration.fields().instance;
    let principal = registered.registration.fields().principal;
    let request = challenge_request(&registered, 0x80, 0x71, 0x73, principal);

    let inserted = register_challenge_samples(
        &mut registered,
        &request,
        vec![Ok(sample(152, 3_000)), Ok(sample(153, 4_000))],
    )
    .expect("register fresh challenge");
    assert_eq!(inserted.outcome, PublisherIngressWriteOutcome::Inserted);
    assert_eq!(inserted.registration.fields().registered_wall_seconds, 152);
    assert_eq!(
        inserted
            .registration
            .fields()
            .registered_boottime_nanoseconds,
        3_000
    );
    assert_eq!(inserted.registration.fields().expires_wall_seconds, 190);

    let replayed = register_challenge_samples(
        &mut registered,
        &request,
        vec![Ok(sample(154, 5_000)), Ok(sample(155, 6_000))],
    )
    .expect("replay exact challenge");
    assert_eq!(
        replayed.outcome,
        PublisherIngressWriteOutcome::AlreadyPresent
    );
    assert_eq!(replayed.registration, inserted.registration);
    let ingress_limits = config(&registered.local).ingress_limits;
    assert_eq!(
        PublisherIngressStore::load(&mut registered.local.journal, ingress_limits,)
            .expect("replay challenge audit")
            .challenge(instance, request.challenge())
            .expect("read challenge audit"),
        Some(inserted.registration)
    );

    let changed = challenge_request(&registered, 0x80, 0x79, 0x73, principal);
    assert!(matches!(
        register_challenge_samples(&mut registered, &changed, vec![Ok(sample(156, 7_000))],),
        Err(PublisherControlError::Ingress(
            PublisherIngressError::IdentityConflict
        ))
    ));
    assert!(matches!(
        registered.sessions.receive(instance),
        Err(PublisherSessionError::Transport(SeqpacketError::WouldBlock))
    ));

    for (challenge, mut draft) in [
        (
            0x81_u8,
            challenge_draft(&registered, 0x81, 0x71, 0x73, principal),
        ),
        (
            0x82_u8,
            challenge_draft(&registered, 0x82, 0x71, 0x73, principal),
        ),
        (
            0x83_u8,
            challenge_draft(&registered, 0x83, 0x71, 0x73, principal),
        ),
        (
            0x84_u8,
            challenge_draft(&registered, 0x84, 0x71, 0x73, principal),
        ),
    ] {
        match challenge {
            0x81 => draft.authority.policy = ObjectDigest::from_bytes([0x91; 32]),
            0x82 => draft.authority.policy_generation += 1,
            0x83 => draft.authority.controller_generation += 1,
            0x84 => draft.authority.revocation_generation += 1,
            _ => unreachable!("closed stale-head fixture set"),
        }
        let request = PublisherAdmissionRequestV1::new(draft).expect("stale-head request");
        assert!(matches!(
            register_challenge_samples(
                &mut registered,
                &request,
                vec![Ok(sample(160, u64::from(challenge) * 1_000))],
            ),
            Err(PublisherControlError::PolicyDenied)
        ));
        assert!(matches!(
            registered.sessions.receive(instance),
            Err(PublisherSessionError::Transport(SeqpacketError::WouldBlock))
        ));
    }

    assert!(matches!(
        register_challenge_samples(&mut registered, &request, vec![Ok(sample(190, 1_000_000))],),
        Err(PublisherControlError::Clock)
    ));
    assert!(matches!(
        registered.sessions.receive(instance),
        Err(PublisherSessionError::Transport(SeqpacketError::WouldBlock))
    ));
}

#[test]
fn postcommit_challenge_deadline_failure_keeps_inert_audit_and_active_execution() {
    // Exercise both the request deadline and the earlier protected-policy
    // deadline when the publisher proposes a longer interval.
    for (request_expiry, observed_wall) in [(190, 189), (210, 199)] {
        let mut registered = registered_fixture();
        let instance = registered.registration.fields().instance;
        let principal = registered.registration.fields().principal;
        let mut draft = challenge_draft(&registered, 0x85, 0x71, 0x73, principal);
        draft.expires_seconds = request_expiry;
        let request = PublisherAdmissionRequestV1::new(draft).expect("deadline request");

        assert!(matches!(
            register_challenge_samples(
                &mut registered,
                &request,
                vec![
                    Ok(sample(observed_wall, 10_000)),
                    Ok(sample(observed_wall, 1_000_010_000))
                ],
            ),
            Err(PublisherControlError::Clock)
        ));
        let ingress_limits = config(&registered.local).ingress_limits;
        let registration =
            PublisherIngressStore::load(&mut registered.local.journal, ingress_limits)
                .expect("replay postcommit challenge")
                .challenge(instance, request.challenge())
                .expect("read postcommit challenge")
                .expect("retained inert challenge");
        assert_eq!(
            registration.fields().expires_wall_seconds,
            observed_wall + 1
        );
        assert!(matches!(
            registered.sessions.receive(instance),
            Err(PublisherSessionError::Transport(SeqpacketError::WouldBlock))
        ));
    }
}

#[test]
fn forged_target_and_malformed_transport_retire_the_execution() {
    let mut forged = registered_fixture();
    let instance = forged.registration.fields().instance;
    let request = challenge_request(
        &forged,
        0x86,
        0x71,
        0x73,
        PrincipalId::from_bytes([0x99; 16]),
    );
    assert!(matches!(
        register_challenge_samples(&mut forged, &request, vec![Ok(sample(152, 3_000))],),
        Err(PublisherControlError::Ingress(
            PublisherIngressError::ExecutionMismatch
        ))
    ));
    assert!(matches!(
        forged.sessions.receive(instance),
        Err(PublisherSessionError::Retired)
    ));

    let mut malformed = registered_fixture();
    let instance = malformed.registration.fields().instance;
    malformed
        .client
        .send(&[0xff])
        .expect("send malformed request");
    let control = config(&malformed.local);
    assert!(matches!(
        register_challenge(
            &mut malformed.local.journal,
            &mut malformed.sessions,
            instance,
            control,
            &mut || panic!("malformed request must fail before clock observation"),
        ),
        Err(PublisherControlError::Request(_))
    ));
    assert!(matches!(
        malformed.sessions.receive(instance),
        Err(PublisherSessionError::Retired)
    ));
}
