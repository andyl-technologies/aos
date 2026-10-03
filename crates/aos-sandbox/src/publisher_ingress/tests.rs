//! Pure protected-journal replay and canonical registration regressions.

#![allow(
    clippy::unwrap_used,
    reason = "Invalid fixture state intentionally fails the test."
)]

use super::*;
use crate::JournalLimits;
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn execution() -> PublisherExecutionRegistrationV1 {
    PublisherExecutionRegistrationV1::new(PublisherExecutionDraftV1 {
        instance: PublisherInstanceId::from_bytes([1; 16]),
        principal: PrincipalId::from_bytes([2; 16]),
        node: NodeId::from_bytes([3; 16]),
        project: ProjectId::from_bytes([4; 16]),
        cache_resource: ResourceId::from_bytes([5; 16]),
        cache_domain: CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes([6; 16]),
        ),
        isolation_policy: ObjectDigest::from_bytes([7; 32]),
        channel_binding: ChannelBinding::new([8; 32]),
        boot_id: [9; 16],
        clock_provenance: [10; 16],
        registered_wall_seconds: 100,
        registered_boottime_nanoseconds: 1000,
        controller_generation: 1,
        policy_generation: 1,
        policy_digest: ObjectDigest::from_bytes([11; 32]),
        peer_pid: 123,
        peer_tgid: 123,
        peer_cgroup_id: 456,
    })
    .unwrap()
}

fn challenge(nonce: u8) -> PublisherChallengeRegistrationV1 {
    let execution = execution();
    let e = execution.fields();
    let request = PublisherAdmissionRequestV1::new(PublisherAdmissionRequestDraftV1 {
        capability: CapabilityId::from_bytes([12; 16]),
        cache_resource: e.cache_resource,
        challenge: PublisherChallengeV1::from_bytes([nonce; 32]).unwrap(),
        protocol_version: ProtocolVersion::new(1, 0),
        target: PublisherTarget {
            principal: e.principal,
            instance: e.instance,
            node: e.node,
            project: e.project,
            cache_domain: e.cache_domain,
            isolation_policy: e.isolation_policy,
        },
        claim: PublisherAdmissionClaimV1 {
            holder: PrincipalId::from_bytes([13; 16]),
            channel: ChannelBinding::new([14; 32]),
            operation: OperationId::from_bytes([15; 16]),
            reservation: PublicationReservationId::from_bytes([16; 16]),
            content: descriptor_for_bytes(
                MediaType::new(PortableMediaType::Content.as_str()).unwrap(),
                b"x",
            ),
            source_authorization: ObjectDigest::from_bytes([17; 32]),
            maximum_bytes: 1,
        },
        authority: PublisherAuthorityBindings {
            policy: e.policy_digest,
            policy_generation: 1,
            controller_generation: 1,
            revocation_scope: RevocationScopeId::from_bytes([18; 16]),
            revocation_generation: 1,
            root_registry_generation: 1,
        },
        issued_seconds: 100,
        expires_seconds: 200,
        required_features: vec![],
    })
    .unwrap();
    PublisherChallengeRegistrationV1::new(PublisherChallengeDraftV1 {
        request,
        boot_id: e.boot_id,
        clock_provenance: e.clock_provenance,
        registered_wall_seconds: 110,
        registered_boottime_nanoseconds: 2000,
        expires_wall_seconds: 150,
    })
    .unwrap()
}

fn open(path: &std::path::Path) -> Journal {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    Journal::open_protected_at_uid(
        path,
        "ingress.journal",
        JournalLimits::default(),
        fs::metadata(path).unwrap().uid(),
    )
    .unwrap()
    .0
}

#[test]
fn immutable_execution_and_idempotent_challenge_survive_replay() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = open(directory.path());
    let e = execution();
    let c = challenge(19);
    {
        let mut store =
            PublisherIngressStore::load(&mut journal, PublisherIngressLimits::default()).unwrap();
        assert_eq!(
            store.install_execution([1; 16], e.clone()).unwrap(),
            PublisherIngressWriteOutcome::Inserted
        );
        assert!(matches!(
            store.install_execution([2; 16], e.clone()),
            Err(PublisherIngressError::IdentityConflict)
        ));
        assert_eq!(
            store.register_challenge([3; 16], c.clone()).unwrap(),
            PublisherIngressWriteOutcome::Inserted
        );
        assert_eq!(
            store.register_challenge([4; 16], c.clone()).unwrap(),
            PublisherIngressWriteOutcome::AlreadyPresent
        );
        let mut changed = c.fields().clone();
        changed.expires_wall_seconds += 1;
        assert!(matches!(
            store.register_challenge(
                [5; 16],
                PublisherChallengeRegistrationV1::new(changed).unwrap()
            ),
            Err(PublisherIngressError::IdentityConflict)
        ));
    }
    journal.compact().unwrap();
    drop(journal);
    let mut journal = open(directory.path());
    let store =
        PublisherIngressStore::load(&mut journal, PublisherIngressLimits::default()).unwrap();
    assert_eq!(
        store.execution(e.fields().instance).unwrap(),
        Some(e.clone())
    );
    assert_eq!(
        store
            .challenge(e.fields().instance, c.fields().request.challenge())
            .unwrap(),
        Some(c)
    );
}

#[test]
fn lifetime_count_and_scope_limits_do_not_allow_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = open(directory.path());
    let limits = PublisherIngressLimits::new(1, 1, 1, HARD_RECORD_BYTES, 1024 * 1024).unwrap();
    let mut store = PublisherIngressStore::load(&mut journal, limits).unwrap();
    assert!(matches!(
        store.register_challenge([1; 16], challenge(19)),
        Err(PublisherIngressError::UnknownExecution)
    ));
    store.install_execution([2; 16], execution()).unwrap();
    let mut wrong = challenge(19).fields().clone();
    wrong.boot_id = [99; 16];
    assert!(matches!(
        store.register_challenge(
            [3; 16],
            PublisherChallengeRegistrationV1::new(wrong).unwrap()
        ),
        Err(PublisherIngressError::ExecutionMismatch)
    ));
    store.register_challenge([4; 16], challenge(19)).unwrap();
    assert!(matches!(
        store.register_challenge([5; 16], challenge(20)),
        Err(PublisherIngressError::LimitExceeded(_))
    ));
    assert_eq!(
        store.register_challenge([6; 16], challenge(19)).unwrap(),
        PublisherIngressWriteOutcome::AlreadyPresent
    );
}

#[test]
fn canonical_record_framing_rejects_unknown_fields_trailing_data_and_wrong_keys() {
    let e = execution();
    let c = challenge(19);
    let encoded = record::encode_execution(&e, HARD_RECORD_BYTES).unwrap();
    use sha2::Digest as _;
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(&encoded)),
        "041a1930b66797dd9088a2ea94bb6628baf975d583f0f6143d21d9320ab98107"
    );
    assert_eq!(&encoded[..8], b"AOSPEX01");
    assert_eq!(
        record::decode_execution(&encoded, HARD_RECORD_BYTES).unwrap(),
        e
    );
    let mut unknown = encoded.clone();
    unknown.pop();
    unknown.extend_from_slice(b",\"unknown\":0}");
    assert!(record::decode_execution(&unknown, HARD_RECORD_BYTES).is_err());
    let encoded = record::encode_challenge(&c, HARD_RECORD_BYTES).unwrap();
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(&encoded)),
        "7e48abe1e3c78a109592f34e314848d4d496f939a1ec8c9f83b7172ffe076524"
    );
    let mut header = b"AOSPCH01".to_vec();
    header.extend_from_slice(&[9; 16]);
    header.extend_from_slice(&[10; 16]);
    header.extend_from_slice(&110i64.to_be_bytes());
    header.extend_from_slice(&2000u64.to_be_bytes());
    header.extend_from_slice(&150i64.to_be_bytes());
    assert_eq!(&encoded[..64], header);
    assert_eq!(
        record::decode_challenge(&encoded, HARD_RECORD_BYTES).unwrap(),
        c
    );
    let mut bad = encoded.clone();
    bad.push(0);
    assert!(record::decode_challenge(&bad, HARD_RECORD_BYTES).is_err());
    let mut bad = encoded.clone();
    bad[7] = b'2';
    assert!(record::decode_challenge(&bad, HARD_RECORD_BYTES).is_err());
    assert!(record::decode_challenge(&encoded[..encoded.len() - 1], HARD_RECORD_BYTES).is_err());
    assert!(record::encode_challenge(&c, 67).is_err());
    assert!(record::parse_key(b"unknown/").is_err());
    assert!(record::parse_key(&[EXECUTION_PREFIX, &[0; 16]].concat()).is_err());
}

#[test]
fn replay_rejects_orphan_challenge_and_unprotected_storage() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = open(directory.path());
    let c = challenge(19);
    let key = record::challenge_key(
        execution().fields().instance,
        c.fields().request.challenge(),
    )
    .unwrap();
    journal
        .commit(
            &JournalTransaction::new(
                [1; 16],
                vec![JournalRecord::put(
                    RecordNamespace::PublisherIngress,
                    key,
                    record::encode_challenge(&c, HARD_RECORD_BYTES).unwrap(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        PublisherIngressStore::load(&mut journal, PublisherIngressLimits::default()),
        Err(PublisherIngressError::UnknownExecution)
    ));
    let mut plain = Journal::open(directory.path().join("plain"), JournalLimits::default())
        .unwrap()
        .0;
    assert!(matches!(
        PublisherIngressStore::load(&mut plain, PublisherIngressLimits::default()),
        Err(PublisherIngressError::Journal(
            JournalError::ProtectedBoundary
        ))
    ));
}

#[test]
fn execution_profile_and_all_challenge_scope_crosslinks_are_checked() {
    type Change = fn(&mut PublisherExecutionDraftV1);
    let invalid: &[Change] = &[
        |d| d.instance = PublisherInstanceId::from_bytes([0; 16]),
        |d| d.principal = PrincipalId::from_bytes([0; 16]),
        |d| d.node = NodeId::from_bytes([0; 16]),
        |d| d.project = ProjectId::from_bytes([0; 16]),
        |d| d.cache_resource = ResourceId::from_bytes([0; 16]),
        |d| d.channel_binding = ChannelBinding::new([0; 32]),
        |d| d.policy_generation = 0,
        |d| d.controller_generation = 0,
        |d| d.peer_pid = 0,
        |d| d.peer_tgid += 1,
        |d| d.peer_cgroup_id = 0,
        |d| d.boot_id = [0; 16],
        |d| d.clock_provenance = [0; 16],
    ];
    for change in invalid {
        let mut draft = execution().fields().clone();
        change(&mut draft);
        assert!(matches!(
            PublisherExecutionRegistrationV1::new(draft),
            Err(PublisherIngressError::InvalidFacts)
        ));
    }
    let mismatches: &[Change] = &[
        |d| d.instance = PublisherInstanceId::from_bytes([99; 16]),
        |d| d.principal = PrincipalId::from_bytes([99; 16]),
        |d| d.node = NodeId::from_bytes([99; 16]),
        |d| d.project = ProjectId::from_bytes([99; 16]),
        |d| d.cache_resource = ResourceId::from_bytes([99; 16]),
        |d| {
            d.cache_domain = CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes([99; 16]),
            )
        },
        |d| d.isolation_policy = ObjectDigest::from_bytes([99; 32]),
        |d| d.boot_id = [99; 16],
        |d| d.clock_provenance = [99; 16],
        |d| d.registered_wall_seconds = 111,
        |d| d.registered_boottime_nanoseconds = 2001,
    ];
    for change in mismatches {
        let mut draft = execution().fields().clone();
        change(&mut draft);
        assert!(matches!(
            challenge(19)
                .validate_execution(&PublisherExecutionRegistrationV1::new(draft).unwrap()),
            Err(PublisherIngressError::ExecutionMismatch)
        ));
    }
}

#[test]
fn replay_checks_byte_limits_keys_and_canonical_versions() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = open(directory.path());
    let e = execution();
    PublisherIngressStore::load(&mut journal, PublisherIngressLimits::default())
        .unwrap()
        .install_execution([1; 16], e.clone())
        .unwrap();
    let sequence = journal.snapshot_sequence();
    let bytes = record::encode_execution(&e, HARD_RECORD_BYTES).unwrap();
    let key = record::execution_key(e.fields().instance).unwrap();
    let tiny = PublisherIngressLimits::new(1, 1, 1, bytes.len() - 1, 1_000_000).unwrap();
    assert!(matches!(
        PublisherIngressStore::load(&mut journal, tiny),
        Err(PublisherIngressError::LimitExceeded("record bytes"))
    ));
    let tiny = PublisherIngressLimits::new(1, 1, 1, HARD_RECORD_BYTES, bytes.len() + key.len() - 1)
        .unwrap();
    assert!(matches!(
        PublisherIngressStore::load(&mut journal, tiny),
        Err(PublisherIngressError::LimitExceeded("materialized bytes"))
    ));
    assert_eq!(journal.snapshot_sequence(), sequence);
    let mut bad = bytes;
    bad[7] = b'2';
    journal
        .commit(
            &JournalTransaction::new(
                [2; 16],
                vec![JournalRecord::put(
                    RecordNamespace::PublisherIngress,
                    key,
                    bad,
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        PublisherIngressStore::load(&mut journal, PublisherIngressLimits::default()),
        Err(PublisherIngressError::MalformedRecord)
    ));
}
