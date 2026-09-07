//! Protected issuance and real local-ingress integration without an external RPC claim.
//!
//! The existing protected-directory test helper bypasses ancestor-policy setup
//! only; journal ownership, exclusive locking, record validation and durable
//! writes remain real. Cgroups are opened read-only and never created or changed.

#![allow(
    clippy::expect_used,
    reason = "Integration fixture failures intentionally panic."
)]

use std::collections::VecDeque;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox_core::format::encode_policy;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, CacheDomainId, CapabilityId, DecodeLimits, IncarnationId, ObjectDigest,
    PrincipalId, ProjectId, RawClockProvenance, ResourceId, SandboxId,
};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

use super::*;
use crate::local_sessions::{LocalSessionId, LocalSessionLimits};
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherResourceBindingV1,
    PublisherRevocationHeadV1,
};
use crate::{JournalLimits, RecordNamespace};

const PROVENANCE: [u8; 16] = [0x22; 16];
const CONTROLLER: [u8; 16] = [0x66; 16];

pub(crate) struct Fixture {
    pub(crate) journal: Journal,
    pub(crate) directory: tempfile::TempDir,
    pub(crate) scope: LocalSessionScope,
    pub(crate) config: LocalProvisioningPolicy,
    pub(crate) policy: PreparedPublisherPolicyRevisionV1,
}

pub(crate) fn open_journal(directory: &Path) -> Journal {
    let uid = fs::metadata(directory)
        .expect("test directory metadata")
        .uid();
    Journal::open_protected_at_uid(directory, "issuance.journal", JournalLimits::default(), uid)
        .expect("protected test journal")
        .0
}

pub(crate) fn fixture(install_policy: bool, allow_publish: bool) -> Fixture {
    let directory = tempfile::tempdir().expect("test directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut journal = open_journal(directory.path());
    let scope = LocalSessionScope {
        holder: PrincipalId::from_bytes([1; 16]),
        project: ProjectId::from_bytes([2; 16]),
        sandbox: SandboxId::from_bytes([3; 16]),
        incarnation: IncarnationId::from_bytes([4; 16]),
        epoch: AssignmentEpoch::new(7),
        cache_resource: ResourceId::from_bytes([5; 16]),
    };
    let config = LocalProvisioningPolicy {
        validity_seconds: 60,
        revocation_scope: RevocationScopeId::from_bytes([6; 16]),
        clock_provenance: PROVENANCE,
        authority_limits: PublisherAuthorityLimits::default(),
        policy_limits: PublisherPolicyLimits::default(),
    };
    let domain = CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([7; 16]));
    let grants = if allow_publish {
        vec![
            Grant::new(
                GrantId::from_bytes([8; 16]),
                ResourceKind::CachePublish,
                OperationSet::one(Operation::Publish),
                Selector::Resource {
                    resource: scope.cache_resource,
                },
                false,
            )
            .expect("policy grant"),
        ]
    } else {
        Vec::new()
    };
    let policy = Policy::new(
        Vec::new(),
        Vec::new(),
        grants,
        Vec::new(),
        ResourceProfile::new(Vec::new()).expect("resource profile"),
        Vec::new(),
        domain,
        RevocationPolicy::new(RevocationMode::DenyNew, 0),
        None,
        Vec::new(),
    )
    .expect("policy");
    let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        scope.project,
        1,
        100,
        200,
        &encode_policy(&policy),
        DecodeLimits::default(),
    )
    .expect("prepared policy");
    {
        let mut store =
            PublisherPolicyStore::load(&mut journal, config.policy_limits).expect("policy store");
        store
            .install_resource_from_trusted_controller(
                [0x11; 16],
                &PublisherResourceBindingV1::new(
                    scope.cache_resource,
                    scope.project,
                    domain,
                    ObjectDigest::from_bytes([9; 32]),
                )
                .expect("resource binding"),
            )
            .expect("install resource");
        if install_policy {
            store
                .publish_policy_from_trusted_controller([0x12; 16], None, &policy)
                .expect("install policy");
        }
        store
            .advance_controller_from_trusted_controller(
                [0x13; 16],
                None,
                PublisherControllerHeadV1 {
                    principal: PrincipalId::from_bytes(CONTROLLER),
                    generation: 1,
                },
            )
            .expect("controller head");
        store
            .advance_revocation_from_trusted_controller(
                [0x14; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope: config.revocation_scope,
                    generation: 1,
                },
            )
            .expect("revocation head");
    }
    Fixture {
        journal,
        directory,
        scope,
        config,
        policy,
    }
}

pub(crate) fn sessions() -> LocalSessionRegistry {
    LocalSessionRegistry::new(LocalSessionLimits {
        maximum_sessions: 1,
    })
    .expect("session table")
}

pub(crate) fn anchor() -> RetainedCgroupAnchor {
    let root = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").expect("cgroup root").into())
        .expect("typed cgroup root");
    let membership = fs::read_to_string("/proc/self/cgroup").expect("own cgroup");
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .expect("unified hierarchy");
    root.resolve(Path::new(if relative.is_empty() { "." } else { relative }))
        .expect("own cgroup anchor")
}

pub(crate) fn sample(wall: i64, boottime: u64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(PROVENANCE).expect("test provenance"),
        KernelBootId::current().expect("host boot").into_bytes(),
        wall,
        boottime,
    )
    .expect("paired sample")
}

pub(crate) fn provision_samples(
    fixture: &mut Fixture,
    sessions: &mut LocalSessionRegistry,
    observations: Vec<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
) -> Result<LocalSessionEndpoint, LocalProvisioningError> {
    let mut observations = VecDeque::from(observations);
    provision(
        &mut fixture.journal,
        sessions,
        fixture.scope,
        anchor(),
        fixture.config,
        &mut || {
            observations
                .pop_front()
                .expect("unexpected extra clock read")
        },
    )
}

fn only_issued_capability(journal: &Journal) -> CapabilityId {
    let records: Vec<_> = journal
        .records(RecordNamespace::PublisherAuthority)
        .collect();
    assert_eq!(
        records.len(),
        1,
        "expected exactly one durable issuance record"
    );
    let suffix = records[0]
        .0
        .strip_prefix(b"capability/")
        .expect("capability record family");
    CapabilityId::from_bytes(suffix.try_into().expect("capability key width"))
}

#[test]
fn successful_issuance_binds_exact_claims_audit_and_real_ingress() {
    let mut fixture = fixture(true, true);
    let mut sessions = sessions();
    let endpoint = provision_samples(
        &mut fixture,
        &mut sessions,
        vec![Ok(sample(150, 1000)), Ok(sample(151, 2000))],
    )
    .expect("provision");
    let session = endpoint.session_id();
    let capability_id = endpoint.capability_id();
    let binding = endpoint.channel_binding();
    let registry =
        PublisherCapabilityRegistry::load(&mut fixture.journal, fixture.config.authority_limits)
            .expect("authority registry");
    let capability = registry
        .resolve_current(capability_id)
        .expect("current capability");
    let claims = capability.claims();
    assert_eq!(claims.issuer, PrincipalId::from_bytes(CONTROLLER));
    assert_eq!(claims.audience, claims.issuer);
    assert_eq!(claims.holder, fixture.scope.holder);
    assert_eq!(claims.root_subject, fixture.scope.holder);
    assert_eq!(claims.project, fixture.scope.project);
    assert_eq!(claims.sandbox, Some(fixture.scope.sandbox));
    assert_eq!(claims.incarnation, Some(fixture.scope.incarnation));
    assert_eq!(claims.assignment_epoch, Some(fixture.scope.epoch));
    assert_eq!(claims.channel_binding, binding);
    assert_eq!(claims.policy_digest, fixture.policy.descriptor().digest());
    assert_eq!(claims.not_before, 150);
    assert_eq!(claims.expires_at, 200, "validity clamps to policy expiry");
    assert_eq!(claims.revocation_scope, fixture.config.revocation_scope);
    assert_eq!(claims.revocation_generation, Revision::new(1));
    assert_eq!(claims.grants.len(), 1);
    let grant = &claims.grants[0];
    assert_eq!(grant.resource_kind(), ResourceKind::CachePublish);
    assert_eq!(grant.operations(), OperationSet::one(Operation::Publish));
    assert_eq!(
        grant.selector(),
        &Selector::Resource {
            resource: fixture.scope.cache_resource
        }
    );
    assert!(!grant.delegable());
    assert_eq!(
        claims.delegation,
        DelegationLimits::new(0, 0, ResourceVector::ZERO)
    );
    assert_eq!(claims.parent_decision.as_bytes(), capability_id.as_bytes());
    let audit = registry
        .resolve_issuance(capability_id)
        .expect("issuance lookup")
        .expect("issuance evidence");
    assert!(!audit.is_revoked());
    let metadata = audit.metadata();
    assert_eq!(metadata.decision_id(), claims.parent_decision);
    assert_eq!(metadata.session_id(), *session.as_bytes());
    assert_eq!(
        metadata.boot_id(),
        KernelBootId::current().expect("boot ID").into_bytes()
    );
    assert_eq!(metadata.clock_provenance(), PROVENANCE);
    assert_eq!(metadata.observed_wall_seconds(), 150);
    assert_eq!(metadata.observed_boottime_nanoseconds(), 1000);
    assert_eq!(metadata.policy_generation(), 1);
    assert_eq!(metadata.controller_generation(), 1);
    assert_eq!(metadata.cache_resource(), fixture.scope.cache_resource);
    assert_eq!(
        metadata.isolation_policy(),
        ObjectDigest::from_bytes([9; 32])
    );
    let mut client = SeqpacketSocket::from_owned(endpoint.into_fd()).expect("client transport");
    let mut frame = b"AOSLHI01\0\0".to_vec();
    frame.extend_from_slice(b"application request");
    client.send(&frame).expect("send ingress frame");
    let received = sessions.receive(session).expect("authenticate ingress");
    assert_eq!(received.payload(), b"application request");
    assert_eq!(received.capability_id(), capability_id);
    assert_eq!(received.channel_binding(), binding);
    assert_eq!(received.scope(), &fixture.scope);
}

#[test]
fn missing_policy_missing_resource_and_nonpublish_policy_issue_nothing() {
    for (install, allow, wrong_resource) in [
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let mut fixture = fixture(install, allow);
        if wrong_resource {
            fixture.scope.cache_resource = ResourceId::from_bytes([0x99; 16]);
        }
        assert!(matches!(
            provision_samples(&mut fixture, &mut sessions(), vec![Ok(sample(150, 1000))]),
            Err(LocalProvisioningError::PolicyDenied)
        ));
        assert_eq!(
            fixture
                .journal
                .records(RecordNamespace::PublisherAuthority)
                .count(),
            0
        );
    }
}

#[test]
fn precommit_clock_expiry_boot_and_provenance_fail_without_issuance() {
    let valid = sample(150, 1000);
    let bad_boot = RawPairedClockSample::new_untrusted(valid.provenance(), [0x88; 16], 150, 1000)
        .expect("bad boot fixture");
    let bad_provenance = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([0x89; 16]).expect("other provenance"),
        valid.host_boot_id(),
        150,
        1000,
    )
    .expect("bad provenance fixture");
    for observed in [
        sample(99, 1000),
        sample(200, 1000),
        bad_boot,
        bad_provenance,
    ] {
        let mut fixture = fixture(true, true);
        assert!(matches!(
            provision_samples(&mut fixture, &mut sessions(), vec![Ok(observed)]),
            Err(LocalProvisioningError::Clock | LocalProvisioningError::PolicyDenied)
        ));
        assert_eq!(
            fixture
                .journal
                .records(RecordNamespace::PublisherAuthority)
                .count(),
            0
        );
    }
}

#[test]
fn postcommit_clock_failures_leave_auditable_but_unactivated_capability() {
    for fresh in [
        Err(ProtectedOwnershipClockError),
        Ok(sample(149, 2000)),
        Ok(sample(151, 999)),
        Ok(sample(200, 2000)),
        Ok(sample(150, 50_000_001_000)),
    ] {
        let mut fixture = fixture(true, true);
        let mut sessions = sessions();
        assert!(matches!(
            provision_samples(
                &mut fixture,
                &mut sessions,
                vec![Ok(sample(150, 1000)), fresh]
            ),
            Err(LocalProvisioningError::Clock)
        ));
        let capability_id = only_issued_capability(&fixture.journal);
        let registry = PublisherCapabilityRegistry::load(
            &mut fixture.journal,
            fixture.config.authority_limits,
        )
        .expect("authority registry");
        let audit = registry
            .resolve_issuance(capability_id)
            .expect("audit lookup")
            .expect("retained audit");
        let session_id = LocalSessionId::from_bytes(audit.metadata().session_id());
        assert!(matches!(
            sessions.receive(session_id),
            Err(LocalSessionError::UnknownSession)
        ));
        assert!(
            registry.resolve_current(capability_id).is_ok(),
            "issued evidence is retained, not automatically revoked"
        );

        let endpoint = provision_samples(
            &mut fixture,
            &mut sessions,
            vec![Ok(sample(150, 1000)), Ok(sample(151, 2000))],
        )
        .expect("failed activation releases the sole session slot");
        assert_ne!(endpoint.session_id(), session_id);
        assert_ne!(endpoint.capability_id(), capability_id);
    }
}

#[test]
fn capacity_fails_before_new_issuance_or_clock_access() {
    let mut fixture = fixture(true, true);
    let mut sessions = sessions();
    let _endpoint = provision_samples(
        &mut fixture,
        &mut sessions,
        vec![Ok(sample(150, 1000)), Ok(sample(151, 2000))],
    )
    .expect("first session");
    assert!(matches!(
        provision_samples(&mut fixture, &mut sessions, Vec::new()),
        Err(LocalProvisioningError::Session(LocalSessionError::Capacity))
    ));
    assert_eq!(
        fixture
            .journal
            .records(RecordNamespace::PublisherAuthority)
            .count(),
        1
    );
}

#[test]
fn restart_recovers_audit_but_never_reconstructs_live_session() {
    let mut fixture = fixture(true, true);
    let mut live = sessions();
    let endpoint = provision_samples(
        &mut fixture,
        &mut live,
        vec![Ok(sample(150, 1000)), Ok(sample(151, 2000))],
    )
    .expect("initial session");
    let session = endpoint.session_id();
    let capability = endpoint.capability_id();
    let mut client = SeqpacketSocket::from_owned(endpoint.into_fd()).expect("client transport");
    drop(live);
    drop(fixture.journal);
    let mut reopened = open_journal(fixture.directory.path());
    let registry =
        PublisherCapabilityRegistry::load(&mut reopened, fixture.config.authority_limits)
            .expect("recovered registry");
    assert!(
        registry
            .resolve_issuance(capability)
            .expect("recovered audit")
            .is_some()
    );
    assert!(matches!(
        sessions().receive(session),
        Err(LocalSessionError::UnknownSession)
    ));
    assert!(client.send(b"old endpoint closed").is_err());
}
