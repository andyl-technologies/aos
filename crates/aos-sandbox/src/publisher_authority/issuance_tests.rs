//! Local-session issuance envelope and immutable audit regressions.

#![allow(clippy::unwrap_used, reason = "Invalid test fixtures must panic.")]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use aos_sandbox_core::{
    AssignmentEpoch, AuditId, CapabilityDraft, ChannelBinding, DelegationLimits, Grant, GrantId,
    IncarnationId, ObjectDigest, Operation, OperationSet, PrincipalId, ProjectId,
    ResourceDimension, ResourceId, ResourceKind, ResourceVector, Revision, RevocationScopeId,
    SandboxId, Selector,
};

use super::*;
use crate::JournalLimits;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aos-publisher-issuance-{}-{}",
            std::process::id(),
            CapabilityId::new()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn open(&self) -> Journal {
        open(&self.0)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(path: &Path) -> Journal {
    let uid = fs::metadata(path).unwrap().uid();
    Journal::open_protected_at_uid(path, "authority.journal", JournalLimits::default(), uid)
        .unwrap()
        .0
}

pub(super) fn capability_draft(id: u8, resource: u8) -> CapabilityDraft {
    let id = CapabilityId::from_bytes([id; 16]);
    let principal = PrincipalId::from_bytes([4; 16]);
    let grant = Grant::new(
        GrantId::from_bytes([2; 16]),
        ResourceKind::CachePublish,
        OperationSet::one(Operation::Publish),
        Selector::Resource {
            resource: ResourceId::from_bytes([resource; 16]),
        },
        false,
    )
    .unwrap();
    CapabilityDraft {
        id,
        issuer: principal,
        audience: principal,
        holder: PrincipalId::from_bytes([6; 16]),
        channel_binding: ChannelBinding::new([7; 32]),
        root_subject: PrincipalId::from_bytes([6; 16]),
        project: ProjectId::from_bytes([9; 16]),
        sandbox: Some(SandboxId::from_bytes([8; 16])),
        incarnation: Some(IncarnationId::from_bytes([19; 16])),
        grants: vec![grant],
        policy_digest: ObjectDigest::from_bytes([10; 32]),
        assignment_epoch: Some(AssignmentEpoch::new(13)),
        not_before: 100,
        expires_at: 200,
        revocation_scope: RevocationScopeId::from_bytes([11; 16]),
        revocation_generation: Revision::new(12),
        delegation: DelegationLimits::new(0, 0, ResourceVector::ZERO),
        parent_decision: AuditId::from_bytes([id.as_bytes()[0]; 16]),
    }
}

fn capability(id: u8, resource: u8) -> CapabilityRecord {
    CapabilityRecord::issue(capability_draft(id, resource)).unwrap()
}

pub(super) fn metadata(id: u8, resource: u8) -> IssuanceDecisionMetadataV1 {
    IssuanceDecisionMetadataV1::new(IssuanceDecisionMetadataDraftV1 {
        decision_id: AuditId::from_bytes([id; 16]),
        session_id: [13; 16],
        boot_id: [14; 16],
        clock_provenance: [15; 16],
        observed_wall_seconds: 150,
        observed_boottime_nanoseconds: 123_456,
        policy_generation: 16,
        controller_generation: 17,
        cache_resource: ResourceId::from_bytes([resource; 16]),
        isolation_policy: ObjectDigest::from_bytes([18; 32]),
    })
    .unwrap()
}

#[test]
fn version_two_issuance_survives_revocation_compaction_and_restart() {
    let directory = TestDirectory::new();
    let mut journal = directory.open();
    let record = capability(20, 3);
    let evidence = metadata(20, 3);
    let digest = evidence.validate_for(&record).unwrap();
    let encoded = encode_record_with_issuance(
        DurableCapabilityStateV1::Active,
        &record,
        Some(&(evidence.clone(), digest)),
        MAXIMUM_RECORD_BYTES,
    )
    .unwrap();
    let limits =
        PublisherAuthorityLimits::new(1, encoded.len(), RECORD_KEY_BYTES + encoded.len()).unwrap();
    {
        let mut registry = PublisherCapabilityRegistry::load(&mut journal, limits).unwrap();
        registry
            .install_local_session_from_trusted_controller(
                [1; 16],
                record.clone(),
                evidence.clone(),
            )
            .unwrap();
        assert_eq!(registry.resolve_current(record.id()).unwrap(), record);
        let resolved = registry.resolve_issuance(record.id()).unwrap().unwrap();
        assert_eq!(resolved.metadata(), &evidence);
        assert_eq!(resolved.claims_digest(), digest);
        assert!(!resolved.is_revoked());
        registry
            .revoke_from_trusted_controller([2; 16], record.id())
            .unwrap();
        let resolved = registry.resolve_issuance(record.id()).unwrap().unwrap();
        assert!(resolved.is_revoked());
    }
    journal.compact().unwrap();
    drop(journal);

    let mut reopened = open(&directory.0);
    let registry = PublisherCapabilityRegistry::load(&mut reopened, limits).unwrap();
    assert!(matches!(
        registry.resolve_current(record.id()),
        Err(PublisherAuthorityError::Revoked)
    ));
    assert!(
        registry
            .resolve_issuance(record.id())
            .unwrap()
            .unwrap()
            .is_revoked()
    );
}

#[test]
fn version_two_rejects_crosslink_substitution_unknown_fields_and_size_excess() {
    let record = capability(21, 3);
    let evidence = metadata(21, 3);
    let digest = evidence.validate_for(&record).unwrap();
    let canonical = encode_record_with_issuance(
        DurableCapabilityStateV1::Active,
        &record,
        Some(&(evidence.clone(), digest)),
        MAXIMUM_RECORD_BYTES,
    )
    .unwrap();
    assert!(matches!(
        encode_record_with_issuance(
            DurableCapabilityStateV1::Active,
            &record,
            Some(&(evidence.clone(), digest)),
            canonical.len() - 1,
        ),
        Err(PublisherAuthorityError::LimitExceeded("record bytes"))
    ));

    let wrong_resource = metadata(21, 22);
    let wire = DurableCapabilityRecordRefV2 {
        version: RECORD_VERSION_V2,
        state: 0,
        capability: &record,
        issuance: &wrong_resource,
        claims_digest: digest,
    };
    let substituted = serde_json::to_vec(&wire).unwrap();
    assert!(matches!(
        decode_record(
            &capability_key(record.id()),
            &substituted,
            MAXIMUM_RECORD_BYTES
        ),
        Err(PublisherAuthorityError::IssuanceCrosslinkMismatch)
    ));

    let mut unknown = b"{\"unknown\":0,".to_vec();
    unknown.extend_from_slice(&canonical[1..]);
    assert!(matches!(
        decode_record(&capability_key(record.id()), &unknown, MAXIMUM_RECORD_BYTES),
        Err(PublisherAuthorityError::MalformedRecord)
    ));
    assert!(matches!(
        decode_record(
            &capability_key(record.id()),
            &[canonical, b"\n".to_vec()].concat(),
            MAXIMUM_RECORD_BYTES,
        ),
        Err(PublisherAuthorityError::MalformedRecord)
    ));
}

#[test]
fn metadata_and_capability_crosslinks_fail_closed() {
    assert!(matches!(
        IssuanceDecisionMetadataV1::new(IssuanceDecisionMetadataDraftV1 {
            decision_id: AuditId::from_bytes([0; 16]),
            session_id: [13; 16],
            boot_id: [14; 16],
            clock_provenance: [15; 16],
            observed_wall_seconds: 150,
            observed_boottime_nanoseconds: 123,
            policy_generation: 1,
            controller_generation: 1,
            cache_resource: ResourceId::from_bytes([3; 16]),
            isolation_policy: ObjectDigest::from_bytes([18; 32]),
        }),
        Err(PublisherAuthorityError::InvalidIssuanceMetadata)
    ));
    for invalid in [capability(22, 23), capability(23, 3)] {
        assert!(matches!(
            metadata(22, 3).validate_for(&invalid),
            Err(PublisherAuthorityError::IssuanceCrosslinkMismatch)
        ));
    }

    let mut sentinel_claims = capability_draft(24, 3);
    sentinel_claims.issuer = PrincipalId::from_bytes([0; 16]);
    sentinel_claims.audience = PrincipalId::from_bytes([0; 16]);
    sentinel_claims.holder = PrincipalId::from_bytes([0; 16]);
    sentinel_claims.root_subject = PrincipalId::from_bytes([0; 16]);
    sentinel_claims.channel_binding = ChannelBinding::new([0; 32]);
    sentinel_claims.project = ProjectId::from_bytes([0; 16]);
    sentinel_claims.policy_digest = ObjectDigest::from_bytes([0; 32]);
    sentinel_claims.revocation_scope = RevocationScopeId::from_bytes([0; 16]);
    sentinel_claims.revocation_generation = Revision::new(0);
    sentinel_claims.grants = vec![
        Grant::new(
            GrantId::from_bytes([0; 16]),
            ResourceKind::CachePublish,
            OperationSet::one(Operation::Publish),
            Selector::Resource {
                resource: ResourceId::from_bytes([3; 16]),
            },
            false,
        )
        .unwrap(),
    ];
    let mut runtime_unbound = capability_draft(24, 3);
    runtime_unbound.sandbox = None;
    runtime_unbound.incarnation = None;
    let mut assignment_unbound = capability_draft(24, 3);
    assignment_unbound.assignment_epoch = None;
    let mut delegation_enabled = capability_draft(24, 3);
    delegation_enabled.delegation = DelegationLimits::new(
        0,
        0,
        ResourceVector::ZERO.with(ResourceDimension::StorageBytes, 1),
    );
    let mut different_root = capability_draft(24, 3);
    different_root.root_subject = PrincipalId::from_bytes([8; 16]);
    for draft in [
        sentinel_claims,
        runtime_unbound,
        assignment_unbound,
        delegation_enabled,
        different_root,
    ] {
        let invalid = CapabilityRecord::issue(draft).unwrap();
        assert!(matches!(
            metadata(24, 3).validate_for(&invalid),
            Err(PublisherAuthorityError::IssuanceCrosslinkMismatch)
        ));
    }
}
