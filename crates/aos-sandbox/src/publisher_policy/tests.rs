//! Publisher-policy persistence, replay, and compare-and-swap regressions.

#![allow(clippy::unwrap_used, reason = "Invalid test fixtures must panic.")]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

use aos_sandbox_core::format::encode_policy;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
};
use aos_sandbox_core::{CacheDomainId, CanonicalCborError, Grant, GrantId, OperationSet, Selector};

use super::*;
use crate::JournalLimits;

#[test]
fn all_record_families_match_fixed_goldens_and_reject_magic_or_length_changes() {
    fn golden_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
    // Independently framed minimal policy: no grants or limits, project domain
    // 03, deny-new revocation. The literal digest uses the portable object
    // domain, media-type length/text, encoded length, and these exact 32 bytes.
    const POLICY_HEX: &str = "8b0180808080808082015003030303030303030303030303030303820000f680";
    const DIGEST_HEX: &str = "cf76e11e367ae3f447f761210c706ec784ac60d628e89761a9055fabdc160a42";
    let bytes = golden_bytes(POLICY_HEX);
    let project = ProjectId::from_bytes([1; 16]);
    let revision = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        project,
        1,
        100,
        200,
        &bytes,
        DecodeLimits::default(),
    )
    .unwrap();
    assert_eq!(
        revision.descriptor().digest().as_bytes(),
        golden_bytes(DIGEST_HEX).as_slice()
    );
    let resource = PublisherResourceBindingV1::new(
        ResourceId::from_bytes([2; 16]),
        project,
        CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([3; 16])),
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    let controller = PublisherControllerHeadV1 {
        principal: PrincipalId::from_bytes([6; 16]),
        generation: 1,
    };
    let revocation = PublisherRevocationHeadV1 {
        scope: RevocationScopeId::from_bytes([7; 16]),
        generation: 1,
    };
    type Golden = (&'static str, Vec<u8>, String, fn(&[u8]) -> bool);
    let families: [Golden; 7] = [
        (
            "policy revision",
            encode_policy_revision(&revision).unwrap(),
            format!(
                "414f53504f4c5231{}0000000000000001000000000000006400000000000000c8{DIGEST_HEX}00000020{POLICY_HEX}",
                "01".repeat(16)
            ),
            |bytes| decode_policy_revision(bytes).is_ok(),
        ),
        (
            "policy head",
            encode_policy_head(&revision),
            format!(
                "414f53504f4c4831{}0000000000000001{DIGEST_HEX}",
                "01".repeat(16)
            ),
            |bytes| decode_policy_head(bytes).is_ok(),
        ),
        (
            "resource",
            encode_resource(&resource),
            format!(
                "414f535245534231{}{}01{}{}",
                "02".repeat(16),
                "01".repeat(16),
                "03".repeat(16),
                "05".repeat(32)
            ),
            |bytes| decode_resource(bytes).is_ok(),
        ),
        (
            "controller revision",
            encode_controller(controller, CONTROLLER_REVISION_MAGIC),
            format!("414f5343544c5231{}0000000000000001", "06".repeat(16)),
            |bytes| decode_controller(bytes, CONTROLLER_REVISION_MAGIC).is_ok(),
        ),
        (
            "controller head",
            encode_controller(controller, CONTROLLER_CURRENT_MAGIC),
            format!("414f5343544c4831{}0000000000000001", "06".repeat(16)),
            |bytes| decode_controller(bytes, CONTROLLER_CURRENT_MAGIC).is_ok(),
        ),
        (
            "revocation revision",
            encode_revocation(revocation, REVOCATION_REVISION_MAGIC),
            format!("414f535245565231{}0000000000000001", "07".repeat(16)),
            |bytes| decode_revocation(bytes, REVOCATION_REVISION_MAGIC).is_ok(),
        ),
        (
            "revocation head",
            encode_revocation(revocation, REVOCATION_CURRENT_MAGIC),
            format!("414f535245564831{}0000000000000001", "07".repeat(16)),
            |bytes| decode_revocation(bytes, REVOCATION_CURRENT_MAGIC).is_ok(),
        ),
    ];
    for (family, encoded, golden, accepts) in families {
        let expected = golden_bytes(&golden);
        assert_eq!(encoded, expected, "{family} wire changed");
        assert!(accepts(&expected), "{family} golden rejected");
        let mut bad_magic = expected.clone();
        bad_magic[0] ^= 1;
        assert!(!accepts(&bad_magic), "{family} accepted bad magic");
        let mut trailing = expected.clone();
        trailing.push(0);
        assert!(!accepts(&trailing), "{family} accepted trailing bytes");
        assert!(
            !accepts(&expected[..expected.len() - 1]),
            "{family} accepted truncation"
        );
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aos-publisher-policy-{label}-{}-{}",
            std::process::id(),
            ProjectId::new()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn open(&self) -> Journal {
        let uid = fs::metadata(&self.0).unwrap().uid();
        Journal::open_protected_at_uid(&self.0, "policy.journal", JournalLimits::default(), uid)
            .unwrap()
            .0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    project: ProjectId,
    resource: ResourceId,
    domain: CacheDomain,
    policy_bytes: Vec<u8>,
}

fn fixture(domain_byte: u8) -> Fixture {
    let project = ProjectId::from_bytes([1; 16]);
    let resource = ResourceId::from_bytes([2; 16]);
    let domain = CacheDomain::new(
        CacheDomainKind::Project,
        CacheDomainId::from_bytes([domain_byte; 16]),
    );
    let grant = Grant::new(
        GrantId::from_bytes([4; 16]),
        ResourceKind::CachePublish,
        OperationSet::one(Operation::Publish),
        Selector::Resource { resource },
        false,
    )
    .unwrap();
    let policy = Policy::new(
        Vec::new(),
        Vec::new(),
        vec![grant],
        Vec::new(),
        ResourceProfile::new(Vec::new()).unwrap(),
        Vec::new(),
        domain,
        RevocationPolicy::new(RevocationMode::DenyNew, 0),
        None,
        Vec::new(),
    )
    .unwrap();
    Fixture {
        project,
        resource,
        domain,
        policy_bytes: encode_policy(&policy),
    }
}

fn prepared(fixture: &Fixture, generation: u64) -> PreparedPublisherPolicyRevisionV1 {
    PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        fixture.project,
        generation,
        100,
        200,
        &fixture.policy_bytes,
        DecodeLimits::default(),
    )
    .unwrap()
}

fn raw(journal: &mut Journal, id: u8, key: Vec<u8>, value: Vec<u8>) {
    let transaction = JournalTransaction::new(
        [id; 16],
        vec![JournalRecord::put(
            RecordNamespace::PublisherPolicy,
            key,
            value,
        )],
    )
    .unwrap();
    journal.commit(&transaction).unwrap();
}

#[test]
fn current_policy_resource_and_generation_heads_survive_restart() {
    let directory = TestDirectory::new("restart");
    let fixture = fixture(3);
    let binding = PublisherResourceBindingV1::new(
        fixture.resource,
        fixture.project,
        fixture.domain,
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    let controller = PrincipalId::from_bytes([6; 16]);
    let scope = RevocationScopeId::from_bytes([7; 16]);
    let mut journal = directory.open();
    {
        let mut store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        store
            .install_resource_from_trusted_controller([1; 16], &binding)
            .unwrap();
        store
            .publish_policy_from_trusted_controller([2; 16], None, &prepared(&fixture, 1))
            .unwrap();
        store
            .publish_policy_from_trusted_controller([3; 16], Some(1), &prepared(&fixture, 2))
            .unwrap();
        store
            .advance_controller_from_trusted_controller(
                [4; 16],
                None,
                PublisherControllerHeadV1 {
                    principal: controller,
                    generation: 1,
                },
            )
            .unwrap();
        store
            .advance_controller_from_trusted_controller(
                [5; 16],
                Some(1),
                PublisherControllerHeadV1 {
                    principal: controller,
                    generation: 2,
                },
            )
            .unwrap();
        store
            .advance_revocation_from_trusted_controller(
                [6; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope,
                    generation: 1,
                },
            )
            .unwrap();
        assert!(matches!(
            store.advance_controller_from_trusted_controller(
                [7; 16],
                Some(2),
                PublisherControllerHeadV1 {
                    principal: PrincipalId::from_bytes([8; 16]),
                    generation: 3,
                },
            ),
            Err(PublisherPolicyError::ControllerPrincipalMismatch)
        ));
    }
    drop(journal);

    let mut journal = directory.open();
    let store = PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
    let current = store.current_policy(fixture.project).unwrap().unwrap();
    assert_eq!(current.generation(), 2);
    assert_eq!(current.policy().cache_domain(), fixture.domain);
    assert_eq!(
        store.resource_binding(fixture.resource).unwrap(),
        Some(binding)
    );
    assert_eq!(
        store.controller_head().unwrap(),
        Some(PublisherControllerHeadV1 {
            principal: controller,
            generation: 2,
        })
    );
    assert_eq!(
        store.revocation_head(scope).unwrap(),
        Some(PublisherRevocationHeadV1 {
            scope,
            generation: 1,
        })
    );
}

#[test]
fn policy_publish_requires_exact_resource_domain_and_cas_successor() {
    let directory = TestDirectory::new("cas");
    let fixture = fixture(3);
    let wrong = PublisherResourceBindingV1::new(
        fixture.resource,
        fixture.project,
        CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([9; 16])),
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    let mut journal = directory.open();
    let mut store =
        PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
    store
        .install_resource_from_trusted_controller([1; 16], &wrong)
        .unwrap();
    assert!(matches!(
        store.publish_policy_from_trusted_controller([2; 16], None, &prepared(&fixture, 1)),
        Err(PublisherPolicyError::ResourcePolicyMismatch)
    ));
    assert!(matches!(
        store.install_resource_from_trusted_controller([3; 16], &wrong),
        Err(PublisherPolicyError::ResourceAlreadyExists)
    ));

    let no_grant_policy = Policy::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        ResourceProfile::new(Vec::new()).unwrap(),
        Vec::new(),
        fixture.domain,
        RevocationPolicy::new(RevocationMode::DenyNew, 0),
        None,
        Vec::new(),
    )
    .unwrap();
    let bytes = encode_policy(&no_grant_policy);
    let initial = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        fixture.project,
        1,
        100,
        200,
        &bytes,
        DecodeLimits::default(),
    )
    .unwrap();
    store
        .publish_policy_from_trusted_controller([4; 16], None, &initial)
        .unwrap();
    assert!(matches!(
        store.publish_policy_from_trusted_controller([5; 16], Some(1), &initial),
        Err(PublisherPolicyError::NoncontiguousGeneration)
    ));
    assert!(matches!(
        store.publish_policy_from_trusted_controller(
            [6; 16],
            Some(9),
            &PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
                fixture.project,
                2,
                100,
                200,
                &bytes,
                DecodeLimits::default(),
            )
            .unwrap(),
        ),
        Err(PublisherPolicyError::CompareAndSwapFailed)
    ));
}

#[test]
fn replay_rejects_unknown_or_orphaned_and_noncontiguous_history() {
    let unknown_directory = TestDirectory::new("unknown");
    let mut unknown = unknown_directory.open();
    raw(&mut unknown, 1, b"unknown/family".to_vec(), vec![1]);
    assert!(matches!(
        PublisherPolicyStore::load(&mut unknown, PublisherPolicyLimits::default()),
        Err(PublisherPolicyError::CorruptState)
    ));

    let orphan_directory = TestDirectory::new("orphan");
    let fixture = fixture(3);
    let revision = prepared(&fixture, 1);
    let mut orphan = orphan_directory.open();
    raw(
        &mut orphan,
        1,
        policy_revision_key(fixture.project, 1),
        encode_policy_revision(&revision).unwrap(),
    );
    assert!(matches!(
        PublisherPolicyStore::load(&mut orphan, PublisherPolicyLimits::default()),
        Err(PublisherPolicyError::CorruptState)
    ));

    let gap_directory = TestDirectory::new("gap");
    let mut gap = gap_directory.open();
    for (transaction, generation) in [(1, 1), (2, 3)] {
        let revision = prepared(&fixture, generation);
        raw(
            &mut gap,
            transaction,
            policy_revision_key(fixture.project, generation),
            encode_policy_revision(&revision).unwrap(),
        );
        if generation == 3 {
            raw(
                &mut gap,
                3,
                policy_current_key(fixture.project),
                encode_policy_head(&revision),
            );
        }
    }
    assert!(matches!(
        PublisherPolicyStore::load(&mut gap, PublisherPolicyLimits::default()),
        Err(PublisherPolicyError::CorruptState)
    ));

    let missing_directory = TestDirectory::new("missing-revision");
    let mut missing = missing_directory.open();
    raw(
        &mut missing,
        1,
        policy_current_key(fixture.project),
        encode_policy_head(&revision),
    );
    assert!(matches!(
        PublisherPolicyStore::load(&mut missing, PublisherPolicyLimits::default()),
        Err(PublisherPolicyError::CorruptState)
    ));

    let substituted_directory = TestDirectory::new("head-substitution");
    let mut substituted = substituted_directory.open();
    let binding = PublisherResourceBindingV1::new(
        fixture.resource,
        fixture.project,
        fixture.domain,
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    raw(
        &mut substituted,
        1,
        resource_key(fixture.resource),
        encode_resource(&binding),
    );
    raw(
        &mut substituted,
        2,
        policy_revision_key(fixture.project, 1),
        encode_policy_revision(&revision).unwrap(),
    );
    let mut substituted_head = encode_policy_head(&revision);
    *substituted_head.last_mut().unwrap() ^= 1;
    raw(
        &mut substituted,
        3,
        policy_current_key(fixture.project),
        substituted_head,
    );
    assert!(matches!(
        PublisherPolicyStore::load(&mut substituted, PublisherPolicyLimits::default()),
        Err(PublisherPolicyError::CorruptState)
    ));

    let controller_directory = TestDirectory::new("controller-rebound");
    let mut controller = controller_directory.open();
    let first = PublisherControllerHeadV1 {
        principal: PrincipalId::from_bytes([6; 16]),
        generation: 1,
    };
    let rebound = PublisherControllerHeadV1 {
        principal: PrincipalId::from_bytes([8; 16]),
        generation: 2,
    };
    raw(
        &mut controller,
        1,
        controller_revision_key(1),
        encode_controller(first, CONTROLLER_REVISION_MAGIC),
    );
    raw(
        &mut controller,
        2,
        controller_revision_key(2),
        encode_controller(rebound, CONTROLLER_REVISION_MAGIC),
    );
    raw(
        &mut controller,
        3,
        CONTROLLER_CURRENT_KEY.to_vec(),
        encode_controller(rebound, CONTROLLER_CURRENT_MAGIC),
    );
    assert!(matches!(
        PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default()),
        Err(PublisherPolicyError::CorruptState)
    ));

    assert!(matches!(
        validate_successor(Some(u64::MAX), Some(u64::MAX), u64::MAX),
        Err(PublisherPolicyError::GenerationExhausted)
    ));
}

#[test]
fn policy_decoder_and_store_limits_are_hard_clamped() {
    let fixture = fixture(3);
    let tiny = DecodeLimits {
        maximum_bytes: fixture.policy_bytes.len() - 1,
        ..DecodeLimits::default()
    };
    assert!(matches!(
        PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            fixture.project,
            1,
            100,
            200,
            &fixture.policy_bytes,
            tiny,
        ),
        Err(PublisherPolicyError::InvalidPolicyRevision)
    ));
    assert_eq!(
        bounded_decode_limits(DecodeLimits::default()).maximum_collection_items,
        MAXIMUM_COLLECTION_ITEMS
    );
    let oversized_required_features = [0x8b, 0x01, 0x99, 0x04, 0x01];
    assert!(matches!(
        aos_sandbox_core::format::decode_policy(
            &oversized_required_features,
            bounded_decode_limits(DecodeLimits::default()),
        ),
        Err(CanonicalCborError::CollectionTooLarge { .. })
    ));
    assert!(matches!(
        PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            fixture.project,
            1,
            100,
            200,
            &vec![0; MAXIMUM_POLICY_BYTES + 1],
            DecodeLimits::default(),
        ),
        Err(PublisherPolicyError::LimitExceeded("policy bytes"))
    ));

    let directory = TestDirectory::new("limits");
    let mut journal = directory.open();
    let limits =
        PublisherPolicyLimits::new(1, MAXIMUM_RECORD_BYTES, MAXIMUM_MATERIALIZED_BYTES).unwrap();
    let mut store = PublisherPolicyStore::load(&mut journal, limits).unwrap();
    let binding = PublisherResourceBindingV1::new(
        fixture.resource,
        fixture.project,
        fixture.domain,
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    store
        .install_resource_from_trusted_controller([1; 16], &binding)
        .unwrap();
    assert!(matches!(
        store.publish_policy_from_trusted_controller([2; 16], None, &prepared(&fixture, 1)),
        Err(PublisherPolicyError::LimitExceeded(_))
    ));
}
