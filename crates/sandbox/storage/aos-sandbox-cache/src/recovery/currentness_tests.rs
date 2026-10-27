//! Live protected-authority regressions for the historical recovery boundary.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_model::{
    CacheDomainId,
    model::{CacheDomain, CacheDomainKind},
};
use aos_sandbox_protocol::cache_state::{CacheNodeIdV1, ProtectedBackingIdentityV1};

use super::*;

fn historical_fixture() -> (PhysicalPartitionId, Vec<u8>, CacheHistoryFloorV1) {
    let partition = PhysicalPartitionId::derive(
        CacheNodeIdV1::from_bytes([1; 16]).expect("node DATA"),
        ProtectedBackingIdentityV1::new(
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
        )
        .expect("backing DATA"),
        CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([6; 16])),
        ObjectDigest::from_bytes([7; 32]),
    )
    .expect("partition DATA");
    let quota = NodeCacheQuotaV1 {
        partition,
        maximum_physical_bytes: 1024,
        maximum_resident_objects: 16,
        maximum_logical_pins: 16,
        maximum_source_retentions: 16,
        maximum_kernel_references: 16,
        maximum_backing_registrations: 16,
        recovery_reserve_bytes: 0,
        high_water_bytes: 768,
        low_water_bytes: 512,
    };
    let limits = CacheRecoveryLimitsV1::default();
    let global = CacheGlobalRecoveryStateV1::new(
        quota,
        vec![],
        vec![],
        vec![],
        None,
        None,
        vec![],
        vec![],
        None,
        limits,
    )
    .expect("empty global DATA");
    let checkpoint = CacheTypedCheckpointV1::from_baselines(
        1,
        ObjectDigest::from_bytes([8; 32]),
        ObjectDigest::from_bytes([0; 32]),
        vec![],
        vec![],
        global,
        partition,
        limits,
    )
    .expect("genesis checkpoint");
    let floor = CacheHistoryFloorV1::new(
        2,
        checkpoint.checkpoint.digest,
        ObjectDigest::from_bytes([0; 32]),
        checkpoint.checkpoint.history_head,
    )
    .expect("history floor");
    let bytes =
        encode_typed_checkpoint(&checkpoint, partition, limits).expect("canonical checkpoint");
    (partition, bytes, floor)
}

fn journal_fixture() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().expect("private authority directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private directory mode");
    let uid = std::fs::metadata(directory.path())
        .expect("directory metadata")
        .uid();
    let (journal, _) = Journal::open_cache_ordinary_role_v1(
        directory.path(),
        "authority.journal",
        JournalLimits::default(),
        uid,
        crate::journal::CacheOrdinaryOpenV1::Creating,
    )
    .expect("protected journal");
    (directory, journal)
}

#[test]
fn recovery_validates_history_before_expiry_and_keeps_native_expiry() {
    let (_directory, mut journal) = journal_fixture();
    let (partition, checkpoint, floor) = historical_fixture();
    let limits = CacheRecoveryLimitsV1::default();
    let scope = CacheRecoveryInventoryV1::replay_authority_scope(
        partition,
        &checkpoint,
        None,
        floor,
        100,
        limits,
    )
    .expect("Replay scope");
    let owner_scope = ObjectDigest::from_bytes([9; 32]);
    let canonical =
        aos_sandbox_protocol::cache_state::authority_record::encode_cache_authority_record_v1(
            owner_scope,
            CacheAuthorityPurposeV1::Replay,
            scope,
        );
    journal
        .commit(
            &JournalTransaction::new(
                [1; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"replay".to_vec(),
                    canonical.to_vec(),
                )],
            )
            .expect("authority transaction"),
        )
        .expect("commit authority");
    let authority = journal
        .claim_cache_authority_v1()
        .expect("protected namespace");
    let owner = CacheAuthorityOwner::new(&authority, owner_scope, 208).expect("Native owner");
    let capability = owner
        .verify_current_record(CacheAuthorityPurposeV1::Replay, scope, b"replay")
        .expect("current Replay capability");

    let inventory = CacheRecoveryInventoryV1::from_verified(
        &owner,
        &capability,
        partition,
        &checkpoint,
        None,
        floor,
        Vec::<Vec<u8>>::new(),
        limits,
        10,
    )
    .expect("live historical recovery");
    assert_eq!(inventory.global.node_quota.partition, partition);
    assert!(inventory.reconstructed.is_empty());
    assert!(matches!(
        CacheRecoveryInventoryV1::from_verified(
            &owner,
            &capability,
            partition,
            &checkpoint,
            None,
            floor,
            Vec::<Vec<u8>>::new(),
            limits,
            100
        ),
        Err(RecoveryError::Authority(CacheAuthorityError::Expired))
    ));
    assert!(matches!(
        CacheRecoveryInventoryV1::from_verified(
            &owner,
            &capability,
            partition,
            &[],
            None,
            floor,
            Vec::<Vec<u8>>::new(),
            limits,
            100
        ),
        Err(RecoveryError::MalformedPayload)
    ));
    // A later row cannot erase an earlier malformed event: the same loop
    // decodes and validates the current event before requesting its successor.
    let reached = std::cell::Cell::new(0);
    let records = vec![vec![0], vec![1]]
        .into_iter()
        .inspect(|_| reached.set(reached.get() + 1));
    assert!(matches!(
        CacheRecoveryInventoryV1::from_verified(
            &owner,
            &capability,
            partition,
            &checkpoint,
            None,
            floor,
            records,
            limits,
            100
        ),
        Err(RecoveryError::MalformedPayload)
    ));
    assert_eq!(reached.get(), 1);
}

#[test]
fn advanced_same_journal_refuses_the_original_replay_capability() {
    let (_directory, mut journal) = journal_fixture();
    let (partition, checkpoint, floor) = historical_fixture();
    let limits = CacheRecoveryLimitsV1::default();
    let scope = CacheRecoveryInventoryV1::replay_authority_scope(
        partition,
        &checkpoint,
        None,
        floor,
        100,
        limits,
    )
    .expect("Replay scope");
    let owner_scope = ObjectDigest::from_bytes([10; 32]);
    let canonical =
        aos_sandbox_protocol::cache_state::authority_record::encode_cache_authority_record_v1(
            owner_scope,
            CacheAuthorityPurposeV1::Replay,
            scope,
        );
    journal
        .commit(
            &JournalTransaction::new(
                [2; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"replay".to_vec(),
                    canonical.to_vec(),
                )],
            )
            .expect("authority transaction"),
        )
        .expect("commit authority");
    let capability = {
        let authority = journal
            .claim_cache_authority_v1()
            .expect("protected namespace");
        let owner = CacheAuthorityOwner::new(&authority, owner_scope, 208).expect("Native owner");
        owner
            .verify_current_record(CacheAuthorityPurposeV1::Replay, scope, b"replay")
            .expect("original current capability")
    };
    journal
        .commit(
            &JournalTransaction::new(
                [3; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"advance".to_vec(),
                    vec![1],
                )],
            )
            .expect("later transaction"),
        )
        .expect("advance same journal");
    let authority = journal
        .claim_cache_authority_v1()
        .expect("same protected namespace");
    let owner =
        CacheAuthorityOwner::new(&authority, owner_scope, 208).expect("current Native owner");

    assert!(matches!(
        CacheRecoveryInventoryV1::from_verified(
            &owner,
            &capability,
            partition,
            &checkpoint,
            None,
            floor,
            Vec::<Vec<u8>>::new(),
            limits,
            10
        ),
        Err(RecoveryError::Authority(CacheAuthorityError::Journal(
            JournalError::Mechanical(
                aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot
            )
        )))
    ));
}
