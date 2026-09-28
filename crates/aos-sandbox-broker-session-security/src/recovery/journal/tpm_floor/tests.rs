//! Canonical floor vectors and the nonauthorizing crash/restart state matrix.

use aos_sandbox::{JournalRecord, JournalTransaction, RecordNamespace};

use super::format::{CHECKPOINT_BYTES, FloorEndpointV1, INTENT_BYTES, PROFILE_BYTES};
use super::head::{cut_from_records_v1, transaction_digest_v1};
use super::*;

pub(super) fn floor_fixture() -> (
    FloorProfileV1,
    FloorCheckpointV1,
    FloorIntentV1,
    JournalTransaction,
) {
    let profile = FloorProfileV1::new(
        FloorEndpointV1::ControllerStorageClient,
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let old = cut_from_records_v1(1, [(b"a".as_slice(), b"z".as_slice())]).unwrap();
    let checkpoint = FloorCheckpointV1::new(1, profile.scope(), old, [0; 32], [0; 32]).unwrap();
    let transaction = JournalTransaction::new(
        [5; 16],
        vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            b"a".to_vec(),
            b"y".to_vec(),
        )],
    )
    .unwrap();
    let target = cut_from_records_v1(4, [(b"a".as_slice(), b"y".as_slice())]).unwrap();
    let prepared = FloorIntentV1::new(profile, checkpoint, target, &transaction).unwrap();
    (profile, checkpoint, prepared, transaction)
}

#[test]
fn tpm_floor_independent_sha256_vectors_match_documented_preimages() {
    // Independently hashed literal documented fields with the realized AOS
    // OpenSSL 4.0.2 binary, not output from these Rust codec/hash helpers.
    let (profile, checkpoint, _, _) = floor_fixture();
    let decode = |value: &str| <[u8; 32]>::try_from(hex::decode(value).unwrap()).unwrap();

    assert_eq!(
        profile.scope(),
        decode("b6eb9dba080a323b6f11937df70e87a8a1982ee31e1a99ff612ef2b7a675902e")
    );
    assert_eq!(
        checkpoint.cut().head(),
        decode("d56c7f4df877af36a1db91f7415f72a9ecb4480afec19c5fe4b00dc00dca717e")
    );
    assert_eq!(
        checkpoint.extend_input(),
        decode("3af27fe0021a69eb0f383cbbab684a322672adb46510a46b9a1b3bfffac410cc")
    );
    assert_eq!(
        checkpoint.nv_value(),
        decode("68ea818747c4236ba6bcd7acb4cdc00bfa4c75fc63dc12281dcdb5a49cae69ad")
    );
    assert_eq!(&profile.nv_name()[..2], &[0, 0x0b]);
    assert_eq!(
        &profile.nv_name()[2..],
        &decode("1ed0ed8e68f053c45e3af51db9046cedc99519d8abec43142d3e78845db5e11e")
    );
}

#[test]
fn tpm_floor_fixed_formats_reject_versions_padding_reserved_and_sentinels() {
    let (profile, checkpoint, prepared, _) = floor_fixture();
    assert_eq!(profile.encode().len(), PROFILE_BYTES);
    assert_eq!(checkpoint.encode().len(), CHECKPOINT_BYTES);
    assert_eq!(prepared.encode().len(), INTENT_BYTES);
    assert_eq!(FloorProfileV1::decode(&profile.encode()).unwrap(), profile);
    assert_eq!(
        FloorCheckpointV1::decode(&checkpoint.encode()).unwrap(),
        checkpoint
    );
    assert_eq!(
        FloorIntentV1::decode(profile, &prepared.encode()).unwrap(),
        prepared
    );

    for offset in [0, 8, 9, 10, 11, 13, 14, 15] {
        let mut bytes = profile.encode();
        bytes[offset] ^= 1;
        assert!(FloorProfileV1::decode(&bytes).is_err(), "offset {offset}");
    }
    for offset in [0, 8, 9, 10, 11] {
        let mut bytes = checkpoint.encode();
        bytes[offset] ^= 1;
        assert!(FloorCheckpointV1::decode(&bytes).is_err());
        let mut bytes = prepared.encode();
        bytes[offset] ^= 1;
        assert!(FloorIntentV1::decode(profile, &bytes).is_err());
    }
    for bytes in [
        profile.encode().to_vec(),
        checkpoint.encode().to_vec(),
        prepared.encode().to_vec(),
    ] {
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(FloorProfileV1::decode(&padded).is_err());
        assert!(FloorCheckpointV1::decode(&padded).is_err());
        assert!(FloorIntentV1::decode(profile, &padded).is_err());
    }
    for ordinal in [0, u64::MAX] {
        assert!(
            FloorCheckpointV1::new(ordinal, profile.scope(), checkpoint.cut(), [0; 32], [0; 32])
                .is_err()
        );
    }
    assert!(FloorCutV1::new(0, [1; 32]).is_err());
    assert!(FloorCutV1::new(u64::MAX, [1; 32]).is_err());
    assert!(FloorCutV1::new(1, [0; 32]).is_err());
    assert!(
        FloorCheckpointV1::new(2, profile.scope(), checkpoint.cut(), [0; 32], [1; 32]).is_err()
    );
    assert!(
        FloorCheckpointV1::new(1, profile.scope(), checkpoint.cut(), [1; 32], [0; 32]).is_err()
    );
}

#[test]
fn tpm_floor_crash_matrix_never_accepts_unfloored_or_rolled_back_head() {
    let (profile, checkpoint, prepared, _) = floor_fixture();
    let old = checkpoint.cut();
    let target = prepared.target().cut();
    let old_nv = checkpoint.nv_value();
    let target_nv = prepared.target().nv_value();
    assert_eq!(
        reconcile_floor_v1(profile, checkpoint, None, old, old_nv),
        Ok(FloorRecoveryV1::Current)
    );
    assert_eq!(
        reconcile_floor_v1(profile, checkpoint, Some(prepared), old, old_nv),
        Ok(FloorRecoveryV1::ExtendPrepared)
    );
    assert_eq!(
        reconcile_floor_v1(profile, checkpoint, Some(prepared), old, target_nv),
        Ok(FloorRecoveryV1::CommitPrepared)
    );
    assert_eq!(
        reconcile_floor_v1(profile, checkpoint, Some(prepared), target, target_nv),
        Ok(FloorRecoveryV1::FinalizePrepared)
    );
    assert_eq!(
        reconcile_floor_v1(profile, prepared.target(), None, target, target_nv),
        Ok(FloorRecoveryV1::Current)
    );

    for (disk, nv) in [
        (target, old_nv),
        (old, target_nv),
        (target, target_nv),
        (old, [99; 32]),
    ] {
        assert!(reconcile_floor_v1(profile, checkpoint, None, disk, nv).is_err());
    }
    for (disk, nv) in [(target, old_nv), (old, [99; 32]), (target, [99; 32])] {
        assert!(reconcile_floor_v1(profile, checkpoint, Some(prepared), disk, nv).is_err());
    }
    let fork = FloorCutV1::new(target.sequence(), [99; 32]).unwrap();
    assert!(reconcile_floor_v1(profile, checkpoint, Some(prepared), fork, target_nv).is_err());
    assert!(reconcile_floor_v1(profile, prepared.target(), None, old, target_nv).is_err());
}

#[test]
fn tpm_floor_scope_transplant_and_reprovision_cannot_adopt_old_checkpoint() {
    let (profile, checkpoint, _, _) = floor_fixture();
    for changed in [
        FloorProfileV1::new(
            FloorEndpointV1::StorageBroker,
            [1; 16],
            [2; 16],
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        FloorProfileV1::new(profile.endpoint(), [9; 16], [2; 16], [3; 32], [4; 32]).unwrap(),
        FloorProfileV1::new(profile.endpoint(), [1; 16], [9; 16], [3; 32], [4; 32]).unwrap(),
        FloorProfileV1::new(profile.endpoint(), [1; 16], [2; 16], [9; 32], [4; 32]).unwrap(),
        FloorProfileV1::new(profile.endpoint(), [1; 16], [2; 16], [3; 32], [9; 32]).unwrap(),
    ] {
        assert!(
            reconcile_floor_v1(
                changed,
                checkpoint,
                None,
                checkpoint.cut(),
                checkpoint.nv_value()
            )
            .is_err()
        );
    }
    assert_ne!(
        profile.endpoint().nv_index(),
        FloorEndpointV1::StorageBroker.nv_index()
    );
}

#[test]
fn tpm_floor_intent_binds_exact_transaction_id_order_tags_and_frame_geometry() {
    let (profile, checkpoint, prepared, transaction) = floor_fixture();
    prepared.require_transaction(&transaction).unwrap();
    let changed_id = JournalTransaction::new([6; 16], transaction.records().to_vec()).unwrap();
    assert!(prepared.require_transaction(&changed_id).is_err());
    let deletion = JournalTransaction::new(
        *transaction.id(),
        vec![JournalRecord::delete(
            RecordNamespace::BrokerSessionTraffic,
            b"a".to_vec(),
        )],
    )
    .unwrap();
    assert!(prepared.require_transaction(&deletion).is_err());
    let empty_put = JournalTransaction::new(
        *transaction.id(),
        vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            b"a".to_vec(),
            Vec::new(),
        )],
    )
    .unwrap();
    assert_ne!(
        transaction_digest_v1(&deletion).unwrap(),
        transaction_digest_v1(&empty_put).unwrap()
    );
    let two = JournalTransaction::new(
        [6; 16],
        vec![
            transaction.records()[0].clone(),
            JournalRecord::delete(RecordNamespace::BrokerSessionTraffic, b"b".to_vec()),
        ],
    )
    .unwrap();
    let reversed =
        JournalTransaction::new(*two.id(), two.records().iter().rev().cloned().collect()).unwrap();
    assert_ne!(
        transaction_digest_v1(&two).unwrap(),
        transaction_digest_v1(&reversed).unwrap()
    );
    assert!(FloorIntentV1::new(profile, checkpoint, prepared.target().cut(), &two).is_err());
    assert!(FloorIntentV1::new(profile, checkpoint, checkpoint.cut(), &transaction).is_err());
    let same_cut_changed_tx =
        FloorIntentV1::new(profile, checkpoint, prepared.target().cut(), &changed_id).unwrap();
    assert_ne!(
        same_cut_changed_tx.target().nv_value(),
        prepared.target().nv_value()
    );
}

#[test]
fn tpm_floor_head_commits_archives_and_length_boundaries_without_exclusions() {
    let original = cut_from_records_v1(1, [(b"a".as_slice(), b"bc".as_slice())]).unwrap();
    let changed = cut_from_records_v1(1, [(b"ab".as_slice(), b"c".as_slice())]).unwrap();
    let archived = cut_from_records_v1(
        1,
        [
            (b"a".as_slice(), b"bc".as_slice()),
            (b"archive".as_slice(), b"retained".as_slice()),
        ],
    )
    .unwrap();
    assert_ne!(original, changed);
    assert_ne!(original, archived);
    assert_ne!(
        original,
        cut_from_records_v1(2, [(b"a".as_slice(), b"bc".as_slice())]).unwrap()
    );
    assert!(
        cut_from_records_v1(
            1,
            [
                (b"b".as_slice(), b"x".as_slice()),
                (b"a".as_slice(), b"y".as_slice())
            ]
        )
        .is_err()
    );
    assert!(
        cut_from_records_v1(
            1,
            [
                (b"a".as_slice(), b"x".as_slice()),
                (b"a".as_slice(), b"y".as_slice())
            ]
        )
        .is_err()
    );
    let foreign = JournalTransaction::new(
        [1; 16],
        vec![JournalRecord::put(
            RecordNamespace::HostExecution,
            b"a".to_vec(),
            b"x".to_vec(),
        )],
    )
    .unwrap();
    assert!(transaction_digest_v1(&foreign).is_err());
}
