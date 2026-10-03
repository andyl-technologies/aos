//! UNRUN canonical DATA vectors; no fixture admits a physical or journal owner.

use aos_sandbox::{JournalRecord, JournalTransaction, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::*;

const fn broker_const_scalars(
    profile: FloorProfileV1,
    checkpoint: FloorCheckpointV1,
    intent: FloorIntentV1,
) -> (FloorEndpointV1, u64, u64, [u8; 32], [u8; 32]) {
    (
        profile.endpoint(),
        checkpoint.ordinal(),
        intent.target().cut().sequence(),
        intent.predecessor().cut().head(),
        intent.transaction_digest(),
    )
}

fn broker_fixture() -> (
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
    let old = broker_cut_from_records_v1(1, [(b"a".as_slice(), b"z".as_slice())]).unwrap();
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
    let target = broker_cut_from_records_v1(4, [(b"a".as_slice(), b"y".as_slice())]).unwrap();
    let intent = FloorIntentV1::new(profile, checkpoint, target, &transaction).unwrap();
    (profile, checkpoint, intent, transaction)
}

fn host_fixture() -> (
    HostFloorCheckpointDataV1,
    HostFloorIntentDataV1,
    JournalTransaction,
) {
    let old = FloorCutV1::new(4, [8; 32]).unwrap();
    let checkpoint = HostFloorCheckpointDataV1::initial([7; 32], old).unwrap();
    // Deliberately only TX DATA: this is not a signed phase or Core schema fixture.
    let transaction = JournalTransaction::new(
        [9; 16],
        vec![JournalRecord::put(
            RecordNamespace::HostCatalogReconciliation,
            b"data".to_vec(),
            b"bytes".to_vec(),
        )],
    )
    .unwrap();
    let target = FloorCutV1::new(7, [10; 32]).unwrap();
    let intent = HostFloorIntentDataV1::compare_successor(
        [7; 32],
        checkpoint,
        target,
        &transaction,
    )
    .unwrap();
    (checkpoint, intent, transaction)
}

#[test]
fn unrun_broker_original_literal_vectors_and_const_data_getters_remain_exact() {
    let (profile, checkpoint, intent, transaction) = broker_fixture();
    let decode = |value: &str| <[u8; 32]>::try_from(hex::decode(value).unwrap()).unwrap();

    assert_eq!(profile.encode().len(), 112);
    assert_eq!(checkpoint.encode().len(), 156);
    assert_eq!(intent.encode().len(), 324);
    assert_eq!(
        profile.scope(),
        decode("b6eb9dba080a323b6f11937df70e87a8a1982ee31e1a99ff612ef2b7a675902e"),
    );
    assert_eq!(
        checkpoint.cut().head(),
        decode("d56c7f4df877af36a1db91f7415f72a9ecb4480afec19c5fe4b00dc00dca717e"),
    );
    assert_eq!(
        checkpoint.extend_input(),
        decode("3af27fe0021a69eb0f383cbbab684a322672adb46510a46b9a1b3bfffac410cc"),
    );
    assert_eq!(
        checkpoint.nv_value(),
        decode("68ea818747c4236ba6bcd7acb4cdc00bfa4c75fc63dc12281dcdb5a49cae69ad"),
    );
    assert_eq!(FloorProfileV1::decode(&profile.encode()).unwrap(), profile);
    assert_eq!(
        FloorCheckpointV1::decode(&checkpoint.encode()).unwrap(),
        checkpoint,
    );
    assert_eq!(
        FloorIntentV1::decode(profile, &intent.encode()).unwrap(),
        intent,
    );
    assert_eq!(
        intent.transaction_digest(),
        broker_transaction_digest_v1(&transaction).unwrap(),
    );
    assert_eq!(checkpoint.ordinal(), 1);
    assert_eq!(intent.predecessor(), checkpoint);
    assert_eq!(
        broker_const_scalars(profile, checkpoint, intent),
        (
            FloorEndpointV1::ControllerStorageClient,
            1,
            4,
            checkpoint.cut().head(),
            intent.transaction_digest(),
        ),
    );
}

#[test]
fn unrun_broker_failure_precedence_keeps_sequence_digest_and_wire_before_profile() {
    let (profile, checkpoint, intent, transaction) = broker_fixture();
    let other = FloorProfileV1::new(
        FloorEndpointV1::StorageBroker,
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
    )
    .unwrap();

    assert_eq!(
        FloorIntentV1::new(other, checkpoint, checkpoint.cut(), &transaction),
        Err(FloorErrorV1::Successor),
    );
    let foreign = JournalTransaction::new(
        *transaction.id(),
        vec![JournalRecord::put(
            RecordNamespace::HostCatalogReconciliation,
            b"a".to_vec(),
            b"y".to_vec(),
        )],
    )
    .unwrap();
    assert_eq!(
        FloorIntentV1::new(other, checkpoint, intent.target().cut(), &foreign),
        Err(FloorErrorV1::Encoding),
    );
    assert_eq!(
        FloorIntentV1::new(other, checkpoint, intent.target().cut(), &transaction),
        Err(FloorErrorV1::Provisioning),
    );
    let mut bytes = intent.encode();
    bytes[0] ^= 1;
    assert_eq!(FloorIntentV1::decode(other, &bytes), Err(FloorErrorV1::Encoding));
    assert_eq!(
        FloorIntentV1::decode(other, &intent.encode()),
        Err(FloorErrorV1::Provisioning),
    );
}

#[test]
fn unrun_host_initial_layout_and_equation_use_the_actual_single_nul_domain() {
    let (checkpoint, intent, _) = host_fixture();
    let mut expected = b"AOSRDF01".to_vec();
    expected.extend_from_slice(&[0, 1, 0, 0]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&4_u64.to_be_bytes());
    expected.extend_from_slice(&[8; 32]);
    expected.extend_from_slice(&[0; 64]);

    assert_eq!(checkpoint.encode().as_slice(), expected.as_slice());
    let mut extension = b"aos.runtime-deployment.tpm-floor.extend.v1\0".to_vec();
    assert_eq!(extension.last(), Some(&0));
    extension.extend_from_slice(&expected);
    let extend_digest: [u8; 32] = Sha256::digest(&extension).into();
    assert_eq!(checkpoint.extend_input(), extend_digest);
    let mut initial_nv = vec![0; 32];
    initial_nv.extend_from_slice(&extend_digest);
    assert_eq!(checkpoint.nv_value(), <[u8; 32]>::from(Sha256::digest(initial_nv)));

    let mut wrong = b"aos.runtime-deployment.tpm-floor.extend.v1\\0".to_vec();
    wrong.extend_from_slice(&expected);
    assert_ne!(checkpoint.extend_input(), <[u8; 32]>::from(Sha256::digest(wrong)));
    assert_eq!(HostFloorCheckpointDataV1::decode(&expected).unwrap(), checkpoint);
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &intent.encode()).unwrap(),
        intent,
    );
    let empty_anchor = FloorCutV1::new(1, [8; 32]).unwrap();
    assert!(HostFloorCheckpointDataV1::initial([7; 32], empty_anchor).is_err());
}

#[test]
fn unrun_distinct_typed_purpose_frames_and_scope_equations_cannot_transplant() {
    let (profile, broker, broker_intent, _) = broker_fixture();
    let (host, host_intent, _) = host_fixture();

    assert_eq!(FloorCheckpointV1::decode(&host.encode()), Err(FloorErrorV1::Encoding));
    assert_eq!(
        HostFloorCheckpointDataV1::decode(&broker.encode()),
        Err(FloorErrorV1::Encoding),
    );
    assert_eq!(
        FloorIntentV1::decode(profile, &host_intent.encode()),
        Err(FloorErrorV1::Encoding),
    );
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &broker_intent.encode()),
        Err(FloorErrorV1::Encoding),
    );
    assert_eq!(
        HostFloorIntentDataV1::decode([11; 32], &host_intent.encode()),
        Err(FloorErrorV1::Provisioning),
    );

    let mut nested = host_intent.encode();
    nested[12..20].copy_from_slice(b"AOSBTF01");
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &nested),
        Err(FloorErrorV1::Encoding),
    );
    let mut target_scope = host_intent.encode();
    target_scope[188..220].fill(11);
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &target_scope),
        Err(FloorErrorV1::Successor),
    );
}

#[test]
fn unrun_host_framing_sentinels_and_checked_ordinal_cut_geometry_refuse() {
    let (checkpoint, intent, _) = host_fixture();
    let bytes = checkpoint.encode();

    for offset in [0, 8, 9, 10, 11] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert_eq!(
            HostFloorCheckpointDataV1::decode(&changed),
            Err(FloorErrorV1::Encoding),
            "offset {offset}",
        );
    }
    for range in [12..20, 20..52, 52..60, 60..92] {
        let mut changed = bytes;
        changed[range.clone()].fill(0);
        assert_eq!(
            HostFloorCheckpointDataV1::decode(&changed),
            Err(FloorErrorV1::Encoding),
            "range {range:?}",
        );
    }
    for range in [92..124, 124..156] {
        let mut changed = bytes;
        changed[range].fill(1);
        assert_eq!(HostFloorCheckpointDataV1::decode(&changed), Err(FloorErrorV1::Encoding));
    }
    for length in 0..bytes.len() {
        assert!(HostFloorCheckpointDataV1::decode(&bytes[..length]).is_err());
    }
    let mut padded = bytes.to_vec();
    padded.push(0);
    assert_eq!(HostFloorCheckpointDataV1::decode(&padded), Err(FloorErrorV1::Encoding));
    let mut exhausted = bytes;
    exhausted[12..20].fill(255);
    assert_eq!(HostFloorCheckpointDataV1::decode(&exhausted), Err(FloorErrorV1::Encoding));

    let intent_bytes = intent.encode();
    for length in 0..intent_bytes.len() {
        assert!(HostFloorIntentDataV1::decode([7; 32], &intent_bytes[..length]).is_err());
    }
    let mut padded_intent = intent_bytes.to_vec();
    padded_intent.push(0);
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &padded_intent),
        Err(FloorErrorV1::Encoding),
    );

    let mut target = intent.encode();
    target[180..188].copy_from_slice(&3_u64.to_be_bytes());
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &target),
        Err(FloorErrorV1::Encoding),
    );
    let mut predecessor_nv = intent.encode();
    predecessor_nv[260..292].fill(1);
    assert_eq!(
        HostFloorIntentDataV1::decode([7; 32], &predecessor_nv),
        Err(FloorErrorV1::Successor),
    );
}

#[test]
fn unrun_host_exact_transaction_digest_commits_scope_uuid_tags_and_lengths() {
    let (checkpoint, intent, transaction) = host_fixture();
    let mut preimage = b"aos.runtime-deployment.tpm-floor.transaction.v1\0".to_vec();
    preimage.extend_from_slice(&[7; 32]);
    preimage.extend_from_slice(&[9; 16]);
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    preimage.extend_from_slice(&[27, 1]);
    preimage.extend_from_slice(&4_u64.to_be_bytes());
    preimage.extend_from_slice(b"data");
    preimage.extend_from_slice(&5_u64.to_be_bytes());
    preimage.extend_from_slice(b"bytes");

    let encoded = intent.target().encode();
    assert_eq!(&encoded[124..156], Sha256::digest(preimage).as_slice());
    intent.require_transaction(&transaction).unwrap();
    let changed = JournalTransaction::new([11; 16], transaction.records().to_vec()).unwrap();
    assert_eq!(intent.require_transaction(&changed), Err(FloorErrorV1::Successor));
    let deletion = JournalTransaction::new(
        *transaction.id(),
        vec![JournalRecord::delete(RecordNamespace::HostCatalogReconciliation, b"data".to_vec())],
    )
    .unwrap();
    assert_eq!(intent.require_transaction(&deletion), Err(FloorErrorV1::Successor));
    let empty_put = JournalTransaction::new(
        *transaction.id(),
        vec![JournalRecord::put(
            RecordNamespace::HostCatalogReconciliation,
            b"data".to_vec(),
            Vec::new(),
        )],
    )
    .unwrap();
    assert_ne!(
        HostFloorIntentDataV1::compare_successor(
            [7; 32], checkpoint, intent.target().cut(), &deletion,
        )
        .unwrap()
        .target()
        .nv_value(),
        HostFloorIntentDataV1::compare_successor(
            [7; 32], checkpoint, intent.target().cut(), &empty_put,
        )
        .unwrap()
        .target()
        .nv_value(),
    );
    let other_scope = HostFloorCheckpointDataV1::initial([12; 32], checkpoint.cut()).unwrap();
    let other = HostFloorIntentDataV1::compare_successor(
        [12; 32],
        other_scope,
        intent.target().cut(),
        &transaction,
    )
    .unwrap();
    assert_ne!(intent.target().nv_value(), other.target().nv_value());
    let foreign = JournalTransaction::new(
        *transaction.id(),
        vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            b"data".to_vec(),
            b"bytes".to_vec(),
        )],
    )
    .unwrap();
    assert_eq!(
        HostFloorIntentDataV1::compare_successor(
            [7; 32],
            checkpoint,
            intent.target().cut(),
            &foreign,
        ),
        Err(FloorErrorV1::Encoding),
    );

    // Ordered multi-row hashes remain DATA; the genuine Host phase owner must
    // separately refuse this shape before a native one-PUT advance.
    let first = JournalRecord::put(
        RecordNamespace::HostCatalogReconciliation,
        b"first".to_vec(),
        b"a".to_vec(),
    );
    let second = JournalRecord::put(
        RecordNamespace::HostCatalogReconciliation,
        b"second".to_vec(),
        b"b".to_vec(),
    );
    let ordered = JournalTransaction::new([13; 16], vec![first.clone(), second.clone()]).unwrap();
    let reversed = JournalTransaction::new([13; 16], vec![second, first]).unwrap();
    let hash = |transaction| {
        digest::transaction_digest_v1(
            RecordPurposeDataV1::RuntimeDeploymentV1,
            [7; 32],
            transaction,
        )
        .unwrap()
    };
    assert_ne!(hash(&ordered), hash(&reversed));
    let duplicate = JournalTransaction::new(
        [13; 16],
        vec![ordered.records()[0].clone(), ordered.records()[0].clone()],
    )
    .unwrap();
    assert_eq!(
        digest::transaction_digest_v1(
            RecordPurposeDataV1::RuntimeDeploymentV1,
            [7; 32],
            &duplicate,
        ),
        Err(FloorErrorV1::Encoding),
    );
    let empty_key = JournalTransaction::new(
        [13; 16],
        vec![JournalRecord::put(
            RecordNamespace::HostCatalogReconciliation,
            Vec::new(),
            b"a".to_vec(),
        )],
    )
    .unwrap();
    assert_eq!(
        digest::transaction_digest_v1(
            RecordPurposeDataV1::RuntimeDeploymentV1,
            [7; 32],
            &empty_key,
        ),
        Err(FloorErrorV1::Encoding),
    );
    let target_cut = FloorCutV1::new(8, [10; 32]).unwrap();
    assert_eq!(
        HostFloorIntentDataV1::compare_successor([7; 32], checkpoint, target_cut, &ordered),
        Err(FloorErrorV1::Encoding),
    );
}

#[test]
fn unrun_both_typed_purposes_share_only_the_four_comparison_states() {
    let (profile, broker, broker_intent, _) = broker_fixture();
    let (host, host_intent, _) = host_fixture();

    for (target_disk, target_nv, expected) in [
        (false, false, FloorRecoveryV1::ExtendPrepared),
        (false, true, FloorRecoveryV1::CommitPrepared),
        (true, true, FloorRecoveryV1::FinalizePrepared),
    ] {
        let broker_cut = if target_disk {
            broker_intent.target().cut()
        } else {
            broker.cut()
        };
        let broker_nv = if target_nv {
            broker_intent.target().nv_value()
        } else {
            broker.nv_value()
        };
        assert_eq!(
            reconcile_floor_v1(profile, broker, Some(broker_intent), broker_cut, broker_nv),
            Ok(expected),
        );

        let host_cut = if target_disk {
            host_intent.target().cut()
        } else {
            host.cut()
        };
        let host_nv = if target_nv {
            host_intent.target().nv_value()
        } else {
            host.nv_value()
        };
        assert_eq!(
            reconcile_host_floor_data_v1([7; 32], host, Some(host_intent), host_cut, host_nv),
            Ok(expected),
        );
    }

    assert_eq!(
        reconcile_floor_v1(profile, broker, None, broker.cut(), broker.nv_value()),
        Ok(FloorRecoveryV1::Current),
    );
    assert_eq!(
        reconcile_host_floor_data_v1([7; 32], host, None, host.cut(), host.nv_value()),
        Ok(FloorRecoveryV1::Current),
    );
    assert_eq!(
        reconcile_floor_v1(
            profile, broker, Some(broker_intent), broker_intent.target().cut(), broker.nv_value(),
        ),
        Err(FloorErrorV1::Diverged),
    );
    assert_eq!(
        reconcile_host_floor_data_v1(
            [7; 32], host, Some(host_intent), host_intent.target().cut(), host.nv_value(),
        ),
        Err(FloorErrorV1::Diverged),
    );
    for nv in [host_intent.target().nv_value(), [99; 32]] {
        assert_eq!(
            reconcile_host_floor_data_v1([7; 32], host, None, host.cut(), nv),
            Err(FloorErrorV1::Diverged),
        );
    }
}

#[test]
fn unrun_shared_sequence_geometry_preserves_original_error_boundaries() {
    let (_, _, _, transaction) = broker_fixture();

    for (ordinal, pending, expected) in [
        (1, false, 4),
        (1, true, 8),
        (2, false, 13),
        (2, true, 17),
    ] {
        assert_eq!(sidecar_sequence_v1(ordinal, pending), Ok(expected));
    }
    for ordinal in [0, u64::MAX, u64::MAX / 9 + 2] {
        assert_eq!(sidecar_sequence_v1(ordinal, false), Err(FloorErrorV1::Encoding));
    }
    assert_eq!(successor_sequence(1, &transaction), Ok(4));
    assert_eq!(
        successor_sequence(u64::MAX - 3, &transaction),
        Err(FloorErrorV1::Successor),
    );
    assert_eq!(
        successor_sequence(u64::MAX - 1, &transaction),
        Err(FloorErrorV1::Successor),
    );
}
