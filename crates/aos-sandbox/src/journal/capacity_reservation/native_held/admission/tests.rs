//! Synthetic DATA adapter tests; no original owner or protected journal exists.

use super::super::super::{
    GlobalCapacityReservationRequestV1, encode_reservation, reservation_id, reservation_key,
};
use super::super::NativeHeldCapacityRequestV3;
use super::*;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn data() -> NativeHeldProviderAdmissionDataV3 {
    let mut requested_key = b"AOSNCK02".to_vec();
    requested_key.extend_from_slice(&[3; 32]);
    let mut value = NativeHeldProviderAdmissionDataV3 {
        provider: SourceProviderAuthorityV1::new([1; 16], 1, d(1)).unwrap(),
        holder: SourceProviderAuthorityV1::new([2; 16], 1, d(2)).unwrap(),
        acquisition_id: d(3),
        operation_id: [4; 16],
        reservation_acquisition_digest: d(5),
        attempt_digest: d(6),
        root_request_digest: d(7),
        session_binding: d(8),
        native_request_digest: d(9),
        root_prepared_digest: d(10),
        catalog_generation: 11,
        catalog_digest: d(12),
        normalized_intent_digest: d(13),
        resource_namespace_digest: d(14),
        backend_id: [0; 32],
        backend_lineage_digest: d(15),
        requested_key,
        // This opaque fixture deliberately is not a Source graph. The adapter
        // measures DATA only; the separately mandatory owner reducer rejects it.
        requested_value: vec![16; 64],
    };
    value.backend_id = native_dispatch_backend_identity_v2(
        value.normalized_intent_digest,
        value.catalog_generation,
        value.catalog_digest,
        value.attempt_digest,
    );
    value
}

fn capacity(
    data: &NativeHeldProviderAdmissionDataV3,
) -> (JournalRecord, NativeHeldCapacityRecordV3) {
    let mut owner = Sha256::new();
    owner.update(DISPATCH_OWNER_DOMAIN);
    owner.update(data.provider.authority_id());
    owner.update(data.holder.authority_id());
    owner.update(data.acquisition_id.as_bytes());
    let owner_id = owner.finalize().into();
    let old = GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id,
        owner_digest: *data.reservation_acquisition_digest.as_bytes(),
        operation_id: data.operation_id,
        artifact_digest: *data.attempt_digest.as_bytes(),
        checkpoint_digest: *data.root_request_digest.as_bytes(),
        chain_head_digest: *data.session_binding.as_bytes(),
        future_transactions: 1,
        terminal_records: 7,
        terminal_bytes: LEGACY_DISPATCH_FLOOR_BYTES,
        poison_records: 7,
        poison_bytes: LEGACY_DISPATCH_FLOOR_BYTES,
    };
    let old_id = reservation_id(&old, [17; 16]);
    let old_record = JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key(old_id),
        encode_reservation(&old, [17; 16], old_id),
    );
    let new = NativeHeldCapacityRecordV3::new(
        NativeHeldCapacityRequestV3 {
            purpose: NativeHeldCapacityPurposeV3::Provider,
            owner_id,
            owner_digest: old.owner_digest,
            operation_id: data.operation_id,
            artifact_digest: *data.native_request_digest.as_bytes(),
            checkpoint_digest: *data.root_prepared_digest.as_bytes(),
            chain_head_digest: *data.catalog_digest.as_bytes(),
            future_transactions: 19,
            terminal_records: 64,
            terminal_bytes: 8_000_000,
            poison_records: 96,
            poison_bytes: 12_000_000,
        },
        [18; 16],
    )
    .unwrap();
    (old_record, new)
}

#[test]
fn atomic_provider_data_shape_preserves_original_floor_and_is_not_a_permit() {
    let data = data();
    let (old, new) = capacity(&data);
    let transaction = provider_native_capacity_admission_v3(
        &data,
        &old,
        &new,
        [18; 16],
        JournalLimits::default(),
    )
    .unwrap();

    assert_eq!(LEGACY_DISPATCH_OWNER_BYTES, 3_677_574);
    assert_eq!(LEGACY_DISPATCH_FLOOR_BYTES, 3_678_341);
    assert_eq!(
        transaction.records(),
        &[
            JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                old.key().to_vec()
            ),
            new.to_journal_record(),
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                data.requested_key.clone(),
                data.requested_value.clone()
            ),
        ]
    );
    assert!(super::super::require_legacy_transaction(&Default::default(), &transaction).is_err());
}

#[test]
fn no_dispatch_five_row_floor_cannot_upgrade_even_with_recomputed_identity() {
    let data = data();
    let (old, new) = capacity(&data);
    let (mut request, admission, _) = decode_capacity_reservation_request_v1(&old).unwrap();
    request.terminal_records = 5;
    request.poison_records = 5;
    let id = reservation_id(&request, admission);
    let no_dispatch = JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key(id),
        encode_reservation(&request, admission, id),
    );
    assert!(
        provider_native_capacity_admission_v3(
            &data,
            &no_dispatch,
            &new,
            [18; 16],
            JournalLimits::default()
        )
        .is_err()
    );

    let mut wrong_backend = data.clone();
    wrong_backend.backend_id = [19; 32];
    assert!(
        provider_native_capacity_admission_v3(
            &wrong_backend,
            &old,
            &new,
            [18; 16],
            JournalLimits::default()
        )
        .is_err()
    );
}

#[test]
fn changed_original_binding_or_late_smaller_native_floor_is_rejected() {
    let data = data();
    let (old, new) = capacity(&data);
    let mut changed = data.clone();
    changed.attempt_digest = d(20);
    assert!(
        provider_native_capacity_admission_v3(
            &changed,
            &old,
            &new,
            [18; 16],
            JournalLimits::default()
        )
        .is_err()
    );
    assert!(
        provider_native_capacity_admission_v3(
            &data,
            &old,
            &new,
            [19; 16],
            JournalLimits::default()
        )
        .is_err()
    );

    let mut request = new.request();
    request.future_transactions = 18;
    let smaller = NativeHeldCapacityRecordV3::new(request, [18; 16]).unwrap();
    assert!(
        provider_native_capacity_admission_v3(
            &data,
            &old,
            &smaller,
            [18; 16],
            JournalLimits::default()
        )
        .is_err()
    );
}

#[test]
fn root_terminal_proof_keeps_one_cleanup_floor_and_only_cleanup_deletes_it() {
    use super::super::{
        NativeHeldCapacityChangeV3, NativeHeldCapacityPathV3, NativeHeldCapacityStepV3 as Step,
    };
    let (_, old) = capacity(&data());
    let key = vec![1; 40];
    let terminal = NativeHeldCapacityAppendV3::new(
        Step::ProviderRootTerminalStored,
        [19; 16],
        vec![
            NativeHeldCapacityChangeV3::new(key.clone(), Some(vec![1; 16]), Some(vec![2; 16]))
                .unwrap(),
        ],
    )
    .unwrap();
    let cleanup = NativeHeldCapacityAppendV3::new(
        Step::ProviderLifecycleCleanup,
        [20; 16],
        vec![NativeHeldCapacityChangeV3::new(key, Some(vec![2; 16]), None).unwrap()],
    )
    .unwrap();
    let normal = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::Normal,
        vec![cleanup.clone()],
    )
    .unwrap();
    let cold = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::ColdClosed,
        vec![cleanup.clone()],
    )
    .unwrap();
    assert!(
        provider_native_capacity_transition_v3(&terminal, &old, None, JournalLimits::default())
            .is_err()
    );
    let (transaction, floor) = provider_native_capacity_transition_v3(
        &terminal,
        &old,
        Some((&normal, &cold)),
        JournalLimits::default(),
    )
    .unwrap();
    let floor = floor.unwrap();
    assert_eq!(floor.request().future_transactions, 1);
    assert_eq!(
        floor.admission_transaction_id(),
        old.admission_transaction_id()
    );
    assert_eq!(transaction.records().len(), 3);
    assert_eq!(transaction.records()[2], floor.to_journal_record());

    let (transaction, deleted) =
        provider_native_capacity_transition_v3(&cleanup, &floor, None, JournalLimits::default())
            .unwrap();
    assert_eq!(transaction.records().len(), 2);
    assert!(
        transaction
            .records()
            .iter()
            .all(|record| record.value().is_none())
    );
    assert!(deleted.is_none());
    assert!(
        provider_native_capacity_transition_v3(&cleanup, &old, None, JournalLimits::default(),)
            .is_err()
    );
}
