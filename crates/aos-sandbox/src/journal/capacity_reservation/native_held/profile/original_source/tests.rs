//! UNRUN width-only accounting vectors through the unchanged private engine.
//!
//! Marker values are not canonical owners. These tests create no Journal,
//! protected IO, admission receipt, ordinary association or funding authority.

use super::*;
use super::super::{measure_appends, reservation_key};

#[test]
fn measurement_owner_view_borrows_existing_payload_without_a_second_graph_copy() {
    let owners = BTreeMap::from([(vec![1; 40], vec![2; 4096])]);
    let view = owners
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect::<OwnerView<'_>>();
    let actual = view.get(owners.keys().next().unwrap().as_slice()).copied().unwrap();

    assert!(std::ptr::eq(actual, owners.values().next().unwrap().as_slice()));
    assert_eq!(actual.len(), 4096);
}

#[test]
fn shared_usage_adapter_checks_existing_fold_and_next_without_remeasuring() {
    let measured = measure(&cold_appends(1000), 1000);
    let (coupled, bytes, records) = coupled_prefixes(
        &measured,
        reservation_key([1; 32]).len(),
        1000,
        true,
    )
    .unwrap();
    let owner = measured.geometry;
    let alternative = OriginalSourceMeasuredAlternativeV5 {
        owner,
        coupled,
        maximum_coupled_growth_bytes: bytes,
        maximum_coupled_growth_records: records,
        maximum_key_bytes: measured.maximum_key_bytes,
        maximum_record_payload_bytes: measured.maximum_record_payload_bytes,
        frames: transaction_frames(owner.records as u64, owner.transactions as u64).unwrap(),
        poison: false,
        independent_cut_required: false,
        original_custody_required: false,
    };
    let data = OriginalSourceGeometryDataV5 {
        alternatives: vec![alternative],
        normal: owner,
        poison: owner,
        remaining: None,
        staged_peak_bytes: bytes,
        staged_peak_records: records,
        other_frames: 0,
        ordinary_association_required: true,
        original_membership_required: true,
    };
    let usage = NativeHeldCapacityUsageV3 {
        journal_bytes: 7,
        transactions: 1,
        materialized_bytes: 11,
        materialized_records: 2,
        reserved_bytes: 13,
        reserved_records: 3,
        reserved_transactions: 1,
    };

    assert!(data.require_usage_headroom(JournalLimits::default(), usage, u64::MAX - 24, 6).is_ok());
    assert!(data.require_usage_headroom(JournalLimits::default(), usage, u64::MAX - 23, 6).is_err());
    assert!(data.require_usage_headroom(JournalLimits {
        maximum_journal_bytes: 7 + 13 + owner.append_bytes - 1,
        ..JournalLimits::default()
    }, usage, 1, 6).is_err());
}

fn original_append(
    index: usize,
    changes: Vec<NativeHeldCapacityChangeV3>,
    final_append: bool,
) -> SourceMeasurementAppend {
    SourceMeasurementAppend::Original {
        transaction_id: template_transaction_id(index).unwrap(),
        changes,
        final_append,
    }
}

fn cold_appends(floor: usize) -> Vec<SourceMeasurementAppend> {
    let native_key = vec![1; 40];
    let mut first = [96, 99, 63, 103].into_iter().enumerate().map(|(index, width)| {
        NativeHeldCapacityChangeV3::new(
            vec![index as u8 + 2; width],
            Some(vec![1; 16]),
            Some(forecast_marker(16, 0, index).unwrap()),
        ).unwrap()
    }).collect::<Vec<_>>();
    first.push(NativeHeldCapacityChangeV3::new(
        native_key.clone(), None, Some(forecast_marker(floor + 1317, 0, 4).unwrap()),
    ).unwrap());

    vec![
        original_append(0, first, false),
        original_append(1, vec![NativeHeldCapacityChangeV3::new(
            native_key.clone(),
            Some(forecast_marker(floor + 1317, 0, 4).unwrap()),
            Some(forecast_marker(floor + 2602, 1, 0).unwrap()),
        ).unwrap()], false),
        original_append(2, vec![NativeHeldCapacityChangeV3::new(
            native_key,
            Some(forecast_marker(floor + 2602, 1, 0).unwrap()),
            Some(forecast_marker(floor + 3314, 2, 0).unwrap()),
        ).unwrap()], true),
    ]
}

fn measure(appends: &[SourceMeasurementAppend], floor: usize) -> MeasuredAppends {
    measure_appends_with_prefixes(
        NativeHeldCapacityPurposeV3::Provider,
        appends.iter().map(SourceMeasurementAppend::measurement),
        JournalLimits::default(), floor,
    ).unwrap()
}

#[test]
fn real_cold_three_step_framing_and_coupled_peak_differ_from_owner_peak() {
    for floor in [1000, 30_413] {
        let appends = cold_appends(floor);
        let measured = measure(&appends, floor);
        let (coupled, peak_bytes, peak_records) = coupled_prefixes(
            &measured, reservation_key([1; 32]).len(), floor, true,
        ).unwrap();

        assert_eq!(measured.geometry.transactions, 3);
        assert_eq!(measured.geometry.records, 12); // Actual7/3/2, not labels only.
        assert_eq!(transaction_frames(12, 3).unwrap(), 18);
        assert_eq!(measured.geometry.append_bytes, 4 * 16 + 9589 + 5 * floor as u64);
        assert_eq!(measured.geometry.maximum_retained_growth_bytes, 40 + floor as u64 + 3314);
        assert_eq!(peak_bytes, 40 + floor as u64 + 2602);
        assert_eq!(peak_records, 1);
        assert_eq!(coupled.iter().map(|prefix| prefix.records).collect::<Vec<_>>(), [1, 1, 0]);
        assert_eq!(coupled.last().unwrap().bytes, 3279);
        assert!(measured.geometry.maximum_retained_growth_bytes > peak_bytes);
    }
}

#[test]
fn cold_reopen_suffixes_preserve_two_one_absent_and_still_fund_append_bytes() {
    let floor = 1000;
    let appends = cold_appends(floor);
    let after_prepared = measure(&appends[1..], floor);
    let (_, peak_bytes, peak_records) = coupled_prefixes(
        &after_prepared, reservation_key([1; 32]).len(), floor, true,
    ).unwrap();
    assert_eq!(after_prepared.geometry.transactions, 2);
    assert_eq!(after_prepared.geometry.records, 5);
    assert_eq!(transaction_frames(5, 2).unwrap(), 9);
    assert_eq!(peak_bytes, 1285);
    assert_eq!(peak_records, 0);

    let after_stored = measure(&appends[2..], floor);
    let (_, peak_bytes, peak_records) = coupled_prefixes(
        &after_stored, reservation_key([1; 32]).len(), floor, true,
    ).unwrap();
    assert_eq!(after_stored.geometry.transactions, 1);
    assert_eq!(after_stored.geometry.records, 2);
    assert_eq!(after_stored.geometry.append_bytes, 3771 + floor as u64);
    assert_eq!(transaction_frames(2, 1).unwrap(), 4);
    assert_eq!((peak_bytes, peak_records), (0, 0));
}

#[test]
fn old_fixed_266_measurement_uses_the_same_accumulator_and_framing() {
    let appends = cold_appends(266);
    let old = measure_appends(
        NativeHeldCapacityPurposeV3::Provider,
        appends.iter().map(SourceMeasurementAppend::measurement),
        JournalLimits::default(), 266,
    ).unwrap();
    let retained = measure(&appends, 266);

    assert_eq!(old, retained.geometry);
    assert_eq!(old.append_bytes, 4 * 16 + 9589 + 5 * 266);
    assert_eq!(old.maximum_retained_growth_records, 1);
}

#[test]
fn distinct_forecasts_preserve_width_and_reject_noop_or_wrong_before() {
    let first = forecast_marker(64, 0, 0).unwrap();
    let next = forecast_marker(64, 1, 0).unwrap();
    assert_eq!(first.len(), next.len());
    assert_ne!(first, next);
    assert!(forecast_marker(10, 0, 0).is_err());
    assert!(NativeHeldCapacityChangeV3::new(vec![1; 40], Some(first.clone()), Some(first)).is_err());

    let appends = [
        original_append(0, vec![NativeHeldCapacityChangeV3::new(vec![1; 40], None, Some(vec![1; 64])).unwrap()], false),
        original_append(1, vec![NativeHeldCapacityChangeV3::new(vec![1; 40], Some(vec![2; 64]), Some(next)).unwrap()], true),
    ];
    assert!(measure_appends_with_prefixes(
        NativeHeldCapacityPurposeV3::Provider,
        appends.iter().map(SourceMeasurementAppend::measurement), JournalLimits::default(), 1000,
    ).is_err());
}

#[test]
fn all_four_per_append_limits_have_exact_boundary_and_one_less_refusal() {
    let appends = cold_appends(1000);
    let measured = measure(&appends, 1000);
    let baseline = JournalLimits::default();
    let boundaries = [
        JournalLimits { maximum_key_bytes: measured.maximum_key_bytes, ..baseline },
        JournalLimits { maximum_record_bytes: measured.maximum_record_payload_bytes, ..baseline },
        JournalLimits { maximum_records_per_transaction: measured.geometry.maximum_transaction_records as usize, ..baseline },
        JournalLimits { maximum_transaction_bytes: measured.geometry.maximum_transaction_record_bytes as usize, ..baseline },
    ];
    for (index, boundary) in boundaries.into_iter().enumerate() {
        assert!(measure_appends_with_prefixes(
            NativeHeldCapacityPurposeV3::Provider,
            appends.iter().map(SourceMeasurementAppend::measurement), boundary, 1000,
        ).is_ok());
        let mut short = boundary;
        match index {
            0 => short.maximum_key_bytes -= 1,
            1 => short.maximum_record_bytes -= 1,
            2 => short.maximum_records_per_transaction -= 1,
            3 => short.maximum_transaction_bytes -= 1,
            _ => unreachable!(),
        }
        assert!(measure_appends_with_prefixes(
            NativeHeldCapacityPurposeV3::Provider,
            appends.iter().map(SourceMeasurementAppend::measurement), short, 1000,
        ).is_err());
    }
}

#[test]
fn all_four_aggregate_limits_count_existing_usage_and_other_floors_once() {
    let measured = measure(&cold_appends(1000), 1000);
    let geometry = measured.geometry;
    let usage = NativeHeldCapacityUsageV3 {
        journal_bytes: 17, transactions: 2, materialized_bytes: 19, materialized_records: 3,
        reserved_bytes: 23, reserved_records: 5, reserved_transactions: 7,
    };
    let baseline = JournalLimits::default();
    let boundaries = [
        JournalLimits { maximum_journal_bytes: 17 + 23 + geometry.append_bytes, ..baseline },
        JournalLimits { maximum_transactions: 2 + 7 + geometry.transactions as usize, ..baseline },
        JournalLimits { maximum_materialized_bytes: 19 + 23 + geometry.append_bytes as usize, ..baseline },
        JournalLimits { maximum_materialized_records: 3 + 5 + geometry.records as usize, ..baseline },
    ];
    for (index, boundary) in boundaries.into_iter().enumerate() {
        assert!(geometry.require_headroom(boundary, usage).is_ok());
        let mut short = boundary;
        match index {
            0 => short.maximum_journal_bytes -= 1,
            1 => short.maximum_transactions -= 1,
            2 => short.maximum_materialized_bytes -= 1,
            3 => short.maximum_materialized_records -= 1,
            _ => unreachable!(),
        }
        assert!(geometry.require_headroom(short, usage).is_err());
    }
}

#[test]
fn next_sequence_post_append_bound_includes_both_transaction_frames_and_other_debt() {
    let own = transaction_frames(12, 3).unwrap();
    let other = transaction_frames(5, 2).unwrap();
    assert_eq!((own, other), (18, 9));
    assert!(require_sequence_headroom(u64::MAX - 27, own, other).is_ok());
    assert!(require_sequence_headroom(u64::MAX - 26, own, other).is_err());
    assert!(transaction_frames(1, u64::MAX).is_err());
    assert!(transaction_frames(u64::MAX, 1).is_err());
}

#[test]
fn envelope_fold_is_componentwise_and_extra_ordinary_delete_is_full_spend() {
    let mut envelope = NativeHeldCapacityGeometryV3 { transactions: 2, records: 8, append_bytes: 100, ..Default::default() };
    fold_envelope(&mut envelope, NativeHeldCapacityGeometryV3 { transactions: 3, records: 5, append_bytes: 200, ..Default::default() });
    assert_eq!((envelope.transactions, envelope.records, envelope.append_bytes), (3, 8, 200));

    let own = JournalRecord::delete(RecordNamespace::GlobalCapacityReservation, reservation_key([1; 32]));
    let ordinary = JournalRecord::delete(RecordNamespace::GlobalCapacityReservation, reservation_key([2; 32]));
    let one = JournalTransaction::new([1; 16], vec![own.clone()]).unwrap();
    let both = JournalTransaction::new([2; 16], vec![own, ordinary]).unwrap();
    let one_bytes = encoded_transaction_append_bytes(&one).unwrap();
    assert_eq!(encoded_transaction_append_bytes(&both).unwrap() - one_bytes, 7 + 75 + 72);
    let request = NativeHeldCapacityRequestV3 {
        purpose: NativeHeldCapacityPurposeV3::Provider,
        owner_id: [1; 32], owner_digest: [2; 32], operation_id: [3; 16],
        artifact_digest: [4; 32], checkpoint_digest: [5; 32], chain_head_digest: [6; 32],
        future_transactions: 1, terminal_records: 1, terminal_bytes: one_bytes,
        poison_records: 1, poison_bytes: one_bytes,
    };
    assert!(check_transfer(&one, request, None, JournalLimits::default(), ("records", "bytes")).is_ok());
    assert!(check_transfer(&both, request, None, JournalLimits::default(), ("records", "bytes")).is_err());
    assert!(require_own_debt(request, NativeHeldCapacityRequestV3 { poison_bytes: one_bytes + 1, ..request }).is_err());
}
