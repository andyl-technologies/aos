//! UNRUN complete-cut continuation vectors reusing the original private Flight.

use super::*;
use crate::ledger::native_held_completion::{
    OriginalSourceContinuationDataV5,
    OriginalSourceContinuationKindV5 as EdgeKind,
    OriginalSourceContinuationPrefixV5 as CurrentPrefix,
    derive_original_source_continuations_v5,
};

fn comparison(
    flight: &Flight,
) -> crate::ledger::native_completion::OriginalSourceAdmissionComparisonV5 {
    let keys = flight.keys();
    propose_original_source_applying_v5(
        views(&flight.before),
        puts(&flight.applying, &keys),
        &flight.provenance,
        d(102),
    )
    .unwrap()
    .admission_comparison()
    .unwrap()
}

fn own_floor_records(data: &OriginalSourceContinuationDataV5) -> usize {
    data.alternatives()
        .iter()
        .map(|branch| {
            branch
                .edges()
                .iter()
                .map(|edge| edge.values().len() + if edge.is_final() { 1 } else { 2 })
                .sum::<usize>()
        })
        .max()
        .unwrap()
}

#[test]
fn applying_projection_keeps_expensive_hot_and_actual_three_step_cold_families() {
    let flight = Flight::applying();
    let comparison = comparison(&flight);
    let data = derive_original_source_continuations_v5(
        views(&flight.applying),
        Some(&comparison),
        &flight.provenance,
        d(102),
    )
    .unwrap();

    assert_eq!(data.prefix(), CurrentPrefix::Applying);
    assert_eq!(data.current_records().count(), flight.applying.len());
    assert_eq!(own_floor_records(&data), 69); // Excludes ordinary co-settlement DEL.
    assert_eq!(
        data.alternatives().iter().map(|branch| branch.edges().len()).max(),
        Some(20),
    );
    assert!(data
        .alternatives()
        .iter()
        .flat_map(|branch| branch.edges())
        .any(|edge| {
            edge.kind() == EdgeKind::Held(SourceNativeHeldStepV1::CompletionCommitted)
                && edge.values().len() == 6
        }));
    assert!(data
        .alternatives()
        .iter()
        .flat_map(|branch| branch.edges())
        .any(|edge| {
            edge.kind() == EdgeKind::Cleanup(SourceNativeHeldLifecycleV1::ReleaseCompleted)
                && edge.values().iter().any(|value| value.key().len() == 95)
                && edge.values().len() == 6
                && edge.requires_independent_cut()
        }));

    let cold = data
        .alternatives()
        .iter()
        .find(|branch| matches!(branch.edges()[0].kind(), EdgeKind::PreRequestedCold(_)))
        .unwrap();
    assert_eq!(cold.edges().len(), 3);
    assert_eq!(
        cold.edges().iter().map(|edge| edge.values().len()).collect::<Vec<_>>(),
        [5, 1, 1],
    );
    for (index, fixed) in [1317, 2602, 3314].into_iter().enumerate() {
        let native = cold.edges()[index]
            .values()
            .iter()
            .find(|value| value.key().len() == 40)
            .unwrap();
        assert!(native.requires_source_floor_width());
        assert_eq!(native.maximum_value_bytes(), fixed);
        assert_eq!(cold.edges()[index].is_final(), index == 2);
    }
}

#[test]
fn historical_comparison_remains_separate_from_requested_current_graph() {
    let flight = Flight::applying();
    let comparison = comparison(&flight);
    let rows = flight.requested_rows();
    let data = derive_original_source_continuations_v5(
        views(&rows),
        Some(&comparison),
        &flight.provenance,
        d(102),
    )
    .unwrap();

    assert_eq!(data.prefix(), CurrentPrefix::Held(0));
    assert_eq!(comparison.original().prefix, Prefix::Applying);
    assert_eq!(own_floor_records(&data), 66);
    assert_eq!(
        data.alternatives().iter().map(|branch| branch.edges().len()).max(),
        Some(19),
    );
    assert!(data.alternatives().iter().all(|branch| {
        !matches!(branch.edges()[0].kind(), EdgeKind::FirstRequested | EdgeKind::PreRequestedCold(_))
    }));

    let key = native_completion::native_completion_key_v2(flight.held.original().acquisition_id);
    let requested = propose_original_source_requested_v5(
        views(&flight.applying),
        [(key.as_slice(), Some(rows[&key].as_slice()))],
        &flight.provenance,
        d(102),
    )
    .unwrap();
    assert!(requested.admission_comparison().is_err());
}

#[test]
fn complete_cut_refuses_duplicate_missing_foreign_and_unseeded_data() {
    let flight = Flight::applying();
    let comparison = comparison(&flight);
    let rows = flight.requested_rows();
    let mut duplicate = views(&rows).collect::<Vec<_>>();
    duplicate.push(duplicate[0]);

    assert!(derive_original_source_continuations_v5(
        duplicate, Some(&comparison), &flight.provenance, d(102),
    ).is_err());
    assert!(derive_original_source_continuations_v5(
        views(&rows), None, &flight.provenance, d(102),
    ).is_err());
    assert!(derive_original_source_continuations_v5(
        views(&rows), Some(&comparison), &flight.provenance, d(103),
    ).is_err());
    let mut missing = rows.clone();
    missing.remove(&flight.keys()[3]);
    assert!(derive_original_source_continuations_v5(
        views(&missing), Some(&comparison), &flight.provenance, d(102),
    ).is_err());
}

#[test]
fn response_headroom_is_attributed_to_each_actual_history_not_unknown_release() {
    let mut flight = Flight::applying();
    let keys = flight.keys();
    flight.graph.sessions[0].next_response_sequence = u64::MAX - 1;
    flight.applying.insert(
        keys[2].clone(),
        format::encode_session(&flight.graph.sessions[0]),
    );
    flight.applying.insert(
        keys[3].clone(),
        format::encode_session_history(&flight.graph.sessions[0]),
    );
    for (index, key) in keys[2..].iter().enumerate() {
        let decoded = format::decode_record(key, &flight.before[key]).unwrap();
        let mut holder = match decoded {
            crate::ledger::model::DecodedRecordV1::Session(value)
            | crate::ledger::model::DecodedRecordV1::SessionHistory(value) => value,
            _ => panic!("fixture Holder family"),
        };
        holder.next_response_sequence = u64::MAX - 1;
        let bytes = if index == 0 {
            format::encode_session(&holder)
        } else {
            format::encode_session_history(&holder)
        };
        flight.before.insert(key.clone(), bytes);
    }
    flight.provenance = provenance(&flight.graph, &flight.applying);
    let comparison = comparison(&flight);
    let rows = flight.requested_rows();

    let data = derive_original_source_continuations_v5(
        views(&rows),
        Some(&comparison),
        &flight.provenance,
        d(102),
    )
    .unwrap();

    // Original Complete increments this History exactly once to MAX. A future
    // independently admitted Release History is unresolved, not the old key.
    assert!(data
        .alternatives()
        .iter()
        .flat_map(|branch| branch.edges())
        .any(|edge| {
            edge.values()
                .iter()
                .any(|value| value.key().len() == 103 && value.is_symbolic_key())
        }));
}

#[test]
fn received_storage_prepared_branch_preserves_original_preparation_and_archive() {
    let requested = initial(request_tests::requested());
    let issued = advance(&requested, 1);
    let prepared = storage_prepared(&issued);

    transition::validate_step(
        Some(&issued),
        &prepared,
        SourceNativeHeldStepV1::StoragePrepared,
    )
    .unwrap();
    assert_eq!(issued.suffix().prepared(), prepared.suffix().prepared());
    assert!(prepared.suffix().control(Kind::StorageHeld).is_some());
    assert!(transition::validate_step(
        Some(&requested),
        &prepared,
        SourceNativeHeldStepV1::StoragePrepared,
    ).is_err());
    assert!(transition::validate_step(
        Some(&issued),
        &prepared,
        SourceNativeHeldStepV1::ChallengeSpent,
    ).is_err());
}
