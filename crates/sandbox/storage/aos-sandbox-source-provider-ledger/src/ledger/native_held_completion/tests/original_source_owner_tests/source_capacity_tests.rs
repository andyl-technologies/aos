//! UNRUN exact core/edge vectors using the unchanged private original Flight.
//!
//! Synthetic canonical signatures and clocks prove only DATA joins. No protected
//! configuration, original membership, challenge writer or live owner is created.

use super::*;
use crate::ledger::source_capacity::*;

fn seed(flight: &Flight) -> crate::ledger::native_completion::OriginalSourceAdmissionComparisonV5 {
    propose_original_source_applying_v5(
        views(&flight.before),
        puts(&flight.applying, &flight.keys()),
        &flight.provenance,
        d(102),
    )
    .unwrap()
    .admission_comparison()
    .unwrap()
}

fn origin<'a>(
    flight: &'a Flight,
    seed: &'a crate::ledger::native_completion::OriginalSourceAdmissionComparisonV5,
) -> OriginalSourceOwnerOriginInputV5<'a> {
    OriginalSourceOwnerOriginInputV5 {
        comparison: seed,
        provenance: &flight.provenance,
        retirement: None,
    }
}

#[test]
fn shared_ordinary_original_acquire_binding_and_original_exclusion_are_distinct() {
    let flight = Flight::applying();
    let comparison = seed(&flight);
    let legacy = derive_source_capacity_owner_data_v1(views(&flight.applying), &[]).unwrap();
    let expected = derive_native_acquire_ordinary_binding_v1(
        &flight.graph.acquisition, &flight.graph.attempts[0], &flight.graph.sessions[0], None,
    ).unwrap();

    assert_eq!(legacy.ordinary_bindings(), &[expected]);
    assert_eq!(expected.kind(), SourceOrdinaryCapacityKindV1::LegacyDispatchAcquire);
    let original = derive_source_capacity_owner_data_v1(
        views(&flight.applying), &[origin(&flight, &comparison)],
    ).unwrap();
    assert!(original.ordinary_bindings().is_empty());
    assert!(original.is_original(flight.graph.acquisition.acquisition_id));
    assert_eq!(original.originals().count(), 1);

    let mut wrong = flight.graph.sessions[0].clone();
    wrong.session_binding = d(232);
    assert!(derive_native_acquire_ordinary_binding_v1(
        &flight.graph.acquisition, &flight.graph.attempts[0], &wrong, None,
    ).is_err());
}

#[test]
fn applying_and_requested_inference_reuses_exact_proposers_and_real_semantic_order() {
    let flight = Flight::applying();
    let comparison = seed(&flight);
    let origins = [origin(&flight, &comparison)];
    let applying = compare_original_source_capacity_owner_edge_v5(
        views(&flight.before), views(&flight.applying), &origins, &[],
    ).unwrap();

    assert_eq!(applying.kind(), SourceCapacityOwnerEdgeKindV5::Applying);
    assert_eq!(applying.mutations().iter().map(|mutation| mutation.key()).collect::<Vec<_>>(),
        flight.provenance.claims().records.iter().map(|witness| witness.key()).collect::<Vec<_>>());
    let requested = flight.requested_rows();
    let edge = compare_original_source_capacity_owner_edge_v5(
        views(&flight.applying), views(&requested), &origins, &[],
    ).unwrap();
    assert_eq!(edge.kind(), SourceCapacityOwnerEdgeKindV5::Held(SourceNativeHeldStepV1::Requested));
    assert_eq!(edge.mutations().len(), 1);
    assert!(!edge.newly_retires_original_debt());
    assert!(edge.retirement().is_none());
    assert!(compare_original_source_capacity_owner_edge_v5(
        views(&requested), views(&requested), &origins, &[],
    ).is_err());
}

#[test]
fn challenge_edge_requires_actual_borrowed_key_bytes_and_rejects_substitution() {
    let flight = Flight::applying();
    let comparison = seed(&flight);
    let origins = [origin(&flight, &comparison)];
    let requested = flight.requested_rows();
    let issued = advance(&flight.held, 1);
    let native_key = native_completion::native_completion_key_v2(issued.original().acquisition_id);
    let mut after = requested.clone();
    after.insert(native_key, issued.to_canonical_bytes().unwrap());
    let key = graph::challenge_key(&issued);
    let bytes = challenge_bytes(issued.original(), false);
    let observed = OriginalSourceChallengeDataV5 {
        acquisition: issued.original().acquisition_id, key: &key, value: &bytes,
    };
    let edge = compare_original_source_capacity_owner_edge_v5(
        views(&requested), views(&after), &origins, &[observed],
    ).unwrap();

    assert_eq!(edge.kind(), SourceCapacityOwnerEdgeKindV5::Held(SourceNativeHeldStepV1::ChallengeIssued));
    assert!(compare_original_source_capacity_owner_edge_v5(
        views(&requested), views(&after), &origins, &[],
    ).is_err());
    let mut wrong_key = key.clone();
    wrong_key[39] ^= 1;
    let mut wrong_value = bytes.clone();
    wrong_value[20] ^= 1;
    for changed in [
        OriginalSourceChallengeDataV5 { key: &wrong_key, ..observed },
        OriginalSourceChallengeDataV5 { value: &wrong_value, ..observed },
        OriginalSourceChallengeDataV5 { acquisition: d(233), ..observed },
    ] {
        assert!(compare_original_source_capacity_owner_edge_v5(
            views(&requested), views(&after), &origins, &[changed],
        ).is_err());
    }
    assert!(compare_original_source_capacity_owner_edge_v5(
        views(&requested), views(&after), &origins, &[observed, observed],
    ).is_err());
    assert_eq!(bytes, challenge_bytes(issued.original(), false));
}

#[test]
fn independently_resealed_historical_quartet_cannot_substitute_for_current_origin() {
    let flight = Flight::applying();
    let comparison = seed(&flight);
    let mut changed = Flight::applying();
    changed.graph.sessions[0].next_response_sequence += 1;
    let keys = changed.keys();
    changed.applying.insert(keys[2].clone(), format::encode_session(&changed.graph.sessions[0]));
    changed.applying.insert(keys[3].clone(), format::encode_session_history(&changed.graph.sessions[0]));
    changed.provenance = provenance(&changed.graph, &changed.applying);
    let wrong = OriginalSourceOwnerOriginInputV5 {
        comparison: &comparison, provenance: &changed.provenance, retirement: None,
    };

    assert!(derive_source_capacity_owner_data_v1(views(&flight.requested_rows()), &[wrong]).is_err());
    assert!(crate::ledger::native_held_completion::validate_original_source_admission_provenance_v5(
        &comparison, &changed.provenance, d(102),
    ).is_err());
    assert!(derive_source_capacity_owner_data_v1(
        views(&flight.requested_rows()), &[origin(&flight, &comparison), origin(&flight, &comparison)],
    ).is_err());
    assert!(compare_original_source_capacity_owner_edge_v5(
        views(&flight.applying),
        views(&flight.requested_rows()),
        &[origin(&flight, &comparison), origin(&flight, &comparison)],
        &[],
    ).is_err());
}

fn completed_rows(flight: &Flight) -> Rows {
    let issued = advance(&flight.held, 1);
    let original = fixtures::prepared(issued.original());
    let prototype = storage_prepared(&advance(&initial(request_tests::requested()), 1));
    let witness = prototype
        .suffix()
        .control(Kind::StorageHeld)
        .unwrap()
        .prepared()
        .section(Tag::Witness)
        .unwrap()
        .to_vec();
    let root = issued.suffix().control(Kind::RootPrepared).unwrap();
    let reply = original.accepted_reply.as_ref().unwrap();
    let storage = PreparedNativeHeldControlV1::new(
        Kind::StorageHeld,
        evidence::full_scope(&issued).unwrap(),
        root.digest(),
        vec![
            section(Tag::Witness, witness),
            section(Tag::RootPrepared, root.to_canonical_bytes()),
            section(Tag::NativeReply, reply.to_canonical_bytes()),
        ],
        NativeHeldSignerV1::Storage(reply.acceptance().signer()),
    )
    .unwrap()
    .with_signature([0xA2; 64]);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        2,
        issued.suffix().flight(),
        None,
        vec![root.clone(), storage],
    )
    .unwrap();
    let prepared = SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap();
    let spent = advance(&prepared, 3);
    let mut rows = flight.requested_rows();
    let key = native_completion::native_completion_key_v2(spent.original().acquisition_id);
    rows.insert(key, spent.to_canonical_bytes().unwrap());
    fixtures::completion_rows(&rows, &spent)
}

fn fault_only_phase9(
    complete: &SourceNativeHeldCompletionRecordV1,
) -> SourceNativeHeldCompletionRecordV1 {
    use aos_sandbox_source_provider_protocol::native_held_completion::assertion::{
        NativeHeldSettlementV1, ProviderNativeSettlementAssertionV1,
        StorageNativeSettlementAssertionV1,
    };

    let closed = cold_closed(complete);
    let relay = closed.suffix().prepared().unwrap().clone().with_signature([0xA5; 64]);
    let disposition = evidence::root_disposition(&closed).unwrap().unwrap();
    let reply = complete.original().accepted_reply.as_ref().unwrap();
    let assertion = StorageNativeSettlementAssertionV1 {
        disposition: disposition.disposition,
        scope: evidence::full_scope(complete).unwrap(),
        root_disposition: disposition.digest().unwrap(),
        acceptance: reply.acceptance().acceptance().clone(),
    };
    let mut settlement = NativeHeldSettlementV1 {
        disposition: disposition.disposition,
        root_disposition: assertion.root_disposition,
        storage_settlement: assertion.digest().unwrap(),
        provider_settlement: d(0),
    };
    let original_storage = complete.suffix().control(Kind::StorageHeld).unwrap();
    let storage = PreparedNativeHeldControlV1::new(
        Kind::StorageSettled,
        assertion.scope,
        relay.digest(),
        vec![
            section(Tag::Witness, original_storage.prepared().section(Tag::Witness).unwrap().to_vec()),
            section(Tag::Settlement, settlement.to_canonical_bytes().unwrap().to_vec()),
        ],
        original_storage.prepared().signer().clone(),
    )
    .unwrap()
    .with_signature([0xA6; 64]);
    settlement.provider_settlement = ProviderNativeSettlementAssertionV1 {
        disposition: disposition.disposition,
        scope: assertion.scope,
        root_disposition: settlement.root_disposition,
        storage_settlement: settlement.storage_settlement,
        source_artifact: d(0),
    }
    .digest()
    .unwrap();

    let provider = PreparedNativeHeldControlV1::new(
        Kind::ProviderSettled,
        assertion.scope,
        storage.digest(),
        vec![
            section(Tag::Witness, provider_witness(complete)),
            section(Tag::Settlement, settlement.to_canonical_bytes().unwrap().to_vec()),
        ],
        NativeHeldSignerV1::SourceProvider(
            complete.original().canonical_request.as_ref().unwrap().signer().clone(),
        ),
    )
    .unwrap()
    .with_signature([0xA7; 64]);

    let mut controls = closed.suffix().controls().to_vec();
    controls.extend([relay, storage, provider]);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        9,
        complete.suffix().flight(),
        None,
        controls,
    )
    .unwrap();
    let mut original = complete.original().clone();
    original.revision += 5;
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

#[test]
fn exact_fault_only_phase9_retirement_does_not_require_a_nonexistent_future() {
    let flight = Flight::applying();
    let comparison = seed(&flight);
    let native_key = native_completion::native_completion_key_v2(comparison.original().acquisition_id);
    let mut before = completed_rows(&flight);
    let complete = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&native_key, &before[&native_key]).unwrap();
    let fault = fault_only_phase9(&complete);
    before.insert(native_key.clone(), fault.to_canonical_bytes().unwrap());
    crate::validate_current_records(&before).unwrap();

    let mut marked = fault.original().advance(Outer::CleanupRequired).unwrap();
    marked.revision = fault.original().revision + 1;
    let marked = SourceNativeHeldCompletionRecordV1::new(marked, fault.suffix().clone()).unwrap();
    let mut after = before.clone();
    after.insert(native_key.clone(), marked.to_canonical_bytes().unwrap());
    let edge = compare_original_source_capacity_owner_edge_v5(
        views(&before), views(&after), &[origin(&flight, &comparison)], &[],
    ).unwrap();
    let retirement = edge.retirement().unwrap();

    assert!(edge.newly_retires_original_debt());
    assert_eq!(retirement.kind(), SourceCapacityOwnerEdgeKindV5::Lifecycle(
        SourceNativeHeldLifecycleV1::OriginalCustodyMarked,
    ));
    let retired = derive_source_capacity_owner_data_v1(
        views(&after), &[OriginalSourceOwnerOriginInputV5 {
            retirement: Some(retirement), ..origin(&flight, &comparison)
        }],
    ).unwrap();
    assert!(retired.is_original(comparison.original().acquisition_id));
    assert_eq!(retired.retired_originals().count(), 1);
    assert_eq!(retired.originals().count(), 0);
    assert!(retired.ordinary_bindings().is_empty());

    let disposition = evidence::root_disposition(&marked).unwrap().unwrap();
    let query = recovery_tests::recovery_query(&marked, disposition);
    let mut controls = marked.suffix().controls().to_vec();
    controls.push(query);
    let recovered = recovery_tests::changed(&marked, 9, None, controls);
    let mut recovery_after = after.clone();
    recovery_after.insert(native_key.clone(), recovered.to_canonical_bytes().unwrap());
    let carried = compare_original_source_capacity_owner_edge_v5(
        views(&after),
        views(&recovery_after),
        &[OriginalSourceOwnerOriginInputV5 {
            retirement: Some(retirement),
            ..origin(&flight, &comparison)
        }],
        &[],
    ).unwrap();

    assert_eq!(carried.kind(), SourceCapacityOwnerEdgeKindV5::Held(
        SourceNativeHeldStepV1::RootRecoveryRecorded,
    ));
    assert!(!carried.newly_retires_original_debt());
    assert_eq!(carried.retirement().unwrap().kind(), retirement.kind());
    assert!(derive_source_capacity_owner_data_v1(
        views(&recovery_after),
        &[OriginalSourceOwnerOriginInputV5 {
            retirement: carried.retirement(),
            ..origin(&flight, &comparison)
        }],
    ).is_ok());
    assert!(derive_source_capacity_owner_data_v1(
        views(&recovery_after),
        &[OriginalSourceOwnerOriginInputV5 {
            retirement: Some(retirement),
            ..origin(&flight, &comparison)
        }],
    ).is_err());

    assert!(derive_source_capacity_owner_data_v1(
        views(&after), &[origin(&flight, &comparison)],
    ).is_err());
    let mut substituted = after.clone();
    let changed = advance(&marked, 9);
    substituted.insert(native_key, changed.to_canonical_bytes().unwrap());
    assert!(derive_source_capacity_owner_data_v1(
        views(&substituted), &[OriginalSourceOwnerOriginInputV5 {
            retirement: Some(retirement), ..origin(&flight, &comparison)
        }],
    ).is_err());
}
