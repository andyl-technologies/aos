//! UNRUN signed Pending, exact four-owner and additive cut refusal vectors.
//!
//! These pure fixtures model verifier output; they do not mint actual carrier,
//! clock, protected writer or signer custody and are not qualification evidence.

use super::*;

#[path = "../../ordinary_inventory_v6/tests.rs"]
mod ordinary_inventory_vectors;

fn pending_graphs() -> (Fixture, RootNativeHeldGraphV2, RootNativeHeldGraphV2) {
    let fixture = Fixture::new(true);
    let root1 = sign(fixture.prepared());
    let mut before = fixture.legacy.clone();
    let key = native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap();
    before.insert(
        key.clone(),
        sidecar(&fixture, &fixture.phase1(), None).to_canonical_bytes().unwrap(),
    );
    let before = checked_v2(&before).unwrap();

    let mut rows = fixture::pending_original_rows(&fixture.legacy);
    let state = validate_mount_source_state_graph_v2(
        rows.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Disposition,
        [161; 16],
        &state,
        fixture.attempt.attempt_id,
    )
    .unwrap();
    let captured = cut.reconstruct(&state, fixture.attempt.attempt_id).unwrap();
    let r = RootNativeDispositionAssertionV1 {
        disposition: NativeHeldDispositionV1::Closed,
        observation: RootNativeObservationV1::PreparedOnly,
        scope: fixture.scope,
        source_artifact: digest(0),
        descriptor_commitment: digest(0),
        records: captured.witnesses().clone(),
    };
    let mut witness = fixture.witness.clone();
    witness.journal_sequence += 8;
    witness.records = r.records.clone();
    let eight = PreparedNativeHeldControlV1::new(
        Kind::RootClosed,
        fixture.scope,
        root1.digest(),
        vec![
            NativeHeldSectionV1::new(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Root(witness).to_canonical_bytes().unwrap(),
            )
            .unwrap(),
            NativeHeldSectionV1::new(Tag::RootPrepared, root1.to_canonical_bytes()).unwrap(),
            NativeHeldSectionV1::new(
                Tag::RootDispositionAssertion,
                r.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        root1.prepared().signer().clone(),
    )
    .unwrap();
    let value = RootNativeHeldSidecarV2::new(
        fixture.scope,
        [0; 16],
        Some(r),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            10,
            fixture.scope.flight,
            Some(eight),
            vec![root1],
        )
        .unwrap(),
        admission(&fixture),
        Some(cut),
        None,
    )
    .unwrap();
    rows.insert(key, value.to_canonical_bytes().unwrap());
    let after = checked_v2(&rows).unwrap();
    (fixture, before, after)
}

#[test]
fn original_pending_is_exact_four_owner_closed_with_three_remaining_transactions() {
    let (fixture, before, after) = pending_graphs();
    let attempt = fixture.attempt.attempt_id;
    let proposal =
        validate_original_pending_closed_transition_v5(&before, &after, attempt, [161; 16]).unwrap();

    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV2::OriginalPendingClosedRecorded,
    );
    assert_eq!(proposal.puts.len(), 4);
    assert_eq!(proposal.maximum_remaining_transactions, 3);
    assert_eq!(original_root_remaining_v5(&before, attempt).unwrap(), 6);
    assert_eq!(original_root_remaining_v5(&after, attempt).unwrap(), 3);
    assert_eq!(after.sidecars()[&attempt].response_transaction(), [0; 16]);
    assert!(has_original_pending_closed_cut_v5(&after, &after.sidecars()[&attempt]).unwrap());
    assert_eq!(
        after.data_class(attempt),
        Some(RootNativeDataClassV2::LiveOriginal),
    );
}

#[test]
fn pending_owner_cannot_use_generic_complete_cold_or_changed_capture_transaction() {
    let (fixture, before, after) = pending_graphs();
    let attempt = fixture.attempt.attempt_id;

    assert!(validate_native_root_transition_v2(&before, &after, attempt, [161; 16]).is_err());
    assert!(validate_native_root_cold_transition_v2(&before, &after, attempt, [161; 16]).is_err());
    assert!(validate_original_pending_closed_transition_v5(&before, &after, attempt, [162; 16]).is_err());
    assert!(validate_original_pending_closed_transition_v5(&after, &after, attempt, [161; 16]).is_err());
}

#[test]
fn pending_tag6_roundtrips_and_rejects_admission_unknown_or_unbalanced_companions() {
    let (fixture, _, after) = pending_graphs();
    let cut = after.sidecars()[&fixture.attempt.attempt_id]
        .disposition_cut()
        .unwrap();
    let bytes = cut.to_canonical_bytes().unwrap();

    assert_eq!(&bytes[..16], b"AOSMNC01\0\x01\x02\x06\0\0\0\0");
    assert_eq!(RootNativeCutV1::from_canonical_bytes(&bytes).unwrap(), *cut);
    for (offset, replacement) in [(10, 1), (11, 7), (11, 255)] {
        let mut changed = bytes.clone();
        changed[offset] = replacement;
        assert!(RootNativeCutV1::from_canonical_bytes(&changed).is_err());
    }
    let mut head = cut.head().clone();
    head.next_response_sequence += 1;
    let head = serde_json::to_vec(&head).unwrap();
    let old_head_length = serde_json::to_vec(cut.head()).unwrap().len();
    let mut changed = bytes[..152].to_vec();
    changed[144..148].copy_from_slice(&(head.len() as u32).to_be_bytes());
    changed.extend_from_slice(&head);
    changed.extend_from_slice(&bytes[152 + old_head_length..]);
    assert!(RootNativeCutV1::from_canonical_bytes(&changed).is_err());
}

#[test]
fn pending_data_counts_agree_after_exact_disposition_signature_store() {
    let (fixture, _, after) = pending_graphs();
    let attempt = fixture.attempt.attempt_id;
    let old = &after.sidecars()[&attempt];
    let mut controls = old.suffix().controls().to_vec();
    controls.push(sign(old.suffix().prepared().unwrap().clone()));
    let stored = RootNativeHeldSidecarV2::new(
        *old.original_scope(),
        [0; 16],
        old.disposition().cloned(),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(Owner::Root, 11, old.suffix().flight(), None, controls)
            .unwrap(),
        old.admission_cut().clone(),
        old.disposition_cut().cloned(),
        None,
    )
    .unwrap();
    let mut rows = after.canonical_records().clone();
    rows.insert(
        native_root_sidecar_key_v2(attempt).unwrap(),
        stored.to_canonical_bytes().unwrap(),
    );
    let stored_graph = checked_v2(&rows).unwrap();

    let proposal = validate_native_root_transition_v2(&after, &stored_graph, attempt, [163; 16]).unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV2::DispositionStored);
    assert_eq!(proposal.maximum_remaining_transactions, 2);
    assert_eq!(original_root_remaining_v5(&stored_graph, attempt).unwrap(), 2);
}
