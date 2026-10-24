//! Actual signed replacement, Inventory and dedicated no-dispatch v2 vectors.

use super::*;
use crate::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, ProviderAttemptStateV2, SourceAcquisitionPhaseV2,
    SourceAcquisitionTableV2,
    validation::native_settlement_tests::{
        canonical_records, later_unrelated_barrier_graph, native_absence_stages,
        reserve_later_acquire, settled_unresolved_graph,
    },
};

fn graph(
    table: &SourceAcquisitionTableV2,
    value: &RootNativeHeldSidecarV2,
) -> RootNativeHeldGraphV2 {
    let mut records = canonical_records(table);
    records.insert(
        native_root_sidecar_key_v2(*value.original_scope().mount_attempt.as_bytes()).unwrap(),
        value.to_canonical_bytes().unwrap(),
    );
    checked_v2(&records).unwrap()
}

fn closed(fixture: &Fixture) -> (RootNativeHeldSidecarV2, RootNativeHeldSidecarV2) {
    let one = sign(fixture.prepared());
    let r = fixture.closed();
    let eight = PreparedNativeHeldControlV1::new(
        Kind::RootClosed,
        fixture.scope,
        one.digest(),
        vec![
            fixture.w(),
            NativeHeldSectionV1::new(Tag::RootPrepared, one.to_canonical_bytes()).unwrap(),
            NativeHeldSectionV1::new(
                Tag::RootDispositionAssertion,
                r.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        one.prepared().signer().clone(),
    )
    .unwrap();
    let cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Disposition,
        [140; 16],
        &legacy(fixture),
        fixture.attempt.attempt_id,
    )
    .unwrap();
    let prepared = fixture.sidecar(10, Some(eight.clone()), vec![one.clone()], Some(r.clone()));
    let stored = fixture.sidecar(11, None, vec![one, sign(eight)], Some(r));
    (
        sidecar(fixture, &prepared, Some(cut.clone())),
        sidecar(fixture, &stored, Some(cut)),
    )
}

fn terminal(
    old: &RootNativeHeldSidecarV2,
    table: &SourceAcquisitionTableV2,
) -> RootNativeHeldSidecarV2 {
    let attempt = &table.provider_attempts[old.original_scope().mount_attempt.as_bytes()];
    let row = &table.acquisitions[&attempt.owner.owner_id()];
    let mut value = old.clone();
    value.claims.suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Root,
        old.suffix().phase(),
        old.original_scope().flight,
        None,
        old.suffix().controls().to_vec(),
    )
    .unwrap();
    // The exact Sandbox old-floor join/deletion is deliberately a separate
    // contract. Nonzero DATA IDs here cannot manufacture that protected proof.
    value.no_interest_terminal = Some(RootNativeNoInterestTerminalV1 {
        cleanup_transaction: [144; 16],
        closed_disposition: old.disposition().unwrap().digest().unwrap(),
        settled_attempt: RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        },
        faulted_acquisition: RecordRefV2 {
            id: row.acquisition_id,
            revision: row.revision,
            record_digest: row.record_digest,
        },
        retired_capacity_id: [145; 32],
        retired_capacity_digest: [146; 32],
    });
    value
}

fn later_fixture(table: &SourceAcquisitionTableV2) -> Fixture {
    let head = table.provider_heads.values().next().unwrap();
    let attempt = table.provider_attempts[&head.pending_attempt.unwrap().id].clone();
    let session = table.provider_sessions[&attempt.session_id].clone();
    let legacy = canonical_records(table);
    let signed =
        aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &attempt.signed_request,
        )
        .unwrap();
    let request =
        aos_sandbox_source_provider_protocol::decode_acquire_request(signed.subject()).unwrap();
    let catalog = request.native_catalog().unwrap();
    let keys = [
        provider_session_key(session.session_id),
        provider_attempt_key(attempt.attempt_id),
        acquisition_key(attempt.owner.owner_id()),
        provider_head_key(
            session.scope.holder_authority_id,
            session.scope.provider_authority_id,
        ),
    ];
    let records = keys
        .into_iter()
        .zip(ROOT_NATIVE_WITNESS_FAMILIES_V1)
        .map(|(key, family)| {
            let commitment =
                native_held_record_byte_digest_v1(family, &key, &legacy[&key]).unwrap();
            NativeHeldByteWitnessV1::new(family, key, commitment).unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let root_request = ObjectDigest::from_bytes(attempt.signed_request_digest);
    let mount_attempt = ObjectDigest::from_bytes(attempt.attempt_id);
    let source_session = ObjectDigest::from_bytes(session.session_binding);
    let scope = NativeHeldScopeV1 {
        flight: native_held_flight_digest_v1(root_request, mount_attempt, source_session),
        original_source_session: source_session,
        mount_attempt,
        provider_attempt: digest(0),
        provider_acquisition: ObjectDigest::from_bytes(
            attempt.provider_acquisition.unwrap().acquisition_id,
        ),
        original_root_request: root_request,
        original_native_request: digest(0),
    };
    let witness = RootNativeHeldWitnessV1 {
        local_socket_cookie: 7,
        journal_sequence: 160,
        planning_sequence: 1,
        trust: NativeHeldGenerationClaimV1 {
            generation: session.trust_generation,
            digest: ObjectDigest::from_bytes(session.trust_digest),
        },
        revocation: NativeHeldGenerationClaimV1 {
            generation: session.revocation_generation,
            digest: ObjectDigest::from_bytes(session.revocation_digest),
        },
        provider_head: NativeHeldGenerationClaimV1 {
            generation: catalog.head().0,
            digest: catalog.head().1,
        },
        provider_floor: NativeHeldGenerationClaimV1 {
            generation: catalog.floor().0,
            digest: catalog.floor().1,
        },
        publication: catalog.canonical_publication_digest(),
        records,
    };
    Fixture {
        legacy,
        session,
        attempt,
        scope,
        witness,
    }
}

#[test]
fn subsequent_native_admission_captures_actual_reserved_head_and_retains_old_terminal_and_floor() {
    let original = Fixture::new(true);
    let stages = native_absence_stages();
    let (_, stored) = closed(&original);
    let old_terminal = terminal(&stored, &stages.settled);
    let before = graph(&stages.settled, &old_terminal);
    let next_table = reserve_later_acquire(stages.settled, true);
    let fixture = later_fixture(&next_table);
    let capture = RootNativeCutV1::capture(
        RootNativeCutKindV1::Admission,
        [160; 16],
        &next_table,
        fixture.attempt.attempt_id,
    )
    .unwrap();
    let claims = fixture.phase0();
    let value = RootNativeHeldSidecarV2::new(
        *claims.original_scope(),
        [0; 16],
        None,
        None,
        None,
        claims.suffix().clone(),
        capture,
        None,
        None,
    )
    .unwrap();
    let mut records = canonical_records(&next_table);
    let old_key = native_root_sidecar_key_v2(original.attempt.attempt_id).unwrap();
    records.insert(old_key.clone(), old_terminal.to_canonical_bytes().unwrap());
    records.insert(
        native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap(),
        value.to_canonical_bytes().unwrap(),
    );
    let after = checked_v2(&records).unwrap();
    let proposal =
        validate_native_root_transition_v2(&before, &after, fixture.attempt.attempt_id, [160; 16])
            .unwrap();

    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV2::PreparedAssertionRecorded
    );
    assert_eq!(proposal.puts.len(), 5);
    assert_eq!(proposal.maximum_remaining_transactions, 7);
    assert!(!proposal.puts.contains_key(&old_key));
    assert_eq!(
        before.canonical_records()[&old_key],
        after.canonical_records()[&old_key]
    );
    let previous_head = before.legacy().provider_heads.values().next().unwrap();
    let reserved_head = after.legacy().provider_heads.values().next().unwrap();
    assert_ne!(value.admission_cut().head(), previous_head);
    assert_eq!(value.admission_cut().head(), reserved_head);
    assert_eq!(
        value.admission_cut().head().inventory_floor,
        previous_head.inventory_floor
    );
    assert_eq!(
        value.admission_cut().head().inventory_observation_ordinal,
        previous_head.inventory_observation_ordinal
    );
    assert!(previous_head.inventory_floor.is_some());
    assert_eq!(value.admission_cut().acquisition().record.revision, 1);
    assert_eq!(
        proposal
            .admission_binding
            .unwrap()
            .original
            .reserved_head_digest,
        reserved_head.record_digest
    );
}

#[test]
fn first_r_after_actual_absent_resolution_captures_prior_three_without_reviving_hot_custody() {
    let fixture = Fixture::new(true);
    let stages = native_absence_stages();
    let phase1 = sidecar(&fixture, &fixture.phase1(), None);
    let before = graph(&stages.resolved, &phase1);
    let cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Disposition,
        [161; 16],
        &stages.resolved,
        fixture.attempt.attempt_id,
    )
    .unwrap();
    let reconstructed = cut
        .reconstruct(&stages.resolved, fixture.attempt.attempt_id)
        .unwrap();
    let mut r = fixture.closed();
    r.records = reconstructed.witnesses().clone();
    let one = sign(fixture.prepared());
    let claims = fixture.sidecar(10, None, vec![one.clone()], Some(r.clone()));
    let value = sidecar(&fixture, &claims, Some(cut.clone()));
    let after = graph(&stages.resolved, &value);
    let proposal = validate_native_root_cold_transition_v2(
        &before,
        &after,
        fixture.attempt.attempt_id,
        [161; 16],
    )
    .unwrap();

    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV2::ClosedAssertionRecorded
    );
    assert_eq!(proposal.maximum_remaining_transactions, 1);
    assert_ne!(value.admission_cut(), &cut);
    assert_eq!(
        &cut.to_canonical_bytes().unwrap()[..16],
        b"AOSMNC01\0\x01\x02\x05\0\0\0\0"
    );
    assert_eq!(cut.original_attempt(fixture.attempt.attempt_id).revision, 3);
    assert_eq!(
        after.data_class(fixture.attempt.attempt_id),
        Some(RootNativeDataClassV2::ClosedRecoveryPending)
    );
    let mut witness = fixture.witness.clone();
    witness.records = r.records.clone();
    let eight = PreparedNativeHeldControlV1::new(
        Kind::RootClosed,
        fixture.scope,
        one.digest(),
        vec![
            NativeHeldSectionV1::new(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Root(witness)
                    .to_canonical_bytes()
                    .unwrap(),
            )
            .unwrap(),
            NativeHeldSectionV1::new(Tag::RootPrepared, one.to_canonical_bytes()).unwrap(),
            NativeHeldSectionV1::new(
                Tag::RootDispositionAssertion,
                r.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        one.prepared().signer().clone(),
    )
    .unwrap();
    let preparation = sidecar(
        &fixture,
        &fixture.sidecar(10, Some(eight.clone()), vec![one.clone()], Some(r.clone())),
        Some(cut.clone()),
    );
    let stored = sidecar(
        &fixture,
        &fixture.sidecar(11, None, vec![one, sign(eight)], Some(r)),
        Some(cut.clone()),
    );
    assert!(
        validate_native_root_transition_v2(
            &graph(&stages.resolved, &preparation),
            &graph(&stages.resolved, &stored),
            fixture.attempt.attempt_id,
            [162; 16],
        )
        .is_err()
    );

    let settled = terminal(&value, &stages.settled);
    let terminal_graph = graph(&stages.settled, &settled);
    let historical = cut
        .reconstruct(terminal_graph.legacy(), fixture.attempt.attempt_id)
        .unwrap();
    assert_eq!(
        historical.canonical_records(),
        reconstructed.canonical_records()
    );
    let final_proposal = validate_native_root_cold_transition_v2(
        &after,
        &terminal_graph,
        fixture.attempt.attempt_id,
        [144; 16],
    )
    .unwrap();
    assert_eq!(final_proposal.maximum_remaining_transactions, 0);
}

#[test]
fn genuine_signed_inventory_prefix_has_exact_four_two_four_four_puts_and_before_images() {
    let fixture = Fixture::new(true);
    let stages = native_absence_stages();
    assert_eq!(canonical_records(&stages.initial), fixture.legacy);
    let phase1 = sidecar(&fixture, &fixture.phase1(), None);
    let (prepared, stored) = closed(&fixture);
    let initial = graph(&stages.initial, &phase1);
    let prepared_graph = graph(&stages.initial, &prepared);
    let stored_graph = graph(&stages.initial, &stored);
    let replacement = graph(&stages.replacement, &stored);
    let reserved = graph(&stages.inventory_reserved, &stored);
    let resolved = graph(&stages.resolved, &stored);
    let terminal = terminal(&stored, &stages.settled);
    let settled = graph(&stages.settled, &terminal);
    let attempt_id = fixture.attempt.attempt_id;

    let r =
        validate_native_root_cold_transition_v2(&initial, &prepared_graph, attempt_id, [140; 16])
            .unwrap();
    assert_eq!(r.kind, RootNativeTransitionKindV2::ClosedAssertionRecorded);
    assert_eq!(r.maximum_remaining_transactions, 5);
    let signature =
        validate_native_root_transition_v2(&prepared_graph, &stored_graph, attempt_id, [141; 16])
            .unwrap();
    assert_eq!(signature.maximum_remaining_transactions, 4);

    for (before, after, kind, count, remaining, transaction) in [
        (
            &stored_graph,
            &replacement,
            RootNativeTransitionKindV2::NativeRecoveryReplacement,
            4,
            3,
            [142; 16],
        ),
        (
            &replacement,
            &reserved,
            RootNativeTransitionKindV2::NativeRecoveryInventoryReserved,
            2,
            2,
            [143; 16],
        ),
        (
            &reserved,
            &resolved,
            RootNativeTransitionKindV2::NativeRecoveryInventoryResolved,
            4,
            1,
            [147; 16],
        ),
        (
            &resolved,
            &settled,
            RootNativeTransitionKindV2::NativeNoInterestCleanup,
            4,
            0,
            [144; 16],
        ),
    ] {
        let immutable_before = before.canonical_records().clone();
        let proposal =
            validate_native_root_cold_transition_v2(before, after, attempt_id, transaction)
                .unwrap();
        assert_eq!(proposal.kind, kind);
        assert_eq!(proposal.puts.len(), count);
        assert_eq!(proposal.maximum_remaining_transactions, remaining);
        assert!(proposal.admission_binding.is_none());
        for key in proposal.puts.keys() {
            assert_eq!(
                proposal.before_images[key].as_ref(),
                immutable_before.get(key)
            );
        }
        assert_eq!(*before.canonical_records(), immutable_before);
        assert_eq!(
            after.sidecars()[&attempt_id].admission_cut(),
            stored.admission_cut()
        );
        assert_eq!(
            after.sidecars()[&attempt_id].disposition_cut(),
            stored.disposition_cut()
        );
    }

    let reserved_head = reserved.legacy().provider_heads.values().next().unwrap();
    assert!(reserved_head.pending_attempt.is_some());
    assert!(
        reserved_head
            .recovery_barrier
            .as_ref()
            .unwrap()
            .recovery_inventory_tail
            .is_none()
    );
    for (checked, revision) in [
        (&initial, 1),
        (&replacement, 2),
        (&resolved, 3),
        (&settled, 4),
    ] {
        let row = &checked.legacy().acquisitions[&fixture.attempt.owner.owner_id()];
        let attempt = &checked.legacy().provider_attempts[&attempt_id];
        assert_eq!(row.acquire_lineage.root, row.acquire_lineage.tail);
        assert_eq!(row.acquire_lineage.root.revision, revision);
        assert_eq!(
            row.acquire_lineage.root.record_digest,
            attempt.record_digest
        );
    }
    assert_eq!(
        replacement.data_class(attempt_id),
        Some(RootNativeDataClassV2::ClosedRecoveryPending)
    );
    assert_eq!(
        settled.data_class(attempt_id),
        Some(RootNativeDataClassV2::NoInterestTerminal)
    );
    let marker_bytes = terminal
        .no_interest_terminal()
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    assert_eq!(marker_bytes.len(), 272);
    assert_eq!(
        u64::from_be_bytes(marker_bytes[96..104].try_into().unwrap()),
        4
    );
    assert!(
        validate_native_root_transition_v2(&resolved, &settled, attempt_id, [148; 16]).is_err()
    );
}

#[test]
fn direct_prior_two_cleanup_erases_only_unescaped_unsigned_eight_and_retains_signed_archives() {
    let fixture = Fixture::new(true);
    let stages = native_absence_stages();
    let (prepared, _) = closed(&fixture);
    let before = graph(&stages.replacement, &prepared);
    let table = settled_unresolved_graph();
    let value = terminal(&prepared, &table);
    let after = graph(&table, &value);
    let proposal = validate_native_root_cold_transition_v2(
        &before,
        &after,
        fixture.attempt.attempt_id,
        [144; 16],
    )
    .unwrap();

    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV2::NativeNoInterestCleanup
    );
    assert_eq!(proposal.maximum_remaining_transactions, 0);
    assert_eq!(proposal.puts.len(), 4);
    assert!(value.suffix().prepared().is_none());
    assert_eq!(value.suffix().controls(), prepared.suffix().controls());
    assert_eq!(
        value
            .no_interest_terminal()
            .unwrap()
            .settled_attempt()
            .revision,
        3
    );
    let row = &after.legacy().acquisitions[&fixture.attempt.owner.owner_id()];
    assert_eq!(row.phase, SourceAcquisitionPhaseV2::Faulted);
    assert_eq!(
        row.faulted_from,
        Some(SourceAcquisitionPhaseV2::PendingQuery)
    );
    assert_eq!(row.recovery, AcquisitionRecoveryV2::Ready);
    assert!(row.evidence.is_none());
    assert!(matches!(
        after.legacy().provider_attempts[&fixture.attempt.attempt_id].state,
        ProviderAttemptStateV2::NativeNoDispatchSettled { .. }
    ));
}

#[test]
fn historical_no_interest_survives_genuine_different_current_barrier_without_recreating_hot_cut() {
    let fixture = Fixture::new(true);
    let (_, stored) = closed(&fixture);
    let original_terminal = native_absence_stages().settled;
    let value = terminal(&stored, &original_terminal);
    let current = later_unrelated_barrier_graph();
    let checked = graph(&current, &value);
    let head = checked.legacy().provider_heads.values().next().unwrap();

    assert_ne!(
        head.recovery_barrier.as_ref().unwrap().root_attempt.id,
        fixture.attempt.attempt_id
    );
    assert_eq!(
        checked.data_class(fixture.attempt.attempt_id),
        Some(RootNativeDataClassV2::NoInterestTerminal)
    );
    assert!(!super::super::super::graph_v2::current_companions_equal(
        &checked,
        &value
            .disposition_cut()
            .unwrap()
            .reconstruct(checked.legacy(), fixture.attempt.attempt_id)
            .unwrap(),
    ));
    assert!(
        validate_native_root_transition_v2(
            &graph(&original_terminal, &value),
            &checked,
            fixture.attempt.attempt_id,
            [149; 16],
        )
        .is_err()
    );
    // This is an independent ordinary DATA graph, not a native old-flight slot.
    // The missing own-reserved ordinary adapter remains outside this proposal.
}

#[test]
fn stale_root_tail_or_marker_companions_are_rejected_without_repair() {
    let fixture = Fixture::new(true);
    let stages = native_absence_stages();
    let (_, stored) = closed(&fixture);
    let id = fixture.attempt.owner.owner_id();
    for root in [true, false] {
        let mut table = stages.replacement.clone();
        let row = table.acquisitions.get_mut(&id).unwrap();
        if root {
            row.acquire_lineage.root.record_digest[0] ^= 1;
        } else {
            row.acquire_lineage.tail = RecordRefV2 {
                id: [153; 32],
                revision: 2,
                record_digest: [154; 32],
            };
        }
        row.record_digest =
            record_digest(&StoredRecordV2::Acquisition { value: row.clone() }).unwrap();
        let mut records = canonical_records(&table);
        records.insert(
            native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap(),
            stored.to_canonical_bytes().unwrap(),
        );
        let retained = records.clone();
        assert!(checked_v2(&records).is_err());
        assert_eq!(records, retained);
    }

    let mut value = terminal(&stored, &stages.settled);
    value
        .no_interest_terminal
        .as_mut()
        .unwrap()
        .faulted_acquisition
        .record_digest[0] ^= 1;
    let mut records = canonical_records(&stages.settled);
    records.insert(
        native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap(),
        value.to_canonical_bytes().unwrap(),
    );
    assert!(checked_v2(&records).is_err());
}
