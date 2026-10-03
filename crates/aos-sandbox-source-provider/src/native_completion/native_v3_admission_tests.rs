//! Protected-row V3 no-dispatch replay and terminal-capacity fixtures.
//!
//! These tests use real signed artifacts, strict graph validation and protected
//! writer/reopen/terminal primitives. They do not mint installed ingress,
//! signer custody, Storage acceptance or a positive native bridge.

use super::*;

fn native_no_dispatch_graph() -> (Graph, AcquireSourceRequestV1) {
    let mut graph = Graph::applying();
    let original = graph
        .native
        .canonical_request
        .as_ref()
        .unwrap()
        .request()
        .signed_root_request();
    let legacy = decode_acquire_request(original.subject()).unwrap();
    let mut commitment = Sha256::new();
    commitment.update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0");
    commitment.update(encode_catalog(&graph.catalog));
    let claims = NativeAcquireCatalogBindingV3::new(
        graph.catalog.resource_namespace_digest,
        graph.catalog.catalog_generation,
        graph.catalog.catalog_digest,
        graph.catalog.catalog_floor_generation,
        graph.catalog.catalog_floor_digest,
        ObjectDigest::from_bytes(commitment.finalize().into()),
        ObjectDigest::from_bytes(Sha256::digest(&graph.catalog.canonical_publication).into()),
    )
    .unwrap();
    let request = AcquireSourceRequestV1::new_native_v3(legacy, claims).unwrap();
    let signed = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&request),
        original.signer().clone(),
        &SigningKey::from_bytes(&[51; 32]),
    )
    .unwrap();
    let session = &graph.sessions[0];
    let normalized = crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
        &request,
        session.provider.clone(),
        session.holder.clone(),
        request.node_id(),
        request.boot_id(),
        session.route_id,
        session.route_generation,
        session.route_digest,
        session.resource_namespace_digest,
        session.revocation_generation,
        session.revocation_digest,
    )
    .unwrap();
    let attempt = &mut graph.attempts[0];
    attempt.signed_request_digest = digest_signed_request(&signed);
    attempt.signed_request_digest_again = attempt.signed_request_digest;
    attempt.typed_request_digest = digest_acquire_request(&request);
    attempt.operation_intent_digest = normalized.digest();
    attempt.signed_request = signed.to_canonical_bytes();
    let acquisition = &mut graph.acquisition;
    acquisition.normalized_intent = normalized;
    acquisition.backend_id = crate::acquire::derive_native_no_dispatch_id(
        acquisition.normalized_intent.digest(),
        acquisition.catalog_generation,
        acquisition.catalog_digest,
    );
    acquisition.backend_lineage_digest = crate::AcquirePlanV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        session_binding: attempt.session_binding,
        attempt_digest: attempt.attempt_digest,
        acquisition_id: acquisition.acquisition_id,
        effect_id: acquisition.effect_id,
        normalized_intent_digest: acquisition.normalized_intent.digest(),
        kernel_coupled: false,
        backend_id: acquisition.backend_id,
    }
    .lineage_digest();
    graph.refresh_inventory();
    (graph, request)
}

fn no_dispatch_rows(graph: &Graph) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut rows = graph.rows();
    rows.remove(&crate::ledger::native_completion::native_completion_key_v2(
        graph.acquisition.acquisition_id,
    ));
    rows
}

#[test]
fn native_v3_reservation_cold_replay_preserves_complete_original_profile() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (graph, original) = native_no_dispatch_graph();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let reservation = admit_rows(&mut owner, &graph, no_dispatch_rows(&graph));
    let expected_floor = reservation.request();
    let recovered = recover_graph(&owner).unwrap();
    let actual = recovered.acquisitions.values().next().unwrap();
    assert_eq!(
        actual.normalized_intent,
        graph.acquisition.normalized_intent
    );
    assert!(
        crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(&original, actual)
    );
    assert!(actual.source_root.is_none());
    assert!(recovered.native_completions.is_empty());
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(expected_floor))
            .unwrap()
            .request(),
        expected_floor
    );
    assert_eq!(
        recovered
            .acquisitions
            .values()
            .next()
            .unwrap()
            .normalized_intent
            .native_catalog(),
        original.native_catalog()
    );
    // Cold rows are historical DATA. No hot original clock is fabricated here.
}

#[test]
fn native_v3_terminal_comparison_rejects_stripped_profile_and_outer_tuple_substitution() {
    let (graph, original) = native_no_dispatch_graph();
    let acquisition = &graph.acquisition;
    assert!(
        crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original,
            acquisition
        )
    );
    let mut wrong = acquisition.clone();
    wrong.resource_namespace_digest = digest(99);
    assert!(
        !crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original, &wrong
        )
    );
    wrong = acquisition.clone();
    wrong.catalog_generation += 1;
    assert!(
        !crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original, &wrong
        )
    );
    wrong = acquisition.clone();
    wrong.catalog_digest = digest(99);
    assert!(
        !crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original, &wrong
        )
    );
    let legacy = decode_acquire_request(
        graph
            .native
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request()
            .subject(),
    )
    .unwrap();
    wrong = acquisition.clone();
    wrong.normalized_intent = crate::NormalizedAcquisitionIntentV1::from_acquire_request(
        &legacy,
        wrong.provider.clone(),
        wrong.holder.clone(),
        legacy.node_id(),
        legacy.boot_id(),
        graph.sessions[0].route_id,
        graph.sessions[0].route_generation,
        graph.sessions[0].route_digest,
        wrong.resource_namespace_digest,
        graph.sessions[0].revocation_generation,
        graph.sessions[0].revocation_digest,
    )
    .unwrap();
    assert!(
        !crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original, &wrong
        )
    );
    assert!(
        !crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &legacy,
            acquisition
        )
    );
}

#[test]
fn native_v3_rebind_and_selected_resource_substitution_are_not_original_replay() {
    let (graph, request) = native_no_dispatch_graph();
    let catalog = graph
        .native
        .canonical_request
        .as_ref()
        .unwrap()
        .request()
        .claims()
        .catalog();
    let (resource, _) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            request.binding_digest(),
        )
        .unwrap();
    let original_attempt = graph.attempts[0].attempt_digest;
    assert!(crate::acquire::matches_original_native_acquisition(
        &graph.acquisition,
        &graph.acquisition.normalized_intent,
        &resource,
        original_attempt,
    ));
    for field in 0..7 {
        let mut changed = graph.acquisition.clone();
        match field {
            0 => changed.effect_attempt_digest = digest(99),
            1 => changed.current_attempt_digest = digest(99),
            2 => changed.backend_id = [99; 32],
            3 => changed.resource_id = [99; 32],
            4 => changed.resource_generation += 1,
            5 => changed.selection_generation += 1,
            _ => changed.selection_digest = digest(99),
        }
        assert!(
            !crate::acquire::matches_original_native_acquisition(
                &changed,
                &graph.acquisition.normalized_intent,
                &resource,
                original_attempt,
            ),
            "field {field}"
        );
    }
}

#[test]
fn native_v3_all_seven_retained_claim_substitutions_reject_terminal_equality() {
    let (graph, original) = native_no_dispatch_graph();
    let claims = original.native_catalog().unwrap();
    let legacy = decode_acquire_request(
        graph
            .native
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request()
            .subject(),
    )
    .unwrap();
    for field in 0..7 {
        // At an equal-generation floor, change the pair together to preserve
        // valid DATA shape while testing the exact old signed meaning.
        let head_generation = if field == 1 {
            claims.head().0 + 1
        } else {
            claims.head().0
        };
        let head_digest = if field == 2 {
            digest(99)
        } else {
            claims.head().1
        };
        let floor_generation = if field == 3 || field == 4 {
            claims.floor().0 - 1
        } else {
            claims.floor().0
        };
        let floor_digest = if field == 4 || field == 2 {
            digest(99)
        } else {
            claims.floor().1
        };
        let altered = NativeAcquireCatalogBindingV3::new(
            if field == 0 {
                digest(99)
            } else {
                claims.resource_namespace_digest()
            },
            head_generation,
            head_digest,
            floor_generation,
            floor_digest,
            if field == 5 {
                digest(99)
            } else {
                claims.current_head_commitment()
            },
            if field == 6 {
                digest(99)
            } else {
                claims.canonical_publication_digest()
            },
        )
        .unwrap();
        let request = AcquireSourceRequestV1::new_native_v3(legacy.clone(), altered).unwrap();
        assert!(
            !crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
                &request,
                &graph.acquisition
            ),
            "field {field}"
        );
    }
}

#[test]
fn native_v3_occupied_reservation_survives_original_physical_name_loss() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (graph, _) = native_no_dispatch_graph();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let capacity = admit_rows(&mut owner, &graph, no_dispatch_rows(&graph)).request();
    drop(owner);
    let original = directory.path().join("native-whole-graph.journal");
    let moved = directory.path().join("retained-original.journal");
    std::fs::rename(&original, &moved).unwrap();
    assert!(journal.validate_held_protected_names().is_err());
    assert!(moved.is_file());
    // Physical custody failure is not evidence of absence or rollback.
    std::fs::rename(&moved, &original).unwrap();
    drop(journal);
    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    assert_eq!(
        recovered.acquisitions.values().next().unwrap(),
        &graph.acquisition
    );
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(capacity))
            .unwrap()
            .request(),
        capacity
    );
    validate_set(&owner, &recovered).unwrap();
}

#[test]
fn native_v3_no_dispatch_terminal_consumes_exact_floor_and_reopens_idempotently() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (graph, original) = native_no_dispatch_graph();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    admit_rows(&mut owner, &graph, no_dispatch_rows(&graph));
    let reservation = exact_reservation(
        &owner,
        &graph.acquisition,
        &graph.attempts[0],
        &graph.sessions[0],
        None,
    )
    .unwrap();
    let mut faulted = graph.acquisition.clone();
    faulted.revision += 1;
    faulted.state = ProviderAcquisitionStateV1::Faulted;
    faulted.native_no_dispatch_reservation_digest =
        Some(record_digest(&encode_acquisition(&graph.acquisition)).unwrap());
    let mut retired = graph.attempts[0].clone();
    retired.revision += 1;
    retired.state = ProviderAttemptStateV1::Retired;
    let mut cleared = graph.sessions[0].clone();
    cleared.revision += 1;
    cleared.pending_attempt_digest = None;
    let acquisition_key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: faulted.provider.authority_id(),
        holder_id: faulted.holder.authority_id(),
        acquisition_id: faulted.acquisition_id,
    });
    let attempt_key = attempt_key(&AttemptKeyV1 {
        provider_id: retired.provider.authority_id(),
        holder_id: retired.holder.authority_id(),
        root_record_key_id: retired.root_record_signer.key_id(),
        method: retired.method as u8,
        request_id: retired.request_id,
    });
    let mut next = no_dispatch_rows(&graph);
    let changed = vec![
        (acquisition_key, encode_acquisition(&faulted)),
        (attempt_key, encode_attempt(&retired)),
        (
            session_key(
                cleared.provider.authority_id(),
                cleared.holder.authority_id(),
            ),
            encode_session(&cleared),
        ),
    ];
    for (key, value) in &changed {
        next.insert(key.clone(), value.clone());
    }
    let old = no_dispatch_rows(&graph);
    aos_sandbox_source_provider_ledger::validate_prospective_transition(
        old.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        next.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap();
    let mut records = transaction(101, changed.into_iter().collect())
        .records()
        .to_vec();
    records.push(reservation.settlement_record());
    let terminal = JournalTransaction::new([101; 16], records).unwrap();
    let preflight = owner
        .preflight_reserved_terminal_v1(&reservation, &terminal)
        .unwrap();
    owner
        .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    assert_eq!(recovered.acquisitions.values().next().unwrap(), &faulted);
    assert!(
        crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original, &faulted
        )
    );
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let reopened = recover_graph(&owner).unwrap();
    validate_set(&owner, &reopened).unwrap();
    assert_eq!(reopened.acquisitions.values().next().unwrap(), &faulted);
    assert!(
        crate::native_no_dispatch_recovery::matches_original_no_dispatch_profile(
            &original, &faulted
        )
    );
    // Re-read only: the historical terminal equality check has no clock,
    // current catalog requirement, backend dispatch or new lease constructor.
}
