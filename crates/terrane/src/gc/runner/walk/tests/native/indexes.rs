//! Checks exact contextual I/P/G retention using independently encoded Index bytes.

use super::*;

/// Checks complete metadata reachability against genuine native publication.
///
/// # Panics
/// Panics if setup fails or actual traversal differs from the independent oracle.
pub(super) async fn gc_common_walk_native_indexes_preserve_exact_auxiliary_roles() {
    let fixture = Fixture::new_indexed().await;
    let repository = production_repository(&fixture).await;
    let publication = publish_indexed(&fixture, &repository).await;
    let IndexedPublication {
        head,
        owner,
        data,
        present_object,
        missing_object,
        value,
    } = publication;
    let present_route = raw_carrier(b"present", present_object, None, None);
    let missing_route = raw_carrier(b"missing", missing_object, None, None);
    let present_hash = digest(IdentityKind::Node, &present_route);
    let missing_hash = digest(IdentityKind::Node, &missing_route);
    let gap = raw_carrier(&missing_object, missing_object, Some(missing_hash), None);
    let gap_hash = digest(IdentityKind::Node, &gap);
    let mut primary_key = value.clone();
    primary_key.extend(present_object);
    let primary = raw_carrier(
        &primary_key,
        present_object,
        Some(present_hash),
        Some(gap_hash),
    );
    let primary_hash = digest(IdentityKind::Node, &primary);
    let expected_nodes = BTreeMap::from([
        (present_hash, present_route),
        (missing_hash, missing_route),
        (gap_hash, gap),
        (primary_hash, primary),
    ]);
    assert_eq!(data.root, primary_hash);
    assert_eq!(data.nodes, expected_nodes);
    let verified = repository
        .coordinator()
        .guard()
        .verified_tree(head.commit)
        .await
        .assert_success();
    let mut expected_records = Vec::new();
    for (object, value) in [(present_object, [11; 32]), (missing_object, [12; 32])] {
        let mut record = AttrRecord::new(object, AttributeValue::Sha256(value), head.commit);
        record
            .sign(&verified.commit, &terminal_seed())
            .assert_success();
        let encoded = record.encode().assert_success();
        let expected = digest(IdentityKind::Attribute, &encoded);
        let actual = repository
            .coordinator()
            .store()
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Attribute, &encoded).assert_success(),
            ))
            .await
            .assert_success()
            .terrane_v1_digest()
            .assert_success();
        assert_eq!(actual, expected);
        expected_records.push(expected);
    }
    let collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(repository.coordinator().guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let guard = crate::guard::collection_authority::historical_guard(
        repository.coordinator().guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(repository.coordinator().guard(), &fixture.authority)
        .assert_success();
    let root_histories = crate::selected_bridge::native_collection_roots::cycle(
        &guard,
        &consumed,
        &held,
        &observed,
        &collection.session,
        1,
    )
    .await
    .assert_success();
    let data_paths = arm_data_reads(&fixture, guard.store()).await;
    let mut state = frontier(head.commit, false);
    let mut marks = BTreeSet::new();

    expand(
        &guard,
        &consumed,
        HistoryObservation::held(observed.identity()).tracked(&consumed),
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    let occurrence = ProofContext::new(head.commit, owner, b"/".to_vec()).assert_success();
    let actual = state
        .objects
        .iter()
        .filter(|object| object.flags & INDEX != 0)
        .cloned()
        .collect::<Vec<_>>();
    let expected = expected_nodes
        .keys()
        .map(|hash| ExpandedObject {
            kind: 2,
            hash: *hash,
            flags: INDEX | ROOT,
            proof_context: Some(occurrence.clone()),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert!(expected_nodes.keys().all(|hash| marks.contains(hash)));
    assert!(marks.contains(&present_object));
    assert!(marks.contains(&missing_object));
    for record in expected_records {
        assert!(marks.contains(&record));
        assert!(state.objects.contains(&ExpandedObject {
            kind: 7,
            hash: record,
            flags: 0,
            proof_context: Some(occurrence.clone()),
        }));
    }
    assert!(state.pending.iter().any(|pending| {
        pending.is_witness()
            && pending.hash == head.commit
            && pending.proof_context.as_ref() == Some(&occurrence)
    }));
    let mut changed_config = guard.config().clone();
    changed_config.initial_acl = vec![("writer".into(), 15)];
    let changed_guard = crate::gc::runner::fixture::configured_guard(
        crate::bucket::publication::collection_observation::MetadataStore::new(
            &held,
            &observed,
            &collection.session,
        ),
        collection.session.clock().assert_success(),
        guard.keys().to_vec(),
        changed_config,
        fixture.authoring.as_ref(),
    );
    let mut refused_state = frontier(head.commit, false);
    let before_state = refused_state.clone();
    let mut refused_marks = BTreeSet::from([[77; 32]]);
    let before_marks = refused_marks.clone();
    let CollectionError::Store(failure) = expand(
        &changed_guard,
        &consumed,
        HistoryObservation::held(observed.identity()).tracked(&consumed),
        &root_histories,
        &mut refused_state,
        &mut refused_marks,
    )
    .await
    .assert_failure() else {
        panic!("expected precise configured-Guard refusal")
    };

    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert!(std::error::Error::source(&failure).is_none());
    assert_eq!(refused_state, before_state);
    assert_eq!(refused_marks, before_marks);
    assert!(changed_guard.store().reads().assert_success().is_empty());
    assert!(
        changed_guard
            .store()
            .identities()
            .assert_success()
            .is_empty()
    );
    assert!(
        guard
            .store()
            .identities()
            .assert_success()
            .iter()
            .all(|identity| identity.kind() != IdentityKind::Chunk)
    );
    prove_data_read_traps(&fixture, &data_paths).await;
    drop(guard);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    drop(repository);
    fixture.cleanup();
}
