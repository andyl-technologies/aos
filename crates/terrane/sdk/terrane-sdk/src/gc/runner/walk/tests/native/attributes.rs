//! Checks signed, legacy and inactive side records with manifest and dictionary edges.

use super::*;

/// Checks complete metadata reachability against genuine native publication.
///
/// # Panics
/// Panics if setup fails or actual traversal differs from the independent oracle.
pub(super) async fn gc_common_walk_native_manifest_dictionary_and_legacy_records_keep_declared_edges()
 {
    use terrane_format::manifest::{ChunkRef, Manifest};
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let mut plaintext = vec![19; fixture.config.chunk_profile.maximum() + 1];
    let first_end = fixture.config.chunk_profile.boundaries(&plaintext)[0].end;
    plaintext.truncate(first_end + 1);
    let first = &plaintext[..first_end];
    let member = &plaintext[first_end..];
    assert!(first.len() >= fixture.config.chunk_profile.minimum());
    assert_eq!(member.len(), 1);
    assert!(fixture.config.chunk_profile.valid_nonfinal_chunk(first));
    assert_eq!(
        fixture.config.chunk_profile.boundaries(&plaintext),
        vec![0..first_end, first_end..first_end + 1]
    );
    let first_chunk = digest(IdentityKind::Chunk, first);
    let chunk = digest(IdentityKind::Chunk, member);
    let dictionary_bytes = b"explicitly declared dictionary";
    let dictionary = digest(IdentityKind::Chunk, dictionary_bytes);
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![
            ChunkRef {
                digest: first_chunk,
                length: first.len() as u64,
            },
            ChunkRef {
                digest: chunk,
                length: member.len() as u64,
            },
        ],
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    };
    let manifest_bytes = manifest
        .encode(&fixture.config.chunk_profile)
        .assert_success();
    let manifest_root = digest(IdentityKind::Manifest, &manifest_bytes);
    let dictionary_value = AttributeValue::ZstdDictionary(dictionary)
        .encode()
        .assert_success();
    let value = AttributeValue::Sha256([66; 32]).encode().assert_success();
    let mut file = entry(&plaintext);
    file.kind = EntryKind::File {
        mode: 0o644,
        size: plaintext.len() as u64,
        content: ContentRef::Manifest(manifest_root),
        link_id: None,
    };
    file.attrs = vec![Attribute {
        name: "zstd-dictionary",
        value: &dictionary_value,
    }];
    file.attrs_present = true;
    let mut dictionary_entry = entry(dictionary_bytes);
    dictionary_entry.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &value,
    }];
    dictionary_entry.attrs_present = true;
    let tree = Tree::build(
        vec![
            LeafItem {
                key: b"dictionary".to_vec(),
                entry: dictionary_entry,
            },
            LeafItem {
                key: b"manifest".to_vec(),
                entry: file,
            },
            LeafItem {
                key: b"member".to_vec(),
                entry: entry(member),
            },
        ],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let mut request = proposal(&fixture, &tree, None, &[first, member, dictionary_bytes]).await;
    request.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Manifest,
        bytes: manifest_bytes,
    });
    let mut writer = repository
        .begin("refs/heads/_/main", &token(&fixture), "sdk")
        .await
        .assert_success();
    let head = repository
        .commit_request(&mut writer, request)
        .await
        .assert_success();
    let guard = repository.coordinator().guard();
    let verified = guard.verified_tree(head.commit).await.assert_success();
    let mut record = AttrRecord::new(
        manifest_root,
        AttributeValue::ZstdDictionary(dictionary),
        head.commit,
    );
    record
        .sign(&verified.commit, &terminal_seed())
        .assert_success();
    let mut member_record = AttrRecord::new(chunk, AttributeValue::Sha256([55; 32]), head.commit);
    member_record
        .sign(&verified.commit, &terminal_seed())
        .assert_success();
    let legacy = AttrRecord::new(dictionary, AttributeValue::Sha256([66; 32]), head.commit);
    let mut inactive_legacy = legacy.clone();
    inactive_legacy.function.version = "2".into();
    let mut records = Vec::new();
    for record in [&record, &member_record, &legacy, &inactive_legacy] {
        let bytes = record.encode().assert_success();
        records.push(
            guard
                .store()
                .put(ContentUpload::Meta(
                    MetaUpload::new(IdentityKind::Attribute, &bytes).assert_success(),
                ))
                .await
                .assert_success()
                .terrane_v1_digest()
                .assert_success(),
        );
    }
    let collection = Collection::start(
        guard,
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(guard.store()).await.assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let adapted = crate::guard::collection_authority::historical_guard(
        guard,
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(guard, &fixture.authority).assert_success();
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let root_histories = crate::selected_bridge::native_collection_roots::cycle(
        &adapted,
        &consumed,
        &held,
        &observed,
        &collection.session,
        1,
    )
    .await
    .assert_success();
    let data_paths = arm_data_reads(&fixture, adapted.store()).await;
    let mut state = frontier(head.commit, true);
    let mut marks = BTreeSet::new();

    expand(
        &adapted,
        &consumed,
        observation,
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert!(marks.contains(&manifest_root));
    assert!(!marks.contains(&chunk));
    assert!(!marks.contains(&first_chunk));
    assert!(!marks.contains(&dictionary));
    assert!(records.iter().all(|record| marks.contains(record)));
    state.pending = frontier(head.commit, false).pending;

    expand(
        &adapted,
        &consumed,
        observation,
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    let context =
        ProofContext::new(head.commit, tree.root_identity(), b"/".to_vec()).assert_success();
    assert!(marks.contains(&chunk));
    assert!(marks.contains(&first_chunk));
    assert!(marks.contains(&dictionary));
    assert!(!marks.contains(&[66; 32]));
    for (kind, hash, flags) in [
        (1, manifest_root, WITNESS),
        (1, manifest_root, 0),
        (0, chunk, 0),
        (0, first_chunk, 0),
        (0, dictionary, 0),
    ] {
        assert!(state.objects.contains(&ExpandedObject {
            kind,
            hash,
            flags,
            proof_context: Some(context.clone())
        }));
    }
    assert!(
        adapted
            .store()
            .identities()
            .assert_success()
            .iter()
            .all(|identity| identity.kind() != IdentityKind::Chunk)
    );
    assert!(
        adapted
            .store()
            .identities()
            .assert_success()
            .iter()
            .any(|identity| identity.kind() == IdentityKind::Manifest)
    );
    prove_data_read_traps(&fixture, &data_paths).await;
    drop(adapted);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    drop(repository);
    fixture.cleanup();
}

/// Checks complete metadata reachability against genuine native publication.
///
/// # Panics
/// Panics if setup fails or actual traversal differs from the independent oracle.
pub(super) async fn gc_common_walk_native_attributes_retain_versions_without_discovery_roots() {
    let fixture = Fixture::new().await;
    let object = digest(IdentityKind::Chunk, b"published source");
    let verified = fixture
        .guard()
        .verified_tree(fixture.head.commit)
        .await
        .assert_success();
    let mut supported =
        AttrRecord::new(object, AttributeValue::Sha256([3; 32]), fixture.head.commit);
    supported
        .sign(&verified.commit, &terminal_seed())
        .assert_success();
    let mut inactive = supported.clone();
    inactive.function.version = "2".into();
    inactive
        .sign(&verified.commit, &terminal_seed())
        .assert_success();
    let unrelated = AttrRecord::new([99; 32], AttributeValue::Sha256([4; 32]), [98; 32]);
    let expected = [
        put_record(&fixture, &supported).await,
        put_record(&fixture, &inactive).await,
    ];
    let excluded = put_record(&fixture, &unrelated).await;
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(fixture.guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let guard = crate::guard::collection_authority::historical_guard(
        fixture.guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(fixture.guard(), &fixture.authority).assert_success();
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
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
    let mut state = frontier(fixture.head.commit, false);
    let mut marks = BTreeSet::new();

    expand(
        &guard,
        &consumed,
        observation,
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    let context = ProofContext::new(
        fixture.head.commit,
        verified.commit.commit().tree,
        b"/".to_vec(),
    )
    .assert_success();
    for record in expected {
        assert!(marks.contains(&record));
        assert!(state.objects.contains(&ExpandedObject {
            kind: 7,
            hash: record,
            flags: 0,
            proof_context: Some(context.clone())
        }));
    }
    assert!(!marks.contains(&excluded));
    assert!(!marks.contains(&[98; 32]));
    assert!(marks.contains(&object));
    assert!(
        guard
            .store()
            .identities()
            .assert_success()
            .iter()
            .all(|identity| identity.kind() != IdentityKind::Chunk)
    );
    assert!(
        guard
            .store()
            .identities()
            .assert_success()
            .iter()
            .all(|identity| identity.terrane_v1_digest().assert_success() != excluded)
    );
    assert!(!guard.store().reads().assert_success().is_empty());
    assert_eq!(state.pending.len(), 2);
    assert!(
        state
            .pending
            .iter()
            .all(|item| item.hash == fixture.head.commit && item.is_witness())
    );
    prove_data_read_traps(&fixture, &data_paths).await;
    drop(guard);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}

/// Checks complete metadata reachability against genuine native publication.
///
/// # Panics
/// Panics if setup fails or actual traversal differs from the independent oracle.
pub(super) async fn gc_common_walk_native_witness_then_full_keeps_declared_chunks_without_body_reads()
 {
    let fixture = Fixture::new().await;
    let verified = fixture
        .guard()
        .verified_tree(fixture.head.commit)
        .await
        .assert_success();
    let object = digest(IdentityKind::Chunk, b"published source");
    let context = ProofContext::new(
        fixture.head.commit,
        verified.commit.commit().tree,
        b"/".to_vec(),
    )
    .assert_success();
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(fixture.guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let guard = crate::guard::collection_authority::historical_guard(
        fixture.guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(fixture.guard(), &fixture.authority).assert_success();
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
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
    let mut state = frontier(fixture.head.commit, true);
    let mut marks = BTreeSet::new();

    expand(
        &guard,
        &consumed,
        observation,
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert!(!marks.contains(&object));
    assert!(state.objects.contains(&ExpandedObject {
        kind: 3,
        hash: fixture.head.commit,
        flags: WITNESS,
        proof_context: Some(context.clone())
    }));
    state.pending = frontier(fixture.head.commit, false).pending;

    expand(
        &guard,
        &consumed,
        observation,
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert!(marks.contains(&object));
    assert!(state.objects.contains(&ExpandedObject {
        kind: 0,
        hash: object,
        flags: 0,
        proof_context: Some(context.clone())
    }));
    assert!(state.expanded.contains(&ExpandedContext {
        commit: fixture.head.commit,
        parent_cutoff: ParentCutoff::RootsOnly,
        proof_context: Some(context)
    }));
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
    fixture.cleanup();
}

/// Checks complete metadata reachability against genuine native publication.
///
/// # Panics
/// Panics if setup fails or actual traversal differs from the independent oracle.
pub(super) async fn gc_common_walk_native_invalid_matching_attribution_keeps_frontier_unchanged() {
    let fixture = Fixture::new().await;
    let object = digest(IdentityKind::Chunk, b"published source");
    // Structurally valid unsigned metadata disagrees with the actual absence
    // of inline attribution in this genuinely published producer.
    let record = AttrRecord::new(object, AttributeValue::Sha256([3; 32]), fixture.head.commit);
    put_record(&fixture, &record).await;
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(fixture.guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let guard = crate::guard::collection_authority::historical_guard(
        fixture.guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(fixture.guard(), &fixture.authority).assert_success();
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
    let mut state = frontier(fixture.head.commit, false);
    let original = state.clone();
    let mut marks = BTreeSet::from([[7; 32]]);
    let original_marks = marks.clone();

    let error = expand(
        &guard,
        &consumed,
        HistoryObservation::held(observed.identity()).tracked(&consumed),
        &root_histories,
        &mut state,
        &mut marks,
    )
    .await
    .assert_failure();

    let CollectionError::Store(error) = error else {
        panic!("expected attribution refusal")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert!(
        std::error::Error::source(&error)
            .assert_success()
            .is::<terrane_format::derived::Error>()
    );
    assert_eq!(state, original);
    assert_eq!(marks, original_marks);
    assert!(!guard.store().reads().assert_success().is_empty());
    prove_data_read_traps(&fixture, &data_paths).await;
    drop(guard);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}
