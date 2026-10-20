//! Exercises signed contextual layers through real publication and collection.

use super::*;
use crate::guard::{OverlayInput, ViewSelection};
use crate::repository::PublishedOverlayLayer;

/// Reports test progress only under the existing index diagnostic opt-in.
fn indexed_replay_stage(stage: &'static str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        static STARTED: std::sync::OnceLock<crate::diagnostic_clock::Tick> =
            std::sync::OnceLock::new();

        let started = STARTED.get_or_init(crate::diagnostic_clock::tick);
        let elapsed = crate::diagnostic_clock::elapsed(*started).as_secs_f64();
        eprintln!("indexed-overlay-replay stage={stage} elapsed_seconds={elapsed:.3}");
    }
}

/// Publishes a contextual deletion over independently published indexed data.
async fn publish_overlay(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
) -> (
    PublishedOverlayLayer,
    terrane_format::refs::RefRecord,
    IndexedPublication,
) {
    indexed_replay_stage("publish-overlay.baseline-publication");
    let baseline = publish_indexed(fixture, repository).await;
    indexed_replay_stage("publish-overlay.baseline-verification");
    let verified = repository
        .coordinator()
        .guard()
        .verified_tree(baseline.head.commit)
        .await
        .assert_success();
    let ordinary = verified
        .evidence
        .tree(verified.evidence.root, 262144)
        .assert_success();
    let mut deletion = entry(b"");
    deletion.kind = EntryKind::Whiteout;
    let mut properties = ordinary
        .props()
        .assert_success()
        .iter()
        .filter(|property| property.name != "index-roots")
        .copied()
        .collect::<Vec<_>>();
    properties.push(Property {
        name: "index",
        value: b"\x81\x6bhash.sha256",
    });
    properties.sort_by_cached_key(|property| {
        let mut key = Vec::new();
        terrane_format::cbor::write_text(&mut key, property.name);
        key
    });
    let layer = Tree::build(
        vec![LeafItem {
            key: b"missing".to_vec(),
            entry: deletion,
        }],
        Some(properties),
        262144,
        TreeUse::OverlayLayer,
    )
    .assert_success();
    indexed_replay_stage("publish-overlay.writer-begin");
    let mut writer = repository
        .begin("refs/heads/_/main", &token(fixture), "sdk")
        .await
        .assert_success();
    let graph = BTreeMap::from([(layer.root_identity(), layer.clone())]);
    let recipe = IndexEvaluationRecipe::new(layer.root_identity(), "hash.sha256").assert_success();
    let context = SemanticContext::new(3, 2, 1).assert_success();
    let data = evaluation::construct(&recipe, &graph, 262144, context).assert_success();
    let arena = maintenance::ByteArena::new(1 << 20).assert_success();
    let completed = completion::complete(
        layer.root_identity(),
        &graph,
        &[completion::Selection {
            attribute: "hash.sha256",
            data: &data,
        }],
        &arena,
        262144,
        context,
        completion::MemoPolicy::Omit,
    )
    .assert_success();
    indexed_replay_stage("publish-overlay.layer-proposal");
    let mut request = proposal(fixture, &completed.owner.tree, Some(&data), &[]).await;
    // The indexed publication advanced this ref beyond the fixture's seed head.
    request.commit.parents = vec![writer.record().assert_success().commit];
    indexed_replay_stage("publish-overlay.layer-publication");
    let published = repository
        .publish_overlay_layer(&mut writer, request)
        .await
        .assert_success();
    assert_eq!(writer.record(), Some(&baseline.head));
    let inputs = [
        OverlayInput {
            reference: "refs/heads/_/main".into(),
            commit: published.commit,
        },
        OverlayInput {
            reference: "refs/heads/_/main".into(),
            commit: baseline.head.commit,
        },
    ];
    indexed_replay_stage("publish-overlay.output-proposal");
    let request = proposal(fixture, &ordinary, None, &[]).await;
    indexed_replay_stage("publish-overlay.output-publication");
    let output = repository
        .overlay(&mut writer, &inputs, request)
        .await
        .assert_success();
    indexed_replay_stage("publish-overlay.output-verification");
    let verified = repository
        .coordinator()
        .guard()
        .verified_tree(output.commit)
        .await
        .assert_success();
    assert_eq!(
        verified.commit.commit().parents,
        vec![baseline.head.commit, published.commit, baseline.head.commit]
    );
    let tree = verified
        .evidence
        .tree(verified.evidence.root, 262144)
        .assert_success();
    assert!(tree.get(b"missing").is_none());
    assert!(tree.get(b"present").is_some());
    assert!(
        tree.iter()
            .all(|item| !matches!(item.entry.kind, EntryKind::Whiteout))
    );
    indexed_replay_stage("publish-overlay.complete");
    (published, output, baseline)
}

/// Captures ordinary configuration from fresh addressed Commit data, including layers.
///
/// These rows retain the source Guard's actual selections without constructing
/// authenticated history, Original evidence or operation permission. Publication,
/// collection and reopened output verification remain independent real checks.
///
/// # Panics
/// Panics on unavailable or invalid canonical data, a different chunk profile,
/// or missing or contradictory source-selected interpretation inputs.
async fn selections(repository: &RepositoryWithIndexes, output: Digest) -> Vec<ViewSelection> {
    let guard = repository.coordinator().guard();
    indexed_replay_stage("selections.commit-data-capture");
    let mut pending = vec![output];
    let mut visited = BTreeSet::new();
    let mut selections = Vec::new();
    while let Some(identity) = pending.pop() {
        if !visited.insert(identity) {
            continue;
        }
        let address = TERRANE_V1
            .from_digest(IdentityKind::Commit, &identity)
            .assert_success();
        let bytes = guard.store().get(&address, None).await.assert_success();
        TERRANE_V1.verify(&address, &bytes).assert_success();
        let commit = terrane_format::refs::Commit::decode(&bytes).assert_success();
        assert_eq!(
            commit.profile_pair.chunk_profile,
            guard.config().chunk_profile_name
        );
        let (selection, inputs) = guard
            .selected_view_context_for_tests(identity, commit.tree)
            .assert_success();
        selections.push(
            ViewSelection::new(identity, commit.tree, selection, inputs.attribute_revision)
                .assert_success(),
        );
        pending.extend(commit.parents.iter().copied());
    }
    indexed_replay_stage("selections.complete");
    selections
}

/// Publishes one real unreferenced pack and derives age from backend metadata.
async fn orphan(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
) -> (crate::pack::PackId, u64) {
    let plaintext = b"unrooted overlay collection witness";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .assert_success();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    repository
        .coordinator()
        .store()
        .put(ContentUpload::Chunk(crate::store::ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: crate::store::ChunkPosition::Final,
            profile: &fixture.config.chunk_profile,
        }))
        .await
        .assert_success();
    let holder = SingleHeld::acquire(repository.coordinator().store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let capabilities = terrane_format::bucket::BucketCapabilities::decode(
        observed.logical()["CAPABILITIES"]
            .as_deref()
            .assert_success(),
    )
    .assert_success();
    let generation = capabilities.generation.assert_success();
    let manifest = terrane_format::bucket::GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{generation}/MANIFEST")]
            .as_deref()
            .assert_success(),
    )
    .assert_success();
    let hash = identity.terrane_v1_digest().assert_success();
    for row in manifest.inventory.as_ref().assert_success() {
        let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
        let bytes = std::fs::read(fixture.config.root.join(pack.index_key())).assert_success();
        let index = crate::pack::PackIndexSnapshot::decode(&bytes, generation).assert_success();
        if !index.entries().iter().any(|entry| entry.hash() == &hash) {
            continue;
        }
        let upper = [pack.pack_key(), pack.index_key()]
            .iter()
            .map(|key| {
                let modified = std::fs::symlink_metadata(fixture.config.root.join(key))
                    .assert_success()
                    .modified()
                    .assert_success()
                    .duration_since(std::time::UNIX_EPOCH)
                    .assert_success();
                modified
                    .as_secs()
                    .checked_add(u64::from(modified.subsec_nanos() != 0))
                    .assert_success()
            })
            .max()
            .assert_success();
        return (pack, upper);
    }
    panic!("actual orphan publication did not appear in selected pack inventory");
}

#[tokio::test]
async fn signed_overlay_layer_ancestry_survives_collection_and_reopen() {
    indexed_replay_stage("ancestry.fixture-setup");
    let fixture = Fixture::new_indexed().await;
    indexed_replay_stage("ancestry.repository-setup");
    let repository = production_repository(&fixture).await;
    indexed_replay_stage("ancestry.overlay-publication");
    let (layer, output, baseline) = publish_overlay(&fixture, &repository).await;
    indexed_replay_stage("ancestry.orphan-publication");
    let (orphan, upper) = orphan(&fixture, &repository).await;
    let aged = upper
        .checked_add(windows().grace())
        .assert_success()
        .checked_add(1)
        .assert_success();
    fixture.clock.set(aged, 100);
    indexed_replay_stage("ancestry.collection-start");
    let mut collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();

    indexed_replay_stage("ancestry.mark-batch");
    collection.mark_batch(512).await.assert_success();

    assert!(collection.state().pending.is_empty());
    indexed_replay_stage("ancestry.selected-state");
    let selected = fixture.selected_state(1).await;
    assert_eq!(collection.state(), &selected);
    let mut marked = BTreeSet::new();
    for pointer in &selected.checkpoints {
        let path = fixture
            .config
            .root
            .join(format!("gc/1/mark/{}/{}", pointer.shard, pointer.revision));
        let bytes = std::fs::read(path).assert_success();
        marked.extend(
            terrane_format::gc::GcMark::decode(&bytes)
                .assert_success()
                .hashes()
                .iter()
                .copied(),
        );
    }
    for required in [
        layer.commit,
        layer.root,
        output.commit,
        baseline.head.commit,
    ] {
        assert!(
            marked.contains(&required),
            "missing retained identity {required:?}"
        );
    }
    let lease = collection.lease().clone();
    drop(collection);
    indexed_replay_stage("ancestry.selection-capture");
    let captured = selections(&repository, output.commit).await;
    drop(repository);
    indexed_replay_stage("ancestry.repository-reopen");
    let reopened = production_repository_with_selections(&fixture, captured).await;
    indexed_replay_stage("ancestry.collection-resume");
    let mut resumed = Collection::resume(
        reopened.coordinator().guard(),
        &fixture.authority,
        lease,
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    assert_eq!(resumed.state(), &selected);
    indexed_replay_stage("ancestry.finish-mark");
    resumed.finish_mark().await.assert_success();
    assert_eq!(resumed.state().phase, terrane_format::gc::Phase::Sweep);
    assert_eq!(resumed.state().checkpoints, selected.checkpoints);

    indexed_replay_stage("ancestry.inventory-acquire");
    let inventory = {
        let holder = SingleHeld::acquire(reopened.coordinator().store())
            .await
            .assert_success();
        let held = holder.destination();
        indexed_replay_stage("ancestry.inventory-observation");
        let observed = held.observe_publication_unrepaired().await.assert_success();
        let capabilities = terrane_format::bucket::BucketCapabilities::decode(
            observed.logical()["CAPABILITIES"]
                .as_deref()
                .assert_success(),
        )
        .assert_success();
        let generation = capabilities.generation.assert_success();
        let manifest = terrane_format::bucket::GenerationManifest::decode(
            observed.logical()[&format!("objects/index/{generation}/MANIFEST")]
                .as_deref()
                .assert_success(),
        )
        .assert_success();
        let mut inventory = BTreeMap::new();
        for row in manifest.inventory.as_ref().assert_success() {
            let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
            let bytes = std::fs::read(fixture.config.root.join(pack.index_key())).assert_success();
            assert_eq!(digest(IdentityKind::Index, &bytes), row.index_hash);
            let index = crate::pack::PackIndexSnapshot::decode(&bytes, generation).assert_success();
            assert_eq!(index.header().id(), pack);
            assert!(inventory.insert(row.pack_id, index).is_none());
        }
        inventory
    };
    assert!(inventory.contains_key(orphan.as_bytes()));

    // Expired baseline content is unmarked even though its signed metadata is
    // retained. Eligible packs have no ordering guarantee relative to the orphan.
    let mut retired_packs = BTreeSet::new();
    let mut orphan_retirement = None;
    indexed_replay_stage("ancestry.retire-packs");
    for _ in 0..inventory.len() {
        let candidate = resumed
            .retire_one(reopened.coordinator())
            .await
            .assert_success()
            .assert_success();
        assert!(retired_packs.insert(candidate.pack));
        let index = inventory.get(&candidate.pack).assert_success();
        assert!(
            index
                .entries()
                .iter()
                .all(|entry| !marked.contains(entry.hash()))
        );
        if candidate.pack == *orphan.as_bytes() {
            orphan_retirement = Some(candidate);
            break;
        }
    }
    let retired = orphan_retirement.assert_success();
    assert_eq!(retired.pack, *orphan.as_bytes());
    indexed_replay_stage("ancestry.delete-pack");
    fixture.clock.enable_timer();
    let done = resumed
        .delete_local_pack(
            reopened.coordinator(),
            terrane_format::bucket::PackExclusion {
                pack_id: retired.pack,
                cycle: retired.cycle,
                epoch: retired.epoch,
            },
        )
        .await
        .assert_success();
    assert_eq!(done.phase, terrane_format::gc::DeletePhase::Done);
    assert!(done.authorization.elapsed_ns >= windows().deletion() * 1_000_000_000);
    assert!(!fixture.config.root.join(orphan.pack_key()).exists());
    assert!(!fixture.config.root.join(orphan.index_key()).exists());
    assert!(
        !fixture
            .config
            .root
            .join(format!("trash/{}/{}", retired.cycle, orphan))
            .exists()
    );
    indexed_replay_stage("ancestry.output-verification");
    reopened
        .coordinator()
        .guard()
        .verified_tree(output.commit)
        .await
        .assert_success();
    indexed_replay_stage("ancestry.layer-refusal");
    assert!(
        reopened
            .coordinator()
            .guard()
            .verified_tree(layer.commit)
            .await
            .is_err()
    );
    drop(resumed);
    indexed_replay_stage("ancestry.retained-selection-capture");
    let retained = selections(&reopened, output.commit).await;
    drop(reopened);
    indexed_replay_stage("ancestry.repository-reclaim");
    let reclaimed = production_repository_with_selections(&fixture, retained).await;
    indexed_replay_stage("ancestry.reclaimed-output-verification");
    reclaimed
        .coordinator()
        .guard()
        .verified_tree(output.commit)
        .await
        .assert_success();
    indexed_replay_stage("ancestry.reclaimed-layer-refusal");
    assert!(
        reclaimed
            .coordinator()
            .guard()
            .verified_tree(layer.commit)
            .await
            .is_err()
    );
    assert!(!fixture.config.root.join(orphan.pack_key()).exists());
    drop(reclaimed);
    indexed_replay_stage("ancestry.cleanup");
    fixture.cleanup();
    indexed_replay_stage("ancestry.complete");
}

#[tokio::test]
async fn signed_overlay_layer_default_and_forged_context_are_refused() {
    let fixture = Fixture::new_indexed().await;
    let repository = production_repository(&fixture).await;
    let (layer, output, _) = publish_overlay(&fixture, &repository).await;
    let guard = repository.coordinator().guard();

    assert!(guard.verified_tree(layer.commit).await.is_err());
    assert!(
        guard
            .verified_collection_tree_observed(
                layer.commit,
                HistoryObservation::default().overlay_layer(layer.commit, [0; 32]),
            )
            .await
            .is_err()
    );
    guard.verified_tree(output.commit).await.assert_success();
    drop(repository);
    fixture.cleanup();
}

/// Preserves actual producer locations when a lower graft is projected inline.
async fn nested_overlay_preserves_source_paths(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
) {
    indexed_replay_stage("nested.source-construction");
    let value = AttributeValue::Sha256([11; 32]).encode().assert_success();
    let mut surviving = entry(b"nested surviving producer");
    surviving.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &value,
    }];
    surviving.attrs_present = true;
    let child = Tree::build(
        vec![
            LeafItem {
                key: b"x".to_vec(),
                entry: entry(b"nested removed producer"),
            },
            LeafItem {
                key: b"y".to_vec(),
                entry: surviving,
            },
        ],
        None,
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let properties = vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
    ];
    let mut graft = entry(b"");
    graft.kind = EntryKind::Tree {
        root: child.root_identity(),
        props: None,
    };
    let parent = Tree::build(
        vec![LeafItem {
            key: b"g".to_vec(),
            entry: graft,
        }],
        Some(properties.clone()),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    indexed_replay_stage("nested.source-proposal");
    let mut request = proposal(
        fixture,
        &parent,
        None,
        &[b"nested surviving producer", b"nested removed producer"],
    )
    .await;
    request
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    indexed_replay_stage("nested.writer-begin");
    let mut writer = repository
        .begin("refs/heads/_/main", &token(fixture), "sdk")
        .await
        .assert_success();
    request.commit.parents = vec![writer.record().assert_success().commit];
    indexed_replay_stage("nested.source-publication");
    let source = repository
        .commit_request(&mut writer, request)
        .await
        .assert_success();
    let mut directory = entry(b"");
    directory.kind = EntryKind::Directory { mode: 0o755 };
    let mut deletion = entry(b"");
    deletion.kind = EntryKind::Whiteout;
    let layer = Tree::build(
        vec![
            LeafItem {
                key: b"g".to_vec(),
                entry: directory,
            },
            LeafItem {
                key: b"g/x".to_vec(),
                entry: deletion,
            },
        ],
        Some(properties),
        262144,
        TreeUse::OverlayLayer,
    )
    .assert_success();
    indexed_replay_stage("nested.layer-proposal");
    let mut request = proposal(fixture, &layer, None, &[]).await;
    request.commit.parents = vec![writer.record().assert_success().commit];
    indexed_replay_stage("nested.layer-publication");
    let upper = repository
        .publish_overlay_layer(&mut writer, request)
        .await
        .assert_success();
    let inputs = [
        OverlayInput {
            reference: "refs/heads/_/main".into(),
            commit: upper.commit,
        },
        OverlayInput {
            reference: "refs/heads/_/main".into(),
            commit: source.commit,
        },
    ];
    indexed_replay_stage("nested.output-proposal");
    let request = proposal(fixture, &parent, None, &[b"nested surviving producer"]).await;
    indexed_replay_stage("nested.output-publication");
    let output = repository
        .overlay(&mut writer, &inputs, request)
        .await
        .assert_success();
    let guard = repository.coordinator().guard();
    indexed_replay_stage("nested.output-verification");
    let verified = guard.verified_tree(output.commit).await.assert_success();
    let tree = verified
        .evidence
        .tree(verified.evidence.root, 262144)
        .assert_success();
    assert!(tree.get(b"g/x").is_none());
    assert!(tree.get(b"g/y").is_some());
    let receipts = verified
        .commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_deref()
        .assert_success();
    let receipt = receipts
        .iter()
        .find(|receipt| receipt.path == b"g/y")
        .assert_success();
    let expected = terrane_format::refs::EntrySource {
        commit: source.commit,
        root: child.root_identity(),
        path: b"y".to_vec(),
    };
    assert_eq!(
        receipt.origin,
        terrane_format::refs::EntryOrigin::Source(expected.clone())
    );
    assert_eq!(
        receipt.attributes.as_ref().assert_success(),
        &vec![(
            "hash.sha256".into(),
            terrane_format::refs::EntryOrigin::Source(expected)
        ),]
    );
    indexed_replay_stage("nested.complete");
}

/// Refuses a layer that associates a valid old index with a different namespace.
async fn forged_layer_index_association_is_refused(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
    baseline: &IndexedPublication,
) {
    indexed_replay_stage("forged.baseline-verification");
    let signed = repository
        .coordinator()
        .guard()
        .verified_tree(baseline.head.commit)
        .await
        .assert_success();
    let source = signed
        .evidence
        .tree(signed.evidence.root, 262144)
        .assert_success();
    let mut properties = source.props().assert_success().to_vec();
    properties.push(Property {
        name: "index",
        value: b"\x81\x6bhash.sha256",
    });
    properties.sort_by_cached_key(|property| {
        let mut key = Vec::new();
        terrane_format::cbor::write_text(&mut key, property.name);
        key
    });
    let mut deletion = entry(b"");
    deletion.kind = EntryKind::Whiteout;
    let forged = Tree::build(
        vec![LeafItem {
            key: b"missing".to_vec(),
            entry: deletion,
        }],
        Some(properties),
        262144,
        TreeUse::OverlayLayer,
    )
    .assert_success();
    indexed_replay_stage("forged.writer-begin");
    let mut writer = repository
        .begin("refs/heads/_/main", &token(fixture), "sdk")
        .await
        .assert_success();
    let before = writer.record().assert_success().clone();
    indexed_replay_stage("forged.layer-proposal");
    let mut request = proposal(fixture, &forged, None, &[]).await;
    // Keep the index-association refusal independent of a stale parent request.
    request.commit.parents = vec![before.commit];

    indexed_replay_stage("forged.layer-refusal");
    assert!(
        repository
            .publish_overlay_layer(&mut writer, request)
            .await
            .is_err()
    );

    assert_eq!(writer.record(), Some(&before));
    indexed_replay_stage("forged.unchanged-ref-verification");
    let actual =
        crate::store::RefStore::ref_get(repository.coordinator().store(), "refs/heads/_/main")
            .await
            .assert_success();
    assert_eq!(actual, Some(before));
    indexed_replay_stage("forged.complete");
}

#[tokio::test]
async fn indexed_signed_overlay_layer_replays_exact_output() {
    indexed_replay_stage("replay.fixture-setup");
    let fixture = Fixture::new_indexed().await;
    indexed_replay_stage("replay.repository-setup");
    let repository = production_repository(&fixture).await;
    indexed_replay_stage("replay.overlay-publication");
    let (layer, output, baseline) = publish_overlay(&fixture, &repository).await;
    let guard = repository.coordinator().guard();
    indexed_replay_stage("replay.output-verification");
    let verified = guard.verified_tree(output.commit).await.assert_success();
    let tree = verified
        .evidence
        .tree(verified.evidence.root, 262144)
        .assert_success();
    assert!(
        tree.props()
            .assert_success()
            .iter()
            .any(|property| property.name == "index-roots")
    );
    let present = raw_carrier(b"present", baseline.present_object, None, None);
    let present_hash = digest(IdentityKind::Node, &present);
    let mut primary_key = baseline.value.clone();
    primary_key.extend(baseline.present_object);
    let primary = raw_carrier(
        &primary_key,
        baseline.present_object,
        Some(present_hash),
        None,
    );
    let expected_root = digest(IdentityKind::Node, &primary);
    let expected_nodes = BTreeMap::from([(present_hash, present), (expected_root, primary)]);
    indexed_replay_stage("replay.output-index-loading");
    let indexed = crate::indexing::load_for(
        guard.store(),
        verified.evidence.root,
        "hash.sha256",
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
        TreeUse::Ordinary,
    )
    .await
    .assert_success();
    assert_eq!(indexed.index_root(), expected_root);
    assert_eq!(indexed.index_data().nodes, expected_nodes);
    assert_ne!(indexed.index_root(), baseline.data.root);
    indexed_replay_stage("replay.selection-retention");
    let retained = selections(&repository, output.commit).await;
    drop(tree);
    drop(verified);
    drop(repository);
    indexed_replay_stage("replay.repository-reopen");
    let reopened = production_repository_with_selections(&fixture, retained).await;
    indexed_replay_stage("replay.writer-begin");
    let mut writer = reopened
        .begin("refs/heads/_/main", &token(&fixture), "sdk")
        .await
        .assert_success();
    let reversed = [
        OverlayInput {
            reference: "refs/heads/_/main".into(),
            commit: baseline.head.commit,
        },
        OverlayInput {
            reference: "refs/heads/_/main".into(),
            commit: layer.commit,
        },
    ];
    indexed_replay_stage("replay.baseline-verification");
    let verified_baseline = reopened
        .coordinator()
        .guard()
        .verified_tree(baseline.head.commit)
        .await
        .assert_success();
    let tree = verified_baseline
        .evidence
        .tree(verified_baseline.evidence.root, 262144)
        .assert_success();
    indexed_replay_stage("replay.stale-writer-begin");
    let mut stale = reopened
        .begin("refs/heads/_/main", &token(&fixture), "sdk")
        .await
        .assert_success();
    indexed_replay_stage("replay.mismatched-proposal");
    let mut mismatched = proposal(&fixture, &tree, None, &[]).await;
    mismatched.commit.profile_pair.recipe =
        Some(terrane_format::algebra::Recipe::Overlay(&[layer.root, baseline.owner]).encode());
    indexed_replay_stage("replay.mismatched-overlay-refusal");
    assert!(
        reopened
            .overlay(&mut writer, &reversed, mismatched)
            .await
            .is_err()
    );

    // Reversing the layers reintroduces the baseline file. Its existing bytes
    // need independently verified domain evidence before ordinary admission.
    let guard = reopened.coordinator().guard();
    indexed_replay_stage("replay.domain-snapshot");
    let snapshot = guard
        .read_commit_snapshot(baseline.head.commit, &token(&fixture), b"/missing", "sdk")
        .await
        .assert_success();
    let missing = tree.get(b"missing").assert_success();
    let EntryKind::File { content, size, .. } = missing.kind else {
        panic!("baseline missing entry is not a file");
    };
    indexed_replay_stage("replay.domain-access");
    let access = guard
        .domain_content_access(&snapshot, b"/missing", content, size)
        .await
        .assert_success();
    let domain_store =
        crate::domain::DomainStore::new("public".into(), reopened.coordinator().store().clone())
            .assert_success();
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, &baseline.missing_object)
        .assert_success();
    indexed_replay_stage("replay.domain-reference-verification");
    let record = domain_store
        .verify_reference(&access, &identity)
        .await
        .assert_success();
    indexed_replay_stage("replay.reversed-proposal");
    let mut request = proposal(&fixture, &tree, None, &[]).await;
    request.reference_records.push(record);

    indexed_replay_stage("replay.reversed-overlay-publication");
    let next = reopened
        .overlay(&mut writer, &reversed, request)
        .await
        .assert_success();
    indexed_replay_stage("replay.next-verification");
    let verified_next = reopened
        .coordinator()
        .guard()
        .verified_tree(next.commit)
        .await
        .assert_success();
    assert_eq!(
        verified_next.commit.commit().parents,
        vec![output.commit, baseline.head.commit, layer.commit]
    );
    let tree = verified_next
        .evidence
        .tree(verified_next.evidence.root, 262144)
        .assert_success();
    assert!(tree.get(b"missing").is_some());
    assert!(
        !tree
            .props()
            .assert_success()
            .iter()
            .any(|property| property.name == "index")
    );
    indexed_replay_stage("replay.next-index-loading");
    let optional = crate::indexing::load_for(
        reopened.coordinator().guard().store(),
        verified_next.evidence.root,
        "hash.sha256",
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
        TreeUse::Ordinary,
    )
    .await
    .assert_success();
    assert_eq!(optional.index_root(), baseline.data.root);
    assert_eq!(optional.index_data().nodes, baseline.data.nodes);
    indexed_replay_stage("replay.stale-overlay-refusal");
    assert!(
        reopened
            .overlay(
                &mut stale,
                &reversed,
                proposal(&fixture, &tree, None, &[]).await,
            )
            .await
            .is_err()
    );
    indexed_replay_stage("replay.nested-overlay");
    nested_overlay_preserves_source_paths(&fixture, &reopened).await;
    indexed_replay_stage("replay.forged-association");
    forged_layer_index_association_is_refused(&fixture, &reopened, &baseline).await;
    drop(reopened);
    fixture.cleanup();
    indexed_replay_stage("replay.complete");
}
