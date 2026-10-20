//! Checks own occurrence reuse separately from ordinary parent-cutoff progress.

use super::*;
use terrane_format::gc::{ParentCutoff, RootReason};
use terrane_format::manifest::{ChunkRef, Manifest};
use terrane_format::refs::{RefPolicy, Retention};

/// Publishes two genuine refs with different retention for the same signed commit.
async fn publish_cutoffs(
    fixture: &Fixture,
    repository: &RepositoryWithIndexes,
) -> (Digest, Digest, Digest, [Digest; 2]) {
    let profile = &fixture.config.chunk_profile;
    let mut plaintext = vec![19; profile.maximum() + 1];
    let first_end = profile.boundaries(&plaintext)[0].end;
    plaintext.truncate(first_end + 1);
    let first = &plaintext[..first_end];
    let last = &plaintext[first_end..];
    // TREE-8 requires a Manifest above the actual minimum. These bytes use an
    // actual profile boundary rather than inventing a nonfinal chunk length.
    assert!(plaintext.len() > profile.minimum());
    assert!(profile.valid_nonfinal_chunk(first));
    assert_eq!(last.len(), 1);
    assert_eq!(
        profile.boundaries(&plaintext),
        vec![0..first_end, first_end..first_end + 1]
    );
    let chunks = [
        digest(IdentityKind::Chunk, first),
        digest(IdentityKind::Chunk, last),
    ];
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![
            ChunkRef {
                digest: chunks[0],
                length: first.len() as u64,
            },
            ChunkRef {
                digest: chunks[1],
                length: last.len() as u64,
            },
        ],
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    };
    let bytes = manifest
        .encode(&fixture.config.chunk_profile)
        .assert_success();
    let manifest_hash = digest(IdentityKind::Manifest, &bytes);
    let mut file = entry(&plaintext);
    file.kind = EntryKind::File {
        mode: 0o644,
        size: plaintext.len() as u64,
        content: ContentRef::Manifest(manifest_hash),
        link_id: None,
    };
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file,
        }],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "reflog_retain",
                value: b"\x82\x65count\x01",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let mut request = proposal(fixture, &tree, None, &[first, last]).await;
    request.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Manifest,
        bytes,
    });
    let count_name = "refs/heads/_/main";
    let forever_name = "refs/heads/_/z-forever";
    let mut writer = repository
        .begin(count_name, &token(fixture), "sdk")
        .await
        .assert_success();
    let count = repository
        .commit_request(&mut writer, request)
        .await
        .assert_success();
    let mut fork = proposal(fixture, &tree, None, &[]).await;
    fork.uploads.clear();
    repository
        .fork(count_name, forever_name, fork)
        .await
        .assert_success();
    let mut writer = repository
        .begin(forever_name, &token(fixture), "sdk")
        .await
        .assert_success();
    repository
        .coordinator()
        .rollback(&mut writer, count.commit, &token(fixture), "sdk")
        .await
        .assert_success();
    let forever = repository
        .coordinator()
        .set_policy(
            forever_name,
            Some(RefPolicy {
                retention: Some(Retention::Forever),
                ..RefPolicy::default()
            }),
            &token(fixture),
            "sdk",
        )
        .await
        .assert_success();
    assert_eq!(forever.commit, count.commit);
    (count.commit, tree.root_identity(), manifest_hash, chunks)
}

/// Checks actual read work and newly eligible parents under a held current root set.
///
/// # Panics
/// Panics if genuine publication, qualification or traversal contradicts the oracle.
pub(super) async fn broader_cutoff_reuses_full_occurrence_expansion() {
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let (commit, root, manifest, chunks) = publish_cutoffs(&fixture, &repository).await;
    let guard = repository.coordinator().guard();
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
    let roots = crate::selected_bridge::native_collection_roots::current(
        &adapted,
        &consumed,
        &held,
        &observed,
        &collection.session,
        (1, windows()),
    )
    .await
    .assert_success();
    let initial = crate::gc::runner::roots::initial(roots.snapshot());
    let select = |reference: &str, reason: RootReason, cutoff: ParentCutoff| {
        let index = roots
            .snapshot()
            .roots
            .iter()
            .position(|row| {
                row.reference.as_str() == reference
                    && row.commit == commit
                    && row.reason == reason
                    && row.parent_cutoff == cutoff
            })
            .assert_success();
        initial.pending[index].clone()
    };
    let narrow = select(
        "refs/heads/_/main",
        RootReason::Current,
        ParentCutoff::RootsOnly,
    );
    let repeat_narrow = select(
        "refs/heads/_/main",
        RootReason::ReflogCount,
        ParentCutoff::RootsOnly,
    );
    let broad = select(
        "refs/heads/_/z-forever",
        RootReason::Current,
        ParentCutoff::Unbounded,
    );
    let repeat_broad = select(
        "refs/heads/_/z-forever",
        RootReason::Forever,
        ParentCutoff::Unbounded,
    );
    let paths = arm_data_reads(&fixture, adapted.store()).await;
    let mut state = initial;
    // These are actual root-derived inputs. Isolate their ordering to observe
    // the narrow parent witness before the independently inventoried broad root.
    state.pending = vec![narrow];
    let mut marks = BTreeSet::new();
    let context = ProofContext::new(commit, root, b"/".to_vec()).assert_success();
    let parent_chunk = digest(IdentityKind::Chunk, b"published source");
    let manifest_gets_before = adapted
        .store()
        .identities()
        .assert_success()
        .iter()
        .filter(|identity| identity.kind() == IdentityKind::Manifest)
        .count();

    expand(
        &adapted,
        &consumed,
        observation,
        &roots,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert!(marks.contains(&manifest));
    for chunk in chunks {
        assert!(marks.contains(&chunk));
    }
    assert_eq!(
        adapted
            .store()
            .identities()
            .assert_success()
            .iter()
            .filter(|identity| identity.kind() == IdentityKind::Manifest)
            .count(),
        manifest_gets_before + 1
    );
    assert!(!marks.contains(&parent_chunk));
    assert!(state.expanded.contains(&ExpandedContext {
        commit,
        parent_cutoff: ParentCutoff::RootsOnly,
        proof_context: Some(context.clone()),
    }));
    assert!(
        state
            .pending
            .iter()
            .any(|row| row.hash == fixture.head.commit
                && row.is_parent()
                && row.parent_cutoff == ParentCutoff::RootsOnly)
    );
    let objects = state.objects.clone();
    let read_count = adapted.store().reads().assert_success().len();
    let identities = adapted.store().identities().assert_success();
    assert!(read_count > 0);
    assert!(
        identities
            .iter()
            .any(|identity| identity.kind() == IdentityKind::Manifest)
    );
    state.pending.insert(0, repeat_narrow);

    expand(
        &adapted,
        &consumed,
        observation,
        &roots,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert_eq!(state.objects, objects);
    assert_eq!(adapted.store().reads().assert_success().len(), read_count);
    assert_eq!(adapted.store().identities().assert_success(), identities);
    while !state.pending.is_empty() {
        expand(
            &adapted,
            &consumed,
            observation,
            &roots,
            &mut state,
            &mut marks,
        )
        .await
        .assert_success();
    }
    assert!(!marks.contains(&parent_chunk));
    let objects = state.objects.clone();
    let before_marks = marks.clone();
    let read_count = adapted.store().reads().assert_success().len();
    let identities = adapted.store().identities().assert_success();
    state.pending.push(broad);

    expand(
        &adapted,
        &consumed,
        observation,
        &roots,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    // Logical GET observations include body-cache hits; physical catalog reads
    // append separately. Both remain unchanged for the already full occurrence.
    assert_eq!(state.objects, objects);
    assert_eq!(marks, before_marks);
    assert_eq!(adapted.store().reads().assert_success().len(), read_count);
    assert_eq!(adapted.store().identities().assert_success(), identities);
    assert!(state.expanded.contains(&ExpandedContext {
        commit,
        parent_cutoff: ParentCutoff::Unbounded,
        proof_context: Some(context),
    }));
    assert!(
        state
            .pending
            .iter()
            .any(|row| row.hash == fixture.head.commit
                && row.is_parent()
                && row.parent_cutoff == ParentCutoff::Unbounded)
    );
    while !state.pending.is_empty() {
        expand(
            &adapted,
            &consumed,
            observation,
            &roots,
            &mut state,
            &mut marks,
        )
        .await
        .assert_success();
    }
    assert!(marks.contains(&parent_chunk));
    let objects = state.objects.clone();
    let before_marks = marks.clone();
    let read_count = adapted.store().reads().assert_success().len();
    let identities = adapted.store().identities().assert_success();
    state.pending.push(repeat_broad);

    expand(
        &adapted,
        &consumed,
        observation,
        &roots,
        &mut state,
        &mut marks,
    )
    .await
    .assert_success();

    assert!(state.pending.is_empty());
    assert_eq!(state.objects, objects);
    assert_eq!(marks, before_marks);
    assert_eq!(adapted.store().reads().assert_success().len(), read_count);
    assert_eq!(adapted.store().identities().assert_success(), identities);
    observed.revalidate().await.assert_success();
    prove_data_read_traps(&fixture, &paths).await;
    drop(roots);
    drop(adapted);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    drop(repository);
    fixture.cleanup();
}
