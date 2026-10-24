//! Checks conditional Memo retention through real selected native metadata.
//!
//! The independent raw records have the unchanged common schema:
//! ```text
//! {1: recipe-digest32, 2: output-node32}
//! ```
//! A recipe-shaped key, an orphan output and a live Chunk never establish a Node
//! root. Both witness and full walks preserve only independently live Node
//! associations, without opening data bodies or changing their proof positions.

use super::*;

fn raw_memo(recipe: Digest, output: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1];
    terrane_format::cbor::write_bytes(&mut bytes, &recipe);
    bytes.push(2);
    terrane_format::cbor::write_bytes(&mut bytes, &output);
    bytes
}

#[tokio::test]
async fn gc_memo_native_retains_only_independently_live_output_nodes()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = Fixture::new().await;
    let repository = production_repository(&fixture).await;
    let guard = repository.coordinator().guard();
    let verified = guard.verified_tree(fixture.head.commit).await?;
    let output = verified.commit.commit().tree;
    let chunk = digest(IdentityKind::Chunk, b"published source");

    // Uploading an unrelated Node establishes content presence only. A Memo's
    // recipe key or output claim must not promote this orphan into reachability.
    let orphan = Tree::build(
        Vec::new(),
        None,
        guard.config().min_chunk_size,
        TreeUse::Ordinary,
    )?;
    let orphan_root = orphan.root_identity();
    assert_ne!(orphan_root, output);
    for node in orphan.nodes() {
        guard
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                node.encoded(),
            )?))
            .await?;
    }

    let records = [
        raw_memo(orphan_root, output),
        raw_memo([0xa4; 32], output),
        raw_memo(output, orphan_root),
        raw_memo(output, chunk),
    ];
    let mut addresses = Vec::new();
    for bytes in &records {
        let actual = guard
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Memo,
                bytes,
            )?))
            .await?;
        assert_eq!(
            actual.terrane_v1_digest()?,
            digest(IdentityKind::Memo, bytes)
        );
        addresses.push(actual);
    }

    let collection = Collection::start(
        guard,
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await?;
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await?;
    let adapted = crate::guard::collection_authority::historical_guard(
        guard,
        &held,
        &observed,
        &collection.session,
        collection.session.clock()?,
    )?;
    let consumed = ConsumedResolver::new(guard, &fixture.authority)?;
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let root_histories = crate::selected_bridge::native_collection_roots::cycle(
        &adapted,
        &consumed,
        &held,
        &observed,
        &collection.session,
        1,
    )
    .await?;
    let paths = arm_data_reads(&fixture, adapted.store()).await;

    let inspected = adapted.store().memo_records().await?;
    assert_eq!(inspected.len(), records.len());
    assert!(
        adapted
            .store()
            .identities()?
            .iter()
            .all(|identity| identity.kind() != IdentityKind::Memo)
    );
    let expected: BTreeSet<_> = addresses[..2]
        .iter()
        .map(|identity| identity.terrane_v1_digest())
        .collect::<Result<_, _>>()?;

    for witness in [true, false] {
        let mut state = frontier(fixture.head.commit, witness);
        let mut marks = BTreeSet::new();
        expand(
            &adapted,
            &consumed,
            observation,
            &root_histories,
            &mut state,
            &mut marks,
        )
        .await?;

        let emitted: BTreeSet<_> = state
            .objects
            .iter()
            .filter(|object| object.kind == crate::pack::EntryKind::Memo as u8)
            .map(|object| object.hash)
            .collect();
        assert_eq!(emitted, expected);
        assert!(expected.iter().all(|hash| marks.contains(hash)));
        assert!(marks.contains(&output));
        assert!(!marks.contains(&orphan_root));
        assert_eq!(marks.contains(&chunk), !witness);
        for identity in &addresses[2..] {
            assert!(!marks.contains(&identity.terrane_v1_digest()?));
        }
        assert!(state.pending.is_empty());

        let contexts: BTreeSet<_> = state
            .objects
            .iter()
            .filter(|object| object.kind == 2 && object.hash == output)
            .map(|object| object.proof_context.clone())
            .collect();
        for object in state
            .objects
            .iter()
            .filter(|object| object.kind == crate::pack::EntryKind::Memo as u8)
        {
            assert_eq!(object.flags, if witness { WITNESS } else { 0 });
            assert!(object.proof_context.is_some());
            assert!(contexts.contains(&object.proof_context));
        }
        assert_eq!(GcState::decode(&state.encode()?)?, state);
    }

    let retained: BTreeSet<_> = adapted
        .store()
        .identities()?
        .into_iter()
        .filter(|identity| identity.kind() == IdentityKind::Memo)
        .map(|identity| identity.terrane_v1_digest())
        .collect::<Result<_, _>>()?;
    assert_eq!(retained, expected);
    prove_data_read_traps(&fixture, &paths).await;
    Ok(())
}
