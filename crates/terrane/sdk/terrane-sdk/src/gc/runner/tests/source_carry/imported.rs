//! Proves local-head foreign used-view carry through retirement and cold fork.
//!
//! Actual public producers, imported controls and calibrated metadata reads retain
//! independent contexts; decoded lineage is compared evidence, never authority.

use super::*;

#[tokio::test]
async fn local_head_foreign_used_view_survives_retirement_and_zero_node_cold_fork() {
    use support::{PublicFixture, public_image, public_lineage, public_metadata, public_orphan};
    use terrane_format::gc::publication::evidence::ControlKind;

    const FOREIGN_VIEW_HEAD: &str = "refs/heads/_/foreign-used-view";
    const FORK: &str = "refs/heads/_/foreign-used-view-fork";
    let foreign = PublicFixture::open_file().await;
    let destination = PublicFixture::open().await;
    let source = support::disclose_public_file(&foreign, &destination, FOREIGN_VIEW_HEAD).await;
    let repository = &destination.repository;
    let guard = repository.coordinator().guard();
    let authority = guard.configured_original_authority().unwrap();
    let owner = crate::guard::consumed_registration(&authority);
    let before = public_image(repository).await;
    let prior = public_lineage(repository, FOREIGN_VIEW_HEAD).await;

    let local_original = guard.original_commit(&source.commit).unwrap();
    let foreign_original = guard.original_commit(&foreign.record.commit).unwrap();
    assert_eq!(local_original.baseline().authority(), &authority);
    assert_ne!(foreign_original.baseline().authority().id(), authority.id());
    assert_eq!(
        foreign_original.baseline().authority().id(),
        foreign
            .repository
            .coordinator()
            .guard()
            .configured_original_authority()
            .unwrap()
            .id()
    );
    assert_eq!(prior.source, source);
    assert_eq!(prior.original, owner);
    assert!(
        prior
            .used
            .views
            .iter()
            .any(|view| view.view == foreign.record.commit)
    );
    let foreign_commit = terrane_format::refs::Commit::decode(
        &foreign
            .repository
            .coordinator()
            .store()
            .get(
                &TERRANE_V1
                    .from_digest(IdentityKind::Commit, &foreign.record.commit)
                    .unwrap(),
                None,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let foreign_context = prior
        .used
        .view_interpretations
        .as_ref()
        .unwrap()
        .iter()
        .find(|context| context.view == foreign.record.commit)
        .unwrap();
    assert_eq!(foreign_context.original_root, foreign_commit.tree);
    assert!(prior.used.check_supported_view_contexts().unwrap());
    assert!(!prior.controls.is_empty());
    assert!(prior.controls.iter().all(|pin| pin.owner == owner));
    for kind in [
        ControlKind::Import,
        ControlKind::ImportBinding,
        ControlKind::ImportTrust,
    ] {
        assert!(prior.controls.iter().any(|pin| pin.kind == kind));
    }

    let (pack, modified) = public_orphan(&destination).await;
    let base = modified.checked_add(61).unwrap();
    destination.clock.set(base, base.checked_sub(100).unwrap());
    let mut collection = Collection::start(
        guard,
        &authority,
        "retirement-collector".into(),
        1_000,
        51,
        windows(),
    )
    .await
    .unwrap();
    while !collection.state().pending.is_empty() {
        collection.mark_batch(32).await.unwrap();
    }
    collection.finish_mark().await.unwrap();
    assert_eq!(collection.state().phase, terrane_format::gc::Phase::Sweep);
    // Real imports add containers; inventory order need not select the seeded
    // orphan first. Every successful step must preserve its own whole source
    // evidence and advance loss exactly once before the next fresh selection.
    let limit = public_image(repository)
        .await
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .len();
    let mut retired_ids = std::collections::BTreeSet::new();
    let carried = loop {
        assert!(retired_ids.len() < limit, "seeded orphan was not retired");
        let before = public_image(repository).await;
        let prior = public_lineage(repository, FOREIGN_VIEW_HEAD).await;
        let retired = collection
            .retire_one(repository.coordinator())
            .await
            .unwrap()
            .unwrap();
        assert!(retired_ids.insert(retired.pack));
        let retired_pack = crate::pack::PackId::from_random_bytes(retired.pack);
        let after = public_image(repository).await;
        let carried = public_lineage(repository, FOREIGN_VIEW_HEAD).await;
        assert_eq!(
            after.state.loss_generation,
            before.state.loss_generation + 1
        );
        assert_eq!(carried.loss_generation, after.state.loss_generation);
        assert_eq!(carried.source, prior.source);
        assert_eq!(carried.commit_bytes, prior.commit_bytes);
        assert_eq!(carried.original, prior.original);
        assert_eq!(carried.guard_digest, prior.guard_digest);
        assert_eq!(carried.controls, prior.controls);
        assert_eq!(
            carried.used.view_interpretations,
            prior.used.view_interpretations
        );
        assert!(
            prior
                .used
                .views
                .iter()
                .all(|view| carried.used.views.contains(view))
        );
        assert!(carried.used.check_supported_view_contexts().unwrap());
        assert!(
            carried
                .used
                .views
                .iter()
                .any(|view| view.view == foreign.record.commit)
        );
        assert!(carried.controls.iter().all(|pin| pin.owner == owner));
        assert_eq!(after.state.branches, before.state.branches);
        assert_eq!(after.state.guard, before.state.guard);
        assert_eq!(after.state.binding, before.state.binding);
        assert_eq!(after.state.sources.len(), before.state.sources.len());
        assert_ne!(after.state.sources, before.state.sources);
        assert!(
            after
                .manifest
                .exclusions
                .as_ref()
                .unwrap()
                .iter()
                .any(|row| row.pack_id == retired.pack)
        );
        assert!(
            repository
                .coordinator()
                .store()
                .root()
                .join(retired_pack.pack_key())
                .exists()
        );
        assert!(
            repository
                .coordinator()
                .store()
                .root()
                .join(retired_pack.index_key())
                .exists()
        );
        assert_eq!(
            repository
                .coordinator()
                .store()
                .ref_get(FOREIGN_VIEW_HEAD)
                .await
                .unwrap(),
            Some(source.clone())
        );
        if retired.pack == *pack.as_bytes() {
            break carried;
        }
    };
    let final_image = public_image(repository).await;
    assert_eq!(
        final_image.state.loss_generation,
        before.state.loss_generation + u64::try_from(retired_ids.len()).unwrap()
    );
    assert!(retired_ids.contains(pack.as_bytes()));
    assert!(
        final_image
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .iter()
            .any(|row| row.pack_id == *pack.as_bytes())
    );
    drop(collection);

    // Calibration attaches to the very metadata validator used by this fork.
    let store = repository.coordinator().store();
    let observer = store.observe_metadata_for_tests().unwrap();
    observer.reset();
    let root = terrane_format::refs::Commit::decode(&carried.commit_bytes)
        .unwrap()
        .tree;
    let root_identity = TERRANE_V1.from_digest(IdentityKind::Node, &root).unwrap();
    let bytes = store.get(&root_identity, None).await.unwrap();
    assert!(observer.snapshot().node_gets > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &bytes).unwrap(),
        ))
        .await
        .unwrap();
    let calibrated = observer.snapshot();
    assert!(calibrated.node_puts > 0);
    assert!(calibrated.node_decodes > 0);
    observer.reset();

    // This forks the local head whose completed used inputs actually include
    // the foreign view; forking the unrelated initialized head is insufficient.
    let fork = repository
        .fork(
            FOREIGN_VIEW_HEAD,
            FORK,
            repository.source_request(
                &destination.authority,
                public_metadata("Fork actual carried foreign-used-view source"),
            ),
        )
        .await
        .unwrap();
    let counts = observer.snapshot();
    assert_eq!(counts.node_gets, 0);
    assert_eq!(counts.node_puts, 0);
    assert_eq!(counts.node_decodes, 0);
    assert_eq!(counts.commit_puts, 1);
    let commit_bytes = store
        .get(
            &TERRANE_V1
                .from_digest(IdentityKind::Commit, &fork.commit)
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    let commit = terrane_format::refs::Commit::decode(&commit_bytes).unwrap();
    assert_eq!(commit.tree, root);
    assert_eq!(commit.parents, vec![source.commit]);
    assert!(commit.signature.is_some());
    let context = commit.profile_pair.commit_context.as_ref().unwrap();
    assert_eq!(context.reference(), FORK);
    let roots = context
        .roots()
        .iter()
        .map(|root| terrane_format::auth::RequestRoot {
            path: root.path(),
            domain: root.domain(),
        })
        .collect::<Vec<_>>();
    let verified = terrane_format::provenance::verify_history(
        &commit,
        guard.keys(),
        &roots,
        &[(FORK, fork.writer_epoch)],
    )
    .unwrap();
    assert_eq!(verified.identity(), fork.commit);
    assert_eq!(
        store.ref_get(FOREIGN_VIEW_HEAD).await.unwrap(),
        Some(source)
    );
    assert_eq!(store.ref_get(FORK).await.unwrap(), Some(fork));
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_puts, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);
}
