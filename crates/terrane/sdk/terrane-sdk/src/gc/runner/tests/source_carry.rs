//! Qualifies genuine independently visited sources through destructive retirement.
//!
//! Each case uses real signed publication, current collectors and native pair
//! observations. Prior selected lineage is compared data, never caller permission.

mod imported;
mod post_done;
mod support;

use super::*;
use crate::bucket::held::SingleHeld;
use crate::store::{ContentStore, RefStore};
use support::{completed, image, orphan};
use terrane_format::gc::publication::evidence::CheckedLineage;

const SOURCE: &str = "refs/heads/_/main";

async fn selected_lineage(fixture: &Fixture) -> CheckedLineage {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let read = held
        .selected_lineage_record(&observed, SOURCE)
        .await
        .unwrap()
        .unwrap();
    CheckedLineage::decode(read.bytes().unwrap()).unwrap()
}

#[tokio::test]
async fn source_preserving_retirement_carries_complete_view_contexts_to_new_loss_generation() {
    let fixture = Fixture::new().await;
    let (pack, modified) = orphan(&fixture).await;
    let mut collection = completed(&fixture, modified.checked_add(61).unwrap(), windows()).await;
    let before = image(&fixture).await;
    let prior = selected_lineage(&fixture).await;
    assert!(prior.used.check_supported_view_contexts().unwrap());
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pack, *pack.as_bytes());
    let after = image(&fixture).await;
    let carried = selected_lineage(&fixture).await;
    assert_eq!(
        after.state.loss_generation,
        before.state.loss_generation + 1
    );
    assert_eq!(carried.loss_generation, after.state.loss_generation);
    assert_eq!(carried.source, prior.source);
    assert_eq!(carried.commit_bytes, prior.commit_bytes);
    assert_eq!(carried.guard_digest, prior.guard_digest);
    assert_eq!(carried.original, prior.original);
    assert_eq!(
        carried.used.view_interpretations,
        prior.used.view_interpretations
    );
    assert!(carried.used.check_supported_view_contexts().unwrap());
    assert_ne!(after.state.sources, before.state.sources);
    assert_eq!(after.state.sources.len(), before.state.sources.len());
    assert_eq!(after.state.branches, before.state.branches);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.binding, before.state.binding);
    assert!(
        after
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .iter()
            .any(|row| row.pack_id == retired.pack)
    );
    assert!(fixture.config.root.join(pack.pack_key()).exists());
    assert!(fixture.config.root.join(pack.index_key()).exists());
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn cold_fork_after_source_preserving_retirement_reads_zero_tree_nodes() {
    let fixture = Fixture::new().await;
    let (pack, modified) = orphan(&fixture).await;
    let mut collection = completed(&fixture, modified.checked_add(61).unwrap(), windows()).await;
    let source = fixture
        .guard()
        .store()
        .ref_get(SOURCE)
        .await
        .unwrap()
        .unwrap();
    let request = support::request(&fixture).await;
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pack, *pack.as_bytes());
    let carried = selected_lineage(&fixture).await;
    assert_eq!(carried.source, source);
    drop(collection);
    let reopened = support::reopen_for_cold(&fixture).await;
    let store = reopened.coordinator().store();
    let observer = store.observe_metadata_for_tests().unwrap();
    observer.reset();
    let root = terrane_format::refs::Commit::decode(&carried.commit_bytes)
        .unwrap()
        .tree;
    let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root).unwrap();
    let root_bytes = store.get(&identity, None).await.unwrap();
    assert!(observer.snapshot().node_gets > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &root_bytes).unwrap(),
        ))
        .await
        .unwrap();
    let calibrated = observer.snapshot();
    assert!(calibrated.node_puts > 0);
    assert!(calibrated.node_decodes > 0);
    observer.reset();
    let fork = reopened
        .fork(SOURCE, "refs/heads/_/carried-fork", request)
        .await
        .unwrap();
    let counts = observer.snapshot();
    assert_eq!(counts.node_gets, 0);
    assert_eq!(counts.node_decodes, 0);
    assert_eq!(counts.node_puts, 0);
    assert_eq!(counts.commit_puts, 1);
    assert_ne!(fork.commit, source.commit);
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Commit, &fork.commit)
        .unwrap();
    let commit_bytes = store.get(&identity, None).await.unwrap();
    let commit = terrane_format::refs::Commit::decode(&commit_bytes).unwrap();
    assert_eq!(commit.tree, root);
    assert_eq!(commit.parents, vec![source.commit]);
    assert!(commit.signature.is_some());
    let context = commit.profile_pair.commit_context.as_ref().unwrap();
    assert_eq!(context.reference(), "refs/heads/_/carried-fork");
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
        reopened.coordinator().guard().keys(),
        &roots,
        &[("refs/heads/_/carried-fork", fork.writer_epoch)],
    )
    .unwrap();
    assert_eq!(verified.identity(), fork.commit);
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_puts, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);

    assert_eq!(
        reopened
            .coordinator()
            .store()
            .ref_get(SOURCE)
            .await
            .unwrap(),
        Some(source)
    );
    assert_eq!(
        reopened
            .coordinator()
            .store()
            .ref_get("refs/heads/_/carried-fork")
            .await
            .unwrap(),
        Some(fork)
    );
    drop(reopened);
    fixture.cleanup();
}

#[tokio::test]
async fn expired_lease_source_drops_carry_without_reviving_witness_chunks() {
    let fixture = Fixture::new().await;
    let source = support::witness_source(&fixture).await;
    let (pack, modified) = orphan(&fixture).await;
    let mut collection = completed(&fixture, modified.checked_add(61).unwrap(), windows()).await;
    assert!(collection.roots().roots.iter().any(|root|
        root.commit == source.commit && root.reason == RootReason::RetentionWitness));
    let operation = collection.session.operation().unwrap();
    collection
        .session
        .renew(&Collector::new(fixture.guard(), &fixture.authority))
        .await
        .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let current = crate::selected_bridge::native_current_collection::qualify_retirement(
        fixture.guard(),
        &fixture.authority,
        &collection.session,
        &held,
        &observed,
        (collection.roots(), collection.state()),
        windows(),
    )
    .await
    .unwrap();
    let sources = current.sources().unwrap();
    assert!(sources.lineages().is_empty());
    assert!(sources.prior().is_empty());
    assert!(sources.marks().is_empty());
    assert!(!sources.protected().is_empty());
    let member = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    assert!(current.member_unmarked(&member));
    drop(current);
    drop(observed);
    drop(held);
    drop(holder);
    operation.complete();
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.cycle, collection.roots().cycle);
    assert!(image(&fixture).await.state.sources.is_empty());
    assert!(fixture.config.root.join(pack.pack_key()).exists());
    assert_eq!(
        fixture.guard().store().ref_get(SOURCE).await.unwrap(),
        Some(source)
    );
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn changed_selected_source_original_or_interpretation_refuses_stale_carry() {
    use std::io::Write;
    use std::time::Duration;
    use terrane_format::gc::publication::evidence::{ControlKind, ViewInterpretationMode};
    for change in ["source", "original", "interpretation"] {
        let fixture = Fixture::new().await;
        let (pack, modified) = orphan(&fixture).await;
        let mut collection =
            completed(&fixture, modified.checked_add(61).unwrap(), windows()).await;
        let before = image(&fixture).await;
        let lineage = selected_lineage(&fixture).await;
        let (path, bytes) = match change {
            "source" => {
                let key = BucketKey::ref_record(SOURCE).unwrap();
                let path = fixture.config.root.join(key.as_str());
                let mut changed = lineage.source.clone();
                changed.writer_epoch = changed.writer_epoch.checked_add(1).unwrap();
                (path, changed.encode().unwrap())
            }
            "original" => {
                let pin = lineage
                    .controls
                    .iter()
                    .find(|pin| pin.kind == ControlKind::Association)
                    .unwrap();
                let path = fixture.authority.control().join(&pin.key);
                let mut bytes = std::fs::read(&path).unwrap();
                bytes.push(0);
                (path, bytes)
            }
            "interpretation" => {
                let row = before
                    .state
                    .sources
                    .iter()
                    .find(|row| row.name == SOURCE)
                    .unwrap();
                let suffix: String = row
                    .digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                let path = fixture
                    .parent
                    .join(format!("publication/publication/lineage/{suffix}"));
                let mut changed = lineage.clone();
                let context = changed
                    .used
                    .view_interpretations
                    .as_mut()
                    .unwrap()
                    .first_mut()
                    .unwrap();
                context.mode = match context.mode {
                    ViewInterpretationMode::Legacy => ViewInterpretationMode::Recorded,
                    ViewInterpretationMode::Recorded => ViewInterpretationMode::Legacy,
                };
                (path, changed.encode().unwrap())
            }
            _ => unreachable!(),
        };
        let original = std::fs::read(&path).unwrap();
        let slot = fixture.next_checkpoint_slot().await;
        let (arrival, release) = fixture.fs.before_slot(slot);
        let waiter = tokio::task::spawn_blocking(move || {
            arrival.recv_timeout(Duration::from_secs(30)).unwrap()
        });
        let mut pending = Box::pin(collection.retire_one(fixture.repository.coordinator()));
        tokio::select! {
            result = &mut pending => panic!("retirement ended before actual held handoff: {result:?}"),
            result = waiter => result.unwrap(),
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        release.send(()).unwrap();
        let error = pending.await.unwrap_err();
        let CollectionError::Store(error) = error else {
            panic!("wrong actual native refusal: {error}")
        };
        assert_eq!(
            error.kind(),
            &crate::store::StoreErrorKind::Unavailable { retry_after: None }
        );
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "whole preimage changed"
        );
        fixture.fs.assert_current_pair_hook_consumed();
        std::fs::write(&path, &original).unwrap();
        let after = image(&fixture).await;
        assert_eq!(after.state.loss_generation, before.state.loss_generation);
        assert_eq!(after.state.sources, before.state.sources);
        assert_eq!(after.state.guard, before.state.guard);
        assert_eq!(after.state.branches, before.state.branches);
        assert_eq!(after.manifest, before.manifest);
        assert!(
            !fixture
                .config
                .root
                .join(format!("trash/51/{pack}"))
                .exists()
        );
        assert!(fixture.config.root.join(pack.pack_key()).exists());
        assert!(fixture.config.root.join(pack.index_key()).exists());
        drop(collection);
        fixture.cleanup();
    }
}

#[tokio::test]
async fn removed_index_marked_member_prevents_source_preserving_retirement() {
    use crate::bucket::publication::collection_observation::MetadataStore;
    let fixture = Fixture::new().await;
    let source = support::retained_source(&fixture, b"\x67forever", None).await;
    let selected = image(&fixture).await;
    let base = selected
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .map(|row| {
            let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
            support::rounded_modified(&fixture.config.root.join(pack.pack_key())).max(
                support::rounded_modified(&fixture.config.root.join(pack.index_key())),
            )
        })
        .max()
        .unwrap()
        .checked_add(61)
        .unwrap();
    let mut collection = completed(&fixture, base, windows()).await;
    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| root.commit == source.commit && root.reason == RootReason::Current)
    );
    let operation = collection.session.operation().unwrap();
    collection
        .session
        .renew(&Collector::new(fixture.guard(), &fixture.authority))
        .await
        .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let current = crate::selected_bridge::native_current_collection::qualify_retirement(
        fixture.guard(),
        &fixture.authority,
        &collection.session,
        &held,
        &observed,
        (collection.roots(), collection.state()),
        windows(),
    )
    .await
    .unwrap();
    let member = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    assert!(current.sources().unwrap().marks().contains(&member));
    let metadata = MetadataStore::new(&held, &observed, &collection.session);
    let catalog = metadata.collection_catalog().await.unwrap();
    let mut matched = false;
    for row in catalog.inventory().unwrap() {
        let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
        let index = metadata.pack_index(&catalog, pack).await.unwrap();
        if index
            .snapshot()
            .entries()
            .iter()
            .any(|entry| entry.hash() == &member)
        {
            matched = true;
            assert!(!current.members_unmarked(index.snapshot()));
            assert!(!current.member_unmarked(&member));
        }
    }
    assert!(matched);
    drop(current);
    drop(observed);
    drop(held);
    drop(holder);
    operation.complete();
    let before = image(&fixture).await;
    assert!(
        collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap()
            .is_none()
    );
    let after = image(&fixture).await;
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.state.sources, before.state.sources);
    assert_eq!(after.manifest, before.manifest);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn lineage_stage_or_native_sync_failure_never_acknowledges_partial_carry() {
    use crate::store::native_publication_effects::collection::test_fs::RetirementPhase;
    use crate::store::{EffectFault, StoreErrorKind};
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let fixture = Fixture::new().await;
        let (pack, modified) = orphan(&fixture).await;
        let mut collection =
            completed(&fixture, modified.checked_add(61).unwrap(), windows()).await;
        let operation = collection.session.operation().unwrap();
        collection
            .session
            .renew(&Collector::new(fixture.guard(), &fixture.authority))
            .await
            .unwrap();
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let current = crate::selected_bridge::native_current_collection::qualify_retirement(
            fixture.guard(),
            &fixture.authority,
            &collection.session,
            &held,
            &observed,
            (collection.roots(), collection.state()),
            windows(),
        )
        .await
        .unwrap();
        let (lineage, _) = current
            .sources()
            .unwrap()
            .lineages()
            .iter()
            .find(|(row, _)| row.name == SOURCE)
            .unwrap();
        let suffix: String = lineage
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let target = fixture
            .parent
            .join(format!("publication/publication/lineage/{suffix}"));
        assert!(!target.exists());
        drop(current);
        drop(observed);
        drop(held);
        drop(holder);
        operation.complete();
        let before = image(&fixture).await;
        let conflicting = b"untrusted conflicting immutable lineage body";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .unwrap();
        file.write_all(conflicting).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let error = collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap_err();
        let CollectionError::Store(error) = error else {
            panic!("wrong actual immutable-stage refusal: {error}")
        };
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName("publication".into()))
        );
        assert_eq!(std::fs::read(&target).unwrap(), conflicting);
        let after = image(&fixture).await;
        assert_eq!(after.state.loss_generation, before.state.loss_generation);
        assert_eq!(after.state.sources, before.state.sources);
        assert_eq!(after.manifest, before.manifest);
        assert!(
            !fixture
                .config
                .root
                .join(format!("trash/51/{pack}"))
                .exists()
        );
        assert!(!support::journal(&fixture, &format!("trash/51/{pack}")).exists());
        assert!(fixture.config.root.join(pack.pack_key()).exists());
        assert!(fixture.config.root.join(pack.index_key()).exists());
        drop(collection);
        fixture.cleanup();
    }
    for point in 0..3 {
        let fault = match point {
            0 => None,
            1 => Some(EffectFault::BeforeFileSync),
            2 => Some(EffectFault::BeforeDirectorySync),
            _ => unreachable!(),
        };
        let fixture = Fixture::new().await;
        let (pack, modified) = orphan(&fixture).await;
        let mut collection =
            completed(&fixture, modified.checked_add(61).unwrap(), windows()).await;
        let before = image(&fixture).await;
        if let Some(fault) = fault {
            fixture
                .fs
                .fail_next_retirement(RetirementPhase::Barrier, fault, false);
        } else {
            fixture.fs.noop_next_retirement_barrier();
        }
        let error = collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap_err();
        let CollectionError::Store(error) = error else {
            panic!("wrong actual native refusal: {error}")
        };
        let expected = if point != 0 {
            StoreErrorKind::Unavailable { retry_after: None }
        } else {
            StoreErrorKind::Unsupported
        };
        assert_eq!(error.kind(), &expected);
        let source = std::error::Error::source(&error).unwrap().to_string();
        assert_eq!(
            source,
            match point {
                1 => "injected creation file sync failure",
                2 => "injected creation directory sync failure",
                0 => "native retirement barrier acknowledgment unavailable",
                _ => unreachable!(),
            }
        );
        fixture.fs.assert_retirement_hook_consumed();
        let after = image(&fixture).await;
        assert_eq!(
            after.state.loss_generation,
            before.state.loss_generation + 1
        );
        let carried = selected_lineage(&fixture).await;
        assert_eq!(carried.loss_generation, after.state.loss_generation);
        assert!(carried.used.check_supported_view_contexts().unwrap());
        assert_eq!(carried.source, fixture.head);
        assert_eq!(after.state.guard, before.state.guard);
        assert_eq!(after.state.branches, before.state.branches);
        assert!(
            !fixture
                .config
                .root
                .join(format!("trash/51/{pack}"))
                .exists()
        );
        assert!(!support::journal(&fixture, &format!("trash/51/{pack}")).exists());
        assert!(fixture.config.root.join(pack.pack_key()).exists());
        assert!(fixture.config.root.join(pack.index_key()).exists());
        drop(collection);
        fixture.cleanup();
    }
}

async fn bounded_source_ancestry(reflog: &[u8], expected_count: bool) {
    use crate::bucket::publication::collection_observation::MetadataStore;
    use terrane_format::gc::ParentCutoff;
    let fixture = Fixture::new().await;
    let source = support::retained_source(&fixture, b"\x62gc", Some(reflog)).await;
    let mut collection =
        completed(&fixture, support::pair_age_base(&fixture).await, windows()).await;
    let selected_root = collection
        .roots()
        .roots
        .iter()
        .find(|root| root.reference.as_str() == SOURCE && root.reason == RootReason::Current)
        .unwrap();
    if expected_count {
        assert_eq!(selected_root.parent_cutoff, ParentCutoff::RootsOnly);
    } else {
        assert!(matches!(
            selected_root.parent_cutoff,
            ParentCutoff::Since(_)
        ));
    }
    let operation = collection.session.operation().unwrap();
    collection
        .session
        .renew(&Collector::new(fixture.guard(), &fixture.authority))
        .await
        .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let current = crate::selected_bridge::native_current_collection::qualify_retirement(
        fixture.guard(),
        &fixture.authority,
        &collection.session,
        &held,
        &observed,
        (collection.roots(), collection.state()),
        windows(),
    )
    .await
    .unwrap();
    let sources = current.sources().unwrap();
    let body = CheckedLineage::decode(
        &sources
            .lineages()
            .iter()
            .find(|(row, _)| row.name == SOURCE)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(body.source, source);
    assert!(body.used.views.iter().any(|row| row.view == source.commit));
    assert!(
        body.used
            .view_interpretations
            .as_ref()
            .unwrap()
            .iter()
            .any(|row| row.view == source.commit)
    );
    assert!(sources.marks().contains(&source.commit));
    let head = terrane_format::refs::Commit::decode(&body.commit_bytes).unwrap();
    assert!(sources.marks().contains(&head.tree));
    let member = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    assert!(!sources.marks().contains(&member));
    assert!(current.member_unmarked(&member));
    let metadata = MetadataStore::new(&held, &observed, &collection.session);
    let catalog = metadata.collection_catalog().await.unwrap();
    let mut candidate = None;
    for row in catalog.inventory().unwrap() {
        let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
        let index = metadata.pack_index(&catalog, pack).await.unwrap();
        if index
            .snapshot()
            .entries()
            .iter()
            .any(|row| row.hash() == &member)
        {
            assert!(current.members_unmarked(index.snapshot()));
            candidate = Some(pack);
        }
    }
    let candidate = candidate.unwrap();
    drop(current);
    drop(observed);
    drop(held);
    drop(holder);
    operation.complete();
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pack, *candidate.as_bytes());
    assert!(
        fixture
            .config
            .root
            .join(format!("trash/51/{candidate}"))
            .exists()
    );
    let carried = selected_lineage(&fixture).await;
    assert_eq!(carried.source, source);
    let request = support::request(&fixture).await;
    drop(collection);
    let reopened = support::reopen_for_cold(&fixture).await;
    let store = reopened.coordinator().store();
    let observer = store.observe_metadata_for_tests().unwrap();
    observer.reset();
    let root = terrane_format::refs::Commit::decode(&carried.commit_bytes)
        .unwrap()
        .tree;
    let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root).unwrap();
    let root_bytes = store.get(&identity, None).await.unwrap();
    assert!(observer.snapshot().node_gets > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &root_bytes).unwrap(),
        ))
        .await
        .unwrap();
    let calibrated = observer.snapshot();
    assert!(calibrated.node_puts > 0);
    assert!(calibrated.node_decodes > 0);
    observer.reset();
    let fork = reopened
        .fork(SOURCE, "refs/heads/_/carried-fork", request)
        .await
        .unwrap();
    let counts = observer.snapshot();
    assert_eq!(counts.node_gets, 0);
    assert_eq!(counts.node_decodes, 0);
    assert_eq!(counts.node_puts, 0);
    assert_eq!(counts.commit_puts, 1);
    assert_ne!(fork.commit, source.commit);
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Commit, &fork.commit)
        .unwrap();
    let commit_bytes = store.get(&identity, None).await.unwrap();
    let commit = terrane_format::refs::Commit::decode(&commit_bytes).unwrap();
    assert_eq!(commit.tree, root);
    assert_eq!(commit.parents, vec![source.commit]);
    assert!(commit.signature.is_some());
    let context = commit.profile_pair.commit_context.as_ref().unwrap();
    assert_eq!(context.reference(), "refs/heads/_/carried-fork");
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
        reopened.coordinator().guard().keys(),
        &roots,
        &[("refs/heads/_/carried-fork", fork.writer_epoch)],
    )
    .unwrap();
    assert_eq!(verified.identity(), fork.commit);
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_puts, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);

    assert_eq!(store.ref_get(SOURCE).await.unwrap(), Some(source));
    assert_eq!(
        store.ref_get("refs/heads/_/carried-fork").await.unwrap(),
        Some(fork)
    );
    drop(reopened);
    fixture.cleanup();
}

#[tokio::test]
async fn count_zero_source_carry_does_not_revive_unrelated_parent_chunks() {
    bounded_source_ancestry(b"\x82\x65count\x00", true).await;
}

#[tokio::test]
async fn duration_source_carry_does_not_revive_expired_parent_chunks() {
    bounded_source_ancestry(b"\x18\x3c", false).await;
}
