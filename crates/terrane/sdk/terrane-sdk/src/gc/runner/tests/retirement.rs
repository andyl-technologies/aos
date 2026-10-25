//! Qualifies initial retirement with genuine native creators and backend-anchored age.
//!
//! These cases leave physical containers present and selected deletion progress
//! unchanged. No Tombstone, journal or returned record is treated as elapsed D,
//! restore permission or permanent ownership. Data-pack body traps remain armed.

mod durability;

use super::*;
use crate::bucket::held::SingleHeld;
use crate::pack::{PackId, PackIndexSnapshot};
use crate::store::native_publication_effects::collection::test_fs::RetirementPhase;
use crate::store::{
    ChunkPosition, ChunkUpload, ContentStore, ContentUpload, EffectFault, StoreErrorKind,
};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationState, PublicationTransaction,
};
use terrane_format::gc::{ArtifactBinding, CreationJournal, JournalState, Tombstone};

use terrane_format::gc::publication::evidence::CheckedLineage;

pub(super) struct Image {
    state: PublicationState,
    logical: BTreeMap<String, Option<Vec<u8>>>,
    cap: BucketCapabilities,
    manifest: GenerationManifest,
    lineages: BTreeMap<String, CheckedLineage>,
}

pub(super) async fn image(fixture: &Fixture) -> Image {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let cap =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{}/MANIFEST", cap.generation.unwrap())]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut lineages = BTreeMap::new();
    for source in &observed.state().sources {
        let read = held
            .selected_lineage_record(&observed, &source.name)
            .await
            .unwrap()
            .unwrap();
        let bytes = read.bytes().unwrap();
        assert_eq!(*blake3::hash(bytes).as_bytes(), source.digest);
        let lineage = CheckedLineage::decode(bytes).unwrap();
        assert_eq!(lineage.source_name, source.name);
        assert!(lineages.insert(source.name.clone(), lineage).is_none());
    }
    Image {
        state: observed.state().clone(),
        logical: observed.logical().clone(),
        cap,
        manifest,
        lineages,
    }
}

fn journal(fixture: &Fixture, key: &str) -> std::path::PathBuf {
    let suffix = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    fixture
        .parent
        .join("publication/.terrane-creation")
        .join(suffix)
}

fn rounded_modified(path: &std::path::Path) -> u64 {
    let elapsed = std::fs::symlink_metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    elapsed
        .as_secs()
        .checked_add(u64::from(elapsed.subsec_nanos() != 0))
        .unwrap()
}

/// Creates one unrooted chunk through actual production container admission.
async fn orphan(fixture: &Fixture) -> (PackId, u64) {
    let plaintext = b"unreferenced genuine retirement candidate";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    let uploaded = fixture
        .guard()
        .store()
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &fixture.config.chunk_profile,
        }))
        .await
        .unwrap();
    assert_eq!(uploaded, identity);
    let before = image(fixture).await;
    let digest = identity.terrane_v1_digest().unwrap();
    let mut candidate = None;
    let mut data = Vec::new();
    for row in before.manifest.inventory.as_ref().unwrap() {
        let id = PackId::from_random_bytes(row.pack_id);
        let bytes = tokio::fs::read(fixture.config.root.join(id.index_key()))
            .await
            .unwrap();
        assert_eq!(&bytes[..6], b"TRPK\x01\x00");
        let index = PackIndexSnapshot::decode(&bytes, before.cap.generation.unwrap()).unwrap();
        if bytes[6] & 2 == 0 {
            data.push(fixture.config.root.join(id.pack_key()));
        }
        if index.entries().iter().any(|row| row.hash() == &digest) {
            assert_eq!(bytes[6] & 2, 0);
            candidate = Some(id);
        }
    }
    let id = candidate.unwrap();
    let upper = rounded_modified(&fixture.config.root.join(id.pack_key()))
        .max(rounded_modified(&fixture.config.root.join(id.index_key())));
    // Establish the injected wall base from actual backend metadata BEFORE
    // acquiring the collector. No file or commit timestamp is rewritten.
    fixture.fs.forbid_data_body_reads(&data).unwrap();
    (id, upper)
}

type NativeCollection<'a> = Collection<
    'a,
    crate::store::native_publication_effects::collection::test_fs::TestFs,
    crate::store::NativeEffectClock,
    super::super::fixture::Validator,
    crate::store::NativeEffectClock,
>;

async fn completed(fixture: &Fixture, base: u64, configured: Windows) -> NativeCollection<'_> {
    fixture.clock.set(base, base.checked_sub(100).unwrap());
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "retirement-collector".into(),
        1_000,
        51,
        configured,
    )
    .await
    .unwrap();
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    assert_eq!(collection.state().phase, Phase::Sweep);
    collection
}

fn failure_kind(error: &CollectionError) -> &StoreErrorKind {
    match error {
        CollectionError::Store(error) => error.kind(),
        _ => panic!("expected native storage refusal: {error}"),
    }
}

fn native_failure_contains(error: &CollectionError, expected: &str) {
    use std::error::Error;
    assert_eq!(
        failure_kind(error),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.to_string().contains(expected) {
            return;
        }
        source = cause.source();
    }
    panic!("original native cause missing: {error}");
}

// Each expected source comes from actual prior protected selection. Newly
// completed history may consume additional ancestors, but it must independently
// preserve every prior signed view, interpretation and administrative dependency.
pub(super) fn assert_carried(previous: &Image, after: &Image) {
    let mut names = Vec::new();
    for (name, prior) in &previous.lineages {
        if prior.used.view_interpretations.is_none() {
            assert!(!after.lineages.contains_key(name));
            continue;
        }
        assert!(prior.used.check_supported_view_contexts().unwrap());
        names.push(name.as_str());
        let next = after.lineages.get(name).unwrap();
        assert_eq!(next.source_name, prior.source_name);
        assert_eq!(next.source, prior.source);
        assert_eq!(next.commit_id, prior.commit_id);
        assert_eq!(next.commit_bytes, prior.commit_bytes);
        assert_eq!(next.guard_digest, prior.guard_digest);
        assert_eq!(Some(next.guard_digest), after.state.guard);
        assert_eq!(next.original, prior.original);
        assert_eq!(next.loss_generation, after.state.loss_generation);
        assert_eq!(prior.loss_generation, previous.state.loss_generation);
        assert_eq!(next.controls, next.used.controls);
        assert_eq!(next.used.configuration, prior.used.configuration);
        assert_eq!(next.used.registries, prior.used.registries);
        assert!(next.used.check_supported_view_contexts().unwrap());
        assert!(prior.controls.iter().all(|pin| next.controls.contains(pin)));
        assert!(
            prior
                .used
                .issuers
                .iter()
                .all(|row| next.used.issuers.contains(row))
        );
        assert!(
            prior
                .used
                .disclosures
                .iter()
                .all(|row| next.used.disclosures.contains(row))
        );
        assert!(
            prior
                .used
                .views
                .iter()
                .all(|view| next.used.views.contains(view))
        );
        let contexts = next.used.view_interpretations.as_ref().unwrap();
        assert!(
            prior
                .used
                .view_interpretations
                .as_ref()
                .unwrap()
                .iter()
                .all(|context| contexts.contains(context))
        );
    }
    assert_eq!(
        after
            .state
            .sources
            .iter()
            .map(|row| row.name.as_str())
            .collect::<Vec<_>>(),
        names
    );
    assert_eq!(after.lineages.len(), names.len());
}

async fn assert_preserved(
    fixture: &Fixture,
    previous: &Image,
    id: PackId,
    cycle: u64,
    excluded: bool,
) {
    let after = image(fixture).await;
    assert_eq!(after.state.binding, previous.state.binding);
    assert_eq!(after.state.guard, previous.state.guard);
    assert_eq!(after.state.branches, previous.state.branches);
    assert_eq!(after.state.burn_owners, previous.state.burn_owners);
    assert_eq!(after.manifest.inventory, previous.manifest.inventory);
    assert_eq!(after.manifest.burns, previous.manifest.burns);
    let mut expected = previous.manifest.exclusions.clone().unwrap();
    if excluded {
        let row = after
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .iter()
            .find(|row| row.pack_id == *id.as_bytes())
            .unwrap()
            .clone();
        assert_eq!(row.cycle, cycle);
        assert!(row.epoch > 0);
        let position = expected
            .binary_search_by_key(id.as_bytes(), |row| row.pack_id)
            .unwrap_err();
        expected.insert(position, row);
        assert_carried(previous, &after);
        assert_eq!(
            after.state.loss_generation,
            previous.state.loss_generation + 1
        );
    } else {
        assert_eq!(after.cap.generation, previous.cap.generation);
        assert_eq!(after.state.loss_generation, previous.state.loss_generation);
        assert_eq!(after.state.sources, previous.state.sources);
        assert_eq!(after.lineages, previous.lineages);
    }
    assert_eq!(after.manifest.exclusions, Some(expected));
    for (key, value) in &previous.logical {
        if key != "gc/lease" && key != "CAPABILITIES" {
            assert_eq!(after.logical.get(key), Some(value));
        }
    }
    if excluded {
        for shard in &previous.manifest.shards {
            let old_key = format!(
                "objects/index/{}/{}.idx",
                previous.manifest.generation, shard.shard
            );
            let new_key = format!(
                "objects/index/{}/{}.idx",
                after.manifest.generation, shard.shard
            );
            let old = previous.logical[&old_key].as_deref().unwrap();
            let new = after.logical[&new_key].as_deref().unwrap();
            let mut expected =
                terrane_format::pack_format::decode_shard(old, shard.shard as u8).unwrap();
            for row in &mut expected {
                if row.pack == *id.as_bytes() && row.state == 0 {
                    row.state = 1;
                }
            }
            assert_eq!(new, terrane_format::pack_format::encode_shard(&expected));
            let new_row = after
                .manifest
                .shards
                .iter()
                .find(|row| row.shard == shard.shard)
                .unwrap();
            if old == new {
                assert_eq!(new_row, shard);
                if shard.filter.is_some() {
                    let old_key = format!(
                        "objects/index/{}/{}.flt",
                        previous.manifest.generation, shard.shard
                    );
                    let new_key = format!(
                        "objects/index/{}/{}.flt",
                        after.manifest.generation, shard.shard
                    );
                    assert_eq!(after.logical[&new_key], previous.logical[&old_key]);
                }
            } else {
                assert!(new_row.filter.is_none());
            }
        }
    }
    assert!(fixture.config.root.join(id.pack_key()).exists());
    assert!(fixture.config.root.join(id.index_key()).exists());
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}

#[tokio::test]
async fn gc_initial_retirement_native_selects_exact_exclusion_then_committed_trash() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let base = upper
        .checked_add(windows().grace())
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut collection = completed(&fixture, base, windows()).await;
    let before = image(&fixture).await;
    let progress = collection.state().clone();
    let tombstone = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tombstone.pack, *id.as_bytes());
    assert_eq!(tombstone.cycle, collection.roots().cycle);
    assert_eq!(tombstone.timestamp, base);
    assert_eq!(collection.state(), &progress);
    let key = format!("trash/{}/{id}", tombstone.cycle);
    let bytes = tokio::fs::read(fixture.config.root.join(&key))
        .await
        .unwrap();
    assert_eq!(Tombstone::decode(&bytes).unwrap(), tombstone);
    assert_eq!(bytes, tombstone.encode());
    let record =
        CreationJournal::decode(&tokio::fs::read(journal(&fixture, &key)).await.unwrap()).unwrap();
    assert_eq!(record.key, key);
    let JournalState::Committed {
        binding,
        file_identity,
    } = record.state
    else {
        panic!("Trash was not genuinely committed");
    };
    assert_eq!(binding, ArtifactBinding::Trash(bytes));
    let metadata = std::fs::symlink_metadata(fixture.config.root.join(&key)).unwrap();
    let identity = [metadata.dev().to_be_bytes(), metadata.ino().to_be_bytes()].concat();
    assert_eq!(file_identity, identity);
    let after = image(&fixture).await;
    let control = fixture.parent.join("publication");
    let slot = PublicationCommit::decode(
        &tokio::fs::read(control.join(format!("publication/commits/{}", after.state.revision)))
            .await
            .unwrap(),
    )
    .unwrap();
    let transaction = PublicationTransaction::decode(
        &tokio::fs::read(control.join(slot.transaction_key))
            .await
            .unwrap(),
    )
    .unwrap();
    let PublicationProof::Collection {
        removed, carried, ..
    } = transaction.proof
    else {
        panic!("not a case-2 collector transition");
    };
    assert_eq!(carried, before.state.sources);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].pack, *id.as_bytes());
    // Reopen can select a capabilities-probe update. Inspect the retirement
    // transaction first, then independently verify its persisted GC progress.
    assert_eq!(fixture.selected_state(tombstone.cycle).await, progress);
    assert_preserved(&fixture, &before, id, tombstone.cycle, true).await;
    assert!(
        collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap()
            .is_none()
    );
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_requested_retirement_preserves_marking_grace_and_exact_candidate_scope() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let base = upper.checked_add(windows().grace()).unwrap();
    let mut collection = completed(&fixture, base, windows()).await;
    let before = image(&fixture).await;
    let progress = collection.state().clone();

    let mut rooted = None;
    for row in before.manifest.inventory.as_ref().unwrap() {
        let pack = PackId::from_random_bytes(row.pack_id);
        let bytes = std::fs::read(fixture.config.root.join(pack.index_key())).unwrap();
        assert_eq!(
            TERRANE_V1
                .calculate(IdentityKind::Index, &bytes)
                .unwrap()
                .terrane_v1_digest()
                .unwrap(),
            row.index_hash
        );
        let index = PackIndexSnapshot::decode(&bytes, before.manifest.generation).unwrap();
        if index
            .entries()
            .iter()
            .any(|entry| entry.hash() == &fixture.head.commit)
        {
            rooted = Some(pack);
        }
    }
    let rooted = rooted.unwrap();
    assert_ne!(rooted, id);
    let missing = PackId::from_random_bytes([0; 16]);
    assert!(
        before
            .manifest
            .inventory
            .as_ref()
            .unwrap()
            .iter()
            .all(|row| row.pack_id != *missing.as_bytes())
    );

    // A caller-chosen ID cannot exempt a marked pack, create an absent pair,
    // or shorten the strict grace boundary for a real unmarked orphan.
    for requested in [rooted, missing, id] {
        assert!(
            collection
                .retire_pack(fixture.repository.coordinator(), requested)
                .await
                .unwrap()
                .is_none()
        );
        assert_preserved(&fixture, &before, id, 51, false).await;
        assert_eq!(collection.state(), &progress);
    }

    fixture
        .clock
        .set(base.checked_add(1).unwrap(), base.checked_sub(99).unwrap());
    assert!(
        collection
            .retire_pack(fixture.repository.coordinator(), rooted)
            .await
            .unwrap()
            .is_none()
    );
    let retired = collection
        .retire_pack(fixture.repository.coordinator(), id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pack, *id.as_bytes());
    assert_preserved(&fixture, &before, id, 51, true).await;
    assert_eq!(collection.state(), &progress);

    let after = image(&fixture).await;
    assert!(
        collection
            .retire_pack(fixture.repository.coordinator(), id)
            .await
            .unwrap()
            .is_none()
    );
    assert_preserved(&fixture, &after, id, 51, false).await;
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_initial_retirement_native_grace_uses_pair_backend_upper_bound() {
    for offset in [0, 60, 61] {
        let fixture = Fixture::new().await;
        let (id, upper) = orphan(&fixture).await;
        let mut collection =
            completed(&fixture, upper.checked_add(offset).unwrap(), windows()).await;
        let before = image(&fixture).await;
        let result = collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap();
        assert_eq!(result.is_some(), offset > 60);
        assert_preserved(&fixture, &before, id, 51, offset > 60).await;
        assert_eq!(
            fixture.config.root.join(format!("trash/51/{id}")).exists(),
            offset > 60
        );
        drop(collection);
        fixture.cleanup();
    }
}

#[tokio::test]
async fn gc_initial_retirement_native_refuses_unenforced_commit_window_before_effects() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let configured = Windows::new(29, 60, 60, 90).unwrap();
    let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), configured).await;
    let before = image(&fixture).await;
    fixture.fs.reset();
    assert!(matches!(
        collection
            .retire_one(fixture.repository.coordinator())
            .await,
        Err(CollectionError::Record(GcError::Window))
    ));
    assert_eq!(fixture.fs.effects(), 0);
    assert_preserved(&fixture, &before, id, 51, false).await;
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_initial_retirement_native_unknown_creator_never_mints_trash() {
    for (member, requested) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = Fixture::new().await;
        let (id, upper) = orphan(&fixture).await;
        let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), windows()).await;
        let before = image(&fixture).await;
        let key = if member {
            id.index_key()
        } else {
            id.pack_key()
        };
        tokio::fs::remove_file(journal(&fixture, &key))
            .await
            .unwrap();
        let error = if requested {
            collection
                .retire_pack(fixture.repository.coordinator(), id)
                .await
        } else {
            collection
                .retire_one(fixture.repository.coordinator())
                .await
        }
        .unwrap_err();
        assert_eq!(failure_kind(&error), &StoreErrorKind::Unsupported);
        assert_preserved(&fixture, &before, id, 51, false).await;
        assert!(!fixture.config.root.join(format!("trash/51/{id}")).exists());
        drop(collection);
        fixture.cleanup();
    }
}

#[tokio::test]
async fn gc_initial_retirement_native_barrier_requires_actual_closed_acknowledgment() {
    for failure in [
        None,
        Some(EffectFault::BeforeFileSync),
        Some(EffectFault::BeforeDirectorySync),
    ] {
        let fixture = Fixture::new().await;
        let (id, upper) = orphan(&fixture).await;
        let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), windows()).await;
        let before = image(&fixture).await;
        if let Some(fault) = failure {
            fixture
                .fs
                .fail_next_retirement(RetirementPhase::Barrier, fault, true);
        } else {
            fixture.fs.noop_next_retirement_barrier();
        }
        let error = collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap_err();
        assert_eq!(failure_kind(&error), &StoreErrorKind::Unsupported);
        fixture.fs.assert_retirement_hook_consumed();
        assert_preserved(&fixture, &before, id, 51, true).await;
        let key = format!("trash/51/{id}");
        assert!(!fixture.config.root.join(&key).exists());
        assert!(!journal(&fixture, &key).exists());
        drop(collection);
        fixture.cleanup();
    }
}

#[tokio::test]
async fn gc_initial_retirement_native_trash_faults_keep_exclusion_without_acknowledgment() {
    for (phase, point) in [
        (RetirementPhase::Pending, 0),
        (RetirementPhase::Pending, 1),
        (RetirementPhase::Artifact, 0),
        (RetirementPhase::Artifact, 1),
        (RetirementPhase::Commit, 0),
        (RetirementPhase::Commit, 2),
    ] {
        let fixture = Fixture::new().await;
        let (id, upper) = orphan(&fixture).await;
        let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), windows()).await;
        let before = image(&fixture).await;
        let fault = match point {
            0 => EffectFault::BeforeFileSync,
            1 => EffectFault::BeforeDirectorySync,
            _ => EffectFault::BeforeCommittedDirectorySyncAt(
                fixture.parent.join("publication/.terrane-creation"),
            ),
        };
        fixture.fs.fail_next_retirement(phase, fault, false);
        let error = collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap_err();
        native_failure_contains(
            &error,
            if point == 0 {
                "file sync failure"
            } else {
                "directory sync failure"
            },
        );
        fixture.fs.assert_retirement_hook_consumed();
        assert_preserved(&fixture, &before, id, 51, true).await;
        let key = format!("trash/51/{id}");
        if phase == RetirementPhase::Pending {
            assert!(!fixture.config.root.join(&key).exists());
        }
        if point == 2 {
            let record =
                CreationJournal::decode(&tokio::fs::read(journal(&fixture, &key)).await.unwrap())
                    .unwrap();
            assert!(matches!(record.state, JournalState::Committed { .. }));
        }
        assert!(
            collection
                .retire_one(fixture.repository.coordinator())
                .await
                .is_err()
        );
        drop(collection);
        fixture.cleanup();
    }
}

#[tokio::test]
async fn gc_initial_retirement_native_prior_cycle_history_refuses_missing_old_artifacts() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), windows()).await;
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    let key = format!("trash/{}/{id}", retired.cycle);
    tokio::fs::remove_file(fixture.config.root.join(&key))
        .await
        .unwrap();
    tokio::fs::remove_file(journal(&fixture, &key))
        .await
        .unwrap();
    let before = image(&fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    fixture.fs.reset();
    let error = crate::selected_bridge::native_collection_retirement::check_first_incarnation(
        &held,
        &observed,
        id.as_bytes(),
        retired.cycle,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), &StoreErrorKind::Unsupported);
    assert_eq!(fixture.fs.effects(), 0);
    drop(observed);
    drop(held);
    drop(holder);
    assert_preserved(&fixture, &before, id, 51, false).await;
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_initial_retirement_native_refreshes_clock_after_barrier_directory_sync() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let base = upper.checked_add(61).unwrap();
    let mut collection = completed(&fixture, base, windows()).await;
    let before = image(&fixture).await;
    let slot = fixture.next_checkpoint_slot().await;
    let (arrival, release) = fixture.fs.pause_retirement_barrier(slot);
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.retire_one(fixture.repository.coordinator()));
    tokio::select! {
        result=&mut operation=>panic!("retirement ended before native handoff: {}",result.is_ok()),
        result=waiter=>result.unwrap(),
    }
    // Renew adds one duration to the actual remaining selected lease. Crossing
    // that genuine expiry invalidates the same native clock/final-check state.
    let expiry = before.logical["gc/lease"]
        .as_deref()
        .map(terrane_format::gc::GcLease::decode)
        .unwrap()
        .unwrap()
        .expiry
        .checked_add(1_000)
        .unwrap();
    fixture.clock.set(expiry, expiry.checked_sub(100).unwrap());
    release.send(()).unwrap();
    let error = operation.await.unwrap_err();
    assert!(matches!(
        failure_kind(&error),
        StoreErrorKind::Denied { .. }
    ));
    fixture.fs.assert_retirement_hook_consumed();
    let key = format!("trash/51/{id}");
    assert!(!fixture.config.root.join(&key).exists());
    assert!(!journal(&fixture, &key).exists());
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_initial_retirement_native_cancellation_retains_exclusion_until_worker_finishes() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), windows()).await;
    let slot = fixture.next_checkpoint_slot().await;
    let (arrival, release) = fixture.fs.pause_retirement_barrier(slot);
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.retire_one(fixture.repository.coordinator()));
    tokio::select! {
        result=&mut operation=>panic!("retirement ended before held worker: {}",result.is_ok()),
        result=waiter=>result.unwrap(),
    }
    drop(operation);
    let lock = fixture
        .config
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    release.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            contender.lock().unwrap();
            contender.unlock().unwrap();
        }),
    )
    .await
    .unwrap()
    .unwrap();
    fixture.fs.assert_retirement_hook_consumed();
    let key = format!("trash/51/{id}");
    assert!(!fixture.config.root.join(&key).exists());
    assert!(!journal(&fixture, &key).exists());
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    assert!(
        collection
            .retire_one(fixture.repository.coordinator())
            .await
            .is_err()
    );
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_initial_retirement_native_prior_trash_or_journal_refuses_before_exclusion() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for prior_journal in [false, true] {
        let fixture = Fixture::new().await;
        let (id, upper) = orphan(&fixture).await;
        let mut collection = completed(&fixture, upper.checked_add(61).unwrap(), windows()).await;
        let before = image(&fixture).await;
        let key = format!("trash/51/{id}");
        let (path, bytes) = if prior_journal {
            let bytes = CreationJournal {
                key: key.clone(),
                nonce: [7; 32],
                state: JournalState::Pending,
            }
            .encode()
            .unwrap();
            assert_eq!(CreationJournal::decode(&bytes).unwrap().key, key);
            (journal(&fixture, &key), bytes)
        } else {
            let mut directories = std::fs::DirBuilder::new();
            directories
                .recursive(true)
                .mode(0o755)
                .create(fixture.config.root.join("trash/51"))
                .unwrap();
            (
                fixture.config.root.join(&key),
                Tombstone {
                    pack: *id.as_bytes(),
                    cycle: 51,
                    timestamp: upper,
                    removed: 1,
                    epoch: collection.lease().epoch,
                }
                .encode(),
            )
        };
        tokio::fs::write(&path, &bytes).await.unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        // These are refusal inputs, never constructor evidence or a receipt.
        let error = collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap_err();
        assert_eq!(failure_kind(&error), &StoreErrorKind::Unsupported);
        assert_preserved(&fixture, &before, id, 51, false).await;
        assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
        drop(collection);
        fixture.cleanup();
    }
}

/// Checks decoded creator data against the actual file without granting authority.
fn assert_native_creator(fixture: &Fixture, key: &str, expected: ArtifactBinding) {
    let record = CreationJournal::decode(&std::fs::read(journal(fixture, key)).unwrap()).unwrap();
    assert_eq!(record.key, key);
    let JournalState::Committed {
        binding,
        file_identity,
    } = record.state
    else {
        panic!("actual production creator did not complete");
    };
    assert_eq!(binding, expected);
    let metadata = std::fs::symlink_metadata(fixture.config.root.join(key)).unwrap();
    assert!(metadata.is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(
        file_identity,
        [metadata.dev().to_be_bytes(), metadata.ino().to_be_bytes()].concat()
    );
}

#[tokio::test]
async fn gc_initial_retirement_native_newer_index_controls_pair_grace() {
    let fixture = Fixture::new().await;
    let plaintext = b"genuine pack before independently newer detached index";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    let (arrival, release) = fixture.fs.pause_next_pack_seal(fixture.config.root.clone());
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut upload = Box::pin(
        fixture
            .guard()
            .store()
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: &encoded,
                identity: &identity,
                declared_plaintext_len: plaintext.len(),
                position: ChunkPosition::Final,
                profile: &fixture.config.chunk_profile,
            })),
    );
    tokio::select! {
        result = &mut upload => panic!("upload ended before actual pack sync: {}", result.is_ok()),
        result = waiter => result.unwrap(),
    }
    fixture.fs.assert_pack_seal_hook_consumed();
    let pack_path = fixture.fs.paused_pack_seal_path();
    let pack_upper = rounded_modified(&pack_path);
    let index_path = pack_path.with_extension("idx");
    assert!(!index_path.exists());
    let index_key = index_path
        .strip_prefix(&fixture.config.root)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!journal(&fixture, index_key).exists());
    let pack_key = pack_path
        .strip_prefix(&fixture.config.root)
        .unwrap()
        .to_str()
        .unwrap();
    let pending =
        CreationJournal::decode(&std::fs::read(journal(&fixture, pack_key)).unwrap()).unwrap();
    assert_eq!(pending.key, pack_key);
    assert!(matches!(pending.state, JournalState::Pending));

    // A separate file's actual backend timestamp delays the still-absent index.
    // Neither artifact timestamp is rewritten, and the age oracle below reads
    // only the real pack/index pair. Two rounded seconds ensure a full boundary
    // has passed even when the probe timestamp has fractional seconds.
    let timestamp_probe = fixture.parent.join("distinct-mtime-probe");
    let next_upper = pack_upper.checked_add(2).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::fs::write(&timestamp_probe, b"observe backend modification time")
                .await
                .unwrap();
            if rounded_modified(&timestamp_probe) >= next_upper {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    release.send(()).unwrap();
    assert_eq!(upload.await.unwrap(), identity);
    assert_eq!(rounded_modified(&pack_path), pack_upper);
    let index_upper = rounded_modified(&index_path);
    assert!(index_upper > pack_upper);

    let selected = image(&fixture).await;
    let row = selected
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| {
            fixture
                .config
                .root
                .join(PackId::from_random_bytes(row.pack_id).pack_key())
                == pack_path
        })
        .unwrap();
    let id = PackId::from_random_bytes(row.pack_id);
    let index_bytes = std::fs::read(&index_path).unwrap();
    assert_eq!(&index_bytes[..6], b"TRPK\x01\x00");
    assert_eq!(index_bytes[6] & 2, 0);
    let index = PackIndexSnapshot::decode(&index_bytes, selected.cap.generation.unwrap()).unwrap();
    assert!(
        index
            .entries()
            .iter()
            .any(|entry| entry.hash() == &identity.terrane_v1_digest().unwrap())
    );
    assert_native_creator(
        &fixture,
        &id.pack_key(),
        ArtifactBinding::Pack {
            digest: row.pack_hash,
            size: row.pack_size,
        },
    );
    assert_native_creator(
        &fixture,
        &id.index_key(),
        ArtifactBinding::Index {
            digest: row.index_hash,
            size: row.index_size,
        },
    );
    let data = selected
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .filter_map(|row| {
            let id = PackId::from_random_bytes(row.pack_id);
            let bytes = std::fs::read(fixture.config.root.join(id.index_key())).unwrap();
            assert_eq!(&bytes[..6], b"TRPK\x01\x00");
            if bytes[6] & 2 == 0 {
                Some(fixture.config.root.join(id.pack_key()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    fixture.fs.forbid_data_body_reads(&data).unwrap();

    // Establish the actual pair-derived injected wall base before acquisition.
    let pair_upper = pack_upper.max(index_upper);
    let base = pair_upper.checked_add(windows().grace()).unwrap();
    assert!(windows().sweep_age(base, pack_upper));
    assert!(!windows().sweep_age(base, pair_upper));
    let mut collection = completed(&fixture, base, windows()).await;
    let before = image(&fixture).await;
    assert!(
        collection
            .retire_one(fixture.repository.coordinator())
            .await
            .unwrap()
            .is_none()
    );
    assert_preserved(&fixture, &before, id, 51, false).await;
    assert!(!fixture.config.root.join(format!("trash/51/{id}")).exists());
    assert!(!journal(&fixture, &format!("trash/51/{id}")).exists());

    // Advance only the same already-retained clock, preserving its relation.
    // Strict G now holds for the newer index as well as the pack.
    let later = base.checked_add(1).unwrap();
    fixture.clock.set(later, later.checked_sub(100).unwrap());
    let progress = collection.state().clone();
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pack, *id.as_bytes());
    assert_eq!(retired.timestamp, later);
    assert_eq!(collection.state(), &progress);
    assert_eq!(fixture.selected_state(51).await, progress);
    let trash_key = format!("trash/51/{id}");
    let trash_bytes = std::fs::read(fixture.config.root.join(&trash_key)).unwrap();
    assert_eq!(trash_bytes, retired.encode());
    assert_native_creator(&fixture, &trash_key, ArtifactBinding::Trash(trash_bytes));
    assert_preserved(&fixture, &before, id, 51, true).await;
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    drop(collection);
    fixture.cleanup();
}
