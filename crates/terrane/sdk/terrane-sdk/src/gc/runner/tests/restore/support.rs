//! Supplies genuine native admission and initial retirement for restore witnesses.

use super::super::*;
use crate::bucket::held::SingleHeld;
use crate::pack::{PackId, PackIndexSnapshot};
use crate::store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload, StoreErrorKind};
use std::collections::BTreeMap;
use std::time::UNIX_EPOCH;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::Tombstone;
use terrane_format::gc::publication::PublicationState;

/// Captures actual whole selected semantics for independent successor assertions.
pub(super) struct Image {
    /// Actual complete selected state.
    pub(super) state: PublicationState,
    /// Actual selected logical projection.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Actual decoded selected capabilities.
    pub(super) cap: BucketCapabilities,
    /// Actual decoded selected generation manifest.
    pub(super) manifest: GenerationManifest,
}

/// Reads complete authoritative selected semantics under actual backend exclusion.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
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
    Image {
        state: observed.state().clone(),
        logical: observed.logical().clone(),
        cap,
        manifest,
    }
}

/// Resolves the protected canonical creation-journal path for one physical key.
pub(super) fn journal(fixture: &Fixture, key: &str) -> std::path::PathBuf {
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

/// Rounds an actual descriptor modification time conservatively upward.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) fn rounded_modified(path: &std::path::Path) -> u64 {
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
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) async fn orphan(fixture: &Fixture) -> (PackId, u64) {
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

/// Names a genuine collector with retained native clock and controls.
pub(super) type NativeCollection<'a> = Collection<
    'a,
    crate::store::native_publication_effects::collection::test_fs::TestFs,
    crate::store::NativeEffectClock,
    super::super::super::fixture::Validator,
    crate::store::NativeEffectClock,
>;

/// Completes a genuine collection after choosing a backend-anchored wall base.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) async fn completed(
    fixture: &Fixture,
    base: u64,
    configured: Windows,
) -> NativeCollection<'_> {
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

/// Extracts the actual typed storage refusal from a collection result.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) fn failure_kind(error: &CollectionError) -> &StoreErrorKind {
    match error {
        CollectionError::Store(error) => error.kind(),
        _ => panic!("expected native storage refusal: {error}"),
    }
}

/// Retires a real newly admitted unrooted pack through the complete native producer.
///
/// # Panics
/// Panics when production admission, complete marking or initial retirement fails.
pub(super) async fn retired(fixture: &Fixture) -> (NativeCollection<'_>, PackId, Tombstone) {
    let (id, upper) = orphan(fixture).await;
    let base = upper
        .checked_add(windows().grace())
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut collection = completed(fixture, base, windows()).await;
    let trash = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trash.pack, *id.as_bytes());
    (collection, id, trash)
}

/// Predicts exactly the restore successor independently of its encoded generation.
///
/// # Panics
/// Panics if any unrelated selected semantics or native container bytes change.
pub(super) async fn assert_restored(fixture: &Fixture, before: &Image, id: PackId) {
    let after = image(fixture).await;
    assert_eq!(after.state.binding, before.state.binding);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.branches, before.state.branches);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.state.sources, before.state.sources);
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
    assert_eq!(after.manifest.inventory, before.manifest.inventory);
    assert_eq!(after.manifest.burns, before.manifest.burns);
    assert_eq!(after.manifest.cycle, before.manifest.cycle);
    let mut exclusions = before.manifest.exclusions.clone().unwrap();
    exclusions.retain(|row| row.pack_id != *id.as_bytes());
    assert_eq!(after.manifest.exclusions, Some(exclusions));
    assert!(after.cap.generation.unwrap() > before.cap.generation.unwrap());
    let mut expected_cap = before.cap.clone();
    expected_cap.generation = after.cap.generation;
    assert_eq!(after.cap, expected_cap);
    for (key, value) in &before.logical {
        if key != "gc/lease" && key != "CAPABILITIES" {
            assert_eq!(after.logical.get(key), Some(value));
        }
    }
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}

/// Proves exact Live placement under the restore trap, then ordinary serving.
///
/// The detached index supplies the independent physical record oracle. The
/// original restore executor's data-body trap remains armed throughout this
/// check. A separately reopened ordinary serving observer may read data bodies
/// when its public `has` verifies the restored member; that phase supplies no
/// collector permission and may update only the ordinary capability probe.
///
/// # Panics
/// Panics if the canonical orphan record, selected Live row or `has` differs,
/// or if the armed data-body read trap observes a body request.
pub(super) async fn assert_orphan_live(fixture: &Fixture, id: PackId) {
    let identity = TERRANE_V1
        .calculate(
            IdentityKind::Chunk,
            b"unreferenced genuine retirement candidate",
        )
        .unwrap();
    let hash = identity.terrane_v1_digest().unwrap();
    let bytes = tokio::fs::read(fixture.config.root.join(id.index_key()))
        .await
        .unwrap();
    let (header, records) = terrane_format::pack_format::decode_detached_index(&bytes).unwrap();
    assert_eq!(header.id(), id.as_bytes());
    let record = records
        .into_iter()
        .find(|record| record.hash == hash)
        .unwrap();
    let after = image(fixture).await;
    let key = format!(
        "objects/index/{}/{}.idx",
        after.manifest.generation, hash[0]
    );
    let selected =
        terrane_format::pack_format::decode_shard(after.logical[&key].as_deref().unwrap(), hash[0])
            .unwrap();
    assert_eq!(
        selected
            .into_iter()
            .find(|row| row.record.hash == hash)
            .unwrap(),
        terrane_format::pack_format::MergedRecord {
            record,
            pack: *id.as_bytes(),
            state: crate::pack::RecordState::Live as u8,
        }
    );
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);

    let serving = FileBucket::open(
        fixture.config.clone(),
        crate::store::TokioLocalFs,
        fixture.clock.retain_native_clock().unwrap(),
        super::super::super::fixture::Validator,
    )
    .await
    .unwrap();
    assert_eq!(serving.has(&[identity]).await.unwrap(), vec![true]);
    let after_probe = image(fixture).await;
    let mut expected_cap = after.cap.clone();
    expected_cap.probed_at = after_probe.cap.probed_at;
    assert_eq!(after_probe.cap, expected_cap);
    assert_eq!(after_probe.manifest, after.manifest);
    assert_eq!(after_probe.state.binding, after.state.binding);
    assert_eq!(after_probe.state.guard, after.state.guard);
    assert_eq!(after_probe.state.branches, after.state.branches);
    assert_eq!(after_probe.state.sources, after.state.sources);
    assert_eq!(
        after_probe.state.loss_generation,
        after.state.loss_generation
    );
    assert_eq!(after_probe.state.burn_owners, after.state.burn_owners);
    for (key, value) in &after.logical {
        if key != "CAPABILITIES" {
            assert_eq!(after_probe.logical.get(key), Some(value));
        }
    }
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}

/// Admits the canonical future Derived root node as an initially unrooted Meta pack.
///
/// # Panics
/// Panics if real metadata admission, the independent tree oracle or inventory fails.
pub(super) async fn orphan_meta(
    fixture: &Fixture,
) -> (PackId, u64, terrane_format::identity::Identity) {
    use crate::store::MetaUpload;
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};
    let plaintext = b"derived source";
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(chunk.terrane_v1_digest().unwrap()),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
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
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let node = tree.nodes().next().unwrap();
    let identity = fixture
        .guard()
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Node, node.encoded()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(identity.terrane_v1_digest().unwrap(), tree.root_identity());
    let before = image(fixture).await;
    let hash = identity.terrane_v1_digest().unwrap();
    let mut id = None;
    let mut data = Vec::new();
    for row in before.manifest.inventory.as_ref().unwrap() {
        let candidate = PackId::from_random_bytes(row.pack_id);
        let bytes = tokio::fs::read(fixture.config.root.join(candidate.index_key()))
            .await
            .unwrap();
        let index = PackIndexSnapshot::decode(&bytes, before.manifest.generation).unwrap();
        if bytes[6] & 2 == 0 {
            data.push(fixture.config.root.join(candidate.pack_key()));
        }
        if index.entries().iter().any(|entry| entry.hash() == &hash) {
            assert_ne!(bytes[6] & 2, 0);
            id = Some(candidate);
        }
    }
    fixture.fs.forbid_data_body_reads(&data).unwrap();
    let id = id.unwrap();
    let upper = rounded_modified(&fixture.config.root.join(id.pack_key()))
        .max(rounded_modified(&fixture.config.root.join(id.index_key())));
    (id, upper, identity)
}

/// Exercises candidate-only Meta history after genuine fresh publication and body loss.
///
/// # Panics
/// Panics if the genuine retired node, replacement root, loss or restore oracle fails.
pub(super) async fn restore_meta_after_reopen() {
    restore_meta_reopened(false).await;
}

/// Exercises bounded startup selection and marking after required Meta restoration.
///
/// # Panics
/// Panics if native selection, restoration or original-session marking fails.
pub(super) async fn restore_meta_at_startup() {
    restore_meta_reopened(true).await;
}

async fn restore_meta_reopened(startup: bool) {
    let fixture = Fixture::new().await;
    let (id, upper, node) = orphan_meta(&fixture).await;
    let node_body = fixture.guard().store().get(&node, None).await.unwrap();
    let mut collection = completed(&fixture, upper + windows().grace() + 1, windows()).await;
    let trash = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trash.pack, *id.as_bytes());
    // Isolate the replacement node before committing its new root. The writer
    // batches new metadata with the signed Commit; losing that whole batch
    // would also lose the Commit, which the old node pack cannot restore.
    let admitted = fixture
        .guard()
        .store()
        .put(ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &node_body).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(admitted, node);
    let replacement = fixture.publish_derived().await;
    assert_ne!(replacement.commit, fixture.head.commit);
    let commit_identity = TERRANE_V1
        .from_digest(IdentityKind::Commit, &replacement.commit)
        .unwrap();
    let commit_body = fixture
        .guard()
        .store()
        .get(&commit_identity, None)
        .await
        .unwrap();
    let commit = terrane_format::refs::Commit::decode(&commit_body).unwrap();
    assert_eq!(commit.tree, node.terrane_v1_digest().unwrap());
    let before = image(&fixture).await;
    let mut data_paths = Vec::new();
    for entry in before.manifest.inventory.as_ref().unwrap() {
        let id = PackId::from_random_bytes(entry.pack_id);
        let bytes = tokio::fs::read(fixture.config.root.join(id.index_key()))
            .await
            .unwrap();
        if bytes[6] & 2 == 0 {
            data_paths.push(fixture.config.root.join(id.pack_key()));
        }
    }
    fixture.fs.forbid_data_body_reads(&data_paths).unwrap();
    let hash = node.terrane_v1_digest().unwrap();
    let key = format!(
        "objects/index/{}/{}.idx",
        before.manifest.generation, hash[0]
    );
    let rows = terrane_format::pack_format::decode_shard(
        before.logical[&key].as_deref().unwrap(),
        hash[0],
    )
    .unwrap();
    let row = rows
        .iter()
        .find(|row| row.record.hash == hash)
        .unwrap()
        .clone();
    assert_eq!(row.state, crate::pack::RecordState::Live as u8);
    assert_ne!(row.pack, *id.as_bytes());
    let fresh = PackId::from_random_bytes(row.pack);
    let fresh_index = tokio::fs::read(fixture.config.root.join(fresh.index_key()))
        .await
        .unwrap();
    let fresh_index = PackIndexSnapshot::decode(&fresh_index, before.manifest.generation).unwrap();
    assert_eq!(fresh_index.entries().len(), 1);
    assert_eq!(fresh_index.entries()[0].hash(), &hash);
    tokio::fs::remove_file(fixture.config.root.join(fresh.pack_key()))
        .await
        .unwrap();
    let expiry = collection.lease().expiry;
    drop(collection);
    fixture.clock.set(expiry + 1, expiry - 99);
    let reopened = fixture.reopen_repository().await;
    let mut maintenance = if startup {
        Restoration::start_next(
            reopened.coordinator().guard(),
            &fixture.authority,
            "meta-startup-maintenance".into(),
            1_000,
            windows(),
        )
        .await
        .unwrap()
    } else {
        Restoration::start(
            reopened.coordinator().guard(),
            &fixture.authority,
            "meta-maintenance".into(),
            1_000,
            52,
            windows(),
        )
        .await
        .unwrap()
    };
    let mut startup_cursor =
        crate::gc::runner::maintenance::restoration::RestorationCursor::default();
    if startup {
        let candidates = maintenance
            .restoration_hints(&mut startup_cursor, 1)
            .await
            .unwrap();
        assert_eq!(candidates, vec![super::selector(&trash)]);
        assert!(
            maintenance
                .local_deletion_hint(&candidates[0])
                .await
                .unwrap()
                .is_none()
        );
    }
    if startup {
        let holder = SingleHeld::acquire(reopened.coordinator().guard().store())
            .await
            .unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let metadata = crate::bucket::publication::collection_observation::MetadataStore::new(
            &held,
            &observed,
            &maintenance.session,
        );
        let error = metadata.get(&node, None).await.unwrap_err();
        assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    }
    let restore_before = image(&fixture).await;
    assert!(
        maintenance
            .restore_pack(super::selector(&trash))
            .await
            .unwrap()
    );
    assert_restored(&fixture, &restore_before, id).await;
    let after = image(&fixture).await;
    let key = format!(
        "objects/index/{}/{}.idx",
        after.manifest.generation, hash[0]
    );
    let rows =
        terrane_format::pack_format::decode_shard(after.logical[&key].as_deref().unwrap(), hash[0])
            .unwrap();
    assert_eq!(rows.iter().find(|row| row.record.hash == hash), Some(&row));
    assert!(!fixture.config.root.join(fresh.pack_key()).exists());
    if startup {
        {
            let holder = SingleHeld::acquire(reopened.coordinator().guard().store())
                .await
                .unwrap();
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await.unwrap();
            let metadata = crate::bucket::publication::collection_observation::MetadataStore::new(
                &held,
                &observed,
                &maintenance.session,
            );
            assert_eq!(metadata.get(&node, None).await.unwrap(), node_body);
            let reads = metadata.reads().unwrap();
            assert!(reads.iter().any(|read| read.path()
                == fixture.config.root.join(fresh.pack_key())
                && read.bytes().is_none()));
            assert!(reads.iter().any(|read| read.path()
                == fixture.config.root.join(id.pack_key())
                && read.bytes().is_some()));
        }
        // An eligible duplicate must not hide present corrupt primary bytes.
        // Remove only this deliberate replacement, leaving the original loss.
        let missing_path = fixture.config.root.join(fresh.pack_key());
        let mut corrupt_primary = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&missing_path)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut corrupt_primary, b"corrupt primary")
            .await
            .unwrap();
        corrupt_primary.sync_all().await.unwrap();
        drop(corrupt_primary);
        {
            let holder = SingleHeld::acquire(reopened.coordinator().guard().store())
                .await
                .unwrap();
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await.unwrap();
            let metadata = crate::bucket::publication::collection_observation::MetadataStore::new(
                &held,
                &observed,
                &maintenance.session,
            );
            let error = metadata.get(&node, None).await.unwrap_err();
            assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
        }
        tokio::fs::remove_file(&missing_path).await.unwrap();
        assert!(!missing_path.exists());
        assert!(
            maintenance
                .restoration_hints(&mut startup_cursor, 1)
                .await
                .unwrap()
                .is_empty()
        );
        let lease = maintenance.lease().clone();
        let mut collection = maintenance.begin_next_collection().await.unwrap();
        assert_eq!(collection.lease().holder, lease.holder);
        assert_eq!(collection.lease().epoch, lease.epoch);
        assert!(
            collection
                .roots()
                .roots
                .iter()
                .any(|root| root.commit == replacement.commit)
        );
        collection.mark_batch(32).await.unwrap();
        collection.finish_mark().await.unwrap();
        assert_eq!(collection.state().phase, Phase::Sweep);
    }
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}
