//! Refuses changed earlier native pairs during a later actual acquisition.
//!
//! Genuine lease, metadata and executor acknowledgments supply the fixture.
//! These acquisition-boundary witnesses check retained-prefix continuity and
//! cancellation lifetime; they do not isolate mutation during the reverse pass
//! or establish copied-retirement permission from physical observations.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded real filesystem fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::gc::lease::Collector;
use crate::gc::runner::{fixture::Fixture, session::Session};
use crate::pack::PackId;
use crate::store::{Clock, ContentStore, ContentUpload, StoreErrorKind};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use terrane_format::bucket::BucketKey;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

async fn add_data(fixture: &Fixture, plaintext: &[u8]) {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    fixture
        .guard()
        .store()
        .put(ContentUpload::Chunk(crate::store::ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: crate::store::ChunkPosition::Final,
            profile: &fixture.config.chunk_profile,
        }))
        .await
        .unwrap();
}

fn replace_same_bytes(path: &Path) {
    let original = std::fs::File::open(path).unwrap();
    let before = original.metadata().unwrap();
    let bytes = std::fs::read(path).unwrap();
    let replacement = path.with_extension("retained-prefix-replacement");
    std::fs::write(&replacement, &bytes).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(before.mode())).unwrap();
    std::fs::rename(replacement, path).unwrap();

    let after = std::fs::symlink_metadata(path).unwrap();
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

fn mutate_same_inode(path: &Path) {
    let before = std::fs::symlink_metadata(path).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(b"changed after earlier acknowledgment")
        .unwrap();

    let after = std::fs::symlink_metadata(path).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert!(after.len() > before.len());
}

async fn retained_prefix_refusal(cancelled: bool) {
    let fixture = Fixture::new().await;
    add_data(&fixture, b"first independent retained-prefix placement").await;
    add_data(&fixture, b"second independent retained-prefix placement").await;
    let receipt = Collector::new(fixture.guard(), &fixture.authority)
        .acquire("pair-bracketing".into(), 1_000)
        .await
        .unwrap();
    let session =
        Session::from_receipt(receipt, 1_000, fixture.clock.retain_native_clock().unwrap())
            .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let selected = held.observe_publication_unrepaired().await.unwrap();
    let metadata = MetadataStore::new(&held, &selected, &session);
    let catalog = metadata.collection_catalog().await.unwrap();
    let mut reads = Vec::new();
    for row in catalog.inventory().unwrap().iter().take(3) {
        reads.push(
            metadata
                .pack_index(&catalog, PackId::from_random_bytes(row.pack_id))
                .await
                .unwrap(),
        );
    }
    assert_eq!(reads.len(), 3);
    drop(metadata);

    let (mut frame, control) = super::super::raw::backend_with_control(&fixture.fs, &selected)
        .await
        .unwrap();
    // This typed check retains the real clock for native effect mechanics; the
    // real Frame supplies physical exclusion, not collector deletion authority.
    let base_current = crate::selected_bridge::effect_test_checks::deadline_check(
        fixture.clock.retain_native_clock().unwrap(),
        fixture.clock.monotonic(),
        Duration::from_secs(1_000),
    );
    frame.final_check = Some(base_current.clone());
    let mut pairs = Vec::new();
    fixture.fs.reset();
    for read in &reads[..2] {
        session.recheck().unwrap();
        frame
            .observed_read(
                &fixture.fs,
                read.index().path(),
                read.index().bytes(),
                read.index().metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await
            .unwrap();
        let (plan, receiver) =
            super::super::super::artifact_seal::restore_pair::eligible_data_pair_plan(
                &fixture.config.root,
                &control,
                read,
                frame.owner,
            )
            .unwrap();
        frame.execute(&fixture.fs, plan).await.unwrap();
        pairs.push(receiver.take().unwrap());
    }
    frame.final_check = Some(base_current.with_restore_pairs(&pairs));
    assert_eq!(fixture.fs.effects(), 2);

    session.recheck().unwrap();
    let later = &reads[2];
    frame
        .observed_read(
            &fixture.fs,
            later.index().path(),
            later.index().bytes(),
            later.index().metadata(),
            FencePolicy::Payload { owner: frame.owner },
        )
        .await
        .unwrap();
    let (plan, receiver) =
        super::super::super::artifact_seal::restore_pair::eligible_data_pair_plan(
            &fixture.config.root,
            &control,
            later,
            frame.owner,
        )
        .unwrap();
    let (arrived, release) = fixture
        .fs
        .pause_current_pair(later.pack_path().to_owned(), true);
    let arrival =
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut pending = Box::pin(frame.execute(&fixture.fs, plan));
    tokio::select! {
        result = &mut pending => panic!("later pair returned before native read handoff: {result:?}"),
        result = arrival => result.unwrap(),
    }
    // The earlier pack body is not a whole Frame preimage. Its genuine retained
    // pair must independently notice this change when the later worker refreshes.
    if cancelled {
        mutate_same_inode(reads[0].pack_path());
    } else {
        replace_same_bytes(reads[0].pack_path());
    }

    if cancelled {
        drop(pending);
    } else {
        release.send(()).unwrap();
        let error = pending.await.unwrap_err();
        assert!(matches!(
            error.kind(),
            StoreErrorKind::Unsupported | StoreErrorKind::Unavailable { .. }
        ));
    }
    drop(frame);
    drop(pairs);
    drop(selected);
    drop(held);
    drop(holder);

    if cancelled {
        let namespace = fixture
            .config
            .root
            .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(namespace)
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
    }
    assert!(receiver.take().is_err());
    fixture.fs.assert_current_pair_hook_consumed();
    assert_eq!(fixture.fs.effects(), 3);
    session.recheck().unwrap();
    drop(session);
    fixture.cleanup();
}

#[tokio::test]
async fn collector_pairs_refuse_earlier_replacement_during_later_native_observation() {
    retained_prefix_refusal(false).await;
}

#[tokio::test]
async fn collector_pairs_cancelled_later_worker_keeps_earlier_receipt_and_exclusion() {
    retained_prefix_refusal(true).await;
}
