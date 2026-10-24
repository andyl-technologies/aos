//! Checks real local reopen and expired-lease takeover without imported barrier age.

use super::fs::Phase;
use super::support::{CopiedFixture, Residue};
use crate::bucket::held::SingleHeld;
use crate::gc::runner::CollectionError;
use crate::store::{RefStore, StoreErrorKind};
use std::os::unix::fs::MetadataExt;
use terrane_format::gc::retirement::{BarrierArtifact, PermanentDeleteAuthorization};
use terrane_format::gc::{ArtifactBinding, CreationJournal, GcLease, JournalState, Tombstone};

/// Reopens genuine committed Trash, then obtains a wholly fresh native first owner.
///
/// # Panics
/// Panics on fixture setup, typed refusal, physical preservation or full wait failure.
pub(super) async fn qualify(takeover: bool) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let name = "refs/heads/_/main";
    let source = fixture.guard().store().ref_get(name).await.unwrap();
    fixture.guard().store().fs().noop(Phase::Barrier);
    let failure = fixture.attempt().await.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Unavailable { retry_after: None })),
        "{failure}"
    );
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation]
    );
    let old_lease = {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        GcLease::decode(observed.logical()["gc/lease"].as_deref().unwrap()).unwrap()
    };
    let mut rows = Vec::new();
    let mut cycles = tokio::fs::read_dir(fixture.guard().store().root().join("trash"))
        .await
        .unwrap();
    while let Some(cycle) = cycles.next_entry().await.unwrap() {
        let mut files = tokio::fs::read_dir(cycle.path()).await.unwrap();
        while let Some(file) = files.next_entry().await.unwrap() {
            let path = file.path();
            let bytes = tokio::fs::read(&path).await.unwrap();
            let tombstone = Tombstone::decode(&bytes).unwrap();
            assert_eq!(tombstone.pack, *fixture.pack.as_bytes());
            assert_eq!(tombstone.removed, 0);
            let metadata = tokio::fs::metadata(&path).await.unwrap();
            let key = path
                .strip_prefix(fixture.guard().store().root())
                .unwrap()
                .to_str()
                .unwrap();
            let suffix: String = blake3::hash(key.as_bytes())
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let journal_path = fixture
                .source
                .parent
                .join("copied-publication/.terrane-creation")
                .join(suffix);
            let journal_bytes = tokio::fs::read(&journal_path).await.unwrap();
            let journal = CreationJournal::decode(&journal_bytes).unwrap();
            assert!(matches!(
                journal.state,
                JournalState::Committed {
                    binding: ArtifactBinding::Trash(ref actual),
                    ..
                } if actual == &bytes
            ));
            rows.push((
                path,
                bytes,
                (metadata.dev(), metadata.ino()),
                journal_path,
                journal_bytes,
            ));
        }
    }
    assert_eq!(rows.len(), 1);
    fixture.expire_selected_lease().await;
    let fixture = fixture.reopen().await;
    assert!(fixture.guard().store().fs().completed().is_empty());
    let holder_name = if takeover {
        "independent-takeover"
    } else {
        "copied-first-owner"
    };
    let operation = fixture.own_with_holder(holder_name).await;
    let PermanentDeleteAuthorization::Copied(authorization) = operation.authorization else {
        panic!("actual copied authorization expected");
    };
    assert!(authorization.lease.epoch > old_lease.epoch);
    assert_eq!(authorization.lease.holder, holder_name);
    if takeover {
        assert_ne!(authorization.lease.holder, old_lease.holder);
    }
    let BarrierArtifact::Local(barrier) = authorization.barrier else {
        panic!("actual new local barrier expected");
    };
    assert_ne!(fixture.guard().store().root().join(barrier.key), rows[0].0);
    for (path, bytes, identity, journal, journal_bytes) in rows {
        assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
        let metadata = tokio::fs::metadata(path).await.unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
        assert_eq!(tokio::fs::read(journal).await.unwrap(), journal_bytes);
    }
    assert_eq!(fixture.guard().store().ref_get(name).await.unwrap(), source);
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation, Phase::Barrier, Phase::Ownership]
    );
    fixture.cleanup();
}
