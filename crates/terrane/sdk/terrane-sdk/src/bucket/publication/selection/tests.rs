//! Compares fresh held refusal behavior with a populated pure decode memo.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::{DecodeMemo, resolve_held, resolve_held_reusing};
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::{Selected as SelectedChain, control::Control};
use crate::bucket::tests::{PreparedCas, Selected, control_path, fixture};
use crate::store::StoreFailure;
use terrane_format::gc::publication::{PublicationCommit, PublicationTransaction};
use terrane_format::refs::RefRecord;

fn assert_same_resolution(
    ordinary: Result<SelectedChain, StoreFailure>,
    cached: Result<SelectedChain, StoreFailure>,
) -> Option<SelectedChain> {
    match (ordinary, cached) {
        (Ok(ordinary), Ok(cached)) => {
            assert_same_selection(&ordinary, &cached);
            Some(cached)
        }
        (Err(ordinary), Err(cached)) => {
            assert_eq!(ordinary.kind(), cached.kind());
            None
        }
        (Ok(_), Err(error)) => panic!("memo rejected a valid resolution: {error:?}"),
        (Err(error), Ok(_)) => panic!("memo accepted a rejected resolution: {error:?}"),
    }
}

fn assert_same_selection(expected: &SelectedChain, current: &SelectedChain) {
    assert_eq!(expected.state, current.state);
    assert_eq!(expected.digest, current.digest);
    assert_eq!(expected.logical, current.logical);
    assert_eq!(expected.snapshot, current.snapshot);
    assert_eq!(expected.control_identity, current.control_identity);
}

#[tokio::test]
async fn populated_memo_preserves_fresh_record_mutation_and_absence_refusals() {
    let bucket = fixture().await;
    let record = RefRecord::first([1; 32], 1, Default::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/memo", None, &record)
        .await
        .unwrap();
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();
    let memo = DecodeMemo::new();
    let before = resolve_held_reusing(&bucket, &control, &held, &memo)
        .await
        .unwrap();
    let repeated = resolve_held_reusing(&bucket, &control, &held, &memo)
        .await
        .unwrap();
    assert_same_selection(&before, &repeated);
    // This compares retained record counts, not filesystem read dispatches.
    assert_eq!(before.reads.len(), repeated.reads.len());
    let observed = adapter.observe_for_read().await.unwrap();
    observed.revalidate().await.unwrap();
    observed.revalidate().await.unwrap();

    let slot_path = control
        .path
        .join(format!("publication/commits/{}", before.state.revision));
    let commit = PublicationCommit::decode(&tokio::fs::read(&slot_path).await.unwrap()).unwrap();
    let transaction_path = control.path.join(&commit.transaction_key);
    let transaction =
        PublicationTransaction::decode(&tokio::fs::read(&transaction_path).await.unwrap()).unwrap();
    let snapshot_path = bucket.root().join(&transaction.snapshot.key);

    // Earlier valid prefix entries remain populated while a later exact input
    // changes or disappears. The memo must never supply the missing fresh read.
    for path in [
        control.path.join("backend-registration.cbor"),
        slot_path.clone(),
        transaction_path,
        snapshot_path,
    ] {
        let original = tokio::fs::read(&path).await.unwrap();
        for missing in [false, true] {
            if missing {
                tokio::fs::remove_file(&path).await.unwrap();
            } else {
                tokio::fs::write(&path, [0xff]).await.unwrap();
            }

            let current = assert_same_resolution(
                resolve_held(&bucket, &control, &held).await,
                resolve_held_reusing(&bucket, &control, &held, &memo).await,
            );
            if missing && path == slot_path {
                let current = current.unwrap();
                assert!(current.state.revision < before.state.revision);
                assert_ne!(current.digest, before.digest);
            } else {
                assert!(current.is_none(), "{}", path.display());
            }
            // Missing the last slot legitimately exposes its valid predecessor;
            // complete observation comparison must still reject that changed tip.
            assert!(observed.revalidate().await.is_err(), "{}", path.display());

            tokio::fs::write(&path, &original).await.unwrap();
            // A removed protected record loses its original file mode.
            if path.starts_with(&control.path) {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .await
                    .unwrap();
            }

            let restored = assert_same_resolution(
                resolve_held(&bucket, &control, &held).await,
                resolve_held_reusing(&bucket, &control, &held, &memo).await,
            )
            .unwrap();
            assert_same_selection(&before, &restored);
            observed.revalidate().await.unwrap();
        }
    }

    // A newly visible malformed successor cannot be hidden by a memoized tip.
    let successor = control
        .path
        .join(format!("publication/commits/{}", before.state.revision + 1));
    tokio::fs::write(&successor, [0xff]).await.unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&successor, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
    }
    assert!(
        assert_same_resolution(
            resolve_held(&bucket, &control, &held).await,
            resolve_held_reusing(&bucket, &control, &held, &memo).await,
        )
        .is_none()
    );
    assert!(observed.revalidate().await.is_err());

    tokio::fs::remove_file(&successor).await.unwrap();
    let restored = assert_same_resolution(
        resolve_held(&bucket, &control, &held).await,
        resolve_held_reusing(&bucket, &control, &held, &memo).await,
    )
    .unwrap();
    assert_same_selection(&before, &restored);
    observed.revalidate().await.unwrap();

    drop(observed);
    drop(holder);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}

#[tokio::test]
async fn initial_retained_memo_preserves_recipes_and_fresh_physical_refusals() {
    let bucket = fixture().await;
    let record = RefRecord::first([2; 32], 1, Default::default()).selected();
    bucket
        .prepared_cas("refs/heads/_/retained-memo", None, &record)
        .await
        .unwrap();
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let adapter = holder.destination();
    let held = adapter.identity_proof();
    let control = Control::open(&bucket, false).await.unwrap();
    let memo = DecodeMemo::new();

    let uncached = super::resolve_held_mode(
        &bucket,
        &control,
        &held,
        super::PayloadRetention::Ordinary,
        None,
    )
    .await
    .unwrap();
    let initial = super::resolve_held_ordinary_retained(&bucket, &control, &held, &memo)
        .await
        .unwrap();
    let repeated = super::resolve_held_ordinary_retained(&bucket, &control, &held, &memo)
        .await
        .unwrap();
    assert_same_selection(&uncached, &initial);
    assert_same_selection(&initial, &repeated);
    assert_eq!(uncached.reads.len(), initial.reads.len());
    assert_eq!(initial.reads.len(), repeated.reads.len());
    for ((uncached, initial), repeated) in uncached
        .reads
        .iter()
        .zip(&initial.reads)
        .zip(&repeated.reads)
    {
        assert_eq!(uncached.path(), initial.path());
        assert_eq!(initial.path(), repeated.path());
        assert_eq!(uncached.bytes(), initial.bytes());
        assert_eq!(initial.bytes(), repeated.bytes());
        assert_eq!(
            uncached.is_ordinary_retained(),
            initial.is_ordinary_retained()
        );
        assert_eq!(
            initial.is_ordinary_retained(),
            repeated.is_ordinary_retained()
        );
        initial.revalidate_retained(&bucket.inner.fs).await.unwrap();
        repeated
            .revalidate_retained(&bucket.inner.fs)
            .await
            .unwrap();
    }
    assert!(initial.reads.iter().any(|read| read.is_ordinary_retained()));
    assert!(
        initial
            .reads
            .iter()
            .any(|read| read.retained_payload().is_some())
    );

    let observed = adapter.observe_for_read_ordinary_retained().await.unwrap();
    observed
        .revalidate_physical_reads(&bucket.inner.fs)
        .await
        .unwrap();
    observed
        .revalidate_physical_reads(&bucket.inner.fs)
        .await
        .unwrap();
    let snapshot_path = bucket.root().join(&initial.snapshot.key);
    let original = tokio::fs::read(&snapshot_path).await.unwrap();

    // A populated initial memo cannot supply bytes after a fresh read changes.
    tokio::fs::write(&snapshot_path, [0xff]).await.unwrap();
    assert!(
        assert_same_resolution(
            super::resolve_held_mode(
                &bucket,
                &control,
                &held,
                super::PayloadRetention::Ordinary,
                None,
            )
            .await,
            super::resolve_held_ordinary_retained(&bucket, &control, &held, &memo).await,
        )
        .is_none()
    );
    assert!(observed.revalidate().await.is_err());
    tokio::fs::write(&snapshot_path, &original).await.unwrap();
    drop(observed);
    let restored = super::resolve_held_ordinary_retained(&bucket, &control, &held, &memo)
        .await
        .unwrap();
    let observed = adapter.observe_for_read_ordinary_retained().await.unwrap();
    observed
        .revalidate_physical_reads(&bucket.inner.fs)
        .await
        .unwrap();

    // Fresh complete selection may accept identical bytes at a new incarnation;
    // the actual original receipt must still reject that physical replacement.
    let replacement = snapshot_path.with_extension("memo-replacement");
    tokio::fs::copy(&snapshot_path, &replacement).await.unwrap();
    tokio::fs::rename(&replacement, &snapshot_path)
        .await
        .unwrap();
    let fresh = assert_same_resolution(
        super::resolve_held_mode(
            &bucket,
            &control,
            &held,
            super::PayloadRetention::Ordinary,
            None,
        )
        .await,
        super::resolve_held_ordinary_retained(&bucket, &control, &held, &memo).await,
    )
    .unwrap();
    assert_same_selection(&initial, &fresh);
    let original_snapshot = restored
        .reads
        .iter()
        .find(|read| read.path() == snapshot_path)
        .unwrap();
    assert!(
        original_snapshot
            .revalidate_retained(&bucket.inner.fs)
            .await
            .is_err()
    );
    assert!(
        observed
            .revalidate_physical_reads(&bucket.inner.fs)
            .await
            .is_err()
    );

    drop(observed);
    drop(holder);
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
    tokio::fs::remove_dir_all(control_path(bucket.root()))
        .await
        .unwrap();
}
