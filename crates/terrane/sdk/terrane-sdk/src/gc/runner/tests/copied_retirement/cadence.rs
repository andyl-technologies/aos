//! Checks real lease ACKs and refusals during effect-free copied-barrier polling.
//!
//! Selected slots, whole leases and physical controls are observed from actual
//! native publications. Clock faults cannot supply elapsed ownership evidence.

use super::fs::Phase;
use super::support::{CopiedFixture, Residue};
use crate::bucket::held::SingleHeld;
use crate::gc::lease::Collector;
use crate::gc::runner::CollectionError;
use crate::store::{Clock, RefStore, StoreErrorKind};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::gc::GcLease;
use terrane_format::gc::publication::{
    PermanentOwnerSelection, PublicationCommit, PublicationTransaction,
};

/// Rereads a genuinely acknowledged lease slot and its actual current selection.
///
/// # Panics
/// Panics on missing native evidence, changed selected slot or unequal whole lease.
pub(super) async fn acknowledged_lease(fixture: &CopiedFixture, slot_path: &Path) -> GcLease {
    let slot_bytes = tokio::fs::read(slot_path).await.unwrap();
    let slot = PublicationCommit::decode(&slot_bytes).unwrap();
    let transaction_bytes = tokio::fs::read(
        fixture
            .source
            .parent
            .join("copied-publication")
            .join(&slot.transaction_key),
    )
    .await
    .unwrap();
    assert_eq!(
        *blake3::hash(&transaction_bytes).as_bytes(),
        slot.transaction_digest
    );
    let transaction = PublicationTransaction::decode(&transaction_bytes).unwrap();
    assert_eq!(transaction.changes.len(), 1);
    let change = &transaction.changes[0];
    assert_eq!(change.key, "gc/lease");
    let bytes = change.new.as_deref().unwrap();
    let lease = GcLease::decode(bytes).unwrap();

    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!(
        observed.stamp(),
        (slot.revision, *blake3::hash(&slot_bytes).as_bytes())
    );
    assert_eq!(observed.logical()["gc/lease"].as_deref().unwrap(), bytes);
    assert_eq!(
        tokio::fs::read(held.root().join("gc/lease")).await.unwrap(),
        bytes
    );
    assert!(
        observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .any(|owner| {
                owner.pack == *fixture.pack.as_bytes()
                    && owner.selection == PermanentOwnerSelection::CopiedVisibility
            })
    );
    lease
}

async fn changed_during_skipped_renewal(guard_record: bool) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let source_before = fixture
        .guard()
        .store()
        .ref_get("refs/heads/_/main")
        .await
        .unwrap();
    let (arrived, release) = fixture.guard().store().fs().pause_completed(Phase::Barrier);
    let change = async {
        arrived.await.unwrap();
        let mut acknowledgments = fixture.guard().store().fs().observe_lease_completions();
        release.send(()).unwrap();
        let slot = acknowledgments.recv().await.unwrap();
        let old = acknowledged_lease(&fixture, &slot).await;

        // Wait through real timer polls after the first acknowledged renewal.
        // Reading selected state grants no authority and produces no progress.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(matches!(
            acknowledgments.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        assert_eq!(
            GcLease::decode(observed.logical()["gc/lease"].as_deref().unwrap()).unwrap(),
            old
        );
        let stamp = observed.stamp();
        let guard_path = if guard_record {
            Some(
                held.selected_guard_snapshot_record(&observed)
                    .await
                    .unwrap()
                    .unwrap()
                    .path()
                    .to_owned(),
            )
        } else {
            None
        };
        drop(observed);
        drop(held);
        drop(holder);

        let new = if let Some(path) = guard_path {
            let bytes = tokio::fs::read(&path).await.unwrap();
            let before = tokio::fs::metadata(&path).await.unwrap();
            let replacement = path.with_extension("skipped-renewal-control");
            tokio::fs::write(&replacement, &bytes).await.unwrap();
            tokio::fs::set_permissions(&replacement, before.permissions())
                .await
                .unwrap();
            tokio::fs::rename(replacement, &path).await.unwrap();
            let after = tokio::fs::metadata(&path).await.unwrap();
            assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
            old.clone()
        } else {
            let now = fixture
                .source
                .clock
                .now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let duration = old
                .expiry
                .checked_sub(now)
                .unwrap()
                .checked_add(90)
                .unwrap();
            // The public Collector really acknowledges a different whole lease;
            // its requested duration is derived from the actual current expiry.
            let receipt = Collector::new(fixture.guard(), &fixture.authority)
                .renew(&old, duration)
                .await
                .unwrap();
            let new = receipt.lease;
            let slot = acknowledgments.recv().await.unwrap();
            assert_eq!(acknowledged_lease(&fixture, &slot).await, new);
            assert_eq!(new.holder, old.holder);
            assert_eq!(new.epoch, old.epoch);
            assert!(new.expiry > old.expiry);
            new
        };
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(matches!(
            acknowledgments.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty
                | tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        if guard_record {
            assert_eq!(observed.stamp(), stamp);
        }
        assert_eq!(
            GcLease::decode(observed.logical()["gc/lease"].as_deref().unwrap()).unwrap(),
            new
        );
        assert_eq!(
            fixture.guard().store().fs().completed(),
            vec![Phase::Preparation, Phase::Barrier]
        );
        new
    };
    let (result, new) = tokio::join!(fixture.attempt(), change);
    let failure = result.unwrap_err();
    if guard_record {
        assert!(
            matches!(&failure, CollectionError::Store(error) | CollectionError::Lease(crate::gc::lease::LeaseError::Store(error))
            if matches!(error.kind(), StoreErrorKind::Denied { .. } | StoreErrorKind::Unavailable { retry_after: None })),
            "{failure}"
        );
    } else {
        assert!(
            matches!(
                &failure,
                CollectionError::Lease(crate::gc::lease::LeaseError::Lease(
                    terrane_format::gc::GcError::LeaseLost
                ))
            ),
            "{failure}"
        );
    }
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation, Phase::Barrier]
    );
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let bytes = observed.logical()["gc/lease"].as_deref().unwrap();
    let selected = GcLease::decode(bytes).unwrap();
    if guard_record {
        // Fresh lease publishers still check the complete actual Guard. A
        // same-byte replacement cannot satisfy the immutable preparing Guard
        // at final copied qualification, even if a later lease ACK succeeds.
        assert_eq!(selected.holder, new.holder);
        assert_eq!(selected.epoch, new.epoch);
        assert!(selected.expiry >= new.expiry);
    } else {
        assert_eq!(selected, new);
    }
    assert_eq!(
        tokio::fs::read(held.root().join("gc/lease")).await.unwrap(),
        bytes
    );
    assert!(
        observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .any(|owner| {
                owner.pack == *fixture.pack.as_bytes()
                    && owner.selection == PermanentOwnerSelection::CopiedVisibility
            })
    );
    drop(observed);
    drop(held);
    drop(holder);
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        source_before
    );
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_skipped_renewal_whole_lease_change_refuses_owner() {
    changed_during_skipped_renewal(false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_skipped_renewal_guard_change_refuses_owner() {
    changed_during_skipped_renewal(true).await;
}

async fn clock_fault_during_skipped_renewal(regress: bool) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let source_before = fixture
        .guard()
        .store()
        .ref_get("refs/heads/_/main")
        .await
        .unwrap();
    let (arrived, release) = fixture.guard().store().fs().pause_completed(Phase::Barrier);
    let fault = async {
        arrived.await.unwrap();
        let mut acknowledgments = fixture.guard().store().fs().observe_lease_completions();
        release.send(()).unwrap();
        let slot = acknowledgments.recv().await.unwrap();
        let lease = acknowledged_lease(&fixture, &slot).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(matches!(
            acknowledgments.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        let monotonic = fixture.source.clock.monotonic().as_secs();
        assert!(monotonic > 0);
        if regress {
            let wall = fixture
                .source
                .clock
                .now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            fixture.source.clock.set(wall, 0);
        } else {
            // Exact actual expiry with forward monotonic progression cannot be
            // rescued by waiting for the next scheduled durable renewal.
            fixture
                .source
                .clock
                .set(lease.expiry, monotonic.checked_add(1).unwrap());
        }
        lease
    };
    let (result, lease) = tokio::join!(fixture.attempt(), fault);
    let failure = result.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Denied { .. })
            || (regress && matches!(error.kind(), StoreErrorKind::Unavailable { retry_after: None }))),
        "{failure}"
    );
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation, Phase::Barrier]
    );
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let bytes = observed.logical()["gc/lease"].as_deref().unwrap();
    assert_eq!(GcLease::decode(bytes).unwrap(), lease);
    assert_eq!(
        tokio::fs::read(held.root().join("gc/lease")).await.unwrap(),
        bytes
    );
    assert!(
        observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .any(|owner| {
                owner.pack == *fixture.pack.as_bytes()
                    && owner.selection == PermanentOwnerSelection::CopiedVisibility
            })
    );
    drop(observed);
    drop(held);
    drop(holder);
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        source_before
    );
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_skipped_renewal_expiry_or_clock_regression_refuses_owner() {
    clock_fault_during_skipped_renewal(false).await;
    clock_fault_during_skipped_renewal(true).await;
}
