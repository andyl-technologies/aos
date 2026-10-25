//! Exercises repeatable complete native passes, late residues and lease takeover.

use super::support::*;
use crate::gc::runner::copied_retirement_tests::support::{CopiedFixture, Residue};
use crate::gc::runner::maintenance::{MaintenanceCursor, MaintenanceHint};
use crate::gc::runner::permanent_local::Recovery;
use crate::store::{Clock, RefStore};
use terrane_format::gc::retirement::{ObservationState, PassCoverage, PassPhase};
use terrane_format::gc::{GcLease, Windows};

#[path = "recovery/renewal.rs"]
mod renewal;

#[path = "recovery/staging.rs"]
mod staging;

async fn residue_paths(fixture: &CopiedFixture) -> Vec<std::path::PathBuf> {
    let root = fixture.guard().store().root();
    let mut paths = vec![
        root.join(fixture.pack.pack_key()),
        root.join(fixture.pack.index_key()),
    ];
    let mut directories = tokio::fs::read_dir(root.join("trash")).await.unwrap();
    while let Some(entry) = directories.next_entry().await.unwrap() {
        assert!(entry.file_type().await.unwrap().is_dir());
        paths.push(entry.path().join(fixture.pack.to_string()));
    }
    paths.into_iter().filter(|path| path.exists()).collect()
}

fn assert_completed(image: &Image) {
    let pass = image.pass.as_ref().unwrap();
    assert_eq!(pass.phase, PassPhase::PassCompleted);
    assert_eq!(
        pass.coverage,
        [PassCoverage::CandidateTraversalCompleted; 3]
    );
    assert!(
        pass.observations
            .iter()
            .all(|row| row.state != ObservationState::Planned)
    );
}

#[tokio::test]
async fn permanent_local_collection_reconciles_with_its_original_live_session() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    fixture.own().await;
    let before = image(&fixture).await;
    let key = before.owner_key.as_deref().unwrap();
    let previous = GcLease::decode(before.logical["gc/lease"].as_deref().unwrap()).unwrap();
    let ticks = fixture
        .source
        .clock
        .monotonic()
        .as_secs()
        .checked_add(1)
        .unwrap();
    fixture
        .source
        .clock
        .set(previous.expiry.checked_add(1).unwrap(), ticks);
    let windows = Windows::new(30, 60, 60, 90).unwrap();
    let mut collection = fixture
        .repository
        .start_local_collection("combined-maintenance".into(), 90, 9001, windows)
        .await
        .unwrap();
    let roots = collection.roots().clone();
    let checkpoint = collection.state().clone();
    let initial = collection.lease().clone();
    assert!(
        Recovery::start(
            fixture.guard(),
            &fixture.authority,
            initial.holder.clone(),
            90,
            fixture.repository.coordinator(),
            windows,
        )
        .await
        .is_err()
    );

    let report = collection.reconcile_permanent(key, 8).await.unwrap();

    assert_eq!(report.reclaimed, 1);
    assert!(report.selected_events > report.reclaimed);
    assert!(
        !fixture
            .guard()
            .store()
            .root()
            .join(fixture.pack.pack_key())
            .exists()
    );
    assert_eq!(collection.roots(), &roots);
    assert_eq!(collection.state(), &checkpoint);
    assert_eq!(collection.lease().holder, initial.holder);
    assert_eq!(collection.lease().epoch, initial.epoch);
    let first = image(&fixture).await;
    assert_owner_retained(&before, &first);
    assert_completed(&first);
    assert_eq!(first.pass.as_ref().unwrap().lease, *collection.lease());

    // A completed pass cannot certify future absence. The same session must
    // qualify and remove genuinely late residue while retaining its checkpoint.
    let path = fixture.guard().store().root().join(fixture.pack.pack_key());
    tokio::fs::write(&path, b"late residue during the original marking session")
        .await
        .unwrap();
    let late = collection.reconcile_permanent(key, 8).await.unwrap();
    assert_eq!(late.reclaimed, 1);
    assert!(!path.exists());
    assert_eq!(collection.state(), &checkpoint);
    let after = image(&fixture).await;
    assert_owner_retained(&before, &after);
    assert_completed(&after);
    assert_eq!(
        after.pass.as_ref().unwrap().pass,
        first.pass.as_ref().unwrap().pass + 1
    );
    assert_eq!(after.pass.as_ref().unwrap().lease, *collection.lease());

    collection.mark_batch(1).await.unwrap();
    assert_eq!(collection.roots(), &roots);
    assert_eq!(collection.lease().epoch, initial.epoch);
    drop(collection);
    let fixture = reopen_checked(fixture, &after).await;
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_pass_reclaims_pack_index_and_all_observed_trash_cycles() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    fixture.own().await;
    let root = fixture.guard().store().root();
    tokio::fs::write(
        root.join(fixture.pack.index_key()),
        b"arbitrary copied index residue",
    )
    .await
    .unwrap();
    for cycle in [7, 13, 99] {
        tokio::fs::create_dir_all(root.join(format!("trash/{cycle}")))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(format!("trash/{cycle}/{}", fixture.pack)),
            b"untrusted old residue",
        )
        .await
        .unwrap();
    }
    // Empty canonical families still require real discovery. Their total
    // exceeds one encoded event without increasing its observation bound.
    let extra_cycles = 4100;
    assert!(extra_cycles > terrane_format::gc::retirement::MAX_OBSERVATIONS);
    for cycle in 1000..1000 + extra_cycles {
        tokio::fs::create_dir_all(root.join(format!("trash/{cycle}")))
            .await
            .unwrap();
    }
    let candidates = residue_paths(&fixture).await;
    assert!(candidates.len() >= 5);
    let before = image(&fixture).await;
    let branch = fixture
        .guard()
        .store()
        .ref_get("refs/heads/_/main")
        .await
        .unwrap();
    let mut recovery = takeover(&fixture, "recurring-all-families").await;
    let initial_lease = recovery.lease().clone();
    let mut acknowledgments = fixture.guard().store().fs().observe_lease_completions();

    let report = recovery
        .reconcile(before.owner_key.as_deref().unwrap(), 64)
        .await
        .unwrap();

    assert_eq!(report.reclaimed, candidates.len());
    assert!(report.selected_events > report.reclaimed);
    assert!(report.selected_events >= extra_cycles.div_ceil(128));
    for path in candidates {
        assert!(!path.exists());
    }
    let after = image(&fixture).await;
    assert_owner_retained(&before, &after);
    assert_completed(&after);
    assert_eq!(after.manifest, before.manifest);
    assert_eq!(after.capabilities, before.capabilities);
    assert_eq!(after.pass.as_ref().unwrap().lease, *recovery.lease());
    renewal::assert_selected_renewals(
        &fixture,
        &initial_lease,
        recovery.lease(),
        &mut acknowledgments,
    )
    .await;
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        branch
    );
    drop(recovery);
    let fixture = reopen_checked(fixture, &after).await;
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_empty_pass_keeps_owner_and_reclaims_late_same_key_residue() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    fixture.own().await;
    let before = image(&fixture).await;
    let key = before.owner_key.as_deref().unwrap();
    let mut recovery = takeover(&fixture, "recurring-empty-and-late").await;
    let mut cursor = MaintenanceCursor::default();
    let hints = recovery.maintenance_hints(&mut cursor, 1).await.unwrap();
    assert_eq!(
        hints,
        [MaintenanceHint::PermanentOwner {
            pack: fixture.pack,
            operation_key: key.to_owned(),
        }]
    );
    let initial_lease = recovery.lease().clone();
    let mut acknowledgments = fixture.guard().store().fs().observe_lease_completions();
    recovery.reconcile(key, 64).await.unwrap();
    let first = image(&fixture).await;
    assert_completed(&first);
    renewal::assert_selected_renewals(
        &fixture,
        &initial_lease,
        recovery.lease(),
        &mut acknowledgments,
    )
    .await;

    let empty = recovery.reconcile(key, 64).await.unwrap();
    assert_eq!(empty.reclaimed, 0);
    let second = image(&fixture).await;
    assert_completed(&second);
    assert_eq!(
        second.pass.as_ref().unwrap().pass,
        first.pass.as_ref().unwrap().pass + 1
    );
    assert_owner_retained(&before, &second);

    assert_eq!(
        recovery.maintenance_hints(&mut cursor, 1).await.unwrap(),
        hints
    );

    let path = fixture.guard().store().root().join(fixture.pack.pack_key());
    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(
        &path,
        b"late same-key residue without imported creator journal",
    )
    .await
    .unwrap();
    let late = recovery.reconcile(key, 64).await.unwrap();
    assert_eq!(late.reclaimed, 1);
    assert!(!path.exists());
    let third = image(&fixture).await;
    assert_completed(&third);
    assert_eq!(
        third.pass.as_ref().unwrap().pass,
        second.pass.as_ref().unwrap().pass + 1
    );
    assert_owner_retained(&before, &third);
    assert_eq!(third.manifest, before.manifest);
    drop(recovery);
    let fixture = reopen_checked(fixture, &third).await;
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_takeover_uses_current_lease_without_replacing_owner() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    fixture.own().await;
    let before = image(&fixture).await;
    let first = takeover(&fixture, "recurring-first-holder").await;
    let first_lease = first.lease().clone();
    drop(first);

    let mut second = takeover(&fixture, "recurring-second-holder").await;
    assert_eq!(second.lease().epoch, first_lease.epoch + 1);
    assert_ne!(second.lease().holder, first_lease.holder);
    second
        .reconcile(before.owner_key.as_deref().unwrap(), 64)
        .await
        .unwrap();

    let after = image(&fixture).await;
    assert_owner_retained(&before, &after);
    assert_completed(&after);
    assert_eq!(after.pass.as_ref().unwrap().lease, *second.lease());
    assert_eq!(after.manifest, before.manifest);
    drop(second);
    let fixture = reopen_checked(fixture, &after).await;
    cleanup(fixture);
}
