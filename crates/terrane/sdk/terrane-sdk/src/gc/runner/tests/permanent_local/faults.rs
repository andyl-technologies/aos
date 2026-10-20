//! Exercises genuine permanent native faults, cancellation and progress conflicts.
//!
//! Every fixture reaches ownership through the full real copied barrier wait.
//! Faults change actual physical inputs or execute the actual retained worker;
//! selected history and filesystem artifacts supply independent result oracles.

#![allow(
    clippy::unwrap_used,
    reason = "Genuine native fixture operations and independent assertions intentionally panic."
)]

#[path = "faults/support.rs"]
mod support;

use crate::bucket::held::SingleHeld;
use crate::gc::runner::CollectionError;
use crate::gc::runner::copied_retirement_tests::support::{CopiedFixture, Residue};
use crate::store::native_publication_effects::collection::test_fs::{
    PermanentBoundary, PermanentPhase,
};
use crate::store::{EffectFault, StoreErrorKind};
use std::os::unix::fs::symlink;
use support::*;
use terrane_format::bucket::BucketKey;
use terrane_format::gc::retirement::{ObservedArtifact, PermanentDeletePass, RecordPointer};

fn assert_io(error: CollectionError, expected: &str) {
    let CollectionError::Store(error) = error else {
        panic!("expected genuine native storage refusal: {error:?}");
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        expected
    );
}

async fn replacement_handoff() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let before = selected(&fixture, &key).await;
    let target = fixture.guard().store().root().join(fixture.pack.pack_key());
    let mut runner = recovery(&fixture, &key).await;
    let (arrived, release) = fixture.source.fs.pause_permanent(
        PermanentPhase::Reclaim,
        Some(target.clone()),
        PermanentBoundary::BeforeOpen,
    );
    let mut pending = Box::pin(runner.reconcile(&key, 16));
    tokio::select! {
        result = &mut pending => panic!("request completed before native replacement handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    let bytes = replace(&target);
    release.send(()).unwrap();
    // Rename unlinks the retained old descriptor. Its zero-link payload fails
    // physical policy before the later named-incarnation comparison.
    assert_io(pending.await.unwrap_err(), "unsafe native physical fence");

    fixture.source.fs.assert_permanent_hooks_consumed();
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    let after = selected(&fixture, &key).await;
    assert_owner(&before, &after, fixture.pack.as_bytes());
    assert_planned(&after, ObservedArtifact::Pack);
    assert!(
        fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim)
            .contains(&(target, false))
    );
    drop(runner);
    cleanup(fixture).await;
}

#[derive(Clone, Copy, Debug)]
enum UnsafeFamily {
    SymlinkLeaf,
    SymlinkCycle,
    NoncanonicalCycle,
    ForeignHardLink,
}

async fn unsafe_family(kind: UnsafeFamily) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let before = selected(&fixture, &key).await;
    let root = fixture.guard().store().root();
    std::fs::create_dir_all(root.join(fixture.pack.pack_key()).parent().unwrap()).unwrap();
    let foreign = fixture.source.parent.join("foreign-residue");
    let foreign_bytes = b"foreign inode must survive permanent recovery";
    std::fs::write(&foreign, foreign_bytes).unwrap();
    let unsafe_path = match kind {
        UnsafeFamily::SymlinkLeaf => {
            let path = root.join(fixture.pack.pack_key());
            symlink(&foreign, &path).unwrap();
            path
        }
        UnsafeFamily::SymlinkCycle => {
            let directory = fixture.source.parent.join("foreign-cycle");
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join(fixture.pack.to_string()), foreign_bytes).unwrap();
            let path = root.join("trash/71");
            symlink(&directory, &path).unwrap();
            path
        }
        UnsafeFamily::NoncanonicalCycle => {
            let path = root.join("trash/071");
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join(fixture.pack.to_string()), foreign_bytes).unwrap();
            path
        }
        UnsafeFamily::ForeignHardLink => {
            let path = root.join(fixture.pack.pack_key());
            std::fs::hard_link(&foreign, &path).unwrap();
            path
        }
    };
    let mut runner = recovery(&fixture, &key).await;
    let error = runner.reconcile(&key, 16).await.unwrap_err();
    assert!(
        matches!(error, CollectionError::Store(_)),
        "{kind:?}: {error:?}"
    );

    assert_eq!(std::fs::read(&foreign).unwrap(), foreign_bytes);
    assert!(std::fs::symlink_metadata(&unsafe_path).is_ok(), "{kind:?}");
    if matches!(
        kind,
        UnsafeFamily::SymlinkCycle | UnsafeFamily::NoncanonicalCycle
    ) {
        assert_eq!(
            std::fs::read(unsafe_path.join(fixture.pack.to_string())).unwrap(),
            foreign_bytes
        );
    }
    assert!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim)
            .is_empty()
    );
    let after = selected(&fixture, &key).await;
    assert_owner(&before, &after, fixture.pack.as_bytes());
    assert_eq!(after.operation, before.operation);
    drop(runner);
    cleanup(fixture).await;
}

#[tokio::test]
async fn permanent_local_replaced_pack_refuses_foreign_unlink() {
    replacement_handoff().await;
}

#[tokio::test]
async fn permanent_local_symlink_pack_refuses_foreign_unlink() {
    unsafe_family(UnsafeFamily::SymlinkLeaf).await;
}

#[tokio::test]
async fn permanent_local_symlink_trash_cycle_refuses_foreign_unlink() {
    unsafe_family(UnsafeFamily::SymlinkCycle).await;
}

#[tokio::test]
async fn permanent_local_noncanonical_trash_cycle_refuses_foreign_unlink() {
    unsafe_family(UnsafeFamily::NoncanonicalCycle).await;
}

#[tokio::test]
async fn permanent_local_foreign_hardlink_refuses_unlink() {
    unsafe_family(UnsafeFamily::ForeignHardLink).await;
}

#[derive(Clone, Copy, Debug)]
enum CurrentChange {
    Expiry,
    Original,
    BackendRegistration,
    SelectedData,
}

async fn current_handoff(change: CurrentChange) {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let before = selected(&fixture, &key).await;
    let root = fixture.guard().store().root();
    let target = root.join(fixture.pack.pack_key());
    let bytes = std::fs::read(&target).unwrap();
    let mut runner = recovery(&fixture, &key).await;
    let (arrived, release) = fixture.source.fs.pause_permanent(
        PermanentPhase::Reclaim,
        Some(target.clone()),
        PermanentBoundary::BeforeOpen,
    );
    let mut pending = Box::pin(runner.reconcile(&key, 16));
    tokio::select! {
        result = &mut pending => panic!("request completed before current-input handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    match change {
        CurrentChange::Expiry => {
            // Renewal has already selected its actual whole lease by this point.
            let lease =
                terrane_format::gc::GcLease::decode(&std::fs::read(root.join("gc/lease")).unwrap())
                    .unwrap();
            expire(&fixture, lease.expiry);
        }
        CurrentChange::Original => {
            replace(&fixture.authority.control().join("registration.cbor"));
        }
        CurrentChange::BackendRegistration => {
            replace(&control(&fixture).join("backend-registration.cbor"));
        }
        CurrentChange::SelectedData => {
            let live = before
                .manifest
                .inventory
                .as_ref()
                .unwrap()
                .iter()
                .find(|row| row.pack_id != *fixture.pack.as_bytes())
                .unwrap();
            let pack = crate::pack::PackId::from_random_bytes(live.pack_id);
            replace(&root.join(pack.pack_key()));
        }
    }
    release.send(()).unwrap();
    let error = pending.await.unwrap_err();
    let CollectionError::Store(error) = error else {
        panic!("{change:?}: expected native current-input refusal: {error:?}");
    };
    if matches!(change, CurrentChange::Expiry) {
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Denied {
                verb: "gc-checkpoint",
                pattern: "current configured collector session".into(),
            }
        );
    }
    fixture.source.fs.assert_permanent_hooks_consumed();
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    let requests = fixture
        .source
        .fs
        .permanent_submitted_paths(PermanentPhase::Reclaim);
    assert_eq!(requests, vec![target.clone()]);
    assert_eq!(
        fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim),
        vec![(target, false)]
    );
    assert!(runner.reconcile(&key, 16).await.is_err());
    assert_eq!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim),
        requests
    );
    let after = selected(&fixture, &key).await;
    assert_owner(&before, &after, fixture.pack.as_bytes());
    assert_planned(&after, ObservedArtifact::Pack);
    drop(runner);
    cleanup(fixture).await;
}

#[tokio::test]
async fn permanent_local_queued_lease_expiry_refuses_new_requests() {
    current_handoff(CurrentChange::Expiry).await;
}

#[tokio::test]
async fn permanent_local_queued_original_replacement_refuses_new_requests() {
    current_handoff(CurrentChange::Original).await;
}

#[tokio::test]
async fn permanent_local_queued_backend_registration_replacement_refuses_new_requests() {
    current_handoff(CurrentChange::BackendRegistration).await;
}

#[tokio::test]
async fn permanent_local_queued_data_replacement_refuses_new_requests() {
    current_handoff(CurrentChange::SelectedData).await;
}

async fn reclaim_fault(fault: EffectFault, expected: &str, unlinked: bool) {
    let interrupted_unlink = matches!(fault, EffectFault::AfterUnlink);
    let fixture = CopiedFixture::new(Residue::Pack).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let before = selected(&fixture, &key).await;
    let root = fixture.guard().store().root();
    let target = root.join(fixture.pack.pack_key());
    let bytes = std::fs::read(&target).unwrap();
    let mut runner = recovery(&fixture, &key).await;
    fixture
        .source
        .fs
        .fail_next_permanent(PermanentPhase::Reclaim, Some(target.clone()), fault);

    assert_io(runner.reconcile(&key, 16).await.unwrap_err(), expected);

    fixture.source.fs.assert_permanent_hooks_consumed();
    if unlinked {
        assert_absent(&target);
    } else {
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }
    let failed = selected(&fixture, &key).await;
    assert_owner(&before, &failed, fixture.pack.as_bytes());
    assert_planned(&failed, ObservedArtifact::Pack);
    assert_eq!(
        fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim),
        vec![(target.clone(), false)]
    );
    drop(runner);

    if interrupted_unlink {
        let mut interrupted = recovery(&fixture, &key).await;
        let progress = fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Progress);
        let reclaims = fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim);
        fixture.source.fs.fail_next_permanent(
            PermanentPhase::Observation,
            Some(control(&fixture).join(&key)),
            EffectFault::BeforeDirectorySyncAt(target.parent().unwrap().to_owned()),
        );

        // Fresh observation must synchronize the old pack's actual parent
        // before publishing ConfirmedAbsent for the interrupted unlink.
        assert_io(
            interrupted.reconcile(&key, 16).await.unwrap_err(),
            "injected creation directory sync failure",
        );

        fixture.source.fs.assert_permanent_hooks_consumed();
        assert_absent(&target);
        let unsynchronized = selected(&fixture, &key).await;
        assert_owner(&failed, &unsynchronized, fixture.pack.as_bytes());
        assert_eq!(unsynchronized.operation, failed.operation);
        assert_eq!(unsynchronized.pass, failed.pass);
        assert_planned(&unsynchronized, ObservedArtifact::Pack);
        assert_eq!(
            fixture
                .source
                .fs
                .permanent_completed(PermanentPhase::Observation)
                .last(),
            Some(&(control(&fixture).join(&key), false))
        );
        assert_eq!(
            fixture
                .source
                .fs
                .permanent_submitted_paths(PermanentPhase::Progress),
            progress
        );
        assert_eq!(
            fixture
                .source
                .fs
                .permanent_submitted_paths(PermanentPhase::Reclaim),
            reclaims
        );
        drop(interrupted);
    }

    let mut fresh = recovery(&fixture, &key).await;
    let report = fresh.reconcile(&key, 16).await.unwrap();
    assert!(report.selected_events > 0);
    assert_absent(&target);
    let recovered = selected(&fixture, &key).await;
    assert_owner(&failed, &recovered, fixture.pack.as_bytes());
    assert!(recovered.operation.revision > failed.operation.revision);
    assert!(
        recovered
            .history
            .iter()
            .flat_map(|pass| &pass.observations)
            .any(|row| {
                row.artifact == ObservedArtifact::Pack
                    && row.state
                        == terrane_format::gc::retirement::ObservationState::ConfirmedAbsent
            })
    );
    drop(fresh);
    cleanup(fixture).await;
}

async fn progress_sync_fault() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let before = selected(&fixture, &key).await;
    let target = fixture.guard().store().root().join(fixture.pack.pack_key());
    let bytes = std::fs::read(&target).unwrap();
    let mut runner = recovery(&fixture, &key).await;
    fixture.source.fs.fail_next_permanent(
        PermanentPhase::Progress,
        None,
        EffectFault::BeforeDirectorySync,
    );

    assert_io(
        runner.reconcile(&key, 16).await.unwrap_err(),
        "injected creation directory sync failure",
    );

    // Selection precedes this final durability seal. Refusal retains the real
    // selected event; claiming an unchanged operation here would be false.
    let failed = selected(&fixture, &key).await;
    assert_owner(&before, &failed, fixture.pack.as_bytes());
    assert_planned(&failed, ObservedArtifact::Pack);
    assert!(failed.operation.revision > before.operation.revision);
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    assert!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim)
            .is_empty()
    );
    fixture.source.fs.assert_permanent_hooks_consumed();
    assert!(
        fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Progress)
            .iter()
            .any(|(_, success)| !success)
    );
    drop(runner);
    let mut fresh = recovery(&fixture, &key).await;
    assert!(fresh.reconcile(&key, 16).await.unwrap().reclaimed > 0);
    assert_absent(&target);
    assert_owner(
        &failed,
        &selected(&fixture, &key).await,
        fixture.pack.as_bytes(),
    );
    drop(fresh);
    cleanup(fixture).await;
}

#[tokio::test]
async fn permanent_local_before_unlink_failure_keeps_selected_recovery_duties() {
    reclaim_fault(
        EffectFault::BeforeUnlink,
        "injected permanent unlink failure",
        false,
    )
    .await;
}

#[tokio::test]
async fn permanent_local_after_unlink_failure_keeps_selected_recovery_duties() {
    reclaim_fault(
        EffectFault::AfterUnlink,
        "injected failure after permanent unlink",
        true,
    )
    .await;
}

#[tokio::test]
async fn permanent_local_directory_sync_failure_keeps_selected_recovery_duties() {
    reclaim_fault(
        EffectFault::BeforeDirectorySync,
        "injected creation directory sync failure",
        true,
    )
    .await;
}

#[tokio::test]
async fn permanent_local_progress_sync_failure_keeps_selected_recovery_duties() {
    progress_sync_fault().await;
}

async fn cancelled_waiter(boundary: PermanentBoundary) {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let before = selected(&fixture, &key).await;
    let target = fixture.guard().store().root().join(fixture.pack.pack_key());
    let bytes = std::fs::read(&target).unwrap();
    let mut runner = recovery(&fixture, &key).await;
    let (arrived, release) =
        fixture
            .source
            .fs
            .pause_permanent(PermanentPhase::Reclaim, Some(target.clone()), boundary);
    let mut pending = Box::pin(runner.reconcile(&key, 16));
    tokio::select! {
        result = &mut pending => panic!("request completed before {boundary:?} cancellation handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    drop(pending);
    assert!(
        fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim)
            .is_empty()
    );
    let coordination = fixture
        .guard()
        .store()
        .root()
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(coordination)
        .unwrap();
    assert!(
        matches!(contender.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "{boundary:?}: canceled waiter released the worker's namespace exclusion"
    );
    drop(contender);

    {
        let competing = SingleHeld::acquire(fixture.guard().store());
        tokio::pin!(competing);
        release.send(()).unwrap();
        // Acquiring the real exclusion waits for the canceled worker's retained
        // Frame to release it. Bound this wait before checking its terminal row.
        let holder = tokio::time::timeout(std::time::Duration::from_secs(30), competing)
            .await
            .unwrap_or_else(|_| {
                panic!("{boundary:?}: canceled worker did not release its namespace exclusion")
            })
            .unwrap();
        drop(holder);
    }
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim)
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    // Cancellation poisons the retained Session: this queued request must
    // terminate in refusal, while its preselected duty remains recoverable.
    assert_eq!(
        fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim),
        vec![(target.clone(), false)]
    );
    fixture.source.fs.assert_permanent_hooks_consumed();
    if matches!(boundary, PermanentBoundary::BeforeOpen) {
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    } else {
        // Both sync gates follow the actual unlink. Cancellation must retain
        // the selected Planned duty despite physical absence at this prefix.
        assert_absent(&target);
    }
    let failed = selected(&fixture, &key).await;
    assert_owner(&before, &failed, fixture.pack.as_bytes());
    assert_planned(&failed, ObservedArtifact::Pack);
    let CollectionError::Store(error) = runner.reconcile(&key, 16).await.unwrap_err() else {
        panic!("{boundary:?}: expected the poisoned current Session to refuse recovery");
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Denied {
            verb: "gc-checkpoint",
            pattern: "current configured collector session".into(),
        }
    );
    assert_eq!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim),
        vec![target.clone()]
    );
    drop(runner);
    let mut fresh = recovery(&fixture, &key).await;
    assert!(fresh.reconcile(&key, 16).await.unwrap().reclaimed > 0);
    assert_absent(&target);
    let recovered = selected(&fixture, &key).await;
    assert_owner(&failed, &recovered, fixture.pack.as_bytes());
    assert!(
        recovered
            .history
            .iter()
            .flat_map(|pass| &pass.observations)
            .any(|row| {
                row.artifact == ObservedArtifact::Pack
                    && row.state
                        == terrane_format::gc::retirement::ObservationState::ConfirmedAbsent
            })
    );
    drop(fresh);
    cleanup(fixture).await;
}

#[tokio::test]
async fn permanent_local_cancelled_waiter_before_open_retains_exclusion_through_worker_completion()
{
    cancelled_waiter(PermanentBoundary::BeforeOpen).await;
}

#[tokio::test]
async fn permanent_local_cancelled_waiter_before_directory_sync_retains_exclusion_through_worker_completion()
 {
    cancelled_waiter(PermanentBoundary::BeforeDirectorySync).await;
}

#[tokio::test]
async fn permanent_local_cancelled_waiter_after_directory_sync_retains_exclusion_through_worker_completion()
 {
    cancelled_waiter(PermanentBoundary::AfterDirectorySync).await;
}

fn staged_events(fixture: &CopiedFixture, cycle: u64) -> Vec<(RecordPointer, PermanentDeletePass)> {
    let directory = control(fixture).join(format!("gc/{cycle}/reconcile"));
    let mut events = Vec::new();
    for nonce in std::fs::read_dir(directory).unwrap() {
        for event in std::fs::read_dir(nonce.unwrap().path()).unwrap() {
            let path = event.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            let key = path
                .strip_prefix(control(fixture))
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let pass = PermanentDeletePass::decode(&bytes).unwrap();
            pass.check_key(&key, cycle).unwrap();
            events.push((
                RecordPointer {
                    key,
                    digest: *blake3::hash(&bytes).as_bytes(),
                },
                pass,
            ));
        }
    }
    events
}

#[tokio::test]
async fn permanent_local_progress_conflict_retains_owner_and_uses_fresh_event_nonce() {
    let fixture = CopiedFixture::new(Residue::Pack).await;
    let owned = fixture.own().await;
    let key = owner_key(&owned);
    let original = selected(&fixture, &key).await;
    let mut runner = recovery(&fixture, &key).await;
    let before = selected(&fixture, &key).await;
    // Reconcile selects its real whole-lease renewal before its first event.
    let next_revision = before.stamp.0.checked_add(2).unwrap();
    let slot = control(&fixture).join(format!("publication/commits/{next_revision}"));
    let (arrived, release) = fixture.source.fs.before_slot(slot.clone());
    let mut pending = Box::pin(runner.reconcile(&key, 16));
    tokio::select! {
        result = &mut pending => panic!("progress completed before authentic slot handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    let events = staged_events(&fixture, owned.authorization.exclusion().cycle);
    assert_eq!(events.len(), 1);
    let (losing_pointer, losing_pass) = &events[0];
    assert_eq!(losing_pass.predecessor.revision, before.stamp.0 + 1);
    // Replace equal cache bytes at a new inode. Its retained protected preimage
    // must fail the actual slot worker comparison, after authentic event staging.
    replace(&control(&fixture).join(&key));
    release.send(()).unwrap();
    assert!(pending.await.is_err());
    assert_absent(&slot);
    let lost = selected(&fixture, &key).await;
    assert_eq!(lost.stamp.0, before.stamp.0 + 1);
    assert_eq!(lost.operation, before.operation);
    assert_owner(&original, &lost, fixture.pack.as_bytes());
    assert!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim)
            .is_empty()
    );
    drop(runner);

    let mut fresh = recovery(&fixture, &key).await;
    assert!(fresh.reconcile(&key, 16).await.unwrap().reclaimed > 0);
    let won = selected(&fixture, &key).await;
    assert_owner(&lost, &won, fixture.pack.as_bytes());
    let selected_pointer = won.operation.pass.as_ref().unwrap();
    assert_ne!(selected_pointer.key, losing_pointer.key);
    assert_ne!(won.pass.as_ref().unwrap().nonce, losing_pass.nonce);
    assert!(
        won.history
            .iter()
            .all(|pass| pass.nonce != losing_pass.nonce)
    );
    assert!(won.history.iter().any(|pass| {
        pass.predecessor.revision > losing_pass.predecessor.revision
            && pass.nonce != losing_pass.nonce
    }));
    let surviving = std::fs::read(control(&fixture).join(&losing_pointer.key)).unwrap();
    assert_eq!(*blake3::hash(&surviving).as_bytes(), losing_pointer.digest);
    assert_absent(&fixture.guard().store().root().join(fixture.pack.pack_key()));
    drop(fresh);
    cleanup(fixture).await;
}
