//! Exercises original-directory and current-input fences during real proposal staging.
//!
//! Genuine native workers pause before installing an immutable roots proposal.
//! Selected operation bytes, physical proposals and native progress submissions
//! distinguish staging from authoritative selection without manufacturing an ACK.

use super::super::support::*;
use crate::bucket::held::SingleHeld;
use crate::gc::runner::CollectionError;
use crate::gc::runner::copied_retirement_tests::support::{CopiedFixture, Residue};
use crate::store::native_publication_effects::collection::test_fs::PermanentPhase;
use crate::store::{Clock, StoreErrorKind};
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::bucket::Tombstone;
use terrane_format::gc::GcLease;
use terrane_format::gc::publication::{PublicationCommit, PublicationTransaction};
use terrane_format::gc::retirement::{
    ObservationState, ObservedArtifact, PermanentDeleteAuthorization, PermanentDeleteOperation,
    PermanentDeletePass,
};

/// Identifies the genuine destination barrier independently of later reclaim counts.
fn original_barrier(fixture: &CopiedFixture, before: &Image) -> (u64, PathBuf, Vec<u8>) {
    let operation = before.operation.as_ref().unwrap();
    let PermanentDeleteAuthorization::Copied(authorization) = &operation.authorization else {
        panic!("expected genuine copied-destination ownership");
    };
    let exclusion = &authorization.exclusion;
    assert_eq!(exclusion.pack, *fixture.pack.as_bytes());
    assert!(
        before
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .iter()
            .any(|row| {
                row.pack_id == exclusion.pack
                    && row.cycle == exclusion.cycle
                    && row.epoch == exclusion.epoch
            })
    );

    let root = fixture.guard().store().root();
    for key in [fixture.pack.pack_key(), fixture.pack.index_key()] {
        assert_eq!(
            std::fs::symlink_metadata(root.join(key))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }
    let path = root.join(format!("trash/{}/{}", exclusion.cycle, fixture.pack));
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(
        metadata.uid(),
        std::fs::symlink_metadata(root).unwrap().uid()
    );
    assert_eq!(metadata.mode() & 0o022, 0);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes, authorization.tombstone);
    let tombstone = Tombstone::decode(&bytes).unwrap();
    assert_eq!(tombstone.encode(), bytes);
    assert_eq!(tombstone.pack_id, exclusion.pack);
    assert_eq!(tombstone.cycle, exclusion.cycle);
    assert_eq!(tombstone.epoch, exclusion.epoch);
    assert_eq!(tombstone.removed_entries, 0);
    (exclusion.cycle, path, bytes)
}

/// Reads confirmation deltas only through actual selected publication commits.
fn selected_absences(fixture: &CopiedFixture, before: &Image, after: &Image) -> BTreeSet<u64> {
    let control = fixture.source.parent.join("copied-publication");
    let operation_key = before.owner_key.as_deref().unwrap();
    let mut cycles = BTreeSet::new();
    for revision in before.state.revision + 1..=after.state.revision {
        let key = format!("publication/commits/{revision}");
        let commit =
            PublicationCommit::decode(&std::fs::read(control.join(&key)).unwrap()).unwrap();
        let bytes = std::fs::read(control.join(&commit.transaction_key)).unwrap();
        commit.check_transaction(&key, &bytes).unwrap();
        let transaction = PublicationTransaction::decode(&bytes).unwrap();
        for change in transaction
            .changes
            .iter()
            .filter(|row| row.key == operation_key)
        {
            let operation =
                PermanentDeleteOperation::decode(change.new.as_deref().unwrap()).unwrap();
            assert_eq!(
                operation.authorization,
                before.operation.as_ref().unwrap().authorization
            );
            assert_eq!(operation.owner, before.owner_slot);
            let pointer = operation.pass.as_ref().unwrap();
            let bytes = std::fs::read(control.join(&pointer.key)).unwrap();
            assert_eq!(*blake3::hash(&bytes).as_bytes(), pointer.digest);
            operation.check_pass(&bytes, operation_key).unwrap();
            let pass = PermanentDeletePass::decode(&bytes).unwrap();
            for row in pass.observations {
                if let ObservedArtifact::Trash(cycle) = row.artifact
                    && row.state == ObservationState::ConfirmedAbsent
                {
                    cycles.insert(cycle);
                }
            }
        }
    }
    cycles
}

/// Waits for the actual submitted worker's bounded staging handoff.
async fn arrival(receiver: mpsc::Receiver<()>) {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || receiver.recv()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
}

fn directory_recipe(path: &Path) -> (u64, u32, u32, i64, i64, i64, i64) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    (
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn reservations(root: &Path) -> BTreeSet<u64> {
    let path = root.join("gc/cycle");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // First copied ownership need not create a recovery reservation
            // directory. This is test inventory, never native absence authority.
            return BTreeSet::new();
        }
        Err(error) => panic!("cycle reservation inventory metadata failed: {error}"),
    };
    assert!(
        metadata.is_dir(),
        "cycle reservation inventory is not a directory"
    );
    assert_eq!(
        metadata.uid(),
        std::fs::symlink_metadata(root).unwrap().uid()
    );
    assert_eq!(metadata.mode() & 0o022, 0);

    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter_map(|name| {
            let text = name.to_str()?;
            let cycle = text.parse::<u64>().ok()?;
            (text == cycle.to_string()).then_some(cycle)
        })
        .collect()
}

/// Checks the real once-only native proposal path independently of its pause.
fn proposal_path(fixture: &CopiedFixture) -> PathBuf {
    let path = fixture.source.fs.gc_proposal_path();
    let key = path.strip_prefix(fixture.guard().store().root()).unwrap();
    let parts: Vec<_> = key.to_str().unwrap().split('/').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "gc");
    assert_eq!(parts[1].parse::<u64>().unwrap().to_string(), parts[1]);
    assert_eq!(parts[2], "roots");
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    path
}

async fn assert_unselected(fixture: &CopiedFixture, before: &Image) -> Image {
    assert!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Progress)
            .is_empty()
    );
    assert!(
        fixture
            .source
            .fs
            .permanent_submitted_paths(PermanentPhase::Reclaim)
            .is_empty()
    );
    let after = image(fixture).await;
    assert_owner_retained(before, &after);
    assert_eq!(after.operation, before.operation);
    assert_eq!(after.pass, before.pass);
    assert_eq!(after.manifest, before.manifest);
    after
}

/// Requires the precise native I/O fence rather than an unrelated Store failure.
fn assert_native_refusal(error: &CollectionError, expected: &str) {
    let CollectionError::Store(failure) = error else {
        panic!("expected native physical-input refusal: {error:?}");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(failure).unwrap().to_string(),
        expected
    );
}

#[derive(Clone, Copy, Debug)]
enum DirectoryChange {
    RequestedReplacement,
    RequestedPolicy,
    OffBatchPolicy,
    AddedCycle,
    RemovedCycle,
    NoncanonicalCycle,
    SymlinkCycle,
}

async fn directory_handoff(change: DirectoryChange) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let trace = crate::ref_advance::NativeTrace::new(
        fixture.guard().store().root(),
        "permanent-staging-directory-witness",
    );
    trace.mark(&format!("directory-change={change:?}"));
    fixture.own().await;
    trace.mark("fixture-permanent-ownership-acknowledged");
    let root = fixture.guard().store().root();
    let trash = root.join("trash");
    // Cycle zero is necessarily requested; cycle 129 is outside the fixed
    // first 128-cycle batch regardless of any preexisting fixture cycle.
    for cycle in 0..130 {
        std::fs::create_dir_all(trash.join(cycle.to_string())).unwrap();
    }
    let before = image(&fixture).await;
    let barrier = if matches!(change, DirectoryChange::AddedCycle) {
        let barrier = original_barrier(&fixture, &before);
        // Absent source artifacts do not remove the NEW destination barrier.
        // The exact owned-family inventory must contain that barrier alone.
        assert_eq!(
            super::residue_paths(&fixture).await,
            vec![barrier.1.clone()]
        );
        Some(barrier)
    } else {
        None
    };
    let unrelated = if matches!(change, DirectoryChange::AddedCycle) {
        let path = fixture.live_data_path().await;
        let bytes = std::fs::read(&path).unwrap();
        Some((path, bytes))
    } else {
        None
    };
    let old_reservations = reservations(root);
    trace.mark("initial-state-and-reservations-observed");
    let mut runner = takeover(&fixture, "permanent-staging-directory-fault").await;
    trace.mark("fault-session-takeover-acknowledged");
    let (arrived, release) = fixture.source.fs.pause_next_gc_proposal(root.to_owned());
    let mut pending = Box::pin(runner.reconcile(before.owner_key.as_deref().unwrap(), 16));
    tokio::select! {
        result = &mut pending => panic!("progress completed before staging handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    let proposal = proposal_path(&fixture);
    trace.mark("actual-proposal-handoff-arrived");

    let parent_recipe = directory_recipe(&trash);
    let late_path = trash.join(format!("9000/{}", fixture.pack));
    let late_bytes = b"late canonical-cycle residue must remain recoverable";
    match change {
        DirectoryChange::RequestedReplacement => {
            let path = trash.join("0");
            let old_inode = directory_recipe(&path).0;
            std::fs::rename(
                &path,
                fixture.source.parent.join("replaced-requested-cycle"),
            )
            .unwrap();
            std::fs::create_dir(&path).unwrap();
            assert_ne!(directory_recipe(&path).0, old_inode);
        }
        DirectoryChange::RequestedPolicy | DirectoryChange::OffBatchPolicy => {
            let cycle = if matches!(change, DirectoryChange::RequestedPolicy) {
                "0"
            } else {
                "129"
            };
            std::fs::set_permissions(trash.join(cycle), std::fs::Permissions::from_mode(0o777))
                .unwrap();
            assert_eq!(directory_recipe(&trash), parent_recipe);
        }
        DirectoryChange::AddedCycle => {
            assert_ne!(barrier.as_ref().unwrap().0, 9000);
            std::fs::create_dir(late_path.parent().unwrap()).unwrap();
            std::fs::write(&late_path, late_bytes).unwrap();
        }
        DirectoryChange::RemovedCycle => std::fs::remove_dir(trash.join("129")).unwrap(),
        DirectoryChange::NoncanonicalCycle => std::fs::create_dir(trash.join("09000")).unwrap(),
        DirectoryChange::SymlinkCycle => {
            let foreign = fixture.source.parent.join("foreign-staging-cycle");
            std::fs::create_dir(&foreign).unwrap();
            std::fs::write(foreign.join(fixture.pack.to_string()), late_bytes).unwrap();
            symlink(&foreign, trash.join("9000")).unwrap();
        }
    }
    release.send(()).unwrap();
    trace.mark("fault-injected-native-worker-released");
    let error = pending.await.unwrap_err();
    trace.mark("fault-reconciliation-returned");
    let expected = match change {
        // The submitting Frame checks requested names before its final callback.
        DirectoryChange::RequestedReplacement => "current physical fence changed",
        DirectoryChange::RequestedPolicy | DirectoryChange::OffBatchPolicy => {
            "unsafe native physical fence"
        }
        // These change the original Trash mtime/ctime without changing its named
        // incarnation. Candidate continuity refuses before another proposal rename.
        DirectoryChange::AddedCycle
        | DirectoryChange::RemovedCycle
        | DirectoryChange::NoncanonicalCycle
        | DirectoryChange::SymlinkCycle => "candidate directory changed during traversal",
    };
    assert_native_refusal(&error, expected);
    assert_eq!(reservations(root).difference(&old_reservations).count(), 1);
    if matches!(change, DirectoryChange::OffBatchPolicy) {
        // The unrequested child does not change the retained Trash recipe.
        // Staging installs the genuine roots proposal; full preselection traversal
        // then refuses its policy before any progress can become authoritative.
        let bytes = std::fs::read(&proposal).unwrap();
        let roots = terrane_format::gc::GcRoots::decode(&bytes).unwrap();
        assert_eq!(proposal, root.join(format!("gc/{}/roots", roots.cycle)));
    } else {
        assert_eq!(
            std::fs::symlink_metadata(&proposal).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    if matches!(
        change,
        DirectoryChange::AddedCycle | DirectoryChange::SymlinkCycle
    ) {
        assert_eq!(std::fs::read(&late_path).unwrap(), late_bytes);
    }
    assert_unselected(&fixture, &before).await;
    trace.mark("fault-refusal-and-unselected-state-verified");
    drop(runner);
    let fixture = if matches!(change, DirectoryChange::AddedCycle) {
        let (barrier_cycle, barrier_path, barrier_bytes) = barrier.unwrap();
        assert_eq!(std::fs::read(&barrier_path).unwrap(), barrier_bytes);
        assert_eq!(std::fs::read(&late_path).unwrap(), late_bytes);
        let expected_paths = BTreeSet::from([barrier_path, late_path.clone()]);
        assert_eq!(
            super::residue_paths(&fixture)
                .await
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected_paths
        );
        // The refused traversal carries no future permission. A fresh genuine
        // takeover discovers the new canonical cycle and resolves its late duty.
        let mut fresh = takeover(&fixture, "permanent-staging-added-cycle-recovery").await;
        trace.mark("fresh-recovery-takeover-acknowledged");
        let report = fresh
            .reconcile(before.owner_key.as_deref().unwrap(), 16)
            .await
            .unwrap();
        trace.mark("fresh-reconciliation-returned");
        assert_eq!(report.reclaimed, expected_paths.len());
        for path in &expected_paths {
            assert_eq!(
                std::fs::symlink_metadata(path).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
        }
        let mut completed = fixture
            .source
            .fs
            .permanent_completed(PermanentPhase::Reclaim);
        completed.sort();
        assert_eq!(
            completed,
            expected_paths
                .into_iter()
                .map(|path| (path, true))
                .collect::<Vec<_>>()
        );
        let after = image(&fixture).await;
        assert_owner_retained(&before, &after);
        assert_eq!(after.manifest, before.manifest);
        super::assert_completed(&after);
        let confirmed = selected_absences(&fixture, &before, &after);
        assert!(confirmed.contains(&barrier_cycle));
        assert!(confirmed.contains(&9000));
        let (path, bytes) = unrelated.unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        trace.mark("late-reclaim-and-selected-completion-verified");
        drop(fresh);
        let reopened = reopen_checked(fixture, &after).await;
        trace.mark("completed-state-verified-after-native-reopen");
        reopened
    } else {
        fixture
    };
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_staging_requested_directory_replacement_refuses_selection() {
    directory_handoff(DirectoryChange::RequestedReplacement).await;
}

#[tokio::test]
async fn permanent_local_staging_requested_directory_policy_refuses_selection() {
    directory_handoff(DirectoryChange::RequestedPolicy).await;
}

#[tokio::test]
async fn permanent_local_staging_off_batch_policy_refuses_before_selection() {
    directory_handoff(DirectoryChange::OffBatchPolicy).await;
}

#[tokio::test]
async fn permanent_local_staging_added_cycle_keeps_late_residue_unselected() {
    directory_handoff(DirectoryChange::AddedCycle).await;
}

#[tokio::test]
async fn permanent_local_staging_removed_cycle_refuses_selection() {
    directory_handoff(DirectoryChange::RemovedCycle).await;
}

#[tokio::test]
async fn permanent_local_staging_noncanonical_cycle_refuses_selection() {
    directory_handoff(DirectoryChange::NoncanonicalCycle).await;
}

#[tokio::test]
async fn permanent_local_staging_symlink_cycle_refuses_selection() {
    directory_handoff(DirectoryChange::SymlinkCycle).await;
}

#[derive(Clone, Copy, Debug)]
enum CurrentChange {
    LeaseExpiry,
    OwnerPreimage,
    OriginalPreimage,
}

/// Replaces actual equal bytes with a distinct synchronized inode.
fn replace(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    let old = std::fs::symlink_metadata(path).unwrap();
    let temporary = path.with_extension("staging-replacement");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(old.mode() & 0o777)
        .open(&temporary)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(&temporary, path).unwrap();
    std::fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    assert_ne!(std::fs::symlink_metadata(path).unwrap().ino(), old.ino());
}

async fn current_handoff(change: CurrentChange) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    fixture.own().await;
    let before = image(&fixture).await;
    let root = fixture.guard().store().root();
    let old_reservations = reservations(root);
    let key = before.owner_key.as_deref().unwrap();
    let mut runner = takeover(&fixture, "permanent-staging-current-fault").await;
    let (arrived, release) = fixture.source.fs.pause_next_gc_proposal(root.to_owned());
    let mut pending = Box::pin(runner.reconcile(key, 16));
    tokio::select! {
        result = &mut pending => panic!("progress completed before staging current handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    let proposal = proposal_path(&fixture);
    match change {
        CurrentChange::LeaseExpiry => {
            let lease = GcLease::decode(&std::fs::read(root.join("gc/lease")).unwrap()).unwrap();
            let wall = fixture
                .source
                .clock
                .now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let next = lease.expiry.checked_add(1).unwrap().max(wall + 1);
            let ticks = fixture
                .source
                .clock
                .monotonic()
                .as_secs()
                .checked_add(next - wall)
                .unwrap();
            fixture.source.clock.set(next, ticks);
        }
        CurrentChange::OwnerPreimage => {
            replace(&fixture.source.parent.join("copied-publication").join(key))
        }
        CurrentChange::OriginalPreimage => {
            replace(&fixture.authority.control().join("registration.cbor"))
        }
    }
    release.send(()).unwrap();
    let error = pending.await.unwrap_err();
    if !matches!(change, CurrentChange::LeaseExpiry) {
        // Both protected leaves were captured as exact physical preimages.
        // Equal bytes cannot satisfy the original inode/metadata observation.
        assert_native_refusal(&error, "exact read metadata changed");
    }
    let CollectionError::Store(error) = error else {
        panic!("{change:?}: expected native current-input refusal: {error:?}");
    };
    if matches!(change, CurrentChange::LeaseExpiry) {
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Denied {
                verb: "gc-checkpoint",
                pattern: "current configured collector session".into(),
            }
        );
    }
    assert_eq!(reservations(root).difference(&old_reservations).count(), 1);
    assert_eq!(
        std::fs::symlink_metadata(&proposal).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_unselected(&fixture, &before).await;
    drop(runner);
    cleanup(fixture);
}

#[tokio::test]
async fn permanent_local_staging_expired_whole_lease_refuses_selection() {
    current_handoff(CurrentChange::LeaseExpiry).await;
}

#[tokio::test]
async fn permanent_local_staging_replaced_owner_preimage_refuses_selection() {
    current_handoff(CurrentChange::OwnerPreimage).await;
}

#[tokio::test]
async fn permanent_local_staging_replaced_original_preimage_refuses_selection() {
    current_handoff(CurrentChange::OriginalPreimage).await;
}

#[tokio::test]
async fn permanent_local_staging_cancellation_keeps_proposals_unselected_after_reopen() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    fixture.own().await;
    let before = image(&fixture).await;
    let root = fixture.guard().store().root();
    let old_reservations = reservations(root);
    let key = before.owner_key.as_deref().unwrap();
    let mut runner = takeover(&fixture, "permanent-staging-cancellation").await;
    let (arrived, release) = fixture.source.fs.pause_next_gc_proposal(root.to_owned());
    let mut pending = Box::pin(runner.reconcile(key, 16));
    tokio::select! {
        result = &mut pending => panic!("progress completed before staging cancellation: {result:?}"),
        () = arrival(arrived) => {}
    }
    let proposal = proposal_path(&fixture);
    drop(pending);
    release.send(()).unwrap();
    // Reacquiring the actual namespace exclusion waits for the queued worker to
    // finish and release its retained Frame; channel release alone is not ACK.
    let holder = tokio::time::timeout(
        Duration::from_secs(30),
        SingleHeld::acquire(fixture.guard().store()),
    )
    .await
    .unwrap()
    .unwrap();
    drop(holder);
    assert_eq!(fixture.source.fs.gc_proposal_path(), proposal);
    assert_eq!(
        std::fs::symlink_metadata(&proposal).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(reservations(root).difference(&old_reservations).count(), 1);
    let effects = fixture.source.fs.effects();
    assert!(runner.reconcile(key, 16).await.is_err());
    assert_eq!(fixture.source.fs.effects(), effects);
    let after = assert_unselected(&fixture, &before).await;
    drop(runner);
    let fixture = reopen_checked(fixture, &after).await;
    cleanup(fixture);
}
