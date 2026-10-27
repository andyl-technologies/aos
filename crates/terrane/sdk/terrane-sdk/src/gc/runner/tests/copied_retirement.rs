//! Exercises actual local copied preparation, NEW journals and first ownership.
//!
//! These cases use repository-local temporary payloads and independently
//! initialized destination controls. Completion status is accepted only from
//! production native acknowledgment channels; no physical deletion is executed.

// Fixture failures are intended test panics; production modules retain strict handling.
#![allow(clippy::unwrap_used)]

#[path = "copied_retirement/fs.rs"]
pub(crate) mod fs;

#[path = "copied_retirement/support.rs"]
pub(crate) mod support;

#[path = "copied_retirement/restart.rs"]
mod restart;

#[path = "copied_retirement/indexed.rs"]
mod indexed;

#[path = "copied_retirement/cadence.rs"]
mod cadence;

use crate::bucket::held::SingleHeld;
use crate::gc::runner::CollectionError;
use crate::store::{Clock, ContentStore, RefStore, StoreErrorKind};
use fs::Phase;
use std::os::unix::fs::MetadataExt;
use support::{CopiedFixture, Residue};
use terrane_format::bucket::{BucketCapabilities, BucketKey, GenerationManifest};
use terrane_format::gc::retirement::{BarrierArtifact, PermanentDeleteAuthorization};
use terrane_format::gc::{ArtifactBinding, CreationJournal, GcLease, JournalState, Tombstone};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn gc_copied_retirement_native_reopen_restarts_full_same_clock_wait() {
    restart::qualify(false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_takeover_selects_fresh_preparation_and_barrier() {
    restart::qualify(true).await;
}

async fn positive(residue: Residue, unavailable_foreign_original: bool) {
    let fixture = CopiedFixture::new(residue).await;
    let name = "refs/heads/_/main";
    let before_ref = fixture
        .guard()
        .store()
        .ref_get(name)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before_ref, fixture.source.head);
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Commit, &before_ref.commit)
        .unwrap();
    let before_commit = fixture.guard().store().get(&identity, None).await.unwrap();
    let before_state = {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        if matches!(residue, Residue::AbsentWithoutExclusion) {
            let capabilities =
                BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap())
                    .unwrap();
            let key = format!(
                "objects/index/{}/MANIFEST",
                capabilities.generation.unwrap()
            );
            let manifest =
                GenerationManifest::decode(observed.logical()[&key].as_deref().unwrap()).unwrap();
            assert!(manifest.exclusions.as_ref().unwrap().is_empty());
        }
        observed.state().clone()
    };
    let paths = [
        fixture.pack.pack_key(),
        fixture.pack.index_key(),
        format!("trash/7/{}", fixture.pack),
    ];
    let root = fixture.guard().store().root();
    let mut residues = Vec::new();
    for key in paths {
        let path = root.join(key);
        let body = match tokio::fs::read(&path).await {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("actual residue read failed: {error}"),
        };
        residues.push((path, body));
    }

    // Destination qualification must not infer or require source Original.
    // Move the real source authority name only after its signed history and
    // independently configured destination have genuinely been initialized.
    if unavailable_foreign_original {
        let original = fixture.source.parent.join("original");
        let unavailable = fixture.source.parent.join("unavailable-source-original");
        tokio::fs::rename(&original, &unavailable).await.unwrap();
        assert!(!original.exists());
    }
    let chunk_reads_before = fixture.forbid_chunk_reads().await;
    let operation = fixture.own().await;
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation, Phase::Barrier, Phase::Ownership]
    );
    assert_eq!(
        fixture.source.fs.data_body_read_attempts(),
        chunk_reads_before
    );

    let PermanentDeleteAuthorization::Copied(authorization) = &operation.authorization else {
        panic!("actual copied authorization expected");
    };
    let BarrierArtifact::Local(barrier) = &authorization.barrier else {
        panic!("actual local committed barrier expected");
    };
    assert_eq!(
        tokio::fs::read(root.join(&barrier.key)).await.unwrap(),
        barrier.tombstone
    );
    assert_ne!(barrier.key, format!("trash/7/{}", fixture.pack));
    assert!(authorization.deletion_elapsed_nanos >= 60_000_000_000);
    assert!(authorization.grace_elapsed_nanos >= 60_000_000_000);
    assert_eq!(
        fixture.guard().store().ref_get(name).await.unwrap(),
        Some(before_ref)
    );
    assert_eq!(
        fixture.guard().store().get(&identity, None).await.unwrap(),
        before_commit
    );
    for (path, bytes) in residues {
        match bytes {
            Some(bytes) => assert_eq!(tokio::fs::read(path).await.unwrap(), bytes),
            None => assert!(!path.exists()),
        }
    }
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let after = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!(
        after.state().loss_generation,
        before_state.loss_generation + 1
    );
    assert_eq!(after.state().binding, before_state.binding);
    assert_eq!(after.state().branches, before_state.branches);
    assert_eq!(after.state().guard, before_state.guard);
    assert!(authorization.lineage_fence.is_none());
    assert!(after.state().sources.is_empty());
    let capabilities =
        BucketCapabilities::decode(after.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest_key = format!(
        "objects/index/{}/MANIFEST",
        capabilities.generation.unwrap()
    );
    let manifest =
        GenerationManifest::decode(after.logical()[&manifest_key].as_deref().unwrap()).unwrap();
    assert!(
        manifest
            .burns
            .as_ref()
            .unwrap()
            .binary_search(fixture.pack.as_bytes())
            .is_ok()
    );
    let record = BucketKey::ref_record(name).unwrap();
    assert_eq!(
        after.logical().get(record.as_str()).unwrap().as_deref(),
        Some(fixture.source.head.encode().unwrap().as_slice())
    );
    drop(after);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_pack_only_selects_new_destination_owner() {
    positive(Residue::Pack, false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_index_only_selects_new_destination_owner() {
    positive(Residue::Index, false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_trash_only_selects_new_destination_owner() {
    positive(Residue::Trash, false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_all_absent_selects_new_destination_owner() {
    positive(Residue::Absent, false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_absent_source_exclusion_selects_new_destination_owner() {
    positive(Residue::AbsentWithoutExclusion, false).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_new_exclusion_preserves_unrelated_binding() {
    let (fixture, unrelated) =
        CopiedFixture::new_with_unrelated_retirement(Residue::AbsentWithoutExclusion).await;
    let operation = fixture.own().await;
    let PermanentDeleteAuthorization::Copied(authorization) = &operation.authorization else {
        panic!("actual copied authorization expected");
    };
    assert!(authorization.deletion_elapsed_nanos >= 60_000_000_000);
    assert!(authorization.grace_elapsed_nanos >= 60_000_000_000);
    assert_ne!(authorization.exclusion.cycle, 7);

    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let capabilities =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let key = format!(
        "objects/index/{}/MANIFEST",
        capabilities.generation.unwrap()
    );
    let manifest =
        GenerationManifest::decode(observed.logical()[&key].as_deref().unwrap()).unwrap();
    let exclusions = manifest.exclusions.as_ref().unwrap();
    assert_eq!(exclusions.len(), 2);
    assert!(
        exclusions
            .windows(2)
            .all(|rows| rows[0].pack_id < rows[1].pack_id)
    );
    assert!(exclusions.contains(&unrelated));
    let position = exclusions
        .binary_search_by_key(fixture.pack.as_bytes(), |row| row.pack_id)
        .unwrap();
    assert_eq!(exclusions[position].cycle, authorization.exclusion.cycle);
    assert_eq!(exclusions[position].epoch, authorization.exclusion.epoch);

    drop(observed);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_missing_foreign_original_keeps_complete_live_data() {
    positive(Residue::Absent, true).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_first_owner_drops_unqualified_lineage_and_keeps_burns() {
    positive(Residue::Trash, true).await;
}

/// Retains observations of one unchanged genuine barrier across native renewals.
struct WaitingBarrier {
    started: std::time::Duration,
    original_lease: GcLease,
    during_wait: GcLease,
    tombstone: Vec<u8>,
    path: std::path::PathBuf,
    identity: (u64, u64),
    journal_path: std::path::PathBuf,
    journal_bytes: Vec<u8>,
}

async fn committed_barrier_wait() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let (arrived, release) = fixture.guard().store().fs().pause(Phase::Barrier);
    let observe = async {
        let path = arrived.await.unwrap();
        let key = path
            .strip_prefix(fixture.guard().store().root())
            .unwrap()
            .to_str()
            .unwrap();
        let tombstone = tokio::fs::read(&path).await.unwrap();
        let decoded = Tombstone::decode(&tombstone).unwrap();
        assert_eq!(decoded.pack, *fixture.pack.as_bytes());
        assert_eq!(decoded.removed, 0);
        let suffix: String = blake3::hash(key.as_bytes())
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let journal = fixture
            .source
            .parent
            .join("copied-publication/.terrane-creation")
            .join(suffix);
        let journal_path = journal;
        let journal_bytes = tokio::fs::read(&journal_path).await.unwrap();
        let journal = CreationJournal::decode(&journal_bytes).unwrap();
        assert!(matches!(
            journal.state,
            JournalState::Committed {
                binding: ArtifactBinding::Trash(ref actual),
                ..
            } if actual == &tombstone
        ));
        assert_eq!(
            fixture.guard().store().fs().completed(),
            vec![Phase::Preparation]
        );
        let lease = GcLease::decode(
            &tokio::fs::read(fixture.guard().store().root().join("gc/lease"))
                .await
                .unwrap(),
        )
        .unwrap();
        let barrier_ready = fixture.source.clock.monotonic();
        let metadata = tokio::fs::metadata(&path).await.unwrap();
        let identity = (metadata.dev(), metadata.ino());
        let mut acknowledgments = fixture.guard().store().fs().observe_lease_completions();
        release.send(()).unwrap();

        let first_slot = acknowledgments.recv().await.unwrap();
        let first = cadence::acknowledged_lease(&fixture, &first_slot).await;
        assert_eq!(first.holder, lease.holder);
        assert_eq!(first.epoch, lease.epoch);
        assert!(first.expiry > lease.expiry);

        let next_slot = acknowledgments.recv().await.unwrap();
        let during_wait = cadence::acknowledged_lease(&fixture, &next_slot).await;
        assert_ne!(next_slot, first_slot);
        assert_eq!(during_wait.holder, first.holder);
        assert_eq!(during_wait.epoch, first.epoch);
        assert!(during_wait.expiry > first.expiry);
        assert!(
            fixture
                .source
                .clock
                .monotonic()
                .checked_sub(barrier_ready)
                .unwrap()
                < std::time::Duration::from_secs(60)
        );
        assert_eq!(
            fixture.guard().store().fs().completed(),
            vec![Phase::Preparation, Phase::Barrier]
        );
        assert_eq!(tokio::fs::read(&path).await.unwrap(), tombstone);
        assert_eq!(tokio::fs::read(&journal_path).await.unwrap(), journal_bytes);
        let metadata = tokio::fs::metadata(&path).await.unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
        WaitingBarrier {
            started: barrier_ready,
            original_lease: lease,
            during_wait,
            tombstone,
            path,
            identity,
            journal_path,
            journal_bytes,
        }
    };
    let (operation, observation) = tokio::join!(fixture.own(), observe);
    assert!(
        fixture
            .source
            .clock
            .monotonic()
            .checked_sub(observation.started)
            .unwrap()
            >= std::time::Duration::from_secs(60)
    );
    let PermanentDeleteAuthorization::Copied(authorization) = operation.authorization else {
        panic!("actual copied authorization expected");
    };
    assert!(authorization.grace_elapsed_nanos >= 60_000_000_000);
    assert!(authorization.deletion_elapsed_nanos >= 60_000_000_000);
    assert_eq!(
        authorization.lease.holder,
        observation.original_lease.holder
    );
    assert_eq!(authorization.lease.epoch, observation.original_lease.epoch);
    assert!(authorization.lease.expiry > observation.original_lease.expiry);
    assert!(authorization.lease.expiry > observation.during_wait.expiry);
    let BarrierArtifact::Local(barrier) = authorization.barrier else {
        panic!("actual local barrier expected");
    };
    assert_eq!(barrier.tombstone, observation.tombstone);
    assert_eq!(
        tokio::fs::read(fixture.guard().store().root().join(barrier.key))
            .await
            .unwrap(),
        observation.tombstone
    );
    let metadata = tokio::fs::metadata(&observation.path).await.unwrap();
    assert_eq!((metadata.dev(), metadata.ino()), observation.identity);
    assert_eq!(
        tokio::fs::read(observation.journal_path).await.unwrap(),
        observation.journal_bytes
    );
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_new_barrier_journal_precedes_full_g_and_d() {
    committed_barrier_wait().await;
}

#[tokio::test]
async fn gc_copied_retirement_native_same_holder_renewal_preserves_barrier_wait() {
    committed_barrier_wait().await;
}

async fn invalidate_completed_barrier(regress_clock: bool) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    fixture.source.clock.set(100, 100);
    let (arrived, release) = fixture.guard().store().fs().pause_completed(Phase::Barrier);
    let mutate = async {
        let path = arrived.await.unwrap();
        assert_eq!(
            fixture.guard().store().fs().completed(),
            vec![Phase::Preparation, Phase::Barrier]
        );
        if regress_clock {
            // The same retained injected clock actually rolls back; neither
            // a replacement clock nor an imported elapsed claim is supplied.
            assert!(fixture.source.clock.monotonic().as_secs() >= 100);
            fixture.source.clock.set(100, 0);
        } else {
            let bytes = tokio::fs::read(&path).await.unwrap();
            let before = tokio::fs::metadata(&path).await.unwrap();
            let replaced = path.with_extension("reincarnated");
            tokio::fs::write(&replaced, &bytes).await.unwrap();
            tokio::fs::set_permissions(&replaced, before.permissions())
                .await
                .unwrap();
            tokio::fs::rename(&replaced, &path).await.unwrap();
            let after = tokio::fs::metadata(&path).await.unwrap();
            assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
        }
        release.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(fixture.attempt(), mutate);
    let failure = result.unwrap_err();
    match &failure {
        CollectionError::Store(error) if regress_clock => {
            assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));
        }
        CollectionError::Store(error) => {
            assert!(matches!(
                error.kind(),
                StoreErrorKind::Unavailable { retry_after: None }
            ));
        }
        _ => panic!("unexpected actual barrier refusal: {failure}"),
    }
    assert!(
        !fixture
            .guard()
            .store()
            .fs()
            .completed()
            .contains(&Phase::Ownership)
    );
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let owner = observed
        .state()
        .burn_owners
        .as_ref()
        .unwrap()
        .iter()
        .find(|owner| owner.pack == *fixture.pack.as_bytes())
        .unwrap();
    assert_eq!(
        owner.selection,
        terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility
    );
    drop(observed);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_replaced_barrier_or_clock_regression_resets_wait() {
    invalidate_completed_barrier(false).await;
    invalidate_completed_barrier(true).await;
}

async fn replace_consumed_control(guard_record: bool) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let name = "refs/heads/_/main";
    let source = fixture.guard().store().ref_get(name).await.unwrap();
    let path = if guard_record {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        held.selected_guard_snapshot_record(&observed)
            .await
            .unwrap()
            .unwrap()
            .path()
            .to_owned()
    } else {
        fixture.authority.control().join("registration.cbor")
    };
    let bytes = tokio::fs::read(&path).await.unwrap();
    let before = tokio::fs::metadata(&path).await.unwrap();
    let (arrived, release) = fixture.guard().store().fs().pause_completed(Phase::Barrier);
    let replace = async {
        arrived.await.unwrap();
        // Qualification and the real barrier ACK have already consumed this
        // exact physical control. Identical bytes cannot preserve incarnation.
        let next = path.with_extension("copied-control-replacement");
        tokio::fs::write(&next, &bytes).await.unwrap();
        tokio::fs::set_permissions(&next, before.permissions())
            .await
            .unwrap();
        tokio::fs::rename(next, &path).await.unwrap();
        let after = tokio::fs::metadata(&path).await.unwrap();
        assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
        release.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(fixture.attempt(), replace);
    let failure = result.unwrap_err();
    let error = match (&failure, guard_record) {
        (CollectionError::Store(error), true) => error,
        (CollectionError::Lease(crate::gc::lease::LeaseError::Store(error)), false) => error,
        _ => panic!("unexpected control refusal wrapper: {failure}"),
    };
    if guard_record {
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Denied {
                verb: "gc-copied-preparation",
                pattern: "genuine fresh destination plan".into(),
            }
        );
    } else {
        // Fresh lease qualification rejects the changed consumed registration
        // before copied-placement qualification can issue ownership.
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Denied {
                verb: "gc-lease",
                pattern: "configured collector lease".into(),
            }
        );
    }
    assert_eq!(fixture.guard().store().ref_get(name).await.unwrap(), source);
    assert!(
        !fixture
            .guard()
            .store()
            .fs()
            .completed()
            .contains(&Phase::Ownership)
    );
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    assert!(
        observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .any(|owner| {
                owner.pack == *fixture.pack.as_bytes()
                    && owner.selection
                        == terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility
            })
    );
    drop(observed);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_changed_guard_or_consumed_control_refuses_owner() {
    replace_consumed_control(true).await;
    replace_consumed_control(false).await;
}

async fn changed_selected_whole_lease_refuses_owner() {
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
        let old = GcLease::decode(
            &tokio::fs::read(fixture.guard().store().root().join("gc/lease"))
                .await
                .unwrap(),
        )
        .unwrap();
        let attempted = fixture.guard().store().fs().observe_queued_lock();
        let collector = crate::gc::lease::Collector::new(fixture.guard(), &fixture.authority);
        let renewal = collector.renew(&old, 180);
        let release_barrier = async {
            attempted.await.unwrap();
            release.send(()).unwrap();
        };
        let (receipt, ()) = tokio::join!(renewal, release_barrier);
        let new = receipt.unwrap().lease;
        assert_eq!(new.holder, old.holder);
        assert_eq!(new.epoch, old.epoch);
        assert!(new.expiry > old.expiry);
        new
    };
    let (result, new) = tokio::join!(fixture.attempt(), change);
    let failure = result.unwrap_err();
    assert!(
        matches!(
            &failure,
            CollectionError::Lease(crate::gc::lease::LeaseError::Lease(
                terrane_format::gc::GcError::LeaseLost
            ))
        ),
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
    assert_eq!(GcLease::decode(bytes).unwrap(), new);
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
            .any(|owner| owner.pack == *fixture.pack.as_bytes()
                && owner.selection
                    == terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility)
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
async fn gc_copied_retirement_native_queued_whole_lease_change_or_expiry_refuses_owner() {
    changed_selected_whole_lease_refuses_owner().await;
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let (arrived, release) = fixture.guard().store().fs().pause_completed(Phase::Barrier);
    let expire = async {
        arrived.await.unwrap();
        let lease = GcLease::decode(
            &tokio::fs::read(fixture.guard().store().root().join("gc/lease"))
                .await
                .unwrap(),
        )
        .unwrap();
        let monotonic = fixture.source.clock.monotonic().as_secs() + 1;
        // Expire the actual acquired whole lease on its same injected clock.
        // Monotonic time advances, so rollback cannot explain this refusal.
        fixture.source.clock.set(lease.expiry, monotonic);
        release.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(fixture.attempt(), expire);
    let failure = result.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Denied { .. })),
        "{failure}"
    );
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation, Phase::Barrier]
    );
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    assert!(
        observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .any(|owner| {
                owner.pack == *fixture.pack.as_bytes()
                    && owner.selection
                        == terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility
            })
    );
    drop(observed);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_barrier_collision_preserves_old_trash() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let (arrived, release) = fixture
        .guard()
        .store()
        .fs()
        .pause_completed(Phase::Preparation);
    let collision = async {
        let path = arrived.await.unwrap();
        let slot = terrane_format::gc::publication::PublicationCommit::decode(
            &tokio::fs::read(path).await.unwrap(),
        )
        .unwrap();
        let control = fixture.source.parent.join("copied-publication");
        let transaction = terrane_format::gc::publication::PublicationTransaction::decode(
            &tokio::fs::read(control.join(slot.transaction_key))
                .await
                .unwrap(),
        )
        .unwrap();
        let preparation: Vec<_> = transaction
            .changes
            .iter()
            .filter_map(|change| {
                let body = change.new.as_deref()?;
                let preparation =
                    terrane_format::gc::retirement::CopiedRetirementPreparation::decode(body)
                        .ok()?;
                preparation.plan.check_key(&change.key).unwrap();
                Some(preparation)
            })
            .collect();
        assert_eq!(preparation.len(), 1);
        let proposed = Tombstone::decode(&preparation[0].plan.tombstone).unwrap();
        assert_eq!(proposed.pack, *fixture.pack.as_bytes());
        let path = fixture
            .guard()
            .store()
            .root()
            .join(format!("trash/{}/{}", proposed.cycle, fixture.pack));
        assert!(!path.exists());
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        // The actual submitted preparation identifies only the fault target.
        // These old bytes supply neither a creation journal nor barrier age.
        let old = fixture.old_trash.clone();
        assert_ne!(old, preparation[0].plan.tombstone);
        tokio::fs::write(&path, &old).await.unwrap();
        let metadata = tokio::fs::metadata(&path).await.unwrap();
        release.send(()).unwrap();
        (path, old, (metadata.dev(), metadata.ino()))
    };
    let (result, (path, old, identity)) = tokio::join!(fixture.attempt(), collision);
    let failure = result.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Unavailable { retry_after: None })),
        "{failure}"
    );
    assert_eq!(
        fixture.guard().store().fs().completed(),
        vec![Phase::Preparation]
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), old);
    let metadata = tokio::fs::metadata(path).await.unwrap();
    assert_eq!((metadata.dev(), metadata.ino()), identity);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_losing_preparation_cannot_create_barrier() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let fs = fixture.guard().store().fs();
    fs.noop_preparation_slot();
    // Skipping the actual slot rename violates install's exact reread
    // postcondition, before any preparation ACK or new barrier can exist.
    let failure = fixture.attempt().await.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Corrupt(_))),
        "{failure}"
    );
    let path = fs.refused_slot().unwrap();
    assert!(!path.exists());
    assert!(fs.completed().is_empty());
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    assert!(
        observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .any(|owner| {
                owner.pack == *fixture.pack.as_bytes()
                    && owner.selection
                        == terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility
            })
    );
    assert!(observed.logical().iter().all(|(key, bytes)| {
        !key.contains("/delete/")
            || bytes.as_deref().is_none_or(|bytes| {
                terrane_format::gc::retirement::CopiedRetirementPreparation::decode(bytes).is_err()
            })
    }));
    let trash = fixture.guard().store().root().join("trash");
    if trash.exists() {
        let mut directories = tokio::fs::read_dir(trash).await.unwrap();
        while let Some(directory) = directories.next_entry().await.unwrap() {
            let mut entries = tokio::fs::read_dir(directory.path()).await.unwrap();
            assert!(entries.next_entry().await.unwrap().is_none());
        }
    }
    drop(observed);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_burned_or_excluded_fallback_cannot_cover_live_data() {
    let fixture = CopiedFixture::with_live_old_fallback().await;
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap();
    let served = fixture.guard().store().get(&chunk, None).await.unwrap();
    let verified = crate::codec::decode_verified(
        &served,
        b"published source".len(),
        &fixture.source.config.chunk_profile,
        true,
        &chunk,
        None,
    )
    .unwrap();
    assert_eq!(verified.plaintext(), b"published source");
    let old_path = fixture.guard().store().root().join(fixture.pack.pack_key());
    let old = tokio::fs::read(&old_path).await.unwrap();
    let fallback = crate::pack::PackReader::open(&old)
        .unwrap()
        .read(
            crate::pack::EntryKind::Chunk,
            &chunk.terrane_v1_digest().unwrap(),
            &crate::pack::RawBodyDecoder,
        )
        .unwrap();
    // PackReader verifies the requested Chunk identity after RawBodyDecoder
    // removes its codec envelope; serving returns that still-encoded envelope.
    assert_eq!(fallback, verified.plaintext());
    assert_eq!(fallback, b"published source");
    let index = fixture
        .guard()
        .store()
        .root()
        .join(fixture.pack.index_key());
    assert!(!index.exists());
    let live = fixture.live_data_path().await;
    assert_ne!(live, old_path);
    let unavailable = live.with_extension("live-unavailable");
    tokio::fs::rename(&live, &unavailable).await.unwrap();
    let baseline = fixture.forbid_chunk_reads().await;
    let failure = fixture.attempt().await.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Unavailable { retry_after: None })),
        "{failure}"
    );
    assert!(fixture.guard().store().fs().completed().is_empty());
    assert_eq!(fixture.source.fs.data_body_read_attempts(), baseline);
    assert_eq!(tokio::fs::read(old_path).await.unwrap(), old);
    assert!(unavailable.exists());
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_incomplete_ref_or_absent_history_refuses_preparation() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let before = held.observe_publication_unrepaired().await.unwrap();
        let bytes = before.logical()["CAPABILITIES"].as_ref().unwrap();
        let complete = BucketCapabilities::decode(bytes).unwrap();
        assert!(
            complete
                .ref_names
                .as_ref()
                .unwrap()
                .iter()
                .any(|name| name == "refs/heads/_/main")
        );
        for names in [None, Some(Vec::new())] {
            let mut incomplete = complete.clone();
            incomplete.ref_names = names;
            fixture.source.fs.reset();
            let error = match held
                .publish_raw(
                    &before,
                    vec![terrane_format::gc::publication::LogicalChange {
                        key: "CAPABILITIES".into(),
                        expected: Some(bytes.clone()),
                        new: Some(incomplete.encode().unwrap()),
                    }],
                )
                .await
            {
                Err(error) => error,
                Ok(_) => panic!("incomplete inventory must refuse publication"),
            };
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName(
                    "publication".into()
                ))
            );
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(fixture.source.fs.effects(), 0);
            assert!(fixture.guard().store().fs().completed().is_empty());
            let after = held.observe_publication_unrepaired().await.unwrap();
            assert_eq!(after.stamp(), before.stamp());
            assert_eq!(after.state(), before.state());
            assert_eq!(after.logical(), before.logical());
        }
    }
    let name = "refs/heads/_/main";
    let selected = fixture
        .guard()
        .store()
        .ref_get(name)
        .await
        .unwrap()
        .unwrap();
    let candidate = selected.candidate_id.as_ref().unwrap();
    let key = BucketKey::reflog_candidate(name, selected.seq, candidate).unwrap();
    let path = fixture.guard().store().root().join(key.as_str());
    let bytes = tokio::fs::read(&path).await.unwrap();
    let log = terrane_format::refs::RefLogRecord::decode(&bytes).unwrap();
    assert_eq!(log.record, selected);
    let unavailable = path.with_extension("history-unavailable");
    tokio::fs::rename(&path, &unavailable).await.unwrap();

    fixture.source.fs.reset();
    let failure = fixture.attempt().await.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Lease(crate::gc::lease::LeaseError::Store(error))
        if matches!(error.kind(), StoreErrorKind::Corrupt(_))),
        "{failure}"
    );
    assert!(fixture.guard().store().fs().completed().is_empty());
    assert_eq!(fixture.source.fs.effects(), 0);
    assert!(!path.exists());
    assert_eq!(tokio::fs::read(unavailable).await.unwrap(), bytes);
    assert_eq!(fixture.source.head, selected);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_unused_memo_sharing_live_index_result_keeps_actual_context() {
    let (fixture, observation) = CopiedFixture::with_indexed_memo().await;
    let memo_hash = observation.memo.terrane_v1_digest().unwrap();
    assert_ne!(memo_hash, observation.index);
    assert_eq!(
        fixture
            .guard()
            .store()
            .get(&observation.memo, None)
            .await
            .unwrap(),
        observation.bytes
    );
    let baseline = fixture.forbid_chunk_reads().await;
    let operation = fixture.own().await;
    assert_eq!(fixture.source.fs.data_body_read_attempts(), baseline);
    let PermanentDeleteAuthorization::Copied(authorization) = operation.authorization else {
        panic!("actual copied authorization expected");
    };
    let bytes = tokio::fs::read(
        fixture
            .source
            .parent
            .join("copied-publication")
            .join(&authorization.fence.key),
    )
    .await
    .unwrap();
    assert_eq!(*blake3::hash(&bytes).as_bytes(), authorization.fence.digest);
    let fence = terrane_format::gc::retirement::CopiedPlacementFence::decode(&bytes).unwrap();
    assert_eq!(fence.encode().unwrap(), bytes);
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let bytes = observed.logical()[&fence.marks.key].as_deref().unwrap();
    assert_eq!(*blake3::hash(bytes).as_bytes(), fence.marks.digest);
    let state = terrane_format::gc::GcState::decode(bytes).unwrap();
    let contexts: Vec<_> = state
        .objects
        .iter()
        .filter(|object| object.kind == 2 && object.hash == observation.index)
        .collect();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].flags, 6);
    assert!(contexts[0].proof_context.is_none());
    let physical_memo: Vec<_> = state
        .objects
        .iter()
        .filter(|object| object.kind == 9 && object.hash == memo_hash)
        .collect();
    assert_eq!(physical_memo.len(), 1);
    assert_eq!(physical_memo[0].flags, 0);
    assert!(physical_memo[0].proof_context.is_none());
    drop(observed);
    drop(held);
    drop(holder);
    assert_eq!(
        fixture
            .guard()
            .store()
            .get(&observation.memo, None)
            .await
            .unwrap(),
        observation.bytes
    );
    fixture.cleanup();
}

async fn no_ack(phase: Option<Phase>) {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let fs = fixture.guard().store().fs();
    match phase {
        Some(phase) => fs.noop(phase),
        None => fs.noop_owner_slot(),
    }
    let failure = fixture.attempt().await.unwrap_err();
    let CollectionError::Store(error) = &failure else {
        panic!("unexpected missing-ACK wrapper: {failure}");
    };
    if phase.is_some() {
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Unavailable { retry_after: None }
        );
    } else {
        // The actual skipped slot rename leaves its destination absent. The
        // fixed install command detects that failed postcondition as corruption.
        assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
        let slot = fs.refused_slot().unwrap();
        assert!(!slot.exists());
    }
    assert!(!fs.completed().contains(&Phase::Ownership));
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let owner = observed
        .state()
        .burn_owners
        .as_ref()
        .unwrap()
        .iter()
        .find(|owner| owner.pack == *fixture.pack.as_bytes())
        .unwrap();
    assert_eq!(
        owner.selection,
        terrane_format::gc::publication::PermanentOwnerSelection::CopiedVisibility
    );
    let record = BucketKey::ref_record("refs/heads/_/main").unwrap();
    assert_eq!(
        observed.logical()[record.as_str()].as_deref(),
        Some(fixture.source.head.encode().unwrap().as_slice())
    );
    drop(observed);
    drop(held);
    drop(holder);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_copied_retirement_native_failed_or_unexecuted_native_ack_cannot_select_owner() {
    no_ack(Some(Phase::Preparation)).await;
    no_ack(Some(Phase::Barrier)).await;
    // The final fault targets the actual owner slot before rename and ACK,
    // not a later seal after durable selection can already be indeterminate.
    no_ack(None).await;
}

#[tokio::test]
async fn gc_copied_retirement_native_unresolved_live_data_refuses_before_preparation() {
    let fixture = CopiedFixture::new(Residue::Absent).await;
    let path = fixture.live_data_path().await;
    let unavailable = path.with_extension("unavailable");
    tokio::fs::rename(&path, &unavailable).await.unwrap();
    let failure = fixture.attempt().await.unwrap_err();
    assert!(
        matches!(&failure, CollectionError::Store(error)
        if matches!(error.kind(), StoreErrorKind::Unavailable { retry_after: None })),
        "{failure}"
    );
    assert!(fixture.guard().store().fs().completed().is_empty());
    assert!(!path.exists());
    assert!(unavailable.exists());
    fixture.cleanup();
}
