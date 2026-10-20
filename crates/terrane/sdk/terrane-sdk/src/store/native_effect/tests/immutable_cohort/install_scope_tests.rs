//! Exercises body deferral through real retained workers and actual handoffs.

use super::*;
use crate::store::native_effect::immutable_cohort::{request_scoped, scope::Candidates};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
#[cfg(feature = "tokio")]
use std::os::unix::fs::PermissionsExt;

fn scoped_cohort(root: &std::path::Path, held: &HeldLock) -> (NativeFsEffect, Receipt) {
    let (mut effect, _) = cohort(root, held);
    let owner = effect.preimages[0].owner;
    let installs: Vec<_> = (0..2)
        .map(|index| Install {
            temporary: root.join(format!(".terrane-tmp:cohort-{index}")),
            target: root.join(format!("shard-{index}.idx")),
            bytes: format!("canonical shard {index}").into_bytes(),
            policy: FencePolicy::Payload { owner },
        })
        .collect();
    let bodies = installs
        .iter()
        .map(|install| (install.target.clone(), install.bytes.clone()))
        .collect();
    let scope = Candidates::new(root, owner, bodies).cohort(&BTreeSet::new());
    let (plan, receipt) = request_scoped(installs, Some(scope));
    effect.plan = plan;
    (effect, receipt)
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_prior_body_tamper_is_rejected_by_complete_cohort_boundary() {
    let (root, held) = fixture();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let (first, release_first) = staging_gate(&mut effect);
    let (second, release_second) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(first).await;
    release_first.send(()).unwrap();
    await_staging(second).await;

    std::fs::write(root.join("shard-0.idx"), b"persistent changed body").unwrap();
    release_second.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(receipt.take().is_err());
    // Unrelated body refusal may follow harmless completion of another output.
    assert_eq!(
        std::fs::read(root.join("shard-1.idx")).unwrap(),
        b"canonical shard 1"
    );
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_prior_inode_replacement_refuses_before_next_rename() {
    let (root, held) = fixture();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let (first, release_first) = staging_gate(&mut effect);
    let (second, release_second) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(first).await;
    release_first.send(()).unwrap();
    await_staging(second).await;

    std::fs::rename(root.join("shard-0.idx"), root.join("retained-old-inode")).unwrap();
    std::fs::write(root.join("shard-0.idx"), b"canonical shard 0").unwrap();
    release_second.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(receipt.take().is_err());
    assert!(!root.join("shard-1.idx").exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_current_staging_and_target_bodies_remain_checked_at_real_handoffs() {
    for phase in [
        TestGatePhase::BeforeOpen,
        TestGatePhase::AfterOpen,
        TestGatePhase::AfterSourceSync,
        TestGatePhase::AfterRename,
        TestGatePhase::AfterCohortStaging,
    ] {
        let (root, held) = fixture();
        let (mut effect, receipt) = scoped_cohort(&root, &held);
        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        effect.gates.push(TestGate {
            phase,
            arrived,
            release: released,
        });
        let task = tokio::spawn(effect.execute_tokio());
        await_staging(received).await;

        let path = if phase == TestGatePhase::AfterRename {
            root.join("shard-0.idx")
        } else {
            root.join(".terrane-tmp:cohort-0")
        };
        std::fs::write(path, b"changed current body").unwrap();
        release.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(receipt.take().is_err());
        assert!(!root.join("shard-1.idx").exists());
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn scoped_sync_and_rename_failures_never_supply_native_receipts() {
    for fault in [
        EffectFault::BeforeFileSync,
        EffectFault::AfterFileSync,
        EffectFault::BeforeRename,
        EffectFault::AfterRename,
        EffectFault::BeforeDirectorySync,
    ] {
        let (root, held) = fixture();
        let (mut effect, receipt) = scoped_cohort(&root, &held);
        effect.faults.push(fault);
        assert!(effect.execute_inline().is_err());
        assert!(receipt.take().is_err());
        assert!(!root.join("shard-1.idx").exists());
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn scoped_previous_batch_changed_body_refuses_at_complete_entry() {
    let (root, held) = fixture();
    let (first, first_receipt) = scoped_cohort(&root, &held);
    first.execute_inline().unwrap();
    first_receipt.take().unwrap();
    let prior = root.join("shard-0.idx");
    let metadata = std::fs::symlink_metadata(&prior).unwrap();
    let stamp = MetadataStamp::checked(&metadata).unwrap();
    let policy = FencePolicy::Payload { owner: stamp.owner };
    let install = Install {
        temporary: root.join(".terrane-tmp:next-batch"),
        target: root.join("next-batch.idx"),
        bytes: b"next canonical".to_vec(),
        policy,
    };
    let bodies = BTreeMap::from([
        (prior.clone(), b"canonical shard 0".to_vec()),
        (install.target.clone(), install.bytes.clone()),
    ]);
    let scope =
        Candidates::new(&root, stamp.owner, bodies).cohort(&BTreeSet::from([prior.clone()]));
    let absent = [&install.temporary, &install.target]
        .into_iter()
        .map(|path| ExactRead {
            path: path.clone(),
            expected: None,
            identity: None,
            metadata: None,
            policy,
            owner: stamp.owner,
            parents: parents(path),
        })
        .collect::<Vec<_>>();
    let (plan, receipt) = request_scoped(vec![install], Some(scope));
    let mut next = effect(&held, plan);
    next.preimages = absent;
    next.preimages.push(ExactRead {
        path: prior.clone(),
        expected: Some(b"canonical shard 0".to_vec()),
        identity: Some((metadata.dev(), metadata.ino())),
        metadata: Some(stamp),
        policy,
        owner: stamp.owner,
        parents: parents(&prior),
    });

    // Actual preceding receipt does not certify current bytes at the next entry.
    std::fs::write(&prior, b"changed prior batch body").unwrap();
    assert!(next.execute_inline().is_err());
    assert!(receipt.take().is_err());
    assert!(!root.join(".terrane-tmp:next-batch").exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn scope_conflicting_variants_unknown_roots_and_bodies_keep_full_reads() {
    let (root, held) = fixture();
    let path = root.join("prior.idx");
    std::fs::write(&path, b"canonical").unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    let stamp = MetadataStamp::checked(&metadata).unwrap();
    let read = ExactRead {
        path: path.clone(),
        expected: Some(b"canonical".to_vec()),
        identity: Some((metadata.dev(), metadata.ino())),
        metadata: Some(stamp),
        policy: FencePolicy::Payload { owner: stamp.owner },
        owner: stamp.owner,
        parents: parents(&path),
    };
    let created = BTreeSet::from([path.clone()]);
    let bodies = BTreeMap::from([(path.clone(), b"canonical".to_vec())]);
    let mut scope = Candidates::new(&root, stamp.owner, bodies.clone()).cohort(&created);
    scope.prepare(std::slice::from_ref(&read));
    assert!(scope.defers(&read));
    let absent = ExactRead {
        path: path.clone(),
        expected: None,
        identity: None,
        metadata: None,
        policy: read.policy,
        owner: read.owner,
        parents: parents(&path),
    };
    let variants = [read, absent];
    scope.prepare(&variants);
    let read = &variants[0];
    assert!(!scope.defers(read));
    let mut unknown = Candidates::new(&root.join("other"), stamp.owner, bodies).cohort(&created);
    unknown.prepare(std::slice::from_ref(read));
    assert!(!unknown.defers(read));
    let mut mismatch = Candidates::new(
        &root,
        stamp.owner,
        BTreeMap::from([(path, b"different".to_vec())]),
    )
    .cohort(&created);
    mismatch.prepare(std::slice::from_ref(read));
    assert!(!mismatch.defers(read));
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_cohort_expiry_between_primitives_refuses() {
    let (root, held) = fixture();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let exact_clock = Arc::new(AtomicUsize::new(0));
    effect.final_check = Some(crate::selected_bridge::effect_test_checks::deadline_check(
        crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&exact_clock))),
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(9),
    ));
    let (received, release) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(received).await;

    exact_clock.store(10, Ordering::SeqCst);
    release.send(()).unwrap();
    assert!(
        matches!(task.await.unwrap(), Err(NativeEffectFailure::Rejected(failure))
        if matches!(failure.kind(), crate::store::StoreErrorKind::Denied { verb: "test-deadline", .. }))
    );
    assert!(receipt.take().is_err());
    assert!(!root.join("shard-0.idx").exists());
    assert!(!root.join("shard-1.idx").exists());

    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_cohort_dropped_waiter_retains_actual_lock_to_completion() {
    let (root, held) = fixture();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let (received, release) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(received).await;

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(held);
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("coordination"))
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));

    release.send(()).unwrap();
    tokio::task::spawn_blocking(move || {
        contender.lock().unwrap();
    })
    .await
    .unwrap();
    receipt.take().unwrap();
    assert_eq!(
        std::fs::read(root.join("shard-1.idx")).unwrap(),
        b"canonical shard 1"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_consumed_source_body_refuses_before_current_rename() {
    let (root, held) = fixture();
    let path = root.join("consumed-source");
    std::fs::write(&path, b"consumed canonical body").unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    let stamp = MetadataStamp::checked(&metadata).unwrap();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    effect.preimages.push(ExactRead {
        path: path.clone(),
        expected: Some(b"consumed canonical body".to_vec()),
        identity: Some((metadata.dev(), metadata.ino())),
        metadata: Some(stamp),
        policy: FencePolicy::Payload { owner: stamp.owner },
        owner: stamp.owner,
        parents: parents(&path),
    });
    let (received, release) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(received).await;

    std::fs::write(&path, b"changed consumed source").unwrap();
    release.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(receipt.take().is_err());
    assert!(!root.join("shard-0.idx").exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_consumed_absence_change_refuses_before_current_rename() {
    let (root, held) = fixture();
    let path = root.join("consumed-absent-source");
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let owner = effect.preimages[0].owner;
    effect.preimages.push(ExactRead {
        path: path.clone(),
        expected: None,
        identity: None,
        metadata: None,
        policy: FencePolicy::Payload { owner },
        owner,
        parents: parents(&path),
    });
    let (received, release) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(received).await;

    std::fs::write(&path, b"newly present consumed source").unwrap();
    release.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(receipt.take().is_err());
    assert!(!root.join("shard-0.idx").exists());
    assert!(!root.join("shard-1.idx").exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_conflicting_live_variants_refuse_before_second_rename() {
    let (root, held) = fixture();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let path = root.join("shard-0.idx");
    let owner = effect.preimages[0].owner;
    // The real private 0600 output satisfies both policies initially. Rebind
    // preserves their different roles, so this exercises intermediate fallback.
    effect.preimages.push(ExactRead {
        path,
        expected: None,
        identity: None,
        metadata: None,
        policy: FencePolicy::ProtectedRecord { owner },
        owner,
        parents: parents(&root.join("shard-0.idx")),
    });
    let (first, release_first) = staging_gate(&mut effect);
    let (second, release_second) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(first).await;
    release_first.send(()).unwrap();
    await_staging(second).await;

    std::fs::write(root.join("shard-0.idx"), b"changed conflicting body").unwrap();
    release_second.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(receipt.take().is_err());
    assert!(!root.join("shard-1.idx").exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_canceled_waiter_holds_exclusion_through_promoted_body_refusal() {
    let (root, held) = fixture();
    let (mut effect, receipt) = scoped_cohort(&root, &held);
    let (first, release_first) = staging_gate(&mut effect);
    let (second, release_second) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(first).await;
    release_first.send(()).unwrap();
    await_staging(second).await;
    assert!(root.join("shard-0.idx").exists());

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(held);
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("coordination"))
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    std::fs::write(root.join("shard-0.idx"), b"persistent promoted body fault").unwrap();
    release_second.send(()).unwrap();
    tokio::task::spawn_blocking(move || contender.lock().unwrap())
        .await
        .unwrap();

    // The canceled waiter cannot release the worker's holds or manufacture ACK.
    assert!(receipt.take().is_err());
    assert_eq!(
        std::fs::read(root.join("shard-1.idx")).unwrap(),
        b"canonical shard 1"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[derive(Clone, Copy)]
enum PriorPhysicalFault {
    ExtraLink,
    Unlink,
    Symlink,
    WritableMode,
    ParentReplacement,
}

#[cfg(feature = "tokio")]
fn change_promoted_physical_receipt(root: &std::path::Path, fault: PriorPhysicalFault) -> PathBuf {
    let prior = root.join("shard-0.idx");
    let displaced = root.with_extension("displaced-parent");
    match fault {
        PriorPhysicalFault::ExtraLink => std::fs::hard_link(prior, root.join("alias")).unwrap(),
        PriorPhysicalFault::Unlink => std::fs::remove_file(prior).unwrap(),
        PriorPhysicalFault::Symlink => {
            let old = root.join("old-prior");
            std::fs::rename(&prior, &old).unwrap();
            std::os::unix::fs::symlink(old, prior).unwrap();
        }
        PriorPhysicalFault::WritableMode => {
            std::fs::set_permissions(prior, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        PriorPhysicalFault::ParentReplacement => {
            std::fs::rename(root, &displaced).unwrap();
            std::fs::DirBuilder::new().mode(0o700).create(root).unwrap();
        }
    }
    displaced
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn scoped_promoted_physical_faults_refuse_before_second_rename() {
    for fault in [
        PriorPhysicalFault::ExtraLink,
        PriorPhysicalFault::Unlink,
        PriorPhysicalFault::Symlink,
        PriorPhysicalFault::WritableMode,
        PriorPhysicalFault::ParentReplacement,
    ] {
        let (root, held) = fixture();
        let (mut effect, receipt) = scoped_cohort(&root, &held);
        let (first, release_first) = staging_gate(&mut effect);
        let (second, release_second) = staging_gate(&mut effect);
        let task = tokio::spawn(effect.execute_tokio());
        await_staging(first).await;
        release_first.send(()).unwrap();
        await_staging(second).await;
        assert!(root.join("shard-0.idx").exists());

        let displaced = change_promoted_physical_receipt(&root, fault);
        release_second.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(receipt.take().is_err());
        assert!(!root.join("shard-1.idx").exists());
        if displaced.exists() {
            assert!(!displaced.join("shard-1.idx").exists());
        }
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
        if displaced.exists() {
            std::fs::remove_dir_all(displaced).unwrap();
        }
    }
}
