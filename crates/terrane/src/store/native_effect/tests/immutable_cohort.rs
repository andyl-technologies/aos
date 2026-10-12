//! Exercises real cohort durability, complete checks and worker-owned exclusions.

use super::*;
use crate::store::native_effect::immutable_cohort::{Install, Receipt, request};

fn cohort(root: &std::path::Path, held: &HeldLock) -> (NativeFsEffect, Receipt) {
    let owner = MetadataStamp::checked(&held.file.metadata().unwrap())
        .unwrap()
        .owner;
    let policy = FencePolicy::Payload { owner };
    let installs: Vec<_> = (0..2)
        .map(|index| Install {
            temporary: root.join(format!(".terrane-tmp:cohort-{index}")),
            target: root.join(format!("shard-{index}.idx")),
            bytes: format!("canonical shard {index}").into_bytes(),
            policy,
        })
        .collect();
    let reads = installs
        .iter()
        .flat_map(|install| [&install.temporary, &install.target])
        .map(|path| ExactRead {
            path: path.clone(),
            expected: None,
            identity: None,
            metadata: None,
            policy,
            owner,
            parents: parents(path),
        })
        .collect();
    let (plan, receipt) = request(installs);
    let mut effect = effect(held, plan);
    effect.preimages = reads;
    (effect, receipt)
}

#[test]
fn immutable_cohort_acknowledges_actual_complete_installation() {
    let (root, held) = fixture();
    let (effect, receipt) = cohort(&root, &held);

    effect.execute_inline().unwrap();
    receipt.take().unwrap();

    for index in 0..2 {
        assert_eq!(
            std::fs::read(root.join(format!("shard-{index}.idx"))).unwrap(),
            format!("canonical shard {index}").into_bytes()
        );
        assert!(!root.join(format!(".terrane-tmp:cohort-{index}")).exists());
    }
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn immutable_cohort_callback_success_cannot_supply_native_acknowledgment() {
    let (root, held) = fixture();
    let (effect, receipt) = cohort(&root, &held);

    // Model an adapter acknowledging its request without running the worker.
    drop(effect);
    assert!(matches!(receipt.take(), Err(NativeEffectFailure::Io(error))
        if error.kind() == std::io::ErrorKind::Unsupported));
    assert!(!root.join("shard-0.idx").exists());

    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn immutable_cohort_partial_rename_failure_never_acknowledges() {
    let (root, held) = fixture();
    let (mut effect, receipt) = cohort(&root, &held);
    effect.faults.push(EffectFault::AfterRename);

    assert!(effect.execute_inline().is_err());
    assert!(receipt.take().is_err());

    assert_eq!(
        std::fs::read(root.join("shard-0.idx")).unwrap(),
        b"canonical shard 0"
    );
    assert!(!root.join("shard-1.idx").exists());
    assert!(!root.join(".terrane-tmp:cohort-0").exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
fn staging_gate(
    effect: &mut NativeFsEffect,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (arrived, received) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    effect.gates.push(TestGate {
        phase: TestGatePhase::AfterCohortStaging,
        arrived,
        release: released,
    });
    (received, release)
}

#[cfg(feature = "tokio")]
async fn await_staging(received: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || received.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn immutable_cohort_changed_whole_preimage_between_primitives_refuses() {
    let (root, held) = fixture();
    let (mut effect, receipt) = cohort(&root, &held);
    let (received, release) = staging_gate(&mut effect);
    let task = tokio::spawn(effect.execute_tokio());
    await_staging(received).await;

    // Preserve inode, owner and modes; exact whole bytes alone must refuse.
    std::fs::write(root.join(".terrane-tmp:cohort-0"), b"changed shard bytes").unwrap();
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
async fn immutable_cohort_expiry_between_primitives_refuses() {
    let (root, held) = fixture();
    let (mut effect, receipt) = cohort(&root, &held);
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
async fn immutable_cohort_dropped_waiter_retains_actual_lock_to_completion() {
    let (root, held) = fixture();
    let (mut effect, receipt) = cohort(&root, &held);
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

#[path = "immutable_cohort/install_scope_tests.rs"]
mod install_scope_tests;

#[path = "immutable_cohort/targeted_rename_tests.rs"]
mod targeted_rename_tests;
