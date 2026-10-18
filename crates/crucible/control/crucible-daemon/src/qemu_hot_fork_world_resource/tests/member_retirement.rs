//! Local member receipts across quarantine, real child retention and healthy return.
//!
//! Shared registries and counters are real component state. Their backing guard
//! remains a fixture; these controls issue no Main, native Source or child grant.

use super::*;
use std::process::{Command, Stdio};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_retained(result: Result<(), crate::QemuAttemptResourceGuardCleanupFailure>) {
    let failure = result.expect_err("quarantine must remain retained");
    assert!(matches!(
        failure.error(),
        QemuVmRealizationError::CleanupRetained { .. }
    ));
    assert!(failure.was_quarantined());
    assert!(
        !failure.has_raw_cause(),
        "member status cannot contain an aggregate host leaf"
    );
}

#[test]
fn quarantined_target_retains_its_exact_unreturned_share() -> TestResult {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner =
        QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
    let exact = identity("target", 1)?;
    let mut target = owner.reserve_node(exact.clone())?;
    target.quarantine();
    target.quarantine();
    let first = owner
        .state
        .lock()
        .unwrap()
        .terminal_failure
        .as_ref()
        .unwrap()
        .as_ptr();

    // Terminal observation does not borrow or wait on the shared registry.
    let state = owner.state.lock().unwrap();
    assert_retained(target.finish());
    assert_retained(target.finish());
    assert!(state.issued.contains(&exact));
    assert!(!state.released.contains(&exact));
    assert_eq!(state.terminal_failure.as_ref().unwrap().as_ptr(), first);
    drop(state);
    assert!(owner.finish().is_err());
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn quarantined_primary_launcher_never_records_launcher_return() -> TestResult {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner =
        QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
    let mut launcher = owner.lifecycle_guard()?;
    launcher.quarantine();
    launcher.quarantine();
    let first = owner
        .state
        .lock()
        .unwrap()
        .terminal_failure
        .as_ref()
        .unwrap()
        .as_ptr();

    // Terminal observation does not borrow or wait on the shared registry.
    let state = owner.state.lock().unwrap();
    assert_retained(launcher.finish());
    assert_retained(launcher.finish());
    assert!(state.lifecycle_launcher_required);
    assert!(!state.lifecycle_launcher_finished);
    assert_eq!(state.terminal_failure.as_ref().unwrap().as_ptr(), first);
    drop(state);
    assert!(owner.finish().is_err());
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn quarantined_auxiliary_keeps_its_real_lease_active() -> TestResult {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner =
        QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
    finish_primary_lifecycle(&mut owner, "node")?;
    let (_binding, mut factory) = bound_auxiliary_resources(&owner)?;
    let mut auxiliary = begin_auxiliary_resources(&mut factory, &owner)?;
    auxiliary.quarantine();
    auxiliary.quarantine();
    let first = owner
        .state
        .lock()
        .unwrap()
        .terminal_failure
        .as_ref()
        .unwrap()
        .as_ptr();

    // Terminal observation does not borrow or wait on the shared registry.
    let state = owner.state.lock().unwrap();
    assert_retained(auxiliary.finish());
    assert_retained(auxiliary.finish());
    assert!(state.auxiliary_lifecycle_active);
    assert_eq!(state.terminal_failure.as_ref().unwrap().as_ptr(), first);
    drop(state);
    assert!(begin_auxiliary_resources(&mut factory, &owner).is_err());
    assert!(owner.finish().is_err());
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

// Uses the existing uniquely owned child wrapper; no QEMU or native authority
// is constructed. The same real wait authority remains in the shared fixture.
fn retain_child_and_refuse_member_finish<M: QemuAttemptProcessResourceGuard>(
    member: &mut M,
    state: &Arc<Mutex<QemuHotForkWorldResourceState<FakeGuard>>>,
) -> TestResult {
    let process = Command::new(std::env::current_exe()?)
        .arg("--list")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let child = QemuNodeChild::from_test_process(process);
    let process_id = child.process_id();
    // A later child transfer must not replace an earlier actual quarantine cause.
    quarantine_world_state(state);
    let first = state
        .lock()
        .unwrap()
        .terminal_failure
        .as_ref()
        .unwrap()
        .as_ptr();
    member.retain_failed_launch_child(child);

    assert_retained(member.finish());
    assert_retained(member.finish());

    let mut state = state.lock().unwrap();
    assert_eq!(state.terminal_failure.as_ref().unwrap().as_ptr(), first);
    let child = state.guard.retained_child.as_mut().unwrap();
    assert_eq!(child.process_id(), process_id);
    assert!(!child.reaped());
    child.force_kill_and_reap_failed_helper(Duration::from_secs(2))?;
    assert!(child.reaped());
    drop(state);
    // Reaping that fixture child is not the missing native/member return proof.
    assert_retained(member.finish());
    Ok(())
}

#[test]
fn all_three_members_preserve_actual_retained_child_authority() -> TestResult {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    {
        let mut owner =
            QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
        let exact = identity("target", 1)?;
        let mut target = owner.reserve_process_node(exact.clone())?;
        retain_child_and_refuse_member_finish(&mut target, &owner.state)?;
        assert!(!owner.state.lock().unwrap().released.contains(&exact));
        assert!(owner.finish().is_err());
    }
    {
        let mut owner =
            QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
        let mut launcher = owner.lifecycle_guard()?;
        retain_child_and_refuse_member_finish(&mut launcher, &owner.state)?;
        assert!(!owner.state.lock().unwrap().lifecycle_launcher_finished);
        assert!(owner.finish().is_err());
    }
    {
        let mut owner =
            QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
        finish_primary_lifecycle(&mut owner, "node")?;
        let (_binding, mut factory) = bound_auxiliary_resources(&owner)?;
        let mut auxiliary = begin_auxiliary_resources(&mut factory, &owner)?;
        retain_child_and_refuse_member_finish(&mut auxiliary, &owner.state)?;
        assert!(owner.state.lock().unwrap().auxiliary_lifecycle_active);
        assert!(owner.finish().is_err());
    }
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 3);
    Ok(())
}

#[test]
fn successful_local_returns_remain_idempotent_after_aggregate_quarantine() -> TestResult {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner =
        QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 1)?;
    let exact = identity("target", 1)?;
    let mut target = owner.reserve_node(exact.clone())?;
    target.finish()?;
    target.finish()?;
    let mut launcher = owner.lifecycle_guard()?;
    launcher.finish()?;
    launcher.finish()?;
    let (_binding, mut factory) = bound_auxiliary_resources(&owner)?;
    let mut auxiliary = begin_auxiliary_resources(&mut factory, &owner)?;
    auxiliary.finish()?;
    auxiliary.finish()?;
    owner.quarantine();

    target.finish()?;
    launcher.finish()?;
    auxiliary.finish()?;

    let state = owner.state.lock().unwrap();
    assert_eq!(state.released.len(), 1);
    assert!(state.released.contains(&exact));
    assert!(state.lifecycle_launcher_finished);
    assert!(!state.auxiliary_lifecycle_active);
    drop(state);
    assert!(owner.finish().is_err());
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn direct_member_release_updates_only_exact_member_and_never_finishes_host() -> TestResult {
    let finishes = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let mut owner =
        QemuHotForkWorldResourceOwner::new(guard(finishes.clone(), quarantines.clone())?, 2)?;
    let exact = identity("first", 1)?;
    let sibling = identity("second", 1)?;
    let mut target = owner.reserve_node(exact.clone())?;
    let mut peer = owner.reserve_node(sibling.clone())?;

    target.finish_member()?;
    target.finish_member()?;

    let state = owner.state.lock().unwrap();
    assert!(state.released.contains(&exact));
    assert!(!state.released.contains(&sibling));
    assert_eq!(state.retirement, WorldResourceRetirement::Active);
    assert_eq!(finishes.load(Ordering::Acquire), 0);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    drop(state);
    peer.finish_member()?;
    owner.finish()?;
    assert_eq!(finishes.load(Ordering::Acquire), 1);
    assert_eq!(quarantines.load(Ordering::Acquire), 0);
    Ok(())
}
