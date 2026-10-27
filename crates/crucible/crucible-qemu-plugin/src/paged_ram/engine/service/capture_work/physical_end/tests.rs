//! Checks refusal-only scalar validation without a native or Source issuer.

// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn unchanged_output_never_consumes_cleanup_identity() {
    let mut custody = PhysicalEndCustody::new().unwrap();
    // This names test bookkeeping only; no native begin or end is simulated.
    custody.token = 73;
    custody.accept_snapshot(NativePhysicalEnd::initialized().unwrap());

    assert!(!custody.returned);
    assert!(custody.latest_valid.is_none());
}

#[test]
fn prior_geometry_and_foreign_identity_are_refused() {
    let mut output = NativePhysicalEnd::initialized().unwrap();
    output.token = 73;
    output.struct_size = 416;
    assert!(output.check(73).is_err());

    output.struct_size = u32::try_from(size_of::<NativePhysicalEnd>()).unwrap();
    assert!(output.check(74).is_err());
}

#[test]
fn unsupported_completion_and_unreturned_post_are_refused() {
    let mut output = NativePhysicalEnd::initialized().unwrap();
    output.token = 73;
    output.return_complete = 1;
    assert!(output.check(73).is_err());

    output.return_complete = 0;
    output.stage[4].post_returned = 1;
    assert!(output.check(73).is_err());

    output.stage[4].post_returned = 0;
    output.stage[4].post_complete = 1;
    assert!(output.check(73).is_err());
}

#[test]
fn malformed_receipt_retains_first_failure_without_return_authority() {
    let mut custody = PhysicalEndCustody::new().unwrap();
    custody.token = 73;
    let first = RamError::Io(Arc::new(io::Error::from_raw_os_error(libc::EIO)));
    custody.retain_failure(first.clone());
    let mut output = NativePhysicalEnd::initialized().unwrap();
    output.token = 74;

    custody.accept_snapshot(output);

    assert_eq!(custody.first_failure, Some(first));
    assert!(!custody.returned);
    assert!(custody.latest_valid.is_none());
}

#[test]
fn unproved_physical_return_cannot_reopen_scratch_or_refund_pending_body() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    let body = owner.body.as_ref().unwrap();
    // Pending cleanup and a borrowed gate issue no physical success receipt.
    body.end_pending.store(true, Ordering::Release);
    body.placement.store(true, Ordering::Release);
    body.scratch_returned.store(true, Ordering::Release);

    assert!(owner.return_gate_after_end(73).is_err());
    assert!(body.placement.load(Ordering::Acquire));
    assert!(owner.require_end_ready().is_err());
    assert!(owner.check_settled().is_err());
    drop(owner);

    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn scalar_layout_matches_the_frozen_sdk_geometry() {
    assert_eq!(size_of::<NativeReleaseStep>(), 56);
    assert_eq!(size_of::<NativePhysicalEnd>(), 472);
    assert_eq!(std::mem::offset_of!(NativeReleaseStep, post_status), 20);
    assert_eq!(std::mem::offset_of!(NativeReleaseStep, post_entered), 36);
    assert_eq!(std::mem::offset_of!(NativeReleaseStep, uncertain), 52);
    assert_eq!(std::mem::offset_of!(NativePhysicalEnd, token), 8);
    assert_eq!(std::mem::offset_of!(NativePhysicalEnd, return_complete), 76);
    assert_eq!(std::mem::offset_of!(NativePhysicalEnd, stage), 80);
}

#[test]
fn active_observer_history_blocks_reuse_fork_and_metadata_return() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    // An active callback/post is pending custody, not a physical-return issuer.
    owner
        .body
        .as_ref()
        .unwrap()
        .end
        .lock()
        .unwrap()
        .observation_running = true;

    assert!(owner.require_end_ready().is_err());
    assert!(owner.check_settled().is_err());
    drop(owner);

    assert_eq!(budget.used_bytes(), extent);
}

struct RefusingCleanup {
    checks: std::sync::atomic::AtomicUsize,
    completions: std::sync::atomic::AtomicUsize,
}

impl SourceOperation for RefusingCleanup {
    fn wait_slice(&self) -> io::Result<std::time::Duration> {
        let error = if self.checks.fetch_add(1, Ordering::SeqCst) == 0 {
            libc::EIO
        } else {
            libc::ETIMEDOUT
        };
        Err(io::Error::from_raw_os_error(error))
    }

    fn complete(&self) -> io::Result<()> {
        self.completions.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::from_raw_os_error(libc::ECANCELED))
    }

    fn wait_slice_for_observation(
        &self,
    ) -> Result<std::time::Duration, crate::paged_ram::source::ObservationOperationError> {
        self.wait_slice().map_err(Into::into)
    }

    fn complete_observation(
        &self,
    ) -> Result<(), crate::paged_ram::source::ObservationOperationError> {
        self.complete().map_err(Into::into)
    }
}

#[test]
fn refusing_owned_pre_still_saves_independent_post_without_native_or_completion() {
    let operation = RefusingCleanup {
        checks: std::sync::atomic::AtomicUsize::new(0),
        completions: std::sync::atomic::AtomicUsize::new(0),
    };
    let native_calls = std::sync::atomic::AtomicUsize::new(0);
    let mut custody = PhysicalEndCustody::new().unwrap();
    custody.observation_running = true;

    let attempt = run_owned_observation(&operation, || {
        native_calls.fetch_add(1, Ordering::SeqCst);
        Err(RamError::Invariant(
            "refused pre must not dispatch native work",
        ))
    });
    let first = attempt.pre.clone().unwrap_err();
    assert!(attempt.dispatch.is_none());
    custody.save_observation_attempt(attempt);

    assert!(matches!(&first, RamError::Io(error) if error.raw_os_error() == Some(libc::EIO)));
    assert_eq!(custody.first_failure, Some(first));
    assert!(
        matches!(&custody.observation_post, Some(Err(RamError::Io(error))) if error.raw_os_error() == Some(libc::ETIMEDOUT))
    );
    assert_eq!(operation.checks.load(Ordering::SeqCst), 2);
    assert_eq!(operation.completions.load(Ordering::SeqCst), 0);
    assert_eq!(native_calls.load(Ordering::SeqCst), 0);
    assert!(!custody.observation_runner_entered);
    assert!(!custody.observation_callback_entered);
    assert!(!custody.observation_running);
    assert!(!custody.returned);
}

#[test]
fn actual_birth_slot_and_cleanup_admission_exclude_each_other_before_effects() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    let birth = owner.prepare_physical_birth().unwrap();

    assert!(owner.admit_physical_cleanup().is_err());
    drop(birth);
    let cleanup = owner.admit_physical_cleanup().unwrap();
    assert!(cleanup.token.is_none());
    assert!(owner.prepare_physical_birth().is_err());
    assert!(owner.check_settled().is_err());

    // No native birth occurred. Abandoned cleanup still retains its real
    // admission/body, with no zero-token bypass or invented return receipt.
    drop(cleanup);
    assert!(owner.require_end_ready().is_err());
    drop(owner);

    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn actual_join_pre_refusal_keeps_first_and_independent_post_without_retirement() {
    let worker = Mutex::new(None);
    let operation = RefusingCleanup {
        checks: std::sync::atomic::AtomicUsize::new(0),
        completions: std::sync::atomic::AtomicUsize::new(0),
    };

    let joined =
        super::super::super::join_stopped_worker(&worker, &operation, None, |_| {}, |_| {});

    let first = joined.pre.as_ref().unwrap().as_ref().unwrap_err();
    assert!(matches!(first, RamError::Io(error) if error.raw_os_error() == Some(libc::EIO)));
    assert_eq!(joined.result.as_ref().unwrap_err(), first);
    assert!(
        matches!(&joined.post, Some(Err(RamError::Io(error))) if error.raw_os_error() == Some(libc::ETIMEDOUT))
    );
    assert!(!joined.physical_returned);
    assert!(joined.join.is_none());
    assert_eq!(operation.checks.load(Ordering::SeqCst), 2);
    assert_eq!(operation.completions.load(Ordering::SeqCst), 0);
    assert!(worker.lock().unwrap().is_none());
}

#[test]
fn actual_join_slot_refusal_still_posts_owned_original_and_keeps_slot_first() {
    let worker = Mutex::new(None);
    let held = worker.lock().unwrap();
    let operation = RefusingCleanup {
        checks: std::sync::atomic::AtomicUsize::new(0),
        completions: std::sync::atomic::AtomicUsize::new(0),
    };

    let joined =
        super::super::super::join_stopped_worker(&worker, &operation, None, |_| {}, |_| {});

    assert_eq!(
        joined.result.unwrap_err(),
        RamError::Invariant("paging worker owner unavailable")
    );
    assert!(joined.pre.is_none());
    assert!(
        matches!(&joined.post, Some(Err(RamError::Io(error))) if error.raw_os_error() == Some(libc::EIO))
    );
    assert!(!joined.physical_returned);
    assert!(joined.join.is_none());
    assert_eq!(operation.checks.load(Ordering::SeqCst), 1);
    assert_eq!(operation.completions.load(Ordering::SeqCst), 0);
    drop(held);
}

#[test]
fn cleanup_cannot_borrow_end_journal_from_an_entered_action_awaiting_end() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    let action = owner.admit_physical_action().unwrap();

    assert!(owner.admit_physical_cleanup().is_err());
    // Cleanup refused before even trying the actual end journal. The active
    // action can still acquire that real mutex; no native birth is fabricated.
    let end = owner.body.as_ref().unwrap().end.try_lock().unwrap();
    drop(end);
    action.finish().unwrap();

    let cleanup = owner.admit_physical_cleanup().unwrap();
    assert!(cleanup.token.is_none());
    assert!(owner.admit_physical_action().is_err());
    drop(cleanup);
    assert!(owner.admit_physical_action().is_err());
    drop(owner);

    assert_eq!(budget.used_bytes(), extent);
}
