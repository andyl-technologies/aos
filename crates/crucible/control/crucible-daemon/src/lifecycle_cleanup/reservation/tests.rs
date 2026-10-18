//! Exercises exact-cell isolation and real file destruction without Main issuance.

use super::*;
use crate::{
    ProductionVmExactNodeRestoreAdmission, ProductionVmNodeLaunch, ProductionVmNodeLaunchRequest,
    ProductionVmNodeLauncher,
};
use std::fs::{self, File};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize};

struct FileOwner {
    _file: File,
    slot: Weak<CleanupSlot>,
    attempts: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    drop_outside_lock: Arc<AtomicBool>,
    refuse_once: bool,
}

impl crucible_control_api::ProductionVmCleanupOwner for FileOwner {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        // This component launcher owns no native World or Service return.
        Ok(None)
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}

impl ProductionVmNodeLauncher for FileOwner {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Err(refusal("component owns no execution authority"))
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Err(refusal("component owns no execution authority"))
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu: &Path,
        _image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(refusal("component owns no process authority"))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(refusal("component owns no restore authority"))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(refusal("component owns no replay authority"))
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if std::mem::take(&mut self.refuse_once) {
            return Err((refusal("first file cleanup refusal")).into());
        }
        Ok(())
    }
}

impl Drop for FileOwner {
    fn drop(&mut self) {
        let outside = self
            .slot
            .upgrade()
            .is_some_and(|slot| slot.cell.try_lock().is_ok());
        self.drop_outside_lock.store(outside, Ordering::Release);
        self.dropped.store(true, Ordering::Release);
    }
}

mod file_cell;
use file_cell::{begin_file_epoch, dispose_file_receipt, retry_file_cell};

struct CellFixture {
    descriptor: RawFd,
    identity: (u64, u64),
    slot: Arc<CleanupSlot>,
    attempts: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    drop_outside_lock: Arc<AtomicBool>,
}

fn fixture(epoch: u64, refuse_once: bool) -> Result<CellFixture, std::io::Error> {
    let slot = Arc::new(CleanupSlot::unissued_for_test(epoch, CleanupPhase::Queued));
    let attempts = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let drop_outside_lock = Arc::new(AtomicBool::new(false));
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    let owner = FileOwner {
        _file: file,
        slot: Arc::downgrade(&slot),
        attempts: Arc::clone(&attempts),
        dropped: Arc::clone(&dropped),
        drop_outside_lock: Arc::clone(&drop_outside_lock),
        refuse_once,
    };
    {
        let mut cell = slot.cell.lock().unwrap();
        cell.owner = Some(Box::new(owner));
        cell.handoff = true;
    }
    Ok(CellFixture {
        descriptor,
        identity,
        slot,
        attempts,
        dropped,
        drop_outside_lock,
    })
}

fn receipt(epoch: u64) -> CleanupReservation {
    // No genuine Main/queue is constructed. The tests below call the actual
    // cell primitive directly; all process and execution entrypoints refuse.
    CleanupReservation {
        report_reference: false,
        queue: Weak::new(),
        index: 0,
        epoch,
        observed: ProductionVmCleanupStage::BodyRetained,
        first_failure: None,
        terminal_history: None,
    }
}

#[test]
fn unavailable_world_bundle_returns_the_same_reservation_box() {
    let reservation = LifecycleCleanupHandle::unavailable_reservation_for_test();
    let original = std::ptr::from_ref(reservation.as_ref()).cast::<()>();
    let bundle = WorldLifecycleCleanupReservation {
        reservation,
        cell: ReservedWorldCell {
            queue: Weak::new(),
            index: 0,
            epoch: 7,
        },
    };

    let selection = bundle.service_preclaim();
    assert_eq!(selection.index, 0);
    assert_eq!(selection.epoch, 7);
    assert!(selection.containing_queue().is_err());
    assert!(!bundle.is_reserved());
    let reservation = bundle.into_reservation();

    assert_eq!(
        std::ptr::from_ref(reservation.as_ref()).cast::<()>(),
        original
    );
}

#[test]
fn reserved_cell_observation_preserves_real_custody_on_every_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(7, false)?;
    let owner = {
        let mut cell = selected.slot.cell.lock().unwrap();
        cell.handoff = false;
        cell.owner.take().unwrap()
    };
    selected.slot.publish(CleanupPhase::Reserved);
    // This exercises only row observation, without a Main or World lease.
    // Full bundle validation additionally requires its genuine queue/controls.
    assert!(
        borrow_reserved_cell(&selected.slot, 7)
            .unwrap()
            .controls
            .is_none()
    );
    assert!(borrow_reserved_cell(&selected.slot, 8).is_none());

    for phase in [
        CleanupPhase::Publishing,
        CleanupPhase::Queued,
        CleanupPhase::Closed,
    ] {
        selected.slot.publish(phase);
        assert!(borrow_reserved_cell(&selected.slot, 7).is_none());
    }
    selected.slot.publish(CleanupPhase::Reserved);
    {
        let mut cell = selected.slot.cell.lock().unwrap();
        assert!(borrow_reserved_cell(&selected.slot, 7).is_none());
        cell.handoff = true;
    }
    assert!(borrow_reserved_cell(&selected.slot, 7).is_none());
    selected.slot.cell.lock().unwrap().handoff = false;
    selected.slot.cell.lock().unwrap().owner = Some(owner);
    assert!(borrow_reserved_cell(&selected.slot, 7).is_none());
    let owner = selected.slot.cell.lock().unwrap().owner.take().unwrap();

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _cell = selected.slot.cell.lock().unwrap();
        panic!("component control poisons the retained cell");
    }));
    assert!(poisoned.is_err());
    assert!(borrow_reserved_cell(&selected.slot, 7).is_none());
    let poisoned_cell = match selected.slot.cell.lock() {
        Err(poison) => poison.into_inner(),
        Ok(_) => panic!("the actual cell must remain poisoned"),
    };
    assert_eq!(poisoned_cell.epoch, 7);
    assert!(poisoned_cell.owner.is_none());
    assert!(!poisoned_cell.handoff);
    drop(poisoned_cell);

    let retained = fs::metadata(format!("/proc/self/fd/{}", selected.descriptor))?;
    assert_eq!((retained.dev(), retained.ino()), selected.identity);
    assert_eq!(selected.attempts.load(Ordering::Acquire), 0);
    assert!(!selected.dropped.load(Ordering::Acquire));
    drop(owner);
    assert!(selected.dropped.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn exact_retry_preserves_siblings_and_history_until_receipt_observes_close()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(7, true)?;
    let sibling = fixture(12, false)?;
    let mut handoff = receipt(7);

    assert!(retry_file_cell(&selected.slot, Some(7)).is_err());
    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::BodyRetained
    );
    assert!(!selected.dropped.load(Ordering::Acquire));
    let retained = fs::metadata(format!("/proc/self/fd/{}", selected.descriptor))?;
    assert_eq!((retained.dev(), retained.ino()), selected.identity);
    assert_eq!(sibling.attempts.load(Ordering::Acquire), 0);

    retry_file_cell(&selected.slot, Some(7))?;
    assert!(selected.dropped.load(Ordering::Acquire));
    assert!(selected.drop_outside_lock.load(Ordering::Acquire));
    assert!(
        fs::metadata(format!("/proc/self/fd/{}", selected.descriptor)).map_or(true, |current| (
            current.dev(),
            current.ino()
        )
            != selected.identity)
    );
    assert!(selected.slot.is(CleanupPhase::Closed));
    assert!(
        !selected
            .slot
            .claim(CleanupPhase::Free, CleanupPhase::Reserving)
    );
    assert!(selected.slot.cell.lock().unwrap().first_failure.is_some());

    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::Complete
    );
    assert!(
        handoff
            .first_failure()
            .unwrap()
            .to_string()
            .contains("first file cleanup refusal")
    );
    dispose_file_receipt(&mut handoff, &selected.slot)?;
    assert!(selected.slot.is(CleanupPhase::Free));
    assert_eq!(selected.slot.completed_epoch.load(Ordering::Acquire), 7);
    assert_eq!(sibling.attempts.load(Ordering::Acquire), 0);
    assert!(!sibling.dropped.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn stale_receipt_cannot_run_another_epoch() -> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(8, false)?;

    assert!(retry_slot(&selected.slot, Some(7)).is_err());

    assert!(selected.slot.is(CleanupPhase::Queued));
    assert_eq!(selected.attempts.load(Ordering::Acquire), 0);
    assert!(!selected.dropped.load(Ordering::Acquire));
    assert!(selected.slot.cell.lock().unwrap().first_failure.is_none());
    Ok(())
}

#[test]
fn actual_file_closure_cannot_authorize_a_native_return_without_its_role()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(19, false)?;

    assert!(retry_slot(&selected.slot, Some(19)).is_err());

    assert!(selected.dropped.load(Ordering::Acquire));
    assert!(selected.drop_outside_lock.load(Ordering::Acquire));
    assert!(selected.slot.is(CleanupPhase::DestructionRefused));
    assert_eq!(
        selected.slot.body_destroyed_epoch.load(Ordering::Acquire),
        19
    );
    assert_eq!(
        selected.slot.worlds_returned_epoch.load(Ordering::Acquire),
        0
    );
    assert_eq!(selected.slot.completed_epoch.load(Ordering::Acquire), 0);
    assert!(
        !selected
            .slot
            .claim(CleanupPhase::Free, CleanupPhase::Reserving)
    );
    Ok(())
}

#[test]
fn completed_receipt_never_drives_reused_cell() -> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(7, false)?;
    let mut handoff = receipt(7);
    retry_file_cell(&selected.slot, Some(7))?;
    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::Complete
    );

    dispose_file_receipt(&mut handoff, &selected.slot)?;

    let next = fixture(8, false)?;
    assert_eq!(
        handoff.observe_slot(&next.slot)?,
        ProductionVmCleanupStage::Complete
    );
    assert_eq!(handoff.retry()?, ProductionVmCleanupStage::Complete);

    assert_eq!(next.attempts.load(Ordering::Acquire), 0);
    assert!(!next.dropped.load(Ordering::Acquire));
    assert!(next.slot.is(CleanupPhase::Queued));
    Ok(())
}

#[test]
fn one_cell_reuses_actual_reservation_and_owner_for_twenty_four_epochs()
-> Result<(), Box<dyn std::error::Error>> {
    // Reuses the real publication and body/control primitives in one file-only
    // cell. This fixture does not issue a Main role or a native return proof.
    let slot = Arc::new(CleanupSlot::unissued_for_test(0, CleanupPhase::Free));

    for expected_epoch in 1..=24 {
        assert!(slot.claim(CleanupPhase::Free, CleanupPhase::Reserving));
        let epoch = begin_file_epoch(&slot)?;
        assert_eq!(epoch, expected_epoch);
        // Allocate the same real token type before the containing file owner.
        let token = Box::new(receipt(epoch));
        let attempts = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let outside_lock = Arc::new(AtomicBool::new(false));
        let file = tempfile::tempfile()?;
        let descriptor = file.as_raw_fd();
        let identity = file.metadata()?;
        let refuse_once = epoch % 3 == 0;
        let owner = FileOwner {
            _file: file,
            slot: Arc::downgrade(&slot),
            attempts: Arc::clone(&attempts),
            dropped: Arc::clone(&dropped),
            drop_outside_lock: Arc::clone(&outside_lock),
            refuse_once,
        };
        let mut handoff = match token.publish_owner(&slot, Box::new(owner)) {
            Ok(handoff) => handoff,
            Err(_) => panic!("the exact unused reservation must accept its file owner"),
        };
        assert!(handoff.report_reference);
        assert_eq!(slot.report_references.load(Ordering::Acquire), 1);
        assert_eq!(
            handoff.observe_slot(&slot)?,
            ProductionVmCleanupStage::BodyRetained
        );

        if refuse_once {
            assert!(retry_file_cell(&slot, Some(epoch)).is_err());
            assert!(!dropped.load(Ordering::Acquire));
            let retained = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
            assert_eq!(
                (retained.dev(), retained.ino()),
                (identity.dev(), identity.ino())
            );
        }
        retry_file_cell(&slot, Some(epoch))?;
        assert!(dropped.load(Ordering::Acquire));
        assert!(outside_lock.load(Ordering::Acquire));
        assert_eq!(
            attempts.load(Ordering::Acquire),
            if refuse_once { 2 } else { 1 }
        );
        assert!(slot.is(CleanupPhase::Closed));
        assert!(!slot.claim(CleanupPhase::Free, CleanupPhase::Reserving));
        assert!(
            fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |current| {
                (current.dev(), current.ino()) != (identity.dev(), identity.ino())
            })
        );

        assert_eq!(
            handoff.observe_slot(&slot)?,
            ProductionVmCleanupStage::Complete
        );
        let historical = handoff.first_failure.take();
        assert_eq!(historical.is_some(), refuse_once);
        assert!(handoff.first_failure().is_none());
        drop(historical);
        dispose_file_receipt(&mut handoff, &slot)?;
        assert!(!handoff.report_reference);
        assert_eq!(slot.report_references.load(Ordering::Acquire), 0);
        assert_eq!(handoff.retry()?, ProductionVmCleanupStage::Complete);
        assert_eq!(slot.completed_epoch.load(Ordering::Acquire), epoch);
        // The completed token leaves before the same one-cell capacity issues
        // another token. No second receipt or queue slot accumulates.
        drop(handoff);
        assert!(slot.is(CleanupPhase::Free));
    }
    Ok(())
}

struct FileWorker {
    _file: File,
    dropped: Arc<AtomicBool>,
}

impl crate::LocalAttemptWorker for FileWorker {
    type Error = crucible_host_resources::host_supervision::HostSupervisionError;

    fn execute(&mut self, _: crate::QueuedAttempt) -> crate::AttemptWorkResult<Self::Error> {
        panic!("unissued file custody does not execute a campaign");
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        original.wait_slice().map(|_| ())
    }
}

impl Drop for FileWorker {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn actual_closed_worker_and_file_stay_closed_after_same_original_expires()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::campaign_process::{ExecutorWorkerRetirementError, retire_control_bodies};
    use crucible_host_resources::host_supervision::{
        HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationState,
        HostOperationSupervisor, HostSupervisionError,
    };
    use std::cell::RefCell;
    use std::time::Duration;

    let file = tempfile::tempfile()?;
    let worker_fd = file.as_raw_fd();
    let metadata = file.metadata()?;
    let worker_identity = (metadata.dev(), metadata.ino());
    let worker_dropped = Arc::new(AtomicBool::new(false));
    let workers = crate::executor_pool::PreparedExecutorWorkers::unissued_component_custody(vec![
        FileWorker {
            _file: file,
            dropped: worker_dropped.clone(),
        },
    ]);
    let selected = fixture(71, true)?;
    let handoff = RefCell::new(receipt(71));
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;

    let result = retire_control_bodies(
        &original,
        || {
            workers
                .try_retire_original(&original)
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            let work = retry_file_cell(&selected.slot, Some(71));
            let stage = handoff.borrow_mut().observe_slot(&selected.slot)?;
            if stage == ProductionVmCleanupStage::Complete {
                let historical = handoff.borrow_mut().first_failure.take();
                dispose_file_receipt(&mut handoff.borrow_mut(), &selected.slot)?;
                // Tighten the SAME actual operation only after both real file
                // owners closed. This changes policy without renewing its clock.
                let (revision, mut budgets) = supervisor
                    .budgets()
                    .map_err(|_| refusal("component policy observation"))?;
                budgets.classes[HostOperationClass::Cleanup as usize] =
                    HostOperationBudget::finite(Duration::from_nanos(1));
                supervisor
                    .update_budgets(revision, budgets)
                    .map_err(|_| refusal("component policy tightening"))?;
                // Return its real historical cause after physical closure,
                // reproducing work.and(empty) without fabricating an owner.
                if let Some(first) = historical {
                    return Err(LifecycleApiError::LoopFactory {
                        message: first.to_string(),
                    });
                }
            }
            work
        },
        || {
            workers
                .verify_retired()
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            if selected.slot.is(CleanupPhase::Free) {
                Ok(())
            } else {
                Err(refusal("actual component cell remains occupied"))
            }
        },
    );
    let report = result.expect_err("expired Original remains an operational refusal");

    assert!(worker_dropped.load(Ordering::Acquire));
    assert!(selected.dropped.load(Ordering::Acquire));
    assert!(selected.drop_outside_lock.load(Ordering::Acquire));
    assert!(workers.verify_retired().is_ok());
    assert!(selected.slot.is(CleanupPhase::Free));
    for (fd, identity) in [
        (worker_fd, worker_identity),
        (selected.descriptor, selected.identity),
    ] {
        assert!(
            fs::metadata(format!("/proc/self/fd/{fd}"))
                .map_or(true, |current| (current.dev(), current.ino()) != identity)
        );
    }
    assert!(report.physically_closed());
    assert!(matches!(
        report.original_post(),
        Some(HostSupervisionError::DeadlineExpired { .. })
            | Some(HostSupervisionError::Terminal {
                state: HostOperationState::Expired
            })
    ));
    assert!(
        original.wait_slice().is_err(),
        "physical closure supplies no authority for the next effect"
    );
    assert_eq!(selected.attempts.load(Ordering::Acquire), 2);
    Ok(())
}

// Dispatcher controls use only the same local Original and real file/cell
// primitives. No Main or native dispatcher admission is constructed.
fn expire_component_cleanup(
    supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
) {
    use crucible_host_resources::host_supervision::{HostOperationBudget, HostOperationClass};
    let (revision, mut budgets) = supervisor.budgets().unwrap();
    budgets.classes[HostOperationClass::Cleanup as usize] =
        HostOperationBudget::finite(std::time::Duration::from_nanos(1));
    supervisor.update_budgets(revision, budgets).unwrap();
    assert!(original.wait_slice().is_err());
}

fn loop_failure_message(error: &LifecycleApiError) -> &str {
    match error {
        LifecycleApiError::LoopFactory { message } => message,
        other => panic!("unexpected component cleanup report: {other:?}"),
    }
}

#[test]
fn typed_retirement_view_keeps_the_first_phase_across_later_history()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::packaged_qemu_executor::retirement::{
        AttachedRetirementReport, PackagedQemuExecutorRetirementError,
        PackagedQemuExecutorRetirementFailure,
    };
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let report = PackagedQemuExecutorRetirementError::new();
    assert!(report.first_failure().is_none());
    expire_component_cleanup(&supervisor, &original);
    let post = original.wait_slice().unwrap_err();

    report.retain(AttachedRetirementReport::from_post(post));
    let Some(PackagedQemuExecutorRetirementFailure::Post(first)) = report.first_failure() else {
        panic!("the original post remains typed");
    };
    assert_eq!(*first, post);
    let later = LifecycleApiError::LoopFactory {
        message: String::from("later component cleanup history"),
    };
    let later_message = loop_failure_message(&later).as_ptr();
    report.retain(AttachedRetirementReport::new(
        None, None, None, Some(later), Default::default(),
    ));

    let Some(PackagedQemuExecutorRetirementFailure::Post(retained)) = report.first_failure() else {
        panic!("later history cannot replace the first phase");
    };
    assert!(std::ptr::eq(first, retained));
    assert_eq!(report.original_post(), Some(post));
    assert_eq!(
        loop_failure_message(report.lifecycle().unwrap()).as_ptr(),
        later_message
    );
    Ok(())
}

#[test]
fn actual_cell_failure_survives_same_original_refusal_before_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::packaged_qemu_executor::retirement::{
        AttachedRetirementReport, PackagedQemuExecutorRetirementError, retire_dispatcher,
    };
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let selected = fixture(91, true)?;
    let first = retry_slot(&selected.slot, Some(91)).unwrap_err();
    let first_message = loop_failure_message(&first).as_ptr();
    let mut dispatcher_file = Some(tempfile::tempfile()?);
    let descriptor = dispatcher_file.as_ref().unwrap().as_raw_fd();
    let identity = dispatcher_file.as_ref().unwrap().metadata()?;
    let mut physically_closed = false;
    let mut attempts = 0;
    expire_component_cleanup(&supervisor, &original);

    let dispatch = retire_dispatcher(&original, true, &mut physically_closed, || {
        attempts += 1;
        drop(dispatcher_file.take());
        (Ok(()), dispatcher_file.is_none())
    });
    let report = PackagedQemuExecutorRetirementError::new();
    report.retain(AttachedRetirementReport::new(
        None,
        None,
        None,
        Some(first),
        dispatch,
    ));

    assert_eq!(attempts, 0);
    assert!(!physically_closed);
    assert_eq!(
        loop_failure_message(report.lifecycle().unwrap()).as_ptr(),
        first_message
    );
    assert!(report.before_dispatch().is_some());
    assert!(report.original_post().is_some());
    assert!(report.dispatcher().is_none());
    assert!(!selected.dropped.load(Ordering::Acquire));
    assert_eq!(selected.attempts.load(Ordering::Acquire), 1);
    let retained = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!(
        (retained.dev(), retained.ino()),
        (identity.dev(), identity.ino())
    );
    Ok(())
}

#[test]
fn dispatcher_refusal_and_independent_post_preserve_actual_cell_history()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::packaged_qemu_executor::retirement::{
        AttachedRetirementReport, PackagedQemuExecutorRetirementError, retire_dispatcher,
    };
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let selected = fixture(92, true)?;
    let first = retry_file_cell(&selected.slot, Some(92)).unwrap_err();
    let first_message = loop_failure_message(&first).as_ptr();
    retry_file_cell(&selected.slot, Some(92))?;
    let mut handoff = receipt(92);
    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::Complete
    );
    assert!(handoff.first_failure().is_some());
    let mut dispatcher_file = Some(tempfile::tempfile()?);
    let mut physically_closed = false;
    let mut attempts = 0;

    let report = PackagedQemuExecutorRetirementError::new();
    report.retain(AttachedRetirementReport::new(
        None,
        None,
        None,
        Some(first),
        Default::default(),
    ));
    let dispatch = retire_dispatcher(&original, true, &mut physically_closed, || {
        attempts += 1;
        drop(dispatcher_file.take());
        expire_component_cleanup(&supervisor, &original);
        // The local file is actually gone despite this historical component
        // refusal. This observes no native dispatcher or other resource.
        (
            Err(crucible_qemu_host::QemuVmRealizationError::Canceled {
                operation: "component dispatcher refusal",
            }),
            dispatcher_file.is_none(),
        )
    });
    // A later phase augments the same inline history, rather than replacing
    // the earlier real cleanup cause with a whole-attempt snapshot.
    report.retain(AttachedRetirementReport::new(
        None, None, None, None, dispatch,
    ));

    assert_eq!(attempts, 1);
    assert!(physically_closed);
    assert_eq!(
        loop_failure_message(report.lifecycle().unwrap()).as_ptr(),
        first_message
    );
    assert!(report.before_dispatch().is_none());
    assert!(matches!(
        report.dispatcher(),
        Some(crucible_qemu_host::QemuVmRealizationError::Canceled {
            operation: "component dispatcher refusal"
        })
    ));
    assert!(report.original_post().is_some());
    let Some(crate::PackagedQemuExecutorRetirementFailure::Lifecycle(first)) = report.first_failure()
    else {
        panic!("the original lifecycle cause remains selected");
    };
    assert!(std::ptr::eq(first, report.lifecycle().unwrap()));
    assert!(selected.dropped.load(Ordering::Acquire));
    dispose_file_receipt(&mut handoff, &selected.slot)?;
    assert!(selected.slot.is(CleanupPhase::Free));
    let repeated = retire_dispatcher(&original, true, &mut physically_closed, || {
        panic!("physical closure beside a historical error must not replay")
    });
    assert!(repeated.post.is_some());
    assert!(physically_closed);
    Ok(())
}

#[test]
fn successful_file_retirement_latches_before_post_without_erasing_history()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::packaged_qemu_executor::retirement::{
        AttachedRetirementReport, PackagedQemuExecutorRetirementError, retire_dispatcher,
    };
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let selected = fixture(93, true)?;
    let first = retry_file_cell(&selected.slot, Some(93)).unwrap_err();
    let first_message = loop_failure_message(&first).as_ptr();
    retry_file_cell(&selected.slot, Some(93))?;
    let mut handoff = receipt(93);
    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::Complete
    );
    let mut dispatcher_file = Some(tempfile::tempfile()?);
    let descriptor = dispatcher_file.as_ref().unwrap().as_raw_fd();
    let identity = dispatcher_file.as_ref().unwrap().metadata()?;
    let mut physically_closed = false;

    let dispatch = retire_dispatcher(&original, true, &mut physically_closed, || {
        drop(dispatcher_file.take());
        expire_component_cleanup(&supervisor, &original);
        (Ok(()), dispatcher_file.is_none())
    });
    let report = PackagedQemuExecutorRetirementError::new();
    report.retain(AttachedRetirementReport::new(
        None,
        None,
        None,
        Some(first),
        dispatch,
    ));

    assert!(physically_closed);
    assert_eq!(
        loop_failure_message(report.lifecycle().unwrap()).as_ptr(),
        first_message
    );
    assert!(report.before_dispatch().is_none());
    assert!(report.dispatcher().is_none());
    assert!(report.original_post().is_some());
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |current| (
            current.dev(),
            current.ino()
        ) != (
            identity.dev(),
            identity.ino()
        ))
    );
    dispose_file_receipt(&mut handoff, &selected.slot)?;
    assert!(selected.slot.is(CleanupPhase::Free));
    // A later observation cannot replay a completed effect, even after expiry.
    let repeated = retire_dispatcher(&original, true, &mut physically_closed, || {
        panic!("closed physical effect must not replay")
    });
    assert!(repeated.post.is_some());
    assert!(physically_closed);
    Ok(())
}

#[test]
fn successful_dispatch_without_actual_file_return_does_not_latch_closure()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::packaged_qemu_executor::retirement::retire_dispatcher;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let mut dispatcher_file = Some(tempfile::tempfile()?);
    let mut physically_closed = false;
    let mut attempts = 0;

    let incomplete = retire_dispatcher(&original, true, &mut physically_closed, || {
        attempts += 1;
        (Ok(()), dispatcher_file.is_none())
    });

    assert!(!physically_closed);
    assert!(dispatcher_file.is_some());
    assert!(incomplete.failure.is_none());
    assert!(incomplete.post.is_none());
    assert_eq!(attempts, 1);

    let complete = retire_dispatcher(&original, true, &mut physically_closed, || {
        attempts += 1;
        drop(dispatcher_file.take());
        (Ok(()), dispatcher_file.is_none())
    });

    assert!(physically_closed);
    assert!(dispatcher_file.is_none());
    assert!(complete.failure.is_none());
    assert!(complete.post.is_none());
    assert_eq!(attempts, 2);
    Ok(())
}

#[derive(Clone, Copy)]
enum ComponentPanicAt {
    Cleanup,
    PostBody,
}

struct ComponentPanicOwner {
    file: Option<File>,
    attempts: Arc<AtomicUsize>,
    at: ComponentPanicAt,
}

impl ProductionVmCleanupOwner for ComponentPanicOwner {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if matches!(self.at, ComponentPanicAt::Cleanup) {
            std::panic::panic_any(self.file.take().unwrap());
        }
        Ok(())
    }

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if matches!(self.at, ComponentPanicAt::PostBody) {
            std::panic::panic_any(self.file.take().unwrap());
        }
        Ok(None)
    }
}

fn no_component_history(
    _owner: &(dyn std::any::Any + Send),
) -> Option<&(dyn std::error::Error + 'static)> {
    None
}

fn no_component_first(
    _owner: &(dyn std::any::Any + Send),
) -> Option<crate::LifecycleFailureRef<'_>> {
    None
}

#[test]
fn actual_prepared_panic_retains_its_file_and_does_not_repeat_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(41, false)?;
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut prepared = prepared_service::PreparedCell::installed(
        41,
        Box::new(ComponentPanicOwner {
            file: Some(file),
            attempts: Arc::clone(&attempts),
            at: ComponentPanicAt::Cleanup,
        }),
        prepared_service::PreparedSourceProjections {
            first: no_component_first,
            history: no_component_history,
            terminal_metadata_return: None,
        },
        prepared_driver::PreparedBodyOperations::for_owner::<ComponentPanicOwner>(),
    );

    assert!(prepared_driver::retry_body_in_place(&fixture.slot, &mut prepared).is_err());
    assert!(fixture.slot.is(CleanupPhase::DestructionRefused));
    assert!(!prepared.body_closed);
    let retained = prepared
        .panic_payload
        .as_ref()
        .unwrap()
        .downcast_ref::<File>()
        .unwrap();
    assert_eq!(retained.as_raw_fd(), descriptor);
    let retained_metadata = retained.metadata()?;
    assert_eq!((retained_metadata.dev(), retained_metadata.ino()), identity);

    assert!(prepared_driver::retry_body_in_place(&fixture.slot, &mut prepared).is_err());
    assert_eq!(attempts.load(Ordering::Acquire), 1);
    assert!(fixture.slot.body_destroyed_epoch.load(Ordering::Acquire) < 41);
    Ok(())
}

#[test]
fn actual_prepared_postbody_panic_keeps_payload_without_a_second_transfer()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(42, false)?;
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let attempts = Arc::new(AtomicUsize::new(0));
    *fixture.slot.prepared.lock().unwrap() = prepared_service::PreparedCell::installed(
        42,
        Box::new(ComponentPanicOwner {
            file: Some(file),
            attempts: Arc::clone(&attempts),
            at: ComponentPanicAt::PostBody,
        }),
        prepared_service::PreparedSourceProjections {
            first: no_component_first,
            history: no_component_history,
            terminal_metadata_return: None,
        },
        prepared_driver::PreparedBodyOperations::for_owner::<ComponentPanicOwner>(),
    );

    assert!(prepared_driver::retry_prepared(&fixture.slot, 42).is_err());
    {
        let prepared = fixture.slot.prepared.lock().unwrap();
        assert!(prepared.body_closed);
        assert!(!prepared.post_body_taken);
        let retained = prepared
            .panic_payload
            .as_ref()
            .unwrap()
            .downcast_ref::<File>()
            .unwrap();
        assert_eq!(retained.as_raw_fd(), descriptor);
        retained.metadata()?;
    }
    assert!(fixture.slot.is(CleanupPhase::DestructionRefused));

    assert!(prepared_driver::retry_prepared(&fixture.slot, 42).is_err());
    assert_eq!(attempts.load(Ordering::Acquire), 2);
    assert_eq!(
        fixture.slot.controls_closed_epoch.load(Ordering::Acquire),
        0
    );
    Ok(())
}

struct ComponentPanickingDrop {
    file: Option<File>,
    slot: Weak<CleanupSlot>,
    outside_control: Arc<AtomicBool>,
}

impl Drop for ComponentPanickingDrop {
    fn drop(&mut self) {
        self.outside_control.store(
            self.slot
                .upgrade()
                .is_some_and(|slot| slot.cell.try_lock().is_ok()),
            Ordering::Release,
        );
        std::panic::panic_any(self.file.take().unwrap());
    }
}

#[test]
fn actual_destructor_panic_keeps_file_outside_control_and_refuses_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(43, false)?;
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let outside_control = Arc::new(AtomicBool::new(false));
    fixture.slot.publish(CleanupPhase::Destroying);
    let payload = ComponentPanickingDrop {
        file: Some(file),
        slot: Arc::downgrade(&fixture.slot),
        outside_control: Arc::clone(&outside_control),
    };

    assert!(!terminal::destroy_payload(&fixture.slot, payload));
    assert!(outside_control.load(Ordering::Acquire));
    assert!(fixture.slot.is(CleanupPhase::DestructionRefused));
    let cell = fixture.slot.cell.lock().unwrap();
    let retained = cell
        .panic_payload
        .as_ref()
        .unwrap()
        .downcast_ref::<File>()
        .unwrap();
    assert_eq!(retained.as_raw_fd(), descriptor);
    retained.metadata()?;
    assert_eq!(fixture.slot.body_destroyed_epoch.load(Ordering::Acquire), 0);
    assert_eq!(fixture.slot.completed_epoch.load(Ordering::Acquire), 0);
    Ok(())
}

struct UnlockedQueuedOwner {
    file: Option<File>,
    slot: Weak<CleanupSlot>,
    callbacks: Arc<AtomicUsize>,
    unlocked_callbacks: Arc<AtomicUsize>,
    dropped_outside: Arc<AtomicBool>,
    panic_with_service_borrow: bool,
}

impl UnlockedQueuedOwner {
    fn inspect_locks(&self) {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
        let slot = self.slot.upgrade().unwrap();
        if slot.cell.try_lock().is_ok() && slot.service.try_lock().is_ok() {
            self.unlocked_callbacks.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl ProductionVmCleanupOwner for UnlockedQueuedOwner {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        self.inspect_locks();
        if self.panic_with_service_borrow {
            let slot = self.slot.upgrade().unwrap();
            let _service = slot.service.lock().unwrap();
            std::panic::panic_any(self.file.take().unwrap());
        }
        Ok(())
    }

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        self.inspect_locks();
        // This unissued file owner carries no native or Service obligation.
        Ok(None)
    }
}

impl Drop for UnlockedQueuedOwner {
    fn drop(&mut self) {
        let outside = self
            .slot
            .upgrade()
            .is_some_and(|slot| slot.cell.try_lock().is_ok() && slot.service.try_lock().is_ok());
        self.dropped_outside.store(outside, Ordering::Release);
    }
}

#[test]
fn queued_callbacks_and_actual_file_destruction_leave_publication_locks_available()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(51, false)?;
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    let callbacks = Arc::new(AtomicUsize::new(0));
    let unlocked = Arc::new(AtomicUsize::new(0));
    let dropped_outside = Arc::new(AtomicBool::new(false));
    let old = fixture
        .slot
        .cell
        .lock()
        .unwrap()
        .owner
        .replace(Box::new(UnlockedQueuedOwner {
            file: Some(file),
            slot: Arc::downgrade(&fixture.slot),
            callbacks: Arc::clone(&callbacks),
            unlocked_callbacks: Arc::clone(&unlocked),
            dropped_outside: Arc::clone(&dropped_outside),
            panic_with_service_borrow: false,
        }));
    drop(old);

    // The component has no genuine native tail: only actual body destruction
    // can complete here, and the whole role must remain pending.
    assert!(retry_slot(&fixture.slot, Some(51)).is_err());
    assert_eq!(callbacks.load(Ordering::Acquire), 2);
    assert_eq!(unlocked.load(Ordering::Acquire), 2);
    assert!(dropped_outside.load(Ordering::Acquire));
    assert_eq!(
        fixture.slot.body_destroyed_epoch.load(Ordering::Acquire),
        51
    );
    assert_eq!(fixture.slot.completed_epoch.load(Ordering::Acquire), 0);
    assert!(!fixture.slot.is(CleanupPhase::Free));
    {
        let service = fixture.slot.service.lock().unwrap();
        assert!(service.queued_owner.is_none());
        assert!(!service.queued_owner_borrowed);
    }
    if let Ok(metadata) = fs::metadata(format!("/proc/self/fd/{descriptor}")) {
        assert_ne!((metadata.dev(), metadata.ino()), identity);
    }
    Ok(())
}

#[test]
fn queued_unwind_restores_the_same_box_and_retains_its_file_panic_without_reentry()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(52, false)?;
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let callbacks = Arc::new(AtomicUsize::new(0));
    let unlocked = Arc::new(AtomicUsize::new(0));
    let dropped_outside = Arc::new(AtomicBool::new(false));
    let old = fixture
        .slot
        .cell
        .lock()
        .unwrap()
        .owner
        .replace(Box::new(UnlockedQueuedOwner {
            file: Some(file),
            slot: Arc::downgrade(&fixture.slot),
            callbacks: Arc::clone(&callbacks),
            unlocked_callbacks: Arc::clone(&unlocked),
            dropped_outside: Arc::clone(&dropped_outside),
            panic_with_service_borrow: true,
        }));
    drop(old);
    let original_box = {
        let cell = fixture.slot.cell.lock().unwrap();
        std::ptr::from_ref(cell.owner.as_deref().unwrap()).cast::<()>()
    };

    assert!(retry_slot(&fixture.slot, Some(52)).is_err());
    assert!(fixture.slot.is(CleanupPhase::DestructionRefused));
    assert_eq!(callbacks.load(Ordering::Acquire), 1);
    assert_eq!(unlocked.load(Ordering::Acquire), 1);
    assert!(!dropped_outside.load(Ordering::Acquire));
    assert!(fixture.slot.service.is_poisoned());
    {
        let service = fixture
            .slot
            .service
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let restored_box =
            std::ptr::from_ref(service.queued_owner.as_deref().unwrap()).cast::<()>();
        assert_eq!(restored_box, original_box);
        assert!(!service.queued_owner_borrowed);
    }
    {
        let cell = fixture.slot.cell.lock().unwrap();
        assert!(cell.owner.is_none());
        let retained = cell
            .panic_payload
            .as_ref()
            .unwrap()
            .downcast_ref::<File>()
            .unwrap();
        assert_eq!(retained.as_raw_fd(), descriptor);
        retained.metadata()?;
    }

    assert!(retry_slot(&fixture.slot, Some(52)).is_err());
    assert_eq!(callbacks.load(Ordering::Acquire), 1);
    assert_eq!(fixture.slot.body_destroyed_epoch.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture.slot.controls_closed_epoch.load(Ordering::Acquire),
        0
    );
    Ok(())
}

#[test]
fn original_receipt_box_is_destroyed_before_its_terminal_tail() {
    use std::sync::atomic::{AtomicU8, Ordering};

    struct Receipt(Arc<AtomicU8>);
    impl Drop for Receipt {
        fn drop(&mut self) {
            assert_eq!(self.0.swap(1, Ordering::AcqRel), 0);
        }
    }
    struct Terminal(Arc<AtomicU8>);
    impl Drop for Terminal {
        fn drop(&mut self) {
            // The actual shared disposer has returned from drop(Box<Receipt>),
            // including its allocation release, before this destructor starts.
            assert_eq!(self.0.swap(2, Ordering::AcqRel), 1);
        }
    }

    // Drop ordering only. This constructs no Main, native body or permission.
    let progress = Arc::new(AtomicU8::new(0));
    dispose_receipt_before_terminal(
        Box::new(Receipt(Arc::clone(&progress))),
        Some(Terminal(Arc::clone(&progress))),
    );

    assert_eq!(progress.load(Ordering::Acquire), 2);
}

#[test]
fn unavailable_receipt_cannot_latch_terminal_history() {
    // The existing negative-only token has no authentic Main or cell.
    let mut owner = receipt(7);

    assert!(!owner.retain_post_body());
    assert!(owner.retained_post_body().is_none());
    assert_eq!(owner.epoch, 7);
    assert!(!owner.report_reference);
    Box::new(owner).dispose();
}

mod shared_source_tests;
