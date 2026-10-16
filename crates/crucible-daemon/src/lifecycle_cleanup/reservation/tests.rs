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

impl crucible_api::ProductionVmCleanupOwner for FileOwner {
    fn retry_cleanup(&mut self) -> Result<(), crucible::SchedulerError> {
        ProductionVmNodeLauncher::finish(self).map_err(|error| {
            crucible::SchedulerError::BoundaryViolation {
                message: error.to_string(),
            }
        })
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

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if std::mem::take(&mut self.refuse_once) {
            return Err(refusal("first file cleanup refusal"));
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

struct CellFixture {
    descriptor: RawFd,
    identity: (u64, u64),
    slot: Arc<CleanupSlot>,
    attempts: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    drop_outside_lock: Arc<AtomicBool>,
}

fn fixture(epoch: u64, refuse_once: bool) -> Result<CellFixture, std::io::Error> {
    let slot = Arc::new(CleanupSlot {
        phase: AtomicU8::new(CleanupPhase::Queued as u8),
        body_destroyed_epoch: AtomicU64::new(0),
        completed_epoch: AtomicU64::new(0),
        cell: Mutex::new(CleanupCell {
            epoch,
            owner: None,
            controls: None,
            first_failure: None,
            handoff: true,
        }),
    });
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
    slot.cell.lock().unwrap().owner = Some(Box::new(owner));
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
        queue: Weak::new(),
        index: 0,
        epoch,
        observed: ProductionVmCleanupStage::BodyRetained,
        first_failure: None,
    }
}

#[test]
fn exact_retry_preserves_siblings_and_history_until_receipt_observes_close()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(7, true)?;
    let sibling = fixture(12, false)?;
    let mut handoff = receipt(7);

    assert!(retry_slot(&selected.slot, Some(7)).is_err());
    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::BodyRetained
    );
    assert!(!selected.dropped.load(Ordering::Acquire));
    let retained = fs::metadata(format!("/proc/self/fd/{}", selected.descriptor))?;
    assert_eq!((retained.dev(), retained.ino()), selected.identity);
    assert_eq!(sibling.attempts.load(Ordering::Acquire), 0);

    retry_slot(&selected.slot, Some(7))?;
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
fn completed_receipt_never_drives_reused_cell() -> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(7, false)?;
    let mut handoff = receipt(7);
    retry_slot(&selected.slot, Some(7))?;
    assert_eq!(
        handoff.observe_slot(&selected.slot)?,
        ProductionVmCleanupStage::Complete
    );

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
    // This is the production cell primitive, with no containing Main/Source
    // purpose. The normal facade's authentic queue selection is not modeled.
    let slot = Arc::new(CleanupSlot {
        phase: AtomicU8::new(CleanupPhase::Free as u8),
        body_destroyed_epoch: AtomicU64::new(0),
        completed_epoch: AtomicU64::new(0),
        cell: Mutex::new(CleanupCell {
            epoch: 0,
            owner: None,
            controls: None,
            first_failure: None,
            handoff: false,
        }),
    });

    for expected_epoch in 1..=24 {
        assert!(slot.claim(CleanupPhase::Free, CleanupPhase::Reserving));
        let epoch = initialize_reserved_slot(&slot, (), |_, ()| {}).unwrap();
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
        assert_eq!(
            handoff.observe_slot(&slot)?,
            ProductionVmCleanupStage::BodyRetained
        );

        if refuse_once {
            assert!(retry_slot(&slot, Some(epoch)).is_err());
            assert!(!dropped.load(Ordering::Acquire));
            let retained = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
            assert_eq!(
                (retained.dev(), retained.ino()),
                (identity.dev(), identity.ino())
            );
        }
        retry_slot(&slot, Some(epoch))?;
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
        let historical = handoff.take_first_failure();
        assert_eq!(historical.is_some(), refuse_once);
        assert!(handoff.first_failure().is_none());
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
    type Error = crucible_linux_resource::host_supervision::HostSupervisionError;

    fn execute(&mut self, _: crate::QueuedAttempt) -> crate::AttemptWorkResult<Self::Error> {
        panic!("unissued file custody does not execute a campaign");
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
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
    use crucible_linux_resource::host_supervision::{
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
            let work = retry_slot(&selected.slot, Some(71));
            let stage = handoff.borrow_mut().observe_slot(&selected.slot)?;
            if stage == ProductionVmCleanupStage::Complete {
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
                if let Some(first) = handoff.borrow_mut().take_first_failure() {
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
