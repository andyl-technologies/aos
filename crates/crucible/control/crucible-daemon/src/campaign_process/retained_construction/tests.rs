//! Component controls for physical body closure and independent Original reports.
//!
//! Real files, a retained mutex cell and the actual worker directory exercise
//! finalization. These controls construct no authenticated Main or native Source.

use super::*;
use crate::campaign_process::{ExecutorWorkerRetirementError, retire_control_bodies};
use crucible_control_api::LifecycleApiError;
use crucible_host_resources::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationGuard,
    HostOperationState, HostOperationSupervisor,
};
use std::cell::Cell;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Weak};
use std::time::Duration;

static FIRST: ServiceBirthError = ServiceBirthError::Supervision(HostSupervisionError::Terminal {
    state: HostOperationState::Canceled,
});

struct Body {
    member: Option<File>,
    containing_file: File,
    slot: Weak<Mutex<Option<Body>>>,
    dropped: Arc<AtomicBool>,
    outside_lock: Arc<AtomicBool>,
}

impl Body {
    fn physically_closed(&self) -> bool {
        self.member.is_none()
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        self.outside_lock.store(
            self.slot
                .upgrade()
                .is_some_and(|slot| slot.try_lock().is_ok()),
            Ordering::Release,
        );
        self.dropped.store(true, Ordering::Release);
    }
}

fn body_cell() -> std::io::Result<Arc<Mutex<Option<Body>>>> {
    let slot = Arc::new(Mutex::new(None));
    *slot.lock().unwrap() = Some(Body {
        member: Some(tempfile::tempfile()?),
        containing_file: tempfile::tempfile()?,
        slot: Arc::downgrade(&slot),
        dropped: Arc::new(AtomicBool::new(false)),
        outside_lock: Arc::new(AtomicBool::new(false)),
    });
    Ok(slot)
}

fn expire_same_cleanup(
    supervisor: &HostOperationSupervisor,
    original: &HostOperationGuard,
) -> HostSupervisionError {
    let (revision, mut budgets) = supervisor.budgets().unwrap();
    budgets.classes[HostOperationClass::Cleanup as usize] =
        HostOperationBudget::finite(Duration::from_nanos(1));
    supervisor.update_budgets(revision, budgets).unwrap();
    let post = original.wait_slice().unwrap_err();
    assert!(matches!(
        post,
        HostSupervisionError::DeadlineExpired { .. }
            | HostSupervisionError::Terminal {
                state: HostOperationState::Expired
            }
    ));
    post
}

#[test]
fn closed_body_is_destroyed_outside_cell_before_reporting_expired_original()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let cell = body_cell()?;
    let mut slot = cell.lock().unwrap();
    let body = slot.as_mut().unwrap();
    let dropped = body.dropped.clone();
    let outside_lock = body.outside_lock.clone();
    let descriptor = body.containing_file.as_raw_fd();
    let identity = body.containing_file.metadata()?;
    original.wait_slice()?;
    drop(body.member.take());
    let post = expire_same_cleanup(&supervisor, &original);

    let report = finish_retained_construction(
        slot,
        Body::physically_closed,
        &FIRST,
        None,
        None,
        Some(post),
    )
    .unwrap_err();

    let RetainedExecutorRetirementError::Post {
        first,
        post: actual,
    } = report
    else {
        panic!("actual closure must remain separate from the late postcut");
    };
    assert!(std::ptr::eq(first, &FIRST));
    assert_eq!(actual, post);
    assert!(cell.lock().unwrap().is_none());
    assert!(dropped.load(Ordering::Acquire));
    assert!(outside_lock.load(Ordering::Acquire));
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |current| {
            (current.dev(), current.ino()) != (identity.dev(), identity.ino())
        })
    );
    assert!(original.wait_slice().is_err());
    Ok(())
}

struct FileWorker {
    _file: File,
}

impl crate::LocalAttemptWorker for FileWorker {
    type Error = HostSupervisionError;

    fn execute(&mut self, _: crate::QueuedAttempt) -> crate::AttemptWorkResult<Self::Error> {
        panic!("component custody owns no campaign execution");
    }

    fn try_retire_original(&mut self, original: &HostOperationGuard) -> Result<(), Self::Error> {
        original.wait_slice().map(|_| ())
    }
}

#[test]
fn closed_body_preserves_first_work_controls_and_post_reports()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let workers = crate::executor_pool::PreparedExecutorWorkers::unissued_component_custody(vec![
        FileWorker {
            _file: tempfile::tempfile()?,
        },
    ]);
    workers.try_retire_original(&original)?;
    assert!(workers.verify_retired().is_ok());
    let cell = body_cell()?;
    let mut slot = cell.lock().unwrap();
    let body = slot.as_mut().unwrap();
    let dropped = body.dropped.clone();
    drop(body.member.take());
    let post = expire_same_cleanup(&supervisor, &original);
    let work = original.wait_slice().unwrap_err();
    let effects = Cell::new(0);
    let observations = Cell::new(0);
    // The actual directory is closed; no Main or lifecycle queue exists here.
    let controls = retire_control_bodies(
        &original,
        || {
            effects.set(effects.get() + 1);
            workers
                .try_retire_original(&original)
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            effects.set(effects.get() + 1);
            Ok(())
        },
        || {
            observations.set(observations.get() + 1);
            workers
                .verify_retired()
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            observations.set(observations.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(effects.get(), 0);
    assert_eq!(observations.get(), 2);
    assert_eq!(controls.original_before(), Some(work));
    assert!(controls.physically_closed());
    let control_post = controls.original_post();

    let report = finish_retained_construction(
        slot,
        Body::physically_closed,
        &FIRST,
        Some(RetainedExecutorCleanupError::Original(work)),
        Some(controls),
        Some(post),
    )
    .unwrap_err();

    let RetainedExecutorRetirementError::Cleanup {
        first,
        cause,
        controls,
        post: actual,
    } = report
    else {
        panic!("physical destruction must preserve every independent report");
    };
    assert!(std::ptr::eq(first, &FIRST));
    assert!(
        matches!(cause, Some(RetainedExecutorCleanupError::Original(actual)) if actual == work)
    );
    let controls = controls.unwrap();
    assert!(controls.physically_closed());
    assert_eq!(controls.original_post(), control_post);
    assert_eq!(actual, Some(post));
    assert!(cell.lock().unwrap().is_none());
    assert!(dropped.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn deadline_expiry_during_worker_step_preserves_queued_file_and_first_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let workers = crate::executor_pool::PreparedExecutorWorkers::unissued_component_custody(vec![
        FileWorker {
            _file: tempfile::tempfile()?,
        },
    ]);
    // This is a component-owned File, not an authenticated Main or queue grant.
    let queued = Mutex::new(Some(tempfile::tempfile()?));
    let descriptor = queued.lock().unwrap().as_ref().unwrap().as_raw_fd();
    let identity = queued.lock().unwrap().as_ref().unwrap().metadata()?;
    let worker_effects = Cell::new(0);
    let queue_effects = Cell::new(0);
    let observations = Cell::new(0);

    let controls = retire_control_bodies(
        &original,
        || {
            worker_effects.set(worker_effects.get() + 1);
            expire_same_cleanup(&supervisor, &original);
            workers
                .try_retire_original(&original)
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            queue_effects.set(queue_effects.get() + 1);
            drop(queued.lock().unwrap().take());
            Ok(())
        },
        || {
            observations.set(observations.get() + 1);
            workers
                .verify_retired()
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            observations.set(observations.get() + 1);
            if queued.lock().unwrap().is_some() {
                Err(LifecycleApiError::ConstructionCustodyUnavailable)
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();

    let post = original.wait_slice().unwrap_err();
    assert_eq!(worker_effects.get(), 1);
    assert_eq!(queue_effects.get(), 0);
    assert_eq!(observations.get(), 2);
    assert!(!controls.physically_closed());
    assert_eq!(controls.original_before(), None);
    assert_eq!(controls.original_post(), Some(post));
    let first = std::error::Error::source(&controls)
        .unwrap()
        .downcast_ref::<ExecutorWorkerRetirementError>();
    assert!(matches!(
        first,
        Some(ExecutorWorkerRetirementError::Worker(
            crate::executor_pool::WorkerRetirementRefusal::Original(first)
        )) if *first == post
    ));
    let retained = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!(
        (retained.dev(), retained.ino()),
        (identity.dev(), identity.ino())
    );
    assert!(queued.lock().unwrap().is_some());
    Ok(())
}

#[test]
fn queue_effect_failure_and_deadline_expiry_allow_actual_closed_body_return()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let workers = crate::executor_pool::PreparedExecutorWorkers::unissued_component_custody(vec![
        FileWorker {
            _file: tempfile::tempfile()?,
        },
    ]);
    workers.try_retire_original(&original)?;
    let cell = body_cell()?;
    let dropped = cell.lock().unwrap().as_ref().unwrap().dropped.clone();
    let outside_lock = cell.lock().unwrap().as_ref().unwrap().outside_lock.clone();
    let worker_effects = Cell::new(0);
    let queue_effects = Cell::new(0);
    let observations = Cell::new(0);

    let controls = retire_control_bodies(
        &original,
        || {
            worker_effects.set(worker_effects.get() + 1);
            workers
                .try_retire_original(&original)
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            queue_effects.set(queue_effects.get() + 1);
            drop(cell.lock().unwrap().as_mut().unwrap().member.take());
            expire_same_cleanup(&supervisor, &original);
            Err(LifecycleApiError::ConstructionCustodyUnavailable)
        },
        || {
            observations.set(observations.get() + 1);
            workers
                .verify_retired()
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || {
            observations.set(observations.get() + 1);
            if cell.lock().unwrap().as_ref().unwrap().physically_closed() {
                Ok(())
            } else {
                Err(LifecycleApiError::ConstructionCustodyUnavailable)
            }
        },
    )
    .unwrap_err();

    let post = original.wait_slice().unwrap_err();
    assert_eq!(worker_effects.get(), 1);
    assert_eq!(queue_effects.get(), 1);
    assert_eq!(observations.get(), 2);
    assert!(controls.physically_closed());
    assert_eq!(controls.original_before(), None);
    assert_eq!(controls.original_post(), Some(post));
    assert_eq!(
        std::error::Error::source(&controls)
            .unwrap()
            .downcast_ref::<LifecycleApiError>(),
        Some(&LifecycleApiError::ConstructionCustodyUnavailable),
    );

    let report = finish_retained_construction(
        cell.lock().unwrap(),
        Body::physically_closed,
        &FIRST,
        None,
        Some(controls),
        Some(post),
    )
    .unwrap_err();
    assert!(matches!(
        report,
        RetainedExecutorRetirementError::Cleanup {
            controls: Some(ref controls),
            post: Some(actual),
            ..
        } if controls.physically_closed() && actual == post
    ));
    assert!(cell.lock().unwrap().is_none());
    assert!(dropped.load(Ordering::Acquire));
    assert!(outside_lock.load(Ordering::Acquire));
    assert!(original.wait_slice().is_err());
    Ok(())
}

#[test]
fn unclosed_body_stays_in_same_cell_with_its_typed_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let cell = body_cell()?;
    let slot = cell.lock().unwrap();
    let body = slot.as_ref().unwrap();
    let address = std::ptr::from_ref(body);
    let dropped = body.dropped.clone();
    let descriptor = body.member.as_ref().unwrap().as_raw_fd();
    let identity = body.member.as_ref().unwrap().metadata()?;
    let post = expire_same_cleanup(&supervisor, &original);

    let report = finish_retained_construction(
        slot,
        Body::physically_closed,
        &FIRST,
        Some(RetainedExecutorCleanupError::Original(post)),
        None,
        Some(post),
    )
    .unwrap_err();

    let RetainedExecutorRetirementError::Cleanup {
        first,
        cause,
        post: actual,
        ..
    } = report
    else {
        panic!("pending member must retain its complete containing body");
    };
    assert!(std::ptr::eq(first, &FIRST));
    assert!(
        matches!(cause, Some(RetainedExecutorCleanupError::Original(actual)) if actual == post)
    );
    assert_eq!(actual, Some(post));
    let slot = cell.lock().unwrap();
    assert!(std::ptr::eq(slot.as_ref().unwrap(), address));
    assert!(!dropped.load(Ordering::Acquire));
    let retained = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!(
        (retained.dev(), retained.ino()),
        (identity.dev(), identity.ino())
    );
    Ok(())
}
