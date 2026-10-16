//! Component controls for physical body closure and independent Original reports.
//!
//! Real files, a retained mutex cell and the actual worker directory exercise
//! finalization. These controls construct no authenticated Main or native Source.

use super::*;
use crate::campaign_process::{ExecutorWorkerRetirementError, retire_control_bodies};
use crucible_linux_resource::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationGuard,
    HostOperationState, HostOperationSupervisor,
};
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
    // The actual directory is closed; no Main or lifecycle queue exists here.
    let controls = retire_control_bodies(
        &original,
        || {
            workers
                .try_retire_original(&original)
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || Ok(()),
        || {
            workers
                .verify_retired()
                .map_err(ExecutorWorkerRetirementError::Worker)
        },
        || Ok(()),
    )
    .unwrap_err();
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
