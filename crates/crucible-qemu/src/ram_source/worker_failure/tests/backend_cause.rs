//! Same-allocation backend observers retaining original native RAM evidence.

use std::fs::File;
use std::os::fd::AsRawFd;

use super::*;
use crate::{QemuAsyncDriverError, QemuAsyncDriverHealthError, QemuNodeError};
use crucible::{BackendError, BackendOperationalFailureKind, SchedulerError};
use crucible_cas::content_store::StoreError;
use crucible_cas::ram::RamStoreError;
use crucible_linux_resource::host_supervision::{HostOperationClass, HostSupervisionError};

#[test]
fn backend_observers_share_original_worker_allocation_through_final_close() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let (failure, target) = failure(&account);
    let original = failure.shared.source_ref() as *const WorkerFailureBody;
    let health = QemuAsyncDriverHealthError::ram_source(QemuRamSourceError::WorkerFailed(failure));

    let left = health.clone().into_backend_cause();
    let right = health.clone().into_backend_cause();
    let body = left
        .source()
        .and_then(|source| source.downcast_ref::<WorkerFailureBody>())
        .unwrap();
    assert_eq!(body as *const WorkerFailureBody, original);
    assert_eq!(
        left, right,
        "repeated observation must reuse the original control"
    );
    assert!(matches!(body.error, QemuRamSourceError::Ownership));

    drop(health);
    drop(left);
    assert!(matches!(
        account.reserve_resources(0, 0, 1),
        Err(HostServiceError::CapacityExhausted)
    ));

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || drop(right))
            .unwrap();

    verify_original_refusal(report);
    verify_closed(&account);
}

#[test]
fn scheduler_retains_first_boundary_and_complete_typed_ram_error() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let error = QemuRamSourceError::RamBackingFailure {
        kind: BackendOperationalFailureKind::Expired,
        source: RamStoreError::Store(StoreError::Unavailable),
        first: Some(super::super::super::QemuRamReadBoundaryError::Supervision(
            HostSupervisionError::DeadlineExpired {
                operation_id: 41,
                class: HostOperationClass::PageIn,
            },
        )),
    };
    let (failure, target) = failure_with_error(&account, error);
    let original = &failure.shared.source_ref().error as *const QemuRamSourceError;
    let health = QemuAsyncDriverHealthError::ram_source(QemuRamSourceError::WorkerFailed(failure));
    let node = QemuNodeError::from_async_driver(QemuAsyncDriverError::OperationalHealth(health));
    let scheduler = SchedulerError::from(BackendError::from(node));

    assert!(matches!(
        scheduler,
        SchedulerError::Backend(BackendError::RetainedOperationalFailure {
            kind: BackendOperationalFailureKind::Expired,
            ..
        })
    ));
    let source = scheduler
        .source()
        .and_then(Error::source)
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<WorkerFailureBody>())
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<QemuRamSourceError>())
        .unwrap();
    assert_eq!(source as *const QemuRamSourceError, original);
    assert!(matches!(
        source,
        QemuRamSourceError::RamBackingFailure {
            source: RamStoreError::Store(StoreError::Unavailable),
            first: Some(super::super::super::QemuRamReadBoundaryError::Supervision(
                HostSupervisionError::DeadlineExpired {
                    operation_id: 41,
                    class: HostOperationClass::PageIn,
                }
            )),
            ..
        }
    ));
    assert!(source.source().unwrap().is::<RamStoreError>());

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || drop(scheduler))
            .unwrap();

    verify_original_refusal(report);
    verify_closed(&account);
}

#[derive(Debug)]
struct RetainedFileError {
    file: Option<File>,
}

static FILE_CLOSED: AtomicBool = AtomicBool::new(false);

impl Drop for RetainedFileError {
    fn drop(&mut self) {
        drop(self.file.take());
        FILE_CLOSED.store(true, Ordering::Release);
    }
}

impl fmt::Display for RetainedFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("retained original file")
    }
}

impl Error for RetainedFileError {}

#[test]
fn erased_worker_observer_retains_actual_file_until_original_control_closes() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let lease = account.reserve_resources(1, 1, 4096).unwrap();
    FILE_CLOSED.store(false, Ordering::Release);
    let file = File::open("/dev/null").unwrap();
    let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    assert!(
        QemuRamWorkerFailure::allocation_bytes().unwrap()
            + shared_allocation_bytes::<RetainedFileError>().unwrap()
            + HostServiceLease::metadata_bytes()
            <= 4096
    );
    let error = QemuRamSourceError::BackingFailure {
        kind: BackendOperationalFailureKind::Unavailable,
        source: BackendOperationalCause::new(RetainedFileError { file: Some(file) }),
    };
    let (failure, target) = captured_failure(error, lease);
    let backend = failure.clone().into_backend_cause();
    drop(failure);
    assert!(std::fs::metadata(&fd_path).is_ok());
    assert!(!FILE_CLOSED.load(Ordering::Acquire));

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || drop(backend))
            .unwrap();

    verify_original_refusal(report);
    assert!(FILE_CLOSED.load(Ordering::Acquire));
    verify_closed(&account);
}
