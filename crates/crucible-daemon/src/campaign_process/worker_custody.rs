//! Pins the one actual worker directory outside every factory's strong graph.

use super::*;
use crucible_linux_resource::host_services::process_birth::AuthenticatedNativeSlotPurpose;
use crucible_linux_resource::host_supervision::HostOperationGuard;

pub(crate) fn install_executor_worker_custody(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    workers: Arc<crate::executor_pool::ExecutorWorkerCustody>,
) -> Result<(), crucible_qemu::QemuVmRealizationError> {
    let actor = actor_for(main)?;
    if let Some(current) = actor.executor_workers.get() {
        return if Arc::ptr_eq(current, &workers) {
            Ok(())
        } else {
            Err(refusal("Main already retains another worker directory"))
        };
    }
    actor
        .executor_workers
        .set(workers)
        .map_err(|_| refusal("Main worker custody publication raced another directory"))
}

/// Revisits the same workers even when startup returned before a pool existed.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum ExecutorWorkerRetirementError {
    #[error("same admitted Main worker custody is unavailable")]
    Main,
    #[error(transparent)]
    Worker(#[from] crate::executor_pool::WorkerRetirementRefusal),
}

pub(crate) fn try_retire_executor_workers(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    original: &HostOperationGuard,
) -> Result<(), ExecutorWorkerRetirementError> {
    let actor = ACTOR.get().ok_or(ExecutorWorkerRetirementError::Main)?;
    if actor
        .executor
        .get()
        .is_none_or(|admitted| !Arc::ptr_eq(admitted, main))
    {
        return Err(ExecutorWorkerRetirementError::Main);
    }
    if let Some(workers) = actor.executor_workers.get() {
        workers.try_retire_original(original)?;
    }
    Ok(())
}

fn actor_for(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<&'static ProcessActor, crucible_qemu::QemuVmRealizationError> {
    let actor = ACTOR.get().ok_or_else(|| refusal("Main is unpublished"))?;
    actor
        .verify()
        .map_err(|_| refusal("Main is no longer live"))?;
    if actor
        .executor
        .get()
        .is_none_or(|admitted| !Arc::ptr_eq(admitted, main))
    {
        return Err(refusal("worker directory belongs to another admitted Main"));
    }
    Ok(actor)
}

fn refusal(message: &'static str) -> crucible_qemu::QemuVmRealizationError {
    crucible_qemu::QemuVmRealizationError::ExecutorUnavailable {
        operation: "retain permanent Main worker custody",
        message: String::from(message),
    }
}

/// Preserves independent worker, lifecycle and saved-Original cleanup reports.
///
/// Physical worker closure is tracked in the same Main cells. A historical
/// cause remains a report; it never restores an already destroyed worker.
#[derive(Debug)]
pub struct ExecutorControlRetirementError {
    admission: Option<crucible_linux_resource::host_services::process_birth::ServiceBirthError>,
    workers: Option<ExecutorWorkerRetirementError>,
    lifecycle: Option<crucible_api::LifecycleApiError>,
    post: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    physically_closed: bool,
}

impl ExecutorControlRetirementError {
    /// Reports the final same-owner observations, independently of prior failures.
    pub(crate) fn physically_closed(&self) -> bool {
        self.physically_closed
    }

    pub(crate) fn original_post(
        &self,
    ) -> Option<crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.post
    }
}

impl std::fmt::Display for ExecutorControlRetirementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Main cleanup admission: {:?}; workers: {:?}; lifecycle: {:?}; independent post: {:?}",
            self.admission, self.workers, self.lifecycle, self.post
        )
    }
}

impl std::error::Error for ExecutorControlRetirementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = &self.admission {
            return Some(cause);
        }
        if let Some(cause) = &self.workers {
            return Some(cause);
        }
        if let Some(cause) = &self.lifecycle {
            return Some(cause);
        }
        self.post
            .as_ref()
            .map(|cause| cause as &dyn std::error::Error)
    }
}

/// Attempts worker/queue/worker/queue once under the same retained Original.
///
/// The second worker pass can finish a factory whose first pass published a
/// lifecycle. Earlier failures remain reports even when final bodies are gone.
pub(crate) fn try_retire_executor_controls(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    original: &HostOperationGuard,
) -> Result<(), ExecutorControlRetirementError> {
    retire_control_bodies(
        original,
        || try_retire_executor_workers(main, original),
        || drain_executor_lifecycles(main),
        || verify_executor_workers_retired(main),
        || verify_executor_lifecycles_retired(main),
    )
}

/// Keeps same-owner physical observations distinct from initiating reports.
///
/// Production supplies only the exact Main-selected methods above. Concrete
/// component controls can use actual worker/cell bodies without issuing Main.
/// Closures are borrowed, synchronous and allocate no callback storage.
pub(crate) fn retire_control_bodies(
    original: &HostOperationGuard,
    mut retire_workers: impl FnMut() -> Result<(), ExecutorWorkerRetirementError>,
    mut drain_lifecycles: impl FnMut() -> Result<(), crucible_api::LifecycleApiError>,
    observe_workers: impl FnOnce() -> Result<(), ExecutorWorkerRetirementError>,
    observe_lifecycles: impl FnOnce() -> Result<(), crucible_api::LifecycleApiError>,
) -> Result<(), ExecutorControlRetirementError> {
    let mut workers = retire_workers().err();
    let mut lifecycle = drain_lifecycles().err();
    if let Err(error) = retire_workers() {
        workers.get_or_insert(error);
    }
    if let Err(error) = drain_lifecycles() {
        lifecycle.get_or_insert(error);
    }

    // A historical drain error cannot change the independently observed state
    // of the actual bodies. Neither observation executes another cleanup cut.
    let workers_closed = observe_workers().is_ok();
    let lifecycle_closed = observe_lifecycles().is_ok();
    let physically_closed = workers_closed && lifecycle_closed;
    let post = original.wait_slice().err();
    if workers.is_none() && lifecycle.is_none() && post.is_none() && physically_closed {
        Ok(())
    } else {
        Err(ExecutorControlRetirementError {
            admission: None,
            workers,
            lifecycle,
            post,
            physically_closed,
        })
    }
}

pub(crate) fn verify_executor_workers_retired(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), ExecutorWorkerRetirementError> {
    let actor = ACTOR.get().ok_or(ExecutorWorkerRetirementError::Main)?;
    if actor
        .executor
        .get()
        .is_none_or(|actual| !Arc::ptr_eq(actual, main))
    {
        return Err(ExecutorWorkerRetirementError::Main);
    }
    if let Some(workers) = actor.executor_workers.get() {
        workers.verify_retired()?;
    }
    Ok(())
}

fn verify_executor_lifecycles_retired(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), crucible_api::LifecycleApiError> {
    let actor = ACTOR
        .get()
        .filter(|actor| {
            actor
                .executor
                .get()
                .is_some_and(|actual| Arc::ptr_eq(actual, main))
        })
        .ok_or(crucible_api::LifecycleApiError::ConstructionCustodyUnavailable)?;
    actor
        .lifecycle_cleanup
        .get()
        .map_or(Ok(()), |queue| queue.verify_empty())
}

fn drain_executor_lifecycles(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), crucible_api::LifecycleApiError> {
    let actor = ACTOR
        .get()
        .filter(|actor| {
            actor
                .executor
                .get()
                .is_some_and(|actual| Arc::ptr_eq(actual, main))
        })
        .ok_or(crucible_api::LifecycleApiError::ConstructionCustodyUnavailable)?;
    if let Some(queue) = actor.lifecycle_cleanup.get() {
        let work = queue.retry_pending();
        let empty = queue.verify_empty();
        work.and(empty)
    } else {
        Ok(())
    }
}

pub(crate) fn try_retire_executor_controls_for_main(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), ExecutorControlRetirementError> {
    let original = main
        .retained_cleanup()
        .map_err(|cause| ExecutorControlRetirementError {
            admission: Some(cause),
            workers: None,
            lifecycle: None,
            post: None,
            physically_closed: false,
        })?;
    try_retire_executor_controls(main, &original)
}
