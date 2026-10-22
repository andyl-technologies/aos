//! Binds worker cleanup to the same Main, saved operation and physical observers.

use super::{Companion, Contract};

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/campaign_process/worker_custody",
    required: &[
        (
            r#"fn drain_executor_lifecycles(
                main: &Arc<AuthenticatedNativeSlotPurpose>,
            ) -> Result<(), crucible_control_api::LifecycleApiError> {
                let actor = ACTOR.get().filter(|actor| {
                    actor.executor.get().is_some_and(|actual| Arc::ptr_eq(actual, main))
                }).ok_or(crucible_control_api::LifecycleApiError::ConstructionCustodyUnavailable)?;
                if let Some(queue) = actor.lifecycle_cleanup.get() {
                    let work = queue."#,
            1,
        ),
        (
            r#"(); let empty = queue.verify_empty(); work.and(empty) } else { Ok(()) } }"#,
            1,
        ),
        (
            r#"retire_control_bodies(
                original,
                || try_retire_executor_workers(main, original),
                || drain_executor_lifecycles(main),
                || verify_executor_workers_retired(main),
                || verify_executor_lifecycles_retired(main),
            )"#,
            1,
        ),
        (
            r#"let mut before = None; let mut post = None;
                let mut workers = run_retirement_step(original, &mut before, &mut post, &mut retire_workers);
                let mut lifecycle = run_retirement_step(original, &mut before, &mut post, &mut drain_lifecycles);
                if let Some(error) = run_retirement_step(original, &mut before, &mut post, &mut retire_workers) {
                    workers.get_or_insert(error);
                }
                if let Some(error) = run_retirement_step(original, &mut before, &mut post, &mut drain_lifecycles) {
                    lifecycle.get_or_insert(error);
                }"#,
            1,
        ),
        (
            r#"fn run_retirement_step<E>(
                original: &HostOperationGuard,
                before: &mut Option<HostSupervisionError>,
                post: &mut Option<HostSupervisionError>,
                attempt: &mut impl FnMut() -> Result<(), E>,
            ) -> Option<E> {
                if before.is_some() || post.is_some() { return None; }
                if let Err(first) = original.wait_slice() {
                    *before = Some(first); return None;
                }
                let result = attempt();
                *post = original.wait_slice().err();
                result.err()
            }"#,
            1,
        ),
        (
            r#"let workers_closed = observe_workers().is_ok();
                let lifecycle_closed = observe_lifecycles().is_ok();
                let physically_closed = workers_closed && lifecycle_closed;
                let final_post = original.wait_slice().err();
                let post = post.or(final_post);"#,
            1,
        ),
        (
            r#"if before.is_none() && workers.is_none() && lifecycle.is_none() && post.is_none() && physically_closed {
                Ok(())
            } else {
                Err(ExecutorControlRetirementError {
                    admission: None, before, workers, lifecycle, post, physically_closed,
                })
            }"#,
            1,
        ),
        (
            r#"let original = main.retained_cleanup().map_err(|cause| ExecutorControlRetirementError {
                admission: Some(cause), before: None, workers: None, lifecycle: None, post: None,
                physically_closed: false,
            })?; try_retire_executor_controls(main, &original)"#,
            1,
        ),
        (
            r#"run_retirement_step(original, &mut before, &mut post, &mut retire_workers)"#,
            2,
        ),
        (
            r#"run_retirement_step(original, &mut before, &mut post, &mut drain_lifecycles)"#,
            2,
        ),
        (r#"let result = attempt();"#, 1),
        (r#"original.wait_slice()"#, 3),
        (r#"observe_workers()"#, 1),
        (r#"observe_lifecycles()"#, 1),
        (r#".is_none_or(|admitted| !Arc::ptr_eq(admitted, main))"#, 2),
        (r#".is_none_or(|actual| !Arc::ptr_eq(actual, main))"#, 1),
        (r#"workers.try_retire_original(original)?;"#, 1),
        (r#"workers.verify_retired()?;"#, 1),
        (r#".map_or(Ok(()), |queue| queue.verify_empty())"#, 1),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#"HostOperationClass::Preparation"#, 0),
    ],
    expressions: &[(r#"queue.retry_pending();"#, 1)],
    identifiers: &[("retry_pending", 1)],
    companions: &[Companion {
        path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose.rs",
        required: &[
            (
                r#"cleanup: std::sync::OnceLock<
                    Result<Arc<HostOperationGuard>, crate::host_supervision::HostSupervisionError>,
                >,"#,
                1,
            ),
            (
                r#"pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
                    let cleanup = self.cleanup.get_or_init(|| self.original.begin_original_cleanup_control().map(Arc::new));
                    let cleanup = cleanup.as_ref().map_err(|source| ServiceBirthError::from(*source))?;
                    cleanup.wait_slice().map_err(ServiceBirthError::from)?;
                    Ok(Arc::clone(cleanup))
                }"#,
                1,
            ),
        ],
    }],
}];
