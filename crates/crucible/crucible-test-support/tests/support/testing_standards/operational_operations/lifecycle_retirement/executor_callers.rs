//! Binds executor callers to saved Main cleanup or the actual component queue.
//!
//! The component branch closes each retained owner before its dispatcher. Main
//! panic handback keeps its original completion header and retained body.

use super::super::{Companion, Contract};

pub(super) const EXECUTOR: &[(&str, usize)] = &[
    (
        r###"pub fn start(service: PackagedQemuExecutor) -> Result<Self, PackagedQemuExecutorStartError> {
        if let Some(main) = service.guarded_state.config.normal_executor.clone() {
            return Self::start_main(service, main);
        }
        let PackagedQemuExecutor {
            guarded_state,
            host_operational_registry,
            repository_identity,
            admitted_scenarios,
            endpoint,
            service,
            exact_pin_materializer,
            original_physically_retired: _,
            source_physically_retired: _,
            operational_status,
            hot_fork_owner,
            hot_fork_retention,
            campaign_debug,
        } = service;
        let shutdown = service.shutdown_handle();
        // This is a handle to the same actual factory saved in guarded_state.
        // The outer owner retains it through any uncertain thread retirement.
        let dispatcher_host_for_owner = guarded_state.host.clone();
        let lifecycle_cleanup_for_owner = guarded_state.lifecycle_cleanup.clone();
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let thread_completion = Arc::clone(&completion);
        let thread = thread::Builder::new()
            .name(String::from("crucible-packaged-qemu-executor"))
            .spawn(move || {
                let _completion = PackagedQemuExecutorCompletionGuard(thread_completion);
                // Drop this existing factory alias before completion publication
                // on both success and refusal; the outer guarded_state keeps it.
                let target_dispatcher_host = dispatcher_host_for_owner;
                let service_result = service.serve();
                exact_pin_materializer.request_shutdown();
                let materializer_result = exact_pin_materializer.join();
                let hot_fork_result = hot_fork_owner
                    .as_ref()
                    .map(|owner| owner.orderly_shutdown())
                    .unwrap_or(Ok(()));
                // Cleanup is attempted even when an earlier independent join
                // failed. The original join errors remain in the combined report.
                let lifecycle_cleanup_result = lifecycle_cleanup_for_owner
                    .as_ref()
                    .map(|cleanup| {
                        cleanup
                            .retry_pending()
                            .and_then(|()| cleanup.verify_empty())
                    })
                    .unwrap_or(Ok(()));
                let report = combine_packaged_qemu_join_results(
                    service_result,
                    materializer_result,
                    hot_fork_result,
                    lifecycle_cleanup_result,
                    Ok(()),
                )?;
                // This branch has no Main. Component factories may have no
                // native dispatcher; every saved host still closes its actual
                // dispatcher after all worker and Source owners have closed.
                if let Some(host) = target_dispatcher_host.as_ref() {
                    let (work, physically_closed) = host.finish_target_dispatcher();
                    work.map_err(PackagedQemuExecutorJoinError::TargetDispatcher)?;
                    if !physically_closed {
                        return Err(PackagedQemuExecutorJoinError::TargetDispatcherPending);
                    }
                }
                Ok(report)
            })
            .map_err(|source| PackagedQemuExecutorStartError::Spawn { source })?;
        Ok(Self {
            guarded_state,
            host_operational_registry,
            repository_identity,
            admitted_scenarios,
            endpoint,
            operational_status,
            hot_fork_retention,
            campaign_debug,
            shutdown,
            completion,
            thread: Some(thread),
        })
    }"###,
        1,
    ),
    (
        r###"fn join_inner(&mut self) -> Result<ExecutorLocalServiceReport, PackagedQemuExecutorJoinError> {
        let Some(thread) = self.thread.take() else {
            return Err(PackagedQemuExecutorJoinError::OwnerUnavailable);
        };
        match thread.join() {
            Ok(result) => result,
            Err(_) => {
                if let Some(main) = &self.guarded_state.config.normal_executor {
                    let mark = crate::campaign_process::mark_attached_returned(
                        main,
                        Some(PackagedQemuExecutorJoinError::ThreadPanicked),
                    );
                    // Even a marker contention leaves the same body in Main;
                    // its retained actual completion header proves thread exit.
                    let _retirement = crate::campaign_process::retry_attached_retirement(main);
                    return match mark {
                        Ok(()) => Err(crate::campaign_process::retained_attached_report(main)),
                        Err(error) => Err(error),
                    };
                }
                Err(PackagedQemuExecutorJoinError::ThreadPanicked)
            }
        }
    }"###,
        1,
    ),
    (
        r###"impl Drop for AttachedPackagedQemuExecutor {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_inner();
    }
}"###,
        1,
    ),
];
pub(super) const QUEUE_RETURN: &[(&str, usize)] = &[
    (
        r###"pub(crate) fn retry_pending(self: &Arc<Self>) -> Result<(), LifecycleApiError> {
        let mut refused = false;
        for (index, slot) in self.slots.iter().enumerate() {
            let epoch = slot.epoch.load(Ordering::Acquire);
            if slot.is(CleanupPhase::Reserved) && report_refs::register(slot, epoch) {
                if slot.epoch.load(Ordering::Acquire) == epoch && slot.is(CleanupPhase::Reserved) {
                    slot.request_retirement();
                    if slot.report_references.load(Ordering::Acquire) == 1 {
                        slot.export_abandoned.store(true, Ordering::Release);
                    }
                }
                report_refs::release(slot, epoch, false);
            }
            let _attempt = retry_slot(slot, Some(epoch));
            if slot.is(CleanupPhase::TerminalReady)
                && slot.report_references.load(Ordering::Acquire) == 0
                && report_refs::register(slot, epoch)
            {
                let key = ServiceMainPreclaim {
                    queue: Arc::downgrade(self),
                    index,
                    epoch,
                };
                match terminal::take_terminal_body(&key) {
                    Ok(body) => drop(body),
                    Err(_) => report_refs::release(slot, epoch, false),
                }
            }
            refused |= !slot.is(CleanupPhase::Free);
        }
        if refused {
            Err(refusal("lifecycle cleanup remains owned or pending"))
        } else {
            Ok(())
        }
    }"###,
        1,
    ),
    (
        r###"pub(crate) fn verify_empty(&self) -> Result<(), LifecycleApiError> {
        if self.slots.iter().all(|slot| slot.is(CleanupPhase::Free)) {
            Ok(())
        } else {
            Err(refusal("cleanup ownership has not physically returned"))
        }
    }"###,
        1,
    ),
];

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/packaged_qemu_executor",
    required: EXECUTOR,
    expressions: &[
        ("cleanup.retry_pending()", 1),
        (
            "crate::campaign_process::retry_attached_retirement(main)",
            1,
        ),
    ],
    identifiers: &[("retry_pending", 1), ("retry_attached_retirement", 1)],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup.rs",
            required: QUEUE_RETURN,
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/campaign_process/attached_retirement.rs",
            required: super::main::MAIN_ATTACHED.required,
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/packaged_qemu_executor/attached_retirement.rs",
            required: super::main::ATTACHED.required,
        },
        super::ORIGINAL,
        super::ATTACHED_BODY,
        super::MAIN_ATTACHMENT,
        super::DISPATCHER,
        super::super::production_publication::CONSTRUCTOR_RESERVATION,
        super::super::production_publication::CONSTRUCTOR_QUEUE,
        super::super::production_publication::CONSTRUCTOR_DRIVER,
        super::super::production_publication::CONSTRUCTOR_QUEUED_OWNER,
        super::super::production_publication::ROLE_REPORTS,
    ],
};
