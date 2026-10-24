//! Shares concrete saved-Original, backend and physical-return obligations.

use super::super::Companion;

pub(super) const ORIGINAL: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_services/process_birth/executor_purpose.rs",
    required: &[
        (
            r#"cleanup: std::sync::OnceLock<Result<Arc<HostOperationGuard>, crate::host_supervision::HostSupervisionError>,>,"#,
            1,
        ),
        (
            r#"pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let cleanup = self.cleanup.get_or_init(|| self.original.begin_original_cleanup_control().map(Arc::new));
        let cleanup = cleanup.as_ref().map_err(|source| ServiceBirthError::from(*source))?;
        cleanup.wait_slice().map_err(ServiceBirthError::from)?; Ok(Arc::clone(cleanup))
    }"#,
            1,
        ),
    ],
};

pub(super) const BACKEND: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
    required: &[
        (
            r#"pub fn retry_cleanup(&self) -> Result<(), ProductionVmConstructionCleanupError> {
        let mut phase = self.phase.try_lock().map_err(phase_lock_error)?;
        if self.physically_closed.load(Ordering::Acquire) { return Ok(()); }"#,
            1,
        ),
        (r#"Phase::Partial(partial) => retire_partial(partial)?,"#, 1),
        (
            r#"Phase::Complete(lifecycle) => retire_complete(lifecycle)?,"#,
            1,
        ),
        (
            r#"Phase::Source(source) => source.retry_source_retirement_body()?,"#,
            1,
        ),
        (
            r#"self.physically_closed.store(true, Ordering::Release);"#,
            1,
        ),
        (r#"Some(first) => first.with_later_failure(source),"#, 1),
    ],
};

pub(super) const SOURCE: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/vm_lifecycle/hot_fork/source_retirement.rs",
    required: &[
        (r#"if state.body_closed { return Ok(()); }"#, 1),
        (r#"Some(Ok(cleanup)) => state.cleanup = Some(cleanup),"#, 1),
        (r#"history.admission.get_or_insert(first);"#, 1),
        (
            r#"let cleanup = state.cleanup.as_ref().ok_or(CleanupError::Retained("#,
            1,
        ),
        (r#"let post = cleanup.wait_slice();"#, 2),
        (
            r#"if ack && let Some(prepared) = self.prepared.pop() { self.disk_custody.remove(prepared.node()); }"#,
            1,
        ),
        (
            r#"state.shutdown_attempted = true; if let Err(first) = lifecycle.shutdown() { history.shutdown.get_or_insert(first); }"#,
            1,
        ),
        (
            r#"let closed = body.is_ok(); let post = cleanup.wait_slice();"#,
            1,
        ),
        (r#"history.body.get_or_insert(first);"#, 1),
        (r#"history.body_post.get_or_insert(first);"#, 1),
        (r#"if closed { state.body_closed = true;"#, 1),
    ],
};

pub(super) const SERVICE: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/packaged_qemu_executor/hot_fork/retained_service/startup.rs",
    required: &[
        (r#"if self.released { return Ok(()); }"#, 1),
        (
            r#"if let Some(watchdog) = self.watchdog.take() { self.stop = Some(watchdog.stop_service_owned()); self.completion_attempted = true; }"#,
            1,
        ),
        (
            r#"else if !self.completion_attempted { self.completion_attempted = true;"#,
            1,
        ),
        (
            r#"if let Some(imported) = imported.take() { *imported_return = Some(imported.retire_unpublished()); }"#,
            1,
        ),
        (
            r#"drop(admission.take()); drop(self.supervisor.take()); drop(self.prepared.take());"#,
            1,
        ),
        (
            r#"self.registry.release_service_after_cleanup(self.owner)?;"#,
            1,
        ),
        (r#"self.released = !self.reserved || release_actor;"#, 1),
    ],
};

pub(super) const RECEIVER: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/imported_checkpoint.rs",
    required: &[(
        r#"pub fn retry_parent_return(&mut self) -> bool {
        let Some(receiver) = self.parent_receiver.take() else { return true; };
        self.receiver_return_attempted = true;
        match receiver.return_after_alias_destruction() {
            Ok(()) => true,
            Err(receiver) => { self.receiver_return_refused = true; self.parent_receiver = Some(receiver); false }
        }
    }"#,
        1,
    )],
};
