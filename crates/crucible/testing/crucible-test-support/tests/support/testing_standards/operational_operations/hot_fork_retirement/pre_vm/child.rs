//! Binds helper cleanup to its retained child, saved Source Original and reap.

use super::{Companion, source};

pub(super) const CALLER: Companion = Companion {
    path: source::PRE_VM_RECEIVER.path,
    required: &[
        source::PRE_VM_RECEIVER.required[0],
        (
            r#"pub(super) fn with_spawned_helper<T: HelperOutput>(
    &self,
    command: Command,
    operation: &'static str,
    body: impl FnOnce(
        &mut QemuNodeChild,
        &crucible_host_resources::host_supervision::HostOperationGuard,
        &mut Option<RetainedHelperOutput>,
    ) -> Result<T, QemuSpawnError>,
) -> Result<T::Received, QemuGuardedImagePreparationError> {
    #[cfg(target_os = "linux")]
    {
        let receiver = self.attempt_binding.helper_receiver.get().ok_or_else(|| {
            QemuGuardedImagePreparationError::local(helper_custody_refusal())
        })?;
        let controller = receiver.controller()
            .map_err(|_| QemuGuardedImagePreparationError::local(helper_custody_refusal()))?;
        controller.with_spawned_helper(receiver, command, operation, body)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, operation, body);
        Err(QemuGuardedImagePreparationError::local(helper_custody_refusal(),))
    }
}"#,
            1,
        ),
    ],
};

pub(super) const HELPER: Companion = Companion {
    path: source::PRE_VM_HELPER_RETURN.path,
    required: &[
        source::PRE_VM_HELPER_RETURN.required[0],
        source::PRE_VM_HELPER_RETURN.required[1],
        (
            r#"fn observe(&mut self, first: crate::QemuNodeError) {
    if self.first_cleanup.is_none() { self.first_cleanup = Some(first); }
    else if self.latest_cleanup.as_ref() != Some(&first) { self.latest_cleanup = Some(first); }
}
fn save_first(&mut self, first: crate::QemuSpawnError) {
    if self.first_cause().is_some() {
        return;
    }
    match self.first_journal.take() {
        Some(journal) => self.first = Some(journal.record(first)),
        // An unissued fixture can retain a local refusal in its existing
        // journal, but cannot publish a shared diagnostic without a payer.
        None => self.unshared_first = Some(first),
    }
}"#,
            1,
        ),
        (
            r#"impl Drop for HelperPost<'_> {
    fn drop(&mut self) {
        // Authenticate the retained action and sample its independent post even
        // when the helper body or its preceding check already refused.
        let boundary = self
            .effect
            .map_or(Ok(()), |(effect, receiver)| effect.check(receiver));
        let post = self.original.wait_slice();
        self.slot.source_after = boundary.err();
        self.slot.after = post.err();
        self.slot.panicked |= std::thread::panicking();
    }
}"#,
            1,
        ),
        (
            r#"pub(crate) fn with_spawned_helper<T: HelperOutput>(
        &self,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut crate::QemuNodeChild,
            &HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, crate::QemuSpawnError>,
    ) -> Result<T::Received, crate::spawn::QemuGuardedImagePreparationError> {
        self.with_spawned_helper_original(receiver, None, command, operation, body)
    }
pub(crate) fn with_spawned_helper_original<T: HelperOutput>(
        &self,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
        effect_original: Option<&crate::QemuHotForkSourceOriginal>,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut crate::QemuNodeChild,
            &HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, crate::QemuSpawnError>,
    ) -> Result<T::Received, crate::spawn::QemuGuardedImagePreparationError> {
        let refused = || {
            crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::spawn::helper_receiver::helper_custody_refusal(),
                receiver,
            )
        };
        if !receiver
            .controller()
            .is_ok_and(|current| std::ptr::eq(self, current.as_ref()))
        {
            return Err(crate::spawn::QemuGuardedImagePreparationError::local(
                crate::spawn::helper_receiver::helper_custody_refusal(),
            ));
        }
        let mut slot = self.helper.try_lock().map_err(|_| refused())?;
        if let Some(first) = &slot.first {
            return Err(crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::QemuSpawnError::HelperFailure {
                    first: first.clone(),
                },
                receiver,
            ));
        }
        if slot.first_journal.is_none()
            || slot.unshared_first.is_some()
            || (T::CAPTURES_PROBE && slot.probe_prepared)
            || slot.controls.is_some()
            || slot.panicked
            || slot.child.is_some()
            || slot.output.is_some()
            || slot.before.is_some()
        || slot.source_after.is_some()
            || slot.after.is_some()
            || slot.first_cleanup.is_some()
        {
            return Err(refused());
        }

        slot.lender = Some(receiver.clone());
        slot.effect_original = effect_original.cloned();
        let effect = slot.effect_original.clone();
        let original = effect
            .as_ref()
            .map_or(self.origin.as_ref(), |effect| effect.guard());
        let before = effect
            .as_ref()
            .map_or(Ok(()), |effect| effect.check(receiver))
            .and_then(|()| original.wait_slice());
        slot.before = before.as_ref().err().copied();
        let post = HelperPost {
            original,
            effect: effect.as_ref().map(|effect| (effect, receiver)),
            slot: &mut slot,
        };
        match before {
            Err(first) => post
                .slot
                .save_first(crate::QemuSpawnError::SourceAdmission {
                    source: first.into(),
                }),
            Ok(_) => self.run_helper(post.slot, original, command, operation, body),
        }
        drop(post);
        for first in [slot.source_after, slot.after].into_iter().flatten() {
            slot.save_first(crate::QemuSpawnError::SourceAdmission {
                source: first.into(),
            });
        }
        if let Some(first) = &slot.first {
            let _ = self.helper_first.set(first.clone());
        }
        self.settle_helper(&mut slot, receiver);
        if let Some(first) = &slot.first {
            return Err(crate::spawn::QemuGuardedImagePreparationError::issued(
                crate::QemuSpawnError::HelperFailure {
                    first: first.clone(),
                },
                receiver,
            ));
        }
        if slot.child.is_none() && slot.first_cleanup.is_none() && slot.output.is_some() {
            // The returned captures keep their original loan independently of
            // this controller. No raw Output can detach the funded buffers.
            let controls = slot.controls.take().ok_or_else(refused)?;
            let output = slot.output.take().ok_or_else(refused)?;
            let output = T::take(output).ok_or_else(refused)?;
            drop(slot.effect_original.take());
            return Ok(output.receive(controls));
        }
        Err(refused())
    }
fn run_helper<T: HelperOutput>(
        &self,
        slot: &mut HelperDebt,
        original: &HostOperationGuard,
        mut command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut crate::QemuNodeChild,
            &HostOperationGuard,
            &mut Option<RetainedHelperOutput>,
        ) -> Result<T, crate::QemuSpawnError>,
    ) {
        let controls = match self.reserve_helper_controls(original) {
            Ok(controls) => controls,
            Err(source) => {
                slot.save_first(crate::QemuSpawnError::SourceAdmission { source });
                return;
            }
        };
        slot.controls = Some(controls);
        slot.probe_prepared |= T::CAPTURES_PROBE;
        slot.output = T::prepare_storage();

        let child = match command.spawn() {
            Ok(child) => child,
            Err(source) => {
                slot.save_first(crate::QemuSpawnError::Io { operation, source });
                return;
            }
        };
        // Publish the actual child before pipe validation or any Original post.
        slot.child = Some(crate::node::RetainedChild::new(
            crate::QemuNodeChild::new(child),
            None,
        ));

        let result = match slot
            .child
            .as_mut()
            .and_then(crate::node::RetainedChild::direct_child_mut)
        {
            Some(child) => body(child, original, &mut slot.output),
            None => Err(crate::spawn::helper_receiver::helper_custody_refusal()),
        };
        match result {
            Ok(output) => slot.output = Some(output.retain()),
            Err(first) => slot.save_first(first),
        }
    }"#,
            1,
        ),
    ],
};

pub(super) const OWNER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/failed_launch.rs",
    required: &[(
        r#"pub(crate) struct RetainedChild {
    child: QemuNodeProcessControl,
    cleanup: shutdown_continuation::ChildShutdown,
    supervisor: Option<HostOperationSupervisor>,
}
impl RetainedChild {
    pub(crate) fn new(child: QemuNodeChild, supervisor: Option<&HostOperationSupervisor>) -> Self {
        Self {
            child: QemuNodeProcessControl::Direct(child),
            cleanup: shutdown_continuation::ChildShutdown::new(),
            supervisor: supervisor.cloned(),
        }
    }
    pub(crate) fn process_id(&self) -> u32 { self.child.process_id() }
    pub(crate) fn direct_child_mut(&mut self) -> Option<&mut QemuNodeChild> {
        match &mut self.child {
            QemuNodeProcessControl::Direct(child) => Some(child),
            QemuNodeProcessControl::External(_) => None,
        }
    }
    pub(crate) fn child_reaped(&self) -> bool { self.child.reaped() }
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_source_original(
        &mut self,
        original: crate::linux_attempt_host::SourceCleanupOriginal,
    ) { self.cleanup.retain_source_original(original); }
    pub(crate) fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
        let process = self.cleanup.close_unconstructed(&mut self.child, self.supervisor.as_ref());
        if !self.child.reaped() { return process.map(|_| ()); }
        let ram = self.cleanup.finish_ram(|original, history| match &mut self.child {
            QemuNodeProcessControl::Direct(child) => {
                #[cfg(target_os = "linux")]
                {
                    drop(child.ram_source_start.take());
                    history.source(1, &mut child.ram_source, original)
                }
                #[cfg(not(target_os = "linux"))]
                { true }
            }
            QemuNodeProcessControl::External(_) => false,
        });
        match (process, ram) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(first), Ok(())) | (Ok(_), Err(first)) => Err(first),
            (Err(first), Err(ram)) => Err(QemuNodeError::ShutdownAndRam {
                first: Box::new(first), ram: Box::new(ram),
            }),
        }
    }
}"#,
        1,
    )],
};

pub(super) const ORIGINAL: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/shutdown_continuation.rs",
    required: &[
        (
            r#"pub(super) const fn new() -> Self {
    Self {
        progress: crate::shutdown::QemuShutdownProgress::new(),
        begin_attempted: false,
        begin_returned: false,
        guard: None,
        ram: super::ram_cleanup::RamCleanup::new(),
        begin_failure: None,
        observations: [(None, None); 5],
        completion_attempted: false,
        completion_returned: false,
        completion_effect: false,
        completion_failure: None,
        ladder_attempted: false,
        history_pending: false,
    }
}"#,
            1,
        ),
        ("Self::Source(original) => original.original(),", 1),
        (
            "Self::Source(original) => crate::ram_control::RamCleanupOriginal::source(original),",
            1,
        ),
        (
            r#"pub(super) fn retain_source_original(
    &mut self,
    original: crate::linux_attempt_host::SourceCleanupOriginal,
) {
    if !self.begin_attempted {
        self.begin_failure = original.checked_original()
            .and_then(|original| original.verify_operation_class(HostOperationClass::Cleanup))
            .err();
        self.guard = Some(CleanupOriginal::Source(original));
        self.begin_attempted = true;
        self.begin_returned = true;
        self.history_pending = true;
    }
}"#,
            1,
        ),
        (
            r#"fn begin(&mut self, supervisor: Option<&HostOperationSupervisor>) {
    if self.begin_attempted { return; }
    self.begin_attempted = true;
    self.history_pending = true;
    match supervisor.map(|owner| owner.begin(HostOperationClass::Cleanup)).transpose() {
        Ok(guard) => {
            self.guard = guard.zip(supervisor)
                .map(|(original, supervisor)| CleanupOriginal::Owned {
                    original, supervisor: supervisor.clone(),
                })
        }
        Err(first) => self.begin_failure = Some(first),
    }
    self.begin_returned = true;
}"#,
            1,
        ),
        (
            r#"fn failed(&self) -> bool {
    (self.begin_attempted && !self.begin_returned)
        || (self.completion_attempted && !self.completion_returned)
        || self.begin_failure.is_some()
        || self.observations.iter().any(|(before, after)| before.is_some() || after.is_some())
        || self.completion_failure.is_some()
        || self.progress.failed()
        || self.ram.failed()
}
pub(super) fn health(&self) -> Result<(), QemuNodeError> {
    match (self.process_health(), self.ram.failure()) {
        (Ok(()), None) => Ok(()),
        (Err(first), None) | (Ok(()), Some(first)) => Err(first),
        (Err(first), Some(ram)) => Err(QemuNodeError::ShutdownAndRam {
            first: Box::new(first), ram: Box::new(ram),
        }),
    }
}
fn process_health(&self) -> Result<(), QemuNodeError> {
    if (self.begin_attempted && !self.begin_returned)
        || (self.completion_attempted && !self.completion_returned)
    {
        return Err(QemuNodeError::from_shutdown(
            crate::QemuShutdownError::Uncertain {
                rung: if !self.begin_returned { QemuShutdownRung::ControlQuit }
                    else { QemuShutdownRung::Reap },
            },
        ));
    }
    if self.begin_failure.is_some()
        || self.observations.iter().any(|(before, after)| before.is_some() || after.is_some())
        || self.completion_failure.is_some()
    {
        return Err(QemuNodeError::ShutdownOriginal {
            begin: self.begin_failure,
            observations: self.observations,
            completion_effect: self.completion_effect,
            completion: self.completion_failure,
            report: self.progress.report(),
        });
    }
    match self.progress.failure() {
        Some(source) => Err(QemuNodeError::from_shutdown(source)),
        None => Ok(()),
    }
}"#,
            1,
        ),
        (
            r#"pub(super) fn close_unconstructed(
    &mut self,
    child: &mut QemuNodeProcessControl,
    supervisor: Option<&HostOperationSupervisor>,
) -> Result<QemuShutdownReport, QemuNodeError> {
    self.close_process(
        child, None, None,
        QemuShutdownPolicy {
            control_quit_wait: Duration::ZERO,
            qmp_quit_wait: Duration::ZERO,
            sigterm_wait: Duration::ZERO,
            sigkill_wait: DROP_REAP_DEADLINE,
            reap_wait: DROP_REAP_DEADLINE,
        },
        supervisor, true,
    )
}"#,
            1,
        ),
        (
            r#"fn close_process<'plugin, 'qmp>(
    &mut self,
    child: &mut QemuNodeProcessControl,
    plugin_control: Option<&mut (dyn QemuPluginIpcControlChannel + 'plugin)>,
    qmp_machine_control: Option<&mut (dyn QemuQmpMachineControlChannel + 'qmp)>,
    policy: QemuShutdownPolicy,
    supervisor: Option<&HostOperationSupervisor>,
    containment: bool,
) -> Result<QemuShutdownReport, QemuNodeError> {
    let previously_reaped = self.progress.reaped;
    self.begin(supervisor);
    if child.reaped() {
        self.progress.observe_reaped();
    } else if self.begin_attempted {
        match child.try_wait_natural_exit() {
            Ok(_) if child.reaped() => self.progress.observe_reaped(),
            Ok(_) => {}
            Err(source) => {
                if self.progress.retain_observation_failure(source) { self.history_pending = true; }
            }
        }
    }
    if !self.progress.reaped {
        self.begin(supervisor);
        if self.begin_returned && self.begin_failure.is_none() {
            if !self.ladder_attempted {
                self.ladder_attempted = true;
                self.history_pending = true;
            }
            let mut target = QemuNodeShutdownTarget {
                child: &mut *child, plugin_control, qmp_machine_control, supervisor,
                guard: self.guard.as_ref().map(CleanupOriginal::original),
                observations: &mut self.observations,
                history_pending: &mut self.history_pending,
            };
            if containment { self.progress.advance_containment(&mut target, policy); }
            else { self.progress.advance(&mut target, policy); }
        }
    }
    if child.reaped() { self.progress.observe_reaped(); }
    if self.failed() && (!self.progress.reaped || self.history_pending) {
        self.history_pending = false;
        self.health()?;
    }
    if previously_reaped {
        return Ok(QemuShutdownReport {
            attempts: Vec::new(), failures: Vec::new(), reaped: true, leaked: false,
        });
    }
    Ok(self.progress.report())
}"#,
            1,
        ),
        (
            r#"pub(super) fn under_original<T: Copy>(
    &mut self,
    rung: QemuShutdownRung,
    effect: impl FnOnce(&mut Self) -> Result<T, QemuShutdownTargetError>,
) -> Result<T, QemuShutdownTargetError> {
    let (output, status) = self.under_original_observed(rung, effect);
    status?;
    output.ok_or_else(|| {
        QemuShutdownTargetError::new("child cleanup rung", "returned output is absent")
    })
}
pub(super) fn under_original_observed<T>(
    &mut self,
    rung: QemuShutdownRung,
    effect: impl FnOnce(&mut Self) -> Result<T, QemuShutdownTargetError>,
) -> (Option<T>, Result<(), QemuShutdownTargetError>) {
    let index = match rung {
        QemuShutdownRung::ControlQuit => 0,
        QemuShutdownRung::QmpQuit => 1,
        QemuShutdownRung::Sigterm => 2,
        QemuShutdownRung::Sigkill => 3,
        QemuShutdownRung::Reap => 4,
    };
    let original = self.guard;
    let before = original.and_then(|original| original.wait_slice().err());
    let work = match before {
        Some(first) => {
            if self.observations[index].0.is_none() {
                self.observations[index].0 = Some(first);
                *self.history_pending = true;
            }
            Err(QemuShutdownTargetError::new("enter child cleanup rung", first.to_string(),))
        }
        None => effect(self),
    };
    let (output, first) = match work {
        Ok(output) => (Some(output), None),
        Err(first) => (None, Some(first)),
    };
    let after = original.and_then(|original| original.wait_slice().err());
    if let Some(after) = after {
        if self.observations[index].1.is_none() {
            self.observations[index].1 = Some(after);
            *self.history_pending = true;
        }
    }
    let status = match (first, after) {
        (Some(first), _) => Err(first),
        (None, Some(after)) => Err(QemuShutdownTargetError::new("post child cleanup rung", after.to_string(),)),
        (None, None) => Ok(()),
    };
    (output, status)
}"#,
            1,
        ),
        super::super::super::construction_endpoint::NODE_COMPLETION.required[0],
    ],
};

pub(super) const WAIT: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/shutdown_budget.rs",
    required: &[(
        r#"pub(super) fn wait_for_live_exit(&mut self) -> Result<QemuChildWait, QemuShutdownTargetError> {
    let guard = self.guard.ok_or_else(|| {
        QemuShutdownTargetError::new("wait for cleanup", "live cleanup guard is absent")
    })?;
    let supervisor = self.supervisor.ok_or_else(|| {
        QemuShutdownTargetError::new("wait for cleanup", "live cleanup owner is absent")
    })?;
    let started = Instant::now();
    loop {
        if self.child.reaped() || self.child.try_wait_natural_exit()?.is_some() {
            return Ok(QemuChildWait::Exited);
        }
        guard.wait_slice().map_err(|source| {
            QemuShutdownTargetError::new("wait for cleanup", source.to_string())
        })?;
        let (_, budgets) = supervisor.budgets().map_err(|source| {
            QemuShutdownTargetError::new("observe cleanup policy", source.to_string())
        })?;
        let budget = budgets.classes[HostOperationClass::Cleanup as usize];
        let allowance = [budget.total_timeout, budget.progress_timeout]
            .into_iter().flatten().min().ok_or_else(|| {
                QemuShutdownTargetError::new("observe cleanup policy", "cleanup has no finite class allowance",)
            })?;
        if started.elapsed() >= allowance / 5 { return Ok(QemuChildWait::StillRunning); }
        guard.wait_for_change().map_err(|source| {
            QemuShutdownTargetError::new("wait for cleanup", source.to_string())
        })?;
    }
}"#,
        1,
    )],
};

pub(super) const ACTUAL_CHILD: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/child.rs",
    required: &[
        ("use super::*;", 1),
        ("impl QemuNodeChild {", 1),
        ("impl Drop for QemuNodeChild {", 1),
        (
            r#"pub(crate) const fn new(child: Child) -> Self {
    Self {
        child: source_child::OwnedNodeChild::Ordinary(child),
        reaped: false,
        #[cfg(target_os = "linux")]
        ram_source: None,
        #[cfg(target_os = "linux")]
        ram_source_start: None,
        #[cfg(target_os = "linux")]
        launch_cleanup: None,
        #[cfg(target_os = "linux")]
        original_plugin_startup: None,
        #[cfg(target_os = "linux")]
        preexec_setup: None,
        #[cfg(target_os = "linux")]
        checkpoint_original: None,
    }
}"#,
            1,
        ),
        ("pub const fn reaped(&self) -> bool { self.reaped }", 1),
        (
            r#"pub(super) fn mark_reaped(&mut self) {
    self.reaped = true;
    #[cfg(target_os = "linux")]
    if let Some(original) = self.checkpoint_original.as_mut() { original.retire_after_reap(); }
    #[cfg(target_os = "linux")]
    if let Some(startup) = self.original_plugin_startup.as_mut() { startup.retire_workspace_after_reap(); }
    #[cfg(target_os = "linux")]
    if let Some(cleanup) = &self.launch_cleanup { cleanup.child_reaped(); }
}"#,
            1,
        ),
        (
            r#"pub fn try_wait_natural_exit(
    &mut self,
) -> Result<Option<std::process::ExitStatus>, QemuShutdownTargetError> {
    self.try_wait_natural_exit_raw().map_err(ChildNaturalWaitFailure::into_shutdown_error)
}
pub(crate) fn try_wait_natural_exit_raw(
    &mut self,
) -> Result<Option<std::process::ExitStatus>, ChildNaturalWaitFailure> {
    if self.reaped {
        return Err(ChildNaturalWaitFailure::AlreadyReaped);
    }
    match self.child.try_wait() {
        Ok(Some(status)) => { self.mark_reaped(); Ok(Some(status)) }
        Ok(None) => Ok(None),
        Err(source) => Err(ChildNaturalWaitFailure::Io(source)),
    }
}"#,
            1,
        ),
    ],
};

pub(super) const SHUTDOWN_TARGET: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node.rs",
    required: &[
        ("mod child;", 1),
        ("impl QemuNodeChild {", 0),
        ("impl Drop for QemuNodeChild {", 0),
        (
            r#"pub(crate) enum ChildNaturalWaitFailure {
    AlreadyReaped,
    Io(std::io::Error),
}
impl ChildNaturalWaitFailure {
    fn into_shutdown_error(self) -> QemuShutdownTargetError {
        match self {
            Self::AlreadyReaped => {
                QemuShutdownTargetError::new("poll natural QEMU exit", "child was already reaped")
            }
            Self::Io(source) => {
                QemuShutdownTargetError::new("poll natural QEMU exit", source.to_string())
            }
        }
    }
}"#,
            1,
        ),
        (
            r#"fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
    self.under_original(QemuShutdownRung::Sigkill, |target| { target.child.send_sigkill() })
}
fn wait_for_exit_observed(
    &mut self,
    rung: QemuShutdownRung,
    timeout: Duration,
) -> (Option<QemuChildWait>, Result<(), QemuShutdownTargetError>) {
    self.under_original_observed(rung, |target| {
        if target.guard.is_some() { target.wait_for_live_exit() }
        else { target.child.wait_for_exit(rung, timeout) }
    })
}
fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
    self.under_original(QemuShutdownRung::Reap, |target| {
        if target.guard.is_none() { return target.child.reap(timeout); }
        target.wait_for_live_exit().map(|state| match state {
            QemuChildWait::Exited => QemuReap::Reaped,
            QemuChildWait::StillRunning => QemuReap::StillAlive,
        })
    })
}"#,
            1,
        ),
    ],
};

pub(super) const PROCESS_CONTROL: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/process_control.rs",
    required: &[
        (
            r#"pub(super) fn reaped(&self) -> bool {
    match self { Self::Direct(child) => child.reaped(), Self::External(child) => child.control.reaped(), }
}"#,
            1,
        ),
        (
            r#"pub(super) fn try_wait_natural_exit(
    &mut self,
) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
    match self {
        Self::Direct(child) => child.try_wait_natural_exit(),
        Self::External(child) => {
            let result = child.control.try_wait_natural_exit();
            #[cfg(target_os = "linux")]
            child.observe_reap();
            result
        }
    }
}"#,
            1,
        ),
    ],
};

pub(super) const LADDER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/shutdown/continuation.rs",
    required: &[
        (
            r#"pub(crate) const fn new() -> Self {
    Self {
        next: 0,
        entered: None,
        attempts: [None; 4],
        failures: [const { None }; 6],
        failure: None,
        reaped: false,
        reap_attempted: false,
    }
}
pub(crate) fn observe_reaped(&mut self) { self.reaped = true; }
pub(crate) fn failed(&self) -> bool { self.entered.is_some() || self.failure.is_some() }
pub(crate) fn retain_observation_failure(&mut self, source: QemuShutdownTargetError) -> bool {
    if self.failures[5].is_some() { return false; }
    self.failures[5] = Some(QemuShutdownFailure { rung: QemuShutdownRung::Reap, source, });
    if self.failure.is_none() { self.failure = Some(Failure::Target(5)); }
    true
}
pub(crate) fn failure(&self) -> Option<QemuShutdownError> {
    if let Some(rung) = self.entered { return Some(QemuShutdownError::Uncertain { rung }); }
    match self.failure {
        Some(Failure::Target(index)) => {
            self.failures[index].as_ref().map(|failure| QemuShutdownError::Target {
                rung: failure.rung, source: failure.source.clone(), report: self.report(),
            })
        }
        Some(Failure::Leaked) => Some(QemuShutdownError::LeakedChild { report: self.report(), }),
        None => None,
    }
}
pub(crate) fn report(&self) -> QemuShutdownReport {
    QemuShutdownReport {
        attempts: self.attempts.iter().flatten().copied().collect(),
        failures: self.failures.iter().flatten().cloned().collect(),
        reaped: self.reaped,
        leaked: matches!(self.failure, Some(Failure::Leaked)),
    }
}"#,
            1,
        ),
        (
            r#"pub(crate) fn advance_containment<T: QemuShutdownTarget>(
    &mut self,
    target: &mut T,
    policy: QemuShutdownPolicy,
) {
    if self.entered.is_none() && !self.failed() { self.next = self.next.max(3); }
    self.advance(target, policy);
}
pub(crate) fn advance<T: QemuShutdownTarget>(
    &mut self,
    target: &mut T,
    policy: QemuShutdownPolicy,
) {
    if target.child_reaped() { self.observe_reaped(); }
    if self.failed() || self.reaped { return; }
    let rungs = [
        (QemuShutdownRung::ControlQuit, policy.control_quit_wait),
        (QemuShutdownRung::QmpQuit, policy.qmp_quit_wait),
        (QemuShutdownRung::Sigterm, policy.sigterm_wait),
        (QemuShutdownRung::Sigkill, policy.sigkill_wait),
    ];
    while let Some(&(rung, wait)) = rungs.get(self.next) {
        if self.attempts.iter().flatten().any(|attempt| attempt.child == QemuChildWait::Exited) { break; }
        if target.child_reaped() { self.observe_reaped(); break; }
        let index = self.next;
        self.next += 1;
        self.entered = Some(rung);
        let effect = execute_shutdown_rung(target, rung);
        let effect_failed = effect.is_err();
        if let Err(source) = effect { self.failures[index] = Some(QemuShutdownFailure { rung, source }); }
        if target.child_reaped() { self.observe_reaped(); self.entered = None; break; }
        if effect_failed { self.entered = None; continue; }
        let (output, status) = target.wait_for_exit_observed(rung, wait);
        self.attempts[index] = Some(QemuShutdownAttempt {
            rung, wait, child: output.unwrap_or(QemuChildWait::StillRunning),
        });
        if let Err(source) = status { self.failures[index] = Some(QemuShutdownFailure { rung, source }); }
        self.entered = None;
        if target.child_reaped() { self.observe_reaped(); break; }
        if output == Some(QemuChildWait::Exited) { break; }
    }
    if target.child_reaped() { self.observe_reaped(); }
    if !self.reaped && !self.reap_attempted {
        self.reap_attempted = true;
        self.entered = Some(QemuShutdownRung::Reap);
        match target.reap(policy.reap_wait) {
            Ok(QemuReap::Reaped) => self.reaped = true,
            Ok(QemuReap::StillAlive) => self.failure = Some(Failure::Leaked),
            Err(source) => {
                self.failures[4] = Some(QemuShutdownFailure { rung: QemuShutdownRung::Reap, source, });
                self.failure = Some(Failure::Target(4));
            }
        }
        self.entered = None;
    }
}"#,
            1,
        ),
    ],
};

pub(super) const OWNED_WAIT: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/source_child.rs",
    required: &[
        ("use std::process::{Child, ExitStatus};", 1),
        (
            r#"pub(crate) enum OwnedNodeChild {
    Ordinary(Child),
    #[cfg(target_os = "linux")]
    Source(crucible_host_resources::host_services::process_birth::AuthenticatedSourceChild),
}"#,
            1,
        ),
        (
            r#"pub(super) fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
    match self {
        Self::Ordinary(child) => child.try_wait(),
        #[cfg(target_os = "linux")]
        Self::Source(child) => child.try_wait(),
    }
}"#,
            1,
        ),
    ],
};
