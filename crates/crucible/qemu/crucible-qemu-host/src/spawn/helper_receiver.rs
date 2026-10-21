//! Routes helper births into their constructor-bound issued Source recipient.
//!
//! The contract keeps only weak nominal links. The source's existing fixed
//! controller owns the child before any pipe validation or independent post.
//! Polling borrows that same creation Original; a command limit cannot renew it.

use super::*;

impl QemuChildProcessContract {
    /// Projects an inert weak identity for this contract's genuine helper owner.
    ///
    /// The actual first-bound Source lender validates its active incarnation
    /// before this projection. The weak reference grants no helper effect,
    /// Cleanup, return loan or funding; cleanup still uses that owner's saved
    /// lender and Original. Missing or unavailable custody returns `None`.
    #[must_use]
    pub fn issued_helper_receiver(
        &self,
    ) -> Option<std::sync::Weak<crate::OriginalNativeFreshLaunchError>> {
        let lender = self.attempt_binding.helper_receiver.get()?;
        let controller = lender.controller().ok()?;
        Some(std::sync::Arc::downgrade(&controller))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bind_helper_receiver(
        &self,
        receiver: crate::linux_attempt_host::SourceCleanupLender,
    ) -> Result<(), QemuSpawnError> {
        if let Some(bound) = self.attempt_binding.helper_receiver.get() {
            return if bound.same_identity(&receiver) {
                Ok(())
            } else {
                Err(helper_custody_refusal())
            };
        }
        self.attempt_binding
            .helper_receiver
            .set(receiver)
            .map_err(|_| helper_custody_refusal())
    }

    /// Validates the actual first-bound helper recipient before any birth.
    ///
    /// # Errors
    /// Refuses absent, expired, mismatched or unavailable Source custody.
    pub fn require_issued_helper_receiver(&self) -> Result<(), QemuSpawnError> {
        #[cfg(target_os = "linux")]
        {
            let lender = self
                .attempt_binding
                .helper_receiver
                .get()
                .ok_or_else(helper_custody_refusal)?;
            lender
                .controller()
                .map(|_| ())
                .map_err(|_| helper_custody_refusal())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(helper_custody_refusal())
        }
    }

    pub(super) fn with_spawned_helper<T: HelperOutput>(
        &self,
        command: Command,
        operation: &'static str,
        body: impl FnOnce(
            &mut QemuNodeChild,
            &crucible_host_resources::host_supervision::HostOperationGuard,
        ) -> Result<T, QemuSpawnError>,
    ) -> Result<T, QemuGuardedImagePreparationError> {
        #[cfg(target_os = "linux")]
        {
            let receiver =
                self.attempt_binding.helper_receiver.get().ok_or_else(|| {
                    QemuGuardedImagePreparationError::local(helper_custody_refusal())
                })?;
            let controller = receiver
                .controller()
                .map_err(|_| QemuGuardedImagePreparationError::local(helper_custody_refusal()))?;
            controller.with_spawned_helper(receiver, command, operation, body)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, operation, body);
            Err(QemuGuardedImagePreparationError::local(
                helper_custody_refusal(),
            ))
        }
    }
}

pub(crate) fn helper_custody_refusal() -> QemuSpawnError {
    invalid_input(
        "retain guarded helper",
        "issued helper custody is unavailable or still occupied",
    )
}

/// Borrows the creation Original's remaining slice without entering new work.
///
/// # Errors
/// Preserves the same Original's cancellation, expiry or supervision refusal.
pub(super) fn wait_slice(
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
) -> Result<Duration, QemuSpawnError> {
    original
        .wait_slice()
        .map_err(|source| QemuSpawnError::SourceAdmission {
            source: source.into(),
        })
}

/// Observes an image helper under its creator's existing operation.
///
/// # Errors
/// Preserves operation refusal, command timeout, unsuccessful exit or wait IO.
/// The caller retains the child and remains responsible for physical cleanup.
pub(super) fn wait_image_tool(
    child: &mut QemuNodeChild,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
    operation: &'static str,
) -> Result<(), QemuSpawnError> {
    let deadline = HostSupervisionDeadline::start(GUARDED_IMAGE_TOOL_TIMEOUT);
    loop {
        // The command limit can only tighten the saved Original. A local
        // timeout never permits polling or waiting after that Original refuses.
        let remaining = wait_slice(original)?;
        match child.try_wait_natural_exit_raw() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(QemuSpawnError::GuardedImageTool { operation, status });
            }
            Ok(None) if deadline.has_time_remaining() => {
                thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL.min(remaining));
            }
            Ok(None) => {
                return Err(QemuSpawnError::GuardedImageToolTimeout { operation });
            }
            Err(error) => return Err(QemuSpawnError::from_helper_wait(operation, error)),
        }
    }
}

/// Moves either existing helper output into the same fixed recipient journal.
pub(crate) trait HelperOutput: Sized {
    fn retain(self) -> RetainedHelperOutput;
    fn take(output: RetainedHelperOutput) -> Option<Self>;
}

pub(crate) enum RetainedHelperOutput {
    Image,
    Probe(std::process::Output),
}

impl HelperOutput for () {
    fn retain(self) -> RetainedHelperOutput {
        RetainedHelperOutput::Image
    }
    fn take(output: RetainedHelperOutput) -> Option<Self> {
        match output {
            RetainedHelperOutput::Image => Some(()),
            _ => None,
        }
    }
}

impl HelperOutput for std::process::Output {
    fn retain(self) -> RetainedHelperOutput {
        RetainedHelperOutput::Probe(self)
    }
    fn take(output: RetainedHelperOutput) -> Option<Self> {
        match output {
            RetainedHelperOutput::Probe(output) => Some(output),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    const CHILD_WAIT: &str = "CRUCIBLE_HELPER_ORIGINAL_WAIT_COMPONENT";
    const CHILD_CASE: &str = "spawn::helper_receiver::tests::image_wait_component_child";

    // These controls exercise the production wait with a real process and a
    // component Original. They issue no native Source, receiver or funding.
    #[test]
    fn image_wait_retains_the_live_child_when_its_same_original_is_canceled()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE])
            .env(CHILD_WAIT, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = QemuNodeChild::new(child);
        assert!(child.try_wait_natural_exit_raw().unwrap().is_none());

        // Cancellation occurs after process birth and the creation entry cut.
        original.wait_slice()?;
        supervisor.cancel()?;
        let first = original.wait_slice().unwrap_err();
        let observed = wait_image_tool(&mut child, &original, "component image wait");

        assert!(matches!(
            observed,
            Err(QemuSpawnError::SourceAdmission {
                source: crate::linux_attempt_host::OriginalActorAccountError::Supervision(source),
            }) if source == first
        ));
        assert!(child.try_wait_natural_exit_raw().unwrap().is_none());
        // The process owner, rather than the wait's returned error, still
        // performs physical containment and reap on this component path.
        drop(child);
        Ok(())
    }

    #[test]
    fn image_wait_observes_success_under_the_existing_original()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let operation_id = original.status()?.operation_id;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE])
            .env_remove(CHILD_WAIT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = QemuNodeChild::new(child);

        wait_image_tool(&mut child, &original, "component image wait")?;

        assert_eq!(original.status()?.operation_id, operation_id);
        original.complete()?;
        Ok(())
    }

    #[test]
    fn image_wait_component_child() -> std::io::Result<()> {
        if std::env::var_os(CHILD_WAIT).is_some() {
            std::io::copy(&mut std::io::stdin(), &mut std::io::sink())?;
        }
        Ok(())
    }
}
