//! Routes helper births into their constructor-bound issued Source recipient.
//!
//! The contract keeps only weak nominal links. The source's existing fixed
//! controller owns the child before any pipe validation or independent post.

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
        body: impl FnOnce(&mut QemuNodeChild) -> Result<T, QemuSpawnError>,
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
