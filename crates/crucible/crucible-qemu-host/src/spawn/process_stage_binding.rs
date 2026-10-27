//! Preserves the private identity of one retained process-stage contract.
//!
//! This witness authenticates the existing attempt allocation. It grants no
//! process, descriptor, resource allowance, cancellation event, or deadline.

use std::sync::{Arc, Weak};

use super::{AttemptResourceBinding, QemuChildProcessContract};

/// Retains the private identity of the contract that entered a process stage.
///
/// The witness cannot be cloned or reconstructed from process identifiers or
/// numeric limits. Its containing stage prepays the retained allocation header
/// and frees the witness before refunding that custody.
pub struct QemuProcessStageBinding {
    attempt: Weak<AttemptResourceBinding>,
}

/// Refuses a contract outside the retained stage's actual attempt.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("process stage contract is not current")]
pub struct QemuProcessStageIdentityError;

impl QemuProcessStageBinding {
    /// Returns the checked allocation extent retained by this weak witness.
    ///
    /// This distinct header custody outlives a possible last strong contract.
    /// The witness's inline extent belongs to its containing stage body.
    #[must_use]
    pub fn retained_control_bytes() -> Option<u64> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<AttemptResourceBinding>())
        .ok()?;
        u64::try_from(layout.pad_to_align().size()).ok()
    }
}

impl QemuChildProcessContract {
    /// Retains this contract's private identity for its entered process stage.
    ///
    /// The actual issuer prepays the target-sized witness and retained header
    /// before this operation. No descriptor or allocation is created here.
    #[must_use]
    pub fn retain_process_stage_binding(&self) -> QemuProcessStageBinding {
        QemuProcessStageBinding {
            attempt: Arc::downgrade(&self.attempt_binding),
        }
    }

    /// Verifies this contract against the actual retained stage identity.
    ///
    /// # Errors
    /// Refuses a separately created attempt even when every limit is equal.
    pub fn verify_process_stage_binding(
        &self,
        binding: &QemuProcessStageBinding,
    ) -> Result<(), QemuProcessStageIdentityError> {
        if Weak::ptr_eq(&binding.attempt, &Arc::downgrade(&self.attempt_binding)) {
            Ok(())
        } else {
            Err(QemuProcessStageIdentityError)
        }
    }
}

/// Pins the existing contract allocation until physical aliases have closed.
///
/// The containing fixed target loan pays this same allocation before contract
/// birth. Retaining this pin allocates nothing and lends no launch authority.
pub(crate) struct QemuProcessStageRetirement {
    attempt: Option<Arc<AttemptResourceBinding>>,
}

impl QemuChildProcessContract {
    pub(crate) fn retain_process_stage_retirement(&self) -> QemuProcessStageRetirement {
        QemuProcessStageRetirement {
            attempt: Some(Arc::clone(&self.attempt_binding)),
        }
    }
}

impl QemuProcessStageRetirement {
    /// Closes only the uniquely retained, physically retired contract allocation.
    ///
    /// Callers separately prove process and cgroup retirement. Surviving strong
    /// contracts or weak stage witnesses refuse without dropping this same pin.
    pub(crate) fn close(&mut self) -> Result<(), QemuProcessStageIdentityError> {
        let attempt = self.attempt.as_mut().ok_or(QemuProcessStageIdentityError)?;
        Arc::get_mut(attempt).ok_or(QemuProcessStageIdentityError)?;
        drop(self.attempt.take());
        Ok(())
    }
}

impl Drop for QemuProcessStageRetirement {
    fn drop(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            std::mem::forget(attempt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> QemuChildProcessContract {
        let (control, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        QemuChildProcessContract::for_test(control.into(), event, 4096)
    }

    #[test]
    fn physical_target_pin_waits_for_actual_contract_and_stage_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = contract();
        let stage = contract.retain_process_stage_binding();
        let mut retirement = contract.retain_process_stage_retirement();
        let alias = contract.try_clone_for_attempt_generation()?;
        drop(contract);

        assert!(retirement.close().is_err());
        drop(alias);
        assert!(retirement.close().is_err());

        drop(stage);
        retirement.close()?;
        assert!(retirement.close().is_err());
        Ok(())
    }

    #[test]
    fn process_stage_binding_accepts_only_the_same_retained_attempt() {
        let original = contract();
        let binding = original.retain_process_stage_binding();
        let duplicate = original.try_clone_for_attempt_generation().unwrap();
        let foreign = contract();

        assert!(duplicate.verify_process_stage_binding(&binding).is_ok());
        assert!(foreign.verify_process_stage_binding(&binding).is_err());
        drop(original);
        assert!(duplicate.verify_process_stage_binding(&binding).is_ok());
        assert!(QemuProcessStageBinding::retained_control_bytes().unwrap() > 0);
    }
}
