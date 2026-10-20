//! Retained original attempt identity for the ordinary guarded QEMU constructor.
//!
//! This private host identity is not serialized, exported to the guest, or a
//! substitute for source/class/native readiness and whole-resource qualification.

use std::{sync::Arc, thread::ThreadId};

use super::{AttemptResourceBinding, QemuChildProcessContract, QemuSpawnError, invalid_input};

#[derive(Debug)]
pub(crate) struct OriginalQemuLaunchBinding {
    creator_pid: u32,
    thread: ThreadId,
    attempt: Arc<AttemptResourceBinding>,
}

impl QemuChildProcessContract {
    pub(crate) fn retain_original_launch_binding(&self) -> OriginalQemuLaunchBinding {
        OriginalQemuLaunchBinding {
            creator_pid: std::process::id(),
            thread: std::thread::current().id(),
            attempt: Arc::clone(&self.attempt_binding),
        }
    }
}

impl OriginalQemuLaunchBinding {
    pub(crate) fn authenticate(
        &self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if std::process::id() != self.creator_pid {
            return Err(invalid_input(
                "authenticate original QEMU launch",
                "original attempt belongs to another creator process",
            ));
        }
        if std::thread::current().id() != self.thread {
            return Err(invalid_input(
                "authenticate original QEMU launch",
                "original attempt belongs to another owning thread",
            ));
        }
        if !Arc::ptr_eq(&self.attempt, &contract.attempt_binding) {
            return Err(invalid_input(
                "authenticate original QEMU launch",
                "different original attempt process contract",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Assertions and fixture setup panics are the test oracle.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs::File;

    // Only private alias/current-origin logic is exercised here. These inert
    // descriptors are not cgroup/eventfd credentials and must never be passed
    // to a real guarded launcher. A matching alias does not imply native rights.
    fn inert_contract() -> QemuChildProcessContract {
        QemuChildProcessContract {
            cgroup_directory: None,
            cgroup_procs: File::open("/dev/null").unwrap().into(),
            cancellation_event: File::open("/dev/null").unwrap().into(),
            maximum_vcpus: 1,
            maximum_resident_bytes: 1024,
            maximum_writable_bytes: 0,
            credentials: None,
            attempt_binding: Arc::new(AttemptResourceBinding),
            exact_checkpoint_root: None,
        }
    }

    #[test]
    fn same_original_clone_matches_but_equal_foreign_contract_refuses() {
        let original = inert_contract();
        let binding = original.retain_original_launch_binding();
        let clone = original.try_clone_for_attempt_generation().unwrap();
        let foreign = inert_contract();

        assert!(binding.authenticate(&original).is_ok());
        assert!(binding.authenticate(&clone).is_ok());
        assert!(binding.authenticate(&foreign).is_err());
        assert!(Arc::ptr_eq(&binding.attempt, &clone.attempt_binding));
        assert!(!Arc::ptr_eq(&binding.attempt, &foreign.attempt_binding));
    }

    #[test]
    fn creator_origin_refuses_before_thread_and_private_attempt_match() {
        let original = inert_contract();
        let mut binding = original.retain_original_launch_binding();
        binding.creator_pid = binding.creator_pid.checked_add(1).unwrap();
        let foreign = inert_contract();

        assert!(
            binding
                .authenticate(&foreign)
                .unwrap_err()
                .to_string()
                .contains("creator process")
        );
    }
}
