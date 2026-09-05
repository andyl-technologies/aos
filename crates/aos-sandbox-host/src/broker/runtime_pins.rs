//! Physical payload continuity across separately authorized assignment updates.
//!
//! An opaque scope handle identifies simultaneously retained live execution
//! pins. It is not a runtime resource handle, assignment fence, or permission.
//! Reindexing the same execution under new assignment metadata must not mint
//! another namespace generation and trigger another assignment update.

use super::{HostRuntimeIdentity, PinnedLeader, PinnedPayloadLeader, Result, RetainedRuntimePins};
use crate::HostError;

impl RetainedRuntimePins {
    /// Preserves a scope only after comparing two complete live kernel proofs.
    ///
    /// The broker must independently admit the new assignment before selecting
    /// these pins. This method never transfers the prior assignment's authority.
    /// Dead, replaced, or uncheckable prior pins yield no continuity; no audit
    /// or numeric PID can reconstruct a lost proof. The new payload must also
    /// pass its own kernel check before the broker publishes any scope.
    ///
    /// # Errors
    ///
    /// Returns an error if retained root descriptors cannot be inspected.
    pub(crate) fn scope_for_observation(
        &self,
        prior_identity: &HostRuntimeIdentity,
        identity: &HostRuntimeIdentity,
        invocation: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
    ) -> Result<Option<[u8; 32]>> {
        if !same_incarnation(prior_identity, identity)
            || invocation != self.invocation_id
            || supervisor.handle() != self.supervisor.handle()
            || !payload.has_same_cgroup(&self.payload)
            || payload.relative_cgroup_hint() != self.payload.relative_cgroup_hint()
            || payload.mount().identity() != self.payload.mount().identity()
            || payload.network().identity() != self.payload.network().identity()
        {
            return Ok(None);
        }

        let prior_root = rustix::fs::fstat(self.payload.root())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let current_root = rustix::fs::fstat(payload.root())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if (prior_root.st_dev, prior_root.st_ino) != (current_root.st_dev, current_root.st_ino)
            || self.recheck_kernel().is_err()
            || payload.recheck_kernel(supervisor).is_err()
        {
            return Ok(None);
        }
        let same_payload = self
            .payload
            .pidfd()
            .info()
            .ok()
            .zip(payload.pidfd().info().ok())
            .is_some_and(|(prior, current)| prior == current);
        let same_supervisor = self
            .supervisor
            .pidfd()
            .info()
            .ok()
            .zip(supervisor.pidfd().info().ok())
            .is_some_and(|(prior, current)| prior == current);
        if !same_payload || !same_supervisor || self.recheck_kernel().is_err() {
            return Ok(None);
        }
        Ok(Some(self.scope_handle))
    }
}

fn same_incarnation(prior: &HostRuntimeIdentity, current: &HostRuntimeIdentity) -> bool {
    prior.sandbox_id() == current.sandbox_id() && prior.incarnation_id() == current.incarnation_id()
}

#[cfg(test)]
mod tests {
    //! Metadata filtering tests; live continuity is qualified in the worker VM.

    use super::*;

    #[test]
    fn assignment_updates_do_not_change_the_physical_incarnation_selector() {
        let prior = HostRuntimeIdentity::new([1; 16], [2; 16], 3, 4, [5; 32]);
        let current = HostRuntimeIdentity::new([1; 16], [2; 16], 6, 7, [8; 32]);
        assert!(same_incarnation(&prior, &current));
        assert!(!same_incarnation(
            &prior,
            &HostRuntimeIdentity::new([9; 16], [2; 16], 3, 4, [5; 32])
        ));
        assert!(!same_incarnation(
            &prior,
            &HostRuntimeIdentity::new([1; 16], [9; 16], 3, 4, [5; 32])
        ));
    }
}
