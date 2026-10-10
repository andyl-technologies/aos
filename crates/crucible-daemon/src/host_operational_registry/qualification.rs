//! Native qualification exercises beneath the unqualified public policy gate.
//!
//! This module exists only in test binaries. Its caller must launch through the
//! real executor actor and retain the complete original execution peak. It does
//! not issue deployment evidence, enable capabilities, or release reservations.

use super::*;
use crucible_protocol::ram_control::RamControlDisposition;

impl HostOperationalRegistry {
    /// Exercises placement using the genuinely admitted independent controller.
    ///
    /// Qualification must test the underlying mechanism before its evidence can
    /// authorize public policy changes. This test-only entry retains every
    /// original resource and keeps the live observation revisions coherent.
    ///
    /// # Errors
    /// Refuses a stale target, absent client, reduced peak, changed supervision,
    /// invalid policy, failed controller exchange, or inconsistent observation.
    pub(crate) fn apply_native_qualification_policy(
        &self,
        target: HostRamTarget,
        resident_target_bytes: u64,
    ) -> Result<(), HostOperationalError> {
        self.apply_native_qualification_mode(target, HostRamMode::Managed, resident_target_bytes)
    }

    /// Exercises a strict mode beneath the public qualification gate.
    ///
    /// # Errors
    /// Refuses missing genuine native custody, changed complete resources or
    /// supervision, and any mode the real manager cannot accept.
    pub(crate) fn apply_native_qualification_mode(
        &self,
        target: HostRamTarget,
        mode: HostRamMode,
        resident_target_bytes: u64,
    ) -> Result<(), HostOperationalError> {
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        let owner = self.node(target)?;
        let _owner_transaction = owner.mutation.try_lock().map_err(unavailable)?;
        let previous = {
            let state = owner.state.lock().map_err(unavailable)?;
            output::policy_snapshot(&state)
        };
        let cap = owner.supervisor.outer_cap_status().map_err(unavailable)?;
        if cap.state != HostOperationState::Running
            || previous.transition.is_some()
            || previous.admitted_resources.resident_peak_bytes
                < owner.capabilities.logical_ram_bytes
            || resident_target_bytes > owner.capabilities.logical_ram_bytes
        {
            return Err(HostOperationalError::Unavailable);
        }

        let mut policy = previous.requested_policy;
        policy.mode = mode;
        policy.resident_target_bytes = resident_target_bytes;
        policy.eviction_preference = 100;
        let revision = previous
            .policy_revision
            .checked_add(1)
            .ok_or(HostOperationalError::Unavailable)?;
        let mut client = owner.client.try_lock().map_err(unavailable)?;
        let reply = client
            .as_mut()
            .ok_or(HostOperationalError::Unavailable)?
            .apply(
                previous.policy_revision,
                revision,
                previous.reservation_revision,
                policy,
                previous.admitted_resources,
            )
            .map_err(unavailable)?;
        if reply.disposition != RamControlDisposition::Accepted
            || reply.requested_policy_revision != revision
            || reply.reservation_revision != previous.reservation_revision
        {
            return Err(HostOperationalError::Unavailable);
        }

        let mut status = owner.state.lock().map_err(unavailable)?;
        status.policy_revision = revision;
        status.requested_policy = policy;
        mutation::observe_reply(&mut status, reply, policy, revision)?;
        Ok(())
    }
}
