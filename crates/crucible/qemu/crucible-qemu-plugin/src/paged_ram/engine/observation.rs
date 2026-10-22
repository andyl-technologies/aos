//! Observes retained placement without scanning RAM or touching guest mappings.
//!
//! An application revision is an acknowledgement, not a physical measurement.
//! Only live verified lock custody proves resident-required convergence here;
//! disk receipts describe historical preservation and cannot prove a fresh cut.

// SPDX-License-Identifier: GPL-2.0-or-later

use crucible_qemu_protocol::ram_control::{
    RamControlConvergence, RamControlMode, RamControlPlacementReceipt, RamControlPolicy,
};

use super::*;

/// One bounded observation of the same retained policy and mapping owner.
pub(crate) struct PagingStatusSnapshot {
    pub(crate) authority: PagingAuthoritySnapshot,
    pub(crate) placement_receipt: Option<RamControlPlacementReceipt>,
    pub(crate) convergence: RamControlConvergence,
    pub(crate) resident_observation:
        Option<crucible_qemu_protocol::ram_control::RamControlResidentObservation>,
}

impl PausedPagingOwner {
    /// Records the existing component fixture's acknowledged policy tuple.
    ///
    /// This test-only setup does not schedule work, issue native authority or
    /// establish physical convergence. Production updates use `apply_policy`.
    ///
    /// # Panics
    /// Panics when the fixture's policy mutex is poisoned.
    #[cfg(test)]
    pub(in crate::paged_ram) fn record_capture_fixture_policy(
        &self,
        policy: RamControlPolicy,
        revision: u64,
    ) {
        *self.policy.lock().unwrap() = Some(policy);
        self.requested_policy_revision
            .store(revision, Ordering::Release);
    }

    /// Borrows existing owners without waiting, allocating, faulting or sampling RAM.
    ///
    /// # Errors
    /// Refuses contended or poisoned custody, changed policy identity and overflow.
    pub(crate) fn status_snapshot(
        &self,
        expected_policy: Option<RamControlPolicy>,
        expected_revision: u64,
    ) -> Result<PagingStatusSnapshot, RamError> {
        let policy = self
            .policy
            .try_lock()
            .map_err(|_| "status policy ownership unavailable")?;
        let queued = self
            .queued_operation
            .try_lock()
            .map_err(|_| "status placement ownership unavailable")?;
        let receipt = self
            .placement_receipt
            .try_lock()
            .map_err(|_| "status placement evidence unavailable")?;
        let locks = self
            .locks
            .try_lock()
            .map_err(|_| "status lock custody unavailable")?;
        let active = self
            .active
            .try_lock()
            .map_err(|_| "status mapping ownership unavailable")?;
        let revision = self.requested_policy_revision.load(Ordering::Acquire);
        if *policy != expected_policy || revision != expected_revision {
            return Err(RamError::Invariant("status policy identity changed"));
        }
        let generation = self.policy_generation.load(Ordering::Acquire);
        if queued
            .receipt
            .as_ref()
            .is_some_and(|queued| queued.generation != generation)
        {
            return Err(RamError::Invariant("status placement generation changed"));
        }

        let logical_bytes = self.logical_bytes.load(Ordering::Acquire);
        let topology_generation = self.topology_generation.load(Ordering::Acquire);
        let verified_locked_bytes = locks.as_ref().and_then(|locks| locks.verified_bytes());
        let authority = PagingAuthoritySnapshot {
            logical_bytes,
            topology_generation,
            activated: active
                .as_ref()
                .is_some_and(|service| service.activated.load(Ordering::Acquire)),
            failed: self.failed.load(Ordering::Acquire)
                || active
                    .as_ref()
                    .is_some_and(|service| service.failed.load(Ordering::Acquire)),
            full_peak_bytes: logical_bytes
                .checked_add(self.resources.metadata_bytes)
                .and_then(|bytes| bytes.checked_add(self.resources.staging_bytes))
                .ok_or("status peak snapshot overflow")?,
            permanent_resident_bytes: self
                .permanent_resident_bytes
                .load(Ordering::Acquire)
                .max(verified_locked_bytes.unwrap_or(0)),
        };
        let placement_receipt = (*receipt).filter(|receipt| {
            receipt.policy_revision == revision
                && receipt.topology_generation == topology_generation
                && policy.is_some_and(|policy| policy.mode == receipt.mode)
        });
        let convergence = if authority.failed {
            RamControlConvergence::Failed
        } else if queued.capture.is_held() {
            RamControlConvergence::Blocked
        } else {
            observed_convergence(
                authority,
                *policy,
                revision,
                queued.receipt.is_some(),
                placement_receipt,
                verified_locked_bytes,
            )
        };
        let resident_observation = active
            .as_ref()
            .map(|service| {
                service
                    .resident_observation
                    .try_lock()
                    .map(|value| {
                        (*value).filter(|observation| {
                            observation.topology_generation == topology_generation
                                && observation.policy_revision == revision
                                && observation.policy_generation == generation
                                && observation.worker_generation == service.worker_generation
                                && observation.covered_bytes == logical_bytes
                        })
                    })
                    .map_err(|_| RamError::Invariant("resident observation ownership unavailable"))
            })
            .transpose()?
            .flatten();

        Ok(PagingStatusSnapshot {
            authority,
            placement_receipt,
            convergence,
            resident_observation,
        })
    }
}

fn observed_convergence(
    authority: PagingAuthoritySnapshot,
    policy: Option<RamControlPolicy>,
    revision: u64,
    queued: bool,
    receipt: Option<RamControlPlacementReceipt>,
    verified_locked_bytes: Option<u64>,
) -> RamControlConvergence {
    if authority.failed {
        return RamControlConvergence::Failed;
    }
    if queued {
        return RamControlConvergence::Applying;
    }
    let locked = policy.is_some_and(|policy| policy.mode == RamControlMode::ResidentRequired)
        && authority.activated
        && authority.logical_bytes != 0
        && revision != 0
        && receipt.is_some_and(|receipt| {
            receipt.mode == RamControlMode::ResidentRequired
                && receipt.policy_revision == revision
                && receipt.topology_generation == authority.topology_generation
                && receipt.placement_epoch != 0
                && receipt.locked_bytes >= authority.logical_bytes
                && verified_locked_bytes == Some(receipt.locked_bytes)
        });
    if locked {
        RamControlConvergence::Stable
    } else {
        // A managed target has no fresh physical classification; a disk cut
        // cannot say whether later writers have outstanding preservation.
        RamControlConvergence::Blocked
    }
}

#[cfg(test)]
mod tests;
