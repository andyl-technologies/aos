//! Bounded strict-placement completion evidence for one authenticated owner.
//!
//! The enclosing frame binds the process and arena incarnations. A receipt
//! binds an applied policy to its immutable topology and physical transition.
//! It is an observation, rather than a transferable admission capability.
//!
//! ```text
//! u8 mode (DiskOriented or ResidentRequired)
//! u64 policy_revision, topology_generation, placement_epoch
//! u64 locked_bytes, disk_preserved_logical_pages
//! u64 disk_preserved_logical_bytes, ram_write_generation_at_cut
//! ```

use super::{RamControlError, RamControlMode, RamControlReply};

/// Records a verified strict-placement transition under the original operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlPlacementReceipt {
    /// Strict placement mode whose transition completed.
    pub mode: RamControlMode,
    /// Applied policy revision that requested this transition.
    pub policy_revision: u64,
    /// Exact immutable native RAM topology generation.
    pub topology_generation: u64,
    /// Positive, nonreused physical-transition sequence within this arena.
    pub placement_epoch: u64,
    /// Actual deduplicated, page-rounded spans verified locked in resident mode.
    ///
    /// This guarantee remains active until a verified unlock or arena teardown.
    /// It never denotes an aggregate process `VmLck` measurement.
    pub locked_bytes: u64,
    /// Complete logical page count authenticated at a disk-preservation cut.
    pub disk_preserved_logical_pages: u64,
    /// Complete logical RAM bytes authenticated at the same preservation cut.
    pub disk_preserved_logical_bytes: u64,
    /// Native independent writer generation observed at the preservation cut.
    ///
    /// Subsequent writes do not change this historical receipt. Resident-mode
    /// receipts canonically set this field and both disk counters to zero.
    pub ram_write_generation_at_cut: u64,
}

impl RamControlPlacementReceipt {
    pub(super) fn validate(self, state: &RamControlReply) -> Result<(), RamControlError> {
        let inventory = state.inventory.ok_or(RamControlError::InvalidFrame)?;
        if self.policy_revision == 0
            || self.policy_revision != state.applied_policy_revision
            || self.topology_generation != inventory.topology_generation
            || !inventory.granted
            || self.placement_epoch == 0
            || state.logical_ram_bytes == 0
            || state.logical_ram_bytes != inventory.logical_bytes
        {
            return Err(RamControlError::InvalidFrame);
        }

        match self.mode {
            RamControlMode::Managed => Err(RamControlError::InvalidFrame),
            RamControlMode::ResidentRequired => {
                if self.locked_bytes == 0
                    || !self.locked_bytes.is_multiple_of(4096)
                    || self.disk_preserved_logical_pages != 0
                    || self.disk_preserved_logical_bytes != 0
                    || self.ram_write_generation_at_cut != 0
                {
                    return Err(RamControlError::InvalidFrame);
                }
                Ok(())
            }
            RamControlMode::DiskOriented => {
                let minimum_pages = state.logical_ram_bytes.div_ceil(4096);
                let maximum_pages = minimum_pages
                    .checked_add(u64::from(inventory.region_count.saturating_sub(1)))
                    .ok_or(RamControlError::InvalidFrame)?;
                if self.locked_bytes != 0
                    || self.disk_preserved_logical_bytes != state.logical_ram_bytes
                    || !(minimum_pages..=maximum_pages).contains(&self.disk_preserved_logical_pages)
                {
                    return Err(RamControlError::InvalidFrame);
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests;
