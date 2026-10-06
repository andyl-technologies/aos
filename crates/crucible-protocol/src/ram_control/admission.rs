//! Portable pre-CPU inventory reports and exact resource grants.
//!
//! Reports contain logical identities and checked scalar capacities only. Host
//! addresses and native mapping layouts remain private to the GPL process.
//! Every region response is tied to the report's immutable topology generation.

use super::RamControlError;

/// Complete independent host admission envelope, separate from resident targets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RamControlResources {
    /// Complete retained resident peak.
    pub resident_peak_bytes: u64,
    /// Complete retained preserved backing peak.
    pub backing_peak_bytes: u64,
    /// Metadata subset within the complete peaks.
    pub metadata_bytes: u64,
    /// Staging subset within the complete peaks.
    pub staging_bytes: u64,
    /// Paging/preservation I/O slots.
    pub paging_io_slots: u64,
    /// CPU/vCPU slots.
    pub cpu_slots: u64,
    /// Process and service task slots.
    pub task_slots: u64,
    /// Owned descriptor slots.
    pub file_descriptors: u64,
}

impl RamControlResources {
    pub(super) fn components(self) -> [u64; 8] {
        [
            self.resident_peak_bytes,
            self.backing_peak_bytes,
            self.metadata_bytes,
            self.staging_bytes,
            self.paging_io_slots,
            self.cpu_slots,
            self.task_slots,
            self.file_descriptors,
        ]
    }

    pub(super) fn from_components(values: [u64; 8]) -> Self {
        Self {
            resident_peak_bytes: values[0],
            backing_peak_bytes: values[1],
            metadata_bytes: values[2],
            staging_bytes: values[3],
            paging_io_slots: values[4],
            cpu_slots: values[5],
            task_slots: values[6],
            file_descriptors: values[7],
        }
    }
}

/// Actual immutable inventory selected before CPU admission and metadata sealing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlInventoryReport {
    /// Nonreused native topology ownership generation.
    pub topology_generation: u64,
    /// Complete realized logical RAM, including device regions.
    pub logical_bytes: u64,
    /// Exact bounded portable region count, at most 4096.
    pub region_count: u32,
    /// Actual native metadata allocation requirement.
    pub native_metadata_bytes: u64,
    /// Actual native observation/population scratch requirement.
    pub native_scratch_bytes: u64,
    /// Whether the authenticated initial grant was accepted by the native owner.
    pub granted: bool,
}

/// One portable logical region in the immutable reported inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlInventoryRegion {
    /// Exact ordinal selected by the region request.
    pub ordinal: u32,
    /// Positive logical region length.
    pub logical_length: u64,
    /// Closed canonical region classification, one through four.
    pub class: u8,
    /// Valid UTF-8 identity bytes in the fixed inline buffer.
    pub identity_length: u8,
    /// Identity bytes followed by canonical zero padding.
    pub identity: [u8; 255],
}

impl RamControlInventoryRegion {
    /// Constructs a bounded canonical region response without dynamic allocation.
    ///
    /// # Errors
    /// Refuses invalid ordinal, zero length, unknown class, or empty/long/NUL identity.
    pub fn new(
        ordinal: u32,
        logical_length: u64,
        class: u8,
        identity: &str,
    ) -> Result<Self, RamControlError> {
        if ordinal >= 4096
            || logical_length == 0
            || !(1..=4).contains(&class)
            || identity.is_empty()
            || identity.len() > 255
            || identity.as_bytes().contains(&0)
        {
            return Err(RamControlError::InvalidFrame);
        }
        let mut bytes = [0; 255];
        bytes[..identity.len()].copy_from_slice(identity.as_bytes());
        Ok(Self {
            ordinal,
            logical_length,
            class,
            identity_length: identity.len() as u8,
            identity: bytes,
        })
    }

    /// Returns the checked canonical logical region identity.
    ///
    /// # Errors
    /// Refuses invalid scalar fields, padding, UTF-8 or NUL/empty identity.
    pub fn identity(&self) -> Result<&str, RamControlError> {
        let length = self.identity_length as usize;
        if self.ordinal >= 4096
            || self.logical_length == 0
            || !(1..=4).contains(&self.class)
            || length == 0
            || self.identity[length..].iter().any(|byte| *byte != 0)
            || self.identity[..length].contains(&0)
        {
            return Err(RamControlError::InvalidFrame);
        }
        std::str::from_utf8(&self.identity[..length]).map_err(|_| RamControlError::InvalidFrame)
    }
}
