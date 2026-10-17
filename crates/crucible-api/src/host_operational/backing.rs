//! Physical node backing partitions and separate canonical capture bounds.

use super::HostRamInventoryTopology;

/// Typed refusal while separating independently retained disk owners.
#[derive(Debug, thiserror::Error)]
pub enum HostRamBackingError {
    /// A canonical CAS graph cannot be represented within its format bounds.
    #[error("RAM backing graph refused: {0}")]
    Graph(#[from] crucible_cas::ram::RamStoreError),
    /// A required component or aggregate exceeds the unsigned byte domain.
    #[error("RAM backing arithmetic overflow")]
    Overflow,
    /// The complete retained peak cannot cover every independent owner.
    #[error("RAM backing peak {available} is below required {required}")]
    Insufficient {
        /// Complete retained node backing peak.
        available: u64,
        /// Checked sum of all required independent owners.
        required: u64,
    },
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixed backing-geometry fixtures intentionally panic when setup is invalid.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::host_operational::{
        HostRamInventoryLimits, HostRamInventoryRegion, HostRamInventoryRegionClass,
    };

    #[test]
    fn partial_regions_keep_spill_and_encoded_cas_versions_disjoint() {
        let topology = HostRamInventoryTopology::new(
            vec![
                HostRamInventoryRegion::new(
                    "main",
                    HostRamInventoryRegionClass::MutableMain,
                    5 * 4096 + 19,
                )
                .unwrap(),
                HostRamInventoryRegion::new(
                    "device",
                    HostRamInventoryRegionClass::MutableDevice,
                    123,
                )
                .unwrap(),
            ],
            HostRamInventoryLimits::default(),
        )
        .unwrap();
        let minimum =
            HostRamBackingPartition::required(&topology, 2 * 7 * 4096, 4 << 20, 512 << 20).unwrap();
        let headroom = 8 << 20;
        let retained = minimum.within_peak(minimum.peak_bytes + headroom).unwrap();

        assert_eq!(minimum.spill_bytes, 2 * 7 * 4096);
        assert!(minimum.canonical_capture_bytes > 4 * topology.total_logical_bytes());
        assert_eq!(retained.overlay_bytes, headroom);
        assert_eq!(
            retained.peak_bytes,
            retained.spill_bytes
                + retained.device_state_bytes
                + retained.staging_bytes
                + retained.overlay_bytes
        );
        assert!(matches!(
            minimum.within_peak(minimum.peak_bytes - 1),
            Err(HostRamBackingError::Insufficient { .. })
        ));
    }
}

/// Disjoint disk entitlements contained by one complete node backing peak.
///
/// The canonical capture bound is logical and excluded from the physical peak.
/// Persistent catalogs have an independent quota and service reservation that
/// survives node cleanup; their allocation is never charged to overlay space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamBackingPartition {
    /// Two page-padded generations of private mutable preservation slots.
    pub spill_bytes: u64,
    /// Logical bound for four canonical encoded graph versions, including envelopes.
    /// This is excluded from `peak_bytes` and does not bound backend allocation.
    pub canonical_capture_bytes: u64,
    /// Compact VMState and independently admitted device-state envelope.
    pub device_state_bytes: u64,
    /// Independently retained operation transport and write staging.
    pub staging_bytes: u64,
    /// Remaining node-local writable-overlay entitlement.
    pub overlay_bytes: u64,
    /// Checked complete sum; no subset borrows another owner's quota.
    pub peak_bytes: u64,
}

impl HostRamBackingPartition {
    /// Combines explicit backend spill ownership with checked graph admission.
    ///
    /// The composition owner supplies the spill quota for its selected backend;
    /// logical topology alone does not select a physical preservation format.
    ///
    /// # Errors
    /// Rejects invalid graph geometry or arithmetic overflow.
    pub fn required(
        topology: &HostRamInventoryTopology,
        spill_bytes: u64,
        staging_bytes: u64,
        device_state_bytes: u64,
    ) -> Result<Self, HostRamBackingError> {
        let canonical_capture_bytes =
            crucible_cas::ram::maximum_encoded_ram_graph_bytes(topology, 4)?;
        let peak_bytes = spill_bytes
            .checked_add(device_state_bytes)
            .and_then(|bytes| bytes.checked_add(staging_bytes))
            .ok_or(HostRamBackingError::Overflow)?;
        Ok(Self {
            spill_bytes,
            canonical_capture_bytes,
            device_state_bytes,
            staging_bytes,
            overlay_bytes: 0,
            peak_bytes,
        })
    }

    /// Retains the complete peak and classifies its remaining writable headroom.
    ///
    /// # Errors
    /// Rejects a peak below the independently retained minimum.
    pub fn within_peak(mut self, peak_bytes: u64) -> Result<Self, HostRamBackingError> {
        self.overlay_bytes =
            peak_bytes
                .checked_sub(self.peak_bytes)
                .ok_or(HostRamBackingError::Insufficient {
                    available: peak_bytes,
                    required: self.peak_bytes,
                })?;
        self.peak_bytes = peak_bytes;
        Ok(self)
    }
}
