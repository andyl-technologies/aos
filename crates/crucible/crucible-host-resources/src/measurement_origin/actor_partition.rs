//! Projects the fixed actor partition from authenticated parent evidence.
//!
//! Physical residency includes metadata and staging. Aggregate descriptor
//! accounting remains distinct from the inherited per-process file limit.
//! This borrowed view cannot issue credit, replace an invocation, or outlive
//! the evidence whose private producer retains the original external payer.

use super::parent_evidence::CertifiedNativeRoleEvidence;
use crate::host_supervision::{HostOperationBudgets, HostOperationClass};
use std::time::Duration;

/// Borrows the authored actor partition from the same parent certificate.
///
/// The partition supplies fixed account ceilings, not additional capacity.
/// Source and loader births remain covered by the externally retained parent
/// assignments. Local structure is charged once before publication, while
/// native controls are charged within their actual TOTAL metadata purposes.
pub struct CertifiedActorPartition<'evidence> {
    _evidence: &'evidence CertifiedNativeRoleEvidence,
}

impl CertifiedNativeRoleEvidence {
    /// Borrows the fixed actor partition certified by the same invocation.
    ///
    /// No actor argument selects these values. Only the private parent producer
    /// can create the evidence after binding its whole-actor financing, exact
    /// installed images, operator contract, mode, width and incarnation.
    #[must_use]
    pub fn actor_partition(&self) -> CertifiedActorPartition<'_> {
        CertifiedActorPartition { _evidence: self }
    }
}

impl CertifiedActorPartition<'_> {
    /// Returns the immutable original class roster before supervisor publication.
    ///
    /// The shipped corpus changes only Preparation's total allowance to one
    /// hour. Progress, cleanup and other class policies keep their existing
    /// values; constructing this roster neither starts nor renews a clock.
    #[must_use]
    pub fn operation_budgets(&self) -> HostOperationBudgets {
        let mut budgets = HostOperationBudgets::default();
        budgets.classes[HostOperationClass::Preparation as usize].total_timeout =
            Some(Duration::from_secs(3600));
        budgets
    }

    /// Borrows the fixed capture stage with one active native attempt.
    #[must_use]
    pub fn capture_stage(&self) -> CertifiedNativeStage<'_> {
        CertifiedNativeStage {
            partition: self,
            width: 1,
        }
    }

    /// Borrows the authenticated fresh-worker stage after capture retirement.
    ///
    /// This descriptor certifies no hot-fork source-service occupancy. Actual
    /// capture images and Source/control loans remain retained independently;
    /// process reap alone cannot refund those purposes.
    #[must_use]
    pub fn worker_stage(&self) -> CertifiedNativeStage<'_> {
        CertifiedNativeStage {
            partition: self,
            width: self._evidence.native_count() as u8,
        }
    }

    /// Returns the original physical actor resident ceiling.
    #[must_use]
    pub const fn resident_bytes(&self) -> u64 {
        16 << 30
    }

    /// Returns the metadata subset of the same resident ceiling.
    #[must_use]
    pub const fn metadata_bytes(&self) -> u64 {
        8 << 30
    }

    /// Returns the staging subset of the same resident ceiling.
    #[must_use]
    pub const fn staging_bytes(&self) -> u64 {
        1 << 30
    }

    /// Returns the fixed aggregate task-accounting ceiling.
    #[must_use]
    pub const fn tasks(&self) -> u64 {
        4096
    }

    /// Returns the aggregate descriptor-accounting ceiling.
    ///
    /// This counter covers simultaneous independent purposes; it does not
    /// modify the hard limit inherited by any particular process.
    #[must_use]
    pub const fn descriptors(&self) -> u64 {
        65_536
    }

    /// Returns the unchanged per-process hard and soft descriptor limit.
    #[must_use]
    pub const fn process_file_limit(&self) -> u64 {
        1024
    }

    /// Returns the authored aggregate I/O-slot ceiling.
    #[must_use]
    pub const fn io_slots(&self) -> u64 {
        16
    }

    /// Returns the unchanged actor CPU-slot ceiling.
    #[must_use]
    pub const fn cpu_slots(&self) -> u64 {
        10
    }
}

/// Borrows a fixed active native stage within the same original actor domain.
///
/// The per-attempt metadata and staging fields are resident subsets. The same
/// TOTAL metadata pays target-derived native controls before the native runtime
/// allowance is computed. These facts do not themselves construct a paid role.
pub struct CertifiedNativeStage<'partition> {
    partition: &'partition CertifiedActorPartition<'partition>,
    width: u8,
}

impl CertifiedNativeStage<'_> {
    /// Returns the fixed number of active native attempts.
    #[must_use]
    pub const fn width(&self) -> u8 {
        self.width
    }

    /// Returns each native attempt's complete resident allowance.
    #[must_use]
    pub const fn resident_bytes(&self) -> u64 {
        1536 << 20
    }

    /// Returns each native attempt's TOTAL metadata subset.
    #[must_use]
    pub const fn metadata_bytes(&self) -> u64 {
        512 << 20
    }

    /// Returns each native attempt's staging subset.
    #[must_use]
    pub const fn staging_bytes(&self) -> u64 {
        32 << 20
    }

    /// Returns each native attempt's writable backing allowance.
    #[must_use]
    pub const fn backing_bytes(&self) -> u64 {
        4 << 30
    }

    /// Returns each native attempt's admitted task purpose.
    #[must_use]
    pub const fn tasks(&self) -> u64 {
        69
    }

    /// Returns each native attempt's aggregate descriptor purpose.
    #[must_use]
    pub const fn descriptors(&self) -> u64 {
        1056
    }

    /// Returns the unchanged hard limit of an individual native process.
    #[must_use]
    pub const fn process_file_limit(&self) -> u64 {
        self.partition.process_file_limit()
    }

    /// Returns each native attempt's original CPU purpose.
    #[must_use]
    pub const fn cpu_slots(&self) -> u64 {
        1
    }

    /// Returns each native attempt's paging I/O purpose.
    #[must_use]
    pub const fn io_slots(&self) -> u64 {
        1
    }
}
