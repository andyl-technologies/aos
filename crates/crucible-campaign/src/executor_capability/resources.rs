//! Portable physical resource vectors and aggregate-versus-assignment bounds.
//!
//! Metadata and staging are independently admitted subsets of the complete
//! resident and backing peaks. Adding them to those peaks again would charge
//! the same bytes twice. The canonical vector contains eight unsigned 64-bit
//! integers in the field order shown here, using the campaign codec's byte order:
//!
//! ```text
//! resident_peak | backing_peak | metadata | staging |
//! paging_io_slots | cpu_slots | task_slots | file_descriptors
//! ```

use crate::codec::{Canonical, Decoder, Encoder};
use crate::{AttemptResourceLimits, CampaignCodecError};

/// Describes eight portable host resource dimensions without platform handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorHostResources {
    /// Complete resident peak, including metadata, staging, and process overhead.
    pub resident_peak_bytes: u64,
    /// Complete writable backing peak, including preservation and disk staging.
    pub backing_peak_bytes: u64,
    /// Independently limited metadata subset already included in complete peaks.
    pub metadata_bytes: u64,
    /// Independently limited staging subset already included in complete peaks.
    pub staging_bytes: u64,
    /// Paging and preservation I/O concurrency allowance.
    pub paging_io_slots: u64,
    /// CPU and virtual CPU admission allowance.
    pub cpu_slots: u64,
    /// Process and worker task allowance.
    pub task_slots: u64,
    /// Owned file descriptor allowance.
    pub file_descriptors: u64,
}

impl ExecutorHostResources {
    /// Returns whether every dimension fits the corresponding admitted bound.
    #[must_use]
    pub fn fits(self, ceiling: Self) -> bool {
        self.components()
            .into_iter()
            .zip(ceiling.components())
            .all(|(used, limit)| used <= limit)
    }

    fn components(self) -> [u64; 8] {
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

    fn validate_static(self) -> Result<(), CampaignCodecError> {
        if self.cpu_slots == 0 || self.resident_peak_bytes == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor host bound has zero CPU or resident capacity",
            });
        }
        if self
            .metadata_bytes
            .checked_add(self.staging_bytes)
            .is_none_or(|subsets| subsets > self.resident_peak_bytes)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor host metadata and staging exceed resident peak",
            });
        }
        Ok(())
    }
}

impl Canonical for ExecutorHostResources {
    fn encode(&self, encoder: &mut Encoder) {
        for component in self.components() {
            component.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            resident_peak_bytes: u64::decode(decoder)?,
            backing_peak_bytes: u64::decode(decoder)?,
            metadata_bytes: u64::decode(decoder)?,
            staging_bytes: u64::decode(decoder)?,
            paging_io_slots: u64::decode(decoder)?,
            cpu_slots: u64::decode(decoder)?,
            task_slots: u64::decode(decoder)?,
            file_descriptors: u64::decode(decoder)?,
        })
    }
}

/// Separates aggregate executor capacity from one assignment's physical bounds.
///
/// The original attempt limits retain their deterministic execution-quanta
/// meaning. Physical placement conservatively reserves the full assignment
/// vector, even when an attempt requests smaller CPU, memory, or disk limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorResourceBounds {
    aggregate: ExecutorHostResources,
    assignment: ExecutorHostResources,
    attempt_limits: AttemptResourceLimits,
}

impl ExecutorResourceBounds {
    /// Builds explicit aggregate and assignment bounds with original attempt limits.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid static subset accounting, an
    /// assignment dimension above aggregate capacity, or attempt CPU, memory,
    /// or disk limits above the assignment's complete physical peaks.
    pub fn new(
        aggregate: ExecutorHostResources,
        assignment: ExecutorHostResources,
        attempt_limits: AttemptResourceLimits,
    ) -> Result<Self, CampaignCodecError> {
        aggregate.validate_static()?;
        assignment.validate_static()?;
        if !assignment.fits(aggregate) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor assignment bound exceeds aggregate capacity",
            });
        }
        if u64::from(attempt_limits.maximum_vcpus()) > assignment.cpu_slots
            || attempt_limits.maximum_resident_bytes() > assignment.resident_peak_bytes
            || attempt_limits.maximum_disk_bytes() > assignment.backing_peak_bytes
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor attempt limits exceed assignment host bounds",
            });
        }
        Ok(Self {
            aggregate,
            assignment,
            attempt_limits,
        })
    }

    /// Returns the complete aggregate executor entitlement.
    #[must_use]
    pub const fn aggregate(self) -> ExecutorHostResources {
        self.aggregate
    }

    /// Returns the complete physical reservation for one admitted assignment.
    #[must_use]
    pub const fn assignment(self) -> ExecutorHostResources {
        self.assignment
    }

    /// Returns the original request ceilings, including deterministic execution quanta.
    #[must_use]
    pub const fn attempt_limits(self) -> AttemptResourceLimits {
        self.attempt_limits
    }
}

impl Canonical for ExecutorResourceBounds {
    fn encode(&self, encoder: &mut Encoder) {
        self.aggregate.encode(encoder);
        self.assignment.encode(encoder);
        self.attempt_limits.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ExecutorHostResources::decode(decoder)?,
            ExecutorHostResources::decode(decoder)?,
            AttemptResourceLimits::decode(decoder)?,
        )
    }
}
