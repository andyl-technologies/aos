//! Resolved flash rules and checkpointed flash state.

use super::*;

/// A resolved retention transition policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockFlashRetention {
    /// Minimum programmed age before a cell is eligible.
    pub minimum_age_nanos: u64,
    /// Extra eligible age added for each erase cycle.
    pub wear_age_nanos: u64,
    /// Per-bit probability in millionths.
    pub bit_probability_millionths: u32,
    /// Maximum changed bits in one page and opportunity.
    pub maximum_changed_bits: u32,
}

/// A resolved neighboring-page read-disturb policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockFlashReadDisturb {
    /// Reads of an aggressor page required for one disturbance transition.
    pub read_threshold: u64,
    /// Symmetric neighboring-page distance.
    pub neighbor_pages: u32,
    /// Per-bit probability in millionths.
    pub bit_probability_millionths: u32,
    /// Maximum changed bits in each affected page and opportunity.
    pub maximum_changed_bits: u32,
}

/// A resolved program/erase failure policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockFlashProgramErase {
    /// Program failure probability before rated endurance.
    pub program_probability_millionths: u32,
    /// Erase failure probability before rated endurance.
    pub erase_probability_millionths: u32,
    /// Program or erase failure probability at rated endurance.
    pub worn_probability_millionths: u32,
    /// Whether a failed program applies a canonical nonempty prefix.
    pub partial_program: bool,
    /// Whether a failed erase applies a canonical nonempty block prefix.
    pub partial_erase: bool,
}

/// One complete resolved flash-device contribution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockFlashRule {
    /// Stable resolved binding-action identity.
    pub contributor: [u8; 32],
    /// Scenario- and action-bound key for every physical choice.
    pub choice_key: [u8; 32],
    /// Erase-block size in bytes.
    pub erase_block_bytes: u64,
    /// Program-page size in bytes.
    pub program_page_bytes: u64,
    /// Rated erase cycles before the worn probability applies.
    pub endurance_cycles: u64,
    /// Retention transition policy.
    pub retention: ResolvedBlockFlashRetention,
    /// Read-disturb transition policy.
    pub read_disturb: ResolvedBlockFlashReadDisturb,
    /// Program and erase failure policy.
    pub program_erase: ResolvedBlockFlashProgramErase,
}

impl ResolvedBlockFlashRule {
    /// Validates geometry and bounded probability fields.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when geometry is zero, inconsistent with the
    /// device, or a probability exceeds one million millionths.
    pub fn validate(&self, device_length: u64) -> Result<(), DeviceError> {
        if self.erase_block_bytes == 0
            || self.program_page_bytes == 0
            || self.endurance_cycles == 0
            || !self
                .erase_block_bytes
                .is_multiple_of(self.program_page_bytes)
            || !device_length.is_multiple_of(self.erase_block_bytes)
            || self.retention.minimum_age_nanos == 0
            || self.read_disturb.read_threshold == 0
            || self.retention.maximum_changed_bits == 0
            || self.read_disturb.maximum_changed_bits == 0
            || self.retention.bit_probability_millionths > 1_000_000
            || self.read_disturb.bit_probability_millionths > 1_000_000
            || self.program_erase.program_probability_millionths > 1_000_000
            || self.program_erase.erase_probability_millionths > 1_000_000
            || self.program_erase.worn_probability_millionths > 1_000_000
        {
            return Err(invalid("invalid flash geometry or probability"));
        }
        Ok(())
    }
}

/// Sparse state for one touched erase block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFlashEraseBlockState {
    /// Successful erase transitions applied to this block.
    pub erase_count: u64,
    /// Virtual time of the last successful erase.
    pub last_erase_nanos: u64,
}

/// Sparse state for one touched program page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFlashPageState {
    /// Virtual time of the most recent successful program.
    pub programmed_nanos: u64,
    /// Reads since the most recent disturb threshold transition.
    pub reads_since_disturb: u64,
}

/// Checkpointed continuation for one flash rule.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFlashContinuation {
    /// Immutable rule authenticated whenever it is observed again.
    pub rule: ResolvedBlockFlashRule,
    /// Sparse erase-block counters keyed by block ordinal.
    pub erase_blocks: BTreeMap<u64, BlockFlashEraseBlockState>,
    /// Sparse program/read counters keyed by page ordinal.
    pub pages: BTreeMap<u64, BlockFlashPageState>,
    /// Persistent physical-cell XOR masks keyed by absolute byte offset.
    pub changed_bytes: BTreeMap<u64, u8>,
    /// In-progress erase decisions keyed by logical operation sequence and block ordinal.
    pub erase_decisions: BTreeMap<(u64, u64), BlockFlashEraseDecision>,
    /// Monotone physical transition sequence used in keyed choices.
    pub transition_sequence: u64,
}

/// Frozen result of one erase-block attempt shared by all request fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFlashEraseDecision {
    /// Bytes erased from the beginning of the physical block.
    pub applied_prefix_bytes: u64,
    /// Whether the erase attempt failed.
    pub failed: bool,
}

/// Exact result of a flash program or erase opportunity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFlashMutationOutcome {
    /// Fragment-relative spans that physically programmed or erased.
    pub spans: Vec<BlockFaultByteSpan>,
    /// Whether the device reports a media failure after applying `spans`.
    pub failed: bool,
}

/// Canonical sparse flash state owned by one block device.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFlashState {
    continuations: BTreeMap<[u8; 32], BlockFlashContinuation>,
}
