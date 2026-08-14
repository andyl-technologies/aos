//! Shared-memory coverage ring entries and layout constants.

use super::*;

/// A compact plugin-to-host basic-block coverage observation.
///
/// Each coverage map index is published at most once for a plugin process. The
/// SPSC ring order supplies the deterministic sequence, so the entry carries no
/// independently mutable sequence counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct CoverageEntry {
    pub(super) current_icount: u64,
    pub(super) guest_pc: u64,
    pub(super) map_index: u64,
    pub(super) vcpu_index: u32,
    pub(super) block_len: u32,
    pub(super) _reserved: [u8; 32],
}

/// Byte offset of [`CoverageEntry`]'s exact TB-entry icount.
pub const COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(CoverageEntry, current_icount);
/// Byte offset of [`CoverageEntry`]'s guest basic-block address.
pub const COVERAGE_ENTRY_GUEST_PC_OFFSET: usize = core::mem::offset_of!(CoverageEntry, guest_pc);
/// Byte offset of [`CoverageEntry`]'s fixed-map index.
pub const COVERAGE_ENTRY_MAP_INDEX_OFFSET: usize = core::mem::offset_of!(CoverageEntry, map_index);
/// Byte offset of [`CoverageEntry`]'s QEMU vCPU index.
pub const COVERAGE_ENTRY_VCPU_INDEX_OFFSET: usize =
    core::mem::offset_of!(CoverageEntry, vcpu_index);
/// Byte offset of [`CoverageEntry`]'s translated block byte length.
pub const COVERAGE_ENTRY_BLOCK_LEN_OFFSET: usize = core::mem::offset_of!(CoverageEntry, block_len);
/// Byte offset of [`CoverageEntry`]'s zeroed forward-compatibility bytes.
pub const COVERAGE_ENTRY_RESERVED_OFFSET: usize = core::mem::offset_of!(CoverageEntry, _reserved);
/// Wire size of one [`CoverageEntry`].
pub const COVERAGE_ENTRY_SIZE: usize = core::mem::size_of::<CoverageEntry>();
/// Wire alignment of one [`CoverageEntry`].
pub const COVERAGE_ENTRY_ALIGN: usize = core::mem::align_of::<CoverageEntry>();

const _: () = assert!(COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET == 0);
const _: () = assert!(COVERAGE_ENTRY_GUEST_PC_OFFSET == 8);
const _: () = assert!(COVERAGE_ENTRY_MAP_INDEX_OFFSET == 16);
const _: () = assert!(COVERAGE_ENTRY_VCPU_INDEX_OFFSET == 24);
const _: () = assert!(COVERAGE_ENTRY_BLOCK_LEN_OFFSET == 28);
const _: () = assert!(COVERAGE_ENTRY_RESERVED_OFFSET == 32);
const _: () = assert!(COVERAGE_ENTRY_SIZE == 64);
const _: () = assert!(COVERAGE_ENTRY_ALIGN == 64);

impl CoverageEntry {
    /// Builds one validated novel coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageEntryError::InvalidBlockLength`] for a zero-length
    /// block, or [`CoverageEntryError::MapIndexOutOfRange`] when `map_index` is
    /// outside the ABI-fixed coverage-map cardinality.
    pub fn new(
        current_icount: u64,
        vcpu_index: u32,
        guest_pc: u64,
        block_len: u32,
        map_index: u64,
    ) -> Result<Self, CoverageEntryError> {
        if block_len == 0 {
            return Err(CoverageEntryError::InvalidBlockLength { block_len });
        }
        if map_index >= u64::from(COVERAGE_QUEUE_CAPACITY) {
            return Err(CoverageEntryError::MapIndexOutOfRange {
                map_index,
                map_entries: COVERAGE_QUEUE_CAPACITY,
            });
        }
        Ok(Self {
            current_icount,
            guest_pc,
            map_index,
            vcpu_index,
            block_len,
            _reserved: [0; 32],
        })
    }

    /// Returns the exact icount before the covered block's first instruction.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the QEMU vCPU that executed the block.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest basic-block address.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block byte length.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }

    /// Returns the fixed coverage-map index first reached by this observation.
    #[must_use]
    pub const fn map_index(self) -> u64 {
        self.map_index
    }

    /// Validates an entry loaded from shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageEntryError`] for an invalid block length, out-of-range
    /// map index, or nonzero reserved bytes.
    pub fn validate(self) -> Result<Self, CoverageEntryError> {
        let validated = Self::new(
            self.current_icount,
            self.vcpu_index,
            self.guest_pc,
            self.block_len,
            self.map_index,
        )?;
        if self._reserved.iter().any(|byte| *byte != 0) {
            return Err(CoverageEntryError::NonzeroReservedBytes);
        }
        Ok(validated)
    }
}
