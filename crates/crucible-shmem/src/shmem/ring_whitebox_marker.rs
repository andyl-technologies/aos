//! Plugin-to-host white-box marker ring entries.
//!
//! Each successful guest doorbell decode publishes one bounded marker body to
//! a dedicated observational SPSC ring. The ring is separate from causal frame
//! traffic and basic-block coverage so markers cannot influence delivery order,
//! device scheduling, or fingerprint material.

use super::*;

/// One decoded white-box marker published by the QEMU plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct WhiteboxMarkerEntry {
    pub(super) current_icount: u64,
    pub(super) vcpu_index: u32,
    pub(super) kind: u16,
    pub(super) payload_len: u16,
    pub(super) payload: [u8; MAX_FRAME_DATA],
    pub(super) _reserved: [u8; 48],
}

impl Default for WhiteboxMarkerEntry {
    fn default() -> Self {
        Self {
            current_icount: 0,
            vcpu_index: 0,
            kind: 0,
            payload_len: 0,
            payload: [0; MAX_FRAME_DATA],
            _reserved: [0; 48],
        }
    }
}

/// Byte offset of [`WhiteboxMarkerEntry`]'s exact trap icount.
pub const WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(WhiteboxMarkerEntry, current_icount);
/// Byte offset of [`WhiteboxMarkerEntry`]'s QEMU vCPU index.
pub const WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET: usize =
    core::mem::offset_of!(WhiteboxMarkerEntry, vcpu_index);
/// Byte offset of [`WhiteboxMarkerEntry`]'s doorbell marker kind.
pub const WHITEBOX_MARKER_ENTRY_KIND_OFFSET: usize =
    core::mem::offset_of!(WhiteboxMarkerEntry, kind);
/// Byte offset of [`WhiteboxMarkerEntry`]'s marker-body length.
pub const WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET: usize =
    core::mem::offset_of!(WhiteboxMarkerEntry, payload_len);
/// Byte offset of [`WhiteboxMarkerEntry`]'s marker-body bytes.
pub const WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET: usize =
    core::mem::offset_of!(WhiteboxMarkerEntry, payload);
/// Byte offset of [`WhiteboxMarkerEntry`]'s zeroed forward-compatibility bytes.
pub const WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET: usize =
    core::mem::offset_of!(WhiteboxMarkerEntry, _reserved);
/// Wire size of one [`WhiteboxMarkerEntry`].
pub const WHITEBOX_MARKER_ENTRY_SIZE: usize = core::mem::size_of::<WhiteboxMarkerEntry>();
/// Wire alignment of one [`WhiteboxMarkerEntry`].
pub const WHITEBOX_MARKER_ENTRY_ALIGN: usize = core::mem::align_of::<WhiteboxMarkerEntry>();

const _: () = assert!(WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET == 0);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET == 8);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_KIND_OFFSET == 12);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET == 14);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET == 16);
const _: () = assert!(MAX_FRAME_DATA == crucible_protocol::WHITEBOX_MARKER_BODY_MAX_BYTES);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET == 16 + MAX_FRAME_DATA);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_SIZE == 4_672);
const _: () = assert!(WHITEBOX_MARKER_ENTRY_ALIGN == 64);

impl WhiteboxMarkerEntry {
    /// Builds one bounded observational marker entry.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxMarkerEntryError::PayloadLengthExceedsCapacity`] when
    /// `payload` is larger than [`MAX_FRAME_DATA`].
    pub fn new(
        current_icount: u64,
        vcpu_index: u32,
        kind: u16,
        payload: &[u8],
    ) -> Result<Self, WhiteboxMarkerEntryError> {
        let payload_len = u16::try_from(payload.len()).map_err(|_error| {
            WhiteboxMarkerEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: MAX_FRAME_DATA,
            }
        })?;
        if payload.len() > MAX_FRAME_DATA {
            return Err(WhiteboxMarkerEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: MAX_FRAME_DATA,
            });
        }
        let mut entry = Self {
            current_icount,
            vcpu_index,
            kind,
            payload_len,
            ..Self::default()
        };
        entry.payload[..payload.len()].copy_from_slice(payload);
        Ok(entry)
    }

    /// Returns the exact icount at which the guest rang the doorbell.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the QEMU vCPU that rang the doorbell.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the decoded white-box marker kind.
    #[must_use]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    /// Returns the decoded marker body.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.payload_len)]
    }

    /// Validates an entry copied from shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxMarkerEntryError`] when the advertised length exceeds
    /// the fixed payload area, unused payload bytes are nonzero, or reserved
    /// bytes are nonzero.
    pub fn validate(self) -> Result<Self, WhiteboxMarkerEntryError> {
        let payload_len = usize::from(self.payload_len);
        if payload_len > MAX_FRAME_DATA {
            return Err(WhiteboxMarkerEntryError::PayloadLengthExceedsCapacity {
                len: payload_len,
                capacity: MAX_FRAME_DATA,
            });
        }
        if self.payload[payload_len..].iter().any(|byte| *byte != 0) {
            return Err(WhiteboxMarkerEntryError::NonzeroPayloadTail);
        }
        if self._reserved.iter().any(|byte| *byte != 0) {
            return Err(WhiteboxMarkerEntryError::NonzeroReservedBytes);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_entry_round_trips_exact_observational_fields() {
        let entry = WhiteboxMarkerEntry::new(41, 2, 4, b"marker")
            .unwrap_or_else(|error| panic!("marker entry should build: {error}"));
        assert_eq!(entry.current_icount(), 41);
        assert_eq!(entry.vcpu_index(), 2);
        assert_eq!(entry.kind(), 4);
        assert_eq!(entry.payload(), b"marker");
        assert_eq!(entry.validate(), Ok(entry));
    }

    #[test]
    fn marker_entry_rejects_oversized_payload() {
        let payload = vec![0; MAX_FRAME_DATA + 1];
        assert_eq!(
            WhiteboxMarkerEntry::new(0, 0, 1, &payload),
            Err(WhiteboxMarkerEntryError::PayloadLengthExceedsCapacity {
                len: MAX_FRAME_DATA + 1,
                capacity: MAX_FRAME_DATA,
            })
        );
    }
}
