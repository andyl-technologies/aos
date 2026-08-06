//! Bidirectional guest-introspection shared-memory entries.
//!
//! ABI v6 appends two SPSC rings per VM: host-to-plugin requests followed by
//! plugin-to-host responses. Each entry carries one complete bounded `CRGI`
//! protocol record as owned bytes. Ring direction supplies producer ownership;
//! no process-private object crosses the mapping.

use super::*;
use crucible_protocol::guest_introspection::{GuestIntrospectionError, GuestIntrospectionRecord};

/// Maximum complete guest-introspection record bytes in one entry.
pub const GUEST_INTROSPECTION_ENTRY_DATA_BYTES: usize = MAX_FRAME_DATA;

/// Direction of one VM's guest-introspection SPSC ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestIntrospectionRingDirection {
    /// Host requests consumed by the QEMU-side adapter.
    Request,
    /// QEMU-side responses consumed by the host.
    Response,
}

impl GuestIntrospectionRingDirection {
    /// Returns the ABI-stable ring index for a logical VM slot.
    ///
    /// Returns `None` when the index cannot be represented as `u32`.
    #[must_use]
    pub const fn ring_index(self, vm_slot: u32) -> Option<u32> {
        let direction_offset = match self {
            Self::Request => GUEST_INTROSPECTION_REQUEST_RING_OFFSET,
            Self::Response => GUEST_INTROSPECTION_RESPONSE_RING_OFFSET,
        };
        match vm_slot.checked_mul(GUEST_INTROSPECTION_RINGS_PER_VM) {
            Some(base) => base.checked_add(direction_offset),
            None => None,
        }
    }
}

/// One complete guest-introspection record in a directional SPSC ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct GuestIntrospectionEntry {
    pub(super) sequence: u64,
    pub(super) len: u16,
    pub(super) _pad: [u8; 6],
    pub(super) data: [u8; GUEST_INTROSPECTION_ENTRY_DATA_BYTES],
    pub(super) _reserved: [u8; 48],
}

impl Default for GuestIntrospectionEntry {
    fn default() -> Self {
        Self {
            sequence: 0,
            len: 0,
            _pad: [0; 6],
            data: [0; GUEST_INTROSPECTION_ENTRY_DATA_BYTES],
            _reserved: [0; 48],
        }
    }
}

/// Byte offset of [`GuestIntrospectionEntry`]'s channel sequence.
pub const GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET: usize =
    core::mem::offset_of!(GuestIntrospectionEntry, sequence);
/// Byte offset of [`GuestIntrospectionEntry`]'s record length.
pub const GUEST_INTROSPECTION_ENTRY_LEN_OFFSET: usize =
    core::mem::offset_of!(GuestIntrospectionEntry, len);
/// Byte offset of [`GuestIntrospectionEntry`]'s zero padding.
pub const GUEST_INTROSPECTION_ENTRY_PAD_OFFSET: usize =
    core::mem::offset_of!(GuestIntrospectionEntry, _pad);
/// Byte offset of [`GuestIntrospectionEntry`]'s complete record bytes.
pub const GUEST_INTROSPECTION_ENTRY_DATA_OFFSET: usize =
    core::mem::offset_of!(GuestIntrospectionEntry, data);
/// Byte offset of [`GuestIntrospectionEntry`]'s reserved tail.
pub const GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET: usize =
    core::mem::offset_of!(GuestIntrospectionEntry, _reserved);
/// Wire size of one [`GuestIntrospectionEntry`].
pub const GUEST_INTROSPECTION_ENTRY_SIZE: usize = core::mem::size_of::<GuestIntrospectionEntry>();
/// Wire alignment of one [`GuestIntrospectionEntry`].
pub const GUEST_INTROSPECTION_ENTRY_ALIGN: usize = core::mem::align_of::<GuestIntrospectionEntry>();

const _: () = assert!(GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET == 0);
const _: () = assert!(GUEST_INTROSPECTION_ENTRY_LEN_OFFSET == 8);
const _: () = assert!(GUEST_INTROSPECTION_ENTRY_PAD_OFFSET == 10);
const _: () = assert!(GUEST_INTROSPECTION_ENTRY_DATA_OFFSET == 16);
const _: () = assert!(GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET == 4624);
const _: () = assert!(GUEST_INTROSPECTION_ENTRY_SIZE == 4672);
const _: () = assert!(GUEST_INTROSPECTION_ENTRY_ALIGN == 64);

impl GuestIntrospectionEntry {
    /// Builds an entry from one complete bounded protocol record.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionEntryError::InvalidSequence`] for sequence
    /// zero, [`GuestIntrospectionEntryError::RecordTooLarge`] when `record`
    /// exceeds [`GUEST_INTROSPECTION_ENTRY_DATA_BYTES`], or
    /// [`GuestIntrospectionEntryError::MalformedRecord`] when `record` is not a
    /// complete valid `CRGI` protocol record.
    pub fn new(sequence: u64, record: &[u8]) -> Result<Self, GuestIntrospectionEntryError> {
        if sequence == 0 {
            return Err(GuestIntrospectionEntryError::InvalidSequence);
        }
        if record.len() > GUEST_INTROSPECTION_ENTRY_DATA_BYTES {
            return Err(GuestIntrospectionEntryError::RecordTooLarge {
                len: record.len(),
                capacity: GUEST_INTROSPECTION_ENTRY_DATA_BYTES,
            });
        }
        GuestIntrospectionRecord::decode(record)
            .map_err(|source| GuestIntrospectionEntryError::MalformedRecord { source })?;
        let len = u16::try_from(record.len()).map_err(|_error| {
            GuestIntrospectionEntryError::RecordTooLarge {
                len: record.len(),
                capacity: GUEST_INTROSPECTION_ENTRY_DATA_BYTES,
            }
        })?;
        let mut entry = Self {
            sequence,
            len,
            ..Self::default()
        };
        entry.data[..record.len()].copy_from_slice(record);
        Ok(entry)
    }

    /// Returns the directional publication sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the complete validated encoded protocol record.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionEntryError`] when bytes copied from shared
    /// memory have an invalid envelope or embedded `CRGI` record.
    pub fn record(&self) -> Result<&[u8], GuestIntrospectionEntryError> {
        self.validate_ref()?;
        Ok(&self.data[..usize::from(self.len)])
    }

    /// Validates bytes copied from the shared mapping.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionEntryError`] when the sequence is zero, the
    /// length exceeds capacity, or any padding, unused data, or reserved byte
    /// is nonzero.
    pub fn validate(self) -> Result<Self, GuestIntrospectionEntryError> {
        self.validate_ref()?;
        Ok(self)
    }

    fn validate_ref(&self) -> Result<(), GuestIntrospectionEntryError> {
        if self.sequence == 0 {
            return Err(GuestIntrospectionEntryError::InvalidSequence);
        }
        let len = usize::from(self.len);
        if len > GUEST_INTROSPECTION_ENTRY_DATA_BYTES {
            return Err(GuestIntrospectionEntryError::RecordTooLarge {
                len,
                capacity: GUEST_INTROSPECTION_ENTRY_DATA_BYTES,
            });
        }
        if self._pad.iter().any(|byte| *byte != 0) {
            return Err(GuestIntrospectionEntryError::NonzeroPadding);
        }
        if self.data[len..].iter().any(|byte| *byte != 0) {
            return Err(GuestIntrospectionEntryError::NonzeroDataTail);
        }
        if self._reserved.iter().any(|byte| *byte != 0) {
            return Err(GuestIntrospectionEntryError::NonzeroReservedBytes);
        }
        GuestIntrospectionRecord::decode(&self.data[..len])
            .map_err(|source| GuestIntrospectionEntryError::MalformedRecord { source })?;
        Ok(())
    }
}

/// Invalid guest-introspection shared-memory entry.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GuestIntrospectionEntryError {
    /// Sequence zero is reserved for an unpublished entry.
    #[error("guest-introspection entry sequence must be nonzero")]
    InvalidSequence,
    /// The complete record exceeds the fixed entry payload.
    #[error("guest-introspection record length {len} exceeds capacity {capacity}")]
    RecordTooLarge {
        /// Rejected record length.
        len: usize,
        /// Fixed entry capacity.
        capacity: usize,
    },
    /// The owned record is not a complete valid `CRGI` protocol record.
    #[error("guest-introspection record is malformed")]
    MalformedRecord {
        /// Protocol validation failure.
        #[source]
        source: GuestIntrospectionError,
    },
    /// Alignment padding was not zero.
    #[error("guest-introspection entry padding is nonzero")]
    NonzeroPadding,
    /// Bytes after the advertised record length were not zero.
    #[error("guest-introspection entry data tail is nonzero")]
    NonzeroDataTail,
    /// Reserved forward-compatibility bytes were not zero.
    #[error("guest-introspection entry reserved bytes are nonzero")]
    NonzeroReservedBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_protocol::guest_introspection::{
        GuestIntrospectionMessage, GuestIntrospectionRecord,
    };

    fn close_record(channel_id: u64) -> Vec<u8> {
        GuestIntrospectionRecord::new(channel_id, GuestIntrospectionMessage::Close)
            .and_then(|record| record.encode())
            .unwrap_or_else(|error| panic!("close record should encode: {error}"))
    }

    fn unchecked_entry(sequence: u64, record: &[u8]) -> GuestIntrospectionEntry {
        let mut entry = GuestIntrospectionEntry {
            sequence,
            len: u16::try_from(record.len())
                .unwrap_or_else(|error| panic!("test record length should fit: {error}")),
            ..GuestIntrospectionEntry::default()
        };
        entry.data[..record.len()].copy_from_slice(record);
        entry
    }

    #[test]
    fn entry_round_trips_owned_record_bytes() {
        let record = close_record(7);
        let entry = GuestIntrospectionEntry::new(7, &record)
            .unwrap_or_else(|error| panic!("entry should build: {error}"));
        assert_eq!(entry.sequence(), 7);
        assert_eq!(entry.record(), Ok(record.as_slice()));
        assert_eq!(entry.validate(), Ok(entry));
    }

    #[test]
    fn consumer_rejects_malformed_entry_without_releasing_its_slot() {
        let header = RingHeader::new();
        let mut entries = vec![GuestIntrospectionEntry::default(); 2];
        let record = close_record(1);
        let mut malformed = GuestIntrospectionEntry::new(1, &record)
            .unwrap_or_else(|error| panic!("entry should build: {error}"));
        malformed._reserved[0] = 1;
        header
            .enqueue_guest_introspection(&mut entries, malformed)
            .unwrap_or_else(|error| panic!("entry should enqueue: {error}"));

        assert_eq!(
            header.dequeue_guest_introspection(&entries),
            Err(SpscRingError::InvalidGuestIntrospectionEntry {
                source: GuestIntrospectionEntryError::NonzeroReservedBytes,
            })
        );
        assert_eq!(
            header.dequeue_guest_introspection(&entries),
            Err(SpscRingError::InvalidGuestIntrospectionEntry {
                source: GuestIntrospectionEntryError::NonzeroReservedBytes,
            })
        );
    }

    #[test]
    fn entry_rejects_every_untrusted_envelope_and_protocol_shape() {
        let record = close_record(1);

        assert!(matches!(
            GuestIntrospectionEntry::new(0, &record),
            Err(GuestIntrospectionEntryError::InvalidSequence)
        ));
        assert!(matches!(
            GuestIntrospectionEntry::new(1, b"CRGI"),
            Err(GuestIntrospectionEntryError::MalformedRecord { .. })
        ));

        let mut oversized_len = unchecked_entry(1, &record);
        oversized_len.len = u16::MAX;
        assert!(matches!(
            oversized_len.record(),
            Err(GuestIntrospectionEntryError::RecordTooLarge { .. })
        ));

        let mut padding = unchecked_entry(1, &record);
        padding._pad[0] = 1;
        assert_eq!(
            padding.validate(),
            Err(GuestIntrospectionEntryError::NonzeroPadding)
        );

        let mut data_tail = unchecked_entry(1, &record);
        data_tail.data[record.len()] = 1;
        assert_eq!(
            data_tail.validate(),
            Err(GuestIntrospectionEntryError::NonzeroDataTail)
        );

        let mut invalid_kind = record;
        invalid_kind[6] = u8::MAX;
        assert!(matches!(
            unchecked_entry(1, &invalid_kind).validate(),
            Err(GuestIntrospectionEntryError::MalformedRecord {
                source: GuestIntrospectionError::UnknownKind { kind: u8::MAX }
            })
        ));
    }

    #[test]
    fn directional_ring_applies_backpressure_and_wraps_without_overwrite() {
        let header = RingHeader::new();
        let mut entries = vec![GuestIntrospectionEntry::default(); 2];
        let first = GuestIntrospectionEntry::new(1, &close_record(1))
            .unwrap_or_else(|error| panic!("first entry should build: {error}"));
        let second = GuestIntrospectionEntry::new(2, &close_record(2))
            .unwrap_or_else(|error| panic!("second entry should build: {error}"));
        let third = GuestIntrospectionEntry::new(3, &close_record(3))
            .unwrap_or_else(|error| panic!("third entry should build: {error}"));

        assert_eq!(
            header.enqueue_guest_introspection(&mut entries, first),
            Ok(())
        );
        assert_eq!(
            header.enqueue_guest_introspection(&mut entries, second),
            Ok(())
        );
        assert_eq!(
            header.enqueue_guest_introspection(&mut entries, third),
            Err(SpscRingError::QueueFull { capacity: 2 })
        );
        assert_eq!(
            header.dequeue_guest_introspection(&entries),
            Ok(Some(first))
        );
        assert_eq!(
            header.enqueue_guest_introspection(&mut entries, third),
            Ok(())
        );
        assert_eq!(
            header.dequeue_guest_introspection(&entries),
            Ok(Some(second))
        );
        assert_eq!(
            header.dequeue_guest_introspection(&entries),
            Ok(Some(third))
        );
        assert_eq!(header.dequeue_guest_introspection(&entries), Ok(None));
    }
}
