//! Accelerator co-simulation request and completion transport.
//!
//! ABI v11 appends one guest/QEMU-to-host request ring and one host-to-QEMU
//! completion ring per VM. Each fixed-size entry owns a complete, bounded job
//! or result; no guest address, native pointer, or process-private object
//! crosses the Apache/GPL process boundary.

use super::*;

/// Fixed entry capacity for each accelerator direction.
pub const ACCELERATOR_QUEUE_CAPACITY: u32 = 64;
/// Number of accelerator rings per VM.
pub const ACCELERATOR_RINGS_PER_VM: u32 = 2;
/// Per-VM request ring offset.
pub const ACCELERATOR_REQUEST_RING_OFFSET: u32 = 0;
/// Per-VM completion ring offset.
pub const ACCELERATOR_COMPLETION_RING_OFFSET: u32 = 1;
/// Maximum input or output bytes carried by one accelerator job.
pub const ACCELERATOR_ENTRY_DATA_BYTES: usize = MAX_FRAME_DATA;
/// Accelerator entry protocol version.
pub const ACCELERATOR_PROTOCOL_VERSION: u16 = 1;

/// Accelerator class encoded on the public process boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AcceleratorClass {
    /// Integer vector compute representing a GPU compute queue.
    Gpu = 1,
    /// Integer matrix compute representing a tensor processor.
    Tpu = 2,
    /// Deterministic bitstream/LUT compute representing an FPGA job queue.
    Fpga = 3,
}

/// Direction of an accelerator SPSC ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceleratorRingDirection {
    /// QEMU-to-host job requests.
    Request,
    /// Host-to-QEMU job completions.
    Completion,
}

impl AcceleratorRingDirection {
    /// Returns the ABI-stable ring index for `vm_slot`.
    #[must_use]
    pub const fn ring_index(self, vm_slot: u32) -> Option<u32> {
        let offset = match self {
            Self::Request => ACCELERATOR_REQUEST_RING_OFFSET,
            Self::Completion => ACCELERATOR_COMPLETION_RING_OFFSET,
        };
        match vm_slot.checked_mul(ACCELERATOR_RINGS_PER_VM) {
            Some(base) => base.checked_add(offset),
            None => None,
        }
    }
}

/// One owned accelerator request or completion record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct AcceleratorEntry {
    sequence: u64,
    generation: u64,
    device_id: [u8; 32],
    class: u16,
    job_kind: u16,
    queue_id: u16,
    status: u16,
    protocol_version: u16,
    flags: u16,
    data_len: u32,
    service_units: u64,
    data: [u8; ACCELERATOR_ENTRY_DATA_BYTES],
    _reserved: [u8; 40],
}

impl Default for AcceleratorEntry {
    fn default() -> Self {
        Self {
            sequence: 0,
            generation: 0,
            device_id: [0; 32],
            class: 0,
            job_kind: 0,
            queue_id: 0,
            status: 0,
            protocol_version: 0,
            flags: 0,
            data_len: 0,
            service_units: 0,
            data: [0; ACCELERATOR_ENTRY_DATA_BYTES],
            _reserved: [0; 40],
        }
    }
}

/// Wire size of one [`AcceleratorEntry`].
pub const ACCELERATOR_ENTRY_SIZE: usize = core::mem::size_of::<AcceleratorEntry>();
/// Wire alignment of one [`AcceleratorEntry`].
pub const ACCELERATOR_ENTRY_ALIGN: usize = core::mem::align_of::<AcceleratorEntry>();
/// Byte offset of the sequence field.
pub const ACCELERATOR_ENTRY_SEQUENCE_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, sequence);
/// Byte offset of the process generation.
pub const ACCELERATOR_ENTRY_GENERATION_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, generation);
/// Byte offset of the device digest.
pub const ACCELERATOR_ENTRY_DEVICE_ID_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, device_id);
/// Byte offset of the class field.
pub const ACCELERATOR_ENTRY_CLASS_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, class);
/// Byte offset of the job-kind field.
pub const ACCELERATOR_ENTRY_JOB_KIND_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, job_kind);
/// Byte offset of the queue ID.
pub const ACCELERATOR_ENTRY_QUEUE_ID_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, queue_id);
/// Byte offset of the status field.
pub const ACCELERATOR_ENTRY_STATUS_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, status);
/// Byte offset of the protocol version.
pub const ACCELERATOR_ENTRY_PROTOCOL_VERSION_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, protocol_version);
/// Byte offset of the flags field.
pub const ACCELERATOR_ENTRY_FLAGS_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, flags);
/// Byte offset of the data length.
pub const ACCELERATOR_ENTRY_DATA_LEN_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, data_len);
/// Byte offset of deterministic service units.
pub const ACCELERATOR_ENTRY_SERVICE_UNITS_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, service_units);
/// Byte offset of job or result bytes.
pub const ACCELERATOR_ENTRY_DATA_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, data);
/// Byte offset of the reserved tail.
pub const ACCELERATOR_ENTRY_RESERVED_OFFSET: usize = core::mem::offset_of!(AcceleratorEntry, _reserved);

const _: () = assert!(core::mem::offset_of!(AcceleratorEntry, sequence) == 0);
const _: () = assert!(core::mem::offset_of!(AcceleratorEntry, generation) == 8);
const _: () = assert!(core::mem::offset_of!(AcceleratorEntry, device_id) == 16);
const _: () = assert!(core::mem::offset_of!(AcceleratorEntry, class) == 48);
const _: () = assert!(core::mem::offset_of!(AcceleratorEntry, data) == 72);
const _: () = assert!(ACCELERATOR_ENTRY_SIZE == 4_736);
const _: () = assert!(ACCELERATOR_ENTRY_ALIGN == 64);

impl AcceleratorEntry {
    /// Builds a canonical accelerator entry.
    ///
    /// # Errors
    ///
    /// Returns [`AcceleratorEntryError`] for zero identity fields, unsupported
    /// classes, an oversized payload, invalid flags, or a nonzero completion
    /// status on a request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        generation: u64,
        device_id: [u8; 32],
        class: AcceleratorClass,
        job_kind: u16,
        queue_id: u16,
        status: u16,
        completion: bool,
        service_units: u64,
        data: &[u8],
    ) -> Result<Self, AcceleratorEntryError> {
        if sequence == 0 || generation == 0 || device_id.iter().all(|byte| *byte == 0) {
            return Err(AcceleratorEntryError::InvalidIdentity);
        }
        if job_kind == 0 || service_units == 0 || (!completion && status != 0) {
            return Err(AcceleratorEntryError::InvalidJob);
        }
        if data.len() > ACCELERATOR_ENTRY_DATA_BYTES {
            return Err(AcceleratorEntryError::DataTooLarge {
                len: data.len(),
                capacity: ACCELERATOR_ENTRY_DATA_BYTES,
            });
        }
        let mut entry = Self {
            sequence,
            generation,
            device_id,
            class: class as u16,
            job_kind,
            queue_id,
            status,
            protocol_version: ACCELERATOR_PROTOCOL_VERSION,
            flags: u16::from(completion),
            data_len: u32::try_from(data.len()).map_err(|_error| {
                AcceleratorEntryError::DataTooLarge {
                    len: data.len(),
                    capacity: ACCELERATOR_ENTRY_DATA_BYTES,
                }
            })?,
            service_units,
            ..Self::default()
        };
        entry.data[..data.len()].copy_from_slice(data);
        Ok(entry)
    }

    /// Returns the publication sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 { self.sequence }

    /// Returns the immutable process generation.
    #[must_use]
    pub const fn generation(self) -> u64 { self.generation }

    /// Returns the stable device identity digest.
    #[must_use]
    pub const fn device_id(self) -> [u8; 32] { self.device_id }

    /// Returns the encoded accelerator class.
    #[must_use]
    pub const fn class(self) -> u16 { self.class }

    /// Returns the class-specific job kind.
    #[must_use]
    pub const fn job_kind(self) -> u16 { self.job_kind }

    /// Returns the device queue identifier.
    #[must_use]
    pub const fn queue_id(self) -> u16 { self.queue_id }

    /// Returns the completion status, or zero for requests.
    #[must_use]
    pub const fn status(self) -> u16 { self.status }

    /// Returns deterministic service units for the job.
    #[must_use]
    pub const fn service_units(self) -> u64 { self.service_units }

    /// Returns whether this record is a completion.
    #[must_use]
    pub const fn is_completion(self) -> bool { self.flags == 1 }

    /// Returns the owned job or result bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AcceleratorEntryError`] if the copied cross-process record is
    /// malformed.
    pub fn data(&self) -> Result<&[u8], AcceleratorEntryError> {
        self.validate_ref()?;
        Ok(&self.data[..self.data_len as usize])
    }

    /// Validates an entry copied from shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`AcceleratorEntryError`] for any noncanonical field or byte.
    pub fn validate(self) -> Result<Self, AcceleratorEntryError> {
        self.validate_ref()?;
        Ok(self)
    }

    fn validate_ref(&self) -> Result<(), AcceleratorEntryError> {
        if self.sequence == 0 || self.generation == 0 ||
            self.device_id.iter().all(|byte| *byte == 0) {
            return Err(AcceleratorEntryError::InvalidIdentity);
        }
        if self.protocol_version != ACCELERATOR_PROTOCOL_VERSION ||
            !matches!(self.class, 1..=3) || self.job_kind == 0 ||
            self.service_units == 0 || self.flags > 1 ||
            (self.flags == 0 && self.status != 0) {
            return Err(AcceleratorEntryError::InvalidJob);
        }
        let len = self.data_len as usize;
        if len > ACCELERATOR_ENTRY_DATA_BYTES {
            return Err(AcceleratorEntryError::DataTooLarge {
                len,
                capacity: ACCELERATOR_ENTRY_DATA_BYTES,
            });
        }
        if self.data[len..].iter().any(|byte| *byte != 0) ||
            self._reserved.iter().any(|byte| *byte != 0) {
            return Err(AcceleratorEntryError::NonzeroReservedBytes);
        }
        Ok(())
    }
}

/// Invalid accelerator shared-memory record.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AcceleratorEntryError {
    /// Sequence, generation, or device identity was zero.
    #[error("accelerator entry identity is invalid")]
    InvalidIdentity,
    /// Class, job, status, flags, protocol, or service units were invalid.
    #[error("accelerator entry job envelope is invalid")]
    InvalidJob,
    /// Payload length exceeded the fixed entry capacity.
    #[error("accelerator data length {len} exceeds capacity {capacity}")]
    DataTooLarge {
        /// Rejected byte length.
        len: usize,
        /// Fixed byte capacity.
        capacity: usize,
    },
    /// Unused payload or reserved bytes were nonzero.
    #[error("accelerator entry reserved bytes are nonzero")]
    NonzeroReservedBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accelerator_entry_round_trips_and_rejects_tail_bytes() {
        let entry = AcceleratorEntry::new(
            1, 2, [3; 32], AcceleratorClass::Gpu, 1, 0, 0, false, 4,
            &[1, 2, 3, 4],
        ).unwrap_or_else(|error| panic!("entry should build: {error}"));
        assert_eq!(entry.data(), Ok(&[1, 2, 3, 4][..]));
        let mut malformed = entry;
        malformed.data[4] = 1;
        assert_eq!(malformed.validate(), Err(AcceleratorEntryError::NonzeroReservedBytes));
    }
}
