//! Encodes original startup-operation evidence beside the fixed workspace record.
//!
//! The launch owner enters Setup before child birth, retains that exact guard,
//! and binds its process-contract cancellation event. This codec validates data;
//! it cannot create that guard, authenticate its issuer, or admit native storage.
//!
//! ```text
//! 0..80     original guard basis (CRUCSTP1/schema2/length128/cap/id/start/end/poll)
//! 80..88    actual process generation
//! 88..96    cancellation event device
//! 96..104   cancellation event inode
//! 104..108  inherited cancellation descriptor number
//! 108..112  flags = 1 (same retained process-contract event)
//! 112..120  nonzero kernel eventfd-id + 1 token (not shared anon-inode identity)
//! 120..128  unchanged registered-world native TOTAL metadata bytes
//! ```

use thiserror::Error;

/// Canonical encoded bytes in one original startup-operation record.
pub const STARTUP_OPERATION_BYTES: usize = 128;

/// Describes an already-issued original operation and its actual cancellation role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupOperationFields {
    /// Exact preexisting supervisor cap identity.
    pub cap_id: [u8; 32],
    /// Already-entered Setup operation identity, retained by the launch owner.
    pub operation_id: u64,
    /// Shared-kernel original operation coordinate, never a new native clock origin.
    pub original_start_ns: u64,
    /// Conservative minimum original total, progress, outer, and invocation end.
    pub absolute_end_ns: u64,
    /// Original responsive poll ceiling, capped again by the absolute end.
    pub poll_ns: u64,
    /// Actual process incarnation to which the record was issued before birth.
    pub process_generation: u64,
    /// Actual same-process-contract cancellation event device identity.
    pub cancellation_device: u64,
    /// Actual same-process-contract cancellation event inode identity.
    pub cancellation_inode: u64,
    /// Existing nonzero eventfd-id + 1 token for the same retained event.
    pub cancellation_event_id: u64,
    /// Process-local inherited descriptor for the same event, checked before effects.
    pub cancellation_descriptor: i32,
    /// Unchanged native TOTAL from the same retained registered-world resource owner.
    ///
    /// The matched native consumer pins and compares this issued value before
    /// context birth. Syntactic decoding alone does not grant these bytes.
    pub original_total_metadata_bytes: u64,
}

/// Contains syntactically validated evidence for one original startup operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupOperation {
    fields: StartupOperationFields,
}

impl StartupOperation {
    /// Validates fixed framing terms and original operation identities.
    ///
    /// # Errors
    /// Refuses absent identities, invalid deadlines, or invalid descriptor roles.
    /// Validation grants neither a clock nor resources to a native caller.
    pub fn new(fields: StartupOperationFields) -> Result<Self, StartupOperationError> {
        if fields.cap_id == [0; 32]
            || fields.operation_id == 0
            || fields.original_start_ns == 0
            || fields.absolute_end_ns <= fields.original_start_ns
            || fields.poll_ns == 0
            || fields.process_generation == 0
            || fields.cancellation_inode == 0
            || fields.cancellation_event_id == 0
            || fields.cancellation_descriptor <= 2
            || fields.original_total_metadata_bytes == 0
        {
            return Err(StartupOperationError::InvalidTerms);
        }
        Ok(Self { fields })
    }

    /// Borrows the original-operation evidence without issuing its authority.
    #[must_use]
    pub const fn fields(&self) -> &StartupOperationFields {
        &self.fields
    }

    /// Encodes exactly one fixed record without allocating storage.
    #[must_use]
    pub fn encode(&self) -> [u8; STARTUP_OPERATION_BYTES] {
        let mut bytes = [0; STARTUP_OPERATION_BYTES];
        bytes[..8].copy_from_slice(b"CRUCSTP1");
        bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&(STARTUP_OPERATION_BYTES as u32).to_be_bytes());
        bytes[16..48].copy_from_slice(&self.fields.cap_id);
        for (offset, value) in [
            (48, self.fields.operation_id),
            (56, self.fields.original_start_ns),
            (64, self.fields.absolute_end_ns),
            (72, self.fields.poll_ns),
            (80, self.fields.process_generation),
            (88, self.fields.cancellation_device),
            (96, self.fields.cancellation_inode),
            (112, self.fields.cancellation_event_id),
            (120, self.fields.original_total_metadata_bytes),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[104..108].copy_from_slice(&self.fields.cancellation_descriptor.to_be_bytes());
        bytes[108..112].copy_from_slice(&1_u32.to_be_bytes());
        bytes
    }

    /// Decodes exactly one fixed original startup-operation record.
    ///
    /// # Errors
    /// Refuses invalid length, magic, schema, flags, or terms.
    pub fn decode(bytes: &[u8]) -> Result<Self, StartupOperationError> {
        let bytes: &[u8; STARTUP_OPERATION_BYTES] = bytes
            .try_into()
            .map_err(|_| StartupOperationError::InvalidFraming)?;
        let u32_at = |offset: usize| {
            let mut value = [0; 4];
            value.copy_from_slice(&bytes[offset..offset + 4]);
            u32::from_be_bytes(value)
        };
        let u64_at = |offset: usize| {
            let mut value = [0; 8];
            value.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_be_bytes(value)
        };
        if bytes[..8] != *b"CRUCSTP1"
            || u32_at(8) != 2
            || u32_at(12) != STARTUP_OPERATION_BYTES as u32
            || u32_at(108) != 1
        {
            return Err(StartupOperationError::InvalidFraming);
        }
        let mut cap_id = [0; 32];
        cap_id.copy_from_slice(&bytes[16..48]);
        Self::new(StartupOperationFields {
            cap_id,
            operation_id: u64_at(48),
            original_start_ns: u64_at(56),
            absolute_end_ns: u64_at(64),
            poll_ns: u64_at(72),
            process_generation: u64_at(80),
            cancellation_device: u64_at(88),
            cancellation_inode: u64_at(96),
            cancellation_event_id: u64_at(112),
            original_total_metadata_bytes: u64_at(120),
            cancellation_descriptor: i32::try_from(u32_at(104))
                .map_err(|_| StartupOperationError::InvalidTerms)?,
        })
    }
}

/// Invalid fixed original startup-operation evidence.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StartupOperationError {
    /// Length, magic, schema, or flags differ.
    #[error("original startup operation framing is invalid")]
    InvalidFraming,
    /// An original identity, deadline, or descriptor role is invalid.
    #[error("original startup operation terms are invalid")]
    InvalidTerms,
}
