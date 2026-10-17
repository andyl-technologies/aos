//! Historical source-selected evidence after original construction callbacks.
//!
//! These values describe one immutable native post-Applied observation. Neither
//! its flags nor matching hashes establish an ACK, current suspension, input
//! closure, exact capture, or readiness. The original startup observation remains
//! a different object. Implementations must authenticate the native query and
//! retained initialization journal independently.
//!
//! ```text
//! facts248 = version:u32be, size:u32be, flags:u32be, reserved:u32be,
//! init_sequence:u64be, hold_generation:u64be, current_ps:u64be,
//! retired_count:u64be, scope[32], initialization[32], realize[32],
//! original_cut[32], applied_receipt_sha256[32], content_length:u64be,
//! content_sha256[32]
//! ```

use super::{NativeCommandError, codec::Cursor};
use crucible_node_contract::U64;

/// Bounds the entire immutable preparation-successor object before allocation.
pub const NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Identifies one source-selected historical post-initialization observation.
///
/// Edition one records only Applied and no execution at capture. It carries no
/// native ACK or readiness claim and can remain cached after later execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePreparationSuccessorFacts {
    /// Identifies the exact original initialization command.
    pub initialization_sequence: U64,
    /// Preserves the actual native HOLD lifetime, distinct from content identity.
    pub hold_generation: U64,
    /// Records the original zero construction clock, never a current clock claim.
    pub current_ps: U64,
    /// Records original zero retirement, never an instruction phase projection.
    pub retired_count: U64,
    /// Binds the complete originally pinned prepared scope.
    pub prepared_scope_hash: [u8; 32],
    /// Binds the complete original initialization preparation.
    pub initialization_commitment: [u8; 32],
    /// Binds the actual original Realize envelope.
    pub realize_request_digest: [u8; 32],
    /// Binds the source-selected original callback cut.
    pub original_cut_digest: [u8; 32],
    /// Binds the tagged SHA-256 of the exact original Applied receipt.
    pub applied_receipt_sha256: [u8; 32],
    /// Bounds the complete canonical source object.
    pub content_length: U64,
    /// Binds the SHA-256 of the exact canonical source object bytes.
    pub content_sha256: [u8; 32],
}

impl NativePreparationSuccessorFacts {
    /// Validates finite historical fields without authenticating native custody.
    ///
    /// # Errors
    /// Rejects missing identities, nonzero construction progress, zero HOLD or
    /// sequence, and absent or excessive immutable object extents.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.initialization_sequence.get() == 0
            || self.hold_generation.get() == 0
            || self.current_ps.get() != 0
            || self.retired_count.get() != 0
            || self.content_length.get() == 0
            || self.content_length.get() > NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES as u64
            || [
                self.prepared_scope_hash,
                self.initialization_commitment,
                self.realize_request_digest,
                self.original_cut_digest,
                self.applied_receipt_sha256,
                self.content_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(NativeCommandError::Invalid(
                "invalid historical preparation successor",
            ));
        }
        Ok(())
    }

    /// Encodes closed historical flags without adding an ACK or Ready bit.
    ///
    /// # Errors
    /// Rejects any field that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; 248], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 248];
        for (offset, value) in [(0, 1u32), (4, 248), (8, 3), (12, 0)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (16, self.initialization_sequence),
            (24, self.hold_generation),
            (32, self.current_ps),
            (40, self.retired_count),
            (208, self.content_length),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.get().to_be_bytes());
        }
        for (offset, value) in [
            (48, &self.prepared_scope_hash),
            (80, &self.initialization_commitment),
            (112, &self.realize_request_digest),
            (144, &self.original_cut_digest),
            (176, &self.applied_receipt_sha256),
            (216, &self.content_sha256),
        ] {
            bytes[offset..offset + 32].copy_from_slice(value);
        }
        Ok(bytes)
    }

    /// Decodes exactly one fixed historical facts record.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, open flags or reserved fields, wrong
    /// edition/size, or any invalid finite historical field.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 248 {
            return Err(NativeCommandError::Invalid(
                "preparation successor facts extent",
            ));
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != 248 || cursor.u32()? != 3 || cursor.u32()? != 0 {
            return Err(NativeCommandError::Invalid(
                "preparation successor facts format",
            ));
        }
        let value = Self {
            initialization_sequence: U64::new(cursor.u64()?),
            hold_generation: U64::new(cursor.u64()?),
            current_ps: U64::new(cursor.u64()?),
            retired_count: U64::new(cursor.u64()?),
            prepared_scope_hash: cursor.array()?,
            initialization_commitment: cursor.array()?,
            realize_request_digest: cursor.array()?,
            original_cut_digest: cursor.array()?,
            applied_receipt_sha256: cursor.array()?,
            content_length: U64::new(cursor.u64()?),
            content_sha256: cursor.array()?,
        };
        value.validate()?;
        Ok(value)
    }
}
