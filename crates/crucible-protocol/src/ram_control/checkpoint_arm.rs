//! Fixed checkpoint request basis and receipt on the independent RAM channel.
//!
//! ```text
//! Request tag 9: original[80]; one SCM_RIGHTS on the first framing byte
//! Reply tag 129: digest[32], disposition:u8, request_generation:u64,
//!                first_status:i32, post_status:i32 (all integers big endian)
//! ```
//!
//! The original describes an existing host operation. Neither the encoded basis
//! nor a generation or digest creates a native request, stop, or execution loan.

use super::{RamControlDisposition, RamControlError};

/// Fixed extent of an immutable checkpoint Quiescence basis.
pub const RAM_CONTROL_CHECKPOINT_ORIGINAL_BYTES: usize = 80;

/// Maximum fixed body extent for checkpoint ARM requests and custody replies.
pub const RAM_CONTROL_CHECKPOINT_MAX_BYTES: usize = 238;

/// Observes actual checkpoint request custody before QMP consumes the request.
///
/// An accepted receipt certifies only retention of the native pending owner.
/// A refusal can still name an owner born before a failed independent postcut;
/// that generation must remain observable through containment and reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlCheckpointArmReceipt {
    /// Actual receiver disposition; acceptance supplies no stopped-state proof.
    pub disposition: RamControlDisposition,
    /// Actual retained request generation, or zero if no owner was born.
    pub request_generation: u64,
    /// Raw initiating native status, kept independently of the postcut.
    pub first_status: i32,
    /// Raw native postcut status after the attempted retention.
    pub post_status: i32,
}

impl RamControlCheckpointArmReceipt {
    /// Checks the canonical relationship between acceptance and custody status.
    ///
    /// # Errors
    /// Refuses acceptance without an actual generation or with either failure.
    pub fn validate(self) -> Result<(), RamControlError> {
        if self.disposition == RamControlDisposition::Accepted
            && (self.request_generation == 0 || self.first_status != 0 || self.post_status != 0)
        {
            return Err(RamControlError::InvalidFrame);
        }
        Ok(())
    }
}

/// Checks the fixed syntax of an existing checkpoint original without issuing it.
///
/// Native receipt independently validates the actual event, live original,
/// registered worker, containing purpose, and retained runtime owner.
///
/// # Errors
/// Refuses another basis format, absent cap/operation identity, or invalid fixed
/// monotonic bounds. This check alone provides no supervision or native custody.
pub fn validate_checkpoint_original(
    original: &[u8; RAM_CONTROL_CHECKPOINT_ORIGINAL_BYTES],
) -> Result<(), RamControlError> {
    let number = |offset| {
        original
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(RamControlError::InvalidFrame)
    };
    if &original[..8] != b"CRUCPAU1"
        || original[8..12] != 1_u32.to_be_bytes()
        || original[12..16] != 80_u32.to_be_bytes()
        || original[16..48] == [0; 32]
        || number(48)? == 0
        || number(56)? == 0
        || number(64)? <= number(56)?
        || number(72)? == 0
    {
        return Err(RamControlError::InvalidFrame);
    }
    Ok(())
}
