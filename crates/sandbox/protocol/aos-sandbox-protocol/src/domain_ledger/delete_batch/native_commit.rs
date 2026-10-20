//! Formats the existing Delete native COMMIT coordinates as passive DATA.
//!
//! ```text
//! native64 = transaction16 | COMMIT-payload-digest32 | sequence:u64be | end:u64be
//! ```
//!
//! Real roles obtain every input from the same canonical native parser. This
//! formatter cannot establish that provenance, a pending fence or currentness.

use super::LifecycleModelError;

/// Encodes the existing exact native-coordinate representation without authority.
///
/// # Errors
/// Rejects a COMMIT digest whose width differs from the existing 32-byte format.
pub fn encode_native_commit_data_v1(transaction: [u8; 16], commit_sequence: u64,
    end_offset: u64, native_digest: &[u8],
) -> Result<[u8; 64], LifecycleModelError> {
    if native_digest.len() != 32 { return Err(LifecycleModelError::CorruptEncoding); }
    let mut proof = [0; 64];
    proof[..16].copy_from_slice(&transaction);
    proof[16..48].copy_from_slice(native_digest);
    proof[48..56].copy_from_slice(&commit_sequence.to_be_bytes());
    proof[56..64].copy_from_slice(&end_offset.to_be_bytes());
    Ok(proof)
}
