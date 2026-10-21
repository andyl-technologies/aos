//! Dedicated prepaid bounds for the original Guest argument observation.
//!
//! These passive amounts grant no observation or execution permission. Host
//! pays them with its actual Accept20 before nonce creation and Guest traffic.

/// Bounds the actual Guest helper controls checked against its compiled types.
///
/// The Guest assertion names its real owner, return, argument and error planes.
/// This is a receiving byte ceiling, independent of native policy/resource caps.
pub const ARGUMENT_GUEST_CONTROL_BYTES_V1: usize = 64 * 1024;

/// Prices the unchanged receive ceiling and actual signing scratch separately.
///
/// The native receiver's two samples, headers and descriptor slots are supplied
/// separately by the exact installed Linux Authorize transport helper. This
/// amount covers the decoded request, request encoding, subject, signing message
/// and returned packet planes using their existing closed codec ceilings.
#[must_use]
pub fn argument_guest_receiving_bytes_v1() -> Option<usize> {
    super::runtime_argument_observation::MAXIMUM_REQUEST_BYTES.checked_mul(8)?
        .checked_add(super::runtime_argument_observation::MAXIMUM_READBACK_BYTES.checked_mul(8)?)?
        .checked_add(super::runtime_argument_observation::GUEST_ARGUMENT_READBACK_SIGNATURE_DOMAIN_V1.len().checked_mul(2)?)?
        .checked_add(ARGUMENT_GUEST_CONTROL_BYTES_V1)
}
