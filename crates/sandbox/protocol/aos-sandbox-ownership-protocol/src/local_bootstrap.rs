//! Decodes the fixed local Ownership bootstrap without admitting its provenance.
//!
//! ```text
//! bootstrap = "AOSMOL01" | policy-length:u32be | policy | public-key32 |
//!             sha256("aos.sandbox.multi-node.ownership-bootstrap.v1\0" | payload)
//! ```
//!
//! Native consumers retain their own protected files and pay before decoding.

use aos_sandbox_model::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};

/// Reports invalid framing without constructing a trust anchor or native owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("local Ownership bootstrap framing is invalid")]
pub struct LocalOwnershipBootstrapDataErrorV1;

/// Returns the bounded raw policy and public key from the sole framing engine.
///
/// # Errors
/// Rejects malformed framing, checksum, empty/oversized policy or trailing bytes.
pub fn decode_local_ownership_bootstrap_data_v1(
    bytes: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), LocalOwnershipBootstrapDataErrorV1> {
    decode_with_error(bytes, || LocalOwnershipBootstrapDataErrorV1)
}

/// Preserves a protected caller's original framing error class.
///
/// # Errors
/// Returns the supplied error for exactly the same invalid encodings.
pub fn decode_local_ownership_bootstrap_with_error_v1<E>(
    bytes: &[u8],
    invalid: impl Fn() -> E + Copy,
) -> Result<(Vec<u8>, [u8; 32]), E> {
    decode_with_error(bytes, invalid)
}

fn decode_with_error<E>(
    bytes: &[u8],
    invalid: impl Fn() -> E + Copy,
) -> Result<(Vec<u8>, [u8; 32]), E> {
    if bytes.len() < 8 + 4 + 32 + 32 || &bytes[..8] != b"AOSMOL01" {
        return Err(invalid());
    }
    let (payload, retained_checksum) = bytes.split_at(bytes.len() - 32);
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.ownership-bootstrap.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_checksum != expected_checksum {
        return Err(invalid());
    }
    let mut reader = BoundedReader::new(&payload[8..], |cause| cause);
    let policy_length = usize::try_from(reader.u32().map_err(|_| invalid())?).map_err(|_| invalid())?;
    if policy_length == 0 || policy_length > 64 * 1024 {
        return Err(invalid());
    }
    let policy_bytes = reader.bytes(policy_length).map_err(|_| invalid())?.to_vec();
    let public_key = reader.array().map_err(|_| invalid())?;
    if !reader.is_empty() {
        return Err(invalid());
    }
    Ok((policy_bytes, public_key))
}
