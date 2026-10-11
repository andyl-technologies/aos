use aos_sandbox_core::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};

use super::{
    OwnershipAuthorityError, OwnershipClaimV1, ProtectedLeaseAuthorityErrorV1,
    UnverifiedOwnershipLeaseResponse, fixed_bootstrap_error,
};

pub(super) fn decode_bootstrap(
    bytes: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), ProtectedLeaseAuthorityErrorV1> {
    if bytes.len() < 8 + 4 + 32 + 32 || &bytes[..8] != b"AOSMOL01" {
        return Err(fixed_bootstrap_error());
    }
    let (payload, retained_checksum) = bytes.split_at(bytes.len() - 32);
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.ownership-bootstrap.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_checksum != expected_checksum {
        return Err(fixed_bootstrap_error());
    }
    let mut reader = BoundedReader::new(&payload[8..], |_| fixed_bootstrap_error());
    let policy_length =
        usize::try_from(reader.u32()?).map_err(|_| fixed_bootstrap_error())?;
    if policy_length == 0 || policy_length > 64 * 1024 {
        return Err(fixed_bootstrap_error());
    }
    let policy_bytes = reader.bytes(policy_length)?.to_vec();
    let public_key = reader.array()?;
    if !reader.is_empty() {
        return Err(fixed_bootstrap_error());
    }
    Ok((policy_bytes, public_key))
}

pub(super) fn decode_fixed_issuer_response(
    bytes: &[u8],
    claim: &OwnershipClaimV1,
) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
    if bytes.len() < 8 + 16 + 32 + 16 + 32 || &bytes[..8] != b"AOSMOI01" {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    let (payload, retained_checksum) = bytes.split_at(bytes.len() - 32);
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.ownership-response.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_checksum != expected_checksum {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    let mut reader = BoundedReader::new(&payload[8..], |_| OwnershipAuthorityError::Unavailable);
    let request_id: [u8; 16] = reader.array()?;
    let claim_digest: [u8; 32] = reader.array()?;
    if &request_id != claim.request_id() || claim_digest != *claim.digest().as_bytes() {
        return Err(OwnershipAuthorityError::IdempotencyConflict);
    }
    let lease = read_artifact(&mut reader, 64 * 1024)?;
    let signature = read_artifact(&mut reader, 64 * 1024)?;
    let receipt = read_artifact(&mut reader, 1024)?;
    let receipt_signature = read_artifact(&mut reader, 64 * 1024)?;
    if !reader.is_empty() {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    UnverifiedOwnershipLeaseResponse::from_transport(
        lease.to_vec(),
        signature.to_vec(),
        receipt.to_vec(),
        receipt_signature.to_vec(),
    )
    .map_err(|_| OwnershipAuthorityError::Internal)
}

fn read_artifact<'a>(
    reader: &mut BoundedReader<'a, OwnershipAuthorityError>,
    maximum: usize,
) -> Result<&'a [u8], OwnershipAuthorityError> {
    let length = usize::try_from(reader.u32()?)
        .map_err(|_| OwnershipAuthorityError::Unavailable)?;
    if length == 0 || length > maximum {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    reader.bytes(length)
}

#[cfg(test)]
mod tests;
