//! Private framing for role-specific, public Ed25519 verifier credentials.
//!
//! Callers retain separate public types and supply their fixed role magic and
//! checksum domain. Decoding these bytes does not establish key custody.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

pub(crate) const ROLE_CREDENTIAL_BYTES: usize = 80;

pub(crate) fn decode_role_credential(
    bytes: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Option<(u64, VerifyingKey)> {
    if bytes.len() != ROLE_CREDENTIAL_BYTES || bytes.get(..8) != Some(magic.as_slice()) {
        return None;
    }

    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..48])
        .finalize();
    if bytes[48..] != checksum[..] {
        return None;
    }

    let generation = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    let key = VerifyingKey::from_bytes(bytes[16..48].try_into().ok()?).ok()?;
    (generation != 0).then_some((generation, key))
}

pub(crate) fn encode_role_credential(
    generation: u64,
    key: &VerifyingKey,
    magic: &[u8; 8],
    domain: &[u8],
) -> Option<[u8; ROLE_CREDENTIAL_BYTES]> {
    if generation == 0 {
        return None;
    }

    let mut bytes = [0; ROLE_CREDENTIAL_BYTES];
    bytes[..8].copy_from_slice(magic);
    bytes[8..16].copy_from_slice(&generation.to_be_bytes());
    bytes[16..48].copy_from_slice(key.as_bytes());
    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..48])
        .finalize();
    bytes[48..].copy_from_slice(&checksum);
    Some(bytes)
}
