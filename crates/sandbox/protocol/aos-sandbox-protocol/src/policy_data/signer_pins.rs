//! Encodes and decodes the saved two-role Policy signer-pin tuple DATA.
//!
//! The existing 120-byte format contains only public verifier information:
//!
//! ```text
//! AOSPKP01 | deployment generation:u64be | deployment key:[u8;32]
//!          | project generation:u64be | project key:[u8;32]
//!          | SHA-256(domain || preceding bytes):[u8;32]
//! ```
//!
//! Canonical framing and nonzero generations do not establish protected pin
//! custody, native currentness, signing authority or admission.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

/// Reports the exact historical Policy public tuple codec failure.
#[derive(Debug, thiserror::Error)]
pub enum PolicySignerPinsDataErrorV1 {
    /// A requested generation or fixed integer field is invalid.
    #[error("invalid deployment signer generation or field")]
    InvalidHead,
    /// The canonical saved tuple framing, public key or bytes differ.
    #[error("stale or malformed deployment signer tuple")]
    StaleHead,
}

const SIGNER_PINS_MAGIC: &[u8; 8] = b"AOSPKP01";

/// Names the unchanged canonical two-role policy signer-pin record width.
pub const POLICY_SIGNER_PINS_BYTES_V1: usize = SIGNER_PINS_MAGIC.len() + 2 * 8 + 2 * 32 + 32;
const SIGNER_PINS_DOMAIN: &[u8] = b"aos.sandbox.policy-signer-pins.v1\0";

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn encode_policy_signer_pins_v1(
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<Vec<u8>, PolicySignerPinsDataErrorV1> {
    if deployment_generation == 0 || project_generation == 0 {
        return Err(PolicySignerPinsDataErrorV1::InvalidHead);
    }
    let mut encoded = Vec::with_capacity(POLICY_SIGNER_PINS_BYTES_V1);
    encoded.extend_from_slice(SIGNER_PINS_MAGIC);
    encoded.extend_from_slice(&deployment_generation.to_be_bytes());
    encoded.extend_from_slice(deployment_key.as_bytes());
    encoded.extend_from_slice(&project_generation.to_be_bytes());
    encoded.extend_from_slice(project_key.as_bytes());
    let checksum = Sha256::new()
        .chain_update(SIGNER_PINS_DOMAIN)
        .chain_update(&encoded)
        .finalize();
    encoded.extend_from_slice(&checksum);
    Ok(encoded)
}

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn decode_policy_signer_pins_v1(
    pins: &[u8],
) -> Result<(u64, VerifyingKey, u64, VerifyingKey), PolicySignerPinsDataErrorV1> {
    if pins.len() != POLICY_SIGNER_PINS_BYTES_V1 || &pins[..8] != SIGNER_PINS_MAGIC {
        return Err(PolicySignerPinsDataErrorV1::StaleHead);
    }
    let deployment_generation = read_u64(pins, 8)?;
    let project_generation = read_u64(pins, 48)?;
    let key_at = |offset: usize| {
        let bytes = pins
            .get(offset..offset + 32)
            .and_then(|field| field.try_into().ok())
            .ok_or(PolicySignerPinsDataErrorV1::StaleHead)?;
        VerifyingKey::from_bytes(bytes).map_err(|_| PolicySignerPinsDataErrorV1::StaleHead)
    };
    let deployment = key_at(16)?;
    let project = key_at(56)?;
    if encode_policy_signer_pins_v1(
        deployment_generation,
        &deployment,
        project_generation,
        &project,
    )?
    .as_slice()
        != pins
    {
        return Err(PolicySignerPinsDataErrorV1::StaleHead);
    }
    Ok((
        deployment_generation,
        deployment,
        project_generation,
        project,
    ))
}

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PolicySignerPinsDataErrorV1> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|part| part.try_into().ok())
            .ok_or(PolicySignerPinsDataErrorV1::InvalidHead)?,
    ))
}
