//! Owns the saved Root public verifier tuple and its signature comparisons.
//!
//! Fixed public-key bytes are historical DATA. Live Root code separately owns
//! independent credentials, current deployment association and writer custody.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::role_credential::decode_role_credential;
use aos_sandbox_protocol::controller_source_seed::PinnedControllerSourceTreeSeedIssuerV1;
use aos_sandbox_protocol::publisher_project_authorization::{
    PinnedPublisherProjectAuthorizationIssuerV2, verify_signed_project_authorization_claims_v2,
};
use crate::data::{SourceSuccessorDataErrorV2 as SourceGenesisErrorV1, hash, take};

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

/// Decodes Controller-purpose public DATA without establishing pin custody.
pub fn decode_controller_hold_signer_data_v1(bytes: &[u8]) -> Option<(u64, VerifyingKey)> {
    decode_role_credential(bytes, b"AOSCTK01", b"aos.sandbox.controller-policy-hold.verifier.v1\0")
}

/// Decodes Source-purpose public DATA without establishing pin custody.
pub fn decode_source_hold_signer_data_v1(bytes: &[u8]) -> Option<(u64, VerifyingKey)> {
    decode_role_credential(bytes, b"AOSSPK01", b"aos.sandbox.source-hold-readback-verifier.v1\0")
}

const SIGNER_PINS_MAGIC: &[u8; 8] = b"AOSPKP01";
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
    let mut encoded = Vec::with_capacity(120);
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
    if pins.len() != 120 || &pins[..8] != SIGNER_PINS_MAGIC {
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

const MAGIC: &[u8; 8] = b"AOSGPK01";
const DOMAIN: &[u8] = b"aos.sandbox.source-genesis.root-role-pins.v1\0";
const BYTES: usize = 488;

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn verify_retained_first_source_successor_v2(
    encoded: &[u8],
    packet: &crate::successor::SourceSuccessorApprovalDataV2,
) -> Result<(), SourceGenesisErrorV1> {
    decode(encoded)?;
    let seed = PinnedControllerSourceTreeSeedIssuerV1::decode(&encoded[16..96])?;
    let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(&encoded[96..176])
        .map_err(SourceGenesisErrorV1::from)?;
    if u64::from_be_bytes(take(packet.body(), 16)?)
        != seed.generation()
        || &packet.body()[112..144] != role_tuple_digest(encoded)?.as_bytes()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }

    packet.verify_signature(seed.verifying_key())?;
    verify_signed_project_authorization_claims_v2(packet.authorization_packet(), &authorization)
        .map_err(SourceGenesisErrorV1::from)?;
    Ok(())
}

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn role_tuple_digest(bytes: &[u8]) -> Result<ObjectDigest, SourceGenesisErrorV1> {
    decode(bytes)?;
    Ok(hash(DOMAIN, bytes))
}

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn encode(
    seed: &[u8; 80],
    authorization: &[u8; 80],
    controller: &[u8; 80],
    source: &[u8; 80],
    deployment: &[u8; 120],
) -> Result<[u8; BYTES], SourceGenesisErrorV1> {
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    for (range, value) in [
        (16..96, seed.as_slice()),
        (96..176, authorization.as_slice()),
        (176..256, controller.as_slice()),
        (256..336, source.as_slice()),
        (336..456, deployment.as_slice()),
    ] {
        bytes[range].copy_from_slice(value);
    }
    let checksum = hash(DOMAIN, &bytes[..456]);
    bytes[456..].copy_from_slice(checksum.as_bytes());
    decode(&bytes)?;
    Ok(bytes)
}

/// Applies the existing canonical saved public-verifier comparison.
///
/// # Errors
/// Rejects malformed framing, noncanonical generations or failed exact verification.
pub fn decode(bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
    if bytes.len() != BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
        || hash(DOMAIN, &bytes[..456]).as_bytes() != &bytes[456..]
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let seed = PinnedControllerSourceTreeSeedIssuerV1::decode(&bytes[16..96])?;
    let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(&bytes[96..176])
        .map_err(SourceGenesisErrorV1::from)?;
    let controller = decode_controller_hold_signer_data_v1(&bytes[176..256]).ok_or(SourceGenesisErrorV1::NonCanonical)
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let source = decode_source_hold_signer_data_v1(&bytes[256..336]).ok_or(SourceGenesisErrorV1::NonCanonical)
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let (_, deployment, _, project) = decode_policy_signer_pins_v1(&bytes[336..456])
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let keys = [
        seed.verifying_key(),
        authorization.verifying_key(),
        &controller.1,
        &source.1,
        &deployment,
        &project,
    ];
    for (index, key) in keys.iter().enumerate() {
        if keys[..index].contains(key) {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
    }
    Ok(())
}
