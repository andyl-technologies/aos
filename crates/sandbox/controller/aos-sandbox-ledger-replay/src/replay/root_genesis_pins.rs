//! Owns the saved Root public verifier tuple and its signature comparisons.
//!
//! Fixed public-key bytes are historical DATA. Live Root code separately owns
//! independent credentials, current deployment association and writer custody.

use aos_sandbox_model::ObjectDigest;
use ed25519_dalek::VerifyingKey;
use aos_sandbox_protocol::role_credential::decode_role_credential;
use aos_sandbox_protocol::controller_source_seed::PinnedControllerSourceTreeSeedIssuerV1;
use aos_sandbox_protocol::publisher_project_authorization::{
    PinnedPublisherProjectAuthorizationIssuerV2, verify_signed_project_authorization_claims_v2,
};
use crate::data::{SourceSuccessorDataErrorV2 as SourceGenesisErrorV1, hash, take};

pub use aos_sandbox_protocol::policy_data::signer_pins::{
    POLICY_SIGNER_PINS_BYTES_V1, PolicySignerPinsDataErrorV1,
    decode_policy_signer_pins_v1, encode_policy_signer_pins_v1, read_u64,
};

/// Decodes Controller-purpose public DATA without establishing pin custody.
pub fn decode_controller_hold_signer_data_v1(bytes: &[u8]) -> Option<(u64, VerifyingKey)> {
    decode_role_credential(bytes, b"AOSCTK01", b"aos.sandbox.controller-policy-hold.verifier.v1\0")
}

/// Decodes Source-purpose public DATA without establishing pin custody.
pub fn decode_source_hold_signer_data_v1(bytes: &[u8]) -> Option<(u64, VerifyingKey)> {
    decode_role_credential(bytes, b"AOSSPK01", b"aos.sandbox.source-hold-readback-verifier.v1\0")
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

/// Preserves a refused administrative comparison without native role authority.
#[derive(Debug, thiserror::Error)]
pub enum RootAdministrativePinsDataErrorV1 {
    /// The original canonical seed, authorization or signature check refused.
    #[error(transparent)]
    Data(#[from] crate::data::SourceSuccessorDataErrorV2),
    /// The complete saved administrative role tuple has another commitment.
    #[error("Source genesis owner or credential is not current")]
    Stale,
}

/// Verifies the exact administrative input against a complete saved role tuple.
///
/// The tuple and acceptance are DATA. Native callers separately retain their
/// actual fixed writer and independent credential originals and currentness.
///
/// # Errors
/// Preserves the original seed, authorization and signature errors, and refuses
/// a different whole administrative role commitment without granting admission.
pub fn verify_administrative_input_data_v1(
    encoded: &[u8; 488],
    acceptance: &aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1,
) -> Result<(), RootAdministrativePinsDataErrorV1> {
    use aos_sandbox_protocol::controller_source_seed::{
        ControllerSourceTreeSeedExpectedV1, verify_controller_source_tree_seed_v1,
    };

    let verified = (|| -> Result<(), SourceGenesisErrorV1> {
        let seed_pin = PinnedControllerSourceTreeSeedIssuerV1::decode(&encoded[16..96])?;
        let authorization_pin =
            PinnedPublisherProjectAuthorizationIssuerV2::decode(&encoded[96..176])?;
        let seed = acceptance.seed_claims()?;
        let expected = ControllerSourceTreeSeedExpectedV1::new(
            seed.project(),
            seed.publisher_generation(),
            seed.publisher_head(),
            seed.project_authorization_head(),
            seed.request_id(),
            seed.epoch() - 1,
        )?;
        verify_controller_source_tree_seed_v1(acceptance.seed_packet(), &seed_pin, expected)?;
        verify_signed_project_authorization_claims_v2(
            acceptance.auth_packet(),
            &authorization_pin,
        )?;
        Ok(())
    })();
    verified?;
    if acceptance.administrative_roles()
        != hash(
            b"aos.sandbox.source-genesis.administrative-roles.v1\0",
            &encoded[16..176],
        )
    {
        return Err(RootAdministrativePinsDataErrorV1::Stale);
    }
    Ok(())
}
