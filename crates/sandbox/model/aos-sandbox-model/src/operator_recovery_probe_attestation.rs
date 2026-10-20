//! Owner-signed exact Storage Repair admission-probe preimage.
//!
//! The signed payload is separate from the V2 terminal receipt. It exposes
//! every byte hashed by Storage's admission probe, so the controller can
//! independently recompute that digest and compare selected physical fields
//! with a separately authenticated broker inventory. A signature alone does
//! not prove that a live broker-session query occurred.
//!
//! ```text
//! AOSOPA01 | owner-id[16] | owner-key-generation:u64be | effect-id[32]
//!          | probe-epoch:u32be | preimage-length:u16be | reserved[2]
//!          | probe-preimage[preimage-length]
//!          | ed25519-signature[64]
//! ```

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSOPA01";
const SIGN_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-probe-attestation.v1\0";
const PROBE_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-repair-admission-probe.v2\0";
const HEADER_BYTES: usize = 72;
const SIGNATURE_BYTES: usize = 64;
const MINIMUM_PREIMAGE_BYTES: usize = 438;
const MAXIMUM_PREIMAGE_BYTES: usize = 1024;

/// Rejects malformed, stale-generation, or unauthenticated probe attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperatorRecoveryProbeAttestationErrorV1 {
    /// The packet or exact probe preimage violates its versioned contract.
    #[error("operator Repair probe attestation is malformed")]
    Invalid,
    /// The owner signature or deployment-pinned identity does not match.
    #[error("operator Repair probe attestation owner is not trusted")]
    Owner,
}

/// Retains the verified exact pre-effect probe and selected public facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOperatorRecoveryProbeAttestationV1 {
    owner_id: [u8; 16],
    owner_key_generation: u64,
    effect_id: [u8; 32],
    probe_epoch: u32,
    preimage: Vec<u8>,
    probe_digest: [u8; 32],
    repair_request_id: [u8; 16],
    repair_operation_id: [u8; 16],
    storage_request_digest: [u8; 32],
    assignment_digest: [u8; 32],
    workspace_handle: [u8; 32],
    catalog_generation: u64,
    catalog_digest: [u8; 32],
    dataset_name: String,
    dataset_guid: u64,
}

impl VerifiedOperatorRecoveryProbeAttestationV1 {
    /// Returns the pinned owner identity that signed the pre-effect probe.
    #[must_use]
    pub const fn owner_id(&self) -> [u8; 16] {
        self.owner_id
    }

    /// Returns the deployment-pinned owner signing generation.
    #[must_use]
    pub const fn owner_key_generation(&self) -> u64 {
        self.owner_key_generation
    }

    /// Returns the exact controller-issued Storage effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Returns the durable sidecar probe generation before effect dispatch.
    #[must_use]
    pub const fn probe_epoch(&self) -> u32 {
        self.probe_epoch
    }

    /// Returns the exact bytes hashed by the Storage admission probe.
    #[must_use]
    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }

    /// Returns the independent digest of that complete versioned probe.
    #[must_use]
    pub const fn probe_digest(&self) -> [u8; 32] {
        self.probe_digest
    }

    /// Returns the exact Storage Repair request ID covered by the probe.
    #[must_use]
    pub const fn repair_request_id(&self) -> [u8; 16] {
        self.repair_request_id
    }

    /// Returns the selected public Repair operation identity.
    #[must_use]
    pub const fn repair_operation_id(&self) -> [u8; 16] {
        self.repair_operation_id
    }

    /// Returns SHA-256 of the exact Storage Repair request body.
    #[must_use]
    pub const fn storage_request_digest(&self) -> [u8; 32] {
        self.storage_request_digest
    }

    /// Returns the exact assignment digest observed by Storage.
    #[must_use]
    pub const fn assignment_digest(&self) -> [u8; 32] {
        self.assignment_digest
    }

    /// Returns the exact selected workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    /// Returns the physical pre-effect catalog generation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns the physical pre-effect catalog digest.
    #[must_use]
    pub const fn catalog_digest(&self) -> [u8; 32] {
        self.catalog_digest
    }

    /// Returns the exact selected dataset name, without a lossy conversion.
    #[must_use]
    pub fn dataset_name(&self) -> &str {
        &self.dataset_name
    }

    /// Returns the selected physical dataset GUID.
    #[must_use]
    pub const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }
}

/// Signs a complete Storage admission-probe preimage under the pinned owner key.
///
/// # Errors
///
/// Rejects absent owner/effect identities or an invalid probe preimage.
pub fn sign_operator_recovery_probe_attestation_v1(
    owner_id: [u8; 16],
    owner_key_generation: u64,
    effect_id: [u8; 32],
    probe_epoch: u32,
    preimage: &[u8],
    key: &SigningKey,
) -> Result<Vec<u8>, OperatorRecoveryProbeAttestationErrorV1> {
    if owner_id == [0; 16] || owner_key_generation == 0 || effect_id == [0; 32] || probe_epoch == 0
    {
        return Err(OperatorRecoveryProbeAttestationErrorV1::Invalid);
    }
    validate_preimage(preimage)?;
    let length = u16::try_from(preimage.len())
        .map_err(|_| OperatorRecoveryProbeAttestationErrorV1::Invalid)?;
    let mut packet = Vec::with_capacity(HEADER_BYTES + preimage.len() + SIGNATURE_BYTES);
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&owner_id);
    packet.extend_from_slice(&owner_key_generation.to_be_bytes());
    packet.extend_from_slice(&effect_id);
    packet.extend_from_slice(&probe_epoch.to_be_bytes());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0; 2]);
    packet.extend_from_slice(preimage);
    let signature = key.sign(&[SIGN_DOMAIN, packet.as_slice()].concat());
    packet.extend_from_slice(&signature.to_bytes());
    Ok(packet)
}

/// Verifies a complete pre-effect probe under the exact deployed owner pin.
///
/// # Errors
///
/// Rejects another format, owner, key generation, effect, signature, or
/// noncanonical probe preimage. Old receipt formats are never reinterpreted.
pub fn verify_operator_recovery_probe_attestation_v1(
    packet: &[u8],
    owner_key: &VerifyingKey,
    owner_id: [u8; 16],
    owner_key_generation: u64,
    effect_id: [u8; 32],
    probe_epoch: u32,
) -> Result<VerifiedOperatorRecoveryProbeAttestationV1, OperatorRecoveryProbeAttestationErrorV1> {
    if packet.len() < HEADER_BYTES + MINIMUM_PREIMAGE_BYTES + SIGNATURE_BYTES
        || packet.get(..8) != Some(MAGIC.as_slice())
        || packet.get(8..24) != Some(owner_id.as_slice())
        || packet.get(24..32) != Some(owner_key_generation.to_be_bytes().as_slice())
        || packet.get(32..64) != Some(effect_id.as_slice())
        || packet.get(64..68) != Some(probe_epoch.to_be_bytes().as_slice())
        || packet.get(70..72) != Some([0; 2].as_slice())
        || owner_id == [0; 16]
        || owner_key_generation == 0
        || effect_id == [0; 32]
        || probe_epoch == 0
    {
        return Err(OperatorRecoveryProbeAttestationErrorV1::Invalid);
    }
    let length = u16::from_be_bytes(array(packet, 68)?) as usize;
    let signature_offset = HEADER_BYTES
        .checked_add(length)
        .ok_or(OperatorRecoveryProbeAttestationErrorV1::Invalid)?;
    if packet.len() != signature_offset + SIGNATURE_BYTES {
        return Err(OperatorRecoveryProbeAttestationErrorV1::Invalid);
    }
    let signature = Signature::from_bytes(&array(packet, signature_offset)?);
    owner_key
        .verify(
            &[SIGN_DOMAIN, &packet[..signature_offset]].concat(),
            &signature,
        )
        .map_err(|_| OperatorRecoveryProbeAttestationErrorV1::Owner)?;
    let preimage = &packet[HEADER_BYTES..signature_offset];
    let parsed = validate_preimage(preimage)?;
    let probe_digest = Sha256::new()
        .chain_update(PROBE_DOMAIN)
        .chain_update(preimage)
        .finalize()
        .into();
    Ok(VerifiedOperatorRecoveryProbeAttestationV1 {
        owner_id,
        owner_key_generation,
        effect_id,
        probe_epoch,
        preimage: preimage.to_vec(),
        probe_digest,
        repair_request_id: parsed.repair_request_id,
        repair_operation_id: parsed.repair_operation_id,
        storage_request_digest: parsed.storage_request_digest,
        assignment_digest: parsed.assignment_digest,
        workspace_handle: parsed.workspace_handle,
        catalog_generation: parsed.catalog_generation,
        catalog_digest: parsed.catalog_digest,
        dataset_name: parsed.dataset_name,
        dataset_guid: parsed.dataset_guid,
    })
}

struct ParsedPreimage {
    repair_request_id: [u8; 16],
    repair_operation_id: [u8; 16],
    storage_request_digest: [u8; 32],
    assignment_digest: [u8; 32],
    workspace_handle: [u8; 32],
    catalog_generation: u64,
    catalog_digest: [u8; 32],
    dataset_name: String,
    dataset_guid: u64,
}

fn validate_preimage(
    preimage: &[u8],
) -> Result<ParsedPreimage, OperatorRecoveryProbeAttestationErrorV1> {
    if !(MINIMUM_PREIMAGE_BYTES..=MAXIMUM_PREIMAGE_BYTES).contains(&preimage.len()) {
        return Err(OperatorRecoveryProbeAttestationErrorV1::Invalid);
    }
    let dataset_name_length = u16::from_be_bytes(array(preimage, 395)?) as usize;
    let name_end = 397_usize
        .checked_add(dataset_name_length)
        .ok_or(OperatorRecoveryProbeAttestationErrorV1::Invalid)?;
    if dataset_name_length == 0 || preimage.len() != name_end + 40 {
        return Err(OperatorRecoveryProbeAttestationErrorV1::Invalid);
    }
    let dataset_name = std::str::from_utf8(&preimage[397..name_end])
        .map_err(|_| OperatorRecoveryProbeAttestationErrorV1::Invalid)?;
    let parsed = ParsedPreimage {
        repair_request_id: array(preimage, 16)?,
        repair_operation_id: array(preimage, 32)?,
        storage_request_digest: array(preimage, 48)?,
        assignment_digest: array(preimage, 112)?,
        workspace_handle: array(preimage, 144)?,
        catalog_generation: u64::from_be_bytes(array(preimage, 209)?),
        catalog_digest: array(preimage, 217)?,
        dataset_name: dataset_name.to_owned(),
        dataset_guid: u64::from_be_bytes(array(preimage, name_end)?),
    };
    if preimage[..16] == [0; 16]
        || preimage[16..32] == [0; 16]
        || parsed.repair_operation_id == [0; 16]
        || parsed.storage_request_digest == [0; 32]
        || parsed.assignment_digest == [0; 32]
        || parsed.workspace_handle == [0; 32]
        || parsed.catalog_generation == 0
        || parsed.catalog_digest == [0; 32]
        || parsed.dataset_guid == 0
        || dataset_name.as_bytes().contains(&0)
        || preimage[name_end + 8..] == [0; 32]
    {
        return Err(OperatorRecoveryProbeAttestationErrorV1::Invalid);
    }
    Ok(parsed)
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OperatorRecoveryProbeAttestationErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(OperatorRecoveryProbeAttestationErrorV1::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preimage() -> Vec<u8> {
        let mut bytes = vec![0; 438];
        bytes[..16].fill(1);
        bytes[16..32].fill(2);
        bytes[32..48].fill(3);
        bytes[48..80].fill(4);
        bytes[112..144].fill(5);
        bytes[144..176].fill(6);
        bytes[209..217].copy_from_slice(&7_u64.to_be_bytes());
        bytes[217..249].fill(8);
        bytes[395..397].copy_from_slice(&1_u16.to_be_bytes());
        bytes[397] = b'x';
        bytes[398..406].copy_from_slice(&9_u64.to_be_bytes());
        bytes[406..438].fill(10);
        bytes
    }

    #[test]
    fn exact_preimage_and_owner_generation_are_signed() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let packet = sign_operator_recovery_probe_attestation_v1(
            [12; 16],
            13,
            [14; 32],
            15,
            &preimage(),
            &key,
        )
        .unwrap();
        let verified = verify_operator_recovery_probe_attestation_v1(
            &packet,
            &key.verifying_key(),
            [12; 16],
            13,
            [14; 32],
            15,
        )
        .unwrap();
        assert_eq!(verified.dataset_name(), "x");
        assert_eq!(verified.dataset_guid(), 9);
        assert_eq!(verified.catalog_generation(), 7);
        assert_eq!(verified.probe_epoch(), 15);
        let expected: [u8; 32] = Sha256::new()
            .chain_update(PROBE_DOMAIN)
            .chain_update(preimage())
            .finalize()
            .into();
        assert_eq!(verified.probe_digest(), expected);
        assert!(
            verify_operator_recovery_probe_attestation_v1(
                &packet,
                &key.verifying_key(),
                [12; 16],
                14,
                [14; 32],
                15,
            )
            .is_err()
        );
        assert!(
            verify_operator_recovery_probe_attestation_v1(
                &packet,
                &key.verifying_key(),
                [12; 16],
                13,
                [14; 32],
                16,
            )
            .is_err()
        );
        let mut tampered = packet;
        tampered[HEADER_BYTES + 397] = b'y';
        assert!(
            verify_operator_recovery_probe_attestation_v1(
                &tampered,
                &key.verifying_key(),
                [12; 16],
                13,
                [14; 32],
                15,
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_and_noncanonical_preimages_fail_closed() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let mut malformed = preimage();
        malformed[395..397].copy_from_slice(&2_u16.to_be_bytes());
        assert!(
            sign_operator_recovery_probe_attestation_v1(
                [12; 16], 13, [14; 32], 15, &malformed, &key,
            )
            .is_err()
        );
        let mut packet = sign_operator_recovery_probe_attestation_v1(
            [12; 16],
            13,
            [14; 32],
            15,
            &preimage(),
            &key,
        )
        .unwrap();
        packet[..8].copy_from_slice(b"AOSOPA00");
        assert!(
            verify_operator_recovery_probe_attestation_v1(
                &packet,
                &key.verifying_key(),
                [12; 16],
                13,
                [14; 32],
                15,
            )
            .is_err()
        );
    }
}
