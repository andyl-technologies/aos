//! Non-authorizing deployment proof for the fixed runtime-owner bootstrap tuple.
//!
//! `AOSRBT01` is an independently provisioned signer pin and deployment-epoch
//! floor. It must come from a deployment credential outside Host-writable state.
//! `AOSRBP01` signs the exact `AOSRBM01` bytes and kernel fs-verity measurement:
//!
//! ```text
//! AOSRBT01 || signer_generation:u64be || minimum_deployment_epoch:u64be
//! || signer_public_key[32]
//!
//! AOSRBP01 || version:u16be=1 || reserved[6]=0
//! || signer_generation:u64be || deployment_epoch:u64be || host_boot_id[16]
//! || sandbox[16] || incarnation[16] || node[16]
//! || assignment_epoch:u64be || assignment_digest[32]
//! || desired_generation:u64be || namespace_generation:u64be
//! || manifest_sha256[32] || manifest_fsverity_sha256[32] || signature[64]
//! ```
//!
//! Verification is deliberately pure. A caller-supplied pin, currentness, or
//! measurement is not proof of deployment origin, a kernel measurement, or a
//! monotonic floor. The external deployment owner must advance the floor and
//! prevent rollback of that credential across process and machine restarts.
//! Neither the fixed bootstrap writer nor Host startup calls
//! this module until an external publisher and journal-replay join exist.

use aos_sandbox_core::runtime_backend::RuntimeCurrentnessV1;
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    SandboxId,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{
    BOOTSTRAP_MANIFEST_BYTES, BOOTSTRAP_MANIFEST_MAGIC, CAPABILITIES_BYTES, CAPABILITIES_MAGIC,
    CURRENTNESS_BYTES, CURRENTNESS_MAGIC, HOST_EVIDENCE_BYTES, HOST_EVIDENCE_MAGIC, PEER_BYTES,
    PEER_MAGIC, PEER_PROVISION_TRANSACTION_FRAME_COUNT, PLAN_CATALOG_BYTES, PLAN_CATALOG_MAGIC,
    resolve_currentness, validate_record,
};

const PIN_MAGIC: &[u8; 8] = b"AOSRBT01";
const PROOF_MAGIC: &[u8; 8] = b"AOSRBP01";
const PROOF_VERSION: u16 = 1;
const PIN_BYTES: usize = 56;
const SIGNED_BYTES: usize = 216;
const PROOF_BYTES: usize = SIGNED_BYTES + 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.runtime-bootstrap.deployment-proof.v1\0";
const _: () = assert!(BOOTSTRAP_MANIFEST_BYTES == 932);
const _: () = assert!(PIN_BYTES == 56 && PROOF_BYTES == 280);

/// Reports malformed or unbound deployment bootstrap evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeBootstrapProofErrorV1 {
    /// The externally supplied signer pin or floor is malformed.
    #[error("runtime bootstrap trust pin is malformed")]
    Pin,
    /// The proof has an unknown version, reserved bytes, or malformed fields.
    #[error("runtime bootstrap proof is malformed")]
    Proof,
    /// The proof signature does not verify under the pinned signer.
    #[error("runtime bootstrap proof signature is invalid")]
    Signature,
    /// Signer generation or deployment epoch is below the external floor.
    #[error("runtime bootstrap proof is stale")]
    Replay,
    /// The proof differs from independent boot or assignment currentness.
    #[error("runtime bootstrap proof currentness differs")]
    Currentness,
    /// The fixed manifest is malformed or differs from the signed tuple.
    #[error("runtime bootstrap manifest differs")]
    Manifest,
    /// The fs-verity measurement differs from the signed measurement.
    #[error("runtime bootstrap fs-verity measurement differs")]
    Measurement,
}

/// Holds an external signer pin and monotonic deployment-epoch floor.
///
/// Decoding checks shape, not provenance. The future Host consumer must read
/// these bytes from a separately managed PID 1 credential, not its state root.
#[derive(Clone)]
pub struct RuntimeBootstrapSignerPinV1 {
    signer_generation: u64,
    minimum_deployment_epoch: u64,
    signer: VerifyingKey,
}

impl RuntimeBootstrapSignerPinV1 {
    /// Decodes the exact versioned deployment trust credential.
    ///
    /// # Errors
    ///
    /// Rejects an unknown version, wrong length, zero generation or floor, or
    /// invalid Ed25519 public key.
    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeBootstrapProofErrorV1> {
        if bytes.len() != PIN_BYTES || bytes.get(..8) != Some(PIN_MAGIC.as_slice()) {
            return Err(RuntimeBootstrapProofErrorV1::Pin);
        }
        let signer_generation = read_u64(bytes, 8, RuntimeBootstrapProofErrorV1::Pin)?;
        let minimum_deployment_epoch = read_u64(bytes, 16, RuntimeBootstrapProofErrorV1::Pin)?;
        let public_key = read_array(bytes, 24, RuntimeBootstrapProofErrorV1::Pin)?;
        if signer_generation == 0 || minimum_deployment_epoch == 0 || public_key == [0; 32] {
            return Err(RuntimeBootstrapProofErrorV1::Pin);
        }
        let signer =
            VerifyingKey::from_bytes(&public_key).map_err(|_| RuntimeBootstrapProofErrorV1::Pin)?;

        Ok(Self {
            signer_generation,
            minimum_deployment_epoch,
            signer,
        })
    }
}

/// Supplies independently established boot and assignment currentness.
///
/// This value alone is nonauthorizing. A future consumer must join it to the
/// current kernel boot and protected Controller assignment/desired proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeBootstrapExpectationV1 {
    host_boot_id: [u8; 16],
    currentness: RuntimeCurrentnessV1,
}

impl RuntimeBootstrapExpectationV1 {
    /// Constructs one nonzero expected boot and typed currentness pair.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero Host boot identifier.
    pub fn new(
        host_boot_id: [u8; 16],
        currentness: RuntimeCurrentnessV1,
    ) -> Result<Self, RuntimeBootstrapProofErrorV1> {
        if host_boot_id == [0; 16] {
            return Err(RuntimeBootstrapProofErrorV1::Currentness);
        }
        Ok(Self {
            host_boot_id,
            currentness,
        })
    }
}

/// Carries one canonical deployment signature without granting bootstrap authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBootstrapProofV1 {
    signed: [u8; SIGNED_BYTES],
    signer_generation: u64,
    deployment_epoch: u64,
    host_boot_id: [u8; 16],
    currentness: RuntimeCurrentnessV1,
    manifest_digest: [u8; 32],
    manifest_verity: [u8; 32],
    signature: Signature,
}

impl RuntimeBootstrapProofV1 {
    /// Decodes the exact, separately versioned deployment proof.
    ///
    /// # Errors
    ///
    /// Rejects an unknown version, wrong length, nonzero reserved bytes, or
    /// sentinel currentness. Decoding does not establish signature authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeBootstrapProofErrorV1> {
        if bytes.len() != PROOF_BYTES
            || bytes.get(..8) != Some(PROOF_MAGIC.as_slice())
            || read_array::<2>(bytes, 8, RuntimeBootstrapProofErrorV1::Proof)?
                != PROOF_VERSION.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(RuntimeBootstrapProofErrorV1::Proof);
        }
        let signer_generation = read_u64(bytes, 16, RuntimeBootstrapProofErrorV1::Proof)?;
        let deployment_epoch = read_u64(bytes, 24, RuntimeBootstrapProofErrorV1::Proof)?;
        let host_boot_id = read_array(bytes, 32, RuntimeBootstrapProofErrorV1::Proof)?;
        let currentness = RuntimeCurrentnessV1::new(
            SandboxId::from_bytes(read_array(bytes, 48, RuntimeBootstrapProofErrorV1::Proof)?),
            IncarnationId::from_bytes(read_array(bytes, 64, RuntimeBootstrapProofErrorV1::Proof)?),
            NodeId::from_bytes(read_array(bytes, 80, RuntimeBootstrapProofErrorV1::Proof)?),
            AssignmentEpoch::new(read_u64(bytes, 96, RuntimeBootstrapProofErrorV1::Proof)?),
            ObjectDigest::from_bytes(read_array(bytes, 104, RuntimeBootstrapProofErrorV1::Proof)?),
            DesiredGeneration::new(read_u64(bytes, 136, RuntimeBootstrapProofErrorV1::Proof)?),
            NamespaceGeneration::new(read_u64(bytes, 144, RuntimeBootstrapProofErrorV1::Proof)?),
        )
        .map_err(|_| RuntimeBootstrapProofErrorV1::Proof)?;
        let manifest_digest = read_array(bytes, 152, RuntimeBootstrapProofErrorV1::Proof)?;
        let manifest_verity = read_array(bytes, 184, RuntimeBootstrapProofErrorV1::Proof)?;
        if signer_generation == 0
            || deployment_epoch == 0
            || host_boot_id == [0; 16]
            || manifest_digest == [0; 32]
            || manifest_verity == [0; 32]
        {
            return Err(RuntimeBootstrapProofErrorV1::Proof);
        }

        let signed = read_array(bytes, 0, RuntimeBootstrapProofErrorV1::Proof)?;
        let signature_bytes = read_array(bytes, SIGNED_BYTES, RuntimeBootstrapProofErrorV1::Proof)?;
        Ok(Self {
            signed,
            signer_generation,
            deployment_epoch,
            host_boot_id,
            currentness,
            manifest_digest,
            manifest_verity,
            signature: Signature::from_bytes(&signature_bytes),
        })
    }

    /// Checks the independent pin, replay floor, currentness, and exact tuple.
    ///
    /// `measured_verity` must eventually come from a retained, kernel-measured
    /// fs-verity FD; accepting a caller's arbitrary bytes does not authorize
    /// [`crate::runtime_execution::DormantRuntimeExecutionOwnerV1::bootstrap_fixed`].
    ///
    /// # Errors
    ///
    /// Rejects a wrong signer, stale epoch, changed boot or assignment, invalid
    /// signature, malformed fixed manifest, or changed manifest/measurement.
    pub fn verify(
        &self,
        manifest: &[u8],
        measured_verity: [u8; 32],
        pin: &RuntimeBootstrapSignerPinV1,
        expected: &RuntimeBootstrapExpectationV1,
    ) -> Result<(), RuntimeBootstrapProofErrorV1> {
        if self.signer_generation != pin.signer_generation
            || self.deployment_epoch < pin.minimum_deployment_epoch
        {
            return Err(RuntimeBootstrapProofErrorV1::Replay);
        }
        if self.host_boot_id != expected.host_boot_id || self.currentness != expected.currentness {
            return Err(RuntimeBootstrapProofErrorV1::Currentness);
        }

        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNED_BYTES);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&self.signed);
        pin.signer
            .verify_strict(&message, &self.signature)
            .map_err(|_| RuntimeBootstrapProofErrorV1::Signature)?;

        if self.manifest_verity != measured_verity {
            return Err(RuntimeBootstrapProofErrorV1::Measurement);
        }
        if manifest.len() != BOOTSTRAP_MANIFEST_BYTES
            || manifest.get(..8) != Some(BOOTSTRAP_MANIFEST_MAGIC.as_slice())
            || Sha256::digest(manifest).as_slice() != self.manifest_digest
        {
            return Err(RuntimeBootstrapProofErrorV1::Manifest);
        }
        let checksum_start = BOOTSTRAP_MANIFEST_BYTES - 32;
        if Sha256::digest(&manifest[..checksum_start]).as_slice() != &manifest[checksum_start..] {
            return Err(RuntimeBootstrapProofErrorV1::Manifest);
        }
        let mut cursor = 8;
        let peer = take_record(manifest, &mut cursor, PEER_BYTES, PEER_MAGIC)?;
        let currentness = take_record(manifest, &mut cursor, CURRENTNESS_BYTES, CURRENTNESS_MAGIC)?;
        let capabilities = take_record(
            manifest,
            &mut cursor,
            CAPABILITIES_BYTES,
            CAPABILITIES_MAGIC,
        )?;
        let host_evidence = take_record(
            manifest,
            &mut cursor,
            HOST_EVIDENCE_BYTES,
            HOST_EVIDENCE_MAGIC,
        )?;
        let plan_catalog = take_record(
            manifest,
            &mut cursor,
            PLAN_CATALOG_BYTES,
            PLAN_CATALOG_MAGIC,
        )?;
        if cursor != checksum_start {
            return Err(RuntimeBootstrapProofErrorV1::Manifest);
        }
        let resolved = resolve_currentness(
            PEER_PROVISION_TRANSACTION_FRAME_COUNT,
            peer,
            currentness,
            capabilities,
            host_evidence,
            plan_catalog,
        )
        .map_err(|_| RuntimeBootstrapProofErrorV1::Manifest)?;
        if resolved.currentness.runtime().currentness() != &self.currentness
            || resolved.host_verifier.boot_id() != self.host_boot_id
        {
            return Err(RuntimeBootstrapProofErrorV1::Manifest);
        }

        Ok(())
    }
}

fn take_record<'a>(
    manifest: &'a [u8],
    cursor: &mut usize,
    length: usize,
    magic: &[u8; 8],
) -> Result<&'a [u8], RuntimeBootstrapProofErrorV1> {
    let end = cursor
        .checked_add(length)
        .ok_or(RuntimeBootstrapProofErrorV1::Manifest)?;
    let record = manifest
        .get(*cursor..end)
        .ok_or(RuntimeBootstrapProofErrorV1::Manifest)?;
    validate_record(record, magic, length).map_err(|_| RuntimeBootstrapProofErrorV1::Manifest)?;
    *cursor = end;
    Ok(record)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    error: RuntimeBootstrapProofErrorV1,
) -> Result<[u8; N], RuntimeBootstrapProofErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(error)
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
    error: RuntimeBootstrapProofErrorV1,
) -> Result<u64, RuntimeBootstrapProofErrorV1> {
    read_array(bytes, offset, error).map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests;
