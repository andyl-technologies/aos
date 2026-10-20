//! Nonauthorizing signed readback of a protected source-domain policy hold.
//!
//! The Source owner signs only while its fixed journal writer is held and the
//! retained hierarchy head matches the durable hold. A verifier needs an
//! independently provisioned Source-purpose public key and a fresh challenge.
//! These codecs establish neither key custody nor a live Root exchange.
//!
//! ```text
//! AOSSRB01 | version:u16 | reserved[6]=0 | signer-generation:u64 |
//! nonce[16] | root-cut[32] | project[16] | operation[16] | sandbox[16] |
//! controller-source[32] | ancestry[32] | binding[32] | epoch:u64 |
//! Ed25519 signature[64]
//!
//! AOSSPK01 | signer-generation:u64 | Ed25519 public key[32] |
//! SHA-256(Source-key-domain || preceding 48 bytes)[32]
//! ```

use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use thiserror::Error;

use aos_sandbox_protocol::role_credential::encode_role_credential;

/// Names the legacy hold comparison framing.
#[doc(hidden)]
pub const MAGIC: &[u8; 8] = b"AOSSRB01";
const KEY_MAGIC: &[u8; 8] = b"AOSSPK01";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.source-hold-readback-verifier.v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-hold-readback.signature.v1\0";
/// Bounds the legacy hold unsigned comparison body.
#[doc(hidden)]
pub const BODY_BYTES: usize = 224;
/// Bounds one signed Source hold/head readback packet.
pub const SOURCE_HOLD_READBACK_BYTES_V1: usize = BODY_BYTES + 64;
const KEY_BYTES: usize = 80;

/// Reports a malformed, stale, or unauthenticated Source readback.
#[derive(Debug, Error)]
pub enum SourceHoldReadbackErrorV1 {
    /// The protected Source owner could not establish the exact held head.
    #[error("protected Source hold or hierarchy head is not current")]
    Stale,
    /// The packet, challenge, or verifier credential is not canonical.
    #[error("invalid Source hold readback framing")]
    NonCanonical,
    /// The Source-purpose signature does not verify.
    #[error("invalid Source hold readback signature")]
    Signature,
}

/// Binds one Source answer to a caller-selected session and root source cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceHoldReadbackChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
}

impl SourceHoldReadbackChallengeV1 {
    /// Constructs a nonzero challenge for one exact root source cut.
    ///
    /// # Errors
    ///
    /// Rejects a zero nonce or cut.
    pub fn new(nonce: [u8; 16], cut: ObjectDigest) -> Result<Self, SourceHoldReadbackErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        Ok(Self { nonce, cut })
    }

    /// Returns the session nonce to send to the protected Source owner.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the root-authenticated source cut bound by this challenge.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }
}

/// Retains an independently supplied Source-purpose public key generation.
///
/// Decoding does not establish key custody. A future root exchange must pin
/// these exact bytes from a privileged deployment source.
pub struct PinnedSourceHoldReadbackSignerV1 {
    generation: u64,
    key: VerifyingKey,
}

impl PinnedSourceHoldReadbackSignerV1 {
    /// Decodes the exact Source-purpose verifier credential.
    ///
    /// # Errors
    ///
    /// Rejects a foreign role, altered checksum, zero generation, or bad key.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceHoldReadbackErrorV1> {
        let (generation, key) = crate::replay::root_genesis_pins::decode_source_hold_signer_data_v1(bytes)
            .ok_or(SourceHoldReadbackErrorV1::NonCanonical)?;
        Ok(Self { generation, key })
    }

    /// Returns the exact pinned Source signer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the Source-purpose public key for protected root admission.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Encodes a public-only Source verifier credential for offline provisioning.
///
/// This does not install a trust root or grant Q04 authority.
///
/// # Errors
///
/// Rejects generation zero.
pub fn encode_source_hold_readback_signer_credential_v1(
    generation: u64,
    key: &VerifyingKey,
) -> Result<[u8; KEY_BYTES], SourceHoldReadbackErrorV1> {
    encode_role_credential(generation, key, KEY_MAGIC, KEY_DOMAIN)
        .ok_or(SourceHoldReadbackErrorV1::NonCanonical)
}

/// Checks a signed Source statement against an independently expected hold.
///
/// A valid signature proves only what its key asserted for this challenge.
/// Root must separately establish signer custody, fresh challenge spending,
/// and simultaneous Controller and Cache currentness before any Q04 SUBMIT.
///
/// # Errors
///
/// Rejects changed fields, a released or mismatched hold, wrong key role or
/// generation, malformed framing, or an invalid signature.
pub fn verify_current_source_hold_readback_v1(
    packet: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceDomainPolicyHoldV1,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if packet.len() != SOURCE_HOLD_READBACK_BYTES_V1
        || project.as_bytes() == &[0; 16]
        || !expected.is_held()
        || packet.get(..8) != Some(MAGIC)
        || take::<2>(packet, 8)? != 1_u16.to_be_bytes()
        || take::<6>(packet, 10)? != [0; 6]
        || u64::from_be_bytes(take::<8>(packet, 16)?) != signer.generation
        || take::<16>(packet, 24)? != challenge.nonce
        || take::<32>(packet, 40)? != *challenge.cut.as_bytes()
        || take::<16>(packet, 72)? != *project.as_bytes()
        || take::<16>(packet, 88)? != *expected.operation().as_bytes()
        || take::<16>(packet, 104)? != *expected.sandbox().as_bytes()
        || take::<32>(packet, 120)? != *expected.controller_source().as_bytes()
        || take::<32>(packet, 152)? != *expected.ancestry().as_bytes()
        || take::<32>(packet, 184)? != *expected.binding().as_bytes()
        || take::<8>(packet, 216)? != expected.epoch().to_be_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(packet, BODY_BYTES)?);
    signer
        .key
        .verify_strict(&signature_preimage(&packet[..BODY_BYTES]), &signature)
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)
}

/// Signs supplied comparison fields without establishing writer custody.
pub fn sign_fields(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    hold: SourceDomainPolicyHoldV1,
    generation: u64,
    signing_key: &SigningKey,
) -> [u8; SOURCE_HOLD_READBACK_BYTES_V1] {
    let mut packet = [0; SOURCE_HOLD_READBACK_BYTES_V1];
    packet[..BODY_BYTES]
        .copy_from_slice(&source_hold_body_v1(challenge, project, hold, generation));
    let signature = signing_key.sign(&signature_preimage(&packet[..BODY_BYTES]));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    packet
}

/// Encodes supplied held fields as comparison DATA.
pub fn source_hold_body_v1(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    hold: SourceDomainPolicyHoldV1,
    generation: u64,
) -> [u8; BODY_BYTES] {
    let mut packet = [0; BODY_BYTES];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
    packet[16..24].copy_from_slice(&generation.to_be_bytes());
    packet[24..40].copy_from_slice(&challenge.nonce);
    packet[40..72].copy_from_slice(challenge.cut.as_bytes());
    packet[72..88].copy_from_slice(project.as_bytes());
    packet[88..104].copy_from_slice(hold.operation().as_bytes());
    packet[104..120].copy_from_slice(hold.sandbox().as_bytes());
    packet[120..152].copy_from_slice(hold.controller_source().as_bytes());
    packet[152..184].copy_from_slice(hold.ancestry().as_bytes());
    packet[184..216].copy_from_slice(hold.binding().as_bytes());
    packet[216..224].copy_from_slice(&hold.epoch().to_be_bytes());
    packet
}

/// Builds the legacy hold comparison signature preimage.
#[doc(hidden)]
pub fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceHoldReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(SourceHoldReadbackErrorV1::NonCanonical)
}

