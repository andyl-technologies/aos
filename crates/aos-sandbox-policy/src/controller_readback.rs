//! Verifies Controller-purpose public readback DATA without native authority.
//!
//! The canonical fixed credential and signed AOSCTW01 packet retain their
//! exact role domains, bounds and strict Ed25519 verification. A decoded pin
//! establishes no protected custody; a verified receipt supplies no writer
//! lock, selected currentness, Q04 borrower or publication permission. Genuine
//! Root owners reverify original packets against their actual protected pins.
//!
//! ```text
//! AOSCTW01 | version:u16 | reserved:u16 | signer-generation:u64 |
//! root-nonce:16 | root-session-cut:32 | Controller-UID:u32 |
//! journal-sequence:u64 | operation:16 | sandbox:16 | source:32 |
//! binding:32 | epoch:u64 | Ed25519 signature:64
//! AOSCTK01 | signer-generation:u64 | public-key:32 | checksum:32
//! ```

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use aos_sandbox_protocol::role_credential::{decode_role_credential, encode_role_credential};
use ed25519_dalek::{Signature, VerifyingKey};

const MAGIC: &[u8; 8] = b"AOSCTW01";
const KEY_MAGIC: &[u8; 8] = b"AOSCTK01";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 184;
const CREDENTIAL_BYTES: usize = 80;
const SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-hold.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold.verifier.v1\0";

/// Bounds the exact signed Controller policy-hold receipt.
pub const CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Bounds the exact public Controller credential DATA envelope.
pub const CLOSED_CONTROLLER_HOLD_CREDENTIAL_BYTES_V1: usize = CREDENTIAL_BYTES;

/// Bounds the existing signed Controller receipt's exact unsigned body.
pub const CONTROLLER_HOLD_READBACK_BODY_BYTES_V1: usize = BODY_BYTES;

/// Names one root writer session without supplying an expected Controller hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerHoldReadbackChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
}

impl ControllerHoldReadbackChallengeV1 {
    /// Constructs a nonzero root-generated challenge and session commitment.
    ///
    /// # Errors
    ///
    /// Rejects a zero nonce or cut.
    pub fn new(
        nonce: [u8; 16],
        cut: ObjectDigest,
    ) -> Result<Self, ControllerHoldReadbackDataErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(ControllerHoldReadbackDataErrorV1::NonCanonical);
        }
        Ok(Self { nonce, cut })
    }

    /// Returns the root-generated nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the root-owned session commitment.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }
}

/// Retains a distinct Controller-hold verifier generation and public key.
///
/// Decoding does not establish deployment custody. Root must load these bytes
/// from its own fixed credential and reconcile the pin with its journal.
pub struct PinnedControllerHoldSignerV1 {
    generation: u64,
    key: VerifyingKey,
}

impl PinnedControllerHoldSignerV1 {
    /// Decodes one Controller-only public credential.
    ///
    /// # Errors
    ///
    /// Rejects a foreign role, zero generation, malformed key, or alteration.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControllerHoldReadbackDataErrorV1> {
        let (generation, key) = decode_role_credential(bytes, KEY_MAGIC, KEY_DOMAIN)
            .ok_or(ControllerHoldReadbackDataErrorV1::NonCanonical)?;
        Ok(Self { generation, key })
    }

    /// Returns the deployment-pinned signer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the Controller-only public verification key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Encodes a public-only Controller signer credential for offline provisioning.
///
/// # Errors
///
/// Rejects a zero generation. This does not install a trust root.
pub fn encode_controller_hold_signer_credential_v1(
    generation: u64,
    key: &VerifyingKey,
) -> Result<[u8; CREDENTIAL_BYTES], ControllerHoldReadbackDataErrorV1> {
    encode_role_credential(generation, key, KEY_MAGIC, KEY_DOMAIN)
        .ok_or(ControllerHoldReadbackDataErrorV1::NonCanonical)
}

/// Reports a signed Controller hold checked against a root-held challenge.
///
/// This is nonauthorizing evidence. In particular, its copied sequence is not
/// a transferable writer lock, and root still needs a source-domain witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedControllerHoldReadbackV1 {
    controller_uid: u32,
    journal_sequence: u64,
    operation: OperationId,
    sandbox: SandboxId,
    source: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
}

impl VerifiedControllerHoldReadbackV1 {
    /// Returns the protected Controller owner UID claimed by the signer.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.controller_uid
    }

    /// Returns the checked diagnostic journal sequence.
    #[must_use]
    pub const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }

    /// Returns the exact held public Create operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact held sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the rejoined Controller source commitment.
    #[must_use]
    pub const fn source(self) -> ObjectDigest {
        self.source
    }

    /// Returns the held proposed root binding.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the held root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Verifies a Controller-only receipt against a root-owned challenge and pin.
///
/// The caller must obtain the pin from root deployment custody, not from the
/// receipt or Controller. Signature verification alone cannot prove a held
/// writer or enable Q04, publication, or Create.
///
/// # Errors
///
/// Rejects wrong role/generation, nonce/cut, UID, malformed fields, or signature.
pub fn verify_controller_hold_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerHoldReadbackChallengeV1,
    expected_uid: u32,
) -> Result<VerifiedControllerHoldReadbackV1, ControllerHoldReadbackDataErrorV1> {
    if bytes.len() != CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1 {
        return Err(ControllerHoldReadbackDataErrorV1::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES];
    if body[..8] != MAGIC[..]
        || take::<2>(body, 8)? != VERSION.to_be_bytes()
        || take::<2>(body, 10)? != [0; 2]
        || u64::from_be_bytes(take::<8>(body, 12)?) != signer.generation
        || take::<16>(body, 20)? != challenge.nonce
        || take::<32>(body, 36)? != *challenge.cut.as_bytes()
    {
        return Err(ControllerHoldReadbackDataErrorV1::Stale);
    }
    let fields = VerifiedControllerHoldReadbackV1 {
        controller_uid: u32::from_be_bytes(take::<4>(body, 68)?),
        journal_sequence: u64::from_be_bytes(take::<8>(body, 72)?),
        operation: OperationId::from_bytes(take::<16>(body, 80)?),
        sandbox: SandboxId::from_bytes(take::<16>(body, 96)?),
        source: ObjectDigest::from_bytes(take::<32>(body, 112)?),
        binding: ObjectDigest::from_bytes(take::<32>(body, 144)?),
        epoch: u64::from_be_bytes(take::<8>(body, 176)?),
    };
    fields.validate(expected_uid)?;
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    signer
        .key
        .verify_strict(&signature_preimage(body), &signature)
        .map_err(|_| ControllerHoldReadbackDataErrorV1::Signature)?;
    Ok(fields)
}

/// Retains unsigned Controller hold fields as nonauthorizing comparison DATA.
///
/// This value is not a verified receipt, current hold or signing permission.
/// Only the actual Controller owner supplies its fields to its native signer.
///
/// Unsigned fields cannot substitute for the private verified representation:
///
/// ```compile_fail
/// use aos_sandbox_policy::controller_readback::{
///     ControllerHoldReadbackFieldsDataV1, VerifiedControllerHoldReadbackV1,
/// };
/// fn substitute(fields: ControllerHoldReadbackFieldsDataV1) -> VerifiedControllerHoldReadbackV1 {
///     fields
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerHoldReadbackFieldsDataV1 {
    /// Names the owner UID claimed by the actual signer.
    pub controller_uid: u32,
    /// Names the original diagnostic Controller sequence.
    pub journal_sequence: u64,
    /// Names the held public Create operation.
    pub operation: OperationId,
    /// Names the held sandbox.
    pub sandbox: SandboxId,
    /// Retains the proposed source commitment.
    pub source: ObjectDigest,
    /// Retains the proposed Root binding.
    pub binding: ObjectDigest,
    /// Retains the original handoff epoch.
    pub epoch: u64,
}

// Native signing replaces its old verified-fields local with this unsigned
// carrier. Enforce the same paid header size and alignment on every target.
const _: [(); std::mem::size_of::<VerifiedControllerHoldReadbackV1>()] =
    [(); std::mem::size_of::<ControllerHoldReadbackFieldsDataV1>()];
const _: [(); std::mem::align_of::<VerifiedControllerHoldReadbackV1>()] =
    [(); std::mem::align_of::<ControllerHoldReadbackFieldsDataV1>()];

// Both representations have the same scalar fields. Share the original
// predicate without materializing another field carrier during verification.
macro_rules! validate_fields {
    ($fields:ty) => {
        impl $fields {
            fn validate(self, expected_uid: u32) -> Result<(), ControllerHoldReadbackDataErrorV1> {
                if expected_uid == 0
                    || self.controller_uid != expected_uid
                    || self.journal_sequence == 0
                    || self.operation.as_bytes() == &[0; 16]
                    || self.sandbox.as_bytes() == &[0; 16]
                    || self.source.as_bytes() == &[0; 32]
                    || self.binding.as_bytes() == &[0; 32]
                    || self.epoch == 0
                {
                    return Err(ControllerHoldReadbackDataErrorV1::NonCanonical);
                }
                Ok(())
            }
        }
    };
}

validate_fields!(ControllerHoldReadbackFieldsDataV1);
validate_fields!(VerifiedControllerHoldReadbackV1);

impl VerifiedControllerHoldReadbackV1 {
    /// Copies checked claims as unsigned DATA without lending native custody.
    #[must_use]
    pub const fn fields_data_v1(self) -> ControllerHoldReadbackFieldsDataV1 {
        ControllerHoldReadbackFieldsDataV1 {
            controller_uid: self.controller_uid,
            journal_sequence: self.journal_sequence,
            operation: self.operation,
            sandbox: self.sandbox,
            source: self.source,
            binding: self.binding,
            epoch: self.epoch,
        }
    }
}

/// Encodes exact unsigned fields for the actual owner's existing signing boundary.
///
/// The returned signature lane is zero. This accepts no key, currentness loan,
/// callback or native owner, and cannot construct a verified receipt.
///
/// # Errors
/// Rejects zero signer generation or malformed original unsigned fields.
pub fn prepare_controller_hold_readback_data_v1(
    fields: ControllerHoldReadbackFieldsDataV1,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackDataErrorV1> {
    if signer_generation == 0 {
        return Err(ControllerHoldReadbackDataErrorV1::NonCanonical);
    }
    fields.validate(fields.controller_uid)?;
    let mut bytes = [0; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[12..20].copy_from_slice(&signer_generation.to_be_bytes());
    bytes[20..36].copy_from_slice(&challenge.nonce);
    bytes[36..68].copy_from_slice(challenge.cut.as_bytes());
    bytes[68..72].copy_from_slice(&fields.controller_uid.to_be_bytes());
    bytes[72..80].copy_from_slice(&fields.journal_sequence.to_be_bytes());
    bytes[80..96].copy_from_slice(fields.operation.as_bytes());
    bytes[96..112].copy_from_slice(fields.sandbox.as_bytes());
    bytes[112..144].copy_from_slice(fields.source.as_bytes());
    bytes[144..176].copy_from_slice(fields.binding.as_bytes());
    bytes[176..184].copy_from_slice(&fields.epoch.to_be_bytes());
    Ok(bytes)
}

/// Builds the sole signature-domain preimage for an exact prepared packet.
///
/// This is bounded DATA, not signing authority or a current-owner assertion.
#[must_use]
pub fn controller_hold_readback_signature_preimage_v1(
    bytes: &[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1],
) -> Vec<u8> {
    signature_preimage(&bytes[..BODY_BYTES])
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ControllerHoldReadbackDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ControllerHoldReadbackDataErrorV1::NonCanonical)
}

/// Reports a rejected Controller-only comparison receipt.
#[derive(Debug, thiserror::Error)]
pub enum ControllerHoldReadbackDataErrorV1 {
    /// The challenge, credential, or receipt is not canonical.
    #[error("noncanonical Controller hold readback")]
    NonCanonical,
    /// The held Controller record or root challenge is no longer current.
    #[error("stale Controller hold readback")]
    Stale,
    /// The dedicated Controller signature failed verification.
    #[error("invalid Controller hold readback signature")]
    Signature,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn packet(challenge: ControllerHoldReadbackChallengeV1, key: &SigningKey) -> Vec<u8> {
        let mut bytes = vec![0; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[12..20].copy_from_slice(&9_u64.to_be_bytes());
        bytes[20..36].copy_from_slice(&challenge.nonce);
        bytes[36..68].copy_from_slice(challenge.cut.as_bytes());
        bytes[68..72].copy_from_slice(&811_u32.to_be_bytes());
        bytes[72..80].copy_from_slice(&7_u64.to_be_bytes());
        bytes[80..96].copy_from_slice(&[1; 16]);
        bytes[96..112].copy_from_slice(&[2; 16]);
        bytes[112..144].copy_from_slice(&[3; 32]);
        bytes[144..176].copy_from_slice(&[4; 32]);
        bytes[176..184].copy_from_slice(&5_u64.to_be_bytes());
        let signature = key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
        bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
        bytes
    }

    #[test]
    fn unsigned_data_matches_the_original_signed_wire_fixture() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let challenge =
            ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))
                .unwrap();
        let fields = ControllerHoldReadbackFieldsDataV1 {
            controller_uid: 811,
            journal_sequence: 7,
            operation: OperationId::from_bytes([1; 16]),
            sandbox: SandboxId::from_bytes([2; 16]),
            source: ObjectDigest::from_bytes([3; 32]),
            binding: ObjectDigest::from_bytes([4; 32]),
            epoch: 5,
        };

        let mut bytes = prepare_controller_hold_readback_data_v1(fields, challenge, 9).unwrap();
        assert_eq!(bytes[BODY_BYTES..], [0; 64]);
        let signature = key.sign(&controller_hold_readback_signature_preimage_v1(&bytes));
        bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());

        assert_eq!(bytes.as_slice(), packet(challenge, &key));
        let credential =
            encode_controller_hold_signer_credential_v1(9, &key.verifying_key()).unwrap();
        let pin = PinnedControllerHoldSignerV1::decode(&credential).unwrap();
        let verified = verify_controller_hold_readback_v1(&bytes, &pin, challenge, 811).unwrap();
        assert_eq!(verified.fields_data_v1(), fields);
    }

    #[test]
    fn exact_signed_packet_stays_comparison_data_and_rejects_every_field_substitution() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential =
            encode_controller_hold_signer_credential_v1(9, &key.verifying_key()).unwrap();
        let signer = PinnedControllerHoldSignerV1::decode(&credential).unwrap();
        let challenge =
            ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))
                .unwrap();
        let signed = packet(challenge, &key);
        let verified =
            verify_controller_hold_readback_v1(&signed, &signer, challenge, 811).unwrap();

        assert_eq!(verified.controller_uid(), 811);
        assert_eq!(verified.journal_sequence(), 7);
        assert_eq!(verified.operation(), OperationId::from_bytes([1; 16]));
        assert_eq!(verified.sandbox(), SandboxId::from_bytes([2; 16]));
        assert_eq!(verified.source(), ObjectDigest::from_bytes([3; 32]));
        assert_eq!(verified.binding(), ObjectDigest::from_bytes([4; 32]));
        assert_eq!(verified.epoch(), 5);
        for offset in [0, 8, 10, 12, 20, 36, 68, 72, 80, 96, 112, 144, 176, 184] {
            let mut changed = signed.clone();
            changed[offset] ^= 1;
            assert!(verify_controller_hold_readback_v1(&changed, &signer, challenge, 811).is_err());
        }
        assert!(
            verify_controller_hold_readback_v1(
                &signed[..signed.len() - 1],
                &signer,
                challenge,
                811
            )
            .is_err()
        );
        let mut extended = signed.clone();
        extended.push(0);
        assert!(verify_controller_hold_readback_v1(&extended, &signer, challenge, 811).is_err());
        assert!(verify_controller_hold_readback_v1(&signed, &signer, challenge, 812).is_err());
        assert!(ControllerHoldReadbackChallengeV1::new([0; 16], challenge.cut()).is_err());
        assert!(PinnedControllerHoldSignerV1::decode(key.verifying_key().as_bytes()).is_err());
    }
}
