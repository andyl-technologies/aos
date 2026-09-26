//! Closed, Controller-purpose readback of one protected policy hold.
//!
//! The owner signs only while retaining its protected Controller writer and
//! rejoining the selected public Create source. The verifier authenticates an
//! owner statement, not a transferable lock or an all-owner policy cut.
//!
//! ```text
//! AOSCTW01 | version:u16 | reserved:u16 | signer-generation:u64 |
//! root-nonce:16 | root-session-cut:32 | Controller-UID:u32 |
//! journal-sequence:u64 | operation:16 | sandbox:16 | source:32 |
//! binding:32 | epoch:u64 | Ed25519 signature:64
//!
//! AOSCTK01 | signer-generation:u64 | Ed25519 public key:32 |
//! SHA-256(Controller-key-domain || preceding 48 bytes):32
//! ```

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::controller_service::journal::production_journal_limits;
use crate::journal::{ControllerPolicyHoldV1, Journal, JournalError, RecordNamespace};
use crate::role_credential::{decode_role_credential, encode_role_credential};

use super::public_create_source::current_parentless_create_project_source_v1;

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";
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
    pub fn new(nonce: [u8; 16], cut: ObjectDigest) -> Result<Self, ControllerHoldReadbackErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(ControllerHoldReadbackErrorV1::NonCanonical);
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
    pub fn decode(bytes: &[u8]) -> Result<Self, ControllerHoldReadbackErrorV1> {
        let (generation, key) = decode_role_credential(bytes, KEY_MAGIC, KEY_DOMAIN)
            .ok_or(ControllerHoldReadbackErrorV1::NonCanonical)?;
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
) -> Result<[u8; CREDENTIAL_BYTES], ControllerHoldReadbackErrorV1> {
    encode_role_credential(generation, key, KEY_MAGIC, KEY_DOMAIN)
        .ok_or(ControllerHoldReadbackErrorV1::NonCanonical)
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

/// Signs a current protected Controller hold under its retained writer.
///
/// The signing key must be loaded from a distinct Controller-only credential.
/// This function never accepts a caller-supplied hold or source commitment.
/// The exact fixed journal path, current Create join, hold, and sequence are
/// checked before and after signing. The held V7 terminal flight uses this
/// receipt only as nonauthorizing Root-row evidence.
///
/// # Errors
///
/// Rejects a missing/released hold, stale Create join, unsafe or replaced
/// protected journal, changed sequence, or invalid signer generation.
pub fn sign_fixed_controller_hold_readback_v1(
    journal: &mut Journal,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    let uid = rustix::process::getuid().as_raw();
    sign_controller_hold_readback_at(
        journal,
        Path::new(CONTROLLER_DIRECTORY),
        uid,
        challenge,
        signer_generation,
        signing_key,
    )
}

fn sign_controller_hold_readback_at(
    journal: &mut Journal,
    directory: &Path,
    uid: u32,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    if uid == 0 || signer_generation == 0 {
        return Err(ControllerHoldReadbackErrorV1::NonCanonical);
    }
    journal.require_protected_named_location(
        directory,
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    let held = journal
        .controller_policy_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(ControllerHoldReadbackErrorV1::Stale)?;
    require_current_source(journal, held)?;
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let fields = VerifiedControllerHoldReadbackV1 {
        controller_uid: uid,
        journal_sequence: snapshot.sequence(),
        operation: held.operation(),
        sandbox: held.sandbox(),
        source: held.source(),
        binding: held.binding(),
        epoch: held.epoch(),
    };
    let bytes = sign_fields(fields, challenge, signer_generation, signing_key)?;

    journal.require_protected_named_location(
        directory,
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .validate_snapshot_for_effect(&snapshot)?;
    if journal.controller_policy_hold_v1()? != Some(held) {
        return Err(ControllerHoldReadbackErrorV1::Stale);
    }
    require_current_source(journal, held)?;
    Ok(bytes)
}

fn require_current_source(
    journal: &mut Journal,
    held: ControllerPolicyHoldV1,
) -> Result<(), ControllerHoldReadbackErrorV1> {
    let source =
        current_parentless_create_project_source_v1(journal, held.operation(), held.sandbox())
            .map_err(|_| ControllerHoldReadbackErrorV1::Stale)?;
    if source.commitment() != held.source() {
        return Err(ControllerHoldReadbackErrorV1::Stale);
    }
    Ok(())
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
) -> Result<VerifiedControllerHoldReadbackV1, ControllerHoldReadbackErrorV1> {
    if bytes.len() != CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1 {
        return Err(ControllerHoldReadbackErrorV1::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES];
    if body[..8] != MAGIC[..]
        || take::<2>(body, 8)? != VERSION.to_be_bytes()
        || take::<2>(body, 10)? != [0; 2]
        || u64::from_be_bytes(take::<8>(body, 12)?) != signer.generation
        || take::<16>(body, 20)? != challenge.nonce
        || take::<32>(body, 36)? != *challenge.cut.as_bytes()
    {
        return Err(ControllerHoldReadbackErrorV1::Stale);
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
        .map_err(|_| ControllerHoldReadbackErrorV1::Signature)?;
    Ok(fields)
}

impl VerifiedControllerHoldReadbackV1 {
    fn validate(self, expected_uid: u32) -> Result<(), ControllerHoldReadbackErrorV1> {
        if expected_uid == 0
            || self.controller_uid != expected_uid
            || self.journal_sequence == 0
            || self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.source.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(ControllerHoldReadbackErrorV1::NonCanonical);
        }
        Ok(())
    }
}

fn sign_fields(
    fields: VerifiedControllerHoldReadbackV1,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    if signer_generation == 0 {
        return Err(ControllerHoldReadbackErrorV1::NonCanonical);
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
    let signature = key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn sign_test_controller_hold_readback_v1(
    held: ControllerPolicyHoldV1,
    controller_uid: u32,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    sign_fields(
        VerifiedControllerHoldReadbackV1 {
            controller_uid,
            journal_sequence: 7,
            operation: held.operation(),
            sandbox: held.sandbox(),
            source: held.source(),
            binding: held.binding(),
            epoch: held.epoch(),
        },
        challenge,
        signer_generation,
        key,
    )
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
) -> Result<[u8; N], ControllerHoldReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ControllerHoldReadbackErrorV1::NonCanonical)
}

/// Reports a rejected Controller-only readback or protected owner cut.
#[derive(Debug, thiserror::Error)]
pub enum ControllerHoldReadbackErrorV1 {
    /// The challenge, credential, or receipt is not canonical.
    #[error("noncanonical Controller hold readback")]
    NonCanonical,
    /// The held Controller record or root challenge is no longer current.
    #[error("stale Controller hold readback")]
    Stale,
    /// The dedicated Controller signature failed verification.
    #[error("invalid Controller hold readback signature")]
    Signature,
    /// Protected journal custody failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use super::*;

    fn fields() -> VerifiedControllerHoldReadbackV1 {
        VerifiedControllerHoldReadbackV1 {
            controller_uid: 811,
            journal_sequence: 7,
            operation: OperationId::from_bytes([1; 16]),
            sandbox: SandboxId::from_bytes([2; 16]),
            source: ObjectDigest::from_bytes([3; 32]),
            binding: ObjectDigest::from_bytes([4; 32]),
            epoch: 5,
        }
    }

    #[test]
    fn receipt_rejects_wrong_nonce_cut_role_generation_uid_and_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = encode_controller_hold_signer_credential_v1(9, &key.verifying_key())
            .expect("Controller pin");
        let signer = PinnedControllerHoldSignerV1::decode(&credential).expect("pinned signer");
        let challenge =
            ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))
                .expect("root challenge");
        let bytes = sign_fields(fields(), challenge, 9, &key).expect("signed receipt");

        assert_eq!(
            verify_controller_hold_readback_v1(&bytes, &signer, challenge, 811)
                .expect("verified readback"),
            fields()
        );
        assert!(verify_controller_hold_readback_v1(&bytes, &signer, challenge, 812).is_err());
        assert!(
            verify_controller_hold_readback_v1(
                &bytes,
                &signer,
                ControllerHoldReadbackChallengeV1::new([10; 16], ObjectDigest::from_bytes([9; 32]))
                    .unwrap(),
                811
            )
            .is_err()
        );
        assert!(
            verify_controller_hold_readback_v1(
                &bytes,
                &signer,
                ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([10; 32]))
                    .unwrap(),
                811
            )
            .is_err()
        );

        let rotated = encode_controller_hold_signer_credential_v1(10, &key.verifying_key())
            .expect("rotated pin");
        let rotated = PinnedControllerHoldSignerV1::decode(&rotated).unwrap();
        assert!(verify_controller_hold_readback_v1(&bytes, &rotated, challenge, 811).is_err());
        let wrong = SigningKey::from_bytes(&[11; 32]);
        let wrong = encode_controller_hold_signer_credential_v1(9, &wrong.verifying_key()).unwrap();
        let wrong = PinnedControllerHoldSignerV1::decode(&wrong).unwrap();
        assert!(verify_controller_hold_readback_v1(&bytes, &wrong, challenge, 811).is_err());

        let mut altered = bytes;
        altered[112] ^= 1;
        assert!(verify_controller_hold_readback_v1(&altered, &signer, challenge, 811).is_err());
        assert!(PinnedControllerHoldSignerV1::decode(key.verifying_key().as_bytes()).is_err());
        assert!(PinnedControllerHoldSignerV1::decode(&[0; CREDENTIAL_BYTES]).is_err());
        assert!(ControllerHoldReadbackChallengeV1::new([0; 16], challenge.cut()).is_err());
    }

    #[test]
    fn protected_signer_rejects_hold_without_current_create_join() {
        let directory = tempfile::tempdir().expect("Controller directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            CONTROLLER_JOURNAL,
            production_journal_limits(),
            uid,
        )
        .expect("protected Controller writer");
        let challenge =
            ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))
                .unwrap();
        let signer = SigningKey::from_bytes(&[7; 32]);
        assert!(
            sign_controller_hold_readback_at(
                &mut journal,
                directory.path(),
                uid,
                challenge,
                3,
                &signer
            )
            .is_err()
        );

        let held = ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .unwrap();
        journal.acquire_controller_policy_hold_v1(held).unwrap();
        assert!(matches!(
            require_current_source(&mut journal, held),
            Err(ControllerHoldReadbackErrorV1::Stale)
        ));
        let result = sign_controller_hold_readback_at(
            &mut journal,
            directory.path(),
            uid,
            challenge,
            3,
            &signer,
        );
        assert!(
            matches!(
                result,
                Err(ControllerHoldReadbackErrorV1::Journal(
                    JournalError::ProtectedBoundary
                ))
            ),
            "{result:?}"
        );
    }
}
