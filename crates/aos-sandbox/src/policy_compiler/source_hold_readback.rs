//! Nonauthorizing signed readback of a protected source-domain policy hold.
//!
//! The Source owner signs only while its fixed journal writer is held and the
//! retained hierarchy head matches the durable hold. A verifier needs an
//! independently provisioned Source-purpose public key and a fresh challenge.
//! Neither key custody nor a root challenge exchange is deployed here.
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

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::hierarchy::protected_journal::HierarchyProtectedJournalOwnerV1;
use crate::journal::SourceDomainPolicyHoldV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

const MAGIC: &[u8; 8] = b"AOSSRB01";
const KEY_MAGIC: &[u8; 8] = b"AOSSPK01";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.source-hold-readback-verifier.v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-hold-readback.signature.v1\0";
const BODY_BYTES: usize = 224;
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
        if bytes.len() != KEY_BYTES || bytes.get(..8) != Some(KEY_MAGIC) {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        let checksum = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(&bytes[..48])
            .finalize();
        if bytes[48..] != checksum[..] {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        let generation = u64::from_be_bytes(take::<8>(bytes, 8)?);
        let key = VerifyingKey::from_bytes(&take::<32>(bytes, 16)?)
            .map_err(|_| SourceHoldReadbackErrorV1::NonCanonical)?;
        if generation == 0 {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
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
    if generation == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; KEY_BYTES];
    bytes[..8].copy_from_slice(KEY_MAGIC);
    bytes[8..16].copy_from_slice(&generation.to_be_bytes());
    bytes[16..48].copy_from_slice(key.as_bytes());
    let checksum = Sha256::new()
        .chain_update(KEY_DOMAIN)
        .chain_update(&bytes[..48])
        .finalize();
    bytes[48..].copy_from_slice(&checksum);
    Ok(bytes)
}

/// Signs the exact held Source record after checking its current hierarchy head.
///
/// The caller must keep the fixed protected Source writer and control the
/// Source-purpose signing key independently from the public Create request.
/// Signing a challenge alone cannot establish that root spent that challenge
/// or retained the Controller and Cache cuts.
///
/// # Errors
///
/// Rejects an absent or released hold, stale hierarchy, zero project, or an
/// unhealthy protected journal.
pub fn sign_current_source_hold_readback_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    owner
        .require_fixed_named_writer_v1()
        .map_err(|_| SourceHoldReadbackErrorV1::Stale)?;
    let hold = require_current_hold_and_head(owner, project)?;

    let packet = sign_fields(challenge, project, hold, signer_generation, signing_key);

    owner
        .require_fixed_named_writer_v1()
        .map_err(|_| SourceHoldReadbackErrorV1::Stale)?;
    if require_current_hold_and_head(owner, project)? != hold {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    Ok(packet)
}

fn require_current_hold_and_head(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    project: ProjectId,
) -> Result<SourceDomainPolicyHoldV1, SourceHoldReadbackErrorV1> {
    let hold = owner
        .closed_policy_source_hold_v1()
        .map_err(|_| SourceHoldReadbackErrorV1::Stale)?
        .filter(|hold| hold.is_held())
        .ok_or(SourceHoldReadbackErrorV1::Stale)?;
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(owner)
        .map_err(|_| SourceHoldReadbackErrorV1::Stale)?;
    let ancestry = hierarchy
        .project_ancestry_head(project)
        .map_err(|_| SourceHoldReadbackErrorV1::Stale)?
        .ok_or(SourceHoldReadbackErrorV1::Stale)?
        .evidence()
        .head();
    if ancestry != hold.ancestry() {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    Ok(hold)
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

pub(super) fn sign_fields(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    hold: SourceDomainPolicyHoldV1,
    generation: u64,
    signing_key: &SigningKey,
) -> [u8; SOURCE_HOLD_READBACK_BYTES_V1] {
    let mut packet = [0; SOURCE_HOLD_READBACK_BYTES_V1];
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
    let signature = signing_key.sign(&signature_preimage(&packet[..BODY_BYTES]));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    packet
}

#[cfg(test)]
pub(super) fn sign_test_source_hold_readback_v1(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    hold: SourceDomainPolicyHoldV1,
    generation: u64,
    signing_key: &SigningKey,
) -> [u8; SOURCE_HOLD_READBACK_BYTES_V1] {
    sign_fields(challenge, project, hold, generation, signing_key)
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use aos_sandbox_core::{OperationId, SandboxId};

    use super::*;

    #[test]
    fn source_witness_rejects_substitution_and_foreign_keys() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = encode_source_hold_readback_signer_credential_v1(3, &key.verifying_key())
            .expect("credential");
        let signer = PinnedSourceHoldReadbackSignerV1::decode(&credential).expect("pin");
        let challenge =
            SourceHoldReadbackChallengeV1::new([4; 16], ObjectDigest::from_bytes([5; 32]))
                .expect("challenge");
        let project = ProjectId::from_bytes([6; 16]);
        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([8; 32]),
            ObjectDigest::from_bytes([9; 32]),
            11,
        )
        .expect("hold");
        let mut packet = [0; SOURCE_HOLD_READBACK_BYTES_V1];
        packet[..8].copy_from_slice(MAGIC);
        packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
        packet[16..24].copy_from_slice(&3_u64.to_be_bytes());
        packet[24..40].copy_from_slice(&challenge.nonce);
        packet[40..72].copy_from_slice(challenge.cut.as_bytes());
        packet[72..88].copy_from_slice(project.as_bytes());
        packet[88..104].copy_from_slice(hold.operation().as_bytes());
        packet[104..120].copy_from_slice(hold.sandbox().as_bytes());
        packet[120..152].copy_from_slice(hold.controller_source().as_bytes());
        packet[152..184].copy_from_slice(hold.ancestry().as_bytes());
        packet[184..216].copy_from_slice(hold.binding().as_bytes());
        packet[216..224].copy_from_slice(&hold.epoch().to_be_bytes());
        let signature = key.sign(&signature_preimage(&packet[..BODY_BYTES]));
        packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
        assert_eq!(sign_fields(challenge, project, hold, 3, &key), packet);
        verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
            .expect("exact witness");

        let wrong_hold = SourceDomainPolicyHoldV1::new(
            hold.operation(),
            hold.sandbox(),
            hold.controller_source(),
            hold.ancestry(),
            hold.binding(),
            hold.epoch() + 1,
        )
        .expect("different epoch");
        assert!(
            verify_current_source_hold_readback_v1(
                &packet, &signer, challenge, project, wrong_hold
            )
            .is_err()
        );

        let wrong_challenge =
            SourceHoldReadbackChallengeV1::new([10; 16], ObjectDigest::from_bytes([5; 32]))
                .expect("challenge");
        assert!(
            verify_current_source_hold_readback_v1(
                &packet,
                &signer,
                wrong_challenge,
                project,
                hold
            )
            .is_err()
        );
        assert!(
            verify_current_source_hold_readback_v1(
                &packet,
                &signer,
                challenge,
                ProjectId::from_bytes([11; 16]),
                hold,
            )
            .is_err()
        );
        packet[184] ^= 1;
        assert!(
            verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
                .is_err()
        );
        packet[184] ^= 1;
        packet[10] = 1;
        assert!(
            verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
                .is_err()
        );
        packet[10] = 0;
        let wrong_key = SigningKey::from_bytes(&[12; 32]);
        let wrong_pin =
            encode_source_hold_readback_signer_credential_v1(3, &wrong_key.verifying_key())
                .expect("credential");
        let wrong_signer = PinnedSourceHoldReadbackSignerV1::decode(&wrong_pin).expect("pin");
        assert!(
            verify_current_source_hold_readback_v1(
                &packet,
                &wrong_signer,
                challenge,
                project,
                hold
            )
            .is_err()
        );
    }

    #[test]
    fn source_key_role_and_challenge_are_strict() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut credential =
            encode_source_hold_readback_signer_credential_v1(1, &key.verifying_key())
                .expect("credential");
        credential[..8].copy_from_slice(b"AOSCPK01");
        assert!(PinnedSourceHoldReadbackSignerV1::decode(&credential).is_err());
        assert!(
            SourceHoldReadbackChallengeV1::new([0; 16], ObjectDigest::from_bytes([1; 32])).is_err()
        );
    }

    #[test]
    fn protected_source_owner_cannot_sign_a_hold_without_its_hierarchy_head() {
        let directory = tempfile::tempdir().expect("protected journal directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let journal = crate::journal::Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            crate::journal::JournalLimits::default(),
            uid,
        )
        .expect("protected journal")
        .0;
        let mut owner = ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal);
        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
        )
        .expect("hold");
        owner
            .acquire_closed_policy_source_hold_v1(hold)
            .expect("durable hold");

        let challenge =
            SourceHoldReadbackChallengeV1::new([7; 16], ObjectDigest::from_bytes([8; 32]))
                .expect("challenge");
        assert!(
            sign_current_source_hold_readback_v1(
                &mut owner,
                ProjectId::from_bytes([9; 16]),
                challenge,
                1,
                &SigningKey::from_bytes(&[10; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn source_writer_rejects_replaced_journal_and_lock_names() {
        let directory = tempfile::tempdir().expect("protected journal directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let limits = crate::journal::JournalLimits::default();
        let journal = crate::journal::Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            limits,
            uid,
        )
        .expect("protected journal")
        .0;
        let owner = ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal);
        assert!(owner.require_named_writer_for_test().is_ok());

        for name in [
            "source-domains-v1.journal",
            "source-domains-v1.journal.lock",
        ] {
            let current = directory.path().join(name);
            let retained = directory.path().join(format!("{name}.retained"));
            fs::rename(&current, &retained).expect("orphan retained writer");
            fs::write(&current, []).expect("replace fixed name");
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600))
                .expect("private replacement");
            assert!(owner.require_named_writer_for_test().is_err());
            fs::remove_file(&current).expect("remove replacement");
            fs::rename(&retained, &current).expect("restore retained writer");
            assert!(owner.require_named_writer_for_test().is_ok());
        }
    }
}
