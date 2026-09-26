//! Signed, nonauthorizing Controller proposal for an initial Source tree.
//!
//! The seven hierarchy ceilings are an explicit administrative deployment
//! decision. Neither a signed project policy nor a publisher policy supplies
//! them. This codec does not issue that decision, establish current Controller
//! heads, spend an epoch, or append to the Source journal.
//!
//! ```text
//! AOSCSE01 | version:u16be | reserved:u16be | issuer-generation:u64be |
//! project:16 | publisher-generation:u64be | publisher-head:32 |
//! project-authorization-head:32 | request-id:16 | epoch:u64be |
//! seven TreeLimitsV1 ceilings:u32be each | Ed25519 signature:64
//!
//! AOSCSK01 | issuer-generation:u64be | Ed25519 public key:32 |
//! SHA-256(key-domain || preceding 48 bytes):32
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::model::TreeLimitsV1;
#[cfg(target_os = "linux")]
use crate::public_api_session::PinnedSystemdCredential;
use crate::role_credential::{decode_role_credential, encode_role_credential};

const MAGIC: &[u8; 8] = b"AOSCSE01";
const KEY_MAGIC: &[u8; 8] = b"AOSCSK01";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 160;
const CREDENTIAL_BYTES: usize = 80;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.controller-source-tree-seed.signature.v1\0/var/lib/aos/sandbox/source-domains/source-domains-v1.journal\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.controller-source-tree-seed.verifier.v1\0";

/// Bounds the signed, initial Source-tree proposal packet.
pub const CONTROLLER_SOURCE_TREE_SEED_BYTES_V1: usize = BODY_BYTES + 64;

/// Reports a noncanonical, stale, or unauthenticated seed proposal.
#[derive(Debug, Error)]
pub enum ControllerSourceTreeSeedErrorV1 {
    /// The fixed privileged issuer credential is missing or has changed.
    #[error("Controller Source-tree seed issuer credential is unavailable")]
    Credential,
    /// The packet, credential, or proposed limits are malformed.
    #[error("invalid Controller Source-tree seed framing")]
    NonCanonical,
    /// A pinned context or anti-replay epoch does not match.
    #[error("Controller Source-tree seed is stale")]
    Stale,
    /// The role-pinned Controller issuer did not sign this packet.
    #[error("invalid Controller Source-tree seed signature")]
    Signature,
}

/// Holds administrative seed fields before they acquire Controller authority.
///
/// Construction does not prove that the project, limits, or head claims came
/// from an authorized administrative issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerSourceTreeSeedV1 {
    project: ProjectId,
    limits: TreeLimitsV1,
    publisher_generation: u64,
    publisher_head: ObjectDigest,
    project_authorization_head: ObjectDigest,
    request_id: [u8; 16],
    epoch: u64,
}

impl ControllerSourceTreeSeedV1 {
    /// Constructs a canonical, nonauthorizing administrative seed proposal.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, heads, or generations. The caller must
    /// supply a previously validated [`TreeLimitsV1`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        limits: TreeLimitsV1,
        publisher_generation: u64,
        publisher_head: ObjectDigest,
        project_authorization_head: ObjectDigest,
        request_id: [u8; 16],
        epoch: u64,
    ) -> Result<Self, ControllerSourceTreeSeedErrorV1> {
        if project.as_bytes() == &[0; 16]
            || publisher_generation == 0
            || publisher_head.as_bytes() == &[0; 32]
            || project_authorization_head.as_bytes() == &[0; 32]
            || request_id == [0; 16]
            || epoch == 0
        {
            return Err(ControllerSourceTreeSeedErrorV1::NonCanonical);
        }
        Ok(Self {
            project,
            limits,
            publisher_generation,
            publisher_head,
            project_authorization_head,
            request_id,
            epoch,
        })
    }

    /// Returns the proposed project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the seven explicitly proposed tree ceilings.
    #[must_use]
    pub const fn limits(self) -> TreeLimitsV1 {
        self.limits
    }

    /// Returns the claimed current publisher generation.
    #[must_use]
    pub const fn publisher_generation(self) -> u64 {
        self.publisher_generation
    }

    /// Returns the claimed current publisher head.
    #[must_use]
    pub const fn publisher_head(self) -> ObjectDigest {
        self.publisher_head
    }

    /// Returns the claimed Controller project-authorization head.
    #[must_use]
    pub const fn project_authorization_head(self) -> ObjectDigest {
        self.project_authorization_head
    }

    /// Returns the original administrative request identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the claimed monotonic issuer epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Pins the distinct Controller Source-seed issuer role and generation.
///
/// Decoding a credential does not install a trust root. A later Source owner
/// must obtain these bytes from privileged configuration, not from a packet.
pub struct PinnedControllerSourceTreeSeedIssuerV1 {
    generation: u64,
    key: VerifyingKey,
}

/// Retains the fixed systemd issuer pin and its protected file identity.
///
/// Only the Controller's fixed credential name can supply the trust root for
/// this path. Verification still grants no Source append authority.
#[cfg(target_os = "linux")]
struct ProtectedControllerSourceTreeSeedIssuerV1 {
    credential: PinnedSystemdCredential,
    pin: PinnedControllerSourceTreeSeedIssuerV1,
}

#[cfg(target_os = "linux")]
impl ProtectedControllerSourceTreeSeedIssuerV1 {
    fn from_systemd_credentials() -> Result<Self, ControllerSourceTreeSeedErrorV1> {
        let credential = PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        let pin = PinnedControllerSourceTreeSeedIssuerV1::decode(credential.bytes())?;
        credential
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        Ok(Self { credential, pin })
    }

    fn verify(
        &self,
        bytes: &[u8],
        expected: ControllerSourceTreeSeedExpectedV1,
    ) -> Result<VerifiedControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1> {
        self.credential
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        let verified = verify_controller_source_tree_seed_v1(bytes, &self.pin, expected);
        self.credential
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        verified
    }
}

impl PinnedControllerSourceTreeSeedIssuerV1 {
    /// Decodes a public-only, role-specific issuer credential.
    ///
    /// # Errors
    ///
    /// Rejects a foreign role, altered checksum, zero generation, or bad key.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControllerSourceTreeSeedErrorV1> {
        let (generation, key) = decode_role_credential(bytes, KEY_MAGIC, KEY_DOMAIN)
            .ok_or(ControllerSourceTreeSeedErrorV1::NonCanonical)?;
        Ok(Self { generation, key })
    }

    /// Returns the externally pinned issuer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the role-specific public verification key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Encodes a public-only Controller Source-seed verifier credential.
///
/// The result is provisioning data, not a trust root by itself.
///
/// # Errors
///
/// Rejects generation zero.
pub fn encode_controller_source_tree_seed_credential_v1(
    generation: u64,
    key: &VerifyingKey,
) -> Result<[u8; CREDENTIAL_BYTES], ControllerSourceTreeSeedErrorV1> {
    encode_role_credential(generation, key, KEY_MAGIC, KEY_DOMAIN)
        .ok_or(ControllerSourceTreeSeedErrorV1::NonCanonical)
}

/// Signs an administrative proposal without issuing or appending it.
///
/// A production issuer must first derive every field from protected current
/// Controller authority and use a distinct, provisioned Source-seed key.
///
/// # Errors
///
/// Rejects generation zero or a limit that cannot fit the canonical wire.
pub fn sign_controller_source_tree_seed_v1(
    seed: ControllerSourceTreeSeedV1,
    issuer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1], ControllerSourceTreeSeedErrorV1> {
    if issuer_generation == 0 {
        return Err(ControllerSourceTreeSeedErrorV1::NonCanonical);
    }
    let mut bytes = [0; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[12..20].copy_from_slice(&issuer_generation.to_be_bytes());
    bytes[20..36].copy_from_slice(seed.project.as_bytes());
    bytes[36..44].copy_from_slice(&seed.publisher_generation.to_be_bytes());
    bytes[44..76].copy_from_slice(seed.publisher_head.as_bytes());
    bytes[76..108].copy_from_slice(seed.project_authorization_head.as_bytes());
    bytes[108..124].copy_from_slice(&seed.request_id);
    bytes[124..132].copy_from_slice(&seed.epoch.to_be_bytes());
    for (index, limit) in limit_values(seed.limits).into_iter().enumerate() {
        let limit =
            u32::try_from(limit).map_err(|_| ControllerSourceTreeSeedErrorV1::NonCanonical)?;
        let offset = 132 + index * 4;
        bytes[offset..offset + 4].copy_from_slice(&limit.to_be_bytes());
    }
    let signature = signing_key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Selects independently observed Controller heads and a protected epoch floor.
///
/// The caller must derive these values under Controller custody. Constructing
/// this value from untrusted packet fields supplies no currentness or replay
/// protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerSourceTreeSeedExpectedV1 {
    project: ProjectId,
    publisher_generation: u64,
    publisher_head: ObjectDigest,
    project_authorization_head: ObjectDigest,
    request_id: [u8; 16],
    last_epoch: u64,
}

impl ControllerSourceTreeSeedExpectedV1 {
    /// Constructs an expected Controller cut and durable anti-replay floor.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, heads, or publisher generation.
    pub fn new(
        project: ProjectId,
        publisher_generation: u64,
        publisher_head: ObjectDigest,
        project_authorization_head: ObjectDigest,
        request_id: [u8; 16],
        last_epoch: u64,
    ) -> Result<Self, ControllerSourceTreeSeedErrorV1> {
        if project.as_bytes() == &[0; 16]
            || publisher_generation == 0
            || publisher_head.as_bytes() == &[0; 32]
            || project_authorization_head.as_bytes() == &[0; 32]
            || request_id == [0; 16]
        {
            return Err(ControllerSourceTreeSeedErrorV1::NonCanonical);
        }
        Ok(Self {
            project,
            publisher_generation,
            publisher_head,
            project_authorization_head,
            request_id,
            last_epoch,
        })
    }
}

/// Retains a signature-checked proposal, not a Source append capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedControllerSourceTreeSeedV1 {
    seed: ControllerSourceTreeSeedV1,
    packet_digest: ObjectDigest,
}

impl VerifiedControllerSourceTreeSeedV1 {
    /// Returns the signature-checked administrative claims.
    #[must_use]
    pub const fn seed(self) -> ControllerSourceTreeSeedV1 {
        self.seed
    }

    /// Returns the digest of the exact signed packet.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }
}

/// Verifies a seed against a distinct issuer pin and expected Controller cut.
///
/// This does not authenticate the expected heads, durably spend the epoch, or
/// authorize a Source append. A future owner must compare them under retained
/// Controller and Source writers and retain an anti-replay floor.
///
/// # Errors
///
/// Rejects malformed framing or limits, rotated signer, stale expected fields
/// or epoch, and invalid signature.
pub fn verify_controller_source_tree_seed_v1(
    bytes: &[u8],
    issuer: &PinnedControllerSourceTreeSeedIssuerV1,
    expected: ControllerSourceTreeSeedExpectedV1,
) -> Result<VerifiedControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1> {
    if bytes.len() != CONTROLLER_SOURCE_TREE_SEED_BYTES_V1 {
        return Err(ControllerSourceTreeSeedErrorV1::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES];
    if body[..8] != MAGIC[..]
        || take::<2>(body, 8)? != VERSION.to_be_bytes()
        || take::<2>(body, 10)? != [0; 2]
    {
        return Err(ControllerSourceTreeSeedErrorV1::NonCanonical);
    }
    if u64::from_be_bytes(take::<8>(body, 12)?) != issuer.generation {
        return Err(ControllerSourceTreeSeedErrorV1::Stale);
    }

    let limits = TreeLimitsV1::new(
        read_limit(body, 132)?,
        read_limit(body, 136)?,
        read_limit(body, 140)?,
        read_limit(body, 144)?,
        read_limit(body, 148)?,
        read_limit(body, 152)?,
        read_limit(body, 156)?,
    )
    .map_err(|_| ControllerSourceTreeSeedErrorV1::NonCanonical)?;
    let seed = ControllerSourceTreeSeedV1::new(
        ProjectId::from_bytes(take::<16>(body, 20)?),
        limits,
        u64::from_be_bytes(take::<8>(body, 36)?),
        ObjectDigest::from_bytes(take::<32>(body, 44)?),
        ObjectDigest::from_bytes(take::<32>(body, 76)?),
        take::<16>(body, 108)?,
        u64::from_be_bytes(take::<8>(body, 124)?),
    )?;
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    issuer
        .key
        .verify_strict(&signature_preimage(body), &signature)
        .map_err(|_| ControllerSourceTreeSeedErrorV1::Signature)?;
    if seed.project != expected.project
        || seed.publisher_generation != expected.publisher_generation
        || seed.publisher_head != expected.publisher_head
        || seed.project_authorization_head != expected.project_authorization_head
        || seed.request_id != expected.request_id
        || seed.epoch <= expected.last_epoch
    {
        return Err(ControllerSourceTreeSeedErrorV1::Stale);
    }
    let packet_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
    Ok(VerifiedControllerSourceTreeSeedV1 {
        seed,
        packet_digest,
    })
}

/// Verifies a proposal using the Controller's fixed privileged issuer pin.
///
/// The Controller must derive `expected` under protected current custody.
/// Even then, the verified packet is nonauthorizing until a future owner
/// retains the Controller writer through the Source append and durably spends
/// the issuer epoch. This check performs none of those effects.
///
/// # Errors
///
/// Rejects absent, malformed, or replaced credential custody, malformed or
/// stale packet claims, and invalid signatures.
#[cfg(target_os = "linux")]
pub(crate) fn verify_controller_source_tree_seed_from_fixed_issuer_v1(
    bytes: &[u8],
    expected: ControllerSourceTreeSeedExpectedV1,
) -> Result<VerifiedControllerSourceTreeSeedV1, ControllerSourceTreeSeedErrorV1> {
    ProtectedControllerSourceTreeSeedIssuerV1::from_systemd_credentials()?.verify(bytes, expected)
}

fn limit_values(limits: TreeLimitsV1) -> [usize; 7] {
    [
        limits.maximum_project_roots(),
        limits.maximum_project_sandboxes(),
        limits.maximum_project_live_sandboxes(),
        limits.maximum_depth(),
        limits.maximum_children_per_parent(),
        limits.maximum_descendants(),
        limits.maximum_live_descendants(),
    ]
}

fn read_limit(body: &[u8], offset: usize) -> Result<usize, ControllerSourceTreeSeedErrorV1> {
    usize::try_from(u32::from_be_bytes(take::<4>(body, offset)?))
        .map_err(|_| ControllerSourceTreeSeedErrorV1::NonCanonical)
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ControllerSourceTreeSeedErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ControllerSourceTreeSeedErrorV1::NonCanonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        SigningKey,
        PinnedControllerSourceTreeSeedIssuerV1,
        ControllerSourceTreeSeedV1,
        ControllerSourceTreeSeedExpectedV1,
    ) {
        let key = SigningKey::from_bytes(&[41; 32]);
        let credential =
            encode_controller_source_tree_seed_credential_v1(7, &key.verifying_key()).unwrap();
        let pin = PinnedControllerSourceTreeSeedIssuerV1::decode(&credential).unwrap();
        let project = ProjectId::from_bytes([1; 16]);
        let publisher_head = ObjectDigest::from_bytes([2; 32]);
        let authorization_head = ObjectDigest::from_bytes([3; 32]);
        let limits = TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap();
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            limits,
            5,
            publisher_head,
            authorization_head,
            [4; 16],
            9,
        )
        .unwrap();
        let expected = ControllerSourceTreeSeedExpectedV1::new(
            project,
            5,
            publisher_head,
            authorization_head,
            [4; 16],
            8,
        )
        .unwrap();
        (key, pin, seed, expected)
    }

    #[test]
    fn exact_signed_seed_roundtrips_all_limits_without_source_authority() {
        let (key, pin, seed, expected) = fixture();
        let packet = sign_controller_source_tree_seed_v1(seed, pin.generation(), &key).unwrap();
        let verified = verify_controller_source_tree_seed_v1(&packet, &pin, expected).unwrap();

        assert_eq!(verified.seed(), seed);
        assert_eq!(verified.seed().limits(), seed.limits());
        assert_eq!(verified.seed().request_id(), [4; 16]);
        assert_eq!(verified.seed().epoch(), 9);
        assert_eq!(
            verified.packet_digest(),
            ObjectDigest::from_bytes(Sha256::digest(packet).into())
        );
        assert_eq!(
            packet,
            sign_controller_source_tree_seed_v1(seed, 7, &key).unwrap()
        );
    }

    #[test]
    fn tampered_field_signature_and_framing_fail_closed() {
        let (key, pin, seed, expected) = fixture();
        let packet = sign_controller_source_tree_seed_v1(seed, 7, &key).unwrap();

        for offset in [
            12, 20, 36, 44, 76, 108, 124, 132, 136, 140, 144, 148, 152, 156, 160,
        ] {
            let mut altered = packet;
            altered[offset] ^= 1;
            assert!(verify_controller_source_tree_seed_v1(&altered, &pin, expected).is_err());
        }
        for offset in [0, 8, 10] {
            let mut altered = packet;
            altered[offset] ^= 1;
            assert!(matches!(
                verify_controller_source_tree_seed_v1(&altered, &pin, expected),
                Err(ControllerSourceTreeSeedErrorV1::NonCanonical)
            ));
        }
        assert!(
            verify_controller_source_tree_seed_v1(&packet[..packet.len() - 1], &pin, expected)
                .is_err()
        );
        let mut trailing = packet.to_vec();
        trailing.push(0);
        assert!(verify_controller_source_tree_seed_v1(&trailing, &pin, expected).is_err());

        let mut wrong_domain = packet;
        let signature = key.sign(&wrong_domain[..BODY_BYTES]);
        wrong_domain[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
        assert!(matches!(
            verify_controller_source_tree_seed_v1(&wrong_domain, &pin, expected),
            Err(ControllerSourceTreeSeedErrorV1::Signature)
        ));
    }

    #[test]
    fn role_pin_rotation_and_issuer_generation_are_not_packet_selected() {
        let (key, pin, seed, expected) = fixture();
        let packet = sign_controller_source_tree_seed_v1(seed, 7, &key).unwrap();
        let next_key = SigningKey::from_bytes(&[42; 32]);
        for (generation, public_key) in [(8, key.verifying_key()), (7, next_key.verifying_key())] {
            let credential =
                encode_controller_source_tree_seed_credential_v1(generation, &public_key).unwrap();
            let rotated = PinnedControllerSourceTreeSeedIssuerV1::decode(&credential).unwrap();
            assert!(verify_controller_source_tree_seed_v1(&packet, &rotated, expected).is_err());
        }
        let mut credential =
            encode_controller_source_tree_seed_credential_v1(7, &key.verifying_key()).unwrap();
        credential[0] ^= 1;
        assert!(PinnedControllerSourceTreeSeedIssuerV1::decode(&credential).is_err());
        credential[0] ^= 1;
        credential[79] ^= 1;
        assert!(PinnedControllerSourceTreeSeedIssuerV1::decode(&credential).is_err());
        let foreign_role = crate::policy_compiler::encode_controller_hold_signer_credential_v1(
            7,
            &key.verifying_key(),
        )
        .unwrap();
        assert!(PinnedControllerSourceTreeSeedIssuerV1::decode(&foreign_role).is_err());
        assert!(encode_controller_source_tree_seed_credential_v1(0, &key.verifying_key()).is_err());
        assert!(sign_controller_source_tree_seed_v1(seed, 0, &key).is_err());
        assert_eq!(pin.verifying_key(), &key.verifying_key());
    }

    #[test]
    fn request_head_and_epoch_replay_are_rejected() {
        let (key, pin, seed, expected) = fixture();
        let packet = sign_controller_source_tree_seed_v1(seed, 7, &key).unwrap();
        let contexts = [
            ControllerSourceTreeSeedExpectedV1::new(
                seed.project(),
                seed.publisher_generation(),
                seed.publisher_head(),
                seed.project_authorization_head(),
                seed.request_id(),
                9,
            )
            .unwrap(),
            ControllerSourceTreeSeedExpectedV1::new(
                seed.project(),
                seed.publisher_generation(),
                seed.publisher_head(),
                seed.project_authorization_head(),
                seed.request_id(),
                10,
            )
            .unwrap(),
            ControllerSourceTreeSeedExpectedV1::new(
                seed.project(),
                seed.publisher_generation(),
                seed.publisher_head(),
                seed.project_authorization_head(),
                [5; 16],
                8,
            )
            .unwrap(),
            ControllerSourceTreeSeedExpectedV1::new(
                seed.project(),
                6,
                seed.publisher_head(),
                seed.project_authorization_head(),
                seed.request_id(),
                8,
            )
            .unwrap(),
            ControllerSourceTreeSeedExpectedV1::new(
                seed.project(),
                seed.publisher_generation(),
                ObjectDigest::from_bytes([6; 32]),
                seed.project_authorization_head(),
                seed.request_id(),
                8,
            )
            .unwrap(),
            ControllerSourceTreeSeedExpectedV1::new(
                seed.project(),
                seed.publisher_generation(),
                seed.publisher_head(),
                ObjectDigest::from_bytes([7; 32]),
                seed.request_id(),
                8,
            )
            .unwrap(),
            ControllerSourceTreeSeedExpectedV1::new(
                ProjectId::from_bytes([8; 16]),
                seed.publisher_generation(),
                seed.publisher_head(),
                seed.project_authorization_head(),
                seed.request_id(),
                8,
            )
            .unwrap(),
        ];
        for context in contexts {
            assert!(matches!(
                verify_controller_source_tree_seed_v1(&packet, &pin, context),
                Err(ControllerSourceTreeSeedErrorV1::Stale)
            ));
        }
        assert!(verify_controller_source_tree_seed_v1(&packet, &pin, expected).is_ok());
    }

    #[test]
    fn signed_but_invalid_tree_limits_remain_noncanonical() {
        let (key, pin, seed, expected) = fixture();
        let mut packet = sign_controller_source_tree_seed_v1(seed, 7, &key).unwrap();
        packet[136..140].copy_from_slice(&65_537_u32.to_be_bytes());
        let signature = key.sign(&signature_preimage(&packet[..BODY_BYTES]));
        packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());

        assert!(matches!(
            verify_controller_source_tree_seed_v1(&packet, &pin, expected),
            Err(ControllerSourceTreeSeedErrorV1::NonCanonical)
        ));
    }
}
