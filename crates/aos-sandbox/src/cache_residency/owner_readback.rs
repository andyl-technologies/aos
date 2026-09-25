//! Closed signed readback of the physical Cache owner's fixed names.
//!
//! The packet authenticates a held owner's statement, not the verifier's own
//! filesystem observation. A closed root challenge exchange may verify it,
//! but no policy-publication path consumes it.
//!
//! ```text
//! AOSCRB01 | version:u16 | reserved:u16 | signer-generation:u64 |
//! root-nonce:16 | held-cut:32 | root-dev:u64 | root-inode:u64 |
//! root-uid:u32 | root-mode:u32 | lock-dev:u64 | lock-inode:u64 |
//! manifest-generation:u64 | manifest-digest:32 | limits-digest:32 |
//! Ed25519 signature:64
//!
//! AOSCPK01 | signer-generation:u64 | Ed25519 public key:32 |
//! SHA-256(Cache-key-domain || preceding 48 bytes):32
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::effect_owner::{CacheOwnerErrorV1, CacheOwnerLimitsV1};

const MAGIC: &[u8; 8] = b"AOSCRB01";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 180;
const RECEIPT_BYTES: usize = BODY_BYTES + 64;
/// Bounds one closed Cache owner named-readback packet.
pub const CLOSED_CACHE_OWNER_READBACK_BYTES_V1: usize = RECEIPT_BYTES;
const SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.cache-owner.named-readback.v1\0/var/lib/aos/sandbox/cache-residency/objects\0";
const LIMITS_DOMAIN: &[u8] = b"aos.sandbox.cache-owner.limits.v1\0";
const KEY_MAGIC: &[u8; 8] = b"AOSCPK01";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.cache-owner-readback-verifier.v1\0";
const KEY_CREDENTIAL_BYTES: usize = 80;

/// Names one root session and its root-authenticated signed-source cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheOwnerReadbackChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
}

impl CacheOwnerReadbackChallengeV1 {
    /// Constructs a nonzero session challenge and cut commitment.
    ///
    /// # Errors
    ///
    /// Rejects a zero nonce or cut; neither can identify a held session.
    pub fn new(nonce: [u8; 16], cut: ObjectDigest) -> Result<Self, CacheOwnerReadbackErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(CacheOwnerReadbackErrorV1::NonCanonical);
        }
        Ok(Self { nonce, cut })
    }

    /// Returns the root-generated session nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the protected root-source cut bound by the challenge.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }
}

/// Retains a role-specific Cache readback verification key generation.
///
/// Decoding this type does not prove credential custody. The root caller must
/// load its bytes from a fixed privileged deployment credential, never from
/// the Controller request or the signed packet.
pub struct PinnedCacheOwnerReadbackSignerV1 {
    generation: u64,
    key: VerifyingKey,
}

impl PinnedCacheOwnerReadbackSignerV1 {
    /// Decodes one exact public-only Cache signer credential.
    ///
    /// # Errors
    ///
    /// Rejects raw keys, foreign roles, zero generations, malformed keys,
    /// or altered framing.
    pub fn decode(bytes: &[u8]) -> Result<Self, CacheOwnerReadbackErrorV1> {
        if bytes.len() != KEY_CREDENTIAL_BYTES || bytes.get(..8) != Some(KEY_MAGIC) {
            return Err(CacheOwnerReadbackErrorV1::NonCanonical);
        }
        let checksum = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(&bytes[..48])
            .finalize();
        if bytes[48..] != checksum[..] {
            return Err(CacheOwnerReadbackErrorV1::NonCanonical);
        }

        let generation = u64::from_be_bytes(take::<8>(bytes, 8)?);
        let key = VerifyingKey::from_bytes(&take::<32>(bytes, 16)?)
            .map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
        if generation == 0 {
            return Err(CacheOwnerReadbackErrorV1::NonCanonical);
        }
        Ok(Self { generation, key })
    }

    /// Returns the protected deployment's claimed generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the role-specific public key for protected root pin admission.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Encodes a public-only, Cache-purpose credential for offline provisioning.
///
/// This does not install a trust root or grant receipt authority. Private key
/// custody and non-reuse with deployment/project keys need separate review.
///
/// # Errors
///
/// Rejects generation zero.
pub fn encode_cache_owner_readback_signer_credential_v1(
    generation: u64,
    key: &VerifyingKey,
) -> Result<[u8; KEY_CREDENTIAL_BYTES], CacheOwnerReadbackErrorV1> {
    if generation == 0 {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; KEY_CREDENTIAL_BYTES];
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

/// Reports a verified but non-authorizing physical owner statement.
///
/// Signature verification does not prove the names are currently bound to
/// these inodes, the signer was holding the flock, or its key was deployed by
/// an independent authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedClosedCacheOwnerReadbackV1 {
    root_device: u64,
    root_inode: u64,
    lock_device: u64,
    lock_inode: u64,
    manifest_generation: u64,
    manifest_digest: ObjectDigest,
    limits_digest: ObjectDigest,
}

impl VerifiedClosedCacheOwnerReadbackV1 {
    /// Returns the claimed fixed-root device and inode.
    #[must_use]
    pub const fn root_identity(self) -> (u64, u64) {
        (self.root_device, self.root_inode)
    }

    /// Returns the claimed named-lock device and inode.
    #[must_use]
    pub const fn lock_identity(self) -> (u64, u64) {
        (self.lock_device, self.lock_inode)
    }

    /// Returns the claimed durable manifest generation and digest.
    #[must_use]
    pub const fn manifest_head(self) -> (u64, ObjectDigest) {
        (self.manifest_generation, self.manifest_digest)
    }

    /// Returns the claimed complete physical owner envelope commitment.
    #[must_use]
    pub const fn limits_digest(self) -> ObjectDigest {
        self.limits_digest
    }
}

/// Verifies canonical framing and a nonce-bound Cache-purpose signature.
///
/// The credential must come from a fixed protected deployment source. This
/// closed verifier neither replays Cache names nor authorizes AOSPCB02, Q04,
/// public Create, or a physical effect.
///
/// # Errors
///
/// Rejects malformed or noncanonical bytes, stale nonce/cut, wrong owner UID,
/// signer generation mismatch, or a failed signature.
pub fn verify_closed_cache_owner_readback_v1(
    bytes: &[u8],
    signer: &PinnedCacheOwnerReadbackSignerV1,
    challenge: CacheOwnerReadbackChallengeV1,
    expected_owner_uid: u32,
) -> Result<VerifiedClosedCacheOwnerReadbackV1, CacheOwnerReadbackErrorV1> {
    if bytes.len() != RECEIPT_BYTES || expected_owner_uid == 0 {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES];
    if body[..8] != MAGIC[..]
        || u16::from_be_bytes(take::<2>(body, 8)?) != VERSION
        || take::<2>(body, 10)? != [0; 2]
        || u64::from_be_bytes(take::<8>(body, 12)?) != signer.generation
        || take::<16>(body, 20)? != challenge.nonce
        || take::<32>(body, 36)? != *challenge.cut.as_bytes()
    {
        return Err(CacheOwnerReadbackErrorV1::Stale);
    }
    let fields = CacheOwnerReadbackFieldsV1 {
        root_device: u64::from_be_bytes(take::<8>(body, 68)?),
        root_inode: u64::from_be_bytes(take::<8>(body, 76)?),
        root_uid: u32::from_be_bytes(take::<4>(body, 84)?),
        root_mode: u32::from_be_bytes(take::<4>(body, 88)?),
        lock_device: u64::from_be_bytes(take::<8>(body, 92)?),
        lock_inode: u64::from_be_bytes(take::<8>(body, 100)?),
        manifest_generation: u64::from_be_bytes(take::<8>(body, 108)?),
        manifest_digest: ObjectDigest::from_bytes(take::<32>(body, 116)?),
        limits_digest: ObjectDigest::from_bytes(take::<32>(body, 148)?),
    };
    fields.validate(expected_owner_uid)?;

    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    let preimage = signature_preimage(body);
    signer
        .key
        .verify_strict(&preimage, &signature)
        .map_err(|_| CacheOwnerReadbackErrorV1::Signature)?;
    Ok(VerifiedClosedCacheOwnerReadbackV1 {
        root_device: fields.root_device,
        root_inode: fields.root_inode,
        lock_device: fields.lock_device,
        lock_inode: fields.lock_inode,
        manifest_generation: fields.manifest_generation,
        manifest_digest: fields.manifest_digest,
        limits_digest: fields.limits_digest,
    })
}

/// Rejects malformed, stale, or unauthenticated closed readbacks.
#[derive(Debug, Error)]
pub enum CacheOwnerReadbackErrorV1 {
    /// The credential, challenge, or readback framing is not canonical.
    #[error("noncanonical Cache owner readback")]
    NonCanonical,
    /// The packet does not bind this signer generation and held root session.
    #[error("stale Cache owner readback challenge")]
    Stale,
    /// The Cache-purpose signature does not verify.
    #[error("invalid Cache owner readback signature")]
    Signature,
    /// The physical owner lost its held fixed-name proof.
    #[error("Cache owner readback lost held custody: {0}")]
    Owner(#[from] CacheOwnerErrorV1),
}

pub(super) struct CacheOwnerReadbackFieldsV1 {
    pub root_device: u64,
    pub root_inode: u64,
    pub root_uid: u32,
    pub root_mode: u32,
    pub lock_device: u64,
    pub lock_inode: u64,
    pub manifest_generation: u64,
    pub manifest_digest: ObjectDigest,
    pub limits_digest: ObjectDigest,
}

impl CacheOwnerReadbackFieldsV1 {
    fn validate(&self, expected_owner_uid: u32) -> Result<(), CacheOwnerReadbackErrorV1> {
        let genesis = self.manifest_generation == 0 && self.manifest_digest.as_bytes() == &[0; 32];
        let committed =
            self.manifest_generation != 0 && self.manifest_digest.as_bytes() != &[0; 32];
        if self.root_device == 0
            || self.root_inode == 0
            || self.root_uid == 0
            || self.root_uid != expected_owner_uid
            || self.root_mode != 0o700
            || self.lock_device != self.root_device
            || self.lock_inode == 0
            || self.lock_inode == self.root_inode
            || (!genesis && !committed)
            || self.limits_digest.as_bytes() == &[0; 32]
        {
            return Err(CacheOwnerReadbackErrorV1::NonCanonical);
        }
        Ok(())
    }
}

pub(super) fn sign_closed_cache_owner_readback_v1(
    fields: CacheOwnerReadbackFieldsV1,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; RECEIPT_BYTES], CacheOwnerReadbackErrorV1> {
    if signer_generation == 0 {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    fields.validate(fields.root_uid)?;
    let mut bytes = [0; RECEIPT_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[12..20].copy_from_slice(&signer_generation.to_be_bytes());
    bytes[20..36].copy_from_slice(&challenge.nonce);
    bytes[36..68].copy_from_slice(challenge.cut.as_bytes());
    bytes[68..76].copy_from_slice(&fields.root_device.to_be_bytes());
    bytes[76..84].copy_from_slice(&fields.root_inode.to_be_bytes());
    bytes[84..88].copy_from_slice(&fields.root_uid.to_be_bytes());
    bytes[88..92].copy_from_slice(&fields.root_mode.to_be_bytes());
    bytes[92..100].copy_from_slice(&fields.lock_device.to_be_bytes());
    bytes[100..108].copy_from_slice(&fields.lock_inode.to_be_bytes());
    bytes[108..116].copy_from_slice(&fields.manifest_generation.to_be_bytes());
    bytes[116..148].copy_from_slice(fields.manifest_digest.as_bytes());
    bytes[148..180].copy_from_slice(fields.limits_digest.as_bytes());
    let signature = signing_key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn sign_test_cache_owner_readback_v1(
    challenge: CacheOwnerReadbackChallengeV1,
    generation: u64,
    signing_key: &SigningKey,
    owner_uid: u32,
) -> Result<[u8; RECEIPT_BYTES], CacheOwnerReadbackErrorV1> {
    sign_test_cache_owner_readback_with_manifest_v1(
        challenge,
        generation,
        signing_key,
        owner_uid,
        ObjectDigest::from_bytes([4; 32]),
    )
}

#[cfg(test)]
pub(crate) fn sign_test_cache_owner_readback_with_manifest_v1(
    challenge: CacheOwnerReadbackChallengeV1,
    generation: u64,
    signing_key: &SigningKey,
    owner_uid: u32,
    manifest_digest: ObjectDigest,
) -> Result<[u8; RECEIPT_BYTES], CacheOwnerReadbackErrorV1> {
    sign_closed_cache_owner_readback_v1(
        CacheOwnerReadbackFieldsV1 {
            root_device: 11,
            root_inode: 12,
            root_uid: owner_uid,
            root_mode: 0o700,
            lock_device: 11,
            lock_inode: 13,
            manifest_generation: 7,
            manifest_digest,
            limits_digest: ObjectDigest::from_bytes([5; 32]),
        },
        challenge,
        generation,
        signing_key,
    )
}

pub(super) fn cache_owner_limits_digest_v1(
    limits: CacheOwnerLimitsV1,
) -> Result<ObjectDigest, CacheOwnerReadbackErrorV1> {
    let positive = u64::try_from(limits.maximum_positive_entries)
        .map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    let negative = u64::try_from(limits.maximum_negative_entries)
        .map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    let pins =
        u64::try_from(limits.maximum_pins).map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    let digest = Sha256::new()
        .chain_update(LIMITS_DOMAIN)
        .chain_update(limits.maximum_memory_bytes.to_be_bytes())
        .chain_update(limits.maximum_disk_bytes.to_be_bytes())
        .chain_update(limits.disk_low_water_bytes.to_be_bytes())
        .chain_update(positive.to_be_bytes())
        .chain_update(negative.to_be_bytes())
        .chain_update(pins.to_be_bytes())
        .chain_update(limits.maximum_pinned_bytes.to_be_bytes())
        .finalize();
    Ok(ObjectDigest::from_bytes(digest.into()))
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], CacheOwnerReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CacheOwnerReadbackErrorV1::NonCanonical)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn fields() -> CacheOwnerReadbackFieldsV1 {
        CacheOwnerReadbackFieldsV1 {
            root_device: 11,
            root_inode: 12,
            root_uid: 811,
            root_mode: 0o700,
            lock_device: 11,
            lock_inode: 13,
            manifest_generation: 7,
            manifest_digest: ObjectDigest::from_bytes([4; 32]),
            limits_digest: ObjectDigest::from_bytes([5; 32]),
        }
    }

    fn challenge() -> CacheOwnerReadbackChallengeV1 {
        CacheOwnerReadbackChallengeV1::new([6; 16], ObjectDigest::from_bytes([7; 32]))
            .expect("valid challenge")
    }

    #[test]
    fn closed_readback_binds_role_generation_and_exact_session() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let credential = encode_cache_owner_readback_signer_credential_v1(9, &key.verifying_key())
            .expect("credential");
        let pinned = PinnedCacheOwnerReadbackSignerV1::decode(&credential).expect("pinned key");
        let packet = sign_closed_cache_owner_readback_v1(fields(), challenge(), 9, &key)
            .expect("closed readback");
        let verified = verify_closed_cache_owner_readback_v1(&packet, &pinned, challenge(), 811)
            .expect("matching signer and session");
        assert_eq!(verified.root_identity(), (11, 12));
        assert_eq!(verified.lock_identity(), (11, 13));
        assert_eq!(
            verified.manifest_head(),
            (7, ObjectDigest::from_bytes([4; 32]))
        );

        let stale = CacheOwnerReadbackChallengeV1::new([10; 16], ObjectDigest::from_bytes([7; 32]))
            .expect("stale challenge");
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&packet, &pinned, stale, 811),
            Err(CacheOwnerReadbackErrorV1::Stale)
        ));
        let stale_cut =
            CacheOwnerReadbackChallengeV1::new([6; 16], ObjectDigest::from_bytes([10; 32]))
                .expect("stale cut");
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&packet, &pinned, stale_cut, 811),
            Err(CacheOwnerReadbackErrorV1::Stale)
        ));
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&packet, &pinned, challenge(), 812),
            Err(CacheOwnerReadbackErrorV1::NonCanonical)
        ));

        let rotated_credential =
            encode_cache_owner_readback_signer_credential_v1(10, &key.verifying_key())
                .expect("rotated credential");
        let rotated =
            PinnedCacheOwnerReadbackSignerV1::decode(&rotated_credential).expect("rotated pin");
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&packet, &rotated, challenge(), 811),
            Err(CacheOwnerReadbackErrorV1::Stale)
        ));

        let foreign_key = SigningKey::from_bytes(&[9; 32]);
        let foreign_credential =
            encode_cache_owner_readback_signer_credential_v1(9, &foreign_key.verifying_key())
                .expect("credential");
        let foreign = PinnedCacheOwnerReadbackSignerV1::decode(&foreign_credential)
            .expect("foreign pinned key");
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&packet, &foreign, challenge(), 811),
            Err(CacheOwnerReadbackErrorV1::Signature)
        ));

        let mut changed = packet;
        changed[148] ^= 1;
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&changed, &pinned, challenge(), 811),
            Err(CacheOwnerReadbackErrorV1::Signature)
        ));
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(
                &packet[..packet.len() - 1],
                &pinned,
                challenge(),
                811
            ),
            Err(CacheOwnerReadbackErrorV1::NonCanonical)
        ));
        let mut wrong_role = credential;
        wrong_role[..8].copy_from_slice(b"AOSPPK01");
        assert!(PinnedCacheOwnerReadbackSignerV1::decode(&wrong_role).is_err());

        let mut old_magic = packet;
        old_magic[..8].copy_from_slice(b"AOSCOR01");
        assert!(matches!(
            verify_closed_cache_owner_readback_v1(&old_magic, &pinned, challenge(), 811),
            Err(CacheOwnerReadbackErrorV1::Stale)
        ));
    }

    #[test]
    fn genesis_head_is_canonical_but_mixed_zero_head_is_not() {
        let mut value = fields();
        value.manifest_generation = 0;
        value.manifest_digest = ObjectDigest::from_bytes([0; 32]);
        assert!(value.validate(811).is_ok());

        value.manifest_generation = 1;
        assert!(matches!(
            value.validate(811),
            Err(CacheOwnerReadbackErrorV1::NonCanonical)
        ));
    }

    #[test]
    fn signed_noncanonical_fixed_names_are_rejected() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let credential = encode_cache_owner_readback_signer_credential_v1(9, &key.verifying_key())
            .expect("credential");
        let pinned = PinnedCacheOwnerReadbackSignerV1::decode(&credential).expect("pinned key");
        let packet = sign_closed_cache_owner_readback_v1(fields(), challenge(), 9, &key)
            .expect("closed readback");

        for (offset, replacement) in [(88, 0o755_u32.to_be_bytes()), (84, 812_u32.to_be_bytes())] {
            let mut malformed = packet;
            malformed[offset..offset + 4].copy_from_slice(&replacement);
            let signature = key.sign(&signature_preimage(&malformed[..BODY_BYTES]));
            malformed[BODY_BYTES..].copy_from_slice(&signature.to_bytes());

            assert!(matches!(
                verify_closed_cache_owner_readback_v1(&malformed, &pinned, challenge(), 811),
                Err(CacheOwnerReadbackErrorV1::NonCanonical)
            ));
        }
    }
}
