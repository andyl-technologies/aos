//! Closed signed readback of physical and protected Cache owner facts.
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
//!
//! AOSCRB02 | version:u16 | reserved:u16 | signer-generation:u64 |
//! root-nonce:16 | held-cut:32 | v1 physical fields at offsets 68..180 |
//! manifest-dev:u64 | manifest-inode:u64 | project:16 |
//! partition:32 | protected-head:32 | binding:32 |
//! epoch:u64 | complete-node-quota-digest:32 | Ed25519 signature:64
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::effect_owner::{CacheOwnerErrorV1, CacheOwnerLimitsV1};
use crate::journal::CachePolicyHoldV1;

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
const MAGIC_V2: &[u8; 8] = b"AOSCRB02";
const VERSION_V2: u16 = 2;
const BODY_BYTES_V2: usize = 348;
/// Bounds one joined Cache physical and protected readback packet.
pub const CLOSED_CACHE_OWNER_READBACK_BYTES_V2: usize = BODY_BYTES_V2 + 64;
const SIGNATURE_DOMAIN_V2: &[u8] =
    b"aos.sandbox.cache-owner.physical-protected-readback.v2\0/var/lib/aos/sandbox/cache-residency/objects\0";

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

/// Reports the signed physical and protected Cache statement for one challenge.
///
/// Verification authenticates the packet but does not prove current owner
/// custody. Root must compare the protected fields with its fixed read-only
/// replay while every required owner remains held.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedClosedCacheOwnerReadbackV2 {
    physical: VerifiedClosedCacheOwnerReadbackV1,
    manifest_device: u64,
    manifest_inode: u64,
    hold: CachePolicyHoldV1,
    quota_digest: ObjectDigest,
}

impl VerifiedClosedCacheOwnerReadbackV2 {
    /// Returns the signed physical root, lock, manifest, and limits statement.
    #[must_use]
    pub const fn physical(self) -> VerifiedClosedCacheOwnerReadbackV1 {
        self.physical
    }

    /// Returns the signed named manifest device and inode, or zero at genesis.
    #[must_use]
    pub const fn manifest_identity(self) -> (u64, u64) {
        (self.manifest_device, self.manifest_inode)
    }

    /// Returns the signed active protected hold and replay head.
    #[must_use]
    pub const fn hold(self) -> CachePolicyHoldV1 {
        self.hold
    }

    /// Returns the signed complete node quota envelope commitment.
    #[must_use]
    pub const fn quota_digest(self) -> ObjectDigest {
        self.quota_digest
    }
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
    let fields = CacheOwnerReadbackFieldsV1::decode(body)?;
    fields.validate(expected_owner_uid)?;

    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    let preimage = signature_preimage(body);
    signer
        .key
        .verify_strict(&preimage, &signature)
        .map_err(|_| CacheOwnerReadbackErrorV1::Signature)?;
    Ok(fields.verified())
}

/// Verifies the distinct v2 physical and protected Cache signature domain.
///
/// The credential must be a fixed Cache-purpose deployment pin. This verifier
/// does not replay journals, establish a held cut, or authorize Q04.
///
/// # Errors
///
/// Rejects malformed framing, stale challenge or signer generation, wrong
/// owner UID, invalid hold or quota digest, or a failed signature.
pub fn verify_closed_cache_owner_readback_v2(
    bytes: &[u8],
    signer: &PinnedCacheOwnerReadbackSignerV1,
    challenge: CacheOwnerReadbackChallengeV1,
    expected_owner_uid: u32,
) -> Result<VerifiedClosedCacheOwnerReadbackV2, CacheOwnerReadbackErrorV1> {
    if bytes.len() != CLOSED_CACHE_OWNER_READBACK_BYTES_V2 || expected_owner_uid == 0 {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES_V2];
    if body[..8] != MAGIC_V2[..]
        || u16::from_be_bytes(take::<2>(body, 8)?) != VERSION_V2
        || take::<2>(body, 10)? != [0; 2]
        || u64::from_be_bytes(take::<8>(body, 12)?) != signer.generation
        || take::<16>(body, 20)? != challenge.nonce
        || take::<32>(body, 36)? != *challenge.cut.as_bytes()
    {
        return Err(CacheOwnerReadbackErrorV1::Stale);
    }
    let physical = CacheOwnerReadbackFieldsV1::decode(body)?;
    physical.validate(expected_owner_uid)?;
    let manifest_device = u64::from_be_bytes(take::<8>(body, 180)?);
    let manifest_inode = u64::from_be_bytes(take::<8>(body, 188)?);
    validate_manifest_identity(physical, manifest_device, manifest_inode)?;
    let hold = CachePolicyHoldV1::new(
        ProjectId::from_bytes(take::<16>(body, 196)?),
        ObjectDigest::from_bytes(take::<32>(body, 212)?),
        ObjectDigest::from_bytes(take::<32>(body, 244)?),
        ObjectDigest::from_bytes(take::<32>(body, 276)?),
        u64::from_be_bytes(take::<8>(body, 308)?),
    )
    .map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    let quota_digest = ObjectDigest::from_bytes(take::<32>(body, 316)?);
    if quota_digest.as_bytes() == &[0; 32] {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES_V2)?);
    signer
        .key
        .verify_strict(&signature_preimage_v2(body), &signature)
        .map_err(|_| CacheOwnerReadbackErrorV1::Signature)?;
    Ok(VerifiedClosedCacheOwnerReadbackV2 {
        physical: physical.verified(),
        manifest_device,
        manifest_inode,
        hold,
        quota_digest,
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

#[derive(Clone, Copy)]
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
    fn decode(body: &[u8]) -> Result<Self, CacheOwnerReadbackErrorV1> {
        Ok(Self {
            root_device: u64::from_be_bytes(take::<8>(body, 68)?),
            root_inode: u64::from_be_bytes(take::<8>(body, 76)?),
            root_uid: u32::from_be_bytes(take::<4>(body, 84)?),
            root_mode: u32::from_be_bytes(take::<4>(body, 88)?),
            lock_device: u64::from_be_bytes(take::<8>(body, 92)?),
            lock_inode: u64::from_be_bytes(take::<8>(body, 100)?),
            manifest_generation: u64::from_be_bytes(take::<8>(body, 108)?),
            manifest_digest: ObjectDigest::from_bytes(take::<32>(body, 116)?),
            limits_digest: ObjectDigest::from_bytes(take::<32>(body, 148)?),
        })
    }

    fn verified(self) -> VerifiedClosedCacheOwnerReadbackV1 {
        VerifiedClosedCacheOwnerReadbackV1 {
            root_device: self.root_device,
            root_inode: self.root_inode,
            lock_device: self.lock_device,
            lock_inode: self.lock_inode,
            manifest_generation: self.manifest_generation,
            manifest_digest: self.manifest_digest,
            limits_digest: self.limits_digest,
        }
    }

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

fn validate_manifest_identity(
    physical: CacheOwnerReadbackFieldsV1,
    device: u64,
    inode: u64,
) -> Result<(), CacheOwnerReadbackErrorV1> {
    let genesis = physical.manifest_generation == 0 && device == 0 && inode == 0;
    let committed = physical.manifest_generation != 0
        && device == physical.root_device
        && inode != 0
        && inode != physical.root_inode
        && inode != physical.lock_inode;
    if genesis || committed {
        Ok(())
    } else {
        Err(CacheOwnerReadbackErrorV1::NonCanonical)
    }
}

pub(super) fn sign_closed_cache_owner_readback_v1(
    fields: CacheOwnerReadbackFieldsV1,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; RECEIPT_BYTES], CacheOwnerReadbackErrorV1> {
    let mut bytes = [0; RECEIPT_BYTES];
    write_physical_body(
        &mut bytes[..BODY_BYTES],
        fields,
        challenge,
        signer_generation,
    )?;
    let signature = signing_key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

pub(super) fn sign_closed_cache_owner_readback_v2(
    fields: CacheOwnerReadbackFieldsV1,
    manifest_identity: Option<(u64, u64)>,
    hold: CachePolicyHoldV1,
    quota_digest: ObjectDigest,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2], CacheOwnerReadbackErrorV1> {
    if !hold.is_held() || quota_digest.as_bytes() == &[0; 32] {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
    write_physical_body(
        &mut bytes[..BODY_BYTES],
        fields,
        challenge,
        signer_generation,
    )?;
    let (manifest_device, manifest_inode) = manifest_identity.unwrap_or((0, 0));
    validate_manifest_identity(fields, manifest_device, manifest_inode)?;
    bytes[..8].copy_from_slice(MAGIC_V2);
    bytes[8..10].copy_from_slice(&VERSION_V2.to_be_bytes());
    bytes[180..188].copy_from_slice(&manifest_device.to_be_bytes());
    bytes[188..196].copy_from_slice(&manifest_inode.to_be_bytes());
    bytes[196..212].copy_from_slice(hold.project().as_bytes());
    bytes[212..244].copy_from_slice(hold.partition().as_bytes());
    bytes[244..276].copy_from_slice(hold.cache_head().as_bytes());
    bytes[276..308].copy_from_slice(hold.binding().as_bytes());
    bytes[308..316].copy_from_slice(&hold.epoch().to_be_bytes());
    bytes[316..348].copy_from_slice(quota_digest.as_bytes());
    let signature = signing_key.sign(&signature_preimage_v2(&bytes[..BODY_BYTES_V2]));
    bytes[BODY_BYTES_V2..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

fn write_physical_body(
    body: &mut [u8],
    fields: CacheOwnerReadbackFieldsV1,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
) -> Result<(), CacheOwnerReadbackErrorV1> {
    if signer_generation == 0 {
        return Err(CacheOwnerReadbackErrorV1::NonCanonical);
    }
    fields.validate(fields.root_uid)?;
    body[..8].copy_from_slice(MAGIC);
    body[8..10].copy_from_slice(&VERSION.to_be_bytes());
    body[12..20].copy_from_slice(&signer_generation.to_be_bytes());
    body[20..36].copy_from_slice(&challenge.nonce);
    body[36..68].copy_from_slice(challenge.cut.as_bytes());
    body[68..76].copy_from_slice(&fields.root_device.to_be_bytes());
    body[76..84].copy_from_slice(&fields.root_inode.to_be_bytes());
    body[84..88].copy_from_slice(&fields.root_uid.to_be_bytes());
    body[88..92].copy_from_slice(&fields.root_mode.to_be_bytes());
    body[92..100].copy_from_slice(&fields.lock_device.to_be_bytes());
    body[100..108].copy_from_slice(&fields.lock_inode.to_be_bytes());
    body[108..116].copy_from_slice(&fields.manifest_generation.to_be_bytes());
    body[116..148].copy_from_slice(fields.manifest_digest.as_bytes());
    body[148..180].copy_from_slice(fields.limits_digest.as_bytes());
    Ok(())
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

#[cfg(test)]
pub(crate) fn sign_test_cache_owner_readback_v2(
    challenge: CacheOwnerReadbackChallengeV1,
    generation: u64,
    signing_key: &SigningKey,
    owner_uid: u32,
    hold: CachePolicyHoldV1,
    quota_digest: ObjectDigest,
) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2], CacheOwnerReadbackErrorV1> {
    sign_closed_cache_owner_readback_v2(
        CacheOwnerReadbackFieldsV1 {
            root_device: 11,
            root_inode: 12,
            root_uid: owner_uid,
            root_mode: 0o700,
            lock_device: 11,
            lock_inode: 13,
            manifest_generation: 7,
            manifest_digest: ObjectDigest::from_bytes([4; 32]),
            limits_digest: ObjectDigest::from_bytes([5; 32]),
        },
        Some((11, 14)),
        hold,
        quota_digest,
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

fn signature_preimage_v2(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN_V2.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN_V2);
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

    #[test]
    fn v2_receipt_binds_hold_quota_and_distinct_signature_domain() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let credential = encode_cache_owner_readback_signer_credential_v1(9, &key.verifying_key())
            .expect("Cache credential");
        let pinned =
            PinnedCacheOwnerReadbackSignerV1::decode(&credential).expect("pinned Cache key");
        let hold = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("active Cache hold");
        let quota = ObjectDigest::from_bytes([6; 32]);
        let packet = sign_closed_cache_owner_readback_v2(
            fields(),
            Some((11, 14)),
            hold,
            quota,
            challenge(),
            9,
            &key,
        )
        .expect("v2 receipt");
        let verified = verify_closed_cache_owner_readback_v2(&packet, &pinned, challenge(), 811)
            .expect("matching joined receipt");
        assert_eq!(verified.hold(), hold);
        assert_eq!(verified.quota_digest(), quota);
        assert_eq!(verified.manifest_identity(), (11, 14));
        assert_eq!(
            verified.physical().manifest_head(),
            (7, ObjectDigest::from_bytes([4; 32]))
        );
        assert!(verify_closed_cache_owner_readback_v1(&packet, &pinned, challenge(), 811).is_err());

        for offset in [20, 116, 180, 188, 196, 244, 276, 315, 316] {
            let mut altered = packet;
            altered[offset] ^= 1;
            assert!(
                verify_closed_cache_owner_readback_v2(&altered, &pinned, challenge(), 811).is_err()
            );
        }
        let rotated = encode_cache_owner_readback_signer_credential_v1(10, &key.verifying_key())
            .expect("rotated credential");
        let rotated = PinnedCacheOwnerReadbackSignerV1::decode(&rotated).expect("rotated pin");
        assert!(
            verify_closed_cache_owner_readback_v2(&packet, &rotated, challenge(), 811).is_err()
        );
        let v1 = sign_closed_cache_owner_readback_v1(fields(), challenge(), 9, &key)
            .expect("v1 receipt");
        assert!(verify_closed_cache_owner_readback_v2(&v1, &pinned, challenge(), 811).is_err());
    }
}
