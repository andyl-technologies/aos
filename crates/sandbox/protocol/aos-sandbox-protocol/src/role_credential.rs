//! Shares canonical framing for public Ed25519 verifier credential DATA.
//!
//! Callers keep their own closed role magic/checksum domain and genuine native
//! key-custody checks. Decoding or encoding this public-only DATA cannot install
//! a trust root, load a signing seed or construct a protected role grant.

use std::error::Error;

use ed25519_dalek::{SignatureError, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Defines the exact generation, public key and checksum credential width.
pub const ROLE_CREDENTIAL_BYTES: usize = 80;

/// Names the existing public-only Cache verifier credential framing.
pub const CACHE_OWNER_ROLE_CREDENTIAL_MAGIC_V1: &[u8; 8] = b"AOSCPK01";
/// Names the existing Cache public-verifier credential checksum domain.
pub const CACHE_OWNER_ROLE_CREDENTIAL_DOMAIN_V1: &[u8] =
    b"aos.sandbox.cache-owner-readback-verifier.v1\0";

/// Decodes a canonical generation and public verifier key for the supplied DATA frame.
///
/// Returns `None` for a different width/magic/checksum, a zero generation or an
/// invalid public key. The result establishes no custody or role authority.
pub fn decode_role_credential(
    bytes: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Option<(u64, VerifyingKey)> {
    decode_role_credential_inner(bytes, magic, domain, None)
}

// Both dispositions preserve width -> magic -> checksum -> generation bytes ->
// actual key decompression -> nonzero generation. Generation zero must not
// bypass the reached public-key decoder or change its ordinary drop boundary.
fn decode_role_credential_inner(
    bytes: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
    mut original: Option<&mut RoleCredentialDecodeCaptureV1>,
) -> Option<(u64, VerifyingKey)> {
    if bytes.len() != ROLE_CREDENTIAL_BYTES || bytes.get(..8) != Some(magic.as_slice()) {
        return None;
    }

    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..48])
        .finalize();
    if let Some(original) = original.as_deref_mut() {
        original.checksum = Some(checksum.into());
    }
    if bytes[48..] != checksum[..] {
        return None;
    }

    let generation = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    if let Some(original) = original.as_deref_mut() {
        original.generation = Some(generation);
    }
    let key = match original {
        Some(original) => {
            original.key = Some(VerifyingKey::from_bytes(bytes[16..48].try_into().ok()?));
            *original.key.as_ref()?.as_ref().ok()?
        }
        None => VerifyingKey::from_bytes(bytes[16..48].try_into().ok()?).ok()?,
    };
    (generation != 0).then_some((generation, key))
}

/// Reports a malformed or repeated public verifier DATA decode.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("public verifier credential DATA is malformed or already entered")]
pub struct RoleCredentialDecodeClosedV1;

/// Retains the reached checksum, generation and actual public-key decoder result.
///
/// This inert capture selects no role, trust pin, private key or receiving
/// authority. Callers retain their actual bytes and native custody separately.
#[derive(Default)]
pub struct RoleCredentialDecodeCaptureV1 {
    checksum: Option<[u8; 32]>,
    generation: Option<u64>,
    key: Option<Result<VerifyingKey, SignatureError>>,
    model: Option<(u64, VerifyingKey)>,
    completion: Option<Result<(), RoleCredentialDecodeClosedV1>>,
    entered: bool,
    closed: bool,
}

impl RoleCredentialDecodeCaptureV1 {
    /// Creates empty fixed destinations without parsing or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the original key failure or fixed outer classification.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.key.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.completion.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.then_some(&RoleCredentialDecodeClosedV1 as _))
    }

    /// Borrows the completed comparison model without installing it as a pin.
    #[must_use]
    pub fn decoded(&self) -> Option<&(u64, VerifyingKey)> {
        if self.closed || !matches!(self.completion, Some(Ok(()))) {
            return None;
        }
        self.model.as_ref()
    }

    /// Prices fixed resident/construction/hash/return carriers and key refusal.
    ///
    /// The pinned Dalek constructor can box only its fixed PointDecompression
    /// error; 256 bytes covers that closed error carrier without input strings.
    /// Original credential bytes and their native readers are separate debt.
    #[must_use]
    pub fn receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Sha256>())?
            .checked_add(std::mem::size_of::<Result<VerifyingKey, SignatureError>>())?
            .checked_add(std::mem::size_of::<(u64, VerifyingKey)>())?
            .checked_add(32 + 256)
    }

    /// Counts seven fields, one possible error allocation and six local controls.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        7 + 1 + 6
    }
}

/// Decodes once into the actual public-only DATA destination using the same parser.
///
/// # Errors
/// Retains malformed framing, checksum, zero generation, actual Dalek error or
/// reentry refusal. A reached failed decoder result is never replaced.
pub fn decode_role_credential_retaining_v1(
    bytes: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
    original: &mut RoleCredentialDecodeCaptureV1,
) -> Result<(), RoleCredentialDecodeClosedV1> {
    if original.entered {
        original.closed = true;
        return Err(RoleCredentialDecodeClosedV1);
    }
    original.entered = true;
    original.model = decode_role_credential_inner(bytes, magic, domain, Some(original));
    original.completion = Some(original.model.as_ref()
        .map(|_| ()).ok_or(RoleCredentialDecodeClosedV1));
    if matches!(original.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(RoleCredentialDecodeClosedV1)
    }
}

/// Encodes public verifier credential DATA with the existing canonical checksum.
///
/// Returns `None` for generation zero. Encoding chooses no signing key, native
/// credential, admitted issuer, protected journal or current role.
pub fn encode_role_credential(
    generation: u64,
    key: &VerifyingKey,
    magic: &[u8; 8],
    domain: &[u8],
) -> Option<[u8; ROLE_CREDENTIAL_BYTES]> {
    if generation == 0 {
        return None;
    }

    let mut bytes = [0; ROLE_CREDENTIAL_BYTES];
    bytes[..8].copy_from_slice(magic);
    bytes[8..16].copy_from_slice(&generation.to_be_bytes());
    bytes[16..48].copy_from_slice(key.as_bytes());
    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..48])
        .finalize();
    bytes[48..].copy_from_slice(&checksum);
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(generation: u64, public: [u8; 32]) -> [u8; ROLE_CREDENTIAL_BYTES] {
        let mut bytes = [0; ROLE_CREDENTIAL_BYTES];
        bytes[..8].copy_from_slice(b"AOSTEST1");
        bytes[8..16].copy_from_slice(&generation.to_be_bytes());
        bytes[16..48].copy_from_slice(&public);
        let digest = Sha256::new().chain_update(b"test-public-data")
            .chain_update(&bytes[..48]).finalize();
        bytes[48..].copy_from_slice(&digest);
        bytes
    }

    #[test]
    fn actual_bad_public_key_result_stays_in_its_original_slot_on_reentry() {
        let public = (0..=u8::MAX).map(|byte| [byte; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err()).unwrap();
        let bytes = frame(7, public);
        let mut original = RoleCredentialDecodeCaptureV1::new();

        assert!(decode_role_credential_retaining_v1(
            &bytes, b"AOSTEST1", b"test-public-data", &mut original,
        ).is_err());
        let actual = original.key.as_ref().unwrap().as_ref().unwrap_err()
            as *const SignatureError;
        assert_eq!(original.generation, Some(7));
        assert!(original.checksum.is_some());
        assert!(decode_role_credential(&bytes, b"AOSTEST1", b"test-public-data").is_none());

        assert!(decode_role_credential_retaining_v1(
            &[], b"AOSTEST1", b"test-public-data", &mut original,
        ).is_err());
        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<SignatureError>().unwrap(), actual));
        assert!(original.decoded().is_none());
    }

    #[test]
    fn zero_generation_is_checked_after_the_same_actual_key_decode() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let bytes = frame(0, key.to_bytes());
        let mut original = RoleCredentialDecodeCaptureV1::new();

        assert!(decode_role_credential_retaining_v1(
            &bytes, b"AOSTEST1", b"test-public-data", &mut original,
        ).is_err());
        assert!(matches!(original.key, Some(Ok(_))));
        assert_eq!(original.generation, Some(0));
        assert!(original.decoded().is_none());
        assert!(decode_role_credential(&bytes, b"AOSTEST1", b"test-public-data").is_none());
    }
}

/// Shares the fixed Cache seed/memory input grammar without custody or authority.
pub mod cache_signer_inputs;
