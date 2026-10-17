//! Explicit archive key custody and context-bound wrapped stream keys.

use std::fmt;

use anyhow::{ensure, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use rand::TryCryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::seal::{AesGcmSealer, SecretSealer};
use crate::snapshot::archive::{FreshStreamKey, StreamRole};

use super::{canonical_bytes, identifier, parse_closed, WrappedDeclaration};

const KEY_SCHEMA: &str = "aos.hub.snapshot-stream-key/v1";
const WRAP_SUITE: &str = "aes-256-gcm-sealer-v1";
const MAX_INNER_BYTES: usize = 512;
pub(super) const MAX_WRAPPED_BYTES: usize = 1024;
const MAX_EXCLUDED_KEYS: usize = 32;

/// A fresh archive identity generated from explicitly trusted fresh RNG state.
///
/// It is not a deployment identity or source lineage. RNG entropy/freshness is
/// caller-owned; no raw-import or Clone constructor is supplied for producers.
pub struct FreshArchiveId([u8; 16]);

impl FreshArchiveId {
    /// Generates a new identity with a caller-selected fallible CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if RNG generation fails.
    pub fn generate(rng: &mut impl TryCryptoRng) -> Result<Self> {
        let mut bytes = [0u8; 16];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| anyhow::anyhow!("snapshot archive identity generation failed"))?;
        Ok(Self(bytes))
    }

    /// Returns the public framing context identity.
    pub fn bytes(&self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for FreshArchiveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshArchiveId { <opaque> }")
    }
}

/// An explicitly supplied dedicated archive-export signing seed.
///
/// Source/Hub/release keys are never selected or loaded implicitly. This
/// wrapper has redacted Debug and no automatic serialization or Clone.
pub struct ArchiveSigningKey {
    pub(super) id: String,
    pub(super) key: SigningKey,
}

impl fmt::Debug for ArchiveSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveSigningKey { <redacted> }")
    }
}

impl ArchiveSigningKey {
    /// Accepts an explicit opaque identity and private Ed25519 seed.
    ///
    /// # Errors
    ///
    /// Rejects a malformed opaque identifier without exposing it.
    pub fn from_seed(id: &str, seed: [u8; 32]) -> Result<Self> {
        let seed = Zeroizing::new(seed);
        identifier(id)?;
        Ok(Self {
            id: id.to_owned(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Returns the public identity for an independently provisioned trust pin.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the public Ed25519 bytes, never the private seed.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// One explicitly supplied AES wrapping key and its opaque custody identifier.
///
/// No provider locator, key lookup, sealer initialization or private-key
/// serialization is performed by this wrapper.
pub struct ArchiveWrappingKey {
    pub(super) id: String,
    pub(super) bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ArchiveWrappingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveWrappingKey { <redacted> }")
    }
}

impl ArchiveWrappingKey {
    /// Accepts explicit private AES material and a bounded opaque identity.
    ///
    /// # Errors
    ///
    /// Rejects a malformed identifier without exposing it.
    pub fn from_bytes(id: &str, bytes: [u8; 32]) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        identifier(id)?;
        Ok(Self {
            id: id.to_owned(),
            bytes,
        })
    }
}

/// Separately owned metadata/private wrapping keys with distinct IDs/material.
///
/// The constructor rejects aliases even if their opaque IDs differ. It does
/// not establish external provider custody or exclude unknown source keys.
pub struct ArchiveWrappingKeys {
    pub(super) metadata: ArchiveWrappingKey,
    pub(super) private: ArchiveWrappingKey,
}

impl fmt::Debug for ArchiveWrappingKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveWrappingKeys { <redacted> }")
    }
}

impl ArchiveWrappingKeys {
    /// Creates the fixed role-specific pair from distinct explicit keys.
    ///
    /// # Errors
    ///
    /// Rejects equal opaque identifiers or key material.
    pub fn new(metadata: ArchiveWrappingKey, private: ArchiveWrappingKey) -> Result<Self> {
        ensure!(
            metadata.id != private.id && metadata.bytes[..] != private.bytes[..],
            "snapshot wrapping key roles overlap"
        );
        Ok(Self { metadata, private })
    }
}

/// Known non-archive material used only to reject accidental key-role equality.
///
/// Examples include known source sealing/release keys. No key is loaded,
/// serialized or used to decrypt a source cell. Omission does not establish
/// global/source key separation. Debug is redacted and no Clone is available.
pub struct ExcludedArchiveKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for ExcludedArchiveKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExcludedArchiveKey { <redacted> }")
    }
}

impl ExcludedArchiveKey {
    /// Accepts explicitly supplied known material for bounded equality checks.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Prepared encrypted associations for one fresh archive/signing identity.
///
/// No plaintext key is retained here. This producer object is not automatically
/// serializable and is consumed when signing a declared framing root.
pub struct PreparedArchiveKeys {
    pub(super) archive_id: [u8; 16],
    pub(super) signer_id: String,
    pub(super) signer_public: [u8; 32],
    pub(super) metadata: WrappedDeclaration,
    pub(super) private: WrappedDeclaration,
}

impl fmt::Debug for PreparedArchiveKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedArchiveKeys { <redacted> }")
    }
}

/// Wraps fresh independent stream keys with authenticated inner context.
///
/// The existing AES-GCM sealer draws independent random wrapping nonces. Its
/// encrypted closed inner record binds archive ID, role, suite and wrapping ID;
/// the signed root later binds the complete ciphertext association. Known keys
/// are compared before wrapping. Cipher/library/caller copies have no perfect
/// erasure guarantee, and absent exclusions prove no global source-key property.
///
/// # Errors
///
/// Rejects key-role equality, more than 32 exclusions, or wrapping failure with
/// redacted errors. Nothing is signed and no source/runtime key is initialized.
pub fn prepare_archive_keys(
    archive_id: &FreshArchiveId,
    signer: &ArchiveSigningKey,
    wrapping: &ArchiveWrappingKeys,
    metadata: &FreshStreamKey,
    private: &FreshStreamKey,
    exclusions: &[ExcludedArchiveKey],
) -> Result<PreparedArchiveKeys> {
    let seed = Zeroizing::new(signer.key.to_bytes());
    let public = signer.public_key();
    check_separation(
        &[
            &seed,
            &wrapping.metadata.bytes,
            &wrapping.private.bytes,
            &metadata.0,
            &private.0,
        ],
        exclusions,
        &public,
    )?;
    let metadata = wrap(
        archive_id.0,
        StreamRole::Metadata,
        &wrapping.metadata,
        &metadata.0,
    )?;
    let private = wrap(
        archive_id.0,
        StreamRole::Private,
        &wrapping.private,
        &private.0,
    )?;

    Ok(PreparedArchiveKeys {
        archive_id: archive_id.0,
        signer_id: signer.id.clone(),
        signer_public: public,
        metadata,
        private,
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WrappedKeyRecord {
    schema_version: String,
    archive_id: String,
    role: String,
    wrapping_key_id: String,
    algorithm: String,
    stream_key_base64url: String,
}

impl Drop for WrappedKeyRecord {
    fn drop(&mut self) {
        self.stream_key_base64url.zeroize();
    }
}

fn wrap(
    archive_id: [u8; 16],
    role: StreamRole,
    wrapping: &ArchiveWrappingKey,
    key: &[u8; 32],
) -> Result<WrappedDeclaration> {
    let record = WrappedKeyRecord {
        schema_version: KEY_SCHEMA.into(),
        archive_id: hex::encode(archive_id),
        role: super::role_name(role).into(),
        wrapping_key_id: wrapping.id.clone(),
        algorithm: WRAP_SUITE.into(),
        stream_key_base64url: URL_SAFE_NO_PAD.encode(key),
    };
    let bytes = Zeroizing::new(canonical_bytes(&record)?);
    ensure!(
        bytes.len() <= MAX_INNER_BYTES,
        "snapshot wrapped key payload exceeds limits"
    );
    let plaintext = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("snapshot wrapped key payload is invalid"))?;
    let sealer = AesGcmSealer::new(&wrapping.bytes[..])
        .map_err(|_| anyhow::anyhow!("snapshot wrapping key is invalid"))?;
    let sealed = sealer
        .seal(plaintext)
        .map_err(|_| anyhow::anyhow!("snapshot stream key wrapping failed"))?;
    ensure!(
        sealed.len() <= MAX_WRAPPED_BYTES,
        "snapshot wrapped key exceeds limits"
    );
    Ok(WrappedDeclaration {
        key_id: wrapping.id.clone(),
        sealed,
    })
}

pub(super) fn unwrap(
    archive_id: [u8; 16],
    role: StreamRole,
    declared: &WrappedDeclaration,
    wrapping: &ArchiveWrappingKey,
) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        declared.key_id == wrapping.id,
        "snapshot wrapping identity differs"
    );
    let sealer = AesGcmSealer::new(&wrapping.bytes[..])
        .map_err(|_| anyhow::anyhow!("snapshot wrapping key is invalid"))?;
    let plaintext = Zeroizing::new(
        sealer
            .unseal(&declared.sealed)
            .map_err(|_| anyhow::anyhow!("snapshot stream key unwrapping failed"))?,
    );
    ensure!(
        plaintext.len() <= MAX_INNER_BYTES,
        "snapshot wrapped key payload exceeds limits"
    );
    let record: WrappedKeyRecord = parse_closed(plaintext.as_bytes())?;
    let canonical = Zeroizing::new(canonical_bytes(&record)?);
    ensure!(
        canonical.as_slice() == plaintext.as_bytes()
            && record.schema_version == KEY_SCHEMA
            && record.archive_id == hex::encode(archive_id)
            && record.role == super::role_name(role)
            && record.wrapping_key_id == wrapping.id
            && record.algorithm == WRAP_SUITE
            && record.stream_key_base64url.len() == 43,
        "snapshot wrapped key context differs"
    );
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&record.stream_key_base64url)
            .map_err(|_| anyhow::anyhow!("snapshot unwrapped key encoding is invalid"))?,
    );
    let canonical_key = Zeroizing::new(URL_SAFE_NO_PAD.encode(&decoded[..]));
    ensure!(
        decoded.len() == 32 && canonical_key.as_str() == record.stream_key_base64url,
        "snapshot unwrapped key encoding is invalid"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

pub(super) fn check_separation(
    keys: &[&[u8; 32]],
    exclusions: &[ExcludedArchiveKey],
    signer_public: &[u8; 32],
) -> Result<()> {
    ensure!(
        exclusions.len() <= MAX_EXCLUDED_KEYS,
        "snapshot excluded key set exceeds limits"
    );
    for (index, key) in keys.iter().enumerate() {
        ensure!(
            *key != signer_public
                && keys[..index].iter().all(|prior| *prior != *key)
                && exclusions.iter().all(|excluded| &*excluded.0 != *key),
            "snapshot archive key roles overlap"
        );
    }
    Ok(())
}
