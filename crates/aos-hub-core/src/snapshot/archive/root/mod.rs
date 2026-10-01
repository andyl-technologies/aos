//! Signed declarations and separate key custody for encrypted framing streams.
//!
//! A pinned Ed25519 signature authenticates a closed canonical declaration. It
//! does not inspect files, prove SQL/record/object closure or provenance, or
//! authorize import/activation. The only profile is `framing_only`; complete or
//! activation flags are unknown fields and reject. Caller-owned verified stream
//! summaries must be reconciled separately with the declared counts/hashes.
//!
//! ```json
//! {"schema_version":"aos.hub.snapshot-archive/v1","payload":{"profile":"framing_only"},"signature_base64url":"..."}
//! ```
//!
//! The example abbreviates required fields. Exact fixed stream roles/filenames,
//! suite, identity, canonical decimal counts and lowercase hashes are signed.
//! Signer IDs select only external trust pins; no archive-supplied public key is
//! admitted. Wrapped closed inner key records bind the archive/role/wrapping ID
//! under AES-GCM and under the signed root. Verification precedes unwrapping.
//! Unwrapped material can construct reader keys only. No Hub/source key lookup,
//! filesystem, SQL, network, Hub runtime initialization or logical record operation
//! is implemented. Known equality checks do not prove separation from keys not
//! explicitly supplied. Owned sensitive buffers are zeroizing; cipher/library/
//! caller copies have no perfect-erasure guarantee. RNG entropy, source custody
//! and actual decoder-summary provenance remain trusted caller obligations.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{ensure, Result};
use aos_release::digest::Sha256Digest;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::frames::{COMMITMENT_BYTES, FRAME_CAP, HEADER_BYTES, PREFIX_BYTES, TAG_BYTES};
use super::{StreamContext, StreamDecryptionKey, StreamLimits, StreamRole, StreamSummary};

mod keys;

pub use keys::{
    prepare_archive_keys, ArchiveSigningKey, ArchiveWrappingKey, ArchiveWrappingKeys,
    ExcludedArchiveKey, FreshArchiveId, PreparedArchiveKeys,
};

#[cfg(test)]
mod tests;

const ROOT_SCHEMA: &str = "aos.hub.snapshot-archive/v1";
const SIGNATURE_DOMAIN: &str = "aos.hub.snapshot-archive-signature/v1";
const PROFILE: &str = "framing_only";
const SUITE: &str = "aes-256-gcm-aosh-v1+ed25519-sha256-v1";
const MAX_ROOT_BYTES: usize = 64 * 1024;
const MAX_TRUST_PINS: usize = 32;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootEnvelope {
    schema_version: String,
    payload: RootPayload,
    signature_base64url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootPayload {
    archive_id: String,
    signer_key_id: String,
    profile: String,
    algorithm_suite: String,
    streams: RootStreams,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootStreams {
    metadata: RootStream,
    private: RootStream,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootStream {
    filename: String,
    role: String,
    ciphertext_bytes: String,
    data_frames: String,
    plaintext_bytes: String,
    ciphertext_sha256: String,
    wrapped_key: WrappedDeclaration,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WrappedDeclaration {
    key_id: String,
    sealed: String,
}

/// Canonical signed bytes declaring two encrypted framing streams.
///
/// This producer result is not evidence that any file was read or verified.
/// It has no automatic serialization; the explicit byte accessor supplies the
/// public signed root, never plaintext key material or source values.
pub struct SignedDeclaredRoot(Vec<u8>);

impl fmt::Debug for SignedDeclaredRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedDeclaredRoot { <declared framing> }")
    }
}

impl SignedDeclaredRoot {
    /// Borrows the exact canonical signed root bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Explicitly provisioned external export-signer public trust pins.
///
/// No constructor accepts archive bytes or a self-supplied public-key field.
/// This establishes cryptographic signer trust, not source/provider provenance.
pub struct ArchiveSignerTrust(BTreeMap<String, VerifyingKey>);

impl fmt::Debug for ArchiveSignerTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveSignerTrust { <external pins> }")
    }
}

impl ArchiveSignerTrust {
    /// Admits at most 32 distinct opaque IDs and strong Ed25519 public keys.
    ///
    /// # Errors
    ///
    /// Rejects malformed/duplicate IDs, excessive pins or invalid/weak public
    /// keys. Errors omit identifiers and parser/public-key input details.
    pub fn new(pins: impl IntoIterator<Item = (String, [u8; 32])>) -> Result<Self> {
        let mut keys = BTreeMap::new();
        for (id, public) in pins {
            ensure!(
                keys.len() < MAX_TRUST_PINS,
                "snapshot signer trust exceeds limits"
            );
            identifier(&id)?;
            let key = VerifyingKey::from_bytes(&public)
                .map_err(|_| anyhow::anyhow!("snapshot trusted signer key is invalid"))?;
            ensure!(!key.is_weak(), "snapshot trusted signer key is weak");
            ensure!(
                keys.insert(id, key).is_none(),
                "snapshot signer trust is duplicated"
            );
        }
        Ok(Self(keys))
    }
}

/// A trusted signature over framing declarations, with no actual-file claim.
///
/// Construction is restricted to closed canonical verification against external
/// pins. This wrapper permits context-bound reader-key unwrapping and separate
/// reconciliation; it authorizes no import, serving, jobs, or provider effects.
pub struct VerifiedDeclaredRoot {
    payload: RootPayload,
    archive_id: [u8; 16],
    signer_public: [u8; 32],
    metadata: StreamSummary,
    private: StreamSummary,
}

impl fmt::Debug for VerifiedDeclaredRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedDeclaredRoot { <authenticated declarations only> }")
    }
}

impl VerifiedDeclaredRoot {
    /// Returns the authenticated public archive identity, not a source identity.
    pub fn archive_id(&self) -> [u8; 16] {
        self.archive_id
    }

    /// Returns the externally trusted signer identity covered by the signature.
    pub fn signer_id(&self) -> &str {
        &self.payload.signer_key_id
    }

    /// Returns the fixed role context callers must use for frame verification.
    pub fn stream_context(&self, role: StreamRole) -> StreamContext {
        StreamContext::new(self.archive_id, role)
    }

    /// Borrows declared counts/hashes, never actual decoder/file evidence.
    pub fn declared_summary(&self, role: StreamRole) -> &StreamSummary {
        match role {
            StreamRole::Metadata => &self.metadata,
            StreamRole::Private => &self.private,
        }
    }

    /// Compares one caller-provided completion summary with its signed declaration.
    ///
    /// Callers must obtain the summary from a fully completed decoder using
    /// [`Self::stream_context`], after END and clean EOF. Since `StreamSummary`
    /// is caller-constructible, this method does not prove its provenance or
    /// inspect files. Even a match grants no typed/whole-Hub/activation claim.
    ///
    /// # Errors
    ///
    /// Rejects any count, length or hash difference with a redacted error.
    pub fn reconcile_declared_summary(
        &self,
        role: StreamRole,
        observed: &StreamSummary,
    ) -> Result<()> {
        ensure!(
            observed == self.declared_summary(role),
            "snapshot observed framing summary differs"
        );
        Ok(())
    }

    /// Unwraps one selected role without requiring custody of the other key.
    ///
    /// Metadata-only readers need not possess a private wrapping key. This
    /// validates only the selected signed association, inner context and known
    /// selected-key exclusions; absent other-role material is not checked.
    ///
    /// # Errors
    ///
    /// Rejects wrong custody identity/material, malformed encrypted context or
    /// selected-key equality. Errors contain no key payload or parser detail.
    pub fn unwrap_reader_key(
        &self,
        role: StreamRole,
        wrapping: &ArchiveWrappingKey,
        exclusions: &[ExcludedArchiveKey],
    ) -> Result<StreamDecryptionKey> {
        keys::check_separation(&[&wrapping.bytes], exclusions, &self.signer_public)?;
        let declared = match role {
            StreamRole::Metadata => &self.payload.streams.metadata.wrapped_key,
            StreamRole::Private => &self.payload.streams.private.wrapped_key,
        };
        let key = keys::unwrap(self.archive_id, role, declared, wrapping)?;
        keys::check_separation(&[&wrapping.bytes, &key], exclusions, &self.signer_public)?;
        Ok(StreamDecryptionKey::from_bytes(*key))
    }

    /// Unwraps both role-bound keys only after signature/structure/scope validation.
    ///
    /// Explicit wrapping IDs/material must be distinct and match the signed
    /// associations. Inner context and known key equality checks apply before
    /// reader-only key wrappers are returned. Exclusions do not prove properties
    /// of absent source keys or unknown signing seeds.
    ///
    /// # Errors
    ///
    /// Rejects missing/wrong identities, decryption/inner-context tampering,
    /// invalid key encodings or known equality. Errors contain no key payloads.
    pub fn unwrap_reader_keys(
        &self,
        wrapping: &ArchiveWrappingKeys,
        exclusions: &[ExcludedArchiveKey],
    ) -> Result<UnwrappedReaderKeys> {
        keys::check_separation(
            &[&wrapping.metadata.bytes, &wrapping.private.bytes],
            exclusions,
            &self.signer_public,
        )?;
        let metadata = keys::unwrap(
            self.archive_id,
            StreamRole::Metadata,
            &self.payload.streams.metadata.wrapped_key,
            &wrapping.metadata,
        )?;
        let private = keys::unwrap(
            self.archive_id,
            StreamRole::Private,
            &self.payload.streams.private.wrapped_key,
            &wrapping.private,
        )?;
        keys::check_separation(
            &[
                &wrapping.metadata.bytes,
                &wrapping.private.bytes,
                &metadata,
                &private,
            ],
            exclusions,
            &self.signer_public,
        )?;
        Ok(UnwrappedReaderKeys {
            metadata: StreamDecryptionKey::from_bytes(*metadata),
            private: StreamDecryptionKey::from_bytes(*private),
        })
    }
}

/// Distinct unwrapped role keys usable only by framing readers.
///
/// No writer-key conversion, raw key serialization or Clone is supplied.
pub struct UnwrappedReaderKeys {
    metadata: StreamDecryptionKey,
    private: StreamDecryptionKey,
}

impl fmt::Debug for UnwrappedReaderKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnwrappedReaderKeys { <redacted> }")
    }
}

impl UnwrappedReaderKeys {
    /// Transfers the metadata and private decryption keys in fixed role order.
    pub fn into_role_keys(self) -> (StreamDecryptionKey, StreamDecryptionKey) {
        (self.metadata, self.private)
    }
}

/// Signs a fixed framing-only root from prepared custody and caller declarations.
///
/// The prepared identity must match this exact signer. Counts/hashes are supplied
/// declarations, not actual-file or decoder evidence. The function performs no
/// I/O and consumes preparation to avoid accidental reuse for another manifest.
///
/// # Errors
///
/// Rejects a different signer, impossible/over-limit summaries or encoding errors.
/// The result never contains plaintext keys, source data or completeness flags.
pub fn sign_declared_root(
    prepared: PreparedArchiveKeys,
    signer: &ArchiveSigningKey,
    metadata: &StreamSummary,
    private: &StreamSummary,
) -> Result<SignedDeclaredRoot> {
    ensure!(
        prepared.signer_id == signer.id && prepared.signer_public == signer.public_key(),
        "snapshot prepared signer differs"
    );
    let payload = RootPayload {
        archive_id: hex::encode(prepared.archive_id),
        signer_key_id: prepared.signer_id,
        profile: PROFILE.into(),
        algorithm_suite: SUITE.into(),
        streams: RootStreams {
            metadata: declaration(StreamRole::Metadata, metadata, prepared.metadata)?,
            private: declaration(StreamRole::Private, private, prepared.private)?,
        },
    };
    let bytes = canonical_bytes(&payload)?;
    let digest = Sha256Digest::separated(SIGNATURE_DOMAIN, &bytes);
    let signature = signer.key.sign(digest.as_bytes());
    let envelope = RootEnvelope {
        schema_version: ROOT_SCHEMA.into(),
        payload,
        signature_base64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    let encoded = canonical_bytes(&envelope)?;
    ensure!(
        encoded.len() <= MAX_ROOT_BYTES,
        "snapshot root exceeds limits"
    );
    Ok(SignedDeclaredRoot(encoded))
}

/// Verifies a bounded canonical framing-only root using external signer trust.
///
/// Closed schema, exact suite/profile/context declarations and canonical bytes
/// are admitted before signature verification; no key is unwrapped during this
/// function. The result authenticates declarations only, not actual files.
///
/// # Errors
///
/// Rejects excessive/noncanonical/duplicate/unknown input, unsupported scope or
/// algorithms, invalid identities/counts/hashes, unknown signer, malformed or
/// invalid signature. Errors omit input and cryptographic/parser context.
pub fn verify_declared_root(
    bytes: &[u8],
    trust: &ArchiveSignerTrust,
) -> Result<VerifiedDeclaredRoot> {
    ensure!(
        bytes.len() <= MAX_ROOT_BYTES,
        "snapshot root exceeds limits"
    );
    let envelope: RootEnvelope = parse_closed(bytes)?;
    ensure!(
        canonical_bytes(&envelope)? == bytes
            && envelope.schema_version == ROOT_SCHEMA
            && envelope.payload.profile == PROFILE
            && envelope.payload.algorithm_suite == SUITE,
        "snapshot root schema, scope or canonical bytes differ"
    );
    identifier(&envelope.payload.signer_key_id)?;
    let archive_id = fixed_hex::<16>(&envelope.payload.archive_id)?;
    let metadata = validate_declaration(StreamRole::Metadata, &envelope.payload.streams.metadata)?;
    let private = validate_declaration(StreamRole::Private, &envelope.payload.streams.private)?;
    ensure!(
        envelope.payload.streams.metadata.wrapped_key.key_id
            != envelope.payload.streams.private.wrapped_key.key_id,
        "snapshot wrapping identities overlap"
    );
    let key = trust
        .0
        .get(&envelope.payload.signer_key_id)
        .ok_or_else(|| anyhow::anyhow!("snapshot root signer is not trusted"))?;
    ensure!(
        envelope.signature_base64url.len() == 86,
        "snapshot root signature encoding is invalid"
    );
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.signature_base64url)
        .map_err(|_| anyhow::anyhow!("snapshot root signature encoding is invalid"))?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&signature_bytes) == envelope.signature_base64url,
        "snapshot root signature encoding is invalid"
    );
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("snapshot root signature encoding is invalid"))?;
    let payload = canonical_bytes(&envelope.payload)?;
    let digest = Sha256Digest::separated(SIGNATURE_DOMAIN, &payload);
    key.verify_strict(digest.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("snapshot root signature is invalid"))?;
    Ok(VerifiedDeclaredRoot {
        archive_id,
        signer_public: key.to_bytes(),
        payload: envelope.payload,
        metadata,
        private,
    })
}

fn declaration(
    role: StreamRole,
    summary: &StreamSummary,
    wrapped_key: WrappedDeclaration,
) -> Result<RootStream> {
    validate_summary(summary)?;
    Ok(RootStream {
        filename: filename(role).into(),
        role: role_name(role).into(),
        ciphertext_bytes: summary.ciphertext_bytes.to_string(),
        data_frames: summary.data_frames.to_string(),
        plaintext_bytes: summary.plaintext_bytes.to_string(),
        ciphertext_sha256: hex::encode(summary.ciphertext_sha256),
        wrapped_key,
    })
}

fn validate_declaration(role: StreamRole, stream: &RootStream) -> Result<StreamSummary> {
    ensure!(
        stream.filename == filename(role) && stream.role == role_name(role),
        "snapshot stream role or filename differs"
    );
    identifier(&stream.wrapped_key.key_id)?;
    ensure!(
        stream.wrapped_key.sealed.len() <= keys::MAX_WRAPPED_BYTES,
        "snapshot wrapped key exceeds limits"
    );
    let decoded = URL_SAFE_NO_PAD
        .decode(&stream.wrapped_key.sealed)
        .map_err(|_| anyhow::anyhow!("snapshot wrapped key encoding is invalid"))?;
    ensure!(
        decoded.len() >= 12 + 16 && URL_SAFE_NO_PAD.encode(&decoded) == stream.wrapped_key.sealed,
        "snapshot wrapped key encoding is invalid"
    );
    let summary = StreamSummary {
        data_frames: decimal(&stream.data_frames)?,
        plaintext_bytes: decimal(&stream.plaintext_bytes)?,
        ciphertext_bytes: decimal(&stream.ciphertext_bytes)?,
        ciphertext_sha256: fixed_hex::<32>(&stream.ciphertext_sha256)?,
    };
    validate_summary(&summary)?;
    Ok(summary)
}

fn validate_summary(summary: &StreamSummary) -> Result<()> {
    let limits = StreamLimits::default();
    let overhead = summary
        .data_frames
        .checked_mul((PREFIX_BYTES + TAG_BYTES) as u64)
        .and_then(|value| {
            value.checked_add((HEADER_BYTES + PREFIX_BYTES + COMMITMENT_BYTES + TAG_BYTES) as u64)
        })
        .and_then(|value| value.checked_add(summary.plaintext_bytes))
        .ok_or_else(|| anyhow::anyhow!("snapshot declared summary exceeds limits"))?;
    let capacity = summary
        .data_frames
        .checked_mul(FRAME_CAP as u64)
        .ok_or_else(|| anyhow::anyhow!("snapshot declared summary exceeds limits"))?;
    ensure!(
        summary.data_frames <= limits.max_data_frames
            && summary.plaintext_bytes <= limits.max_plaintext_bytes
            && summary.ciphertext_bytes <= limits.max_ciphertext_bytes
            && summary.ciphertext_bytes == overhead
            && summary.plaintext_bytes >= summary.data_frames
            && summary.plaintext_bytes <= capacity,
        "snapshot declared framing summary is impossible or exceeds limits"
    );
    Ok(())
}

fn filename(role: StreamRole) -> &'static str {
    match role {
        StreamRole::Metadata => "metadata.aosh",
        StreamRole::Private => "private.aosh",
    }
}

fn role_name(role: StreamRole) -> &'static str {
    match role {
        StreamRole::Metadata => "metadata",
        StreamRole::Private => "private",
    }
}

fn identifier(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "snapshot opaque key identity is invalid"
    );
    Ok(())
}

fn decimal(text: &str) -> Result<u64> {
    ensure!(text.len() <= 20, "snapshot decimal count is invalid");
    let value = text
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("snapshot decimal count is invalid"))?;
    ensure!(
        value.to_string() == text,
        "snapshot decimal count is invalid"
    );
    Ok(value)
}

fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == N * 2
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "snapshot hexadecimal identity is invalid"
    );
    let mut bytes = [0u8; N];
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|_| anyhow::anyhow!("snapshot hexadecimal identity is invalid"))?;
    Ok(bytes)
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    aos_release::canonical::to_vec(value)
        .map_err(|_| anyhow::anyhow!("snapshot canonical encoding failed"))
}

fn parse_closed<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    aos_release::canonical::from_slice(bytes, "snapshot root contract")
        .map_err(|_| anyhow::anyhow!("snapshot closed contract is invalid"))
}
