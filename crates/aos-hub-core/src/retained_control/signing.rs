//! Signing-key generations, custody, and typed usage bindings.

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::plan::HeadSeal;
use super::primitives::{ContentDigest, ControlError, Generation, Revision, StableId};

/// Supported signing-key algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    /// Ed25519 signatures.
    Ed25519,
}

/// An immutable operator-managed secret-provider version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecretVersionRef {
    /// Secret provider stable identity.
    provider: StableId,
    /// Secret identity within the provider.
    secret: StableId,
    /// Immutable provider version, never `latest`.
    version: StableId,
    /// Exact immutable secret-provider configuration revision.
    provider_revision: HeadSeal,
    /// SHA-256 fingerprint of the resolved key seed.
    credential_fingerprint: ContentDigest,
    /// Digest of provider-signed or operator-attested version resolution evidence.
    resolution_evidence_digest: ContentDigest,
}

/// Unforgeable module capability held only by a verified provider resolver.
pub(super) struct ProviderResolutionCapability {
    _private: (),
}

impl ProviderResolutionCapability {
    /// Creates the capability at the retained-control resolver boundary.
    pub(super) fn for_verified_resolver() -> Self {
        Self { _private: () }
    }
}

impl SecretVersionRef {
    /// Constructs a secret reference from resolver-controlled immutable evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the provider, secret, version, or
    /// provider-revision identities are mismatched or the version is mutable.
    pub(super) fn from_provider_resolution(
        _capability: &ProviderResolutionCapability,
        provider: StableId,
        secret: StableId,
        version: StableId,
        provider_revision: HeadSeal,
        credential_fingerprint: ContentDigest,
        resolution_evidence_digest: ContentDigest,
    ) -> Result<Self, ControlError> {
        let reference = Self {
            provider,
            secret,
            version,
            provider_revision,
            credential_fingerprint,
            resolution_evidence_digest,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Rejects a mutable or ambiguous secret version.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when identities or the provider head
    /// are mismatched, or the version is named `latest`, `current`, or `active`.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.provider.kind() != "secret-provider"
            || self.secret.kind() != "secret"
            || self.version.kind() != "secret-version"
            || self.provider_revision.stable_id != self.provider
        {
            return Err(invalid(
                "secret_version",
                "provider, secret, version, and provider revision must have matching typed identities",
            ));
        }
        if matches!(self.version.opaque(), "latest" | "current" | "active") {
            return Err(invalid(
                "secret_version",
                "must name an immutable provider version",
            ));
        }
        Ok(())
    }
}

/// Custody model for one exact signing-key generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyCustody {
    /// The private key remains outside the Hub; apply accepts signed artifacts.
    External,
    /// The Hub resolves an immutable secret-provider version at operation time.
    SecretProvider {
        /// Exact provider resolution plus a private-key possession proof.
        resolution: SecretProviderCustodyResolutionProof,
    },
}

/// Proof that immutable secret-provider custody resolves the declared public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecretProviderCustodyResolutionProof {
    /// Exact immutable secret-provider reference.
    secret_version: SecretVersionRef,
    /// Digest of provider/version/public-key facts challenged by the Hub.
    challenge_digest: ContentDigest,
    /// Fingerprint of the declared public key challenged by the Hub.
    public_key_fingerprint: ContentDigest,
    /// Canonical unpadded standard-base64 Ed25519 challenge signature.
    signature: String,
    /// Digest of the exact challenge signature bytes.
    signature_digest: ContentDigest,
}

impl SecretProviderCustodyResolutionProof {
    /// Constructs proof evidence only after a trusted provider resolver has
    /// resolved the immutable version and returned a challenge signature.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or digest error when the immutable reference,
    /// challenge, public key, or canonical Ed25519 signature is inconsistent.
    pub(super) fn from_provider_resolution(
        _capability: &ProviderResolutionCapability,
        secret_version: SecretVersionRef,
        public_key_bytes: &[u8; 32],
        public_key_fingerprint: ContentDigest,
        challenge_digest: ContentDigest,
        signature: String,
        signature_digest: ContentDigest,
    ) -> Result<Self, ControlError> {
        let proof = Self {
            secret_version,
            challenge_digest,
            public_key_fingerprint: public_key_fingerprint.clone(),
            signature,
            signature_digest,
        };
        proof.validate(public_key_bytes, &public_key_fingerprint)?;
        Ok(proof)
    }

    fn validate(
        &self,
        public_key_bytes: &[u8; 32],
        public_key_fingerprint: &ContentDigest,
    ) -> Result<(), ControlError> {
        self.secret_version.validate()?;
        if &self.public_key_fingerprint != public_key_fingerprint || self.signature.len() != 86 {
            return Err(invalid(
                "secret_provider_custody_resolution",
                "must challenge the exact declared public key",
            ));
        }
        let expected_challenge = ContentDigest::of_value(&(
            &self.secret_version.provider,
            &self.secret_version.secret,
            &self.secret_version.version,
            &self.secret_version.provider_revision,
            &self.secret_version.credential_fingerprint,
            &self.secret_version.resolution_evidence_digest,
            public_key_fingerprint,
        ))?;
        if self.challenge_digest != expected_challenge {
            return Err(ControlError::DigestMismatch);
        }
        let signature = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.signature)
            .map_err(|_| invalid("signature", "must be canonical unpadded base64"))?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| invalid("signature", "Ed25519 signatures must contain 64 bytes"))?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature) != self.signature
            || ContentDigest::of_bytes(signature) != self.signature_digest
        {
            return Err(ControlError::DigestMismatch);
        }
        let mut message = b"aos-hub-secret-provider-custody-resolution-v1\0".to_vec();
        message.extend_from_slice(self.challenge_digest.as_str().as_bytes());
        VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|_| invalid("public_key", "must encode a valid Ed25519 key"))?
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| {
                invalid(
                    "secret_provider_custody_resolution",
                    "resolved private key does not match the declared public key",
                )
            })
    }
}

/// Lifecycle state of one immutable signing-key generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyGenerationState {
    /// The generation may sign new content.
    Active,
    /// The generation remains trusted for verification but cannot sign new content.
    Retired,
}

/// Immutable contents of one signing-key generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SigningKeyGenerationContents {
    /// Signing algorithm.
    pub(super) algorithm: SigningAlgorithm,
    /// Canonical unpadded standard-base64 encoding of the 32-byte Ed25519 key.
    pub(super) public_key: String,
    /// SHA-256 fingerprint of the canonical public key.
    pub(super) public_key_fingerprint: ContentDigest,
    /// Private-key custody policy; never private bytes.
    pub(super) custody: KeyCustody,
    /// Generation lifecycle state.
    pub(super) state: KeyGenerationState,
}

/// One immutable signing-key generation revision.
pub type SigningKeyGeneration = Revision<SigningKeyGenerationContents>;

impl SigningKeyGenerationContents {
    /// Creates a new externally custodied active signing-key generation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or digest error for malformed public material
    /// or a fingerprint that does not match the parsed key bytes.
    pub fn external(
        public_key: String,
        public_key_fingerprint: ContentDigest,
    ) -> Result<Self, ControlError> {
        let contents = Self {
            algorithm: SigningAlgorithm::Ed25519,
            public_key,
            public_key_fingerprint,
            custody: KeyCustody::External,
            state: KeyGenerationState::Active,
        };
        contents.validate_new()?;
        Ok(contents)
    }

    /// Creates an active provider-custodied generation after immutable resolution.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or digest error when public material and the
    /// provider-resolved possession proof disagree.
    pub(super) fn secret_provider_from_resolution(
        _capability: &ProviderResolutionCapability,
        public_key: String,
        public_key_fingerprint: ContentDigest,
        resolution: SecretProviderCustodyResolutionProof,
    ) -> Result<Self, ControlError> {
        let contents = Self {
            algorithm: SigningAlgorithm::Ed25519,
            public_key,
            public_key_fingerprint,
            custody: KeyCustody::SecretProvider { resolution },
            state: KeyGenerationState::Active,
        };
        contents.validate_new()?;
        Ok(contents)
    }

    /// Validates public material, fingerprint, custody, and initial state.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for empty/oversized public material, a
    /// fingerprint mismatch, mutable secret-provider references, or a non-active
    /// initial generation.
    pub fn validate_new(&self) -> Result<(), ControlError> {
        self.validate()?;
        if self.state != KeyGenerationState::Active {
            return Err(invalid("state", "new key generations must be active"));
        }
        Ok(())
    }

    /// Validates public material, fingerprint, and custody for any retained state.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or digest error for malformed public material,
    /// fingerprint substitution, or invalid provider-resolution evidence.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.public_key.len() != 43 {
            return Err(invalid(
                "public_key",
                "Ed25519 public keys require 43 unpadded base64 characters",
            ));
        }
        let public_key_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| invalid("public_key", "must be canonical unpadded standard base64"))?;
        let public_key_bytes: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| invalid("public_key", "Ed25519 public keys must contain 32 bytes"))?;
        VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| invalid("public_key", "must encode a valid Ed25519 verification key"))?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key_bytes)
            != self.public_key
        {
            return Err(invalid(
                "public_key",
                "must use the canonical base64 encoding",
            ));
        }
        if ContentDigest::of_bytes(public_key_bytes) != self.public_key_fingerprint {
            return Err(ControlError::DigestMismatch);
        }
        if let KeyCustody::SecretProvider { resolution } = &self.custody {
            resolution.validate(&public_key_bytes, &self.public_key_fingerprint)?;
        }
        Ok(())
    }

    /// Retires an active generation without deleting verification material.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] if already retired.
    pub fn retire(&self) -> Result<Self, ControlError> {
        self.validate_new()?;
        let mut next = self.clone();
        next.state = KeyGenerationState::Retired;
        Ok(next)
    }
}

/// A typed consumer of a signing key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "stable_id", rename_all = "snake_case")]
pub enum SigningKeyConsumer {
    /// A registry surface.
    Registry(StableId),
    /// A standalone or shared binary cache.
    BinaryCache(StableId),
    /// A registry channel intent.
    Channel(StableId),
}

/// The purpose for which a consumer uses a signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningPurpose {
    /// Registry tag or commit signing.
    RegistryPublication,
    /// Nix `narinfo` signing.
    NarInfo,
    /// Channel frontier signing.
    ChannelFrontier,
}

/// Whether a key-usage binding participates in new signing work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningUsageState {
    /// New signing work resolves this exact key generation.
    Active,
    /// The association remains historical only.
    Detached,
}

/// Immutable contents of a typed signing-key usage revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SigningKeyUsageContents {
    /// Typed consumer identity.
    pub(super) consumer: SigningKeyConsumer,
    /// Signing purpose.
    pub(super) purpose: SigningPurpose,
    /// Signing-key stable identity.
    pub(super) signing_key_id: StableId,
    /// Exact immutable key generation.
    pub(super) signing_key_generation: Generation,
    /// Usage lifecycle state.
    pub(super) state: SigningUsageState,
}

/// One immutable typed key-usage binding revision.
pub type SigningKeyUsageRevision = Revision<SigningKeyUsageContents>;

impl SigningKeyUsageContents {
    /// Creates a new active typed signing-key usage.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an incompatible consumer,
    /// purpose, or signing-key identity.
    pub fn new(
        consumer: SigningKeyConsumer,
        purpose: SigningPurpose,
        signing_key_id: StableId,
        signing_key_generation: Generation,
    ) -> Result<Self, ControlError> {
        let usage = Self {
            consumer,
            purpose,
            signing_key_id,
            signing_key_generation,
            state: SigningUsageState::Active,
        };
        usage.validate_new()?;
        Ok(usage)
    }

    /// Validates the consumer type, purpose, key identity, and lifecycle pair.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for a mismatched stable-id kind or an
    /// illegal consumer/purpose pair.
    pub fn validate(&self) -> Result<(), ControlError> {
        let legal_pair = match (&self.consumer, self.purpose) {
            (SigningKeyConsumer::Registry(id), SigningPurpose::RegistryPublication) => {
                id.kind() == "registry"
            }
            (SigningKeyConsumer::BinaryCache(id), SigningPurpose::NarInfo) => id.kind() == "cache",
            (SigningKeyConsumer::Channel(id), SigningPurpose::ChannelFrontier) => {
                id.kind() == "channel"
            }
            _ => false,
        };
        if !legal_pair || self.signing_key_id.kind() != "signing-key" {
            return Err(invalid(
                "signing_usage",
                "consumer kind, purpose, and signing-key identity must be compatible",
            ));
        }
        Ok(())
    }

    /// Validates an initially active signing usage.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for invalid identity/purpose pairing or
    /// an initially detached association.
    pub fn validate_new(&self) -> Result<(), ControlError> {
        self.validate()?;
        if self.state != SigningUsageState::Active {
            return Err(invalid("state", "new signing usages must be active"));
        }
        Ok(())
    }

    /// Derives stable relationship identity independent of key rotation.
    ///
    /// # Errors
    ///
    /// Returns a canonical serialization or stable-id validation error.
    pub fn stable_id(&self) -> Result<StableId, ControlError> {
        self.validate()?;
        let digest = ContentDigest::of_value(&(&self.consumer, self.purpose))?;
        StableId::new(format!("signing-usage:{}", digest.as_str()))
    }

    /// Pins the usage to the next key generation.
    ///
    /// # Errors
    ///
    /// Returns a generation error if `next_generation` is not exactly one
    /// greater, or a state error if the usage is detached.
    pub fn rotate(&self, next_generation: Generation) -> Result<Self, ControlError> {
        self.validate_new()?;
        if self.state != SigningUsageState::Active {
            return Err(invalid("state", "a detached signing usage is immutable"));
        }
        let required = self.signing_key_generation.next()?;
        if next_generation != required {
            return Err(ControlError::NonContiguousGeneration {
                expected: required.get(),
                received: next_generation.get(),
            });
        }
        let mut next = self.clone();
        next.signing_key_generation = next_generation;
        next.validate_successor(self)?;
        Ok(next)
    }

    /// Detaches a signing usage while retaining history.
    ///
    /// # Errors
    ///
    /// Returns a state error if already detached.
    pub fn detach(&self) -> Result<Self, ControlError> {
        self.validate_new()?;
        if self.state != SigningUsageState::Active {
            return Err(invalid("state", "a detached signing usage is immutable"));
        }
        let mut next = self.clone();
        next.state = SigningUsageState::Detached;
        next.validate_successor(self)?;
        Ok(next)
    }

    fn validate_successor(&self, current: &Self) -> Result<(), ControlError> {
        current.validate()?;
        self.validate()?;
        let rotated = if current.state == SigningUsageState::Active
            && self.state == SigningUsageState::Active
        {
            self.signing_key_generation == current.signing_key_generation.next()?
        } else {
            false
        };
        let detached = current.state == SigningUsageState::Active
            && self.state == SigningUsageState::Detached
            && self.signing_key_generation == current.signing_key_generation;
        if self.consumer != current.consumer
            || self.purpose != current.purpose
            || self.signing_key_id != current.signing_key_id
            || !(rotated || detached)
        {
            return Err(invalid(
                "signing_usage",
                "successor must rotate one generation or detach without changing identity/key",
            ));
        }
        Ok(())
    }
}

/// Snapshot seal proving that a rotation reviewed every active usage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SigningRotationGate {
    /// Exact signing-key identity being rotated.
    pub signing_key_id: StableId,
    /// Current key generation.
    pub current_generation: Generation,
    /// Exact current signing-key generation head.
    pub signing_key_head: HeadSeal,
    /// Exact current active signing-key generation contents.
    pub signing_key: SigningKeyGenerationContents,
    /// Complete current usage snapshot, strictly usage-id sorted.
    pub usage_snapshot: Vec<SigningUsageSnapshotEntry>,
    /// Digest of the complete exact usage snapshot.
    pub usage_snapshot_digest: ContentDigest,
    /// Authoritative current head of this key's usage index.
    pub usage_index_head: HeadSeal,
}

/// One exact current signing-usage revision retained by a key lifecycle gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SigningUsageSnapshotEntry {
    /// Stable relationship identity.
    pub usage_id: StableId,
    /// Exact current usage head.
    pub head: HeadSeal,
    /// Exact current immutable usage contents.
    pub contents: SigningKeyUsageContents,
}

/// Usage snapshot sealed before retiring one key generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SigningRetirementGate {
    /// Exact signing-key identity being retired.
    pub signing_key_id: StableId,
    /// Exact generation proposed for retirement.
    pub generation: Generation,
    /// Exact current signing-key generation head.
    pub signing_key_head: HeadSeal,
    /// Exact current active signing-key generation contents.
    pub signing_key: SigningKeyGenerationContents,
    /// Complete current usage snapshot, including detached history.
    pub usage_snapshot: Vec<SigningUsageSnapshotEntry>,
    /// Digest of the complete exact usage snapshot.
    pub usage_snapshot_digest: ContentDigest,
    /// Authoritative current head of this key's usage index.
    pub usage_index_head: HeadSeal,
}

impl SigningRetirementGate {
    /// Ensures no active consumer remains pinned to a retiring generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when any active usage remains or the
    /// supplied usage list is not strictly ordered and duplicate-free.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_signing_key_generation(
            &self.signing_key_id,
            self.generation,
            &self.signing_key_head,
            &self.signing_key,
        )?;
        validate_usage_snapshot(
            &self.signing_key_id,
            &self.usage_snapshot,
            &self.usage_snapshot_digest,
            &self.usage_index_head,
        )?;
        if self.usage_snapshot.iter().any(|entry| {
            entry.contents.state == SigningUsageState::Active
                && entry.contents.signing_key_generation == self.generation
        }) {
            return Err(invalid(
                "usage_snapshot",
                "detach or rotate every active usage before retirement",
            ));
        }
        Ok(())
    }
}

impl SigningRotationGate {
    /// Validates the exact authoritative usage snapshot reviewed for rotation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] if usages are not strictly ordered or
    /// do not retain their exact heads and contents, or a digest error when the
    /// snapshot and authoritative index head disagree.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_signing_key_generation(
            &self.signing_key_id,
            self.current_generation,
            &self.signing_key_head,
            &self.signing_key,
        )?;
        validate_usage_snapshot(
            &self.signing_key_id,
            &self.usage_snapshot,
            &self.usage_snapshot_digest,
            &self.usage_index_head,
        )
    }
}

fn validate_signing_key_generation(
    signing_key_id: &StableId,
    generation: Generation,
    head: &HeadSeal,
    contents: &SigningKeyGenerationContents,
) -> Result<(), ControlError> {
    contents.validate_new()?;
    if head.stable_id != *signing_key_id
        || head.generation != generation
        || head.content_digest != ContentDigest::of_value(contents)?
    {
        return Err(invalid(
            "signing_key_head",
            "must bind the exact active signing-key generation contents",
        ));
    }
    Ok(())
}

fn validate_usage_snapshot(
    signing_key_id: &StableId,
    snapshot: &[SigningUsageSnapshotEntry],
    snapshot_digest: &ContentDigest,
    index_head: &HeadSeal,
) -> Result<(), ControlError> {
    if signing_key_id.kind() != "signing-key"
        || snapshot.len() > 4_096
        || snapshot
            .windows(2)
            .any(|pair| pair[0].usage_id >= pair[1].usage_id)
    {
        return Err(invalid(
            "usage_snapshot",
            "must be bounded, strictly ordered, and tied to a signing key",
        ));
    }
    for entry in snapshot {
        entry.contents.validate()?;
        if entry.usage_id != entry.contents.stable_id()?
            || entry.head.stable_id != entry.usage_id
            || entry.head.content_digest != ContentDigest::of_value(&entry.contents)?
            || entry.contents.signing_key_id != *signing_key_id
        {
            return Err(invalid(
                "usage_snapshot",
                "every usage must retain its exact current head and contents",
            ));
        }
    }
    if ContentDigest::of_value(snapshot)? != *snapshot_digest
        || index_head.stable_id != signing_usage_index_id(signing_key_id)?
        || index_head.content_digest != *snapshot_digest
    {
        return Err(ControlError::DigestMismatch);
    }
    Ok(())
}

fn signing_usage_index_id(signing_key_id: &StableId) -> Result<StableId, ControlError> {
    StableId::new(format!(
        "signing-usage-index:{}",
        ContentDigest::of_value(signing_key_id)?.as_str()
    ))
}

fn invalid(field: &'static str, reason: &str) -> ControlError {
    ControlError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;
    use crate::retained_control::primitives::ResourceVersion;

    fn provider_head() -> HeadSeal {
        HeadSeal {
            stable_id: StableId::new("secret-provider:vault").unwrap(),
            generation: Generation::new(2).unwrap(),
            content_digest: ContentDigest::of_bytes("provider-config"),
            resource_version: ResourceVersion::new(3).unwrap(),
        }
    }

    fn external_contents(seed: u8) -> SigningKeyGenerationContents {
        let public_key_bytes = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        SigningKeyGenerationContents {
            algorithm: SigningAlgorithm::Ed25519,
            public_key: base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key_bytes),
            public_key_fingerprint: ContentDigest::of_bytes(public_key_bytes),
            custody: KeyCustody::External,
            state: KeyGenerationState::Active,
        }
    }

    fn key_head(
        signing_key_id: &StableId,
        generation: Generation,
        contents: &SigningKeyGenerationContents,
    ) -> HeadSeal {
        HeadSeal {
            stable_id: signing_key_id.clone(),
            generation,
            content_digest: ContentDigest::of_value(contents).unwrap(),
            resource_version: ResourceVersion::new(1).unwrap(),
        }
    }

    #[test]
    fn provider_custody_requires_an_immutable_secret_version() {
        let custody = SecretVersionRef {
            provider: StableId::new("secret-provider:vault").unwrap(),
            secret: StableId::new("secret:signer").unwrap(),
            version: StableId::new("secret-version:latest").unwrap(),
            provider_revision: provider_head(),
            credential_fingerprint: ContentDigest::of_bytes("seed"),
            resolution_evidence_digest: ContentDigest::of_bytes("resolution"),
        };
        assert!(custody.validate().is_err());
    }

    fn provider_custodied_contents(
        signing_key: &ed25519_dalek::SigningKey,
    ) -> SigningKeyGenerationContents {
        let capability = ProviderResolutionCapability::for_verified_resolver();
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key_fingerprint = ContentDigest::of_bytes(public_key_bytes);
        let secret_version = SecretVersionRef::from_provider_resolution(
            &capability,
            StableId::new("secret-provider:vault").unwrap(),
            StableId::new("secret:signer").unwrap(),
            StableId::new("secret-version:42").unwrap(),
            provider_head(),
            ContentDigest::of_bytes("seed-fingerprint"),
            ContentDigest::of_bytes("provider-resolution"),
        )
        .unwrap();
        let challenge_digest = ContentDigest::of_value(&(
            &secret_version.provider,
            &secret_version.secret,
            &secret_version.version,
            &secret_version.provider_revision,
            &secret_version.credential_fingerprint,
            &secret_version.resolution_evidence_digest,
            &public_key_fingerprint,
        ))
        .unwrap();
        let mut message = b"aos-hub-secret-provider-custody-resolution-v1\0".to_vec();
        message.extend_from_slice(challenge_digest.as_str().as_bytes());
        let signature_bytes = signing_key.sign(&message).to_bytes();
        let resolution = SecretProviderCustodyResolutionProof::from_provider_resolution(
            &capability,
            secret_version,
            &public_key_bytes,
            public_key_fingerprint.clone(),
            challenge_digest,
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature_bytes),
            ContentDigest::of_bytes(signature_bytes),
        )
        .unwrap();
        SigningKeyGenerationContents {
            algorithm: SigningAlgorithm::Ed25519,
            public_key: base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key_bytes),
            public_key_fingerprint: public_key_fingerprint.clone(),
            custody: KeyCustody::SecretProvider { resolution },
            state: KeyGenerationState::Active,
        }
    }

    #[test]
    fn provider_resolution_proves_private_key_matches_declared_public_key() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[17_u8; 32]);
        let contents = provider_custodied_contents(&signing_key);
        contents.validate_new().unwrap();

        let mut changed_version = contents.clone();
        let KeyCustody::SecretProvider { resolution } = &mut changed_version.custody else {
            panic!("test fixture uses secret-provider custody");
        };
        resolution.secret_version.version = StableId::new("secret-version:43").unwrap();
        assert!(changed_version.validate_new().is_err());

        let other_key = ed25519_dalek::SigningKey::from_bytes(&[19_u8; 32]);
        let mut substituted_key = provider_custodied_contents(&signing_key);
        substituted_key.public_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(other_key.verifying_key().to_bytes());
        substituted_key.public_key_fingerprint =
            ContentDigest::of_bytes(other_key.verifying_key().to_bytes());
        assert!(substituted_key.validate_new().is_err());
    }

    #[test]
    fn usage_identity_survives_rotation_but_generation_is_exact() {
        let usage = SigningKeyUsageContents {
            consumer: SigningKeyConsumer::Registry(StableId::new("registry:main").unwrap()),
            purpose: SigningPurpose::RegistryPublication,
            signing_key_id: StableId::new("signing-key:release").unwrap(),
            signing_key_generation: Generation::new(1).unwrap(),
            state: SigningUsageState::Active,
        };
        let rotated = usage.rotate(Generation::new(2).unwrap()).unwrap();
        assert_eq!(usage.stable_id().unwrap(), rotated.stable_id().unwrap());
        assert!(usage.rotate(Generation::new(3).unwrap()).is_err());

        let detached = usage.detach().unwrap();
        assert!(detached.validate_new().is_err());
        assert!(detached.rotate(Generation::new(2).unwrap()).is_err());

        let mut substituted_key = rotated.clone();
        substituted_key.signing_key_id = StableId::new("signing-key:other").unwrap();
        assert!(substituted_key.validate_successor(&usage).is_err());

        let mut resurrected = detached.clone();
        resurrected.state = SigningUsageState::Active;
        resurrected.signing_key_generation = Generation::new(2).unwrap();
        assert!(resurrected.validate_successor(&detached).is_err());
    }

    #[test]
    fn key_generation_gates_bind_exact_current_contents_and_head() {
        let signing_key_id = StableId::new("signing-key:release").unwrap();
        let signing_key = external_contents(7);
        let snapshot = Vec::new();
        let snapshot_digest = ContentDigest::of_value(&snapshot).unwrap();
        let mut gate = SigningRotationGate {
            signing_key_id: signing_key_id.clone(),
            current_generation: Generation::new(1).unwrap(),
            signing_key_head: key_head(&signing_key_id, Generation::new(1).unwrap(), &signing_key),
            signing_key,
            usage_snapshot: snapshot,
            usage_snapshot_digest: snapshot_digest.clone(),
            usage_index_head: HeadSeal {
                stable_id: signing_usage_index_id(&signing_key_id).unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: snapshot_digest,
                resource_version: ResourceVersion::new(1).unwrap(),
            },
        };
        gate.validate().unwrap();

        gate.signing_key_head.content_digest = ContentDigest::of_bytes("substituted-key");
        assert!(gate.validate().is_err());

        let mut retired = external_contents(7);
        retired.state = KeyGenerationState::Retired;
        assert!(retired.validate().is_ok());
        assert!(retired.validate_new().is_err());
        assert!(retired.retire().is_err());
    }

    #[test]
    fn retirement_fails_while_any_usage_is_active() {
        let signing_key_id = StableId::new("signing-key:release").unwrap();
        let contents = SigningKeyUsageContents {
            consumer: SigningKeyConsumer::Registry(StableId::new("registry:main").unwrap()),
            purpose: SigningPurpose::RegistryPublication,
            signing_key_id: signing_key_id.clone(),
            signing_key_generation: Generation::new(1).unwrap(),
            state: SigningUsageState::Active,
        };
        let usage_id = contents.stable_id().unwrap();
        let usage_snapshot = vec![SigningUsageSnapshotEntry {
            usage_id: usage_id.clone(),
            head: HeadSeal {
                stable_id: usage_id,
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&contents).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            contents,
        }];
        let usage_snapshot_digest = ContentDigest::of_value(&usage_snapshot).unwrap();
        let signing_key = external_contents(7);
        let gate = SigningRetirementGate {
            signing_key_id: signing_key_id.clone(),
            generation: Generation::new(1).unwrap(),
            signing_key_head: key_head(&signing_key_id, Generation::new(1).unwrap(), &signing_key),
            signing_key,
            usage_index_head: HeadSeal {
                stable_id: signing_usage_index_id(&signing_key_id).unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: usage_snapshot_digest.clone(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            usage_snapshot,
            usage_snapshot_digest,
        };
        assert!(gate.validate().is_err());

        let mut substituted = gate;
        substituted.usage_snapshot[0].head.resource_version = ResourceVersion::new(2).unwrap();
        assert!(substituted.validate().is_err());
    }

    #[test]
    fn lifecycle_gates_reject_usage_head_and_index_substitution() {
        let signing_key_id = StableId::new("signing-key:release").unwrap();
        let contents = SigningKeyUsageContents {
            consumer: SigningKeyConsumer::Registry(StableId::new("registry:main").unwrap()),
            purpose: SigningPurpose::RegistryPublication,
            signing_key_id: signing_key_id.clone(),
            signing_key_generation: Generation::new(1).unwrap(),
            state: SigningUsageState::Detached,
        };
        let usage_id = contents.stable_id().unwrap();
        let usage_snapshot = vec![SigningUsageSnapshotEntry {
            usage_id: usage_id.clone(),
            head: HeadSeal {
                stable_id: usage_id,
                generation: Generation::new(2).unwrap(),
                content_digest: ContentDigest::of_value(&contents).unwrap(),
                resource_version: ResourceVersion::new(2).unwrap(),
            },
            contents,
        }];
        let usage_snapshot_digest = ContentDigest::of_value(&usage_snapshot).unwrap();
        let index_head = HeadSeal {
            stable_id: signing_usage_index_id(&signing_key_id).unwrap(),
            generation: Generation::new(2).unwrap(),
            content_digest: usage_snapshot_digest.clone(),
            resource_version: ResourceVersion::new(2).unwrap(),
        };
        let signing_key = external_contents(7);
        let gate = SigningRetirementGate {
            signing_key_id: signing_key_id.clone(),
            generation: Generation::new(1).unwrap(),
            signing_key_head: key_head(&signing_key_id, Generation::new(1).unwrap(), &signing_key),
            signing_key: signing_key.clone(),
            usage_snapshot: usage_snapshot.clone(),
            usage_snapshot_digest: usage_snapshot_digest.clone(),
            usage_index_head: index_head.clone(),
        };
        gate.validate().unwrap();

        let mut forged_usage_head = gate;
        forged_usage_head.usage_snapshot[0].head.resource_version =
            ResourceVersion::new(3).unwrap();
        assert!(forged_usage_head.validate().is_err());

        let mut forged_index = SigningRotationGate {
            signing_key_id: signing_key_id.clone(),
            current_generation: Generation::new(1).unwrap(),
            signing_key_head: key_head(&signing_key_id, Generation::new(1).unwrap(), &signing_key),
            signing_key,
            usage_snapshot,
            usage_snapshot_digest,
            usage_index_head: index_head,
        };
        forged_index.validate().unwrap();
        forged_index.usage_index_head.content_digest = ContentDigest::of_bytes("other-snapshot");
        assert!(forged_index.validate().is_err());
    }

    #[test]
    fn ed25519_public_keys_are_parsed_and_fingerprinted_as_bytes() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        let bytes = signing_key.verifying_key().to_bytes();
        let public_key = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        let contents = SigningKeyGenerationContents {
            algorithm: SigningAlgorithm::Ed25519,
            public_key,
            public_key_fingerprint: ContentDigest::of_bytes(bytes),
            custody: KeyCustody::External,
            state: KeyGenerationState::Active,
        };
        contents.validate_new().unwrap();

        let mut malformed = contents;
        malformed.public_key.push('=');
        assert!(malformed.validate_new().is_err());
    }

    #[test]
    fn usage_rejects_illegal_consumer_purpose_pairs() {
        let usage = SigningKeyUsageContents {
            consumer: SigningKeyConsumer::BinaryCache(StableId::new("cache:primary").unwrap()),
            purpose: SigningPurpose::RegistryPublication,
            signing_key_id: StableId::new("signing-key:release").unwrap(),
            signing_key_generation: Generation::new(1).unwrap(),
            state: SigningUsageState::Active,
        };
        assert!(usage.validate().is_err());
    }
}
