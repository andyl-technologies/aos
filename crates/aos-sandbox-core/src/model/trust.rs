//! Portable trust-policy and detached signature-envelope values.
//!
//! The statement binds an immutable signer generation and raw-public-key
//! fingerprint to an exact subject descriptor, trust scope, purpose, time
//! interval, and trust-policy descriptor. Cryptographic verification over the
//! canonical statement bytes is layered on this semantic model.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ObjectDescriptor, ObjectDigest, TrustScopeId};

const MAX_STABLE_KEY_ID_BYTES: usize = 255;

/// Reports an invalid trust-policy or signature value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidTrustModel {
    /// A stable key identifier is empty or too large.
    #[error("stable key ID must contain 1..=255 UTF-8 bytes")]
    InvalidStableKeyId,
    /// Allowed keys are unordered or repeat a stable-ID/generation pair.
    #[error("allowed keys must be ordered by stable key ID and generation")]
    KeysNotCanonical,
    /// A key's typed usage does not match the trust/signature purpose.
    #[error("signer key usage must match signature purpose")]
    UsagePurposeMismatch,
    /// A signature expiry is not later than its issue time.
    #[error("signature expiry must be later than issue time")]
    InvalidValidityInterval,
}

/// Stores one bounded stable key identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StableKeyId(String);

impl StableKeyId {
    /// Constructs a bounded stable key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTrustModel::InvalidStableKeyId`] for an empty value or
    /// one longer than 255 UTF-8 bytes.
    pub fn new(value: String) -> Result<Self, InvalidTrustModel> {
        if value.is_empty() || value.len() > MAX_STABLE_KEY_ID_BYTES {
            Err(InvalidTrustModel::InvalidStableKeyId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the stable key identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StableKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Identifies the authority class carried by one signing key generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyUsage {
    /// Signs audience-specific local broker authorization plans.
    BrokerAuthorization,
    /// Signs short-lived assignment ownership leases.
    OwnershipLease,
    /// Signs resolved policy objects.
    Policy,
    /// Signs portable tree/view/environment objects.
    Tree,
    /// Signs snapshots and sandbox specifications.
    Snapshot,
    /// Signs distribution provenance without adding authority.
    Distribution,
}

/// Identifies the purpose asserted by a signature statement or trust policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignaturePurpose {
    /// Authorizes one audience-specific local broker plan.
    BrokerAuthorization,
    /// Authorizes a resolved policy object.
    Policy,
    /// Authenticates tree/view/environment provenance.
    Tree,
    /// Authenticates a snapshot or sandbox specification.
    Snapshot,
    /// Authenticates distribution provenance without adding authority.
    Distribution,
}

impl SignaturePurpose {
    const fn required_usage(self) -> KeyUsage {
        match self {
            Self::BrokerAuthorization => KeyUsage::BrokerAuthorization,
            Self::Policy => KeyUsage::Policy,
            Self::Tree => KeyUsage::Tree,
            Self::Snapshot => KeyUsage::Snapshot,
            Self::Distribution => KeyUsage::Distribution,
        }
    }
}

/// Binds a stable signing-key identity to one immutable key generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyReference {
    stable_key_id: StableKeyId,
    generation: u64,
    public_key_sha256: ObjectDigest,
    usage: KeyUsage,
}

impl KeyReference {
    /// Constructs an immutable key-generation reference.
    #[must_use]
    pub const fn new(
        stable_key_id: StableKeyId,
        generation: u64,
        public_key_sha256: ObjectDigest,
        usage: KeyUsage,
    ) -> Self {
        Self {
            stable_key_id,
            generation,
            public_key_sha256,
            usage,
        }
    }

    /// Returns the stable key identifier.
    #[must_use]
    pub const fn stable_key_id(&self) -> &StableKeyId {
        &self.stable_key_id
    }

    /// Returns the immutable key generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns SHA-256 over the raw 32-byte Ed25519 public key.
    #[must_use]
    pub const fn public_key_sha256(&self) -> ObjectDigest {
        self.public_key_sha256
    }

    /// Returns the typed signing authority carried by the key.
    #[must_use]
    pub const fn usage(&self) -> KeyUsage {
        self.usage
    }
}

/// Stores the exact allowed key generations for one trust scope and purpose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustPolicy {
    trust_scope: TrustScopeId,
    purpose: SignaturePurpose,
    allowed_keys: Vec<KeyReference>,
    required_features: Vec<crate::FeatureRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPolicyWire {
    trust_scope: TrustScopeId,
    purpose: SignaturePurpose,
    allowed_keys: Vec<KeyReference>,
    required_features: Vec<crate::FeatureRef>,
}

impl<'de> Deserialize<'de> for TrustPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TrustPolicyWire::deserialize(deserializer)?;
        Self::new(
            wire.trust_scope,
            wire.purpose,
            wire.allowed_keys,
            wire.required_features,
        )
        .map_err(de::Error::custom)
    }
}

impl TrustPolicy {
    /// Constructs an exact trust-policy generation.
    ///
    /// # Errors
    ///
    /// Returns an error unless keys are ordered by stable ID/generation with
    /// matching usage, and required features form a strictly ordered set.
    pub fn new(
        trust_scope: TrustScopeId,
        purpose: SignaturePurpose,
        allowed_keys: Vec<KeyReference>,
        required_features: Vec<crate::FeatureRef>,
    ) -> Result<Self, InvalidTrustModel> {
        if !allowed_keys.windows(2).all(|pair| {
            (pair[0].stable_key_id(), pair[0].generation())
                < (pair[1].stable_key_id(), pair[1].generation())
        }) || !required_features.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(InvalidTrustModel::KeysNotCanonical);
        }
        if allowed_keys
            .iter()
            .any(|key| key.usage() != purpose.required_usage())
        {
            return Err(InvalidTrustModel::UsagePurposeMismatch);
        }
        Ok(Self {
            trust_scope,
            purpose,
            allowed_keys,
            required_features,
        })
    }

    /// Returns the exact trust and revocation scope.
    #[must_use]
    pub const fn trust_scope(&self) -> TrustScopeId {
        self.trust_scope
    }

    /// Returns the sole signature purpose authorized by the policy.
    #[must_use]
    pub const fn purpose(&self) -> SignaturePurpose {
        self.purpose
    }

    /// Returns allowed immutable key generations in canonical key order.
    #[must_use]
    pub fn allowed_keys(&self) -> &[KeyReference] {
        &self.allowed_keys
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[crate::FeatureRef] {
        &self.required_features
    }
}

/// Stores the exact authority and provenance statement signed by Ed25519.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignatureStatement {
    subject: ObjectDescriptor,
    trust_scope: TrustScopeId,
    signer: KeyReference,
    purpose: SignaturePurpose,
    issued_seconds: i64,
    expires_seconds: Option<i64>,
    verification_policy: ObjectDescriptor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureStatementWire {
    subject: ObjectDescriptor,
    trust_scope: TrustScopeId,
    signer: KeyReference,
    purpose: SignaturePurpose,
    issued_seconds: i64,
    expires_seconds: Option<i64>,
    verification_policy: ObjectDescriptor,
}

impl<'de> Deserialize<'de> for SignatureStatement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SignatureStatementWire::deserialize(deserializer)?;
        Self::new(
            wire.subject,
            wire.trust_scope,
            wire.signer,
            wire.purpose,
            wire.issued_seconds,
            wire.expires_seconds,
            wire.verification_policy,
        )
        .map_err(de::Error::custom)
    }
}

impl SignatureStatement {
    /// Constructs a signature statement with closed usage and time semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if signer usage differs from purpose or an optional
    /// expiry is not later than issue time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: ObjectDescriptor,
        trust_scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        issued_seconds: i64,
        expires_seconds: Option<i64>,
        verification_policy: ObjectDescriptor,
    ) -> Result<Self, InvalidTrustModel> {
        if signer.usage() != purpose.required_usage() {
            return Err(InvalidTrustModel::UsagePurposeMismatch);
        }
        if expires_seconds.is_some_and(|expiry| expiry <= issued_seconds) {
            return Err(InvalidTrustModel::InvalidValidityInterval);
        }
        Ok(Self {
            subject,
            trust_scope,
            signer,
            purpose,
            issued_seconds,
            expires_seconds,
            verification_policy,
        })
    }

    /// Returns the exact signed subject descriptor.
    #[must_use]
    pub const fn subject(&self) -> &ObjectDescriptor {
        &self.subject
    }

    /// Returns the exact trust scope.
    #[must_use]
    pub const fn trust_scope(&self) -> TrustScopeId {
        self.trust_scope
    }

    /// Returns the immutable signer key generation.
    #[must_use]
    pub const fn signer(&self) -> &KeyReference {
        &self.signer
    }

    /// Returns the closed signature purpose.
    #[must_use]
    pub const fn purpose(&self) -> SignaturePurpose {
        self.purpose
    }

    /// Returns the inclusive issue time as a Unix second.
    #[must_use]
    pub const fn issued_seconds(&self) -> i64 {
        self.issued_seconds
    }

    /// Returns the exclusive expiry Unix second, when bounded.
    #[must_use]
    pub const fn expires_seconds(&self) -> Option<i64> {
        self.expires_seconds
    }

    /// Returns the exact trust-policy descriptor used for verification.
    #[must_use]
    pub const fn verification_policy(&self) -> &ObjectDescriptor {
        &self.verification_policy
    }
}

/// Stores an exact 64-byte Ed25519 signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignatureBytes([u8; 64]);

impl SignatureBytes {
    /// Constructs an exact Ed25519 signature byte string.
    #[must_use]
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignatureBytes([REDACTED; 64])")
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = SignatureBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an exact 64-byte Ed25519 signature")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| E::invalid_length(bytes.len(), &self))?;
                Ok(SignatureBytes::new(bytes))
            }

            fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(bytes)
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&bytes)
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

/// Stores a detached signature statement and its exact Ed25519 bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    statement: SignatureStatement,
    signature: SignatureBytes,
}

impl Signature {
    /// Constructs a detached signature envelope.
    #[must_use]
    pub const fn new(statement: SignatureStatement, signature: SignatureBytes) -> Self {
        Self {
            statement,
            signature,
        }
    }

    /// Returns the exact signed statement.
    #[must_use]
    pub const fn statement(&self) -> &SignatureStatement {
        &self.statement
    }

    /// Returns the exact Ed25519 signature bytes.
    #[must_use]
    pub const fn signature(&self) -> SignatureBytes {
        self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FeatureRef, MediaType};

    fn descriptor(kind: &str) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(format!("application/vnd.aos.sandbox.{kind}.v1+cbor"))
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            1,
        )
    }

    fn key(name: &str, generation: u64, usage: KeyUsage) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            generation,
            ObjectDigest::from_bytes([2; 32]),
            usage,
        )
    }

    #[test]
    fn trust_keys_require_stable_id_generation_order() {
        let result = TrustPolicy::new(
            TrustScopeId::from_bytes([3; 16]),
            SignaturePurpose::Tree,
            vec![key("z", 1, KeyUsage::Tree), key("a", 1, KeyUsage::Tree)],
            Vec::new(),
        );

        assert_eq!(result, Err(InvalidTrustModel::KeysNotCanonical));
    }

    #[test]
    fn trust_policy_rejects_mismatched_key_usage() {
        let result = TrustPolicy::new(
            TrustScopeId::from_bytes([3; 16]),
            SignaturePurpose::Snapshot,
            vec![key("snapshot", 1, KeyUsage::Policy)],
            Vec::new(),
        );

        assert_eq!(result, Err(InvalidTrustModel::UsagePurposeMismatch));
    }

    #[test]
    fn signature_statement_rejects_inverted_validity() {
        let result = SignatureStatement::new(
            descriptor("tree"),
            TrustScopeId::from_bytes([3; 16]),
            key("tree", 1, KeyUsage::Tree),
            SignaturePurpose::Tree,
            10,
            Some(10),
            descriptor("trust-policy"),
        );

        assert_eq!(result, Err(InvalidTrustModel::InvalidValidityInterval));
    }

    #[test]
    fn signature_bytes_require_exact_binary_length() {
        let mut encoded = Vec::new();
        ciborium::into_writer(&ciborium::Value::Bytes(vec![7_u8; 63]), &mut encoded)
            .unwrap_or_else(|error| panic!("test encoding failed: {error}"));

        assert!(ciborium::from_reader::<SignatureBytes, _>(encoded.as_slice()).is_err());
    }

    #[test]
    fn required_features_must_be_unique() {
        let feature = FeatureRef::new("aos.test", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));
        let result = TrustPolicy::new(
            TrustScopeId::from_bytes([3; 16]),
            SignaturePurpose::Tree,
            Vec::new(),
            vec![feature.clone(), feature],
        );

        assert_eq!(result, Err(InvalidTrustModel::KeysNotCanonical));
    }
}
