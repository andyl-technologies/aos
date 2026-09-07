//! Domain-separated Ed25519 signing and trust-envelope verification.
//!
//! Verification binds canonical statement bytes to an exact trust-policy
//! object, immutable signer generation, raw-public-key fingerprint, purpose,
//! scope, and validity interval. Signature validity alone never grants
//! authority.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::format::{
    CanonicalCborError, DecodeLimits, decode_trust_policy, descriptor_for_bytes,
    encode_signature_statement,
};
use crate::model::{Signature, SignatureBytes, SignatureStatement};
use crate::registry::{
    DescriptorRole, RegistryError, validate_descriptor_role, validate_signature_subject,
};
use crate::{ObjectDescriptor, ObjectDigest};

const SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-signature-v1\0";

/// Reports a signing or trust-envelope verification failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignatureVerificationError {
    /// A descriptor, subject-purpose, or feature registry check failed.
    #[error("signature registry validation failed: {0}")]
    Registry(#[from] RegistryError),
    /// Canonical trust-policy decoding failed.
    #[error("trust policy is not a valid canonical object: {0}")]
    TrustPolicy(#[from] CanonicalCborError),
    /// The supplied raw public key is not a valid Ed25519 point.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// The raw public key does not match the statement fingerprint.
    #[error("Ed25519 public key fingerprint does not match the signer reference")]
    PublicKeyFingerprintMismatch,
    /// The canonical trust-policy bytes do not match the committed descriptor.
    #[error("canonical trust-policy bytes do not match the statement descriptor")]
    TrustPolicyDescriptorMismatch,
    /// The trust policy authorizes another trust scope.
    #[error("signature statement and trust policy have different trust scopes")]
    TrustScopeMismatch,
    /// The trust policy authorizes another signature purpose.
    #[error("signature statement and trust policy have different purposes")]
    PurposeMismatch,
    /// The exact stable ID, generation, fingerprint, and usage is not allowed.
    #[error("signer key generation is not allowed by the referenced trust policy")]
    SignerNotAllowed,
    /// Verification time precedes the inclusive issue time.
    #[error("signature is not yet valid")]
    NotYetValid,
    /// Verification time is at or after the exclusive expiry time.
    #[error("signature has expired")]
    Expired,
    /// Ed25519 verification of the domain-separated canonical statement failed.
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
}

/// Carries the authority-bearing facts proven by successful verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignature {
    subject: ObjectDescriptor,
    verification_policy: ObjectDescriptor,
}

impl VerifiedSignature {
    /// Returns the exact authenticated subject descriptor.
    #[must_use]
    pub const fn subject(&self) -> &ObjectDescriptor {
        &self.subject
    }

    /// Returns the exact trust-policy generation used for verification.
    #[must_use]
    pub const fn verification_policy(&self) -> &ObjectDescriptor {
        &self.verification_policy
    }
}

/// Signs one validated statement with domain-separated canonical bytes.
///
/// This operation verifies that the signing key matches the statement's raw
/// public-key fingerprint. It does not claim that the signer is currently
/// authorized by the referenced policy; consumers must call
/// [`verify_signature`] against current policy state.
///
/// # Errors
///
/// Returns [`SignatureVerificationError`] for an invalid subject-purpose or
/// verification-policy role, or when the key fingerprint does not match.
pub fn sign_statement(
    statement: SignatureStatement,
    signing_key: &SigningKey,
) -> Result<Signature, SignatureVerificationError> {
    validate_statement_registry(&statement)?;
    let public_key = signing_key.verifying_key().to_bytes();
    validate_public_key_fingerprint(&statement, &public_key)?;

    let message = signature_signing_message(&statement);
    let signature = signing_key.sign(&message);
    Ok(Signature::new(
        statement,
        SignatureBytes::new(signature.to_bytes()),
    ))
}

/// Verifies a detached signature against exact canonical trust-policy bytes.
///
/// The supplied policy bytes are decoded under the portable CBOR limits and
/// hashed under the descriptor framing before any authority is accepted. The
/// policy's scope, purpose, and exact allowed key reference must match the
/// statement. `now_seconds` uses inclusive issue and exclusive expiry bounds.
///
/// # Errors
///
/// Returns [`SignatureVerificationError`] for malformed policy bytes,
/// descriptor or registry mismatch, invalid time, unauthorized key generation,
/// public-key mismatch, or failed Ed25519 verification.
pub fn verify_signature(
    signature: &Signature,
    canonical_trust_policy: &[u8],
    public_key: &[u8; 32],
    now_seconds: i64,
    limits: DecodeLimits,
) -> Result<VerifiedSignature, SignatureVerificationError> {
    let statement = signature.statement();
    validate_statement_registry(statement)?;
    validate_public_key_fingerprint(statement, public_key)?;

    let policy = decode_trust_policy(canonical_trust_policy, limits)?;
    let computed_policy = descriptor_for_bytes(
        statement.verification_policy().media_type().clone(),
        canonical_trust_policy,
    );
    if &computed_policy != statement.verification_policy() {
        return Err(SignatureVerificationError::TrustPolicyDescriptorMismatch);
    }
    if policy.trust_scope() != statement.trust_scope() {
        return Err(SignatureVerificationError::TrustScopeMismatch);
    }
    if policy.purpose() != statement.purpose() {
        return Err(SignatureVerificationError::PurposeMismatch);
    }
    if !policy.allowed_keys().contains(statement.signer()) {
        return Err(SignatureVerificationError::SignerNotAllowed);
    }
    if now_seconds < statement.issued_seconds() {
        return Err(SignatureVerificationError::NotYetValid);
    }
    if statement
        .expires_seconds()
        .is_some_and(|expiry| now_seconds >= expiry)
    {
        return Err(SignatureVerificationError::Expired);
    }

    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidPublicKey)?;
    let dalek_signature = ed25519_dalek::Signature::from_bytes(signature.signature().as_bytes());
    verifying_key
        .verify_strict(&signature_signing_message(statement), &dalek_signature)
        .map_err(|_| SignatureVerificationError::InvalidSignature)?;

    Ok(VerifiedSignature {
        subject: statement.subject().clone(),
        verification_policy: statement.verification_policy().clone(),
    })
}

fn validate_statement_registry(
    statement: &SignatureStatement,
) -> Result<(), SignatureVerificationError> {
    validate_signature_subject(statement.purpose(), statement.subject())?;
    validate_descriptor_role(
        DescriptorRole::SignatureVerificationPolicy,
        statement.verification_policy(),
    )?;
    Ok(())
}

fn validate_public_key_fingerprint(
    statement: &SignatureStatement,
    public_key: &[u8; 32],
) -> Result<(), SignatureVerificationError> {
    let digest = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    if digest == statement.signer().public_key_sha256() {
        Ok(())
    } else {
        Err(SignatureVerificationError::PublicKeyFingerprintMismatch)
    }
}

/// Encodes the exact domain-separated message signed for one statement.
///
/// Protected signing services use this function to consume a prepared public
/// [`SignatureStatement`] without importing a private key into its producer.
/// The returned bytes, rather than the canonical statement alone, are the
/// Ed25519 message used by [`sign_statement`] and [`verify_signature`].
#[must_use]
pub fn signature_signing_message(statement: &SignatureStatement) -> Vec<u8> {
    let statement_bytes = encode_signature_statement(statement);
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + statement_bytes.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&statement_bytes);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::encode_trust_policy;
    use crate::model::{KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy};
    use crate::{MediaType, TrustScopeId};

    fn descriptor(media_type: &str, byte: u8, size: u64) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(media_type)
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            size,
        )
    }

    fn key_reference(signing_key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new("test-key".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into()),
            KeyUsage::Policy,
        )
    }

    fn statement(
        signer: KeyReference,
        verification_policy: ObjectDescriptor,
    ) -> SignatureStatement {
        SignatureStatement::new(
            descriptor("application/vnd.aos.sandbox.policy.v1+cbor", 3, 1),
            TrustScopeId::from_bytes([4; 16]),
            signer,
            SignaturePurpose::Policy,
            10,
            Some(20),
            verification_policy,
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"))
    }

    #[test]
    fn verification_binds_exact_policy_key_scope_purpose_and_time() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signer = key_reference(&signing_key);
        let policy = TrustPolicy::new(
            TrustScopeId::from_bytes([4; 16]),
            SignaturePurpose::Policy,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.trust-policy.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &policy_bytes,
        );
        let signature = sign_statement(statement(signer, policy_descriptor), &signing_key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"));

        let verified = verify_signature(
            &signature,
            &policy_bytes,
            &signing_key.verifying_key().to_bytes(),
            10,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test verification failed: {error}"));
        assert_eq!(verified.subject(), signature.statement().subject());
        assert_eq!(
            verify_signature(
                &signature,
                &policy_bytes,
                &signing_key.verifying_key().to_bytes(),
                20,
                DecodeLimits::default(),
            ),
            Err(SignatureVerificationError::Expired)
        );
    }

    #[test]
    fn signing_matches_the_rfc_golden_vector() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap_or_else(|error| panic!("test seed hex failed: {error}"))
                .try_into()
                .unwrap_or_else(|_| panic!("test seed length is wrong"));
        let signing_key = SigningKey::from_bytes(&seed);
        let signer = KeyReference::new(
            StableKeyId::new("test-key".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes(
                hex::decode("21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9")
                    .unwrap_or_else(|error| panic!("test digest hex failed: {error}"))
                    .try_into()
                    .unwrap_or_else(|_| panic!("test digest length is wrong")),
            ),
            KeyUsage::Policy,
        );
        let statement = SignatureStatement::new(
            descriptor("application/vnd.aos.sandbox.policy.v1+cbor", 0, 0),
            TrustScopeId::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            signer,
            SignaturePurpose::Policy,
            0,
            None,
            descriptor("application/vnd.aos.sandbox.trust-policy.v1+cbor", 0x11, 0),
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"));
        let signature = sign_statement(statement, &signing_key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"));

        assert_eq!(
            hex::encode(Sha256::digest(signature_signing_message(
                signature.statement(),
            ))),
            "5e5ec9e08a6b30742772fad729cc3bdbdaa0cd4a90c83f5e8019f04f337450a3"
        );
        assert_eq!(
            hex::encode(signature.signature().as_bytes()),
            "178954bd499ff335316e416d4b0f35801e04e06ee5978e7305b78b5151f6dac09b8d8520301f64cff1af6d9deecdd39439ceb0b3a48c1358f340eef7ef74e807"
        );
    }
}
