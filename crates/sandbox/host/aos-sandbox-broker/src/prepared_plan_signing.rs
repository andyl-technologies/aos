//! Holds one actual prepared plan, expanded key and canonical signing message.
//!
//! This mechanical owner shares the existing staged signer algorithm. It reads
//! no credential and supplies no resource, original-currentness or dispatch
//! permission. Protected callers must admit construction and close their actual
//! key/clock/U/Root gates before lending the final key-message pair.

use ed25519_dalek::SigningKey;
use aos_sandbox_model::{PreparedStatementSigningV1, PreparedStatementKeyLoanV1,
    SignatureVerificationError};
use aos_sandbox_model::model::SignatureBytes;
use aos_sandbox_protocol::authorization_artifact::{AuthorizationPreparationError, BrokerPlanPreparation,
    ReturnedSignature, SignedBrokerPlan};

/// Retains the exact preparation, expanded key and staged signing message.
///
/// Possessing this data does not verify a live policy or permit a native effect.
/// The caller must retain the original seed/credential owner and actual returned
/// signature/error through all its independently owed currentness observations.
#[must_use = "retain this owner through signature completion and original posts"]
pub struct PreparedBrokerPlanSigningV1 {
    preparation: Option<BrokerPlanPreparation>,
    key: SigningKey,
    message: PreparedStatementSigningV1,
}

/// Reports unavailable preparation or the actual signature completion error.
#[derive(Debug, thiserror::Error)]
pub enum PreparedBrokerPlanCompletionErrorV1 {
    /// The once-only preparation was already consumed by completion.
    #[error("prepared broker-plan completion was already attempted")]
    Consumed,
    /// The original public policy or returned signature failed completion.
    #[error(transparent)]
    Authorization(#[from] AuthorizationPreparationError),
}

impl PreparedBrokerPlanSigningV1 {
    /// Prepares the existing domain-separated message with the supplied key.
    ///
    /// This performs no signing. Key fingerprint validation remains at the
    /// unchanged key-message loan boundary immediately before the caller's
    /// original final clock check and raw signature operation.
    ///
    /// # Errors
    /// Returns the actual statement registry/descriptor validation error.
    pub fn new(preparation: BrokerPlanPreparation, key: SigningKey)
        -> Result<Self, SignatureVerificationError>
    {
        let message = PreparedStatementSigningV1::new(
            preparation.signing_request().statement().clone(),
        )?;
        Ok(Self { preparation: Some(preparation), key, message })
    }

    /// Borrows the actual immutable preparation before completion consumes it.
    #[must_use]
    pub fn preparation(&self) -> Option<&BrokerPlanPreparation> {
        self.preparation.as_ref()
    }

    /// Borrows the same fingerprint-checked key and prepared message.
    ///
    /// # Errors
    /// Returns the actual mismatch when the supplied key differs from the
    /// immutable prepared statement. No file, clock or role is observed here.
    pub fn key_message_loan(&self) -> Result<PreparedStatementKeyLoanV1<'_>, SignatureVerificationError> {
        self.message.key_message_loan(&self.key)
    }

    /// Completes the actual preparation once using the same verifier engine.
    ///
    /// The signature must first be retained by the actual protected caller.
    /// This consumes the preparation even on error, matching the existing
    /// staged signer; it never retries, signs a replacement or changes time.
    ///
    /// # Errors
    /// Rejects repeated completion or returns the actual public-policy,
    /// canonical signature, binding or validity failure.
    pub fn complete_once(&mut self, signature: &SignatureBytes, now_seconds: i64)
        -> Result<SignedBrokerPlan, PreparedBrokerPlanCompletionErrorV1>
    {
        let preparation = self.preparation.take()
            .ok_or(PreparedBrokerPlanCompletionErrorV1::Consumed)?;
        preparation.complete(ReturnedSignature::Bytes(signature.clone()), now_seconds)
            .map_err(PreparedBrokerPlanCompletionErrorV1::Authorization)
    }

    /// Returns actual compiled constructor overlap beyond the retained slot.
    ///
    /// Plan/policy/canonical byte buffers retain their separate dynamic recipe.
    /// This passive layout supplies no admission, key or signature authority.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<PreparedStatementSigningV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<SigningKey>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment,
        BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget, BrokerVerb,
        DecodeLimits, DesiredGeneration, FeatureRef, IncarnationId, MediaType, NodeId,
        ObjectDigest, PortableMediaType, ProtocolId, ProtocolVersion, RevocationScopeId,
        SandboxId, TrustScopeId, descriptor_for_bytes, sign_statement};
    use aos_sandbox_model::format::{encode_signature, encode_trust_policy};
    use aos_sandbox_model::model::{KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy};
    use aos_sandbox_protocol::authorization_artifact::SigningAuthority;
    use sha2::{Digest as _, Sha256};

    fn prepared() -> (BrokerPlanPreparation, SigningKey) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let reference = |name: &str, usage| KeyReference::new(
            StableKeyId::new(name.to_owned()).unwrap(), 1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()), usage,
        );
        let signer = reference("controller", KeyUsage::BrokerAuthorization);
        let owner = reference("ownership", KeyUsage::OwnershipLease);
        let scope = TrustScopeId::from_bytes([10; 16]);
        let policy = TrustPolicy::new(scope, SignaturePurpose::BrokerAuthorization,
            vec![signer.clone()], Vec::new()).unwrap();
        let policy_bytes = encode_trust_policy(&policy);
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(), &policy_bytes,
        );
        let authority = SigningAuthority::new(policy_bytes, descriptor, scope, signer,
            key.verifying_key().to_bytes(), SignaturePurpose::BrokerAuthorization,
            DecodeLimits::default()).unwrap();
        let assignment = BrokerAssignment::new(SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]), AssignmentEpoch::new(3),
            DesiredGeneration::new(4), ObjectDigest::from_bytes([5; 32])).unwrap();
        let grant = BrokerGrant::new(BrokerVerb::StoragePrepareCatalog,
            BrokerGrantTarget::Assignment, BrokerArgumentCommitment::for_canonical_bytes(b"prepare"),
            300, 0).unwrap();
        let plan = BrokerAuthorizationPlan::new(BrokerAudience::Storage,
            ProtocolId::StorageBroker, ProtocolVersion::new(1, 0), assignment,
            NodeId::from_bytes([6; 16]), owner, vec![grant], ObjectDigest::from_bytes([7; 32]),
            RevocationScopeId::from_bytes([8; 16]), 100, 200,
            vec![FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0).unwrap()],
        ).unwrap();
        (BrokerPlanPreparation::new(plan, authority).unwrap(), key)
    }

    #[test]
    fn same_prepared_signer_keeps_exact_signature_and_once_only_completion() {
        let (preparation, key) = prepared();
        let expected = sign_statement(preparation.signing_request().statement().clone(), &key).unwrap();
        let mut actual = PreparedBrokerPlanSigningV1::new(preparation, key).unwrap();

        let raw = actual.key_message_loan().unwrap().sign();
        let completed = actual.complete_once(&raw, 150).unwrap();

        assert_eq!(raw, expected.signature());
        assert_eq!(completed.canonical_signature(), encode_signature(&expected));
        assert!(actual.preparation().is_none());
        assert!(matches!(actual.complete_once(&raw, 150),
            Err(PreparedBrokerPlanCompletionErrorV1::Consumed)));
    }

    #[test]
    fn wrong_key_and_actual_late_crypto_error_stay_distinct() {
        let (preparation, _) = prepared();
        let wrong = PreparedBrokerPlanSigningV1::new(preparation,
            SigningKey::from_bytes(&[39; 32])).unwrap();
        assert!(wrong.key_message_loan().is_err());

        let (preparation, key) = prepared();
        let mut late = PreparedBrokerPlanSigningV1::new(preparation, key).unwrap();
        let raw = late.key_message_loan().unwrap().sign();
        let error = late.complete_once(&raw, 300).unwrap_err();

        assert!(matches!(error, PreparedBrokerPlanCompletionErrorV1::Authorization(
            AuthorizationPreparationError::Signature(SignatureVerificationError::Expired)
        )));
        assert!(late.preparation().is_none());
    }
}
