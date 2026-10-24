//! Owns subject and signing-message buffers of one strict signed-artifact check.

use super::*;

/// Retains one reached fixed artifact verification without selecting trust.
#[doc(hidden)]
pub struct BrokerSessionArtifactVerifyCaptureV1 {
    subject: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
    result: Option<Result<(), BrokerSessionArtifactError>>,
    closed: Option<BrokerSessionArtifactError>,
}

impl Default for BrokerSessionArtifactVerifyCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerSessionArtifactVerifyCaptureV1 {
    /// Prearms empty subject, preimage and outcome slots without allocating.
    #[must_use]
    pub const fn new() -> Self {
        Self { subject: None, message: None, result: None, closed: None }
    }

    /// Bounds both exact subject and complete signing-preimage buffers.
    ///
    /// The maximum is taken over the four actual fixed macro recipes, not a
    /// caller-selected packet limit. Allocator-private overhead is excluded.
    #[must_use]
    pub fn receiving_heap_bytes_v1() -> Option<usize> {
        let subject = CLIENT_HELLO_SUBJECT_BYTES.max(BROKER_HELLO_SUBJECT_BYTES)
            .max(BROKER_REQUEST_SUBJECT_BYTES).max(BROKER_OUTCOME_SUBJECT_BYTES);
        let domain = CLIENT_HELLO_SIGNATURE_DOMAIN.len().max(BROKER_HELLO_SIGNATURE_DOMAIN.len())
            .max(REQUEST_SIGNATURE_DOMAIN.len()).max(OUTCOME_SIGNATURE_DOMAIN.len());
        // Subject buffer plus the complete domain/purpose/method/signer/length
        // signing preimage. Both are exact-capacity fixed-format encoders.
        subject.checked_mul(2)?.checked_add(domain)?.checked_add(2 + 120 + 4)
    }

    /// Counts the two buffers and the actual result and reentry slots.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> Option<usize> {
        Some(4)
    }

    /// Borrows the original strict verification cause before any reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&BrokerSessionArtifactError> {
        self.result.as_ref().and_then(|r| r.as_ref().err()).or(self.closed.as_ref())
    }

    /// Reports the concrete fixed capture layout, excluding its two buffers.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    pub(super) fn reject_before_subject(&mut self, error: BrokerSessionArtifactError)
        -> Result<(), BrokerSessionArtifactError>
    {
        if self.result.is_none() {
            self.result = Some(Err(error));
        } else {
            self.closed.get_or_insert(BrokerSessionArtifactError::InvalidSignature);
        }
        Err(self.failure().cloned().unwrap_or(BrokerSessionArtifactError::InvalidSignature))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture_once(
        &mut self, domain: &[u8], purpose: u8, method: u8,
        signer: &BrokerSessionSignerReferenceV1, signature: &BrokerSessionSignature,
        usage: BrokerSessionKeyUsageV1, public_key: &[u8; 32],
        encode_subject: impl FnOnce() -> Vec<u8>,
    ) -> Result<(), BrokerSessionArtifactError> {
        if self.result.is_some() {
            self.closed.get_or_insert(BrokerSessionArtifactError::InvalidSignature);
            return Err(BrokerSessionArtifactError::InvalidSignature);
        }
        // The only callers are the four fixed artifact macro expansions. This
        // closure encodes their subject DATA; it cannot supply trust or IO.
        self.subject = Some(encode_subject());
        self.result = Some(match self.subject.as_deref() {
            Some(subject) => verify_into(domain, purpose, method, subject, signer, signature,
                usage, public_key, &mut self.message, true),
            None => Err(BrokerSessionArtifactError::InvalidSignature),
        });
        if let Some(Err(error)) = &self.result {
            return Err(error.clone());
        }
        // A complete pure strict check has no later buffer borrower.
        drop(self.message.take());
        drop(self.subject.take());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::Audience;

    #[test]
    fn failed_strict_signature_retains_subject_and_signing_message() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            [1; 16], 1, [2; 32], [3; 16], 1,
            BrokerSessionKeyUsageV1::ClientHello, &key,
        ).unwrap();
        let subject = BrokerClientHelloSubjectV1::new(
            [4; 16], [5; 16], crate::model::BrokerSessionProtocolV1::Storage,
            1, 0, Audience::AUDIENCE_NODE_CONTROLLER, [6; 16], [7; 32], [8; 32], [9; 32],
        ).unwrap();
        let valid = sign_client_hello_v1(subject, signer, &key).unwrap();
        let mut changed = valid.to_canonical_bytes();
        *changed.last_mut().unwrap() ^= 1;
        let changed = SignedBrokerClientHelloV1::from_canonical_bytes(&changed).unwrap();
        let mut capture = BrokerSessionArtifactVerifyCaptureV1::new();

        assert!(changed.verify_with_public_key_retaining_v1(
            &key.verifying_key().to_bytes(), &mut capture,
        ).is_err());
        assert_eq!(capture.subject.as_ref().unwrap().len(), CLIENT_HELLO_SUBJECT_BYTES);
        assert!(capture.message.as_ref().unwrap().len() > CLIENT_HELLO_SUBJECT_BYTES);
        assert_eq!(changed.verify_with_public_key(&key.verifying_key().to_bytes()),
            Err(BrokerSessionArtifactError::InvalidSignature));
        let pointer = capture.message.as_ref().unwrap().as_ptr();
        let original = capture.result.as_ref().unwrap().as_ref().unwrap_err()
            as *const BrokerSessionArtifactError;
        assert!(std::ptr::eq(capture.failure().unwrap(), original));

        assert!(changed.verify_with_public_key_retaining_v1(
            &key.verifying_key().to_bytes(), &mut capture,
        ).is_err());
        assert_eq!(capture.message.as_ref().unwrap().as_ptr(), pointer);
        assert!(std::ptr::eq(capture.failure().unwrap(), original));
    }

    #[test]
    fn request_and_outcome_signature_refusals_keep_the_same_preimage_owner() {
        use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
        let key = SigningKey::from_bytes(&[20; 32]);
        let signer = |usage| BrokerSessionSignerReferenceV1::for_signing_key(
            [1; 16], 1, [2; 32], [3; 16], 1, usage, &key,
        ).unwrap();
        let method = BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG;
        let request = sign_request_v1(method,
            BrokerRequestSubjectV1::new([4; 32], [5; 16], 1, [6; 16], [7; 32]).unwrap(),
            signer(BrokerSessionKeyUsageV1::ClientRecord), &key,
        ).unwrap();
        let outcome = sign_outcome_v1(method,
            BrokerOutcomeSubjectV1::new([4; 32], [5; 16], 1, [6; 16], [8; 32], [7; 32]).unwrap(),
            signer(BrokerSessionKeyUsageV1::BrokerOutcome), &key,
        ).unwrap();

        macro_rules! check {
            ($signed:expr, $type:ty, $subject_bytes:expr) => {{
                let mut bytes = $signed.to_canonical_bytes();
                *bytes.last_mut().unwrap() ^= 1;
                let changed = <$type>::from_canonical_bytes(&bytes).unwrap();
                let mut capture = BrokerSessionArtifactVerifyCaptureV1::new();
                assert!(changed.verify_with_public_key_retaining_v1(
                    &key.verifying_key().to_bytes(), &mut capture,
                ).is_err());
                assert_eq!(capture.subject.as_ref().unwrap().len(), $subject_bytes);
                assert!(capture.message.as_ref().unwrap().len() > $subject_bytes);
                assert_eq!(capture.failure(), Some(&BrokerSessionArtifactError::InvalidSignature));
                assert_eq!(changed.verify_with_public_key(&key.verifying_key().to_bytes()),
                    Err(BrokerSessionArtifactError::InvalidSignature));
            }};
        }
        check!(request, SignedBrokerRequestV1, BROKER_REQUEST_SUBJECT_BYTES);
        check!(outcome, SignedBrokerOutcomeV1, BROKER_OUTCOME_SUBJECT_BYTES);
    }

}
