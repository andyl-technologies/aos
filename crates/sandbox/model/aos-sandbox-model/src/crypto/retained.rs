//! Owns reached public verification models and crypto errors for lease callers.
//!
//! This private representation never supplies an anchor, key, policy, clock or
//! authority. The existing verifier performs every original check in order.

use super::*;
use crate::format::TrustPolicyDecodeCaptureV1;
use crate::model::TrustPolicy;

#[derive(Default)]
pub(crate) struct SignatureVerificationCaptureV1 {
    pub(super) subject_role: Option<Result<crate::PortableMediaType, RegistryError>>,
    pub(super) policy_role: Option<Result<crate::PortableMediaType, RegistryError>>,
    pub(super) fingerprint: Option<Result<(), SignatureVerificationError>>,
    pub(super) policy_decode: TrustPolicyDecodeCaptureV1,
    pub(super) policy: Option<TrustPolicy>,
    pub(super) computed_policy: Option<ObjectDescriptor>,
    pub(super) verifying_key: Option<Result<VerifyingKey, ed25519_dalek::SignatureError>>,
    pub(super) dalek_signature: Option<ed25519_dalek::Signature>,
    pub(super) statement_bytes: Vec<u8>,
    pub(super) message: Option<Vec<u8>>,
    pub(super) crypto: Option<Result<(), ed25519_dalek::SignatureError>>,
}

impl SignatureVerificationCaptureV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(result: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.subject_role).or_else(|| error(&self.policy_role))
            .or_else(|| error(&self.fingerprint)).or_else(|| self.policy_decode.cause())
            .or_else(|| error(&self.verifying_key)).or_else(|| error(&self.crypto))
    }

    pub(crate) const fn metadata_cells() -> usize { 11 }
}
