//! Coordinator-supplied authorization for finalizer signing effects.

use anyhow::{Result, bail};
use aos_release::digest::Sha256Digest;
use aos_release::signing::{
    SignatureAlgorithm, SignerRole, SigningContext, SigningOperation, SigningRequestV1,
};

/// Fully constrained signing intent emitted by image mechanics.
pub struct ImageSigningIntent<'a> {
    /// Assembly-declared provider policy id for this purpose.
    pub assembly_policy_id: &'a str,
    /// Independent authority required by the operation.
    pub role: SignerRole,
    /// Required signing mechanism.
    pub algorithm: SignatureAlgorithm,
    /// Narrow provider effect.
    pub operation: SigningOperation,
    /// Exact operation-specific policy context.
    pub context: SigningContext,
    /// Exact bytes that the provider must authorize.
    pub payload_digest: Sha256Digest,
}

/// Supplies reviewed requests without giving finalizer mechanics key access.
pub trait ImageRequestAuthorizer: Send + Sync {
    /// Returns a complete release-plan-bound request for `intent`.
    ///
    /// # Errors
    ///
    /// Returns an error when no reviewed signer policy authorizes the intent
    /// or a unique anti-replay nonce cannot be allocated.
    fn authorize(&self, intent: &ImageSigningIntent<'_>) -> Result<SigningRequestV1>;
}

/// Verifies that a coordinator-supplied request exactly implements an intent.
///
/// # Errors
///
/// Returns an error for any role, mechanism, operation, context, or payload
/// mismatch. The caller must separately bind release, plan, approval policy,
/// key id, provider revision, and nonce when constructing the request.
pub fn verify_intent(request: &SigningRequestV1, intent: &ImageSigningIntent<'_>) -> Result<()> {
    request.validate()?;
    if request.role != intent.role
        || request.algorithm != intent.algorithm
        || request.operation != intent.operation
        || request.context != intent.context
        || request.payload_digest != intent.payload_digest
        || intent.assembly_policy_id.is_empty()
    {
        bail!("coordinator signing request does not match finalizer intent");
    }
    Ok(())
}
