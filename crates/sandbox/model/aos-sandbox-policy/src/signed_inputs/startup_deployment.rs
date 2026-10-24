//! Retains one exact verified deployment packet and its decoded source model.
//!
//! This provenance DATA grants no writer, funding loan, currentness or admission.

use super::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    SignedPolicyInputDataErrorV1, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1,
};
use ed25519_dalek::VerifyingKey;

/// Retains a verified packet and the typed sources decoded from its exact inputs.
///
/// Private fields prevent combining a verified head with unrelated sources.
/// This is deployment provenance only; protected admission remains separate.
pub struct RootPolicyStartupDeploymentV1<'input> {
    pub(crate) packet: &'input [u8],
    pub(crate) key: &'input VerifyingKey,
    pub(crate) signer_generation: u64,
    pub(crate) head: PolicyDeploymentHeadV1,
    _sources: PolicyDeploymentSourcesV1,
}

impl<'input> RootPolicyStartupDeploymentV1<'input> {
    /// Quotes this token's constructor, typed verification result and arguments.
    ///
    /// Source-model backing remains in the sole startup decoding supplier.
    #[must_use]
    pub fn receiving_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<Self>()
            .checked_mul(3)?
            .checked_add(size_of::<Result<Self, SignedPolicyInputDataErrorV1>>().checked_mul(3)?)?
            .checked_add(
                size_of::<(
                    &[u8],
                    &PolicyDeploymentInputsV1<'_>,
                    &VerifyingKey,
                    u64,
                    i64,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
    }

    /// Verifies and decodes one exact signed deployment without opening a journal.
    ///
    /// # Errors
    ///
    /// Rejects zero signer generations and preserves signature, validity,
    /// canonical-input, and typed-source errors.
    pub fn verify(
        packet: &'input [u8],
        inputs: &PolicyDeploymentInputsV1<'_>,
        key: &'input VerifyingKey,
        signer_generation: u64,
        now_unix_seconds: i64,
    ) -> Result<Self, SignedPolicyInputDataErrorV1> {
        if signer_generation == 0 {
            return Err(SignedPolicyInputDataErrorV1::InvalidHead);
        }
        let head = verify_policy_deployment_head_v1(packet, inputs, key, now_unix_seconds)?;
        let sources = decode_policy_deployment_sources_v1(inputs, head)?;

        Ok(Self {
            packet,
            key,
            signer_generation,
            head,
            _sources: sources,
        })
    }

    /// Returns the head whose exact sources were verified and decoded.
    #[must_use]
    pub const fn head(&self) -> PolicyDeploymentHeadV1 {
        self.head
    }

    /// Transfers the already-decoded sources while ending packet/key borrows.
    ///
    /// Legacy startup keeps these sources until its original credential scope
    /// ends. This transfer performs no verification, decode, or admission.
    #[must_use]
    pub fn into_sources(self) -> PolicyDeploymentSourcesV1 {
        self._sources
    }
}
