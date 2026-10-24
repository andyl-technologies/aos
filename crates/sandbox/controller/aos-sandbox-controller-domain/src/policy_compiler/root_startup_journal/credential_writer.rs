//! Exposes the sole native writer and preserves unsupported-platform refusals.

#[cfg(target_os = "linux")]
pub use aos_sandbox_policy::native::RootStartupCredentialWriterV1;

#[cfg(not(target_os = "linux"))]
use super::super::{
    CacheReadbackPinErrorV1, ControllerHoldPinErrorV1, PolicyDeploymentHeadErrorV1,
    SourceHoldPinErrorV1,
};
#[cfg(not(target_os = "linux"))]
use super::{RootPolicyStartupDeploymentV1, RootPolicyStartupJournalV1};

/// Retains an unsupported-platform startup borrow without admitting credentials.
#[cfg(not(target_os = "linux"))]
pub struct RootStartupCredentialWriterV1<'borrow> {
    _journal: &'borrow mut RootPolicyStartupJournalV1,
}

#[cfg(not(target_os = "linux"))]
impl RootStartupCredentialWriterV1<'_> {
    /// Preserves the platform's existing unsupported protected-open refusal.
    ///
    /// # Errors
    /// Always returns the original unsupported protected-open category.
    pub fn admit_signer_pins(
        &mut self,
        deployment_generation: u64,
        deployment_key: &ed25519_dalek::VerifyingKey,
        project_generation: u64,
        project_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), PolicyDeploymentHeadErrorV1> {
        let _ = (
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
        );
        Err(PolicyDeploymentHeadErrorV1::Journal(
            crate::journal::JournalError::UnsupportedProtectedOpen,
        ))
    }

    /// Preserves the platform's existing unsupported protected-open refusal.
    ///
    /// # Errors
    /// Always returns the original unsupported protected-open category.
    pub fn admit_deployment_head(
        &mut self,
        deployment: RootPolicyStartupDeploymentV1<'_>,
    ) -> Result<
        aos_sandbox_policy::signed_inputs::PolicyDeploymentHeadV1,
        PolicyDeploymentHeadErrorV1,
    > {
        let _ = (deployment);
        Err(PolicyDeploymentHeadErrorV1::Journal(
            crate::journal::JournalError::UnsupportedProtectedOpen,
        ))
    }

    /// Preserves the platform's existing unsupported protected-open refusal.
    ///
    /// # Errors
    /// Always returns the original unsupported protected-open category.
    pub fn admit_cache_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), CacheReadbackPinErrorV1> {
        let _ = (credential);
        Err(CacheReadbackPinErrorV1::Journal(
            crate::journal::JournalError::UnsupportedProtectedOpen,
        ))
    }

    /// Preserves the platform's existing unsupported protected-open refusal.
    ///
    /// # Errors
    /// Always returns the original unsupported protected-open category.
    pub fn admit_controller_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), ControllerHoldPinErrorV1> {
        let _ = (credential);
        Err(ControllerHoldPinErrorV1::Journal(
            crate::journal::JournalError::UnsupportedProtectedOpen,
        ))
    }

    /// Preserves the platform's existing unsupported protected-open refusal.
    ///
    /// # Errors
    /// Always returns the original unsupported protected-open category.
    pub fn admit_source_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), SourceHoldPinErrorV1> {
        let _ = (credential);
        Err(SourceHoldPinErrorV1::Journal(
            crate::journal::JournalError::UnsupportedProtectedOpen,
        ))
    }
}
