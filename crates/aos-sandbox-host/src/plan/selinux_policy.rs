//! Host's independently sourced enforcing SELinux policy proof.
//!
//! The shared Linux readback compares the deployed immutable policy with
//! selinuxfs. Host retains its own error type and readiness boundary.

use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;

use crate::{HostError, Result};

/// Retains the exact enforcing policy used for Host readiness.
///
/// This is a point observation. Revalidate it near each consuming operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLiveSelinuxPolicyV1 {
    inner: VerifiedLiveSelinuxPolicy,
}

impl VerifiedLiveSelinuxPolicyV1 {
    /// Compares the active kernel policy with the immutable AOS derivation.
    ///
    /// # Errors
    ///
    /// Rejects a foreign package, permissive mode, non-selinuxfs readback,
    /// changed or oversized package, unequal bytes, or a read failure.
    pub fn verify(deployed_policy_path: &str) -> Result<Self> {
        let inner = VerifiedLiveSelinuxPolicy::verify(deployed_policy_path)
            .map_err(|error| HostError::State(error.to_string()))?;
        Ok(Self { inner })
    }

    /// Repeats the comparison and requires the same live policy.
    ///
    /// # Errors
    ///
    /// Rejects a changed package, policy, or enforcement state.
    pub fn revalidate(self, deployed_policy_path: &str) -> Result<()> {
        self.inner
            .revalidate(deployed_policy_path)
            .map_err(|error| HostError::State(error.to_string()))
    }

    /// Returns the digest of the exact active policy bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.inner.digest()
    }
}
