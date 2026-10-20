//! Retains the four compiled Publisher bootstrap credential originals.
//!
//! This owner shares the sole native read and named-readback engines. It
//! supplies DATA custody only; purpose, payment, and issuer authority stay upper.

use super::*;

/// Owns the first actual fixed Publisher credential failure.
#[derive(Debug)]
pub struct PublisherPolicyBootstrapCredentialErrorV1(ControllerNixPublicCredentialErrorV1);

impl std::fmt::Display for PublisherPolicyBootstrapCredentialErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Publisher bootstrap credential custody failed")
    }
}

impl std::error::Error for PublisherPolicyBootstrapCredentialErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<ControllerNixPublicCredentialErrorV1> for PublisherPolicyBootstrapCredentialErrorV1 {
    fn from(cause: ControllerNixPublicCredentialErrorV1) -> Self {
        Self(cause)
    }
}

/// Retains only the four fixed Publisher bootstrap credentials and ancestry.
///
/// This is local DATA custody, not PID1, policy, funding or admission authority.
/// Every returned original and partial read remains resident on Err or unwind.
pub struct PublisherPolicyBootstrapCredentialCustodyV1 {
    custody: CredentialRosterCustodyV1<4, PublisherPolicyBootstrapCredentialErrorV1>,
}

pub(super) const PUBLISHER_BOOTSTRAP_NAMES: [&str; 4] = [
    "publisher-policy-source-v1",
    "publisher-policy-v1.cbor",
    "publisher-policy-source-public-key-v1",
    "git-upload-capacity-v1.cbor",
];

impl std::fmt::Debug for PublisherPolicyBootstrapCredentialCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublisherPolicyBootstrapCredentialCustodyV1(<original fixed DATA>)")
    }
}

impl Default for PublisherPolicyBootstrapCredentialCustodyV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl PublisherPolicyBootstrapCredentialCustodyV1 {
    /// Prepares empty fixed slots without opening files or granting authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            custody: CredentialRosterCustodyV1::new(CredentialRosterKindV1::PublisherBootstrap),
        }
    }

    /// Captures the four original fixed inputs exactly once.
    ///
    /// # Errors
    ///
    /// Permanently closes on reentry, unsafe files, bounded read failure or
    /// changed original/named bindings; borrows the resident first typed cause.
    pub fn capture(&mut self) -> Result<(), &PublisherPolicyBootstrapCredentialErrorV1> {
        self.custody.capture()
    }

    /// Rechecks the same originals and fixed names under the same size profile.
    ///
    /// # Errors
    ///
    /// Closes on interruption, reentry or changed/unsafe input without replacing
    /// originals or retiring a partially failed readback batch.
    pub fn recheck(&mut self) -> Result<(), &PublisherPolicyBootstrapCredentialErrorV1> {
        self.custody.recheck()
    }

    /// Borrows complete input DATA without moving bytes or descriptors.
    #[must_use]
    pub fn ready(&self) -> Option<[&[u8]; 4]> {
        Some([
            self.custody.public(0)?.bytes(),
            self.custody.public(1)?.bytes(),
            self.custody.public(2)?.bytes(),
            self.custody.public(3)?.bytes(),
        ])
    }

    /// Borrows the first failure without displacing any retained originals.
    #[must_use]
    pub fn failure(&self) -> Option<&PublisherPolicyBootstrapCredentialErrorV1> {
        self.custody.failure()
    }

    /// Closes DATA observation without asserting physical drain.
    pub fn fence(&mut self) {
        self.custody.fence();
    }
}

pub(super) fn publisher_read_profile(index: usize) -> CredentialReadProfile {
    match index {
        0 => CredentialReadProfile::Ordinary(272),
        1 => CredentialReadProfile::PublisherPolicy,
        2 => CredentialReadProfile::Ordinary(32),
        _ => CredentialReadProfile::Ordinary(645),
    }
}



#[cfg(test)]
mod publisher_bootstrap_tests {
    use super::*;

    #[test]
    fn fixed_profiles_preserve_ordinary_and_nix_ceiling() {
        assert_eq!(MAXIMUM_CREDENTIAL_BYTES, 1024 * 1024);
        assert_eq!(CredentialReadProfile::Ordinary(MAXIMUM_CREDENTIAL_BYTES).maximum(), 1024 * 1024);
        assert_eq!(publisher_read_profile(0).maximum(), 272);
        assert_eq!(publisher_read_profile(1).maximum(), 4 * 1024 * 1024);
        assert_eq!(publisher_read_profile(2).maximum(), 32);
        assert_eq!(publisher_read_profile(3).maximum(), 645);
    }

    #[test]
    fn fresh_and_fenced_fixed_holders_expose_no_ready_bytes() {
        let mut owner = PublisherPolicyBootstrapCredentialCustodyV1::new();
        assert!(owner.ready().is_none());
        assert!(owner.failure().is_none());

        owner.fence();
        assert!(owner.ready().is_none());
        assert!(owner.custody.originals.iter().all(|original|
            original.public.is_none() && original.read.file.is_none() && original.read.bytes.is_none()));
    }
}
