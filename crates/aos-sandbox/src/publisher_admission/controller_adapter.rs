//! Dormant controller conversion for publisher-admission commits.
//!
//! The returned acknowledgement is usable only by the exact staged reducer
//! branch. Effect, current-publication, and retained terminal-capacity authority
//! travel in one composite postcommit capability.

use super::{
    AppliedPublisherAdmissionTransactionV1, ProtectedStoreCommitToken,
    PublisherAdmissionPostcommitCapabilityV1,
};

/// Carries exact publisher reducer and postcommit controller authority.
#[must_use = "publisher controller authority must be consumed or deliberately discarded"]
pub(crate) struct PublisherAdmissionControllerCommitV1 {
    acknowledgement: Option<ProtectedStoreCommitToken>,
    postcommit: Option<PublisherAdmissionPostcommitCapabilityV1>,
}

impl PublisherAdmissionControllerCommitV1 {
    /// Takes the exact reducer checkpoint and hash-chain acknowledgement.
    #[must_use]
    pub(crate) fn take_acknowledgement(&mut self) -> Option<ProtectedStoreCommitToken> {
        self.acknowledgement.take()
    }

    /// Takes composite authority for one exact current revalidation.
    #[must_use]
    pub(crate) fn take_postcommit(&mut self) -> Option<PublisherAdmissionPostcommitCapabilityV1> {
        self.postcommit.take()
    }
}

/// Converts exact publisher journal readback into controller capabilities.
#[must_use]
pub(crate) fn publisher_admission_controller_commit_v1(
    mut applied: AppliedPublisherAdmissionTransactionV1,
) -> PublisherAdmissionControllerCommitV1 {
    PublisherAdmissionControllerCommitV1 {
        acknowledgement: applied.take_acknowledgement(),
        postcommit: applied.take_postcommit(),
    }
}
