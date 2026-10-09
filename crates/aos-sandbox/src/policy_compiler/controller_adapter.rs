//! Dormant controller conversion for compiled-policy publication.
//!
//! The conversion performs no installation or public advertisement. It only
//! carries the exact durable head and downstream effect as one composite
//! handoff for a future activated controller.

use super::{AppliedPolicyPublicationV1, PolicyCompilerPostcommitCapabilityV1};

/// Carries controller authority released by an exact policy readback.
#[must_use = "policy controller authority must be consumed or deliberately discarded"]
pub struct PolicyCompilerControllerCommitV1 {
    postcommit: Option<PolicyCompilerPostcommitCapabilityV1>,
}

impl PolicyCompilerControllerCommitV1 {
    /// Takes composite authority for exact prerequisite and journal revalidation.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<PolicyCompilerPostcommitCapabilityV1> {
        self.postcommit.take()
    }
}

/// Converts exact policy journal readback into dormant controller capabilities.
#[must_use]
pub fn policy_compiler_controller_commit_v1(
    mut applied: AppliedPolicyPublicationV1,
) -> PolicyCompilerControllerCommitV1 {
    PolicyCompilerControllerCommitV1 {
        postcommit: applied.take_postcommit(),
    }
}
