//! Complete compiler derivation joined to a retained Policy-state observation.
//!
//! This module owns one nonauthorizing comparison needed by a future genuine
//! Root-last resource-read owner. It uses the real compiler once and the shared
//! Candidate codec; it does not open Root early or decode cold input bytes into
//! authenticated models. The caller must rebuild typed input from genuine held
//! owners and separately authenticate publisher origin and current history.
//!
//! No live read guard is produced here. Source ancestry still needs its genuine
//! Controller receipt and independent rollback floor; Root must retain current
//! signing pins, history and revocation; and the connected Mount/worker owner
//! must supply its actual live guard. Those missing producers remain closed.
//! Historical Attach/caller capability expiry is not an accepted resource's
//! lifetime. Both current content-read grants and a fresh single-use owner
//! barrier are required for every later disclosure/backing handoff.

use crate::publisher_policy::PublisherPolicyError;
use aos_sandbox_core::model::{AssignmentManifestV1, CacheDomain};
use aos_sandbox_core::{Operation, OperationSet, ResourceKind, Selector};

use super::protected_journal::compare_recompiled_candidate_derivation_v1;
use super::{
    CompiledPolicyCandidateV1, HeldResolvedRuntimePolicyV1, PolicyCompilationError,
    PolicyCompilerInputV1, PolicyCompilerJournalErrorV1, PolicyCompilerV1,
    PolicyPublicationPrerequisitesV1, RetainedPublisherCompilerOriginV3,
};

#[cfg(test)]
mod tests;

/// Retains a complete derivation comparison without conferring read authority.
///
/// The state borrow keeps the real Policy writer alive. The compiled candidate
/// remains inert: equal bytes cannot establish current Source floors, Root
/// history, accepted assignment/lease custody or the connected worker channel.
pub(crate) struct ComparedResourceReadPolicyV1<'claim, 'policy> {
    state: &'claim HeldResolvedRuntimePolicyV1<'policy>,
    input: &'claim PolicyCompilerInputV1,
    candidate: CompiledPolicyCandidateV1,
}

impl ComparedResourceReadPolicyV1<'_, '_> {
    /// Borrows the once-compiled candidate for exact original-input comparison.
    ///
    /// Publisher origin comparison must retain the original target. A different
    /// applied target legitimately requires its own complete typed derivation.
    pub(crate) const fn candidate(&self) -> &CompiledPolicyCandidateV1 {
        &self.candidate
    }

    /// Compares same-target publisher provenance with the once-compiled input.
    ///
    /// The caller independently retains the genuine publisher/input owners.
    /// This comparison adds no authorization to cold origin data or the state
    /// claim. The borrowed input is exactly the expected typed input freshly
    /// compiled by this comparison, not a replacement supplied afterward.
    /// A different publisher-original target needs its own independent typed
    /// input reconstruction and compilation; it cannot reuse this candidate.
    ///
    /// # Errors
    ///
    /// Rejects changed state custody, original target/project, any original
    /// input byte, normalized commitment, five plans, or four output fields.
    pub(crate) fn compare_same_target_publisher_origin(
        &self,
        origin: &RetainedPublisherCompilerOriginV3,
    ) -> Result<(), ResourceReadPolicyComparisonErrorV1> {
        self.recheck()?;
        if self.state.target() != (origin.project(), origin.original_target()) {
            return Err(ResourceReadPolicyComparisonErrorV1::OriginalTargetMismatch);
        }
        origin.compare_compiled_derivation(self.input, self.candidate())?;
        self.recheck()?;
        Ok(())
    }

    /// Returns the exact compiled domain claim, including all four RFC domains.
    pub(crate) const fn cache_domain(&self) -> CacheDomain {
        self.candidate.portable().policy().cache_domain()
    }

    /// Checks both independent grant selectors without granting disclosure.
    ///
    /// The eventual owner derives these selectors from the original visible
    /// file/range and exact Cache domain, not from caller-proposed identities.
    /// Projection membership, lease, revocation and both live owner guards are
    /// independent requirements; a Publisher-self open cannot replace either.
    pub(crate) fn content_read_grants_cover(&self, tree: &Selector, cache: &Selector) -> bool {
        let read = OperationSet::one(Operation::ContentRead);
        self.candidate
            .authority()
            .admits(ResourceKind::Tree, read, tree)
            && self
                .candidate
                .authority()
                .admits(ResourceKind::CacheRead, read, cache)
    }

    /// Rechecks the original named Policy writer and snapshot.
    ///
    /// # Errors
    ///
    /// Rejects changed/unsafe names, unhealthy custody or a changed state cut.
    pub(crate) fn recheck(&self) -> Result<(), PolicyCompilerJournalErrorV1> {
        self.state.recheck()
    }
}

/// Compiles complete typed input once and joins all retained Policy claims.
///
/// The assignment and expected tuple are comparison inputs, not authenticated
/// owner tokens. A future genuine Root-last caller must keep their actual
/// Controller/Source/Cache/Mount owners held and independently authenticate
/// current history and original publisher derivation. This function returns
/// neither an authority factory nor a serializable proof.
///
/// # Errors
///
/// Rejects unsafe Policy custody, failed compilation, legacy/substituted
/// Candidate evidence, mismatched complete publication context or an assignment
/// whose target or effective Policy descriptor differs from the held Current.
pub(crate) fn compare_held_resource_read_policy_v1<'claim, 'policy>(
    state: &'claim HeldResolvedRuntimePolicyV1<'policy>,
    input: &'claim PolicyCompilerInputV1,
    assignment: &AssignmentManifestV1,
    generation: u64,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) -> Result<ComparedResourceReadPolicyV1<'claim, 'policy>, ResourceReadPolicyComparisonErrorV1> {
    state.recheck()?;
    if state.target() != (assignment.project(), assignment.sandbox())
        || assignment.policy() != state.policy_descriptor()
    {
        return Err(ResourceReadPolicyComparisonErrorV1::AssignmentMismatch);
    }

    let candidate = PolicyCompilerV1::compile_retained(input)?;
    compare_recompiled_candidate_derivation_v1(
        state.candidate_bytes(),
        input,
        &candidate,
        generation,
        prerequisites,
    )?;
    state.recheck()?;
    Ok(ComparedResourceReadPolicyV1 {
        state,
        input,
        candidate,
    })
}

/// Reports comparison failures without asserting authorization or retirement.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResourceReadPolicyComparisonErrorV1 {
    /// The actual compiler rejected complete typed input.
    #[error(transparent)]
    Compilation(#[from] PolicyCompilationError),
    /// Held canonical claims or protected writer custody differ.
    #[error(transparent)]
    State(#[from] PolicyCompilerJournalErrorV1),
    /// The supplied assignment differs from the held target/effective Policy.
    #[error("resource-read comparison differs from accepted assignment policy")]
    AssignmentMismatch,
    /// The retained publisher origin belongs to a different original target.
    #[error("publisher origin requires an independent original-target derivation")]
    OriginalTargetMismatch,
    /// Complete original input/output provenance differs from fresh compilation.
    #[error(transparent)]
    PublisherOrigin(#[from] PublisherPolicyError),
}
