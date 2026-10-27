//! Preserves unsupported protected-opening APIs without a native owner.
//!
//! The owner and held claim contain a private uninhabited field. No constructor,
//! DATA, fixture or callback can produce them. Inert opening destinations retain
//! the same typed unsupported failure; native opening and effects are absent.

use std::{convert::Infallible, marker::PhantomData, path::Path};
use aos_sandbox_model::{ObjectDescriptor, ObjectDigest, ProjectId, SandboxId, model::Policy};
use super::{PolicyCompilerJournalErrorV1, PolicyCompilerJournalProjectionV1,
    PolicyPublicationPrerequisitesV1, ProtectedDomainJournalErrorV1, RecoveryReport,
    PolicyCompilerProtectedOpenReportV1};

const UNSUPPORTED: PolicyCompilerJournalErrorV1 = PolicyCompilerJournalErrorV1::Journal(
    ProtectedDomainJournalErrorV1::UnsupportedProtectedOpen,
);

/// Names an unavailable state owner; its private field has no inhabitants.
pub struct PolicyCompilerStateReadbackOwnerV1 {
    unavailable: Infallible,
}

/// Names an unavailable held claim without manufacturing native custody.
pub struct HeldResolvedRuntimePolicyV1<'policy> {
    unavailable: Infallible,
    lifetime: PhantomData<&'policy ()>,
}

/// Names an unavailable ordinary legacy owner without a successful constructor.
pub struct PolicyCompilerProtectedOwnerV1 {
    unavailable: Infallible,
}

impl PolicyCompilerProtectedOwnerV1 {
    /// Preserves the existing typed refusal on unsupported protected openers.
    ///
    /// # Errors
    /// Always returns the platform's unsupported protected-opening class.
    pub fn open_fixed_protected()
        -> Result<(Self, PolicyCompilerProtectedOpenReportV1), PolicyCompilerJournalErrorV1>
    {
        Err(UNSUPPORTED)
    }

    /// Preserves fixture API availability without adopting an arbitrary path.
    ///
    /// # Errors
    /// Always returns the unsupported protected-opening class.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn open_fixture_at_uid(_directory: &Path, _uid: u32)
        -> Result<(Self, PolicyCompilerProtectedOpenReportV1), PolicyCompilerJournalErrorV1>
    {
        Err(UNSUPPORTED)
    }

    /// Retains the replay signature; no valid receiver can be constructed.
    ///
    /// # Errors
    /// No safe caller can provide this uninhabited receiver.
    pub fn replay(&mut self) -> Result<PolicyCompilerJournalProjectionV1, PolicyCompilerJournalErrorV1> {
        match self.unavailable {}
    }
}

impl PolicyCompilerStateReadbackOwnerV1 {
    /// Preserves the existing-only opener's typed unsupported refusal.
    ///
    /// # Errors
    /// Always returns the unsupported protected-opening class.
    pub fn open_existing_fixed_protected() -> Result<Self, PolicyCompilerJournalErrorV1> {
        Err(UNSUPPORTED)
    }

    /// Preserves the fixed opener's typed unsupported refusal and report type.
    ///
    /// # Errors
    /// Always returns the unsupported protected-opening class.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), PolicyCompilerJournalErrorV1> {
        Err(UNSUPPORTED)
    }

    /// Preserves fixture API availability without adopting a native owner.
    ///
    /// # Errors
    /// Always returns the unsupported protected-opening class.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn open_fixture_at_uid(_directory: &Path, _uid: u32) -> Result<Self, PolicyCompilerJournalErrorV1> {
        Err(UNSUPPORTED)
    }

    /// Retains the guarded callback signature without a constructible receiver.
    ///
    /// # Errors
    /// No safe caller can provide this uninhabited receiver; action is never run.
    pub fn with_current_policy_claim<R>(
        &mut self,
        _project: ProjectId,
        _sandbox: SandboxId,
        _action: impl for<'policy> FnOnce(&HeldResolvedRuntimePolicyV1<'policy>) -> R,
    ) -> Result<R, PolicyCompilerJournalErrorV1> {
        match self.unavailable {}
    }
}

impl HeldResolvedRuntimePolicyV1<'_> {
    /// Returns the canonical decoded Policy, not a disclosure grant.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        match self.unavailable {}
    }

    /// Returns original canonical bytes from the structurally checked Candidate.
    #[must_use]
    pub const fn policy_bytes(&self) -> &[u8] {
        match self.unavailable {}
    }

    /// Borrows exact canonical Candidate evidence for independent verification.
    ///
    /// Complete preimage consistency does not authenticate current Policy/Root authority.
    #[must_use]
    pub const fn candidate_bytes(&self) -> &[u8] {
        match self.unavailable {}
    }

    /// Returns exact output descriptor claims for independent Root verification.
    #[must_use]
    pub const fn policy_descriptor(&self) -> &ObjectDescriptor {
        match self.unavailable {}
    }

    /// Returns all four checked output descriptor claims in canonical order.
    #[must_use]
    pub const fn outputs(&self) -> &[ObjectDescriptor; 4] {
        match self.unavailable {}
    }

    /// Returns the retained diagnostics-body commitment claim.
    #[must_use]
    pub const fn diagnostics(&self) -> ObjectDigest {
        match self.unavailable {}
    }

    /// Returns the project and sandbox named by the retained current records.
    #[must_use]
    pub const fn target(&self) -> (ProjectId, SandboxId) {
        match self.unavailable {}
    }

    /// Returns candidate commitment claims and retained publication generation.
    #[must_use]
    pub const fn candidate(&self) -> (ObjectDigest, u64) {
        match self.unavailable {}
    }

    /// Returns exact Current and Candidate envelope commitments for comparison.
    #[must_use]
    pub const fn envelopes(&self) -> (ObjectDigest, ObjectDigest) {
        match self.unavailable {}
    }

    /// Returns the normalized retained compiler-input commitment claim.
    #[must_use]
    pub const fn normalized_input(&self) -> ObjectDigest {
        match self.unavailable {}
    }

    /// Returns prerequisite claims, not authenticated current owner heads.
    #[must_use]
    pub const fn prerequisites(&self) -> &PolicyPublicationPrerequisitesV1 {
        match self.unavailable {}
    }

    /// Rechecks the same healthy fixed state writer/path/names and sequence.
    ///
    /// # Errors
    ///
    /// Rejects poisoned custody, renamed paths/files or changed shared state.
    pub fn recheck(&self) -> Result<(), PolicyCompilerJournalErrorV1> {
        match self.unavailable {}
    }
}

/// Retains an inert unsupported opening attempt and its first owning refusal.
pub struct CurrentNixPolicyOpeningV1 {
    entered: bool,
    refusal: Option<PolicyCompilerJournalErrorV1>,
}

impl CurrentNixPolicyOpeningV1 {
    /// Constructs vacant unsupported-platform destinations without native IO.
    #[must_use]
    pub const fn empty() -> Self {
        Self { entered: false, refusal: None }
    }

    /// Parks the typed unsupported refusal without constructing a writer.
    ///
    /// # Errors
    /// Retains unsupported opening, or the original entry/destination refusal.
    pub fn open_into(
        &mut self,
        destination: &mut Option<(PolicyCompilerStateReadbackOwnerV1, RecoveryReport)>,
    ) -> Result<(), ()> {
        if self.entered || destination.is_some() {
            if self.refusal.is_none() {
                self.refusal = Some(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            return Err(());
        }
        self.entered = true;
        self.refusal = Some(UNSUPPORTED);
        Err(())
    }

    /// Retains the original comparison signature without a possible owner.
    ///
    /// # Errors
    /// No safe caller can provide the uninhabited original.
    pub fn recheck_transferred_original(
        &self,
        original: &PolicyCompilerStateReadbackOwnerV1,
    ) -> Result<(), PolicyCompilerJournalErrorV1> {
        match original.unavailable {}
    }

    /// Borrows the retained first entry or unsupported-opening refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.refusal.as_ref().map(|cause| cause as _)
    }
}
