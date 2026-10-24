//! Routes fresh execution and exact resume through source-owned proof contracts.
//!
//! The router owns only dispatch and post-publication reconciliation. Each runner
//! must independently authenticate its source, native state and capabilities.
//! Contract fingerprints fence incompatible adapters; they grant no preparation,
//! execution, restoration, repeatability or Ready authority. This module defines
//! no serialized state format and does not reinterpret legacy QEMU lineages.

use crucible_campaign::{CampaignHash, StopCondition};

use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, CrucibleResolvedAttemptStart,
};

/// Binds an adapter pair to one complete source-selected replay compatibility basis.
///
/// The fingerprint is routing metadata. Runners must still authenticate the
/// complete original source and each actual native owner before performing work.
/// A coupled implementation may bind its full owner roster into this fingerprint;
/// matching labels alone never authorize a mixed world or cross-backend restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptReplayContract(CampaignHash);

impl AttemptReplayContract {
    /// Retains an independently derived complete replay-contract fingerprint.
    #[must_use]
    pub const fn new(compatibility: CampaignHash) -> Self {
        Self(compatibility)
    }

    /// Returns the exact retained routing fingerprint.
    #[must_use]
    pub const fn compatibility(self) -> CampaignHash {
        self.0
    }
}

/// Independently reconstructs original boundaries for an exact-resume adapter.
pub trait AttemptOriginVerifier: CrucibleExecutionRunner {
    /// Opaque source boundary understood by the paired adapter.
    type SelectedBoundary;
    /// Owning source proof passed once to selected resume.
    type SelectedProof;
    /// Owning inherited-prefix proof passed once to ordinary resume.
    type StartProof;

    /// Returns the current source-selected compatibility contract.
    ///
    /// `None` refuses construction through the common public router. It is used
    /// only by the private unchanged legacy QEMU compatibility adapter.
    fn replay_contract(&self) -> Option<AttemptReplayContract>;

    /// Reconstructs the selected boundary independently of its physical source.
    ///
    /// # Errors
    /// Refuses a changed configuration, scheduler coordinate or original prefix.
    fn verify_selected_resume(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &Self::SelectedBoundary,
    ) -> Result<Self::SelectedProof, AttemptWorkerFailure<Self::Error>>;

    /// Reconstructs the immutable inherited start prefix before ordinary resume.
    ///
    /// # Errors
    /// Refuses an unsupported start or a changed complete original prefix.
    fn verify_start_prefix(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Self::StartProof, AttemptWorkerFailure<Self::Error>>;
}

/// Authenticates native restoration against independently reconstructed proofs.
pub trait AttemptOriginResumeRunner: CrucibleExecutionRunner {
    /// Opaque original source boundary authenticated by this adapter.
    type SelectedBoundary;
    /// Owning selected-boundary proof accepted by this adapter.
    type SelectedProof;
    /// Owning inherited-prefix proof accepted by this adapter.
    type StartProof;

    /// Returns the current source-selected compatibility contract.
    fn replay_contract(&self) -> Option<AttemptReplayContract>;

    /// Authenticates the original selected source before physical preparation.
    ///
    /// `None` permits the existing preferred-source cold path only when the
    /// original source is absent; later own-resume absence must remain an error.
    ///
    /// # Errors
    /// Refuses malformed, unavailable or incompatible original source state.
    fn authenticate_resume_source(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Option<Self::SelectedBoundary>, AttemptWorkerFailure<Self::Error>>;

    /// Resumes only after original native custody agrees with the owning proof.
    ///
    /// # Errors
    /// Refuses unavailable native custody or any original source/proof mismatch.
    fn resume_verified_source(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: Self::SelectedProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>>;

    /// Resumes an ordinary source after authenticating its inherited event prefix.
    ///
    /// # Errors
    /// Refuses unavailable custody or a native prefix differing from the proof.
    fn resume_verified_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: Self::StartProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>>;
}

/// Owns disjoint fresh and resume paths through final semantic reconciliation.
pub struct AttemptExecutionRouter<F, R> {
    fresh: F,
    resume: R,
    pending: Option<PendingRoute>,
    replay_contract: Option<AttemptReplayContract>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingRoute {
    Fresh,
    Resume,
}

/// Reports incompatible or undeclared source contracts before adapter execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttemptExecutionRouterConstructionError {
    /// One adapter has no declared source compatibility contract.
    #[error("execution router requires both original replay contracts")]
    MissingReplayContract,
    /// The original source contracts are different.
    #[error("execution router adapters have incompatible replay contracts")]
    IncompatibleReplayContract,
}

/// Retains both original adapters when compatibility refuses router construction.
///
/// Refusal performs no execution and leaves the complete adapters owned by this
/// failure. Callers can recover them for their original containment or retry
/// policy without reconstructing a native owner from metadata.
pub struct AttemptExecutionRouterConstructionFailure<F, R> {
    reason: AttemptExecutionRouterConstructionError,
    fresh: F,
    resume: R,
}

impl<F, R> AttemptExecutionRouterConstructionFailure<F, R> {
    /// Returns the exact compatibility refusal.
    #[must_use]
    pub const fn reason(&self) -> AttemptExecutionRouterConstructionError {
        self.reason
    }

    /// Borrows the retained original fresh adapter.
    #[must_use]
    pub const fn fresh(&self) -> &F {
        &self.fresh
    }

    /// Borrows the retained original resume adapter.
    #[must_use]
    pub const fn resume(&self) -> &R {
        &self.resume
    }

    /// Returns the refusal and both original owned adapters without replacement.
    #[must_use]
    pub fn into_parts(self) -> (AttemptExecutionRouterConstructionError, F, R) {
        (self.reason, self.fresh, self.resume)
    }
}

impl<F, R> std::fmt::Debug for AttemptExecutionRouterConstructionFailure<F, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttemptExecutionRouterConstructionFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl<F, R> std::fmt::Display for AttemptExecutionRouterConstructionFailure<F, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, formatter)
    }
}

impl<F, R> std::error::Error for AttemptExecutionRouterConstructionFailure<F, R> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

impl<F, R> AttemptExecutionRouter<F, R>
where
    F: AttemptOriginVerifier,
    R: AttemptOriginResumeRunner<
            SelectedBoundary = F::SelectedBoundary,
            SelectedProof = F::SelectedProof,
            StartProof = F::StartProof,
        >,
{
    /// Retains adapters with the same explicit complete replay compatibility basis.
    ///
    /// Construction reads both source-owned compatibility contracts before any
    /// execution or native operation. Accepted
    /// metadata does not replace source qualification or actual native ownership.
    ///
    /// # Errors
    /// Refuses missing or incompatible adapter contracts before execution, retaining
    /// both original adapters in the returned owning failure.
    pub fn new(
        fresh: F,
        resume: R,
    ) -> Result<Self, AttemptExecutionRouterConstructionFailure<F, R>> {
        let (Some(contract), Some(resume_contract)) =
            (fresh.replay_contract(), resume.replay_contract())
        else {
            return Err(AttemptExecutionRouterConstructionFailure {
                reason: AttemptExecutionRouterConstructionError::MissingReplayContract,
                fresh,
                resume,
            });
        };
        if contract != resume_contract {
            return Err(AttemptExecutionRouterConstructionFailure {
                reason: AttemptExecutionRouterConstructionError::IncompatibleReplayContract,
                fresh,
                resume,
            });
        }

        Ok(Self {
            fresh,
            resume,
            pending: None,
            replay_contract: Some(contract),
        })
    }
}

impl<F, R> AttemptExecutionRouter<F, R> {
    // This private path preserves only the existing legacy QEMU adapter contract.
    pub(crate) const fn legacy_qemu(fresh: F, resume: R) -> Self {
        Self {
            fresh,
            resume,
            pending: None,
            replay_contract: None,
        }
    }

    /// Returns the original fresh runner.
    #[must_use]
    pub const fn fresh(&self) -> &F {
        &self.fresh
    }

    /// Returns mutable access to the retained fresh runner.
    #[must_use]
    pub const fn fresh_mut(&mut self) -> &mut F {
        &mut self.fresh
    }

    /// Returns the original resume runner.
    #[must_use]
    pub const fn resume(&self) -> &R {
        &self.resume
    }

    /// Returns both retained execution paths without constructing replacements.
    #[must_use]
    pub fn into_parts(self) -> (F, R) {
        (self.fresh, self.resume)
    }
}

/// Reports the original execution branch or common reconciliation fence failure.
#[derive(Debug, thiserror::Error)]
pub enum AttemptExecutionRouterError<F, R> {
    /// Previous work still owns post-publication authority.
    #[error("execution router still awaits prior semantic reconciliation")]
    PriorReconciliationPending,
    /// The original fresh execution failed.
    #[error("fresh campaign execution failed")]
    Fresh(#[source] F),
    /// The original resume execution failed.
    #[error("resumed campaign execution failed")]
    Resume(#[source] R),
    /// No successful original route awaits reconciliation.
    #[error("execution router has no pending reconciliation")]
    NoPendingReconciliation,
    /// An adapter's source compatibility changed after pair construction.
    #[error("execution router original replay contract changed")]
    ReplayContractChanged,
}

impl<F, R> CrucibleExecutionRunner for AttemptExecutionRouter<F, R>
where
    F: AttemptOriginVerifier,
    R: AttemptOriginResumeRunner<
            SelectedBoundary = F::SelectedBoundary,
            SelectedProof = F::SelectedProof,
            StartProof = F::StartProof,
        >,
{
    type Error = AttemptExecutionRouterError<F::Error, R::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                AttemptExecutionRouterError::PriorReconciliationPending,
            ));
        }

        if self.fresh.replay_contract() != self.replay_contract
            || self.resume.replay_contract() != self.replay_contract
        {
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::ReplayContractChanged,
            ));
        }

        if context.resume_checkpoint().is_none() {
            let outcome = self
                .fresh
                .execute(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            self.pending = Some(PendingRoute::Fresh);
            Ok(outcome)
        } else if input.attempt().continuation_input().is_some() {
            if matches!(
                input.start(),
                CrucibleResolvedAttemptStart::AfterAttempt { .. }
            ) {
                self.resume
                    .authenticate_resume_source(input, context)
                    .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            }
            let cold_context = context.for_absent_selected_source();
            let outcome = self
                .fresh
                .execute(input, &cold_context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            self.pending = Some(PendingRoute::Fresh);
            Ok(outcome)
        } else if matches!(
            input.start(),
            CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            let Some(target) = self
                .resume
                .authenticate_resume_source(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?
            else {
                let cold_context = context.for_absent_selected_source();
                let outcome = self
                    .fresh
                    .execute(input, &cold_context)
                    .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
                self.pending = Some(PendingRoute::Fresh);
                return Ok(outcome);
            };
            let proof = self
                .fresh
                .verify_selected_resume(input, context, &target)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            let outcome = self
                .resume
                .resume_verified_source(input, context, proof)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            self.pending = Some(PendingRoute::Resume);
            Ok(outcome)
        } else if matches!(input.attempt().stop(), StopCondition::EventCount(_)) {
            let proof = self
                .fresh
                .verify_start_prefix(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh))?;
            let outcome = self
                .resume
                .resume_verified_start(input, context, proof)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            self.pending = Some(PendingRoute::Resume);
            Ok(outcome)
        } else {
            let outcome = self
                .resume
                .execute(input, context)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume))?;
            self.pending = Some(PendingRoute::Resume);
            Ok(outcome)
        }
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let route = self.pending.ok_or_else(|| {
            AttemptWorkerFailure::Terminal(AttemptExecutionRouterError::NoPendingReconciliation)
        })?;
        let reconciled = match route {
            PendingRoute::Fresh => self
                .fresh
                .reconcile_execution(disposition)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Fresh)),
            PendingRoute::Resume => self
                .resume
                .reconcile_execution(disposition)
                .map_err(|failure| map_routed_failure(failure, Self::Error::Resume)),
        };
        match reconciled {
            Ok(AttemptExecutionReconciliationStep::Complete) => {
                self.pending = None;
                Ok(AttemptExecutionReconciliationStep::Complete)
            }
            Ok(AttemptExecutionReconciliationStep::Progressed) => {
                Ok(AttemptExecutionReconciliationStep::Progressed)
            }
            Err(failure @ AttemptWorkerFailure::Retryable(_)) => Err(failure),
            Err(
                failure @ (AttemptWorkerFailure::Canceled(_) | AttemptWorkerFailure::Terminal(_)),
            ) => {
                self.pending = None;
                Err(failure)
            }
        }
    }

    fn quarantine_pending_execution(&mut self) {
        let Some(route) = self.pending.take() else {
            return;
        };
        match route {
            PendingRoute::Fresh => {
                self.fresh.quarantine_pending_execution();
            }
            PendingRoute::Resume => {
                self.resume.quarantine_pending_execution();
            }
        }
    }
}

fn map_routed_failure<E, T>(
    failure: AttemptWorkerFailure<E>,
    wrap: impl FnOnce(E) -> T,
) -> AttemptWorkerFailure<T> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(wrap(error)),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(wrap(error)),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(wrap(error)),
    }
}

#[cfg(test)]
mod tests;
