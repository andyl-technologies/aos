//! Hands genuine recovery completion to the publisher under one physical turn.
//!
//! A successful Resume consumes cold observations into original owner/funding
//! provenance. Adopted resources remain registered on the physical executor;
//! standalone sources transfer there before any fallible import.
//! This context is provenance for the concrete native owner, not BKT-15 bucket
//! readiness or publication-allocation authority. Running RPCs additionally
//! require the owner's actual serialized command and synchronized funding.

use std::sync::Arc;

use terrane_sdk::host::cache::HostDomainLocation;

use super::{Client, Error, Phase, State, invalidate};
use crate::{
    host_cache::{
        CompletedRecovery, PublisherResumeTurn, RunningRecovery, VerifiedStandaloneChunk,
    },
    publisher_local::wire::Operation,
};

/// Retains acknowledged running custody without exposing a construction bypass.
///
/// The physical executor must store this outside embedded custody before
/// replying to its waiter. Retained completion is lifetime provenance: its
/// original empty-state predicate must not be reused after legitimate running
/// mutations. Sealed read handles never consult this context or embedded state.
pub(crate) struct PublisherRunningContext {
    session: Arc<Client<HostDomainLocation>>,
    epoch: u64,
    _recovery: RunningRecovery,
}

impl PublisherRunningContext {
    /// Transfers original encoded source custody to the actual physical executor.
    pub(crate) fn take_encoded_sources(&mut self) -> Vec<Arc<VerifiedStandaloneChunk>> {
        self._recovery.take_encoded_sources()
    }

    /// Borrows the actual original session for concrete executor integration.
    pub(crate) fn publisher_session(&self) -> &Arc<Client<HostDomainLocation>> {
        &self.session
    }

    /// Borrows original recovery funding from this actual acknowledged context.
    ///
    /// The registration survives legitimate Running writes, which invalidate
    /// the old completion-generation predicate. This grants no live owner turn.
    pub(crate) fn retained_bootstrap_id(&self) -> &[u8; 16] {
        self._recovery.retained_bootstrap_id()
    }

    /// Rechecks the actual acknowledged session phase without embedded-state locks.
    ///
    /// This is not an owner-turn substitute and enables no running RPC itself.
    ///
    /// # Errors
    /// Rejects another client/root/incarnation, a later Drain, transport
    /// uncertainty or a poisoned actual client mutex.
    pub(crate) fn check_current(&self) -> Result<(), Error> {
        let state = self.session.lock()?;
        self.session.require_running_context(&state, self)?;
        self.session.layout.recheck()?;
        Ok(())
    }
}

/// Distinguishes withheld submission from a conservatively uncertain exchange.
pub(crate) enum ResumeFailureStage {
    /// No Resume exchange was attempted; the completion is still retained.
    BeforeSubmission,
    /// Submission may have occurred; actual recovery must resolve the outcome.
    OutcomeUnknown,
}

/// Retains genuine completion and its holds when Resume cannot be acknowledged.
///
/// The physical owner keeps this even when its response waiter disappears.
/// Neither stage permits automatic retry or discarding recovery records.
pub(crate) struct ResumeFailure {
    error: Error,
    stage: ResumeFailureStage,
    completed: Box<CompletedRecovery>,
}

impl ResumeFailure {
    /// Returns the physical failure with its original completion custody intact.
    pub(crate) fn into_parts(self) -> (Error, ResumeFailureStage, Box<CompletedRecovery>) {
        (self.error, self.stage, self.completed)
    }
}

impl Client<HostDomainLocation> {
    /// Checks running identity atomically with the caller's actual RPC lock.
    ///
    /// The concrete physical turn separately proves executor ownership before
    /// this lock. No old completed-recovery predicate is consulted here.
    ///
    /// # Errors
    /// Rejects another actual session, root or incarnation, a changed running
    /// epoch, a later Drain and an uncertain or non-running client phase.
    pub(super) fn require_running_context(
        &self,
        state: &State,
        context: &PublisherRunningContext,
    ) -> Result<(), Error> {
        if state.phase != Phase::Running
            || state.recovery_epoch != context.epoch
            || !std::ptr::eq(self, context.session.as_ref())
            || self.cache_incarnation != context.session.cache_incarnation
            || !Arc::ptr_eq(&self.layout, &context.session.layout)
        {
            return Err(Error::Invalid(
                "publisher running context is stale or foreign",
            ));
        }
        Ok(())
    }

    /// Submits Resume only inside the genuine producer's exclusive physical turn.
    ///
    /// Producer checks precede the client mutex. The mutable executor borrow
    /// remains held through the complete synchronous exchange, preventing a
    /// queued metadata mutation between validation and physical submission.
    ///
    /// # Errors
    /// Retains completion on every failure. Refuses stale producer custody,
    /// another session or original drain epoch, exhausted local epochs and
    /// failed exchanges. Any attempted exchange failure invalidates the client
    /// barrier and requires actual recovery, including a lost Resume reply.
    pub(crate) fn resume_completed(
        &self,
        completed: Box<CompletedRecovery>,
        turn: &mut PublisherResumeTurn<'_>,
    ) -> Result<PublisherRunningContext, ResumeFailure> {
        let mut stage = ResumeFailureStage::BeforeSubmission;
        let session = completed.publisher_session();
        let outcome = (|| {
            turn.check_completion(&completed)?;
            if !std::ptr::eq(self, session.as_ref())
                || self.cache_incarnation != session.cache_incarnation
                || !Arc::ptr_eq(&self.layout, &session.layout)
            {
                return Err(Error::Invalid(
                    "recovery completion belongs to another client",
                ));
            }

            let mut state = self.lock()?;
            self.require_recovery_context(&state, completed.publisher_context())?;
            self.layout.recheck()?;
            // Reserve the distinct running epoch before any physical effect.
            let epoch = state
                .recovery_epoch
                .checked_add(1)
                .ok_or(Error::Invalid("publisher running epoch exhausted"))?;

            stage = ResumeFailureStage::OutcomeUnknown;
            if let Err(error) = self.exchange(&mut state, Operation::Resume, None, None) {
                // Even a registered failure is not rollback evidence for this
                // handoff. Retain completion and force genuine reconciliation.
                invalidate(&mut state);
                return Err(error);
            }
            state.recovery_epoch = epoch;
            state.phase = Phase::Running;
            Ok(epoch)
        })();

        match outcome {
            Ok(epoch) => Ok(PublisherRunningContext {
                session,
                epoch,
                _recovery: completed.into_running(),
            }),
            Err(error) => Err(ResumeFailure {
                error,
                stage,
                completed,
            }),
        }
    }
}
