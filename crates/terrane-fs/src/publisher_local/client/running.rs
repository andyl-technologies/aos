//! Hands genuine recovery completion to the publisher under one physical turn.
//!
//! A successful Resume retains completion by value with the original session.
//! This context is provenance for the concrete native owner, not BKT-15 bucket
//! readiness or publication-allocation authority. Running RPCs additionally
//! require the owner's actual serialized command and synchronized funding.

use std::sync::Arc;

use terrane::host::{cache::HostDomainLocation, publication::PublicationClaim};

use super::{
    Client, Error, PeerPublishedObject, Phase, RequestPayload, State, invalidate, receipt,
};
use crate::{
    host_cache::{CompletedRecovery, PublisherResumeTurn, PublisherRunningTurn},
    publisher_local::wire::{BodyKey, BodyKind, Claim, Operation},
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
    _completed: Box<CompletedRecovery>,
}

impl PublisherRunningContext {
    /// Borrows the actual original session for concrete executor integration.
    pub(crate) fn publisher_session(&self) -> &Arc<Client<HostDomainLocation>> {
        &self.session
    }

    /// Borrows original recovery funding from this actual acknowledged context.
    ///
    /// The registration survives legitimate Running writes, which invalidate
    /// the old completion-generation predicate. This grants no live owner turn.
    pub(crate) fn retained_bootstrap_id(&self) -> &[u8; 16] {
        self._completed.retained_bootstrap_id()
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
    /// Inspects and adopts sealed inline content under the actual running turn.
    ///
    /// Registered sealed InspectBody performs native adoption: it synchronizes
    /// and records the binding, and rejection may quarantine content or forget
    /// a conflicting binding. Neither a read-only returned descriptor nor the
    /// exclusive turn makes this operation read-only or proves allocation custody.
    ///
    /// An actual inline-publication turn supplies synchronized funding for its
    /// own claim; another claim is refused. The cache exposes no separate running
    /// inspection command yet. Such a command must retain genuine future holds
    /// across accepted physical work and reconcile effects, durable state and
    /// fresh quota before acknowledgment, including failure or cancellation.
    ///
    /// # Errors
    /// Rejects foreign or stale owner/session/epoch/root custody, non-inline
    /// claims, unavailable canonical content, transport uncertainty and any
    /// descriptor, seal or plaintext mismatch. Failed exchanges or verification
    /// invalidate the client phase and require genuine recovery.
    pub(crate) fn inspect_and_adopt_inline_running(
        &self,
        claim: PublicationClaim,
        context: &PublisherRunningContext,
        turn: &mut PublisherRunningTurn<'_>,
    ) -> Result<PeerPublishedObject<HostDomainLocation>, Error> {
        // This can consult embedded native custody, so it must run before the
        // client mutex. The turn retains exclusive dispatch after it returns.
        let claim = self.inline_claim(claim)?;
        turn.check_claim(context, &claim)?;
        let descriptor = claim.descriptor().encode();
        let payload = RequestPayload {
            claim: Some(Claim {
                descriptor: descriptor.clone(),
                chunk_profile: self.config.chunk_profile_name.clone(),
                plaintext_size: claim.plaintext_size(),
                ..Default::default()
            }),
            body: Some(BodyKey {
                kind: BodyKind::Sealed as i32,
                descriptor,
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let received = match self.exchange_payload(&mut state, Operation::InspectBody, payload) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        let result = receipt::published(
            received,
            Arc::clone(&self.layout),
            self.config.identities.publish_uid,
            claim,
        );
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }

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
                _completed: completed,
            }),
            Err(error) => Err(ResumeFailure {
                error,
                stage,
                completed,
            }),
        }
    }
}
