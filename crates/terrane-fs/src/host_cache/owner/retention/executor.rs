//! Retains the sole physical executor and noninterleaving Resume command turn.
//!
//! Only the retained worker constructs an executor from its genuine custody.
//! A Resume turn borrows it mutably for the complete synchronous RPC. Neither
//! a caller-selected session nor a boolean can substitute for that borrow.
//! Acknowledged contexts and failed handoffs remain outside embedded custody,
//! preventing a reference cycle and retaining resources before cancellable replies.

use super::Custody;
use crate::{
    host_cache::CompletedRecovery,
    publisher_local::client::{PublisherRunningContext, ResumeFailureStage},
};
use std::{
    io,
    sync::{Arc, Mutex},
    thread::{self, ThreadId},
};

/// Owns one retained physical queue's native custody on its actual worker thread.
pub(in crate::host_cache::owner) struct NativeOwnerExecutor {
    custody: Arc<Mutex<Custody>>,
    worker: ThreadId,
    running: Option<Arc<PublisherRunningContext>>,
    failed_resume: Option<(ResumeFailureStage, CompletedRecovery)>,
    adopted_inline: Vec<super::super::recovery_inline::AdoptedInline>,
    manifest_sources: Vec<Arc<crate::host_cache::NativeManifestSource>>,
    manifest_bodies: Vec<
        Arc<
            crate::publisher_local::client::PeerPublishedObject<
                terrane::host::cache::HostDomainLocation,
            >,
        >,
    >,
    manifest_backings: Vec<super::recovery_manifest::RecoveryManifestBodyRetention>,
}

impl NativeOwnerExecutor {
    /// Retains actual initialized custody on the physical worker, without cloning it.
    pub(super) fn new(custody: Arc<Mutex<Custody>>) -> Self {
        Self {
            custody,
            worker: thread::current().id(),
            running: None,
            failed_resume: None,
            adopted_inline: Vec::new(),
            manifest_sources: Vec::new(),
            manifest_bodies: Vec::new(),
            manifest_backings: Vec::new(),
        }
    }

    /// Borrows actual custody for one serialized physical command.
    pub(in crate::host_cache::owner) fn custody(&self) -> &Arc<Mutex<Custody>> {
        &self.custody
    }

    /// Checks the actual physical worker before a fixed native command.
    ///
    /// # Errors
    /// Refuses a caller on any thread other than this retained executor.
    pub(super) fn check_physical_worker(&self) -> io::Result<()> {
        if self.worker != thread::current().id() {
            return Err(io::Error::other(
                "native command belongs to another physical worker",
            ));
        }
        Ok(())
    }

    /// Retains actual source handles outside embedded state before write effects.
    ///
    /// # Errors
    /// Refuses another worker or unavailable finite registry allocation.
    pub(super) fn retain_manifest_source(
        &mut self,
        source: Arc<crate::host_cache::NativeManifestSource>,
    ) -> io::Result<()> {
        self.check_physical_worker()?;
        self.manifest_sources
            .try_reserve(1)
            .map_err(io::Error::other)?;
        self.manifest_sources.push(source);
        Ok(())
    }

    /// Borrows actual adopted inline bodies retained by the physical owner.
    pub(in crate::host_cache::owner) fn inline_registry(
        &self,
    ) -> &[super::super::recovery_inline::AdoptedInline] {
        &self.adopted_inline
    }

    /// Borrows the physical inline registry for bounded command-owned insertion.
    pub(in crate::host_cache::owner) fn inline_registry_mut(
        &mut self,
    ) -> &mut Vec<super::super::recovery_inline::AdoptedInline> {
        &mut self.adopted_inline
    }

    /// Borrows the real verified metadata source closure retained by this worker.
    pub(in crate::host_cache::owner) fn manifest_sources(
        &self,
    ) -> &[Arc<crate::host_cache::NativeManifestSource>] {
        &self.manifest_sources
    }

    /// Reserves bounded registry slots before a downstream recovery effect.
    ///
    /// # Errors
    /// Refuses another worker, poisoned custody, exhausted configured record
    /// capacity or unavailable memory. No native publisher effect occurs here.
    pub(super) fn reserve_manifest_body_slots(&mut self) -> io::Result<()> {
        self.check_physical_worker()?;
        let limit = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?
            .preparation
            .config
            .state
            .records;
        if self.manifest_bodies.len() >= limit || self.manifest_backings.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "manifest body registry limit reached",
            ));
        }
        self.manifest_bodies
            .try_reserve(1)
            .map_err(io::Error::other)?;
        self.manifest_backings
            .try_reserve(1)
            .map_err(io::Error::other)?;
        Ok(())
    }

    /// Retains an owned response body before any subsequent fallible checks.
    ///
    /// The exclusive effect owns the slot reserved before its RPC. Only that
    /// effect inserts here, once; no intervening command can consume capacity.
    pub(super) fn retain_adopted_manifest_body(
        &mut self,
        body: Arc<
            crate::publisher_local::client::PeerPublishedObject<
                terrane::host::cache::HostDomainLocation,
            >,
        >,
    ) {
        self.manifest_bodies.push(body);
    }

    /// Retains the actual body/metadata pair before completing its response.
    ///
    /// The same exclusive effect owns the pre-reserved pairing slot. This
    /// registry preserves unresolved pairs too and grants no serving authority.
    pub(super) fn retain_manifest_backing(
        &mut self,
        retained: super::recovery_manifest::RecoveryManifestBodyRetention,
    ) {
        self.manifest_backings.push(retained);
    }

    /// Runs supported recovery while retaining adopted backing beyond any reply.
    ///
    /// # Errors
    /// Refuses unsupported candidates, stale custody, failed synchronization,
    /// quota reconciliation or a prior handoff; all adopted handles stay owned.
    pub(super) async fn recover(&mut self) -> io::Result<CompletedRecovery> {
        self.check_recovery_phase()?;
        super::super::recovery::run(self).await
    }

    /// Retains the complete acknowledged or failed handoff before any reply.
    ///
    /// # Errors
    /// Refuses repeated handoffs, stale completion, failed or uncertain RPCs,
    /// and poisoned custody while retaining the accepted physical outcome.
    pub(super) fn resume(&mut self, completed: CompletedRecovery) -> io::Result<()> {
        if self.running.is_some() || self.failed_resume.is_some() {
            return Err(io::Error::other("owner already retained a Resume outcome"));
        }
        let session = completed.publisher_session();
        let result = session.resume_completed(completed, &mut self.resume_turn());
        match result {
            Ok(context) => {
                self.running = Some(Arc::new(context));
                Ok(())
            }
            Err(failure) => {
                // Keep even a pre-submission failure: neither cancellation nor
                // an uncertain reply may discard the consumed durable proof.
                let (error, stage, completed) = failure.into_parts();
                self.failed_resume = Some((stage, completed));
                let mut custody = self
                    .custody
                    .lock()
                    .map_err(|_| io::Error::other("metadata custody poisoned"))?;
                custody.faulted = true;
                custody.recovery_required = true;
                custody.recovery_id = None;
                Err(io::Error::other(error))
            }
        }
    }

    /// Refuses recovery-only commands after a physical Resume outcome.
    ///
    /// # Errors
    /// Returns an error after any retained acknowledged or failed Resume handoff.
    pub(super) fn check_recovery_phase(&self) -> io::Result<()> {
        if self.running.is_some() || self.failed_resume.is_some() {
            return Err(io::Error::other(
                "owner requires a running command turn or fresh recovery",
            ));
        }
        Ok(())
    }

    /// Borrows the live executor exclusively until the complete Resume RPC returns.
    ///
    /// Only the parent physical dispatch can mint this turn. No turn constructor
    /// accepts an arbitrary session, epoch, generation or asserted validity.
    pub(super) fn resume_turn(&mut self) -> PublisherResumeTurn<'_> {
        PublisherResumeTurn { executor: self }
    }
}

/// Retains exclusive physical dispatch through a genuine completion handoff.
///
/// Fields and construction remain private to the actual executor. The IPC
/// consumer checks completion before its RPC lock and retains this mutable
/// borrow until actual physical submission finishes or becomes uncertain.
pub(crate) struct PublisherResumeTurn<'executor> {
    executor: &'executor mut NativeOwnerExecutor,
}

impl PublisherResumeTurn<'_> {
    /// Checks the actual worker and exact completion custody before an RPC lock.
    ///
    /// The borrow already prevents another dispatch on this executor. This
    /// check retains no embedded-state guard; the client must then atomically
    /// validate the original opaque drain context under its own RPC mutex.
    ///
    /// # Errors
    /// Refuses another worker or owner, stale native state/generation, absent
    /// durable completion records and changed source namespace custody.
    pub(crate) fn check_completion(&mut self, completed: &CompletedRecovery) -> io::Result<()> {
        if self.executor.worker != thread::current().id()
            || !completed.matches_custody(&self.executor.custody)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery completion belongs to another physical executor",
            ));
        }
        completed.check_current()
    }
}

/// Retains exclusive physical dispatch through one genuine running operation.
///
/// No public constructor or caller-selected session exists. A constructor will
/// be added only with actual physical dispatch of a supported running command.
pub(crate) struct PublisherRunningTurn<'executor> {
    executor: &'executor mut NativeOwnerExecutor,
}

impl PublisherRunningTurn<'_> {
    /// Checks the exact executor-owned acknowledged context before an RPC lock.
    ///
    /// This never revalidates the old empty recovery snapshot. The caller must
    /// keep this exclusive turn borrowed through physical completion, and the
    /// client must check its actual Running phase/epoch under its own mutex.
    ///
    /// # Errors
    /// Refuses another physical thread/context, faulted native owner, required
    /// recovery or a changed original publisher session.
    pub(crate) fn check_context(&mut self, context: &PublisherRunningContext) -> io::Result<()> {
        if self.executor.worker != thread::current().id()
            || !self
                .executor
                .running
                .as_ref()
                .is_some_and(|actual| std::ptr::eq(actual.as_ref(), context))
        {
            return Err(io::Error::other(
                "running context belongs to another physical executor",
            ));
        }
        let custody = self
            .executor
            .custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        custody.check_current()?;
        if custody.faulted
            || custody.recovery_required
            || !Arc::ptr_eq(
                context.publisher_session(),
                &custody.preparation.publisher_session(),
            )
        {
            return Err(io::Error::other("running owner requires recovery"));
        }
        Ok(())
    }
}
