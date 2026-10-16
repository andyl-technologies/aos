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
pub(super) struct NativeOwnerExecutor {
    custody: Arc<Mutex<Custody>>,
    worker: ThreadId,
    running: Option<PublisherRunningContext>,
    failed_resume: Option<(ResumeFailureStage, CompletedRecovery)>,
}

impl NativeOwnerExecutor {
    /// Retains actual initialized custody on the physical worker, without cloning it.
    pub(super) fn new(custody: Arc<Mutex<Custody>>) -> Self {
        Self {
            custody,
            worker: thread::current().id(),
            running: None,
            failed_resume: None,
        }
    }

    /// Borrows actual custody for one serialized physical command.
    pub(super) fn custody(&self) -> &Arc<Mutex<Custody>> {
        &self.custody
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
                self.running = Some(context);
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
