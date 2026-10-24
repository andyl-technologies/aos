//! Quarantines original failed sealed reads under exclusive physical custody.

use super::{NativeOwnerExecutor, PublisherRunningContext};
use crate::{host_cache::owner::corruption::Signal, publisher_local::client::PeerPublishedObject};
use std::{io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

/// Borrows the original executor throughout one exact-inode quarantine exchange.
pub(crate) struct PublisherCorruptionTurn<'turn> {
    executor: &'turn mut NativeOwnerExecutor,
    context: Arc<PublisherRunningContext>,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
}

impl NativeOwnerExecutor {
    /// Shares the original executor's report flag without exposing policy custody.
    pub(in crate::host_cache::owner) fn encoded_failure_notifier(
        &self,
    ) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.encoded_failures)
    }

    /// Processes encoded reports without scanning healthy admission jobs.
    ///
    /// # Errors
    /// Refuses absent Running custody, lost original resources or uncertain IO.
    pub(in crate::host_cache::owner) fn quarantine_failed_encoded_reads(
        &mut self,
    ) -> io::Result<()> {
        self.check_physical_worker()?;
        if !self
            .encoded_failures
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        let running = self.running.as_ref().cloned().ok_or_else(|| {
            io::Error::other("encoded read failure lacks original Running custody")
        })?;
        super::super::super::admission::read_custody::quarantine(self, running)
    }

    /// Registers original native backing before any external read can begin.
    ///
    /// # Errors
    /// Refuses another worker, an exhausted finite registry or rejected custody.
    pub(in crate::host_cache::owner) fn sealed_corruption_signal(
        &self,
        owner: &super::Custody,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
    ) -> io::Result<Arc<Signal>> {
        self.check_physical_worker()?;
        self.corruption
            .lock()
            .map_err(|_| io::Error::other("sealed failure registry poisoned"))?
            .register(body, owner.preparation.config.state.records)
    }

    /// Processes latched original failures before the next physical command.
    ///
    /// # Errors
    /// Refuses stale native custody or an uncertain publisher exchange. All
    /// original descriptors, pins and reservations remain retained on failure.
    pub(in crate::host_cache::owner) fn quarantine_failed_reads(&mut self) -> io::Result<()> {
        self.check_physical_worker()?;
        loop {
            let pending = self
                .corruption
                .lock()
                .map_err(|_| io::Error::other("sealed failure registry poisoned"))?
                .next()?;
            let Some((body, failure)) = pending else {
                return Ok(());
            };
            let context = self.running.as_ref().cloned().ok_or_else(|| {
                io::Error::other("sealed failure lacks acknowledged Running custody")
            })?;
            {
                let mut owner = self
                    .custody
                    .lock()
                    .map_err(|_| io::Error::other("failed sealed custody poisoned"))?;
                owner.check_current()?;
                // Revocation never releases the original durable protection.
                // Faulting also excludes later admission, maintenance and Resume
                // until cold reconciliation supplies genuinely verified backing.
                owner.faulted = true;
            }
            eprintln!(
                "terrane: rejecting original sealed incarnation after native read failure stage={failure}"
            );
            let session = Arc::clone(context.publisher_session());
            let mut turn = PublisherCorruptionTurn {
                executor: self,
                context,
                body,
            };
            session
                .quarantine_failed_body(&mut turn)
                .map_err(io::Error::other)?;
        }
    }
}

impl PublisherCorruptionTurn<'_> {
    /// Borrows the actual registered failed body under its original Running context.
    ///
    /// # Errors
    /// Refuses another worker, changed layout or stale acknowledged context.
    pub(crate) fn body(
        &self,
    ) -> io::Result<(
        &PublisherRunningContext,
        &PeerPublishedObject<HostDomainLocation>,
    )> {
        self.executor.check_physical_worker()?;
        self.context.check_current().map_err(io::Error::other)?;
        self.body.layout().recheck()?;
        Ok((&self.context, &self.body))
    }
}
