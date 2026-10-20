//! Retires actual cached bodies through the original physical Running turn.
//!
//! Pending custody is created only from an authenticated Retire response for
//! the original verified body's publisher incarnation. Restoring or finishing
//! requires that same opaque receipt and a fresh physical owner turn.

use super::{
    BodyIncarnationObservation, Client, Error, PeerPublishedObject, PublisherRunningContext,
    invalidate,
};
use crate::{
    host_cache::PublisherCacheRetirementTurn,
    publisher_local::wire::{BodyKey, BodyKind, Operation},
};
use std::{
    io,
    sync::{Arc, Weak},
};
use terrane::host::cache::HostDomainLocation;

/// Retains the original successful Retire exchange and its actual native body.
pub(crate) struct PendingCacheBody {
    session: Arc<Client<HostDomainLocation>>,
    body: Weak<PeerPublishedObject<HostDomainLocation>>,
    observation: Arc<BodyIncarnationObservation<HostDomainLocation>>,
    request_id: u64,
}

impl PendingCacheBody {
    /// Checks another genuine publication receipt for this same retired inode.
    ///
    /// # Errors
    /// Refuses another session, native inode, root, descriptor or incarnation.
    pub(crate) fn check_alias(
        &self,
        session: &Arc<Client<HostDomainLocation>>,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
    ) -> io::Result<()> {
        let original = self
            .body
            .upgrade()
            .ok_or_else(|| io::Error::other("original pending cache body absent"))?;
        self.check_original(session, &original)?;
        use std::os::unix::fs::MetadataExt;
        let first = original.handle().metadata()?;
        let alias = body.handle().metadata()?;
        if (first.dev(), first.ino()) != (alias.dev(), alias.ino())
            || body.claim().descriptor() != original.claim().descriptor()
            || body.incarnation() != original.incarnation()
            || !Arc::ptr_eq(body.layout(), original.layout())
            || first.nlink() != 0
            || alias.nlink() != 0
        {
            return Err(io::Error::other(
                "retired cache alias differs from original unlinked inode",
            ));
        }
        Ok(())
    }

    /// Checks the same original authenticated session and retained body.
    ///
    /// # Errors
    /// Refuses another receipt, original body or publisher session.
    pub(crate) fn check_original(
        &self,
        session: &Arc<Client<HostDomainLocation>>,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
    ) -> io::Result<()> {
        if self.request_id == 0
            || !Arc::ptr_eq(session, &self.session)
            || self
                .body
                .upgrade()
                .is_none_or(|original| !Arc::ptr_eq(body, &original))
        {
            return Err(io::Error::other(
                "pending cache receipt changed original custody",
            ));
        }
        Ok(())
    }
}

/// Retains a correlated restoration or final-removal response for original custody.
pub(crate) struct CacheBodyCompletion {
    pending: Arc<PendingCacheBody>,
    operation: Operation,
    request_id: u64,
}

impl CacheBodyCompletion {
    /// Correlates dependent reconstruction metadata with the actual removed body.
    ///
    /// # Errors
    /// Refuses non-removal replies, absent original custody or another manifest.
    pub(crate) fn check_metadata(
        &self,
        metadata: &crate::host_cache::RetainedManifest,
    ) -> io::Result<()> {
        self.check_removed_body(&self.pending)?;
        let body = self
            .pending
            .body
            .upgrade()
            .ok_or_else(|| io::Error::other("removed metadata lost original body custody"))?;
        if body.claim().descriptor() != metadata.claim().descriptor()
            || !Arc::ptr_eq(body.layout(), metadata.layout())
            || !metadata.matches_client(&self.pending.session)
        {
            return Err(io::Error::other(
                "removed body does not own this reconstruction metadata",
            ));
        }
        Ok(())
    }

    /// Checks an actual final-removal response before dropping physical resources.
    ///
    /// # Errors
    /// Refuses another pending receipt, a restoration or an absent response sequence.
    pub(crate) fn check_removed(&self, pending: &Arc<PendingCacheBody>) -> io::Result<()> {
        if self.request_id == 0
            || self.operation != Operation::FinishRetirement
            || !Arc::ptr_eq(pending, &self.pending)
        {
            return Err(io::Error::other(
                "cache removal lacks its original final acknowledgement",
            ));
        }
        Ok(())
    }

    /// Checks actual unlinking of the original inode before policy or funding release.
    ///
    /// # Errors
    /// Refuses another response, absent original body or any remaining native link.
    pub(crate) fn check_removed_body(&self, pending: &Arc<PendingCacheBody>) -> io::Result<()> {
        self.check_removed(pending)?;
        let body = pending
            .body
            .upgrade()
            .ok_or_else(|| io::Error::other("removed body lost original native custody"))?;
        use std::os::unix::fs::MetadataExt;
        if body.handle().metadata()?.nlink() != 0 {
            return Err(io::Error::other(
                "final cache removal acknowledgement retained original inode links",
            ));
        }
        Ok(())
    }

    /// Checks an actual restoration before granting a new consumer promise.
    ///
    /// # Errors
    /// Refuses another pending receipt, a final removal or an absent response sequence.
    pub(crate) fn check_restored(&self, pending: &Arc<PendingCacheBody>) -> io::Result<()> {
        if self.request_id == 0
            || self.operation != Operation::Restore
            || !Arc::ptr_eq(pending, &self.pending)
        {
            return Err(io::Error::other(
                "cache restoration lacks its original acknowledgement",
            ));
        }
        let body = pending
            .body
            .upgrade()
            .ok_or_else(|| io::Error::other("restored cache body lost original custody"))?;
        body.layout().recheck()?;
        let canonical = body
            .layout()
            .open_sealed_canonical(body.claim().descriptor())?;
        let observed = rustix::fs::fstat(&canonical)?;
        let original = rustix::fs::fstat(body.handle())?;
        if observed.st_dev != original.st_dev
            || observed.st_ino != original.st_ino
            || observed.st_nlink == 0
        {
            return Err(io::Error::other(
                "cache restore did not restore the original canonical inode",
            ));
        }
        Ok(())
    }
}

impl Client<HostDomainLocation> {
    /// Retires only the genuine cache unit selected under current physical exclusion.
    ///
    /// # Errors
    /// Refuses changed cache custody, stale Running context or a failed exchange.
    /// An attempted exchange failure invalidates the session and requires recovery.
    pub(crate) fn retire_cached_body(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherCacheRetirementTurn<'_>,
    ) -> Result<PendingCacheBody, Error> {
        let body = turn.retiring_body(context)?;
        let key = BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor: body.claim().descriptor().encode(),
            ..Default::default()
        };
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let observation = Arc::new(self.observation(&state, key.clone(), body.incarnation())?);
        let payload = observation.checked_payload(self, &state, &key)?;
        let received = match self.exchange_payload(&mut state, Operation::Retire, payload) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        Ok(PendingCacheBody {
            session: Arc::clone(self),
            body: Arc::downgrade(&body),
            observation,
            request_id: received.packet.request_id,
        })
    }

    /// Restores the original pending inode before a new pin or read is granted.
    ///
    /// # Errors
    /// Refuses changed physical custody, stale context or an uncertain exchange.
    pub(crate) fn restore_cached_body(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherCacheRetirementTurn<'_>,
        pending: &Arc<PendingCacheBody>,
    ) -> Result<CacheBodyCompletion, Error> {
        self.transition_cached_body(context, turn, pending, Operation::Restore)
    }

    /// Finishes the original pending inode after its actual publisher deadline.
    ///
    /// # Errors
    /// Refuses active native grace, changed custody or failed/uncertain exchanges.
    /// The publisher's durable deadline remains authoritative.
    pub(crate) fn finish_cached_body(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherCacheRetirementTurn<'_>,
        pending: &Arc<PendingCacheBody>,
    ) -> Result<CacheBodyCompletion, Error> {
        self.transition_cached_body(context, turn, pending, Operation::FinishRetirement)
    }

    fn transition_cached_body(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherCacheRetirementTurn<'_>,
        pending: &Arc<PendingCacheBody>,
        operation: Operation,
    ) -> Result<CacheBodyCompletion, Error> {
        let body = turn.pending_body(context, pending, operation)?;
        pending.check_original(self, &body)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let payload =
            pending
                .observation
                .checked_payload(self, &state, pending.observation.key())?;
        let received = match self.exchange_payload(&mut state, operation, payload) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        Ok(CacheBodyCompletion {
            pending: Arc::clone(pending),
            operation,
            request_id: received.packet.request_id,
        })
    }
}
