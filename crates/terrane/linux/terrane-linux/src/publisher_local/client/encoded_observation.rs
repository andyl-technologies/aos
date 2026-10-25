//! Retains healthy encoded incarnations before independent consumers can read.
//!
//! A failed read publishes only an atomic deny/report signal. The physical
//! owner retains the actual admission and uses its original publisher token;
//! a changed pathname never creates replacement mutation authority.

use super::{
    BodyIncarnationObservation, Client, Error, PublisherRunningContext, RequestPayload, invalidate,
};
use crate::{
    host_cache::PublisherEncodedReadTurn,
    publisher_local::wire::{BodyKey, Operation},
};
use std::{
    io,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Shares original publisher custody and permanent revocation across read aliases.
pub(crate) struct EncodedReadObservation {
    session: Arc<Client<HostDomainLocation>>,
    // Custody registers manifest sources that retain this observation. A strong
    // context would point back to that same custody and keep its exclusive
    // state lock alive after shutdown. The physical executor owns the live
    // context; observations retain its identity without extending its lifetime.
    running: Weak<PublisherRunningContext>,
    original: BodyIncarnationObservation<HostDomainLocation>,
    failed: AtomicU8,
    attempted: AtomicBool,
    pending: Arc<AtomicBool>,
}

impl EncodedReadObservation {
    /// Refuses every alias after an actual failure of the original native source.
    ///
    /// # Errors
    /// Refuses a permanently rejected original incarnation.
    pub(crate) fn check_readable(&self) -> io::Result<()> {
        if self.failed.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original encoded incarnation rejected",
            ));
        }
        Ok(())
    }

    /// Reports actual original custody or content failure without policy or RPC locks.
    pub(crate) fn reject(&self, stage: u8) {
        let _ = self
            .failed
            .compare_exchange(0, stage, Ordering::SeqCst, Ordering::SeqCst);
        self.pending.store(true, Ordering::SeqCst);
    }

    /// Selects one failed original once; uncertain effects are never blindly retried.
    pub(crate) fn take_failed(&self) -> Option<u8> {
        let stage = self.failed.load(Ordering::SeqCst);
        if stage == 0 || self.attempted.swap(true, Ordering::SeqCst) {
            return None;
        }
        Some(stage)
    }

    /// Checks the exact acknowledged owner, peer and retained original key.
    ///
    /// # Errors
    /// Refuses another physical context, publisher session or body key.
    pub(crate) fn check_original(
        &self,
        running: &Arc<PublisherRunningContext>,
        key: &BodyKey,
    ) -> io::Result<()> {
        if !self.running.ptr_eq(&Arc::downgrade(running))
            || !Arc::ptr_eq(running.publisher_session(), &self.session)
            || self.original.key() != key
        {
            return Err(io::Error::other(
                "encoded read observation changed original custody",
            ));
        }
        Ok(())
    }

    /// Bounds the retained observation, its key buffers and shared atomic headers.
    pub(crate) fn storage_bytes() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<BodyIncarnationObservation<HostDomainLocation>>()
            + 512
    }
}

impl Client<HostDomainLocation> {
    /// Captures a healthy original before cache handoff releases producer funding.
    ///
    /// # Errors
    /// Refuses changed original backing, stale Running custody, invalid replies
    /// or failed exchanges. Inspection supplies no content-serving authority.
    pub(crate) fn observe_encoded_read(
        self: &Arc<Self>,
        turn: &mut PublisherEncodedReadTurn<'_>,
    ) -> Result<Arc<EncodedReadObservation>, Error> {
        let (running, key) = turn.key(Operation::InspectBody)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, &running)?;
        let received = match self.exchange_payload(
            &mut state,
            Operation::InspectBody,
            RequestPayload {
                body: Some(key.clone()),
                ..Default::default()
            },
        ) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        let original = match self.observation(&state, key, &received.packet.body_incarnation) {
            Ok(original) => original,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        drop(state);
        if let Err(error) = turn.check_received(&received.files) {
            let mut state = self.lock()?;
            invalidate(&mut state);
            return Err(error.into());
        }
        Ok(Arc::new(EncodedReadObservation {
            session: Arc::clone(self),
            running: Arc::downgrade(&running),
            original,
            failed: AtomicU8::new(0),
            attempted: AtomicBool::new(false),
            pending: turn.notifier(),
        }))
    }

    /// Quarantines a rejected unit through the observation captured while healthy.
    ///
    /// # Errors
    /// Refuses another original unit, stale context, denied or uncertain exchanges.
    pub(crate) fn quarantine_encoded_read(
        self: &Arc<Self>,
        turn: &mut PublisherEncodedReadTurn<'_>,
        original: &Arc<EncodedReadObservation>,
    ) -> Result<(), Error> {
        let (running, key) = turn.key(Operation::Quarantine)?;
        original.check_original(&running, &key)?;
        turn.check_original(original)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, &running)?;
        let payload = original.original.checked_payload(self, &state, &key)?;
        match self.exchange_payload(&mut state, Operation::Quarantine, payload) {
            Ok(_) => Ok(()),
            Err(error) => {
                invalidate(&mut state);
                Err(error)
            }
        }
    }
}
