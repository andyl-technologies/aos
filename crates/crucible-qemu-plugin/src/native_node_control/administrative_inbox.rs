//! Installed raw-inbox custody beside a separately created modeled worker owner.
//!
//! The source-owned reader role observes the actual endpoint/thread. This owner
//! retains raw original preparation and each complete consumed packet before
//! decode, with maximum reply credit reserved before dequeue. It never captures
//! unread kernel backlog, grants modeled dispatch, or supplies complete Ready.

use std::sync::{Arc, Mutex, MutexGuard};

use crucible_protocol::node_control::{NativeChannel, NativeFrame};
use thiserror::Error;

use super::administrative_mailbox::{
    NativeAdministrativeError, NativeAdministrativeMailbox, NativeAdministrativeReceive,
    NativeAdministrativeReplyCredit,
};
use crate::runtime::worker_quiescence::{
    LiveWorkerQuiescence, WORKER_FINGERPRINT, WORKER_REQUIRED,
};

/// Refuses inbox ownership without releasing original resources or admission.
#[derive(Debug, Error)]
pub(crate) enum NativeAdministrativeInboxError {
    #[error("original administrative inbox ownership is unavailable")]
    Busy,
    #[error("original administrative inbox ownership is poisoned")]
    Poisoned,
    #[error("original administrative inbox allocation credit is exhausted")]
    Credit,
    #[error(transparent)]
    Mailbox(#[from] NativeAdministrativeError),
}

/// Owns the only actual socket reader and its separately enrolled modeled workers.
pub(crate) struct NativeAdministrativeInbox {
    scope: [u8; 32],
    descriptor: i32,
    modeled_workers: Arc<LiveWorkerQuiescence>,
    mailbox: Mutex<NativeAdministrativeMailbox>,
}

#[cfg(test)]
#[path = "administrative_inbox_tests.rs"]
mod tests;

impl NativeAdministrativeInbox {
    /// Takes endpoint custody only after fallible original-credit preflight.
    ///
    /// The installed factory/source must separately verify complete preparation
    /// against the early pin. Failure preserves the caller's exact socket and
    /// unread datagrams. Neither constructor nor a role observation permits work.
    ///
    /// # Errors
    /// Refuses absent scope/endpoint, invalid credit or physical metadata failure.
    pub(crate) fn from_pinned_endpoint(
        endpoint: &mut Option<NativeChannel>,
        scope: [u8; 32],
        fingerprint_worker: bool,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<Self, NativeAdministrativeInboxError> {
        let worker_mask = WORKER_REQUIRED
            | if fingerprint_worker {
                WORKER_FINGERPRINT
            } else {
                0
            };
        let modeled_workers = LiveWorkerQuiescence::new(worker_mask);
        let mailbox = NativeAdministrativeMailbox::from_pinned_endpoint(
            endpoint,
            scope,
            maximum_records,
            maximum_bytes,
        )?;
        let descriptor = mailbox.descriptor();
        Ok(Self {
            scope,
            descriptor,
            modeled_workers,
            mailbox: Mutex::new(mailbox),
        })
    }

    pub(crate) fn scope(&self) -> &[u8; 32] {
        &self.scope
    }

    pub(crate) fn modeled_workers(&self) -> &Arc<LiveWorkerQuiescence> {
        &self.modeled_workers
    }

    /// Returns a non-owning descriptor for the only enrolled reader's polling.
    ///
    /// The original mailbox owns the constructor-validated descriptor for this
    /// inbox's lifetime; no additional receiver is created.
    ///
    /// # Errors
    /// Refuses poisoned reply custody. Concurrent reader custody does not prevent
    /// observation of this historical descriptor.
    pub(crate) fn descriptor(&self) -> Result<i32, NativeAdministrativeInboxError> {
        // Manifest installation must not borrow the mutable reader ledger:
        // an original reply can hold it immediately after startup publication.
        if self.mailbox.is_poisoned() {
            return Err(NativeAdministrativeInboxError::Poisoned);
        }
        Ok(self.descriptor)
    }

    /// Returns the actual endpoint identity captured before the first receive.
    ///
    /// # Errors
    /// Refuses busy/poisoned custody without replacing the original endpoint.
    pub(crate) fn socket_identity(&self) -> Result<(u64, u64), NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.socket_identity())
    }

    /// Copies original consumed packets and credits without dequeuing kernel data.
    ///
    /// The real mailbox remains owned separately and may retain later bounded
    /// administrative replies. This historical image is not a peer-write fence.
    ///
    /// # Errors
    /// Refuses poison or exhausted image credit. None reports only busy custody.
    pub(crate) fn try_snapshot(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, NativeAdministrativeInboxError> {
        let mailbox = match self.mailbox.try_lock() {
            Ok(mailbox) => mailbox,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(NativeAdministrativeInboxError::Poisoned);
            }
        };
        Ok(Some(mailbox.snapshot(maximum_bytes)?))
    }

    /// Retains one complete original packet with response credit before dequeue.
    ///
    /// # Errors
    /// Refuses ambiguous, malformed or oversized input, retaining consumed bytes
    /// or leaving an unretainable complete packet unread in its kernel endpoint.
    pub(crate) fn receive_one(
        &self,
    ) -> Result<NativeAdministrativeReceive, NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.receive()?)
    }

    /// Copies an already retained original packet without another socket read.
    ///
    /// # Errors
    /// Refuses busy custody, an unknown cursor or allocation failure.
    pub(crate) fn original(&self, cursor: u64) -> Result<Vec<u8>, NativeAdministrativeInboxError> {
        let mailbox = self.try_mailbox()?;
        let original = mailbox
            .original(cursor)
            .ok_or(NativeAdministrativeError::Conflict)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(original.len())
            .map_err(|_| NativeAdministrativeInboxError::Credit)?;
        bytes.extend_from_slice(original);
        Ok(bytes)
    }

    /// Decodes the unchanged original packet under the immutable endpoint edition.
    ///
    /// # Errors
    /// Refuses unknown or malformed original bytes without receiving again.
    pub(crate) fn original_frame(
        &self,
        cursor: u64,
    ) -> Result<NativeFrame, NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.decode_original(cursor)?)
    }

    /// Recovers original construction reply credit before native admission.
    ///
    /// # Errors
    /// Refuses busy custody, an unknown original request or invalid reply credit.
    pub(crate) fn reserve_construction_reply(
        &self,
        cursor: u64,
    ) -> Result<NativeAdministrativeReplyCredit, NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.reserve_construction_reply(cursor)?)
    }

    /// Consumes credit only while holding the actual original mailbox ledger.
    ///
    /// # Errors
    /// Refuses missing credit, poisoned custody, changed correlation or bytes.
    pub(crate) fn retain_construction_reply(
        &self,
        credit: &mut Option<NativeAdministrativeReplyCredit>,
        frame: &NativeFrame,
    ) -> Result<(), NativeAdministrativeInboxError> {
        let mut mailbox = self.try_mailbox()?;
        let credit = credit.take().ok_or(NativeAdministrativeInboxError::Busy)?;
        Ok(mailbox.retain_reply(credit, frame)?)
    }

    /// Retains an independently authenticated original reply before socket publication.
    ///
    /// # Errors
    /// Refuses foreign credit, mismatched original correlation or changed reply.
    pub(crate) fn retain_reply(
        &self,
        credit: NativeAdministrativeReplyCredit,
        reply: &NativeFrame,
    ) -> Result<(), NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.retain_reply(credit, reply)?)
    }

    /// Sends only bytes already retained as this original request's response.
    ///
    /// # Errors
    /// Refuses absent history, busy custody or physical socket failure.
    pub(crate) fn send_reply(&self, cursor: u64) -> Result<bool, NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.send_reply(cursor)?)
    }

    /// Publishes only the unchanged historical reply for an original query.
    ///
    /// Reservation validation, cached-byte comparison and publication share the
    /// actual mailbox lock. Contention and socket backpressure leave that same
    /// original pending; no second request is received by this operation.
    ///
    /// # Errors
    /// Refuses busy/poisoned custody, changed correlation or transport failure.
    pub(crate) fn reply_administration(
        &self,
        cursor: u64,
        reply: &NativeFrame,
    ) -> Result<bool, NativeAdministrativeInboxError> {
        Ok(self.try_mailbox()?.reply_administration(cursor, reply)?)
    }

    /// Holds the original ledger for contention and poison tests.
    ///
    /// # Panics
    /// Panics when the test ledger is already poisoned.
    #[cfg(test)]
    // crucible-lint: allow rust-allow -- This private test helper deliberately panics when ledger custody is poisoned.
    // crucible-lint: allow panic-shortcut -- Child tests hold this exact ledger to verify contention and poison refusal.
    #[allow(clippy::unwrap_used)]
    pub(super) fn test_hold_mailbox(&self) -> MutexGuard<'_, NativeAdministrativeMailbox> {
        self.mailbox.lock().unwrap()
    }

    fn try_mailbox(
        &self,
    ) -> Result<MutexGuard<'_, NativeAdministrativeMailbox>, NativeAdministrativeInboxError> {
        self.mailbox.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => NativeAdministrativeInboxError::Busy,
            std::sync::TryLockError::Poisoned(_) => NativeAdministrativeInboxError::Poisoned,
        })
    }
}
