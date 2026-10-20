//! Waits on only the actual original Inventory flight's retained pending state.
//!
//! Every poll uses the same immutable cutoff and the same genuine before/after
//! currentness destinations as other turns. A failed capsule stays resident;
//! a complete positive capsule drops before the infallible phase reuse.

use super::*;
use crate::dormant_handshake::HandshakeReadinessOriginalsV1;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use super::super::storage_io::{NativeStorageIoV1, NativeStorageIoDisposalV1};

#[derive(Clone, Copy)]
enum WaitSite {
    Send,
    Receive,
}

pub(in crate::handshake::output_registration_continuation) struct InventoryWaitOriginalsV1<E = CreateStorageInventoryClosedV1> {
    site: Option<WaitSite>,
    before: Option<Result<(), E>>,
    deadline: Option<Result<u64, E>>,
    descriptor: Option<Result<(), SeqpacketError>>,
    native: HandshakeReadinessOriginalsV1,
    after: Option<Result<(), E>>,
    disposition: Option<Result<(), E>>,
    closed: Option<OutputPreparationClosedV1>,
}

impl<E> Default for InventoryWaitOriginalsV1<E> {
    fn default() -> Self { Self::empty() }
}

impl<E> InventoryWaitOriginalsV1<E> {
    fn empty() -> Self {
        Self {
            site: None, before: None, deadline: None, descriptor: None,
            native: HandshakeReadinessOriginalsV1::default(), after: None,
            disposition: None, closed: None,
        }
    }
}

impl<E: Error + 'static> InventoryWaitOriginalsV1<E> {
    pub(in crate::handshake::output_registration_continuation) fn arm_send(&mut self) -> bool {
        self.arm(WaitSite::Send)
    }

    pub(in crate::handshake::output_registration_continuation) fn arm_receive(&mut self) -> bool {
        self.arm(WaitSite::Receive)
    }

    fn arm(&mut self, site: WaitSite) -> bool {
        if self.site.is_some() || self.before.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(OutputPreparationClosedV1);
            return false;
        }

        self.site = Some(site);
        true
    }

    pub(in crate::handshake::output_registration_continuation) fn is_pending(&self) -> bool {
        self.site.is_some() || self.closed.is_some()
    }

    pub(in crate::handshake::output_registration_continuation) fn receiving_construction_bytes_v1() -> Option<usize> {
        // The resident capsule is embedded in the flight. Positive disposal
        // additionally constructs its replacement and the taken poll capsule.
        size_of::<Self>()
            .checked_add(size_of::<HandshakeReadinessOriginalsV1>())?
            .checked_add(HandshakeReadinessOriginalsV1::receiving_construction_bytes_v1()?)
    }

    pub(in crate::handshake::output_registration_continuation) fn failure_with_native<'a>(
        &'a self,
        native: Option<&'a (dyn Error + 'static)>,
    ) -> Option<&'a (dyn Error + 'static)> {
        self.before.as_ref().and_then(|result| result.as_ref().err())
            .map(|marker| native.unwrap_or(marker))
            .or_else(|| self.deadline.as_ref().and_then(|result| result.as_ref().err())
                .map(|marker| native.unwrap_or(marker)))
            .or_else(|| self.descriptor.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.native.failure())
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err())
                .map(|marker| native.unwrap_or(marker)))
            .or_else(|| self.disposition.as_ref().and_then(|result| result.as_ref().err())
                .map(|marker| native.unwrap_or(marker)))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl OriginalStorageInventoryClientFlightV1 {
    pub(crate) fn wait_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> bool {
        if self.completed {
            self.wait.closed.get_or_insert(OutputPreparationClosedV1);
            self.shared.inner.closed = true;
            return false;
        }
        self.wait.wait_original_once(session, &mut self.shared.inner, original)
    }
}

impl<E: Error + 'static> InventoryWaitOriginalsV1<E> {
    pub(in crate::handshake::output_registration_continuation) fn wait_original_once<N: NativeStorageIoV1<Failure = E>>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        flight: &mut OriginalOutputClientFlightV1,
        original: &mut N,
    ) -> bool {
        if flight.closed || self.before.is_some() {
            self.closed.get_or_insert(OutputPreparationClosedV1);
            flight.closed = true;
            return false;
        }

        let wants_write = match self.site {
            Some(WaitSite::Send) => true,
            Some(WaitSite::Receive) => false,
            None => {
                self.closed.get_or_insert(OutputPreparationClosedV1);
                flight.closed = true;
                return false;
            }
        };

        self.before = Some(match original.session_journal_v1(&session.owner) {
            Ok(journal) => original.begin_wait_once(journal, &session.socket, &session.transcript, wants_write),
            Err(cause) => {
                flight.protected_failure.get_or_insert(cause);
                Err(N::closed())
            }
        });

        if matches!(self.before, Some(Ok(()))) {
            self.deadline = Some(original.original_cutoff_data_v1());
            if let Some(cutoff) = self.deadline.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
            {
                match session.socket.as_fd() {
                    Ok(descriptor) => {
                        self.descriptor = Some(Ok(()));
                        self.native.observe_once(descriptor, wants_write, cutoff);
                    }
                    Err(cause) => self.descriptor = Some(Err(cause)),
                }
            }
        }

        if matches!(self.before, Some(Ok(())))
            && (!matches!(self.deadline, Some(Ok(_)))
                || !matches!(self.descriptor, Some(Ok(()))) || !self.native.require_positive())
        {
            original.mark_sdk_primary_before_post_v1();
        }

        // An entered before observation always owns its independent after
        // destination, including when the poll or its earlier sample refused.
        self.after = Some(flight.observe_storage_io_post_v1(session, original));
        if !matches!(self.before, Some(Ok(())))
            || !matches!(self.deadline, Some(Ok(_)))
            || !matches!(self.descriptor, Some(Ok(())))
            || !self.native.require_positive()
            || !matches!(self.after, Some(Ok(()))) {
            flight.closed = true;
            return false;
        }

        let disposition = match original.prepare_positive_wait_disposal_once() {
            Ok(disposition) => {
                self.disposition = Some(Ok(()));
                disposition
            }
            Err(cause) => {
                self.disposition = Some(Err(cause));
                flight.closed = true;
                return false;
            }
        };

        // Both real posts and the exact poll classification are complete.
        // Physically dispose the original capsule before infallible peak reuse.
        drop(std::mem::take(&mut self.native));
        disposition.complete_after_wait_disposal();
        *self = InventoryWaitOriginalsV1::empty();
        true
    }
}
