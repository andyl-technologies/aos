//! One permanently paid Session wire peak with exclusive actual flight loans.
//!
//! HELLO and request/reply are sequential uses of the same original service
//! capacity. Resident/history debt remains separate. Each begin consumes all22
//! dimensions in a fresh noncopy operation; only actual upper disposal followed
//! by infallible completion permits another begin. No ledger charge is refunded.

use super::*;
use crate::controller_resource_reservation::component_receiving::{
    complete_bound_delta_v1, ComponentReceivingOwnedOperationV1,
};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, SeqpacketSocket, StorageSeqpacketSendAttemptV1,
    StorageSeqpacketSessionOriginV1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum WirePurpose {
    InitialHello,
    RetainedHello,
    Request,
}

#[derive(Clone, Copy)]
enum WireFailure {
    Growth,
    Reservation,
    Operation,
    Origin,
    Socket,
    Sent,
    SentBinding,
}

pub(super) struct SessionWireOriginalV1 {
    capacity: ResourceVector,
    growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_model::AccountingError>>,
    reservation: Option<Result<(), aos_sandbox_model::AccountingError>>,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    purpose: Option<WirePurpose>,
    initial_entered: bool,
    initial_complete: bool,
    initial_disposal_entered: bool,
    origin: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    socket_current: Option<Result<(), RecordBindingError>>,
    pub(super) sent: Option<StorageSeqpacketSendAttemptV1>,
    sent_binding: Option<Result<(), RecordBindingError>>,
    first: Option<WireFailure>,
}

impl SessionWireOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            capacity: ResourceVector::ZERO,
            growth: None,
            reservation: None,
            operation: None,
            purpose: None,
            initial_entered: false,
            initial_complete: false,
            initial_disposal_entered: false,
            origin: None,
            socket_current: None,
            sent: None,
            sent_binding: None,
            first: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            WireFailure::Growth => self.growth.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error),
            WireFailure::Reservation => self.reservation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error),
            WireFailure::Operation => self.operation.as_ref()
                .and_then(ComponentReceivingOwnedOperationV1::failure).map(|cause| cause as &dyn Error),
            WireFailure::Origin => self.origin.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error),
            WireFailure::Socket => self.socket_current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error),
            WireFailure::Sent => self.sent.as_ref().and_then(StorageSeqpacketSendAttemptV1::failure),
            WireFailure::SentBinding => self.sent_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error),
        }
    }

    pub(super) fn is_between_flights_v1(&self) -> bool {
        self.first.is_none() && self.operation.is_none() && self.purpose.is_none()
    }

    pub(super) fn initial_is_complete_v1(&self) -> bool {
        self.initial_complete && self.initial_disposal_entered && self.is_between_flights_v1()
    }

    pub(super) fn is_current(&self, purpose: WirePurpose) -> bool {
        self.first.is_none() && self.purpose == Some(purpose)
            && (purpose != WirePurpose::InitialHello || !self.initial_disposal_entered)
            && self.operation.as_ref().is_some_and(ComponentReceivingOwnedOperationV1::is_consumed_current)
    }

    fn begin(
        &mut self,
        ledger: &mut ComponentServiceReceivingLedgerV1,
        socket: &SeqpacketSocket,
        purpose: WirePurpose,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.first.is_some() || self.operation.is_some() || self.purpose.is_some()
            || (purpose == WirePurpose::InitialHello && self.initial_entered)
            || (purpose != WirePurpose::InitialHello && !self.initial_complete)
        {
            return Err(StorageReceivingClosedV1);
        }
        if purpose == WirePurpose::InitialHello {
            self.initial_entered = true;
        }
        self.purpose = Some(purpose);
        self.growth = Some(complete_bound_delta_v1(self.capacity, demand));
        let Some(Ok((capacity, delta))) = self.growth.as_ref().copied() else {
            self.first.get_or_insert(WireFailure::Growth);
            return Err(StorageReceivingClosedV1);
        };
        self.reservation = Some(ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(self.reservation, Some(Ok(()))) {
            self.first.get_or_insert(WireFailure::Reservation);
            return Err(StorageReceivingClosedV1);
        }
        self.capacity = capacity;
        self.operation = Some(ComponentReceivingOwnedOperationV1::preflight(capacity, demand));
        let Some(operation) = self.operation.as_mut() else { std::process::abort() };
        if operation.consume_once().is_err() {
            self.first.get_or_insert(WireFailure::Operation);
            return Err(StorageReceivingClosedV1);
        }
        self.origin = Some(socket.capture_storage_session_origin_v1());
        if !matches!(self.origin, Some(Ok(_))) {
            self.first.get_or_insert(WireFailure::Origin);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn require_socket(&mut self, socket: &SeqpacketSocket) -> Result<(), StorageReceivingClosedV1> {
        let Some(Ok(origin)) = self.origin.as_ref() else { return Err(StorageReceivingClosedV1) };
        self.socket_current = Some(origin.require_same_socket(socket));
        if !matches!(self.socket_current, Some(Ok(()))) {
            self.first.get_or_insert(WireFailure::Socket);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    fn park_initial_sent(
        &mut self,
        sent: StorageSeqpacketSendAttemptV1,
    ) -> Result<(), StorageSessionHelloDisposalErrorV1> {
        if !self.is_current(WirePurpose::InitialHello) {
            return Err(StorageSessionHelloDisposalErrorV1 { rejected: Some(sent) });
        }
        // Arm before moving any offered receipt. Even forgetting a prepared
        // token leaves the original noncurrent and cannot overwrite this Sent.
        self.initial_disposal_entered = true;
        self.sent = Some(sent);
        Ok(())
    }

    pub(super) fn observe_sent(&mut self, socket: &SeqpacketSocket) -> bool {
        let positive = self.sent.as_ref().is_some_and(StorageSeqpacketSendAttemptV1::is_sent);
        self.sent_binding = self.sent.as_ref().map(|sent| sent.require_same_socket(socket));
        let bound = matches!(self.sent_binding, Some(Ok(())));
        if !positive {
            self.first.get_or_insert(WireFailure::Sent);
        } else if !bound {
            self.first.get_or_insert(WireFailure::SentBinding);
        }
        positive && bound
    }

    pub(super) fn complete(&mut self) {
        if self.purpose == Some(WirePurpose::InitialHello) {
            self.initial_complete = true;
        }
        let Some(operation) = self.operation.take() else { std::process::abort() };
        operation.complete_after_disposal();
        self.purpose = None;
    }
}

impl StorageReceivingOriginalV1 {
    pub(super) fn begin_session_wire_v1(
        &mut self,
        socket: &SeqpacketSocket,
        purpose: WirePurpose,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.session_wire.begin(&mut self.ledger, socket, purpose, demand)
    }
}

/// Owns a rejected HELLO receipt without replacing an earlier original cause.
#[derive(Debug)]
pub struct StorageSessionHelloDisposalErrorV1 {
    rejected: Option<StorageSeqpacketSendAttemptV1>,
}

impl std::fmt::Display for StorageSessionHelloDisposalErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the original Storage HELLO disposition is closed")
    }
}

impl Error for StorageSessionHelloDisposalErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.rejected.as_ref().and_then(StorageSeqpacketSendAttemptV1::failure)
    }
}

/// Keeps the actual initial Native facade borrowed through positive HELLO cleanup.
///
/// All fallible upper and Native checks precede this token. The private upper
/// consumer disposes only its successful raw/control copies, then completes
/// this token. Forgetting it blocks reuse; unfinished Drop closes the original
/// and leaves the whole actual facade in its original slot.
#[must_use]
pub struct StorageInitialSessionHelloDisposalV1<'phase, 'original> {
    receiving: &'phase mut StoragePrepareReceivingLoanV1<'original>,
    opening: &'phase mut StorageBrokerCapturedJournalOpenV1,
    completed: bool,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Consumes HELLO wire capacity on the original payer after actual acceptance.
    ///
    /// The socket is already owned and its fixed carrier has already been paid.
    /// This method runs before publication, raw HELLO or canonical model growth;
    /// an idle listener poll creates no wire operation.
    ///
    /// # Errors
    /// Refuses repeat entry, an unavailable fixed original, budget exhaustion or
    /// socket binding failure. The actual reservation and binding stay resident.
    pub fn reserve_initial_session_hello_once_v1(
        &mut self,
        socket: &SeqpacketSocket,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_session_fixed_current_v1()?;
        let action = self.receiving()?.begin_session_wire_v1(socket, WirePurpose::InitialHello, demand);
        let post = self.original.recheck();
        if action.is_err() {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut() {
                receiving.first = Some(Failure::SessionWire);
            }
        }
        if action.is_err() || post.is_err() { Err(StorageReceivingClosedV1) } else { Ok(()) }
    }

    /// Rechecks the same accepted socket and genuine original throughout HELLO.
    ///
    /// # Errors
    /// Refuses an unpaid or closed interval, another socket or original failure.
    pub fn require_initial_session_hello_current_v1(
        &mut self,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.session_wire.is_current(WirePurpose::InitialHello) {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let action = receiving.session_wire.require_socket(socket);
        let post = self.original.recheck();
        if action.is_err() {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut() {
                receiving.first = Some(Failure::SessionWire);
            }
        }
        if action.is_err() || post.is_err() { Err(StorageReceivingClosedV1) } else { Ok(()) }
    }

    /// Checks joint HELLO/native-opening completion while every original is held.
    ///
    /// The actual Journal stays in Security's Session. This borrows the SAME
    /// taken facade joined during paid replay, and parks the actual final Sent
    /// receipt before every fallible check. It does not initialize a request.
    ///
    /// # Errors
    /// Retains any rejected new receipt in the owning error; otherwise it parks
    /// the receipt on the original. Refuses wrong facade, Journal/socket change,
    /// unfinished send, native currentness debt or prior failure.
    pub fn prepare_initial_session_hello_disposal_v1<'phase>(
        &'phase mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        opening: &'phase mut StorageBrokerCapturedJournalOpenV1,
        sent: StorageSeqpacketSendAttemptV1,
    ) -> Result<StorageInitialSessionHelloDisposalV1<'phase, 'original>, StorageSessionHelloDisposalErrorV1> {
        let admission = match self.receiving() {
            Ok(receiving) => receiving.session_wire.park_initial_sent(sent),
            Err(_) => Err(StorageSessionHelloDisposalErrorV1 { rejected: Some(sent) }),
        };
        if let Err(cause) = admission {
            // The Cold owner prepaid this same post before offering Sent.
            // Keep the owning rejected receipt and earlier first cause while
            // the already entered observation completes independently.
            let _ = self.post_session_journal_observation_v1();
            return Err(cause);
        }
        let receiving = match self.receiving() {
            Ok(receiving) => receiving,
            Err(_) => std::process::abort(),
        };
        let sent_positive = receiving.session_wire.observe_sent(socket);
        let socket_current = receiving.session_wire.require_socket(socket);
        let identity = receiving.session_identity.as_ref().is_some_and(|owner| owner.same_journal(journal));
        let names_positive = receiving.session_journal.observe(journal);
        // This fresh original check is independently owed even on Sent failure.
        let native_ready = self.native_opening_ready_v1(
            NativeOpeningKindV1::Session, opening.was_taken_positive_v1(), opening.opening_owner_link_v1(),
        );
        let native = self.post_session_journal_observation_v1();
        if !sent_positive || socket_current.is_err() || !identity || !names_positive || !native_ready {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut() {
                receiving.first = Some(if !sent_positive || socket_current.is_err() || !identity {
                    Failure::SessionWire
                } else {
                    Failure::SessionJournal
                });
            }
        }
        if !sent_positive || socket_current.is_err() || !identity || !names_positive || !native_ready || native.is_err() {
            return Err(StorageSessionHelloDisposalErrorV1 { rejected: None });
        }
        Ok(StorageInitialSessionHelloDisposalV1 { receiving: self, opening, completed: false })
    }
}

impl StorageInitialSessionHelloDisposalV1<'_, '_> {
    /// Completes after actual upper control disposal without further fallible work.
    pub fn complete_after_disposal_v1(mut self) {
        drop(std::mem::take(self.opening));
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.receiving.original.recipient.as_mut() else {
            std::process::abort();
        };
        receiving.native_opening_peak.active = None;
        receiving.native_opening_peak.owner_link = None;
        // All fallible joint posts preceded this token. Dispose this exact
        // positive local sample only after upper control disposal is complete.
        receiving.session_journal.settle_positive();
        receiving.session_wire.complete();
        self.completed = true;
    }
}

impl Drop for StorageInitialSessionHelloDisposalV1<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.receiving.original.recipient.as_mut() {
                receiving.first.get_or_insert(Failure::Closed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket() -> (SeqpacketSocket, std::os::fd::OwnedFd) {
        SeqpacketSocket::pair_with_record_subjects().unwrap()
    }

    fn wire(network: u64, output: u64) -> ResourceVector {
        ResourceVector::ZERO.with(D::NetworkBytes, network)
            .with(D::OutputBytes, output).with(D::ConcurrentOperations, 1)
    }

    #[test]
    fn an_idle_original_cannot_begin_a_warm_flight_without_initial_closure() {
        let (socket, _peer) = socket();
        let demand = wire(131_136, 65_600);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        let mut original = SessionWireOriginalV1::new();

        assert!(original.begin(&mut ledger, &socket, WirePurpose::RetainedHello, demand).is_err());
        assert_eq!(ledger.charged(), ResourceVector::ZERO);
        assert!(original.operation.is_none());
    }

    #[test]
    fn ownership_handoff_keeps_real_wire_debt_and_initial_once_flags() {
        let (socket, _peer) = socket();
        let demand = wire(131_136, 65_600);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        let mut original = SessionWireOriginalV1::new();

        assert!(original.is_between_flights_v1());
        original.begin(&mut ledger, &socket, WirePurpose::InitialHello, demand).unwrap();
        assert!(!original.is_between_flights_v1());
        assert!(!original.initial_is_complete_v1());

        // Only the real positive token publishes these in production. This
        // private accounting test establishes that parking neither refunds the
        // shared capacity nor makes InitialHello usable a second time.
        original.initial_disposal_entered = true;
        original.complete();
        assert!(original.is_between_flights_v1());
        assert!(original.initial_is_complete_v1());
        assert_eq!(ledger.charged(), demand);
        assert!(original.require_socket(&socket).is_ok());
        assert!(original.begin(&mut ledger, &socket, WirePurpose::InitialHello, demand).is_err());
        assert_eq!(ledger.charged(), demand);
    }

    #[test]
    fn an_active_hello_excludes_another_flight_and_cannot_reenter_initially() {
        let (socket, _peer) = socket();
        let demand = wire(131_136, 65_600);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        let mut original = SessionWireOriginalV1::new();
        original.begin(&mut ledger, &socket, WirePurpose::InitialHello, demand).unwrap();

        assert!(original.begin(&mut ledger, &socket, WirePurpose::Request, demand).is_err());
        assert!(original.is_current(WirePurpose::InitialHello));
        assert_eq!(ledger.charged(), demand);

        // This unit test exercises private accounting DATA. Only the actual
        // checked positive-disposal tokens call complete in production.
        original.complete();
        assert!(original.begin(&mut ledger, &socket, WirePurpose::InitialHello, demand).is_err());
        assert_eq!(ledger.charged(), demand);
    }

    #[test]
    fn sequential_larger_requests_charge_only_permanent_capacity_growth() {
        let (socket, _peer) = socket();
        let resident = ResourceVector::ZERO.with(D::MemoryBytes, 4096);
        let hello = wire(131_136, 65_600);
        let request = wire(2_097_152, 1_048_576);
        let ceiling = resident.checked_add(request).unwrap();
        let mut ledger = ComponentServiceReceivingLedgerV1::new(ceiling);
        ledger.reserve(resident).unwrap();
        let mut original = SessionWireOriginalV1::new();
        original.begin(&mut ledger, &socket, WirePurpose::InitialHello, hello).unwrap();
        original.complete();

        original.begin(&mut ledger, &socket, WirePurpose::Request, request).unwrap();
        assert!(original.is_current(WirePurpose::Request));
        assert_eq!(ledger.charged(), ceiling);
        original.complete();
        original.begin(&mut ledger, &socket, WirePurpose::RetainedHello, hello).unwrap();

        assert_eq!(ledger.charged(), ceiling);
        assert_eq!(ledger.remaining().unwrap(), ResourceVector::ZERO);
    }

    #[test]
    fn refused_growth_keeps_resident_debt_and_the_actual_accounting_cause() {
        let (socket, _peer) = socket();
        let resident = ResourceVector::ZERO.with(D::MemoryBytes, 4096);
        let demand = wire(131_136, 65_600);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(resident);
        ledger.reserve(resident).unwrap();
        let mut original = SessionWireOriginalV1::new();

        assert!(original.begin(&mut ledger, &socket, WirePurpose::InitialHello, demand).is_err());
        assert!(original.failure().is_some());
        assert_eq!(ledger.charged(), resident);
        assert!(original.origin.is_none());
        assert!(original.begin(&mut ledger, &socket, WirePurpose::InitialHello, ResourceVector::ZERO).is_err());
        assert_eq!(ledger.charged(), resident);
    }

    #[test]
    fn an_actual_different_socket_is_not_the_paid_flight_origin() {
        let (first, _first_peer) = socket();
        let (second, _second_peer) = socket();
        let demand = wire(131_136, 65_600);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        let mut original = SessionWireOriginalV1::new();
        original.begin(&mut ledger, &first, WirePurpose::InitialHello, demand).unwrap();

        assert!(original.require_socket(&first).is_ok());
        assert!(original.require_socket(&second).is_err());
        assert!(original.failure().is_some());
        assert!(!original.is_current(WirePurpose::InitialHello));
        assert_eq!(ledger.charged(), demand);
    }

    #[test]
    fn a_parked_initial_disposition_refuses_replacement_and_owns_the_offer() {
        let (first, _first_peer) = socket();
        let (second, _second_peer) = socket();
        let demand = wire(131_136, 65_600);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        let mut original = SessionWireOriginalV1::new();
        original.begin(&mut ledger, &first, WirePurpose::InitialHello, demand).unwrap();
        let mut first = first;
        let first_sent = first.send_storage_session_retaining_v1(b"first");
        assert!(first_sent.is_sent());
        original.park_initial_sent(first_sent).unwrap();

        // This is the persistent state after a prepared token is forgotten:
        // its borrow can end, while its actual first receipt remains parked.
        assert!(!original.is_current(WirePurpose::InitialHello));
        let mut second = second;
        let second_sent = second.send_storage_session_retaining_v1(b"second");
        assert!(second_sent.is_sent());
        let refused = original.park_initial_sent(second_sent).unwrap_err();

        assert!(original.sent.as_ref().unwrap().require_same_socket(&first).is_ok());
        assert!(original.sent.as_ref().unwrap().require_same_socket(&second).is_err());
        assert!(refused.rejected.as_ref().unwrap().require_same_socket(&second).is_ok());
        assert_eq!(ledger.charged(), demand);
    }

}
