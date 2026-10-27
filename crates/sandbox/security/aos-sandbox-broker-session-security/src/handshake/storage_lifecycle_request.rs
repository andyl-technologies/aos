//! Paid request receipt on the same retained Storage Session and original.
//!
//! The existing owning raw/admission/CAS reducer remains the sole engine. This
//! owner pays its actual current-history and finite wire operation before raw
//! receive, keeps every reached Result, and never dispatches a domain effect.

use super::*;
use super::output_registration_continuation::OriginalOutputServerReceiptV1;
use aos_sandbox_controller_domain::{StorageLifecycleSessionLoanV1, StorageReceivingClosedV1};
use aos_sandbox_model::ResourceVector;

mod execution_availability;

pub(crate) struct StorageLifecycleRequestOriginalV1 {
    receipt: OriginalOutputServerReceiptV1,
    demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    flight: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    flight_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    resident_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    before: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    post_arm: Option<Result<(), StorageReceivingClosedV1>>,
    after_receiving: Option<Result<(), StorageReceivingClosedV1>>,
    after_endpoint: Option<Result<(), BrokerSessionSecurityError>>,
    after_clock: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    entered: bool,
    completed: bool,
}

impl StorageLifecycleRequestOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            receipt: OriginalOutputServerReceiptV1::empty(),
            demand: None,
            flight: None,
            flight_reservation: None,
            resident_reservation: None,
            before: None,
            post_arm: None,
            after_receiving: None,
            after_endpoint: None,
            after_clock: None,
            entered: false,
            completed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.before { return Some(error); }
        if let Some(Err(error)) = &self.post_arm { return Some(error); }
        if let Some(Err(error)) = &self.demand { return Some(error); }
        if let Some(Err(error)) = &self.flight { return Some(error); }
        if let Some(Err(error)) = &self.flight_reservation { return Some(error); }
        if let Some(Err(error)) = &self.resident_reservation { return Some(error); }
        if let Some(error) = self.receipt.failure() { return Some(error); }
        if let Some(Err(error)) = &self.after_receiving { return Some(error); }
        if let Some(Err(error)) = &self.after_endpoint { return Some(error); }
        self.after_clock.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &dyn std::error::Error)
    }

    pub(crate) fn receive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
        terminal: Option<&crate::recovery::RetainedStorageTerminalV1>,
    ) {
        if self.entered { return; }
        self.entered = true;
        self.before = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if matches!(self.before, Some(Ok(()))) {
            self.post_arm = Some(session.arm_storage_request_post_v1(receiving));
            if matches!(self.post_arm, Some(Ok(()))) {
                self.receive_paid(session, receiving, deadline, terminal);
            }
        }

        // Available required posts execute independently after every primary
        // result. The actual raw/admission/target stays in receipt on failure.
        self.after_receiving = Some(if matches!(self.post_arm, Some(Ok(()))) {
            // This pending sample was paid before the reservation/raw interval.
            // It executes directly even if its primary ledger/receiver closed.
            session.finish_storage_operation_post_v1(receiving)
        } else {
            match session.owner.retained_storage_journal_v1() {
                Ok(journal) => receiving.require_current_v1(journal, &session.socket),
                Err(_) => Err(StorageReceivingClosedV1),
            }
        });
        self.after_endpoint = Some(session.owner.revalidate_storage_lifecycle_transport_v2(
            &session.transcript, session.socket.peer(), receiving,
        ));
        self.after_clock = Some(crate::dormant_handshake::check_production_deadline(deadline));
        self.completed = self.failure().is_none()
            && self.receipt.has_completed_admission_v1()
            && matches!(self.after_receiving, Some(Ok(())))
            && matches!(self.after_endpoint, Some(Ok(())))
            && matches!(self.after_clock, Some(Ok(())));
    }

    fn receive_paid(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
        terminal: Option<&crate::recovery::RetainedStorageTerminalV1>,
    ) {
        self.demand = Some((|| {
            let journal = session.owner.retained_storage_journal_v1()?;
            let extent = receiving.observe_current_session_extent_v1(journal, &session.socket)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let demand = session.owner.retained_storage_request_demand_v1(extent)?;
            match terminal {
                Some(terminal) => demand.checked_add(
                    session.owner.retained_storage_terminal_demand_v1(extent, terminal)?,
                ).map_err(|_| BrokerSessionSecurityError::Currentness),
                None => Ok(demand),
            }
        })());
        let Some(demand) = self.demand.as_ref().and_then(|result| result.as_ref().ok()).copied() else { return; };
        self.flight = Some(session.owner.retained_storage_operation_demand_v1(&session.transcript));
        let Some(flight) = self.flight.as_ref().and_then(|result| result.as_ref().ok()).copied() else { return; };
        let journal = match session.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(_) => return,
        };
        self.flight_reservation = Some(receiving.reserve_operation_flight_v1(
            journal, &session.socket, flight,
        ));
        if !matches!(self.flight_reservation, Some(Ok(()))) { return; }
        self.resident_reservation = Some(receiving.reserve_request_v1(
            journal, &session.socket, demand,
        ));
        if !matches!(self.resident_reservation, Some(Ok(()))) { return; }
        self.receipt.receive_storage_lifecycle_once_v1(session, deadline, receiving, demand);
    }

    pub(crate) fn transport_post_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receipt.replay_transport_failure_v1()
    }

    pub(crate) fn completed_receipt(
        &mut self,
    ) -> Option<&mut OriginalOutputServerReceiptV1> {
        self.completed.then_some(&mut self.receipt)
    }
}
