//! Keeps original Controller and authenticated session custody across FUSE intent.
//!
//! Purpose 57 is signed only from a genuine fixed Controller writer borrow.
//! The existing Broker Session owner chooses the request identity, signs the
//! exact packet, and durably installs RequestPrepared before any send. This
//! closed composition does not advertise method 44 or turn a reply/digest into
//! a live Mount worker or Root resource-read guard.

use aos_sandbox::attachment_effect_owner::CurrentControllerFuseIntentDispatchV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantOutstandingBrokerRequestV1,
};

/// Retains real writers and every durable/transport ambiguity disposition.
///
/// No public constructor or detached prepared-packet getter is provided. A
/// future actual Mount continuation must borrow this flight together with its
/// independently authenticated physical reservation/Host/channel owners.
#[must_use = "retain original Controller/session custody until exact reconciliation"]
pub(crate) struct ControllerFuseIntentPendingFlightV1<'controller, 'session> {
    controller: CurrentControllerFuseIntentDispatchV1<'controller>,
    session: &'session mut DormantAuthenticatedBrokerSessionV1,
    original: AuthenticatedBrokerMethodRequestV1,
    state: FlightState,
}

enum FlightState {
    Prepared(DormantBrokerRequestPreparationV1),
    Transport(DormantBrokerRequestSendProgressV1),
    /// Retains the original sent custody; preparation cannot be reentered.
    Preparation(DormantOutstandingBrokerRequestV1),
    /// The signed RequestPrepared remains in the held journal; no reissue is allowed.
    ReconciliationRequired,
}

impl<'controller, 'session> ControllerFuseIntentPendingFlightV1<'controller, 'session> {
    /// Issues the exact Host grant only on this already-held original Mount flight.
    ///
    /// The real per-record Mount control and complete sealed plan remain joined
    /// to the original reservation ACK. No Host callback reacquires Controller.
    pub(crate) fn issue_original_host_worker<T>(
        &mut self,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) -> Result<(), BrokerSessionSecurityError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.with_preparation_custody(clock, |controller, transport, clock| {
            transport
                .issue_original_host_worker(controller, signer, clock)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })
    }

    /// Keeps local issuance inside the already-held Controller/session cut.
    ///
    /// The callback receives real borrows, not reconstructed wire facts. It
    /// must additionally join genuine Mount custody before Host-purpose-56
    /// issuance; Host must not call back into this held Controller writer.
    /// The original challenge/query is driven once before the callback. An
    /// error or return retains its sent custody for exact reconciliation; it
    /// cannot restart the preparation challenge on the same pending request.
    pub(crate) fn with_preparation_custody<T, F, R>(
        &mut self,
        clock: &mut T,
        action: F,
    ) -> Result<R, BrokerSessionSecurityError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
        F: FnOnce(
            &mut CurrentControllerFuseIntentDispatchV1<'controller>,
            &mut crate::handshake::fuse_intent_continuation::HeldFuseIntentTransportV1<'_>,
            &mut T,
        ) -> Result<R, BrokerSessionSecurityError>,
    {
        self.controller
            .recheck(clock)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let original = std::mem::replace(&mut self.state, FlightState::ReconciliationRequired);
        self.state = match original {
            FlightState::Transport(DormantBrokerRequestSendProgressV1::Sent(sent)) => {
                FlightState::Preparation(sent)
            }
            other => {
                self.state = other;
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        let mut transport = self.session.hold_fuse_intent_transport(&self.original)?;
        transport
            .complete_original_host_query(&mut self.controller, clock)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let result = action(&mut self.controller, &mut transport, clock);
        transport.recheck()?;
        drop(transport);
        self.controller
            .recheck(clock)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        result
    }

    /// Signs and durably prepares while retaining both original owners.
    pub(crate) fn prepare<T>(
        mut controller: CurrentControllerFuseIntentDispatchV1<'controller>,
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) -> Result<Self, BrokerSessionSecurityError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let signed = signer
            .sign_mount_fuse_intent(&mut controller, clock)
            .map_err(|_| BrokerSessionSecurityError::manifest("held FUSE Controller signing"))?;
        let packet = controller
            .authorized_packet_at(&signed, clock)
            .map_err(|_| BrokerSessionSecurityError::manifest("held FUSE ownership rebind"))?;
        controller.recheck(clock).map_err(|_| {
            BrokerSessionSecurityError::manifest("held FUSE pre-prepare currentness")
        })?;
        let preparation =
            session.prepare_authenticated_fuse_intent_request(&packet, controller.request())?;
        let original = preparation.signed_request().clone();
        // Do not discard a recovery-bearing result if the Controller's short
        // observation expires after commit. The next guarded send refuses it,
        // while this flight still retains the exact durable preparation.
        Ok(Self {
            controller,
            session,
            original,
            state: FlightState::Prepared(preparation),
        })
    }

    /// Sends only a durably confirmed exact request while Controller remains held.
    ///
    /// Backpressure retains the original packet. Uncertain commit or transport
    /// states never rebuild a plan, renew a request or release a reservation.
    pub(crate) fn send<T>(&mut self, clock: &mut T) -> Result<(), BrokerSessionSecurityError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.controller
            .recheck(clock)
            .map_err(|_| BrokerSessionSecurityError::manifest("held FUSE pre-send currentness"))?;
        if self.original.exact_body() != self.controller.request_body()
            || self.original.semantic_commitment()
                != *self.controller.semantics().commitment().digest().as_bytes()
        {
            return Err(BrokerSessionSecurityError::manifest(
                "FUSE original pending packet changed",
            ));
        }
        let original = std::mem::replace(&mut self.state, FlightState::ReconciliationRequired);
        let prepared = match original {
            FlightState::Prepared(DormantBrokerRequestPreparationV1::Prepared(prepared))
            | FlightState::Transport(DormantBrokerRequestSendProgressV1::Pending(prepared)) => {
                prepared
            }
            other => {
                self.state = other;
                return Err(BrokerSessionSecurityError::manifest(
                    "FUSE pending flight is not sendable",
                ));
            }
        };
        match self.session.send_authenticated_request(prepared) {
            Ok(progress) => {
                self.state = FlightState::Transport(progress);
                Ok(())
            }
            Err(_) => Err(BrokerSessionSecurityError::manifest(
                "FUSE transport requires exact reconciliation",
            )),
        }
    }
}
