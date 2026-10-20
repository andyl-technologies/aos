//! Holds a genuine fixed-service response through durable commit and native send.
//!
//! The domain observation, original admitted request and actual Session remain
//! co-live. Signing/CAS and retained native send use their existing engines;
//! the caller still owes its independent Session and fixed-service afters.

use super::*;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use super::fixed_service::FixedServiceRequestOriginalV4;
use aos_sandbox_broker::receiving::{FixedServiceOperationClosedV4,
    MountAttachmentAnchorReceivingLoanV4 as Loan};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use crate::recovery::FixedServiceTerminalCurrentOriginalV4;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Eq, PartialEq)]
struct NetworkResponseBindingV5 {
    request: [u8; 16],
    signed_request: [u8; 32],
    session: [u8; 32],
    body: [u8; 32],
    bytes: usize,
}

impl NetworkResponseBindingV5 {
    fn new(request: &AuthenticatedBrokerMethodRequestV1, body: &[u8]) -> Self {
        Self {
            request: request.request_id(),
            signed_request: request.signed_request_digest(),
            session: request.session_binding(),
            body: Sha256::digest(body).into(),
            bytes: body.len(),
        }
    }
}

/// Reports a refusal while the whole original response remains resident.
#[derive(Debug, thiserror::Error)]
#[error("the original fixed-service response remains closed")]
pub struct FixedServiceResponseClosedV4;

/// Reports the one entered native send without inferring remote receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedServiceResponseProgressV4 {
    /// The exact committed packet was sent and its currentness posts passed.
    Sent,
    /// Native nonconsumption left the whole response resident and unfinished.
    Pending,
    /// An actual refusal or ambiguous native prefix prevents completion.
    Closed,
}

#[derive(Clone, Copy)]
enum First { Order, Binding, Geometry, Funding, CommitClock, Commit, SendClock, BeforeSend, Send, AfterSend }

/// Retains the signed durable response and both native terminal validators.
///
/// The actual runtime prices this inert header before construction. The public
/// entry intrinsically pays its compiled native destinations, then the actual
/// enlarged history before signing/mutation, without replacing earlier debt.
pub struct FixedServiceResponseOriginalV4 {
    terminal: OriginalOutputServerTerminalV1,
    currentness: FixedServiceTerminalCurrentOriginalV4,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1, crate::recovery::FixedServiceReceivingExtentErrorV4>>,
    geometry: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    commit_clock: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    send_clock: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    native: Option<super::super::StorageResponseSendAttemptV1>,
    method: Option<BrokerMethod>,
    first: Option<First>,
    attempted_send: bool,
    network_forecast: Option<NetworkResponseBindingV5>,
    commit_entered: bool,
}

impl FixedServiceResponseOriginalV4 {
    /// Creates inert custody without signing, appending or native IO.
    #[must_use]
    pub fn new() -> Self {
        Self { terminal: OriginalOutputServerTerminalV1::empty(), currentness: Default::default(),
            metadata: None, extent: None, geometry: None, funding: None, commit_clock: None,
            send_clock: None, native: None, method: None, first: None, attempted_send: false,
            network_forecast: None, commit_entered: false }
    }

    /// Prices actual compiled carriers and retained terminal native destinations.
    ///
    /// Returns `None` on checked overflow; this passive amount grants no IO.
    #[must_use]
    pub fn fixed_receiving_demand_v4() -> Option<ResourceVector> {
        FixedServiceTerminalCurrentOriginalV4::receiving_demand_v4()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?),
        ).ok()
    }

    /// Commits the response produced only by the actual same Mount operation.
    ///
    /// # Errors
    /// Retains observation/request mismatch, original funding, clock, signing
    /// and exact durable readback refusal. A failed commit cannot be sent.
    pub fn commit_mount_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>,
        loan: &mut Loan<'_>, receipt: &FixedServiceRequestOriginalV4,
        observation: &aos_sandbox_mount::MountServiceObservationV4<'_>,
    ) -> Result<(), FixedServiceResponseClosedV4> {
        let session = &mut *session.inner;
        if self.method.is_some() || self.first.is_some() || self.attempted_send {
            self.first.get_or_insert(First::Order);
            return Err(FixedServiceResponseClosedV4);
        }
        let Some(request) = receipt.borrow_authenticated_request_v4() else {
            self.first = Some(First::Binding);
            return Err(FixedServiceResponseClosedV4);
        };
        if !matches!(request.method(), BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS)
            || observation.method_v4() != request.method() as u32
            || observation.request_id_v4() != request.request_id()
            || observation.signed_request_digest_v4() != request.signed_request_digest()
        {
            self.first = Some(First::Binding);
            return Err(FixedServiceResponseClosedV4);
        }
        self.method = Some(request.method());
        // Rejoin the intrinsically bound purpose; an unbound or different
        // interval cannot pay for this retained authenticated request.
        self.funding = Some(match request.method() {
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 => loan.require_current_v4(),
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => loan.require_inventory_current_v4(),
            _ => Err(FixedServiceOperationClosedV4::default()),
        });
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(FixedServiceResponseClosedV4);
        }
        self.commit_body(session, loan, request, observation.body_v4())
    }

    /// Commits the response produced only by the same actual Network domain operation.
    ///
    /// # Errors
    /// Retains exact observation/request/purpose mismatch, original financial
    /// or clock refusal, signing failure and durable readback refusal.
    pub fn commit_network_once_v4(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>, loan: &mut Loan<'_>,
        receipt: &FixedServiceRequestOriginalV4,
        observation: &aos_sandbox_network::NetworkServiceObservationV4<'_>,
    ) -> Result<(), FixedServiceResponseClosedV4> {
        let session = &mut *session.inner;
        if self.commit_entered || self.first.is_some() || self.attempted_send {
            self.first.get_or_insert(First::Order);
            return Err(FixedServiceResponseClosedV4);
        }
        let Some(request) = receipt.borrow_authenticated_request_v4() else {
            self.first = Some(First::Binding);
            return Err(FixedServiceResponseClosedV4);
        };
        if !matches!(request.method(), BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
            || observation.method_v4() != request.method() as u32
            || observation.request_id_v4() != request.request_id()
            || observation.signed_request_digest_v4() != request.signed_request_digest()
        {
            self.first = Some(First::Binding);
            return Err(FixedServiceResponseClosedV4);
        }
        self.method = Some(request.method());
        self.funding = Some(match request.method() {
            BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 => loan.require_network_prepare_current_v4(),
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => loan.require_network_inventory_current_v4(),
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY => loan.require_network_destroy_current_v4(),
            _ => Err(FixedServiceOperationClosedV4::default()),
        });
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(FixedServiceResponseClosedV4);
        }
        if let Some(forecast) = self.network_forecast {
            if forecast != NetworkResponseBindingV5::new(request, observation.body_v4()) {
                self.first = Some(First::Binding);
                return Err(FixedServiceResponseClosedV4);
            }
        } else {
            self.prepay_body(session, loan, request, observation.body_v4())?;
        }
        self.commit_prepaid_body(session, loan, request, observation.body_v4())
    }

    /// Prepays the exact prospective Network terminal before worker effects.
    ///
    /// The borrowed bytes remain unsigned DATA. Only a later genuine domain
    /// observation with the same admitted request and exact body can commit.
    ///
    /// # Errors
    /// Retains reentry, purpose, actual held-history geometry or same-F refusal.
    pub fn prepay_network_response_once_v5(&mut self,
        session: &mut super::super::FixedServiceSessionBorrowV4<'_>, loan: &mut Loan<'_>,
        receipt: &FixedServiceRequestOriginalV4, body: &[u8],
    ) -> Result<(), FixedServiceResponseClosedV4> {
        if self.method.is_some() || self.first.is_some() || self.attempted_send {
            self.first.get_or_insert(First::Order);
            return Err(FixedServiceResponseClosedV4);
        }
        let Some(request) = receipt.borrow_authenticated_request_v4() else {
            self.first = Some(First::Binding);
            return Err(FixedServiceResponseClosedV4);
        };
        if !matches!(request.method(), BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES) {
            self.first = Some(First::Binding);
            return Err(FixedServiceResponseClosedV4);
        }
        self.method = Some(request.method());
        self.funding = Some(loan.require_selected_network_request_v5(request));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(FixedServiceResponseClosedV4);
        }
        self.prepay_body(session.inner, loan, request, body)?;
        self.network_forecast = Some(NetworkResponseBindingV5::new(request, body));
        Ok(())
    }

    fn commit_body(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, loan: &mut Loan<'_>,
        request: &AuthenticatedBrokerMethodRequestV1, body: &[u8],
    ) -> Result<(), FixedServiceResponseClosedV4> {
        self.prepay_body(session, loan, request, body)?;
        self.commit_prepaid_body(session, loan, request, body)
    }

    fn prepay_body(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, loan: &mut Loan<'_>,
        request: &AuthenticatedBrokerMethodRequestV1, body: &[u8],
    ) -> Result<(), FixedServiceResponseClosedV4> {
        let Some(fixed) = Self::fixed_receiving_demand_v4() else {
            self.first = Some(First::Order);
            return Err(FixedServiceResponseClosedV4);
        };
        self.funding = Some(loan.require_additional_representation_v4(fixed));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(FixedServiceResponseClosedV4);
        }
        self.extent = Some(session.owner.fixed_service_receiving_extent_v4(&mut self.metadata));
        self.geometry = Some((|| {
            let extent = self.extent.as_ref().and_then(|v| v.as_ref().ok()).ok_or(BrokerSessionSecurityError::Currentness)?;
            let demand = session.owner.fixed_service_outcome_demand_v4(extent, &session.transcript, request, body)?;
            // The actual negotiated limit bounds the outer signed packet.
            let wire = u64::from(session.transcript.negotiated_maximum_response_bytes());
            demand.checked_add(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::OutputBytes, wire))
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })());
        let Some(demand) = self.geometry.as_ref().and_then(|v| v.as_ref().ok()).copied() else {
            self.first = Some(First::Geometry);
            return Err(FixedServiceResponseClosedV4);
        };
        self.funding = Some(loan.require_additional_representation_v4(demand));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(FixedServiceResponseClosedV4);
        }
        Ok(())
    }

    fn commit_prepaid_body(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, loan: &mut Loan<'_>,
        request: &AuthenticatedBrokerMethodRequestV1, body: &[u8],
    ) -> Result<(), FixedServiceResponseClosedV4> {
        self.commit_entered = true;
        self.commit_clock = Some(loan.fresh_before_effect_clock_v4());
        if !matches!(self.commit_clock, Some(Ok(_))) {
            self.first = Some(First::CommitClock);
            return Err(FixedServiceResponseClosedV4);
        }
        self.terminal.prepare_fixed_service_once_v4(session, request, body);
        if !matches!(self.terminal.committed, Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_))) {
            self.first = Some(First::Commit);
            return Err(FixedServiceResponseClosedV4);
        }
        Ok(())
    }

    /// Attempts one send with a fresh clock and two distinct terminal validators.
    ///
    /// A nonconsuming attempt remains `Pending`; a second invocation refuses.
    /// Both the outer Session and F after observations remain owed on every path.
    pub fn send_once_v4(&mut self, session: &mut super::super::FixedServiceSessionBorrowV4<'_>, loan: &mut Loan<'_>)
        -> FixedServiceResponseProgressV4 {
        let session = &mut *session.inner;
        if self.first.is_some() || self.attempted_send || self.method.is_none() {
            self.first.get_or_insert(First::Order);
            return FixedServiceResponseProgressV4::Closed;
        }
        self.attempted_send = true;
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = self.terminal.committed.as_ref() else {
            self.first = Some(First::Commit);
            return FixedServiceResponseProgressV4::Closed;
        };
        self.send_clock = Some(loan.fresh_before_effect_clock_v4());
        if !matches!(self.send_clock, Some(Ok(_))) { self.first = Some(First::SendClock); }
        self.terminal.before_send = Some(session.owner.observe_fixed_service_terminal_v4(
            &session.transcript, committed, session.socket.peer(), &mut self.currentness, false));
        if !matches!(self.terminal.before_send, Some(Ok(()))) { self.first.get_or_insert(First::BeforeSend); }
        if self.first.is_none() {
            let _ = session.send_storage_packet_retaining_v1(committed.exact_packet(), &mut self.native);
            if self.native.as_ref().is_none_or(|v| v.refuses_terminal_progress_v1()) { self.first = Some(First::Send); }
        }
        // This independently prepaid validator runs after a refusing clock,
        // before observation or native send; no healthy-path reentry is needed.
        self.terminal.after_send = Some(session.owner.observe_fixed_service_terminal_v4(
            &session.transcript, committed, session.socket.peer(), &mut self.currentness, true));
        if !matches!(self.terminal.after_send, Some(Ok(()))) { self.first.get_or_insert(First::AfterSend); }
        if self.first.is_some() { FixedServiceResponseProgressV4::Closed }
        else if self.native.as_ref().is_some_and(|v| v.is_sent()) { FixedServiceResponseProgressV4::Sent }
        else { FixedServiceResponseProgressV4::Pending }
    }

    pub(super) fn require_completed_inventory_v5(&self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), FixedServiceResponseClosedV4> {
        let committed = match self.terminal.committed.as_ref() {
            Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(actual)) => actual,
            _ => return Err(FixedServiceResponseClosedV4),
        };
        if self.first.is_some() || !self.attempted_send
            || self.terminal.failure().is_some() || self.currentness.failure().is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.commit_clock, Some(Ok(_))) || !matches!(self.send_clock, Some(Ok(_)))
            || self.method != Some(request.method())
            || !matches!(request.method(), BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
                | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
                | BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
            || committed.method() != request.method() || committed.request_id() != request.request_id()
            || committed.signed_request_digest() != request.signed_request_digest()
            || committed.client_sequence() != request.client_sequence()
            || committed.session_binding() != request.session_binding()
            || committed.session_binding() != transcript.session_binding()
            || !matches!(self.terminal.before_send, Some(Ok(())))
            || !matches!(self.terminal.after_send, Some(Ok(())))
            || self.native.as_ref().is_none_or(|native| !native.is_sent())
        { return Err(FixedServiceResponseClosedV4); }
        Ok(())
    }

    /// Borrows the actual selected refusal without consuming its native owners.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Geometry => self.metadata.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)
                .or_else(|| self.extent.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
                .or_else(|| self.geometry.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|e| e as _),
            First::CommitClock => self.commit_clock.as_ref()?.as_ref().err().map(|e| e as _),
            First::SendClock => self.send_clock.as_ref()?.as_ref().err().map(|e| e as _),
            First::BeforeSend | First::AfterSend => self.currentness.failure().or_else(|| self.terminal.failure()),
            First::Commit => self.terminal.failure(),
            First::Send => self.native.as_ref().and_then(|v| v.failure()),
            First::Binding | First::Order => Some(&FixedServiceResponseClosedV4),
        }
    }

    /// Borrows the original errno when the sole send was nonconsuming.
    ///
    /// This diagnostic DATA grants no retry, completion or refund.
    #[must_use]
    pub fn pending_native_cause_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if !self.attempted_send || self.first.is_some() { return None; }
        self.native.as_ref().filter(|native| native.is_nonconsuming()).and_then(|native| native.failure())
    }

    /// Identifies only an earlier actual loan refusal for first-cause routing.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding | First::CommitClock | First::SendClock))
    }
}

impl Default for FixedServiceResponseOriginalV4 {
    fn default() -> Self { Self::new() }
}
