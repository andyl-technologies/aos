//! Retains the sole Storage-to-Host45 endpoint, Session and client flight.
//!
//! Logical output registration and ongoing Capture share this exact client
//! carrier. Their original authenticated request, nomination, domain admission
//! and physical effect owners remain with their respective closed callers.

use crate::DormantAuthenticatedBrokerSessionV1;
use super::wait_output_original;

pub(super) struct StorageOutputHostOriginalV1 {
    pub(super) custody: Option<Result<crate::ProtectedBrokerSessionFixedCustodyV1, crate::BrokerSessionSecurityError>>,
    pub(super) session: Option<Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    funded: Option<crate::handshake::StorageHostSessionOpenV1>,
    exchange: Option<LifecycleHostExchangeV1>,
    pub(super) flight: crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
}

impl StorageOutputHostOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            custody: None,
            session: None,
            funded: None,
            exchange: None,
            flight: crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1::empty(),
        }
    }

    pub(super) fn open_and_park_coordinates_once_v1(&mut self, deadline: u64) {
        self.custody = Some(crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::StorageHostClient,
        ));
        if !matches!(&self.custody, Some(Ok(_))) { return; }
        let Some(Ok(custody)) = self.custody.take() else { return; };
        self.session = Some(custody.connect_output_client_session(deadline));
        let Some(Ok(host_session)) = &mut self.session else { return; };
        host_session.park_output_client_coordinates(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            deadline, &mut self.flight,
        );
    }

    pub(super) fn open_lifecycle_and_park_coordinates_once_v1(
        &mut self,
        storage_session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
    ) {
        if self.funded.is_some() || self.custody.is_some() || self.session.is_some() { return; }
        let mut receiving = match storage_session.borrow_storage_host_client_receiving_v1(request, lifecycle) {
            Ok(receiving) => receiving,
            Err(cause) => { self.custody = Some(Err(cause)); return; }
        };
        self.funded = Some(crate::handshake::StorageHostSessionOpenV1::new(deadline.min(request.deadline_boottime_nanoseconds())));
        let Some(original) = self.funded.as_mut() else { std::process::abort(); };
        original.open_once(&mut receiving, &mut self.flight);
        let Some(session) = DormantAuthenticatedBrokerSessionV1::take_storage_host_opened_once_v1(original) else { return; };
        self.session = Some(Ok(session));

    }

    pub(super) fn native_open_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.funded.as_ref().and_then(|original| original.failure(&self.flight))
    }

    pub(super) fn nominate_and_observe_lifecycle_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        preparation: &mut crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
        nomination: &mut Option<aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1>,
        body: &[u8],
        readiness: &mut [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
    ) -> bool {
        if self.exchange.is_some() || !matches!(self.session, Some(Ok(_))) {
            return false;
        }
        self.exchange = Some(LifecycleHostExchangeV1::new());
        let Some(exchange) = self.exchange.as_mut() else { std::process::abort(); };
        exchange.arm = Some(session.arm_storage_operation_post_v1(lifecycle));
        if !matches!(exchange.arm, Some(Ok(()))) {
            exchange.first = Some(ExchangeFailureV1::Arm);
            return false;
        }

        let admitted = self.admit_lifecycle_exchange_v1(session, request, preparation, lifecycle);
        let observed = admitted && self.nominate_and_observe_once_v1(
            session, request, preparation, nomination, body, readiness,
            deadline.min(request.deadline_boottime_nanoseconds()),
        );
        let Some(exchange) = self.exchange.as_mut() else { std::process::abort(); };
        if !observed { exchange.first.get_or_insert(ExchangeFailureV1::Primary); }
        // A primary financial/native/protocol refusal leaves the same whole
        // Host and Storage originals resident through this independent post.
        exchange.post = Some(session.finish_storage_operation_post_v1(lifecycle));
        if !matches!(exchange.post, Some(Ok(()))) {
            exchange.first.get_or_insert(ExchangeFailureV1::Post);
        }
        observed && exchange.first.is_none()
    }

    fn admit_lifecycle_exchange_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        preparation: &mut crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> bool {
        let Some(Ok(host)) = self.session.as_ref() else { return false; };
        let Some(exchange) = self.exchange.as_mut() else { return false; };
        exchange.demand = Some(host.storage_host_output_receiving_demand_v1().and_then(|demand| {
            let preparation = crate::handshake::output_registration_continuation::OutputPreparationCustodyV1::client_receiving_demand_v1()
                .ok_or(crate::handshake::StorageHostExchangeDemandErrorV1::Geometry(
                    aos_sandbox::journal::broker_session_receiving::StorageSessionGeometryRefusalV1))?;
            demand.checked_add(preparation).map_err(|_| crate::handshake::StorageHostExchangeDemandErrorV1::Geometry(
                aos_sandbox::journal::broker_session_receiving::StorageSessionGeometryRefusalV1))
        }));
        let Some(Ok(demand)) = exchange.demand.as_ref() else {
            exchange.first = Some(ExchangeFailureV1::Demand);
            return false;
        };
        let mut receiving = match session.borrow_storage_host_client_receiving_v1(request, lifecycle) {
            Ok(receiving) => receiving,
            Err(cause) => {
                exchange.selection = Some(Err(cause));
                exchange.first = Some(ExchangeFailureV1::Selection);
                return false;
            }
        };
        exchange.payment = Some(receiving.reserve_upper_v1(*demand));
        if !matches!(exchange.payment, Some(Ok(()))) {
            exchange.first = Some(ExchangeFailureV1::Payment);
            return false;
        }
        exchange.selection = Some(preparation.select_lifecycle_host_v1(&mut receiving));
        if !matches!(exchange.selection, Some(Ok(()))) {
            exchange.first = Some(ExchangeFailureV1::Selection);
            return false;
        }
        true
    }

    pub(super) fn lifecycle_exchange_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.exchange.as_ref()?.failure()
    }

    pub(super) fn nominate_and_observe_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        preparation: &mut crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
        nomination: &mut Option<aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1>,
        body: &[u8],
        readiness: &mut [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
        deadline: u64,
    ) -> bool {
        let Some(Ok(host_session)) = &mut self.session else { return false; };
        let mut transport = session.output_registration_transport(request, preparation);
        let Ok(head) = transport.original_head(request) else { return false; };
        *nomination = Some(aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1 {
            version: 1, stage: 1,
            original_storage_request_id: request.request_id().to_vec(),
            original_storage_session_binding: request.session_binding().to_vec(),
            original_signed_request_digest: request.signed_request_digest().to_vec(),
            original_semantic_request_digest: request.semantic_commitment().to_vec(),
            storage_pending_head: head.to_vec(),
            canonical_host_readback_request: body.to_vec(),
            ..Default::default()
        });
        if transport.finish_turn(request).is_err() { return false; }
        readiness[0] = Some(wait_output_original(session, true, deadline));
        if !matches!(&readiness[0], Some(Ok(()))) { return false; }
        let Some(nomination) = nomination.as_ref() else { return false; };
        let mut transport = session.output_registration_transport(request, preparation);
        if transport.send(request, nomination).is_err() || transport.finish_turn(request).is_err() { return false; }
        readiness[1] = Some(wait_output_original(session, false, deadline));
        if !matches!(&readiness[1], Some(Ok(()))) { return false; }
        let mut transport = session.output_registration_transport(request, preparation);
        if transport.receive(request, 2).is_err() || transport.finish_turn(request).is_err() { return false; }
        let Some(authorization) = preparation.record(2) else { return false; };
        if !aos_sandbox_protocol::storage_output_reserve::continuation::matches_nomination_v1(authorization, nomination) { return false; }
        let message = aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope {
            method: aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT.into(),
            body: body.to_vec(),
            authorization: authorization.host_authorization.clone(),
            ..Default::default()
        };
        if !host_session.park_output_client_request(&mut self.flight, message) { return false; }
        readiness[2] = Some(wait_output_original(host_session, true, deadline));
        if !matches!(&readiness[2], Some(Ok(())))
            || !host_session.send_original_output_client_request(&mut self.flight)
        { return false; }
        readiness[3] = Some(wait_output_original(host_session, false, deadline));
        if !matches!(&readiness[3], Some(Ok(())))
            || !host_session.receive_original_output_client_terminal(&mut self.flight)
        { return false; }
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_)) = &self.flight.committed else { return false; };
        true
    }
}

#[derive(Clone, Copy)]
enum ExchangeFailureV1 { Arm, Demand, Payment, Selection, Primary, Post }

struct LifecycleHostExchangeV1 {
    arm: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    demand: Option<Result<aos_sandbox_core::ResourceVector, crate::handshake::StorageHostExchangeDemandErrorV1>>,
    payment: Option<Result<(), crate::BrokerSessionSecurityError>>,
    selection: Option<Result<(), crate::BrokerSessionSecurityError>>,
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    first: Option<ExchangeFailureV1>,
}

impl LifecycleHostExchangeV1 {
    fn new() -> Self {
        Self { arm: None, demand: None, payment: None, selection: None, post: None, first: None }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            ExchangeFailureV1::Arm => self.arm.as_ref()?.as_ref().err().map(|cause| cause as _),
            ExchangeFailureV1::Demand => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            ExchangeFailureV1::Payment => self.payment.as_ref()?.as_ref().err().map(|cause| cause as _),
            ExchangeFailureV1::Selection => self.selection.as_ref()?.as_ref().err().map(|cause| cause as _),
            // The owning request resolves this marker through its unchanged
            // preparation/readiness/Host-flight original failure destinations.
            ExchangeFailureV1::Primary => None,
            ExchangeFailureV1::Post => self.post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}
