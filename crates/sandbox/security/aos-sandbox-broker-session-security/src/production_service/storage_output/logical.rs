//! Owns one shared logical46/47 or Capture60 request, Host45 and domain sequence.
//!
//! Ordinary and same-F callers keep one actual request/Host owner. The closed
//! receiving adapter selects only the existing owner-specific native ports;
//! it cannot turn packet DATA into funding or a completed domain result.

use super::*;
use crate::handshake::output_registration_continuation::HeldOutputPreparationV1;

// These variants retain the actual received source; Capture never constructs
// or relabels a logical46 registration or an old historical transport deadline.
enum StorageOutputSourceOriginalV1 {
    Logical(aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1),
    Capture(aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1),
}

impl StorageOutputSourceOriginalV1 {
    fn request(&self) -> &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1 {
        match self { Self::Logical(original) => original.original_request(), Self::Capture(request) => request }
    }
}

pub(crate) struct StorageOutputRequestOriginalV1 {
    source: StorageOutputSourceOriginalV1,
    capture_result: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    capture_response: Option<Vec<u8>>,
    pub(super) original: Option<Result<aos_sandbox_controller_domain::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptV1, aos_sandbox_controller_domain::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptErrorV1>>,
    pub(super) host: StorageOutputHostOriginalV1,
    pub(super) preparation: crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
    pub(super) nomination: Option<aos_sandbox_api::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1>,
    pub(super) host_body: Option<Result<Vec<u8>, aos_sandbox_controller_domain::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptErrorV1>>,
    pub(super) host_checks: [Option<Result<(), crate::BrokerSessionSecurityError>>; 2],
    pub(super) readiness: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
    host_body_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    host_body_payment: Option<Result<(), crate::BrokerSessionSecurityError>>,
    entered: bool,
}

impl StorageOutputRequestOriginalV1 {
    pub(crate) fn new(
        registration: aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    ) -> Self {
        Self::with_source_v1(StorageOutputSourceOriginalV1::Logical(registration))
    }

    fn capture_v3(request: aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1) -> Self {
        Self::with_source_v1(StorageOutputSourceOriginalV1::Capture(request))
    }

    fn with_source_v1(source: StorageOutputSourceOriginalV1) -> Self {
        Self {
            source, capture_result: None, capture_response: None,
            original: None,
            host: StorageOutputHostOriginalV1::new(),
            preparation: crate::handshake::output_registration_continuation::OutputPreparationCustodyV1::empty(),
            nomination: None,
            host_body: None,
            host_checks: std::array::from_fn(|_| None),
            readiness: std::array::from_fn(|_| None),
            host_body_demand: None, host_body_payment: None,
            entered: false,
        }
    }

    pub(crate) fn failure<'cause>(
        &'cause self,
        session: Option<&'cause DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.original {
            return Some(error);
        }
        if let Some(Err(error)) = &self.host.custody {
            return Some(error);
        }
        if let Some(error) = self.host.native_open_failure_v1() {
            return Some(error);
        }
        if let Some(Err(error)) = &self.host.session {
            return Some(error);
        }
        let host_failure = match &self.host.session {
            Some(Ok(session)) => session.output_client_flight_failure(&self.host.flight),
            _ => self.host.flight.failure(),
        };
        if let Some(error) = host_failure {
            return Some(error);
        }
        if let Some(error) = self.host.lifecycle_exchange_failure_v1() {
            return Some(error);
        }
        if let Some(Err(error)) = &self.host_body_demand {
            return Some(error);
        }
        if let Some(Err(error)) = &self.host_body_payment {
            return Some(error);
        }
        if let Some(Err(error)) = &self.host_body {
            return Some(error);
        }
        // A reached Capture body parks its actual failure before the
        // independent transport/Host after. Earlier Host/preparation failures
        // never set this selector because the actual body was not entered.
        if let Some(Err(cause)) = &self.capture_result { return Some(cause); }
        let preparation_failure = match &session {
            Some(session) => session.output_preparation_failure(&self.preparation),
            None => self.preparation.failure(),
        };
        if let Some(error) = preparation_failure {
            return Some(error);
        }
        for result in self.readiness.iter().flatten() {
            if let Err(error) = result {
                return Some(error);
            }
        }
        if self.host_checks[0].is_some() {
            if let Some(Ok(session)) = &self.host.session {
                if let Some(witness) = session.output_terminal_witness_failure() {
                    return Some(witness);
                }
            }
        }
        if let Some(Err(error)) = &self.host_checks[0] {
            return Some(error);
        }
        if let StorageOutputSourceOriginalV1::Logical(registration) = &self.source {
            if let Some(error) = registration.failure() { return Some(error); }
        }
        None
    }

    pub(crate) fn postcheck_debt<'cause>(
        &'cause self,
        session: Option<&'cause DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        if let Some(session) = &session {
            if let Some(error) = session.output_preparation_postcheck_debt(&self.preparation) {
                return Some(error);
            }
        }
        if let Some(Ok(session)) = &self.host.session {
            if let Some(error) = session.output_client_flight_postcheck_debt(&self.host.flight) {
                return Some(error);
            }
        }
        if let StorageOutputSourceOriginalV1::Logical(registration) = &self.source {
            if let Some(error) = registration.postcheck_debt() { return Some(error); }
        }
        if self.host_checks[1].is_some() {
            if let Some(Ok(session)) = &self.host.session {
                if let Some(witness) = session.output_terminal_witness_debt_before_protected() {
                    return Some(witness);
                }
            }
        }
        if let Some(Err(error)) = &self.host_checks[1] {
            return Some(error);
        }
        if let Some(Ok(session)) = &self.host.session {
            if let Some(witness) = session.output_terminal_witness_debt() {
                return Some(witness);
            }
        }
        None
    }

    pub(crate) fn request(
        &self,
    ) -> &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1
    {
        self.source.request()
    }

    pub(super) fn finish_logical_terminal_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        terminal: &mut crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
        deadline: u64,
    ) {
        let StorageOutputSourceOriginalV1::Logical(registration) = &self.source else { return; };
        super::finish_original_output_terminal(session, registration, terminal, &mut self.readiness[4], deadline);
    }

    pub(crate) fn response(&self) -> Option<&[u8]> {
        match &self.source {
            StorageOutputSourceOriginalV1::Logical(registration) => registration.response(),
            StorageOutputSourceOriginalV1::Capture(_) => self.capture_response.as_deref(),
        }
    }

    pub(super) fn advance(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        mut receiving: LogicalOutputReceivingV1<'_, '_, '_>,
        deadline: u64,
    ) -> bool {
        if self.entered {
            return false;
        }
        self.entered = true;
        if self.source.request().method()
            == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
        {
            let StorageOutputSourceOriginalV1::Logical(registration) = &mut self.source else { return false; };
            {
                let mut transport = session.output_registration_transport(registration.original_request(), &mut self.preparation);
                if transport.recheck(registration.original_request()).is_err() { return false; }
                let entered = receiving.query(&mut transport, storage, output, registration);
                let posted = transport.finish_action_turn(registration.original_request());
                if !entered || posted.is_err() { return false; }
            }
            return registration.response().is_some();
        }
        if let StorageOutputSourceOriginalV1::Logical(registration) = &self.source {
            self.original = Some(aos_sandbox_controller_domain::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptV1::from_authenticated_captured_request(
                registration.original_request(),
            ));
            if !matches!(&self.original, Some(Ok(_))) { return false; }
        }
        receiving.open(
            &mut self.host,
            session,
            self.source.request(),
            deadline,
        );
        if !matches!(self.host.session, Some(Ok(_))) {
            return false;
        }
        let Some(Ok(coordinates)) = &self.host.flight.coordinates else {
            return false;
        };
        let header = coordinates.request_header();
        match &self.source {
            StorageOutputSourceOriginalV1::Logical(_) => {
                let Some(Ok(original)) = &self.original else { return false; };
                if let LogicalOutputReceivingV1::Lifecycle(lifecycle) = &mut receiving {
                    use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
                    self.host_body_demand = Some(usize::try_from(buffa::Message::encoded_len(&header))
                    .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })
                    .and_then(|header_bytes| aos_sandbox_protocol::host_storage_output_readback::host_storage_output_readback_receiving_bytes_v1(
                        original.canonical_body().len(), header_bytes,
                    )).and_then(|bytes| u64::try_from(bytes).map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                        .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })));
                    let Some(Ok(demand)) = self.host_body_demand.as_ref() else {
                        return false;
                    };
                    self.host_body_payment = Some(session.reserve_storage_output_front_v1(
                        self.source.request(),
                        lifecycle,
                        *demand,
                    ));
                    if !matches!(self.host_body_payment, Some(Ok(()))) {
                        return false;
                    }
                }
                self.host_body = Some(original.captured_host_readback_body(header));
            }
            StorageOutputSourceOriginalV1::Capture(request) => {
                let LogicalOutputReceivingV1::Lifecycle(lifecycle) = &mut receiving else { return false; };
                let mut transport = session.output_registration_transport(request, &mut self.preparation);
                if transport.recheck(request).is_err() { return false; }
                let entered = transport.prepare_capture_host_body_receiving_v3(request, &header, storage, output, lifecycle);
                if entered {
                    self.capture_result = Some(if storage.original_capture_host_body_v3().is_some() { Ok(()) }
                        else { Err(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel) });
                }
                let posted = transport.finish_action_turn(request);
                if !entered || posted.is_err() || !matches!(self.capture_result, Some(Ok(()))) { return false; }
            }
        }
        let body = match &self.source {
            StorageOutputSourceOriginalV1::Logical(_) => match &self.host_body { Some(Ok(body)) => body.as_slice(), _ => return false },
            StorageOutputSourceOriginalV1::Capture(_) => match storage.original_capture_host_body_v3() { Some(body) => body, None => return false },
        };
        let request = self.source.request();
        if !receiving.nominate(
            &mut self.host,
            session,
            request,
            &mut self.preparation,
            &mut self.nomination,
            body,
            &mut self.readiness,
            deadline,
        ) {
            return false;
        }
        let Some(Ok(host_session)) = &mut self.host.session else {
            return false;
        };
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) =
            &self.host.flight.committed
        else {
            return false;
        };
        {
            let mut transport =
                session.output_registration_transport(request, &mut self.preparation);
            if transport.recheck(request).is_err() {
                return false;
            }
            let entered = match &mut self.source {
                StorageOutputSourceOriginalV1::Logical(registration) => receiving.register(
                    &mut transport, host_session, committed, storage, output, registration, &mut self.host_checks,
                ),
                StorageOutputSourceOriginalV1::Capture(request) => {
                    let LogicalOutputReceivingV1::Lifecycle(lifecycle) = &mut receiving else { return false; };
                    let entered = transport.capture_with_host_receiving_v3(host_session, committed, storage, output,
                        request, &mut self.host_checks, lifecycle);
                    if storage.original_capture_reserve_response_v3().is_some() {
                        self.capture_result = Some(Ok(()));
                    } else if storage.original_capture_reserve_failure_v3(output).is_some() {
                        self.capture_result = Some(Err(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel));
                    }
                    entered && storage.original_capture_reserve_response_v3().is_some()
                }
            };
            let posted = transport.finish_action_turn(self.source.request());
            if !entered || posted.is_err() {
                return false;
            }
        }
        if !matches!(&self.host_checks[0], Some(Ok(())))
            || !matches!(&self.host_checks[1], Some(Ok(())))
            || host_session.output_terminal_witness_failure().is_some()
            || host_session.output_terminal_witness_debt().is_some()
        {
            return false;
        }
        if matches!(self.source, StorageOutputSourceOriginalV1::Capture(_)) {
            self.capture_response = storage.original_capture_reserve_response_v3().map(<[u8]>::to_vec);
        }
        self.response().is_some()
    }
}

pub(crate) enum LogicalOutputReceivingV1<'loan, 'cut, 'original> {
    Ordinary,
    Lifecycle(&'loan mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>),
}

impl LogicalOutputReceivingV1<'_, '_, '_> {
    fn open(
        &mut self,
        host: &mut StorageOutputHostOriginalV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        deadline: u64,
    ) {
        match self {
            Self::Ordinary => host.open_and_park_coordinates_once_v1(deadline),
            Self::Lifecycle(receiving) => host
                .open_lifecycle_and_park_coordinates_once_v1(session, request, receiving, deadline),
        }
    }

    fn nominate(
        &mut self,
        host: &mut StorageOutputHostOriginalV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        preparation: &mut crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
        nomination: &mut Option<
            aos_sandbox_api::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1,
        >,
        body: &[u8],
        readiness: &mut [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
        deadline: u64,
    ) -> bool {
        match self {
            Self::Ordinary => host.nominate_and_observe_once_v1(
                session,
                request,
                preparation,
                nomination,
                body,
                readiness,
                deadline,
            ),
            Self::Lifecycle(receiving) => host.nominate_and_observe_lifecycle_once_v1(
                session,
                request,
                preparation,
                nomination,
                body,
                readiness,
                receiving,
                deadline,
            ),
        }
    }

    fn query(
        &mut self,
        transport: &mut HeldOutputPreparationV1<'_>,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        registration: &mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    ) -> bool {
        match self {
            Self::Ordinary => {
                storage.query_original_execution_output(output, registration);
                true
            }
            Self::Lifecycle(receiving) => transport.query_logical_output_receiving_v1(
                storage,
                output,
                registration,
                receiving,
            ),
        }
    }

    fn register(
        &mut self,
        transport: &mut HeldOutputPreparationV1<'_>,
        host: &mut DormantAuthenticatedBrokerSessionV1,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        registration: &mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        checks: &mut [Option<Result<(), crate::BrokerSessionSecurityError>>; 2],
    ) -> bool {
        match self {
            Self::Ordinary => {
                host.register_original_storage_output_with_host(
                    committed,
                    storage,
                    output,
                    registration,
                    checks,
                );
                true
            }
            Self::Lifecycle(receiving) => transport.register_logical_output_with_host_receiving_v1(
                host,
                committed,
                storage,
                output,
                registration,
                checks,
                receiving,
            ),
        }
    }
}

/// Keeps the actual funded logical request through its signed successor.
pub(crate) struct StorageOutputLifecycleOriginalV1 {
    original: Option<Box<StorageOutputRequestOriginalV1>>,
    arm: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), crate::BrokerSessionSecurityError>>,
    post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    first: Option<LogicalEntryFirstV1>,
    entered: bool,
    completed: bool,
}

#[derive(Clone, Copy)]
enum LogicalEntryFirstV1 {
    Arm,
    Demand,
    Payment,
    Post,
    Domain,
}

impl StorageOutputLifecycleOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            original: None,
            arm: None,
            demand: None,
            payment: None,
            post: None,
            first: None,
            entered: false,
            completed: false,
        }
    }

    pub(crate) fn request(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1>{
        self.original.as_ref().map(|original| original.request())
    }

    pub(crate) fn advance(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) {
        if self.entered {
            return;
        }
        self.entered = true;
        self.arm = Some(session.arm_storage_operation_post_v1(receiving));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(LogicalEntryFirstV1::Arm);
            return;
        }
        self.demand = Some((|| {
            use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
            let overflow = || AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            let artifacts = request.authorization().ok_or_else(overflow)?;
            let authorization = [
                artifacts.broker_plan().len(),
                artifacts.broker_plan_signature().len(),
                artifacts.ownership_lease().len(),
                artifacts.ownership_lease_signature().len(),
            ]
            .into_iter()
            .try_fold(0usize, |bytes, width| {
                bytes.checked_add(width).ok_or_else(overflow)
            })?;
            // These three admitted methods have no ancillary descriptor table.
            // Cloning retains the exact packet/body/envelope and artifact
            // quartet; Capture also owns its decoded historical46 body.
            let cloned_request = [
                request.canonical_packet().len(),
                request.exact_body().len(),
                request.exact_body().len(),
                authorization,
                request.storage_execution_capture_original_output_request_v2().map_or(0, <[u8]>::len),
            ]
            .into_iter()
            .try_fold(0usize, |bytes, width| {
                bytes.checked_add(width).ok_or_else(overflow)
            })?;
            let original_buffers = if request.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT {
                let inspected = aos_sandbox_protocol::storage_output_reserve::storage_output_inspection_receiving_bytes_v1(request.exact_body().len())?;
                let frozen_body = request.exact_body().len();
                // AOSCST01's fixed prefix is the sole existing122-byte codec.
                let encoded_record = frozen_body.checked_add(122).ok_or_else(overflow)?;
                inspected.checked_add(frozen_body).and_then(|bytes| bytes.checked_add(encoded_record)).ok_or_else(overflow)?
            } else { 0 };
            let typed = [
                std::mem::size_of::<StorageOutputRequestOriginalV1>(),
                std::mem::size_of::<StorageOutputRequestOriginalV1>(),
                std::mem::size_of::<
                    aos_sandbox_api::aos::sandbox::local::v1::ReserveStorageExecutionOutputRequestV1,
                >(),
                std::mem::size_of::<aos_sandbox_api::aos::sandbox::local::v1::RequestHeader>(),
                std::mem::size_of::<aos_sandbox_model::BrokerGrant>(),
                std::mem::size_of::<
                    aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1,
                >(),
            ]
            .into_iter()
            .try_fold(0usize, |bytes, width| {
                bytes.checked_add(width).ok_or_else(overflow)
            })?;
            let capture_response = if request.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1 {
                aos_sandbox_protocol::storage_capture_grant::MAXIMUM_RESPONSE_BODY_BYTES
            } else { 0 };
            let bytes = cloned_request
                .checked_add(original_buffers)
                .and_then(|bytes| bytes.checked_add(capture_response))
                .and_then(|bytes| bytes.checked_add(typed))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(overflow)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        if let Some(Ok(demand)) = self.demand.as_ref() {
            self.payment =
                Some(session.reserve_storage_output_front_v1(request, receiving, *demand));
            if !matches!(self.payment, Some(Ok(()))) {
                self.first = Some(LogicalEntryFirstV1::Payment);
            }
        } else {
            self.first = Some(LogicalEntryFirstV1::Demand);
        }
        if self.first.is_none() {
            self.original = Some(Box::new(if request.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1 {
                StorageOutputRequestOriginalV1::capture_v3(request.clone())
            } else {
                StorageOutputRequestOriginalV1::new(storage.begin_original_execution_output_registration(request.clone()))
            }));
        }
        self.post = Some(session.finish_storage_operation_post_v1(receiving));
        if !matches!(self.post, Some(Ok(()))) {
            self.first.get_or_insert(LogicalEntryFirstV1::Post);
        }
        if self.first.is_some() {
            return;
        }
        let Some(original) = self.original.as_mut() else {
            std::process::abort();
        };
        self.completed = original.advance(
            session,
            storage,
            output,
            LogicalOutputReceivingV1::Lifecycle(receiving),
            request.deadline_boottime_nanoseconds(),
        );
        if !self.completed {
            self.first = Some(LogicalEntryFirstV1::Domain);
        }
    }

    pub(crate) fn response(&self) -> Option<&[u8]> {
        if self.first.is_some() || !self.completed {
            return None;
        }
        self.original.as_ref()?.response()
    }

    pub(crate) fn failure<'cause>(
        &'cause self,
        session: Option<&'cause DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        match self.first? {
            LogicalEntryFirstV1::Arm => self.arm.as_ref()?.as_ref().err().map(|error| error as _),
            LogicalEntryFirstV1::Demand => {
                self.demand.as_ref()?.as_ref().err().map(|error| error as _)
            }
            LogicalEntryFirstV1::Payment => self
                .payment
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            LogicalEntryFirstV1::Post => self.post.as_ref()?.as_ref().err().map(|error| error as _),
            LogicalEntryFirstV1::Domain => self
                .original
                .as_ref()?
                .failure(session)
                .or_else(|| self.original.as_ref()?.postcheck_debt(session))
                .or(Some(&OriginalStorageOutputClosedV1)),
        }
    }

    pub(crate) fn financial_projection_selected_v1(&self) -> bool {
        matches!(self.first, Some(LogicalEntryFirstV1::Payment))
            || (matches!(self.first, Some(LogicalEntryFirstV1::Domain))
                && self
                    .original
                    .as_ref()
                    .is_some_and(|original| matches!(original.host_body_payment, Some(Err(_)))))
    }

    pub(crate) fn retire_on_successor_v1(
        &mut self,
        successor: &crate::DormantReceivedBrokerRequestV1,
        session: &DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), OriginalStorageOutputClosedV1> {
        let Some(original) = self.original.as_ref() else {
            return if self.entered {
                Err(OriginalStorageOutputClosedV1)
            } else {
                Ok(())
            };
        };
        if !self.completed
            || self.first.is_some()
            || original.response().is_none()
            || original.failure(Some(session)).is_some()
            || original.postcheck_debt(Some(session)).is_some()
            || !successor.is_original_output_successor(original.request())
        {
            return Err(OriginalStorageOutputClosedV1);
        }
        // Only the actual BSA admission of this successor authenticated the
        // predecessor link. Local Sent alone never reaches this disposition.
        drop(self.original.take());
        *self = Self::new();
        Ok(())
    }
}
