//! Retained Controller exchange for a read-only Storage capture candidate.
//!
//! The completed original output registration and its same authenticated
//! Storage Session select one informational method-41 query. The query's fresh
//! Session-selected cutoff never renews Create. Whole native flight results,
//! the issuer, source/clock bookends and classification remain resident; failure
//! or cancellation cannot start another query or release the original Session.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, ReadStorageExecutionCaptureCandidateRequestV1,
    RequestHeader,
};
use aos_sandbox::EffectFailure;
use aos_sandbox::controller_execution_output_settlement::{
    ControllerExecutionOutputSettlementErrorV1, ProtectedControllerOutputSettlementV1,
    read_current_controller_output_settlement_v1,
};
use aos_sandbox::controller_execution_preissue::{
    ControllerExecutionPreissueErrorV1, ControllerExecutionPreissueV1,
    revalidate_historical_execution_preissue_source_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::Journal;
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::storage_capture_candidate::{
    StorageCaptureCandidateQueryV1, ValidatedStorageCaptureCandidateV1,
    decode_storage_capture_candidate_response_for_query_v1,
};
use buffa::Message as _;

use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::controller_service::execution_capture_candidate::{
    AcceptedCaptureLimitsV1, SignedStorageCaptureCandidateQueryV1,
    sign_current_storage_capture_candidate_query_v1,
};
use crate::dormant_handshake::ProtectedStorageSessionBindingV1;
use crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1;
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1, ProtectedBrokerOutcomeCommitResultV1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct CandidateExchangeContextV1 {
    query: StorageCaptureCandidateQueryV1,
    exact_body: Vec<u8>,
    settlement_digest: ObjectDigest,
    capture_limits: AcceptedCaptureLimitsV1,
    maximum_response_bytes: u32,
    session_binding: [u8; 32],
}

/// Holds one signed, informational Storage candidate and its exact query.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ControllerStorageCaptureCandidateObservationV1 {
    candidate: ValidatedStorageCaptureCandidateV1,
    query: StorageCaptureCandidateQueryV1,
    settlement_digest: ObjectDigest,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
}

impl ControllerStorageCaptureCandidateObservationV1 {
    pub(crate) const fn candidate(&self) -> &ValidatedStorageCaptureCandidateV1 {
        &self.candidate
    }

    pub(crate) const fn query(&self) -> &StorageCaptureCandidateQueryV1 {
        &self.query
    }

    pub(crate) const fn settlement_digest(&self) -> ObjectDigest {
        self.settlement_digest
    }

    pub(crate) const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.outcome
    }
}

#[derive(Clone, Copy)]
enum CandidateFailureSiteV1 {
    Binding,
    Coordinates,
    Source(usize),
    Settlement(usize),
    Issuer,
    Validation,
    Flight,
    Readiness(usize),
    Projection,
    Witness,
    Terminal,
    Clock,
    Decode,
    Classification,
    Returned,
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
#[error("original capture query is closed with its custody resident")]
struct CandidateClosedV1;

type CandidateClockReadV1 = Result<RawPairedClockSample, ProtectedOwnershipClockError>;
type CandidateSettlementReadV1 = Result<
    Option<ProtectedControllerOutputSettlementV1>,
    ControllerExecutionOutputSettlementErrorV1,
>;

/// Borrows individual negative slots without selecting a replacement first cause.
pub(crate) struct ControllerStorageCaptureCandidatePostcheckDebtsV1<'resident> {
    /// Borrows the native flight's existing first postcheck debt, if any.
    pub(crate) native: Option<&'resident (dyn std::error::Error + 'static)>,
    /// Borrows each source error except the exact selected primary slot.
    pub(crate) sources: [Option<&'resident ControllerExecutionPreissueErrorV1>; 3],
    /// Borrows each settlement error except the exact selected primary slot.
    pub(crate) settlements: [Option<&'resident ControllerExecutionOutputSettlementErrorV1>; 3],
    /// Borrows every original source/issuer clock Result, including each Err.
    pub(crate) clocks: &'resident [CandidateClockReadV1],
    /// Borrows an entered committed projection error that was not primary.
    pub(crate) projection: Option<&'resident BrokerSessionSecurityError>,
    /// Borrows an entered terminal comparison error that was not primary.
    pub(crate) terminal_current: Option<&'resident BrokerSessionSecurityError>,
    /// Borrows the actual Session's before-action witness error when secondary.
    pub(crate) terminal_witness_before: Option<&'resident (dyn std::error::Error + 'static)>,
    /// Borrows the actual Session's entered terminal post-action witness debt.
    pub(crate) terminal_witness_after: Option<&'resident (dyn std::error::Error + 'static)>,
    /// Borrows an entered terminal clock error that was not primary.
    pub(crate) terminal_clock: Option<&'resident ProtectedOwnershipClockError>,
    /// Borrows the unconditional original Session postcheck error.
    pub(crate) session: Option<&'resident BrokerSessionSecurityError>,
    /// Borrows the actual Session's unconditional final witness debt.
    pub(crate) witness: Option<&'resident (dyn std::error::Error + 'static)>,
    /// Borrows the resident negative final-bookend classification.
    pub(crate) validation: Option<&'resident EffectFailure>,
}

/// Retains one original method-41 continuation beside its actual Storage Session.
pub(crate) struct ControllerStorageCaptureCandidateExchangeV1 {
    operation: OperationId,
    execution: ExecutionId,
    started: bool,
    ended: bool,
    complete: bool,

    binding: Option<Result<ProtectedStorageSessionBindingV1, BrokerSessionSecurityError>>,
    issued: Option<Result<SignedStorageCaptureCandidateQueryV1, EffectFailure>>,
    context: Option<CandidateExchangeContextV1>,
    flight: OriginalOutputClientFlightV1,

    readiness: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 2],
    sources: [Option<Result<(), ControllerExecutionPreissueErrorV1>>; 3],
    settlements: [Option<CandidateSettlementReadV1>; 3],
    clocks: Vec<CandidateClockReadV1>,

    projection: Option<Result<(), BrokerSessionSecurityError>>,
    terminal_current: Option<Result<(), BrokerSessionSecurityError>>,
    terminal_witnesses: [Option<bool>; 2],
    terminal_clock: Option<CandidateClockReadV1>,
    decoded: Option<Result<
        ValidatedStorageCaptureCandidateV1,
        aos_sandbox_protocol::ProtocolValidationError,
    >>,
    classification: Option<Result<ControllerStorageCaptureCandidateObservationV1, EffectFailure>>,
    returned: Option<Result<(), EffectFailure>>,
    validation: Option<EffectFailure>,
    first_site: Option<CandidateFailureSiteV1>,

    session_postcheck: Option<Result<(), BrokerSessionSecurityError>>,
    witness_postcheck: Option<bool>,
    postcheck_validation: Option<EffectFailure>,
}

impl ControllerStorageCaptureCandidateExchangeV1 {
    /// Prearms comparison identity and empty slots, without minting any authority.
    pub(crate) fn begin(operation: OperationId, execution: ExecutionId) -> Self {
        Self {
            operation,
            execution,
            started: false,
            ended: false,
            complete: false,
            binding: None,
            issued: None,
            context: None,
            flight: OriginalOutputClientFlightV1::empty(),
            readiness: std::array::from_fn(|_| None),
            sources: std::array::from_fn(|_| None),
            settlements: std::array::from_fn(|_| None),
            clocks: Vec::new(),
            projection: None,
            terminal_current: None,
            terminal_witnesses: [None; 2],
            terminal_clock: None,
            decoded: None,
            classification: None,
            returned: None,
            validation: None,
            first_site: None,
            session_postcheck: None,
            witness_postcheck: None,
            postcheck_validation: None,
        }
    }

    /// Reports incomplete or closed custody, never permission to replace it.
    pub(crate) const fn has_pending(&self) -> bool {
        !self.complete
    }

    /// Borrows only the completed original informational observation.
    pub(crate) fn observation(&self) -> Option<&ControllerStorageCaptureCandidateObservationV1> {
        if !self.complete { return None; }
        self.classification.as_ref()?.as_ref().ok()
    }

    /// Borrows the first cause, including witness errors from the actual Session.
    pub(crate) fn failure<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        match self.first_site? {
            CandidateFailureSiteV1::Binding => self.binding.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Coordinates | CandidateFailureSiteV1::Flight => {
                Some(session.output_client_flight_failure(&self.flight).unwrap_or(&CandidateClosedV1))
            }
            CandidateFailureSiteV1::Source(index) => self.sources[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Settlement(index) => {
                Some(self.settlements[index].as_ref()?.as_ref().err()
                    .map(|error| error as &dyn std::error::Error).unwrap_or(&CandidateClosedV1))
            }
            CandidateFailureSiteV1::Issuer => self.issued.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Validation => self.validation.as_ref()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Readiness(index) => self.readiness[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Projection => self.projection.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Witness => {
                Some(session.output_terminal_witness_failure().unwrap_or(&CandidateClosedV1))
            }
            CandidateFailureSiteV1::Terminal => self.terminal_current.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Clock => self.terminal_clock.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Decode => self.decoded.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Classification => self.classification.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Returned => self.returned.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateFailureSiteV1::Cancelled => Some(&CandidateClosedV1),
        }
    }

    /// Borrows individual negative results, excluding only the exact primary slot.
    ///
    /// The clock slice contains the original source/issuer Results, not mapped
    /// issuer errors. Each Err remains separately borrowable even when the
    /// issuer or another bookend error was selected first. Witness projections
    /// borrow the actual Session's resident error; this performs no recheck.
    pub(crate) fn postcheck_debts<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> ControllerStorageCaptureCandidatePostcheckDebtsV1<'a> {
        ControllerStorageCaptureCandidatePostcheckDebtsV1 {
            native: session.output_client_flight_postcheck_debt(&self.flight),
            sources: std::array::from_fn(|index| {
                if matches!(self.first_site, Some(CandidateFailureSiteV1::Source(primary)) if primary == index) {
                    return None;
                }
                self.sources[index].as_ref()?.as_ref().err()
            }),
            settlements: std::array::from_fn(|index| {
                if matches!(self.first_site, Some(CandidateFailureSiteV1::Settlement(primary)) if primary == index) {
                    return None;
                }
                self.settlements[index].as_ref()?.as_ref().err()
            }),
            clocks: &self.clocks,
            projection: if matches!(self.first_site, Some(CandidateFailureSiteV1::Projection)) {
                None
            } else {
                self.projection.as_ref().and_then(|result| result.as_ref().err())
            },
            terminal_current: if matches!(self.first_site, Some(CandidateFailureSiteV1::Terminal)) {
                None
            } else {
                self.terminal_current.as_ref().and_then(|result| result.as_ref().err())
            },
            terminal_witness_before: if self.terminal_witnesses[0] == Some(false)
                && !matches!(self.first_site, Some(CandidateFailureSiteV1::Witness))
            {
                Some(session.output_terminal_witness_failure().unwrap_or(&CandidateClosedV1))
            } else {
                None
            },
            terminal_witness_after: if self.terminal_witnesses[1] == Some(false) {
                Some(session.output_terminal_witness_debt().unwrap_or(&CandidateClosedV1))
            } else {
                None
            },
            terminal_clock: if matches!(self.first_site, Some(CandidateFailureSiteV1::Clock)) {
                None
            } else {
                self.terminal_clock.as_ref().and_then(|result| result.as_ref().err())
            },
            session: self.session_postcheck.as_ref().and_then(|result| result.as_ref().err()),
            witness: if self.witness_postcheck == Some(false) {
                Some(session.output_terminal_witness_debt().unwrap_or(&CandidateClosedV1))
            } else {
                None
            },
            validation: self.postcheck_validation.as_ref(),
        }
    }

    /// Borrows the first available debt; [`Self::postcheck_debts`] exposes each slot.
    ///
    /// The original native/final-post diagnostic order stays ahead of newly
    /// exposed secondary bookends. Neither projection replaces `failure()`.
    pub(crate) fn postcheck_debt<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        let debts = self.postcheck_debts(session);
        if let Some(error) = debts.native { return Some(error); }
        if let Some(error) = debts.terminal_witness_after.or(debts.witness) { return Some(error); }
        if let Some(error) = debts.session { return Some(error); }
        if let Some(error) = debts.sources[2] { return Some(error); }
        if let Some(error) = debts.settlements[2] { return Some(error); }
        if let Some(error) = debts.validation { return Some(error); }

        for index in 0..2 {
            if let Some(error) = debts.sources[index] { return Some(error); }
            if let Some(error) = debts.settlements[index] { return Some(error); }
        }
        if let Some(error) = debts.clocks.iter().find_map(|result| result.as_ref().err()) { return Some(error); }
        if let Some(error) = debts.projection { return Some(error); }
        if let Some(error) = debts.terminal_current { return Some(error); }
        if let Some(error) = debts.terminal_witness_before { return Some(error); }
        debts.terminal_clock.map(|error| error as &dyn std::error::Error)
    }

    /// Advances this prearmed original exactly once; re-entry only borrows its result.
    ///
    /// # Errors
    /// Refuses changed correlation, any first action cause or negative postcheck,
    /// cancellation and incomplete custody. It never retries or replaces a flight.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        operation: OperationId,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
        parent: &ExecutionParentResourceSourceV1,
        preissue: &ControllerExecutionPreissueV1,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) -> Result<(), EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.operation != operation || self.operation != preissue.create_operation()
            || self.execution != preissue.execution()
        {
            self.validation.get_or_insert_with(closed);
            self.first_site.get_or_insert(CandidateFailureSiteV1::Validation);
            self.ended = true;
            self.complete = false;
            return Err(closed());
        }
        if self.complete { return Ok(()); }
        if self.started || self.ended { return Err(closed()); }
        self.started = true;

        let boundary = CandidateBoundaryV1 { attempt: self };
        let returned = boundary.attempt.advance_inner(
            session, controller, assignment, environment, parent, preissue, signer, clock,
        );
        boundary.attempt.returned = Some(returned);
        // Retain the first action result before every independent negative
        // readback, including issuer, wait, native send/receive and commit failure.
        if boundary.attempt.returned.as_ref().is_some_and(Result::is_err)
            && boundary.attempt.first_site.is_none()
        {
            boundary.attempt.first_site = Some(CandidateFailureSiteV1::Returned);
        }
        let source_current = boundary.attempt.source_bookend(
            2, controller, assignment, environment, parent, preissue, clock,
        );
        boundary.attempt.session_postcheck = Some(session.recheck_original_capture_candidate_client());
        boundary.attempt.witness_postcheck = Some(session.bookend_output_terminal_witnesses(
            crate::handshake::OutputCurrentnessBoundaryV1::PostAction,
        ));
        if !source_current || boundary.attempt.session_postcheck.as_ref().is_some_and(Result::is_err)
            || boundary.attempt.witness_postcheck == Some(false)
        {
            boundary.attempt.postcheck_validation = Some(closed());
        }
        boundary.attempt.complete = boundary.attempt.first_site.is_none()
            && boundary.attempt.postcheck_debt(session).is_none()
            && matches!(&boundary.attempt.classification, Some(Ok(_)));
        if boundary.attempt.complete { Ok(()) } else { Err(closed()) }
    }

    #[allow(clippy::too_many_arguments)]
    fn advance_inner<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
        parent: &ExecutionParentResourceSourceV1,
        preissue: &ControllerExecutionPreissueV1,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) -> Result<(), EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.binding = Some(session.current_storage_session_binding());
        let Some(Ok(binding)) = &self.binding else {
            self.first_site = Some(CandidateFailureSiteV1::Binding);
            return Err(closed());
        };
        let binding = *binding;
        session.park_capture_candidate_client_coordinates(assignment, &mut self.flight);
        let Some(Ok(coordinates)) = &self.flight.coordinates else {
            self.first_site = Some(CandidateFailureSiteV1::Coordinates);
            return Err(closed());
        };
        let coordinates = *coordinates;
        if !self.source_bookend(0, controller, assignment, environment, parent, preissue, clock) {
            return Err(closed());
        }
        let clocks = &mut self.clocks;
        let mut retained_clock = || {
            let returned = clock();
            clocks.push(returned);
            returned
        };
        self.issued = Some(sign_current_storage_capture_candidate_query_v1(
            controller, assignment, environment, parent, self.execution, self.operation,
            signer, binding, coordinates, &mut retained_clock,
        ));
        let Some(Ok(signed)) = &self.issued else {
            self.first_site = Some(CandidateFailureSiteV1::Issuer);
            return Err(closed());
        };
        if !query_matches_body(signed.query(), signed.body(), binding.digest(), &coordinates.request_header())
            || self.settlements[0].as_ref().and_then(|result| result.as_ref().ok())
                .and_then(Option::as_ref).map(ProtectedControllerOutputSettlementV1::record_digest)
                != Some(signed.settlement_digest())
        {
            self.validation = Some(closed());
            self.first_site = Some(CandidateFailureSiteV1::Validation);
            return Err(closed());
        }
        self.context = Some(CandidateExchangeContextV1 {
            query: *signed.query(), exact_body: signed.body().to_vec(),
            settlement_digest: signed.settlement_digest(), capture_limits: signed.capture_limits(),
            maximum_response_bytes: coordinates.maximum_response_bytes(), session_binding: binding.digest(),
        });
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE.into(),
            body: signed.body().to_vec(), authorization: Some(signed.authorization().clone()).into(),
            ..Default::default()
        };
        if !self.source_bookend(1, controller, assignment, environment, parent, preissue, clock) {
            return Err(closed());
        }
        if !session.park_output_client_request(&mut self.flight, envelope) {
            self.first_site = Some(CandidateFailureSiteV1::Flight);
            return Err(closed());
        }
        if !self.flight.request().is_some_and(|request|
            request.session_binding() == binding.digest()
                && self.context.as_ref().is_some_and(|context| request.exact_body() == context.exact_body))
        {
            self.validation = Some(closed());
            self.first_site = Some(CandidateFailureSiteV1::Validation);
            return Err(closed());
        }
        if !self.wait(session, 0, true, coordinates.deadline_boottime_nanoseconds()) { return Err(closed()); }
        if !session.send_original_output_client_request(&mut self.flight) {
            self.first_site = Some(CandidateFailureSiteV1::Flight);
            return Err(closed());
        }
        if !self.wait(session, 1, false, coordinates.deadline_boottime_nanoseconds()) { return Err(closed()); }
        let received = session.receive_original_output_client_terminal(&mut self.flight);
        if !received { self.first_site = Some(CandidateFailureSiteV1::Flight); }
        let Some(ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = &self.flight.committed else {
            return Err(closed());
        };
        let (outcome, currentness) = match committed.capture_candidate_client_originals() {
            Ok(originals) => {
                self.projection = Some(Ok(()));
                originals
            }
            Err(error) => {
                self.projection = Some(Err(error));
                self.first_site.get_or_insert(CandidateFailureSiteV1::Projection);
                return Err(closed());
            }
        };
        self.terminal_witnesses[0] = Some(session.bookend_output_terminal_witnesses(
            crate::handshake::OutputCurrentnessBoundaryV1::BeforeAction,
        ));
        if self.terminal_witnesses[0] == Some(false) {
            self.first_site.get_or_insert(CandidateFailureSiteV1::Witness);
        } else {
            self.terminal_current = Some(session.compare_original_capture_candidate_outcome(currentness));
            if self.terminal_current.as_ref().is_some_and(Result::is_err) {
                self.first_site.get_or_insert(CandidateFailureSiteV1::Terminal);
            }
        }
        self.terminal_witnesses[1] = Some(session.bookend_output_terminal_witnesses(
            crate::handshake::OutputCurrentnessBoundaryV1::PostAction,
        ));
        if !received || self.first_site.is_some() || self.terminal_witnesses[1] == Some(false) {
            return Err(closed());
        }
        self.terminal_clock = Some(clock());
        let Some(Ok(sample)) = &self.terminal_clock else {
            self.first_site = Some(CandidateFailureSiteV1::Clock);
            return Err(closed());
        };
        let Some(context) = &self.context else { return Err(closed()); };
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            self.classification = Some(Err(closed()));
            self.first_site = Some(CandidateFailureSiteV1::Classification);
            return Err(closed());
        };
        self.decoded = Some(decode_storage_capture_candidate_response_for_query_v1(
            exact_body, &context.query, context.maximum_response_bytes, sample.boottime_nanoseconds(),
        ));
        let Some(Ok(candidate)) = &self.decoded else {
            self.first_site = Some(CandidateFailureSiteV1::Decode);
            return Err(closed());
        };
        self.classification = Some(classify_outcome(context, outcome, *sample, candidate));
        if self.classification.as_ref().is_some_and(Result::is_err) {
            self.first_site = Some(CandidateFailureSiteV1::Classification);
            return Err(closed());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn source_bookend<T>(
        &mut self, index: usize, controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
        parent: &ExecutionParentResourceSourceV1, preissue: &ControllerExecutionPreissueV1,
        clock: &mut T,
    ) -> bool
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let clocks = &mut self.clocks;
        let mut retained_clock = || {
            let returned = clock();
            clocks.push(returned);
            returned
        };
        self.sources[index] = Some(revalidate_historical_execution_preissue_source_v1(
            controller, assignment, environment, parent, preissue, &mut retained_clock,
        ));
        self.settlements[index] = Some(read_current_controller_output_settlement_v1(
            controller, assignment, self.execution, self.operation, &mut retained_clock,
        ));
        let source_current = matches!(&self.sources[index], Some(Ok(())));
        let settlement = self.settlements[index].as_ref().and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref);
        let settlement_current = settlement.is_some_and(|settlement|
            self.context.as_ref().is_none_or(|context| settlement.record_digest() == context.settlement_digest))
            && (index == 0 || self.settlements[0].as_ref().and_then(|result| result.as_ref().ok())
                .and_then(Option::as_ref) == settlement);
        let clock_current = self.clocks.last().is_some_and(|result| result.as_ref().is_ok_and(|sample|
            sample.host_boot_id() == preissue.host_boot_id()
                && self.flight.coordinates.as_ref().and_then(|result| result.as_ref().ok())
                    .is_none_or(|coordinates| sample.boottime_nanoseconds() < coordinates.deadline_boottime_nanoseconds())));
        if index != 2 && self.first_site.is_none() {
            if !source_current { self.first_site = Some(CandidateFailureSiteV1::Source(index)); }
            else if !settlement_current { self.first_site = Some(CandidateFailureSiteV1::Settlement(index)); }
            else if !clock_current {
                self.validation = Some(closed());
                self.first_site = Some(CandidateFailureSiteV1::Validation);
            }
        }
        source_current && settlement_current && clock_current
    }

    fn wait(&mut self, session: &DormantAuthenticatedBrokerSessionV1, index: usize, write: bool, cutoff: u64) -> bool {
        self.readiness[index] = Some((|| {
            crate::dormant_handshake::wait_for_handshake_readiness(session.as_fd()?, write, cutoff)
        })());
        if matches!(&self.readiness[index], Some(Ok(()))) { return true; }
        self.first_site.get_or_insert(CandidateFailureSiteV1::Readiness(index));
        false
    }
}

impl Drop for ControllerStorageCaptureCandidateExchangeV1 {
    fn drop(&mut self) {
        // A local success is not the authenticated successor/physical handoff
        // that could retire this original. Its enclosing field precedes Session.
        if self.started { std::process::abort(); }
    }
}

struct CandidateBoundaryV1<'attempt> {
    attempt: &'attempt mut ControllerStorageCaptureCandidateExchangeV1,
}

impl Drop for CandidateBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.attempt.complete {
            self.attempt.ended = true;
            if self.attempt.session_postcheck.is_none() {
                self.attempt.first_site.get_or_insert(CandidateFailureSiteV1::Cancelled);
            }
        }
    }
}

fn closed() -> EffectFailure {
    EffectFailure::Permanent("original Storage capture query remains resident and closed".to_owned())
}

fn query_matches_body(
    query: &StorageCaptureCandidateQueryV1,
    body: &[u8],
    session_binding: [u8; 32],
    header: &RequestHeader,
) -> bool {
    let Ok(decoded) = ReadStorageExecutionCaptureCandidateRequestV1::decode_from_slice(body) else {
        return false;
    };
    decoded.__buffa_unknown_fields.is_empty()
        && decoded.encode_to_vec() == body
        && decoded.canonical_query == query.canonical_bytes().as_slice()
        && query.request_id().as_slice() == header.request_id.as_slice()
        && query.deadline_boottime_nanoseconds() == header.deadline_boottime_nanoseconds
        && query.claimed_session_binding() == session_binding
        && decoded.header.as_option() == Some(header)
}

fn classify_outcome(
    context: &CandidateExchangeContextV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    sample: RawPairedClockSample,
    candidate: &ValidatedStorageCaptureCandidateV1,
) -> Result<ControllerStorageCaptureCandidateObservationV1, EffectFailure>
{
    let request = outcome.request();
    if outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
        || request.exact_body() != context.exact_body
        || request.request_id() != context.query.request_id()
        || request.session_binding() != context.session_binding
        || request.maximum_response_bytes() != context.maximum_response_bytes
    {
        return Err(EffectFailure::Permanent(
            "Storage candidate outcome differs from signed query".to_owned(),
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { .. } = outcome.result() else {
        return Err(retryable(
            "Storage candidate query did not return a signed candidate",
        ));
    };
    if sample.host_boot_id() != context.query.host_boot_id() {
        return Err(retryable("Storage candidate Host boot changed"));
    }
    if !context.capture_limits.matches(
        candidate.admitted_bytes(),
        candidate.maximum_stdout_bytes(),
        candidate.maximum_stderr_bytes(),
    ) {
        return Err(EffectFailure::Permanent(
            "signed Storage candidate differs from protected accepted Create ceilings".to_owned(),
        ));
    }
    Ok(ControllerStorageCaptureCandidateObservationV1 {
        candidate: *candidate,
        query: context.query,
        settlement_digest: context.settlement_digest,
        outcome: outcome.clone(),
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        Audience, ReadStorageExecutionCaptureCandidateRequestV1, RequestHeader,
    };
    use aos_sandbox_protocol::storage_capture_candidate::{
        STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1, StorageCaptureCandidateQueryV1,
    };
    use buffa::Message as _;
    use sha2::{Digest as _, Sha256};

    use super::query_matches_body;

    fn query() -> StorageCaptureCandidateQueryV1 {
        let mut bytes = [0_u8; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSSCQ01");
        let settlement = &mut bytes[8..216];
        settlement[..8].copy_from_slice(b"AOSCIS01");
        settlement[8..24].fill(1);
        settlement[24..40].fill(2);
        settlement[40..72].fill(3);
        settlement[72..104].fill(4);
        settlement[104..112].copy_from_slice(&5_u64.to_be_bytes());
        settlement[112..144].fill(6);
        settlement[144..176].fill(7);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.controller-output-settlement.v1\0")
            .chain_update(&settlement[..176])
            .finalize();
        settlement[176..208].copy_from_slice(&checksum);

        bytes[216..248].fill(9);
        bytes[248..264].fill(10);
        bytes[264..280].fill(11);
        bytes[280..288].copy_from_slice(&1_u64.to_be_bytes());
        bytes[288..296].copy_from_slice(&2_u64.to_be_bytes());
        bytes[296..328].fill(13);
        bytes[328..344].fill(14);
        bytes[344..376].fill(15);
        bytes[376..392].fill(16);
        bytes[392..400].copy_from_slice(&1_000_u64.to_be_bytes());
        StorageCaptureCandidateQueryV1::from_canonical_bytes(&bytes).unwrap()
    }

    #[test]
    fn signed_query_body_requires_exact_session_request_and_deadline() {
        let query = query();
        let header = RequestHeader {
            protocol_major: 1,
            request_id: vec![16; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 1_000,
            maximum_response_bytes: 4_096,
            ..Default::default()
        };
        let request = ReadStorageExecutionCaptureCandidateRequestV1 {
            header: Some(header.clone()).into(),
            canonical_query: query.canonical_bytes().to_vec(),
            ..Default::default()
        };
        let body = request.encode_to_vec();
        assert!(query_matches_body(&query, &body, [15; 32], &header));
        assert!(!query_matches_body(&query, &body, [23; 32], &header));

        let mut foreign_header = header.clone();
        foreign_header.request_id[0] ^= 1;
        assert!(!query_matches_body(
            &query,
            &body,
            [15; 32],
            &foreign_header
        ));
        let mut foreign_header = header.clone();
        foreign_header.deadline_boottime_nanoseconds += 1;
        assert!(!query_matches_body(
            &query,
            &body,
            [15; 32],
            &foreign_header
        ));

        let mut altered = request;
        altered.canonical_query[216] ^= 1;
        assert!(!query_matches_body(
            &query,
            &altered.encode_to_vec(),
            [15; 32],
            &header
        ));
    }
}
