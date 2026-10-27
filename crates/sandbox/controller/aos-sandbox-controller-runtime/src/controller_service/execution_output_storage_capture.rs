//! Paid original Capture60 issuance and read-only Query61 recovery.
//!
//! The completed logical registration and informational candidate remain on
//! their actual Storage Session. Only the current accepted execution/source,
//! Environment, Parent and assignment conjunction may sign a new Reserve.
//! Historical original source DATA permits only a fresh read-only Query;
//! neither a durable attempt nor a completed result remints a physical flight.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_api::aos::sandbox::local::v1::{Audience, BrokerAuthorizationArtifactsV1,
    BrokerMethod, BrokerRequestEnvelope, ReserveStorageExecutionCaptureRequestV1,
    QueryStorageExecutionCaptureRequestV1};
use aos_sandbox_controller_domain::{AuthorityPublicationStore, EffectFailure, Journal};
use aos_sandbox_controller_domain::controller_execution_preissue::{ControllerExecutionPreissueV1,
    prepare_execution_reserve_source_with_checks_v4};
use aos_sandbox_controller_domain::controller_execution_output_settlement::read_current_controller_output_settlement_with_checks_v4;
use aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1;
use aos_sandbox_controller_domain::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox_controller_domain::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use aos_sandbox_model::{BrokerAudience, ProtocolId, ProtocolVersion, ResourceDimension as D,
    ResourceVector, RawPairedClockSample};
use aos_sandbox_protocol::storage_capture_grant::{StorageCaptureGrantMethodV1,
    StorageCaptureGrantSourceV1, ValidatedStorageCaptureAttemptV1,
    ValidatedStorageCaptureQueryResponseV2};

use crate::{BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1, DormantBrokerRequestPreparationV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1};
use crate::retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use super::capture_candidate_exchange::ControllerStorageCaptureCandidateObservationV1;
use super::execution_output_storage_registration::OriginalControllerOutputRegistrationV1;
use super::execution_output_storage_reserve::{current_output_assignment_matches,
    output_plan, OutputPlanAudience};
use super::plan_signer::ControllerBrokerPlanSignerV1;

use super::execution_lifetime::ExecutionLifetimeOriginalV5;

type Cause = Box<dyn Error + Send + Sync>;
type Bank = aos_sandbox_controller_domain::ControllerResourceBankOpeningV1;
type Profile = aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;

#[derive(Debug, thiserror::Error)]
#[error("the original paid Capture exchange is unavailable")]
struct Closed;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureMethodV2 { Reserve, Query }

impl CaptureMethodV2 {
    const fn broker(self) -> BrokerMethod {
        match self {
            Self::Reserve => BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1,
            Self::Query => BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1,
        }
    }

    const fn grant(self) -> StorageCaptureGrantMethodV1 {
        match self { Self::Reserve => StorageCaptureGrantMethodV1::Reserve,
            Self::Query => StorageCaptureGrantMethodV1::Query }
    }
}

/// This private distinction is derived from a completed original owner, never
/// a caller bool, source tuple or method discriminator accepted as authority.
#[derive(Clone, Copy)]
enum CaptureSourceV2<'source> {
    ReserveOngoing {
        registration: &'source OriginalControllerOutputRegistrationV1,
        candidate: &'source ControllerStorageCaptureCandidateObservationV1,
        specification: &'source aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptV1,
        lifetime: &'source ExecutionLifetimeOriginalV5,
    },
    Query(CaptureSourceDataV4),
}

/// Carries the sole signed ongoing source through the actual original owner.
#[derive(Clone, Copy)]
struct CaptureSourceDataV4(aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2);

impl CaptureSourceDataV4 {
    fn original(&self) -> &StorageCaptureGrantSourceV1 { self.0.original_source_v1() }

    fn bytes(&self) -> &[u8] { self.0.canonical_bytes_v2() }

    fn maximum_deadline(&self) -> u64 { self.0.effective_execution_deadline_v2() }

    fn grant(&self, method: StorageCaptureGrantMethodV1, request: [u8;16])
        -> Result<aos_sandbox_model::BrokerGrant, aos_sandbox_protocol::ProtocolValidationError>
    { self.0.broker_grant_v2(method, request) }
}

enum CaptureEnvironmentV4<'borrow, 'journal, 'evidence, 'historical> {
    Current(&'borrow mut EnvironmentProtectedJournalOwnerV1<'journal, 'evidence>),
    Historical(&'borrow aos_sandbox_controller_domain::environment::HistoricalEnvironmentExecutionOwnerV4<'historical>),
}

fn require_historical_source_v4(
    historical: &aos_sandbox_controller_domain::environment::HistoricalEnvironmentExecutionOwnerV4<'_>,
    source: CaptureSourceDataV4,
) -> Result<(), Cause> {
    historical.require_ongoing_capture_source_v4(&source.0)?;
    Ok(())
}

struct SignedCaptureRequestV2 {
    method: CaptureMethodV2,
    source: CaptureSourceDataV4,
    body: Vec<u8>,
    authorization: BrokerAuthorizationArtifactsV1,
}

#[allow(clippy::too_many_arguments)]
fn issue_current_once<T>(
    controller: &mut Journal, assignment: &CurrentAssignmentTarget,
    mut environment: CaptureEnvironmentV4<'_, '_, '_, '_>,
    parent: &ExecutionParentResourceSourceV1, preissue: &ControllerExecutionPreissueV1,
    signer: &ControllerBrokerPlanSignerV1, coordinates: DormantBrokerRequestCoordinatesV1,
    checks: &mut aos_sandbox_controller_domain::runtime_scope::ControllerCaptureAssignmentChecksV4,
    selected: CaptureSourceV2<'_>, original_records: Option<&aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1>, clock: &mut T,
) -> Result<SignedCaptureRequestV2, Cause>
where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
    if coordinates.request_id() == [0; 16]
        || coordinates.protocol_version() != ProtocolVersion::new(1, 0)
        || coordinates.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || coordinates.maximum_response_bytes()
            < aos_sandbox_protocol::storage_capture_grant::MAXIMUM_RESPONSE_BODY_BYTES as u32
    {
        return Err(Closed.into());
    }
    let settlement = read_current_controller_output_settlement_with_checks_v4(controller, assignment,
        preissue.execution(), preissue.create_operation(), clock, checks)?.ok_or(Closed)?;
    let accepted = match selected {
        CaptureSourceV2::ReserveOngoing { .. } => {
            let CaptureEnvironmentV4::Current(environment) = &mut environment else { return Err(Closed.into()); };
            let accepted = prepare_execution_reserve_source_with_checks_v4(controller, assignment,
                environment, parent, preissue, clock, checks)?;
            if settlement.original_attempt().source() != &accepted { return Err(Closed.into()); }
            accepted
        }
        CaptureSourceV2::Query(original) => {
            // Only the private completed C77 borrower constructs this branch.
            // Current protected settlement/assignment and a fresh signed Query
            // header authorize observation, never a second expired Reserve.
            if let CaptureEnvironmentV4::Historical(historical) = &environment {
                require_historical_source_v4(historical, original)?;
            }
            if original.original().settlement().canonical_bytes() != settlement.canonical_bytes().as_slice() {
                return Err(Closed.into());
            }
            settlement.original_attempt().source().clone()
        }
    };
    let current = AuthorityPublicationStore::new(controller).current(accepted.sandbox())?.ok_or(Closed)?;
    let broker_assignment = current.manifest().broker_assignment()?;
    if !current_output_assignment_matches(&current, &accepted, broker_assignment) {
        return Err(Closed.into());
    }
    let template = current.templates().iter().find(|template|
        template.audience() == BrokerAudience::Storage).ok_or(Closed)?;
    let parent_plan = template.plan();
    if parent_plan.assignment() != broker_assignment || parent_plan.node() != accepted.node()
        || parent_plan.protocol() != ProtocolId::StorageBroker
        || parent_plan.protocol_version() != ProtocolVersion::new(1, 0)
    { return Err(Closed.into()); }
    let (method, source, original_body) = match selected {
        CaptureSourceV2::ReserveOngoing { registration, candidate, specification, lifetime } => {
            let original = registration.completed_original_output_body_for_capture_v2(
                preissue.create_operation(), preissue.execution()).ok_or(Closed)?;
            let records = original_records.ok_or(Closed)?;
            if candidate.settlement_digest() != settlement.record_digest()
                || candidate.query().settlement().canonical_bytes() != settlement.canonical_bytes().as_slice()
                || candidate.query().assignment() != broker_assignment
            { return Err(Closed.into()); }
            if specification.execution() != preissue.execution()
                || specification.create_operation() != preissue.create_operation()
            { return Err(Closed.into()); }
            let owner = lifetime.owner()?;
            if owner.signed_lease_v2()?.digest() != current.lease().digest() {
                return Err(Closed.into());
            }
            let provenance = lifetime.prepared_data_for_parent_v5(specification, parent_plan)?;
            let source = CaptureSourceDataV4(
                    aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2::from_candidate_data_v2(
                        candidate.query(), candidate.candidate(), records, coordinates.request_id(),
                        coordinates.deadline_boottime_nanoseconds(), provenance)?);
            (CaptureMethodV2::Reserve, source, Some(original))
        }
        CaptureSourceV2::Query(original) => {
            // A query preserves the original bytes and ID. Its distinct fresh
            // header may observe an expired source but cannot reserve it again.
            if original.original().settlement().canonical_bytes() != settlement.canonical_bytes().as_slice()
                || original.original().assignment() != broker_assignment
                || original.original().original_reserve_request_id() == coordinates.request_id()
            { return Err(Closed.into()); }
            (CaptureMethodV2::Query, original, None)
        }
    };
    let sample = clock()?;
    if sample.host_boot_id() != preissue.host_boot_id()
        || sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
        || coordinates.deadline_boottime_nanoseconds() > assignment.deadline_boottime_nanoseconds()
        || method == CaptureMethodV2::Reserve
            && coordinates.deadline_boottime_nanoseconds() > preissue.deadline_boottime_nanoseconds()
    { return Err(Closed.into()); }
    let issued = sample.wall_seconds();
    let original_expiry = parent_plan.expires_seconds().min(current.lease().lease().authority_expires_seconds());
    // This is the existing signed ceiling, not candidate freshness or a new TTL.
    let expires = original_expiry;
    if issued < parent_plan.issued_seconds() || expires <= issued { return Err(Closed.into()); }
    let grant = source.grant(method.grant(), coordinates.request_id())?;
    let plan = output_plan(OutputPlanAudience::Storage, broker_assignment, accepted.node(),
        parent_plan, grant, issued, expires)?;
    let signed = signer.sign_plan(plan, issued)?;
    let rechecked = match selected {
        CaptureSourceV2::ReserveOngoing { .. } => {
            let CaptureEnvironmentV4::Current(environment) = &mut environment else { return Err(Closed.into()); };
            prepare_execution_reserve_source_with_checks_v4(controller, assignment, environment, parent, preissue, clock, checks)?
        }
        CaptureSourceV2::Query(source) => {
            let CaptureEnvironmentV4::Historical(historical) = &environment else { return Err(Closed.into()); };
            require_historical_source_v4(historical, source)?;
            accepted.clone()
        }
    };
    let reread = read_current_controller_output_settlement_with_checks_v4(controller, assignment,
        preissue.execution(), preissue.create_operation(), clock, checks)?.ok_or(Closed)?;
    let final_clock = clock()?;
    if rechecked != accepted || reread != settlement
        || final_clock.host_boot_id() != sample.host_boot_id()
        || sample.validate_later_sample(final_clock).is_err()
        || final_clock.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
        || final_clock.wall_seconds() >= expires
    { return Err(Closed.into()); }
    use buffa::Message as _;
    let body = match method {
        CaptureMethodV2::Reserve => ReserveStorageExecutionCaptureRequestV1 {
            header: Some(coordinates.request_header()).into(),
            canonical_grant_source: source.bytes().to_vec(),
            canonical_original_storage_output_request: original_body.ok_or(Closed)?.to_vec(),
            ..Default::default()
        }.encode_to_vec(),
        CaptureMethodV2::Query => QueryStorageExecutionCaptureRequestV1 {
            header: Some(coordinates.request_header()).into(),
            canonical_grant_source: source.bytes().to_vec(),
            ..Default::default()
        }.encode_to_vec(),
    };
    Ok(SignedCaptureRequestV2 { method, source, body,
        authorization: BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        } })
}

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "original Storage Capture request is absent",
    retained: "original Storage Capture request retains recovery custody",
    unusable: "Storage Capture Session is closed with its original custody",
};

struct CaptureRequestContextV2 {
    method: CaptureMethodV2,
    source: CaptureSourceDataV4,
    exact_body: Vec<u8>,
}

/// Borrows only the exact completed authenticated60 outcome on its live owner.
/// Its attempt is a durable effect fence, never physical readiness by itself.
pub(crate) struct AuthenticatedControllerStorageCaptureObservationV3 {
    source: CaptureSourceDataV4,
    outcome: aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    attempt: ValidatedStorageCaptureAttemptV1,
    storage_history: Vec<u8>,
    anchor: aos_sandbox_controller_domain::controller_storage_capture_admission::ControllerStorageCaptureAdmissionOriginalV3,
}

impl AuthenticatedControllerStorageCaptureObservationV3 {
    pub(crate) fn source_v1(&self) -> &StorageCaptureGrantSourceV1 { self.source.original() }

    pub(crate) fn source_v2(&self) -> Option<&aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2> {
        Some(&self.source.0)
    }

    pub(crate) fn response_bytes_v1(&self) -> &[u8] {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        match self.outcome.result() {
            AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
            _ => &[],
        }
    }

    pub(crate) fn storage_history_bytes_v2(&self) -> &[u8] { &self.storage_history }

    pub(crate) fn cutoff_v1(&self) -> u64 {
        self.attempt.effective_deadline_boottime_nanoseconds().unwrap_or(0)
            .min(self.source.maximum_deadline())
    }

    pub(crate) fn admission_anchor_bytes_v3(&self) -> &[u8] {
        self.anchor.completed_anchor_bytes_v3().unwrap_or(&[])
    }

    fn completed_v3(&self) -> bool {
        !self.admission_anchor_bytes_v3().is_empty() && self.cutoff_v1() != 0
    }
}

/// Borrows explicit ongoing source only from the completed native-backed owner.
pub(crate) struct AuthenticatedControllerStorageCaptureObservationV4<'owner> {
    original: &'owner AuthenticatedControllerStorageCaptureObservationV3,
    source: &'owner aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
}

impl AuthenticatedControllerStorageCaptureObservationV4<'_> {
    pub(crate) fn source_v2(&self) -> &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2 { self.source }

    pub(crate) fn response_bytes_v1(&self) -> &[u8] { self.original.response_bytes_v1() }

    pub(crate) fn cutoff_v1(&self) -> u64 { self.original.cutoff_v1() }

    pub(crate) fn admission_anchor_bytes_v3(&self) -> &[u8] { self.original.admission_anchor_bytes_v3() }
}

/// Borrows one actual completed Query61 flight and its protected original C77.
///
/// This view cannot be built from a response or decoded result. The original
/// keeps its signed exchange, currentness owner and all native post destinations
/// resident until the genuine outer Source/C18 disposal frontier.
pub(crate) struct AuthenticatedControllerStorageCaptureQueryObservationV3<'owner> {
    operation: aos_sandbox_model::OperationId,
    execution: aos_sandbox_model::ExecutionId,
    anchor: &'owner aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1,
    outcome: &'owner aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    currentness: &'owner ProtectedBrokerOutcomeCurrentnessOwnerV1,
    response: &'owner ValidatedStorageCaptureQueryResponseV2,
}

impl AuthenticatedControllerStorageCaptureQueryObservationV3<'_> {
    pub(crate) const fn operation_v3(&self) -> aos_sandbox_model::OperationId { self.operation }

    pub(crate) const fn execution_v3(&self) -> aos_sandbox_model::ExecutionId { self.execution }

    pub(crate) fn source_v1(&self) -> &StorageCaptureGrantSourceV1 { self.anchor.source_v1() }

    pub(crate) fn source_v2(&self) -> Option<&aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2> {
        self.anchor.ongoing_source_v2()
    }

    pub(crate) fn attempt_v3(&self) -> ValidatedStorageCaptureAttemptV1 { self.response.attempt() }

    pub(crate) fn outcome_v3(&self)
        -> &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1
    { self.outcome }

    pub(crate) fn currentness_v3(&self) -> &ProtectedBrokerOutcomeCurrentnessOwnerV1 { self.currentness }

    pub(crate) fn complete_record_v3(&self)
        -> Option<&aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2>
    { self.response.complete_record() }

    pub(crate) fn admission_anchor_bytes_v3(&self) -> &[u8] { self.anchor.canonical_bytes_v1() }
}

#[derive(Default)]
struct CaptureFlightV2 {
    receiving: super::argument_exchange::ExecutionSessionReceivingOriginalV1,
    post: super::execution_authorize::ExecutionClientPostSlotV1,
    post_arm: Option<Result<(), BrokerSessionSecurityError>>,
    post_finish: Option<Result<(), BrokerSessionSecurityError>>,
    anchor_result: Option<Result<(), aos_sandbox_controller_domain::controller_storage_capture_admission::ControllerStorageCaptureAdmissionErrorV3>>,
    exchange: RetainedBrokerExchangeV1<CaptureRequestContextV2>,
    output_preparation: Option<Box<CaptureOutputPreparationV3>>,
    preparation: Option<Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>>,
    fixed_payment: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    source_inputs: Option<Result<Option<aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1>, Cause>>,
    history: Option<Result<Vec<u8>, Cause>>,
    issued: Option<Result<SignedCaptureRequestV2, Cause>>,
    context: Option<CaptureRequestContextV2>,
    outcome: Option<aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1>,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    current_before: Option<Result<(), BrokerSessionSecurityError>>,
    current_after: Option<Result<(), BrokerSessionSecurityError>>,
    decoded: Option<Result<ValidatedStorageCaptureQueryResponseV2,
        aos_sandbox_protocol::ProtocolValidationError>>,
    reserve: Option<AuthenticatedControllerStorageCaptureObservationV3>,
    returned: Option<Result<(), EffectFailure>>,
    first: Option<FlightFirstV2>,
    entered: bool,
}

#[derive(Clone, Copy)]
enum FlightFirstV2 { Receiving, PostArm, Inputs, Issuer, Preparation, Exchange, CurrentBefore, Decode, CurrentAfter, History, OutputPreparation, Post, Anchor, Returned }

impl CaptureFlightV2 {
    fn fixed_demand_v2(method: CaptureMethodV2) -> Option<ResourceVector> {
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<SignedCaptureRequestV2>().checked_mul(2)?)?
            .checked_add(size_of::<CaptureRequestContextV2>().checked_mul(2)?)?;
        let preparation = if method == CaptureMethodV2::Reserve {
            CaptureOutputPreparationV3::receiving_demand_v3()?
        } else { ResourceVector::ZERO };
        aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2::receiving_demand_v2()?
            .checked_add(preparation).ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)).ok()?
            .checked_add(super::execution_authorize::ExecutionClientPostSlotV1::receiving_demand_v1()?).ok()
    }

    fn begin<T>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1, method: CaptureMethodV2,
        selected: CaptureSourceV2<'_>,
        assignment: &CurrentAssignmentTarget, controller: &mut Journal,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>, bank: &Bank, profile: &Profile,
        signer: &ControllerBrokerPlanSignerV1, clock: &mut T,
        issue: impl FnOnce(DormantBrokerRequestCoordinatesV1, &mut Journal,
            Option<&aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1>, &mut T) -> Result<SignedCaptureRequestV2, Cause>,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        if self.entered || self.failure().is_some() { return Err(closed()); }
        self.entered = true;
        self.first = Some(FlightFirstV2::Receiving);
        let fixed = Self::fixed_demand_v2(method).ok_or_else(closed)?;
        self.fixed_payment = Some(receiving.admit_stage_v1(bank, controller, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(fixed)));
        if !matches!(self.fixed_payment, Some(Ok(()))) { return Err(closed()); }
        if method == CaptureMethodV2::Reserve {
            self.output_preparation = Some(Box::new(CaptureOutputPreparationV3::new()));
        }
        self.first = Some(FlightFirstV2::PostArm);
        self.post_arm = Some(
            self.post
                .initialize_once_v1()
                .and_then(|()| self.post.native_mut_v1())
                .and_then(|post| session.arm_execution_client_post_v1(post))
        );
        if !matches!(self.post_arm, Some(Ok(()))) { return Err(closed()); }
        self.first = Some(FlightFirstV2::Receiving);
        self.receiving.admit_v1(session, method.broker(), receiving, bank, controller, profile)?;
        self.first = Some(FlightFirstV2::Inputs);
        self.source_inputs = Some((|| {
            match selected {
                CaptureSourceV2::ReserveOngoing { registration, candidate, .. } => {
                    let records = registration.completed_original_records_for_capture_v3(
                        candidate.query().settlement().create_operation(),
                        candidate.query().settlement().execution()).ok_or(Closed)?;
                    if records.assignment() != candidate.query().assignment() {
                        return Err(Closed.into());
                    }
                    Ok(Some(*records))
                }
                CaptureSourceV2::Query(_) => Ok(None),
            }
        })());
        if self.source_inputs.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        self.first = Some(FlightFirstV2::Issuer);
        let mut issued = None;
        let mut context = None;
        let original_records = self.source_inputs.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref);
        let build = |coordinates| {
            issued = Some(issue(coordinates, controller, original_records, clock));
            let Some(Ok(signed)) = &issued else { return Err(BrokerSessionSecurityError::Currentness); };
            if signed.method != method { return Err(BrokerSessionSecurityError::Currentness); }
            context = Some(CaptureRequestContextV2 { method, source: signed.source,
                exact_body: signed.body.clone() });
            Ok(BrokerRequestEnvelope { method: method.broker().into(), body: signed.body.clone(),
                authorization: Some(signed.authorization.clone()).into(), ..Default::default() })
        };
        self.preparation = Some(match selected {
            CaptureSourceV2::ReserveOngoing { candidate, .. } => {
                session.prepare_storage_capture_reserve_ongoing_v3(candidate.candidate(), build, |_| true)
            }
            CaptureSourceV2::Query(_) => session.prepare_storage_capture_query_v2(assignment, build, |_| true),
        });
        self.issued = issued;
        self.context = context;
        if self.issued.as_ref().is_some_and(Result::is_err) { return Err(closed()); }
        self.first = Some(FlightFirstV2::Preparation);
        if !matches!(self.preparation, Some(Ok(DormantBrokerRequestPreparationV1::Prepared(_)))) {
            return Err(closed());
        }
        let context = self.context.take().ok_or_else(closed)?;
        if let Some(Ok(DormantBrokerRequestPreparationV1::Prepared(prepared))) = self.preparation.take() {
            self.exchange.start_generation(context, prepared);
        }
        self.first = Some(FlightFirstV2::Exchange);
        if let CaptureSourceV2::ReserveOngoing { registration, .. } = selected {
            self.exchange.begin_capture_preparation_v3(session, &ERRORS)?;
            self.first = Some(FlightFirstV2::OutputPreparation);
            let request = self.exchange.capture_preparation_request_v3().ok_or_else(closed)?;
            self.output_preparation.as_mut().ok_or_else(closed)?
                .advance_once_v3(session, request, registration, controller, signer, clock)?;
            self.first = Some(FlightFirstV2::Exchange);
        }
        let (context, outcome, currentness) = self.exchange.drive_execution_publication(session, &ERRORS)?;
        self.context = Some(context);
        self.outcome = Some(outcome);
        self.currentness = Some(currentness);
        self.classify_once(session)
    }

    fn classify_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> Result<(), EffectFailure> {
        self.first = Some(FlightFirstV2::CurrentBefore);
        let post = self.post.native_mut_v1()
            .map_err(|_| closed())?;
        let original = self.currentness.take().ok_or_else(closed)?;
        let mut current = match session.retain_execution_outcome_current_with_post_v1(original, post) {
            Ok(current) => { self.current_before = Some(Ok(())); current }
            Err((original, error)) => {
                self.currentness = Some(original);
                self.current_before = Some(Err(error));
                return Err(closed());
            }
        };
        self.first = Some(FlightFirstV2::Decode);
        self.decoded = Some((|| {
            use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
            let invalid = || aos_sandbox_protocol::ProtocolValidationError::InvalidField("original Capture outcome");
            let context = self.context.as_ref().ok_or_else(invalid)?;
            let outcome = self.outcome.as_ref().ok_or_else(invalid)?;
            if outcome.method() != context.method.broker()
                || outcome.request().exact_body() != context.exact_body
            { return Err(invalid()); }
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
                return Err(invalid());
            };
            if context.method == CaptureMethodV2::Reserve {
                // The Reserve decoder explicitly rejects cold Complete. This
                // native-backed observation can enter V4 only as EffectPossible.
                aos_sandbox_protocol::storage_capture_grant::decode_storage_capture_attempt_response_ongoing_v2(
                    exact_body, &context.source.0, false)?;
            }
            aos_sandbox_protocol::storage_capture_grant::decode_storage_capture_query_response_ongoing_v2(
                exact_body, &context.source.0)
        })());
        // This actual terminal post remains owed after classification refusal.
        self.current_after = Some(
            self.post
                .native_mut_v1()
                .and_then(|post| current.revalidate_execution_with_post_v1(post))
        );
        self.currentness = Some(current.into_currentness_owner());
        if self.decoded.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        self.first = Some(FlightFirstV2::CurrentAfter);
        if !matches!(self.current_after, Some(Ok(()))) { return Err(closed()); }
        self.first = Some(FlightFirstV2::History);
        self.history = Some((|| {
            let held = session.storage_capture_history_data_v2()?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(held.len())?;
            bytes.extend_from_slice(held);
            Ok(bytes)
        })());
        if self.history.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        if self.context.as_ref().is_some_and(|context| context.method == CaptureMethodV2::Reserve) {
            self.reserve = Some(AuthenticatedControllerStorageCaptureObservationV3 {
                source: self.context.as_ref().ok_or_else(closed)?.source,
                attempt: self.decoded.as_ref().and_then(|value| value.as_ref().ok()).ok_or_else(closed)?.attempt(),
                outcome: self.outcome.take().ok_or_else(closed)?,
                anchor: aos_sandbox_controller_domain::controller_storage_capture_admission::ControllerStorageCaptureAdmissionOriginalV3::new(),
                storage_history: match self.history.take() {
                    Some(Ok(bytes)) => bytes,
                    retained => { self.history = retained; return Err(closed()); }
                },
            });
        }
        self.first = None;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(FlightFirstV2::Receiving) => self.fixed_payment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.receiving.failure()),
            Some(FlightFirstV2::PostArm) => self.post.failure()
                .or_else(|| self.post_arm.as_ref().and_then(|result| result.as_ref().err()).map(|e| e as _)),
            Some(FlightFirstV2::Inputs) => self.source_inputs.as_ref().and_then(|v| v.as_ref().err())
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            Some(FlightFirstV2::History) => self.history.as_ref().and_then(|v| v.as_ref().err())
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            Some(FlightFirstV2::Issuer) => self.issued.as_ref().and_then(|v| v.as_ref().err())
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            Some(FlightFirstV2::Preparation) => self.preparation.as_ref().and_then(|result| match result {
                Err(error) | Ok(DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error, .. })
                    | Ok(DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error, .. }) => Some(error as _),
                _ => None,
            }),
            Some(FlightFirstV2::Exchange) => self.exchange.execution_failure(),
            Some(FlightFirstV2::OutputPreparation) => self.output_preparation.as_ref()?.failure(),
            Some(FlightFirstV2::CurrentBefore) => self.current_before.as_ref().and_then(|v| v.as_ref().err())
                .map(|cause| self.post.terminal_before_failure_v1().unwrap_or(cause)),
            Some(FlightFirstV2::Decode) => self.decoded.as_ref().and_then(|v| v.as_ref().err()).map(|cause| cause as _),
            Some(FlightFirstV2::CurrentAfter) => self.current_after.as_ref().and_then(|v| v.as_ref().err())
                .map(|cause| self.post.terminal_after_failure_v1().unwrap_or(cause)),
            Some(FlightFirstV2::Post) => self.post.failure()
                .or_else(|| self.post_finish.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)),
            Some(FlightFirstV2::Anchor) => self.reserve.as_ref().and_then(|v| v.anchor.failure())
                .or_else(|| self.anchor_result.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)),
            Some(FlightFirstV2::Returned) | None => None,
        };
        selected.or_else(|| self.returned.as_ref().and_then(|v| v.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.post.failure())
    }
}

fn closed() -> EffectFailure { EffectFailure::Retryable(Closed.to_string()) }


/// Owns the single original physical admission and its distinct read-only query.
///
/// The remote same-F Storage resident and Host20 own the physical lifetime.
/// This Controller owner retains its actual signed Session and protected C
/// anchor until the real outer Source/C18 positive-disposal token.
#[derive(Default)]
pub(crate) struct OriginalControllerStorageCaptureV3 {
    operation: Option<aos_sandbox_model::OperationId>,
    execution: Option<aos_sandbox_model::ExecutionId>,
    source_checks_required: Option<Result<ResourceVector, Closed>>,
    source_checks_funding: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    source_checks: Option<Result<aos_sandbox_controller_domain::runtime_scope::ControllerCaptureAssignmentChecksV4,
        aos_sandbox_controller_domain::runtime_scope::CurrentRuntimeScopeError>>,
    lifetime: ExecutionLifetimeOriginalV5,
    lifetime_preparation: Option<Result<(), EffectFailure>>,
    lifetime_post_first: bool,
    reserve: CaptureFlightV2,
    query: CaptureFlightV2,
    query_source: Option<Result<aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1,
        aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorErrorV1>>,
    query_source_read: Option<Result<(), Cause>>,
    query_source_widths: Option<Result<(usize, usize), aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorErrorV1>>,
    query_source_funding: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    query_source_demand: Option<Result<ResourceVector, aos_sandbox_controller_domain::journal::broker_session_receiving::StorageSessionGeometryRefusalV1>>,
    retired: bool,
}

impl OriginalControllerStorageCaptureV3 {
    pub(crate) fn construction_demand_v3() -> Option<ResourceVector> {
        Some(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(size_of::<Self>().checked_mul(2)?).ok()?))
    }

    fn prepare_source_checks_v4(&mut self, controller: &mut Journal, assignment: &CurrentAssignmentTarget,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>, bank: &Bank, profile: &Profile)
        -> Result<(), EffectFailure>
    {
        if self.source_checks_required.is_some() { return Err(closed()); }
        self.source_checks_required = Some(assignment.capture_source_checks_receiving_demand_v4(controller).ok_or(Closed));
        let demand = self.source_checks_required.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or_else(closed)?;
        self.source_checks_funding = Some(receiving.admit_stage_v1(bank, controller, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
        if !matches!(self.source_checks_funding, Some(Ok(()))) { return Err(closed()); }
        self.source_checks = Some(assignment.prepare_capture_source_checks_v4(controller));
        if self.source_checks.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_once_v4<T>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        registration: &OriginalControllerOutputRegistrationV1,
        candidate: &ControllerStorageCaptureCandidateObservationV1,
        controller: &mut Journal, assignment: &CurrentAssignmentTarget,
        environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
        parent: &ExecutionParentResourceSourceV1, preissue: &ControllerExecutionPreissueV1,
        specification: &aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptV1,
        signer: &ControllerBrokerPlanSignerV1,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &Bank, profile: &Profile, clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.operation.is_some() || self.execution.is_some() || self.retired
            || receiving.operation_v1() != preissue.create_operation()
        { return Err(closed()); }
        self.operation = Some(receiving.operation_v1());
        self.execution = Some(preissue.execution());
        self.prepare_source_checks_v4(controller, assignment, receiving, bank, profile)?;
        self.lifetime_preparation = Some(self.lifetime.prepare_once(assignment, controller, specification,
            receiving, bank, profile, clock));
        if !matches!(self.lifetime_preparation, Some(Ok(()))) {
            // A successful first verifier still owes its distinct bookend
            // when later model decoding refuses before Session entry.
            let _after = self.lifetime.finish_once(assignment, controller, clock);
            return Err(closed());
        }
        let selected = CaptureSourceV2::ReserveOngoing { registration, candidate, specification, lifetime: &self.lifetime };
        let checks = self.source_checks.as_mut().and_then(|result| result.as_mut().ok()).ok_or_else(closed)?;
        let primary = self.reserve.begin(session, CaptureMethodV2::Reserve, selected,
            assignment, controller, receiving, bank, profile, signer, clock,
            |coordinates, controller, original_records, clock| issue_current_once(controller, assignment, CaptureEnvironmentV4::Current(environment),
                parent, preissue, signer, coordinates, &mut *checks, selected, original_records, clock));
        let lifetime_after = self.lifetime.finish_once(assignment, controller, clock);
        let after = if self.reserve.post_arm.is_some() {
            self.reserve.post_finish = Some(
                self.reserve.post
                    .native_mut_v1()
                    .and_then(|post| session.finish_execution_client_post_v1(post))
            );
            if matches!(self.reserve.post_finish, Some(Ok(()))) { Ok(()) }
            else { Err(closed()) }
        } else { Ok(()) };
        self.lifetime_post_first = primary.is_ok() && lifetime_after.is_err();
        if primary.is_ok() && lifetime_after.is_ok() && after.is_err() {
            self.reserve.first = Some(FlightFirstV2::Post);
        }
        self.reserve.returned = Some(primary.and(lifetime_after).and(after));
        if !matches!(self.reserve.returned, Some(Ok(()))) { return Err(closed()); }

        self.reserve.first = Some(FlightFirstV2::Anchor);
        let original = self.reserve.reserve.as_mut().ok_or_else(closed)?;
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = original.outcome.result()
        else { return Err(closed()); };
        self.reserve.anchor_result = Some(original.anchor.retain_ongoing_once_with_checks_v4(controller, assignment,
            receiving, bank, profile, &original.source.0, exact_body, &original.storage_history, clock, checks));
        if !matches!(self.reserve.anchor_result, Some(Ok(()))) { return Err(closed()); }
        self.reserve.first = None;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn query_original_historical_once_v4<T>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &mut Journal, assignment: &CurrentAssignmentTarget,
        historical: &aos_sandbox_controller_domain::environment::HistoricalEnvironmentExecutionOwnerV4<'_>,
        parent: &ExecutionParentResourceSourceV1, preissue: &ControllerExecutionPreissueV1,
        signer: &ControllerBrokerPlanSignerV1,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &Bank, profile: &Profile, clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        historical.require_historical_binding_v4().map_err(|_| closed())?;
        if self.operation.is_some() || self.query.entered || self.query_source.is_some() || self.retired
            || self.reserve.entered || self.failure().is_some()
        { return Err(closed()); }
        self.operation = Some(receiving.operation_v1());
        self.execution = Some(preissue.execution());
        use aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1 as Anchor;
        self.query_source_read = Some((|| {
            let bytes = aos_sandbox_controller_domain::controller_storage_capture_admission::controller_capture_admission_bytes_v3(
                controller, preissue.execution())?.ok_or(Closed)?;
            self.query_source_widths = Some(Anchor::payload_widths_v4(bytes));
            Ok(())
        })());
        if !matches!(self.query_source_read, Some(Ok(()))) { return Err(closed()); }
        let (response, history) = self.query_source_widths.as_ref()
            .and_then(|result| result.as_ref().ok()).copied().ok_or_else(closed)?;
        self.query_source_demand = Some(aos_sandbox_controller_domain::journal::broker_session_receiving::controller_capture_anchor_model_demand_ongoing_v4(
            response, history));
        let model = self.query_source_demand.as_ref().and_then(|v| v.as_ref().ok()).copied().ok_or_else(closed)?;
        self.query_source_funding = Some(receiving.admit_stage_v1(bank, controller, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(model)));
        if !matches!(self.query_source_funding, Some(Ok(()))) { return Err(closed()); }
        // The exact same native row is reborrowed after the funding mutation;
        // no request tuple or current Session checkpoint can substitute it.
        self.query_source_read = Some((|| {
            let bytes = aos_sandbox_controller_domain::controller_storage_capture_admission::controller_capture_admission_bytes_v3(
                controller, preissue.execution())?.ok_or(Closed)?;
            self.query_source = Some(Anchor::decode(bytes));
            Ok(())
        })());
        if !matches!(self.query_source_read, Some(Ok(()))) { return Err(closed()); }
        self.prepare_source_checks_v4(controller, assignment, receiving, bank, profile)?;
        let anchor = self.query_source.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(closed)?;
        if anchor.source_v1().settlement().create_operation() != preissue.create_operation()
            || anchor.source_v1().settlement().execution() != preissue.execution()
        { return Err(closed()); }
        let selected = CaptureSourceV2::Query(CaptureSourceDataV4(*anchor.ongoing_source_v2().ok_or_else(closed)?));
        let checks = self.source_checks.as_mut().and_then(|result| result.as_mut().ok()).ok_or_else(closed)?;
        let primary = self.query.begin(session, CaptureMethodV2::Query, selected,
            assignment, controller, receiving, bank, profile, signer, clock,
            |coordinates, controller, original_records, clock| issue_current_once(controller, assignment, CaptureEnvironmentV4::Historical(historical),
                parent, preissue, signer, coordinates, &mut *checks, selected, original_records, clock));
        let after = if self.query.post_arm.is_some() {
            self.query.post_finish = Some(
                self.query.post
                    .native_mut_v1()
                    .and_then(|post| session.finish_execution_client_post_v1(post))
            );
            if matches!(self.query.post_finish, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
        } else { Ok(()) };
        if primary.is_ok() && after.is_err() { self.query.first = Some(FlightFirstV2::Post); }
        self.query.returned = Some(primary.and(after));
        if !matches!(self.query.returned, Some(Ok(()))) { return Err(closed()); }
        if self.query.decoded.as_ref().and_then(|result| result.as_ref().ok())
            .is_none_or(|response| response.attempt() != anchor.attempt_v3())
        {
            self.query.first = Some(FlightFirstV2::Returned);
            self.query.returned = Some(Err(closed()));
            return Err(closed());
        }
        Ok(())
    }

    pub(crate) fn completed_query_v3(&self, operation: aos_sandbox_model::OperationId,
        execution: aos_sandbox_model::ExecutionId)
        -> Option<AuthenticatedControllerStorageCaptureQueryObservationV3<'_>>
    {
        if self.retired || self.operation != Some(operation) || self.execution != Some(execution)
            || !matches!(self.query.current_before, Some(Ok(())))
            || !matches!(self.query.current_after, Some(Ok(())))
        { return None; }
        let response = self.query_response_v3()?;
        let anchor = self.query_source.as_ref()?.as_ref().ok()?;
        if response.attempt() != anchor.attempt_v3() { return None; }
        Some(AuthenticatedControllerStorageCaptureQueryObservationV3 {
            operation, execution, anchor, response,
            outcome: self.query.outcome.as_ref()?,
            currentness: self.query.currentness.as_ref()?,
        })
    }

    pub(crate) fn query_response_v3(&self) -> Option<&ValidatedStorageCaptureQueryResponseV2> {
        if self.failure().is_some() || !matches!(self.query.returned, Some(Ok(())))
            || !matches!(self.query.post_finish, Some(Ok(()))) { return None; }
        self.query.decoded.as_ref()?.as_ref().ok()
    }

    pub(crate) fn completed_admission_v4(&self, operation: aos_sandbox_model::OperationId,
        execution: aos_sandbox_model::ExecutionId) -> Option<AuthenticatedControllerStorageCaptureObservationV4<'_>>
    {
        if self.retired || self.operation != Some(operation) || self.execution != Some(execution)
            || self.failure().is_some() || !matches!(self.reserve.returned, Some(Ok(())))
            || !matches!(self.reserve.post_finish, Some(Ok(()))) || !self.lifetime.completed()
        { return None; }
        let original = self.reserve.reserve.as_ref().filter(|original| original.completed_v3())?;
        Some(AuthenticatedControllerStorageCaptureObservationV4 { original, source: original.source_v2()? })
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.source_checks_required.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.source_checks_funding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.source_checks.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.lifetime.preparation_failure())
            .or_else(|| self.source_checks.as_ref().and_then(|result| result.as_ref().ok()).and_then(|original| original.failure_v4()))
            .or_else(|| self.lifetime_preparation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| if self.lifetime_post_first { self.lifetime.post_failure() } else { None })
            .or_else(|| self.reserve.failure())
            .or_else(|| self.lifetime.post_failure())
            .or_else(|| self.query_source_read.as_ref().and_then(|v| v.as_ref().err()).map(|e| e.as_ref() as _))
            .or_else(|| self.query_source_widths.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.query_source_demand.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.query_source_funding.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.query_source.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.query.failure())
    }

    pub(crate) fn failure_with_session_v3<'owner>(
        &'owner self, session: &'owner DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'owner (dyn Error + 'static)> {
        let selected = self.failure()?;
        if self.reserve.first.is_some_and(|first| matches!(first, FlightFirstV2::OutputPreparation)) {
            if let Some(preparation) = &self.reserve.output_preparation {
                if preparation.failure().is_some_and(|cause| std::ptr::eq(cause, selected)) {
                    return preparation.failure_with_session_v3(session).or(Some(selected));
                }
            }
        }
        Some(selected)
    }

    pub(crate) fn retire_positive_v3(&mut self,
        disposal: &aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionPositiveDisposalV1<'_>,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<(), EffectFailure> {
        let original = self.completed_admission_v4(disposal.operation_v1(), execution).is_some();
        let queried = self.operation == Some(disposal.operation_v1()) && self.execution == Some(execution)
            && self.query_response_v3().is_some();
        if (!original && !queried) || self.failure().is_some() { return Err(closed()); }
        // The token is the actual outer positive Source/C cut. No physical
        // Storage resident or Host terminal interval is retired by this move.
        self.retired = true;
        Ok(())
    }
}

impl Drop for OriginalControllerStorageCaptureV3 {
    fn drop(&mut self) {
        if !self.retired && (self.reserve.entered || self.query.entered || self.lifetime.entered()) {
            std::process::abort();
        }
    }
}

/// Owns the fresh counterleg until the enclosing60/native77 disposal boundary.
struct CaptureOutputPreparationV3 {
    preparation: aos_sandbox_broker_session_security::controller_composition::OutputPreparationCustodyV1,
    host_issuer: super::execution_output_storage_reserve::OriginalHostOutputIssuerV1,
    authorization: Option<aos_sandbox_api::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1>,
    readiness: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 2],
    result: Option<Result<(), EffectFailure>>,
    first: CapturePreparationFirstV3,
}

#[derive(Clone, Copy)]
enum CapturePreparationFirstV3 { Wait, Receive, Signer, Send, Complete }

impl CaptureOutputPreparationV3 {
    fn new() -> Self {
        Self {
            preparation: aos_sandbox_broker_session_security::controller_composition::OutputPreparationCustodyV1::empty(),
            host_issuer: super::execution_output_storage_reserve::OriginalHostOutputIssuerV1::empty(),
            authorization: None, readiness: std::array::from_fn(|_| None), result: None,
            first: CapturePreparationFirstV3::Wait,
        }
    }

    fn receiving_demand_v3() -> Option<ResourceVector> {
        aos_sandbox_broker_session_security::controller_composition::OutputPreparationCustodyV1::client_receiving_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(size_of::<Self>().checked_mul(2)?).ok()?)).ok()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            CapturePreparationFirstV3::Signer => self.host_issuer.failure()
                .or_else(|| self.host_issuer.postcheck_debt()),
            CapturePreparationFirstV3::Wait => self.readiness.iter().flatten().find_map(|result|
                result.as_ref().err().map(|error| error as _)),
            _ => None,
        }.or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }

    fn failure_with_session_v3<'owner>(&'owner self,
        session: &'owner DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'owner (dyn Error + 'static)> {
        // The immutable stage marker determines chronology; a later native
        // post cannot replace a preceding signer or readiness refusal.
        match self.first {
            CapturePreparationFirstV3::Receive | CapturePreparationFirstV3::Send =>
                session.output_preparation_failure(&self.preparation)
                    .or_else(|| session.output_preparation_postcheck_debt(&self.preparation))
                    .or_else(|| self.failure()),
            _ => self.failure(),
        }
    }

    fn advance_once_v3<T>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        registration: &OriginalControllerOutputRegistrationV1, controller: &mut Journal,
        signer: &ControllerBrokerPlanSignerV1, clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        if self.result.is_some() { return Err(closed()); }
        let result = self.advance_inner_v3(session, request, registration, controller, signer, clock);
        self.result = Some(result);
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    fn advance_inner_v3<T>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        registration: &OriginalControllerOutputRegistrationV1, controller: &mut Journal,
        signer: &ControllerBrokerPlanSignerV1, clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        let cutoff = request.deadline_boottime_nanoseconds();
        self.readiness[0] = Some((|| {
            aos_sandbox_broker_session_security::controller_composition::wait_for_handshake_readiness(
                session.as_fd()?, false, cutoff)
        })());
        if !matches!(self.readiness[0], Some(Ok(()))) { return Err(closed()); }
        self.first = CapturePreparationFirstV3::Receive;
        let authorization = super::execution_output_storage_registration::prepare_output_authorization_v3(
            super::execution_output_storage_registration::HostOutputPreparationSourceV3::Capture(registration),
            session, controller, request, &mut self.preparation, &mut self.host_issuer, signer, clock);
        if self.host_issuer.failure().is_some() || self.host_issuer.postcheck_debt().is_some() {
            self.first = CapturePreparationFirstV3::Signer;
        }
        self.authorization = Some(authorization?);
        self.first = CapturePreparationFirstV3::Wait;
        self.readiness[1] = Some((|| {
            aos_sandbox_broker_session_security::controller_composition::wait_for_handshake_readiness(
                session.as_fd()?, true, cutoff)
        })());
        if !matches!(self.readiness[1], Some(Ok(()))) { return Err(closed()); }
        let record = self.authorization.as_ref().ok_or_else(closed)?;
        self.first = CapturePreparationFirstV3::Send;
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        transport.send(request, record).map_err(|_| closed())?;
        transport.finish_turn(request).map_err(|_| closed())?;
        self.first = CapturePreparationFirstV3::Complete;
        Ok(())
    }
}
