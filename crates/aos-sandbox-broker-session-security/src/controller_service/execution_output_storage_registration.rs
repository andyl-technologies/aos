//! Original Controller output registration over its existing Storage session.
//!
//! One admitted Create owns this prearmed attempt. The Storage request, two
//! pending preparation packets, distinct Host authorization and authenticated
//! terminal remain resident until coordinated terminal retirement. This is
//! logical AOSEOR03/AOSEOS01 registration, not physical capture or Create Ready.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, StorageOutputRegistrationPreparationV1,
};
use aos_sandbox::controller_execution_preissue::{
    ControllerExecutionPreissueV1, ControllerExecutionReserveSourceErrorV1,
    ControllerExecutionReserveSourceV1, prepare_execution_reserve_source_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{EffectFailure, Journal};
use aos_sandbox_core::{ExecutionId, OperationId, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use aos_sandbox_protocol::storage_output_reserve::continuation::{AUTHORIZATION_V1, NOMINATION_V1};

use super::execution_output_storage_reserve::{
    OriginalHostOutputIssuerV1, OriginalStorageOutputIssuerV1,
};
use super::SharedControllerBrokerSessions;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::handshake::output_registration_continuation::{
    OriginalOutputClientFlightV1, OutputPreparationCustodyV1,
};
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    ProtectedBrokerOutcomeCommitResultV1,
};

pub(crate) struct OriginalControllerOutputRegistrationV1 {
    operation: OperationId,
    execution: ExecutionId,
    started: bool,
    ended: bool,
    storage_issuer: OriginalStorageOutputIssuerV1,
    host_issuer: OriginalHostOutputIssuerV1,
    flight: OriginalOutputClientFlightV1,
    preparation: OutputPreparationCustodyV1,
    authorization: Option<StorageOutputRegistrationPreparationV1>,
    readiness: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 4],
    source_bookends: [Option<Result<ControllerExecutionReserveSourceV1, ControllerExecutionReserveSourceErrorV1>>; 3],
    clock_bookends: [Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>; 3],
    terminal_current: Option<Result<(), BrokerSessionSecurityError>>,
    terminal_witness_checks: [Option<bool>; 2],
    first_validation: Option<EffectFailure>,
    postcheck_debt: Option<EffectFailure>,
    coordinated_terminal: bool,
}

impl OriginalControllerOutputRegistrationV1 {
    pub(crate) fn has_pending(&self) -> bool {
        !self.coordinated_terminal
    }

    fn begin(operation: OperationId, execution: ExecutionId) -> Self {
        Self {
            operation,
            execution,
            started: false,
            ended: false,
            storage_issuer: OriginalStorageOutputIssuerV1::empty(),
            host_issuer: OriginalHostOutputIssuerV1::empty(),
            flight: OriginalOutputClientFlightV1::empty(),
            preparation: OutputPreparationCustodyV1::empty(),
            authorization: None,
            readiness: std::array::from_fn(|_| None),
            source_bookends: std::array::from_fn(|_| None),
            clock_bookends: std::array::from_fn(|_| None),
            terminal_current: None,
            terminal_witness_checks: [None; 2],
            first_validation: None,
            postcheck_debt: None,
            coordinated_terminal: false,
        }
    }

    pub(crate) fn failure<'a>(
        &'a self,
        session: &'a crate::DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if let Some(error) = self.storage_issuer.failure() {
            return Some(error);
        }
        if let Some(error) = session.output_client_flight_failure(&self.flight) {
            return Some(error);
        }
        if let Some(error) = session.output_preparation_failure(&self.preparation) {
            return Some(error);
        }
        if let Some(error) = self.host_issuer.failure() {
            return Some(error);
        }
        for result in self.readiness.iter().flatten() {
            if let Err(error) = result {
                return Some(error);
            }
        }
        for result in self.source_bookends[..2].iter().flatten() {
            if let Err(error) = result {
                return Some(error);
            }
        }
        for result in self.clock_bookends[..2].iter().flatten() {
            if let Err(error) = result {
                return Some(error);
            }
        }
        if self.terminal_witness_checks[0] == Some(false) {
            if let Some(witness) = session.output_terminal_witness_failure() {
                return Some(witness);
            }
        }
        if let Some(Err(error)) = &self.terminal_current {
            return Some(error);
        }
        if let Some(error) = &self.first_validation {
            return Some(error);
        }
        (self.ended && !self.has_postcheck_debt()).then_some(&RegistrationEndedV1 as &dyn std::error::Error)
    }

    pub(crate) fn postcheck_debt<'a>(
        &'a self,
        session: &'a crate::DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if let Some(error) = self.storage_issuer.postcheck_debt() {
            return Some(error);
        }
        if let Some(error) = self.host_issuer.postcheck_debt() {
            return Some(error);
        }
        if let Some(error) = session.output_preparation_postcheck_debt(&self.preparation) {
            return Some(error);
        }
        if let Some(error) = session.output_client_flight_postcheck_debt(&self.flight) {
            return Some(error);
        }
        if self.terminal_witness_checks[1] == Some(false) {
            if let Some(error) = session.output_terminal_witness_debt() { return Some(error); }
        }
        if let Some(Err(error)) = &self.source_bookends[2] {
            return Some(error);
        }
        if let Some(Err(error)) = &self.clock_bookends[2] {
            return Some(error);
        }
        self.postcheck_debt.as_ref().map(|error| error as &dyn std::error::Error)
    }

    /// Tests already parked debt without observing or borrowing authority.
    fn has_postcheck_debt(&self) -> bool {
        self.storage_issuer.postcheck_debt().is_some()
            || self.host_issuer.postcheck_debt().is_some()
            || self.preparation.has_postcheck_debt()
            || self.flight.has_postcheck_debt()
            || self.terminal_witness_checks[1] == Some(false)
            || self.source_bookends[2].as_ref().is_some_and(Result::is_err)
            || self.clock_bookends[2].as_ref().is_some_and(Result::is_err)
            || self.postcheck_debt.is_some()
    }

    fn wait(
        &mut self,
        session: &DormantAuthenticatedBrokerSessionV1,
        index: usize,
        write: bool,
        cutoff: u64,
    ) -> bool {
        self.readiness[index] = Some((|| {
            crate::dormant_handshake::wait_for_handshake_readiness(session.as_fd()?, write, cutoff)
        })());
        matches!(&self.readiness[index], Some(Ok(())))
    }
}

struct ControllerRegistrationBoundaryV1<'attempt> {
    attempt: &'attempt mut OriginalControllerOutputRegistrationV1,
}

impl Drop for ControllerRegistrationBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.attempt.coordinated_terminal {
            self.attempt.ended = true;
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("original Controller output registration ended with custody resident")]
struct RegistrationEndedV1;

/// Uses the installed Storage owner; no new connection or signing epoch exists.
#[allow(clippy::too_many_arguments)]
pub(super) fn advance<T>(
    sessions: &SharedControllerBrokerSessions,
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
    let mut sessions = sessions.lock().map_err(|_| closed())?;
    let returned = advance_on_original_session(
        &mut sessions, operation, controller, assignment, environment,
        parent, preissue, signer, clock,
    );
    if returned.is_err() {
        if let Some(worker) = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade) {
            // Close before the shared session lock releases. The marker does
            // not replace the typed first cause borrowed from its resident slot.
            worker.close(super::ControllerResidentCauseV1::OutputRegistration);
        }
        if let Some(storage) = sessions.storage.as_ref() {
            if let Some(cause) = storage.output_registration_failure() {
                eprintln!("aos-sandboxd: original output registration failed: {cause}");
            }
            if let Some(debt) = storage.output_registration_postcheck_debt() {
                eprintln!("aos-sandboxd: original output registration postcheck debt: {debt}");
            }
        }
    }
    returned
}

#[allow(clippy::too_many_arguments)]
fn advance_on_original_session<T>(
    sessions: &mut super::ControllerBrokerSessions,
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
    let storage = sessions.storage.as_mut().ok_or_else(closed)?;
    let (pending, session) = storage.output_registration_loan()?;
    // Retirement requires the actual authenticated client-received terminal.
    // A failed or merely locally sent request can never enter this branch.
    if pending.as_ref().is_some_and(|original|
        original.operation != operation && original.coordinated_terminal)
    {
        *pending = None;
    }
    if pending.is_none() {
        *pending = Some(OriginalControllerOutputRegistrationV1::begin(operation, preissue.execution()));
    }
    let attempt = pending.as_mut().ok_or_else(closed)?;
    if attempt.operation != operation || attempt.execution != preissue.execution() {
        return Err(closed());
    }
    if attempt.coordinated_terminal {
        return Ok(());
    }
    if attempt.started {
        return Err(closed());
    }
    attempt.started = true;
    let mut boundary = ControllerRegistrationBoundaryV1 { attempt };
    let returned = advance_inner(
        &mut *boundary.attempt, session, controller, assignment, environment, parent, preissue, signer, clock,
    );
    if let Err(error) = returned {
        if boundary.attempt.failure(session).is_none() && boundary.attempt.postcheck_debt(session).is_none() {
            boundary.attempt.first_validation = Some(error);
        }
    }
    if boundary.attempt.coordinated_terminal {
        Ok(())
    } else {
        Err(closed())
    }
}

#[allow(clippy::too_many_arguments)]
fn advance_inner<T>(
    attempt: &mut OriginalControllerOutputRegistrationV1,
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
    session.park_output_client_coordinates(
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT,
        preissue.deadline_boottime_nanoseconds(), &mut attempt.flight,
    );
    let Some(Ok(coordinates)) = &attempt.flight.coordinates else {
        return Err(closed());
    };
    let coordinates = *coordinates;
    attempt.storage_issuer.sign(
        controller, assignment, environment, parent, preissue, signer, coordinates, clock,
    );
    let body = attempt.storage_issuer.body().ok_or_else(closed)?;
    let authorization = attempt.storage_issuer.authorization().ok_or_else(closed)?;
    // The encoder's owned wire input is a bounded copy of resident immutable
    // preimages. It is not an authority clone or a replacement original.
    if !session.park_output_client_request(&mut attempt.flight, BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT.into(),
        body: body.to_vec(), authorization: Some(authorization.clone()).into(),
        ..Default::default()
    }) { return Err(closed()); }
    source_bookend(attempt, 0, controller, assignment, environment, parent, preissue, clock)?;
    if !attempt.wait(session, 0, true, coordinates.deadline_boottime_nanoseconds())
        || !session.send_original_output_client_request(&mut attempt.flight)
    { return Err(closed()); }
    if !attempt.wait(session, 1, false, coordinates.deadline_boottime_nanoseconds()) { return Err(closed()); }
    let request = attempt.flight.request().ok_or_else(closed)?;
    {
        let mut transport = session.output_registration_transport(request, &mut attempt.preparation);
        transport.receive(request, NOMINATION_V1).map_err(|_| closed())?;
        transport.finish_turn(request).map_err(|_| closed())?;
    }
    let nomination = attempt.preparation.record(NOMINATION_V1).ok_or_else(closed)?;
    attempt.host_issuer.sign(controller, &attempt.storage_issuer, request, nomination, signer, clock);
    let authorization = attempt.host_issuer.authorization().ok_or_else(closed)?;
    let controller_head = {
        let mut transport = session.output_registration_transport(request, &mut attempt.preparation);
        let head = transport.original_head(request).map_err(|_| closed())?;
        transport.finish_turn(request).map_err(|_| closed())?;
        head
    };
    let nomination = attempt.preparation.record(NOMINATION_V1).ok_or_else(closed)?;
    attempt.authorization = Some(StorageOutputRegistrationPreparationV1 {
        version: 1, stage: AUTHORIZATION_V1,
        original_storage_request_id: nomination.original_storage_request_id.clone(),
        original_storage_session_binding: nomination.original_storage_session_binding.clone(),
        original_signed_request_digest: nomination.original_signed_request_digest.clone(),
        original_semantic_request_digest: nomination.original_semantic_request_digest.clone(),
        storage_pending_head: nomination.storage_pending_head.clone(),
        controller_pending_head: controller_head.to_vec(),
        canonical_host_readback_request: nomination.canonical_host_readback_request.clone(),
        host_authorization: Some(authorization.clone()).into(),
        ..Default::default()
    });
    source_bookend(attempt, 1, controller, assignment, environment, parent, preissue, clock)?;
    if !attempt.wait(session, 2, true, coordinates.deadline_boottime_nanoseconds()) { return Err(closed()); }
    {
        let request = attempt.flight.request().ok_or_else(closed)?;
        let record = attempt.authorization.as_ref().ok_or_else(closed)?;
        let mut transport = session.output_registration_transport(request, &mut attempt.preparation);
        transport.send(request, record).map_err(|_| closed())?;
        transport.finish_turn(request).map_err(|_| closed())?;
    }
    if !attempt.wait(session, 3, false, coordinates.deadline_boottime_nanoseconds()) { return Err(closed()); }
    let received = session.receive_original_output_client_terminal(&mut attempt.flight);
    let mut terminal_success = false;
    if let Some(ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = &attempt.flight.committed {
        match committed.output_registration_originals_v1() {
            Ok((outcome, currentness)) => {
                attempt.terminal_witness_checks[0] = Some(session.bookend_output_terminal_witnesses(
                    crate::handshake::OutputCurrentnessBoundaryV1::BeforeAction,
                ));
                attempt.terminal_current = Some(session.compare_original_storage_output_outcome_v1(currentness));
                attempt.terminal_witness_checks[1] = Some(session.bookend_output_terminal_witnesses(
                    crate::handshake::OutputCurrentnessBoundaryV1::PostAction,
                ));
                terminal_success = matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. });
            }
            Err(error) => attempt.terminal_current = Some(Err(error)),
        }
    }
    // The actual receive/admission/commit result precedes these readbacks,
    // even when that first action or its terminal comparison failed.
    let postcheck = source_bookend(attempt, 2, controller, assignment, environment, parent, preissue, clock);
    if !received || !terminal_success || !matches!(&attempt.terminal_current, Some(Ok(())))
        || attempt.terminal_witness_checks != [Some(true); 2]
    {
        return Err(closed());
    }
    postcheck?;
    // This is the actual authenticated client-received and locally committed
    // terminal, not the Storage unit return or a local send acknowledgement.
    attempt.coordinated_terminal = true;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn source_bookend<T>(
    attempt: &mut OriginalControllerOutputRegistrationV1, index: usize,
    controller: &mut Journal, assignment: &CurrentAssignmentTarget,
    environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1, preissue: &ControllerExecutionPreissueV1,
    clock: &mut T,
) -> Result<(), EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt.source_bookends[index] = Some(prepare_execution_reserve_source_v1(
        controller, assignment, environment, parent, preissue, clock,
    ));
    attempt.clock_bookends[index] = Some(clock());
    let original = attempt.storage_issuer.original_source().ok_or_else(closed)?;
    let original_cutoff = attempt.flight.request().ok_or_else(closed)?
        .deadline_boottime_nanoseconds();
    if attempt.source_bookends[index].as_ref().and_then(|result| result.as_ref().ok()) != Some(original)
        || !attempt.clock_bookends[index].as_ref().and_then(|result| result.as_ref().ok()).is_some_and(|sample|
            sample.host_boot_id() == preissue.host_boot_id()
            && sample.boottime_nanoseconds() < original_cutoff
            && sample.boottime_nanoseconds() < preissue.deadline_boottime_nanoseconds())
    {
        if index == 2 && !attempt.has_postcheck_debt() {
            attempt.postcheck_debt = Some(closed());
        }
        return Err(closed());
    }
    Ok(())
}

fn closed() -> EffectFailure {
    EffectFailure::Permanent("original Storage output registration remains resident and closed".to_owned())
}
