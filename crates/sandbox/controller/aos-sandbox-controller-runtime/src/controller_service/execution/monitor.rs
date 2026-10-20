//! Binds a fresh read-only Query3 to the complete original first Observe.
//!
//! Historical selectors are DATA from the sole signed companion validator.
//! The enclosing current Host Session and paid purpose18 Source interval own
//! native currentness, all IO and the independent disposal obligations.

use super::super::execution_output_storage_capture::AuthenticatedControllerStorageCaptureQueryObservationV3;
use super::*;
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::execution_observe_reservation::{
    ControllerExecutionObserveReservationV1, completion::ObserveChildCompletionDataV1,
};
use aos_sandbox_protocol::host_execution::monitor::HostExecutionMonitorSelectorV3;

pub(super) struct MonitorProjectionReceivingV4<'read, 'scope, 'owner> {
    pub(super) receiving: &'read mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'scope, 'owner>,
    pub(super) bank: &'read aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
    pub(super) profile: &'read aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    pub(super) transaction: &'read mut Option<JournalTransaction>,
    pub(super) geometry: &'read mut Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1>>,
    pub(super) admission: &'read mut Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
}

impl MonitorProjectionReceivingV4<'_, '_, '_> {
    pub(super) fn commit_v4(
        &mut self,
        controller: &mut Journal,
        transaction: JournalTransaction,
        native: &mut Option<Result<aos_sandbox_controller_domain::CommitResult, aos_sandbox_controller_domain::JournalError>>,
    ) -> Result<(), EffectFailure> {
        *self.transaction = Some(transaction);
        let actual = self
            .transaction
            .as_ref()
            .ok_or_else(|| retryable("monitor projection transaction is absent"))?;
        *self.geometry = Some(
            controller.append_receiving_demand_v1(actual.records().iter().map(|record| {
                aos_sandbox_journal::geometry::RecordShape {
                    key_bytes: record.key().len(),
                    value_bytes: record.value().map(<[u8]>::len),
                }
            })),
        );
        let demand = self
            .geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or_else(|| retryable("monitor projection append geometry refused"))?;
        *self.admission = Some(self.receiving.admit_stage_v1(self.bank, controller, self.profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(retryable(
                "same execution original cannot fund exact monitor projection",
            ));
        }
        *native = Some(controller.commit(actual));
        match native.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(cause)) => Err(retryable(cause)),
            None => Err(retryable("monitor projection append is absent")),
        }
    }
}

impl ControllerExecutionIntentV1 {
    pub(in crate::controller_service) fn from_original_monitor_v4(
        journal: &Journal,
        context: &PublicMutationEffectHistoryV1,
        specification: &ControllerExecutionSpecAttemptV1,
        reservation: &ControllerExecutionObserveReservationV1,
    ) -> Result<Self, EffectFailure> {
        if reservation.execution() != specification.execution()
            || reservation.create_operation() != specification.create_operation()
            || reservation.specification_digest() != specification.specification_digest()
            || !specification.matches_accepted_request(context.canonical_request())
        {
            return Err(retryable(
                "periodic execution differs from its protected Create",
            ));
        }
        let projection = PublicProjectionStoreV1::new(journal)
            .get(
                PublicProjectionKindV1::Execution,
                *specification.execution().as_bytes(),
            )
            .map_err(retryable)?
            .ok_or_else(|| retryable("execution projection is absent"))?;
        if projection.project() != context.project() {
            return Err(retryable("periodic execution crossed its admitted project"));
        }
        Ok(Self {
            operation_id: reservation.create_operation(),
            projection_operation_id: projection.operation(),
            execution_id: *reservation.execution().as_bytes(),
            action: ControllerExecutionActionV1::Observe,
            specification: None,
            specification_digest: reservation.specification_digest(),
            source_operation_commitment: reservation.source_operation_commitment(),
        })
    }

    pub(in crate::controller_service) fn prepare_monitor_authorization_v4<T>(
        &self,
        project: ProjectId,
        node: NodeId,
        controller: &mut Journal,
        signer: &ControllerBrokerPlanSignerV1,
        original: &ObserveChildCompletionDataV1,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationArtifactsV1, EffectFailure>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError,
        >,
    {
        self.prepare_authorization_engine_v2(
            ExecutionAuthorizationKindV1::Query,
            project,
            node,
            controller,
            Some(signer),
            ExecutionPlanContentV2::Monitor {
                content: original.monitor_content_v4(),
                selector: original.monitor_selector_v4(),
            },
            clock,
        )
    }

    pub(super) fn monitor_envelope_v4(
        &self,
        coordinates: DormantBrokerRequestCoordinatesV1,
        authorization: &BrokerAuthorizationArtifactsV1,
        content: HostExecutionSpecContentFieldsV1,
        selector: HostExecutionMonitorSelectorV3,
    ) -> BrokerRequestEnvelope {
        self.envelope_content_engine_v4(
            ExecutionAuthorizationKindV1::Query,
            coordinates,
            authorization,
            content,
            ExecutionDescriptorVersionV2::Ordinary,
            Some(selector),
        )
    }
}

pub(super) fn require_monitor_request_v4(
    intent: &ControllerExecutionIntentV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    content: HostExecutionSpecContentFieldsV1,
    selector: HostExecutionMonitorSelectorV3,
) -> Result<(), EffectFailure> {
    let request = outcome.request();
    let query = request
        .host_execution_query_data_v3()
        .ok_or_else(|| retryable("actual signed Host request has no Query3 model"))?;
    let bound = content.bind_query_attempt_v3(
        request.request_id(),
        *intent.operation_id.as_bytes(),
        ExecutionId::from_bytes(intent.execution_id),
        ObjectDigest::from_bytes(intent.source_operation_commitment),
        intent.specification_digest,
        selector,
    );
    if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
        || query.operation_id() != *intent.operation_id.as_bytes()
        || query.execution_id().as_bytes() != &intent.execution_id
        || query.source_commitment().as_bytes() != &intent.source_operation_commitment
        || query.specification_digest() != intent.specification_digest
        || query.monitor_v3() != Some(&selector)
        || query.content_fields() != bound
    {
        return Err(retryable(
            "signed Host monitor request substituted original selectors",
        ));
    }
    Ok(())
}

pub(super) fn classify_monitor_v4(
    intent: &ControllerExecutionIntentV1,
    monitor: &aos_sandbox_protocol::host_execution::ValidatedHostExecutionMonitorOutcomeV3,
    capture: Option<&AuthenticatedControllerStorageCaptureQueryObservationV3<'_>>,
) -> Result<ControllerExecutionObservationV1, EffectFailure> {
    let body = monitor.outcome_v3();
    if matches!(
        body.phase.as_known(),
        Some(
            HostExecutionPhaseV1::HOST_EXECUTION_PHASE_PENDING
                | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ISSUED
                | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_INDETERMINATE
        )
    ) {
        // A signed ongoing read is a positive observation interval. It never
        // becomes effect absence, effect replay, or a terminal projection.
        return Ok(ControllerExecutionObservationV1::Pending);
    }
    let (operation_id, source_operation_commitment) = match monitor.lineage_v3() {
        Some(lineage) => (
            OperationId::from_bytes(*lineage.operation_v5().as_bytes()),
            *lineage.commitment_v5().as_bytes(),
        ),
        None => (
            OperationId::from_bytes(
                body.operation_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| retryable("Host monitor operation is malformed"))?,
            ),
            body.source_operation_commitment
                .as_slice()
                .try_into()
                .map_err(|_| retryable("Host monitor source is malformed"))?,
        ),
    };
    let observed = ControllerExecutionIntentV1 {
        operation_id,
        source_operation_commitment,
        projection_operation_id: intent.projection_operation_id,
        execution_id: intent.execution_id,
        action: ControllerExecutionActionV1::Observe,
        specification: None,
        specification_digest: intent.specification_digest,
    };
    let mut result =
        classify_decoded_outcome_v4(&observed, ExecutionAuthorizationKindV1::Query, body)?;
    if let ControllerExecutionObservationV1::Applied(completion) = &mut result {
        if completion.is_terminal() && capture.is_some() {
            let actual = capture
                .and_then(|capture| capture.complete_record_v3())
                .ok_or_else(|| retryable("Storage61 has no complete physical Capture"))?;
            if monitor.capture_complete_v3() != Some(actual) {
                return Err(retryable("Host828/C1 and Storage61 disagree on full676"));
            }
            completion.capture_complete = Some(*actual);
        }
    }
    Ok(result)
}

pub(super) fn require_capture_terminal_projection_v4(
    intent: &ControllerExecutionIntentV1,
    command: &Command,
    completion: &ControllerExecutionCompletionV1,
    capture: &AuthenticatedControllerStorageCaptureQueryObservationV3<'_>,
) -> Result<(), EffectFailure> {
    let source = capture
        .source_v2()
        .ok_or_else(|| retryable("Capture query has no Source944"))?;
    let original = source.original_source_v1();
    let (bytes, stdout, stderr) = original.output_limits();
    if command.io_mode.as_known() != Some(ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE)
        || command.detached_capture_bytes != bytes
        || command.maximum_stdout_bytes != Some(stdout)
        || command.maximum_stderr_bytes != Some(stderr)
        || capture.operation_v3() != intent.operation_id
        || capture.execution_v3().as_bytes() != &intent.execution_id
        || source.lifetime_v2().specification_digest_v2() != intent.specification_digest
        || completion.capture_complete.as_ref() != capture.complete_record_v3()
        || completion.capture_complete.is_none()
    {
        return Err(retryable(
            "terminal projection lacks exact native-backed Capture conjunction",
        ));
    }
    Ok(())
}
