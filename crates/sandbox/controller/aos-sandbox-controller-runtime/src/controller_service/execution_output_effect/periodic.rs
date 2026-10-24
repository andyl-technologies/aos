//! Observes one original execution through fresh signed Host27 and Storage61.
//!
//! This is a purpose18 read interval. It never repeats Authorize48, reserves
//! output, activates Environment or reconstructs an old execution deadline.
//! The exact original first-Observe companion supplies historical selectors;
//! the current assignment and parent supply the fresh query authorization.

use super::super::execution::{
    ControllerExecutionExchangeV1, ControllerExecutionIntentV1, ControllerExecutionObservationV1,
};
use super::super::execution_authorize::AcceptedSessionPostOriginalV1;
use super::*;
use aos_sandbox_controller_domain::controller_execution_preissue::{
    ControllerExecutionOutputAttemptErrorV1, ControllerExecutionOutputAttemptV1,
};
use aos_sandbox_controller_domain::controller_execution_spec_attempt::{
    ControllerExecutionSpecAttemptErrorV1, ControllerExecutionSpecAttemptV1,
    load_controller_execution_spec_attempt_v1,
};
use aos_sandbox_controller_domain::controller_service::public_projection::PublicProjectionStoreV1;
use aos_sandbox_controller_domain::journal::RecordNamespace;
use aos_sandbox_controller_domain::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox_controller_domain::{ReconcilerError, ResourceReservationErrorV1};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1 as Demand;
use aos_sandbox_broker_session_security::HostExecutionSessionReceivingOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::effect_history::EffectLedgerRecord;
use aos_sandbox_protocol::domain_ledger::execution_observe_reservation::{
    ControllerExecutionObserveReservationV1, completion::ObserveChildCompletionDataV1,
};
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1,
};

type CompletedObserve = (
    ControllerExecutionObserveReservationV1,
    EffectLedgerRecord,
    ObserveChildCompletionDataV1,
);

#[derive(Clone, Copy)]
enum Frontier {
    Preparation,
    Historical,
    Models,
    Specification,
    Companion,
    OutputAttempt,
    Intent,
    Forecast,
    Admission,
    Plan,
    Read,
    Storage,
    Projection,
    Posts,
}

/// Keeps every entered read and its real native destinations through disposal.
pub(super) struct PeriodicExecutionOriginalV4 {
    frontier: Frontier,
    body: Option<Result<(), EffectFailure>>,
    assignment: Option<CurrentAssignmentTarget>,
    historical: Option<aos_sandbox_controller_domain::environment::HistoricalEnvironmentExecutionModelsV4>,
    historical_check: Option<Result<(), EffectFailure>>,
    models: Option<Result<ResourceVector, EffectFailure>>,
    model_admission: Option<Result<(), ResourceReservationErrorV1>>,
    specification: Option<
        Result<Option<ControllerExecutionSpecAttemptV1>, ControllerExecutionSpecAttemptErrorV1>,
    >,
    companion: Option<Result<Option<CompletedObserve>, ReconcilerError>>,
    output_attempt: Option<
        Result<Option<ControllerExecutionOutputAttemptV1>, ControllerExecutionOutputAttemptErrorV1>,
    >,
    intent: Option<Result<ControllerExecutionIntentV1, EffectFailure>>,
    receiving: HostExecutionSessionReceivingOriginalV1,
    forecast: Option<Result<ResourceVector, crate::BrokerSessionSecurityError>>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    plan: Option<
        Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerAuthorizationArtifactsV1, EffectFailure>,
    >,
    exchange: ControllerExecutionExchangeV1,
    posts: [AcceptedSessionPostOriginalV1; 2],
    read: Option<Result<ControllerExecutionObservationV1, EffectFailure>>,
    storage: Option<Result<(), EffectFailure>>,
    projection: Option<Result<ControllerExecutionObservationV1, EffectFailure>>,
    disposal_refusal: Option<ResourceReservationErrorV1>,
    storage_retirement: Option<Result<(), EffectFailure>>,
    host_retirement: Option<Result<(), EffectFailure>>,
    source_refusal: Option<ResourceReservationErrorV1>,
    fence: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
}

impl PeriodicExecutionOriginalV4 {
    fn new() -> Self {
        Self {
            frontier: Frontier::Preparation,
            body: None,
            assignment: None,
            historical: None,
            historical_check: None,
            models: None,
            model_admission: None,
            specification: None,
            companion: None,
            output_attempt: None,
            intent: None,
            receiving: Default::default(),
            forecast: None,
            admission: None,
            plan: None,
            exchange: Default::default(),
            posts: std::array::from_fn(|_| Default::default()),
            read: None,
            storage: None,
            projection: None,
            disposal_refusal: None,
            storage_retirement: None,
            host_retirement: None,
            source_refusal: None,
            fence: None,
        }
    }

    fn fixed_demand() -> Result<ResourceVector, EffectFailure> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Box<Self>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let mut demand = HostExecutionSessionReceivingOriginalV1::fixed_demand_v1()
            .ok_or_else(overflow)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| overflow())?;
        // One request, followed by a distinct rejoin of that same signed
        // outcome after Storage61. Both actual endpoint intervals are prepaid.
        for _ in 0..2 {
            demand = demand.checked_add(
                aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1::receiving_demand_v1()
                    .ok_or_else(overflow)?)
                .map_err(|_| overflow())?;
        }
        let named = aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
            "controller.journal",
        )
        .map_err(|_| overflow())?;
        for _ in 0..4 {
            demand = demand.checked_add(named).map_err(|_| overflow())?;
        }
        Ok(demand)
    }

    fn require_body(&self) -> Result<(), EffectFailure> {
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(retryable("periodic execution retains its original refusal"))
        }
    }
}

/// Runs one fair periodic read in the same configured execution subdivision.
///
/// # Errors
/// Refuses missing current custody or capacity. Once an interval is entered,
/// every refusal retains its complete originals, runs independent native posts,
/// fences the same Controller and terminates before another public command.
pub(in crate::controller_service) fn observe_periodic_v4(
    executor: &mut ProductionEffectExecutor,
    controller: &mut Journal,
) -> Result<(), EffectFailure> {
    let cursor = executor
        .execution_original
        .as_ref()
        .and_then(|original| original.periodic_cursor);
    let Some((execution, operation)) = next_candidate(controller, cursor)? else {
        return Ok(());
    };
    let bank = executor
        .resource_bank
        .as_ref()
        .ok_or_else(|| retryable("execution bank is absent"))?;
    let bank = bank
        .lock()
        .map_err(|_| retryable("execution bank is poisoned"))?;
    let profile = executor
        .execution_profile
        .as_ref()
        .ok_or_else(|| retryable("execution profile is absent"))?;
    let directory = executor
        .execution_credential_directory
        .as_deref()
        .ok_or_else(|| retryable("execution credential directory is absent"))?;
    let host_identity = executor
        .attachment_host
        .as_ref()
        .ok_or_else(|| retryable("Host identity is absent"))?;
    let signer = executor
        .broker_plan_signer
        .as_ref()
        .ok_or_else(|| retryable("execution signer is absent"))?;
    if executor.execution_original.is_none() {
        executor.execution_original = Some(ControllerExecutionOriginalV1::claim_once_v1(
            &bank, controller, profile,
        )?);
    }
    let original = executor
        .execution_original
        .as_mut()
        .ok_or_else(|| retryable("execution original is absent"))?;
    if original.body.is_some() || original.periodic.is_some() {
        return Err(retryable("execution original retains an earlier interval"));
    }
    let fixed = super::super::attachment_target::ControllerAttachmentSourceOriginalV1::fixed_receiving_demand_v1(
        host_identity, directory).ok_or_else(overflow)?
        .checked_add(PeriodicExecutionOriginalV4::fixed_demand()?).map_err(|_| overflow())?;
    let mut loan = original
        .financial
        .as_mut()
        .ok_or_else(|| retryable("execution custody is lent to public compilation"))?
        .begin_periodic_observation_once_v4(
            &bank,
            controller,
            profile,
            operation,
            Demand::from_demand_v1(fixed),
        )
        .map_err(|_| retryable("execution read native entry refused"))?;
    // The fixed header and both Box planes have been paid by the genuine
    // entered purpose18 before any upper allocation or semantic-model growth.
    original.periodic = Some(Box::new(PeriodicExecutionOriginalV4::new()));
    let Some(attempt) = original.periodic.as_mut() else {
        std::process::abort()
    };
    let accepted = loan.accepted_v1().cloned();
    attempt.body = Some((|| {
        let context = accepted
            .as_ref()
            .ok_or_else(|| retryable("protected execution Create is absent"))?;
        loan.prepare_periodic_controller_models_v4(&bank, controller, profile)
            .map_err(|_| retryable("execution source models refused"))?;
        let sandbox = current_sandbox(controller, execution, context)?;
        attempt.assignment = Some(prepare_current_runtime_inputs_v4(
            &mut original.inputs,
            &mut original.parent,
            &mut loan,
            &bank,
            controller,
            profile,
            host_identity,
            executor.node,
            directory,
            context.project(),
            sandbox,
        )?);
        Ok(())
    })());
    if attempt.require_body().is_err() {
        loan.finish_without_source_v1(&bank, controller, profile);
        attempt.fence = Some(loan.fence_observation_after_refusal_v4(controller));
        std::process::abort();
    }
    let source_error =
        match loan.prepare_source_once_v1(&bank, &mut executor.source_domains, controller, profile)
        {
            Ok(mut source) => {
                attempt.body = Some((|| {
                    attempt.frontier = Frontier::Historical;
                    source
                        .prepare_historical_environment_v4(&bank, controller, profile, execution)
                        .map_err(|_| retryable("historical Source representation refused"))?;
                    let (mut historical, mut receiving, clock_original) = source
                        .historical_environment_and_receiving_v4()
                        .map_err(|_| retryable("historical Source interval refused"))?;
                    // Always move the complete historical prefix out before the
                    // borrowed view ends, including partial replay on refusal.
                    let body = (|| {
                        attempt.frontier = Frontier::Specification;
                        attempt.specification = Some(load_controller_execution_spec_attempt_v1(
                            controller, execution,
                        ));
                        let specification = attempt
                            .specification
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .and_then(Option::as_ref)
                            .ok_or_else(|| retryable("original protected CSI is absent"))?;
                        attempt.historical_check = Some(historical.observe_original_specification_v4(specification)
                            .map_err(|cause| retryable(cause.to_string())));
                        if !matches!(attempt.historical_check, Some(Ok(()))) {
                            return Err(retryable(
                                "original Source Environment/spec association refused",
                            ));
                        }
                        attempt.frontier = Frontier::Models;
                        attempt.models = Some(companion_demand(controller, execution));
                        let demand = attempt
                            .models
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .copied()
                            .ok_or_else(|| retryable("historical companion geometry refused"))?;
                        attempt.model_admission = Some(receiving.admit_stage_v1(
                            &bank,
                            controller,
                            profile,
                            Demand::from_demand_v1(demand),
                        ));
                        if !matches!(attempt.model_admission, Some(Ok(()))) {
                            return Err(retryable(
                                "historical companion exceeds same execution subdivision",
                            ));
                        }
                        attempt.frontier = Frontier::Companion;
                        attempt.companion = Some(
                            aos_sandbox_controller_domain::reconciler::completed_execution_observe_from_journal_v4(
                                controller, execution,
                            ),
                        );
                        let (reservation, _, companion) = attempt
                            .companion
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .and_then(Option::as_ref)
                            .ok_or_else(|| {
                                retryable("complete protected original Observe is absent")
                            })?;
                        attempt.frontier = Frontier::OutputAttempt;
                        attempt.output_attempt = Some(load_controller_execution_output_attempt_v1(
                            controller, execution,
                        ));
                        let output = attempt
                            .output_attempt
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .and_then(Option::as_ref)
                            .ok_or_else(|| retryable("original output attempt is absent"))?;
                        attempt.frontier = Frontier::Intent;
                        let context = accepted
                            .as_ref()
                            .ok_or_else(|| retryable("accepted original Create is absent"))?;
                        attempt.intent =
                            Some(ControllerExecutionIntentV1::from_original_monitor_v4(
                                controller,
                                context,
                                specification,
                                reservation,
                            ));
                        let intent = attempt
                            .intent
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .ok_or_else(|| {
                                retryable("original execution monitor intent refused")
                            })?;
                        let assignment = attempt
                            .assignment
                            .as_ref()
                            .ok_or_else(|| retryable("current assignment is absent"))?;
                        let parent = original
                            .parent
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .ok_or_else(|| retryable("current execution Parent is absent"))?;
                        let mut clock = || clock_original.sample_v1();
                        let mut sessions = executor
                            .sessions
                            .lock()
                            .map_err(|_| retryable("Session mutex is poisoned"))?;
                        let super::super::ControllerBrokerSessions { host, storage, .. } =
                            &mut *sessions;
                        let host = host
                            .as_mut()
                            .ok_or_else(|| retryable("actual Host Session is absent"))?;
                        let session = host.periodic_execution_session_v4(&receiving)?;
                        attempt.frontier = Frontier::Forecast;
                        attempt.forecast = Some(
                            session
                                .host_execution_authorize_observe_demand_v2(&mut attempt.receiving),
                        );
                        let forecast = attempt
                            .forecast
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .copied()
                            .ok_or_else(|| retryable("fresh Host query forecast refused"))?;
                        attempt.frontier = Frontier::Admission;
                        attempt.admission = Some(receiving.admit_stage_v1(
                            &bank,
                            controller,
                            profile,
                            Demand::from_demand_v1(forecast),
                        ));
                        if !matches!(attempt.admission, Some(Ok(()))) {
                            return Err(retryable(
                                "fresh query exceeds the same spent execution subdivision",
                            ));
                        }
                        let body = (|| {
                            attempt.posts[0].arm_once(session)?;
                            attempt.posts[1].arm_once(session)?;
                            attempt.frontier = Frontier::Plan;
                            attempt.plan = Some(intent.prepare_monitor_authorization_v4(
                                context.project(),
                                executor.node,
                                controller,
                                signer,
                                companion,
                                &mut clock,
                            ));
                            let plan = attempt
                                .plan
                                .as_ref()
                                .and_then(|value| value.as_ref().ok())
                                .ok_or_else(|| {
                                    retryable("fresh read-only Host query plan refused")
                                })?;
                            attempt.frontier = Frontier::Read;
                            attempt.read = Some(attempt.exchange.publish_monitor_execution_v4(
                                session,
                                intent,
                                plan,
                                context.project(),
                                controller,
                                companion,
                                &mut clock,
                                &mut attempt.posts[0],
                                &mut receiving,
                                &bank,
                                profile,
                            ));
                            if !matches!(attempt.read, Some(Ok(_))) {
                                return Err(retryable("fresh Host monitor read refused"));
                            }
                            let capture = if companion.monitor_selector_v4().source_kind_v3() == 2 {
                                attempt.frontier = Frontier::Storage;
                                let storage = storage
                                    .as_mut()
                                    .ok_or_else(|| retryable("actual Storage Session is absent"))?;
                                attempt.storage =
                                    Some(storage.query_original_capture_historical_v4(
                                        controller,
                                        assignment,
                                        &historical,
                                        parent,
                                        output.source().preissue(),
                                        signer,
                                        &mut receiving,
                                        &bank,
                                        profile,
                                        &mut clock,
                                    ));
                                if !matches!(attempt.storage, Some(Ok(()))) {
                                    return Err(retryable("fresh historical Storage61 refused"));
                                }
                                Some(
                                    storage
                                        .completed_capture_query_v3(operation, execution)
                                        .ok_or_else(|| {
                                            retryable(
                                                "actual native-backed Storage61 result is absent",
                                            )
                                        })?,
                                )
                            } else {
                                None
                            };
                            attempt.frontier = Frontier::Projection;
                            attempt.projection =
                                Some(attempt.exchange.publish_monitor_projection_v4(
                                    session,
                                    context.project(),
                                    controller,
                                    companion,
                                    capture.as_ref(),
                                    &mut clock,
                                    &mut attempt.posts[1],
                                    &mut receiving,
                                    &bank,
                                    profile,
                                ));
                            if !matches!(attempt.projection, Some(Ok(_))) {
                                return Err(retryable(
                                    "exact terminal comparison/projection refused",
                                ));
                            }
                            Ok(())
                        })();
                        // Both actual endpoint destinations remain independently
                        // owed even when plan/preparation/read/Storage/CAS refused.
                        let after0 = attempt.posts[0].finish_once(session);
                        let after1 = attempt.posts[1].finish_once(session);
                        body?;
                        if after0.is_err() || after1.is_err() {
                            attempt.frontier = Frontier::Posts;
                            return Err(retryable(
                                "periodic read retains an actual endpoint post refusal",
                            ));
                        }
                        Ok(())
                    })();
                    attempt.historical = Some(historical.into_retained_models_v4());
                    body
                })());
                // The body result is already parked before either independently
                // owed Source/C native post may populate its own failure slot.
                source.finish_native_once_v1(&bank, controller, profile);
                if attempt.require_body().is_err() || source.failure().is_some() {
                    attempt.fence = Some(source.fence_observation_after_refusal_v4(controller));
                    // Public reads execute on this same serial worker. Cold reopen
                    // requires the real Successor recovery-only quarantine and
                    // cannot render this raw projection or announce ordinary Ready.
                    // These are required closure boundaries, not rollback or proof
                    // that restart reconciliation has completed.
                    std::process::abort();
                }
                let disposal = match source.prepare_positive_disposal_v1(&bank, controller, profile)
                {
                    Ok(disposal) => disposal,
                    Err(cause) => {
                        attempt.disposal_refusal = Some(cause);
                        std::process::abort();
                    }
                };
                {
                    let mut sessions = match executor.sessions.lock() {
                        Ok(sessions) => sessions,
                        Err(_) => std::process::abort(),
                    };
                    let super::super::ControllerBrokerSessions { host, storage, .. } =
                        &mut *sessions;
                    if let Some(storage) = storage.as_mut() {
                        if attempt
                            .companion
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .and_then(Option::as_ref)
                            .is_some_and(|(_, _, companion)| {
                                companion.monitor_selector_v4().source_kind_v3() == 2
                            })
                        {
                            attempt.storage_retirement = Some(
                                storage.retire_execution_capture_query_v4(&disposal, execution),
                            );
                            if !matches!(attempt.storage_retirement, Some(Ok(()))) {
                                std::process::abort();
                            }
                        }
                    }
                    attempt.host_retirement = Some(attempt.exchange.retire_monitor_positive_v4(
                        &disposal,
                        execution,
                        &attempt.posts[1],
                    ));
                    if host.is_none() || !matches!(attempt.host_retirement, Some(Ok(()))) {
                        std::process::abort();
                    }
                }
                // Ongoing/Pending is a successful read interval too. Physically
                // retire all query-only models before closing the genuine native
                // token; spent/highwater and actual wire traffic are never reset.
                *original.inputs =
                    super::super::attachment_target::ControllerAttachmentSourceOriginalV1::new();
                original.parent = None;
                drop(accepted);
                drop(original.periodic.take());
                disposal.complete_after_disposal_v1();
                original.periodic_cursor = Some(execution);
                return Ok(());
            }
            Err(error) => error,
        };
    attempt.source_refusal = Some(source_error);
    attempt.body = Some(Err(retryable("original execution Source entry refused")));
    // The failed Source borrow has ended. The genuine parent still owns and
    // runs its independently prepaid C-only tail before worker termination.
    loan.finish_without_source_v1(&bank, controller, profile);
    attempt.fence = Some(loan.fence_observation_after_refusal_v4(controller));
    std::process::abort();
}

fn current_sandbox(
    controller: &Journal,
    execution: ExecutionId,
    context: &PublicMutationEffectHistoryV1,
) -> Result<SandboxId, EffectFailure> {
    let projection = PublicProjectionStoreV1::new(controller)
        .get(PublicProjectionKindV1::Execution, *execution.as_bytes())
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("current execution projection is absent"))?;
    let PublicProjectionResourceV1::Execution(body) = projection.resource() else {
        return Err(retryable("current execution projection has another kind"));
    };
    if projection.project() != context.project()
        || body.execution_id.as_slice() != execution.as_bytes()
    {
        return Err(retryable(
            "execution projection crossed the admitted project",
        ));
    }
    Ok(SandboxId::from_bytes(
        body.sandbox_id
            .as_slice()
            .try_into()
            .map_err(|_| retryable("execution sandbox identity is malformed"))?,
    ))
}

fn companion_demand(
    controller: &Journal,
    execution: ExecutionId,
) -> Result<ResourceVector, EffectFailure> {
    let reservation = controller
        .get(
            RecordNamespace::ControllerExecutionObserveReservation,
            execution.as_bytes(),
        )
        .ok_or_else(|| retryable("original Observe reservation is absent"))?;
    let reservation =
        ControllerExecutionObserveReservationV1::decode(execution.as_bytes(), reservation)
            .map_err(|error| retryable(error.to_string()))?;
    let key = aos_sandbox_protocol::domain_ledger::operation::effect_key(
        reservation.observe_operation(),
        0,
    );
    let encoded = controller
        .get(RecordNamespace::Effect, &key)
        .ok_or_else(|| retryable("original completed Observe effect is absent"))?
        .len();
    let bytes =
        aos_sandbox_protocol::domain_ledger::effect_history::effect_decoding_receiving_bytes_v1(
            encoded,
        )
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(overflow)?;
    let namespaces = aos_sandbox_protocol::publication::decoding_receiving_namespace_entries_v1(encoded)
        .and_then(|entries| u64::try_from(entries).ok()).ok_or_else(overflow)?;
    // The containing canonical V7 width bounds every embedded signed prefix.
    // Reuse the sole stored-history/schema recipe before any full decoder.
    let history =
        aos_sandbox_controller_domain::journal::broker_session_receiving::historical_signed_session_model_demand_v4(
            encoded,
        )
        .map_err(|_| overflow())?;
    history
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, namespaces))
        .map_err(|_| overflow())
}

fn next_candidate(
    controller: &Journal,
    cursor: Option<ExecutionId>,
) -> Result<Option<(ExecutionId, OperationId)>, EffectFailure> {
    controller
        .ensure_healthy()
        .map_err(|error| retryable(error.to_string()))?;
    let mut first = None;
    let mut next = None;
    for (namespace, key, bytes) in controller.all_records() {
        if namespace != RecordNamespace::ControllerExecutionSpecAttempt {
            continue;
        }
        // This shared framing/hash projection allocates no specification or
        // authority model. It only suppresses unfinished candidates; the paid
        // native interval repeats the complete original semantic validation.
        let (execution, create) =
            aos_sandbox_protocol::execution_spec_attempt::execution_spec_attempt_identity_data_v4(
                bytes,
            )
            .map_err(|error| retryable(error.to_string()))?;
        if key != execution.as_bytes() {
            return Err(retryable("CSI key differs from canonical execution"));
        }
        let Some(encoded) =
            controller.get(RecordNamespace::ControllerExecutionObserveReservation, key)
        else {
            continue;
        };
        let reservation = ControllerExecutionObserveReservationV1::decode(key, encoded)
            .map_err(|error| retryable(error.to_string()))?;
        let effect = aos_sandbox_protocol::domain_ledger::operation::effect_key(
            reservation.observe_operation(),
            0,
        );
        if controller.get(RecordNamespace::Effect, &effect).and_then(|bytes| bytes.first())
            != Some(&aos_sandbox_protocol::domain_ledger::effect_history::observe_completion::COMPLETED_OBSERVE_EFFECT_VERSION)
        { continue; }
        let candidate = (execution, create);
        if first.is_none_or(|(old, _): (ExecutionId, OperationId)| {
            execution.as_bytes() < old.as_bytes()
        }) {
            first = Some(candidate);
        }
        if cursor.is_none_or(|cursor| execution.as_bytes() > cursor.as_bytes())
            && next.is_none_or(|(old, _): (ExecutionId, OperationId)| {
                execution.as_bytes() < old.as_bytes()
            })
        {
            next = Some(candidate);
        }
    }
    Ok(next.or(first))
}

fn overflow() -> EffectFailure {
    retryable("periodic execution receiving geometry overflows")
}
