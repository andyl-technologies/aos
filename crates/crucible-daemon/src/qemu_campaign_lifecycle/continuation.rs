//! Continuation validation, production configuration, and selected-origin replay.

use super::*;

use crate::automatic_finding_runner::{
    FindingExactRetentionSource, FindingTerminalCheckpointIdentity,
};

fn retain_failed_observation_checkpoint<L, D>(
    source: &dyn FindingExactRetentionSource,
    lifecycle: &mut L,
    driver: &D,
    pending: &D::Pending,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
) -> Option<()>
where
    L: QemuFreshAttemptLifecycleOwner,
    D: QemuFreshAttemptDriver,
{
    use crucible_campaign::ExecutionRetentionIntent;

    if !matches!(
        context.retention(),
        ExecutionRetentionIntent::RetainOnFailure | ExecutionRetentionIntent::RetainAlways
    ) || !source.exact_findings_enabled(input, context)
    {
        return None;
    }
    let modeled_assertion_failure = driver
        .has_terminal_assertion_failure(pending)
        .ok()
        .unwrap_or(false);
    // The checkpoint cause describes the trigger verdict. A separately
    // checked property can fail even when that trigger passed or never fired.
    let terminal_cause = match lifecycle.terminal_verdict_for_stop() {
        Some(QuantumTerminalVerdict::Failed(violations)) => {
            Some(CheckpointTerminalCause::Failed(violations))
        }
        Some(QuantumTerminalVerdict::Passed) if modeled_assertion_failure => {
            Some(CheckpointTerminalCause::Passed)
        }
        None if modeled_assertion_failure => None,
        _ => return None,
    };
    let (choices, event_count) = driver.terminal_checkpoint_choices(pending)?;
    if !lifecycle.exact_checkpoint_ready().ok()? {
        return None;
    }

    if let Some(cause) = terminal_cause {
        lifecycle.prepare_terminal_checkpoint(cause).ok()?;
    }
    let capture = lifecycle.capture_attempt_checkpoint(context).ok()?;
    let identity = FindingTerminalCheckpointIdentity {
        scenario: input.lineage().scenario(),
        scenario_artifact: input.lineage().scenario_content(),
        configuration: choices.configuration_id(),
        event_count,
    };
    let capture = choices.bind_capture(input.scenario(), capture).ok()?;
    source
        .retain_terminal_checkpoint(&capture, context, identity)
        .ok()
}

pub(super) fn production_lifecycle_config_for_continuations(
    mut config: ProductionVmLifecycleConfig,
    continuations: &[OwnedQemuAttemptContinuation],
) -> Result<ProductionVmLifecycleConfig, QemuAttemptProductionVmLifecycleError> {
    for continuation in continuations {
        config = production_continuation_plan(Some(continuation))?.apply(config);
    }
    Ok(config)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ProductionContinuationPlan {
    Unchanged,
    Reseed {
        base: Configuration,
        frontier: VirtualTime,
        seed: Seed,
    },
    NetworkSelections {
        base: Configuration,
        frontier: VirtualTime,
        selections: Vec<crucible::SelectionDecision>,
    },
}

impl ProductionContinuationPlan {
    fn apply(self, config: ProductionVmLifecycleConfig) -> ProductionVmLifecycleConfig {
        match self {
            Self::Unchanged => config,
            Self::Reseed {
                base,
                frontier,
                seed,
            } => config.append_branch_reseed(base, frontier, seed),
            Self::NetworkSelections {
                base,
                frontier,
                selections,
            } => config
                .append_branch_boundary(base, frontier)
                .append_branch_network_choices(selections),
        }
    }
}

pub(super) fn production_continuation_plan(
    continuation: Option<&OwnedQemuAttemptContinuation>,
) -> Result<ProductionContinuationPlan, QemuAttemptProductionVmLifecycleError> {
    let Some(continuation) = continuation else {
        return Ok(ProductionContinuationPlan::Unchanged);
    };
    let input = &continuation.input;
    let frontier = VirtualTime {
        ticks: input.source_frontier_ticks(),
    };

    match input {
        AttemptContinuationInput::SchedulerReseed { seed, .. } => {
            Ok(ProductionContinuationPlan::Reseed {
                base: continuation.source.clone(),
                frontier,
                seed: Seed::from_bytes(*seed),
            })
        }
        AttemptContinuationInput::SchedulerSelections {
            selections: records,
            ..
        } => {
            let mut selections = Vec::new();
            selections
                .try_reserve(records.len())
                .map_err(|_| QemuAttemptProductionVmLifecycleError::InvalidContinuationInput)?;
            let mut opportunities = BTreeSet::new();
            for bytes in records {
                let schedule = Schedule::from_compact_binary(bytes)
                    .map_err(|_| QemuAttemptProductionVmLifecycleError::InvalidContinuationInput)?;
                if schedule.to_compact_binary() != *bytes {
                    return Err(QemuAttemptProductionVmLifecycleError::InvalidContinuationInput);
                }
                let [Decision::Selection(decision)] = schedule.decisions() else {
                    return Err(QemuAttemptProductionVmLifecycleError::InvalidContinuationInput);
                };
                let selection = decision
                    .selection()
                    .map_err(|_| QemuAttemptProductionVmLifecycleError::InvalidContinuationInput)?;
                if !decision.is_campaign_branch()
                    || !crucible::is_live_world_network_selection(&selection)
                    || !opportunities.insert(selection.opportunity())
                {
                    return Err(QemuAttemptProductionVmLifecycleError::InvalidContinuationInput);
                }
                selections.push(decision.clone());
            }
            Ok(ProductionContinuationPlan::NetworkSelections {
                base: continuation.source.clone(),
                frontier,
                selections,
            })
        }
    }
}

pub(super) fn production_lifecycle_config_for_start(
    config: &ProductionVmLifecycleConfig,
    source: &ScenarioDefForm,
    start: &Configuration,
    signal_fault_replay: Option<&crucible::SignalFaultCampaignReplayPlan>,
) -> Result<ProductionVmLifecycleConfig, QemuAttemptProductionVmLifecycleError> {
    let (selections, plans) = app_random_branch_replay(start)
        .map_err(QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay)?;
    if plans.keys().any(|node| {
        !source
            .world()
            .vm_nodes()
            .iter()
            .any(|vm| vm.id == *node && vm.white_box == crucible::WhiteBoxPolicy::Enabled)
    }) {
        return Err(
            QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(String::from(
                "app-random branch plan names a missing or white-box-disabled VM",
            )),
        );
    }
    let mut config = config
        .clone()
        .with_app_random_branch_replay(selections, plans);
    if let Some(replay) = signal_fault_replay {
        if replay.target() != start {
            return Err(
                QemuAttemptProductionVmLifecycleError::InvalidSignalFaultBranchReplay(
                    String::from(
                        "signal-fault replay target differs from the admitted start configuration",
                    ),
                ),
            );
        }
        config = config.with_signal_fault_campaign_replay(replay.clone());
    }
    Ok(config)
}

impl<F, D> CrucibleExecutionRunner for QemuFreshExecutionRunner<F, D>
where
    F: QemuFreshAttemptLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    type Error = QemuFreshExecutionRunnerError<F::Error, D::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let continuations = validated_attempt_continuations(input).map_err(|()| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::InvalidContinuationInput)
        })?;
        if !self
            .lifecycles
            .configure_attempt_continuations(&continuations)
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ContinuationInputUnsupported,
            ));
        }
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ResumeCheckpointUnsupported(checkpoint),
            ));
        }
        if matches!(
            context.start_mode(),
            AttemptStartMode::CaptureMaterializedStart { .. }
                | AttemptStartMode::SavepointCapture { .. }
        ) && !context.checkpoint_request().is_requested()
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::CaptureCheckpointNotRequested,
            ));
        }
        let scenario = input.scenario().scenario_def();
        let (start, start_signal_fault_replay) = match input.start() {
            CrucibleResolvedAttemptStart::AfterAttempt {
                base,
                base_signal_fault_replay,
                ..
            } => (base.configuration(), base_signal_fault_replay),
            start @ (CrucibleResolvedAttemptStart::Discover { .. }
            | CrucibleResolvedAttemptStart::Branch { .. }) => {
                (start.configuration(), input.signal_fault_replay())
            }
        };
        if let Some(decision) = unsupported_fresh_replay_decision(start, start_signal_fault_replay)
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                    configuration: start.id(),
                    decision,
                },
            ));
        }
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                input.scenario(),
                start,
                start_signal_fault_replay,
                context,
            )
            .map_err(map_fresh_lifecycle_failure)?;
        let materialization = materialize_fresh_start(&mut lifecycle, input, start, context, false)
            .and_then(|materialization| {
                replay_selected_origins(&mut lifecycle, input, context, materialization)
            });
        let driven = materialization.and_then(|materialization| {
            if matches!(
                context.start_mode(),
                AttemptStartMode::CaptureMaterializedStart { .. }
            ) {
                let lifecycle_terminal = lifecycle.terminal_verdict_for_stop();
                if let (Some(materialized), Some(retained)) =
                    (&materialization.terminal_verdict, &lifecycle_terminal)
                    && materialized != retained
                {
                    return Err(map_checkpoint_capture_failure(
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "materialized terminal verdict differs from lifecycle evidence",
                            ),
                        },
                    ));
                }
                let terminal_verdict = materialization
                    .terminal_verdict
                    .as_ref()
                    .or(lifecycle_terminal.as_ref());
                let checkpoint_ready = lifecycle
                    .exact_checkpoint_ready()
                    .map_err(map_checkpoint_capture_failure)?;
                if !checkpoint_ready {
                    return Err(AttemptWorkerFailure::Terminal(
                        QemuFreshExecutionRunnerError::CaptureStartNotCheckpointReady,
                    ));
                }
                if let Some(verdict) = terminal_verdict {
                    let cause = match verdict {
                        QuantumTerminalVerdict::Passed => CheckpointTerminalCause::Passed,
                        QuantumTerminalVerdict::Failed(violations) => {
                            CheckpointTerminalCause::Failed(violations.clone())
                        }
                    };
                    lifecycle
                        .prepare_terminal_checkpoint(cause)
                        .map_err(map_checkpoint_capture_failure)?;
                }
                let capture = lifecycle
                    .capture_attempt_checkpoint(context)
                    .map_err(map_checkpoint_capture_failure)?;
                return context
                    .prepare_and_stage_checkpoint(capture)
                    .map(QemuFreshRunnerResult::Checkpoint)
                    .map_err(map_checkpoint_handoff_failure);
            }
            if input.attempt().stop().accepts_next_choice() {
                lifecycle.enable_signal_fault_campaign_promotion();
            }
            let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
            let outcome = self
                .driver
                .drive(&mut facade, input, context, materialization)
                .map_err(map_fresh_driver_failure)?;
            match outcome {
                QemuFreshDriveOutcome::Observation(pending) => {
                    Ok(QemuFreshRunnerResult::Observation(pending))
                }
                QemuFreshDriveOutcome::CheckpointRequested(choices) => {
                    if !context.checkpoint_request().is_requested() {
                        return Err(AttemptWorkerFailure::Terminal(
                            QemuFreshExecutionRunnerError::UnsolicitedCheckpoint,
                        ));
                    }
                    if matches!(
                        context.start_mode(),
                        AttemptStartMode::SavepointCapture { .. }
                    ) && let Some(verdict) = lifecycle.terminal_verdict_for_stop()
                    {
                        let cause = match verdict {
                            QuantumTerminalVerdict::Passed => CheckpointTerminalCause::Passed,
                            QuantumTerminalVerdict::Failed(violations) => {
                                CheckpointTerminalCause::Failed(violations)
                            }
                        };
                        lifecycle
                            .prepare_terminal_checkpoint(cause)
                            .map_err(map_checkpoint_capture_failure)?;
                    }
                    let capture = lifecycle
                        .capture_attempt_checkpoint(context)
                        .map_err(map_checkpoint_capture_failure)?;
                    let capture = choices
                        .bind_capture(input.scenario(), capture)
                        .map_err(map_checkpoint_capture_failure)?;
                    context
                        .prepare_and_stage_checkpoint(capture)
                        .map(QemuFreshRunnerResult::Checkpoint)
                        .map_err(map_checkpoint_handoff_failure)
                }
            }
        });
        let driven = driven.and_then(|pending| {
            lifecycle
                .prepare_terminal_fingerprints()
                .map(|()| pending)
                .map_err(map_terminal_fingerprint_capture_failure)
        });
        if let (Some(source), Ok(QemuFreshRunnerResult::Observation(pending))) =
            (&self.terminal_exact_retention, &driven)
        {
            // Optional exact retention never changes the semantic observation.
            // Missing or unsafe physical capture is represented by Incomplete.
            let _ = retain_failed_observation_checkpoint(
                source.as_ref(),
                &mut lifecycle,
                &self.driver,
                pending,
                input,
                context,
            );
        }
        let captured_trace = if matches!(&driven, Ok(QemuFreshRunnerResult::Observation(_))) {
            lifecycle.resolved_effect_trace()
        } else {
            Ok(None)
        };
        let cleanup = lifecycle.shutdown();

        let (pending, final_events) = match (driven, cleanup) {
            (Ok(pending), Ok(events)) => (pending, events),
            (Err(failure), Ok(_events)) => return Err(failure),
            (Ok(_pending), Err(cleanup)) => {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::Cleanup(cleanup),
                ));
            }
            (Err(failure), Err(cleanup)) => {
                return Err(AttemptWorkerFailure::Terminal(
                    cleanup_after_fresh_runner_failure(failure, cleanup),
                ));
            }
        };
        let resolved_effect_trace = captured_trace.map_err(|error| {
            AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ResolvedEffectTraceCapture(error),
            )
        })?;
        let product = match pending {
            QemuFreshRunnerResult::Observation(pending) => self
                .driver
                .seal_with_trace(pending, final_events, resolved_effect_trace)
                .map_err(map_fresh_driver_failure)?,
            QemuFreshRunnerResult::Checkpoint(checkpoint) => {
                AttemptExecutionProduct::exact_checkpoint(checkpoint)
            }
        };
        Ok(CrucibleExecutionOutcome::new(
            product,
            CrucibleMaterializationTier::ThinReplay,
        ))
    }
}

pub(super) fn validated_attempt_continuations(
    input: &CrucibleAttemptExecution,
) -> Result<Vec<QemuAttemptContinuation<'_>>, ()> {
    let Some((origins, terminal_input)) = input.continuation_replay_basis() else {
        return input
            .attempt()
            .continuation_input()
            .is_none()
            .then(Vec::new)
            .ok_or(());
    };
    let mut continuations = Vec::new();
    let mut source = None;
    for origin in origins.iter() {
        if let Some(continuation_input) = origin.attempt().continuation_input() {
            continuations.push(validated_attempt_continuation(
                continuation_input,
                source.ok_or(())?,
            )?);
        }
        source = Some(origin);
    }
    if let Some(continuation_input) = terminal_input {
        continuations.push(validated_attempt_continuation(
            continuation_input,
            source.ok_or(())?,
        )?);
    }
    Ok(continuations)
}

fn validated_attempt_continuation<'a>(
    continuation_input: &'a AttemptContinuationInput,
    source: &'a CrucibleAttemptOrigin,
) -> Result<QemuAttemptContinuation<'a>, ()> {
    let source_frontier_ticks = match (source.attempt().stop(), source.source_stop()) {
        (
            StopCondition::VirtualTimeNanoseconds(requested),
            Some(crucible_campaign::StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(
                reached,
            ))),
        ) if requested == reached => *reached,
        (
            StopCondition::Observation(condition),
            Some(crucible_campaign::StopOutcome::ObservationReached(proof)),
        ) if proof.condition() == condition => proof.boundary().frontier_nanoseconds(),
        (
            requested @ StopCondition::Bounded { .. },
            Some(crucible_campaign::StopOutcome::BoundedPrimaryReached { stop, proof }),
        ) if requested == stop => proof.frontier_nanoseconds(),
        (
            StopCondition::Bounded { primary, .. },
            Some(crucible_campaign::StopOutcome::ObservationReached(proof)),
        ) if matches!(primary.as_ref(), StopCondition::Observation(condition) if proof.condition() == condition) => {
            proof.boundary().frontier_nanoseconds()
        }
        _ => return Err(()),
    };
    if source_frontier_ticks != continuation_input.source_frontier_ticks() {
        return Err(());
    }

    Ok(QemuAttemptContinuation {
        input: continuation_input,
        source: source.reached(),
    })
}

impl<F, D> QemuAttemptStartVerifier for QemuFreshExecutionRunner<F, D>
where
    F: QemuFreshAttemptLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    fn verify_attempt_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>> {
        if !self.lifecycles.configure_attempt_continuations(&[]) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ContinuationInputUnsupported,
            ));
        }
        let start = match input.start() {
            CrucibleResolvedAttemptStart::Discover { configuration } => configuration,
            CrucibleResolvedAttemptStart::Branch { selected, .. } => selected,
            CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::StartReplay(
                        QemuFreshStartReplayError::OrdinaryStartMissing,
                    ),
                ));
            }
        };
        let signal_fault_replay = input.signal_fault_replay();
        if let Some(decision) = unsupported_fresh_replay_decision(start, signal_fault_replay) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                    configuration: start.id(),
                    decision,
                },
            ));
        }

        let replay_context = context.for_origin_replay();
        let scenario = input.scenario().scenario_def();
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                input.scenario(),
                start,
                signal_fault_replay,
                &replay_context,
            )
            .map_err(map_fresh_lifecycle_failure)?;
        let replay = materialize_fresh_start(&mut lifecycle, input, start, &replay_context, false)
            .and_then(|materialization| {
                materialization.attempt_start_proof(start).map_err(|error| {
                    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                        QemuFreshStartReplayError::AttemptStartProof(Box::new(error)),
                    ))
                })
            });
        let cleanup = lifecycle.shutdown();

        match (replay, cleanup) {
            (Ok(proof), Ok(_)) => Ok(proof),
            (Err(failure), Ok(_)) => Err(failure),
            (Ok(_), Err(cleanup)) => Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::Cleanup(cleanup),
            )),
            (Err(failure), Err(cleanup)) => Err(AttemptWorkerFailure::Terminal(
                cleanup_after_fresh_runner_failure(failure, cleanup),
            )),
        }
    }
}

impl<F, D> QemuSelectedOriginVerifier for QemuFreshExecutionRunner<F, D>
where
    F: QemuFreshAttemptLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    fn verify_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>> {
        let continuations = validated_attempt_continuations(input).map_err(|()| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::InvalidContinuationInput)
        })?;
        if !self
            .lifecycles
            .configure_attempt_continuations(&continuations)
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ContinuationInputUnsupported,
            ));
        }
        let CrucibleResolvedAttemptStart::AfterAttempt {
            base,
            base_signal_fault_replay,
            ..
        } = input.start()
        else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::OriginMissing,
                ),
            ));
        };
        let start = base.configuration();
        if let Some(decision) = unsupported_fresh_replay_decision(start, base_signal_fault_replay) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                    configuration: start.id(),
                    decision,
                },
            ));
        }

        let replay_context = context.for_origin_replay();
        let scenario = input.scenario().scenario_def();
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                input.scenario(),
                start,
                base_signal_fault_replay,
                &replay_context,
            )
            .map_err(map_fresh_lifecycle_failure)?;
        let replay = materialize_fresh_start(&mut lifecycle, input, start, &replay_context, false)
            .and_then(|materialization| {
                replay_selected_origins(&mut lifecycle, input, &replay_context, materialization)
            })
            .and_then(|materialization| {
                if context.execution_origin().resume_basis().is_some() {
                    let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
                    let outcome = crate::qemu_campaign_driver::replay_modeled_attempt_to_boundary(
                        &mut facade,
                        input,
                        &replay_context,
                        materialization,
                        target,
                    )
                    .map_err(map_selected_origin_replay_failure)?;
                    let QemuFreshDriveOutcome::Observation(pending) = outcome else {
                        return Err(AttemptWorkerFailure::Terminal(
                            QemuFreshExecutionRunnerError::StartReplay(
                                QemuFreshStartReplayError::OriginUnexpectedCheckpoint,
                            ),
                        ));
                    };
                    pending
                        .into_checkpoint_replay_materialization(lifecycle.completed_quanta())
                        .map_err(|error| {
                            AttemptWorkerFailure::Terminal(
                                QemuFreshExecutionRunnerError::StartReplay(
                                    QemuFreshStartReplayError::Origin(Box::new(error)),
                                ),
                            )
                        })?
                        .selected_origin_proof(target.configuration())
                } else {
                    materialization.selected_origin_proof(input.start().configuration())
                }
                .map_err(|error| {
                    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                        QemuFreshStartReplayError::Origin(Box::new(error)),
                    ))
                })
            })
            .and_then(|proof| {
                if !proof.same_boundary(target.proof()) {
                    return Err(AttemptWorkerFailure::Terminal(
                        QemuFreshExecutionRunnerError::StartReplay(
                            QemuFreshStartReplayError::OriginReachedMismatch,
                        ),
                    ));
                }
                Ok(proof)
            });
        let cleanup = lifecycle.shutdown();

        match (replay, cleanup) {
            (Ok(proof), Ok(_)) => Ok(proof),
            (Err(failure), Ok(_)) => Err(failure),
            (Ok(_), Err(cleanup)) => Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::Cleanup(cleanup),
            )),
            (Err(failure), Err(cleanup)) => Err(AttemptWorkerFailure::Terminal(
                cleanup_after_fresh_runner_failure(failure, cleanup),
            )),
        }
    }
}

pub(super) fn replay_selected_origins<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    mut materialization: QemuFreshStartMaterialization,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let CrucibleResolvedAttemptStart::AfterAttempt {
        base,
        base_signal_fault_replay,
        origins,
    } = input.start()
    else {
        return Ok(materialization);
    };
    let replay_context = context.for_origin_replay();
    let mut segment_start = base.as_ref().clone();
    let mut signal_fault_replay = base_signal_fault_replay.clone();

    for origin in origins.iter() {
        let segment =
            input.for_origin_replay(origin.attempt().clone(), segment_start, signal_fault_replay);
        let mut facade = QemuFreshAttemptLifecycle::new(lifecycle);
        let outcome = crate::qemu_campaign_driver::drive_modeled_attempt(
            &mut facade,
            &segment,
            &replay_context,
            materialization,
        )
        .map_err(map_selected_origin_replay_failure)?;
        let QemuFreshDriveOutcome::Observation(pending) = outcome else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::OriginUnexpectedCheckpoint,
                ),
            ));
        };
        let (reached, next_materialization) = pending
            .into_origin_materialization(lifecycle.completed_quanta())
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::Origin(Box::new(error)),
                ))
            })?;
        if reached != *origin.reached() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::OriginReachedMismatch,
                ),
            ));
        }

        materialization = next_materialization;
        segment_start = CrucibleResolvedAttemptStart::Discover {
            configuration: reached,
        };
        signal_fault_replay = origin.signal_fault_replay().clone();
    }
    Ok(materialization)
}

pub(super) fn map_selected_origin_replay_failure<F, D>(
    failure: AttemptWorkerFailure<crate::QemuFreshModeledDriverError>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let map = |error: crate::QemuFreshModeledDriverError| {
        QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Origin(Box::new(
            error,
        )))
    };
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(map(error)),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(map(error)),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(map(error)),
    }
}

pub(super) fn unsupported_fresh_replay_decision(
    target: &Configuration,
    signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
) -> Option<usize> {
    if signal_fault_replay.target() != target {
        return Some(0);
    }
    let covered_signal_fault_overrides = signal_fault_replay
        .branches()
        .iter()
        .filter(|branch| branch.decisions().len() == 2)
        .map(|branch| branch.parent().schedule.len() + 1)
        .collect::<BTreeSet<_>>();
    target
        .schedule
        .decisions()
        .iter()
        .enumerate()
        .find_map(|(index, decision)| match decision {
            Decision::Override(_) if covered_signal_fault_overrides.contains(&index) => None,
            Decision::Override(_) => Some(index),
            Decision::Selection(selection) => selection
                .selection()
                .map_or(true, |decoded| {
                    matches!(decoded.origin(), SelectionOrigin::ModelSample(_))
                        && !selection.is_app_random_model_sample()
                })
                .then_some(index),
            Decision::DeliveryOrder(_) | Decision::RngDraw(_) | Decision::Preemption(_) => None,
        })
}
