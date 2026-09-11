//! Authenticated fresh-start replay and failure mapping.

use super::*;

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

pub(super) fn validated_attempt_continuation<'a>(
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
            Decision::Override(_) | Decision::AppRandom(_) => Some(index),
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

pub(super) fn materialize_fresh_start<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    target: &Configuration,
    context: &AttemptExecutionContext,
    retain_replayed_discoveries: bool,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let completed_quanta = lifecycle.completed_quanta();
    materialize_start_from(
        lifecycle,
        input,
        Configuration::genesis(target.def.clone()),
        target,
        context,
        QemuFreshStartMaterialization {
            retain_replayed_discoveries,
            ..QemuFreshStartMaterialization::at_quanta(completed_quanta)
        },
    )
}

pub(crate) fn materialize_start_from<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    mut current: Configuration,
    target: &Configuration,
    context: &AttemptExecutionContext,
    mut replay: QemuFreshStartMaterialization,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let authoritative_quanta = lifecycle.completed_quanta();
    if replay.completed_quanta != authoritative_quanta {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::QuantumCoordinateMismatch {
                    materialized: replay.completed_quanta,
                    authoritative: authoritative_quanta,
                },
            ),
        ));
    }
    if current == *target {
        return Ok(replay);
    }
    if replay.terminal_verdict.is_some() {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
        ));
    }

    // A guest selectable can already be pending at lifecycle admission. Replay
    // it at the current boundary before charging a quantum so a saved choice at
    // genesis retains its original absolute quantum and event coordinates.
    let initial_selection_entries = apply_replayed_guest_selectables(
        lifecycle,
        context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: input.attempt(),
            start: input.start(),
        },
        input.lineage().scenario(),
        input.scenario(),
        target,
        &mut current,
        &mut replay,
    )?;
    append_start_replay_events(&mut replay, &initial_selection_entries)?;
    if current == *target {
        return Ok(replay);
    }

    loop {
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }
        let prior_len = current.schedule.len();
        context.charge_execution_quantum().map_err(|error| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::ResourceRefusal(error),
            ))
        })?;
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: current,
                control: Vec::new(),
            })
            .map_err(map_start_replay_scheduler_failure)?;
        let completed_quanta = lifecycle.completed_quanta();
        if completed_quanta < replay.completed_quanta {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::QuantumCounterRegressed {
                        before: replay.completed_quanta,
                        after: completed_quanta,
                    },
                ),
            ));
        }
        let prior_completed_quanta = replay.completed_quanta;
        replay.completed_quanta = completed_quanta;
        replay.frontier = outcome.frontier;
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }

        let mut next = outcome.configuration;
        let next_len = next.schedule.len();
        if next.def != target.def
            || next_len < prior_len
            || next_len > target.schedule.len()
            || next.schedule.decisions()[prior_len..]
                != target.schedule.decisions()[prior_len..next_len]
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Diverged),
            ));
        }
        let terminal = lifecycle.terminal_verdict_for_stop();
        let selection_entries = if terminal.is_none() {
            apply_replayed_guest_selectables(
                lifecycle,
                context,
                GuestSelectableReplayContext {
                    phase: GuestSelectableReplayPhase::FreshStart,
                    attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
                    attempt: input.attempt(),
                    start: input.start(),
                },
                input.lineage().scenario(),
                input.scenario(),
                target,
                &mut next,
                &mut replay,
            )?
        } else {
            Vec::new()
        };

        append_start_replay_events(&mut replay, &outcome.event_log_entries)?;
        append_start_replay_events(&mut replay, &selection_entries)?;
        replay.terminal_quiescence = outcome.scheduler_quiescence;
        current = next;
        if current == *target {
            replay.terminal_verdict = terminal;
            return Ok(replay);
        }
        if terminal.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
            ));
        }
        if replay.completed_quanta == prior_completed_quanta && current.schedule.len() == prior_len
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Diverged),
            ));
        }
    }
}

// crucible-lint: allow rust-allow -- replay validation keeps each authenticated source and mutable materialization target explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_replayed_guest_selectables<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    context: &AttemptExecutionContext,
    replay_context: GuestSelectableReplayContext<'_>,
    scenario: crucible_campaign::ScenarioDefId,
    source: &ScenarioDefForm,
    target: &Configuration,
    current: &mut Configuration,
    materialization: &mut QemuFreshStartMaterialization,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let pending = lifecycle
        .drain_pending_selectable_requests()
        .map_err(map_start_replay_scheduler_failure)?;
    let mut replayed = current.clone();
    let mut replies = Vec::with_capacity(pending.len());
    for pending in pending {
        let discovery =
            resolve_guest_selectable(scenario, source, pending.node(), pending.pending())
                .map_err(start_replay_guest_selectable_failure)?;
        materialization
            .retain_replayed_discovery(discovery.clone())
            .map_err(start_replay_guest_selectable_failure)?;
        let Some(Decision::Selection(decision)) =
            target.schedule.decisions().get(replayed.schedule.len())
        else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Diverged),
            ));
        };
        let selection = decision
            .selection()
            .map_err(GuestSelectableError::Campaign)
            .map_err(start_replay_guest_selectable_failure)?;
        let expected_selection = replay_context
            .start
            .replay_selection(replayed.schedule.len());
        record_guest_selectable_boundary_diagnostic(
            context,
            replay_context.attempt,
            GuestSelectableBoundaryDiagnosticStage::Replay,
            replayed.schedule.len(),
            pending.node(),
            pending.pending(),
            &discovery,
            expected_selection,
        );
        let validation = match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(discovery.opportunity(), discovery.domain())
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent =
                    ConfigurationId::from_hash(CampaignHash::from_bytes(replayed.id().bytes));
                selection.validate_branch_replay(
                    discovery.opportunity(),
                    discovery.domain(),
                    discovery.opportunity().branch_point_id(parent),
                )
            }
            SelectionOrigin::ModelSample(_) => {
                return Err(start_replay_guest_selectable_failure(
                    GuestSelectableError::Campaign(
                        crucible_campaign::CampaignCodecError::InvalidValue {
                            reason: "guest selectable replay does not admit model-sample provenance",
                        },
                    ),
                ));
            }
        };
        if let Err(error) = validation {
            let attempt = replay_context.attempt.id().ok();
            let mismatch = selection
                .replay_mismatch(discovery.opportunity(), discovery.domain())
                .ok()
                .flatten();
            let error = match (attempt, mismatch) {
                (Some(attempt), Some(mismatch)) => {
                    let request = pending.pending().request();
                    let replayed_configuration =
                        ConfigurationId::from_hash(CampaignHash::from_bytes(replayed.id().bytes));
                    let expected_opportunity = expected_selection.map(|selection| {
                        GuestSelectableReplayOpportunityContext::from_opportunity(
                            selection.opportunity(),
                        )
                    });
                    let correlation = GuestSelectableReplayCorrelation {
                        phase: replay_context.phase,
                        attempt_role: replay_context.attempt_role,
                        attempt,
                        replayed_configuration,
                        decision_index: replayed.schedule.len(),
                        node: pending.node().name.clone(),
                        selectable: request.selectable_id().to_owned(),
                        request_instance: request.instance_key().to_owned(),
                        request_sequence: request.sequence(),
                        request_icount: pending.pending().icount(),
                        request_vcpu_index: pending.pending().vcpu_index(),
                        expected_opportunity,
                        replayed_opportunity:
                            GuestSelectableReplayOpportunityContext::from_opportunity(
                                discovery.opportunity(),
                            ),
                    };
                    GuestSelectableError::ReplayMismatch(Box::new(
                        GuestSelectableReplayMismatch::new(correlation, mismatch, error),
                    ))
                }
                _ => GuestSelectableError::Campaign(error),
            };
            return Err(start_replay_guest_selectable_failure(error));
        }
        let reply = selected_guest_reply(pending.pending(), &discovery, &selection)
            .map_err(start_replay_guest_selectable_failure)?;
        replies.push((pending, reply, decision.clone(), replayed.clone()));
        replayed = crucible::step(&replayed, Decision::Selection(decision.clone()));
    }
    let mut selection_entries = Vec::new();
    for (pending, reply, decision, parent) in replies {
        let selected = crucible::step(&parent, Decision::Selection(decision.clone()));
        let entries = lifecycle
            .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
            .map_err(map_start_replay_scheduler_failure)?;
        selection_entries.extend(entries);
    }
    *current = replayed;
    Ok(selection_entries)
}

pub(super) fn start_replay_guest_selectable_failure<F, D>(
    error: GuestSelectableError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(error),
    ))
}

pub(super) fn append_start_replay_events<F, D>(
    replay: &mut QemuFreshStartMaterialization,
    entries: &[SchedulerEventLogEntry],
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let count = replay
        .event_log
        .len()
        .checked_add(entries.len())
        .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-entry-count"))?;
    if count > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::LimitExceeded {
                limit: "fresh-campaign-event-log-entry-count",
            }),
        ));
    }
    let added = entries.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.canonical_material_len())
            .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-bytes"))
    })?;
    let bytes = replay
        .event_log_bytes
        .checked_add(added)
        .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-bytes"))?;
    if bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            }),
        ));
    }
    replay.event_log.extend_from_slice(entries);
    replay.event_log_bytes = bytes;
    Ok(())
}

pub(super) fn start_replay_limit_failure<F, D>(
    limit: &'static str,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::LimitExceeded { limit },
    ))
}

pub(super) fn map_start_replay_scheduler_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error =
        QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Scheduler(error));
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(super) fn map_checkpoint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuFreshExecutionRunnerError::CheckpointCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(super) fn map_terminal_fingerprint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        // crucible-lint: allow host-nondeterminism-state -- this arm only classifies an already-produced scheduler failure as terminal and cannot feed an observation back into execution.
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuFreshExecutionRunnerError::TerminalFingerprintCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(super) fn map_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
    }
}

pub(crate) fn classify_production_lifecycle_failure(
    error: QemuAttemptProductionVmLifecycleError,
) -> AttemptWorkerFailure<QemuAttemptProductionVmLifecycleError> {
    match production_lifecycle_failure_class(&error) {
        SchedulerOperationalFailureClass::Retryable => AttemptWorkerFailure::Retryable(error),
        SchedulerOperationalFailureClass::Canceled => AttemptWorkerFailure::Canceled(error),
        SchedulerOperationalFailureClass::Terminal => AttemptWorkerFailure::Terminal(error),
    }
}

pub(crate) fn production_lifecycle_failure_class(
    error: &QemuAttemptProductionVmLifecycleError,
) -> SchedulerOperationalFailureClass {
    match error {
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::StoreUnavailable { .. }
            | QemuVmRealizationError::ExecutorUnavailable { .. },
        ) => SchedulerOperationalFailureClass::Retryable,
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled { .. },
        )
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(
            ProductionAttemptCheckpointRestoreError::Canceled,
        ) => SchedulerOperationalFailureClass::Canceled,
        QemuAttemptProductionVmLifecycleError::CheckpointRestore(
            ProductionAttemptCheckpointRestoreError::Checkpoint(ExactCheckpointStoreError::Store(
                StoreError::NotFound { .. }
                | StoreError::Unavailable
                | StoreError::Io { .. }
                | StoreError::StreamIo { .. },
            )),
        ) => SchedulerOperationalFailureClass::Retryable,
        QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(_)
        | QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch
        | QemuAttemptProductionVmLifecycleError::InvalidNodeCount(_)
        | QemuAttemptProductionVmLifecycleError::ResourceRefusal(_)
        | QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary
        | QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::InvalidSignalFaultBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::InvalidContinuationInput
        | QemuAttemptProductionVmLifecycleError::ResourceInstallation(_)
        | QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
        | QemuAttemptProductionVmLifecycleError::ResourceContractCleanup(_)
        | QemuAttemptProductionVmLifecycleError::Lifecycle(_)
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(_) => {
            SchedulerOperationalFailureClass::Terminal
        }
    }
}

pub(super) fn map_fresh_lifecycle_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
    }
}

pub(super) fn map_fresh_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error))
        }
    }
}

pub(super) fn cleanup_after_fresh_runner_failure<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
    cleanup: SchedulerError,
) -> QemuFreshExecutionRunnerError<F, D> {
    let driver = match failure {
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error)) => error,
        AttemptWorkerFailure::Retryable(error)
        | AttemptWorkerFailure::Canceled(error)
        | AttemptWorkerFailure::Terminal(error) => {
            return QemuFreshExecutionRunnerError::CleanupAfterRunner {
                failure: Box::new(error),
                cleanup,
            };
        }
    };
    QemuFreshExecutionRunnerError::CleanupAfterDriver { driver, cleanup }
}
