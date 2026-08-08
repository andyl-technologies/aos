//! Debug target resolution and checkpoint-coordinate helpers.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::model) struct DebugResolvedReverseStepTarget {
    pub(in crate::model) configuration: Configuration,
    pub(in crate::model) event_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::model) struct DebugCheckpointCoordinateCandidate {
    pub(in crate::model) configuration: Configuration,
    pub(in crate::model) virtual_time: VirtualTime,
    pub(in crate::model) node_icounts: BTreeMap<NodeId, Icount>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::model) struct DebugScopedNodeMaterial {
    pub(in crate::model) target_configuration: ContentHash,
    pub(in crate::model) node_icount: Icount,
    pub(in crate::model) node_blob: NodeBlobRef,
    pub(in crate::model) goto: DebugPerNodeGotoReport,
}

pub(in crate::model) struct DebugReverseContinueLeafOracle<'a, F> {
    pub(in crate::model) entry: &'a SchedulerEventLogEntry,
    pub(in crate::model) leaf_oracle: &'a mut F,
}

impl<F> ConditionLeafOracle for DebugReverseContinueLeafOracle<'_, F>
where
    F: for<'leaf> FnMut(&SchedulerEventLogEntry, ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        (self.leaf_oracle)(self.entry, leaf)
    }
}

pub(in crate::model) fn debug_validate_same_scenario(
    current: &Configuration,
    target: &Configuration,
) -> Result<(), EngineError> {
    if current.def.id == target.def.id {
        Ok(())
    } else {
        Err(EngineError::DebugGotoScenarioMismatch {
            current: current.id(),
            target: target.id(),
        })
    }
}

pub(in crate::model) fn debug_configuration_is_ancestor_or_self(
    candidate: &Configuration,
    current: &Configuration,
) -> bool {
    candidate.def.id == current.def.id
        && candidate.schedule.len() <= current.schedule.len()
        && current
            .schedule
            .decisions()
            .starts_with(candidate.schedule.decisions())
}

pub(in crate::model) fn debug_configurations_are_linearly_related(
    candidate: &Configuration,
    current: &Configuration,
) -> bool {
    candidate.def.id == current.def.id
        && (current
            .schedule
            .decisions()
            .starts_with(candidate.schedule.decisions())
            || candidate
                .schedule
                .decisions()
                .starts_with(current.schedule.decisions()))
}

pub(in crate::model) fn debug_runtime_node_material(
    runtime: &RuntimeState,
    node: &NodeId,
    configuration: ContentHash,
) -> Result<(Icount, NodeBlobRef), EngineError> {
    let icount = runtime.node_icounts.get(node).copied().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    let blob = runtime.node_blobs.get(node).cloned().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    Ok((icount, blob))
}

pub(in crate::model) fn debug_checkpoint_node_material(
    checkpoint: &Checkpoint,
    node: &NodeId,
    configuration: ContentHash,
) -> Result<(Icount, NodeBlobRef), EngineError> {
    let icount = checkpoint.node_icounts.get(node).copied().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    let blob = checkpoint.node_blobs.get(node).cloned().ok_or_else(|| {
        EngineError::DebugTimeTravelUnknownNode {
            node: node.clone(),
            configuration,
        }
    })?;
    Ok((icount, blob))
}

pub(in crate::model) fn maps_equal_except_key<T: PartialEq>(
    left: &BTreeMap<NodeId, T>,
    right: &BTreeMap<NodeId, T>,
    excluded: &NodeId,
) -> bool {
    left.iter()
        .filter(|(node, _)| *node != excluded)
        .all(|(node, value)| right.get(node) == Some(value))
        && right
            .iter()
            .filter(|(node, _)| *node != excluded)
            .all(|(node, value)| left.get(node) == Some(value))
}

pub(in crate::model) fn debug_configuration_prefix(
    configuration: &Configuration,
    len: usize,
) -> Result<Configuration, EngineError> {
    Ok(Configuration {
        def: configuration.def.clone(),
        schedule: configuration
            .schedule
            .prefix(len)
            .map_err(EngineError::SchedulePrefix)?,
    })
}

pub(in crate::model) fn debug_cached_prefix_matches_replay_oracle(
    graph: &TemporalGraph,
    configuration: &Configuration,
) -> Result<bool, EngineError> {
    let checkpoint = if configuration.is_genesis() {
        graph
            .genesis_snapshot(&configuration.def)
            .map(|genesis| genesis.checkpoint.clone())
    } else {
        graph.cached_snapshot(configuration).cloned()
    };
    let Some(checkpoint) = checkpoint else {
        return Ok(true);
    };
    match graph.replay_checkpoint(configuration, &checkpoint) {
        Ok(_) => Ok(true),
        Err(EngineError::ReplayOracleMismatch { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(in crate::model) fn debug_reverse_step_target(
    request: &DebugReverseStepRequest,
) -> Result<DebugResolvedReverseStepTarget, EngineError> {
    if request.grain == DebugReverseStepGrain::Instruction {
        if request.current.schedule.is_empty() {
            return Err(EngineError::DebugTimeTravelNoEarlierCoordinate {
                grain: request.grain,
                current: request.current.id(),
            });
        }
        let target = debug_configuration_prefix(
            &request.current,
            request.current.schedule.len().saturating_sub(1),
        )?;
        return Ok(DebugResolvedReverseStepTarget {
            configuration: target,
            event_sequence: None,
        });
    }

    let Some(entry) = request.event_log.iter().rev().find(|entry| {
        entry.sequence() < request.current_event_sequence_limit()
            && debug_entry_matches_reverse_grain(entry, request.grain)
    }) else {
        return Err(EngineError::DebugTimeTravelNoEarlierCoordinate {
            grain: request.grain,
            current: request.current.id(),
        });
    };
    let configuration = request
        .event_coordinates
        .get(&entry.sequence())
        .cloned()
        .ok_or_else(|| EngineError::DebugTimeTravelMissingEventCoordinate {
            sequence: entry.sequence(),
        })?;
    Ok(DebugResolvedReverseStepTarget {
        configuration,
        event_sequence: Some(entry.sequence()),
    })
}

pub(in crate::model) fn debug_entry_matches_reverse_grain(
    entry: &SchedulerEventLogEntry,
    grain: DebugReverseStepGrain,
) -> bool {
    match (grain, entry.payload()) {
        (
            DebugReverseStepGrain::Quantum,
            SchedulerEventLogPayload::EvaluationBoundary(
                crate::scheduler::SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ) => true,
        (DebugReverseStepGrain::Event, payload) => debug_payload_is_event_grain(payload),
        (DebugReverseStepGrain::Assertion, payload) => debug_payload_is_assertion_grain(payload),
        (DebugReverseStepGrain::Timer, payload) => debug_payload_is_timer_grain(payload),
        (DebugReverseStepGrain::Instruction, _) => false,
        _ => false,
    }
}

pub(in crate::model) fn debug_payload_is_event_grain(payload: &SchedulerEventLogPayload) -> bool {
    matches!(
        payload,
        SchedulerEventLogPayload::ResolvedHappening(_)
            | SchedulerEventLogPayload::Observable(_)
            | SchedulerEventLogPayload::TriggerFired(_)
            | SchedulerEventLogPayload::TriggerActionApplied(_)
    )
}

pub(in crate::model) fn debug_payload_is_assertion_grain(
    payload: &SchedulerEventLogPayload,
) -> bool {
    match payload {
        SchedulerEventLogPayload::Observable(observable) => {
            matches!(
                observable,
                ObservableEventPayload::AssertionEvaluated { .. }
                    | ObservableEventPayload::GuestAssertionMarker { .. }
            )
        }
        SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::TriggerActionApplied(_) => true,
        _ => false,
    }
}

pub(in crate::model) fn debug_payload_is_timer_grain(payload: &SchedulerEventLogPayload) -> bool {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            matches!(event.payload, ScheduledEventPayload::IoCompletion(_))
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            matches!(
                application.action,
                Action::ArmTimer { .. } | Action::CancelTimer { .. }
            )
        }
        _ => false,
    }
}
