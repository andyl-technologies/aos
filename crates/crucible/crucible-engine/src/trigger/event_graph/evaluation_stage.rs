//! Transactional graph evaluation with a bounded overlay for this pass.

use super::*;

struct Stage {
    updates: EventGraphState,
    failure: Option<EngineError>,
}

pub(super) fn evaluate_at_frontier<E: ConditionEvaluator>(
    state: &mut EventGraphState,
    graph: &EventGraph,
    evaluator: &mut E,
    frontier: Option<VirtualTime>,
) -> Result<EventFirings, EngineError> {
    check_evaluation_admission()?;
    let original = crate::owned_decode::current_budget();
    let persistent_scope = state._decode_custody.enter();
    let install_persistent_custody = persistent_scope.is_none();
    let persistent = if persistent_scope.is_some() {
        crate::owned_decode::current_budget()
    } else {
        original
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::child)
            .transpose()
            .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?
    };
    drop(persistent_scope);
    let temporary = original
        .as_ref()
        .map(crate::owned_decode::DecodeBudget::child)
        .transpose()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let temporary_scope = temporary
        .as_ref()
        .map(crate::owned_decode::DecodeBudget::enter);
    let mut stage = Stage {
        updates: EventGraphState::new(),
        failure: None,
    };
    let latches = graph.events().iter().try_fold(0_usize, |total, event| {
        total
            .checked_add(event.trigger.as_ref().map_or(Ok(0), count_once)?)
            .ok_or_else(overflow)
    })?;
    reserve(&mut stage.updates.once_latches, latches)?;
    let mut firings = Vec::new();
    reserve(&mut firings, graph.events().len())?;
    let point = evaluator.evaluation_point();
    let event_log_offset = evaluator.event_log_offset();
    let timer_fires = evaluator.timer_fires();
    check_evaluation_admission()?;

    for event in graph.events() {
        if frontier.is_some_and(|frontier| point.at() > frontier)
            && event
                .trigger
                .as_ref()
                .is_some_and(super::super::deadlines::requires_global_time)
        {
            continue;
        }
        let truth = match &event.trigger {
            Some(condition) => {
                let mut graph_evaluator = Evaluator {
                    base: state,
                    stage: &mut stage,
                    inner: evaluator,
                };
                super::super::evaluation::try_evaluate_condition(&mut graph_evaluator, condition)?
            }
            None => point.kind() == EventEvaluationKind::Genesis,
        };
        if let Some(error) = stage.failure.take() {
            return Err(error);
        }
        check_evaluation_admission()?;
        let previously_true = state
            .previous_truth
            .get(&event.id)
            .copied()
            .unwrap_or(false);
        admit_map::<bool>(&event.id)?;
        stage.updates.previous_truth.insert(event.id.clone(), truth);
        let should_fire = match event.policy {
            FirePolicy::Once => truth && !state.consumed_once.contains(&event.id),
            FirePolicy::Repeatable => truth && !previously_true,
        };
        if !should_fire {
            continue;
        }
        if event.policy == FirePolicy::Once {
            admit_map::<()>(&event.id)?;
            stage.updates.consumed_once.insert(event.id.clone());
        }
        admit_map::<VirtualTime>(&event.id)?;
        stage
            .updates
            .last_firing
            .insert(event.id.clone(), point.at());
        admit_name(&event.id.name)?;
        let action = copy_action(&event.action)?;
        let condition_summary = match event.trigger.as_ref() {
            Some(condition) => condition.canonical_summary(),
            None => {
                admit_name("entrypoint")?;
                String::from("entrypoint")
            }
        };
        check_evaluation_admission()?;
        firings.push(EventFiring {
            event: event.id.clone(),
            at: point.at(),
            condition_summary,
            action,
        });
    }

    // All destination admission precedes the first persistent state change.
    // Keys and conditions are then moved from the private overlay.
    let persistent_scope = persistent
        .as_ref()
        .map(crate::owned_decode::DecodeBudget::enter);
    for event in stage.updates.previous_truth.keys() {
        if !state.previous_truth.contains_key(event) {
            admit_map::<bool>(event)?;
        }
    }
    for event in &stage.updates.consumed_once {
        if !state.consumed_once.contains(event) {
            admit_map::<()>(event)?;
        }
    }
    for event in stage.updates.last_firing.keys() {
        if !state.last_firing.contains_key(event) {
            admit_map::<VirtualTime>(event)?;
        }
    }
    let mut persistent_latches = Vec::new();
    reserve(&mut persistent_latches, stage.updates.once_latches.len())?;
    for condition in &stage.updates.once_latches {
        persistent_latches.push(condition.try_clone_admitted()?);
    }
    check_evaluation_admission()?;
    let required_latches = state
        .once_latches
        .len()
        .checked_add(persistent_latches.len())
        .ok_or_else(overflow)?;
    // Reserve the graph's complete possible latch inventory once. Repeated
    // passes do not grow a fixed graph's persistent vector one item at a time.
    let capacity = latches.max(required_latches);
    let additional = capacity.saturating_sub(state.once_latches.len());
    reserve(&mut state.once_latches, additional)?;
    if install_persistent_custody {
        // An unsuccessful first pass must not attach its refused authority to
        // an otherwise untouched state. Destination storage is admitted now;
        // the remaining publication only moves already owned values.
        state._decode_custody = persistent
            .as_ref()
            .map(crate::owned_decode::DecodeBudget::custody)
            .unwrap_or_default();
    }
    for (event, truth) in stage.updates.previous_truth {
        state.previous_truth.insert(event, truth);
    }
    for event in stage.updates.consumed_once {
        state.consumed_once.insert(event);
    }
    for (event, at) in stage.updates.last_firing {
        state.last_firing.insert(event, at);
    }
    state.once_latches.extend(persistent_latches);
    drop(persistent_scope);
    let custody = temporary
        .as_ref()
        .map(crate::owned_decode::DecodeBudget::custody)
        .unwrap_or_default();
    drop(temporary_scope);
    Ok(EventFirings::new(
        point,
        event_log_offset,
        timer_fires,
        firings,
        custody,
    ))
}

fn overflow() -> EngineError {
    EngineError::ArtifactDecodeAdmission {
        source: crate::owned_decode::DecodeAdmissionError::new(std::io::Error::other(
            "event evaluation latch count overflowed",
        )),
    }
}

fn count_once(condition: &Condition) -> Result<usize, EngineError> {
    match condition {
        Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
            predicates.iter().try_fold(0_usize, |total, predicate| {
                total
                    .checked_add(count_once(predicate)?)
                    .ok_or_else(overflow)
            })
        }
        Condition::Once { predicate } => count_once(predicate)?.checked_add(1).ok_or_else(overflow),
        Condition::Not { predicate } => count_once(predicate),
        _ => Ok(0),
    }
}

fn reserve<T>(values: &mut Vec<T>, additional: usize) -> Result<(), EngineError> {
    crate::owned_decode::reserve_vec(values, additional)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

fn admit_name(name: &str) -> Result<(), EngineError> {
    crate::owned_decode::charge_array::<u8>(name.len())
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

fn admit_entry<T>() -> Result<(), EngineError> {
    crate::owned_decode::charge_btree_entry::<EventId, T>()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

fn admit_map<T>(event: &EventId) -> Result<(), EngineError> {
    admit_entry::<T>()?;
    admit_name(&event.name)
}

fn copy_action(action: &Action) -> Result<Action, EngineError> {
    Ok(match action {
        Action::ArmTimer { name, after } => Action::ArmTimer {
            name: TimerId {
                name: copy_text(&name.name)?,
            },
            after: *after,
        },
        Action::CancelTimer { name } => Action::CancelTimer {
            name: TimerId {
                name: copy_text(&name.name)?,
            },
        },
        Action::StartNode { node } => Action::StartNode {
            node: NodeId {
                name: copy_text(&node.name)?,
            },
        },
        Action::StopNode { node } => Action::StopNode {
            node: NodeId {
                name: copy_text(&node.name)?,
            },
        },
        Action::CreateSavepoint { label } => Action::CreateSavepoint {
            label: label.as_deref().map(copy_text).transpose()?,
        },
        Action::Fork { label } => Action::Fork {
            label: label.as_deref().map(copy_text).transpose()?,
        },
        Action::Pass => Action::Pass,
        Action::Fail { reason } => Action::Fail {
            reason: copy_text(reason)?,
        },
        Action::Log { level, message } => Action::Log {
            level: *level,
            message: copy_text(message)?,
        },
        Action::Group(actions) => {
            let mut copied = Vec::new();
            reserve(&mut copied, actions.len())?;
            for action in actions {
                copied.push(copy_action(action)?);
            }
            Action::Group(copied)
        }
    })
}

fn copy_text(text: &str) -> Result<String, EngineError> {
    let mut bytes = Vec::new();
    reserve(&mut bytes, text.len())?;
    bytes.extend_from_slice(text.as_bytes());
    String::from_utf8(bytes).map_err(|source| EngineError::ArtifactDecodeAdmission {
        source: crate::owned_decode::DecodeAdmissionError::new(source),
    })
}

struct Evaluator<'state, 'inner, E> {
    base: &'state EventGraphState,
    stage: &'state mut Stage,
    inner: &'inner mut E,
}

impl<E: ConditionEvaluator> condition_evaluator_sealed::Sealed for Evaluator<'_, '_, E> {}

impl<E: ConditionEvaluator> ConditionEvaluator for Evaluator<'_, '_, E> {
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.inner.evaluation_point()
    }
    fn event_log_offset(&self) -> EventLogOffset {
        self.inner.event_log_offset()
    }
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self.inner.leaf_is_true(leaf)
    }
    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.stage
            .updates
            .last_firing(event)
            .or_else(|| self.base.last_firing(event))
            .or_else(|| self.inner.last_event_firing(event))
    }
    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        self.inner.timer_fire_time(timer)
    }
    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        self.inner.timer_fires()
    }
    fn observable_events(&self) -> &[ObservableEvent] {
        self.inner.observable_events()
    }
    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.inner.scheduler_quiescence()
    }
    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.inner.white_box_policy_for_node(node)
    }
    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.base.once_latches.contains(condition)
            || self.stage.updates.once_latches.contains(condition)
    }
    fn prepare_once_latches(&mut self, additional: usize) -> Result<(), EngineError> {
        if self
            .stage
            .updates
            .once_latches
            .len()
            .checked_add(additional)
            .is_none_or(|required| required > self.stage.updates.once_latches.capacity())
        {
            return Err(overflow());
        }
        Ok(())
    }
    fn latch_once_condition(&mut self, condition: Condition) {
        if self.once_condition_is_latched(&condition) || self.stage.failure.is_some() {
            return;
        }
        if self.stage.updates.once_latches.len() == self.stage.updates.once_latches.capacity() {
            self.stage.failure = Some(overflow());
        } else {
            self.stage.updates.once_latches.push(condition);
        }
    }
    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        self.inner.resolve_code_point(node, point)
    }
    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        self.inner.resolve_mem_place(node, place)
    }
}
