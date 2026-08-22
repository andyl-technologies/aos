//! Boundary and opportunity evaluation against host and live QEMU adapters.

use super::*;

impl ProductionFaultRuntime {
    /// Evaluates one scheduler boundary against host devices and live QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when evaluation, preparation, live
    /// application, evidence validation, or checkpointing fails.
    pub fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let Some(runtime) = self.runtime.as_ref() else {
            self.drain_qemu_observations(nodes, coordinate)?;
            if self.pending_qemu_observations.is_empty() {
                return Ok(BindingEvaluation::default());
            }
            return Err(BackendError::Rejected {
                message: String::from("QEMU produced fault events for an inert fault plan"),
            }
            .into());
        };
        let preview = runtime.preview_boundary(coordinate, same_coordinate_sequence)?;
        self.drain_qemu_observations(nodes, coordinate)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let mut evaluation = runtime.evaluate_boundary_with_backend(
            coordinate,
            same_coordinate_sequence,
            &mut sink,
        )?;
        let qemu_commits = sink.take_qemu_commit_evidence();
        if evaluation.emitted_events != preview.emitted_events
            || evaluation.state_machine_events != preview.state_machine_events
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        if let Err(error) = self.update_qemu_action_ledger(&evaluation.actions, qemu_commits) {
            if let Some(runtime) = &mut self.runtime {
                runtime.poison();
            }
            return Err(error);
        }
        // QEMU publishes typed occurrence evidence while committing a command.
        // Drain again only after the issued-action ledger is committed so a
        // one-shot lifecycle action and a persistent-rule removal can both be
        // authenticated at the boundary that caused them. Delaying this until
        // the next scheduler boundary would also lose terminal evidence when
        // the command intentionally exits the child.
        if let Err(error) = self.drain_qemu_observations(nodes, coordinate) {
            if let Some(runtime) = &mut self.runtime {
                runtime.poison();
            }
            return Err(error);
        }
        let mut qemu_observations = std::mem::take(&mut self.pending_qemu_observations);
        qemu_observations.append(&mut evaluation.observations);
        evaluation.observations = qemu_observations;
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        self.pending_node_boot
            .extend(node_boot_requests(&evaluation.actions)?);
        self.retain_search_choices(coordinate, &evaluation.search_choices);
        Ok(evaluation)
    }

    pub(super) fn drain_qemu_observations(
        &mut self,
        nodes: &mut QemuNodeSet,
        boundary: FaultCoordinate,
    ) -> Result<(), ProductionFaultRuntimeError> {
        let mut drained = BTreeMap::new();
        let drain_result = nodes.drain_fault_events(&mut drained);
        for (node, mut events) in drained {
            if !events.is_empty() {
                if let Some(pending) = self.pending_qemu_events.get_mut(&node) {
                    pending.append(&mut events);
                } else {
                    self.resource_limits.reserve(
                        "nodes",
                        u64::try_from(self.pending_qemu_events.len()).map_err(|_| {
                            FaultResourceLimitError::Representation {
                                field: "nodes",
                                value: u64::MAX,
                            }
                        })?,
                        1,
                    )?;
                    self.pending_qemu_events
                        .try_insert(node, events)
                        .map_err(|_| {
                            runtime_collection_allocation(
                                "nodes",
                                self.pending_qemu_events.len(),
                                self.resource_limits,
                            )
                        })?;
                }
            }
        }
        drain_result?;
        validate_production_event_state(
            &self.emitted_events,
            &[],
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        validate_pending_qemu_event_sequences(
            &self.pending_qemu_events,
            &nodes.fault_event_sequences(),
        )?;
        let mut observations = Vec::new();
        let mut lifecycle_decisions = BTreeMap::new();
        for (node, events) in &self.pending_qemu_events {
            for event in events {
                let action_identity = ContentHash {
                    bytes: event.header.action_hash,
                };
                let action = self
                    .qemu_issued_actions
                    .get(&action_identity)
                    .ok_or_else(|| BackendError::Rejected {
                        message: format!(
                            "QEMU fault event {} names an action that was not issued {}",
                            event.header.event_sequence,
                            action_identity.to_hex()
                        ),
                    })?;
                let commit = self
                    .qemu_action_commits
                    .get(&action_identity)
                    .ok_or_else(|| BackendError::Rejected {
                        message: format!(
                            "QEMU fault event {} names an action without an authenticated APPLY result",
                            event.header.event_sequence
                        ),
                    })?;
                let binding_hash = ContentHash::from_canonical_material(
                    "crucible.fault-binding.v1",
                    action.binding.as_str(),
                );
                let target_hash = ContentHash::from_canonical_material(
                    "crucible.resolved-fault-target.v1",
                    &action.target.canonical_material(),
                );
                if event.header.binding_hash != binding_hash.bytes
                    || event.header.target_hash != target_hash.bytes
                    || event.header.generation != action.transition_sequence
                    || !qemu_event_matches_commit(event, action, commit)
                    || boundary
                        .retired_instructions
                        .is_none_or(|retired| event.header.observed_icount > retired)
                {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "QEMU fault event {} does not match its active rule",
                            event.header.event_sequence
                        ),
                    }
                    .into());
                }
                validate_node_event_evidence(event, action)?;
                if let Some(decision) = node_lifecycle_decision(node, action_identity, event)
                    && lifecycle_decisions.insert(node.clone(), decision).is_some()
                {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "QEMU node `{}` produced more than one lifecycle decision in one boundary",
                            node.name
                        ),
                    }
                    .into());
                }
                let opportunity =
                    (event.header.opportunity_hash != [0; 32]).then_some(ContentHash {
                        bytes: event.header.opportunity_hash,
                    });
                let mut evidence = Vec::new();
                evidence.extend_from_slice(&(event.header.command_kind as u16).to_be_bytes());
                evidence.extend_from_slice(&(event.header.outcome as u16).to_be_bytes());
                evidence.extend_from_slice(&event.header.event_sequence.to_be_bytes());
                evidence.extend_from_slice(&event.header.rule_command_sequence.to_be_bytes());
                evidence.extend_from_slice(&event.header.observed_icount.to_be_bytes());
                evidence.extend_from_slice(&event.header.generation.to_be_bytes());
                evidence.extend_from_slice(&event.header.before_hash);
                evidence.extend_from_slice(&event.header.after_hash);
                evidence.extend_from_slice(&event.header.evidence_hash);
                evidence.extend_from_slice(&event.payload);
                observations.push(FaultObservation {
                    semantic_version: crucible::model::FAULT_RUNTIME_STATE_VERSION,
                    kind: if event.header.outcome == crucible_shmem::FaultEventOutcomeV1::Passed {
                        FaultObservationKind::FaultOpportunity
                    } else {
                        FaultObservationKind::EffectApplied
                    },
                    coordinate: FaultCoordinate {
                        virtual_nanos: boundary.virtual_nanos,
                        retired_instructions: Some(event.header.observed_icount),
                    },
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity,
                    evidence: ContentHash::from_bytes(&evidence),
                });
            }
        }
        validate_production_event_state(
            &self.emitted_events,
            &[],
            &self.pending_qemu_observations,
            &observations,
            &PendingQemuEventMap::new(),
            self.resource_limits,
        )?;
        self.pending_node_lifecycle
            .extend(lifecycle_decisions.into_values());
        self.pending_qemu_observations.extend(observations);
        self.pending_qemu_events.clear();
        Ok(())
    }

    pub(super) fn update_qemu_action_ledger(
        &mut self,
        actions: &[ResolvedBindingAction],
        mut commits: BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    ) -> Result<(), ProductionFaultRuntimeError> {
        for action in actions
            .iter()
            .filter(|action| matches!(action.effect.specification(), EffectSpecification::Node(_)))
        {
            match action.kind {
                BindingActionKind::UpsertPersistent | BindingActionKind::Apply => {
                    let identity = action.id();
                    let commit =
                        commits
                            .remove(&identity)
                            .ok_or_else(|| BackendError::Rejected {
                                message: format!(
                                    "QEMU action identity {} has no authenticated APPLY result",
                                    identity.to_hex()
                                ),
                            })?;
                    let retained = u64::try_from(self.qemu_issued_actions.len()).map_err(|_| {
                        FaultResourceLimitError::Representation {
                            field: "event_records",
                            value: u64::MAX,
                        }
                    })?;
                    self.resource_limits.reserve("event_records", retained, 1)?;
                    if self
                        .qemu_issued_actions
                        .try_insert(identity, action.clone())
                        .map_err(|_| {
                            runtime_collection_allocation(
                                "event_records",
                                self.qemu_issued_actions.len(),
                                self.resource_limits,
                            )
                        })?
                        .is_some()
                    {
                        return Err(BackendError::Rejected {
                            message: format!(
                                "QEMU action identity {} was issued more than once",
                                identity.to_hex()
                            ),
                        }
                        .into());
                    }
                    if self
                        .qemu_action_commits
                        .try_insert(identity, commit)
                        .map_err(|_| {
                            runtime_collection_allocation(
                                "event_records",
                                self.qemu_action_commits.len(),
                                self.resource_limits,
                            )
                        })?
                        .is_some()
                    {
                        return Err(BackendError::Rejected {
                            message: format!(
                                "QEMU action identity {} has more than one APPLY result",
                                identity.to_hex()
                            ),
                        }
                        .into());
                    }
                    if action.kind == BindingActionKind::UpsertPersistent {
                        self.qemu_active_rule_ids.retain(|active_id| {
                            self.qemu_issued_actions
                                .get(active_id)
                                .is_none_or(|active| {
                                    active.binding != action.binding
                                        || active.target != action.target
                                        || active.phase != action.phase
                                })
                        });
                        self.qemu_active_rule_ids
                            .try_insert(identity)
                            .map_err(|_| {
                                runtime_collection_allocation(
                                    "event_records",
                                    self.qemu_active_rule_ids.len(),
                                    self.resource_limits,
                                )
                            })?;
                    }
                }
                BindingActionKind::RemovePersistent => {
                    if commits.remove(&action.id()).is_none() {
                        return Err(BackendError::Rejected {
                            message: format!(
                                "QEMU removal identity {} has no authenticated APPLY result",
                                action.id().to_hex()
                            ),
                        }
                        .into());
                    }
                    let prior_len = self.qemu_active_rule_ids.len();
                    self.qemu_active_rule_ids.retain(|active_id| {
                        self.qemu_issued_actions
                            .get(active_id)
                            .is_none_or(|active| {
                                active.binding != action.binding
                                    || active.target != action.target
                                    || active.phase != action.phase
                            })
                    });
                    if self.qemu_active_rule_ids.len() == prior_len {
                        return Err(BackendError::Rejected {
                            message: format!(
                                "QEMU removed an unissued persistent rule for binding `{}`",
                                action.binding.as_str()
                            ),
                        }
                        .into());
                    }
                }
            }
        }
        if !commits.is_empty() {
            return Err(BackendError::Rejected {
                message: String::from("QEMU returned APPLY evidence for an uncommitted action"),
            }
            .into());
        }
        Ok(())
    }

    /// Evaluates one exact device or architectural opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same transaction and evidence
    /// rules as [`Self::evaluate_boundary`].
    pub fn evaluate_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(BindingEvaluation::default());
        };
        let preview = runtime.preview_opportunity(opportunity, same_coordinate_sequence)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let mut sink = ProductionFaultActionSink::new(&mut self.host, nodes);
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let evaluation = runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut sink,
        )?;
        let qemu_commits = sink.take_qemu_commit_evidence();
        if evaluation.emitted_events != preview.emitted_events
            || evaluation.state_machine_events != preview.state_machine_events
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        if let Err(error) = self.update_qemu_action_ledger(&evaluation.actions, qemu_commits) {
            if let Some(runtime) = &mut self.runtime {
                runtime.poison();
            }
            return Err(error);
        }
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        self.retain_search_choices(opportunity.coordinate(), &evaluation.search_choices);
        Ok(evaluation)
    }

    /// Evaluates one host-device opportunity without borrowing the live node set.
    ///
    /// Storage and 9p opportunities can arise while a node's host-I/O runtime is
    /// itself inside `advance_to_ceiling`, so re-borrowing that node set would be
    /// impossible and semantically unnecessary. Opportunity targeting guarantees
    /// that only host-adapter actions can match; a node action is rejected by the
    /// host sink and poisons the same authoritative continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when evaluation, transactional host
    /// application, evidence validation, or checkpointing fails.
    pub fn evaluate_host_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(BindingEvaluation::default());
        };
        let preview = runtime.preview_opportunity(opportunity, same_coordinate_sequence)?;
        validate_production_event_state(
            &self.emitted_events,
            &preview.emitted_events,
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let evaluation = runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            &mut self.host,
        )?;
        if evaluation.emitted_events != preview.emitted_events
            || evaluation.state_machine_events != preview.state_machine_events
        {
            runtime.poison();
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        self.emitted_events
            .extend(evaluation.emitted_events.iter().cloned());
        self.retain_search_choices(opportunity.coordinate(), &evaluation.search_choices);
        Ok(evaluation)
    }

    /// Replaces the one-boundary-delayed telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the snapshot is invalid or the
    /// current continuation cannot be authenticated and checkpointed.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), ProductionFaultRuntimeError> {
        if let Some(runtime) = &mut self.runtime {
            runtime.set_boundary_snapshot(boundary)?;
        }
        Ok(())
    }
}

fn runtime_collection_allocation(
    field: &'static str,
    current: usize,
    limits: FaultResourceLimits,
) -> ProductionFaultRuntimeError {
    let current = u64::try_from(current).unwrap_or(u64::MAX);
    FaultResourceLimitError::Exceeded {
        field,
        current,
        requested: 1,
        configured: limits.configured(field).unwrap_or(0),
        hard: FaultResourceLimits::compiled_maximum()
            .configured(field)
            .unwrap_or(0),
    }
    .into()
}
