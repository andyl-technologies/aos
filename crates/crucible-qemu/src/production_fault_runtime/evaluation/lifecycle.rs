//! Non-consuming lifecycle publication preflight.

use super::*;

impl ProductionFaultRuntime {
    /// Previews lifecycle actions that can publish host-owned work at one boundary.
    ///
    /// The result includes direct lifecycle actions selected by this boundary
    /// and exact lifecycle decisions authenticated from an undrained QEMU
    /// occurrence. It does not mutate the evaluator or action ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when preview evaluation fails,
    /// a node event cannot be drained and authenticated, an action resolves to
    /// a non-node target, or bounded intent storage cannot be reserved.
    pub fn preview_node_lifecycle_intents(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<Vec<QemuNodeLifecycleIntent>, ProductionFaultRuntimeError> {
        if self.lifecycle_work_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        let configured_event_records = usize::try_from(self.resource_limits.event_records)
            .map_err(|_| FaultResourceLimitError::Representation {
                field: "event_records",
                value: self.resource_limits.event_records,
            })?;
        let mut canonical_current = usize::try_from(production_record_state_usage(
            &self.emitted_events,
            &self.pending_qemu_observations,
            &self.pending_qemu_events,
            &self.qemu_issued_actions,
            &self.qemu_action_commits,
            &self.qemu_active_rule_ids,
            self.resource_limits,
        )?)
        .map_err(|_| FaultResourceLimitError::Representation {
            field: "event_records",
            value: u64::MAX,
        })?;
        let (_event_records, event_log_bytes) = production_event_state_usage(
            &self.emitted_events,
            &[],
            &self.pending_qemu_observations,
            &[],
            &self.pending_qemu_events,
            self.resource_limits,
        )?;
        let mut canonical_payload_bytes = usize::try_from(event_log_bytes).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: event_log_bytes,
            }
        })?;
        let configured_payload_bytes = usize::try_from(self.resource_limits.event_log_bytes)
            .map_err(|_| FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: self.resource_limits.event_log_bytes,
            })?;
        let configured_inline_payload_bytes =
            usize::try_from(self.resource_limits.event_inline_payload_bytes).map_err(|_| {
                FaultResourceLimitError::Representation {
                    field: "event_inline_payload_bytes",
                    value: self.resource_limits.event_inline_payload_bytes,
                }
            })?;
        let mut event_decisions = Vec::new();
        nodes.visit_fault_event_nodes(|node, backend| {
            let events = backend
                .preview_fault_events(
                    &mut canonical_current,
                    configured_event_records,
                    &mut canonical_payload_bytes,
                    configured_payload_bytes,
                    configured_inline_payload_bytes,
                )
                .map_err(map_fault_event_drain_error)?;
            event_decisions
                .try_reserve_exact(events.len())
                .map_err(|_| {
                    runtime_collection_reservation(
                        "event_records",
                        event_decisions.len(),
                        events.len(),
                        self.resource_limits,
                    )
                })?;
            for event in &events {
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
                validate_preview_event(
                    event,
                    action,
                    commit,
                    coordinate,
                    self.resource_limits,
                )?;
                validate_node_event_evidence(event, action)?;
                if let Some(decision) = node_lifecycle_decision(
                    node,
                    action_identity,
                    event,
                    event_decisions.len(),
                    self.resource_limits,
                )? {
                    if event_decisions
                        .iter()
                        .any(|prior: &QemuNodeLifecycleDecision| prior.node == decision.node)
                    {
                        return Err(ProductionFaultRuntimeError::from(BackendError::Rejected {
                            message: format!(
                                "QEMU node `{}` produced more than one lifecycle decision in one boundary",
                                node.name
                            ),
                        }));
                    }
                    event_decisions.push(decision);
                }
            }
            Ok(())
        })?;
        let preview = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.preview_boundary(coordinate, same_coordinate_sequence))
            .transpose()?;
        let preview_actions = preview
            .as_ref()
            .map_or([].as_slice(), |evaluation| evaluation.actions.as_slice());
        let direct_lifecycle_actions = preview_actions
            .iter()
            .filter(|action| {
                action.kind == BindingActionKind::Apply
                    && matches!(
                        action.effect.specification(),
                        EffectSpecification::Node(NodeEffectSpecification::Lifecycle { .. })
                    )
            })
            .count();
        let maximum = self
            .pending_node_lifecycle
            .len()
            .checked_add(event_decisions.len())
            .and_then(|count| count.checked_add(direct_lifecycle_actions))
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?;
        self.resource_limits.reserve(
            "nodes",
            0,
            u64::try_from(maximum).map_err(|_| FaultResourceLimitError::Representation {
                field: "nodes",
                value: u64::MAX,
            })?,
        )?;
        let mut intents = Vec::new();
        intents.try_reserve_exact(maximum).map_err(|_| {
            runtime_collection_reservation("nodes", 0, maximum, self.resource_limits)
        })?;
        for decision in &self.pending_node_lifecycle {
            self.resource_limits.reserve(
                "nodes",
                u64::try_from(intents.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "nodes",
                        value: u64::MAX,
                    }
                })?,
                1,
            )?;
            intents.push(QemuNodeLifecycleIntent {
                node: try_clone_ledger_node_id(&decision.node, || {
                    runtime_collection_reservation("nodes", intents.len(), 1, self.resource_limits)
                })?,
                action: decision.action,
                requested_transition: decision.requested_transition,
                event_evidence: Some(decision.event_evidence),
            });
        }
        for decision in event_decisions {
            intents.push(QemuNodeLifecycleIntent {
                node: decision.node,
                action: decision.action,
                requested_transition: decision.requested_transition,
                event_evidence: Some(decision.event_evidence),
            });
        }
        for action in preview_actions {
            let EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: requested_transition,
                ..
            }) = action.effect.specification()
            else {
                continue;
            };
            if action.kind != BindingActionKind::Apply {
                continue;
            }
            let action_identity = action.id();
            if intents
                .iter()
                .any(|intent: &QemuNodeLifecycleIntent| intent.action == action_identity)
            {
                continue;
            }
            let ResolvedFaultTarget::Node { node } = &action.target else {
                return Err(BackendError::Rejected {
                    message: format!(
                        "lifecycle action `{}` resolved to a non-node target",
                        action.binding
                    ),
                }
                .into());
            };
            self.resource_limits.reserve(
                "nodes",
                u64::try_from(intents.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "nodes",
                        value: u64::MAX,
                    }
                })?,
                1,
            )?;
            intents.push(QemuNodeLifecycleIntent {
                node: NodeId {
                    name: try_clone_string(node.as_str(), || {
                        runtime_collection_reservation(
                            "nodes",
                            intents.len(),
                            1,
                            self.resource_limits,
                        )
                    })?,
                },
                action: action_identity,
                requested_transition: *requested_transition,
                event_evidence: None,
            });
        }
        intents.sort_unstable_by(|left, right| {
            left.node
                .cmp(&right.node)
                .then_with(|| left.action.bytes.cmp(&right.action.bytes))
        });
        if intents.windows(2).any(|pair| pair[0].node == pair[1].node) {
            return Err(BackendError::Rejected {
                message: String::from(
                    "one boundary retains more than one lifecycle-capable action for one node",
                ),
            }
            .into());
        }
        Ok(intents)
    }
}

fn validate_preview_event(
    event: &DequeuedFaultEvent,
    action: &ResolvedBindingAction,
    commit: &CommittedQemuActionEvidence,
    boundary: FaultCoordinate,
    limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeError> {
    let binding_hash =
        ContentHash::from_canonical_material("crucible.fault-binding.v1", action.binding.as_str());
    let target_hash = fallible_target_hash(&action.target, limits)?;
    let binding_matches = event.header.binding_hash == binding_hash.bytes;
    let target_matches = event.header.target_hash == target_hash.bytes;
    let generation_matches = event.header.generation == action.transition_sequence;
    let commit_matches = qemu_event_matches_commit(event, action, commit);
    let boundary_matches = boundary
        .retired_instructions
        .is_none_or(|retired| event.header.observed_icount <= retired);
    if binding_matches && target_matches && generation_matches && commit_matches && boundary_matches
    {
        return Ok(());
    }
    Err(BackendError::Rejected {
        message: format!(
            "QEMU fault event {} does not match its active rule during lifecycle preview: binding={binding_matches}, target={target_matches}, generation={generation_matches}, commit={commit_matches}, boundary={boundary_matches}",
            event.header.event_sequence,
        ),
    }
    .into())
}
