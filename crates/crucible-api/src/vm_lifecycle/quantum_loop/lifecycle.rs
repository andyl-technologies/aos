//! Durable lifecycle intent ownership and fail-closed containment.

use super::*;

mod persistence;
mod process_ownership;
mod staging;
pub(in crate::vm_lifecycle) use persistence::LifecycleStatePersistence;
pub(super) use persistence::map_journal_limit;
pub(in crate::vm_lifecycle) use persistence::{
    DurableRunStateError, PRODUCTION_RUN_STATE_FILE, decode_prior_run_state,
    decode_run_json_bounded, persist_run_state_atomic,
};
#[cfg(test)]
pub(in crate::vm_lifecycle) use persistence::{
    HARD_RUN_STATE_JSON_BYTES, validate_recovered_lifecycle_journal,
};
pub(in crate::vm_lifecycle::quantum_loop) use staging::*;

impl ProductionVmLifecycleLoop {
    pub(super) fn begin_terminal_lifecycle_intent(
        &mut self,
        intents: &[QemuNodeLifecycleIntent],
        limits: FaultResourceLimits,
        runtime_event_records: u64,
        runtime_event_log_bytes: u64,
    ) -> Result<PreparedLifecyclePrecommit, SchedulerError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(intents.len())
            .map_err(|_| lifecycle_resource_error("nodes", 0, intents.len(), limits))?;
        self.run_manifest
            .staged_processes
            .try_reserve_exact(intents.len())
            .map_err(|()| lifecycle_resource_error("nodes", 0, intents.len(), limits))?;
        let mut process_owners = Vec::new();
        process_owners
            .try_reserve_exact(intents.len())
            .map_err(|_| lifecycle_resource_error("nodes", 0, intents.len(), limits))?;
        let mut terminal_decisions = Vec::new();
        terminal_decisions
            .try_reserve_exact(intents.len())
            .map_err(|_| lifecycle_resource_error("nodes", 0, intents.len(), limits))?;
        let completed_exit_count = self.lifecycle_journal.completed_exits.len();
        let aggregate_event_records = runtime_event_records
            .checked_add(u64::try_from(completed_exit_count).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                lifecycle_resource_error("event_records", usize::MAX, intents.len(), limits)
            })?;
        limits
            .reserve(
                "event_records",
                aggregate_event_records,
                u64::try_from(intents.len()).map_err(|_| {
                    lifecycle_resource_error("event_records", 0, usize::MAX, limits)
                })?,
            )
            .map_err(|_| {
                lifecycle_resource_error(
                    "event_records",
                    usize::try_from(aggregate_event_records).unwrap_or(usize::MAX),
                    intents.len(),
                    limits,
                )
            })?;
        self.lifecycle_journal
            .completed_exits
            .try_reserve_exact(intents.len())
            .map_err(|_| {
                lifecycle_resource_error(
                    "event_records",
                    self.lifecycle_journal.completed_exits.len(),
                    intents.len(),
                    limits,
                )
            })?;
        for intent in intents {
            let current_generation = self
                .node_generations
                .get(&intent.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no authenticated generation",
                        intent.node.name
                    ),
                })?;
            let next_generation = if lifecycle_intent_may_require_successor_generation(
                intent.requested_transition,
            ) {
                current_generation.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle generation exhausted for `{}`",
                            intent.node.name
                        ),
                    }
                })?
            } else {
                current_generation
            };
            let current_process = self.inner.backend().process_identity(&intent.node)?;
            let journal_node = try_lifecycle_string(&intent.node.name, nodes.len(), limits)?;
            let manifest_node = try_lifecycle_string(&intent.node.name, nodes.len(), limits)?;
            let manifest_executable =
                try_lifecycle_path(&current_process.executable, nodes.len(), limits)?;
            let journal_executable =
                try_lifecycle_path(&current_process.executable, nodes.len(), limits)?;
            process_owners.push(Some(PreparedLifecycleProcessOwner {
                action: intent.action,
                decision_node: Some(NodeId {
                    name: try_lifecycle_string(&intent.node.name, nodes.len(), limits)?,
                }),
                manifest_node,
                manifest_identity: QemuProcessIdentity {
                    process_id: 0,
                    start_time_ticks: 0,
                    executable: manifest_executable,
                },
                journal_identity: QemuProcessIdentity {
                    process_id: 0,
                    start_time_ticks: 0,
                    executable: journal_executable,
                },
            }));
            nodes.push(ProductionLifecycleJournalNode {
                node: journal_node,
                current_process,
                replacement_process: None,
                current_generation,
                next_generation,
                transition: try_lifecycle_transition(
                    intent.requested_transition,
                    nodes.len(),
                    limits,
                )?,
                action_sha256: try_lifecycle_hash(intent.action, nodes.len(), limits)?,
                evidence_sha256: try_lifecycle_hash(
                    intent
                        .event_evidence
                        .unwrap_or(ContentHash { bytes: [0; 32] }),
                    nodes.len(),
                    limits,
                )?,
                expected_exit_code: None,
            });
        }
        let checkpoint = Arc::new(self.terminal_lifecycle_checkpoint()?);
        let mut actions = Vec::new();
        actions
            .try_reserve_exact(intents.len())
            .map_err(|_| lifecycle_resource_error("nodes", 0, intents.len(), limits))?;
        for intent in intents {
            actions.push(intent.action);
        }
        self.lifecycle_journal.transaction = self
            .lifecycle_journal
            .transaction
            .checked_add(1)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("lifecycle transaction sequence exhausted"),
            })?;
        self.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Intent;
        self.lifecycle_journal.nodes = nodes.into();
        let reserved_event_log_bytes = self.reserve_lifecycle_state_encoding(
            limits,
            runtime_event_records,
            runtime_event_log_bytes,
        )?;
        self.persist_lifecycle_state()?;
        let reserved_event_records = u64::try_from(
            self.lifecycle_journal
                .nodes
                .len()
                .checked_add(self.lifecycle_journal.completed_exits.len())
                .ok_or_else(|| lifecycle_resource_error("event_records", usize::MAX, 1, limits))?,
        )
        .map_err(|_| lifecycle_resource_error("event_records", usize::MAX, 1, limits))?;
        Ok(PreparedLifecyclePrecommit {
            checkpoint,
            actions,
            process_owners,
            terminal_decisions,
            reserved_event_records,
            reserved_event_log_bytes: u64::try_from(reserved_event_log_bytes).map_err(|_| {
                lifecycle_resource_error("event_log_bytes", 0, reserved_event_log_bytes, limits)
            })?,
        })
    }

    pub(super) fn authenticate_terminal_lifecycle_intent(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
    ) -> Result<(), SchedulerError> {
        for decision in decisions {
            let journal_node = self
                .lifecycle_journal
                .nodes
                .iter_mut()
                .find(|candidate| {
                    candidate.node == decision.node.name
                        && lifecycle_hash_matches(&candidate.action_sha256, decision.action)
                })
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "committed lifecycle decision for `{}` has no precommit journal intent",
                        decision.node.name
                    ),
                })?;
            let transition = lifecycle_transition_text(decision.effective_transition);
            debug_assert!(journal_node.transition.capacity() >= transition.len());
            journal_node.transition.clear();
            journal_node.transition.push_str(transition);
            journal_node.next_generation = if matches!(
                decision.effective_transition,
                crucible::model::NodeLifecycleTransition::Crash
                    | crucible::model::NodeLifecycleTransition::PowerOff
                    | crucible::model::NodeLifecycleTransition::Reset
                    | crucible::model::NodeLifecycleTransition::PowerCycle
            ) {
                journal_node
                    .current_generation
                    .checked_add(1)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle generation exhausted for `{}`",
                            decision.node.name
                        ),
                    })?
            } else {
                journal_node.current_generation
            };
            replace_lifecycle_hash(&mut journal_node.evidence_sha256, decision.event_evidence);
            journal_node.expected_exit_code = decision.expected_exit_code;
        }
        for node in boot_requests {
            if !self
                .lifecycle_journal
                .nodes
                .iter()
                .any(|candidate| candidate.node == node.name)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "committed boot request for `{}` has no precommit journal intent",
                        node.name
                    ),
                });
            }
        }
        Ok(())
    }

    pub(super) fn advance_lifecycle_journal(
        &mut self,
        phase: ProductionLifecycleJournalPhase,
    ) -> Result<(), SchedulerError> {
        self.lifecycle_journal.phase = phase;
        self.persist_lifecycle_state()
    }

    pub(super) fn record_prepared_lifecycle_processes(
        &mut self,
        prepared: &mut [PreparedTerminalReplacement],
    ) -> Result<(), SchedulerError> {
        for item in prepared {
            let identity = match (&item.replacement, item.process_owner.as_mut()) {
                (Some(replacement), Some(owner)) => {
                    let (process_id, start_time_ticks) = replacement
                        .node()
                        .process_identity_components(&owner.manifest_identity.executable)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "capture staged process identity for `{}`: {error}",
                                item.decision.node.name
                            ),
                        })?;
                    owner.manifest_identity.process_id = process_id;
                    owner.manifest_identity.start_time_ticks = start_time_ticks;
                    owner.journal_identity.process_id = process_id;
                    owner.journal_identity.start_time_ticks = start_time_ticks;
                    Some(())
                }
                (None, Some(_)) => None,
                (_, None) => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "staged lifecycle node `{}` lost its preallocated process owner",
                            item.decision.node.name
                        ),
                    });
                }
            };
            let journal_node = self
                .lifecycle_journal
                .nodes
                .iter_mut()
                .find(|node| node.node == item.decision.node.name)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "staged lifecycle node `{}` has no journal identity",
                        item.decision.node.name
                    ),
                })?;
            if identity.is_some() {
                let owner =
                    item.process_owner
                        .take()
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "staged lifecycle node `{}` lost its process owner",
                                item.decision.node.name
                            ),
                        })?;
                if self
                    .run_manifest
                    .staged_processes
                    .contains_key(&owner.manifest_node)
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "staged lifecycle node `{}` already owns a manifest process",
                            item.decision.node.name
                        ),
                    });
                }
                self.run_manifest
                    .staged_processes
                    .insert_reserved(owner.manifest_node, owner.manifest_identity)
                    .map_err(|()| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "staged lifecycle process reservation was exhausted after commit",
                        ),
                    })?;
                journal_node.replacement_process = Some(owner.journal_identity);
            } else {
                item.process_owner.take();
                journal_node.replacement_process = None;
            }
        }
        self.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Prepared;
        self.persist_lifecycle_state()
    }

    pub(super) fn retain_completed_lifecycle_exits(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        observed_exit_codes: &[(NodeId, i32)],
    ) -> Result<(), SchedulerError> {
        for decision in decisions {
            let Some(expected_exit_code) = decision.expected_exit_code else {
                continue;
            };
            let journal_index = self
                .lifecycle_journal
                .nodes
                .iter()
                .position(|node| node.node == decision.node.name)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "completed lifecycle exit for `{}` lost its journal identity",
                        decision.node.name
                    ),
                })?;
            let observed_exit_code = observed_exit_codes
                .iter()
                .find_map(|(node, code)| (node == &decision.node).then_some(*code))
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "completed lifecycle exit for `{}` lost its observed status",
                        decision.node.name
                    ),
                })?;
            let journal_node = self.lifecycle_journal.nodes.swap_remove(journal_index);
            self.lifecycle_journal
                .completed_exits
                .push(ProductionLifecycleCompletedExit {
                    transaction: self.lifecycle_journal.transaction,
                    node: journal_node.node,
                    process: journal_node.current_process,
                    generation: journal_node.current_generation,
                    transition: journal_node.transition,
                    action_sha256: journal_node.action_sha256,
                    evidence_sha256: journal_node.evidence_sha256,
                    expected_exit_code,
                    observed_exit_code,
                });
        }
        self.lifecycle_journal.nodes.clear();
        self.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Committed;
        self.persist_lifecycle_state()
    }

    pub(super) fn quarantine_terminal_lifecycle_transaction(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let quarantine = self
            .inner
            .backend_mut()
            .quarantine_terminal_lifecycle_work(decisions, boot_requests);
        let scheduler = self.contain_terminal_lifecycle_scheduler(decisions, boot_requests);
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            if let Some(state) = self.node_service_states.get_mut(node) {
                *state = ProductionNodeServiceState::PermanentlyFailed;
            }
        }
        let journal = self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::Quarantined);
        SchedulerError::BoundaryViolation {
            message: format!(
                "terminal lifecycle transaction failed ({primary}); journal containment: {}; process containment: {}; scheduler containment: {}",
                journal.map_or_else(|error| error.to_string(), |()| String::from("recorded")),
                quarantine.map_or_else(|error| error.to_string(), |()| String::from("reaped")),
                scheduler.map_or_else(|error| error.to_string(), |()| String::from("closed")),
            ),
        }
    }

    pub(super) fn quarantine_terminal_lifecycle_transaction_with_staged(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
        prepared: &mut [PreparedTerminalReplacement],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let staged = Self::abort_staged_terminal_replacements(prepared);
        self.quarantine_terminal_lifecycle_transaction(
            decisions,
            boot_requests,
            format!(
                "{primary}; staged-process containment: {}",
                staged.map_or_else(|error| error.to_string(), |()| String::from("reaped"))
            ),
        )
    }

    pub(super) fn quarantine_precommit_lifecycle_intent(
        &mut self,
        intents: &[QemuNodeLifecycleIntent],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let quarantine = self
            .inner
            .backend_mut()
            .quarantine_terminal_lifecycle_intents(intents);
        let scheduler = (|| {
            for intent in intents {
                self.inner
                    .loop_impl()
                    .validate_vm_node_activity_target(&intent.node)?;
            }
            for intent in intents {
                self.inner
                    .loop_impl_mut()
                    .set_vm_node_activity(&intent.node, SchedulerNodeActivity::Done)?;
            }
            Ok::<(), SchedulerError>(())
        })();
        for intent in intents {
            if let Some(state) = self.node_service_states.get_mut(&intent.node) {
                *state = ProductionNodeServiceState::PermanentlyFailed;
            }
        }
        let journal = self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::Quarantined);
        SchedulerError::BoundaryViolation {
            message: format!(
                "precommit lifecycle transaction failed ({primary}); journal containment: {}; process containment: {}; scheduler containment: {}",
                journal.map_or_else(|error| error.to_string(), |()| String::from("persisted")),
                quarantine.map_or_else(|error| error.to_string(), |()| String::from("reaped")),
                scheduler.map_or_else(|error| error.to_string(), |()| String::from("done")),
            ),
        }
    }

    fn contain_terminal_lifecycle_scheduler(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
    ) -> Result<(), SchedulerError> {
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            self.inner
                .loop_impl()
                .validate_vm_node_activity_target(node)?;
        }
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            self.inner
                .loop_impl_mut()
                .set_vm_node_activity(node, SchedulerNodeActivity::Done)?;
        }
        Ok(())
    }
}
