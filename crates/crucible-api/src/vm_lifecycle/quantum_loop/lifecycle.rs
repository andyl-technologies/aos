//! Durable lifecycle intent ownership and fail-closed containment.

use super::*;

mod persistence;
pub(in crate::vm_lifecycle) use persistence::LifecycleJournalPersistence;

pub(super) struct PreparedTerminalReplacement {
    pub(super) decision: QemuNodeLifecycleDecision,
    pub(super) snapshot: QemuVmSnapshot,
    pub(super) run_directory: PathBuf,
    pub(super) launch: ProductionLiveNodeStepGateConfig,
    pub(super) generation: u64,
    pub(super) replacement: Option<QemuNode>,
    pub(super) service_state: ProductionNodeServiceState,
    pub(super) debug_backend_path: Option<PathBuf>,
    pub(super) crash_detector: String,
}

pub(super) struct PreparedLifecyclePrecommit {
    pub(super) checkpoint: Arc<Checkpoint>,
    pub(super) actions: Vec<ContentHash>,
}

pub(super) fn lifecycle_resource_error(
    field: &'static str,
    current: usize,
    requested: usize,
    limits: FaultResourceLimits,
) -> SchedulerError {
    SchedulerError::ResourceLimit {
        field,
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: limits.configured(field).unwrap_or(0),
        hard: FaultResourceLimits::compiled_maximum()
            .configured(field)
            .unwrap_or(0),
    }
}

fn lifecycle_transition_text(transition: crucible::model::NodeLifecycleTransition) -> &'static str {
    match transition {
        crucible::model::NodeLifecycleTransition::Boot => "Boot",
        crucible::model::NodeLifecycleTransition::Crash => "Crash",
        crucible::model::NodeLifecycleTransition::Reset => "Reset",
        crucible::model::NodeLifecycleTransition::PowerOff => "PowerOff",
        crucible::model::NodeLifecycleTransition::PowerCycle => "PowerCycle",
        crucible::model::NodeLifecycleTransition::PermanentFailure => "PermanentFailure",
    }
}

pub(super) fn try_lifecycle_string(
    value: &str,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| lifecycle_resource_error("nodes", current, 1, limits))?;
    owned.push_str(value);
    Ok(owned)
}

fn try_lifecycle_hash(
    value: ContentHash,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(64)
        .map_err(|_| lifecycle_resource_error("event_log_bytes", current, 64, limits))?;
    for byte in value.bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

fn try_lifecycle_transition(
    transition: crucible::model::NodeLifecycleTransition,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    let mut storage = try_lifecycle_string("PermanentFailure", current, limits)?;
    storage.clear();
    storage.push_str(lifecycle_transition_text(transition));
    Ok(storage)
}

fn replace_lifecycle_hash(storage: &mut String, value: ContentHash) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_assert!(storage.capacity() >= 64);
    storage.clear();
    for byte in value.bytes {
        storage.push(HEX[(byte >> 4) as usize] as char);
        storage.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn lifecycle_hash_matches(storage: &str, value: ContentHash) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    storage.len() == 64
        && storage
            .as_bytes()
            .chunks_exact(2)
            .zip(value.bytes)
            .all(|(encoded, byte)| {
                encoded[0] == HEX[(byte >> 4) as usize] && encoded[1] == HEX[(byte & 0x0f) as usize]
            })
}

pub(super) fn try_lifecycle_crash_detector(
    node: &str,
    generation: u64,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    let mut digits = [0_u8; 20];
    let mut cursor = digits.len();
    let mut remaining = generation;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let required = 10_usize
        .checked_add(node.len())
        .and_then(|length| length.checked_add(12))
        .and_then(|length| length.checked_add(digits.len() - cursor))
        .ok_or_else(|| lifecycle_resource_error("event_log_bytes", current, usize::MAX, limits))?;
    let mut detector = String::new();
    detector
        .try_reserve_exact(required)
        .map_err(|_| lifecycle_resource_error("event_log_bytes", current, required, limits))?;
    detector.push_str("lifecycle-");
    detector.push_str(node);
    detector.push_str("-generation-");
    for digit in &digits[cursor..] {
        detector.push(*digit as char);
    }
    Ok(detector)
}

impl ProductionVmLifecycleLoop {
    pub(super) fn begin_terminal_lifecycle_intent(
        &mut self,
        intents: &[QemuNodeLifecycleIntent],
        limits: FaultResourceLimits,
    ) -> Result<PreparedLifecyclePrecommit, SchedulerError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(intents.len())
            .map_err(|_| lifecycle_resource_error("nodes", 0, intents.len(), limits))?;
        let completed_exit_count = self.lifecycle_journal.completed_exits.len();
        limits
            .reserve(
                "event_records",
                u64::try_from(completed_exit_count).map_err(|_| {
                    lifecycle_resource_error("event_records", usize::MAX, 0, limits)
                })?,
                u64::try_from(intents.len()).map_err(|_| {
                    lifecycle_resource_error("event_records", 0, usize::MAX, limits)
                })?,
            )
            .map_err(|_| {
                lifecycle_resource_error(
                    "event_records",
                    completed_exit_count,
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
            let next_generation = if matches!(
                intent.requested_transition,
                crucible::model::NodeLifecycleTransition::Crash
                    | crucible::model::NodeLifecycleTransition::PowerOff
                    | crucible::model::NodeLifecycleTransition::Reset
                    | crucible::model::NodeLifecycleTransition::PowerCycle
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
            nodes.push(ProductionLifecycleJournalNode {
                node: try_lifecycle_string(&intent.node.name, nodes.len(), limits)?,
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
                    ContentHash { bytes: [0; 32] },
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
        self.lifecycle_journal.nodes = nodes;
        self.reserve_lifecycle_journal_encoding(limits)?;
        self.persist_lifecycle_journal()?;
        Ok(PreparedLifecyclePrecommit {
            checkpoint,
            actions,
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
        self.persist_lifecycle_journal()
    }

    pub(super) fn record_prepared_lifecycle_processes(
        &mut self,
        prepared: &[PreparedTerminalReplacement],
    ) -> Result<(), SchedulerError> {
        for item in prepared {
            let identity = item
                .replacement
                .as_ref()
                .map(QemuNode::process_identity)
                .transpose()
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "capture staged process identity for `{}`: {error}",
                        item.decision.node.name
                    ),
                })?;
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
            journal_node.replacement_process = identity;
        }
        self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::Prepared)
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
        self.persist_lifecycle_journal()
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
