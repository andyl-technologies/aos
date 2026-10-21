//! Physical QEMU boundaries used by guarded exact-checkpoint replay.
//!
//! Semantic decisions do not reveal the instruction count of a guest choice.
//! The thin node must reach an actual paused request before a recorded
//! selection can be bound to it and delivered as a reply.

use super::*;

impl QemuReplayValidationExecutor {
    /// Reports whether the replay guest consumed every selected reply.
    ///
    /// # Errors
    ///
    /// Returns an error when no replay node is active.
    pub fn replay_selectable_reply_is_quiescent(&self) -> Result<bool, QemuVmRealizationError> {
        self.active_node
            .as_ref()
            .map(QemuNode::selectable_reply_is_checkpoint_quiescent)
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "inspect guarded replay selectable reply",
                message: String::from("no QEMU replay node is active"),
            })
    }

    /// Returns the authenticated thin node instruction count for a physical replay step.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation is stale or lacks the modeled node.
    pub fn materialized_replay_icount(
        &self,
        thin: &QemuReplayOracleThinObservation,
    ) -> Result<Icount, QemuVmRealizationError> {
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay observation",
        )?;
        self.validate_active_replay_runtime(&thin.runtime)?;
        replay_node_icount(&thin.runtime, &self.node)
    }

    /// Drains guest choice requests at the current guarded replay boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when no replay node is active or its request transport
    /// cannot be authenticated.
    pub fn drain_replay_selectable_requests(
        &mut self,
    ) -> Result<
        Vec<crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        QemuVmRealizationError,
    > {
        self.measure_replay(ReplayPhase::ChoiceDrain, |executor| {
            executor.drain_replay_selectable_requests_untimed()
        })
    }

    fn drain_replay_selectable_requests_untimed(
        &mut self,
    ) -> Result<
        Vec<crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        QemuVmRealizationError,
    > {
        self.active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "drain guarded replay selectable requests",
                message: String::from("no QEMU replay node is active"),
            })?
            .drain_pending_selectable_requests()
            .map_err(|error| QemuVmRealizationError::Executor {
                operation: "drain guarded replay selectable requests",
                message: error.to_string(),
            })
    }

    /// Delivers a validated recorded choice to the paused replay guest.
    ///
    /// # Errors
    ///
    /// Returns an error when no replay node is active or the physical pending
    /// request does not accept the exact recorded reply.
    pub fn enqueue_replay_selectable_reply(
        &mut self,
        pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuVmRealizationError> {
        self.measure_replay(ReplayPhase::ChoiceReply, |executor| {
            executor.enqueue_replay_selectable_reply_untimed(pending, reply)
        })
    }

    fn enqueue_replay_selectable_reply_untimed(
        &mut self,
        pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuVmRealizationError> {
        self.active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "enqueue guarded replay selectable reply",
                message: String::from("no QEMU replay node is active"),
            })?
            .enqueue_selectable_reply(pending, reply)
            .map_err(|error| QemuVmRealizationError::Executor {
                operation: "enqueue guarded replay selectable reply",
                message: error.to_string(),
            })
    }

    /// Queues one root-authenticated backend input at its recorded physical time.
    ///
    /// The input ring retains a future delivery count while the guest is idle;
    /// enqueuing it does not advance the guest or the replay event log.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation is stale, the input belongs to
    /// another node or a past boundary, or the QEMU transport rejects it.
    pub fn enqueue_materialized_replay_input(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        self.measure_replay(ReplayPhase::Input, |executor| {
            executor.enqueue_materialized_replay_input_untimed(thin, input, delivery_icount)
        })
    }

    fn enqueue_materialized_replay_input_untimed(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay observation",
        )?;
        self.validate_active_replay_runtime(&thin.runtime)?;
        let current = replay_node_icount(&thin.runtime, &self.node)?;
        if input.node != self.node || delivery_icount < current {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded replay backend input",
                message: String::from("input node or delivery count differs from the live replay"),
            });
        }

        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "enqueue guarded replay backend input",
                message: String::from("no QEMU replay node is active"),
            })?;
        SimulationBackend::apply(
            node,
            &BackendEffect::DeliverInput(input),
            VirtualTime {
                ticks: delivery_icount.retired,
            },
        )
        .map_err(|source| node_backend_error("enqueue guarded replay backend input", source))?;

        let generation = self.issue_observation_generation()?;
        self.thin_observation_generation = Some(generation);
        Ok(QemuReplayOracleThinObservation {
            runtime: thin.runtime,
            authority: Arc::clone(&self.authority),
            generation,
        })
    }

    /// Arms one recorded preemption on the thin replay node.
    ///
    /// `decision.at` is the node-local physical counter the scheduler
    /// commanded. The command authorizes the window from the thin node's
    /// current counter through `decision.at`. Patched QEMU then applies it
    /// where the live RUN did: exactly at `decision.at` for a halted guest, and
    /// at a running guest's first boundary at or after it.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation is stale, the preemption belongs
    /// to another node, its counter is not ahead of the thin node, or the
    /// shared-memory mailbox refuses the command.
    pub fn arm_materialized_replay_preemption(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        decision: &crucible::PreemptionDecision,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        self.measure_replay(ReplayPhase::ModelDecision, |executor| {
            executor.arm_materialized_replay_preemption_untimed(thin, decision)
        })
    }

    fn arm_materialized_replay_preemption_untimed(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        decision: &crucible::PreemptionDecision,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay observation",
        )?;
        self.validate_active_replay_runtime(&thin.runtime)?;
        let current = replay_node_icount(&thin.runtime, &self.node)?;
        if decision.node != self.node {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded replay preemption",
                message: String::from("preemption belongs to another node"),
            });
        }
        if decision.at.ticks <= current.retired {
            return Err(QemuVmRealizationError::ReplayOracleUnsupported {
                node: self.node.name.clone(),
                effect: crate::QemuReplayOracleUnsupportedEffect::PreemptionNotAhead {
                    at: decision.at.ticks,
                    current: current.retired,
                },
            });
        }

        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "arm guarded replay preemption",
                message: String::from("no QEMU replay node is active"),
            })?;
        node.publish_scheduler_preemption(
            decision,
            Icount {
                retired: decision.at.ticks,
            },
        )
        .map_err(|source| node_backend_error("arm guarded replay preemption", source))?;

        let generation = self.issue_observation_generation()?;
        self.thin_observation_generation = Some(generation);
        Ok(QemuReplayOracleThinObservation {
            runtime: thin.runtime,
            authority: Arc::clone(&self.authority),
            generation,
        })
    }

    /// Confirms that QEMU took an armed preemption at its recorded counter.
    ///
    /// The thin node must stand at `decision.at`, or less than one retirement
    /// past it, which is where a running guest meets the command at its first
    /// boundary at or after it. The plugin must also have handed the command
    /// to patched QEMU, which acknowledges only an accepted injection.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation is stale, the thin node stands
    /// elsewhere, or the command is still waiting in the mailbox.
    pub fn confirm_materialized_replay_preemption(
        &mut self,
        thin: &QemuReplayOracleThinObservation,
        decision: &crucible::PreemptionDecision,
    ) -> Result<(), QemuVmRealizationError> {
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay observation",
        )?;
        self.validate_active_replay_runtime(&thin.runtime)?;
        let current = replay_node_icount(&thin.runtime, &self.node)?;
        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "confirm guarded replay preemption",
                message: String::from("no QEMU replay node is active"),
            })?;
        let pending = node
            .scheduler_preemption_pending()
            .map_err(|source| node_backend_error("confirm guarded replay preemption", source))?;
        if !preemption_taken_at(current, decision) || pending {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded replay preemption",
                message: format!(
                    "thin replay stands at {} with the command {} instead of at {} with it applied",
                    current.retired,
                    if pending { "pending" } else { "taken" },
                    decision.at.ticks
                ),
            });
        }
        Ok(())
    }

    /// Advances thin replay toward a checkpoint ceiling without changing its schedule.
    ///
    /// The caller bounds `ceiling` by the exact checkpoint and charges the
    /// aggregate guard for each physical step. A paused result can then be
    /// inspected for an authenticated guest-selectable request. The returned
    /// idle deadline is the completed plugin boundary's own observation; it
    /// lets the caller advance only its scheduler ceiling across an idle park.
    ///
    /// # Errors
    ///
    /// Returns an error when the thin observation is stale, the ceiling does
    /// not advance its node, or the backend cannot complete the bounded step.
    pub fn advance_materialized_replay_to_ceiling(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        ceiling: Icount,
    ) -> Result<
        (
            QemuReplayOracleThinObservation,
            AdvanceOutcome,
            Option<Icount>,
        ),
        QemuVmRealizationError,
    > {
        self.measure_replay(ReplayPhase::Advance, |executor| {
            executor.advance_materialized_replay_to_ceiling_untimed(thin, ceiling)
        })
    }

    fn advance_materialized_replay_to_ceiling_untimed(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        ceiling: Icount,
    ) -> Result<
        (
            QemuReplayOracleThinObservation,
            AdvanceOutcome,
            Option<Icount>,
        ),
        QemuVmRealizationError,
    > {
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay observation",
        )?;
        let mut runtime = thin.runtime;
        self.validate_active_replay_runtime(&runtime)?;

        let current = replay_node_icount(&runtime, &self.node)?;
        self.performance.observe_physical(current.retired);
        if ceiling.retired <= current.retired {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "thin replay physical boundary",
                message: String::from("physical ceiling must exceed the recorded node count"),
            });
        }

        let node = self
            .active_node
            .as_mut()
            .ok_or_else(|| QemuVmRealizationError::Executor {
                operation: "advance guarded replay to physical boundary",
                message: String::from("no QEMU replay node is active"),
            })?;
        let outcome = QemuRealizedNodeBackend::advance_live_to_horizon(
            node,
            crucible::ExecutionHorizon { icount: ceiling },
            &mut self.event_log,
        )
        .map_err(|source| {
            node_backend_error("advance guarded replay to physical boundary", source)
        })?;
        let current_icount = QemuRealizedNodeBackend::current_icount(node).map_err(|source| {
            node_backend_error("sample guarded replay instruction count", source)
        })?;
        let idle_deadline = node.last_step_final_state().and_then(|state| {
            (state.current_icount == current_icount)
                .then_some(state.next_deadline)
                .flatten()
        });
        validate_replay_advance(current_icount, ceiling, &outcome)?;

        // The opaque observation keeps its last sampled identity while the
        // physical count, event-log offset, and generation bind this step.
        // The oracle takes a fresh full fingerprint at the final comparison.
        runtime
            .node_icounts
            .insert(self.node.clone(), current_icount);
        self.performance.observe_physical(current_icount.retired);
        runtime.event_log = self.event_log.offset();
        let generation = self.issue_observation_generation()?;
        self.thin_observation_generation = Some(generation);
        Ok((
            QemuReplayOracleThinObservation {
                runtime,
                authority: Arc::clone(&self.authority),
                generation,
            },
            outcome,
            idle_deadline,
        ))
    }

    /// Applies an authenticated replay decision at an already reached physical boundary.
    ///
    /// This updates only the modeled configuration. Guest-selectable reply
    /// delivery remains a separate operation at the exact paused QEMU request.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation or transition is stale or invalid.
    pub fn apply_materialized_replay_decision(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        request: QemuVmReplayRequest,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        self.measure_replay(ReplayPhase::ModelDecision, |executor| {
            executor.apply_materialized_replay_decision_untimed(thin, request)
        })
    }

    fn apply_materialized_replay_decision_untimed(
        &mut self,
        thin: QemuReplayOracleThinObservation,
        request: QemuVmReplayRequest,
    ) -> Result<QemuReplayOracleThinObservation, QemuVmRealizationError> {
        self.validate_observation(
            &thin.authority,
            thin.generation,
            self.thin_observation_generation,
            "thin replay observation",
        )?;
        let mut runtime = thin.runtime;
        validate_replay_transition(
            self.active_configuration.as_ref(),
            self.active_runtime_id,
            &runtime,
            &request,
        )?;
        if runtime.event_log != self.event_log.offset() {
            return Err(QemuVmRealizationError::Executor {
                operation: "apply guarded replay decision",
                message: String::from("runtime event-log offset differs from the live replay"),
            });
        }

        runtime.scheduler.apply_decision(request.decision());
        runtime.configuration = request.to().id();
        self.active_configuration = Some(request.to().clone());
        let generation = self.issue_observation_generation()?;
        self.thin_observation_generation = Some(generation);
        Ok(QemuReplayOracleThinObservation {
            runtime,
            authority: Arc::clone(&self.authority),
            generation,
        })
    }

    fn validate_active_replay_runtime(
        &self,
        runtime: &RuntimeState,
    ) -> Result<(), QemuVmRealizationError> {
        if self.active_configuration.as_ref().map(Configuration::id) != Some(runtime.configuration)
            || self.active_runtime_id != Some(runtime.id)
            || runtime.event_log != self.event_log.offset()
        {
            return Err(QemuVmRealizationError::Executor {
                operation: "advance guarded replay to physical boundary",
                message: String::from("thin observation differs from the installed live runtime"),
            });
        }
        Ok(())
    }
}

/// Checks one bounded replay step against the live node count.
///
/// A reached horizon attests settlement through the ceiling (RFC-0010
/// SCHED-12). The live count is the last retirement at or below the ceiling,
/// so it may stop short of it; only crossing the ceiling is refused.
fn validate_replay_advance(
    current_icount: Icount,
    ceiling: Icount,
    outcome: &AdvanceOutcome,
) -> Result<(), QemuVmRealizationError> {
    let refusal = |message: &str| QemuVmRealizationError::Executor {
        operation: "advance guarded replay to physical boundary",
        message: String::from(message),
    };

    if current_icount.retired > ceiling.retired {
        return Err(refusal("QEMU exceeded the authenticated replay ceiling"));
    }
    match outcome {
        AdvanceOutcome::Paused { at } if *at != current_icount => {
            Err(refusal("QEMU pause count differs from the live node count"))
        }
        _ => Ok(()),
    }
}

fn replay_node_icount(
    runtime: &RuntimeState,
    node: &NodeId,
) -> Result<Icount, QemuVmRealizationError> {
    runtime.node_icounts.get(node).copied().ok_or_else(|| {
        QemuVmRealizationError::InvalidCheckpoint {
            role: "thin replay physical boundary",
            message: String::from("restored runtime has no instruction count for replay node"),
        }
    })
}

/// Returns whether a node standing at `current` can have taken `decision`.
///
/// A halted guest takes a preemption exactly at `decision.at`. A running guest
/// never moves its clock without a retirement, so it takes it at its first
/// boundary at or after `decision.at`, less than one retirement later
/// (RFC-0010 SCHED-12, TIME-30).
fn preemption_taken_at(current: Icount, decision: &crucible::PreemptionDecision) -> bool {
    current.retired >= decision.at.ticks
        && current.retired - decision.at.ticks < crucible::SIM_TICKS_PER_INSTRUCTION
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crucible::{Configuration, EventLogOffset, ScenarioDef, Schedule, SchedulerState};

    use super::*;

    #[test]
    fn a_preemption_is_taken_at_its_counter_or_the_first_boundary_after_it() {
        let decision = crucible::PreemptionDecision {
            node: NodeId {
                name: String::from("node"),
            },
            at: crucible::SimInstant { ticks: 1_024 },
            kind: crucible::PreemptionKind::InterruptAt {
                target_vcpu: crucible::VcpuId { index: 0 },
                irq: crucible::IrqVector { vector: 32 },
            },
        };

        for (current, taken) in [
            (1_000, false),
            (1_023, false),
            (1_024, true),
            (1_050, true),
            (1_073, true),
            (1_074, false),
        ] {
            assert_eq!(
                preemption_taken_at(Icount { retired: current }, &decision),
                taken,
                "current={current}"
            );
        }
    }

    #[test]
    fn physical_replay_reads_only_the_owned_node_clock() -> Result<(), QemuVmRealizationError> {
        let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.qemu.replay-physical",
            "multi-node-clock",
        ));
        let local = NodeId {
            name: String::from("local"),
        };
        let remote = NodeId {
            name: String::from("remote"),
        };
        let runtime = RuntimeState {
            id: ContentHash::from_bytes(b"multi-node physical replay"),
            configuration: configuration.id(),
            node_blobs: BTreeMap::new(),
            node_icounts: BTreeMap::from([
                (local.clone(), Icount { retired: 41 }),
                (remote.clone(), Icount { retired: 900 }),
            ]),
            scheduler: SchedulerState::from_schedule(&Schedule::empty()),
            event_log: EventLogOffset::default(),
        };

        assert_eq!(replay_node_icount(&runtime, &local)?.retired, 41);
        assert_eq!(replay_node_icount(&runtime, &remote)?.retired, 900);
        assert!(
            replay_node_icount(
                &runtime,
                &NodeId {
                    name: String::from("missing"),
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn settled_replay_step_may_stop_below_its_ceiling() {
        let ceiling = Icount { retired: 1_000 };
        let below = Icount { retired: 951 };

        assert!(validate_replay_advance(below, ceiling, &AdvanceOutcome::ReachedHorizon).is_ok());
        assert!(validate_replay_advance(ceiling, ceiling, &AdvanceOutcome::ReachedHorizon).is_ok());
        assert!(
            validate_replay_advance(
                Icount { retired: 1_001 },
                ceiling,
                &AdvanceOutcome::ReachedHorizon,
            )
            .is_err(),
            "a settled step must never cross its ceiling"
        );
        assert!(
            validate_replay_advance(below, ceiling, &AdvanceOutcome::Paused { at: below }).is_ok()
        );
        assert!(
            validate_replay_advance(
                below,
                ceiling,
                &AdvanceOutcome::Paused {
                    at: Icount { retired: 900 },
                },
            )
            .is_err(),
            "a pause must report the live count"
        );
    }
}
