//! Engine-state transition, stepping, checkpoint, and replay unit tests.

use super::*;

#[path = "engine_state/guest_introspection.rs"]
mod guest_introspection;

#[test]
fn step_modes_cover_forward_vocabulary_and_reverse_grains() {
    assert_eq!(
        StepMode::ALL,
        [
            StepMode::Quantum,
            StepMode::Event,
            StepMode::Assertion,
            StepMode::Timer,
            StepMode::Duration(StepMode::DEFAULT_DURATION),
        ]
    );
    assert_eq!(
        StepMode::ALL
            .into_iter()
            .filter_map(StepMode::reverse_grain)
            .collect::<Vec<_>>(),
        vec![
            DebugReverseStepGrain::Quantum,
            DebugReverseStepGrain::Event,
            DebugReverseStepGrain::Assertion,
            DebugReverseStepGrain::Timer,
        ]
    );
    assert_eq!(
        StepMode::Duration(SimDuration { nanos: 10 }).reverse_grain(),
        None,
        "duration is a forward-only step bound until the debug model has a duration grain"
    );
}

#[test]
fn step_modes_are_expressible_as_one_shot_breakpoints() {
    let start = VirtualTime { ticks: 10 };
    for mode in StepMode::ALL {
        let step = ActiveStep::new(mode, start);
        assert_eq!(step.breakpoint.disposition, BreakpointDisposition::Suspend);
        assert_eq!(step.breakpoint.policy, BreakpointPolicy::OneShot);
        match (mode, &step.breakpoint.predicate) {
            (
                StepMode::Duration(duration),
                Condition::At {
                    at: VirtualTime { ticks },
                },
            ) => {
                assert_eq!(*ticks, start.ticks.saturating_add(duration.nanos));
            }
            (StepMode::Quantum, Condition::Named { name, nodes }) => {
                assert_eq!(name, "session.step.quantum");
                assert!(nodes.is_empty());
            }
            (StepMode::Event, Condition::Named { name, nodes }) => {
                assert_eq!(name, "session.step.event");
                assert!(nodes.is_empty());
            }
            (StepMode::Assertion, Condition::Named { name, nodes }) => {
                assert_eq!(name, "session.step.assertion");
                assert!(nodes.is_empty());
            }
            (StepMode::Timer, Condition::Named { name, nodes }) => {
                assert_eq!(name, "session.step.timer");
                assert!(nodes.is_empty());
            }
            other => panic!("unexpected step stop condition: {other:?}"),
        }
    }
}

#[test]
fn engine_step_modes_start_bounded_execution_for_forward_vocabulary() {
    let scenario = generated_scenario(22);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    for mode in StepMode::ALL {
        let mut engine = Engine::new(config.clone(), graph.clone(), StubLoop);
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        let snapshot = match engine.apply_command(SessionCommand::Step { mode }) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("{mode:?} step should be accepted: {error}"),
        };
        assert_eq!(snapshot.state, EngineState::Running);
        assert_eq!(engine.quanta(), 0);
        assert_eq!(
            engine.active_step.as_ref().map(|step| step.mode),
            Some(mode)
        );
    }
}

#[test]
fn engine_step_modes_complete_from_quantum_outcomes() {
    let cases = vec![
        (
            22,
            StepMode::Event,
            ScriptedStepLoop::with_payload(2, resolved_backend_input_payload(2)),
        ),
        (
            23,
            StepMode::Assertion,
            ScriptedStepLoop::with_payload(2, assertion_state_change_payload()),
        ),
        (
            24,
            StepMode::Timer,
            ScriptedStepLoop::with_payload(2, timer_fire_payload(2)),
        ),
        (
            25,
            StepMode::Duration(SimDuration { nanos: 2 }),
            ScriptedStepLoop::default(),
        ),
    ];

    for (seed, mode, quantum_loop) in cases {
        assert_engine_step_completes_after_second_quantum(seed, mode, quantum_loop);
    }
}

#[test]
fn duration_step_uses_global_frontier_instead_of_event_timestamp() {
    let scenario = generated_scenario(225);
    let configuration = Configuration::genesis(scenario);
    let target = VirtualTime { ticks: 8 };
    let event = crucible::test_support::condition_boundary_entry_for_test(
        0,
        target,
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    );
    let outcome = QuantumOutcome {
        configuration,
        frontier: VirtualTime { ticks: 4 },
        advanced_node: None,
        resolved_events: Vec::new(),
        decisions: Vec::new(),
        event_log_entries: vec![event],
        event_log_segment_bytes: Vec::new(),
        event_log_segment_text: String::new(),
        event_log_segment_hash: None,
        event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
        scheduler_quiescence: None,
    };
    let step = ActiveStep::new(
        StepMode::Duration(SimDuration { nanos: 8 }),
        VirtualTime::default(),
    );

    assert_eq!(step.target_frontier, Some(target));
    assert!(
        !step
            .is_complete(&outcome, 0)
            .unwrap_or_else(|error| panic!("duration completion should evaluate: {error}"))
    );
}

#[test]
fn timer_step_ignores_timer_actions_without_timer_predicate_fire() {
    let scenario = generated_scenario(26);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_payload(2, timer_action_payload(2)),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime before timer action test: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Step {
        mode: StepMode::Timer,
    }) {
        panic!("timer step should start bounded execution: {error}");
    }

    for iteration in 0..2 {
        if let Err(error) = engine.step_quantum() {
            panic!("timer action test quantum {iteration} should run: {error}");
        }
    }

    assert_eq!(engine.quanta(), 2);
    assert_eq!(engine.state(), &EngineState::Running);
    assert_eq!(
        engine.active_step.as_ref().map(|step| step.mode),
        Some(StepMode::Timer)
    );
}

#[test]
fn lifecycle_state_reason_outcome_and_command_sets_are_closed() {
    assert_eq!(
        LifecycleStateKind::ALL,
        [
            LifecycleStateKind::Loaded,
            LifecycleStateKind::Running,
            LifecycleStateKind::Paused,
            LifecycleStateKind::Stopped,
        ]
    );
    assert_eq!(
        PauseReasonKind::ALL,
        [
            PauseReasonKind::Instantiated,
            PauseReasonKind::UserRequested,
            PauseReasonKind::Breakpoint,
            PauseReasonKind::StepComplete,
        ]
    );
    assert_eq!(
        OutcomeKind::ALL,
        [
            OutcomeKind::Passed,
            OutcomeKind::Failed,
            OutcomeKind::Timeout,
            OutcomeKind::Crashed,
            OutcomeKind::Stopped,
        ]
    );
    assert_eq!(
        SessionCommandKind::ALL,
        [
            SessionCommandKind::Start,
            SessionCommandKind::Continue,
            SessionCommandKind::Pause,
            SessionCommandKind::StepQuantum,
            SessionCommandKind::StepEvent,
            SessionCommandKind::StepAssertion,
            SessionCommandKind::StepTimer,
            SessionCommandKind::StepDuration,
            SessionCommandKind::Stop,
            SessionCommandKind::ExhaustBudget,
            SessionCommandKind::SetBreakpoint,
            SessionCommandKind::RemoveBreakpoint,
            SessionCommandKind::CreateSavepoint,
            SessionCommandKind::Fork,
            SessionCommandKind::Query,
            SessionCommandKind::Snapshot,
            SessionCommandKind::AttachGdb,
            SessionCommandKind::DebugGoto,
            SessionCommandKind::DebugReverseStep,
            SessionCommandKind::DebugReverseContinue,
            SessionCommandKind::DebugForkNonCanonical,
            SessionCommandKind::GuestIntrospection,
        ]
    );
    assert_eq!(
        PauseReasonKind::from(&PauseReason::Breakpoint { id: 7 }),
        PauseReasonKind::Breakpoint
    );
    assert_eq!(
        PauseReasonKind::from(&PauseReason::StepComplete {
            mode: StepMode::Quantum,
        }),
        PauseReasonKind::StepComplete
    );
    assert_eq!(
        OutcomeKind::from(&Outcome::Failed {
            violations: vec![String::from("v")]
        }),
        OutcomeKind::Failed
    );
    assert_eq!(
        OutcomeKind::from(&Outcome::Crashed {
            detail: String::from("crash")
        }),
        OutcomeKind::Crashed
    );
}

#[test]
fn lifecycle_transition_model_is_total_for_representative_commands() {
    for state in LifecycleStateKind::ALL {
        for command in SessionCommandKind::ALL {
            match lifecycle_transition(state, command) {
                LifecycleTransition::Accepted { to } => {
                    assert!(LifecycleStateKind::ALL.contains(&to));
                }
                LifecycleTransition::Rejected => {}
            }
        }
    }
}

#[test]
fn lifecycle_transition_model_matches_rfc_section_table_cells() {
    assert_eq!(
        lifecycle_transition(LifecycleStateKind::Loaded, SessionCommandKind::Start),
        LifecycleTransition::Accepted {
            to: LifecycleStateKind::Paused,
        }
    );
    assert_eq!(
        lifecycle_transition(LifecycleStateKind::Running, SessionCommandKind::StepQuantum),
        LifecycleTransition::Accepted {
            to: LifecycleStateKind::Running,
        }
    );
    assert_eq!(
        lifecycle_transition(LifecycleStateKind::Running, SessionCommandKind::Fork),
        LifecycleTransition::Accepted {
            to: LifecycleStateKind::Paused,
        }
    );
    assert_eq!(
        lifecycle_transition(
            LifecycleStateKind::Running,
            SessionCommandKind::CreateSavepoint
        ),
        LifecycleTransition::Accepted {
            to: LifecycleStateKind::Running,
        }
    );
    assert_eq!(
        lifecycle_transition(
            LifecycleStateKind::Paused,
            SessionCommandKind::SetBreakpoint
        ),
        LifecycleTransition::Accepted {
            to: LifecycleStateKind::Paused,
        }
    );
    assert_eq!(
        lifecycle_transition(
            LifecycleStateKind::Stopped,
            SessionCommandKind::RemoveBreakpoint
        ),
        LifecycleTransition::Rejected
    );
    assert_eq!(
        lifecycle_transition(
            LifecycleStateKind::Loaded,
            SessionCommandKind::CreateSavepoint
        ),
        LifecycleTransition::Rejected
    );
}

#[test]
fn lifecycle_transition_model_command_sequences_never_wedge() {
    let mut frontier = LifecycleStateKind::ALL.to_vec();
    for _ in 0..5 {
        let mut next_frontier = Vec::new();
        for state in frontier {
            for command in SessionCommandKind::ALL {
                let next = match lifecycle_transition(state, command) {
                    LifecycleTransition::Accepted { to } => to,
                    LifecycleTransition::Rejected => state,
                };
                assert!(LifecycleStateKind::ALL.contains(&next));
                next_frontier.push(next);
            }
        }
        frontier = next_frontier;
    }
}

#[test]
fn scheduler_liveness_generated_command_streams_exercise_lifecycle_table() {
    let mut state = LifecycleStateKind::Loaded;
    for seed in 0..64_u64 {
        for step in 0..128_u64 {
            let index = deterministic_command_index(seed, step);
            let command = SessionCommandKind::ALL[index];
            let next = match lifecycle_transition(state, command) {
                LifecycleTransition::Accepted { to } => to,
                LifecycleTransition::Rejected => state,
            };
            assert!(LifecycleStateKind::ALL.contains(&next));
            state = next;
        }
        state = LifecycleStateKind::ALL[seed as usize % LifecycleStateKind::ALL.len()];
    }
}

#[test]
fn engine_transition_table_matches_lifecycle_model_for_current_commands() {
    for state in LifecycleStateKind::ALL {
        for command_kind in SessionCommandKind::ALL {
            let Some(command) = command_kind.representative_command() else {
                continue;
            };
            let mut engine = engine_with_lifecycle_state(state);
            let model = lifecycle_transition(state, command_kind);
            if command_kind == SessionCommandKind::RemoveBreakpoint
                && matches!(model, LifecycleTransition::Accepted { .. })
            {
                engine
                    .apply_command(SessionCommand::SetBreakpoint {
                        spec: BreakpointSpec::suspend_once(Condition::Quiescent),
                        reply: CommandReply::discard(),
                    })
                    .unwrap_or_else(|error| {
                        panic!("remove-breakpoint fixture should register breakpoint: {error}")
                    });
            }
            let before = engine.snapshot();
            let result = engine.apply_command(command.clone());

            match model {
                LifecycleTransition::Accepted { to } => {
                    let snapshot = match result {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            panic!("{state:?} + {command_kind:?} should be accepted: {error}");
                        }
                    };
                    assert_eq!(LifecycleStateKind::from(&snapshot.state), to);
                    assert_eq!(LifecycleStateKind::from(engine.state()), to);
                }
                LifecycleTransition::Rejected => {
                    let error = match result {
                        Ok(snapshot) => {
                            panic!(
                                "{state:?} + {command_kind:?} should reject, got {:?}",
                                snapshot.state
                            );
                        }
                        Err(error) => error,
                    };
                    assert_eq!(engine.snapshot(), before);
                    assert_rejection_names_state_and_command(error, before.state, command);
                }
            }
        }
    }
}

#[tokio::test]
async fn rfc_command_payloads_return_replies_through_engine_boundary() {
    let scenario = generated_scenario(26);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime before command replies: {error}");
    }

    let (state_reply, state_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::Query {
        kind: QueryKind::State,
        reply: state_reply,
    }) {
        panic!("state query should complete at a paused boundary: {error}");
    }
    assert_eq!(
        receive_reply(state_receiver).await,
        QueryResult::State(LifecycleStateKind::Paused)
    );

    let breakpoint = BreakpointSpec::suspend_once(Condition::Quiescent);
    let (breakpoint_reply, breakpoint_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint.clone(),
        reply: breakpoint_reply,
    }) {
        panic!("set breakpoint should return an actor-owned id: {error}");
    }
    let breakpoint_id = receive_reply(breakpoint_receiver).await;
    assert_eq!(engine.breakpoints().get(breakpoint_id), Some(&breakpoint));

    let (remove_reply, remove_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::RemoveBreakpoint {
        id: breakpoint_id,
        reply: remove_reply,
    }) {
        panic!("remove breakpoint should return removal status: {error}");
    }
    assert!(receive_reply(remove_receiver).await);
    assert!(engine.breakpoints().is_empty());

    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter the running command boundary: {error}");
    }
    let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::CreateSavepoint {
        label: String::from("rfc-command-savepoint"),
        reply: savepoint_reply,
    }) {
        panic!("create savepoint should materialize through the temporal graph: {error}");
    }
    let savepoint = receive_reply(savepoint_receiver).await;
    assert_eq!(savepoint.label, "rfc-command-savepoint");
    assert_eq!(savepoint.configuration, engine.configuration().id());
    assert_eq!(
        savepoint.checkpoint.configuration,
        engine.configuration().id()
    );

    let (query_reply, query_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::Query {
        kind: QueryKind::EventLogLength,
        reply: query_reply,
    }) {
        panic!("event-log query should complete at a running boundary: {error}");
    }
    assert_eq!(
        receive_reply(query_receiver).await,
        QueryResult::EventLogLength(0)
    );
    assert_eq!(engine.pending_control_len(), 1);

    if let Err(error) = engine.apply_command(SessionCommand::Pause) {
        panic!("pause should return to a forkable boundary: {error}");
    }
    let (fork_reply, fork_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::Fork {
        from: CheckpointRef::Current,
        reply: fork_reply,
    }) {
        panic!("fork should resolve through the current graph checkpoint: {error}");
    }
    let fork = receive_reply(fork_receiver).await;
    assert_eq!(fork.checkpoint, engine.configuration().id());
    assert_eq!(fork.configuration, engine.configuration().id());
}

#[tokio::test]
async fn debug_time_travel_commands_reposition_without_scheduler_control_log() {
    let (root, first, second, graph) = debug_time_travel_fixture();
    let mut engine = Engine::new(second.clone(), graph, DebugGdbLoop).with_white_box_policies([
        (node_id("guest-a"), WhiteBoxPolicy::Enabled),
        (node_id("node-a"), WhiteBoxPolicy::Enabled),
    ]);

    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("debug fixture should instantiate: {error}");
    }
    let (attach_reply, attach_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::AttachGdb {
        node: node_id("guest-a"),
        listen: gdb_listen("127.0.0.1:9000"),
        debug_genesis: None,
        reply: attach_reply,
    }) {
        panic!("attach-gdb should use the loop gdbstub capability: {error}");
    }
    let attach = receive_reply(attach_receiver).await;
    assert_eq!(attach.configuration, second.id());
    assert!(attach.has_four_channel_debug_boundary());
    assert!(engine.boundary_control_log().is_empty());

    let (reverse_continue_reply, reverse_continue_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::DebugReverseContinue {
        request: DebugReverseContinueRequest::new(
            second.clone(),
            Condition::At {
                at: VirtualTime { ticks: 1 },
            },
            Vec::new(),
        ),
        reply: reverse_continue_reply,
    }) {
        panic!("reverse-continue with no matching prefix should complete: {error}");
    }
    assert!(
        receive_reply(reverse_continue_receiver)
            .await
            .matched
            .is_none()
    );
    assert!(!engine.debug_branch_required());

    let (goto_reply, goto_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::DebugGoto {
        request: DebugGotoRequest::at_configuration(second.clone(), first.clone()),
        reply: goto_reply,
    }) {
        panic!("debug goto should delegate to restore-plus-replay: {error}");
    }
    let goto = receive_reply(goto_receiver).await;
    assert_eq!(goto.target_configuration, first.id());
    assert_eq!(engine.configuration().id(), first.id());
    assert_eq!(
        engine.debug_attach().map(|active| active.configuration),
        Some(first.id())
    );
    assert!(engine.debug_branch_required());
    assert!(engine.boundary_control_log().is_empty());

    let blocked = engine
        .apply_command(SessionCommand::Continue)
        .expect_err("continuing after debug reposition must require branch metadata");
    assert!(matches!(
        blocked,
        SessionError::DebugNonCanonicalBranchRequired {
            operation: "continue"
        }
    ));
    let canonical_guest = match GuestIntrospectionRecord::new(
        1,
        crucible_protocol::guest_introspection::GuestIntrospectionMessage::Close,
    ) {
        Ok(record) => record,
        Err(error) => panic!("guest-introspection fixture must be valid: {error}"),
    };
    let canonical_guest_error = engine
        .apply_command(SessionCommand::GuestIntrospection {
            node: NodeId {
                name: String::from("node-a"),
            },
            channel_id: 1,
            request: Some(canonical_guest),
            reply: CommandReply::discard(),
        })
        .expect_err("canonical guest introspection must require an explicit debug fork");
    assert!(matches!(
        canonical_guest_error,
        SessionError::DebugNonCanonicalBranchRequired {
            operation: "guest-introspection"
        }
    ));

    let branch_request = DebugNonCanonicalBranchRequest::new(
        first.clone(),
        engine.frontier(),
        DebugNonCanonicalBranchTrigger::GuestIntrospection,
    )
    .with_action(DebugNonCanonicalBranchAction::guest_introspection(node_id(
        "node-a",
    )));
    let (branch_reply, branch_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::DebugForkNonCanonical {
        request: branch_request,
        reply: branch_reply,
    }) {
        panic!("non-canonical debug branch should clear forward guard: {error}");
    }
    let branch = receive_reply(branch_receiver).await;
    assert!(branch.proves_non_canonical_debug_branch());
    assert!(
        branch
            .guest_introspection_features
            .is_some_and(GuestIntrospectionFeatures::ssh_bridge)
    );
    assert!(!engine.debug_branch_required());
    let branch_entries = engine.drain_event_log_entries();
    assert_eq!(branch_entries.len(), 1);
    assert_eq!(branch_entries[0].sequence(), 0);
    let branch_count = engine.graph.debug_non_canonical_branch_count();
    let stale_prefix_error = engine
        .apply_command(SessionCommand::DebugForkNonCanonical {
            request: DebugNonCanonicalBranchRequest::new(
                first.clone(),
                engine.frontier(),
                DebugNonCanonicalBranchTrigger::OperatorContinue,
            )
            .with_action(DebugNonCanonicalBranchAction::operator_control(
                DebugOperatorControlKind::Continue,
            )),
            reply: CommandReply::discard(),
        })
        .expect_err("direct branch without a nonzero event-log prefix must fail first");
    assert!(matches!(
        stale_prefix_error,
        SessionError::EventLogOffsetMismatch {
            current: 1,
            emitted: 0,
            next: 0,
        }
    ));
    assert_eq!(
        engine.graph.debug_non_canonical_branch_count(),
        branch_count,
        "prefix mismatch must not mutate graph branch metadata"
    );
    let malformed_prefix_error = engine
        .apply_command_with_event_log(
            SessionCommand::DebugForkNonCanonical {
                request: DebugNonCanonicalBranchRequest::new(
                    first.clone(),
                    engine.frontier(),
                    DebugNonCanonicalBranchTrigger::OperatorContinue,
                )
                .with_action(DebugNonCanonicalBranchAction::operator_control(
                    DebugOperatorControlKind::Continue,
                )),
                reply: CommandReply::discard(),
            },
            &[test_event_log_entry(7)],
        )
        .expect_err("same-length malformed branch prefix must fail before graph mutation");
    assert!(matches!(
        malformed_prefix_error,
        SessionError::EventLogOffsetMismatch {
            current: 1,
            emitted: 0,
            next: 7,
        }
    ));
    assert_eq!(
        engine.graph.debug_non_canonical_branch_count(),
        branch_count,
        "malformed same-length prefix must not mutate graph branch metadata"
    );
    let unauthorized_record = GuestIntrospectionRecord::new(
        1,
        crucible_protocol::guest_introspection::GuestIntrospectionMessage::Close,
    )
    .unwrap_or_else(|error| panic!("guest-introspection fixture must be valid: {error}"));
    let unauthorized_error = engine
        .apply_command_with_event_log(
            SessionCommand::GuestIntrospection {
                node: node_id("guest-disabled"),
                channel_id: 1,
                request: Some(unauthorized_record),
                reply: CommandReply::discard(),
            },
            &branch_entries,
        )
        .expect_err("guest introspection must require explicit white-box authorization");
    assert!(matches!(
        unauthorized_error,
        SessionError::GuestIntrospectionNotAuthorized { node }
            if node == "guest-disabled"
    ));
    let guest_record = match GuestIntrospectionRecord::new(
        1,
        crucible_protocol::guest_introspection::GuestIntrospectionMessage::Close,
    ) {
        Ok(record) => record,
        Err(error) => panic!("guest-introspection fixture must be valid: {error}"),
    };
    let guest_error = engine
        .apply_command_with_event_log(
            SessionCommand::GuestIntrospection {
                node: NodeId {
                    name: String::from("node-a"),
                },
                channel_id: 1,
                request: Some(guest_record),
                reply: CommandReply::discard(),
            },
            &branch_entries,
        )
        .expect_err("stub backend must reject guest introspection after the fork gate opens");
    assert!(matches!(
        guest_error,
        SessionError::Scheduler(SchedulerError::Backend(BackendError::Unsupported {
            capability: "send_guest_introspection"
        }))
    ));
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue after non-canonical branch marker should be accepted: {error}");
    }

    let (reverse_step_reply, reverse_step_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::DebugReverseStep {
        request: DebugReverseStepRequest::new(
            first.clone(),
            DebugReverseStepGrain::Instruction,
            Vec::new(),
        ),
        reply: reverse_step_reply,
    }) {
        panic!("reverse-step should delegate through debug goto: {error}");
    }
    let reverse_step = receive_reply(reverse_step_receiver).await;
    assert_eq!(reverse_step.target_configuration, root.id());
    assert!(reverse_step.realized_by_goto());
    assert_eq!(engine.configuration().id(), root.id());
    assert!(engine.debug_branch_required());
    assert!(engine.boundary_control_log().is_empty());
    if let Err(error) = engine.apply_command(SessionCommand::Stop) {
        panic!("stop after debug reposition should be accepted: {error}");
    }
    let terminal_continue = engine
        .apply_command(SessionCommand::Continue)
        .expect_err("terminal continue should fail as invalid transition, not debug guard");
    assert!(matches!(
        terminal_continue,
        SessionError::InvalidTransition { .. }
    ));
}

#[tokio::test]
async fn rejected_debug_runtime_reposition_preserves_session_transaction() {
    let (_root, first, second, graph) = debug_time_travel_fixture();
    let mut engine = Engine::new(
        second.clone(),
        graph,
        RejectingDebugRepositionLoop {
            scheduler_run_active: false,
            acquire_attempts: 0,
            release_attempts: 0,
        },
    );

    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("debug fixture should instantiate: {error}");
    }
    let (attach_reply, attach_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::AttachGdb {
        node: node_id("guest-a"),
        listen: gdb_listen("127.0.0.1:9000"),
        debug_genesis: None,
        reply: attach_reply,
    }) {
        panic!("attach-gdb should use the loop gdbstub capability: {error}");
    }
    let _attach = receive_reply(attach_receiver).await;
    let active_guest_channel = (node_id("guest-a"), 41);
    engine
        .begin_guest_channel_run()
        .unwrap_or_else(|error| panic!("guest channel run should start: {error}"));
    engine.guest_channels.insert(active_guest_channel.clone());

    let before_snapshot = engine.snapshot();
    let before_runtime = engine.runtime.clone();
    let before_attach = engine.debug_attach.clone();
    let before_graph = engine.graph.clone();
    let error = engine
        .apply_command(SessionCommand::DebugGoto {
            request: DebugGotoRequest::at_configuration(second, first),
            reply: CommandReply::discard(),
        })
        .expect_err("a rejected live-runtime replacement must fail the goto");

    assert!(matches!(
        error,
        SessionError::Scheduler(SchedulerError::Backend(BackendError::Rejected { .. }))
    ));
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime, before_runtime);
    assert_eq!(engine.debug_attach, before_attach);
    assert_eq!(engine.graph, before_graph);
    assert!(!engine.debug_branch_required());
    assert!(engine.guest_channels.contains(&active_guest_channel));
    assert!(!engine.guest_responses.contains_key(&active_guest_channel));
    assert!(engine.quantum_loop.scheduler_run_active);
    assert_eq!(engine.quantum_loop.release_attempts, 1);
    assert_eq!(engine.quantum_loop.acquire_attempts, 2);
}

#[tokio::test]
async fn mismatched_debug_runtime_evidence_fails_closed_without_committing_model_state() {
    let (_root, first, second, graph) = debug_time_travel_fixture();
    let mut engine = Engine::new(second.clone(), graph, MismatchingDebugRepositionLoop);

    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("debug fixture should instantiate: {error}");
    }
    let (attach_reply, attach_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::AttachGdb {
        node: node_id("guest-a"),
        listen: gdb_listen("127.0.0.1:9000"),
        debug_genesis: None,
        reply: attach_reply,
    }) {
        panic!("attach-gdb should use the loop gdbstub capability: {error}");
    }
    let _attach = receive_reply(attach_receiver).await;

    let before_snapshot = engine.snapshot();
    let before_runtime = engine.runtime.clone();
    let before_attach = engine.debug_attach.clone();
    let before_graph = engine.graph.clone();
    let error = engine
        .apply_command(SessionCommand::DebugGoto {
            request: DebugGotoRequest::at_configuration(second, first),
            reply: CommandReply::discard(),
        })
        .expect_err("mismatched replacement evidence must fail the goto");

    assert!(matches!(
        error,
        SessionError::DebugRuntimeRepositionMismatch(_)
    ));
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime, before_runtime);
    assert_eq!(engine.debug_attach, before_attach);
    assert_eq!(engine.graph, before_graph);
    assert!(matches!(
        engine.debug_coordinator().state(),
        DebugCoordinatorState::Failed { .. }
    ));
}

#[tokio::test]
async fn actor_debug_noncanonical_branch_appends_visible_event_log_marker() {
    let (root, first, second, graph) = debug_time_travel_fixture();
    let engine = Engine::new(second.clone(), graph, DebugGdbLoop);
    let (_sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor
        .apply_command_without_spawning_forks(SessionCommand::Start)
        .await
    {
        panic!("debug actor fixture should instantiate: {error}");
    }
    let (attach_reply, attach_receiver) = CommandReply::channel();
    if let Err(error) = actor
        .apply_command_without_spawning_forks(SessionCommand::AttachGdb {
            node: node_id("guest-a"),
            listen: gdb_listen("127.0.0.1:9000"),
            debug_genesis: None,
            reply: attach_reply,
        })
        .await
    {
        panic!("debug actor should attach gdb: {error}");
    }
    let attach = receive_reply(attach_receiver).await;
    assert_eq!(attach.configuration, second.id());

    let mut unread_stream = actor.event_log_stream(EventLogCursor::new(0));
    let mut past_stream = actor.event_log_stream(EventLogCursor::new(0));

    actor
        .append_event_log_entries(&[test_event_log_entry(0), test_event_log_entry(1)])
        .unwrap_or_else(|error| panic!("debug history fixture must append: {error}"));
    actor.engine.event_log_len = 2;
    for expected in [test_event_log_entry(0), test_event_log_entry(1)] {
        let frame = past_stream
            .recv()
            .await
            .expect("past stream should not lag before rewind")
            .expect("past stream should receive the stale prefix before rewind");
        assert_eq!(frame.generation, 0);
        assert_eq!(frame.entry, expected);
    }
    assert_eq!(past_stream.cursor(), EventLogCursor::new(2));

    let (goto_reply, goto_receiver) = CommandReply::channel();
    if let Err(error) = actor
        .apply_command_without_spawning_forks(SessionCommand::DebugGoto {
            // The actor replaces this stale caller-supplied current coordinate
            // with its authoritative engine configuration before dispatch.
            request: DebugGotoRequest::at_configuration(root.clone(), first.clone()),
            reply: goto_reply,
        })
        .await
    {
        panic!("debug goto should rewind actor to first prefix: {error}");
    }
    let goto = receive_reply(goto_receiver).await;
    assert_eq!(goto.target_configuration, first.id());
    assert_eq!(actor.engine.event_log_len(), 0);

    let branch_request = DebugNonCanonicalBranchRequest::new(
        first.clone(),
        actor.engine.frontier(),
        DebugNonCanonicalBranchTrigger::OperatorContinue,
    )
    .with_action(DebugNonCanonicalBranchAction::operator_control(
        DebugOperatorControlKind::Continue,
    ));
    let (branch_reply, branch_receiver) = CommandReply::channel();
    if let Err(error) = actor
        .apply_command_without_spawning_forks(SessionCommand::DebugForkNonCanonical {
            request: branch_request,
            reply: branch_reply,
        })
        .await
    {
        panic!("debug branch should append through actor event log: {error}");
    }
    let branch = receive_reply(branch_receiver).await;
    assert!(branch.proves_non_canonical_debug_branch());
    let marker = branch.branch.fork_marker.entry.clone();
    let mut replay = actor.event_log_stream(EventLogCursor::new(0));
    let frame = replay
        .recv()
        .await
        .expect("event-log stream should not lag")
        .expect("debug branch marker should be visible after stale future truncation");
    assert_eq!(frame.cursor, EventLogCursor::new(0));
    assert!(frame.generation > 0);
    assert_eq!(frame.entry, marker);
    assert_ne!(frame.entry, test_event_log_entry(0));
    assert_ne!(frame.entry, test_event_log_entry(1));

    let unread_frame = unread_stream
        .recv()
        .await
        .expect("unread active stream should not lag")
        .expect("unread active stream should receive the replacement marker");
    assert_eq!(unread_frame.cursor, EventLogCursor::new(0));
    assert!(unread_frame.generation > 0);
    assert_eq!(unread_frame.entry, marker);
    assert_ne!(unread_frame.entry, test_event_log_entry(0));
    assert_ne!(unread_frame.entry, test_event_log_entry(1));

    let past_frame = past_stream
        .recv()
        .await
        .expect("past active stream should not lag")
        .expect("past active stream should receive the replacement marker");
    assert_eq!(past_frame.cursor, EventLogCursor::new(0));
    assert!(past_frame.generation > 0);
    assert_eq!(past_frame.entry, marker);
    assert_ne!(past_frame.entry, test_event_log_entry(0));
    assert_ne!(past_frame.entry, test_event_log_entry(1));

    assert_eq!(actor.event_log.len(), 1);
    assert_eq!(actor.condition_event_log.len(), 1);
    assert_eq!(actor.condition_event_log[0], marker);
    assert_eq!(
        actor.debug_event_coordinates.get(&marker.sequence()),
        Some(&actor.engine().snapshot().configuration),
    );
}

#[test]
fn actor_debug_history_indexes_each_emitted_decision_prefix() {
    let (root, first, second, graph) = debug_time_travel_fixture();
    let engine = Engine::new(second.clone(), graph, DebugGdbLoop);
    let (_sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    actor.debug_index_configuration = root.clone();
    let decisions = second.schedule.decisions();
    let entries = vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 1 },
            SchedulerEventLogPayload::Decision(decisions[0].clone()),
        ),
        crucible::test_support::condition_payload_entry_for_test(
            1,
            VirtualTime { ticks: 1 },
            resolved_backend_input_payload(1),
        ),
        crucible::test_support::condition_payload_entry_for_test(
            2,
            VirtualTime { ticks: 2 },
            SchedulerEventLogPayload::Decision(decisions[1].clone()),
        ),
        crucible::test_support::condition_boundary_entry_for_test(
            3,
            VirtualTime { ticks: 2 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ];
    actor.engine.event_log_len = entries.len();
    actor
        .append_event_log_entries(&entries)
        .unwrap_or_else(|error| panic!("multi-entry history must append: {error}"));

    assert_ne!(root, first);
    assert_eq!(actor.debug_event_coordinates.get(&0), Some(&first));
    assert_eq!(actor.debug_event_coordinates.get(&1), Some(&first));
    assert_eq!(actor.debug_event_coordinates.get(&2), Some(&second));
    assert_eq!(actor.debug_event_coordinates.get(&3), Some(&second));
    assert_eq!(actor.debug_current_event_limit(&second), Some(4));
}

#[test]
fn actor_non_advancing_command_preserves_future_coordinate_indexes() {
    let (_root, _first, second, graph) = debug_time_travel_fixture();
    let engine = Engine::new(second.clone(), graph, DebugGdbLoop);
    let (_sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    actor.condition_event_log = vec![test_event_log_entry(0), test_event_log_entry(1)];
    actor.debug_event_coordinates = BTreeMap::from([(0, second.clone()), (1, second)]);
    actor.engine.event_log_len = 1;

    actor
        .append_event_log_entries(&[])
        .unwrap_or_else(|error| panic!("empty command boundary must preserve history: {error}"));

    assert_eq!(actor.condition_event_log.len(), 2);
    assert!(actor.debug_event_coordinates.contains_key(&1));
}

#[tokio::test]
async fn resumed_actor_rejects_reverse_event_history_before_its_floor() {
    let (_root, _first, second, graph) = debug_time_travel_fixture();
    let mut engine = Engine::new(second.clone(), graph, DebugGdbLoop);
    engine.event_log_len = 7;
    let (_sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    let (reply, receiver) = CommandReply::channel();
    let error = actor
        .apply_command_without_spawning_forks(SessionCommand::DebugReverseStep {
            request: DebugReverseStepRequest::new(
                second,
                DebugReverseStepGrain::Quantum,
                Vec::new(),
            ),
            reply,
        })
        .await
        .expect_err("resumed history before the checkpoint must fail explicitly");
    assert_eq!(
        error,
        SessionError::DebugHistoryUnavailable {
            operation: "debug-reverse-step",
            floor: 7,
        }
    );
    assert_eq!(
        receive_reply_error::<DebugReverseStepReport>(receiver).await,
        error
    );
}

#[tokio::test]
async fn rfc_command_rejections_complete_reply_oneshots_without_side_effects() {
    let scenario = generated_scenario(27);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, StubLoop);
    let (_sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    let before = actor.engine().snapshot();
    let (reply, reply_receiver) = CommandReply::channel();
    let command = SessionCommand::Fork {
        from: CheckpointRef::Current,
        reply,
    };

    let error = actor
        .apply_command(command.clone())
        .await
        .expect_err("loaded fork must reject through actor boundary");
    assert_eq!(
        receive_reply_error::<SessionHandle>(reply_receiver).await,
        error
    );
    assert_eq!(actor.engine().snapshot(), before);
    assert_rejection_names_state_and_command(error, before.state, command);
}

#[tokio::test]
async fn rfc_command_terminal_drain_completes_queued_replies() {
    let scenario = generated_scenario(28);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, StubLoop);
    let (sender, receiver) = mpsc::channel(8);
    let (fork_reply, fork_receiver) = CommandReply::channel();
    let (set_reply, set_receiver) = CommandReply::channel();
    let (remove_reply, remove_receiver) = CommandReply::channel();
    let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
    let rejected_set = SessionCommand::SetBreakpoint {
        spec: BreakpointSpec::suspend_once(Condition::Quiescent),
        reply: set_reply,
    };
    let rejected_remove = SessionCommand::RemoveBreakpoint {
        id: 1,
        reply: remove_reply,
    };
    let rejected_savepoint = SessionCommand::CreateSavepoint {
        label: String::from("terminal-savepoint"),
        reply: savepoint_reply,
    };

    for command in [
        SessionCommand::Start,
        SessionCommand::Stop,
        SessionCommand::Fork {
            from: CheckpointRef::Current,
            reply: fork_reply,
        },
        rejected_set.clone(),
        rejected_remove.clone(),
        rejected_savepoint.clone(),
    ] {
        if let Err(error) = sender.send(command).await {
            panic!("terminal-drain command should enqueue: {error}");
        }
    }

    let report = match SessionActor::new(engine, receiver).run().await {
        Ok(report) => report,
        Err(error) => panic!("actor should report after draining terminal commands: {error}"),
    };

    let fork = receive_reply(fork_receiver).await;
    assert_eq!(fork.checkpoint, report.final_snapshot.configuration.id());
    assert_eq!(fork.configuration, report.final_snapshot.configuration.id());
    let error = receive_reply_error::<BreakpointId>(set_receiver).await;
    assert_rejection_names_state_and_command(
        error,
        report.final_snapshot.state.clone(),
        rejected_set,
    );
    let error = receive_reply_error::<bool>(remove_receiver).await;
    assert_rejection_names_state_and_command(
        error,
        report.final_snapshot.state.clone(),
        rejected_remove,
    );
    let error = receive_reply_error::<SavepointInfo>(savepoint_receiver).await;
    assert_rejection_names_state_and_command(
        error,
        report.final_snapshot.state,
        rejected_savepoint,
    );
}

#[tokio::test]
async fn rfc_command_running_actor_acknowledges_local_boundary_replies_immediately() {
    let scenario = generated_scenario(29);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    let breakpoint = BreakpointSpec::suspend_once(Condition::Quiescent);
    let (set_reply, set_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply: set_reply,
        })
        .await
    {
        panic!("set-breakpoint command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running set-breakpoint should complete locally: {error}");
    }
    let breakpoint_id = receive_reply(set_receiver).await;
    assert_eq!(actor.control_acknowledgements(), 1);
    assert_eq!(actor.engine().quanta(), 0);

    let (remove_reply, remove_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::RemoveBreakpoint {
            id: breakpoint_id,
            reply: remove_reply,
        })
        .await
    {
        panic!("remove-breakpoint command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running remove-breakpoint should complete locally: {error}");
    }
    assert!(receive_reply(remove_receiver).await);
    assert_eq!(actor.control_acknowledgements(), 2);
    assert_eq!(actor.engine().quanta(), 0);

    let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::CreateSavepoint {
            label: String::from("running-local-savepoint"),
            reply: savepoint_reply,
        })
        .await
    {
        panic!("savepoint command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running savepoint should complete locally: {error}");
    }
    let savepoint = receive_reply(savepoint_receiver).await;
    assert_eq!(savepoint.label, "running-local-savepoint");
    assert_eq!(actor.control_acknowledgements(), 3);
    assert_eq!(actor.engine().quanta(), 0);
    assert_eq!(actor.engine().pending_control_len(), 0);
}

#[tokio::test]
async fn running_boundary_commands_record_deterministic_control_log() {
    let scenario = generated_scenario(35);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let control_batches = Arc::new(Mutex::new(Vec::new()));
    let mut engine = Engine::new(
        config,
        graph,
        RecordingLoop::new(Arc::clone(&control_batches)),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (sender, receiver) = mpsc::channel(16);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("initial running iteration should establish a nonzero boundary: {error}");
    }
    assert_eq!(actor.engine().quanta(), 1);

    let breakpoint = BreakpointSpec::suspend_once(Condition::Quiescent);
    let (set_reply, set_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::SetBreakpoint {
            spec: breakpoint,
            reply: set_reply,
        })
        .await
    {
        panic!("set-breakpoint command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running set-breakpoint should be applied at a boundary: {error}");
    }
    let breakpoint_id = receive_reply(set_receiver).await;

    let (remove_reply, remove_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::RemoveBreakpoint {
            id: breakpoint_id,
            reply: remove_reply,
        })
        .await
    {
        panic!("remove-breakpoint command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running remove-breakpoint should be applied at a boundary: {error}");
    }
    assert!(receive_reply(remove_receiver).await);

    let (savepoint_reply, savepoint_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::CreateSavepoint {
            label: String::from("boundary-log-savepoint"),
            reply: savepoint_reply,
        })
        .await
    {
        panic!("savepoint command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running savepoint should be applied at a boundary: {error}");
    }
    assert_eq!(
        receive_reply(savepoint_receiver).await.label,
        "boundary-log-savepoint"
    );

    let (fork_reply, fork_receiver) = CommandReply::channel();
    if let Err(error) = sender
        .send(SessionCommand::Fork {
            from: CheckpointRef::Current,
            reply: fork_reply,
        })
        .await
    {
        panic!("fork command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running fork should pause and resolve at a boundary: {error}");
    }
    let fork = receive_reply(fork_receiver).await;
    assert_eq!(fork.checkpoint, actor.engine().configuration().id());
    assert_eq!(fork.configuration, actor.engine().configuration().id());

    let log = actor.engine().boundary_control_log();
    assert_eq!(log.len(), 4);
    assert_boundary_log_entry(&log[0], 1, SessionCommandKind::SetBreakpoint, None);
    assert_boundary_log_entry(&log[1], 2, SessionCommandKind::RemoveBreakpoint, None);
    assert_boundary_log_entry(&log[2], 3, SessionCommandKind::CreateSavepoint, None);
    assert_boundary_log_entry(&log[3], 4, SessionCommandKind::Fork, None);
    assert!(
        log.iter()
            .all(|entry| entry.frontier.ticks > 0 && entry.quanta > 0),
        "all commands were applied at nonzero scheduler boundaries"
    );
    assert_eq!(log[0].frontier, VirtualTime { ticks: 1 });
    assert_eq!(log[0].quanta, 1);
    assert_eq!(log[3].frontier, VirtualTime { ticks: 1 });
    assert_eq!(log[3].quanta, 1);
    assert_eq!(recorded_control_batches(&control_batches), vec![Vec::new()]);
    assert_eq!(actor.engine().pending_control_len(), 0);
    assert_eq!(actor.engine().quanta(), 1);
    assert!(matches!(
        actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::UserRequested
        }
    ));
}

#[tokio::test]
async fn paused_boundary_mutators_apply_and_record_control_log() {
    let scenario = generated_scenario(43);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let control_batches = Arc::new(Mutex::new(Vec::new()));
    let mut engine = Engine::new(
        config,
        graph,
        RecordingLoop::new(Arc::clone(&control_batches)),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }

    let log = engine.boundary_control_log();
    assert!(log.is_empty());
    assert!(recorded_control_batches(&control_batches).is_empty());
    assert_eq!(engine.pending_control_len(), 0);
    assert!(matches!(
        engine.state(),
        EngineState::Paused {
            reason: PauseReason::Instantiated
        }
    ));
}

#[test]
fn control_replay_artifact_rejects_final_snapshot_mismatch() {
    let scenario = generated_scenario(46);
    let initial = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut interactive = Engine::new(initial.clone(), graph, ControlSensitiveLoop::default());
    if let Err(error) = interactive.apply_command(SessionCommand::Start) {
        panic!("interactive replay producer should instantiate: {error}");
    }
    if let Err(error) = interactive.apply_command(SessionCommand::Continue) {
        panic!("interactive replay producer should run: {error}");
    }
    if let Err(error) = interactive.step_quantum() {
        panic!("producer quantum should establish a replay boundary: {error}");
    }
    let mut artifact = interactive.control_replay_artifact(initial);
    artifact.final_snapshot.event_log_len += 1;

    let error = match Engine::<ControlSensitiveLoop>::replay_control_replay_artifact(
        &artifact,
        graph_with_baked_genesis(&scenario),
        ControlSensitiveLoop::default(),
    ) {
        Ok(snapshot) => {
            panic!("final-snapshot-mismatched artifact should reject, got {snapshot:?}")
        }
        Err(error) => error,
    };

    let SessionError::ControlReplayFinalSnapshotMismatch { expected, actual } = error else {
        panic!("expected final snapshot mismatch, got {error:?}");
    };
    assert_eq!(expected.event_log_len, actual.event_log_len + 1);
    assert_eq!(expected.quanta, actual.quanta);
    assert_eq!(expected.frontier, actual.frontier);
    assert_eq!(expected.configuration.id(), actual.configuration.id());
}

#[tokio::test]
async fn pause_and_stop_take_effect_at_boundary_without_extra_quantum() {
    for command in [SessionCommand::Pause, SessionCommand::Stop] {
        let scenario = generated_scenario(36);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let shutdowns = Arc::new(AtomicU64::new(0));
        let mut engine = Engine::new(config, graph, ShutdownLoop::new(Arc::clone(&shutdowns)));
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("continue should enter running state: {error}");
        }
        let (sender, receiver) = mpsc::channel(2);
        let mut actor = SessionActor::new(engine, receiver);
        if let Err(error) = sender.send(command.clone()).await {
            panic!("boundary command should enqueue: {error}");
        }

        if let Err(error) = actor.run_once().await {
            panic!("{command:?} should be serviced at the next boundary check: {error}");
        }

        assert_eq!(actor.engine().quanta(), 0);
        let log = actor.engine().boundary_control_log();
        assert_eq!(log.len(), 1);
        assert_boundary_log_entry(&log[0], 1, SessionCommandKind::from(&command), None);
        let expected_shutdowns = match &command {
            SessionCommand::Stop => 1,
            _ => 0,
        };
        match &command {
            SessionCommand::Pause => assert!(matches!(
                actor.engine().state(),
                EngineState::Paused {
                    reason: PauseReason::UserRequested
                }
            )),
            SessionCommand::Stop => assert!(matches!(
                actor.engine().state(),
                EngineState::Stopped {
                    outcome: Outcome::Stopped
                }
            )),
            _ => panic!("test only covers pause and stop"),
        }
        assert_eq!(shutdowns.load(Ordering::SeqCst), expected_shutdowns);
    }
}

#[tokio::test]
async fn breakpoint_suspend_uses_shared_condition_and_preserves_canonical_log() {
    let baseline_entries = {
        let scenario = generated_scenario(38);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("baseline start should instantiate runtime: {error}");
        }
        if let Err(error) = engine.apply_command(SessionCommand::Continue) {
            panic!("baseline continue should enter running state: {error}");
        }
        let (_sender, receiver) = mpsc::channel(1);
        let mut actor = SessionActor::new(engine, receiver);
        if let Err(error) = actor.run_once().await {
            panic!("baseline actor should drive one quantum: {error}");
        }
        actor.event_log.lock_entries().clone()
    };

    let scenario = generated_scenario(38);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("breakpoint start should instantiate runtime: {error}");
    }
    let predicate = Predicate::all_of(vec![
        Predicate::once(Predicate::at(VirtualTime { ticks: 1 })),
        Predicate::not(Predicate::at(VirtualTime { ticks: 2 })),
    ]);
    let breakpoint = BreakpointSpec::suspend_once(predicate.clone());
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint.clone(),
        reply,
    }) {
        panic!("breakpoint should register before continue: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("breakpoint actor should drive one quantum: {error}");
    }

    assert_eq!(
        actor.engine().state(),
        &EngineState::Paused {
            reason: PauseReason::Breakpoint { id: breakpoint_id },
        }
    );
    assert!(actor.engine().breakpoints().is_empty());
    assert_eq!(
        &*actor.event_log.lock_entries(),
        baseline_entries.as_slice()
    );
    assert_eq!(
        actor.engine().breakpoint_firings(),
        &[BreakpointFiring {
            sequence: 1,
            id: breakpoint_id,
            predicate,
            disposition: BreakpointDisposition::Suspend,
            frontier: VirtualTime { ticks: 1 },
            quanta: 1,
            scheduler_controls: Vec::new(),
        }]
    );
}

#[tokio::test]
async fn repeatable_trace_breakpoint_fires_on_false_to_true_transitions() {
    let scenario = generated_scenario(39);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("trace breakpoint start should instantiate runtime: {error}");
    }
    let predicate = Predicate::any_of(vec![
        Predicate::at(VirtualTime { ticks: 1 }),
        Predicate::at(VirtualTime { ticks: 3 }),
    ]);
    let breakpoint = BreakpointSpec {
        predicate,
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::Repeatable,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("trace breakpoint should register before continue: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("trace breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("first trace quantum should run: {error}");
    }
    assert_eq!(actor.engine().breakpoint_firings().len(), 1);
    assert!(matches!(actor.engine().state(), EngineState::Running));

    if let Err(error) = actor.run_once().await {
        panic!("second trace quantum should run: {error}");
    }
    assert_eq!(actor.engine().breakpoint_firings().len(), 1);
    assert!(actor.engine().breakpoints().get(breakpoint_id).is_some());

    if let Err(error) = actor.run_once().await {
        panic!("third trace quantum should run: {error}");
    }
    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![breakpoint_id, breakpoint_id]
    );
    assert!(matches!(actor.engine().state(), EngineState::Running));
}

#[tokio::test]
async fn breakpoint_once_combinator_latches_across_boundaries() {
    let scenario = generated_scenario(40);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("once breakpoint start should instantiate runtime: {error}");
    }
    let predicate = Predicate::all_of(vec![
        Predicate::once(Predicate::at(VirtualTime { ticks: 1 })),
        Predicate::at(VirtualTime { ticks: 3 }),
    ]);
    let breakpoint = BreakpointSpec {
        predicate,
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::Repeatable,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("once breakpoint should register before continue: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("once breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    for quantum in 1..=2 {
        if let Err(error) = actor.run_once().await {
            panic!("once breakpoint quantum {quantum} should run: {error}");
        }
        assert!(actor.engine().breakpoint_firings().is_empty());
    }

    if let Err(error) = actor.run_once().await {
        panic!("once breakpoint third quantum should run: {error}");
    }

    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![breakpoint_id]
    );
    assert!(matches!(actor.engine().state(), EngineState::Running));
}

#[tokio::test]
async fn unsupported_breakpoint_action_fails_loudly() {
    let scenario = generated_scenario(42);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("unsupported-action breakpoint start should instantiate runtime: {error}");
    }
    let breakpoint = BreakpointSpec {
        predicate: Predicate::at(VirtualTime { ticks: 1 }),
        disposition: BreakpointDisposition::Action(Action::Log {
            level: LogLevel::Info,
            message: String::from("unsupported breakpoint action"),
        }),
        policy: BreakpointPolicy::OneShot,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("unsupported-action breakpoint should register: {error}");
    }
    let _breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("unsupported-action breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    let error = actor
        .run_once()
        .await
        .expect_err("unsupported action breakpoint should fail loudly");

    assert_eq!(
        error,
        SessionError::UnsupportedBreakpointAction { action: "log" }
    );
    assert!(actor.engine().breakpoint_firings().is_empty());
}

#[tokio::test]
async fn breakpoint_action_group_is_prevalidated_before_control_application() {
    let scenario = generated_scenario(44);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let control_batches = Arc::new(Mutex::new(Vec::new()));
    let mut engine = Engine::new(
        config,
        graph,
        RecordingLoop::new(Arc::clone(&control_batches)),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("group breakpoint start should instantiate runtime: {error}");
    }
    let breakpoint = BreakpointSpec {
        predicate: Predicate::at(VirtualTime { ticks: 1 }),
        disposition: BreakpointDisposition::Action(Action::Group(vec![
            Action::Pass,
            Action::Log {
                level: LogLevel::Info,
                message: String::from("unsupported group suffix"),
            },
        ])),
        policy: BreakpointPolicy::OneShot,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("group breakpoint should register: {error}");
    }
    let _breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("group breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    let error = actor
        .run_once()
        .await
        .expect_err("unsupported group suffix should fail before control application");

    assert_eq!(
        error,
        SessionError::UnsupportedBreakpointAction { action: "log" }
    );
    assert!(actor.engine().breakpoint_firings().is_empty());
    assert!(actor.engine().boundary_control_log().is_empty());
    assert_eq!(recorded_control_batches(&control_batches), vec![Vec::new()]);
}

#[tokio::test]
async fn breakpoint_conditions_cover_node_and_assertion_state_leaves() {
    let scenario = generated_scenario(45);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let node = NodeId {
        name: String::from("node-a"),
    };
    let assertion = AssertionId::from_name("session-step-assertion");
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_payloads(
            1,
            vec![
                SchedulerEventLogPayload::Observable(ObservableEventPayload::NodeState {
                    node: node.clone(),
                    state: NodeLifecycle::Exited,
                }),
                SchedulerEventLogPayload::Observable(
                    ObservableEventPayload::AssertionStateChanged {
                        name: assertion.clone(),
                        state: AssertionPhase::Satisfied,
                    },
                ),
            ],
        ),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("leaf breakpoint start should instantiate runtime: {error}");
    }

    let node_breakpoint = BreakpointSpec {
        predicate: Predicate::node_state(node, NodeLifecycle::Exited),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (node_reply, node_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: node_breakpoint,
        reply: node_reply,
    }) {
        panic!("node-state breakpoint should register: {error}");
    }
    let node_breakpoint_id = receive_reply(node_receiver).await;

    let assertion_breakpoint = BreakpointSpec {
        predicate: Predicate::assertion_state(assertion, AssertionPhase::Satisfied),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (assertion_reply, assertion_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: assertion_breakpoint,
        reply: assertion_reply,
    }) {
        panic!("assertion-state breakpoint should register: {error}");
    }
    let assertion_breakpoint_id = receive_reply(assertion_receiver).await;

    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("leaf breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("leaf breakpoint quantum should run: {error}");
    }

    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![node_breakpoint_id, assertion_breakpoint_id]
    );
    assert!(actor.engine().breakpoints().is_empty());
    assert!(matches!(actor.engine().state(), EngineState::Running));
}

#[tokio::test]
async fn breakpoint_conditions_cover_guest_marker_white_box_leaves() {
    let world = single_node_debug_world("guest-marker-breakpoint")
        .unwrap_or_else(|error| panic!("guest marker world should build: {error}"));
    let scenario = world.scenario_def();
    let node = world
        .vm_nodes()
        .first()
        .map(|node| node.id.clone())
        .unwrap_or_else(|| panic!("guest marker world should contain a node"));
    let marker = crucible::MarkerId::from_name("session-marker");

    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut denied_engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_payloads(
            1,
            vec![SchedulerEventLogPayload::Observable(
                ObservableEventPayload::GuestMarker {
                    retired_icount: crucible::Icount { retired: 1 },
                    node: node.clone(),
                    marker: marker.clone(),
                },
            )],
        ),
    );
    if let Err(error) = denied_engine.apply_command(SessionCommand::Start) {
        panic!("guest-marker denied start should instantiate runtime: {error}");
    }
    let (denied_reply, denied_receiver) = CommandReply::channel();
    if let Err(error) = denied_engine.apply_command(SessionCommand::SetBreakpoint {
        spec: BreakpointSpec::suspend_once(Predicate::guest_marker(marker.clone())),
        reply: denied_reply,
    }) {
        panic!("guest-marker denied breakpoint should register: {error}");
    }
    let denied_breakpoint_id = receive_reply(denied_receiver).await;
    if let Err(error) = denied_engine.apply_command(SessionCommand::Continue) {
        panic!("guest-marker denied continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut denied_actor = SessionActor::new(denied_engine, receiver);
    if let Err(error) = denied_actor.run_once().await {
        panic!("guest-marker denied quantum should run: {error}");
    }
    assert!(denied_actor.engine().breakpoint_firings().is_empty());
    assert!(
        denied_actor
            .engine()
            .breakpoints()
            .get(denied_breakpoint_id)
            .is_some()
    );

    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_payloads(
            1,
            vec![SchedulerEventLogPayload::Observable(
                ObservableEventPayload::GuestMarker {
                    retired_icount: crucible::Icount { retired: 1 },
                    node,
                    marker: marker.clone(),
                },
            )],
        ),
    )
    .with_world_white_box_policies(&world);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("guest-marker breakpoint start should instantiate runtime: {error}");
    }
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: BreakpointSpec::suspend_once(Predicate::guest_marker(marker)),
        reply,
    }) {
        panic!("guest-marker breakpoint should register: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("guest-marker breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("guest-marker breakpoint quantum should run: {error}");
    }

    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![breakpoint_id]
    );
    assert!(actor.engine().breakpoints().is_empty());
    assert!(matches!(actor.engine().state(), EngineState::Paused { .. }));
}

#[tokio::test]
async fn breakpoint_conditions_cover_after_and_timer_runtime_facts() {
    let scenario = generated_scenario(46);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let after_event = EventId::from_name("breakpoint-after-source");
    let timer = TimerId {
        name: String::from("breakpoint-timer"),
    };
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_payloads(
            1,
            vec![
                trigger_fired_payload(
                    1,
                    after_event.clone(),
                    Predicate::at(VirtualTime { ticks: 1 }),
                ),
                SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
                    sequence: 0,
                    event: EventId::from_name("breakpoint-timer-arm"),
                    at: VirtualTime { ticks: 1 },
                    path: Vec::new(),
                    action: Action::arm_timer(timer.clone(), SimDuration { nanos: 1 }),
                }),
            ],
        ),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("runtime-fact breakpoint start should instantiate runtime: {error}");
    }

    let after_breakpoint = BreakpointSpec {
        predicate: Predicate::after(SimDuration { nanos: 1 }, after_event),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (after_reply, after_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: after_breakpoint,
        reply: after_reply,
    }) {
        panic!("after breakpoint should register: {error}");
    }
    let after_breakpoint_id = receive_reply(after_receiver).await;

    let timer_breakpoint = BreakpointSpec {
        predicate: Predicate::timer(timer),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (timer_reply, timer_receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: timer_breakpoint,
        reply: timer_reply,
    }) {
        panic!("timer breakpoint should register: {error}");
    }
    let timer_breakpoint_id = receive_reply(timer_receiver).await;

    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("runtime-fact breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("first runtime-fact quantum should run: {error}");
    }
    assert!(actor.engine().breakpoint_firings().is_empty());

    if let Err(error) = actor.run_once().await {
        panic!("second runtime-fact quantum should run: {error}");
    }

    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![after_breakpoint_id, timer_breakpoint_id]
    );
    assert!(actor.engine().breakpoints().is_empty());
}

#[tokio::test]
async fn quiescent_breakpoint_uses_scheduler_quiescence_evidence() {
    let scenario = generated_scenario(47);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_quiescence(SchedulerQuiescence::default()),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("quiescent breakpoint start should instantiate runtime: {error}");
    }
    let breakpoint = BreakpointSpec {
        predicate: Predicate::quiescent(),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("quiescent breakpoint should register: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("quiescent breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("quiescent breakpoint quantum should run: {error}");
    }

    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![breakpoint_id]
    );
    assert!(actor.engine().breakpoints().is_empty());
    assert!(matches!(
        actor.engine().state(),
        EngineState::Stopped {
            outcome: Outcome::Passed
        }
    ));
}

#[tokio::test]
async fn property_failure_breakpoint_produces_failed_terminal_outcome() {
    let scenario = generated_scenario(4_701);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_quiescence(SchedulerQuiescence::default()),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("failure-outcome start should instantiate runtime: {error}");
    }
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: BreakpointSpec::fail_once(Predicate::quiescent(), "replicated invariant violated"),
        reply,
    }) {
        panic!("failure-outcome breakpoint should register: {error}");
    }
    let _breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("failure-outcome continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);
    if let Err(error) = actor.run_once().await {
        panic!("failure-outcome quantum should complete: {error}");
    }
    assert!(matches!(
        actor.engine().state(),
        EngineState::Stopped {
            outcome: Outcome::Failed { violations }
        } if violations == &[String::from("replicated invariant violated")]
    ));
}

#[tokio::test]
async fn quantum_loop_pass_verdict_produces_passed_terminal_outcome() {
    let scenario = generated_scenario(4_704);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        TerminalVerdictLoop::new(QuantumTerminalVerdict::Passed),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("trigger-pass start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("trigger-pass continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);
    if let Err(error) = actor.run_once().await {
        panic!("trigger-pass quantum should complete: {error}");
    }
    assert!(matches!(
        actor.engine().state(),
        EngineState::Stopped {
            outcome: Outcome::Passed
        }
    ));
}

#[tokio::test]
async fn quantum_loop_failure_verdict_produces_failed_terminal_outcome() {
    let scenario = generated_scenario(4_705);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        TerminalVerdictLoop::new(QuantumTerminalVerdict::Failed(vec![String::from(
            "trigger invariant violated",
        )])),
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("trigger-failure start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("trigger-failure continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);
    if let Err(error) = actor.run_once().await {
        panic!("trigger-failure quantum should complete: {error}");
    }
    assert!(matches!(
        actor.engine().state(),
        EngineState::Stopped {
            outcome: Outcome::Failed { violations }
        } if violations == &[String::from("trigger invariant violated")]
    ));
}

#[tokio::test]
async fn backend_failure_produces_crashed_terminal_outcome() {
    let scenario = generated_scenario(4_703);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, BackendCrashLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("crash-outcome start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("crash-outcome continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);
    if let Err(error) = actor.run_once().await {
        panic!("backend crash should become a terminal outcome: {error}");
    }
    assert!(matches!(
        actor.engine().state(),
        EngineState::Stopped {
            outcome: Outcome::Crashed { detail }
        } if detail.contains("backend process exited unexpectedly")
    ));
}

#[tokio::test]
async fn quiescent_breakpoint_fires_without_emitted_entries() {
    let scenario = generated_scenario(48);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        NoEventQuiescenceLoop {
            quiescence: SchedulerQuiescence::default(),
        },
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("no-event quiescent breakpoint start should instantiate runtime: {error}");
    }
    let breakpoint = BreakpointSpec {
        predicate: Predicate::quiescent(),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("no-event quiescent breakpoint should register: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("no-event quiescent breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("no-event quiescent breakpoint quantum should run: {error}");
    }

    assert!(actor.event_log.lock_entries().is_empty());
    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        vec![breakpoint_id]
    );
}

#[tokio::test]
async fn no_entry_breakpoint_after_prior_event_uses_current_boundary() {
    let scenario = generated_scenario(49);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        PriorEventThenNoEventQuiescenceLoop {
            quanta: 0,
            quiescence: SchedulerQuiescence::default(),
        },
    );
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("post-event no-entry breakpoint start should instantiate runtime: {error}");
    }
    let predicate = Predicate::all_of(vec![
        Predicate::at(VirtualTime { ticks: 2 }),
        Predicate::quiescent(),
    ]);
    let breakpoint = BreakpointSpec {
        predicate: predicate.clone(),
        disposition: BreakpointDisposition::Trace,
        policy: BreakpointPolicy::OneShot,
    };
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: breakpoint,
        reply,
    }) {
        panic!("post-event no-entry breakpoint should register: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("post-event no-entry breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("first post-event no-entry quantum should run: {error}");
    }
    assert!(actor.engine().breakpoint_firings().is_empty());
    assert_eq!(actor.event_log.lock_entries().len(), 1);

    if let Err(error) = actor.run_once().await {
        panic!("second post-event no-entry quantum should run: {error}");
    }

    assert_eq!(actor.event_log.lock_entries().len(), 1);
    assert_eq!(
        actor.engine().breakpoint_firings(),
        &[BreakpointFiring {
            sequence: 1,
            id: breakpoint_id,
            predicate,
            disposition: BreakpointDisposition::Trace,
            frontier: VirtualTime { ticks: 2 },
            quanta: 2,
            scheduler_controls: Vec::new(),
        }]
    );
}

#[path = "engine_state/budget_exhaustion.rs"]
mod budget_exhaustion;
#[path = "engine_state/runtime_smoke.rs"]
mod runtime_smoke;
