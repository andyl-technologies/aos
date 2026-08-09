//! Guest-introspection channel, activation, and terminal lifecycle tests.

use super::*;

struct GuestBrokerLoop {
    responses: VecDeque<GuestIntrospectionRecord>,
    scheduler_run_active: bool,
    fail_release: bool,
    release_attempts: u64,
}

impl QuantumLoop for GuestBrokerLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        StubLoop.drive_quantum(request)
    }

    fn send_guest_introspection(
        &mut self,
        _node: NodeId,
        _record: GuestIntrospectionRecord,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn receive_guest_introspection(
        &mut self,
        _node: NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, SchedulerError> {
        Ok(self.responses.pop_front())
    }

    fn acquire_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        assert!(!self.scheduler_run_active);
        self.scheduler_run_active = true;
        Ok(())
    }

    fn release_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        assert!(self.scheduler_run_active);
        self.release_attempts = self.release_attempts.saturating_add(1);
        if self.fail_release {
            return Err(BackendError::Rejected {
                message: String::from("scheduler lease release failed"),
            }
            .into());
        }
        self.scheduler_run_active = false;
        Ok(())
    }
}

struct PendingActivationLoop {
    scheduler_run_active: bool,
    release_attempts: u64,
}

impl QuantumLoop for PendingActivationLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        StubLoop.drive_quantum(request)
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen).map_err(SchedulerError::from)
    }

    fn activate_debug_guest(&mut self, _node: NodeId) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn receive_guest_introspection(
        &mut self,
        _node: NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, SchedulerError> {
        Ok(None)
    }

    fn acquire_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        assert!(!self.scheduler_run_active);
        self.scheduler_run_active = true;
        Ok(())
    }

    fn release_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        assert!(self.scheduler_run_active);
        self.scheduler_run_active = false;
        self.release_attempts = self.release_attempts.saturating_add(1);
        Ok(())
    }
}

#[tokio::test]
async fn guest_response_broker_does_not_lose_other_channel_records() {
    let scenario = generated_scenario(221);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let response = |channel_id, byte| {
        GuestIntrospectionRecord::new(
            channel_id,
            GuestIntrospectionMessage::Output {
                stream: crucible_protocol::guest_introspection::GuestOutputStream::Stdout,
                bytes: vec![byte],
            },
        )
        .unwrap_or_else(|error| panic!("guest response fixture must be valid: {error}"))
    };
    let mut engine = Engine::new(
        config.clone(),
        graph,
        GuestBrokerLoop {
            responses: VecDeque::from([response(2, b'b'), response(1, b'a')]),
            scheduler_run_active: false,
            fail_release: false,
            release_attempts: 0,
        },
    )
    .with_white_box_policies([(node_id("node-a"), WhiteBoxPolicy::Enabled)]);
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("engine must start: {error}"));
    engine.debug_coordinator.forked_non_canonical(config.id());

    let poll = |channel_id, reply| SessionCommand::GuestIntrospection {
        node: NodeId {
            name: String::from("node-a"),
        },
        channel_id,
        request: None,
        reply,
    };
    let (first_reply, first_receiver) = CommandReply::channel();
    engine
        .apply_command(poll(1, first_reply))
        .unwrap_or_else(|error| panic!("channel one poll must succeed: {error}"));
    assert_eq!(receive_reply(first_receiver).await, Some(response(1, b'a')));

    let (second_reply, second_receiver) = CommandReply::channel();
    engine
        .apply_command(poll(2, second_reply))
        .unwrap_or_else(|error| panic!("buffered channel two poll must succeed: {error}"));
    assert_eq!(
        receive_reply(second_receiver).await,
        Some(response(2, b'b'))
    );

    let node = NodeId {
        name: String::from("node-a"),
    };
    engine.guest_channels.insert((node.clone(), 3));
    engine
        .close_guest_channels_for_reposition()
        .unwrap_or_else(|error| panic!("guest channels should close: {error}"));
    engine.debug_coordinator.repositioned_canonical(config.id());
    let (closed_reply, closed_receiver) = CommandReply::channel();
    engine
        .apply_command(poll(3, closed_reply))
        .unwrap_or_else(|error| panic!("typed reposition closure must remain pollable: {error}"));
    let closed = receive_reply(closed_receiver).await;
    assert!(matches!(
        closed.as_ref().map(GuestIntrospectionRecord::message),
        Some(GuestIntrospectionMessage::Error {
            code: GuestIntrospectionFailureCode::ClosedChannel,
            ..
        })
    ));
}

#[tokio::test]
async fn guest_channel_owns_scheduler_run_until_terminal_response() {
    let scenario = generated_scenario(222);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let node = node_id("node-a");
    let exit = GuestIntrospectionRecord::new(
        7,
        GuestIntrospectionMessage::Exit {
            status: 0,
            signal: None,
        },
    )
    .unwrap_or_else(|error| panic!("guest exit fixture must be valid: {error}"));
    let mut engine = Engine::new(
        config.clone(),
        graph,
        GuestBrokerLoop {
            responses: VecDeque::from([exit.clone()]),
            scheduler_run_active: false,
            fail_release: false,
            release_attempts: 0,
        },
    )
    .with_white_box_policies([(node.clone(), WhiteBoxPolicy::Enabled)]);
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("engine must start: {error}"));
    engine
        .apply_command(SessionCommand::Pause)
        .unwrap_or_else(|error| panic!("engine must pause: {error}"));
    engine.debug_coordinator.forked_non_canonical(config.id());
    engine.guest_features.insert(
        node.clone(),
        GuestIntrospectionFeatures::new(true, true, true, true, 8),
    );

    let open = GuestIntrospectionRecord::new(
        7,
        GuestIntrospectionMessage::Exec {
            argv: vec![String::from("/bin/true")],
            record_transcript: false,
        },
    )
    .unwrap_or_else(|error| panic!("guest exec fixture must be valid: {error}"));
    let (open_reply, open_receiver) = CommandReply::channel();
    engine
        .apply_command(SessionCommand::GuestIntrospection {
            node: node.clone(),
            channel_id: 7,
            request: Some(open),
            reply: open_reply,
        })
        .unwrap_or_else(|error| panic!("guest exec must open: {error}"));
    assert_eq!(receive_reply(open_receiver).await, None);
    assert!(matches!(engine.state(), EngineState::Running));
    assert!(engine.quantum_loop.scheduler_run_active);
    assert!(engine.guest_channels.contains(&(node.clone(), 7)));

    let (poll_reply, poll_receiver) = CommandReply::channel();
    engine
        .apply_command(SessionCommand::GuestIntrospection {
            node,
            channel_id: 7,
            request: None,
            reply: poll_reply,
        })
        .unwrap_or_else(|error| panic!("guest response must poll: {error}"));
    assert_eq!(receive_reply(poll_receiver).await, Some(exit));
    assert!(matches!(engine.state(), EngineState::Paused { .. }));
    assert!(!engine.quantum_loop.scheduler_run_active);
    assert!(engine.guest_channels.is_empty());
}

#[test]
fn terminal_guest_response_survives_scheduler_lease_release_failure() {
    let scenario = generated_scenario(223);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let node = node_id("node-a");
    let exit = GuestIntrospectionRecord::new(
        9,
        GuestIntrospectionMessage::Exit {
            status: 17,
            signal: None,
        },
    )
    .unwrap_or_else(|error| panic!("guest exit fixture must be valid: {error}"));
    let mut engine = Engine::new(
        config,
        graph,
        GuestBrokerLoop {
            responses: VecDeque::from([exit.clone()]),
            scheduler_run_active: false,
            fail_release: true,
            release_attempts: 0,
        },
    );
    engine
        .begin_guest_channel_run()
        .unwrap_or_else(|error| panic!("guest channel run must acquire: {error}"));
    engine.guest_channels.insert((node.clone(), 9));

    let error = engine
        .receive_guest_channel_response(&node, 9)
        .expect_err("terminal response must report the failed lease release");
    assert!(error.to_string().contains("scheduler lease release failed"));
    assert_eq!(
        engine
            .guest_responses
            .get(&(node.clone(), 9))
            .and_then(|records| records.front()),
        Some(&exit),
        "the terminal response must remain durable across release failure"
    );
    assert_eq!(engine.quantum_loop.release_attempts, 1);

    engine.quantum_loop.fail_release = false;
    assert_eq!(
        engine
            .receive_guest_channel_response(&node, 9)
            .unwrap_or_else(|error| panic!("terminal response retry must release: {error}")),
        Some(exit)
    );
    assert_eq!(engine.quantum_loop.release_attempts, 2);
    assert!(!engine.quantum_loop.scheduler_run_active);
}

#[test]
fn continuous_quiescence_terminalizes_active_guest_channels() {
    let scenario = generated_scenario(224);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let node = node_id("node-a");
    let mut engine = Engine::new(
        config,
        graph,
        GuestBrokerLoop {
            responses: VecDeque::new(),
            scheduler_run_active: false,
            fail_release: false,
            release_attempts: 0,
        },
    );
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("engine must start: {error}"));
    engine
        .begin_guest_channel_run()
        .unwrap_or_else(|error| panic!("guest channel run must acquire: {error}"));
    engine.guest_channels.insert((node.clone(), 11));
    engine.scheduler_quiescence = Some(SchedulerQuiescence::default());

    engine
        .stop_on_continuous_quiescence()
        .unwrap_or_else(|error| panic!("quiescent session must stop: {error}"));

    assert!(matches!(
        engine.state(),
        EngineState::Stopped {
            outcome: Outcome::Passed
        }
    ));
    assert!(engine.guest_channels.is_empty());
    assert!(!engine.quantum_loop.scheduler_run_active);
    assert_eq!(engine.quantum_loop.release_attempts, 1);
    assert!(matches!(
        engine
            .guest_responses
            .get(&(node, 11))
            .and_then(|records| records.front())
            .map(GuestIntrospectionRecord::message),
        Some(GuestIntrospectionMessage::Error {
            code: GuestIntrospectionFailureCode::ClosedChannel,
            ..
        })
    ));
}

#[tokio::test]
async fn operator_stop_resolves_pending_guest_activation() {
    let (_root, _first, current, graph) = debug_time_travel_fixture();
    let node = node_id("guest-a");
    let mut engine = Engine::new(
        current.clone(),
        graph,
        PendingActivationLoop {
            scheduler_run_active: false,
            release_attempts: 0,
        },
    )
    .with_white_box_policies([(node.clone(), WhiteBoxPolicy::Enabled)]);
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("debug fixture must instantiate: {error}"));
    let (attach_reply, attach_receiver) = CommandReply::channel();
    engine
        .apply_command(SessionCommand::AttachGdb {
            node: node.clone(),
            listen: gdb_listen("127.0.0.1:9000"),
            debug_genesis: None,
            reply: attach_reply,
        })
        .unwrap_or_else(|error| panic!("attach-gdb must succeed: {error}"));
    let _attach = receive_reply(attach_receiver).await;

    let request = DebugNonCanonicalBranchRequest::new(
        current,
        engine.frontier(),
        DebugNonCanonicalBranchTrigger::GuestIntrospection,
    )
    .with_action(DebugNonCanonicalBranchAction::guest_introspection(
        node.clone(),
    ));
    let (branch_reply, branch_receiver) = CommandReply::channel();
    engine
        .apply_command(SessionCommand::DebugForkNonCanonical {
            request,
            reply: branch_reply,
        })
        .unwrap_or_else(|error| panic!("guest activation fork must start: {error}"));
    assert!(matches!(engine.state(), EngineState::Running));
    assert!(engine.quantum_loop.scheduler_run_active);

    engine
        .apply_command(SessionCommand::Stop)
        .unwrap_or_else(|error| panic!("operator stop must terminalize: {error}"));
    let report = receive_reply(branch_receiver).await;

    assert!(matches!(
        engine.state(),
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    ));
    assert!(
        report
            .guest_introspection_activation_failure
            .as_deref()
            .is_some_and(|reason| reason.contains("session terminated"))
    );
    assert!(!engine.quantum_loop.scheduler_run_active);
    assert_eq!(engine.quantum_loop.release_attempts, 1);
}
