//! Interactive replay terminal sampling, retirement, and failure evidence.

use super::*;
use std::sync::Mutex;

struct RetiringLoop {
    inner: QuiescentLifecycleLoop,
    retired: bool,
    refuse_sample: bool,
    refuse_shutdown: bool,
    operations: Arc<Mutex<Vec<&'static str>>>,
}

impl RetiringLoop {
    fn new(operations: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            inner: QuiescentLifecycleLoop::new(),
            retired: false,
            refuse_sample: false,
            refuse_shutdown: false,
            operations,
        }
    }

    fn record(&self, operation: &'static str) -> Result<(), QErr> {
        self.operations
            .lock()
            .map_err(|_| QErr::BoundaryViolation {
                message: String::from("replay operations lock poisoned"),
            })?
            .push(operation);
        Ok(())
    }
}

impl EngineLoop for RetiringLoop {
    fn drive_quantum(&mut self, request: QReq) -> Result<QOut, QErr> {
        self.record("run")?;
        self.inner.drive_quantum(request)
    }

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, QErr> {
        self.record("sample")?;
        if self.retired || self.refuse_sample {
            return Err(QErr::BoundaryViolation {
                message: String::from("original replay node cannot be sampled"),
            });
        }
        self.inner.sample_fingerprint(node)
    }

    fn shutdown(&mut self) -> Result<Vec<crucible::SchedulerEventLogEntry>, QErr> {
        self.record("shutdown")?;
        if self.refuse_shutdown {
            return Err(QErr::BoundaryViolation {
                message: String::from("original replay node retirement refused"),
            });
        }
        self.retired = true;
        Ok(Vec::new())
    }
}

fn replay_engine(
    initial: &crucible::Configuration,
    quantum_loop: RetiringLoop,
) -> Result<crucible_session::Engine<RetiringLoop>, Box<dyn Error>> {
    let checkpoint = crucible::Checkpoint::from_recorded_configuration(
        initial,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        crucible::CheckpointKind::Fat,
        BTreeMap::new(),
    )?;
    let graph = crucible::TemporalGraph::empty()
        .with_baked_genesis(&initial.def, crucible::GenesisCheckpoint { checkpoint })?;
    Ok(crucible_session::Engine::new(
        initial.clone(),
        graph,
        quantum_loop,
    ))
}

struct CapturedTerminalArtifact {
    artifact: crucible_session::SessionControlReplayArtifact,
    nodes: Vec<crucible::NodeId>,
    samples: Vec<crucible::FingerprintSample>,
}

fn captured_terminal_artifact() -> Result<CapturedTerminalArtifact, Box<dyn Error>> {
    let scenario = crucible::happy_path_scenario()?.scenario;
    let initial = crucible::Configuration::genesis(scenario.scenario_def());
    let operations = Arc::new(Mutex::new(Vec::new()));
    let mut producer = replay_engine(&initial, RetiringLoop::new(operations))?;
    producer.apply_command(crucible_session::SessionCommand::Start)?;
    producer.apply_command(crucible_session::SessionCommand::Continue)?;
    producer.apply_command(crucible_session::SessionCommand::Pause)?;
    let mut nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    let mut samples = Vec::new();
    for node in &nodes {
        let (reply, mut receiver) = crucible_session::CommandReply::channel();
        producer.apply_command(crucible_session::SessionCommand::Query {
            kind: crucible_session::QueryKind::ExecutionFingerprint { node: node.clone() },
            reply,
        })?;
        let crucible_session::QueryResult::ExecutionFingerprint(sample) = receiver.try_recv()??
        else {
            return Err("producer fingerprint query returned unexpected payload".into());
        };
        samples.push(sample);
    }
    producer.apply_command(crucible_session::SessionCommand::Stop)?;
    Ok(CapturedTerminalArtifact {
        artifact: producer.control_replay_artifact(initial),
        nodes,
        samples,
    })
}

#[test]
fn interactive_replay_terminal_samples_precede_genuine_stop_without_run()
-> Result<(), Box<dyn Error>> {
    let CapturedTerminalArtifact {
        artifact,
        nodes,
        samples: expected_samples,
    } = captured_terminal_artifact()?;
    let operations = Arc::new(Mutex::new(Vec::new()));
    let engine = replay_engine(
        &artifact.initial_configuration,
        RetiringLoop::new(operations.clone()),
    )?;
    let (_sender, receiver) = tokio::sync::mpsc::channel(64);

    let (actor, samples) = replay_interactive_terminal_actor(engine, receiver, &artifact, &nodes)?;

    assert_eq!(samples, expected_samples);
    assert_eq!(actor.engine().snapshot(), artifact.final_snapshot);
    assert_eq!(actor.engine().boundary_control_log(), artifact.control_log);
    assert_eq!(actor.reproduction_log().snapshot(), artifact.control_log);
    assert_eq!(artifact.final_snapshot.quanta, 0);
    let mut expected = vec!["sample"; nodes.len()];
    expected.push("shutdown");
    assert_eq!(
        *operations.lock().map_err(|_| "operations lock poisoned")?,
        expected
    );

    // The ordinary replay method still executes Stop and retires sampling
    // authority. This is the same ownership order that caused the physical failure.
    let mut engine = replay_engine(
        &artifact.initial_configuration,
        RetiringLoop::new(Arc::new(Mutex::new(Vec::new()))),
    )?;
    engine.replay_control_replay_artifact(&artifact)?;
    assert!(
        engine
            .apply_command(crucible_session::SessionCommand::Query {
                kind: crucible_session::QueryKind::ExecutionFingerprint {
                    node: nodes[0].clone()
                },
                reply: crucible_session::CommandReply::discard(),
            })
            .is_err()
    );
    Ok(())
}

#[test]
fn interactive_replay_terminal_sampling_refusal_executes_stop_and_preserves_cleanup_error()
-> Result<(), Box<dyn Error>> {
    let CapturedTerminalArtifact {
        artifact, nodes, ..
    } = captured_terminal_artifact()?;
    for refuse_shutdown in [false, true] {
        let operations = Arc::new(Mutex::new(Vec::new()));
        let mut quantum_loop = RetiringLoop::new(operations.clone());
        quantum_loop.refuse_sample = true;
        quantum_loop.refuse_shutdown = refuse_shutdown;
        let engine = replay_engine(&artifact.initial_configuration, quantum_loop)?;
        let (_sender, receiver) = tokio::sync::mpsc::channel(64);

        let error = replay_interactive_terminal_actor(engine, receiver, &artifact, &nodes)
            .err()
            .ok_or("refused sampling must fail interactive replay")?;

        let message = error.to_string();
        assert!(message.contains("original replay node cannot be sampled"));
        assert_eq!(
            message.contains("original replay node retirement refused"),
            refuse_shutdown
        );
        assert_eq!(
            *operations.lock().map_err(|_| "operations lock poisoned")?,
            vec!["sample", "shutdown"]
        );
    }
    Ok(())
}
