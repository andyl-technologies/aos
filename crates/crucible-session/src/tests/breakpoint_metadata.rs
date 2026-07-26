//! Breakpoint host predicate and symbol-metadata unit tests.

use super::*;

#[tokio::test]
async fn breakpoint_named_host_predicate_fires_at_no_entry_quantum_boundary() {
    let scenario = generated_scenario(50);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let node = node_id("named-breakpoint-node");
    let predicate = Predicate::named_for_nodes("host.ready", vec![node.clone()]);
    let metadata = BreakpointHostMetadata::new().with_named_predicate(
        BreakpointNamedPredicateKey::new(VirtualTime { ticks: 1 }, "host.ready", vec![node]),
        true,
    );
    let mut engine =
        Engine::new(config, graph, CountingLoop::default()).with_breakpoint_host_metadata(metadata);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("named-predicate breakpoint start should instantiate runtime: {error}");
    }
    let (reply, receiver) = CommandReply::channel();
    if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
        spec: BreakpointSpec::suspend_once(predicate),
        reply,
    }) {
        panic!("named-predicate breakpoint should register: {error}");
    }
    let breakpoint_id = receive_reply(receiver).await;
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("named-predicate breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("named-predicate breakpoint quantum should run: {error}");
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
    assert!(matches!(actor.engine().state(), EngineState::Paused { .. }));
}

#[tokio::test]
async fn breakpoint_symbol_metadata_resolves_coverage_and_memory_leaves() {
    let scenario = generated_scenario(51);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let node = node_id("symbol-breakpoint-node");
    let code_point = CodePoint::symbol("ready_path");
    let mem_place = MemPlace::symbol("cluster_state", MemoryWidth::U8);
    let resolved_code = ResolvedCodePoint::guest_address(0x4010);
    let resolved_mem = ResolvedMemPlace::virtual_address(0x8000, 1);
    let metadata = BreakpointHostMetadata::new()
        .with_resolved_code_point(node.clone(), code_point.clone(), resolved_code)
        .with_resolved_mem_place(node.clone(), mem_place.clone(), resolved_mem.clone());
    let mut engine = Engine::new(
        config,
        graph,
        ScriptedStepLoop::with_payloads(
            1,
            vec![
                SchedulerEventLogPayload::Observable(ObservableEventPayload::CoverageBlock {
                    execution_icount: crucible::Icount { retired: 1 },
                    node: node.clone(),
                    guest_pc: 0x4000,
                    block_len: 0x20,
                }),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::MemorySample {
                    sample_icount: crucible::Icount { retired: 1 },
                    node: node.clone(),
                    place: resolved_mem,
                    value: 7,
                }),
            ],
        ),
    )
    .with_breakpoint_host_metadata(metadata);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("symbol breakpoint start should instantiate runtime: {error}");
    }

    let predicates = [
        Predicate::coverage_point(node.clone(), code_point),
        Predicate::memory_predicate(node, mem_place, MemoryCmp::Eq, 7),
    ];
    let mut breakpoint_ids = Vec::new();
    for predicate in predicates {
        let (reply, receiver) = CommandReply::channel();
        if let Err(error) = engine.apply_command(SessionCommand::SetBreakpoint {
            spec: BreakpointSpec {
                predicate,
                disposition: BreakpointDisposition::Trace,
                policy: BreakpointPolicy::OneShot,
            },
            reply,
        }) {
            panic!("symbol breakpoint should register: {error}");
        }
        breakpoint_ids.push(receive_reply(receiver).await);
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("symbol breakpoint continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("symbol breakpoint quantum should run: {error}");
    }

    assert_eq!(
        actor
            .engine()
            .breakpoint_firings()
            .iter()
            .map(|firing| firing.id)
            .collect::<Vec<_>>(),
        breakpoint_ids
    );
    assert!(actor.engine().breakpoints().is_empty());
}
