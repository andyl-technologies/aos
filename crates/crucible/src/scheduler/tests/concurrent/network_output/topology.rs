//! Topology authorization fences around held physical RUN evidence.

use super::*;

#[derive(Clone)]
struct TopologyChangingRouteInterceptor;

impl BackendNetworkOutputInterceptor<SingleScheduler, TestConcurrentBackend>
    for TopologyChangingRouteInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        scheduler: &mut SingleScheduler,
        _backend: &mut TestConcurrentBackend,
        _frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        if !outputs.is_empty() {
            scheduler.schedule_topology_change(SchedulerTopologyChange::new(
                1,
                SchedulerTopologyChangeTrigger::LatencyChange,
                vec![SchedulerLookaheadEdge::new(
                    scheduler_node("a-source", SchedulingNodeKind::Vm),
                    scheduler_node("z-peer", SchedulingNodeKind::Vm),
                    SimDuration { ticks: 1 },
                )],
            ))?;
        }
        outputs.clear();
        Ok(Vec::new())
    }
}

#[test]
fn unexpected_topology_change_rejects_residual_run_before_any_new_physical_work() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "network-output-changed-held-authorization",
        16,
        SimInstant { ticks: 100 },
        ["a-source", "z-peer"]
            .into_iter()
            .map(|name| {
                test_scenario_node(
                    name,
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Finite(SimDuration { ticks: 64 }),
                    ExactLocalEvent::NoArmedTimer,
                )
            })
            .collect(),
        Vec::new(),
    );
    let scheduler = SingleScheduler::new(scenario).expect("held topology scenario should build");
    let backend = TestConcurrentBackend::new(false)
        .with_network_output("a-source", 30)
        .with_network_output("z-peer", 60);
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        TopologyChangingRouteInterceptor,
    );
    let configuration = adapter.loop_impl().configuration().clone();

    let error = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect_err("a new graph cannot authorize residual work against held peer evidence");

    assert!(error.to_string().contains("effective topology changed"));
    assert_eq!(adapter.backend().run_history.len(), 2);
    assert_eq!(adapter.committed_frontier(), VirtualTime { ticks: 0 });
}

#[test]
fn declared_topology_activation_fences_every_physical_run_before_later_tx() {
    let source = scheduler_node("a-source", SchedulingNodeKind::Vm);
    let peer = scheduler_node("z-peer", SchedulingNodeKind::Vm);
    let edge = |latency| {
        SchedulerLookaheadEdge::new(source.clone(), peer.clone(), SimDuration { ticks: latency })
    };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "network-output-topology-activation-fence",
        16,
        SimInstant { ticks: 100 },
        ["a-source", "z-peer"]
            .into_iter()
            .map(|name| {
                test_scenario_node(
                    name,
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Finite(SimDuration { ticks: 64 }),
                    ExactLocalEvent::NoArmedTimer,
                )
            })
            .collect(),
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(64)])
    .with_topology_change(
        SchedulerTopologyChange::new(
            1,
            SchedulerTopologyChangeTrigger::LatencyChange,
            vec![edge(32)],
        )
        .with_activation_time(SimInstant { ticks: 20 }),
    );
    let scheduler = SingleScheduler::new(scenario).expect("topology fence scenario should build");
    let admissions = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        TestConcurrentBackend::new(false).with_network_output("a-source", 30),
        RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
    );

    let configuration = adapter.loop_impl().configuration().clone();
    let batch = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect("declared topology activation should fence the physical batch");

    assert_eq!(batch.run_set.candidates.len(), 2);
    assert!(
        batch
            .run_set
            .candidates
            .iter()
            .all(|run| run.max_advance_icount == 20)
    );
    assert!(
        adapter
            .backend()
            .run_history
            .iter()
            .all(|run| run.ceiling().ticks == 20)
    );
    assert!(admissions.borrow().is_empty());
    assert!(
        adapter
            .loop_impl()
            .topology_change_applications()
            .is_empty()
    );
}
