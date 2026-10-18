//! Exact network-output yield and causal publication regressions.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;

#[path = "network_output/topology.rs"]
mod topology;

#[path = "network_output/preemption.rs"]
mod preemption;

// The peer's RUN ceiling stays before either TX's earliest possible delivery.
const NETWORK_PREFIX_TEST_MINIMUM_LATENCY: u64 = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetworkRouteAdmission {
    source: NodeId,
    route_tick: u64,
    condition_prefix_tick: u64,
}

#[derive(Clone)]
struct RecordingNetworkRouteInterceptor(Rc<RefCell<Vec<NetworkRouteAdmission>>>);

impl BackendNetworkOutputInterceptor<SingleScheduler, TestConcurrentBackend>
    for RecordingNetworkRouteInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        loop_impl: &mut SingleScheduler,
        _backend: &mut TestConcurrentBackend,
        _frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        for output in outputs.iter() {
            let route_tick = loop_impl
                .network_output_emit_time(output, &BTreeMap::new())?
                .ticks;
            self.0.borrow_mut().push(NetworkRouteAdmission {
                source: output.source.clone(),
                route_tick,
                condition_prefix_tick: loop_impl.condition_event_log_prefix().point().at().ticks,
            });
        }
        // This test double owns the route; the scheduler must not require a
        // World link to observe whether its condition prefix has passed TX.
        outputs.clear();
        Ok(Vec::new())
    }
}

#[test]
fn one_run_admits_tx_before_its_node_local_emit_overtakes_the_frontier() {
    let scheduler = test_scheduler(
        vec![
            test_scenario_node(
                "source",
                50,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration {
                    ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                }),
                ExactLocalEvent::NoArmedTimer,
            ),
            test_scenario_node(
                "z-peer",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration {
                    ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                }),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    );
    let admissions = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        TestConcurrentBackend::new(false).with_network_output("source", 55),
        RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
    );
    let configuration = adapter.loop_impl().configuration().clone();
    let first = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect("source RUN should admit its exact output-yield boundary");

    assert_eq!(first.run_set.candidates.len(), 1);
    assert_eq!(first.run_set.candidates[0].node.node.name, "source");
    assert_eq!(first.run_set.candidates[0].max_advance_icount, 64);
    assert!(
        first.run_set.candidates[0].max_advance_icount <= 55 + NETWORK_PREFIX_TEST_MINIMUM_LATENCY
    );
    assert_eq!(first.outcomes[0].frontier.ticks, 0);
    assert_eq!(first.outcomes.len(), 3);
    assert_eq!(
        first
            .outcomes
            .last()
            .expect("fully settled union")
            .frontier
            .ticks,
        64
    );
    assert_eq!(adapter.pending_network_output_count(), 0);
    assert_eq!(admissions.borrow().len(), 1);
    let recorded = admissions.borrow();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].source.name, "source");
    assert_eq!(recorded[0].route_tick, 55);
    assert!(
        recorded[0].condition_prefix_tick <= recorded[0].route_tick,
        "a later node-local EMIT must not precede the earlier network route: {recorded:?}"
    );
}

#[test]
fn omitted_lagging_peer_output_precedes_source_candidate() {
    let scheduler = test_scheduler(
        vec![
            test_scenario_node(
                "source",
                50,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration {
                    ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                }),
                ExactLocalEvent::NoArmedTimer,
            ),
            test_scenario_node(
                "z-peer",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration {
                    ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                }),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    );
    let admissions = Rc::new(RefCell::new(Vec::new()));
    let backend = TestConcurrentBackend::new(false)
        .with_network_output("source", 55)
        .with_network_output("z-peer", 30);
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
    );

    for _ in 0..4 {
        let configuration = adapter.loop_impl().configuration().clone();
        adapter
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
                2,
            )
            .expect("lagging peer and source output should remain orderable");
        if admissions.borrow().len() == 2 {
            break;
        }
    }

    let recorded = admissions.borrow();
    assert_eq!(
        recorded
            .iter()
            .map(|entry| entry.route_tick)
            .collect::<Vec<_>>(),
        [30, 55]
    );
    assert!(
        recorded
            .iter()
            .all(|entry| entry.condition_prefix_tick <= entry.route_tick)
    );
}

#[test]
fn omitted_producer_gets_a_fresh_ceiling_after_its_watermark_catchup() {
    let scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "network-output-omitted-producer-catchup",
        16,
        SimInstant { ticks: 100 },
        ["a-source", "b-source", "z-peer"]
            .into_iter()
            .map(|name| {
                test_scenario_node(
                    name,
                    0,
                    SchedulerNodeActivity::Runnable,
                    if name == "z-peer" {
                        NetworkLookahead::Infinite
                    } else {
                        NetworkLookahead::Finite(SimDuration {
                            ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                        })
                    },
                    if name == "z-peer" {
                        ExactLocalEvent::NoArmedTimer
                    } else {
                        ExactLocalEvent::TimerDeadline {
                            virtual_time: SimInstant { ticks: 64 },
                        }
                    },
                )
            })
            .collect(),
        Vec::new(),
    ))
    .expect("three-node catch-up scenario should build");
    let admissions = Rc::new(RefCell::new(Vec::new()));
    let backend = TestConcurrentBackend::new(false)
        .with_network_output("a-source", 30)
        .with_network_output("b-source", 60);
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
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
        .expect("omitted producer should receive a fresh authorized catch-up RUN");

    assert_eq!(batch.run_set.candidates.len(), 2);
    assert!(
        batch
            .run_set
            .candidates
            .iter()
            .all(|run| run.max_advance_icount == 64)
    );
    assert_eq!(
        admissions
            .borrow()
            .iter()
            .map(|entry| (entry.source.name.as_str(), entry.route_tick))
            .collect::<Vec<_>>(),
        [("a-source", 30), ("b-source", 60)],
    );
    assert!(
        admissions
            .borrow()
            .iter()
            .all(|entry| entry.condition_prefix_tick <= entry.route_tick)
    );
    assert_eq!(
        adapter
            .backend()
            .run_history
            .iter()
            .filter(|run| run.node().name == "z-peer")
            .map(|run| run.ceiling().ticks)
            .collect::<Vec<_>>(),
        [30, 100],
    );
}

#[test]
fn concurrent_batch_admits_first_tx_before_later_run_emit() {
    let scheduler = test_scheduler(
        ["source", "z-peer"]
            .into_iter()
            .map(|name| {
                test_scenario_node(
                    name,
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Finite(SimDuration {
                        ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                    }),
                    ExactLocalEvent::NoArmedTimer,
                )
            })
            .collect(),
        Vec::new(),
    );
    let admissions = Rc::new(RefCell::new(Vec::new()));
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        TestConcurrentBackend::new(false).with_network_output("source", 32),
        RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
    );
    let configuration = adapter.loop_impl().configuration().clone();
    let outcome = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect("both canonical RUNs and the first network output should complete");

    assert_eq!(outcome.run_set.candidates.len(), 2);
    assert!(
        outcome
            .run_set
            .candidates
            .iter()
            .all(|candidate| candidate.max_advance_icount == 64)
    );
    assert_eq!(
        outcome.outcomes[0]
            .advanced_node
            .as_ref()
            .map(|node| node.node.name.as_str()),
        Some("source")
    );
    assert_eq!(outcome.outcomes[0].frontier.ticks, 0);
    assert_eq!(outcome.outcomes.len(), 3);
    assert_eq!(
        outcome.outcomes[1]
            .advanced_node
            .as_ref()
            .map(|node| node.node.name.as_str()),
        Some("source")
    );
    assert_eq!(outcome.outcomes[1].frontier.ticks, 0);
    assert_eq!(
        outcome.outcomes[2]
            .advanced_node
            .as_ref()
            .map(|node| node.node.name.as_str()),
        Some("z-peer")
    );
    assert_eq!(outcome.outcomes[2].frontier.ticks, 64);
    assert!(
        outcome.run_set.candidates[1].max_advance_icount
            <= 32 + NETWORK_PREFIX_TEST_MINIMUM_LATENCY
    );
    let recorded = admissions.borrow();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].source.name, "source");
    assert_eq!(recorded[0].route_tick, 32);
    assert!(
        recorded[0].condition_prefix_tick <= recorded[0].route_tick,
        "the batch's later EMIT must not precede the first network route: {recorded:?}"
    );
}

#[test]
fn consecutive_source_outputs_precede_held_peer_emit() {
    let scheduler = test_scheduler(
        ["source", "z-peer"]
            .into_iter()
            .map(|name| {
                test_scenario_node(
                    name,
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Finite(SimDuration {
                        ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                    }),
                    ExactLocalEvent::NoArmedTimer,
                )
            })
            .collect(),
        Vec::new(),
    );
    let admissions = Rc::new(RefCell::new(Vec::new()));
    let backend = TestConcurrentBackend::new(false)
        .with_network_output("source", 32)
        .with_network_output("source", 33);
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
    );

    let configuration = adapter.loop_impl().configuration().clone();
    let outcome = adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect("source outputs should admit before the peer's later EMIT");

    let recorded = admissions.borrow();
    assert_eq!(
        recorded
            .iter()
            .map(|entry| entry.route_tick)
            .collect::<Vec<_>>(),
        [32, 33]
    );
    assert!(
        recorded
            .iter()
            .all(|entry| entry.condition_prefix_tick <= entry.route_tick),
        "the peer's later EMIT must await every earlier source output: {recorded:?}"
    );
    let boundary_times = outcome
        .outcomes
        .iter()
        .flat_map(|quantum| &quantum.event_log_entries)
        .filter(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::EvaluationBoundary(
                    SchedulerEvaluationBoundaryKind::Quantum
                )
            )
        })
        .map(|entry| entry.at().ticks)
        .collect::<Vec<_>>();
    assert_eq!(boundary_times, [32, 33, 64, 64]);
}

#[test]
fn same_tick_outputs_follow_node_identity_across_registration_and_worker_order() {
    for (source, peer) in [("a-source", "z-peer"), ("z-source", "a-peer")] {
        let expected = if source < peer {
            [source, peer]
        } else {
            [peer, source]
        };
        let mut reference = None;

        for workers in [1, 2] {
            for registration in [[source, peer], [peer, source]] {
                let scheduler = test_scheduler(
                    registration
                        .into_iter()
                        .map(|name| {
                            test_scenario_node(
                                name,
                                0,
                                SchedulerNodeActivity::Runnable,
                                NetworkLookahead::Finite(SimDuration {
                                    ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                                }),
                                ExactLocalEvent::NoArmedTimer,
                            )
                        })
                        .collect(),
                    Vec::new(),
                );
                let admissions = Rc::new(RefCell::new(Vec::new()));
                let backend = TestConcurrentBackend::new(false)
                    .with_network_output(source, 30)
                    .with_network_output(peer, 30);
                let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
                    scheduler,
                    backend,
                    RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
                );
                let configuration = adapter.loop_impl().configuration().clone();
                let outcome = adapter
                    .drive_concurrent_quantum(
                        QuantumRequest {
                            configuration,
                            control: Vec::new(),
                        },
                        workers,
                    )
                    .expect("same-tick physical results should publish canonically");

                let recorded = admissions.borrow();
                assert_eq!(
                    recorded
                        .iter()
                        .map(|entry| entry.source.name.as_str())
                        .collect::<Vec<_>>(),
                    expected,
                );
                assert!(
                    recorded.iter().all(|entry| {
                        entry.route_tick == 30 && entry.condition_prefix_tick <= 30
                    })
                );
                let decisions = outcome
                    .outcomes
                    .iter()
                    .flat_map(|quantum| &quantum.decisions)
                    .cloned()
                    .collect::<Vec<_>>();
                let log = adapter.loop_impl().event_log().retained_entries().to_vec();
                let offset = adapter.loop_impl().event_log_offset();
                let result = (decisions, log, offset);
                if let Some(reference) = &reference {
                    assert_eq!(&result, reference);
                } else {
                    reference = Some(result);
                }
            }
        }
    }
}

#[test]
fn early_source_reselection_preserves_same_tick_peer_before_next_source_output() {
    for workers in [1, 2] {
        let scheduler = test_scheduler(
            ["a-source", "z-peer"]
                .into_iter()
                .map(|name| {
                    test_scenario_node(
                        name,
                        0,
                        SchedulerNodeActivity::Runnable,
                        NetworkLookahead::Finite(SimDuration {
                            ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                        }),
                        ExactLocalEvent::NoArmedTimer,
                    )
                })
                .collect(),
            Vec::new(),
        );
        let admissions = Rc::new(RefCell::new(Vec::new()));
        let backend = TestConcurrentBackend::new(false)
            .with_network_output("a-source", 30)
            .with_network_output("a-source", 31)
            .with_network_output("z-peer", 30);
        let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            backend,
            RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
        );

        for _ in 0..3 {
            let configuration = adapter.loop_impl().configuration().clone();
            adapter
                .drive_concurrent_quantum(
                    QuantumRequest {
                        configuration,
                        control: Vec::new(),
                    },
                    workers,
                )
                .expect("source reselection must keep the peer's same-tick route");
            if admissions.borrow().len() == 3 {
                break;
            }
        }

        let recorded = admissions.borrow();
        assert_eq!(
            recorded
                .iter()
                .map(|entry| (entry.source.name.as_str(), entry.route_tick))
                .collect::<Vec<_>>(),
            [("a-source", 30), ("z-peer", 30), ("a-source", 31)],
        );
        assert!(
            recorded
                .iter()
                .all(|entry| entry.condition_prefix_tick <= entry.route_tick)
        );
        assert!(
            adapter
                .backend()
                .run_history
                .iter()
                .filter(|run| run.node().name == "a-source")
                .count()
                >= 2
        );
    }
}

fn same_tick_choice_scheduler(source: &str, peer: &str) -> SingleScheduler {
    let sink = NodeId {
        name: String::from("zz-sink"),
    };
    let nodes = [source, peer]
        .into_iter()
        .map(|name| {
            test_scenario_node(
                name,
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Finite(SimDuration {
                    ticks: NETWORK_PREFIX_TEST_MINIMUM_LATENCY,
                }),
                ExactLocalEvent::NoArmedTimer,
            )
        })
        .chain(std::iter::once(test_scenario_node(
            "zz-sink",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )))
        .collect();
    let mut scheduler = test_scheduler(nodes, Vec::new());

    for name in [source, peer] {
        let sender = NodeId {
            name: name.to_owned(),
        };
        let link_id = scheduler_link_id_for_nodes(&sender, &sink);
        let direction = NetworkLinkDirection::EndpointAToEndpointB;
        let faults = crucible_device::LinkFaults {
            loss: crucible_device::Probability::new(1, 2),
            ..crucible_device::LinkFaults::none()
        };
        let link =
            crucible_device::NetLink::new(0, 64, 1, faults).expect("choice link should build");
        scheduler.world_network_links.insert(
            (link_id.clone(), direction),
            WorldNetworkLinkRuntime {
                canonical_id: link_id.clone(),
                endpoint_a: sender,
                endpoint_b: sink.clone(),
                direction,
                scheduler_node: scheduler_node(name, SchedulingNodeKind::Network),
                rng_stream: RngStreamId::for_link(link_id.name.clone()),
                fault_id: crate::DeviceId::from_name(name),
                link,
            },
        );
        scheduler.world_network_rng_positions.insert(link_id, 0);
    }
    scheduler
}

#[test]
fn same_tick_peer_evidence_survives_a_selectable_offer_until_default_settlement() {
    for (source, peer, first) in [
        ("a-source", "z-peer", "a-source"),
        ("z-source", "a-peer", "a-peer"),
    ] {
        let scheduler = same_tick_choice_scheduler(source, peer);
        let backend = TestConcurrentBackend::new(false)
            .with_network_output_to(source, "zz-sink", 30)
            .with_network_output_to(peer, "zz-sink", 30);
        let mut adapter = BackendQuantumLoop::new(scheduler, backend);
        adapter.set_live_network_choice_pause(true);

        let configuration = adapter.loop_impl().configuration().clone();
        let offered = adapter
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
                2,
            )
            .expect("the first canonical choice should retain peer evidence");
        assert_eq!(offered.run_set.candidates.len(), 1);
        assert_eq!(
            adapter
                .live_network_preselection()
                .map(|choice| choice.output.source.name.as_str()),
            Some(first),
        );
        let held_node = if first == source { peer } else { source };
        let held_token = adapter
            .backend()
            .run_history
            .iter()
            .rev()
            .find(|run| run.node().name == held_node)
            .expect("actual retained peer RUN")
            .admission
            .control_token();
        let held_node_runs = adapter
            .backend()
            .run_history
            .iter()
            .filter(|run| {
                run.node().name == held_node && run.admission.control_token() == held_token
            })
            .count();

        let settled = adapter
            .settle_host_live_network_preselection()
            .expect("default settlement should consume the first frame and release its peer");
        assert!(settled.len() >= 2);
        assert_eq!(
            adapter
                .backend()
                .run_history
                .iter()
                .filter(|run| run.node().name == held_node
                    && run.admission.control_token() == held_token)
                .count(),
            held_node_runs,
            "the exact held peer RUN must not execute again after settlement",
        );
        assert_eq!(
            adapter
                .live_network_preselection()
                .map(|choice| choice.output.source.name.as_str()),
            Some(if first == source { peer } else { source }),
        );
        let last = adapter
            .settle_host_live_network_preselection()
            .expect("the second same-time choice should settle without replaying QEMU");
        assert!(!last.is_empty());
        assert_eq!(
            adapter
                .backend()
                .run_history
                .iter()
                .filter(|run| run.node().name == held_node
                    && run.admission.control_token() == held_token)
                .count(),
            held_node_runs,
        );
        assert!(adapter.live_network_preselection().is_none());
        assert_eq!(
            settled
                .iter()
                .chain(&last)
                .flat_map(|outcome| &outcome.decisions)
                .filter(|decision| matches!(decision, Decision::Selection(_)))
                .count(),
            2,
        );
        let boundary_times = adapter
            .loop_impl()
            .event_log()
            .retained_entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::EvaluationBoundary(
                        SchedulerEvaluationBoundaryKind::Quantum
                    )
                )
            })
            .map(|entry| entry.at().ticks)
            .collect::<Vec<_>>();
        assert!(boundary_times.iter().filter(|&&at| at == 30).count() >= 2);
        assert!(boundary_times.windows(2).all(|times| times[0] <= times[1]));
    }
}

#[test]
fn same_tick_held_evidence_is_discarded_only_with_preselection_world_shutdown() {
    let scheduler = same_tick_choice_scheduler("a-source", "z-peer");
    let backend = TestConcurrentBackend::new(false)
        .with_network_output_to("a-source", "zz-sink", 30)
        .with_network_output_to("z-peer", "zz-sink", 30);
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);

    let configuration = adapter.loop_impl().configuration().clone();
    adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect("first choice should keep one completed peer RUN private");
    let choice = adapter
        .live_network_preselection()
        .cloned()
        .expect("same-time source choice should be offered");
    let physical_runs = adapter.backend().run_history.clone();

    adapter
        .handoff_live_network_preselection(&choice)
        .expect("the exact offered choice should authenticate for handoff");
    adapter
        .shutdown()
        .expect("whole-world shutdown should discard withheld physical evidence");
    assert!(adapter.live_network_preselection().is_none());
    assert_eq!(adapter.backend().run_history, physical_runs);
}

#[test]
fn selected_same_tick_choice_releases_held_peer_once() {
    let scheduler = same_tick_choice_scheduler("a-source", "z-peer");
    let backend = TestConcurrentBackend::new(false)
        .with_network_output_to("a-source", "zz-sink", 30)
        .with_network_output_to("z-peer", "zz-sink", 30);
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);

    let configuration = adapter.loop_impl().configuration().clone();
    adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .expect("first selectable should retain the peer");
    let choice = adapter
        .live_network_preselection()
        .cloned()
        .expect("first selectable should be offered");
    let selection = choice
        .frontier
        .choices
        .choices()
        .iter()
        .find_map(|alternative| match alternative.decisions().first() {
            Some(Decision::Selection(selection)) => Some(selection.clone()),
            _ => None,
        })
        .expect("a typed branch should be offered");
    adapter
        .select_live_network_preselection(selection)
        .expect("the exact offered branch should select");
    let held_runs = adapter
        .backend()
        .run_history
        .iter()
        .filter(|run| run.node().name == "z-peer")
        .count();

    adapter
        .settle_host_live_network_preselection()
        .expect("selected route should release the held peer at the same tick");
    assert_eq!(
        adapter
            .live_network_preselection()
            .map(|choice| choice.output.source.name.as_str()),
        Some("z-peer"),
    );
    assert_eq!(
        adapter
            .backend()
            .run_history
            .iter()
            .filter(|run| run.node().name == "z-peer")
            .count(),
        held_runs,
    );
}
