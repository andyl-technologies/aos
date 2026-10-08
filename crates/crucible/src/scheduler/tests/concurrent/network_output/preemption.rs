//! Armed command ordering across exact output-yield and catch-up boundaries.

use super::*;

#[test]
fn retained_future_command_survives_a_new_control_cap_without_authorizing_a_replacement() {
    let command = PreemptionDecision {
        node: NodeId {
            name: String::from("producer"),
        },
        at: SimInstant { ticks: 80 },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "retained-command-new-global-cap",
        16,
        SimInstant { ticks: 100 },
        vec![test_scenario_node(
            "producer",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    )
    .with_preemption_request(command.clone());
    let mut scheduler = SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("retained command scenario should build: {error}"));
    let first = scheduler
        .prepare_host_catchup_run(0, SimInstant { ticks: 30 })
        .unwrap_or_else(|error| panic!("initial catch-up should preserve future command: {error}"))
        .unwrap_or_else(|| panic!("active producer should have a catch-up RUN"));
    assert_eq!(first.authorized_preemption_horizon, 100);
    assert!(first.preemptions.is_empty());
    scheduler
        .commit_prepared_host_run(first.clone(), 30, &[], Vec::new(), Vec::new())
        .unwrap_or_else(|error| panic!("catch-up should commit at30: {error}"));
    scheduler
        .set_signal_fault_wakeup(Some(40))
        .unwrap_or_else(|error| panic!("new control seam should arm at40: {error}"));

    let mut replacement = scheduler.clone();
    replacement.preemption_requests[0].kind = PreemptionKind::VcpuSwitch {
        from_vcpu: VcpuId { index: 1 },
        to_vcpu: VcpuId { index: 0 },
    };
    let error = replacement
        .prepare_host_catchup_run_after(&first, SimInstant { ticks: 40 })
        .expect_err("a new command cannot inherit the old natural window");
    assert!(error.to_string().contains("outside authorized window"));
    assert!(replacement.preemption_applications().is_empty());
    assert_eq!(replacement.nodes[0].counter.ticks, 30);

    let capped = scheduler
        .prepare_host_catchup_run_after(&first, SimInstant { ticks: 40 })
        .unwrap_or_else(|error| panic!("unchanged command should survive global40: {error}"))
        .unwrap_or_else(|| panic!("producer should advance to the new control cap"));
    assert_eq!(capped.plan.ceiling.max_advance_icount, 40);
    assert_eq!(capped.authorized_preemption_horizon, 100);
    assert!(capped.preemptions.is_empty());
    scheduler
        .commit_prepared_host_run(capped.clone(), 40, &[], Vec::new(), Vec::new())
        .unwrap_or_else(|error| panic!("control cap should commit at40: {error}"));
    assert_eq!(
        scheduler.preemption_requests.as_slice(),
        std::slice::from_ref(&command)
    );
    assert!(scheduler.preemption_applications().is_empty());

    scheduler
        .set_signal_fault_wakeup(None)
        .unwrap_or_else(|error| panic!("settled control seam should clear: {error}"));
    scheduler
        .set_vm_node_activity(&command.node, SchedulerNodeActivity::Runnable)
        .unwrap_or_else(|error| {
            panic!("control settlement should keep the producer runnable: {error}")
        });
    let resumed = scheduler
        .prepare_host_catchup_run_after(&capped, SimInstant { ticks: 100 })
        .unwrap_or_else(|error| panic!("settled seam should retain command authorization: {error}"))
        .unwrap_or_else(|| panic!("producer should resume toward its authorized command"));
    assert_eq!(resumed.plan.ceiling.max_advance_icount, 80);
    assert_eq!(resumed.preemptions.len(), 1);
    assert_eq!(resumed.preemptions[0].decision, command);
    scheduler
        .commit_prepared_host_run(
            resumed,
            80,
            std::slice::from_ref(&command),
            Vec::new(),
            Vec::new(),
        )
        .unwrap_or_else(|error| {
            panic!("actual80 receipt should consume the retained command: {error}")
        });
    assert_eq!(scheduler.preemption_applications().len(), 1);
    assert!(scheduler.preemption_requests.is_empty());
}

#[test]
fn same_tick_tx_and_preemption_preserve_complete_choice_log_across_worker_counts() {
    for (source, peer) in [("a-source", "z-peer"), ("z-source", "a-peer")] {
        let mut reference = None;
        for workers in [1, 2] {
            let mut scheduler = same_tick_choice_scheduler(source, peer);
            let decision = PreemptionDecision {
                node: NodeId {
                    name: source.to_owned(),
                },
                at: SimInstant { ticks: 30 },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
            };
            scheduler.preemption_requests.push(decision.clone());
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
                    workers,
                )
                .expect("same-tick native command and output should stop together");
            let mut outcomes = offered.outcomes;
            while adapter.live_network_preselection().is_some() {
                outcomes.extend(
                    adapter
                        .settle_host_live_network_preselection()
                        .expect("same-tick held choices should settle canonically"),
                );
            }

            assert_eq!(adapter.loop_impl().preemption_applications().len(), 1);
            assert_eq!(
                adapter.loop_impl().preemption_applications()[0].decision,
                decision
            );
            assert!(adapter.loop_impl().preemption_requests.is_empty());
            let decisions = outcomes
                .iter()
                .flat_map(|outcome| outcome.decisions.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                decisions
                    .iter()
                    .filter(|decision| matches!(decision, Decision::Preemption(_)))
                    .count(),
                1,
                "settlement must report the physical application exactly once",
            );
            for entries in [
                outcomes
                    .iter()
                    .flat_map(|outcome| &outcome.event_log_entries)
                    .collect::<Vec<_>>(),
                adapter
                    .loop_impl()
                    .event_log()
                    .retained_entries()
                    .iter()
                    .collect::<Vec<_>>(),
            ] {
                assert_eq!(
                    entries
                        .iter()
                        .filter(|entry| matches!(
                            entry.payload,
                            SchedulerEventLogPayload::Decision(Decision::Preemption(_))
                        ))
                        .count(),
                    1,
                    "returned and retained logs must each contain one application",
                );
            }
            let ordered_actions = decisions
                .iter()
                .filter_map(|decision| match decision {
                    Decision::Preemption(_) => Some("preemption"),
                    Decision::Selection(_) => Some("selection"),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let expected = if source < peer {
                vec!["preemption", "selection", "selection"]
            } else {
                vec!["selection", "preemption", "selection"]
            };
            assert_eq!(
                ordered_actions, expected,
                "native application precedes its source choice; peer order follows NodeId"
            );
            let evidence = (
                decisions,
                adapter.loop_impl().event_log().retained_entries().to_vec(),
                adapter.loop_impl().event_log_offset(),
            );
            if let Some(reference) = &reference {
                assert_eq!(
                    &evidence, reference,
                    "same-tick command/choice ordering must not depend on workers"
                );
            } else {
                reference = Some(evidence);
            }
        }
    }
}

#[test]
fn omitted_producer_keeps_future_command_pending_until_its_natural_horizon() {
    let mut reference = None;
    for workers in [1, 2] {
        let decision = PreemptionDecision {
            node: NodeId {
                name: String::from("z-peer"),
            },
            at: SimInstant { ticks: 80 },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: 0 },
                to_vcpu: VcpuId { index: 1 },
            },
        };
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "network-output-future-catchup-command",
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
                            NetworkLookahead::Finite(SimDuration { ticks: 64 })
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
        )
        .with_preemption_request(decision.clone());
        let scheduler =
            SingleScheduler::new(scenario).expect("future catch-up scenario should build");
        let backend = TestConcurrentBackend::new(false)
            .with_network_output("a-source", 30)
            .with_network_output("b-source", 60)
            .with_network_output("z-peer", 25);
        let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            backend,
            RecordingNetworkRouteInterceptor(Rc::new(RefCell::new(Vec::new()))),
        );
        let configuration = adapter.loop_impl().configuration().clone();

        let batch = adapter
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
                workers,
            )
            .expect("future command should survive every artificial catch-up cap");

        let applications = adapter.loop_impl().preemption_applications();
        assert_eq!(applications.len(), 1);
        assert_eq!(applications[0].decision, decision);
        assert!(adapter.loop_impl().preemption_requests.is_empty());
        assert_eq!(
            adapter
                .backend()
                .run_history
                .iter()
                .flat_map(|run| &run.preemptions)
                .filter(|command| *command == &decision)
                .count(),
            1
        );
        let log = adapter.loop_impl().event_log().retained_entries().to_vec();
        let offset = adapter.loop_impl().event_log_offset();
        let decisions = batch
            .outcomes
            .iter()
            .flat_map(|outcome| outcome.decisions.clone())
            .collect::<Vec<_>>();
        let evidence = (log, offset, decisions);
        if let Some(reference) = &reference {
            assert_eq!(
                &evidence, reference,
                "worker count must not change command or log ordering"
            );
        } else {
            reference = Some(evidence);
        }

        let node_index = adapter
            .loop_impl()
            .nodes
            .iter()
            .position(|node| node.id.node.name == "z-peer")
            .unwrap_or_else(|| panic!("future command node should remain registered"));
        let run = adapter
            .loop_impl_mut()
            .prepare_host_catchup_run(node_index, SimInstant { ticks: 100 })
            .expect("fresh Run after natural horizon preserves one-use command")
            .unwrap_or_else(|| panic!("natural horizon should produce an authorized RUN"));
        assert_eq!(run.plan.ceiling.max_advance_icount, 100);
        assert!(run.preemptions.is_empty());
        assert_eq!(run.authorized_preemption_horizon, 100);
    }
}

#[test]
fn output_yield_before_preemption_defers_the_command_until_the_resumed_run() {
    for preemption_tick in [60] {
        let mut scheduler = test_scheduler(
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
        let preemption = PreemptionDecision {
            node: NodeId {
                name: String::from("source"),
            },
            at: SimInstant {
                ticks: preemption_tick,
            },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: 0 },
                to_vcpu: VcpuId { index: 1 },
            },
        };
        scheduler.preemption_requests.push(preemption.clone());
        let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            TestConcurrentBackend::new(false).with_network_output("source", 55),
            RecordingNetworkRouteInterceptor(Rc::new(RefCell::new(Vec::new()))),
        );

        for expected_applications in [1, 1] {
            let configuration = adapter.loop_impl().configuration().clone();
            adapter
                .drive_concurrent_quantum(
                    QuantumRequest {
                        configuration,
                        control: Vec::new(),
                    },
                    2,
                )
                .expect("output yield and resumed preemption RUN should commit");
            assert_eq!(
                adapter.loop_impl().preemption_applications().len(),
                expected_applications
            );
        }
        assert_eq!(
            adapter.loop_impl().preemption_applications()[0].decision,
            preemption
        );
    }
}

#[test]
fn interior_native_control_commits_before_peer_output_without_retiming_tx() {
    let mut reference = None;
    for workers in [1, 2] {
        let mut scheduler = test_scheduler(
            ["a-source", "b-source"]
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
        let command = PreemptionDecision {
            node: NodeId {
                name: String::from("a-source"),
            },
            at: SimInstant { ticks: 20 },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: 0 },
                to_vcpu: VcpuId { index: 1 },
            },
        };
        scheduler.preemption_requests.push(command.clone());
        let admissions = Rc::new(RefCell::new(Vec::new()));
        let backend = TestConcurrentBackend::new(false)
            .with_network_output("a-source", 60)
            .with_network_output("b-source", 30);
        let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            backend,
            RecordingNetworkRouteInterceptor(Rc::clone(&admissions)),
        );
        let mut decisions = Vec::new();
        for _ in 0..4 {
            let configuration = adapter.loop_impl().configuration().clone();
            let batch = adapter
                .drive_concurrent_quantum(
                    QuantumRequest {
                        configuration,
                        control: Vec::new(),
                    },
                    workers,
                )
                .expect("control boundary20 must precede peerTX30 and sourceTX60");
            decisions.extend(
                batch
                    .outcomes
                    .iter()
                    .flat_map(|outcome| outcome.decisions.clone()),
            );
            if admissions.borrow().len() == 2 {
                break;
            }
        }
        assert_eq!(adapter.loop_impl().preemption_applications().len(), 1);
        assert_eq!(
            adapter.loop_impl().preemption_applications()[0].decision,
            command
        );
        let routes = admissions
            .borrow()
            .iter()
            .map(|route| route.route_tick)
            .collect::<Vec<_>>();
        assert_eq!(routes, [30, 60]);
        assert!(
            admissions
                .borrow()
                .iter()
                .all(|route| route.condition_prefix_tick <= route.route_tick)
        );
        assert_eq!(adapter.backend().run_history[0].ceiling().ticks, 20);
        let entries = adapter.loop_impl().event_log().retained_entries().to_vec();
        let evidence = (decisions, entries, adapter.loop_impl().event_log_offset());
        if let Some(reference) = &reference {
            assert_eq!(&evidence, reference);
        } else {
            reference = Some(evidence);
        }
    }
}
