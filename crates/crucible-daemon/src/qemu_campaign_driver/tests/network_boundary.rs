//! Exact all-VM network phase boundary and discovery regressions.

use super::*;

#[test]
fn same_named_network_scenario_without_boot_capability_stays_serial() {
    let scenario = network_choice_scenario(&[
        "router-a",
        "router-b",
        "router-c",
        "traffic-east",
        "traffic-west",
    ]);
    let input = input_for_scenario(scenario, StopCondition::NextChoice);

    assert!(!envoy_choice_free_boot_eligible(&input));
}

struct NetworkBoundaryLifecycle {
    parked: BTreeMap<NodeId, QemuParkedCampaignMarker>,
    released: Vec<NodeId>,
    release_proofs: BTreeSet<(NodeId, String, ContentHash)>,
    checkpoint_ready: bool,
    queues_empty: bool,
}

impl NetworkBoundaryLifecycle {
    fn parked(nodes: &[(&str, u64)], marker: &str) -> Self {
        let parked = nodes
            .iter()
            .map(|(name, retired)| {
                (
                    node(name),
                    QemuParkedCampaignMarker {
                        marker: marker.to_owned(),
                        marker_icount: Icount { retired: *retired },
                        physical_icount: Icount {
                            retired: retired + 1,
                        },
                    },
                )
            })
            .collect();
        Self {
            parked,
            released: Vec::new(),
            release_proofs: BTreeSet::new(),
            checkpoint_ready: true,
            queues_empty: true,
        }
    }
}

impl QemuModeledAttemptLifecycle for NetworkBoundaryLifecycle {
    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("boundary fixture cannot drive QEMU"),
        })
    }

    fn completed_quanta(&self) -> u64 {
        0
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(self.checkpoint_ready)
    }

    fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        Ok(self.parked.get(node).cloned())
    }

    fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        match self.parked.remove(node) {
            Some(proof) if proof.marker == marker => {
                self.released.push(node.clone());
                self.release_proofs
                    .insert((node.clone(), marker.to_owned(), selected));
                Ok(())
            }
            _ => Err(SchedulerError::BoundaryViolation {
                message: String::from("missing matching marker park"),
            }),
        }
    }

    fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        Ok(self
            .release_proofs
            .contains(&(node.clone(), marker.to_owned(), selected)))
    }

    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        Ok(self.queues_empty)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: SelectionDecision,
        _selected: &Configuration,
        _pending: &QemuNodeSelectablePendingRequest,
        _reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("boundary fixture has no selectable reply"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("boundary fixture has no fingerprint"),
        })
    }
}

#[test]
fn network_fault_marker_rejects_a_frame_before_the_quiescent_barrier() {
    let mut log = EventLog::new();
    let marker = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 10 },
            node("node-a"),
            MarkerId::from_name("fault.transport.ready"),
        )])
        .expect("test ready marker");
    let frame = log
        .append_observable_events([ObservableEvent::network_delivered(
            VirtualTime { ticks: 10 },
            None,
            b"frame-after-marker".to_vec(),
        )])
        .expect("test frame delivery");

    assert!(
        validate_network_fault_boundary(
            marker.entries[0].sequence(),
            VirtualTime { ticks: 10 },
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
            0,
            &marker.entries,
            &frame.entries,
        )
        .is_err()
    );
    assert!(
        validate_network_fault_boundary(
            marker.entries[0].sequence(),
            VirtualTime { ticks: 10 },
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
            0,
            &marker.entries,
            &[],
        )
        .is_ok()
    );
}

#[test]
fn ready_marker_discovers_the_same_public_network_choice_on_repeat() {
    let scenario = network_choice_scenario(&["router-a"]);
    let input = input_for_scenario(scenario, StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let marker = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 10 },
            node("router-a"),
            MarkerId::from_name("fault.transport.ready"),
        )])
        .expect("ready marker");
    let mut lifecycle =
        NetworkBoundaryLifecycle::parked(&[("router-a", 10)], "fault.transport.ready");
    let quiescence = SchedulerQuiescence::default();

    let first = next_network_fault_discovery(
        &mut lifecycle,
        &input,
        &configuration,
        &[],
        &marker.entries,
        VirtualTime { ticks: 10 },
        Some(&quiescence),
    )
    .expect("first discovery")
    .expect("network choice");
    let repeated = next_network_fault_discovery(
        &mut lifecycle,
        &input,
        &configuration,
        &marker.entries,
        &[],
        VirtualTime { ticks: 10 },
        Some(&quiescence),
    )
    .expect("repeat discovery")
    .expect("network choice");
    assert_eq!(first, repeated);
    assert_eq!(first.declaration().name(), "fault.network");
}

#[test]
fn selected_network_group_releases_the_exact_parked_phase() {
    let scenario = network_choice_scenario(&["router-a"]);
    let parent = Configuration::genesis(scenario.scenario_def());
    let selectable = NetworkFaultSelectable::next(
        &scenario,
        &parent,
        NetworkFaultPhase::First,
        VirtualTime { ticks: 10 },
        &[],
    )
    .expect("first environment group")
    .expect("declared network group");
    let value = NetworkFaultSelectable::selected_value("packet_loss", "primary", 1_000, 0, 0)
        .expect("benign complete tuple");
    let branch = selectable
        .resolve_branch(&selectable.branch_selection(value).expect("group selection"))
        .expect("selected branch");
    let selected = branch.selected().clone();
    let replay = crucible::SignalFaultCampaignReplayPlan::empty(selected.clone())
        .with_network_branches(vec![branch])
        .expect("exact network branch prefix");
    let input = input_for_configuration(scenario, selected.clone(), StopCondition::NextChoice)
        .with_test_signal_fault_replay(replay);
    let mut lifecycle =
        NetworkBoundaryLifecycle::parked(&[("router-a", 10)], "fault.transport.ready");
    let mut log = EventLog::new();
    let entries = network_phase_marker(&mut log, "router-a", 10);

    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &selected,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .expect("selected branch releases boundary")
        .is_none()
    );
    assert_eq!(lifecycle.released, vec![node("router-a")]);
    assert!(lifecycle.parked.is_empty());
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &selected,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .expect("checkpointed release proof admits resumed selected phase")
        .is_none()
    );

    let mut vanished = NetworkBoundaryLifecycle::parked(&[], "fault.transport.ready");
    assert!(
        next_network_fault_discovery(
            &mut vanished,
            &input,
            &selected,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .is_err(),
        "a selected child cannot infer release from a missing park"
    );
}

#[test]
fn network_choice_waits_for_every_parked_vm_marker() {
    let names = ["router-a", "router-b", "router-c", "west", "east"];
    let scenario = network_choice_scenario(&names);
    let input = input_for_scenario(scenario, StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let mut lifecycle =
        NetworkBoundaryLifecycle::parked(&[("router-a", 10)], "fault.transport.ready");
    let mut log = EventLog::new();
    let first = network_phase_marker(&mut log, "router-a", 10);

    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &first,
            VirtualTime { ticks: 10 },
            None,
        )
        .expect("a staggered phase remains live")
        .is_none()
    );
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &first,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .expect("scheduler quiescence does not complete a partial semantic boundary")
        .is_none()
    );

    lifecycle =
        NetworkBoundaryLifecycle::parked(&names.map(|name| (name, 10)), "fault.transport.ready");
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &first,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .is_err()
    );

    let mut entries = first;
    for name in &names[1..] {
        entries.extend(network_phase_marker(&mut log, name, 10));
    }
    let discovered = next_network_fault_discovery(
        &mut lifecycle,
        &input,
        &configuration,
        &[],
        &entries,
        VirtualTime { ticks: 10 },
        Some(&SchedulerQuiescence::default()),
    )
    .expect("all VMs reached the exact parked boundary")
    .expect("one atomic network choice");
    assert_eq!(discovered.declaration().name(), "fault.network");
}

#[test]
fn network_choice_rejects_duplicate_unknown_and_stale_physical_markers() {
    let scenario = network_choice_scenario(&["router-a", "router-b"]);
    let input = input_for_scenario(scenario, StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let mut entries = network_phase_marker(&mut log, "router-a", 10);
    entries.extend(network_phase_marker(&mut log, "router-b", 10));
    let mut lifecycle = NetworkBoundaryLifecycle::parked(
        &[("router-a", 10), ("router-b", 10)],
        "fault.transport.ready",
    );
    let quiescence = SchedulerQuiescence::default();

    lifecycle
        .parked
        .get_mut(&node("router-b"))
        .expect("parked B")
        .physical_icount = Icount { retired: 12 };
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&quiescence),
        )
        .is_err()
    );

    lifecycle
        .parked
        .get_mut(&node("router-b"))
        .expect("parked B")
        .physical_icount = Icount { retired: 11 };
    let mut duplicate = entries.clone();
    duplicate.extend(network_phase_marker(&mut log, "router-a", 10));
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &duplicate,
            VirtualTime { ticks: 10 },
            Some(&quiescence),
        )
        .is_err()
    );

    let mut unknown = entries.clone();
    unknown.extend(network_phase_marker(&mut log, "router-d", 10));
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &unknown,
            VirtualTime { ticks: 10 },
            Some(&quiescence),
        )
        .is_err()
    );

    lifecycle.queues_empty = false;
    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&quiescence),
        )
        .is_err()
    );
}

#[test]
fn lifecycle_without_marker_proof_cannot_publish_network_choice() {
    let input = input_for_scenario(
        network_choice_scenario(&["router-a"]),
        StopCondition::NextChoice,
    );
    let configuration = starting_configuration(&input);
    let mut lifecycle = TerminalCrossingLifecycle {
        configuration: configuration.clone(),
        attempt_stop_frontier: None,
        completed_quanta: 0,
        terminal: false,
    };
    let mut log = EventLog::new();
    let entries = network_phase_marker(&mut log, "router-a", 10);

    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .is_err()
    );
}

#[test]
fn incidental_same_name_marker_is_inert_without_network_declaration() {
    let declared = network_choice_scenario(&["router-a"]);
    let scenario = ScenarioDefForm::from_components(
        declared.world(),
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(20),
    )
    .expect("scenario without fault declaration");
    let input = input_for_scenario(scenario, StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let mut lifecycle = TerminalCrossingLifecycle {
        configuration: configuration.clone(),
        attempt_stop_frontier: None,
        completed_quanta: 0,
        terminal: false,
    };
    let mut log = EventLog::new();
    let entries = network_phase_marker(&mut log, "router-a", 10);

    assert!(
        next_network_fault_discovery(
            &mut lifecycle,
            &input,
            &configuration,
            &[],
            &entries,
            VirtualTime { ticks: 10 },
            Some(&SchedulerQuiescence::default()),
        )
        .expect("undeclared fault marker is inert")
        .is_none()
    );
}

fn network_phase_marker(
    log: &mut EventLog,
    name: &str,
    retired: u64,
) -> Vec<SchedulerEventLogEntry> {
    log.append_observable_events([ObservableEvent::guest_marker(
        Icount { retired },
        node(name),
        MarkerId::from_name("fault.transport.ready"),
    )])
    .expect("network phase marker")
    .entries
}

fn network_choice_scenario(names: &[&str]) -> ScenarioDefForm {
    let nodes = names
        .iter()
        .map(|name| WorldNode {
            id: node(name),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::from("network-choice-driver-test"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        })
        .collect();
    let world = World::from_nodes(nodes).expect("network choice world");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(20),
    )
    .expect("network choice scenario")
    .with_selectables(selectables)
    .expect("attach network selectables")
}
