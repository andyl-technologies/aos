//! Model checks for explicit guest release and once-only held peer publication.

use super::*;
use crate::{BackendPhysicalStop, HeldHostStopKind, HeldHostStopWitness};
use std::collections::VecDeque;

struct GuestStopBackend {
    base: TestConcurrentBackend,
    stops: BTreeMap<NodeId, VecDeque<(VirtualTime, BackendPhysicalStop)>>,
    held: BTreeMap<NodeId, VirtualTime>,
    counters: BTreeMap<NodeId, VirtualTime>,
    shutdown_calls: usize,
    fail_shutdown: bool,
}

impl Clone for GuestStopBackend {
    fn clone(&self) -> Self {
        Self {
            base: TestConcurrentBackend {
                inner: self.base.inner.clone(),
                control_v3: self.base.control_v3,
                fail: self.base.fail,
                run_sizes: self.base.run_sizes.clone(),
                run_history: self.base.run_history.clone(),
                network_outputs: self.base.network_outputs.clone(),
                retained_dispatch: self.base.retained_dispatch.clone(),
            },
            stops: self.stops.clone(),
            held: self.held.clone(),
            counters: self.counters.clone(),
            shutdown_calls: self.shutdown_calls,
            fail_shutdown: self.fail_shutdown,
        }
    }
}

impl GuestStopBackend {
    fn new(stops: &[(&str, u64, BackendPhysicalStop)]) -> Self {
        let mut scripted = BTreeMap::<NodeId, VecDeque<_>>::new();
        for &(name, ticks, cause) in stops {
            scripted
                .entry(NodeId {
                    name: name.to_owned(),
                })
                .or_default()
                .push_back((VirtualTime { ticks }, cause));
        }
        Self {
            base: TestConcurrentBackend::new(false),
            stops: scripted,
            held: BTreeMap::new(),
            counters: BTreeMap::new(),
            shutdown_calls: 0,
            fail_shutdown: false,
        }
    }

    fn release(&mut self, witness: &HeldHostStopWitness) -> Result<(), SchedulerError> {
        if self.held.get(witness.node()) != Some(&witness.physical_pause()) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("complete fake authority differs from committed stop"),
            });
        }
        self.held.remove(witness.node());
        Ok(())
    }
}

impl SimulationBackend for GuestStopBackend {
    fn io_inventory_authority(&self) -> crate::BackendIoInventoryAuthority {
        crate::BackendIoInventoryAuthority::SchedulerOwnedModel
    }

    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        self.base.step_to(ceiling)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.base.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.base.snapshot()
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        self.base.restore(snapshot)
    }

    fn now(&self) -> VirtualTime {
        self.base.now()
    }

    fn node_now(&self, node: &NodeId) -> Result<VirtualTime, BackendError> {
        Ok(self
            .counters
            .get(node)
            .copied()
            .unwrap_or(VirtualTime { ticks: 0 }))
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        self.base.fingerprint(node)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.shutdown_calls += 1;
        if self.fail_shutdown {
            return Err(BackendError::Rejected {
                message: String::from("injected physical shutdown failure"),
            });
        }
        self.base.shutdown()?;
        self.held.clear();
        Ok(())
    }
}

impl ConcurrentSimulationBackend for GuestStopBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        if runs.iter().any(|run| self.held.contains_key(run.node())) {
            return Err(BackendError::Rejected {
                message: String::from("RUN attempted before explicit guest release"),
            });
        }
        let mut outcomes = self.base.execute_concurrent_runs(runs, max_host_workers)?;
        for result in &mut outcomes {
            let ConcurrentBackendRunResult::Completed(completed) = result else {
                return Err(BackendError::Rejected {
                    message: String::from("guest-stop model received an operational input handoff"),
                });
            };
            if let Some((pause, cause)) = self
                .stops
                .get_mut(&completed.node)
                .filter(|stops| {
                    stops
                        .front()
                        .is_some_and(|(pause, _)| *pause <= completed.step.reached)
                })
                .and_then(VecDeque::pop_front)
            {
                completed.step.outcome = AdvanceOutcome::Paused {
                    at: Icount {
                        retired: pause.ticks,
                    },
                };
                completed.step.reached = pause;
                completed.step.physical_stop = cause;
                completed
                    .step
                    .applied_preemptions
                    .retain(|command| command.at.ticks <= pause.ticks);
                self.held.insert(completed.node.clone(), pause);
            }
            self.counters
                .insert(completed.node.clone(), completed.step.reached);
        }
        Ok(outcomes)
    }
}

type Adapter = BackendQuantumLoop<SingleScheduler, GuestStopBackend>;

fn adapter(names: &[&str], stops: &[(&str, u64, BackendPhysicalStop)]) -> Adapter {
    let nodes = names
        .iter()
        .map(|name| {
            test_scenario_node(
                name,
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )
        })
        .collect();
    BackendQuantumLoop::new(
        test_scheduler(nodes, Vec::new()),
        GuestStopBackend::new(stops),
    )
}

fn drive(adapter: &mut Adapter) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
    let configuration = adapter.loop_impl().configuration().clone();
    adapter.drive_concurrent_quantum(
        QuantumRequest {
            configuration,
            control: Vec::new(),
        },
        2,
    )
}

#[test]
fn zero_peer_guest_and_marker_stops_require_explicit_release_even_at_ceiling() {
    for (cause, kind) in [
        (
            BackendPhysicalStop::GuestSelectable,
            HeldHostStopKind::GuestSelectable,
        ),
        (
            BackendPhysicalStop::CampaignMarker,
            HeldHostStopKind::CampaignMarker,
        ),
    ] {
        for pause in [20, 64] {
            let mut adapter = adapter(&["source"], &[("source", pause, cause)]);
            let offered = drive(&mut adapter).expect("canonical source stop");
            assert_eq!(offered.outcomes.len(), 1);
            let witness = adapter
                .held_host_stop_witness()
                .expect("zero-peer authority");
            assert_eq!(witness.physical_pause().ticks, pause);
            assert_eq!(witness.kind(), kind);
            assert!(adapter.has_unsettled_host_continuation());
            let runs = adapter.backend().base.run_history.len();

            assert!(drive(&mut adapter).is_err());
            assert_eq!(adapter.backend().base.run_history.len(), runs);
            adapter
                .validate_held_host_stop(&witness)
                .expect("rejected RUN preserves hold");
            let (_, settled) = adapter
                .settle_held_host_stop(&witness, |_, backend, _| backend.release(&witness))
                .expect("explicit authenticated release");
            assert!(settled.is_empty());
            assert!(!adapter.has_unsettled_host_continuation());
            assert_eq!(adapter.backend().base.run_history.len(), runs);
            assert!(
                adapter
                    .settle_held_host_stop(&witness, |_, _, _| -> Result<(), SchedulerError> {
                        panic!("stale release must not execute")
                    })
                    .is_err()
            );
        }
    }
}

#[test]
fn failed_reply_preserves_source_and_peer_ownership_until_success() {
    let mut adapter = adapter(
        &["a-source", "z-peer"],
        &[("a-source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    let offered = drive(&mut adapter).expect("source with physically completed peer");
    assert_eq!(offered.outcomes.len(), 1);
    let witness = adapter.held_host_stop_witness().expect("committed source");
    let before = adapter.loop_impl().event_log_offset();
    let runs = adapter.backend().base.run_history.len();
    let rejected = adapter.settle_held_host_stop(&witness, |_, _, _| {
        Err::<(), _>(SchedulerError::BoundaryViolation {
            message: String::from("injected reply failure"),
        })
    });
    assert!(rejected.is_err());
    assert_eq!(adapter.loop_impl().event_log_offset(), before);
    assert_eq!(adapter.backend().base.run_history.len(), runs);
    adapter
        .validate_held_host_stop(&witness)
        .expect("failed reply retains complete hold");

    let (_, settled) = adapter
        .settle_held_host_stop(&witness, |_, backend, _| backend.release(&witness))
        .expect("retry releases source before causal catch-up");
    assert_eq!(settled.len(), 2);
    assert!(!adapter.has_unsettled_host_continuation());
    assert_eq!(
        adapter
            .backend()
            .base
            .run_history
            .iter()
            .filter(|run| run.node().name == "z-peer")
            .count(),
        1
    );
    assert_eq!(adapter.loop_impl().quanta(), 3);
    assert!(
        adapter
            .settle_held_host_stop(&witness, |_, _, _| -> Result<(), SchedulerError> {
                panic!("no repeated settlement")
            })
            .is_err()
    );
    assert_eq!(adapter.loop_impl().quanta(), 3);
}

#[test]
fn physically_later_guest_is_hidden_until_earlier_source_release() {
    let mut adapter = adapter(
        &["a-source", "z-peer"],
        &[
            ("a-source", 20, BackendPhysicalStop::GuestSelectable),
            ("z-peer", 30, BackendPhysicalStop::CampaignMarker),
        ],
    );
    assert_eq!(
        drive(&mut adapter)
            .expect("earlier canonical source")
            .outcomes
            .len(),
        1
    );
    let first = adapter.held_host_stop_witness().expect("first offer");
    assert_eq!(first.node().name, "a-source");
    assert_eq!(adapter.backend().held.len(), 2);
    let (_, settled) = adapter
        .settle_held_host_stop(&first, |_, backend, _| backend.release(&first))
        .expect("explicit first release");
    assert_eq!(settled.len(), 1);
    let second = adapter
        .held_host_stop_witness()
        .expect("later marker now committed");
    assert_eq!(second.node().name, "z-peer");
    assert_eq!(second.physical_pause().ticks, 30);
    assert_eq!(second.kind(), HeldHostStopKind::CampaignMarker);
    assert!(adapter.validate_held_host_stop(&first).is_err());
    assert!(
        adapter
            .settle_held_host_stop(&first, |_, _, _| -> Result<(), SchedulerError> {
                panic!("old controller authority must not execute")
            })
            .is_err()
    );

    let (_, settled) = adapter
        .settle_held_host_stop(&second, |_, backend, _| backend.release(&second))
        .expect("explicit marker release");
    assert_eq!(settled.len(), 2);
    assert!(!adapter.has_unsettled_host_continuation());
    assert_eq!(adapter.loop_impl().quanta(), 4);
    assert_eq!(
        adapter
            .backend()
            .base
            .run_history
            .iter()
            .filter(|run| run.node().name == "z-peer" && run.ceiling().ticks == 64)
            .count(),
        2
    );
}

#[test]
fn failed_semantic_finish_blocks_run_and_checkpoint_after_zero_peer_release() {
    let mut adapter = adapter(
        &["source"],
        &[("source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    drive(&mut adapter).expect("source stop");
    let witness = adapter.held_host_stop_witness().expect("source proof");
    adapter
        .settle_held_host_stop(&witness, |_, backend, _| backend.release(&witness))
        .expect("release");
    adapter.abort_host_stop_settlement();
    assert!(adapter.has_unsettled_host_continuation());
    assert!(adapter.held_host_stop_witness().is_none());
    assert!(drive(&mut adapter).is_err());
    assert_eq!(adapter.backend().base.run_history.len(), 1);
}

#[test]
fn changed_offer_prefix_rejects_before_external_reply() {
    let mut adapter = adapter(
        &["source"],
        &[("source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    drive(&mut adapter).expect("source stop");
    let witness = adapter.held_host_stop_witness().expect("source proof");
    let offered = adapter.loop_impl().configuration().clone();
    adapter.loop_impl_mut().configuration = Configuration::genesis(
        ScenarioDef::from_canonical_material("held-stop-test", "replaced offered definition"),
    );
    assert!(adapter.validate_held_host_stop(&witness).is_err());
    assert!(
        adapter
            .settle_held_host_stop(&witness, |_, _, _| -> Result<(), SchedulerError> {
                panic!("changed prefix must not reach external reply")
            })
            .is_err()
    );
    assert_eq!(adapter.backend().held.len(), 1);
    assert_eq!(adapter.backend().base.run_history.len(), 1);

    adapter.loop_impl_mut().configuration = offered;
    adapter
        .validate_held_host_stop(&witness)
        .expect("restored exact prefix retains proof");
}

fn same_source_network_guest_adapter() -> Adapter {
    let source = NodeId {
        name: String::from("a-source"),
    };
    let sink = NodeId {
        name: String::from("zz-sink"),
    };
    let nodes = vec![
        test_scenario_node(
            "a-source",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Finite(SimDuration { ticks: 100 }),
            ExactLocalEvent::NoArmedTimer,
        ),
        test_scenario_node(
            "zz-sink",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        ),
    ];
    let mut scheduler = test_scheduler(nodes, Vec::new());
    let link_id = scheduler_link_id_for_nodes(&source, &sink);
    let direction = NetworkLinkDirection::EndpointAToEndpointB;
    let faults = crucible_device::LinkFaults {
        loss: crucible_device::Probability::new(1, 2),
        ..crucible_device::LinkFaults::none()
    };
    scheduler.world_network_links.insert(
        (link_id.clone(), direction),
        WorldNetworkLinkRuntime {
            canonical_id: link_id.clone(),
            endpoint_a: source,
            endpoint_b: sink,
            direction,
            scheduler_node: scheduler_node("a-source", SchedulingNodeKind::Network),
            rng_stream: RngStreamId::for_link(link_id.name.clone()),
            fault_id: crate::DeviceId::from_name("a-source"),
            link: crucible_device::NetLink::new(0, 64, 1, faults).expect("choice link"),
        },
    );
    scheduler.world_network_rng_positions.insert(link_id, 0);
    let mut backend =
        GuestStopBackend::new(&[("a-source", 20, BackendPhysicalStop::GuestSelectable)]);
    backend.base = backend
        .base
        .with_network_output_to("a-source", "zz-sink", 20);
    let mut adapter = BackendQuantumLoop::new(scheduler, backend);
    adapter.set_live_network_choice_pause(true);

    adapter
}

#[test]
fn same_source_network_settlement_preserves_distinct_guest_hold() {
    let mut adapter = same_source_network_guest_adapter();
    drive(&mut adapter).expect("network and guest share one stopped source");
    assert!(adapter.live_network_preselection().is_some());
    assert!(adapter.held_host_stop_witness().is_none());
    assert!(adapter.has_unsettled_host_continuation());
    let runs = adapter.backend().base.run_history.len();
    let settled = adapter
        .settle_host_live_network_preselection()
        .expect("explicit network default settlement");
    assert_eq!(settled.len(), 1);
    assert!(adapter.live_network_preselection().is_none());
    let witness = adapter
        .held_host_stop_witness()
        .expect("network release retains guest stop");
    assert_eq!(witness.physical_pause().ticks, 20);
    assert_eq!(adapter.backend().base.run_history.len(), runs);
    assert_eq!(adapter.backend().held.len(), 1);
    assert!(drive(&mut adapter).is_err());
    adapter
        .settle_held_host_stop(&witness, |_, backend, _| backend.release(&witness))
        .expect("separate explicit guest reply");
    assert!(!adapter.has_unsettled_host_continuation());
    assert_eq!(adapter.backend().base.run_history.len(), runs);
}

#[test]
fn held_peer_application_receipt_is_published_once_after_guest_release() {
    let mut adapter = adapter(
        &["a-source", "z-peer"],
        &[("a-source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    let command = PreemptionDecision {
        node: NodeId {
            name: String::from("z-peer"),
        },
        at: SimInstant { ticks: 32 },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    };
    adapter
        .loop_impl_mut()
        .preemption_requests
        .push(command.clone());
    let mut outcomes = drive(&mut adapter)
        .expect("guest stop retains peer receipt")
        .outcomes;
    assert!(adapter.loop_impl().preemption_applications().is_empty());
    assert!(
        outcomes
            .iter()
            .flat_map(|outcome| &outcome.decisions)
            .all(|decision| !matches!(decision, Decision::Preemption(_)))
    );
    let witness = adapter.held_host_stop_witness().expect("committed source");

    let (_, settled) = adapter
        .settle_held_host_stop(&witness, |_, backend, _| backend.release(&witness))
        .expect("explicit source release admits held receipt");
    outcomes.extend(settled);
    let reported = outcomes
        .iter()
        .flat_map(|outcome| &outcome.decisions)
        .filter(|decision| matches!(decision, Decision::Preemption(value) if value == &command))
        .count();
    assert_eq!(reported, 1);
    assert_eq!(adapter.loop_impl().preemption_applications().len(), 1);
    assert_eq!(
        adapter.loop_impl().preemption_applications()[0].decision,
        command
    );
    let mut sequence = std::collections::BTreeSet::new();
    for entry in outcomes
        .iter()
        .flat_map(|outcome| &outcome.event_log_entries)
    {
        assert!(
            sequence.insert(entry.sequence()),
            "no held entry is returned twice"
        );
    }
    assert!(
        adapter
            .settle_held_host_stop(&witness, |_, _, _| -> Result<(), SchedulerError> {
                panic!("consumed peer evidence cannot be admitted twice")
            })
            .is_err()
    );
    assert_eq!(adapter.loop_impl().preemption_applications().len(), 1);
}

#[test]
fn authenticated_host_publication_refreshes_only_the_same_stopped_source() {
    for cause in [
        BackendPhysicalStop::GuestSelectable,
        BackendPhysicalStop::CampaignMarker,
    ] {
        let mut adapter = adapter(&["source"], &[("source", 20, cause)]);
        drive(&mut adapter).expect("source stop");
        let before = adapter
            .held_host_stop_witness()
            .expect("canonical proof before publication");
        adapter
            .validate_held_host_stop(&before)
            .expect("authenticate old host prefix before effects");
        assert_eq!(
            adapter.backend().held.get(before.node()),
            Some(&before.physical_pause())
        );
        let at = adapter.loop_impl().frontier();
        adapter
            .loop_impl_mut()
            .append_evaluation_boundary(at, crate::SchedulerEvaluationBoundaryKind::Quantum)
            .expect("real host evaluation append");
        assert!(adapter.validate_held_host_stop(&before).is_err());

        adapter
            .refresh_held_host_stop_prefix_after_transition(&before)
            .expect("same authenticated stop with appended prefix");
        let after = adapter.held_host_stop_witness().expect("refreshed offer");
        assert_ne!(before, after);
        assert_eq!(before.node(), after.node());
        assert_eq!(before.kind(), after.kind());
        assert_eq!(before.physical_pause(), after.physical_pause());
        assert_eq!(adapter.backend().base.run_history.len(), 1);
        assert_eq!(adapter.backend().held.len(), 1);
        assert!(adapter.validate_held_host_stop(&before).is_err());
        adapter
            .validate_held_host_stop(&after)
            .expect("actual first offer survives host finish");
        adapter
            .settle_held_host_stop(&after, |_, backend, _| backend.release(&after))
            .expect("explicit reply after publication");
        assert!(!adapter.has_unsettled_host_continuation());
        assert_eq!(adapter.backend().base.run_history.len(), 1);
    }
}

#[test]
fn explicit_shutdown_discards_guest_and_marker_peers_only_after_backend_success() {
    for cause in [
        BackendPhysicalStop::GuestSelectable,
        BackendPhysicalStop::CampaignMarker,
    ] {
        for names in [&["source"][..], &["source", "z-peer"][..]] {
            let mut adapter = adapter(names, &[("source", 20, cause)]);
            drive(&mut adapter).expect("committed stop with optional held peer");
            let quanta = adapter.loop_impl().quanta();
            let offset = adapter.loop_impl().event_log_offset();
            let physical_runs = adapter.backend().base.run_history.len();
            adapter.backend_mut().fail_shutdown = true;

            assert!(adapter.shutdown().is_err());
            assert_eq!(adapter.backend().shutdown_calls, 1);
            assert_eq!(adapter.backend().held.len(), 1);
            assert!(adapter.has_unsettled_host_continuation());
            assert!(adapter.continuation_is_poisoned());
            assert!(drive(&mut adapter).is_err());
            assert_eq!(adapter.backend().base.run_history.len(), physical_runs);
            assert_eq!(adapter.loop_impl().quanta(), quanta);
            assert_eq!(adapter.loop_impl().event_log_offset(), offset);

            adapter.backend_mut().fail_shutdown = false;
            assert!(
                adapter
                    .shutdown()
                    .expect("explicit physical teardown retry")
                    .is_empty()
            );
            assert_eq!(adapter.backend().shutdown_calls, 2);
            assert!(adapter.backend().held.is_empty());
            assert!(adapter.held_host_stop_witness().is_none());
            assert!(adapter.continuation_is_poisoned());
            assert!(drive(&mut adapter).is_err());
            assert_eq!(adapter.backend().base.run_history.len(), physical_runs);
            assert_eq!(adapter.loop_impl().quanta(), quanta);
            assert_eq!(adapter.loop_impl().event_log_offset(), offset);
            assert!(adapter.loop_impl().preemption_applications().is_empty());
        }
    }
}

#[test]
fn same_source_network_and_guest_shutdown_keeps_authorities_until_physical_success() {
    let mut adapter = same_source_network_guest_adapter();
    drive(&mut adapter).expect("same-source network and guest authorities");
    let runs = adapter.backend().base.run_history.len();
    let offset = adapter.loop_impl().event_log_offset();
    adapter.backend_mut().fail_shutdown = true;
    assert!(adapter.shutdown().is_err());
    assert!(adapter.live_network_preselection().is_some());
    assert_eq!(adapter.backend().held.len(), 1);
    assert_eq!(adapter.backend().shutdown_calls, 1);
    assert!(adapter.continuation_is_poisoned());

    adapter.backend_mut().fail_shutdown = false;
    assert!(
        adapter
            .shutdown()
            .expect("explicit whole-world retry")
            .is_empty()
    );
    assert!(adapter.live_network_preselection().is_none());
    assert!(adapter.backend().held.is_empty());
    assert_eq!(adapter.backend().shutdown_calls, 2);
    assert_eq!(adapter.backend().base.run_history.len(), runs);
    assert_eq!(adapter.loop_impl().event_log_offset(), offset);
    assert!(adapter.continuation_is_poisoned());
    assert!(drive(&mut adapter).is_err());
    assert!(adapter.loop_impl().preemption_applications().is_empty());
}

#[test]
fn identical_prefix_new_world_rejects_old_controller_authority_before_reply() {
    let mut first = adapter(
        &["source"],
        &[("source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    let mut second = adapter(
        &["source"],
        &[("source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    drive(&mut first).expect("old world's canonical stop");
    drive(&mut second).expect("identical new world's canonical stop");
    let old = first
        .held_host_stop_witness()
        .expect("old controller proof");
    let current = second
        .held_host_stop_witness()
        .expect("new controller proof");
    assert_eq!(
        first.loop_impl().configuration(),
        second.loop_impl().configuration()
    );
    assert_eq!(
        first.loop_impl().event_log_offset(),
        second.loop_impl().event_log_offset()
    );
    assert_eq!(old.node(), current.node());
    assert_eq!(old.physical_pause(), current.physical_pause());
    assert_eq!(old.kind(), current.kind());
    assert_ne!(old, current);
    first.shutdown().expect("destroy old physical world");

    assert!(second.validate_held_host_stop(&old).is_err());
    assert!(
        second
            .settle_held_host_stop(&old, |_, _, _| -> Result<(), SchedulerError> {
                panic!("another controller's witness must not reach external reply")
            })
            .is_err()
    );
    assert_eq!(second.backend().held.len(), 1);
    assert_eq!(second.backend().base.run_history.len(), 1);
    second
        .validate_held_host_stop(&current)
        .expect("own retained authority remains valid");
    second
        .settle_held_host_stop(&current, |_, backend, _| backend.release(&current))
        .expect("own exact controller can release");
    assert!(!second.has_unsettled_host_continuation());
}

#[test]
fn cloned_world_rejects_original_witness_before_reply_but_keeps_own_authority() {
    let mut original = adapter(
        &["source"],
        &[("source", 20, BackendPhysicalStop::GuestSelectable)],
    );
    drive(&mut original).expect("original world's canonical stop");
    let old = original
        .held_host_stop_witness()
        .expect("original controller witness");
    let mut cloned = original.clone();
    let current = cloned
        .held_host_stop_witness()
        .expect("cloned controller witness");
    assert_eq!(
        original.loop_impl().configuration(),
        cloned.loop_impl().configuration()
    );
    assert_eq!(
        original.loop_impl().event_log_offset(),
        cloned.loop_impl().event_log_offset()
    );
    assert_ne!(old, current);

    assert!(cloned.validate_held_host_stop(&old).is_err());
    assert!(
        cloned
            .settle_held_host_stop(&old, |_, _, _| -> Result<(), SchedulerError> {
                panic!("original authority must not reach a cloned world's reply")
            })
            .is_err()
    );
    assert_eq!(cloned.backend().held.len(), 1);
    assert_eq!(cloned.backend().base.run_history.len(), 1);
    original
        .validate_held_host_stop(&old.clone())
        .expect("witness clone retains original controller authority");
    cloned
        .validate_held_host_stop(&current)
        .expect("cloned world's own authority remains valid");
    cloned
        .settle_held_host_stop(&current, |_, backend, _| backend.release(&current))
        .expect("cloned world's exact controller can release");
    assert!(!cloned.has_unsettled_host_continuation());
    assert!(original.has_unsettled_host_continuation());
}
